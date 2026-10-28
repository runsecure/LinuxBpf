//! L3/L4 header parsing, generic over `reader::PacketReader` so it can run
//! both against a real `cgroup_skb` context (via the `SkbReader` adapter in
//! `linuxbpf-ebpf`) and against a plain byte buffer in tests.
//!
//! `cgroup_skb` attaches below the socket layer, above the device layer:
//! the packet starts at the IP header, there is no Ethernet header to skip.

// `network_types` is a small external crate of plain Rust structs that
// mirror real network protocol headers byte-for-byte (it's not part of
// this project) -- `Ipv4Hdr`/`Ipv6Hdr`/`TcpHdr`/`UdpHdr` below are its
// types, saving this code from having to hand-define the exact byte
// layout of an IP or TCP header itself.
use network_types::{
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{L4Proto, reader::PacketReader};

// "EtherType" values: the two-byte code that identifies what kind of
// payload a frame/packet carries at the network layer. `0x0800` is the
// long-standing standard value for "this is an IPv4 packet"; `0x86DD` for
// IPv6. These are well-known, protocol-defined constants, not something
// this project invented.
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

// An address pair that remembers which IP version it came from. Modeled
// as an enum with two *variants*, each carrying its own differently-sized
// arrays, rather than always using 16-byte arrays and a separate "which
// version" flag -- so the type system itself makes "a V4 flow with a
// 16-byte address" simply not constructible, instead of a runtime
// possibility that has to be checked for.
pub enum FlowAddr {
    V4 { saddr: [u8; 4], daddr: [u8; 4] },
    V6 { saddr: [u8; 16], daddr: [u8; 16] },
}

// Everything `filter.rs` needs to know about one packet's flow, once
// parsing succeeds: who it's between, what port, what protocol, and where
// in the packet the header ends and any payload begins.
pub struct FlowMeta {
    pub addr: FlowAddr,
    pub sport: u16,
    pub dport: u16,
    pub l4_proto: L4Proto,
    /// Byte offset from the start of the packet to the first byte past the
    /// L4 header, i.e. where application payload (if any) begins.
    pub payload_offset: usize,
}

// Every possible result of trying to parse a packet. Modeling this as one
// enum with four variants (rather than, say, `Option<FlowMeta>` plus a
// separate error type) is what lets `filter.rs`'s `evaluate` handle each
// case with a single `match` and give each one its own `MatchKind` for
// telemetry -- see that file's comments.
pub enum ParseOutcome {
    Flow(FlowMeta),
    /// Valid IP header, but not a protocol we classify (e.g. ICMP) or the
    /// L4 header didn't fit in the packet.
    Unsupported,
    /// Not IPv4/IPv6 at all.
    NotIp,
    /// Looked like IP but a header read failed (truncated packet).
    Malformed,
}

/// Entry point: looks at the packet's EtherType and dispatches to the
/// matching IPv4/IPv6 parser, or bails out immediately if it's neither.
// `<R: PacketReader>`: this function doesn't care *how* bytes get read
// from the packet, only that whatever `reader` is knows how to (via the
// trait methods declared in `reader.rs`). At compile time, Rust generates
// a separate, fully concrete copy of this function for each different `R`
// it's ever called with -- in practice that's exactly two: once for the
// real `SkbReader` (used by `linuxbpf-ebpf`), and once for the test-only
// `SliceReader` (used by this file's own tests, below) -- so there's no
// runtime cost to this generality; it's resolved entirely at compile
// time.
pub fn parse<R: PacketReader>(reader: &R) -> ParseOutcome {
    // `reader.ether_type()` already comes back converted to host byte
    // order (see `SkbReader::ether_type`'s comment in `linuxbpf-ebpf`), so
    // it can be compared directly against the plain constants above.
    match reader.ether_type() {
        ETH_P_IP => parse_v4(reader),
        ETH_P_IPV6 => parse_v6(reader),
        // Anything else (ARP, etc.) -- not IP traffic this filter has any
        // opinion about.
        _ => ParseOutcome::NotIp,
    }
}

// Not `pub`: only called from `parse` above, within this same module.
fn parse_v4<R: PacketReader>(reader: &R) -> ParseOutcome {
    // `reader.load(0)`: read `size_of::<Ipv4Hdr>()` bytes starting at
    // offset 0 (the very start of the packet -- see this file's top
    // comment on why there's no Ethernet header to skip first) and
    // reinterpret them as an `Ipv4Hdr` struct. This either succeeds
    // outright or fails as one unit; there's no partial/short read to
    // handle here.
    let ip: Ipv4Hdr = match reader.load(0) {
        Ok(v) => v,
        // A read can fail if the packet is shorter than a full IPv4
        // header (20 bytes) -- an unusually short/truncated packet,
        // treated as unparseable rather than assumed to be some other
        // protocol.
        Err(_) => return ParseOutcome::Malformed,
    };
    // `ihl()` ("Internet Header Length") is the IPv4 header's own
    // self-reported length in bytes -- it can be *longer* than the fixed
    // 20-byte struct just read, if the packet carries IP options (rare in
    // practice, but the field exists for that). `Ipv4Hdr::LEN` is exactly
    // 20 -- the fixed part just parsed. If the header claims to be
    // *shorter* than that fixed part, something is wrong with the packet
    // (or it's actively malformed/adversarial); reject rather than trust
    // a nonsensical value.
    let ihl = ip.ihl() as usize;
    if ihl < Ipv4Hdr::LEN {
        return ParseOutcome::Malformed;
    }
    // `.src_addr()`/`.dst_addr()` return `core::net::Ipv4Addr` values;
    // `.octets()` unwraps those back down to the plain `[u8; 4]` byte
    // arrays this codebase uses everywhere else (see `maps.rs`'s comment
    // on why: so there's exactly one address representation to reason
    // about).
    let saddr = ip.src_addr().octets();
    let daddr = ip.dst_addr().octets();
    // `.proto()` decodes the header's raw protocol-number byte into the
    // `IpProto` enum (`network_types`' own type, listing every
    // IANA-assigned protocol number). It can fail if that byte doesn't
    // correspond to any protocol `network_types` knows about -- treated
    // as "not a protocol we can classify" (`Unsupported`), not as a
    // malformed packet (the header itself is still perfectly valid IP,
    // just carrying something this filter doesn't specifically handle).
    let proto = match ip.proto() {
        Ok(p) => p,
        Err(_) => return ParseOutcome::Unsupported,
    };

    // Only TCP and UDP are understood past this point. This one `match`
    // produces all four values needed for `FlowMeta` at once (via a
    // tuple), since the *how* of getting each one is different for TCP
    // vs. UDP but all four are needed regardless of which it is.
    let (l4_proto, sport, dport, l4_hdr_len) = match proto {
        IpProto::Tcp => {
            // Load the TCP header starting right after the IP header
            // (`ihl` bytes in -- this is *why* `ihl` was read above, not
            // just validated: it's the offset the L4 header actually
            // starts at, which varies packet-to-packet if IP options are
            // present).
            let tcp: TcpHdr = match reader.load(ihl) {
                Ok(v) => v,
                Err(_) => return ParseOutcome::Malformed,
            };
            (
                L4Proto::Tcp,
                // TCP port fields are stored in network byte order (big
                // endian) as raw 2-byte arrays; `u16::from_be_bytes`
                // converts them to an ordinary host-order `u16`.
                u16::from_be_bytes(tcp.source),
                u16::from_be_bytes(tcp.dest),
                // `doff()` ("data offset") is TCP's equivalent of IPv4's
                // `ihl`: the header's own length, but expressed in 32-bit
                // *words* rather than bytes (a TCP-specific quirk), so it
                // has to be multiplied by 4 to get an actual byte count.
                (tcp.doff() as usize) * 4,
            )
        }
        IpProto::Udp => {
            let udp: UdpHdr = match reader.load(ihl) {
                Ok(v) => v,
                Err(_) => return ParseOutcome::Malformed,
            };
            // UDP has no equivalent of TCP's variable-length options, so
            // its header is always exactly `UdpHdr::LEN` (8) bytes --
            // no doff-style field to read.
            (L4Proto::Udp, udp.src_port(), udp.dst_port(), UdpHdr::LEN)
        }
        // Anything other than TCP/UDP (ICMP, etc.): valid IP, unsupported
        // L4 protocol.
        _ => return ParseOutcome::Unsupported,
    };
    // A TCP header genuinely can't be shorter than the fixed struct
    // already successfully loaded above, so an `l4_hdr_len` of `0` here
    // can only mean the packet's own `doff` field was bogus -- treat that
    // as malformed rather than proceeding with a nonsensical payload
    // offset.
    if l4_hdr_len < 1 {
        return ParseOutcome::Malformed;
    }

    // Success: bundle everything parsed into a `FlowMeta` and wrap it in
    // the `Flow` variant. `payload_offset` is simply "where the IP header
    // ended, plus where the L4 header ended" -- the first byte of
    // whatever application data (if any) the packet is carrying.
    ParseOutcome::Flow(FlowMeta {
        addr: FlowAddr::V4 { saddr, daddr },
        sport,
        dport,
        l4_proto,
        payload_offset: ihl + l4_hdr_len,
    })
}

// The IPv6 mirror of `parse_v4` above -- same overall shape, with IPv6's
// own header quirks.
fn parse_v6<R: PacketReader>(reader: &R) -> ParseOutcome {
    let ip: Ipv6Hdr = match reader.load(0) {
        Ok(v) => v,
        Err(_) => return ParseOutcome::Malformed,
    };
    let saddr = ip.src_addr().octets();
    let daddr = ip.dst_addr().octets();
    // Extension headers (hop-by-hop, routing, fragment, ...) are not
    // walked: only the common case of TCP/UDP directly following the fixed
    // IPv6 header is classified by hostname/IP rules below.
    //
    // Unlike IPv4's `ihl`, the fixed IPv6 header (`Ipv6Hdr::LEN`, always
    // exactly 40 bytes) never varies in length -- but IPv6 packets *can*
    // insert one or more optional "extension headers" between the fixed
    // header and the real L4 (TCP/UDP) header, each announcing what comes
    // next via its own `next_hdr`-style field, forming a chain. This code
    // only reads the *first* `next_hdr` (the fixed header's own field)
    // and assumes it points straight at TCP/UDP -- a packet using
    // extension headers would have its real protocol misread here and
    // fall into `Unsupported` below. That's a known, documented
    // simplification (see the project README), not an oversight: real
    // application traffic essentially never uses IPv6 extension headers.
    let proto = match ip.next_hdr() {
        Ok(p) => p,
        Err(_) => return ParseOutcome::Unsupported,
    };

    let (l4_proto, sport, dport, l4_hdr_len) = match proto {
        IpProto::Tcp => {
            // No `ihl` equivalent to add here -- the L4 header always
            // starts exactly `Ipv6Hdr::LEN` bytes in, since (per the
            // simplification above) extension headers aren't accounted
            // for.
            let tcp: TcpHdr = match reader.load(Ipv6Hdr::LEN) {
                Ok(v) => v,
                Err(_) => return ParseOutcome::Malformed,
            };
            (
                L4Proto::Tcp,
                u16::from_be_bytes(tcp.source),
                u16::from_be_bytes(tcp.dest),
                (tcp.doff() as usize) * 4,
            )
        }
        IpProto::Udp => {
            let udp: UdpHdr = match reader.load(Ipv6Hdr::LEN) {
                Ok(v) => v,
                Err(_) => return ParseOutcome::Malformed,
            };
            (L4Proto::Udp, udp.src_port(), udp.dst_port(), UdpHdr::LEN)
        }
        _ => return ParseOutcome::Unsupported,
    };
    if l4_hdr_len < 1 {
        return ParseOutcome::Malformed;
    }

    ParseOutcome::Flow(FlowMeta {
        addr: FlowAddr::V6 { saddr, daddr },
        sport,
        dport,
        l4_proto,
        payload_offset: Ipv6Hdr::LEN + l4_hdr_len,
    })
}

/// Widens a 4-byte IPv4 address into the 16-byte shape `FlowEvent`
/// uses for both address families, placing the real bytes first and
/// zero-filling the rest.
pub fn expand4(a: [u8; 4]) -> [u8; 16] {
    // Start with an all-zero 16-byte array...
    let mut out = [0u8; 16];
    // ...then copy each of the 4 real address bytes into the front of it,
    // one at a time. (A `for` loop or `out[..4].copy_from_slice(&a)` would
    // do the same thing more concisely; this explicit, unrolled form is
    // used instead purely to keep this function trivially simple for the
    // eBPF verifier to reason about -- see `tls.rs`/`http.rs` for where
    // that kind of caution is actually load-bearing. Here it's mostly
    // just consistency of style.)
    out[0] = a[0];
    out[1] = a[1];
    out[2] = a[2];
    out[3] = a[3];
    out
}

// Native unit tests -- see this project's README ("Testing") for why
// these can run on any machine, no Linux/BPF/kernel required: `parse`
// above is written against the `PacketReader` *trait*, and `SliceReader`
// (imported below) is a fake implementation of it backed by a plain
// in-memory byte slice instead of a real kernel packet context.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::SliceReader;

    // Reinterprets any `Copy` value's raw in-memory bytes as a `Vec<u8>`
    // -- used below to turn a hand-built `Ipv4Hdr`/`TcpHdr`/etc. value
    // into the literal bytes a real packet carrying that header would
    // contain, so they can be concatenated into one fake "packet" buffer
    // for `SliceReader` to read from.
    fn bytes_of<T: Copy>(v: &T) -> Vec<u8> {
        let ptr = v as *const T as *const u8;
        // SAFETY: `T: Copy` guarantees no destructors/ownership
        // subtleties, and the slice's length exactly matches `T`'s own
        // size, so this is a straightforward, valid reinterpretation of
        // `v`'s bytes.
        unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<T>()) }.to_vec()
    }

    // Builds a ready-to-use IPv4 header value with sensible defaults
    // filled in, so each test below only has to specify the handful of
    // fields it actually cares about.
    fn ipv4_header(proto: IpProto, src: [u8; 4], dst: [u8; 4], tot_len: u16) -> Ipv4Hdr {
        Ipv4Hdr {
            vihl: (4 << 4) | 5, // version 4, IHL 5 words = 20 bytes
            tos: 0,
            tot_len: tot_len.to_be_bytes(),
            id: [0, 0],
            frags: [0, 0],
            ttl: 64,
            proto: proto as u8,
            check: [0, 0],
            src_addr: src,
            dst_addr: dst,
        }
    }

    fn ipv6_header(next_hdr: IpProto, src: [u8; 16], dst: [u8; 16], payload_len: u16) -> Ipv6Hdr {
        Ipv6Hdr {
            vcf: [0x60, 0, 0, 0],
            payload_len: payload_len.to_be_bytes(),
            next_hdr: next_hdr as u8,
            hop_limit: 64,
            src_addr: src,
            dst_addr: dst,
        }
    }

    fn tcp_header(sport: u16, dport: u16, doff_words: u16) -> TcpHdr {
        TcpHdr {
            source: sport.to_be_bytes(),
            dest: dport.to_be_bytes(),
            seq: [0; 4],
            ack_seq: [0; 4],
            _bitfield_align_1: [],
            // TCP's flags/data-offset byte is a bitfield `network_types`
            // exposes via this constructor rather than plain struct
            // fields; only `doff` (the 5th argument) matters for these
            // tests, so every flag (SYN/ACK/FIN/...) is passed as `0`.
            _bitfield_1: TcpHdr::new_bitfield_1(0, doff_words, 0, 0, 0, 0, 0, 0, 0, 0),
            window: [0; 2],
            check: [0; 2],
            urg_ptr: [0; 2],
        }
    }

    fn udp_header(sport: u16, dport: u16, len: u16) -> UdpHdr {
        let mut udp = UdpHdr {
            src: [0; 2],
            dst: [0; 2],
            len: [0; 2],
            check: [0; 2],
        };
        // UDP's port/length fields have to be set via these methods
        // (rather than the struct literal above) since they handle the
        // host-to-network byte-order conversion; the struct's own fields
        // are the *already-network-order* raw bytes.
        udp.set_src_port(sport);
        udp.set_dst_port(dport);
        udp.set_len(len);
        udp
    }

    #[test]
    fn parses_ipv4_tcp() {
        let ip = ipv4_header(IpProto::Tcp, [10, 0, 0, 1], [93, 184, 216, 34], 60);
        let tcp = tcp_header(54321, 443, 5);
        // Concatenate the two headers' raw bytes, then a few more bytes
        // of fake "payload" -- together this is exactly what a real
        // packet's bytes would look like, laid out the same way a real
        // NIC/kernel would hand them to a `cgroup_skb` program.
        let mut data = bytes_of(&ip);
        data.extend(bytes_of(&tcp));
        data.extend_from_slice(b"payload");

        let reader = SliceReader {
            ether_type: ETH_P_IP,
            data: &data,
        };
        match parse(&reader) {
            ParseOutcome::Flow(meta) => {
                match meta.addr {
                    FlowAddr::V4 { saddr, daddr } => {
                        assert_eq!(saddr, [10, 0, 0, 1]);
                        assert_eq!(daddr, [93, 184, 216, 34]);
                    }
                    FlowAddr::V6 { .. } => panic!("expected V4"),
                }
                assert_eq!(meta.sport, 54321);
                assert_eq!(meta.dport, 443);
                assert!(matches!(meta.l4_proto, L4Proto::Tcp));
                assert_eq!(meta.payload_offset, Ipv4Hdr::LEN + TcpHdr::LEN);
            }
            _ => panic!("expected a parsed flow"),
        }
    }

    #[test]
    fn parses_ipv4_udp() {
        let ip = ipv4_header(IpProto::Udp, [10, 0, 0, 1], [8, 8, 8, 8], 36);
        let udp = udp_header(53000, 53, 16);
        let mut data = bytes_of(&ip);
        data.extend(bytes_of(&udp));

        let reader = SliceReader {
            ether_type: ETH_P_IP,
            data: &data,
        };
        match parse(&reader) {
            ParseOutcome::Flow(meta) => {
                assert!(matches!(meta.l4_proto, L4Proto::Udp));
                assert_eq!(meta.dport, 53);
                assert_eq!(meta.payload_offset, Ipv4Hdr::LEN + UdpHdr::LEN);
            }
            _ => panic!("expected a parsed flow"),
        }
    }

    #[test]
    fn parses_ipv6_tcp() {
        let ip = ipv6_header(IpProto::Tcp, [0xfd; 16], [0xfe; 16], 20);
        let tcp = tcp_header(1111, 8443, 5);
        let mut data = bytes_of(&ip);
        data.extend(bytes_of(&tcp));

        let reader = SliceReader {
            ether_type: ETH_P_IPV6,
            data: &data,
        };
        match parse(&reader) {
            ParseOutcome::Flow(meta) => {
                match meta.addr {
                    FlowAddr::V6 { saddr, daddr } => {
                        assert_eq!(saddr, [0xfd; 16]);
                        assert_eq!(daddr, [0xfe; 16]);
                    }
                    FlowAddr::V4 { .. } => panic!("expected V6"),
                }
                assert_eq!(meta.payload_offset, Ipv6Hdr::LEN + TcpHdr::LEN);
            }
            _ => panic!("expected a parsed flow"),
        }
    }

    #[test]
    fn non_ip_ether_type_is_not_ip() {
        let reader = SliceReader {
            ether_type: 0x0806, // ARP
            data: &[0u8; 64],
        };
        assert!(matches!(parse(&reader), ParseOutcome::NotIp));
    }

    #[test]
    fn unrecognized_l4_protocol_is_unsupported() {
        let ip = ipv4_header(IpProto::Icmp, [1, 1, 1, 1], [2, 2, 2, 2], 20);
        let data = bytes_of(&ip);
        let reader = SliceReader {
            ether_type: ETH_P_IP,
            data: &data,
        };
        assert!(matches!(parse(&reader), ParseOutcome::Unsupported));
    }

    #[test]
    fn truncated_ipv4_header_is_malformed() {
        let data = [0u8; 10]; // shorter than Ipv4Hdr::LEN (20)
        let reader = SliceReader {
            ether_type: ETH_P_IP,
            data: &data,
        };
        assert!(matches!(parse(&reader), ParseOutcome::Malformed));
    }

    #[test]
    fn truncated_l4_header_is_malformed() {
        let ip = ipv4_header(IpProto::Tcp, [1, 1, 1, 1], [2, 2, 2, 2], 20);
        let mut data = bytes_of(&ip);
        data.extend_from_slice(&[0u8; 4]); // way short of a full TCP header
        let reader = SliceReader {
            ether_type: ETH_P_IP,
            data: &data,
        };
        assert!(matches!(parse(&reader), ParseOutcome::Malformed));
    }

    #[test]
    fn expand4_places_v4_bytes_in_first_four_bytes() {
        assert_eq!(
            expand4([1, 2, 3, 4]),
            [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
