//! Shared classification logic invoked by both the ingress and egress
//! `cgroup_skb` programs. Each direction owns its own concrete maps (see
//! `maps.rs`); this module just takes references to whichever set applies
//! and a `Direction` telling it which side of the flow ("remote" party) the
//! IP/subnet allowlists are matched against.
//!
//! Written generically over `linuxbpf_common::reader::PacketReader` rather
//! than directly against `SkBuffContext`, so the parsing it calls into
//! (`linuxbpf_common::ip::parse`) is exactly the same code exercised by
//! that crate's native unit tests.
//!
//! ## Hostname (SNI/HTTP Host) matching is not wired in here
//!
//! `linuxbpf_common::tls`/`http` contain a complete, unit-tested SNI/Host
//! parser, and an earlier version of this file called it as a fallback
//! when the IP/subnet check denied a packet -- it also passed the kernel
//! verifier, after a long chain of BPF-specific fixes (documented in that
//! module's history: stack-overflow from an oversized on-stack buffer,
//! "fat pointer across a real BPF-to-BPF call" ABI violations, the
//! verifier failing to correlate a bounds check on one register with a
//! pointer derived from a different one, and a few more).
//!
//! It was removed after testing against real traffic revealed a structural
//! problem, not a bug: this filter is a purely stateless, per-packet
//! decision point with no connection tracking. A TLS ClientHello only
//! exists in the data packet that follows a *completed* TCP handshake
//! (SYN -> SYN-ACK -> ACK), and hostname matching only ever ran as a
//! fallback *when the IP/subnet check had already denied the packet* --
//! including the SYN itself. So for any destination not already
//! IP/subnet-allowed, the SYN is dropped before the client can ever send
//! the ClientHello, and hostname matching never sees real data to inspect.
//! Conversely, if the IP/subnet check allows the SYN, it also allows every
//! later packet, so hostname matching never runs as a fallback at all. The
//! combination needed for it to ever fire -- IP/subnet denies, but the
//! handshake still completes -- can't happen with this design.
//!
//! A working version needs the TCP handshake for a candidate connection
//! (SYN/SYN-ACK/ACK, no payload, dport 443/80) to be let through
//! provisionally when a hostname rule exists for that direction, with the
//! real decision deferred to (and enforced by dropping) the first
//! data-carrying packet. That's a real change to what "denied" means for
//! such connections -- a destination's port being open becomes
//! observable even when not allowlisted, though no application data ever
//! crosses -- so it's deliberately not implemented silently; see the
//! project's README for the tracking note.

// `aya_ebpf::maps`: the *typed Rust wrappers* around BPF map handles --
// these are the types used below to declare what kind of map each field
// of `AllowMaps` points at (matching the concrete `static` maps declared
// in `maps.rs`). `lpm_trie::Key` is the small helper type used to build a
// *lookup* key (prefix length + address bytes) for an `LpmTrie` map.
use aya_ebpf::maps::{HashMap, LpmTrie, lpm_trie::Key};
// Everything imported here comes from `linuxbpf-common`, the crate shared
// between this kernel-side code and the userspace loader -- see that
// crate's `lib.rs` for each type's definition.
use linuxbpf_common::{
    Direction, FlowEvent, L4Proto, MatchKind, Mode, Verdict, ip,
    ip::{FlowAddr, FlowMeta, ParseOutcome},
    reader::PacketReader,
};

// The specific map `static`s this file actually touches directly (the
// `MODE` flag and the `EVENTS` ring buffer); the four IP/subnet maps are
// received indirectly, via `AllowMaps`, from `ingress.rs`/`egress.rs`.
use crate::maps::{EVENTS, MODE};

// A small bundle of references to one direction's four allowlist maps.
// Its only job is to let `evaluate`/`check_ip_allow` below be written
// once and reused for both ingress and egress, by taking "whichever maps
// apply" as a parameter instead of naming `INGRESS_IPV4` etc. directly.
// `'a` is a lifetime parameter: it says every field is a *reference* that
// must stay valid for at least as long as the `AllowMaps` value holding
// it does -- appropriate here since the maps themselves are `'static`
// (they live for the whole program), so `'a` just gets inferred as
// `'static` at each actual call site.
pub struct AllowMaps<'a> {
    pub ipv4: &'a HashMap<[u8; 4], u8>,
    pub ipv6: &'a HashMap<[u8; 16], u8>,
    pub subnets_v4: &'a LpmTrie<[u8; 4], u8>,
    pub subnets_v6: &'a LpmTrie<[u8; 16], u8>,
}

/// Classifies one packet and returns the value the calling `#[cgroup_skb]`
/// program should return to the kernel (1 = allow, 0 = deny). Always emits
/// a `FlowEvent`, even in `Mode::Monitor` where the return value is forced
/// to allow -- the event's `verdict` field carries what *would* have
/// happened.
// Generic over `R: PacketReader` rather than taking a concrete
// `SkBuffContext`: the real programs pass in a `SkbReader` (see
// `reader.rs`), wrapping the actual kernel packet; the native unit tests
// in `linuxbpf-common` pass in a fake, in-memory reader instead, and this
// exact function body runs unmodified either way. `reader: &R` borrows
// it rather than taking ownership, since the caller (`ingress.rs`/
// `egress.rs`) still needs it after this call returns (well, it doesn't
// here, but borrowing is the natural default when ownership isn't
// needed).
pub fn evaluate<R: PacketReader>(reader: &R, direction: Direction, maps: &AllowMaps) -> i32 {
    // Read the live enforce/monitor flag once, up front, so it's
    // available no matter which path through this function is taken
    // below.
    let mode = current_mode();

    // Attempt to parse the packet's IP + TCP/UDP headers into a small
    // `FlowMeta` struct (addresses, ports, protocol, where the payload
    // starts). `ip::parse` returns one of four outcomes -- this `match`
    // handles the three "not a normal flow" cases inline and falls
    // through to the happy path below.
    let meta = match ip::parse(reader) {
        // The common case: got a fully-parsed IPv4/IPv6 + TCP/UDP header.
        // `m` (a `FlowMeta`) is bound and used for the rest of the
        // function.
        ParseOutcome::Flow(m) => m,
        // Not an IP packet at all (e.g. ARP). This filter only has
        // opinions about IP traffic, so anything else is passed through
        // unfiltered and unlogged -- returning immediately from
        // `evaluate` itself, skipping `finish` (and so skipping the
        // telemetry event) entirely.
        ParseOutcome::NotIp => return Verdict::Allow as i32,
        // Valid IP header, but not a protocol this filter classifies
        // (e.g. ICMP), or the L4 header didn't fit in the packet. Denied,
        // but still logged (via `finish` below) so an operator can see
        // this kind of traffic happened -- using placeholder zeroed
        // addresses/ports since none were successfully parsed.
        ParseOutcome::Unsupported => {
            return finish(
                direction,
                mode,
                Verdict::Deny,
                MatchKind::Unsupported,
                4,
                [0u8; 16],
                [0u8; 16],
                0,
                0,
                L4Proto::Other,
            );
        }
        // Looked like it should be a valid header but a read failed
        // (e.g. the packet was truncated mid-header). Also denied and
        // logged, with its own distinct `MatchKind` so the two "we
        // couldn't classify this" cases are distinguishable in telemetry.
        ParseOutcome::Malformed => {
            return finish(
                direction,
                mode,
                Verdict::Deny,
                MatchKind::Malformed,
                4,
                [0u8; 16],
                [0u8; 16],
                0,
                0,
                L4Proto::Other,
            );
        }
    };

    // `meta.addr` is an enum carrying either a v4 or v6 address pair.
    // This `match` normalizes both cases into one common shape for the
    // rest of the function: a `family` tag (4 or 6) plus two 16-byte
    // arrays, with a v4 address's 4 bytes placed in the first 4 bytes of
    // the 16 (via `ip::expand4`, which just zero-pads the rest) -- purely
    // so `FlowEvent` (below) can have one fixed-size `saddr`/`daddr`
    // field shape regardless of IP version, rather than needing two
    // different event layouts.
    let (family, saddr, daddr): (u8, [u8; 16], [u8; 16]) = match meta.addr {
        FlowAddr::V4 { saddr, daddr } => (4, ip::expand4(saddr), ip::expand4(daddr)),
        FlowAddr::V6 { saddr, daddr } => (6, saddr, daddr),
    };

    // The actual allowlist decision: does the remote party's address
    // match an exact-IP or subnet rule for this direction? Everything
    // above this line was just parsing; this is the one line that
    // implements the filter's actual *policy*.
    let (verdict, match_kind) = check_ip_allow(direction, &meta, maps);

    // Build and emit the telemetry event, and translate the verdict into
    // the `i32` the kernel expects back, honoring monitor mode. This is
    // the last thing `evaluate` does on every "normal" path (the early
    // returns above for `NotIp`/`Unsupported`/`Malformed` each call
    // `finish` themselves and return directly).
    finish(
        direction,
        mode,
        verdict,
        match_kind,
        family,
        saddr,
        daddr,
        meta.sport,
        meta.dport,
        meta.l4_proto,
    )
}

// Checks the *remote party's* address (source on ingress, destination on
// egress -- that's what "remote party" means for a boundary filter: the
// other end of the connection, not this host) against the exact-IP map
// first, then the subnet trie, for whichever IP version the packet
// actually is. Returns as soon as either check matches; falls through to
// "deny, no match" if neither does.
fn check_ip_allow(direction: Direction, meta: &FlowMeta, maps: &AllowMaps) -> (Verdict, MatchKind) {
    // Branch on IP version once, then run the same two checks
    // (exact-match, then subnet) against whichever pair of maps applies.
    match meta.addr {
        FlowAddr::V4 { saddr, daddr } => {
            // On egress, the packet's *destination* is the remote party
            // (the host this box is connecting out to); on ingress, the
            // *source* is (the host that's connecting in). This one line
            // is the entire "which side is 'remote'" decision for the
            // whole filter.
            let addr = if direction == Direction::Egress {
                daddr
            } else {
                saddr
            };
            // `maps.ipv4.get(&addr)`: a BPF map lookup by exact key.
            // `unsafe` is required here because Aya's `HashMap::get` is
            // marked `unsafe` at the API level -- BPF map reads can, in
            // principle, race with a concurrent write from userspace
            // (the loader could be updating the map at the same instant
            // this packet is being evaluated), so the safety obligation
            // is "the caller accepts that the returned reference's
            // *pointee* may be concurrently mutated" -- reading a `u8`
            // value here is fine either way, since this code only checks
            // *whether* an entry exists (`.is_some()`), never inspects
            // the actual byte.
            if unsafe { maps.ipv4.get(&addr) }.is_some() {
                return (Verdict::Allow, MatchKind::ExactIp);
            }
            // No exact match -- try the subnet trie instead.
            // `Key::new(32, addr)` builds an LPM-trie lookup key meaning
            // "find the most specific stored prefix that contains this
            // full, 32-bit-specific address" (32 = "match all 32 bits",
            // i.e. treat `addr` as a single host, not itself a range).
            let key = Key::new(32, addr);
            if maps.subnets_v4.get(&key).is_some() {
                return (Verdict::Allow, MatchKind::Subnet);
            }
            // Neither check matched for v4; fall through to the shared
            // "deny" return at the bottom of the function.
        }
        // Exact mirror of the v4 arm above, just with 16-byte addresses
        // and a 128-bit (full IPv6 address) LPM lookup key.
        FlowAddr::V6 { saddr, daddr } => {
            let addr = if direction == Direction::Egress {
                daddr
            } else {
                saddr
            };
            if unsafe { maps.ipv6.get(&addr) }.is_some() {
                return (Verdict::Allow, MatchKind::ExactIp);
            }
            let key = Key::new(128, addr);
            if maps.subnets_v6.get(&key).is_some() {
                return (Verdict::Allow, MatchKind::Subnet);
            }
        }
    }
    // Reached only if neither the exact-IP nor the subnet check matched,
    // for whichever IP version the packet was. This is the allowlist's
    // default-deny behavior: anything not explicitly matched is denied,
    // not passed through.
    (Verdict::Deny, MatchKind::NoMatch)
}

// Reads the live `MODE` flag map (see `maps.rs`) and turns its raw `u8`
// into the `Mode` enum. Called once per packet, at the very start of
// `evaluate`, so a live toggle from userspace (writing a new value into
// `MODE[0]` without reloading the program) takes effect on the very next
// packet.
fn current_mode() -> Mode {
    // `MODE.get(0)`: read index 0 of the single-element `Array` map.
    // `.copied()` turns the `Option<&u8>` the map API returns into an
    // owned `Option<u8>` (arrays of `Copy` types like `u8` support this
    // directly). `.unwrap_or(0)` treats a missing/unreadable entry as
    // `0` -- which `Mode::from_u8` maps to `Enforce`, the safer default
    // if something ever goes wrong reading this map.
    let flag = MODE.get(0).copied().unwrap_or(0);
    Mode::from_u8(flag)
}

// This function takes a lot of individual scalar parameters instead of
// one struct because every call site (in `evaluate`, above) already has
// the pieces as separate local variables computed at different points --
// bundling them into a temporary struct just to unpack it again here
// wouldn't add clarity, just ceremony.
#[allow(clippy::too_many_arguments)]
// The single choke point every classification path funnels through:
// builds the structured telemetry event, pushes it into the ring buffer
// for userspace to pick up, and computes the actual `i32` this program
// hands back to the kernel -- the one place `mode` (enforce vs. monitor)
// actually changes behavior.
fn finish(
    direction: Direction,
    mode: Mode,
    verdict: Verdict,
    match_kind: MatchKind,
    family: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
    l4_proto: L4Proto,
) -> i32 {
    // Build the fixed-size, `Copy`/POD event record that gets copied
    // byte-for-byte into the ring buffer just below -- see
    // `linuxbpf-common::FlowEvent`'s own doc comment for why it has to be
    // shaped this way (no `String`s, no pointers, just plain fields).
    let event = FlowEvent {
        // Every enum field is stored as its `u8` discriminant (`as u8`),
        // since `FlowEvent` itself has to be a plain-old-data struct with
        // no enum types of its own -- the userspace side (`telemetry.rs`)
        // reconstructs the meaning from the raw byte.
        direction: direction as u8,
        verdict: verdict as u8,
        match_kind: match_kind as u8,
        l4_proto: l4_proto as u8,
        family,
        // Padding bytes purely for the struct's memory layout (keeping
        // later fields aligned); never read by anything.
        _pad: [0; 3],
        saddr,
        daddr,
        sport,
        dport,
        // `bpf_get_current_cgroup_id`: a kernel helper that returns the
        // cgroup ID of the process/socket this packet belongs to --
        // included in telemetry so an operator can tell *which* cgroup
        // (e.g. which container) a given verdict was about, on a host
        // running more than one. `unsafe` for the same reason as the
        // `bpf_skb_load_bytes` call in `reader.rs`: it's a raw call into
        // kernel-provided functionality that Rust's compiler can't check
        // on its own.
        cgroup_id: unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() },
        // Always 0 now that hostname matching isn't wired in (see this
        // file's top doc comment) -- kept as a field so `FlowEvent`'s
        // layout doesn't need to change if/when that feature comes back.
        hostname_hash: 0,
    };
    // Push `event` into the `EVENTS` ring buffer (declared in `maps.rs`)
    // for the userspace telemetry loop to read. `::<FlowEvent>` spells
    // out the type explicitly because `output` is generic and there's
    // nothing else at this call site for the compiler to infer it from.
    // The `Result` this returns (whether the ring buffer had space) is
    // deliberately ignored (`let _ =`): a dropped telemetry event isn't a
    // reason to fail the actual traffic decision below.
    let _ = EVENTS.output::<FlowEvent>(&event, 0);

    // This is the *only* place `mode` changes behavior: in `Enforce`
    // mode, the kernel gets the real computed verdict (so a `Deny`
    // actually drops the packet); in `Monitor` mode, the kernel always
    // gets `Allow`, regardless of what was actually decided -- the event
    // pushed above still carries the real `verdict`, so monitor mode logs
    // exactly what *would* have happened without ever dropping a packet.
    match mode {
        Mode::Enforce => verdict as i32,
        Mode::Monitor => Verdict::Allow as i32,
    }
}
