//! Best-effort TLS ClientHello SNI extraction from a local, bounded buffer.
//!
//! Only matches a ClientHello that begins at offset 0 of the probed buffer
//! (i.e. the very first TLS record of the connection) and only when the
//! `server_name` extension itself falls within the probed window. A
//! resumed session (no ClientHello), a ClientHello split across multiple
//! TCP segments before the SNI extension, or QUIC/HTTP-3 (UDP) are not
//! matched here -- those flows fall back to IP/subnet allow rules.
//!
//! Every loop below is bounded by an explicit constant trip count in
//! addition to the natural data bound, independent of packet contents, so
//! the eBPF verifier can prove termination regardless of what's on the
//! wire. Pure byte-slice logic with no `aya_ebpf` dependency, so it's
//! exercised directly by the tests at the bottom of this file -- no BPF
//! target or kernel needed.
//!
//! This file walks a TLS 1.2/1.3 ClientHello by hand, byte offset by byte
//! offset, following the wire format defined in RFC 8446 section 4.1.2 (and
//! RFC 6066 section 3 for the `server_name` extension). There's no TLS
//! parsing library involved -- everything below is just careful indexing
//! into a `&[u8]`, because that's what's actually practical to compile down
//! to something the eBPF verifier will accept (see the doc comments further
//! down on exactly what shape of code that turned out to require).

use crate::PAYLOAD_PROBE_LEN;

// The outer "TLS record" header's first byte: `0x16` means "this record
// carries a handshake message" (as opposed to, say, `0x17` for
// already-encrypted application data). A ClientHello is always sent as a
// handshake record.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
// The first byte *inside* the handshake message (i.e. past the record
// header) that identifies which specific handshake message this is. `0x01`
// is ClientHello -- the only one this parser looks for.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
// Every TLS extension starts with a 2-byte type code; `0x0000` is the code
// assigned to the `server_name` extension (SNI) by RFC 6066.
const EXT_SERVER_NAME: u16 = 0x0000;
// Inside a `server_name` extension, each entry is tagged with a 1-byte
// "name type". `0` means "this is a DNS hostname" -- the only kind that
// exists in practice; other values are reserved for a future use that was
// never actually defined.
const SNI_HOST_NAME_TYPE: u8 = 0;
/// `server_name` is conventionally one of the first few extensions sent by
/// every major TLS client (OpenSSL, BoringSSL, NSS), so this doesn't need
/// to be large -- and the eBPF verifier's processed-instruction count
/// scales with it directly, so it shouldn't be either. See the comment on
/// `linuxbpf_common::PAYLOAD_PROBE_LEN` for what happens when these bounds
/// are too generous.
// This is the hard cap on how many extensions the loop in `extract_sni`
// below will ever look at before giving up -- a real ClientHello can carry
// more than 16, but if `server_name` isn't among the first 16, this parser
// treats it as not present rather than keep scanning indefinitely.
const MAX_EXTENSIONS: u32 = 16;

/// Sentinel `extract_sni_packed` return value meaning "no SNI found".
// `u64::MAX` (all 64 bits set) is used as an "impossible" packed value: a
// real `(start, len)` pair packed by `extract_sni_packed` below can never
// produce this exact bit pattern, since `buf` is always far shorter than
// `u32::MAX` bytes, so it's safe to reserve this one value to mean "there
// was no match" instead of building a separate `Option`-like wrapper.
pub const NOT_FOUND: u64 = u64::MAX;

/// ABI-safe wrapper around `extract_sni` for callers that need to cross a
/// real (non-inlined) function-call boundary -- notably the eBPF-side
/// hostname-matching code this was originally written for (since removed;
/// see `linuxbpf-ebpf/src/filter.rs`'s doc comment). eBPF only guarantees a
/// single 64-bit return register (R0); a "fat" `Option<&[u8]>` (a
/// pointer-plus-length, wrapped in a discriminant) doesn't fit that and
/// was observed to produce a verifier rejection ("R3 !read_ok") when
/// `extract_sni` itself was marked `#[inline(never)]` and called directly.
/// Packing `(start, len)` into one `u64` (high 32 bits = start, low 32 =
/// len; `buf` is at most `PAYLOAD_PROBE_LEN` bytes so both always fit)
/// sidesteps that entirely -- only this thin wrapper needs to be a real
/// call for the verifier's processed-instruction count to stay in check,
/// so `extract_sni` itself is free to inline normally (including into this
/// wrapper).
// `#[inline(never)]`: the opposite of most other functions in this
// codebase -- this one is deliberately kept as a real, separate function
// (not merged into its caller) specifically so it presents a small, fixed,
// plain-`u64` ABI at the one place a real call is unavoidable.
#[inline(never)]
pub fn extract_sni_packed(buf: &[u8]) -> u64 {
    match extract_sni(buf) {
        Some(hostname) => {
            // SAFETY: `hostname` is always derived as a sub-slice of `buf`
            // by every return path in `extract_sni`, so this offset is
            // within `buf` and the pointer subtraction is well-defined.
            //
            // `hostname.as_ptr()` and `buf.as_ptr()` are both raw memory
            // addresses; since `hostname` is a slice *of* `buf`, its start
            // address is always >= `buf`'s own start address, so
            // subtracting one `usize` address from the other yields the
            // hostname's byte offset within `buf` -- a plain, ordinary
            // arithmetic operation once expressed this way.
            let start = hostname.as_ptr() as usize - buf.as_ptr() as usize;
            // Pack `start` into the upper 32 bits and `hostname.len()`
            // into the lower 32 bits of one `u64`: shift `start` left by
            // 32 bits (moving it into the high half), then `|` (bitwise
            // OR) in the length, masked with `0xFFFF_FFFF` to guarantee
            // only its low 32 bits contribute (defensive, since
            // `hostname.len()` is already far smaller than that in
            // practice).
            ((start as u64) << 32) | (hostname.len() as u64 & 0xFFFF_FFFF)
        }
        None => NOT_FOUND,
    }
}

/// Returns the raw SNI hostname bytes (a sub-slice of `buf`) if `buf` starts
/// with a TLS ClientHello record carrying a `server_name` extension.
///
/// `#[inline(always)]`, forcing this to merge into its one real-call
/// caller, `extract_sni_packed`: LLVM's own size heuristics were observed
/// to keep a same-sized function as a separate (non-inlined) call anyway
/// despite no explicit `#[inline(never)]`, and a *real* call to a function
/// like this one -- taking `line_start`/`line_end`-style derived-range
/// arguments computed from a loop elsewhere in the same parse -- is
/// exactly the shape that blew the verifier's processed-instruction count
/// past 1,000,000 (`http::match_host_header` hit this first). Keeping the
/// whole parse as one function body means the verifier only ever has to
/// reason about it in the context it actually runs in, once.
#[inline(always)]
pub fn extract_sni(buf: &[u8]) -> Option<&[u8]> {
    // `buf.first()` returns `Option<&u8>` (`None` if `buf` is empty); `?`
    // propagates that `None` straight out of this function (as this
    // function's own `None`) rather than needing an explicit `match`.
    // Byte 0 of a TLS record is its content type -- must be
    // `handshake` (0x16) or this isn't a ClientHello at all.
    if *buf.first()? != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    // The record header is 5 bytes total: 1 (content type, just checked) +
    // 2 (protocol version) + 2 (record length). Byte 5 is therefore the
    // first byte of the handshake message itself -- its message type,
    // which must be ClientHello (0x01).
    if *buf.get(5)? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    // Handshake header (4 bytes: type + 3-byte length) + client_version (2)
    // + random (32) = 38 bytes past the 5-byte record header.
    // `pos` is the running "current offset into `buf`" cursor this whole
    // function advances as it walks through each ClientHello field in
    // order. `.checked_add` is used for every step (instead of plain `+`)
    // so a corrupt or adversarial length value earlier in the buffer can
    // never wrap `pos` around to a small, seemingly-in-bounds value --
    // overflow instead becomes `None`, propagated by `?`, which this
    // function treats the same as any other malformed input.
    let mut pos: usize = 5usize.checked_add(38)?;

    // The next field is a variable-length "session ID": one length byte,
    // followed by that many bytes of session ID data (usually empty for a
    // fresh connection). Read the length, then skip past both the length
    // byte itself and the session ID bytes it describes.
    let session_id_len = *buf.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(session_id_len)?;

    // Same pattern for "cipher suites": a 2-byte length (`u16`, so two
    // bytes read big-endian via `from_be_bytes`, matching TLS's own
    // network-byte-order convention), then that many bytes of cipher
    // suite codes.
    let cipher_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?.checked_add(cipher_len)?;

    // Same pattern again for "compression methods": a 1-byte length, then
    // that many bytes.
    let comp_len = *buf.get(pos)? as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;

    // Finally, the "extensions" block: a 2-byte total length, followed by
    // that many bytes containing every extension the client sent, one
    // after another. `pos` is advanced past just the length field here;
    // `ext_end` marks where the whole extensions block ends.
    let ext_total_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    // `core::cmp::min(..., buf.len())`: clamp the claimed extensions-block
    // end to what's actually present in `buf`, in case the ClientHello was
    // truncated (e.g. because only the first `PAYLOAD_PROBE_LEN` bytes of
    // the real packet were ever probed) or the length field is simply
    // wrong/hostile. Every later bounds check in this function is relative
    // to this already-clamped `ext_end`, not the raw claimed length.
    let ext_end = core::cmp::min(pos.checked_add(ext_total_len)?, buf.len());

    // Walk the extensions one at a time, each shaped as: 2-byte type +
    // 2-byte length + that many bytes of extension-specific data. `i` is a
    // plain loop-trip counter, capped at `MAX_EXTENSIONS` -- this is the
    // "explicit constant trip count" the file-level doc comment refers to:
    // it bounds how many times this loop can run independent of anything
    // in `buf`, which is what lets the eBPF verifier prove the loop always
    // terminates no matter what packet data drives it.
    let mut i = 0u32;
    while i < MAX_EXTENSIONS {
        // Need at least 4 more bytes (the type+length header of one
        // extension) before `ext_end` to have a complete extension left to
        // read; if not, there's nothing more to find.
        if pos.checked_add(4)? > ext_end {
            return None;
        }
        let ext_type = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        let ext_len = u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?]) as usize;
        let ext_data_start = pos.checked_add(4)?;
        if ext_type == EXT_SERVER_NAME {
            // Found it -- clamp this one extension's claimed end the same
            // way `ext_end` was clamped above, then hand off to the
            // dedicated parser below for the `server_name` extension's own
            // internal structure.
            let ext_data_end = core::cmp::min(ext_data_start.checked_add(ext_len)?, buf.len());
            return parse_server_name_extension(buf, ext_data_start, ext_data_end);
        }
        // Not the extension we want -- skip past its data (using the
        // *unclamped* `ext_data_start + ext_len`, since this is just
        // advancing the cursor to the next extension header, not reading
        // through this extension's bytes) and go around the loop again.
        pos = ext_data_start.checked_add(ext_len)?;
        i += 1;
    }
    // Looked at `MAX_EXTENSIONS` extensions without finding `server_name`.
    None
}

/// Parses a `server_name` extension occupying `buf[start..end]`.
///
/// Deliberately indexes `buf` directly at absolute offsets throughout,
/// rather than first deriving a `data = buf.get(start..end)` sub-slice and
/// indexing small offsets into *that* (as an earlier version did): the
/// eBPF verifier rejected that version with "invalid access to map value
/// ... R1 max value is outside of the allowed memory range" on a access
/// that was in fact safe -- it tracks each register's value range
/// independently and doesn't correlate a bounds check against a derived
/// sub-slice's own length with the original buffer's pointer range across
/// that extra level of derivation. Checking `offset >= end` immediately
/// before using that exact same `offset` to index `buf` keeps everything
/// the verifier needs to prove safety in one hop.
///
/// `#[inline(always)]`: see the comment on `extract_sni` for why.
///
/// Every offset computed below is checked against the literal
/// `PAYLOAD_PROBE_LEN` constant immediately before it's used to index
/// `buf`, *in addition to* the `end`-relative check that's already
/// logically sufficient (`end <= PAYLOAD_PROBE_LEN` always holds, since
/// callers derive it via `min(_, buf.len())`). This is deliberately
/// redundant: the eBPF verifier was observed to lose track of a value's
/// bound when it was only established relative to another *derived*
/// value (`end`) rather than a literal constant, at more than one offset
/// in this function as loop bounds elsewhere were tightened -- checking
/// against the literal directly, right at each use site, was what
/// actually resolved each occurrence.
#[inline(always)]
fn parse_server_name_extension(buf: &[u8], start: usize, end: usize) -> Option<&[u8]> {
    // Each offset gets its own *standalone* `if offset > PAYLOAD_PROBE_LEN`
    // check, immediately before that offset is used -- deliberately not
    // combined (via `||`) with the `> end` check, and with no early
    // "start/end are already in bounds" pre-check anywhere in this
    // function: combining them, or hoisting an equivalent fact earlier,
    // gave the optimizer enough to prove a later standalone check
    // redundant and elide it entirely (confirmed by it vanishing from the
    // compiled output), leaving the verifier with only the `> end` check,
    // which it can't correlate with the buffer's actual size on its own.
    // See the longer comment above this function.

    // The `server_name` extension's own internal layout (RFC 6066 §3):
    //   [0..2)  server_name_list length (a u16 -- not read by this parser,
    //           since only the first entry is ever supported in practice)
    //   [2]     name_type of the first entry (must be 0 = host_name)
    //   [3..5)  name_length (u16) of that entry
    //   [5..]   the hostname bytes themselves, `name_length` bytes long
    // `start` is where this extension's data begins within `buf`, so each
    // field above is `start` plus that field's offset within the
    // extension.

    // server_name_list length (2) + entry: name_type (1) + name_length (2) + name
    let name_type_off = start.checked_add(2)?;
    if name_type_off > PAYLOAD_PROBE_LEN {
        return None;
    }
    if name_type_off >= end {
        return None;
    }
    let name_type = *buf.get(name_type_off)?;
    if name_type != SNI_HOST_NAME_TYPE {
        return None;
    }

    let len_off = start.checked_add(3)?;
    if len_off > PAYLOAD_PROBE_LEN {
        return None;
    }
    let len_off_end = len_off.checked_add(2)?;
    if len_off_end > PAYLOAD_PROBE_LEN {
        return None;
    }
    if len_off_end > end {
        return None;
    }
    let name_len = u16::from_be_bytes([*buf.get(len_off)?, *buf.get(len_off + 1)?]) as usize;

    // The hostname bytes themselves start 5 bytes into the extension data
    // (2 for server_name_list length + 1 for name_type + 2 for
    // name_length, all accounted for above) and run for `name_len` bytes.
    let name_start = start.checked_add(5)?;
    if name_start > PAYLOAD_PROBE_LEN {
        return None;
    }
    let name_end = name_start.checked_add(name_len)?;
    if name_end > PAYLOAD_PROBE_LEN {
        return None;
    }
    if name_end > end {
        return None;
    }
    // Every bound above has now been checked, so this final slice is
    // guaranteed in range -- but `.get(...)` (returning `Option<&[u8]>`)
    // is still used rather than plain `buf[name_start..name_end]` indexing,
    // keeping this function panic-free by construction rather than relying
    // solely on the preceding checks being exhaustive.
    buf.get(name_start..name_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a wire-format TLS ClientHello record. `extensions` is a list
    /// of already-encoded `(type, data)` pairs; pass `sni` to additionally
    /// append a `server_name` extension for that hostname.
    // A hand-rolled encoder, the mirror image of the parser above: this
    // builds each ClientHello field in the same order `extract_sni` reads
    // them, byte for byte, so the tests below can construct precise,
    // realistic (or deliberately corrupted) input without needing a real
    // TLS client or network capture.
    fn build_client_hello(sni: Option<&str>, extra_extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(1); // compression_methods_len
        body.push(0); // null compression

        let mut extensions = Vec::new();
        for (ext_type, ext_data) in extra_extensions {
            extensions.extend_from_slice(&ext_type.to_be_bytes());
            extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(ext_data);
        }
        if let Some(host) = sni {
            let mut sni_ext = Vec::new();
            let name_entry_len = 1 + 2 + host.len();
            sni_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes()); // server_name_list len
            sni_ext.push(0); // name_type = host_name
            sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(host.as_bytes());

            extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_ext);
        }

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = body.len() as u32;
        handshake.extend_from_slice(&len.to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_a_well_formed_client_hello() {
        let record = build_client_hello(Some("example.com"), &[]);
        assert_eq!(extract_sni(&record), Some(&b"example.com"[..]));
    }

    #[test]
    fn extracts_sni_when_preceded_by_other_extensions() {
        let record =
            build_client_hello(Some("example.com"), &[(0x000a, &[0x00, 0x02, 0x00, 0x17])]);
        assert_eq!(extract_sni(&record), Some(&b"example.com"[..]));
    }

    #[test]
    fn no_sni_extension_present() {
        let record = build_client_hello(None, &[(0x000a, &[0x00, 0x02, 0x00, 0x17])]);
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn wrong_content_type_is_rejected() {
        let mut record = build_client_hello(Some("example.com"), &[]);
        record[0] = 0x17; // application_data, not handshake
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn wrong_handshake_type_is_rejected() {
        let mut record = build_client_hello(Some("example.com"), &[]);
        record[5] = 0x02; // server_hello, not client_hello
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn truncated_buffer_does_not_panic_and_returns_none() {
        let record = build_client_hello(Some("example.com"), &[]);
        for cut in [0, 1, 5, 6, 10, 40, 45, record.len() - 5, record.len() - 1] {
            assert_eq!(extract_sni(&record[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn sni_name_length_exceeding_buffer_does_not_panic() {
        let mut record = build_client_hello(Some("example.com"), &[]);
        // Corrupt the SNI name length (last 2 bytes before the hostname)
        // to claim a huge length.
        let host_start = record.len() - "example.com".len();
        record[host_start - 2] = 0xff;
        record[host_start - 1] = 0xff;
        assert_eq!(extract_sni(&record), None);
    }

    #[test]
    fn empty_buffer_does_not_panic() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn packed_encodes_start_and_len_of_a_found_sni() {
        let record = build_client_hello(Some("example.com"), &[]);
        let packed = extract_sni_packed(&record);
        assert_ne!(packed, NOT_FOUND);
        let start = (packed >> 32) as usize;
        let len = (packed & 0xFFFF_FFFF) as usize;
        assert_eq!(&record[start..start + len], b"example.com");
    }

    #[test]
    fn packed_is_not_found_sentinel_when_no_sni() {
        let record = build_client_hello(None, &[]);
        assert_eq!(extract_sni_packed(&record), NOT_FOUND);
    }
}
