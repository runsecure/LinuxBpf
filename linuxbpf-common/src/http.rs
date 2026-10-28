//! Best-effort plaintext HTTP/1.x `Host:` header extraction from a local,
//! bounded buffer holding the start of a TCP payload (typically port 80).
//!
//! As with `tls::extract_sni`, only the request that begins at offset 0 of
//! the probed buffer is inspected. Every scan is bounded by an explicit
//! constant step count independent of packet contents -- but critically,
//! each bound here is sized for a *single line* (or a single header
//! value), not the whole buffer: the eBPF verifier's processed-instruction
//! count multiplies across nested loops, so bounding an inner loop by the
//! same generous constant as the outer one blows up combinatorially. An
//! earlier version of this file bounded `find_crlf` by the *entire*
//! `PAYLOAD_PROBE_LEN`-sized buffer and called it once per header line
//! (up to `MAX_HEADER_LINES` times), which alone was enough to make the
//! real kernel verifier hit its 1,000,000-instruction processing limit --
//! something neither `cargo build` nor `cargo check` catch, since neither
//! runs the verifier. Pure byte-slice logic with no `aya_ebpf` dependency,
//! exercised directly by the tests below.
//!
//! An HTTP/1.x request looks like:
//! ```text
//! GET /path HTTP/1.1\r\n
//! Host: example.com\r\n
//! User-Agent: ...\r\n
//! \r\n                    <- blank line ends the headers
//! ```
//! i.e. a request line, then zero or more `Name: value` header lines each
//! ending in `\r\n`, then a blank line. This file's job is just to find the
//! line starting with `Host:` (case-insensitively) and pull out its value,
//! without needing to understand any other header.

use crate::MAX_HOSTNAME_LEN;

/// Most real header lines are well under this; a line that isn't found
/// within it is treated as "can't parse, no match" (fails closed) rather
/// than growing the scan bound to cover pathological cases.
///
/// Kept deliberately tight, along with `MAX_HEADER_LINES` and
/// `HOST_VALUE_SCAN_CAP`: with `match_host_header` forced `#[inline(always)]`
/// into `extract_host` (needed so the verifier can correlate its
/// derived-range arguments -- see that function's doc comment), its
/// `MAX_LINE_LEN`/`HOST_VALUE_SCAN_CAP`-bounded scans get a *separate,
/// full copy verified* at every one of `extract_host`'s `MAX_HEADER_LINES`
/// call sites rather than being checked once as a real call. The product
/// of these three constants is what has to stay under the kernel
/// verifier's 1,000,000-processed-instruction budget once combined with
/// everything else on this path (IP/subnet map lookups, TLS's own
/// extension scan, hashing).
// Maximum bytes `find_crlf` will scan looking for one line's `\r\n`
// terminator.
const MAX_LINE_LEN: usize = 64;
// Maximum number of header lines `extract_host`'s outer loop will look at
// before giving up -- if `Host:` isn't among the first 4 lines, it's
// treated as absent.
const MAX_HEADER_LINES: u32 = 4;
// The literal bytes `match_host_header` compares a line's opening bytes
// against, always lowercase -- matching is done case-insensitively (see
// that function) by lowercasing each of the line's own bytes before
// comparing, not by varying this constant.
const HOST_PREFIX: &[u8] = b"host:";
/// Bounds the single merged scan in `match_host_header` (skip leading
/// spaces, then find ':' or end of value).
const HOST_VALUE_SCAN_CAP: usize = MAX_HOSTNAME_LEN + 8;

/// Sentinel `extract_host_packed` return value meaning "no Host header
/// found". See `tls::extract_sni_packed` for why this wrapper exists.
pub const NOT_FOUND: u64 = u64::MAX;

/// ABI-safe wrapper around `extract_host` -- see `tls::extract_sni_packed`
/// for the full explanation of why a "fat" `Option<&[u8]>` can't safely
/// cross a real (non-inlined) BPF-to-BPF call boundary.
#[inline(never)]
pub fn extract_host_packed(buf: &[u8]) -> u64 {
    match extract_host(buf) {
        Some(host) => {
            // SAFETY: `host` is always derived as a sub-slice of `buf` by
            // every return path in `extract_host`.
            // Same packed-(start, len)-into-one-u64 encoding as
            // `tls::extract_sni_packed` -- see that function's comments
            // for the full breakdown of this pointer arithmetic and bit
            // packing.
            let start = host.as_ptr() as usize - buf.as_ptr() as usize;
            ((start as u64) << 32) | (host.len() as u64 & 0xFFFF_FFFF)
        }
        None => NOT_FOUND,
    }
}

/// `#[inline(always)]`, forcing this (and everything it calls) to merge
/// into its one real-call caller, `extract_host_packed`: see the matching
/// comment on `tls::extract_sni` for why -- `match_host_header` (called
/// per header line, with derived `line_start`/`line_end` arguments) is
/// specifically what was observed to blow the verifier's
/// processed-instruction count past 1,000,000 when left as a separate
/// (non-inlined, but *not* explicitly `#[inline(never)]`) call.
#[inline(always)]
pub fn extract_host(buf: &[u8]) -> Option<&[u8]> {
    // Bail immediately if this doesn't even look like the start of an
    // HTTP request -- avoids scanning header-shaped lines in what's
    // actually, say, a TLS ClientHello or arbitrary binary payload.
    if !looks_like_request_line(buf) {
        return None;
    }

    // `pos` tracks the start of the current line being examined; `?` on
    // `find_crlf` below means "if no `\r\n` can be found within this
    // line's bound, give up entirely" (fail closed) rather than skip
    // ahead and keep guessing.
    let mut pos = 0usize;
    let mut line_idx = 0u32;
    while line_idx < MAX_HEADER_LINES {
        let line_end = find_crlf(buf, pos)?;
        if line_end == pos {
            // Blank line: end of headers reached without a Host header.
            return None;
        }
        if let Some(value) = match_host_header(buf, pos, line_end) {
            return Some(value);
        }
        // Advance `pos` past this line's own `\r\n` (2 bytes) to the start
        // of the next line, and try again.
        pos = line_end.checked_add(2)?;
        line_idx += 1;
    }
    None
}

// Cheap sanity check that `buf` starts with a recognized HTTP method
// followed by a space -- enough to distinguish "this is plausibly an HTTP
// request" from other protocols without needing to parse the whole
// request line.
#[inline(always)]
fn looks_like_request_line(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    let mut i = 0usize;
    while i < METHODS.len() {
        let m = METHODS[i];
        // `buf.get(..m.len())`: the leading `m.len()` bytes of `buf` (or
        // `None` if `buf` is shorter than that), compared directly against
        // the method's own bytes via slice equality.
        if buf.get(..m.len()) == Some(m) {
            return true;
        }
        i += 1;
    }
    false
}

/// Finds the next `\r\n` starting at `start`, scanning at most
/// `MAX_LINE_LEN` bytes -- a bound on *this one line*, not the buffer as a
/// whole, so the cost of `extract_host`'s outer per-line loop is
/// `MAX_HEADER_LINES * MAX_LINE_LEN`, not `MAX_HEADER_LINES *
/// PAYLOAD_PROBE_LEN`.
#[inline(always)]
fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut steps = 0usize;
    while steps < MAX_LINE_LEN {
        let a = *buf.get(i)?;
        // A CRLF is the two-byte sequence `\r` (0x0D) immediately followed
        // by `\n` (0x0A); checking the next byte via `buf.get(i + 1)`
        // rather than reading ahead unconditionally means this never reads
        // past what's actually in `buf`.
        if a == b'\r' && buf.get(i + 1) == Some(&b'\n') {
            return Some(i);
        }
        i = i.checked_add(1)?;
        steps += 1;
    }
    None
}

/// Matches the `Host:` header if `buf[line_start..line_end]` is one,
/// returning the (still-absolute-into-`buf`) value bytes.
///
/// Indexes `buf` directly at absolute offsets throughout, rather than
/// first deriving a `line = buf.get(line_start..line_end)` sub-slice and
/// indexing small offsets into *that* -- see the identical note on
/// `tls::parse_server_name_extension` for why: the eBPF verifier doesn't
/// correlate a bounds check against a derived sub-slice's own length with
/// the original buffer's pointer range across that extra level of
/// derivation, and rejects the resulting (in fact safe) access.
///
/// `#[inline(always)]`: see the comment on `extract_host` for why.
#[inline(always)]
fn match_host_header(buf: &[u8], line_start: usize, line_end: usize) -> Option<&[u8]> {
    // Too short to even contain "host:" -- can't be a match.
    if line_end.checked_sub(line_start)? < HOST_PREFIX.len() {
        return None;
    }
    // Compare this line's first `HOST_PREFIX.len()` bytes against
    // `HOST_PREFIX`, one byte at a time, case-insensitively: `c + 32`
    // converts an ASCII uppercase letter to its lowercase equivalent
    // (uppercase and lowercase ASCII letters are exactly 32 code points
    // apart, e.g. `'H'` is 0x48 and `'h'` is 0x68), so `"Host:"`, `"HOST:"`,
    // and `"host:"` all compare equal to the lowercase `HOST_PREFIX`
    // constant.
    let mut i = 0usize;
    while i < HOST_PREFIX.len() {
        let off = line_start.checked_add(i)?;
        let c = *buf.get(off)?;
        let lower = if c.is_ascii_uppercase() { c + 32 } else { c };
        if lower != HOST_PREFIX[i] {
            return None;
        }
        i += 1;
    }

    // Two separate, single-purpose loops -- each iteration of each one
    // makes exactly one comparison, rather than the 3-4-way match a single
    // merged pass needs (skip-spaces-or-find-colon-or-fall-through). An
    // earlier, "optimized" version merged these into one loop with a
    // `skipping_spaces` flag specifically to cut static instruction count,
    // but that added *branches per iteration*, which costs the verifier
    // far more (extra states to explore at every step) than the doubled
    // iteration count this version brings back costs it in raw
    // instructions -- empirically, the merged version was part of what
    // blew the verifier's processed-instruction count past 1,000,000.

    // First loop: starting right after "host:", skip over any spaces
    // (handles both `Host: example.com` and `Host:example.com`,
    // and even `Host:    example.com`).
    let mut start = line_start.checked_add(HOST_PREFIX.len())?;
    let mut steps = 0usize;
    while steps < HOST_VALUE_SCAN_CAP && buf.get(start) == Some(&b' ') {
        start = start.checked_add(1)?;
        steps += 1;
    }

    // Second loop: starting from wherever the value actually begins, scan
    // forward for a `:` (the start of a `:port` suffix, e.g.
    // `example.com:8080`) -- if found, the hostname value ends there
    // instead of at the line's own end, so a port suffix is never included
    // in the returned bytes. If no `:` turns up before `line_end` (or
    // before the scan cap), `end` stays at `line_end` and the whole rest
    // of the line is the value.
    let mut end = line_end;
    let mut j = start;
    steps = 0;
    while steps < HOST_VALUE_SCAN_CAP && j < line_end {
        if buf.get(j) == Some(&b':') {
            end = j;
            break;
        }
        j = j.checked_add(1)?;
        steps += 1;
    }

    buf.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(extract_host(req), Some(&b"example.com"[..]));
    }

    #[test]
    fn strips_port_suffix() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_host(req), Some(&b"example.com"[..]));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
        assert_eq!(extract_host(req), Some(&b"example.com"[..]));
    }

    #[test]
    fn skips_leading_space_after_colon() {
        let req = b"GET / HTTP/1.1\r\nHost:    example.com\r\n\r\n";
        assert_eq!(extract_host(req), Some(&b"example.com"[..]));
    }

    #[test]
    fn host_header_further_down_the_request_is_still_found() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\nUser-Agent: test\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_host(req), Some(&b"example.com"[..]));
    }

    #[test]
    fn missing_host_header_returns_none() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_host(req), None);
    }

    #[test]
    fn non_http_traffic_is_rejected() {
        let req = &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00][..];
        assert_eq!(extract_host(req), None);
    }

    #[test]
    fn host_header_beyond_max_lines_is_not_found() {
        let mut req = Vec::new();
        req.extend_from_slice(b"GET / HTTP/1.1\r\n");
        for i in 0..25 {
            req.extend_from_slice(format!("X-Filler-{i}: x\r\n").as_bytes());
        }
        req.extend_from_slice(b"Host: example.com\r\n\r\n");
        assert_eq!(extract_host(&req), None);
    }

    #[test]
    fn empty_buffer_does_not_panic() {
        assert_eq!(extract_host(&[]), None);
    }

    #[test]
    fn truncated_request_does_not_panic() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        for cut in 0..req.len() {
            let _ = extract_host(&req[..cut]);
        }
    }

    #[test]
    fn packed_encodes_start_and_len_of_a_found_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let packed = extract_host_packed(req);
        assert_ne!(packed, NOT_FOUND);
        let start = (packed >> 32) as usize;
        let len = (packed & 0xFFFF_FFFF) as usize;
        assert_eq!(&req[start..start + len], b"example.com");
    }

    #[test]
    fn packed_is_not_found_sentinel_when_no_host() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(extract_host_packed(req), NOT_FOUND);
    }

    #[test]
    fn line_longer_than_max_line_len_is_not_found() {
        // A header line that exceeds MAX_LINE_LEN can't have its CRLF
        // found at all -- extract_host should fail closed (None), not
        // panic or loop, and a later, findable Host header doesn't help.
        let mut req = Vec::new();
        req.extend_from_slice(b"GET / HTTP/1.1\r\n");
        req.extend_from_slice(&[b'X'; MAX_LINE_LEN + 32]);
        req.extend_from_slice(b"\r\nHost: example.com\r\n\r\n");
        assert_eq!(extract_host(&req), None);
    }
}
