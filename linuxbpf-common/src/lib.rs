// `no_std` only for the real (no-std BPF target) build. Under `cargo test`
// we compile as an ordinary std crate so the parsers below get a real host
// test harness instead of needing a kernel to exercise them; under the
// `user` feature (the userspace `linuxbpf` binary) std is available too --
// that build is always a normal hosted target, and `config` (below) needs
// `String`/`Vec`/`std::fs` regardless.
//
// `cfg_attr(COND, no_std)` means "apply `#![no_std]` only if COND is
// true". `not(any(test, feature = "user"))` reads as "neither building
// tests nor the `user` feature is on" -- i.e. this crate is `no_std` in
// exactly one situation: compiled as part of the real kernel-side BPF
// object, which is neither of those.
#![cfg_attr(not(any(test, feature = "user")), no_std)]
//! Types shared between the `linuxbpf-ebpf` kernel-side programs and the
//! `linuxbpf` userspace loader/telemetry agent. Kept `no_std` so it can be
//! linked into the eBPF object; the userspace crate pulls in the `user`
//! feature for the `aya::Pod` map-key/value impls and the `config` parser.
//!
//! `http`, `tls`, and `ip` hold the packet-parsing logic that used to live
//! in `linuxbpf-ebpf` directly. They're pure functions over byte slices (or
//! generic over the `reader::PacketReader` trait rather than a concrete
//! `aya_ebpf` context type), which is what lets them have real `#[test]`
//! unit tests that run natively -- no BPF target, kernel, or `bpftool`
//! needed. `config` and `cgroup` hold the userspace-only TOML/CIDR and
//! `/proc/mounts` parsing logic, for the same reason.

// `pub mod X;` declares each sibling file (`cgroup.rs`, `http.rs`, etc.)
// as a public submodule of this crate, so other crates can reach into
// them as `linuxbpf_common::cgroup::...`, `linuxbpf_common::ip::...`, etc.
pub mod cgroup;
// `config` is the one submodule that's *conditionally* compiled: only
// when running this crate's own tests, or when a downstream crate opts
// into the `user` feature (see this crate's `Cargo.toml`). It needs
// `String`/`Vec`/`serde`/`toml`, none of which are available in the real
// `no_std` eBPF build, so it must never be compiled into that target.
#[cfg(any(test, feature = "user"))]
pub mod config;
pub mod http;
pub mod ip;
pub mod reader;
pub mod tls;

/// Maximum hostname length considered for SNI / HTTP Host allowlist matching.
/// Longer names are truncated before hashing, which only widens what a
/// hostname can collide with -- it never permits something the operator
/// didn't ask to allow to be denied instead, so truncation fails closed.
///
/// Deliberately small: every one of `tls`/`http`'s bounded scan loops is
/// sized off this (directly or via `PAYLOAD_PROBE_LEN`), and the eBPF
/// verifier processes a bound *multiplicatively* across nested loops, not
/// just additively across static code size -- an earlier, more generous
/// value here (128) combined with `PAYLOAD_PROBE_LEN` (384) blew well past
/// the kernel's 1,000,000-instruction verifier limit once actually loaded
/// against a real kernel (`BPF program is too large. Processed 1000001
/// insn`), despite type-checking and `cargo build`-ing fine -- neither of
/// which run the verifier. Real hostnames essentially never exceed this.
// A `pub const` is just a compile-time-known value, substituted directly
// wherever it's used -- there's no "variable in memory" for it at
// runtime, in either the kernel or userspace build.
pub const MAX_HOSTNAME_LEN: usize = 64;

/// How many bytes of the first data-carrying segment of a flow are copied
/// into a local buffer for TLS ClientHello / HTTP request-line inspection.
/// Large ClientHellos (many extensions, ECH, etc.) that don't fit are simply
/// not hostname-matched on that packet -- IP/subnet allow rules still apply,
/// and a later packet may still get flow-cached once the app-layer handshake
/// completes and the connection is otherwise allowed. See `MAX_HOSTNAME_LEN`
/// above on why this is kept small rather than generous.
pub const PAYLOAD_PROBE_LEN: usize = 192;

// These four constants size the BPF maps declared in
// `linuxbpf-ebpf/src/maps.rs` (`with_max_entries(MAX_ENTRIES_IP, ...)`
// etc.) -- how many *entries* (not bytes) each map can hold before
// further inserts fail. Kept here, alongside the map *key/value* types
// they go with, so both the kernel-side map declarations and the
// userspace loader (which checks these same limits aren't exceeded when
// populating them) stay in sync automatically.
pub const MAX_ENTRIES_IP: u32 = 4096;
pub const MAX_ENTRIES_SUBNET: u32 = 1024;
/// Sizing for a hostname-allowlist map and a per-flow verdict cache that
/// `linuxbpf-ebpf` doesn't currently declare -- hostname/SNI matching is
/// implemented (`tls`, `http`, `normalize_hostname_hash`) but not wired
/// into the active filter; see `linuxbpf-ebpf/src/filter.rs`'s doc comment
/// and the project README's "Hostname/URL matching" section for why. Kept
/// here, unused, so re-enabling that feature doesn't need to re-derive
/// these.
pub const MAX_ENTRIES_HOST: u32 = 2048;
pub const MAX_ENTRIES_FLOW_CACHE: u32 = 8192;

/// Traffic direction relative to the cgroup the program is attached to.
// `#[repr(u8)]`: forces this enum's in-memory representation to be
// exactly one byte, with each variant's value being whatever integer is
// written after `=` below (`Ingress` is byte `0`, `Egress` is byte `1`).
// Ordinary Rust enums don't guarantee any particular layout; this
// attribute is what makes `Direction as u8` (used throughout this
// codebase) a well-defined, stable conversion -- essential since this
// exact byte value is what gets written into `FlowEvent` (below) and read
// back by a *different* program (the userspace telemetry code) that
// wasn't compiled from the same source at the same time.
#[repr(u8)]
// `Copy, Clone`: this type is small and trivial to duplicate, so it
// behaves like a primitive (assigning/passing it copies the value,
// there's no ownership to "move"). `Debug`: lets it be printed with
// `{:?}` (used by `tracing::info!(... mode = ?cfg.mode ...)` in the
// userspace code). `PartialEq, Eq`: lets it be compared with `==` (used
// by `filter.rs`'s `direction == Direction::Egress` check).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Ingress = 0,
    Egress = 1,
}

/// Final verdict for a packet.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Deny = 0,
    Allow = 1,
}

/// Which allowlist rule (if any) produced the verdict, for telemetry.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// No rule matched; verdict is the allowlist default (deny).
    NoMatch = 0,
    ExactIp = 1,
    Subnet = 2,
    // The next two variants (`Hostname`, `FlowCache`) are currently never
    // produced by `linuxbpf-ebpf` -- see `MAX_ENTRIES_HOST`'s comment
    // above -- but are kept in the enum so `FlowEvent`'s `match_kind`
    // byte values don't shift if/when hostname matching comes back.
    Hostname = 3,
    /// A prior packet on this 4-tuple was allowed via `Hostname`; this
    /// packet is riding on that cached flow verdict.
    FlowCache = 4,
    /// Packet was too short / malformed to classify past L3+L4 headers.
    Malformed = 5,
    /// Not IPv4/IPv6, or not TCP/UDP -- passed through unclassified.
    Unsupported = 6,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum L4Proto {
    Other = 0,
    Tcp = 1,
    Udp = 2,
}

/// Runtime enforcement mode, toggled via the `MODE` array map without
/// reloading the programs.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Denied packets are actually dropped.
    Enforce = 0,
    /// Verdicts are computed and logged as usual, but the programs always
    /// return "allow" -- lets an operator validate allowlist coverage
    /// against real traffic before cutting over to enforcement.
    Monitor = 1,
}

impl Mode {
    // Converts the raw byte read out of the `MODE` BPF map back into this
    // enum. Deliberately *not* a `TryFrom`/fallible conversion: any value
    // other than exactly `1` (including a map that was never initialized,
    // reading back `0`) falls through to `Enforce`, the fail-safe default
    // for a boundary-protection tool -- an unexpected byte should never
    // accidentally put the filter into "log only, drop nothing" mode.
    pub fn from_u8(v: u8) -> Mode {
        match v {
            1 => Mode::Monitor,
            _ => Mode::Enforce,
        }
    }
}

/// A single verdict event pushed to the `EVENTS` ring buffer. Sized to be
/// `Copy`/POD so it can be written directly into the ring buffer with no
/// serialization step.
// `#[repr(C)]`: lays this struct's fields out in memory in exactly the
// order they're written below, using C's normal alignment rules -- no
// field reordering for space-saving, which plain Rust structs are
// otherwise free to do. This matters here for the same reason `Direction`
// needed `#[repr(u8)]`: the kernel-side code writes this struct's raw
// bytes into a ring buffer, and the userspace side (`telemetry.rs`) reads
// those same raw bytes back and reinterprets them as a `FlowEvent` -- both
// sides have to agree on the exact byte layout, which only `#[repr(C)]`
// guarantees.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FlowEvent {
    pub direction: u8,  // Direction
    pub verdict: u8,    // Verdict
    pub match_kind: u8, // MatchKind
    pub l4_proto: u8,   // L4Proto
    pub family: u8,     // 4 or 6
    // Explicit padding bytes: without them, the compiler might still add
    // invisible padding here anyway (to align the `u16`/`u64` fields that
    // follow to their natural boundaries), but leaving it implicit would
    // make the struct's exact size less obvious at a glance, and an
    // implicit-padding byte's *contents* are technically unspecified --
    // writing it out explicitly as zeroed bytes keeps the struct's memory
    // fully defined, which matters for anything that hashes or compares
    // its raw bytes.
    pub _pad: [u8; 3],
    /// IPv4 addresses are stored in the first 4 bytes, network byte order.
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub cgroup_id: u64,
    /// FNV-1a hash of the matched/observed hostname, 0 if none was parsed.
    pub hostname_hash: u64,
}

// `#[cfg(feature = "user")]`: this trait implementation is only compiled
// for the userspace build.
#[cfg(feature = "user")]
// `aya::Pod` ("Plain Old Data") is a marker trait Aya's userspace map
// wrappers require of any type used as a map key or value -- it's the
// userspace-side promise "this type's bytes can be safely copied in and
// out of a kernel map with no pointers, no padding surprises, no invalid
// bit patterns". `unsafe impl` is required because the compiler can't
// verify that promise on its own; writing it here is this code accepting
// responsibility for `FlowEvent` actually satisfying it (which it does,
// by being `#[repr(C)]` and built entirely out of plain integers/arrays).
unsafe impl aya::Pod for FlowEvent {}

/// Key for the per-flow allow cache: a classic 4-tuple + protocol + family.
// Currently unused (see `MAX_ENTRIES_FLOW_CACHE`'s comment above) but kept
// for the same "ready for when hostname matching returns" reason.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlowKey {
    pub l4_proto: u8,
    pub family: u8,
    pub _pad: [u8; 2],
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

/// FNV-1a, used both in the kernel programs (hashing a parsed SNI/Host
/// value) and in userspace (hashing configured allowlist hostnames at load
/// time) so the two sides agree on map keys without ever exchanging raw
/// strings through a BPF map.
///
/// `#[inline(always)]` (forced, not just permitted): this and
/// `normalize_hostname_hash` are called with a slice that's itself derived
/// from an already-derived slice (`probe.get(start..end)`, where `probe`
/// is itself `buf.get(..n)`), and passing such a doubly-derived slice as
/// an *argument* across a real (non-inlined) BPF-to-BPF call was observed
/// to produce a verifier rejection ("invalid access to map value ... max
/// value is outside of the allowed memory range") on an access that was in
/// fact safe -- the verifier doesn't reliably carry a derived slice's
/// validated length across that boundary. Merely *not* marking these
/// `#[inline(never)]` wasn't enough to prevent that: LLVM's own size
/// heuristics kept `normalize_hostname_hash` as a separate call anyway
/// (visible as its own frame in the verifier trace) until it was forced
/// with `#[inline(always)]`. Only the eBPF-side caller that derived and
/// used these values in one place (since removed along with the rest of
/// hostname matching -- see `linuxbpf-ebpf/src/filter.rs`'s doc comment)
/// and the `tls`/`http` `_packed` wrappers (whose only argument, `probe`,
/// is a single-derived slice of a fixed-size array, and which return a
/// plain `u64`) were real calls along this path.
#[inline(always)]
// `const fn`: this function *can* be evaluated entirely at compile time if
// every argument is itself a compile-time constant (it isn't here, in
// practice -- `bytes` is always a runtime-derived slice -- but the
// `const` qualifier costs nothing and keeps the option open, e.g. for a
// future test that wants to hash a string literal at compile time).
pub const fn fnv1a_hash(bytes: &[u8]) -> u64 {
    // The FNV-1a "offset basis": a fixed, algorithm-defined starting
    // value, not something derived from the input.
    let mut hash: u64 = 0xcbf29ce484222325;
    // Manual indexing loop rather than `bytes.iter()` -- both compile to
    // the same thing here, but this style (a plain counter, checked
    // against `.len()`) is used consistently throughout this codebase's
    // eBPF-facing parsing code (see `ip.rs`, `tls.rs`, `http.rs`) since it
    // makes each loop's bound trivially visible to a reader (and, more
    // importantly, to the kernel's verifier -- see those files' own
    // comments on *why* loop shape matters there). This particular
    // function doesn't actually run inside the kernel anymore (hostname
    // matching is disabled), but its style still matches its siblings.
    let mut i = 0;
    while i < bytes.len() {
        // The FNV-1a step: XOR the next byte into the hash, then multiply
        // by a fixed prime. `wrapping_mul` performs the multiplication
        // with silent 64-bit overflow wraparound (the normal `*` operator
        // would panic -- or, in a release build, still wrap, but
        // *unsafely* rely on that -- on overflow); wraparound here isn't
        // a bug, it's how the algorithm is defined to behave.
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}

/// Lowercases ASCII, strips a single trailing '.', truncates to
/// `MAX_HOSTNAME_LEN`, and hashes the result. Used identically on both
/// sides so a configured `example.com` and an observed `Example.com.`
/// hash the same way.
///
/// Folds case directly into the FNV-1a accumulation (rather than writing
/// the folded bytes into an intermediate stack array and calling
/// `fnv1a_hash` on that, as an earlier version did) specifically so the
/// loop only ever touches registers and one fixed stack slot (`hash`),
/// never a stack array at a *data-dependent* index. The eBPF verifier was
/// observed to blow past its 1,000,000-instruction processing limit on
/// exactly that array-write pattern -- `total_states`/`peak_states` in the
/// verifier's own output barely changed even after cutting every relevant
/// loop bound elsewhere by 2-4x, which pointed at this loop itself (a
/// symbolic stack write per iteration is one of the more expensive shapes
/// for the verifier's state tracking) rather than at raw iteration count.
///
/// Also `#[inline(always)]` -- see the comment on `fnv1a_hash` just above
/// for why.
#[inline(always)]
pub fn normalize_hostname_hash(raw: &[u8]) -> u64 {
    // Start by assuming the whole input counts...
    let mut len = raw.len();
    if len > 0 {
        // ...then check just the last byte: if the hostname was written
        // with a trailing dot (a valid, if unusual, way to spell a fully
        // qualified domain name, e.g. `example.com.`), drop it from
        // consideration so `example.com` and `example.com.` hash
        // identically. `raw.get(len - 1)` is a bounds-checked read (never
        // panics even if, hypothetically, `len` were wrong) that returns
        // `Option<&u8>`; `.copied()` turns that into `Option<u8>` so it
        // can be matched against the byte literal `b'.'` directly.
        if let Some(b'.') = raw.get(len - 1).copied() {
            len -= 1;
        }
    }
    // Second, independent clamp: never consider more than
    // `MAX_HOSTNAME_LEN` bytes, regardless of how long the real input is
    // (see that constant's own doc comment for why it's kept small).
    if len > MAX_HOSTNAME_LEN {
        len = MAX_HOSTNAME_LEN;
    }

    // From here down, this is `fnv1a_hash`'s loop again, but fused with
    // ASCII case-folding so there's no intermediate buffer -- see the
    // doc comment above for why that fusion specifically matters here.
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut i = 0usize;
    while i < len {
        // `raw.get(i)` (bounds-checked) rather than `raw[i]` (which would
        // panic on an out-of-bounds index): `i` is always `< len <=
        // raw.len()` here by construction, so this can never actually
        // fail, but using `.get()` throughout this codebase's
        // packet-parsing code is a deliberate, consistent habit -- see
        // `tls.rs`/`http.rs` for where it genuinely does matter.
        if let Some(&b) = raw.get(i) {
            // ASCII-only case folding: if this byte is an uppercase
            // letter (`b.is_ascii_uppercase()`), add 32 to get its
            // lowercase equivalent (that's the fixed distance between
            // corresponding upper/lowercase ASCII letters, e.g. `'A'`
            // is 65, `'a'` is 97); otherwise use the byte unchanged.
            // Non-ASCII bytes (any byte >= 128) are left exactly as they
            // are -- hostnames are expected to be ASCII (or
            // Punycode-encoded ASCII, for internationalized names), so
            // there's nothing meaningful to "case-fold" beyond this.
            let lower = if b.is_ascii_uppercase() { b + 32 } else { b };
            hash ^= lower as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        i += 1;
    }
    hash
}

// Everything below only exists when this crate is compiled for its own
// tests (`cargo test -p linuxbpf-common`) -- it's entirely absent from
// both the real kernel build and the userspace build.
#[cfg(test)]
mod tests {
    // Brings everything from the enclosing module (`fnv1a_hash`,
    // `normalize_hostname_hash`, `MAX_HOSTNAME_LEN`, etc.) into scope for
    // the tests below, so they don't need a `super::` prefix on each use.
    use super::*;

    #[test]
    fn hash_is_stable_for_identical_input() {
        assert_eq!(
            normalize_hostname_hash(b"example.com"),
            normalize_hostname_hash(b"example.com")
        );
    }

    #[test]
    fn hash_is_case_insensitive() {
        assert_eq!(
            normalize_hostname_hash(b"Example.COM"),
            normalize_hostname_hash(b"example.com")
        );
    }

    #[test]
    fn hash_ignores_one_trailing_dot() {
        assert_eq!(
            normalize_hostname_hash(b"example.com."),
            normalize_hostname_hash(b"example.com")
        );
    }

    #[test]
    fn hash_does_not_strip_interior_dots() {
        assert_ne!(
            normalize_hostname_hash(b"www.example.com"),
            normalize_hostname_hash(b"example.com")
        );
    }

    #[test]
    fn hash_truncates_overlong_hostnames_consistently() {
        let long_a = [b'a'; MAX_HOSTNAME_LEN + 50];
        let long_b_prefix = [b'a'; MAX_HOSTNAME_LEN];
        // Two inputs that agree on the first MAX_HOSTNAME_LEN bytes but
        // differ after that must hash the same, since both get truncated
        // to the same prefix before hashing.
        assert_eq!(
            normalize_hostname_hash(&long_a),
            normalize_hostname_hash(&long_b_prefix)
        );
    }

    #[test]
    fn distinct_hostnames_hash_differently() {
        assert_ne!(
            normalize_hostname_hash(b"api.github.com"),
            normalize_hostname_hash(b"registry.npmjs.org")
        );
    }
}
