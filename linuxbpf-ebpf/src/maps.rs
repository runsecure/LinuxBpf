//! Map declarations shared by the ingress and egress programs.
//!
//! Addresses are always stored as raw, network-byte-order octets ([u8; 4] /
//! [u8; 16]) copied straight out of the packet -- never converted to a host
//! integer -- so there is exactly one representation to reason about on both
//! the kernel and userspace sides, which matters for a boundary-protection
//! allowlist where an endianness mix-up would silently widen what's allowed.
//!
//! There's no hostname/SNI map here (`*_HOSTS`, as an earlier version had):
//! hostname matching isn't currently wired into `filter.rs` -- see that
//! file's doc comment for why -- so there's nothing to populate one from.
//!
//! ## What a "BPF map" actually is
//!
//! A BPF map is a chunk of memory the kernel itself owns and manages --
//! not a normal Rust `HashMap`/array living on this program's own heap
//! (this program doesn't have a heap). It's created by a kernel syscall
//! before the program is even loaded, it persists independently of any
//! one program (the userspace loader in `linuxbpf/src/loader.rs` writes
//! into these same maps from a completely different process, using the
//! same syscall interface), and every read/write from inside the BPF
//! program below compiles down to a special "call this kernel helper
//! function" instruction, not a plain memory load/store. That's what lets
//! the *userspace* process configure the allowlist (by writing into these
//! maps) while the *kernel* program (compiled once, running for every
//! packet) only ever reads them.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LpmTrie, RingBuf},
};
use linuxbpf_common::{MAX_ENTRIES_IP, MAX_ENTRIES_SUBNET};

/// Single-element flag: 0 = Mode::Enforce, 1 = Mode::Monitor. Set by the
/// userspace loader before attach and can be flipped live afterwards.
// `#[map]`: this attribute is what actually turns the `static` below into
// a BPF map -- it tells the Aya build machinery to emit a special ELF
// section describing the map's type/key-size/value-size/entry-count, which
// `bpftool`/the kernel's loader reads at load time to create the real
// in-kernel map before this program's instructions ever run.
#[map]
// `Array<u8>`: the simplest BPF map kind -- a fixed-size array of values,
// indexed 0..max_entries by a plain integer (no hashing). One `u8` slot is
// enough for a flag. `with_max_entries(1, 0)` asks for exactly one slot;
// the second `0` is a flags bitmask the kernel's map-creation call
// accepts (no special flags needed here).
pub static MODE: Array<u8> = Array::with_max_entries(1, 0);

/// Structured verdict events consumed by the userspace telemetry agent.
#[map]
// `RingBuf`: a single, kernel-managed circular buffer that this program
// writes fixed- or variable-length records into (see `filter.rs`'s
// `EVENTS.output(...)` call) and that a userspace process (`linuxbpf`'s
// `telemetry.rs`) reads from concurrently, in order, without either side
// needing to poll a map by key. `with_byte_size(1 << 18, 0)` reserves
// 256 KiB (`1 << 18` = 2^18 bytes) of buffer space; `0` is again the
// creation-flags argument.
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

// The four maps below are declared once per direction (INGRESS_*/EGRESS_*)
// because the allowlists for inbound and outbound traffic are independent
// -- a host you're allowed to receive connections from isn't automatically
// one you're allowed to connect out to.

#[map]
// `HashMap<[u8; 4], u8>`: a key/value map keyed by a raw 4-byte IPv4
// address, hashed internally by the kernel for O(1)-ish lookup regardless
// of how many entries are loaded. The value type is `u8` and is never
// actually inspected -- the map is used purely as a set: `get(&addr)`
// returning `Some(_)` at all (any value) means "this address is
// allow-listed"; see `filter.rs`'s `check_ip_allow`.
pub static INGRESS_IPV4: HashMap<[u8; 4], u8> = HashMap::with_max_entries(MAX_ENTRIES_IP, 0);
#[map]
// Same idea, but keyed by a raw 16-byte IPv6 address instead of 4 bytes.
pub static INGRESS_IPV6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(MAX_ENTRIES_IP, 0);
#[map]
// `LpmTrie<[u8; 4], u8>`: a "longest prefix match" trie -- the map kind
// purpose-built for CIDR/subnet matching. Each key carries both a prefix
// length and the address bytes (see `filter.rs`'s `Key::new(32, addr)`
// for how a *lookup* key is built as "match this exact 32-bit address
// against whatever prefixes are stored"), and a `get()` finds the
// most-specific stored subnet that contains the looked-up address, if
// any -- exactly the semantics a subnet allowlist needs.
pub static INGRESS_SUBNETS_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_ENTRIES_SUBNET, 0);
#[map]
// IPv6 counterpart of the trie above (16-byte addresses, prefix length up
// to 128 instead of 32).
pub static INGRESS_SUBNETS_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_ENTRIES_SUBNET, 0);

// The egress side mirrors the ingress side exactly, map-kind for map-kind
// -- just a separate set of maps so the two directions' allowlists never
// share state.
#[map]
pub static EGRESS_IPV4: HashMap<[u8; 4], u8> = HashMap::with_max_entries(MAX_ENTRIES_IP, 0);
#[map]
pub static EGRESS_IPV6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(MAX_ENTRIES_IP, 0);
#[map]
pub static EGRESS_SUBNETS_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_ENTRIES_SUBNET, 0);
#[map]
pub static EGRESS_SUBNETS_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_ENTRIES_SUBNET, 0);
