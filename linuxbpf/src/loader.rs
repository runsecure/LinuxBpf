//! Populates the eBPF maps from a `ResolvedConfig` and attaches the
//! ingress/egress programs to a cgroup.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap, MapData};
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType};
use linuxbpf_common::Mode as KernelMode;
use linuxbpf_common::config::{ModeConfig, ResolvedDirection};

// Writes the single enforce-vs-monitor flag the kernel-side filter reads on
// every packet (`linuxbpf-ebpf/src/filter.rs`'s `current_mode`) into the
// `MODE` map declared in `linuxbpf-ebpf/src/maps.rs`.
pub fn set_mode(bpf: &mut Ebpf, mode: ModeConfig) -> Result<()> {
    // `bpf.map_mut("MODE")` looks the map up by the name it was declared
    // with in the eBPF source (`#[map] static MODE: Array<u8> = ...`) and
    // returns a generic, untyped handle to it; `Array::try_from(map)`
    // converts that into a concrete, typed `Array<&mut MapData, u8>`
    // wrapper this code can actually call `.set()` on. This two-step
    // lookup-then-cast is how every map access in this file works.
    let map = bpf
        .map_mut("MODE")
        .context("MODE map not found in object")?;
    let mut array: Array<&mut MapData, u8> = Array::try_from(map)?;
    // Convert the userspace-facing `ModeConfig` enum (parsed from the TOML
    // file, see `config.rs`) into the kernel-side `Mode` enum's raw `u8`
    // representation -- these are two *separate* types (one lives in this
    // crate's config-parsing code, the other in `linuxbpf-common` and is
    // shared with the eBPF build) that happen to mean the same thing, so
    // this match is the one place that translates between them.
    let value = match mode {
        ModeConfig::Enforce => KernelMode::Enforce as u8,
        ModeConfig::Monitor => KernelMode::Monitor as u8,
    };
    // `Array` maps are fixed-size and pre-indexed; index `0` is simply
    // "the only slot this map has" (it holds exactly one value). The
    // trailing `0` argument is a flags parameter Aya's map-write API
    // requires (mirroring the underlying `bpf()` syscall's own signature)
    // and is unused here -- `0` means "no special flags".
    array.set(0, value, 0).context("setting MODE[0]")?;
    Ok(())
}

/// `prefix` is `"INGRESS"` or `"EGRESS"`, matching the map names declared in
/// `linuxbpf-ebpf/src/maps.rs`.
// Writes every resolved IP/subnet allow-rule for one direction into that
// direction's four maps (`{prefix}_IPV4`, `{prefix}_IPV6`,
// `{prefix}_SUBNETS_V4`, `{prefix}_SUBNETS_V6`) -- called once for
// `"INGRESS"` and once for `"EGRESS"` from `main.rs`.
pub fn populate_direction(bpf: &mut Ebpf, prefix: &str, dir: &ResolvedDirection) -> Result<()> {
    // Each of the four blocks below is wrapped in its own `{ ... }` scope
    // purely so its local `map`/`m` variables go out of scope (and release
    // their borrow of `bpf`) before the next block needs to borrow `bpf`
    // again -- without that, the compiler would see multiple overlapping
    // mutable borrows of `bpf` in the same function and refuse to compile.
    {
        let map = bpf
            .map_mut(&format!("{prefix}_IPV4"))
            .with_context(|| format!("{prefix}_IPV4 map not found"))?;
        let mut m: HashMap<&mut MapData, [u8; 4], u8> = HashMap::try_from(map)?;
        // The map's value is always the literal byte `1` -- this map is
        // used purely as a *set* (as in, "is this key present at all?"),
        // so the value stored alongside each key carries no meaning of its
        // own; only its presence does.
        for addr in &dir.ipv4 {
            m.insert(addr, 1u8, 0)
                .with_context(|| format!("inserting {prefix}_IPV4 entry"))?;
        }
    }
    {
        let map = bpf
            .map_mut(&format!("{prefix}_IPV6"))
            .with_context(|| format!("{prefix}_IPV6 map not found"))?;
        let mut m: HashMap<&mut MapData, [u8; 16], u8> = HashMap::try_from(map)?;
        for addr in &dir.ipv6 {
            m.insert(addr, 1u8, 0)
                .with_context(|| format!("inserting {prefix}_IPV6 entry"))?;
        }
    }
    {
        let map = bpf
            .map_mut(&format!("{prefix}_SUBNETS_V4"))
            .with_context(|| format!("{prefix}_SUBNETS_V4 map not found"))?;
        let mut m: LpmTrie<&mut MapData, [u8; 4], u8> = LpmTrie::try_from(map)?;
        for (prefix_len, addr) in &dir.subnets_v4 {
            // An LPM (longest-prefix-match) trie's key isn't just the raw
            // address -- it's the address *paired with* how many of its
            // leading bits actually matter (the prefix length, e.g. `/8`
            // in `10.0.0.0/8`), which is exactly what lets a lookup for
            // some specific address later find the *most specific*
            // matching subnet rule rather than just any overlapping one.
            // `Key::new` builds that combined key type from the two pieces
            // `resolve_direction` (in `config.rs`) already separated out.
            let key = Key::new(*prefix_len, *addr);
            m.insert(&key, 1u8, 0)
                .with_context(|| format!("inserting {prefix}_SUBNETS_V4 entry"))?;
        }
    }
    {
        let map = bpf
            .map_mut(&format!("{prefix}_SUBNETS_V6"))
            .with_context(|| format!("{prefix}_SUBNETS_V6 map not found"))?;
        let mut m: LpmTrie<&mut MapData, [u8; 16], u8> = LpmTrie::try_from(map)?;
        for (prefix_len, addr) in &dir.subnets_v6 {
            let key = Key::new(*prefix_len, *addr);
            m.insert(&key, 1u8, 0)
                .with_context(|| format!("inserting {prefix}_SUBNETS_V6 entry"))?;
        }
    }
    Ok(())
}

// Loads both `cgroup_skb` programs into the kernel (passing them through
// the verifier) and attaches each to `cgroup_path` for its respective
// traffic direction.
pub fn attach_programs(bpf: &mut Ebpf, cgroup_path: &Path) -> Result<()> {
    // Attaching a `cgroup_skb` program is done against an open file
    // descriptor on the cgroup's directory (not just its path string) --
    // this is the one handle both the ingress and egress attach calls
    // below need, which is why it's duplicated (`try_clone`, further
    // down) rather than reopened: both attach calls consume the file
    // descriptor they're given.
    let cgroup = File::open(cgroup_path)
        .with_context(|| format!("opening cgroup directory {}", cgroup_path.display()))?;

    // `bpf.program_mut("cgroup_skb_ingress")` looks up the compiled
    // program by the Rust function name it was defined with in
    // `linuxbpf-ebpf/src/ingress.rs` (via its `#[cgroup_skb(...)]`
    // attribute); `.try_into()?` narrows Aya's generic `Program` enum down
    // to the specific `CgroupSkb` variant this code needs to call
    // `.load()`/`.attach()` on.
    let ingress: &mut CgroupSkb = bpf
        .program_mut("cgroup_skb_ingress")
        .context("cgroup_skb_ingress program not found in object")?
        .try_into()?;
    // `.load()` is the step that actually sends this program's
    // instructions to the kernel's verifier -- if the eBPF bytecode is
    // unsafe in any way the verifier can detect, this is where that
    // surfaces as an error, before any attempt is made to attach it to
    // real traffic.
    ingress.load().context("loading ingress program")?;
    // Duplicate the cgroup directory's file descriptor now, before the
    // ingress `.attach()` call below consumes the original `cgroup`
    // value -- the egress attach further down needs its own descriptor to
    // consume in turn.
    let cgroup_for_egress = cgroup
        .try_clone()
        .context("duplicating cgroup fd for egress attach")?;
    ingress
        .attach(
            cgroup,
            CgroupSkbAttachType::Ingress,
            CgroupAttachMode::Single,
        )
        .context("attaching ingress program to cgroup")?;

    let egress: &mut CgroupSkb = bpf
        .program_mut("cgroup_skb_egress")
        .context("cgroup_skb_egress program not found in object")?
        .try_into()?;
    egress.load().context("loading egress program")?;
    egress
        .attach(
            cgroup_for_egress,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::Single,
        )
        .context("attaching egress program to cgroup")?;

    Ok(())
}
