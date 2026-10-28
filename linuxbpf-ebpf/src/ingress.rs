// Aya's proc-macros: `#[cgroup_skb]` (used below) is what turns a plain
// Rust function into a loadable BPF program; `SkBuffContext` is the typed
// wrapper around the raw kernel packet-context pointer the function
// receives.
use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};
// `Direction` is a tiny shared enum (Ingress/Egress) so `filter::evaluate`
// (used by both this file and `egress.rs`) knows which side of the flow
// -- source or destination -- represents "the remote party" for the
// allowlist check.
use linuxbpf_common::Direction;

use crate::{
    filter::{self, AllowMaps},
    maps::{INGRESS_IPV4, INGRESS_IPV6, INGRESS_SUBNETS_V4, INGRESS_SUBNETS_V6},
    reader::SkbReader,
};

/// Attached as `BPF_CGROUP_INET_INGRESS`: evaluated for every packet
/// arriving at a socket inside the attached cgroup. The remote party is
/// the packet's source address.
// `#[cgroup_skb]`: marks this function as a `cgroup_skb`-type BPF
// program. Aya's macro rewrites it behind the scenes into the exact shape
// the kernel's loader expects (a specific ELF section name, a specific
// calling convention taking a raw `*mut __sk_buff` and returning `i32`) --
// none of that plumbing is visible here. Which *attach type* this becomes
// (ingress vs. egress) isn't decided by the macro at all; it's decided at
// *attach* time, in userspace (`linuxbpf/src/loader.rs`'s
// `CgroupSkbAttachType::Ingress` call) -- the same macro is used in
// `egress.rs` too.
#[cgroup_skb]
// The kernel calls this function once for every packet that matches the
// attach point -- here, every packet arriving at any socket inside the
// cgroup this program ends up attached to. `ctx` is this program's only
// input: a handle to the specific packet currently being evaluated.
// Returning `1` tells the kernel to let the packet through; returning `0`
// tells it to silently drop the packet. There is no other way for a
// `cgroup_skb` program to communicate a result back to the kernel.
pub fn cgroup_skb_ingress(ctx: SkBuffContext) -> i32 {
    // Bundle references to this direction's four allowlist maps (declared
    // in `maps.rs`) into one small struct, so the shared `filter::evaluate`
    // function doesn't need to know the maps' *names* -- just that it was
    // handed "the ingress set" vs. "the egress set". Each field is a
    // `&'static` reference to the map `static` itself; no copying of map
    // contents happens here.
    let maps = AllowMaps {
        ipv4: &INGRESS_IPV4,
        ipv6: &INGRESS_IPV6,
        subnets_v4: &INGRESS_SUBNETS_V4,
        subnets_v6: &INGRESS_SUBNETS_V6,
    };
    // Wrap the raw `ctx` in the small adapter type (`reader.rs`) that
    // implements the `PacketReader` trait `filter::evaluate` is written
    // against, rather than being written directly against
    // `SkBuffContext`. This indirection is what lets the exact same
    // parsing/decision code also run as an ordinary native unit test (see
    // `linuxbpf-common`'s tests), against a fake in-memory reader instead
    // of a real kernel packet.
    let reader = SkbReader(&ctx);
    // Do the actual work in the shared function, telling it this is the
    // *ingress* direction, and hand its `i32` return value straight back
    // to the kernel as this program's own return value -- no `return`
    // keyword needed since it's the last expression in the function.
    filter::evaluate(&reader, Direction::Ingress, &maps)
}
