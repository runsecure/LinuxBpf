// See ingress.rs for a detailed line-by-line walkthrough -- this file is
// the exact same shape, mirrored for the opposite direction.
use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};
use linuxbpf_common::Direction;

use crate::{
    filter::{self, AllowMaps},
    maps::{EGRESS_IPV4, EGRESS_IPV6, EGRESS_SUBNETS_V4, EGRESS_SUBNETS_V6},
    reader::SkbReader,
};

/// Attached as `BPF_CGROUP_INET_EGRESS`: evaluated for every packet a
/// socket inside the attached cgroup is about to send. The remote party is
/// the packet's destination address.
// Same macro, same underlying program *type* (`cgroup_skb`) as
// `ingress.rs` -- what makes this one run on outbound traffic instead is
// purely which `CgroupSkbAttachType` the userspace loader attaches it
// with.
#[cgroup_skb]
// Called once per outbound packet a socket in the attached cgroup sends.
// Returning `1` lets it go out; `0` silently drops it before it ever
// leaves the machine.
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    // This direction's allowlist maps, bundled the same way as in
    // ingress.rs.
    let maps = AllowMaps {
        ipv4: &EGRESS_IPV4,
        ipv6: &EGRESS_IPV6,
        subnets_v4: &EGRESS_SUBNETS_V4,
        subnets_v6: &EGRESS_SUBNETS_V6,
    };
    // Same testable-adapter wrapping as ingress.rs.
    let reader = SkbReader(&ctx);
    // Only real difference from ingress.rs: `Direction::Egress` here,
    // which tells `filter::evaluate` to check the packet's *destination*
    // address against the allowlist instead of its source.
    filter::evaluate(&reader, Direction::Egress, &maps)
}
