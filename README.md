# linuxbpf

An eBPF `cgroup_skb` boundary-protection filter, built with [Aya][aya]. It
attaches separately to ingress and egress on a cgroup v2 hierarchy and
enforces an allowlist of IPs and subnets loaded from a TOML config.
Verdicts are streamed out of the kernel via a ring buffer and logged with
`tracing` -- `warn` for rejections, `info` for allows -- to the systemd
journal (or stderr as a fallback).

This has been built and verified end-to-end against a real kernel (see
"Docker" below): loaded, attached via `bpftool`, and exercised with live
traffic -- allowed destinations connect normally, denied ones time out, and
every verdict is logged correctly.

[aya]: https://aya-rs.dev

## Layout

- `linuxbpf-ebpf/` -- the kernel-side `cgroup_skb` programs (`no_std`,
  compiled to a BPF object). `ingress.rs`/`egress.rs` are thin entry points;
  `filter.rs` holds the map-lookup/verdict logic; `reader.rs` adapts a real
  `SkBuffContext` to the `PacketReader` trait from `linuxbpf-common`.
- `linuxbpf-common/` -- types shared by both sides (event/flow-key structs),
  so the kernel and userspace agree on map layout without duplicating
  definitions. Also holds `ip` (L3/L4 header parsing, unconditional) and
  `cgroup` (`/proc/mounts` parsing, unconditional -- it needs only `core`,
  not `std`). `config` (the TOML/CIDR parser) is gated behind the `user`
  feature (or just `cfg(test)`), since it needs `String`/`Vec`/`serde`/
  `toml`, none of which the real `no_std` eBPF build can use. All of it is
  written as pure functions -- over byte slices, strings, or generic over
  the `reader::PacketReader` trait instead of a concrete `aya_ebpf`/`aya`
  type -- specifically so it can have real `#[test]`s that run natively,
  with no filesystem/kernel/BPF access. See "Testing" below. It also still
  holds `tls`/`http` (SNI / HTTP Host parsing) and `normalize_hostname_hash`,
  fully implemented and unit-tested, but **not currently called from
  `linuxbpf-ebpf`** -- see the next section.
- `linuxbpf/` -- the userspace loader: reads the config file and calls
  `linuxbpf_common::config::parse`, populates the maps, attaches the
  programs to a cgroup, and runs the telemetry event loop. `cgroup.rs`
  similarly just reads `/proc/mounts` and calls
  `linuxbpf_common::cgroup::find_cgroup2_mount`.

## How the allowlist is enforced

Both directions apply the same precedence, checked in order, first match
wins:

1. **Exact IP** -- the remote address (source on ingress, destination on
   egress) matches an `[[*.ip]]` entry.
2. **Subnet** -- the remote address falls in an `[[*.subnet]]` CIDR, via an
   LPM trie.

If neither matches, the packet is denied. In `mode = "monitor"` the verdict
is still computed and logged, but the program always returns "allow" to the
kernel -- use this to validate a candidate allowlist against real traffic
before switching to `mode = "enforce"`.

### Hostname/URL (`[[*.url]]`) matching is not currently enforced

An earlier version of this filter also matched TLS SNI / HTTP `Host:`
values against `[[*.url]]` config entries, as a fallback when the IP/subnet
check denied a packet. The parser (`linuxbpf_common::tls`/`http`) is
complete and unit-tested, and getting it to pass the kernel verifier
surfaced (and fixed) a long chain of real BPF-specific issues -- see the
`git` history / doc comments in `linuxbpf-common/src/tls.rs` if you're
curious what that involved.

It was removed after testing against real traffic revealed a **structural**
problem, not a parsing bug: this filter is stateless and per-packet, with
no connection tracking. A TLS ClientHello only exists in the data packet
that follows a *completed* TCP handshake (SYN -> SYN-ACK -> ACK), and
hostname matching only ever ran as a fallback once the IP/subnet check had
already denied a packet -- including the connection's own SYN. So for any
destination not already IP/subnet-allowed, the SYN is dropped before the
client can ever send the ClientHello, and hostname matching never sees real
data. Conversely, if the IP/subnet check allows the SYN, it also allows
every later packet, so the hostname fallback never runs at all. There's no
way, with this design, to reach the situation where the mechanism would
actually do anything.

`[[*.url]]` entries are still parsed (so old configs get a clear rejection
instead of the rule silently never being enforced) but always cause
`linuxbpf` to refuse to start, with a message pointing back to this
section: `[[*.url]]` (hostname/SNI) allowlist entries are not currently
enforced.

A working version needs the TCP handshake for a candidate connection
(SYN/SYN-ACK/ACK, no payload, dport 443/80) to be let through provisionally
whenever a hostname rule exists for that direction, with the real decision
deferred to -- and enforced by dropping -- the first data-carrying packet.
That's a real, deliberate change to what "denied" means for such
connections (a destination's port being open becomes observable even when
not allowlisted, though no application data ever crosses), which is why
it's not implemented silently. See `linuxbpf-ebpf/src/filter.rs`'s doc
comment for the full writeup.

## Building

This needs a Linux host (or VM/container running a Linux kernel) with:

- Rust nightly with the `rust-src` component (already handled by workspace
  tooling; `aya-build` invokes `cargo +nightly` itself for the eBPF crate).
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker#installation) on
  `PATH`. The easiest way to get it is
  [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall) (`cargo
  binstall bpf-linker`), which fetches a prebuilt release binary and avoids
  needing to match a system LLVM version yourself -- see `Dockerfile` for a
  complete, working install sequence.

```sh
cargo build --release
```

`linuxbpf/build.rs` cross-compiles `linuxbpf-ebpf` to a BPF object and
embeds it into the `linuxbpf` binary, so the result is a single
self-contained executable.

## Docker

`Dockerfile` builds a Debian-based image with the full toolchain (Rust
nightly, `bpf-linker` via `cargo-binstall`, `bpftool`) and compiles the
project inside the container -- this is the easiest way to build and try
the filter without setting up a Linux toolchain locally (e.g. from macOS).

```sh
docker build -t linuxbpf .
docker run --rm -it --privileged linuxbpf
```

`--privileged` is the simplest way to get the capabilities BPF loading and
cgroup attachment need. For a narrower grant (on a Docker version recent
enough to know these capability names), try `--cap-add=BPF
--cap-add=NET_ADMIN --cap-add=PERFMON` instead -- the exact set needed
varies by kernel version (see "Running" below), so fall back to
`--privileged` if that's not enough. Inside the container:

```sh
/workspace/target/release/linuxbpf --config /workspace/linuxbpf.toml &
bpftool cgroup tree /sys/fs/cgroup
curl https://1.1.1.1     # or whatever your config allows
```

By default the loader attaches to `/sys/fs/cgroup`, which -- because Docker
gives each container its own cgroup namespace -- is the *container's own*
cgroup root, so this self-contained loop (load the filter, then generate
traffic from a shell in the same container) is a realistic way to exercise
it. This is exactly how the filter was validated during development: real
kernel (Docker Desktop's own Linux VM works fine), real `bpftool`, real
traffic, no host installation needed.

## Testing

```sh
cargo test -p linuxbpf-common
```

Runs natively on any platform, no Linux/BPF/root needed. This covers:

- `ip::parse` -- IPv4/IPv6 + TCP/UDP header parsing, against hand-built
  packet byte buffers (via a `PacketReader` impl backed by a plain `&[u8]`
  instead of a real `__sk_buff`), including truncated/malformed-header and
  unsupported-protocol cases.
- `tls::extract_sni` / `http::extract_host` -- the (currently unused, see
  above) SNI/Host parsers, against wire-format fixtures covering
  present/absent matches, malformed input at every truncation point, and
  case/port-suffix handling, verifying they never panic.
- `normalize_hostname_hash` -- case-folding, trailing-dot handling,
  truncation consistency.
- `config::parse` -- the TOML allowlist parser (`linuxbpf/src/main.rs` just
  reads the file and calls this), covering a full valid config, default
  mode/`cgroup_path`, rejection of `[[*.url]]` entries, and rejection of
  invalid IPs, malformed/out-of-range CIDRs, a config with no allowlist
  entries at all, and malformed TOML.
- `cgroup::find_cgroup2_mount` -- the `/proc/mounts` line-parsing logic
  behind cgroup auto-detection (`linuxbpf/src/cgroup.rs` just reads the
  real file and calls this), against hand-built mounts-file fixtures.

`linuxbpf-ebpf`'s map-lookup/verdict logic (`filter.rs`) and `linuxbpf`'s
`aya::Ebpf`/ring-buffer loading (`loader.rs`, `telemetry.rs`) aren't covered
by these tests -- they're irreducibly tied to real BPF maps and kernel
objects (`aya` itself doesn't compile against macOS's libc) -- but they
*have* been exercised for real, via the Docker workflow above, not just
type-checked.

## Running

```sh
sudo ./target/release/linuxbpf --config ./linuxbpf.toml
```

Root (or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`, depending on kernel
version) is required to load programs and attach to a cgroup.

By default the loader auto-detects the unified cgroup2 mount from
`/proc/mounts`. To scope enforcement to one container instead of the whole
host, either set `cgroup_path` in the TOML config or pass
`--cgroup-path`:

```sh
# find a container's cgroup, e.g. for Docker with the cgroupfs driver:
docker inspect -f '{{.Id}}' my-container
sudo ./target/release/linuxbpf --cgroup-path \
  /sys/fs/cgroup/system.slice/docker-<full-container-id>.scope
```

If the containers run inside a VM (Docker Desktop's LinuxKit VM, a
Kata/microVM sandbox, etc.), run `linuxbpf` *inside that VM* -- attaching
requires being able to see the cgroup2 hierarchy the container's kernel
actually maintains, which a process outside that kernel can't do.

## Validating against `bpftool`

Once loaded and attached:

```sh
# confirm both programs are loaded
sudo bpftool prog show | grep cgroup_skb_

# confirm the cgroup has both attach types
sudo bpftool cgroup tree /sys/fs/cgroup/<path>

# inspect a program's maps and verifier-translated instructions
sudo bpftool prog dump xlated name cgroup_skb_egress

# watch live map contents
sudo bpftool map dump name EGRESS_IPV4
```

## Telemetry

```sh
journalctl -t linuxbpf -f            # everything
journalctl -t linuxbpf -p warning -f # rejections only
```

Set `RUST_LOG=debug` (or any `tracing`/`EnvFilter` directive) before
running to change verbosity; it defaults to `info`.
