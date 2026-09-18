//! Logging setup and the ring-buffer consumer that turns kernel-side
//! `FlowEvent`s into structured `tracing` records: `warn!` for rejections,
//! `info!` for allows, so `journalctl -u linuxbpf` (or `-p warning` to see
//! only rejections) does the right thing out of the box.

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use tokio::io::unix::AsyncFd;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;

use linuxbpf_common::{Direction, FlowEvent, L4Proto, MatchKind, Verdict};

/// Tries to log to the systemd journal (so warn/info map to the matching
/// journal priority and show up under the unit's logs); falls back to
/// plain stderr logging if journald isn't reachable (e.g. not running
/// under systemd, or inside a minimal container without a journald
/// socket).
pub fn init_logging() {
    // `RUST_LOG`, if set in the environment, controls the minimum log
    // level/filters shown (standard `tracing` convention); otherwise
    // default to showing `info` level and above.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // `tracing_journald::layer()` attempts to open a connection to the
    // local systemd-journald socket; this can fail (returning `Err`)
    // simply because journald isn't present or reachable in the current
    // environment (e.g. inside a bare container). `tracing_subscriber`'s
    // "layer" system lets multiple independent concerns (here: the level
    // filter, and where records actually get written) be composed
    // together via `.with(...)` chains -- each of the two branches below
    // builds and installs (`.init()`) a complete subscriber, differing
    // only in which output layer it uses.
    match tracing_journald::layer() {
        Ok(journald) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(journald)
                .init();
        }
        Err(err) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
            warn!(error = %err, "journald not available; falling back to stderr logging");
        }
    }
}

// The long-running loop that reads `FlowEvent` records out of the kernel's
// `EVENTS` ring buffer as they arrive and turns each into a log line. Runs
// forever (`loop`) until cancelled from outside (see `main.rs`'s
// `tokio::select!`).
pub async fn run_event_loop(ring_buf: RingBuf<MapData>) -> Result<()> {
    // `AsyncFd` bridges a raw, blocking-style file descriptor (which is
    // what a BPF ring buffer's poll-notification fd fundamentally is) into
    // Tokio's async I/O reactor, so `.readable_mut().await` below can
    // suspend this task (without blocking the whole program) until the
    // kernel signals there's new data to read, rather than spinning in a
    // busy-loop or blocking a whole OS thread.
    let mut async_fd = AsyncFd::new(ring_buf).context("registering ring buffer fd with tokio")?;
    loop {
        // Suspends here until the ring buffer's fd becomes readable (i.e.
        // the kernel-side filter wrote at least one new event); `guard`
        // then provides access to the underlying `RingBuf` to actually
        // drain it.
        let mut guard = async_fd.readable_mut().await?;
        // `guard.get_inner_mut()` is the `RingBuf` itself; `.next()`
        // returns `Some(item)` for each already-available entry (draining
        // everything currently buffered) and `None` once it's caught up --
        // this inner `while` loop empties the buffer completely each time
        // the outer `loop` wakes up, rather than processing just one event
        // per wakeup.
        while let Some(item) = guard.get_inner_mut().next() {
            if item.len() < size_of::<FlowEvent>() {
                warn!(
                    len = item.len(),
                    "short read from EVENTS ring buffer, dropping"
                );
                continue;
            }
            // SAFETY: length was just checked; FlowEvent is repr(C) and
            // Copy, and the ring buffer entry may not satisfy its natural
            // alignment, so this is read unaligned rather than cast.
            //
            // `item` is just a raw `&[u8]` slice of ring-buffer bytes --
            // reinterpreting it as a `FlowEvent` value is the userspace
            // mirror of the same operation `filter::finish` performs on
            // the kernel side when it *writes* this same struct into the
            // ring buffer via `EVENTS.output(...)`. Both sides agree on
            // the exact byte layout because `FlowEvent` is `#[repr(C)]`
            // (a fixed, predictable layout) and defined once, in
            // `linuxbpf-common`, and compiled into both the kernel and
            // userspace binaries identically.
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FlowEvent) };
            log_event(&event);
        }
        // Tells Tokio's reactor "I've drained everything currently
        // available; go back to waiting for the fd to become readable
        // again" -- without this, `.readable_mut()` on the next loop
        // iteration could return immediately based on stale readiness
        // state instead of actually waiting for new data.
        guard.clear_ready();
    }
}

// Formats one `FlowEvent` into a single structured `tracing` log record,
// at `info` for an allowed flow and `warn` for a rejected one -- this
// warn/info split (rather than, say, a `level` field on one shared log
// call) is what lets `journalctl -p warning` show only rejections, and is
// one of the original project requirements.
fn log_event(event: &FlowEvent) {
    // Every enum value crossing the kernel/userspace boundary through
    // `FlowEvent` travels as a plain `u8` (see `linuxbpf-common/src/lib.rs`'s
    // `#[repr(u8)]` enums) rather than a real Rust enum value, since the
    // kernel side writes these fields as raw bytes with no type
    // information attached -- so each of these comparisons reconstructs
    // "which variant was this" by comparing against `EnumVariant::Foo as
    // u8` rather than via an actual enum match.
    let direction = if event.direction == Direction::Egress as u8 {
        "egress"
    } else {
        "ingress"
    };
    // `match` with guard patterns (`p if p == ... as u8`) here plays the
    // same role as a chain of `if`/`else if` would, but reads slightly
    // more like the enum match it's standing in for; the final `_ =>` arm
    // is the fallback for any byte value that isn't one of the known
    // variants (defensive, in case the kernel and userspace binaries ever
    // drift out of sync).
    let protocol = match event.l4_proto {
        p if p == L4Proto::Tcp as u8 => "tcp",
        p if p == L4Proto::Udp as u8 => "udp",
        _ => "other",
    };
    let match_kind = match event.match_kind {
        k if k == MatchKind::ExactIp as u8 => "ip",
        k if k == MatchKind::Subnet as u8 => "subnet",
        k if k == MatchKind::Hostname as u8 => "hostname",
        k if k == MatchKind::FlowCache as u8 => "flow-cache",
        k if k == MatchKind::Malformed as u8 => "malformed",
        k if k == MatchKind::Unsupported as u8 => "unsupported",
        _ => "no-match",
    };
    let (src, dst) = format_addrs(event);

    if event.verdict == Verdict::Allow as u8 {
        // `src = %src`: the `%` sigil tells `tracing` to format this field
        // using the value's `Display` implementation (`IpAddr` prints as
        // the familiar dotted/colon notation) rather than `Debug`. Each
        // `name = value` pair becomes its own structured field in the
        // emitted log record, independently filterable/searchable by log
        // tooling, rather than being baked into one opaque message
        // string.
        info!(
            direction,
            protocol,
            match_kind,
            src = %src,
            sport = event.sport,
            dst = %dst,
            dport = event.dport,
            cgroup_id = event.cgroup_id,
            hostname_hash = event.hostname_hash,
            "boundary filter: allowed"
        );
    } else {
        warn!(
            direction,
            protocol,
            match_kind,
            src = %src,
            sport = event.sport,
            dst = %dst,
            dport = event.dport,
            cgroup_id = event.cgroup_id,
            "boundary filter: rejected"
        );
    }
}

// Converts a `FlowEvent`'s raw address bytes (always stored as a 16-byte
// array, wide enough for either family) back into proper typed `IpAddr`
// values for display, based on the `family` field the kernel side set (4
// or 6).
fn format_addrs(event: &FlowEvent) -> (IpAddr, IpAddr) {
    if event.family == 4 {
        // For an IPv4 flow, only the first 4 of the 16 stored bytes are
        // meaningful; `[..4]` takes just that prefix, and `.try_into()`
        // converts the resulting slice into a fixed-size `[u8; 4]` array
        // (needed because `Ipv4Addr::from` expects that exact type, not a
        // slice) -- `.unwrap()` is safe here since a 4-byte slice can
        // always convert into a `[u8; 4]`.
        let s: [u8; 4] = event.saddr[..4].try_into().unwrap();
        let d: [u8; 4] = event.daddr[..4].try_into().unwrap();
        (IpAddr::V4(Ipv4Addr::from(s)), IpAddr::V4(Ipv4Addr::from(d)))
    } else {
        // IPv6 addresses use the full 16 bytes as-is.
        (
            IpAddr::V6(Ipv6Addr::from(event.saddr)),
            IpAddr::V6(Ipv6Addr::from(event.daddr)),
        )
    }
}
