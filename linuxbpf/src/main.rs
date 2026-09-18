// Declares the three sibling modules that make up this userspace binary --
// each lives in its own file (`cgroup.rs`, `loader.rs`, `telemetry.rs`) in
// the same directory as this one. This binary is the "control plane": it
// reads the config, loads the compiled eBPF object into the kernel,
// populates its maps, attaches its programs to a cgroup, and then streams
// telemetry back out -- all the actual packet filtering happens in the
// kernel, in code this program never runs directly.
mod cgroup;
mod loader;
mod telemetry;

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::RingBuf;
use clap::Parser;
use linuxbpf_common::config;

/// eBPF cgroup ingress/egress boundary protection filter.
// `#[derive(Parser)]` (from the `clap` crate) turns this plain struct
// definition into a full command-line argument parser: each field below
// becomes a flag, its doc comment becomes that flag's `--help` text, and
// `#[command(author, version, about)]` pulls the binary's name/author/
// version/description straight from this crate's own Cargo.toml metadata.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Opt {
    /// Path to the TOML allowlist configuration.
    // `#[arg(short, long, default_value = ...)]`: accepts both `-c` and
    // `--config`, defaulting to the standard system config path if neither
    // is given on the command line.
    #[arg(short, long, default_value = "/etc/linuxbpf/linuxbpf.toml")]
    config: PathBuf,

    /// cgroup v2 directory to attach to. Overrides [global].cgroup_path in
    /// the config file and skips auto-detection.
    // `Option<PathBuf>` (no `default_value`): genuinely optional -- when
    // omitted this is `None`, and `main` below falls through to the
    // config-file value or auto-detection instead.
    #[arg(long)]
    cgroup_path: Option<PathBuf>,
}

// `#[tokio::main]` expands this `async fn main` into an ordinary,
// synchronous `fn main` that spins up a Tokio async runtime and runs this
// function's body on it -- necessary because `run_event_loop` (called
// below, via `telemetry`) awaits on the ring buffer's file descriptor
// becoming readable, which only works inside an async runtime.
// `Result<()>` as the return type means returning `Err(...)` from anywhere
// in this function (including via any of the `?` operators below) causes
// the process to print that error and exit non-zero, without needing an
// explicit `match`/`std::process::exit` here.
#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    telemetry::init_logging();

    // Read the config file's raw text, then hand it to
    // `linuxbpf_common::config::parse` (a pure function -- see
    // `linuxbpf-common/src/config.rs`) to actually parse and validate it.
    // `.with_context(|| ...)` wraps whatever underlying I/O or parse error
    // occurred with a message naming the specific file path involved, so
    // the eventual error an operator sees points at the right file.
    let config_text = std::fs::read_to_string(&opt.config)
        .with_context(|| format!("reading config file {}", opt.config.display()))?;
    let cfg = config::parse(&config_text)
        .with_context(|| format!("loading config {}", opt.config.display()))?;

    // Prefer an explicit `--cgroup-path` flag; otherwise resolve one from
    // the config file's own `cgroup_path` setting (or auto-detect if that,
    // too, was left unset) via `cgroup::resolve_cgroup_path`.
    let cgroup_path = match opt.cgroup_path {
        Some(p) => p,
        None => cgroup::resolve_cgroup_path(cfg.cgroup_path.as_deref())?,
    };

    // A structured log line summarizing what's about to be loaded --
    // `%cgroup_path.display()` and `?cfg.mode` use `tracing`'s
    // `Display`/`Debug` formatting sigils respectively, and each
    // `field = value` pair becomes a separate, machine-parseable field in
    // the emitted log record (rather than being baked into the message
    // string), which is what lets `journalctl`/log tooling filter or
    // group on them later.
    tracing::info!(
        cgroup = %cgroup_path.display(),
        mode = ?cfg.mode,
        ingress_ip_rules = cfg.ingress.ipv4.len() + cfg.ingress.ipv6.len(),
        ingress_subnet_rules = cfg.ingress.subnets_v4.len() + cfg.ingress.subnets_v6.len(),
        egress_ip_rules = cfg.egress.ipv4.len() + cfg.egress.ipv6.len(),
        egress_subnet_rules = cfg.egress.subnets_v4.len() + cfg.egress.subnets_v6.len(),
        "starting linuxbpf boundary filter"
    );

    // The embedded object must be aligned to a natural word boundary for
    // the BPF verifier; `include_bytes_aligned!` (unlike `include_bytes!`)
    // guarantees that.
    //
    // This is how the compiled eBPF program gets into this binary at all:
    // `linuxbpf-ebpf` is built as a *separate* target (for the BPF
    // instruction set, not this machine's own) by this crate's
    // `build.rs`, which writes the resulting object file into `OUT_DIR`
    // (a directory Cargo sets aside for a build script's generated
    // output). `include_bytes_aligned!` then embeds that file's raw bytes
    // directly into *this* binary at compile time, so the final
    // `linuxbpf` executable is fully self-contained -- no separate `.o`
    // file needs to ship or be found at runtime. `Ebpf::load` (from the
    // `aya` crate) is what actually hands those embedded bytes to the
    // kernel's `bpf()` syscall, parses out its maps/programs, and runs
    // them through the verifier.
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/linuxbpf"
    )))
    .context("loading eBPF object")?;

    // With the object loaded (but its programs not yet attached), populate
    // its maps and attach its programs, in order: enforcement mode first,
    // then the allowlist data each direction's program will read, then
    // finally attach both programs so they actually start seeing traffic
    // -- doing it in this order means there's never a window where a
    // program is live but its maps are still empty/default.
    loader::set_mode(&mut bpf, cfg.mode).context("setting enforcement mode")?;
    loader::populate_direction(&mut bpf, "INGRESS", &cfg.ingress)
        .context("populating ingress allowlist maps")?;
    loader::populate_direction(&mut bpf, "EGRESS", &cfg.egress)
        .context("populating egress allowlist maps")?;
    loader::attach_programs(&mut bpf, &cgroup_path).context("attaching cgroup_skb programs")?;

    // Take ownership of the `EVENTS` ring buffer map (declared in
    // `linuxbpf-ebpf/src/maps.rs`) out of the loaded object, and wrap it in
    // Aya's typed `RingBuf` reader so `telemetry::run_event_loop` can
    // consume the `FlowEvent` records the kernel-side filter writes into
    // it.
    let events_map = bpf
        .take_map("EVENTS")
        .context("EVENTS map not found in object")?;
    let ring_buf = RingBuf::try_from(events_map).context("opening EVENTS ring buffer")?;

    tracing::info!("boundary filter attached; watching for verdicts (Ctrl-C to stop)");
    // `tokio::select!` races the two async operations below and proceeds
    // as soon as *either* one completes, cancelling the other: normally
    // that means `run_event_loop` runs forever (it's an infinite loop)
    // until the user hits Ctrl-C, at which point `ctrl_c()` resolves first
    // and this arm runs instead, logging a shutdown message rather than
    // treating this as an error.
    tokio::select! {
        res = telemetry::run_event_loop(ring_buf) => {
            res.context("event loop exited")?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown requested, detaching");
        }
    }

    // `bpf` must live for the whole run: dropping it earlier detaches the
    // cgroup_skb programs (and drops the maps backing them).
    //
    // This `drop(bpf)` is explicit (rather than just letting `bpf` go out
    // of scope at the end of `main` implicitly) purely to make that
    // ordering dependency visible in the code -- Aya's `Ebpf` type detaches
    // every program it loaded, and frees its maps, as part of its own
    // `Drop` implementation, which is why this value has to be kept alive
    // (not moved into, and dropped early by, any of the code above) for
    // the whole time the filter should actually be running.
    drop(bpf);
    Ok(())
}
