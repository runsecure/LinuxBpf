//! Resolves the cgroup v2 directory the programs attach to.
//!
//! There is nothing container- or virtualization-specific to implement
//! here: a `cgroup_skb` program attached to a cgroup2 directory covers that
//! cgroup and every descendant, which is how it "sees" containers -- their
//! cgroups are descendants of whatever this process attaches to. The only
//! thing that matters is running this loader somewhere that can see the
//! *real* cgroup2 hierarchy the target processes live under:
//!
//! - Attach at the root cgroup2 mount to cover the whole host/node.
//! - Attach at a specific container's cgroup (find it with `docker inspect`
//!   / `systemd-cgls` / `crictl inspect`) to scope enforcement to just it.
//! - If the containers run inside a VM (nested virtualization, e.g. Docker
//!   Desktop's LinuxKit VM, or a Kata/microVM sandbox), run this loader
//!   *inside that VM's kernel* -- it has no visibility into a cgroup2
//!   hierarchy it isn't the kernel for.
//!
//! The actual mount-line parsing (`find_cgroup2_mount`) lives in
//! `linuxbpf_common::cgroup` -- it's pure text parsing with no filesystem
//! access, which is what makes it unit-testable; this module is just the
//! thin, untested glue that reads the real `/proc/mounts`.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use linuxbpf_common::cgroup::find_cgroup2_mount;

// Decides which cgroup2 directory `loader::attach_programs` should attach
// to: an explicitly `configured` path (from `--cgroup-path` or the config
// file's `[global].cgroup_path`) takes priority; otherwise this falls back
// to auto-detecting the host's unified cgroup2 mount from `/proc/mounts`.
pub fn resolve_cgroup_path(configured: Option<&str>) -> Result<PathBuf> {
    if let Some(raw) = configured {
        let path = PathBuf::from(raw);
        // Fail fast, with a specific and actionable error, if the
        // configured path doesn't actually exist as a directory --
        // otherwise this would surface later as a much more confusing
        // "opening cgroup directory" I/O error from deep inside
        // `loader::attach_programs`.
        if !path.is_dir() {
            bail!(
                "configured cgroup_path '{}' is not a directory (is it mounted, and are you \
                 running in the same mount namespace as the target processes?)",
                path.display()
            );
        }
        return Ok(path);
    }

    // No explicit path given -- read the real `/proc/mounts` (this
    // process's own view of currently-mounted filesystems; see the
    // module doc comment above on why that view has to be the *right*
    // one, namespace-wise) and hand its text to the pure, unit-tested
    // `find_cgroup2_mount` parser to pick out the cgroup2 line.
    let mounts = std::fs::read_to_string("/proc/mounts").context("reading /proc/mounts")?;
    // `.map(PathBuf::from)` converts the found `&str` mount point into an
    // owned `PathBuf` (needed since `mounts`, which that `&str` borrows
    // from, is a local variable that would otherwise be dropped before
    // this function returns); `.context(...)` turns a `None` result (no
    // cgroup2 mount found at all) into an `Err` carrying a message
    // explaining both what's missing and how to fix it.
    find_cgroup2_mount(&mounts).map(PathBuf::from).context(
        "no cgroup_path configured (set [global].cgroup_path or pass --cgroup-path) and no \
         cgroup2 (unified) mount was found in /proc/mounts for this process",
    )
}
