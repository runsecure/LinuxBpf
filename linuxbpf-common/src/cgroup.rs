//! Pure parsing of `/proc/mounts`-formatted text to find the cgroup v2
//! (unified) mount point. Split out from `linuxbpf::cgroup`'s actual
//! filesystem access specifically so it's unit-testable without a real
//! `/proc/mounts` -- needs only `core`, not `std`, so it's compiled
//! unconditionally (even into the no_std eBPF build, though nothing there
//! calls it today).

/// Scans `/proc/mounts`-formatted `contents` for the first `cgroup2`
/// filesystem entry and returns its mount point.
// This function takes the *text* of `/proc/mounts` as a plain `&str`
// parameter, rather than reading the real file itself -- that's the whole
// trick that makes it testable without a real Linux system: the actual
// `std::fs::read_to_string("/proc/mounts")` call lives in
// `linuxbpf/src/cgroup.rs` instead, a thin, untested wrapper around this
// pure function.
pub fn find_cgroup2_mount(contents: &str) -> Option<&str> {
    // `/proc/mounts` has one mount entry per line, in the same
    // whitespace-separated format as `/etc/fstab`:
    // `<device> <mount-point> <fstype> <options> <dump> <pass>`
    // `.lines()` splits the text on newlines without including them.
    for line in contents.lines() {
        // `.split_whitespace()` breaks one line into its
        // whitespace-separated fields, skipping over repeated spaces (a
        // real `/proc/mounts` line uses single spaces, but this is
        // tolerant of extra whitespace regardless).
        let mut fields = line.split_whitespace();
        // `.next()` pulls fields off one at a time, in order. The first
        // field (the device/source) isn't needed for anything here, but
        // still has to be consumed to advance past it to the fields that
        // *are* needed.
        let _device = fields.next();
        let mount_point = fields.next();
        let fstype = fields.next();
        // `cgroup2` is the filesystem type Linux uses specifically for
        // the unified cgroup v2 hierarchy (as opposed to `cgroup`, the
        // older v1 style, of which a system can have several
        // simultaneously mounted at different points) -- this is the
        // signal that identifies the *one* mount point this function is
        // looking for.
        if fstype == Some("cgroup2") {
            // Return immediately on the first match. `mount_point` is
            // already an `Option<&str>` (from `.next()`), and that's
            // exactly this function's own return type, so it can be
            // returned as-is -- if the line somehow had a `cgroup2`
            // fstype but no mount-point field at all (a malformed line),
            // this correctly returns `None` rather than panicking.
            return mount_point;
        }
    }
    // Fell through the whole file without finding a `cgroup2` line.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_unified_cgroup2_mount() {
        // A realistic (trimmed) excerpt of what a real `/proc/mounts`
        // looks like, including the `cgroup2` line this test expects to
        // be found.
        let mounts = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1631312k,mode=755 0 0
";
        assert_eq!(find_cgroup2_mount(mounts), Some("/sys/fs/cgroup"));
    }

    #[test]
    fn returns_none_when_no_cgroup2_mount_present() {
        // A host still on cgroup v1 (fstype `cgroup`, not `cgroup2`) --
        // this function should find nothing, rather than mistakenly
        // matching the v1 line.
        let mounts = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/net_cls cgroup rw,nosuid,nodev,noexec,relatime,net_cls 0 0
";
        assert_eq!(find_cgroup2_mount(mounts), None);
    }

    #[test]
    fn returns_first_match_when_multiple_cgroup2_mounts_exist() {
        // Unusual, but a hybrid v1/v2 host could have cgroup2 mounted in
        // more than one place; we take the first one, matching what a
        // straight `/proc/mounts` scan would find first.
        let mounts = "\
cgroup2 /sys/fs/cgroup/unified cgroup2 rw 0 0
cgroup2 /mnt/other cgroup2 rw 0 0
";
        assert_eq!(find_cgroup2_mount(mounts), Some("/sys/fs/cgroup/unified"));
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(find_cgroup2_mount(""), None);
    }

    #[test]
    fn ignores_malformed_short_lines() {
        // Lines with too few fields to even have a real fstype in the
        // third position -- must not panic, and must not be mistaken for
        // a match.
        let mounts = "cgroup2\ncgroup2 /only/two\n";
        assert_eq!(find_cgroup2_mount(mounts), None);
    }
}
