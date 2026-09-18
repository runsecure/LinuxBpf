//! TOML allowlist configuration: parsing (`RawConfig`, mirrors the file
//! layout) and resolution into concrete addresses ready to load into the
//! eBPF maps (`ResolvedConfig`).
//!
//! Only compiled when testing this crate directly, or for the userspace
//! `linuxbpf` binary (the `user` feature) -- there's nothing here the
//! no_std eBPF build needs, and `anyhow`/`serde`/`toml` aren't `no_std`.
//! `parse` takes the config text directly (not a file path) so it's a pure
//! function the tests below can exercise without any filesystem I/O; the
//! userspace crate's `main.rs` does the actual file read before calling it.

use std::net::IpAddr;

// `anyhow`: a general-purpose error-handling crate. `Result` here is
// `anyhow::Result<T>` (shorthand for `Result<T, anyhow::Error>`) -- a
// single, flexible error type that can wrap *any* underlying error and
// carry a chain of human-readable context messages, which is what
// `.context(...)`/`.with_context(...)` (seen throughout this file) attach
// to it. `bail!` is a macro shorthand for "construct an error from this
// message and return it immediately"; `anyhow!` builds an error value
// without returning it.
use anyhow::{Context, Result, anyhow, bail};
// `serde::Deserialize`: the trait (and matching `#[derive(Deserialize)]`
// below) that lets the `toml` crate populate these structs' fields
// directly from parsed TOML data, based on field names matching (or
// explicitly remapped via `#[serde(rename = "...")]`) the TOML file's own
// keys.
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
// Without this, `serde` would expect the TOML file to spell the mode
// values exactly `Enforce`/`Monitor` (matching the Rust variant names
// case-for-case); this makes it accept the lowercase `"enforce"`/
// `"monitor"` a human actually writes in the config file instead.
#[serde(rename_all = "lowercase")]
pub enum ModeConfig {
    // `#[default]` marks which variant `ModeConfig::default()` produces
    // -- used below whenever the config file omits `mode` entirely.
    // `Enforce` (not `Monitor`) is deliberately the fail-safe default: an
    // operator who forgets to set this gets real enforcement, not a
    // silently-inert filter.
    #[default]
    Enforce,
    Monitor,
}

// This struct's shape mirrors the TOML file's own top-level structure
// exactly: a `[global]` table plus `ingress`/`egress` sections (each
// themselves containing arrays of tables, `[[ingress.ip]]` etc. -- see
// `DirectionConfig` below). It's private (`struct`, not `pub struct`) and
// only used as an intermediate step inside this file -- nothing outside
// `config.rs` ever sees a raw, not-yet-validated `RawConfig`.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    // `#[serde(default)]`: if the TOML file has no `[global]` table at
    // all, use `GlobalConfig::default()` rather than failing to parse.
    #[serde(default)]
    global: GlobalConfig,
    #[serde(default)]
    ingress: DirectionConfig,
    #[serde(default)]
    egress: DirectionConfig,
}

#[derive(Debug, Default, Deserialize)]
struct GlobalConfig {
    #[serde(default)]
    mode: ModeConfig,
    /// cgroup v2 directory to attach to. If omitted, the loader auto-detects
    /// the unified cgroup2 mount visible to the process it's running as
    /// (see `linuxbpf::cgroup`) -- point this (or `--cgroup-path`) at a
    /// specific container's cgroup, or run the loader itself inside the
    /// mount/PID namespace where that cgroup2 hierarchy is visible (e.g.
    /// inside the VM actually running the containers, for
    /// nested-virtualization setups).
    // `Option<String>`, not `String`: this field is genuinely optional
    // (auto-detection is the fallback), and its absence in the TOML file
    // (`serde`'s default handling of `Option` fields treats them as
    // implicitly optional even without an explicit `#[serde(default)]`)
    // becomes `None` here, not an empty string.
    cgroup_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DirectionConfig {
    // `#[serde(default, rename = "ip")]`: the TOML key is the singular
    // `ip` (matching how a human writes `[[ingress.ip]]` -- one array
    // entry describes one IP), but the Rust field holding *all* of them
    // is named `ips` (plural, since it's a `Vec`) for readability in this
    // file's own code below.
    #[serde(default, rename = "ip")]
    ips: Vec<IpEntry>,
    #[serde(default, rename = "subnet")]
    subnets: Vec<SubnetEntry>,
    // Parsed (not just ignored via serde's default unknown-field handling)
    // specifically so a config that has `[[*.url]]` entries gets a clear,
    // actionable rejection instead of those rules silently never being
    // enforced -- see the doc comment on `resolve_direction`.
    #[serde(default, rename = "url")]
    urls: Vec<UrlEntry>,
}

#[derive(Debug, Deserialize)]
struct IpEntry {
    address: String,
    // `description` is accepted (so a config author can annotate *why* a
    // rule exists) but never read by any code in this project --
    // `#[allow(dead_code)]` tells the compiler that's intentional, so it
    // doesn't warn about an unused field.
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct SubnetEntry {
    cidr: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
// Applied to the whole struct here (rather than just the one field, as in
// `IpEntry`/`SubnetEntry` above) since *both* of `UrlEntry`'s fields go
// completely unused -- these entries exist purely to be detected and
// rejected (see `resolve_direction` below), never to be read.
#[allow(dead_code)]
struct UrlEntry {
    hostname: String,
    #[serde(default)]
    description: String,
}

// The "resolved" counterpart to `DirectionConfig`: no longer raw strings
// straight out of the TOML file, but the concrete, validated byte-level
// values ready to hand to the userspace loader for insertion into the
// eBPF maps (see `linuxbpf/src/loader.rs`). Building this is what
// `resolve_direction`, below, actually does.
#[derive(Debug, Default)]
pub struct ResolvedDirection {
    pub ipv4: Vec<[u8; 4]>,
    pub ipv6: Vec<[u8; 16]>,
    // Each subnet is a (prefix length, address) pair -- exactly what
    // `aya::maps::lpm_trie::Key::new` (used in `loader.rs`) needs to build
    // an LPM-trie map key.
    pub subnets_v4: Vec<(u32, [u8; 4])>,
    pub subnets_v6: Vec<(u32, [u8; 16])>,
}

impl ResolvedDirection {
    // Used by `parse` below to reject a config that would deny literally
    // everything (see the `bail!` there) -- true only if not a single
    // rule of any kind was configured for this direction.
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty()
            && self.ipv6.is_empty()
            && self.subnets_v4.is_empty()
            && self.subnets_v6.is_empty()
    }
}

#[derive(Debug)]
pub struct ResolvedConfig {
    pub mode: ModeConfig,
    pub cgroup_path: Option<String>,
    pub ingress: ResolvedDirection,
    pub egress: ResolvedDirection,
}

/// Parses and resolves a TOML config given as a string. Pure -- no
/// filesystem access -- so it's directly unit-testable.
pub fn parse(text: &str) -> Result<ResolvedConfig> {
    // `toml::from_str` does the actual TOML-syntax parsing and populates
    // a `RawConfig` via the `#[derive(Deserialize)]` machinery above.
    // `.context("parsing TOML")` attaches a short, human-readable label
    // to whatever underlying parse error this might produce (a syntax
    // error, a field with the wrong type, etc.), so the eventual error
    // message an operator sees isn't just a bare `toml` crate error.
    let raw: RawConfig = toml::from_str(text).context("parsing TOML")?;

    // Turn each raw, string-based direction into its validated,
    // byte-level `ResolvedDirection` -- see `resolve_direction` below for
    // what that involves. `?` propagates a validation failure (e.g. a bad
    // IP address) straight out of `parse` as this function's own error,
    // after `.context(...)` notes *which* direction the problem was in.
    let ingress = resolve_direction(raw.ingress).context("resolving [[ingress.*]] entries")?;
    let egress = resolve_direction(raw.egress).context("resolving [[egress.*]] entries")?;

    // A config with zero rules in *both* directions would deny every
    // packet outright (or, in monitor mode, do nothing at all) -- almost
    // certainly a mistake rather than an intentional "block everything"
    // config, so this is rejected outright with a message explaining
    // exactly why, rather than silently accepted and left to surprise
    // whoever runs it.
    if ingress.is_empty() && egress.is_empty() {
        bail!(
            "config has no ingress or egress allowlist entries at all -- \
             every packet would be denied (or the filter would be a no-op \
             in monitor mode); add at least one [[ingress.*]] or [[egress.*]] entry"
        );
    }

    Ok(ResolvedConfig {
        mode: raw.global.mode,
        cgroup_path: raw.global.cgroup_path,
        ingress,
        egress,
    })
}

/// `[[*.url]]` (hostname/SNI matching) entries are parsed but always
/// rejected right now: the eBPF filter is a stateless, per-packet decision
/// point with no connection tracking, and it turns out that combination
/// can't ever act on a hostname rule for a *new* connection -- the SNI/Host
/// value only exists in the data packet that follows a completed TCP
/// handshake, and that same filter would have already had to deny (drop)
/// the handshake's own SYN for a hostname rule to be relevant in the first
/// place, so the data carrying the hostname never arrives. Silently
/// ignoring `[[*.url]]` entries would let an operator believe a hostname
/// restriction is enforced when it never can be with this design -- hence
/// a hard error instead. See `linuxbpf-ebpf/src/filter.rs`'s doc comment
/// for the full explanation and what a working version would need.
// Takes ownership of `cfg` (not a reference) since it's fully consumed
// here -- each field is read once, into the new `ResolvedDirection` being
// built, and the raw `DirectionConfig` isn't needed again afterward.
fn resolve_direction(cfg: DirectionConfig) -> Result<ResolvedDirection> {
    // Check this *before* doing any of the real resolution work below, so
    // a config mixing valid IP rules with (currently unsupported) URL
    // rules gets the clear, specific "URL rules aren't enforced" message
    // -- not a confusing success, and not some other, unrelated error
    // that happened to trigger first.
    if !cfg.urls.is_empty() {
        bail!(
            "[[*.url]] (hostname/SNI) allowlist entries are not currently enforced -- remove \
             them (use [[*.ip]] / [[*.subnet]] instead) or see linuxbpf-ebpf/src/filter.rs for \
             why and what's needed to re-enable them"
        );
    }

    // Start with an all-empty `ResolvedDirection` (via `Default`) and
    // fill it in below.
    let mut resolved = ResolvedDirection::default();

    // `&cfg.ips`: iterate by reference (not consuming `cfg.ips`), since
    // each `entry` is only being read from, not needed elsewhere
    // afterward.
    for entry in &cfg.ips {
        // `.trim()` tolerates accidental leading/trailing whitespace in
        // the TOML value; `.parse()` (targeting the `IpAddr` type
        // annotation) uses that type's standard string-parsing logic,
        // which itself already recognizes both IPv4 (`"1.2.3.4"`) and
        // IPv6 (`"::1"`) syntax and decides which one it got.
        // `.with_context(...)`: unlike plain `.context(...)` (a fixed
        // string, used elsewhere in this file), this takes a *closure*
        // so the error message can include the actual invalid string --
        // the closure only runs if `.parse()` actually failed, so there's
        // no cost building this message on the successful path.
        let addr: IpAddr = entry
            .address
            .trim()
            .parse()
            .with_context(|| format!("invalid IP address '{}'", entry.address))?;
        // `IpAddr` is itself an enum with `V4`/`V6` variants; this match
        // picks which of `resolved`'s two address lists to push into, and
        // `.octets()` unwraps the parsed address down to the plain byte
        // array this codebase uses everywhere (matching `ip.rs`'s
        // `expand4` comment on why).
        match addr {
            IpAddr::V4(a) => resolved.ipv4.push(a.octets()),
            IpAddr::V6(a) => resolved.ipv6.push(a.octets()),
        }
    }

    for entry in &cfg.subnets {
        // CIDR notation (`"10.0.0.0/8"`) isn't something `IpAddr`'s own
        // parser understands (it's not a plain address) -- `parse_cidr`,
        // below, is this file's own hand-written parser for that specific
        // syntax.
        let (addr, prefix_len) = parse_cidr(&entry.cidr)?;
        match addr {
            IpAddr::V4(a) => resolved.subnets_v4.push((prefix_len, a.octets())),
            IpAddr::V6(a) => resolved.subnets_v6.push((prefix_len, a.octets())),
        }
    }

    Ok(resolved)
}

// Parses a CIDR string like `"10.0.0.0/8"` into its address and prefix
// length. Not `pub`: an internal helper only `resolve_direction` (above)
// calls.
fn parse_cidr(s: &str) -> Result<(IpAddr, u32)> {
    // `.split_once('/')` splits the string at the *first* `/` into
    // exactly two pieces (before and after), or returns `None` if there's
    // no `/` at all -- `.ok_or_else(...)` turns that `None` case into a
    // proper error (built lazily, via a closure, so the `format!`-style
    // `anyhow!` macro only actually runs when there's really an error to
    // report).
    let (addr_part, prefix_part) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR '{s}' is missing a '/prefix-length'"))?;
    let addr: IpAddr = addr_part
        .trim()
        .parse()
        .with_context(|| format!("invalid address in CIDR '{s}'"))?;
    let prefix_len: u32 = prefix_part
        .trim()
        .parse()
        .with_context(|| format!("invalid prefix length in CIDR '{s}'"))?;
    // A prefix length has a hard ceiling depending on address family: 32
    // bits total for IPv4, 128 for IPv6 -- `/33` for an IPv4 address is
    // nonsensical and rejected here, rather than silently accepted and
    // causing confusing behavior later when it's used to build an LPM
    // trie key.
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix_len > max {
        bail!("CIDR '{s}' has prefix /{prefix_len}, but {addr} only has {max} bits");
    }
    Ok((addr, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_example_config() {
        // `r#"..."#`: a Rust "raw string" literal -- everything between
        // the quotes is taken completely literally (no `\n`-style escape
        // processing needed), which is convenient for embedding a
        // multi-line TOML document directly in the test source.
        let cfg = parse(
            r#"
            [global]
            mode = "monitor"
            cgroup_path = "/sys/fs/cgroup"

            [[ingress.ip]]
            address = "203.0.113.10"

            [[ingress.subnet]]
            cidr = "10.0.0.0/8"

            [[egress.ip]]
            address = "1.1.1.1"

            [[egress.subnet]]
            cidr = "172.16.0.0/12"
            "#,
        )
        .expect("valid config should parse");

        assert_eq!(cfg.mode, ModeConfig::Monitor);
        assert_eq!(cfg.cgroup_path.as_deref(), Some("/sys/fs/cgroup"));
        assert_eq!(cfg.ingress.ipv4, vec![[203, 0, 113, 10]]);
        assert_eq!(cfg.ingress.subnets_v4, vec![(8, [10, 0, 0, 0])]);
        assert_eq!(cfg.egress.ipv4, vec![[1, 1, 1, 1]]);
        assert_eq!(cfg.egress.subnets_v4, vec![(12, [172, 16, 0, 0])]);
    }

    #[test]
    fn defaults_to_enforce_mode_when_unspecified() {
        let cfg = parse(
            r#"[[egress.ip]]
address = "1.1.1.1""#,
        )
        .unwrap();
        assert_eq!(cfg.mode, ModeConfig::Enforce);
    }

    #[test]
    fn cgroup_path_defaults_to_none() {
        let cfg = parse(
            r#"[[egress.ip]]
address = "1.1.1.1""#,
        )
        .unwrap();
        assert_eq!(cfg.cgroup_path, None);
    }

    #[test]
    fn rejects_a_config_with_no_allowlist_entries_at_all() {
        let err = parse("[global]\nmode = \"enforce\"\n").unwrap_err();
        assert!(err.to_string().contains("no ingress or egress allowlist"));
    }

    #[test]
    fn rejects_url_entries_with_an_actionable_message() {
        let err = parse(
            r#"[[egress.url]]
hostname = "api.github.com""#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not currently enforced"));
    }

    #[test]
    fn rejects_invalid_ip_address() {
        let err = parse(
            r#"[[ingress.ip]]
address = "not-an-ip""#,
        )
        .unwrap_err();
        // `{:#}` prints the whole anyhow context chain, not just the
        // outermost "resolving [[ingress.*]] entries" frame.
        assert!(format!("{err:#}").contains("invalid IP address"));
    }

    #[test]
    fn rejects_cidr_missing_prefix() {
        let err = parse(
            r#"[[ingress.subnet]]
cidr = "10.0.0.0""#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing a '/prefix-length'"));
    }

    #[test]
    fn rejects_cidr_prefix_out_of_range_for_family() {
        let err = parse(
            r#"[[ingress.subnet]]
cidr = "10.0.0.0/33""#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("only has 32 bits"));
    }

    #[test]
    fn accepts_ipv6_subnet() {
        let cfg = parse(
            r#"[[ingress.subnet]]
cidr = "fd00::/8""#,
        )
        .unwrap();
        assert_eq!(cfg.ingress.subnets_v6.len(), 1);
        assert_eq!(cfg.ingress.subnets_v6[0].0, 8);
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(parse("this is not [valid toml").is_err());
    }
}
