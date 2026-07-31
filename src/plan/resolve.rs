//! Turning layered configuration plus CLI overrides into an immutable `ScanPlan`.
//!
//! Every value records where it came from, which is what lets `scanr plan` answer
//! "why is concurrency 512?" without the user reading the code.

use std::collections::BTreeSet;
use std::io::BufRead;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::builtin::{
    DEFAULT_DIRECT_PROFILE, DEFAULT_OUTPUT_DIR, DEFAULT_PROXY_PROFILE, DEFAULT_TRANSPORT,
    builtin_profile, builtin_profile_names,
};
use crate::config::error::{ConfigError, suggest};
use crate::config::expand_home;
use crate::config::raw::{Layered, Origin, RawProfile};
use crate::diag::HostFacts;
use crate::net::ports::PortSummary;
use crate::net::target::{DEFAULT_MAX_TARGETS, TargetSet, TargetSpec};
use crate::net::{Target, parse_ports, parse_target};
use crate::plan::permute::random_seed;
use crate::plan::types::*;
use crate::units::parse_duration;

/// CLI values permitted to override configuration. Deliberately an allowlist — this is
/// what keeps a run reproducible from a file rather than from shell history.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub profile: Option<String>,
    pub transport: Option<String>,
    pub targets: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    /// Explicit `host:port` pairs, from `scanr output remainder`. Mutually exclusive
    /// with targets/ports, which describe a matrix.
    pub pairs: Option<Vec<String>>,
    /// The scan this one continues. Normally picked up from the `# resumed-from:`
    /// directive in a remainder, so the pipe carries it; settable by hand for a list
    /// that has been edited or reassembled.
    pub resumed_from: Option<String>,
    pub exclude: Option<Vec<String>>,
    pub concurrency: Option<u32>,
    pub rate: Option<u32>,
    pub connect_timeout: Option<Duration>,
    pub retries: Option<u32>,
    pub dns: Option<DnsMode>,
    pub output_dir: Option<PathBuf>,
    pub seed: Option<u64>,
    pub open_only: Option<bool>,
    /// Write the record as framed gzip. Off unless asked for: a plain record is
    /// greppable, and that is worth keeping as the default.
    pub compress: Option<bool>,
    /// Collapse repetitive outcomes into spans. Off unless asked for: it trades
    /// per-probe timestamps for size.
    pub spans: Option<bool>,
    pub allow_large_range: bool,
}

/// The ad-hoc scan name used when no named scan was selected.
pub const ADHOC_SCAN_NAME: &str = "(ad-hoc)";

pub fn resolve(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    facts: &HostFacts,
) -> Result<ScanPlan, ConfigError> {
    let mut prov = Provenance::default();
    let mut warnings = Vec::new();

    check_scan_exists(files, scan_name)?;

    let description = scan_name
        .and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.description.clone())))
        .map(|(d, _)| d);

    // ── transport ───────────────────────────────────────────────────────────
    let (transport_name, transport_origin) = pick_name(
        files,
        scan_name,
        ov.transport.clone(),
        |c, n| c.scans.get(n).and_then(|s| s.transport.clone()),
        |c| c.defaults.transport.clone(),
        DEFAULT_TRANSPORT,
    );
    prov.set("transport", transport_origin);
    let transport = resolve_transport(files, &transport_name)?;

    let (profile, base) = resolve_profile(files, scan_name, ov, &transport, &mut prov)?;

    let timing = resolve_timing(files, scan_name, &profile, &base, ov, &mut prov)?;

    let (dns_requested, dns_effective) =
        resolve_dns(files, scan_name, &transport, &transport_name, ov, &mut prov)?;

    // ── targets and ports ───────────────────────────────────────────────────
    // A pair scan names exact endpoints and bypasses matrix expansion. Targets and ports
    // are still derived from it, so everything downstream — DNS, the record, the plan
    // display — works unchanged.
    let (explicit_pairs, resumed_from) = resolve_pairs(ov)?;

    let (raw_targets, ports, target_specs, exclude_specs, port_spec_override) =
        match &explicit_pairs {
            Some(pairs) => {
                let mut seen = BTreeSet::new();
                let targets: Vec<Target> = pairs
                    .iter()
                    .filter(|(t, _)| seen.insert(t.to_string()))
                    .map(|(t, _)| t.clone())
                    .collect();
                let mut ports: Vec<u16> = pairs.iter().map(|(_, p)| *p).collect();
                ports.sort_unstable();
                ports.dedup();
                (
                    targets,
                    ports,
                    vec![format!("{} explicit host:port pairs", pairs.len())],
                    Vec::new(),
                    Some("(explicit pairs)".to_string()),
                )
            }
            None => {
                let (target_set, target_specs) = resolve_targets(files, scan_name, ov)?;
                let exclude_specs: Vec<String> =
                    target_set.exclude.iter().map(|s| s.to_string()).collect();
                let limit = if ov.allow_large_range {
                    u64::MAX
                } else {
                    DEFAULT_MAX_TARGETS
                };
                let raw_targets = target_set
                    .expand(ov.allow_large_range, limit)
                    .map_err(|e| ConfigError::new(e.to_string()))?;
                let ports = resolve_ports(files, scan_name, ov)?;
                if ports.is_empty() {
                    return Err(ConfigError::new("no ports selected"));
                }
                (raw_targets, ports, target_specs, exclude_specs, None)
            }
        };

    // ── hostname handling ───────────────────────────────────────────────────
    let (targets, resolved_hosts) = apply_dns(raw_targets, dns_effective, &mut warnings)?;
    if targets.is_empty() {
        return Err(ConfigError::new("no targets selected")
            .help("check that the target set expands to at least one address after exclusions"));
    }

    // ── remaining scalars ───────────────────────────────────────────────────
    let output_dir = resolve_output_dir(files, scan_name, ov, &mut prov);
    let open_only = resolve_open_only(files, scan_name, ov, &mut prov);
    let compress = resolve_compress(files, scan_name, ov, &mut prov);
    let spans = resolve_spans(files, scan_name, ov, &mut prov);
    let seed = resolve_seed(ov, &mut prov);

    let port_spec = port_spec_override.unwrap_or_else(|| PortSummary(&ports).to_string());

    let mut plan = ScanPlan {
        scan_name: scan_name.unwrap_or(ADHOC_SCAN_NAME).to_string(),
        description,
        profile,
        transport,
        timing,
        dns_requested,
        dns_effective,
        targets,
        ports,
        pairs: explicit_pairs,
        resumed_from,
        target_specs,
        exclude_specs,
        port_spec,
        resolved_hosts,
        seed,
        open_only,
        compress,
        spans,
        output_dir,
        provenance: prov,
        warnings,
    };
    add_operational_warnings(&mut plan, facts);
    Ok(plan)
}

/// Reject an unknown scan name early, with a suggestion when one is close.
fn check_scan_exists(files: &Layered, scan_name: Option<&str>) -> Result<(), ConfigError> {
    if let Some(name) = scan_name {
        let known = files.scan_names();
        if !known.contains(&name.to_string()) {
            let mut e = ConfigError::new(format!("no such scan: `{name}`"));
            if let Some(s) = suggest(name, known.iter().map(|s| s.as_str())) {
                e = e.help(format!("did you mean `{s}`?"));
            } else if known.is_empty() {
                e = e.help(
                    "no scans are defined.\n\
                     run `scanr config init` to create an annotated scanr.toml,\n\
                     or scan directly:  scanr run --targets 10.0.0.0/24 --ports 22,80,443",
                );
            } else {
                e = e.help(format!("defined scans: {}", known.join(", ")));
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Pick the profile and its numeric floor.
///
/// When nothing selects one, follow the transport: a proxied scan wants the conservative
/// proxy defaults, a direct one does not want their rate limit.
fn resolve_profile(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    transport: &ResolvedTransport,
    prov: &mut Provenance,
) -> Result<(String, crate::config::builtin::BuiltinProfile), ConfigError> {
    // When nothing selects a profile, follow the transport: a proxied scan wants the
    // conservative proxy defaults, a direct one does not want their rate limit.
    let default_profile = if transport.supports_remote_dns() {
        DEFAULT_PROXY_PROFILE
    } else {
        DEFAULT_DIRECT_PROFILE
    };
    let (profile, profile_origin) = pick_name(
        files,
        scan_name,
        ov.profile.clone(),
        |c, n| c.scans.get(n).and_then(|s| s.profile.clone()),
        |c| c.defaults.profile.clone(),
        default_profile,
    );
    prov.set("profile", profile_origin);

    let base = builtin_profile(&profile);
    let user_defined = files.profile_names().contains(&profile);
    if base.is_none() && !user_defined {
        let mut names = files.profile_names();
        names.extend(builtin_profile_names().into_iter().map(String::from));
        let mut e = ConfigError::new(format!("no such profile: `{profile}`"));
        if let Some(s) = suggest(&profile, names.iter().map(|s| s.as_str())) {
            e = e.help(format!("did you mean `{s}`?"));
        } else {
            e = e.help(format!("available profiles: {}", names.join(", ")));
        }
        return Err(e);
    }
    // A user profile with a non-builtin name still needs numeric fallbacks; use the
    // default built-in as the floor so every field has a defined value.
    let base = base.or_else(|| builtin_profile(default_profile)).unwrap();
    Ok((profile, base))
}

/// The six timing knobs, each recording which layer supplied it.
fn resolve_timing(
    files: &Layered,
    scan_name: Option<&str>,
    profile: &str,
    base: &crate::config::builtin::BuiltinProfile,
    ov: &Overrides,
    prov: &mut Provenance,
) -> Result<Timing, ConfigError> {
    let timing = Timing {
        concurrency: field(
            prov,
            "concurrency",
            ov.concurrency,
            timing_source(files, scan_name, profile, |p| p.concurrency),
            base.timing.concurrency,
            profile,
        ),
        rate: field(
            prov,
            "rate",
            ov.rate,
            timing_source(files, scan_name, profile, |p| p.rate),
            base.timing.rate,
            profile,
        ),
        retries: field(
            prov,
            "retries",
            ov.retries,
            timing_source(files, scan_name, profile, |p| p.retries),
            base.timing.retries,
            profile,
        ),
        proxy_connect_timeout: duration_field(
            prov,
            "proxy_connect_timeout",
            None,
            timing_source(files, scan_name, profile, |p| {
                p.proxy_connect_timeout.clone()
            }),
            base.timing.proxy_connect_timeout,
            profile,
        )?,
        handshake_timeout: duration_field(
            prov,
            "handshake_timeout",
            None,
            timing_source(files, scan_name, profile, |p| p.handshake_timeout.clone()),
            base.timing.handshake_timeout,
            profile,
        )?,
        connect_timeout: duration_field(
            prov,
            "connect_timeout",
            ov.connect_timeout,
            timing_source(files, scan_name, profile, |p| p.connect_timeout.clone()),
            base.timing.connect_timeout,
            profile,
        )?,
        retry_delay: duration_field(
            prov,
            "retry_delay",
            None,
            timing_source(files, scan_name, profile, |p| p.retry_delay.clone()),
            base.timing.retry_delay,
            profile,
        )?,
    };
    Ok(timing)
}

/// The requested DNS mode and what it resolves to for this transport (D15).
fn resolve_dns(
    files: &Layered,
    scan_name: Option<&str>,
    transport: &ResolvedTransport,
    transport_name: &str,
    ov: &Overrides,
    prov: &mut Provenance,
) -> Result<(DnsMode, DnsMode), ConfigError> {
    let (dns_requested, dns_origin) = match ov.dns {
        Some(m) => (m, Origin::Cli),
        None => {
            let from_scan =
                scan_name.and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.dns.clone())));
            let from_transport =
                files.pick(|c| c.transports.get(transport_name).and_then(|t| t.dns.clone()));
            match from_scan.or(from_transport) {
                Some((s, path)) => {
                    let m = DnsMode::parse(&s).ok_or_else(|| {
                        ConfigError::new(format!("unknown dns mode `{s}`")).at(path.clone())
                    })?;
                    (m, Origin::Transport(transport_name.to_string(), path))
                }
                None => (DnsMode::Auto, Origin::Default),
            }
        }
    };
    prov.set("dns", dns_origin);

    let dns_effective = match dns_requested {
        DnsMode::Auto => {
            if transport.supports_remote_dns() {
                DnsMode::Transport
            } else {
                DnsMode::Local
            }
        }
        DnsMode::Transport if !transport.supports_remote_dns() => {
            return Err(ConfigError::new(format!(
                "dns = \"transport\" requires a transport that resolves remotely, but `{}` is {}",
                transport.name,
                transport.type_name()
            ))
            .help("use dns = \"local\", or select a socks5 transport"));
        }
        other => other,
    };
    Ok((dns_requested, dns_effective))
}

fn resolve_output_dir(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    prov: &mut Provenance,
) -> PathBuf {
    match &ov.output_dir {
        Some(p) => {
            prov.set("output_dir", Origin::Cli);
            p.clone()
        }
        None => {
            let from_scan = scan_name
                .and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.output_dir.clone())));
            match from_scan.or_else(|| files.pick(|c| c.defaults.output_dir.clone())) {
                Some((d, path)) => {
                    prov.set("output_dir", Origin::Defaults(path));
                    expand_home(&d)
                }
                None => {
                    prov.set("output_dir", Origin::Default);
                    PathBuf::from(DEFAULT_OUTPUT_DIR)
                }
            }
        }
    }
}

/// Framed gzip for the record. On by default: a full-size record is ~11x its own
/// information content, and `zcat`, `zless` and every `scanr output` command read a
/// compressed one unchanged. `--no-compress` when you want to grep the file directly.
fn resolve_compress(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    prov: &mut Provenance,
) -> bool {
    match ov.compress {
        Some(v) => {
            prov.set("compress", Origin::Cli);
            v
        }
        None => {
            let from_scan =
                scan_name.and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.compress)));
            match from_scan.or_else(|| files.pick(|c| c.defaults.compress)) {
                Some((v, path)) => {
                    prov.set("compress", Origin::Defaults(path));
                    v
                }
                None => {
                    prov.set("compress", Origin::Default);
                    true
                }
            }
        }
    }
}

/// Collapsing bulk outcomes into spans. On by default: it takes a million-probe record
/// from 391 MB to 2.6 KB, and what it drops is the per-probe timestamp and exact timing
/// of results that all said the same thing. `--no-spans` keeps a row per probe.
fn resolve_spans(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    prov: &mut Provenance,
) -> bool {
    match ov.spans {
        Some(v) => {
            prov.set("spans", Origin::Cli);
            v
        }
        None => {
            let from_scan =
                scan_name.and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.spans)));
            match from_scan.or_else(|| files.pick(|c| c.defaults.spans)) {
                Some((v, path)) => {
                    prov.set("spans", Origin::Defaults(path));
                    v
                }
                None => {
                    prov.set("spans", Origin::Default);
                    true
                }
            }
        }
    }
}

fn resolve_open_only(
    files: &Layered,
    scan_name: Option<&str>,
    ov: &Overrides,
    prov: &mut Provenance,
) -> bool {
    match ov.open_only {
        Some(v) => {
            prov.set("open_only", Origin::Cli);
            v
        }
        None => {
            let from_scan =
                scan_name.and_then(|n| files.pick(|c| c.scans.get(n).and_then(|s| s.open_only)));
            match from_scan.or_else(|| files.pick(|c| c.defaults.open_only)) {
                Some((v, path)) => {
                    prov.set("open_only", Origin::Defaults(path));
                    v
                }
                None => {
                    prov.set("open_only", Origin::Default);
                    true
                }
            }
        }
    }
}

fn resolve_seed(ov: &Overrides, prov: &mut Provenance) -> u64 {
    match ov.seed {
        Some(s) => {
            prov.set("seed", Origin::Cli);
            s
        }
        None => {
            prov.set("seed", Origin::Default);
            random_seed()
        }
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Resolve a name-valued setting: CLI, then scan, then `[defaults]`, then compiled.
fn pick_name(
    files: &Layered,
    scan: Option<&str>,
    cli: Option<String>,
    from_scan: fn(&crate::config::raw::RawConfig, &str) -> Option<String>,
    from_defaults: fn(&crate::config::raw::RawConfig) -> Option<String>,
    fallback: &str,
) -> (String, Origin) {
    if let Some(v) = cli {
        return (v, Origin::Cli);
    }
    if let Some(n) = scan
        && let Some((v, path)) = files.pick(|c| from_scan(c, n))
    {
        return (v, Origin::Scan(n.to_string(), path));
    }
    if let Some((v, path)) = files.pick(from_defaults) {
        return (v, Origin::Defaults(path));
    }
    (fallback.to_string(), Origin::Default)
}

/// Look for a timing field on the scan first, then the profile.
fn timing_source<T>(
    files: &Layered,
    scan: Option<&str>,
    profile: &str,
    get: impl Fn(&RawProfile) -> Option<T> + Copy,
) -> Option<(T, Origin)> {
    if let Some(s) = scan
        && let Some((v, path)) = files.pick(|c| c.scans.get(s).and_then(|sc| get(&sc.timing)))
    {
        return Some((v, Origin::Scan(s.to_string(), path)));
    }
    if let Some((v, path)) = files.pick(|c| c.profiles.get(profile).and_then(get)) {
        return Some((v, Origin::Profile(profile.to_string(), path)));
    }
    None
}

fn field<T>(
    prov: &mut Provenance,
    name: &str,
    cli: Option<T>,
    from_config: Option<(T, Origin)>,
    builtin: T,
    profile: &str,
) -> T {
    if let Some(v) = cli {
        prov.set(name, Origin::Cli);
        return v;
    }
    if let Some((v, o)) = from_config {
        prov.set(name, o);
        return v;
    }
    prov.set(name, Origin::BuiltinProfile(profile.to_string()));
    builtin
}

fn duration_field(
    prov: &mut Provenance,
    name: &str,
    cli: Option<Duration>,
    from_config: Option<(String, Origin)>,
    builtin: Duration,
    profile: &str,
) -> Result<Duration, ConfigError> {
    if let Some(v) = cli {
        prov.set(name, Origin::Cli);
        return Ok(v);
    }
    if let Some((s, o)) = from_config {
        let d = parse_duration(&s).map_err(|e| {
            let mut err = ConfigError::new(format!("{name}: {e}"));
            if let Some(p) = o.file() {
                err = err.at(p.to_path_buf());
            }
            err
        })?;
        prov.set(name, o);
        return Ok(d);
    }
    prov.set(name, Origin::BuiltinProfile(profile.to_string()));
    Ok(builtin)
}

fn resolve_transport(files: &Layered, name: &str) -> Result<ResolvedTransport, ConfigError> {
    let found = files.pick(|c| c.transports.get(name).cloned());
    let Some((raw, path)) = found else {
        if name == DEFAULT_TRANSPORT {
            // The direct transport always exists, defined or not.
            return Ok(ResolvedTransport {
                name: name.to_string(),
                kind: TransportKind::Direct,
                fidelity: Fidelity::Full,
            });
        }
        let known = files.transport_names();
        let mut e = ConfigError::new(format!("no such transport: `{name}`"));
        if let Some(s) = suggest(name, known.iter().map(|s| s.as_str())) {
            e = e.help(format!("did you mean `{s}`?"));
        } else if known.is_empty() {
            e = e.help("no transports are defined; `direct` is always available");
        } else {
            e = e.help(format!("defined transports: {}", known.join(", ")));
        }
        return Err(e);
    };

    match raw.kind.as_deref() {
        Some("direct") | None => Ok(ResolvedTransport {
            name: name.to_string(),
            kind: TransportKind::Direct,
            fidelity: Fidelity::Full,
        }),
        Some("socks5") => {
            let addr_s = raw.address.clone().ok_or_else(|| {
                ConfigError::new(format!("socks5 transport `{name}` is missing `address`"))
                    .at(path.clone())
            })?;
            let address: SocketAddr = addr_s.parse().map_err(|_| {
                ConfigError::new(format!("`{addr_s}` is not a valid host:port")).at(path.clone())
            })?;
            let password = load_password(&raw, name)?;
            if password.is_some() && raw.username.is_none() {
                return Err(ConfigError::new(format!(
                    "transport `{name}` supplies a password but no `username`"
                ))
                .at(path.clone()));
            }
            // Unknown unless the operator recorded a measurement from
            // `scanr transport test` (D8).
            let fidelity = match raw.fidelity.as_deref() {
                None => Fidelity::Unknown,
                Some(f) => Fidelity::parse(f).ok_or_else(|| {
                    ConfigError::new(format!("unknown fidelity `{f}` for transport `{name}`"))
                        .at(path.clone())
                        .help(format!(
                            "expected one of: {}\nrun `scanr transport test {name}` to measure it",
                            Fidelity::DECLARABLE.join(", ")
                        ))
                })?,
            };
            Ok(ResolvedTransport {
                name: name.to_string(),
                kind: TransportKind::Socks5 {
                    address,
                    username: raw.username.clone(),
                    password,
                },
                fidelity,
            })
        }
        Some(other) => {
            Err(ConfigError::new(format!("unknown transport type `{other}` for `{name}`")).at(path))
        }
    }
}

fn load_password(
    raw: &crate::config::raw::RawTransport,
    name: &str,
) -> Result<Option<Secret>, ConfigError> {
    if let Some(var) = &raw.password_env {
        return match std::env::var(var) {
            Ok(v) if !v.is_empty() => Ok(Some(Secret::new(v, Origin::Env(var.clone())))),
            _ => Err(ConfigError::new(format!(
                "transport `{name}` needs the password in ${var}, which is unset or empty"
            ))
            .help(format!(
                "export {var}=... before running, or use password_file"
            ))),
        };
    }
    if let Some(f) = &raw.password_file {
        let path = expand_home(f);
        let v = std::fs::read_to_string(&path).map_err(|e| {
            ConfigError::new(format!("cannot read password_file {}: {e}", path.display()))
        })?;
        return Ok(Some(Secret::new(
            v.trim_end_matches(['\n', '\r']).to_string(),
            Origin::Env(format!("file:{}", path.display())),
        )));
    }
    Ok(None)
}

/// A target or pair list, plus anything its comment lines declared.
#[derive(Debug, Default)]
struct ListInput {
    lines: Vec<String>,
    /// From a `# resumed-from: <scan-id>` directive, which `scanr output remainder`
    /// writes so that piping it into `--pairs` carries the link to the original scan
    /// without the user having to pass it.
    resumed_from: Option<String>,
}

impl ListInput {
    fn push(&mut self, line: &str) {
        if let Some(id) = parse_resumed_from(line) {
            // First wins: concatenating two remainders makes the second's origin
            // ambiguous, and silently keeping the last would be a worse guess.
            self.resumed_from.get_or_insert(id);
        }
        let l = line.split('#').next().unwrap_or("").trim();
        if !l.is_empty() {
            self.lines.push(l.to_string());
        }
    }
}

/// Recognise `# resumed-from: <scan-id>` in a list's comment lines.
fn parse_resumed_from(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix('#')?.trim();
    let id = rest.strip_prefix("resumed-from:")?.trim();
    // Scan ids are hex; refuse anything else rather than record a guess.
    (!id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit())).then(|| id.to_string())
}

/// Expand one `--targets` argument: `-` for stdin, an existing file path, or a
/// comma-separated list of specs.
fn expand_target_argument(arg: &str) -> Result<ListInput, ConfigError> {
    if arg == "-" {
        let stdin = std::io::stdin();
        let mut out = ListInput::default();
        for line in stdin.lock().lines() {
            let line = line.map_err(|e| ConfigError::new(format!("reading stdin: {e}")))?;
            out.push(&line);
        }
        return Ok(out);
    }
    let path = expand_home(arg);
    if path.is_file() {
        return read_target_file(&path);
    }
    Ok(ListInput {
        lines: arg
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        resumed_from: None,
    })
}

fn read_target_file(path: &std::path::Path) -> Result<ListInput, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        ConfigError::new(format!("cannot read target file {}: {e}", path.display()))
    })?;
    let mut out = ListInput::default();
    for line in text.lines() {
        out.push(line);
    }
    Ok(out)
}

fn resolve_targets(
    files: &Layered,
    scan: Option<&str>,
    ov: &Overrides,
) -> Result<(TargetSet, Vec<String>), ConfigError> {
    let mut set = TargetSet::default();
    let mut specs = Vec::new();

    let items: Vec<String> = if let Some(t) = &ov.targets {
        let mut v = Vec::new();
        for arg in t {
            v.extend(expand_target_argument(arg)?.lines);
        }
        v
    } else if let Some(n) = scan {
        files
            .pick(|c| c.scans.get(n).and_then(|s| s.targets.clone()))
            .map(|(l, _)| l.items())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if items.is_empty() {
        return Err(ConfigError::new("no targets specified").help(
            "pass --targets, or define `targets` on the scan\n\
             examples:  --targets 10.0.0.0/24   --targets hosts.txt   --targets -",
        ));
    }

    let defined = files.target_set_names();
    for item in items {
        if defined.contains(&item) {
            // A named set: pull its include/exclude/file from the highest layer.
            let (raw, _) = files
                .pick(|c| c.targets.get(&item).cloned())
                .expect("name came from the defined set");
            if let Some(inc) = &raw.include {
                for s in inc.items() {
                    set.include.push(parse_spec(&s)?);
                    specs.push(s);
                }
            }
            if let Some(f) = &raw.file {
                for s in read_target_file(&expand_home(f))?.lines {
                    set.include.push(parse_spec(&s)?);
                }
                specs.push(format!("file:{f}"));
            }
            if let Some(exc) = &raw.exclude {
                for s in exc.items() {
                    set.exclude.push(parse_spec(&s)?);
                }
            }
        } else {
            set.include.push(parse_spec(&item)?);
            specs.push(item);
        }
    }

    // Scan-level and CLI exclusions apply on top of any set-level ones.
    if let Some(n) = scan
        && let Some((l, _)) = files.pick(|c| c.scans.get(n).and_then(|s| s.exclude.clone()))
    {
        for s in l.items() {
            set.exclude.push(parse_spec(&s)?);
        }
    }
    if let Some(ex) = &ov.exclude {
        for arg in ex {
            for s in expand_target_argument(arg)?.lines {
                set.exclude.push(parse_spec(&s)?);
            }
        }
    }

    Ok((set, specs))
}

/// Explicit endpoints, plus the scan they were derived from if the input declared one.
type ResolvedPairs = (Option<Vec<(Target, u16)>>, Option<String>);

/// Read explicit `host:port` pairs, if any were supplied, along with the scan they were
/// derived from when the input declared one.
fn resolve_pairs(ov: &Overrides) -> Result<ResolvedPairs, ConfigError> {
    let Some(args) = &ov.pairs else {
        return Ok((None, ov.resumed_from.clone()));
    };
    if ov.targets.is_some() || ov.ports.is_some() {
        return Err(
            ConfigError::new("--pairs cannot be combined with --targets or --ports").help(
                "--pairs names exact endpoints; --targets and --ports describe a matrix.\n\
                 Use one or the other.",
            ),
        );
    }

    let mut lines = Vec::new();
    // An explicit --resumed-from beats a directive in the input: the user is the more
    // deliberate source, and it lets a hand-edited list keep its provenance.
    let mut resumed_from = ov.resumed_from.clone();
    for arg in args {
        let input = expand_target_argument(arg)?;
        lines.extend(input.lines);
        if resumed_from.is_none() {
            resumed_from = input.resumed_from;
        }
    }
    let mut out = Vec::with_capacity(lines.len());
    for line in &lines {
        let (spec, port) =
            crate::net::target::parse_pair(line).map_err(|e| ConfigError::new(e.to_string()))?;
        let target = match spec {
            TargetSpec::Addr(a) => Target::Addr(a),
            TargetSpec::Host(h) => Target::Host(h),
            // parse_pair rejects ranges and CIDRs, so this cannot be reached.
            other => {
                return Err(ConfigError::new(format!(
                    "`{other}` names more than one host; a pair must name exactly one"
                )));
            }
        };
        out.push((target, port));
    }
    if out.is_empty() {
        return Err(ConfigError::new("--pairs produced no endpoints")
            .help("the input was empty — a scan that completed leaves no remainder"));
    }
    // Deduplicate while preserving order, so concatenated inputs are harmless.
    let mut seen = BTreeSet::new();
    out.retain(|(t, p)| seen.insert((t.to_string(), *p)));
    Ok((Some(out), resumed_from))
}

fn parse_spec(s: &str) -> Result<TargetSpec, ConfigError> {
    parse_target(s).map_err(|e| ConfigError::new(e.to_string()))
}

fn resolve_ports(
    files: &Layered,
    scan: Option<&str>,
    ov: &Overrides,
) -> Result<Vec<u16>, ConfigError> {
    let items: Vec<String> = if let Some(p) = &ov.ports {
        p.clone()
    } else if let Some(n) = scan {
        files
            .pick(|c| c.scans.get(n).and_then(|s| s.ports.clone()))
            .map(|(l, _)| l.items())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    if items.is_empty() {
        return Err(ConfigError::new("no ports specified").help(
            "pass --ports, or define `ports` on the scan\n\
             examples:  --ports 22,80,443   --ports 1-1024   --ports all",
        ));
    }

    let defined = files.port_set_names();
    let mut all = BTreeSet::new();
    for item in items {
        if defined.contains(&item) {
            let (raw, _) = files
                .pick(|c| c.ports.get(&item).cloned())
                .expect("name came from the defined set");
            if let Some(l) = &raw.ports {
                for s in l.items() {
                    all.extend(parse_ports(&s).map_err(|e| ConfigError::new(e.to_string()))?);
                }
            }
        } else {
            all.extend(parse_ports(&item).map_err(|e| ConfigError::new(e.to_string()))?);
        }
    }
    Ok(all.into_iter().collect())
}

/// Apply the effective DNS mode to the expanded target list.
fn apply_dns(
    raw: Vec<Target>,
    mode: DnsMode,
    warnings: &mut Vec<PlanWarning>,
) -> Result<(Vec<Target>, Vec<ResolvedHost>), ConfigError> {
    let hostnames: Vec<String> = raw
        .iter()
        .filter_map(|t| match t {
            Target::Host(h) => Some(h.clone()),
            _ => None,
        })
        .collect();

    if hostnames.is_empty() {
        return Ok((raw, Vec::new()));
    }

    match mode {
        DnsMode::Disabled => {
            let shown: Vec<&str> = hostnames.iter().take(3).map(|s| s.as_str()).collect();
            Err(ConfigError::new(format!(
                "dns is disabled but {} hostname target(s) were given: {}{}",
                hostnames.len(),
                shown.join(", "),
                if hostnames.len() > 3 { ", ..." } else { "" }
            ))
            .help("use --dns local or --dns transport, or give IP addresses"))
        }
        // Hand hostnames to the proxy untouched. resolved_address will be null in the
        // record, because the SOCKS5 reply carries the proxy's bound address (D15).
        DnsMode::Transport => Ok((raw, Vec::new())),
        DnsMode::Local | DnsMode::Auto => {
            let mut out = Vec::new();
            let mut resolved = Vec::new();
            let mut seen = BTreeSet::new();
            for t in raw {
                match t {
                    Target::Addr(a) => {
                        if seen.insert(a) {
                            out.push(Target::Addr(a));
                        }
                    }
                    Target::Host(h) => {
                        let addrs = resolve_host(&h);
                        if addrs.is_empty() {
                            warnings.push(PlanWarning {
                                code: "dns_failure",
                                message: format!("`{h}` did not resolve; it will not be probed"),
                            });
                        }
                        for a in &addrs {
                            if seen.insert(*a) {
                                out.push(Target::Addr(*a));
                            }
                        }
                        resolved.push(ResolvedHost {
                            hostname: h,
                            addresses: addrs,
                        });
                    }
                }
            }
            Ok((out, resolved))
        }
    }
}

fn resolve_host(host: &str) -> Vec<IpAddr> {
    // Port 0 is a placeholder; we only want the addresses.
    match (host, 0u16).to_socket_addrs() {
        Ok(it) => {
            let mut v: Vec<IpAddr> = it.map(|s| s.ip()).collect();
            v.sort();
            v.dedup();
            v
        }
        Err(_) => Vec::new(),
    }
}

/// Warnings that depend on the host we are running on, added after the plan is built.
fn add_operational_warnings(plan: &mut ScanPlan, facts: &HostFacts) {
    if let TransportKind::Socks5 { address, .. } = &plan.transport.kind {
        match plan.transport.fidelity {
            Fidelity::Unknown => plan.warnings.push(PlanWarning {
                code: "fidelity_unknown",
                message: format!(
                    "result fidelity of proxy `{}` has not been measured; \
                     closed and filtered may be indistinguishable\n\
                     run: scanr transport test {}",
                    plan.transport.name, plan.transport.name
                ),
            }),
            Fidelity::OpenOnly => plan.warnings.push(PlanWarning {
                code: "fidelity_open_only",
                message: format!(
                    "proxy `{}` is recorded as open_only: it cannot distinguish a closed \
                     port from a filtered one, so non-open results will be `error`",
                    plan.transport.name
                ),
            }),
            Fidelity::Full => {}
        }

        let remote = !address.ip().is_loopback();
        if let Some(ceiling) = facts.sustained_rate_ceiling(remote) {
            let effective = if plan.timing.rate == 0 {
                u32::MAX
            } else {
                plan.timing.rate
            };
            if effective > ceiling {
                plan.warnings.push(PlanWarning {
                    code: "ephemeral_budget",
                    message: format!(
                        "configured rate ({}) exceeds the sustained ephemeral-port ceiling \
                         of ~{ceiling}/s for a remote proxy\n\
                         scanr closes probe sockets with SO_LINGER to avoid TIME_WAIT, which \
                         lifts this substantially, but expect EADDRNOTAVAIL if the proxy is slow",
                        if plan.timing.rate == 0 {
                            "unlimited".to_string()
                        } else {
                            plan.timing.rate.to_string()
                        }
                    ),
                });
            }
        }
    }

    if plan.dns_requested == DnsMode::Auto && !plan.resolved_hosts.is_empty()
        || (plan.dns_requested == DnsMode::Auto
            && plan.dns_effective == DnsMode::Transport
            && plan.targets.iter().any(|t| matches!(t, Target::Host(_))))
    {
        plan.warnings.push(PlanWarning {
            code: "dns_mode_auto",
            message: format!(
                "dns is `auto`, resolving {} for this transport; \
                 switching transports would change how these hostnames resolve, \
                 and therefore possibly the results",
                plan.dns_effective
            ),
        });
    }

    if let Some(nofile) = facts.rlimit_nofile {
        let needed = plan.timing.concurrency as u64 + 64;
        if needed > nofile {
            plan.warnings.push(PlanWarning {
                code: "fd_budget",
                message: format!(
                    "concurrency {} needs ~{needed} file descriptors but RLIMIT_NOFILE is {nofile}\n\
                     run: ulimit -n {}",
                    plan.timing.concurrency,
                    needed.max(4096)
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::raw::{Layer, LoadedFile, RawConfig};

    fn files(pairs: &[(Layer, &str)]) -> Layered {
        let mut files: Vec<LoadedFile> = pairs
            .iter()
            .map(|(layer, text)| LoadedFile {
                layer: *layer,
                path: PathBuf::from(match layer {
                    Layer::User => "/home/u/.config/scanr/config.toml",
                    _ => "scanr.toml",
                }),
                text: text.to_string(),
                config: toml::from_str::<RawConfig>(text).expect("test config parses"),
            })
            .collect();
        files.sort_by_key(|f| f.layer);
        Layered { files }
    }

    fn facts() -> HostFacts {
        HostFacts {
            ephemeral_range: Some((32768, 60999)),
            tcp_tw_reuse: Some(2),
            rlimit_nofile: Some(1_048_576),
        }
    }

    fn plan_of(text: &str, scan: &str, ov: Overrides) -> ScanPlan {
        resolve(&files(&[(Layer::Project, text)]), Some(scan), &ov, &facts())
            .expect("plan should resolve")
    }

    const BASE: &str = r#"
version = 1
[targets.lab]
include = ["10.20.30.0/29"]
[ports.web]
ports = ["80", "443"]
[scans.s]
targets = ["lab"]
ports = ["web"]
"#;

    #[test]
    fn resolves_a_named_scan() {
        let p = plan_of(BASE, "s", Overrides::default());
        assert_eq!(p.targets.len(), 8);
        assert_eq!(p.ports, vec![80, 443]);
        assert_eq!(p.probe_count(), 16);
        // BASE has no transport, so it is direct, and the default profile follows it.
        assert_eq!(p.profile, "direct");
    }

    #[test]
    fn default_profile_follows_the_transport() {
        // A direct ad-hoc scan must not inherit the proxy profile's rate limit.
        let p = plan_of(BASE, "s", Overrides::default());
        assert_eq!(p.profile, "direct");
        assert_eq!(p.timing.rate, 0, "direct scans are unlimited by default");

        let proxied = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\n\
             [scans.viaproxy]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let p = plan_of(&proxied, "viaproxy", Overrides::default());
        assert_eq!(p.profile, "proxy");
        assert_eq!(
            p.timing.rate, 400,
            "proxied scans get the conservative ceiling"
        );

        // An explicit profile still wins over the transport-derived default.
        let p = plan_of(
            BASE,
            "s",
            Overrides {
                profile: Some("proxy-careful".into()),
                ..Default::default()
            },
        );
        assert_eq!(p.profile, "proxy-careful");
    }

    #[test]
    fn precedence_runs_builtin_to_cli() {
        // builtin
        let p = plan_of(BASE, "s", Overrides::default());
        assert_eq!(p.timing.concurrency, 512);
        assert_eq!(p.provenance.render("concurrency"), "builtin.direct");

        // profile in config beats builtin
        let with_profile = format!("{BASE}\n[profiles.direct]\nconcurrency = 100\n");
        let p = plan_of(&with_profile, "s", Overrides::default());
        assert_eq!(p.timing.concurrency, 100);
        assert_eq!(p.provenance.render("concurrency"), "profile.direct");

        // scan inline beats profile
        let with_scan = format!(
            "{with_profile}\n[scans.s2]\ntargets=[\"lab\"]\nports=[\"web\"]\nconcurrency = 200\n"
        );
        let p = plan_of(&with_scan, "s2", Overrides::default());
        assert_eq!(p.timing.concurrency, 200);
        assert_eq!(p.provenance.render("concurrency"), "scan.s2");

        // cli beats everything
        let p = plan_of(
            &with_scan,
            "s2",
            Overrides {
                concurrency: Some(7),
                ..Default::default()
            },
        );
        assert_eq!(p.timing.concurrency, 7);
        assert_eq!(p.provenance.render("concurrency"), "cli");
    }

    #[test]
    fn project_layer_beats_user_layer() {
        let l = files(&[
            (
                Layer::User,
                "version = 1\n[profiles.direct]\nconcurrency = 111\n",
            ),
            (
                Layer::Project,
                "version = 1\n[profiles.direct]\nconcurrency = 222\n[scans.s]\ntargets=[\"10.0.0.1\"]\nports=[\"80\"]\n",
            ),
        ]);
        let p = resolve(&l, Some("s"), &Overrides::default(), &facts()).unwrap();
        assert_eq!(p.timing.concurrency, 222);
    }

    #[test]
    fn unknown_scan_suggests_a_near_match() {
        let l = files(&[(Layer::Project, BASE)]);
        let e = resolve(&l, Some("z"), &Overrides::default(), &facts()).unwrap_err();
        assert!(e.message.contains("no such scan"));

        let e2 = resolve(&l, Some("ss"), &Overrides::default(), &facts()).unwrap_err();
        assert_eq!(e2.help.as_deref(), Some("did you mean `s`?"));
    }

    #[test]
    fn adhoc_scan_needs_no_config() {
        let l = files(&[(Layer::Project, "version = 1\n")]);
        let p = resolve(
            &l,
            None,
            &Overrides {
                targets: Some(vec!["10.0.0.0/30".into()]),
                ports: Some(vec!["22,80".into()]),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap();
        assert_eq!(p.scan_name, ADHOC_SCAN_NAME);
        assert_eq!(p.probe_count(), 8);
    }

    #[test]
    fn literal_specs_work_where_set_names_go() {
        let l = files(&[(Layer::Project, "version = 1\n")]);
        let p = resolve(
            &l,
            None,
            &Overrides {
                targets: Some(vec!["10.0.0.1,10.0.0.2".into()]),
                ports: Some(vec!["1-3".into()]),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap();
        assert_eq!(p.targets.len(), 2);
        assert_eq!(p.ports, vec![1, 2, 3]);
    }

    #[test]
    fn exclusions_apply_from_set_and_cli() {
        let text = format!(
            "{BASE}\n[targets.lab2]\ninclude=[\"10.20.30.0/29\"]\nexclude=[\"10.20.30.1\"]\n[scans.s3]\ntargets=[\"lab2\"]\nports=[\"web\"]\n"
        );
        let p = plan_of(&text, "s3", Overrides::default());
        assert_eq!(p.targets.len(), 7);

        let p = plan_of(
            &text,
            "s3",
            Overrides {
                exclude: Some(vec!["10.20.30.2".into()]),
                ..Default::default()
            },
        );
        assert_eq!(p.targets.len(), 6);
    }

    #[test]
    fn dns_auto_becomes_local_for_direct() {
        let p = plan_of(BASE, "s", Overrides::default());
        assert_eq!(p.dns_requested, DnsMode::Auto);
        assert_eq!(p.dns_effective, DnsMode::Local);
    }

    #[test]
    fn dns_auto_becomes_transport_for_socks5() {
        let text = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\n\
             [scans.s4]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let p = plan_of(&text, "s4", Overrides::default());
        assert_eq!(p.dns_effective, DnsMode::Transport);
    }

    #[test]
    fn dns_transport_rejected_for_direct_transport() {
        let l = files(&[(Layer::Project, BASE)]);
        let e = resolve(
            &l,
            Some("s"),
            &Overrides {
                dns: Some(DnsMode::Transport),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap_err();
        assert!(
            e.message
                .contains("requires a transport that resolves remotely"),
            "{}",
            e.message
        );
    }

    #[test]
    fn dns_disabled_rejects_hostname_targets() {
        let l = files(&[(Layer::Project, "version = 1\n")]);
        let e = resolve(
            &l,
            None,
            &Overrides {
                targets: Some(vec!["example.invalid".into()]),
                ports: Some(vec!["80".into()]),
                dns: Some(DnsMode::Disabled),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap_err();
        assert!(e.message.contains("dns is disabled"), "{}", e.message);
    }

    #[test]
    fn transport_dns_keeps_hostnames_unresolved() {
        let text = "version = 1\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\n";
        let l = files(&[(Layer::Project, text)]);
        let p = resolve(
            &l,
            None,
            &Overrides {
                targets: Some(vec!["nonexistent.invalid".into()]),
                ports: Some(vec!["80".into()]),
                transport: Some("p".into()),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap();
        assert!(matches!(p.targets[0], Target::Host(_)));
        assert!(p.resolved_hosts.is_empty());
    }

    #[test]
    fn socks5_without_measured_fidelity_warns() {
        let text = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"10.1.1.1:1080\"\n\
             [scans.s5]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let p = plan_of(&text, "s5", Overrides::default());
        assert!(p.warnings.iter().any(|w| w.code == "fidelity_unknown"));
    }

    #[test]
    fn declared_fidelity_silences_the_unknown_warning() {
        // Measuring is only useful if the result can be recorded (D8).
        let text = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\nfidelity=\"full\"\n\
             [scans.sf]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let p = plan_of(&text, "sf", Overrides::default());
        assert_eq!(p.transport.fidelity, Fidelity::Full);
        assert!(!p.warnings.iter().any(|w| w.code == "fidelity_unknown"));
        assert!(!p.warnings.iter().any(|w| w.code == "fidelity_open_only"));
    }

    #[test]
    fn open_only_fidelity_warns_about_what_results_will_mean() {
        let text = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\nfidelity=\"open_only\"\n\
             [scans.so]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let p = plan_of(&text, "so", Overrides::default());
        let w = p
            .warnings
            .iter()
            .find(|w| w.code == "fidelity_open_only")
            .expect("an open_only proxy should say what its results mean");
        assert!(w.message.contains("cannot distinguish"), "{}", w.message);
    }

    #[test]
    fn bad_fidelity_value_is_rejected_with_the_remedy() {
        let text = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\nfidelity=\"maybe\"\n\
             [scans.sb]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\n"
        );
        let l = files(&[(Layer::Project, &text)]);
        let e = resolve(&l, Some("sb"), &Overrides::default(), &facts()).unwrap_err();
        assert!(
            e.message.contains("unknown fidelity `maybe`"),
            "{}",
            e.message
        );
        assert!(e.help.as_deref().unwrap().contains("transport test"));
    }

    #[test]
    fn remote_proxy_rate_warning_respects_tw_reuse() {
        // tcp_tw_reuse = 2 exempts loopback, so a local proxy gets no warning...
        let local = format!(
            "{BASE}\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\n\
             [scans.s6]\ntargets=[\"lab\"]\nports=[\"web\"]\ntransport=\"p\"\nrate = 5000\n"
        );
        let p = plan_of(&local, "s6", Overrides::default());
        assert!(!p.warnings.iter().any(|w| w.code == "ephemeral_budget"));

        // ...while a remote one does.
        let remote = local.replace("127.0.0.1:1080", "10.9.9.9:1080");
        let p = plan_of(&remote, "s6", Overrides::default());
        assert!(p.warnings.iter().any(|w| w.code == "ephemeral_budget"));
    }

    #[test]
    fn fd_budget_warning_when_concurrency_exceeds_rlimit() {
        let f = HostFacts {
            rlimit_nofile: Some(256),
            ..facts()
        };
        let l = files(&[(Layer::Project, BASE)]);
        let p = resolve(&l, Some("s"), &Overrides::default(), &f).unwrap();
        assert!(p.warnings.iter().any(|w| w.code == "fd_budget"));
    }

    #[test]
    fn seed_is_recorded_and_overridable() {
        let a = plan_of(BASE, "s", Overrides::default());
        let b = plan_of(BASE, "s", Overrides::default());
        assert_ne!(
            a.seed, b.seed,
            "seeds should differ between runs by default"
        );

        let c = plan_of(
            BASE,
            "s",
            Overrides {
                seed: Some(42),
                ..Default::default()
            },
        );
        assert_eq!(c.seed, 42);
        assert_eq!(c.provenance.render("seed"), "cli");
    }

    #[test]
    fn probe_decomposition_covers_the_matrix() {
        let p = plan_of(BASE, "s", Overrides::default());
        let mut seen = BTreeSet::new();
        for i in 0..p.probe_count() {
            let (t, port) = p.probe_at(i);
            assert!(seen.insert((t.to_string(), port)), "duplicate probe at {i}");
        }
        assert_eq!(seen.len(), 16);
    }

    #[test]
    fn missing_targets_gives_actionable_help() {
        let l = files(&[(Layer::Project, "version = 1\n")]);
        let e = resolve(
            &l,
            None,
            &Overrides {
                ports: Some(vec!["80".into()]),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap_err();
        assert!(e.help.as_deref().unwrap().contains("--targets"));
    }

    #[test]
    fn password_env_missing_is_a_clear_error() {
        let text = "version = 1\n[transports.p]\ntype=\"socks5\"\naddress=\"127.0.0.1:1080\"\nusername=\"u\"\npassword_env=\"SCANR_TEST_UNSET_VAR\"\n";
        let l = files(&[(Layer::Project, text)]);
        let e = resolve(
            &l,
            None,
            &Overrides {
                targets: Some(vec!["10.0.0.1".into()]),
                ports: Some(vec!["80".into()]),
                transport: Some("p".into()),
                ..Default::default()
            },
            &facts(),
        )
        .unwrap_err();
        assert!(e.message.contains("SCANR_TEST_UNSET_VAR"), "{}", e.message);
    }

    #[test]
    fn port_sets_and_literals_merge_and_dedupe() {
        let text =
            format!("{BASE}\n[scans.s7]\ntargets=[\"lab\"]\nports=[\"web\", \"443\", \"8080\"]\n");
        let p = plan_of(&text, "s7", Overrides::default());
        assert_eq!(p.ports, vec![80, 443, 8080]);
    }

    #[test]
    fn projected_duration_uses_rate() {
        let text = format!("{BASE}\n[scans.s8]\ntargets=[\"lab\"]\nports=[\"web\"]\nrate = 4\n");
        let p = plan_of(&text, "s8", Overrides::default());
        assert_eq!(p.projected_duration(), Some(Duration::from_secs(4)));

        let text = format!("{BASE}\n[scans.s9]\ntargets=[\"lab\"]\nports=[\"web\"]\nrate = 0\n");
        let p = plan_of(&text, "s9", Overrides::default());
        assert_eq!(p.projected_duration(), None);
    }

    // ── resume provenance ───────────────────────────────────────────────────

    fn pairs_plan(contents: &str, resumed_from: Option<&str>) -> ScanPlan {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("pairs.txt");
        std::fs::write(&path, contents).unwrap();
        let ov = Overrides {
            pairs: Some(vec![path.to_string_lossy().into_owned()]),
            resumed_from: resumed_from.map(String::from),
            ..Default::default()
        };
        resolve(
            &files(&[(Layer::Project, "version = 1\n")]),
            None,
            &ov,
            &facts(),
        )
        .expect("plan should resolve")
    }

    #[test]
    fn recognises_the_resumed_from_directive() {
        for (line, expected) in [
            ("# resumed-from: a7b012c0", Some("a7b012c0")),
            ("#resumed-from:a7b012c0", Some("a7b012c0")),
            ("  #  resumed-from:  a7b012c0  ", Some("a7b012c0")),
            // Not hex, so not a scan id — recording a guess would be worse than nothing.
            ("# resumed-from: not-an-id", None),
            ("# resumed-from:", None),
            ("# just a comment", None),
            ("10.0.0.1:80", None),
        ] {
            assert_eq!(
                parse_resumed_from(line).as_deref(),
                expected,
                "for {line:?}"
            );
        }
    }

    #[test]
    fn a_pair_list_carries_the_scan_it_came_from() {
        let p = pairs_plan(
            "# resumed-from: a7b012c0\n10.0.0.1:80\n10.0.0.2:443\n",
            None,
        );
        assert_eq!(p.resumed_from.as_deref(), Some("a7b012c0"));
        // The directive is provenance, not an endpoint.
        assert_eq!(p.probe_count(), 2);
    }

    #[test]
    fn a_pair_list_without_a_directive_records_no_origin() {
        let p = pairs_plan("10.0.0.1:80\n", None);
        assert_eq!(p.resumed_from, None);
    }

    #[test]
    fn an_explicit_resumed_from_beats_the_directive() {
        // A hand-edited or reassembled list needs a way to say where it really came from.
        let p = pairs_plan("# resumed-from: aaaa\n10.0.0.1:80\n", Some("bbbb"));
        assert_eq!(p.resumed_from.as_deref(), Some("bbbb"));
    }

    #[test]
    fn concatenated_remainders_keep_the_first_origin() {
        // Two remainders piped together have no single origin; guessing the last would
        // be no better than guessing the first, and silence would lose both.
        let p = pairs_plan(
            "# resumed-from: aaaa\n10.0.0.1:80\n# resumed-from: bbbb\n10.0.0.2:80\n",
            None,
        );
        assert_eq!(p.resumed_from.as_deref(), Some("aaaa"));
        assert_eq!(p.probe_count(), 2);
    }
}
