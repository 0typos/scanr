//! The resolved, immutable scan plan.
//!
//! Producing this is the whole point of `scanr plan`: it is testable with zero I/O and
//! it forces the resolution and provenance model to be correct before anything depends
//! on it.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::raw::Origin;
use crate::net::Target;

/// Timing controls. Six knobs, down from the thirteen originally proposed — with one
/// proxy per scan the proxy is the shared resource, so per-target limits were dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    /// In-flight probes. Also the worker thread count — there is no queue.
    pub concurrency: u32,
    /// Launches per second; 0 means unlimited.
    pub rate: u32,
    pub proxy_connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    /// Retries apply to timeouts only (D10).
    pub retries: u32,
    pub retry_delay: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    /// Transport-side when the transport supports it, local otherwise (D15).
    Auto,
    /// Hand hostnames to the proxy unresolved.
    Transport,
    /// Resolve on the scanning host; multi-address names expand to several targets.
    Local,
    /// Reject hostname targets outright.
    Disabled,
}

impl DnsMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(DnsMode::Auto),
            "transport" => Some(DnsMode::Transport),
            "local" => Some(DnsMode::Local),
            "disabled" => Some(DnsMode::Disabled),
            _ => None,
        }
    }

    pub const ALL: &'static [&'static str] = &["auto", "transport", "local", "disabled"];
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DnsMode::Auto => "auto",
            DnsMode::Transport => "transport",
            DnsMode::Local => "local",
            DnsMode::Disabled => "disabled",
        };
        f.write_str(s)
    }
}

/// What a transport can actually distinguish (D8).
///
/// SOCKS5 defines separate reply codes for refused (`0x05`) and unreachable
/// (`0x03`/`0x04`), but many proxies collapse everything into `0x01 general failure`.
/// Rather than fabricate a `closed` we cannot observe, we measure and declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fidelity {
    /// Can distinguish open / closed / filtered.
    Full,
    /// Can only distinguish open from not-open.
    OpenOnly,
    /// Not yet measured. `scanr transport test` resolves this.
    Unknown,
}

impl Fidelity {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Fidelity::Full),
            "open_only" => Some(Fidelity::OpenOnly),
            "unknown" => Some(Fidelity::Unknown),
            _ => None,
        }
    }

    pub const DECLARABLE: &'static [&'static str] = &["full", "open_only"];
}

impl fmt::Display for Fidelity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Fidelity::Full => "full",
            Fidelity::OpenOnly => "open_only",
            Fidelity::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Credentials, kept out of Debug output so they cannot leak through a stray `{:?}`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret {
    value: String,
    pub origin: Option<Origin>,
}

impl Secret {
    pub fn new(value: String, origin: Origin) -> Self {
        Self {
            value,
            origin: Some(origin),
        }
    }

    pub fn expose(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Direct,
    Socks5 {
        address: SocketAddr,
        username: Option<String>,
        password: Option<Secret>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTransport {
    pub name: String,
    pub kind: TransportKind,
    pub fidelity: Fidelity,
}

impl ResolvedTransport {
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            TransportKind::Direct => "direct",
            TransportKind::Socks5 { .. } => "socks5",
        }
    }

    /// Whether hostnames can be handed over unresolved.
    pub fn supports_remote_dns(&self) -> bool {
        matches!(self.kind, TransportKind::Socks5 { .. })
    }

    /// Display form with credentials redacted.
    pub fn describe(&self) -> String {
        match &self.kind {
            TransportKind::Direct => "direct".into(),
            TransportKind::Socks5 {
                address, username, ..
            } => match username {
                Some(u) => format!("socks5 {address} (user {u}, password [redacted])"),
                None => format!("socks5 {address}"),
            },
        }
    }
}

/// Records which layer supplied each resolved field, for `scanr plan` and the
/// `scan_config` JSONL event.
#[derive(Debug, Clone, Default)]
pub struct Provenance(BTreeMap<String, Origin>);

impl Provenance {
    pub fn set(&mut self, field: &str, origin: Origin) {
        self.0.insert(field.to_string(), origin);
    }

    pub fn get(&self, field: &str) -> Option<&Origin> {
        self.0.get(field)
    }

    pub fn render(&self, field: &str) -> String {
        self.0
            .get(field)
            .map(|o| o.to_string())
            .unwrap_or_else(|| "builtin".into())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Origin)> {
        self.0.iter()
    }
}

/// A hostname that was resolved locally, retained for the `target_resolved` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub hostname: String,
    pub addresses: Vec<std::net::IpAddr>,
}

/// The fully resolved plan. Immutable once built.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    pub scan_name: String,
    pub description: Option<String>,
    pub profile: String,
    pub transport: ResolvedTransport,
    pub timing: Timing,
    pub dns_requested: DnsMode,
    pub dns_effective: DnsMode,
    pub targets: Vec<Target>,
    pub ports: Vec<u16>,
    /// An explicit list of host:port pairs, when the scan was built from one rather than
    /// from a target x port matrix.
    ///
    /// This exists so `output remainder` can be exact. Resuming an interrupted scan as a
    /// target list re-probes ports that already completed, because a target list cannot
    /// say "this host, only these ports". The record already contains every probed pair,
    /// so the information is there; only a way to express it was missing.
    pub pairs: Option<Vec<(Target, u16)>>,
    /// Canonical unexpanded specs, for the record. The expanded matrix is never
    /// embedded — a /16 x 1000 is 65M probes.
    pub target_specs: Vec<String>,
    pub exclude_specs: Vec<String>,
    pub port_spec: String,
    pub resolved_hosts: Vec<ResolvedHost>,
    /// The `scan_id` this scan continues, when it was built from another scan's
    /// remainder. Without it a scan split across an interruption leaves two records
    /// that cannot be connected.
    pub resumed_from: Option<String>,
    pub seed: u64,
    pub open_only: bool,
    /// Write the record as framed gzip rather than plain JSONL.
    pub compress: bool,
    /// Collapse repetitive `closed`/`filtered` outcomes into `probe_span` events
    /// instead of one row each.
    pub spans: bool,
    pub output_dir: PathBuf,
    /// Port-label sources for this scan, resolved and layered. Carried on the plan
    /// rather than looked up globally so the record can state where its labels came
    /// from, and so `plan` can show it before the scan is spent.
    pub services: crate::services::ServiceTable,
    pub provenance: Provenance,
    pub warnings: Vec<PlanWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanWarning {
    pub code: &'static str,
    pub message: String,
}

impl ScanPlan {
    /// Total probes. `u64` because a large scan genuinely exceeds `u32`.
    pub fn probe_count(&self) -> u64 {
        match &self.pairs {
            Some(p) => p.len() as u64,
            None => self.targets.len() as u64 * self.ports.len() as u64,
        }
    }

    /// Whether this scan came from an explicit pair list rather than a matrix.
    pub fn is_pair_scan(&self) -> bool {
        self.pairs.is_some()
    }

    /// Decompose a permuted index into (target, port).
    pub fn probe_at(&self, index: u64) -> (&Target, u16) {
        if let Some(pairs) = &self.pairs {
            let (t, p) = &pairs[index as usize];
            return (t, *p);
        }
        let per_target = self.ports.len() as u64;
        let t = (index / per_target) as usize;
        let p = (index % per_target) as usize;
        (&self.targets[t], self.ports[p])
    }

    /// Projected duration at the configured rate, if one is set.
    pub fn projected_duration(&self) -> Option<Duration> {
        if self.timing.rate == 0 {
            return None;
        }
        Some(Duration::from_secs_f64(
            self.probe_count() as f64 / self.timing.rate as f64,
        ))
    }

    /// A minimal direct-transport plan over `127.0.0.1`, for tests that need to drive
    /// `run::execute` rather than the resolver.
    #[cfg(test)]
    pub(crate) fn for_test(ports: Vec<u16>, concurrency: u32) -> Self {
        Self {
            scan_name: "test".into(),
            description: None,
            profile: "direct".into(),
            transport: ResolvedTransport {
                name: "direct".into(),
                kind: TransportKind::Direct,
                fidelity: Fidelity::Full,
            },
            timing: Timing {
                concurrency,
                rate: 0,
                proxy_connect_timeout: Duration::from_millis(200),
                handshake_timeout: Duration::from_millis(200),
                connect_timeout: Duration::from_millis(200),
                retries: 0,
                retry_delay: Duration::ZERO,
            },
            dns_requested: DnsMode::Local,
            dns_effective: DnsMode::Local,
            targets: vec![Target::Addr("127.0.0.1".parse().unwrap())],
            port_spec: ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            ports,
            pairs: None,
            target_specs: vec!["127.0.0.1".into()],
            exclude_specs: vec![],
            resolved_hosts: vec![],
            resumed_from: None,
            seed: 1,
            open_only: false,
            compress: false,
            spans: false,
            output_dir: PathBuf::from("(unused)"),
            services: crate::services::ServiceTable::builtin_only(),
            provenance: Provenance::default(),
            warnings: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_mode_round_trips() {
        for s in DnsMode::ALL {
            assert_eq!(DnsMode::parse(s).unwrap().to_string(), *s);
        }
        assert!(DnsMode::parse("remote").is_none());
    }

    #[test]
    fn secret_never_appears_in_debug() {
        let s = Secret::new("hunter2".into(), Origin::Env("PW".into()));
        assert_eq!(format!("{s:?}"), "Secret([redacted])");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn transport_describe_redacts() {
        let t = ResolvedTransport {
            name: "lab".into(),
            kind: TransportKind::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                username: Some("scanner".into()),
                password: Some(Secret::new("hunter2".into(), Origin::Cli)),
            },
            fidelity: Fidelity::Unknown,
        };
        let d = t.describe();
        assert!(d.contains("[redacted]"), "{d}");
        assert!(!d.contains("hunter2"), "{d}");
        // And the whole struct's Debug must be safe too.
        assert!(!format!("{t:?}").contains("hunter2"));
    }

    #[test]
    fn only_socks5_supports_remote_dns() {
        let direct = ResolvedTransport {
            name: "direct".into(),
            kind: TransportKind::Direct,
            fidelity: Fidelity::Full,
        };
        assert!(!direct.supports_remote_dns());
        assert_eq!(direct.type_name(), "direct");
    }

    #[test]
    fn provenance_defaults_to_builtin() {
        let mut p = Provenance::default();
        assert_eq!(p.render("concurrency"), "builtin");
        p.set("concurrency", Origin::Cli);
        assert_eq!(p.render("concurrency"), "cli");
    }
}
