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
    /// `None` when banner grabbing is off, which is the default.
    pub banner: Option<Banner>,
    /// `None` when the TLS ClientHello probe is off, which is the default (D35).
    pub tls: Option<crate::tls::TlsProbe>,
}

impl Timing {
    /// A plain timing set for tests that need one but do not care what is in it.
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            concurrency: 4,
            rate: 0,
            proxy_connect_timeout: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(1),
            retries: 0,
            retry_delay: Duration::ZERO,
            banner: None,
            tls: None,
        }
    }
}

/// Limits for reading what an open service volunteers.
///
/// One struct rather than a bool beside two numbers, so "off" is a state the type can
/// express and every probe site has one thing to check.
///
/// Fields are private and `new` is the only way in, so the caps below are the type's
/// guarantee rather than an agreement between two modules. A zero timeout is refused
/// there: the kernel reads it as "no timeout", which would park a worker on a silent
/// port forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Banner {
    bytes: u32,
    timeout: Duration,
}

/// Enough for every greeting a real service sends: SSH is ~40 bytes, SMTP ~100.
pub const DEFAULT_BANNER_BYTES: u32 = 1024;

/// A hostile service can send as much as you will read. 4 KiB per open port is the most
/// this will put in a record.
pub const MAX_BANNER_BYTES: u32 = 4096;

/// The ceiling on waiting for a greeting, not the wait itself — see [`Banner::wait_for`].
pub const DEFAULT_BANNER_TIMEOUT: Duration = Duration::from_millis(500);

/// Never wait less than this, however fast the connect was.
const MIN_BANNER_WAIT: Duration = Duration::from_millis(50);

impl Banner {
    pub fn new(bytes: u32, timeout: Duration) -> Result<Self, String> {
        if bytes == 0 || bytes > MAX_BANNER_BYTES {
            return Err(format!(
                "banner_bytes must be between 1 and {MAX_BANNER_BYTES}, got {bytes}"
            ));
        }
        if timeout.is_zero() {
            return Err("banner_timeout must be greater than zero".into());
        }
        Ok(Self { bytes, timeout })
    }

    pub fn bytes(&self) -> u32 {
        self.bytes
    }

    /// The configured ceiling, for the plan and the record.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// How long to actually wait, given what the connect to this host cost.
    ///
    /// A greeting arrives about one round trip after the connection is established, so
    /// on a 2 ms LAN the useful wait is a few milliseconds and the configured ceiling is
    /// two hundred times longer than it needs to be. That matters more than it sounds:
    /// concurrency here *is* the worker-thread count with no queue behind it, so a worker
    /// parked in `read` issues no probes at all while it waits. The ports that pay the
    /// full ceiling are exactly the ones that yield nothing — a silent open port, which
    /// HTTP and everything behind TLS are — so a flat 500 ms turned a 1% open rate into a
    /// multiple of the whole scan's duration.
    ///
    /// Scaled off the measured connect instead, floored so a sub-millisecond connect
    /// still leaves room, and capped by the configured timeout so the knob still means
    /// what it says: the most this will ever wait.
    pub fn wait_for(&self, connect: Duration) -> Duration {
        (connect * 3).max(MIN_BANNER_WAIT).min(self.timeout)
    }
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
    /// The less informative of two: what a caller can rely on when either might apply.
    ///
    /// Deliberately not an `Ord` derive. The variants are declared strongest-first, so a
    /// derived `min` returns the *most* capable of a set — the exact opposite of "what
    /// can I trust across all of these" — and it would have compiled without a murmur.
    pub fn weakest(self, other: Fidelity) -> Fidelity {
        match (self, other) {
            (Fidelity::Unknown, _) | (_, Fidelity::Unknown) => Fidelity::Unknown,
            (Fidelity::OpenOnly, _) | (_, Fidelity::OpenOnly) => Fidelity::OpenOnly,
            _ => Fidelity::Full,
        }
    }

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

/// The protocol a proxy hop speaks. Both open a tunnel with a CONNECT; they differ in
/// how they authenticate and, decisively, in what a failure reply can say (D34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKind {
    Socks5,
    Http,
}

impl HopKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HopKind::Socks5 => "socks5",
            HopKind::Http => "http",
        }
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
    /// An HTTP CONNECT proxy, with optional Basic authentication.
    Http {
        address: SocketAddr,
        username: Option<String>,
        password: Option<Secret>,
    },
    /// Several proxies traversed in order, each reached through the previous. Hops may
    /// mix protocols: either kind of CONNECT yields a raw tunnel.
    Chain {
        hops: Vec<ResolvedHop>,
    },
    /// Several transports probed *across* rather than through.
    Pool {
        members: Vec<ResolvedTransport>,
    },
}

/// One proxy on a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHop {
    pub name: String,
    pub kind: HopKind,
    pub address: SocketAddr,
    pub username: Option<String>,
    pub password: Option<Secret>,
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
            TransportKind::Http { .. } => "http",
            TransportKind::Chain { .. } => "chain",
            TransportKind::Pool { .. } => "pool",
        }
    }

    /// Whether hostnames can be handed over unresolved.
    ///
    /// Every proxied kind can: the last hop of a chain issues the CONNECT, and a pool
    /// can only if every member can. This used to be true of a single `socks5` alone,
    /// which handed a chain the *direct* default profile and resolved its targets
    /// locally — a DNS leak through exactly the transport built to avoid one.
    pub fn supports_remote_dns(&self) -> bool {
        match &self.kind {
            TransportKind::Direct => false,
            TransportKind::Socks5 { .. }
            | TransportKind::Http { .. }
            | TransportKind::Chain { .. } => true,
            TransportKind::Pool { members } => members.iter().all(Self::supports_remote_dns),
        }
    }

    /// Display form with credentials redacted.
    pub fn describe(&self) -> String {
        match &self.kind {
            TransportKind::Direct => "direct".into(),
            TransportKind::Socks5 {
                address, username, ..
            }
            | TransportKind::Http {
                address, username, ..
            } => match username {
                Some(u) => format!(
                    "{} {address} (user {u}, password [redacted])",
                    self.type_name()
                ),
                None => format!("{} {address}", self.type_name()),
            },
            TransportKind::Chain { hops } => {
                let path: Vec<String> = hops
                    .iter()
                    .map(|h| format!("{} {}", h.kind.as_str(), h.address))
                    .collect();
                format!("chain of {} via {}", hops.len(), path.join(" -> "))
            }
            TransportKind::Pool { members } => {
                let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
                format!("pool of {} across {}", members.len(), names.join(", "))
            }
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

    /// Which entry of [`ScanPlan::target_names`] a permuted index probes.
    pub fn target_index_at(&self, index: u64) -> usize {
        match &self.pairs {
            Some(_) => index as usize,
            None => (index / self.ports.len() as u64) as usize,
        }
    }

    /// Every target's display form, indexed by [`ScanPlan::target_index_at`]: one entry
    /// per target for a matrix scan, one per pair for a pair scan. Formatted once here
    /// rather than once per probe.
    pub fn target_names(&self) -> Vec<std::sync::Arc<str>> {
        match &self.pairs {
            Some(pairs) => pairs.iter().map(|(t, _)| t.to_string().into()).collect(),
            None => self.targets.iter().map(|t| t.to_string().into()).collect(),
        }
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

    /// How long the scan takes if every probe times out: the bound that surprises
    /// people, and the one `rate` says nothing about.
    ///
    /// A silent destination costs the full connect budget per attempt, and only
    /// `concurrency` probes wait at once, so the time is `probes / concurrency` rounds of
    /// `connect_timeout × attempts` plus the retry delays. Through a proxy the proxy does
    /// the waiting, but the worker waits on the proxy for the same budget, so the
    /// arithmetic is the same. A `/24 × 65,535` on the `proxy` profile is 3.8 days here
    /// against 11.6 hours at its rate cap, which is why both are shown.
    pub fn silent_duration(&self) -> Duration {
        let t = &self.timing;
        let per_probe = t.connect_timeout * (1 + t.retries) + t.retry_delay * t.retries;
        let rounds = self.probe_count().div_ceil(u64::from(t.concurrency.max(1)));
        per_probe.saturating_mul(u32::try_from(rounds).unwrap_or(u32::MAX))
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
                banner: None,
                tls: None,
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
    fn every_proxied_kind_supports_remote_dns_and_direct_does_not() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let direct = ResolvedTransport {
            name: "direct".into(),
            kind: TransportKind::Direct,
            fidelity: Fidelity::Full,
        };
        assert!(!direct.supports_remote_dns());
        assert_eq!(direct.type_name(), "direct");

        let proxy = |kind: TransportKind| ResolvedTransport {
            name: "p".into(),
            kind,
            fidelity: Fidelity::Unknown,
        };
        let socks = proxy(TransportKind::Socks5 {
            address: addr,
            username: None,
            password: None,
        });
        let http = proxy(TransportKind::Http {
            address: addr,
            username: None,
            password: None,
        });
        let chain = proxy(TransportKind::Chain {
            hops: vec![ResolvedHop {
                name: "a".into(),
                kind: HopKind::Http,
                address: addr,
                username: None,
                password: None,
            }],
        });
        assert!(socks.supports_remote_dns());
        assert!(http.supports_remote_dns());
        assert_eq!(http.type_name(), "http");
        assert_eq!(http.describe(), "http 127.0.0.1:1080");
        // A chain's last hop issues the CONNECT; resolving locally instead was a leak.
        assert!(chain.supports_remote_dns());
        assert_eq!(chain.describe(), "chain of 1 via http 127.0.0.1:1080");

        let pool = |members: Vec<ResolvedTransport>| proxy(TransportKind::Pool { members });
        assert!(pool(vec![socks.clone(), http.clone()]).supports_remote_dns());
        assert!(
            !pool(vec![socks, direct]).supports_remote_dns(),
            "one member that resolves locally makes the pool resolve locally"
        );
    }

    /// 16.8M probes at 5 s x 2 attempts, 512 at a time, is days — and the rate cap says
    /// hours. The plan has to show the one that will actually bind.
    #[test]
    fn the_silent_bound_is_timeout_times_attempts_over_concurrency() {
        let mut p = ScanPlan::for_test((1..=100).collect(), 10);
        p.timing.connect_timeout = Duration::from_secs(2);
        p.timing.retries = 1;
        p.timing.retry_delay = Duration::from_millis(500);
        // 100 probes / 10 in flight = 10 rounds of (2 s x 2 + 0.5 s) = 45 s.
        assert_eq!(p.silent_duration(), Duration::from_secs(45));
        p.timing.retries = 0;
        assert_eq!(p.silent_duration(), Duration::from_secs(20));
        // A partial last round still costs a full round.
        let q = ScanPlan::for_test((1..=101).collect(), 10);
        assert_eq!(q.silent_duration(), Duration::from_millis(200) * 11);
    }

    #[test]
    fn provenance_defaults_to_builtin() {
        let mut p = Provenance::default();
        assert_eq!(p.render("concurrency"), "builtin");
        p.set("concurrency", Origin::Cli);
        assert_eq!(p.render("concurrency"), "cli");
    }
}

#[cfg(test)]
mod banner_tests {
    use super::*;

    /// The caps are the type's guarantee, not an agreement between two modules.
    #[test]
    fn the_limits_are_enforced_by_the_constructor() {
        assert!(
            Banner::new(0, DEFAULT_BANNER_TIMEOUT).is_err(),
            "zero bytes reads nothing"
        );
        assert!(Banner::new(MAX_BANNER_BYTES + 1, DEFAULT_BANNER_TIMEOUT).is_err());
        assert!(Banner::new(MAX_BANNER_BYTES, DEFAULT_BANNER_TIMEOUT).is_ok());
        // The kernel reads a zero read-timeout as "no timeout", which would park a worker
        // on a silent port for the life of the scan.
        assert!(
            Banner::new(1024, Duration::ZERO).is_err(),
            "zero timeout blocks forever"
        );
    }

    /// Concurrency here is the worker-thread count with no queue, so a worker waiting on
    /// a silent port issues no probes at all. A greeting arrives about one round trip
    /// after connect, so the wait should follow the measured connect rather than a flat
    /// ceiling that is two hundred times longer on a LAN.
    #[test]
    fn the_wait_follows_the_measured_connect() {
        let b = Banner::new(1024, Duration::from_millis(500)).unwrap();

        // A fast connect gets the floor, not half a second.
        assert_eq!(
            b.wait_for(Duration::from_millis(1)),
            Duration::from_millis(50)
        );
        // A slow one scales up...
        assert_eq!(
            b.wait_for(Duration::from_millis(40)),
            Duration::from_millis(120)
        );
        // ...but never past the configured ceiling, which is what the knob promises.
        assert_eq!(
            b.wait_for(Duration::from_millis(400)),
            Duration::from_millis(500)
        );
        assert_eq!(
            b.wait_for(Duration::from_secs(30)),
            Duration::from_millis(500)
        );
    }

    /// A ceiling below the floor still means the ceiling: the setting is the maximum.
    #[test]
    fn a_tight_ceiling_is_still_respected() {
        let b = Banner::new(1024, Duration::from_millis(10)).unwrap();
        assert_eq!(
            b.wait_for(Duration::from_millis(1)),
            Duration::from_millis(10)
        );
    }
}
