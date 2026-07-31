//! Host facts and operational diagnostics.
//!
//! The point of this module is that errors name the actual operational cause instead of
//! an errno. `EADDRNOTAVAIL` at scale is ephemeral port exhaustion, and the remediation
//! is a sysctl — saying so beats printing "Cannot assign requested address".

use std::fmt;
use std::path::Path;

/// Linux holds TIME_WAIT for a hardcoded 60s (`TCP_TIMEWAIT_LEN`).
pub const TIME_WAIT_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// `net.ipv4.ip_local_port_range`
    pub ephemeral_range: Option<(u32, u32)>,
    /// `net.ipv4.tcp_tw_reuse`: 0 = off, 1 = on, 2 = loopback only (the modern default)
    pub tcp_tw_reuse: Option<u32>,
    /// `RLIMIT_NOFILE` soft limit
    pub rlimit_nofile: Option<u64>,
}

impl HostFacts {
    pub fn probe() -> Self {
        Self {
            ephemeral_range: read_port_range(),
            tcp_tw_reuse: read_sysctl_u32("/proc/sys/net/ipv4/tcp_tw_reuse"),
            rlimit_nofile: read_rlimit_nofile(),
        }
    }

    pub fn ephemeral_ports(&self) -> Option<u32> {
        self.ephemeral_range
            .map(|(lo, hi)| hi.saturating_sub(lo) + 1)
    }

    /// Sustained probes/sec ceiling imposed by ephemeral port recycling, for a proxy at
    /// `remote` distance.
    ///
    /// With one proxy per scan every probe is a connection to the same socket address,
    /// so only the source port varies. Without `SO_LINGER{on,0}` each closed probe sits
    /// in TIME_WAIT for 60s, capping sustained rate at ports/60.
    ///
    /// `tcp_tw_reuse = 2` (the default on modern kernels) exempts loopback only, so a
    /// local proxy escapes this and a remote one does not.
    pub fn sustained_rate_ceiling(&self, remote: bool) -> Option<u32> {
        let ports = self.ephemeral_ports()?;
        let reuse = self.tcp_tw_reuse.unwrap_or(0);
        let exempt = reuse == 1 || (reuse == 2 && !remote);
        if exempt {
            None
        } else {
            Some((ports as u64 / TIME_WAIT_SECS) as u32)
        }
    }
}

impl fmt::Display for HostFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ephemeral_range {
            Some((lo, hi)) => write!(f, "ephemeral {lo}-{hi} ({} ports)", hi - lo + 1)?,
            None => write!(f, "ephemeral unknown")?,
        }
        if let Some(r) = self.tcp_tw_reuse {
            let note = match r {
                0 => " (off)",
                1 => " (on)",
                2 => " (loopback only)",
                _ => "",
            };
            write!(f, ", tcp_tw_reuse={r}{note}")?;
        }
        if let Some(n) = self.rlimit_nofile {
            write!(f, ", nofile={n}")?;
        }
        Ok(())
    }
}

fn read_sysctl_u32(path: &str) -> Option<u32> {
    std::fs::read_to_string(Path::new(path))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn read_port_range() -> Option<(u32, u32)> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut it = s.split_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn read_rlimit_nofile() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a fully initialized rlimit we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        Some(lim.rlim_cur)
    } else {
        None
    }
}

/// Every `scan_warning` code scanr can emit. Owned here so the JSONL specification can
/// be checked against it rather than drifting from it.
pub const WARNING_CODES: &[&str] = &[
    // resolution and planning, emitted before probing starts
    "dns_failure",
    "dns_mode_auto",
    "fidelity_unknown",
    "fidelity_open_only",
    "ephemeral_budget",
    "fd_budget",
    // runtime pressure, emitted at most once each per scan
    "ephemeral_pressure",
    "fd_pressure",
    "proxy_saturation",
    // a scanr bug rather than an environmental condition, emitted just before the
    // terminal event; forces `scan_failed`
    "worker_panic",
];

/// A condition that will degrade or invalidate a scan if it continues, detected while
/// probing. Carried on the probe outcome so the warning is raised from a typed signal
/// rather than by matching on message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pressure {
    EphemeralPortExhaustion,
    FileDescriptorExhaustion,
    /// The proxy itself stopped accepting connections. Unambiguous: this is a failure to
    /// reach the proxy, not a statement about any destination.
    ProxySaturation,
}

impl Pressure {
    /// Recognise the OS errors that mean "the host has run out of something".
    pub fn from_os_error(err: &std::io::Error) -> Option<Self> {
        match err.raw_os_error() {
            Some(libc::EADDRNOTAVAIL) | Some(libc::EADDRINUSE) => {
                Some(Self::EphemeralPortExhaustion)
            }
            Some(libc::EMFILE) | Some(libc::ENFILE) => Some(Self::FileDescriptorExhaustion),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::EphemeralPortExhaustion => "ephemeral_pressure",
            Self::FileDescriptorExhaustion => "fd_pressure",
            Self::ProxySaturation => "proxy_saturation",
        }
    }

    /// One-line summary for stderr.
    pub fn summary(&self) -> &'static str {
        match self {
            Self::EphemeralPortExhaustion => "local ephemeral ports exhausted",
            Self::FileDescriptorExhaustion => "out of file descriptors",
            Self::ProxySaturation => "the proxy stopped accepting connections",
        }
    }

    /// Remediation text, tailored to the host we are actually running on.
    pub fn remediation(&self, facts: &HostFacts, concurrency: u32) -> String {
        match self {
            Self::ProxySaturation => format!(
                "the proxy is refusing or timing out new connections, which means \
                 concurrency {concurrency} is more than it will accept.\n\
                 Results already recorded are still valid, but anything failing this way \
                 is recorded as `error` rather than as a port verdict. Options:\n\
                 \x20 - lower --concurrency (try halving it), or\n\
                 \x20 - use --profile proxy-careful, or\n\
                 \x20 - lower --rate if the proxy limits connection rate rather than count"
            ),
            Self::EphemeralPortExhaustion => {
                let ports = facts.ephemeral_ports().unwrap_or(28_232);
                let mut s = format!(
                    "the local ephemeral port range ({ports} ports) is exhausted.\n\
                     Every probe through a proxy consumes one source port, and Linux holds\n\
                     TIME_WAIT for {TIME_WAIT_SECS}s. Options, cheapest first:\n\
                     \x20 - lower --rate or --concurrency\n\
                     \x20 - widen the range:  sysctl -w net.ipv4.ip_local_port_range=\"10000 65535\""
                );
                if facts.tcp_tw_reuse == Some(2) {
                    s.push_str(
                        "\n  - allow reuse for non-loopback too:  sysctl -w net.ipv4.tcp_tw_reuse=1\n\
                         \x20   (currently 2, which exempts loopback only)",
                    );
                }
                s
            }
            Self::FileDescriptorExhaustion => format!(
                "out of file descriptors at concurrency {concurrency}.\n\
                 The soft RLIMIT_NOFILE is {}. Either:\n\
                 \x20 - lower --concurrency below that limit, or\n\
                 \x20 - raise it:  ulimit -n {}",
                facts
                    .rlimit_nofile
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                concurrency.saturating_add(256).max(4096),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(range: Option<(u32, u32)>, reuse: Option<u32>) -> HostFacts {
        HostFacts {
            ephemeral_range: range,
            tcp_tw_reuse: reuse,
            rlimit_nofile: Some(1024),
        }
    }

    #[test]
    fn reads_real_host_facts() {
        // These files exist on any Linux; the point is that parsing works.
        let f = HostFacts::probe();
        assert!(
            f.ephemeral_range.is_some(),
            "should read ip_local_port_range"
        );
        assert!(f.rlimit_nofile.is_some(), "should read RLIMIT_NOFILE");
        let (lo, hi) = f.ephemeral_range.unwrap();
        assert!(lo < hi && hi <= 65535);
    }

    #[test]
    fn computes_the_default_ceiling() {
        // 32768-60999 is the stock range: 28,232 ports over a 60s TIME_WAIT.
        let f = facts(Some((32768, 60999)), Some(0));
        assert_eq!(f.ephemeral_ports(), Some(28_232));
        assert_eq!(f.sustained_rate_ceiling(true), Some(470));
    }

    #[test]
    fn tw_reuse_2_exempts_loopback_only() {
        let f = facts(Some((32768, 60999)), Some(2));
        // Local proxy: no ceiling.
        assert_eq!(f.sustained_rate_ceiling(false), None);
        // Remote proxy: ceiling still applies.
        assert_eq!(f.sustained_rate_ceiling(true), Some(470));
    }

    #[test]
    fn tw_reuse_1_exempts_everything() {
        let f = facts(Some((32768, 60999)), Some(1));
        assert_eq!(f.sustained_rate_ceiling(true), None);
        assert_eq!(f.sustained_rate_ceiling(false), None);
    }

    #[test]
    fn wider_range_raises_the_ceiling() {
        let f = facts(Some((10000, 65535)), Some(0));
        assert_eq!(f.sustained_rate_ceiling(true), Some(925));
    }

    #[test]
    fn classifies_resource_errors() {
        let e = std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL);
        assert_eq!(
            Pressure::from_os_error(&e),
            Some(Pressure::EphemeralPortExhaustion)
        );
        let e = std::io::Error::from_raw_os_error(libc::EMFILE);
        assert_eq!(
            Pressure::from_os_error(&e),
            Some(Pressure::FileDescriptorExhaustion)
        );
        // An ordinary refusal is a port verdict, not host pressure.
        let e = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert_eq!(Pressure::from_os_error(&e), None);
    }

    #[test]
    fn every_pressure_has_a_code_and_remediation() {
        let f = facts(Some((32768, 60999)), Some(0));
        for p in [
            Pressure::EphemeralPortExhaustion,
            Pressure::FileDescriptorExhaustion,
            Pressure::ProxySaturation,
        ] {
            assert!(
                WARNING_CODES.contains(&p.code()),
                "{:?} code not registered",
                p
            );
            assert!(
                !p.remediation(&f, 512).is_empty(),
                "{:?} has no remediation",
                p
            );
            assert!(!p.summary().is_empty());
        }
    }

    #[test]
    fn proxy_saturation_advice_names_the_actual_knobs() {
        let r = Pressure::ProxySaturation.remediation(&facts(None, None), 512);
        assert!(r.contains("concurrency 512"), "{r}");
        assert!(r.contains("proxy-careful"), "{r}");
    }

    #[test]
    fn warning_codes_are_unique() {
        let mut v = WARNING_CODES.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), WARNING_CODES.len(), "duplicate warning code");
    }

    #[test]
    fn remediation_mentions_the_actual_sysctl_state() {
        let f = facts(Some((32768, 60999)), Some(2));
        let r = Pressure::EphemeralPortExhaustion.remediation(&f, 512);
        assert!(r.contains("28232 ports"), "{r}");
        assert!(r.contains("tcp_tw_reuse=1"), "{r}");
        assert!(r.contains("currently 2"), "{r}");
    }

    #[test]
    fn fd_remediation_suggests_a_workable_limit() {
        let r = Pressure::FileDescriptorExhaustion.remediation(&facts(None, None), 8192);
        assert!(r.contains("ulimit -n 8448"), "{r}");
    }
}
