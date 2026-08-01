//! Probe outcomes and their classification.
//!
//! Four public states (D7), not the twelve originally proposed. Most of those twelve
//! would be permanently unreachable through a proxy, producing a schema that lies by
//! omission. Instead a result carries the state, *where the classification came from*,
//! and a free-form reason.

use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Open,
    Closed,
    Filtered,
    Error,
}

impl State {
    /// The defined states, so a filter can reject a typo instead of silently matching
    /// nothing.
    pub const ALL: [State; 4] = [State::Open, State::Closed, State::Filtered, State::Error];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
            State::Filtered => "filtered",
            State::Error => "error",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a classification came from. This is what keeps the tool honest about proxies
/// that collapse every failure into one reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The local TCP stack gave a definitive answer.
    LocalStack,
    /// A SOCKS5 reply byte gave the answer — only as precise as the proxy is.
    ProxyReply,
    /// Nothing answered within the timeout.
    Timeout,
    /// scanr itself failed (resource exhaustion, cancellation).
    Internal,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::LocalStack => "local_stack",
            Source::ProxyReply => "proxy_reply",
            Source::Timeout => "timeout",
            Source::Internal => "internal",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-phase timings. Through a proxy a single latency figure is misleading — it
/// bundles proxy RTT, handshake, and the proxy's own connection to the destination.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Phases {
    pub proxy_connect: Option<Duration>,
    pub handshake: Option<Duration>,
    pub connect: Option<Duration>,
    pub total: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub state: State,
    pub source: Source,
    pub reason: Option<String>,
    pub phases: Phases,
    /// Set when this probe failed for a reason that will degrade the whole scan if it
    /// continues. Typed rather than inferred from `reason`, so the scan-level warning
    /// cannot drift from the condition that produced it.
    pub pressure: Option<crate::diag::Pressure>,
}

impl ProbeOutcome {
    pub fn open(phases: Phases, source: Source) -> Self {
        Self {
            state: State::Open,
            source,
            reason: None,
            phases,
            pressure: None,
        }
    }

    pub fn new(state: State, source: Source, reason: impl Into<String>, phases: Phases) -> Self {
        Self {
            state,
            source,
            reason: Some(reason.into()),
            phases,
            pressure: None,
        }
    }

    /// Attach a scan-level pressure condition.
    pub fn under_pressure(mut self, p: crate::diag::Pressure) -> Self {
        self.pressure = Some(p);
        self
    }

    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// Only timeouts are retried (D10): a refused connection is a definitive answer,
    /// while a timeout is genuinely ambiguous between a slow proxy and a filtered
    /// destination.
    pub fn is_retryable(&self) -> bool {
        self.source == Source::Timeout
    }
}

/// Classify an OS error from a direct `connect()`.
pub fn classify_os_error(err: &std::io::Error, phases: Phases) -> ProbeOutcome {
    use std::io::ErrorKind;

    let raw = err.raw_os_error();
    match raw {
        Some(libc::ECONNREFUSED) => ProbeOutcome::new(
            State::Closed,
            Source::LocalStack,
            "connection refused",
            phases,
        ),
        Some(libc::ECONNRESET) => ProbeOutcome::new(
            State::Closed,
            Source::LocalStack,
            "connection reset",
            phases,
        ),
        Some(libc::EHOSTUNREACH) => ProbeOutcome::new(
            State::Filtered,
            Source::LocalStack,
            "host unreachable",
            phases,
        ),
        Some(libc::ENETUNREACH) => ProbeOutcome::new(
            State::Filtered,
            Source::LocalStack,
            "network unreachable",
            phases,
        ),
        // A firewall REJECT with an admin-prohibited ICMP surfaces here.
        Some(libc::EACCES) | Some(libc::EPERM) => ProbeOutcome::new(
            State::Filtered,
            Source::LocalStack,
            "administratively prohibited",
            phases,
        ),
        Some(libc::EADDRNOTAVAIL) | Some(libc::EADDRINUSE) => ProbeOutcome::new(
            State::Error,
            Source::Internal,
            "local ephemeral port exhaustion",
            phases,
        )
        .under_pressure(crate::diag::Pressure::EphemeralPortExhaustion),
        Some(libc::EMFILE) | Some(libc::ENFILE) => ProbeOutcome::new(
            State::Error,
            Source::Internal,
            "out of file descriptors",
            phases,
        )
        .under_pressure(crate::diag::Pressure::FileDescriptorExhaustion),
        _ => match err.kind() {
            ErrorKind::TimedOut => ProbeOutcome::new(
                State::Filtered,
                Source::Timeout,
                "connect timed out",
                phases,
            ),
            _ => ProbeOutcome::new(State::Error, Source::LocalStack, err.to_string(), phases),
        },
    }
}

/// Port-number labels. Explicitly a guess from the port number and never a fingerprint;
/// the docs and the JSONL field name both say so.
pub fn service_label(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "ms-sql",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 | 2376 => "docker",
        3000 => "http-alt",
        3128 => "squid",
        3306 => "mysql",
        3389 => "ms-wbt",
        4444 => "krb524",
        5000 => "upnp",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "kube-apiserver",
        7001 => "weblogic",
        8000 | 8001 => "http-alt",
        8080 | 8081 => "http-proxy",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "http-alt",
        9092 => "kafka",
        9200 => "elasticsearch",
        9300 => "elasticsearch",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        27017 | 27018 => "mongodb",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Phases {
        Phases::default()
    }

    #[test]
    fn refused_is_closed_from_the_local_stack() {
        let e = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        let o = classify_os_error(&e, p());
        assert_eq!(o.state, State::Closed);
        assert_eq!(o.source, Source::LocalStack);
        assert!(!o.is_retryable());
    }

    #[test]
    fn timeout_is_filtered_and_retryable() {
        let e = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let o = classify_os_error(&e, p());
        assert_eq!(o.state, State::Filtered);
        assert_eq!(o.source, Source::Timeout);
        assert!(o.is_retryable(), "only timeouts are retried (D10)");
    }

    #[test]
    fn unreachable_is_filtered() {
        for code in [libc::EHOSTUNREACH, libc::ENETUNREACH] {
            let o = classify_os_error(&std::io::Error::from_raw_os_error(code), p());
            assert_eq!(o.state, State::Filtered, "code {code}");
            assert_eq!(o.source, Source::LocalStack);
        }
    }

    #[test]
    fn firewall_reject_is_filtered_not_closed() {
        let o = classify_os_error(&std::io::Error::from_raw_os_error(libc::EACCES), p());
        assert_eq!(o.state, State::Filtered);
        assert_eq!(o.reason.as_deref(), Some("administratively prohibited"));
    }

    #[test]
    fn resource_exhaustion_is_an_internal_error_not_a_port_result() {
        // Misreporting these as `filtered` would silently corrupt scan results.
        for code in [libc::EADDRNOTAVAIL, libc::EMFILE] {
            let o = classify_os_error(&std::io::Error::from_raw_os_error(code), p());
            assert_eq!(o.state, State::Error, "code {code}");
            assert_eq!(o.source, Source::Internal, "code {code}");
        }
    }

    #[test]
    fn resource_exhaustion_raises_a_scan_level_pressure_signal() {
        // Without this the remediation text in `diag` is unreachable, which was the
        // state of things before: classified, tested, and never surfaced.
        let o = classify_os_error(&std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL), p());
        assert_eq!(
            o.pressure,
            Some(crate::diag::Pressure::EphemeralPortExhaustion)
        );
        let o = classify_os_error(&std::io::Error::from_raw_os_error(libc::EMFILE), p());
        assert_eq!(
            o.pressure,
            Some(crate::diag::Pressure::FileDescriptorExhaustion)
        );
        // An ordinary port verdict carries no pressure.
        let o = classify_os_error(&std::io::Error::from_raw_os_error(libc::ECONNREFUSED), p());
        assert_eq!(o.pressure, None);
    }

    #[test]
    fn unknown_errors_fall_through_to_error() {
        let o = classify_os_error(&std::io::Error::from_raw_os_error(libc::EINVAL), p());
        assert_eq!(o.state, State::Error);
        assert!(o.reason.is_some());
    }

    #[test]
    fn state_strings_are_the_schema_values() {
        assert_eq!(State::Open.as_str(), "open");
        assert_eq!(State::Closed.as_str(), "closed");
        assert_eq!(State::Filtered.as_str(), "filtered");
        assert_eq!(State::Error.as_str(), "error");
    }

    #[test]
    fn service_labels_cover_common_ports() {
        assert_eq!(service_label(22), Some("ssh"));
        assert_eq!(service_label(443), Some("https"));
        assert_eq!(service_label(5432), Some("postgresql"));
        assert_eq!(service_label(64321), None);
    }
}
