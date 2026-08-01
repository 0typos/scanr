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
    /// Bytes the service volunteered on connect, when banner grabbing is on and it said
    /// anything. Raw: never decoded here, because what a service sends is its choice and
    /// interpreting it is the reader's job.
    pub banner: Option<Vec<u8>>,
}

impl ProbeOutcome {
    /// Attach what the service volunteered, if anything.
    pub fn with_banner(mut self, banner: Option<Vec<u8>>) -> Self {
        self.banner = banner;
        self
    }

    pub fn open(phases: Phases, source: Source) -> Self {
        Self {
            state: State::Open,
            source,
            reason: None,
            phases,
            pressure: None,
            banner: None,
        }
    }

    pub fn new(state: State, source: Source, reason: impl Into<String>, phases: Phases) -> Self {
        Self {
            state,
            source,
            reason: Some(reason.into()),
            phases,
            pressure: None,
            banner: None,
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
}
