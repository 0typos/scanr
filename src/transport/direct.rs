//! Direct TCP connect transport.
//!
//! `std::net::TcpStream::connect_timeout` already performs the whole non-blocking
//! `connect()` -> `EINPROGRESS` -> wait-for-writable -> `getsockopt(SO_ERROR)` sequence
//! that a readiness-based event loop would have us write by hand. This transport is
//! essentially that call plus classification.

use std::net::TcpStream;
use std::time::Instant;

use super::{Destination, Transport, close_without_time_wait};
use crate::plan::types::{Fidelity, Timing};
use crate::probe::{Phases, ProbeOutcome, Source, State, classify_os_error};

pub struct DirectTransport {
    name: String,
}

impl DirectTransport {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl Transport for DirectTransport {
    fn probe(&self, dest: &Destination, timing: &Timing) -> ProbeOutcome {
        let addr = match dest {
            Destination::Addr(a) => *a,
            // The planner rejects this combination, so reaching it is a bug rather than
            // a user error — say so plainly instead of guessing.
            Destination::Host(h, _) => {
                return ProbeOutcome::new(
                    State::Error,
                    Source::Internal,
                    format!("direct transport received unresolved hostname `{h}`"),
                    Phases::default(),
                );
            }
        };

        let start = Instant::now();
        let result = TcpStream::connect_timeout(&addr, timing.connect_timeout);
        let elapsed = start.elapsed();
        let phases = Phases {
            proxy_connect: None,
            handshake: None,
            connect: Some(elapsed),
            total: elapsed,
        };

        match result {
            Ok(stream) => {
                // Before the RST: the socket is open here and nowhere else, and a banner
                // read is a read on this connection rather than another one.
                let banner = timing
                    .banner
                    .as_ref()
                    .and_then(|o| super::read_banner(&stream, o));
                close_without_time_wait(&stream);
                ProbeOutcome::open(phases, Source::LocalStack).with_banner(banner)
            }
            Err(e) => classify_os_error(&e, phases),
        }
    }

    fn supports_remote_dns(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn type_name(&self) -> &'static str {
        "direct"
    }

    fn fidelity(&self) -> Fidelity {
        // The local stack distinguishes refused, unreachable, and timed out.
        Fidelity::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::{blackhole_destination, closed_port, open_listener};
    use std::time::Duration;

    fn timing(connect_ms: u64) -> Timing {
        Timing {
            concurrency: 1,
            rate: 0,
            proxy_connect_timeout: Duration::from_millis(1000),
            handshake_timeout: Duration::from_millis(1000),
            connect_timeout: Duration::from_millis(connect_ms),
            retries: 0,
            retry_delay: Duration::from_millis(0),
            banner: None,
        }
    }

    #[test]
    fn open_port_reports_open() {
        let (_guard, addr) = open_listener();
        let t = DirectTransport::new("direct".into());
        let o = t.probe(&Destination::Addr(addr), &timing(2000));
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
        assert_eq!(o.source, Source::LocalStack);
        assert!(o.phases.connect.is_some());
        assert!(o.phases.proxy_connect.is_none(), "no proxy in this path");
    }

    #[test]
    fn closed_port_reports_closed() {
        let addr = closed_port();
        let t = DirectTransport::new("direct".into());
        let o = t.probe(&Destination::Addr(addr), &timing(2000));
        assert_eq!(o.state, State::Closed);
        assert_eq!(o.source, Source::LocalStack);
        assert!(!o.is_retryable(), "a refusal is definitive");
    }

    #[test]
    fn blackholed_destination_times_out_as_filtered() {
        let t = DirectTransport::new("direct".into());
        let start = Instant::now();
        let o = t.probe(&blackhole_destination(), &timing(300));
        assert_eq!(o.state, State::Filtered);
        assert_eq!(o.source, Source::Timeout);
        assert!(o.is_retryable(), "timeouts are the retryable case (D10)");
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "timeout must be honoured, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn hostname_is_an_internal_error_not_a_silent_miss() {
        let t = DirectTransport::new("direct".into());
        let o = t.probe(
            &Destination::Host("example.invalid".into(), 80),
            &timing(100),
        );
        assert_eq!(o.state, State::Error);
        assert_eq!(o.source, Source::Internal);
    }

    #[test]
    fn declares_no_remote_dns_and_full_fidelity() {
        let t = DirectTransport::new("d".into());
        assert!(!t.supports_remote_dns());
        assert_eq!(t.fidelity(), Fidelity::Full);
        assert_eq!(t.type_name(), "direct");
    }
}
