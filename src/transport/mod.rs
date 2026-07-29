//! Transports: how a connection to a destination is established.
//!
//! Blocking I/O keeps this trait genuinely simple — no async trait, no pinning, no
//! lifetime gymnastics. That simplicity was a large part of why the runtime evaluation
//! landed where it did (D1), given SOCKS5 is the primary path.

pub mod direct;
pub mod socks5;

use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::plan::types::{Fidelity, Timing, TransportKind};
use crate::probe::ProbeOutcome;

pub use direct::DirectTransport;
pub use socks5::Socks5Transport;

/// Where a probe is aimed. A hostname is only permitted when the transport resolves
/// remotely; the planner enforces that before the scheduler ever sees one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Addr(SocketAddr),
    Host(String, u16),
}

impl Destination {
    pub fn port(&self) -> u16 {
        match self {
            Destination::Addr(a) => a.port(),
            Destination::Host(_, p) => *p,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Destination::Addr(a) => Some(a.ip()),
            Destination::Host(..) => None,
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Addr(a) => write!(f, "{a}"),
            Destination::Host(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

pub trait Transport: Send + Sync {
    fn probe(&self, dest: &Destination, timing: &Timing) -> ProbeOutcome;
    fn supports_remote_dns(&self) -> bool;
    fn name(&self) -> &str;
    fn type_name(&self) -> &'static str;
    /// What this transport is currently believed able to distinguish.
    fn fidelity(&self) -> Fidelity;
}

/// Build a live transport from its resolved configuration.
pub fn build(resolved: &crate::plan::types::ResolvedTransport) -> Box<dyn Transport> {
    match &resolved.kind {
        TransportKind::Direct => Box::new(DirectTransport::new(resolved.name.clone())),
        TransportKind::Socks5 {
            address,
            username,
            password,
        } => Box::new(Socks5Transport::new(
            resolved.name.clone(),
            *address,
            username.clone(),
            password.as_ref().map(|s| s.expose().to_string()),
            resolved.fidelity,
        )),
    }
}

/// Close a probe socket with `SO_LINGER{on,0}` so it sends RST instead of FIN and skips
/// TIME_WAIT entirely (D9).
///
/// We already have the answer from `connect()` and have no data to flush, so this costs
/// nothing functionally. M0 measured it as a 7.5x sustained-throughput multiplier
/// (9,189 -> 68,949 probes/s) with TIME_WAIT accumulation falling from 21,931 to 1.
///
/// `std::net::TcpStream::set_linger` is still unstable (rust#88494), hence `socket2`.
pub fn close_without_time_wait(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    // A failure here costs throughput, not correctness, so it is not worth surfacing.
    let _ = sock.set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn destination_accessors() {
        let a = Destination::Addr("10.0.0.1:443".parse().unwrap());
        assert_eq!(a.port(), 443);
        assert_eq!(a.ip(), Some("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert_eq!(a.to_string(), "10.0.0.1:443");

        let h = Destination::Host("app.internal".into(), 80);
        assert_eq!(h.port(), 80);
        assert_eq!(h.ip(), None, "an unresolved host has no address to record");
        assert_eq!(h.to_string(), "app.internal:80");
    }

    #[test]
    fn linger_zero_is_actually_applied() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let s = TcpStream::connect(addr).unwrap();
        close_without_time_wait(&s);
        let got = socket2::SockRef::from(&s).linger().unwrap();
        assert_eq!(
            got,
            Some(Duration::ZERO),
            "SO_LINGER{{on,0}} must be set — this is the 7.5x throughput mechanism"
        );
    }
}
