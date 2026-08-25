//! Transports: how a connection to a destination is established.
//!
//! Blocking I/O keeps this trait genuinely simple — no async trait, no pinning, no
//! lifetime gymnastics. That simplicity was a large part of why the runtime evaluation
//! landed where it did (D1), given SOCKS5 is the primary path.

pub mod direct;
pub mod http;
pub mod pool;
pub mod socks5;

use std::fmt;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::plan::types::{Banner, Fidelity, HopKind, Timing, TransportKind};
use crate::probe::ProbeOutcome;

pub use direct::DirectTransport;
pub use socks5::{Hop, ProxyTransport};

/// A proxy's raw answer to the CONNECT that named the destination, kept for
/// `transport test`, which judges fidelity from it rather than from the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// RFC 1928 reply code.
    Socks5(u8),
    /// HTTP status code.
    Http(u16),
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Socks5(c) => write!(f, "reply 0x{c:02x}"),
            Reply::Http(s) => write!(f, "status {s}"),
        }
    }
}

/// Read exactly `buf.len()` bytes, or fail — bounded in *time*, not only in bytes.
///
/// `SO_RCVTIMEO` bounds each `read` syscall, not the message. A peer that delivers one
/// byte just inside the timeout resets that clock on every iteration, so a reply parser
/// could hold a worker for many multiples of the configured budget, chosen by the peer —
/// measured at 26x against a 200 ms budget. Concurrency here is the worker-thread count
/// with no queue, so a hostile proxy doing this on every connection stalls the scan.
///
/// `deadline` is `None` only where there is no clock to run against — a fuzz harness
/// driving a `Cursor`, which cannot block.
pub fn read_exact<R: Read>(
    s: &mut R,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer did not deliver a complete message within the budget",
            ));
        }
        match s.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-message",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

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
        } => Box::new(ProxyTransport::chained(
            resolved.name.clone(),
            vec![Hop::new(
                HopKind::Socks5,
                *address,
                username.clone(),
                password.as_ref().map(|s| s.expose().to_string()),
            )],
            resolved.fidelity,
        )),
        TransportKind::Http {
            address,
            username,
            password,
        } => Box::new(ProxyTransport::chained(
            resolved.name.clone(),
            vec![Hop::new(
                HopKind::Http,
                *address,
                username.clone(),
                password.as_ref().map(|s| s.expose().to_string()),
            )],
            resolved.fidelity,
        )),
        TransportKind::Chain { hops } => Box::new(ProxyTransport::chained(
            resolved.name.clone(),
            hops.iter()
                .map(|h| {
                    Hop::new(
                        h.kind,
                        h.address,
                        h.username.clone(),
                        h.password.as_ref().map(|s| s.expose().to_string()),
                    )
                })
                .collect(),
            resolved.fidelity,
        )),
        TransportKind::Pool { members } => Box::new(pool::PoolTransport::new(
            resolved.name.clone(),
            members.iter().map(build).collect(),
        )),
    }
}

/// Read whatever an open service volunteers, without sending anything.
///
/// **Passive by construction: not one byte is written.** That keeps "we connected and
/// listened" literally true, which is a materially different claim from having addressed
/// the service — and it is why this needs no consent story beyond the one a connect scan
/// already has. Sending protocol probes would be a different feature with a different
/// justification (D32).
///
/// The cost is coverage, and it is large: only services that greet first say anything
/// here. SSH, SMTP, FTP, POP3, IMAP, MySQL and Telnet do. HTTP does not, and neither does
/// anything behind TLS, which is most of a modern network. An empty banner means "said
/// nothing unprompted", never "nothing is there".
///
/// One read, bounded by `opts.timeout` and `opts.bytes`. Greetings arrive in a single
/// segment — the protocols above all write theirs with one `write()` — so looping would
/// buy truncation resistance nobody needs at the cost of a second timeout to wait out.
pub fn read_banner(stream: &TcpStream, opts: &Banner, connect: Duration) -> Option<Vec<u8>> {
    use std::io::Read;

    // Scaled off this host's own connect rather than the flat ceiling; see
    // `Banner::wait_for` for why a worker parked here is expensive.
    stream.set_read_timeout(Some(opts.wait_for(connect))).ok()?;
    let mut buf = vec![0u8; opts.bytes() as usize];
    // A timeout, a reset, or a server that simply says nothing all land here, and all
    // three mean the same thing to a reader: it volunteered nothing.
    let n = (&*stream).read(&mut buf).ok()?;
    // `to_vec` rather than `truncate`: a 23-byte greeting should not carry a kilobyte of
    // capacity through the channel and into the record.
    (n > 0).then(|| buf[..n].to_vec())
}

/// Bytes written to a probed service. Zero, and this is the constant the record cites —
/// so the passivity claim and the code that would falsify it cannot drift apart.
pub const BANNER_SENT_BYTES: u64 = 0;

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
