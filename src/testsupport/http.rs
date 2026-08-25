//! An in-process HTTP CONNECT proxy with injectable behaviour.
//!
//! The counterpart of [`super::socks5`] for the HTTP path. `Faithful` answers a
//! refused destination with `503` and `X-Fixture-Error: refused`, and an unreachable one
//! with `504` — the shape squid uses — so tests can exercise both a proxy that
//! distinguishes the two and, via [`Behavior::Status`], one that does not.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::transport::http::base64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Connect to the destination: `200` and relay, `503` when refused, `504` when it
    /// times out.
    Faithful,
    /// `407` with `Proxy-Authenticate: Basic` until the right credentials arrive, then
    /// `Faithful`.
    RequireAuth { user: String, pass: String },
    /// Always this status, without attempting a connection.
    Status(u16),
    /// Answer with SOCKS5 bytes, as a wrongly configured transport would meet.
    NotHttp,
    /// A valid status line followed by headers that never end.
    HeaderFlood,
    /// Part of a status line, then close.
    Truncated,
    /// Read the request and never answer.
    Silent,
    /// Read the request and close without answering.
    DisconnectBeforeReply,
    /// A correct `200`, one byte at a time, pausing between each.
    Trickle(Duration),
}

pub struct HttpFixture {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl HttpFixture {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        listener.set_nonblocking(true).expect("nonblocking");

        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let b = behavior.clone();
                        let s = stop.clone();
                        std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let _ = handle(stream, b, s);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { addr, shutdown }
    }
}

/// The parts of a CONNECT request the fixture acts on.
struct Request {
    authority: String,
    proxy_authorization: Option<String>,
}

fn read_request(s: &mut TcpStream) -> std::io::Result<Request> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(byte[0]);
        if buf.len() > 16 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    if parts.next() != Some("CONNECT") {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let authority = parts.next().unwrap_or_default().to_string();
    let proxy_authorization = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_string());
    Ok(Request {
        authority,
        proxy_authorization,
    })
}

fn respond(
    s: &mut TcpStream,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (n, v) in extra {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    s.write_all(out.as_bytes())
}

fn handle(mut s: TcpStream, behavior: Behavior, shutdown: Arc<AtomicBool>) -> std::io::Result<()> {
    let req = read_request(&mut s)?;

    match &behavior {
        Behavior::Status(code) => return respond(&mut s, *code, "Fixture", &[]),
        Behavior::NotHttp => return s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        Behavior::HeaderFlood => {
            s.write_all(b"HTTP/1.1 200 OK\r\n")?;
            let line =
                b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
            for _ in 0..2048 {
                if shutdown.load(Ordering::Relaxed) || s.write_all(line).is_err() {
                    break;
                }
            }
            return Ok(());
        }
        Behavior::Truncated => return s.write_all(b"HTTP/1.1 20"),
        Behavior::Silent => {
            for _ in 0..500 {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return Ok(());
        }
        Behavior::DisconnectBeforeReply => return Ok(()),
        Behavior::Trickle(gap) => {
            for b in b"HTTP/1.1 200 Connection established\r\n\r\n" {
                if shutdown.load(Ordering::Relaxed) || s.write_all(&[*b]).is_err() {
                    break;
                }
                let _ = s.flush();
                std::thread::sleep(*gap);
            }
            return Ok(());
        }
        Behavior::RequireAuth { user, pass } => {
            let want = format!("Basic {}", base64(format!("{user}:{pass}").as_bytes()));
            if req.proxy_authorization.as_deref() != Some(want.as_str()) {
                return respond(
                    &mut s,
                    407,
                    "Proxy Authentication Required",
                    &[("Proxy-Authenticate", "Basic realm=\"fixture\"")],
                );
            }
        }
        Behavior::Faithful => {}
    }

    // ── Faithful: attempt the connection and say what happened ──────────────
    // A hostname is resolved here, which is what transport-side DNS means; like a real
    // proxy, every address it resolves to is tried before giving up.
    let targets: Vec<SocketAddr> = match req.authority.parse::<SocketAddr>() {
        Ok(a) => vec![a],
        Err(_) => std::net::ToSocketAddrs::to_socket_addrs(&req.authority.as_str())
            .map(|it| it.collect())
            .unwrap_or_default(),
    };
    if targets.is_empty() {
        return respond(&mut s, 502, "Bad Gateway", &[("X-Fixture-Error", "dns")]);
    }
    let mut last = None;
    for target in targets {
        match TcpStream::connect_timeout(&target, Duration::from_millis(500)) {
            Ok(up) => {
                respond(&mut s, 200, "Connection established", &[])?;
                relay(s, up);
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => respond(
            &mut s,
            503,
            "Service Unavailable",
            &[("X-Fixture-Error", "refused")],
        ),
        _ => respond(
            &mut s,
            504,
            "Gateway Timeout",
            &[("X-Fixture-Error", "timeout")],
        ),
    }
}

/// Copy bytes both ways until either side is done.
fn relay(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut c_rx), Ok(mut u_rx)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let (mut c_tx, mut u_tx) = (client, upstream);
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_rx, &mut u_tx);
    });
    let _ = std::io::copy(&mut u_rx, &mut c_tx);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::types::{Fidelity, Timing};
    use crate::testsupport::{closed_port, open_listener};
    use crate::transport::{Destination, ProxyTransport, Reply};

    fn timing() -> Timing {
        Timing {
            concurrency: 1,
            rate: 0,
            proxy_connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            retries: 0,
            retry_delay: Duration::ZERO,
            banner: None,
            tls: None,
        }
    }

    #[test]
    fn faithful_reports_open_and_refused_distinctly() {
        let (_g, open) = open_listener();
        let fx = HttpFixture::start(Behavior::Faithful);
        let t = ProxyTransport::http("fx".into(), fx.addr(), None, None, Fidelity::Unknown);
        let o = t.probe_detailed(&Destination::Addr(open), &timing());
        assert_eq!(o.reply, Some(Reply::Http(200)), "{:?}", o.outcome.reason);
        let c = t.probe_detailed(&Destination::Addr(closed_port()), &timing());
        assert_eq!(c.reply, Some(Reply::Http(503)), "{:?}", c.outcome.reason);
    }
}
