//! An in-process SOCKS5 server with injectable behaviour.
//!
//! Real proxies differ enormously in how faithfully they report failures, and that
//! difference is the whole basis of the fidelity model (D8). A fixture we control is
//! the only way to test both a well-behaved proxy and one that collapses every failure
//! into `0x01`.
//!
//! Verified against real software: `Faithful` matches microsocks byte for byte, and
//! `DisconnectAt("request")` matches OpenSSH's `ssh -D`, which answers a refused
//! destination with no reply at all rather than a failure code.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::transport::socks5::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Attempts the connection and maps OS errors to the proper RFC 1928 reply codes.
    Faithful,
    /// Attempts the connection but reports every failure as `0x01 general failure`.
    /// Some proxies do this; `ssh -D` is worse still and sends no reply at all, which
    /// `DisconnectAt("request")` models.
    Collapsing,
    RequireAuth {
        user: String,
        pass: String,
    },
    NoAcceptableMethods,
    /// Close the connection at "greeting", "auth", or "request".
    DisconnectAt(String),
    WrongVersion,
    /// Send a two-byte reply and close, mid-header.
    TruncatedReply,
    BadAddressType,
    /// Complete the handshake and then never answer the CONNECT.
    SilentAfterHandshake,
    /// Answers correctly, one byte at a time, pausing between each.
    ///
    /// The gap that let a peer choose how long a probe took: `SO_RCVTIMEO` bounds each
    /// `read` syscall, not the message, so a peer delivering a byte just inside the
    /// timeout resets the clock on every iteration. Nothing modelled this, so nothing
    /// asserted a bound on a probe's total wall time.
    Trickle(Duration),
    /// Always succeed without attempting a real connection.
    AlwaysOpen,
    /// Attempts the connection; `0x00` and relay on success, and on *any* failure closes
    /// the connection with no reply at all. This is OpenSSH's `ssh -D`, measured: its
    /// client log says why, its SOCKS5 layer cannot.
    SilentOnFailure,
}

pub struct Socks5Fixture {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl Drop for Socks5Fixture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl Socks5Fixture {
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

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match s.read(&mut buf[n..])? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                ));
            }
            k => n += k,
        }
    }
    Ok(())
}

fn handle(mut s: TcpStream, behavior: Behavior, shutdown: Arc<AtomicBool>) -> std::io::Result<()> {
    // ── greeting ────────────────────────────────────────────────────────────
    let mut head = [0u8; 2];
    read_exact(&mut s, &mut head)?;
    let mut methods = vec![0u8; head[1] as usize];
    read_exact(&mut s, &mut methods)?;

    if behavior == Behavior::DisconnectAt("greeting".into()) {
        return Ok(());
    }
    if behavior == Behavior::NoAcceptableMethods {
        s.write_all(&[VERSION, METHOD_UNACCEPTABLE])?;
        return Ok(());
    }

    // ── authentication ──────────────────────────────────────────────────────
    if let Behavior::RequireAuth { user, pass } = &behavior {
        if !methods.contains(&METHOD_USERPASS) {
            s.write_all(&[VERSION, METHOD_UNACCEPTABLE])?;
            return Ok(());
        }
        s.write_all(&[VERSION, METHOD_USERPASS])?;

        let mut v = [0u8; 2];
        read_exact(&mut s, &mut v)?;
        let mut u = vec![0u8; v[1] as usize];
        read_exact(&mut s, &mut u)?;
        let mut pl = [0u8; 1];
        read_exact(&mut s, &mut pl)?;
        let mut p = vec![0u8; pl[0] as usize];
        read_exact(&mut s, &mut p)?;

        if behavior == Behavior::DisconnectAt("auth".into()) {
            return Ok(());
        }
        let ok = u == user.as_bytes() && p == pass.as_bytes();
        s.write_all(&[AUTH_VERSION, u8::from(!ok)])?;
        if !ok {
            return Ok(());
        }
    } else {
        s.write_all(&[VERSION, METHOD_NONE])?;
    }

    if behavior == Behavior::DisconnectAt("auth".into()) {
        return Ok(());
    }

    // ── CONNECT request ─────────────────────────────────────────────────────
    let mut req = [0u8; 4];
    read_exact(&mut s, &mut req)?;
    let dest = match req[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            read_exact(&mut s, &mut a)?;
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            read_exact(&mut s, &mut a)?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(a)))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            read_exact(&mut s, &mut l)?;
            let mut d = vec![0u8; l[0] as usize];
            read_exact(&mut s, &mut d)?;
            // Resolve remotely, which is the point of transport-side DNS. IPv4 first
            // when a name has both, since the fixtures under test listen on 127.0.0.1.
            String::from_utf8(d)
                .ok()
                .and_then(|h| std::net::ToSocketAddrs::to_socket_addrs(&(h.as_str(), 0)).ok())
                .and_then(|it| {
                    let all: Vec<_> = it.map(|sa| sa.ip()).collect();
                    all.iter().find(|ip| ip.is_ipv4()).or(all.first()).copied()
                })
        }
        _ => None,
    };
    let mut port = [0u8; 2];
    read_exact(&mut s, &mut port)?;
    let port = u16::from_be_bytes(port);

    if behavior == Behavior::DisconnectAt("request".into()) {
        return Ok(());
    }

    // ── reply ───────────────────────────────────────────────────────────────
    match &behavior {
        Behavior::WrongVersion => {
            s.write_all(&[0x04, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])?;
        }
        Behavior::TruncatedReply => {
            s.write_all(&[VERSION, REP_SUCCEEDED])?;
        }
        Behavior::BadAddressType => {
            s.write_all(&[VERSION, REP_SUCCEEDED, 0x00, 0x09, 0, 0])?;
        }
        // One byte at a time, with a pause between each — every individual read succeeds
        // well inside the per-read timeout, so only a message-level deadline stops it.
        Behavior::Trickle(gap) => {
            let reply = [VERSION, REP_SUCCEEDED, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
            for b in reply {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if s.write_all(&[b]).is_err() {
                    break;
                }
                let _ = s.flush();
                std::thread::sleep(*gap);
            }
        }
        Behavior::SilentAfterHandshake => {
            // Hold without answering until the fixture is torn down.
            for _ in 0..500 {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Behavior::AlwaysOpen => write_reply(&mut s, REP_SUCCEEDED)?,
        Behavior::Faithful
        | Behavior::Collapsing
        | Behavior::SilentOnFailure
        | Behavior::RequireAuth { .. } => {
            let collapsing = matches!(behavior, Behavior::Collapsing);
            let silent = matches!(behavior, Behavior::SilentOnFailure);
            let mut upstream = None;
            let code = match dest {
                None => REP_HOST_UNREACHABLE,
                Some(ip) => {
                    let target = SocketAddr::new(ip, port);
                    match TcpStream::connect_timeout(&target, Duration::from_millis(500)) {
                        Ok(up) => {
                            upstream = Some(up);
                            REP_SUCCEEDED
                        }
                        Err(_) if silent => return Ok(()),
                        Err(e) if collapsing => {
                            let _ = e;
                            REP_GENERAL_FAILURE
                        }
                        Err(e) => match e.raw_os_error() {
                            Some(libc::ECONNREFUSED) => REP_CONNECTION_REFUSED,
                            Some(libc::EHOSTUNREACH) => REP_HOST_UNREACHABLE,
                            Some(libc::ENETUNREACH) => REP_NETWORK_UNREACHABLE,
                            _ => REP_HOST_UNREACHABLE,
                        },
                    }
                }
            };
            write_reply(&mut s, code)?;
            // A real proxy relays once it has said `succeeded`; the fixture used to
            // reply and hang up. Nothing noticed while every scan was one hop, because
            // a connect scan never sends anything afterwards. A *chain* does: hop two's
            // greeting has to travel through hop one, and a banner has to travel back.
            if let Some(up) = upstream {
                relay(s, up);
            }
        }
        Behavior::DisconnectAt(_) | Behavior::NoAcceptableMethods => {}
    }
    Ok(())
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

fn write_reply(s: &mut TcpStream, code: u8) -> std::io::Result<()> {
    s.write_all(&[VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::open_listener;

    #[test]
    fn fixture_starts_and_binds_loopback() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        assert!(fx.addr().ip().is_loopback());
        assert_ne!(fx.addr().port(), 0);
    }

    #[test]
    fn faithful_and_collapsing_differ_only_on_failure() {
        // Both must agree that an open port is open; they diverge on the failure path,
        // which is exactly the distinction the fidelity model exists to surface.
        let (_g, open) = open_listener();
        // Port 1 rather than a bound-then-released port: tests run in parallel, and a
        // released port can be re-bound by another test between here and the probe,
        // which made this test report an `open` closed port once in a while.
        let closed: SocketAddr = "127.0.0.1:1".parse().expect("valid literal");

        for b in [Behavior::Faithful, Behavior::Collapsing] {
            let fx = Socks5Fixture::start(b.clone());
            let t = crate::transport::ProxyTransport::new(
                "fx".into(),
                fx.addr(),
                None,
                None,
                crate::plan::types::Fidelity::Unknown,
            );
            let timing = crate::plan::types::Timing {
                concurrency: 1,
                rate: 0,
                proxy_connect_timeout: Duration::from_secs(2),
                handshake_timeout: Duration::from_secs(2),
                connect_timeout: Duration::from_secs(2),
                retries: 0,
                retry_delay: Duration::ZERO,
                banner: None,
                tls: None,
            };
            let o = t.probe_detailed(&crate::transport::Destination::Addr(open), &timing);
            assert_eq!(
                o.reply,
                Some(crate::transport::Reply::Socks5(REP_SUCCEEDED)),
                "{b:?} on open port"
            );

            let c = t.probe_detailed(&crate::transport::Destination::Addr(closed), &timing);
            let expected = match b {
                Behavior::Faithful => REP_CONNECTION_REFUSED,
                _ => REP_GENERAL_FAILURE,
            };
            assert_eq!(
                c.reply,
                Some(crate::transport::Reply::Socks5(expected)),
                "{b:?} on closed port"
            );
        }
    }
}
