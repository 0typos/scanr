//! Deterministic local fixtures.
//!
//! Everything here runs in-process. Nothing reaches the public internet and nothing
//! depends on an installed daemon — no dante or microsocks is required to test the
//! SOCKS5 path, which also means CI needs no service setup.

pub mod socks5;

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::transport::Destination;

/// RFC 5737 TEST-NET-1. Guaranteed not to be routed, so connections hang until the
/// timeout fires — a blackhole that needs no firewall rules or privileges.
pub const BLACKHOLE: &str = "192.0.2.1:80";

pub fn blackhole_destination() -> Destination {
    Destination::Addr(BLACKHOLE.parse().expect("valid literal"))
}

/// Keeps a background server alive for the lifetime of the guard.
pub struct ServerGuard {
    shutdown: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl ServerGuard {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// A listener that accepts and immediately drops connections. Probes report `open`.
pub fn open_listener() -> (ServerGuard, SocketAddr) {
    spawn_listener(drop)
}

/// A listener that accepts then sends RST. A connect scan still reports `open`, which
/// is correct: the handshake completed before the reset.
pub fn reset_listener() -> (ServerGuard, SocketAddr) {
    spawn_listener(|stream| {
        let sock = socket2::SockRef::from(&stream);
        let _ = sock.set_linger(Some(Duration::ZERO));
        drop(stream);
    })
}

fn spawn_listener<F>(handle: F) -> (ServerGuard, SocketAddr)
where
    F: Fn(std::net::TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    listener.set_nonblocking(true).expect("nonblocking");

    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = shutdown.clone();
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    handle(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    (ServerGuard { shutdown, addr }, addr)
}

/// An address on loopback with nothing listening. Probes report `closed` (RST).
pub fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    #[test]
    fn open_listener_accepts() {
        let (_g, addr) = open_listener();
        assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn closed_port_refuses() {
        let addr = closed_port();
        let e = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ECONNREFUSED));
    }

    #[test]
    fn blackhole_times_out_rather_than_failing_fast() {
        let addr: SocketAddr = BLACKHOLE.parse().unwrap();
        let e = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn many_sequential_connections_are_accepted() {
        // The scheduler tests lean on this, so make sure the fixture keeps up.
        let (_g, addr) = open_listener();
        for i in 0..50 {
            assert!(
                TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok(),
                "connection {i} failed"
            );
        }
    }
}
