//! An in-process TLS responder with injectable behaviour.
//!
//! It does not implement TLS. It reads whatever the client sends first and answers with
//! canned bytes shaped like a server's first flight — which is all the probe ever reads
//! (D35) — so tests can exercise a TLS 1.2 server, a 1.3-only server (an alert), and the
//! malformed and hostile shapes a real stack would never produce.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A real self-signed EC certificate (`CN=fixture.scanr.invalid`), so what lands in a
/// record parses with `openssl x509 -inform der`.
pub const FIXTURE_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x95, 0x30, 0x82, 0x01, 0x3b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x33,
    0xfa, 0x2a, 0x29, 0x64, 0x96, 0x85, 0xdf, 0x45, 0x8b, 0xa0, 0x5b, 0x4b, 0x1c, 0xeb, 0x0f, 0x77,
    0xdb, 0x2b, 0x16, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x20, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x66, 0x69, 0x78, 0x74,
    0x75, 0x72, 0x65, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x72, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69,
    0x64, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x35, 0x32, 0x32, 0x33, 0x35, 0x31,
    0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x32, 0x32, 0x32, 0x32, 0x33, 0x35, 0x31, 0x32,
    0x5a, 0x30, 0x20, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x66, 0x69,
    0x78, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x72, 0x2e, 0x69, 0x6e, 0x76, 0x61,
    0x6c, 0x69, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x52, 0xa6,
    0xc7, 0x94, 0xf3, 0x40, 0x79, 0x00, 0x70, 0xf6, 0x26, 0x8e, 0x43, 0x59, 0xe0, 0x74, 0xe2, 0x69,
    0xf4, 0x09, 0x96, 0x15, 0x2d, 0xe6, 0x35, 0xe6, 0xf5, 0x77, 0x6e, 0x38, 0x32, 0x93, 0x24, 0x4d,
    0xaf, 0x4c, 0xe1, 0x93, 0x0b, 0xce, 0xfc, 0xa0, 0xa3, 0x35, 0xd0, 0xe7, 0xcf, 0xbe, 0xbb, 0x8d,
    0x72, 0x9c, 0x6c, 0xe3, 0xa5, 0xa6, 0xb6, 0x5d, 0xda, 0x1d, 0x25, 0xab, 0x58, 0x77, 0xa3, 0x53,
    0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xc7, 0x4f, 0xe1,
    0xc5, 0xc0, 0x15, 0xdb, 0xab, 0x22, 0xed, 0x91, 0xc3, 0x93, 0x5e, 0x96, 0xe2, 0x8b, 0x5f, 0xf8,
    0x93, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc7, 0x4f,
    0xe1, 0xc5, 0xc0, 0x15, 0xdb, 0xab, 0x22, 0xed, 0x91, 0xc3, 0x93, 0x5e, 0x96, 0xe2, 0x8b, 0x5f,
    0xf8, 0x93, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x5a, 0xd7, 0x32, 0x49, 0xcc, 0x19, 0xe9, 0x79, 0x7e, 0x71,
    0xcb, 0xf0, 0x8d, 0xa9, 0x25, 0x1e, 0x9b, 0x4c, 0xb2, 0x3a, 0x49, 0xcb, 0x0e, 0x4f, 0xac, 0x1a,
    0x0a, 0x7e, 0x50, 0xdd, 0xdc, 0x3a, 0x02, 0x21, 0x00, 0x99, 0x9f, 0x7c, 0x14, 0x0a, 0x72, 0xf6,
    0x91, 0x14, 0xc3, 0xbb, 0xc3, 0x1a, 0xc3, 0x98, 0x40, 0xc8, 0x98, 0xfc, 0x71, 0xcc, 0x95, 0xba,
    0xca, 0xd9, 0xc0, 0x58, 0xc0, 0xd5, 0xc7, 0x57, 0xcb,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// A TLS 1.2 server: ServerHello (cipher `0xc02f`, the given ALPN), Certificate
    /// (the fixture leaf, then a copy as issuer), ServerHelloDone.
    Tls12 { alpn: Option<&'static str> },
    /// A 1.3-only server, which answers a 1.2 offer with `protocol_version`.
    Tls13Only,
    /// Any alert.
    Alert { level: u8, description: u8 },
    /// Speaks first: an SSH-style greeting, so the probe should never run.
    Greets,
    /// Answers the hello with HTTP, as a plaintext web server does.
    NotTls,
    /// A record header claiming 64 KiB.
    Oversize,
    /// The ServerHello's first bytes, then close.
    Truncated,
    /// Reads the hello and never answers.
    Silent,
    /// A correct flight one byte at a time, pausing between each.
    Trickle(Duration),
}

pub struct TlsFixture {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

impl TlsFixture {
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

/// The canned TLS 1.2 first flight, as one handshake record.
pub fn tls12_flight(alpn: Option<&str>) -> Vec<u8> {
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x42u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0xc0, 0x2f]);
    hello.push(0);
    let mut ext = Vec::new();
    if let Some(a) = alpn {
        let mut list = vec![0, (a.len() + 1) as u8, a.len() as u8];
        list.extend_from_slice(a.as_bytes());
        ext.extend_from_slice(&[0x00, 0x10]);
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
    }
    hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext);

    let mut certs = Vec::new();
    for der in [FIXTURE_CERT_DER, FIXTURE_CERT_DER] {
        certs.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        certs.extend_from_slice(der);
    }
    let mut cert_body = (certs.len() as u32).to_be_bytes()[1..].to_vec();
    cert_body.extend_from_slice(&certs);

    let mut hs = Vec::new();
    for (kind, body) in [(2u8, hello), (11u8, cert_body), (14u8, Vec::new())] {
        hs.push(kind);
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
    }
    record(0x16, &hs)
}

fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = vec![kind, 0x03, 0x03];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

/// Consume the client's hello: a TLS record header and its body.
fn read_hello(s: &mut TcpStream) -> std::io::Result<()> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head)?;
    let len = u16::from_be_bytes([head[3], head[4]]) as usize;
    let mut body = vec![0u8; len.min(16_384)];
    s.read_exact(&mut body)
}

fn handle(mut s: TcpStream, behavior: Behavior, shutdown: Arc<AtomicBool>) -> std::io::Result<()> {
    if behavior == Behavior::Greets {
        return s.write_all(b"SSH-2.0-fixture\r\n");
    }
    read_hello(&mut s)?;
    match behavior {
        Behavior::Tls12 { alpn } => s.write_all(&tls12_flight(alpn)),
        Behavior::Tls13Only => s.write_all(&record(0x15, &[2, 70])),
        Behavior::Alert { level, description } => s.write_all(&record(0x15, &[level, description])),
        Behavior::Greets => unreachable!("handled above"),
        Behavior::NotTls => s.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"),
        Behavior::Oversize => s.write_all(&[0x16, 0x03, 0x03, 0xff, 0xff]),
        Behavior::Truncated => {
            s.write_all(&[0x16, 0x03, 0x03, 0x00, 0x40, 0x02, 0x00, 0x00, 0x3c, 0x03])
        }
        Behavior::Silent => {
            for _ in 0..500 {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        }
        Behavior::Trickle(gap) => {
            for b in tls12_flight(Some("h2")) {
                if shutdown.load(Ordering::Relaxed) || s.write_all(&[b]).is_err() {
                    break;
                }
                let _ = s.flush();
                std::thread::sleep(gap);
            }
            Ok(())
        }
    }
}
