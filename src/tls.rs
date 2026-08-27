//! The TLS ClientHello probe: the one active probe scanr sends (D35).
//!
//! Off by default. On an open port that volunteered no banner — TLS servers never speak
//! first — a fixed ClientHello offering TLS 1.3 and 1.2 is written on the same
//! connection and the server's first flight is read: ServerHello (version, cipher),
//! Certificate (the leaf, hashed and kept, the chain after it), key exchange, ALPN, or
//! an Alert. Then the socket is reset as every probe socket is. No verification. The
//! leaf's names, validity and key are read by [`crate::x509`] — bounded and unverified —
//! and the DER itself is kept for `tlsx`, `openssl x509` and `nmap -sV`.
//!
//! A 1.2 server sends all of that in the clear. A 1.3 server encrypts everything after
//! the ServerHello, so the probe finishes the key exchange — X25519 from a published
//! private key, the RFC 8446 schedule, AES-128-GCM, all in [`crate::crypto`] — and
//! decrypts the flight up to Finished. Nothing is sent after the hello; the server's
//! Finished is not answered, and the socket is reset like any other. Older servers step
//! down to 1.2, 1.1, 1.0 or SSLv3 and are read as they always were.
//!
//! Everything read here is peer-chosen: record lengths, handshake lengths, certificate
//! lengths, the ALPN string. The parser is bounded in bytes and in time, and the fuzz
//! target `tls_reply` drives it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::transport::http::base64;
use crate::transport::read_exact;

/// The most a server may send in its first flight before the read is abandoned. A
/// ServerHello is ~100 bytes and a certificate chain a few KiB; 64 KiB is not answering us.
pub const MAX_FLIGHT_BYTES: usize = 64 * 1024;
/// The largest leaf certificate kept verbatim in the record. Larger ones are hashed and
/// counted but not embedded, so one hostile service cannot inflate a record.
pub const MAX_LEAF_DER: usize = 8 * 1024;
/// TLS records are at most 2^14 bytes of plaintext (RFC 5246 §6.2.1).
const MAX_RECORD: usize = 16_384;

const RECORD_HANDSHAKE: u8 = 0x16;
const RECORD_ALERT: u8 = 0x15;
const RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const RECORD_APPLICATION_DATA: u8 = 0x17;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const GROUP_X25519: u16 = 0x001d;
/// A ServerHello whose random is this is a HelloRetryRequest (RFC 8446 §4.1.3).
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// The probe's X25519 private key. Published, like the client random: the session carries
/// nothing secret, and a fixed key keeps the hello byte-for-byte reproducible.
pub const PROBE_X25519_PRIVATE: [u8; 32] = *b"scanr tls probe x25519 key    v1";

/// The key share the hello carries, computed once.
pub fn probe_public_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| crate::crypto::x25519_public(&PROBE_X25519_PRIVATE))
}
/// Certificates after the leaf whose fields are kept; the rest are counted.
pub const MAX_CHAIN_KEPT: usize = 8;
/// Server extensions recorded; nothing real sends more.
const MAX_SERVER_EXTENSIONS: usize = 32;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The cipher suites offered, strongest first. Wide enough that a server with any
/// modern or legacy TLS 1.2 configuration finds one it accepts, so a `handshake_failure`
/// means something. One 1.3 suite: the one every 1.3 server must implement.
const CIPHER_SUITES: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    (0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    (0xc030, "ECDHE-RSA-AES256-GCM-SHA384"),
    (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"),
    (0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305"),
    (0xc024, "ECDHE-ECDSA-AES256-SHA384"),
    (0xc023, "ECDHE-ECDSA-AES128-SHA256"),
    (0xc028, "ECDHE-RSA-AES256-SHA384"),
    (0xc027, "ECDHE-RSA-AES128-SHA256"),
    (0xc00a, "ECDHE-ECDSA-AES256-SHA"),
    (0xc009, "ECDHE-ECDSA-AES128-SHA"),
    (0xc014, "ECDHE-RSA-AES256-SHA"),
    (0xc013, "ECDHE-RSA-AES128-SHA"),
    (0x009d, "AES256-GCM-SHA384"),
    (0x009c, "AES128-GCM-SHA256"),
    (0x003d, "AES256-SHA256"),
    (0x003c, "AES128-SHA256"),
    (0x0035, "AES256-SHA"),
    (0x002f, "AES128-SHA"),
];

/// Fixed rather than random: the probe is meant to be byte-for-byte reproducible and
/// documented, and nothing checks the client random.
const CLIENT_RANDOM: [u8; 32] = *b"scanr tls probe: not random  v1 ";

/// Limits for the probe. Fields are private so the zero-timeout trap the kernel sets
/// ("no timeout") is closed at construction, as for [`crate::plan::types::Banner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsProbe {
    timeout: Duration,
}

pub const DEFAULT_TLS_TIMEOUT: Duration = Duration::from_millis(1000);
const MIN_TLS_WAIT: Duration = Duration::from_millis(100);

impl TlsProbe {
    pub fn new(timeout: Duration) -> Result<Self, String> {
        if timeout.is_zero() {
            return Err("tls_timeout must be greater than zero".into());
        }
        Ok(Self { timeout })
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The flight arrives about one round trip after the hello, plus whatever the server
    /// spends choosing a certificate. Scaled off the measured connect like the banner
    /// wait, floored so a loopback connect still leaves room, capped by the ceiling.
    pub fn wait_for(&self, connect: Duration) -> Duration {
        (connect * 4).max(MIN_TLS_WAIT).min(self.timeout)
    }
}

/// The record's `offered`: the versions the hello names.
pub const OFFERED: &str = "1.3,1.2";

/// What the server's first flight said. Every field is optional because the flight can
/// stop anywhere; `error` says where, when it did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsObservation {
    /// Bytes written: the ClientHello.
    pub sent_bytes: u32,
    /// Bytes read before the flight ended or was abandoned.
    pub read_bytes: u32,
    /// Whether an SNI extension named the target.
    pub sni: bool,
    /// The version the server chose, as the ServerHello's `server_version`.
    pub negotiated: Option<u16>,
    pub cipher: Option<u16>,
    /// The ALPN protocol the server selected, printable ASCII only.
    pub alpn: Option<String>,
    /// `(level, description)` of an alert, if the server sent one.
    pub alert: Option<(u8, u8)>,
    pub leaf_sha256: Option<[u8; 32]>,
    /// The leaf certificate, when it fits [`MAX_LEAF_DER`].
    pub leaf_der: Option<Vec<u8>>,
    pub leaf_len: Option<u32>,
    pub chain_len: Option<u32>,
    /// Why the flight ended before a Certificate or Alert, if it did.
    pub error: Option<String>,
    /// What the leaf says, when it parsed. Read, not verified: see [`crate::x509`].
    pub cert: Option<crate::x509::Leaf>,
    /// Why the leaf did not parse, when it did not.
    pub cert_error: Option<&'static str>,
    /// The certificates after the leaf, up to [`MAX_CHAIN_KEPT`].
    pub chain: Vec<ChainCert>,
    /// The ServerHello's compression method; anything but 0 is a finding.
    pub compression: Option<u8>,
    /// Extension types the ServerHello carried, in order.
    pub server_extensions: Vec<u16>,
    /// The ECDHE group from ServerKeyExchange (TLS ≤ 1.2) or the key share (1.3).
    pub kx_group: Option<u16>,
    /// The signature scheme the server signed its key exchange with (TLS 1.2 and 1.3).
    pub sig_scheme: Option<u16>,
    /// A 1.3 server answered HelloRetryRequest, wanting a key share for this group. The
    /// probe carries only x25519, so the flight ends there.
    pub hello_retry: Option<u16>,
}

/// One certificate after the leaf: hashed always, read when it parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCert {
    pub sha256: [u8; 32],
    pub len: u32,
    pub cert: Option<crate::x509::Leaf>,
    pub cert_error: Option<&'static str>,
}

impl ChainCert {
    fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mut v = json!({ "sha256": hex(&self.sha256), "len": self.len });
        match (&self.cert, self.cert_error) {
            (Some(c), _) => {
                v["subject"] = json!(c.subject);
                v["issuer"] = json!(c.issuer);
                v["self_signed"] = json!(c.self_signed);
                v["not_after"] = json!(crate::x509::rfc3339(c.not_after));
                v["key"] = json!(c.key);
                v["sig_alg"] = json!(c.sig_alg);
            }
            (None, Some(e)) => v["cert_error"] = json!(e),
            (None, None) => {}
        }
        v
    }
}

/// Send the ClientHello on an open connection and read the reply.
///
/// Always returns an observation, so the record states what was sent even when nothing
/// usable came back.
pub fn probe(
    stream: &TcpStream,
    opts: &TlsProbe,
    connect: Duration,
    sni: Option<&str>,
) -> TlsObservation {
    let hello = client_hello(sni);
    let mut obs = TlsObservation {
        sent_bytes: hello.len() as u32,
        sni: sni.is_some(),
        ..Default::default()
    };
    let wait = opts.wait_for(connect);
    let deadline = Instant::now() + wait;
    if stream.set_write_timeout(Some(wait)).is_err() || stream.set_read_timeout(Some(wait)).is_err()
    {
        obs.error = Some("cannot set socket timeout".into());
        return obs;
    }
    if let Err(e) = (&*stream).write_all(&hello) {
        obs.error = Some(format!("sending ClientHello: {e}"));
        return obs;
    }
    read_server_flight(&mut &*stream, Some(deadline), &mut obs, &hello);
    if let Some(c) = &mut obs.cert {
        let now = (crate::timefmt::now_epoch_ms() / 1000) as i64;
        c.validity = Some(c.validity_at(now));
    }
    obs
}

/// The bytes sent, for the security documentation and for tests that pin them.
pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
    let mut ext = Vec::with_capacity(160);
    if let Some(name) = sni {
        let name = name.as_bytes();
        let mut list = Vec::with_capacity(name.len() + 3);
        list.push(0); // host_name
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let mut body = Vec::with_capacity(list.len() + 2);
        body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        body.extend_from_slice(&list);
        push_extension(&mut ext, EXT_SERVER_NAME, &body);
    }
    push_extension(
        &mut ext,
        EXT_SUPPORTED_GROUPS,
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    );
    push_extension(&mut ext, EXT_EC_POINT_FORMATS, &[0x01, 0x00]);
    push_extension(
        &mut ext,
        EXT_SIGNATURE_ALGORITHMS,
        &[
            0x00, 0x18, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x08, 0x07, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
        ],
    );
    push_extension(
        &mut ext,
        EXT_ALPN,
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    );
    push_extension(&mut ext, EXT_EXTENDED_MASTER_SECRET, &[]);
    push_extension(&mut ext, EXT_RENEGOTIATION_INFO, &[0x00]);
    // 1.3 first, 1.2 second: a server picks the highest it has.
    push_extension(
        &mut ext,
        EXT_SUPPORTED_VERSIONS,
        &[0x04, 0x03, 0x04, 0x03, 0x03],
    );
    let mut share = vec![0x00, 0x24];
    share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    share.extend_from_slice(&[0x00, 0x20]);
    share.extend_from_slice(probe_public_key());
    push_extension(&mut ext, EXT_KEY_SHARE, &share);

    let mut body = Vec::with_capacity(64 + CIPHER_SUITES.len() * 2 + ext.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&CLIENT_RANDOM);
    body.push(0);
    body.extend_from_slice(&((CIPHER_SUITES.len() * 2) as u16).to_be_bytes());
    for (id, _) in CIPHER_SUITES {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(HS_CLIENT_HELLO);
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.extend_from_slice(&[RECORD_HANDSHAKE, 0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Read records until ServerHelloDone, an Alert, a bound, or an error. Once the leaf is
/// in hand the flight ending early is not an error: what was read stands.
///
/// Generic over the reader so the fuzz harness can drive it. Fills `obs` as it goes, so
/// a flight that stops halfway still leaves what was learned.
pub fn read_server_flight<R: Read>(
    s: &mut R,
    deadline: Option<Instant>,
    obs: &mut TlsObservation,
    client_hello: &[u8],
) {
    let mut handshake: Vec<u8> = Vec::new();
    let mut total = 0usize;
    let mut tls13 = Flight13 {
        client_hello: client_hello.get(5..).unwrap_or(&[]),
        aead: None,
    };
    loop {
        let mut head = [0u8; 5];
        if let Err(e) = read_exact(s, &mut head, deadline) {
            if obs.leaf_sha256.is_some() {
                return;
            }
            obs.error = Some(if total == 0 && is_timeout(&e) {
                "no reply within the budget".into()
            } else {
                format!("reading TLS record header: {e}")
            });
            return;
        }
        total += 5;
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if head[1] != 0x03 || len > MAX_RECORD {
            obs.error = Some(if head[0] == b'H' && head[1] == b'T' {
                "not TLS: the service answered with HTTP".into()
            } else {
                format!(
                    "not TLS: record {:02x} {:02x}{:02x} length {len}",
                    head[0], head[1], head[2]
                )
            });
            obs.read_bytes = total as u32;
            return;
        }
        if total + len > MAX_FLIGHT_BYTES {
            obs.error = Some(format!("server flight exceeds {MAX_FLIGHT_BYTES} bytes"));
            obs.read_bytes = total as u32;
            return;
        }
        let mut body = vec![0u8; len];
        if let Err(e) = read_exact(s, &mut body, deadline) {
            if obs.leaf_sha256.is_some() {
                return;
            }
            obs.error = Some(format!("reading TLS record body: {e}"));
            obs.read_bytes = total as u32;
            return;
        }
        total += len;
        obs.read_bytes = total as u32;

        match head[0] {
            RECORD_ALERT => {
                if body.len() >= 2 {
                    obs.alert = Some((body[0], body[1]));
                } else {
                    obs.error = Some("truncated alert".into());
                }
                return;
            }
            RECORD_HANDSHAKE => {
                handshake.extend_from_slice(&body);
                match drain_handshake(&mut handshake, obs, &mut tls13) {
                    Flight::Continue => {}
                    Flight::Done => return,
                }
            }
            // 1.3 servers send one for middleboxes' sake; it carries nothing.
            RECORD_CHANGE_CIPHER_SPEC => {}
            RECORD_APPLICATION_DATA => {
                let Some((aead, iv, seq)) = tls13.aead.as_mut() else {
                    obs.error = Some("encrypted record before a TLS 1.3 ServerHello".into());
                    return;
                };
                let nonce = crate::crypto::tls13_nonce(iv, *seq);
                *seq += 1;
                let Some(mut plain) = aead.open(&nonce, &head, &body) else {
                    obs.error = Some("TLS 1.3 record did not decrypt".into());
                    return;
                };
                // Padding is zeros after the content-type byte (RFC 8446 §5.4).
                while plain.last() == Some(&0) {
                    plain.pop();
                }
                match plain.pop() {
                    Some(RECORD_HANDSHAKE) => {
                        handshake.extend_from_slice(&plain);
                        match drain_handshake(&mut handshake, obs, &mut tls13) {
                            Flight::Continue => {}
                            Flight::Done => return,
                        }
                    }
                    Some(RECORD_ALERT) => {
                        if plain.len() >= 2 {
                            obs.alert = Some((plain[0], plain[1]));
                        }
                        return;
                    }
                    _ => {}
                }
            }
            other => {
                obs.error = Some(format!("unexpected TLS record type 0x{other:02x}"));
                return;
            }
        }
    }
}

enum Flight {
    Continue,
    Done,
}

/// What a 1.3 handshake needs across records: the hello we sent, for the transcript,
/// and the server's handshake keys once its share is in.
struct Flight13<'a> {
    client_hello: &'a [u8],
    aead: Option<(crate::crypto::Aes128Gcm, [u8; 12], u64)>,
}

/// Parse every complete handshake message buffered so far.
fn drain_handshake(
    buf: &mut Vec<u8>,
    obs: &mut TlsObservation,
    tls13: &mut Flight13<'_>,
) -> Flight {
    loop {
        if buf.len() < 4 {
            return Flight::Continue;
        }
        let kind = buf[0];
        let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if len > MAX_FLIGHT_BYTES {
            obs.error = Some(format!("handshake message of {len} bytes refused"));
            return Flight::Done;
        }
        if buf.len() < 4 + len {
            return Flight::Continue;
        }
        let raw: Vec<u8> = buf.drain(..4 + len).collect();
        let msg = &raw[4..];
        match kind {
            HS_SERVER_HELLO => {
                let extras = match parse_server_hello(msg, obs) {
                    Ok(x) => x,
                    Err(e) => {
                        obs.error = Some(e);
                        return Flight::Done;
                    }
                };
                if obs.negotiated == Some(0x0304) {
                    if extras.hello_retry {
                        obs.hello_retry = Some(extras.key_share_group.unwrap_or(0));
                        obs.error = Some(format!(
                            "HelloRetryRequest: the server wants a key share for {}",
                            group_name(obs.hello_retry.unwrap_or(0))
                        ));
                        return Flight::Done;
                    }
                    let Some(server_key) = extras
                        .key_share
                        .filter(|k| k.len() == 32 && extras.key_share_group == Some(GROUP_X25519))
                    else {
                        obs.error = Some("TLS 1.3 ServerHello without an x25519 key share".into());
                        return Flight::Done;
                    };
                    let server_key: [u8; 32] = server_key.try_into().unwrap();
                    let shared = crate::crypto::x25519(&PROBE_X25519_PRIVATE, &server_key);
                    let mut transcript = tls13.client_hello.to_vec();
                    transcript.extend_from_slice(&raw);
                    let (key, iv) =
                        crate::crypto::tls13_server_handshake_keys(&shared, &sha256(&transcript));
                    tls13.aead = Some((crate::crypto::Aes128Gcm::new(&key), iv, 0));
                }
            }
            HS_ENCRYPTED_EXTENSIONS => parse_extensions(msg, obs),
            HS_CERTIFICATE => {
                if let Err(e) = parse_certificate(msg, obs, obs.negotiated == Some(0x0304)) {
                    obs.error = Some(e);
                    return Flight::Done;
                }
            }
            HS_SERVER_KEY_EXCHANGE => parse_server_key_exchange(msg, obs),
            HS_CERTIFICATE_VERIFY => {
                if let Some(s) = msg.get(..2) {
                    obs.sig_scheme = Some(u16::from_be_bytes([s[0], s[1]]));
                }
            }
            HS_SERVER_HELLO_DONE | HS_FINISHED => return Flight::Done,
            _ => {}
        }
    }
}

/// What a ServerHello says beyond the observation: whether it is a HelloRetryRequest
/// and the key share it carries.
#[derive(Default)]
struct ServerHelloExtras {
    hello_retry: bool,
    key_share_group: Option<u16>,
    key_share: Option<Vec<u8>>,
}

/// On Linux an expired `SO_RCVTIMEO` surfaces as `WouldBlock`, not `TimedOut`.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn parse_server_hello(m: &[u8], obs: &mut TlsObservation) -> Result<ServerHelloExtras, String> {
    // version(2) random(32) session_id<0..32> cipher(2) compression(1) [extensions]
    let sid_len = *m.get(34).ok_or("ServerHello too short")? as usize;
    let at = 35 + sid_len;
    let cipher = m.get(at..at + 2).ok_or("ServerHello truncated at cipher")?;
    obs.negotiated = Some(u16::from_be_bytes([m[0], m[1]]));
    obs.cipher = Some(u16::from_be_bytes([cipher[0], cipher[1]]));
    obs.compression = m.get(at + 2).copied();
    let mut extras = ServerHelloExtras {
        hello_retry: m[2..34] == HELLO_RETRY_REQUEST_RANDOM,
        ..Default::default()
    };
    let Some(ext) = m.get(at + 3..) else {
        return Ok(extras); // no extensions
    };
    for (kind, body) in extensions(ext) {
        if obs.server_extensions.len() < MAX_SERVER_EXTENSIONS {
            obs.server_extensions.push(kind);
        }
        match kind {
            EXT_ALPN => obs.alpn = alpn_from(body),
            // The real version: the fixed field says 1.2 for a 1.3 server.
            EXT_SUPPORTED_VERSIONS if body == [0x03, 0x04] => obs.negotiated = Some(0x0304),
            EXT_KEY_SHARE if body.len() >= 2 => {
                let group = u16::from_be_bytes([body[0], body[1]]);
                extras.key_share_group = Some(group);
                obs.kx_group = Some(group);
                if !extras.hello_retry && body.len() >= 4 {
                    let n = u16::from_be_bytes([body[2], body[3]]) as usize;
                    extras.key_share = body.get(4..4 + n).map(<[u8]>::to_vec);
                }
            }
            _ => {}
        }
    }
    Ok(extras)
}

/// `extensions<0..2^16-1>`: `(type, body)` pairs, stopping at the first malformed one.
fn extensions(m: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if m.len() < 2 {
        return out;
    }
    let ext_len = u16::from_be_bytes([m[0], m[1]]) as usize;
    let end = (2 + ext_len).min(m.len());
    let mut p = 2;
    while p + 4 <= end && out.len() < MAX_SERVER_EXTENSIONS {
        let kind = u16::from_be_bytes([m[p], m[p + 1]]);
        let len = u16::from_be_bytes([m[p + 2], m[p + 3]]) as usize;
        p += 4;
        let Some(body) = m.get(p..p + len).filter(|_| p + len <= end) else {
            break;
        };
        out.push((kind, body));
        p += len;
    }
    out
}

fn alpn_from(body: &[u8]) -> Option<String> {
    let n = *body.get(2)? as usize;
    let proto = body.get(3..3 + n)?;
    Some(
        proto
            .iter()
            .map(|&b| {
                if (b' '..=b'~').contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect(),
    )
}

/// EncryptedExtensions: where a 1.3 server puts ALPN.
fn parse_extensions(m: &[u8], obs: &mut TlsObservation) {
    for (kind, body) in extensions(m) {
        if obs.server_extensions.len() < MAX_SERVER_EXTENSIONS {
            obs.server_extensions.push(kind);
        }
        if kind == EXT_ALPN {
            obs.alpn = alpn_from(body);
        }
    }
}

/// `certificate_list<0..2^24-1>`: entries of `length(3) + DER`, each followed in 1.3 by
/// its own `extensions<0..2^16-1>`, the list preceded in 1.3 by a request context.
fn parse_certificate(m: &[u8], obs: &mut TlsObservation, tls13: bool) -> Result<(), String> {
    let start = if tls13 {
        1 + *m.first().ok_or("Certificate message too short")? as usize
    } else {
        0
    };
    let m = m.get(start..).ok_or("Certificate message too short")?;
    if m.len() < 3 {
        return Err("Certificate message too short".into());
    }
    let list_len = u32::from_be_bytes([0, m[0], m[1], m[2]]) as usize;
    let list = m.get(3..(3 + list_len).min(m.len())).unwrap_or(&[]);
    let mut p = 0;
    let mut count = 0u32;
    while p + 3 <= list.len() {
        let len = u32::from_be_bytes([0, list[p], list[p + 1], list[p + 2]]) as usize;
        p += 3;
        let Some(der) = list.get(p..p + len) else {
            break;
        };
        if count == 0 {
            obs.leaf_sha256 = Some(sha256(der));
            obs.leaf_len = Some(der.len() as u32);
            match crate::x509::parse(der) {
                Ok(c) => obs.cert = Some(c),
                Err(e) => obs.cert_error = Some(e),
            }
            if der.len() <= MAX_LEAF_DER {
                obs.leaf_der = Some(der.to_vec());
            }
        } else if obs.chain.len() < MAX_CHAIN_KEPT {
            let (cert, cert_error) = match crate::x509::parse(der) {
                Ok(c) => (Some(c), None),
                Err(e) => (None, Some(e)),
            };
            obs.chain.push(ChainCert {
                sha256: sha256(der),
                len: der.len() as u32,
                cert,
                cert_error,
            });
        }
        count += 1;
        p += len;
        if tls13 {
            let Some(e) = list.get(p..p + 2) else {
                break;
            };
            p += 2 + u16::from_be_bytes([e[0], e[1]]) as usize;
        }
    }
    obs.chain_len = Some(count);
    if count == 0 {
        return Err("Certificate message carried no certificate".into());
    }
    Ok(())
}

/// ECDHE ServerKeyExchange: `curve_type(1)=3 named_curve(2) point<1..> [scheme(2)]
/// signature<2..>`. Only the group and, in 1.2, the scheme are wanted; static-DH and
/// PSK shapes are left alone.
fn parse_server_key_exchange(m: &[u8], obs: &mut TlsObservation) {
    let ecdhe = matches!(obs.cipher, Some(c) if (0xc000..=0xc0ff).contains(&c) || (0xcc00..=0xccff).contains(&c));
    if !ecdhe || m.len() < 4 || m[0] != 3 {
        return;
    }
    obs.kx_group = Some(u16::from_be_bytes([m[1], m[2]]));
    let at = 4 + m[3] as usize;
    if let Some(s) = m.get(at..at + 2).filter(|_| obs.negotiated == Some(0x0303)) {
        obs.sig_scheme = Some(u16::from_be_bytes([s[0], s[1]]));
    }
}

pub fn group_name(id: u16) -> String {
    match id {
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x0019 => "secp521r1".into(),
        0x001d => "x25519".into(),
        0x001e => "x448".into(),
        0x0100 => "ffdhe2048".into(),
        0x0101 => "ffdhe3072".into(),
        0x0102 => "ffdhe4096".into(),
        other => format!("0x{other:04x}"),
    }
}

pub fn sig_scheme_name(id: u16) -> String {
    match id {
        0x0201 => "rsa_pkcs1_sha1".into(),
        0x0203 => "ecdsa_sha1".into(),
        0x0401 => "rsa_pkcs1_sha256".into(),
        0x0403 => "ecdsa_secp256r1_sha256".into(),
        0x0501 => "rsa_pkcs1_sha384".into(),
        0x0503 => "ecdsa_secp384r1_sha384".into(),
        0x0601 => "rsa_pkcs1_sha512".into(),
        0x0603 => "ecdsa_secp521r1_sha512".into(),
        0x0804 => "rsa_pss_rsae_sha256".into(),
        0x0805 => "rsa_pss_rsae_sha384".into(),
        0x0806 => "rsa_pss_rsae_sha512".into(),
        0x0807 => "ed25519".into(),
        0x0808 => "ed448".into(),
        0x0809 => "rsa_pss_pss_sha256".into(),
        0x080a => "rsa_pss_pss_sha384".into(),
        0x080b => "rsa_pss_pss_sha512".into(),
        other => format!("0x{other:04x}"),
    }
}

pub fn alert_name(description: u8) -> &'static str {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        49 => "access_denied",
        50 => "decode_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

pub fn cipher_name(id: u16) -> Option<&'static str> {
    CIPHER_SUITES
        .iter()
        .find(|(c, _)| *c == id)
        .map(|(_, n)| *n)
}

/// The record's `negotiated` value: `1.2`, or `ssl3` for the one pre-TLS version that
/// shares the record format.
pub fn version_name(v: u16) -> String {
    match v {
        0x0304 => "1.3".into(),
        0x0303 => "1.2".into(),
        0x0302 => "1.1".into(),
        0x0301 => "1.0".into(),
        0x0300 => "ssl3".into(),
        0x0002 => "ssl2".into(),
        other => format!("0x{other:04x}"),
    }
}

/// `tls1.2`, `ssl3`: the word a result line uses.
pub fn protocol_label(name: &str) -> String {
    if name.starts_with("ssl") {
        name.to_string()
    } else {
        format!("tls{name}")
    }
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

impl TlsObservation {
    /// The record's `tls` object.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mut v = json!({
            "offered": OFFERED,
            "sent_bytes": self.sent_bytes,
            "read_bytes": self.read_bytes,
            "sni": self.sni,
            "negotiated": self.negotiated.map(version_name),
            "cipher": self.cipher.map(|c| format!("0x{c:04x}")),
            "cipher_name": self.cipher.and_then(cipher_name),
            "alpn": self.alpn,
            "alert": self.alert.map(|(l, d)| json!({"level": l, "description": d, "name": alert_name(d)})),
            "leaf_sha256": self.leaf_sha256.map(|h| hex(&h)),
            "leaf_len": self.leaf_len,
            "chain_len": self.chain_len,
            "cert": self.cert.as_ref().map(|c| c.to_json()),
            "chain": self.chain.iter().map(ChainCert::to_json).collect::<Vec<_>>(),
            "compression": self.compression,
            "server_extensions": self.server_extensions.iter().map(|e| format!("0x{e:04x}")).collect::<Vec<_>>(),
            "secure_renegotiation": self.server_extensions.contains(&EXT_RENEGOTIATION_INFO),
            "extended_master_secret": self.server_extensions.contains(&EXT_EXTENDED_MASTER_SECRET),
            "session_ticket": self.server_extensions.contains(&EXT_SESSION_TICKET),
            "kx_group": self.kx_group.map(group_name),
            "sig_scheme": self.sig_scheme.map(sig_scheme_name),
            "hello_retry_request": self.hello_retry.map(group_name),
        });
        if let Some(e) = self.cert_error {
            v["cert_error"] = json!(e);
        }
        if let Some(der) = &self.leaf_der {
            v["leaf_der"] = json!(base64(der));
        }
        if let Some(e) = &self.error {
            v["error"] = json!(e);
        }
        v
    }

    /// One short field for a result line: `tls1.2 h2 sha256:ab12cd34`, or what went wrong.
    pub fn display(&self) -> String {
        if let Some((_, d)) = self.alert {
            return format!("tls alert {}", alert_name(d));
        }
        let mut s = match self.negotiated {
            Some(v) => protocol_label(&version_name(v)),
            None => {
                return match &self.error {
                    Some(e) if e.starts_with("not TLS") => "not tls".into(),
                    _ => "tls no reply".into(),
                };
            }
        };
        if let Some(a) = &self.alpn {
            s.push(' ');
            s.push_str(a);
        }
        if let Some(g) = self.hello_retry {
            s.push_str(" hrr:");
            s.push_str(&group_name(g));
        }
        if let Some(c) = &self.cert {
            let words = c.summary();
            if !words.is_empty() {
                s.push(' ');
                s.push_str(&words);
            }
        }
        if let Some(h) = &self.leaf_sha256 {
            s.push_str(" sha256:");
            s.push_str(&hex(&h[..4]));
        }
        s
    }
}

/// FIPS 180-4, hand-rolled: eighty lines against a dependency for one hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_fips_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A multi-block message crossing the padding boundary.
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million_a)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn the_client_hello_is_a_well_formed_record_offering_13_and_12() {
        let h = client_hello(None);
        assert_eq!(
            &h[..3],
            &[0x16, 0x03, 0x01],
            "handshake record, legacy version"
        );
        let rec_len = u16::from_be_bytes([h[3], h[4]]) as usize;
        assert_eq!(rec_len + 5, h.len());
        assert_eq!(h[5], HS_CLIENT_HELLO);
        let hs_len = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
        assert_eq!(hs_len + 9, h.len());
        assert_eq!(&h[9..11], &[0x03, 0x03], "legacy version field says 1.2");
        assert_eq!(&h[11..43], &CLIENT_RANDOM);
        assert_eq!(h[43], 0, "no session id");
        let suites = u16::from_be_bytes([h[44], h[45]]) as usize;
        assert_eq!(suites, CIPHER_SUITES.len() * 2);
        assert_eq!(&h[46..48], &[0x13, 0x01], "the 1.3 suite leads");
        // supported_versions names 1.3 then 1.2; key_share carries the x25519 point.
        let sv = [0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03];
        assert!(h.windows(sv.len()).any(|w| w == sv));
        let mut ks = vec![0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
        ks.extend_from_slice(probe_public_key());
        assert!(h.windows(ks.len()).any(|w| w == ks));
        assert_eq!(
            crate::crypto::x25519_public(&PROBE_X25519_PRIVATE),
            *probe_public_key()
        );
    }

    #[test]
    fn a_hello_retry_request_names_the_group_and_ends_the_flight() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01, 0x00]);
        let mut ext = Vec::new();
        push_extension(&mut ext, EXT_SUPPORTED_VERSIONS, &[0x03, 0x04]);
        push_extension(&mut ext, EXT_KEY_SHARE, &[0x00, 0x17]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![HS_SERVER_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let obs = flight(&record(RECORD_HANDSHAKE, &hs));
        assert_eq!(obs.negotiated, Some(0x0304));
        assert_eq!(obs.hello_retry, Some(0x0017));
        assert!(
            obs.error.as_deref().unwrap().contains("secp256r1"),
            "{obs:?}"
        );
        assert_eq!(obs.display(), "tls1.3 hrr:secp256r1");
        assert_eq!(obs.to_json()["hello_retry_request"], "secp256r1");
    }

    #[test]
    fn an_encrypted_record_before_a_13_hello_is_an_error_not_a_panic() {
        let obs = flight(&record(RECORD_APPLICATION_DATA, &[0u8; 40]));
        assert!(obs.error.as_deref().unwrap().contains("before"), "{obs:?}");
        let mut bytes = crate::testsupport::tls::tls13_flight(&client_hello(None)[5..], Some("h2"));
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        let obs = flight(&bytes);
        assert_eq!(obs.negotiated, Some(0x0304));
        assert!(
            obs.error.as_deref().unwrap().contains("did not decrypt"),
            "{obs:?}"
        );
    }

    #[test]
    fn a_13_flight_is_decrypted_to_certificate_alpn_and_signature() {
        let hello = client_hello(Some("fixture.scanr.invalid"));
        let bytes = crate::testsupport::tls::tls13_flight(&hello[5..], Some("h2"));
        let mut obs = TlsObservation::default();
        read_server_flight(&mut std::io::Cursor::new(&bytes), None, &mut obs, &hello);
        assert_eq!(obs.error, None, "{obs:?}");
        assert_eq!(obs.negotiated, Some(0x0304));
        assert_eq!(obs.cipher, Some(0x1301));
        assert_eq!(obs.kx_group, Some(GROUP_X25519));
        assert_eq!(obs.alpn.as_deref(), Some("h2"));
        assert_eq!(obs.sig_scheme, Some(0x0403));
        assert_eq!(obs.chain_len, Some(2));
        assert_eq!(
            obs.leaf_der.as_deref(),
            Some(crate::testsupport::tls::FIXTURE_CERT_DER)
        );
        assert_eq!(
            obs.cert.as_ref().unwrap().subject,
            "CN=fixture.scanr.invalid"
        );
        assert!(obs.server_extensions.contains(&EXT_ALPN));
        let j = obs.to_json();
        assert_eq!(j["negotiated"], "1.3");
        assert_eq!(j["cipher_name"], "TLS_AES_128_GCM_SHA256");
        assert_eq!(j["offered"], "1.3,1.2");
        assert!(
            obs.display()
                .starts_with("tls1.3 h2 cn=fixture.scanr.invalid self-signed sha256:"),
            "{}",
            obs.display()
        );
    }

    #[test]
    fn sni_is_present_only_for_a_hostname() {
        let without = client_hello(None);
        let with = client_hello(Some("app.internal"));
        assert!(with.len() > without.len());
        let needle = b"app.internal";
        assert!(with.windows(needle.len()).any(|w| w == needle));
        assert!(!without.windows(needle.len()).any(|w| w == needle));
        // The hello is deterministic: the same input gives the same bytes.
        assert_eq!(client_hello(Some("app.internal")), with);
    }

    fn flight(bytes: &[u8]) -> TlsObservation {
        let mut obs = TlsObservation::default();
        read_server_flight(
            &mut std::io::Cursor::new(bytes),
            None,
            &mut obs,
            &client_hello(None),
        );
        obs
    }

    fn server_hello(alpn: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0xc0, 0x2f]);
        body.push(0);
        let mut ext = Vec::new();
        if let Some(a) = alpn {
            let mut list = vec![0, 0, a.len() as u8];
            list.extend_from_slice(a);
            let n = (list.len() - 2) as u16;
            list[0..2].copy_from_slice(&n.to_be_bytes());
            push_extension(&mut ext, EXT_ALPN, &list);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![HS_SERVER_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    fn certificate(ders: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for d in ders {
            list.extend_from_slice(&(d.len() as u32).to_be_bytes()[1..]);
            list.extend_from_slice(d);
        }
        let mut body = (list.len() as u32).to_be_bytes()[1..].to_vec();
        body.extend_from_slice(&list);
        let mut hs = vec![HS_CERTIFICATE];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut r = vec![kind, 0x03, 0x03];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn a_full_flight_yields_version_cipher_alpn_and_the_leaf() {
        let leaf = b"\x30\x82\x01\x00 fake der";
        let mut hs = server_hello(Some(b"h2"));
        hs.extend_from_slice(&certificate(&[leaf, b"issuer"]));
        hs.extend_from_slice(&[HS_SERVER_HELLO_DONE, 0, 0, 0]);
        let obs = flight(&record(RECORD_HANDSHAKE, &hs));
        assert_eq!(obs.error, None);
        assert_eq!(obs.negotiated, Some(0x0303));
        assert_eq!(obs.cipher, Some(0xc02f));
        assert_eq!(obs.alpn.as_deref(), Some("h2"));
        assert_eq!(obs.leaf_der.as_deref(), Some(&leaf[..]));
        assert_eq!(obs.leaf_sha256, Some(sha256(leaf)));
        assert_eq!(obs.chain_len, Some(2));
        assert_eq!(
            obs.display(),
            format!("tls1.2 h2 sha256:{}", hex(&sha256(leaf)[..4]))
        );
    }

    #[test]
    fn key_exchange_hello_extensions_and_the_chain_are_read_from_the_whole_flight() {
        let obs = flight(&crate::testsupport::tls::tls12_flight(Some("h2")));
        assert_eq!(obs.error, None, "{obs:?}");
        assert_eq!(obs.kx_group, Some(0x001d));
        assert_eq!(obs.sig_scheme, Some(0x0403));
        assert_eq!(obs.compression, Some(0));
        assert_eq!(obs.server_extensions, [EXT_RENEGOTIATION_INFO, EXT_ALPN]);
        assert_eq!(obs.chain_len, Some(2));
        assert_eq!(obs.chain.len(), 1, "the leaf is not in its own chain");
        let issuer = obs.chain[0].cert.as_ref().unwrap();
        assert_eq!(issuer.subject, "CN=fixture.scanr.invalid");
        let j = obs.to_json();
        assert_eq!(j["kx_group"], "x25519");
        assert_eq!(j["sig_scheme"], "ecdsa_secp256r1_sha256");
        assert_eq!(j["secure_renegotiation"], true);
        assert_eq!(j["extended_master_secret"], false);
        assert_eq!(j["chain"][0]["subject"], "CN=fixture.scanr.invalid");
        assert_eq!(j["chain"][0]["sig_alg"], "ecdsa-sha256");
        assert_eq!(
            j["cert"]["serial"],
            "33fa2a29649685df458ba05b4b1ceb0f77db2b16"
        );
        assert_eq!(j["cert"]["version"], 3);
    }

    #[test]
    fn a_tls10_flight_without_extensions_or_hello_done_is_read_whole() {
        let obs = flight(&crate::testsupport::tls::tls10_flight());
        assert_eq!(
            obs.error, None,
            "the leaf was in hand when the flight ended: {obs:?}"
        );
        assert_eq!(obs.negotiated, Some(0x0301));
        assert_eq!(obs.cipher, Some(0x002f));
        assert_eq!(obs.compression, Some(0));
        assert!(obs.server_extensions.is_empty());
        assert_eq!(obs.kx_group, None);
        assert!(
            obs.display()
                .starts_with("tls1.0 cn=fixture.scanr.invalid self-signed sha256:"),
            "{}",
            obs.display()
        );
        assert_eq!(obs.to_json()["negotiated"], "1.0");
        assert_eq!(obs.to_json()["cipher_name"], "AES128-SHA");
    }

    #[test]
    fn ssl3_and_ssl2_have_their_own_labels() {
        assert_eq!(version_name(0x0300), "ssl3");
        assert_eq!(protocol_label(&version_name(0x0300)), "ssl3");
        assert_eq!(protocol_label(&version_name(0x0303)), "tls1.2");
        assert_eq!(version_name(0x0002), "ssl2");
        assert_eq!(version_name(0x0299), "0x0299");
    }

    #[test]
    fn handshake_messages_spanning_records_are_reassembled() {
        let leaf = b"leaf";
        let mut hs = server_hello(None);
        hs.extend_from_slice(&certificate(&[leaf]));
        let (a, b) = hs.split_at(20);
        let mut bytes = record(RECORD_HANDSHAKE, a);
        bytes.extend_from_slice(&record(RECORD_HANDSHAKE, b));
        let obs = flight(&bytes);
        assert_eq!(obs.error, None, "{obs:?}");
        assert_eq!(obs.chain_len, Some(1));
        assert_eq!(obs.alpn, None);
    }

    #[test]
    fn an_alert_is_reported_by_name() {
        let obs = flight(&record(RECORD_ALERT, &[2, 70]));
        assert_eq!(obs.alert, Some((2, 70)));
        assert_eq!(obs.display(), "tls alert protocol_version");
        assert_eq!(obs.to_json()["alert"]["name"], "protocol_version");
    }

    #[test]
    fn a_non_tls_answer_is_named_not_parsed() {
        let obs = flight(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        assert!(obs.error.as_deref().unwrap().contains("not TLS"), "{obs:?}");
        assert_eq!(obs.display(), "not tls");
        assert_eq!(obs.negotiated, None);
    }

    #[test]
    fn oversize_records_and_leaves_are_bounded() {
        let obs = flight(&[RECORD_HANDSHAKE, 0x03, 0x03, 0xff, 0xff]);
        assert!(obs.error.as_deref().unwrap().contains("not TLS"), "{obs:?}");

        let big = vec![0x30u8; MAX_LEAF_DER + 1];
        let mut hs = server_hello(None);
        hs.extend_from_slice(&certificate(&[&big]));
        // Split across records, since one record cannot carry it.
        let mut bytes = Vec::new();
        for chunk in hs.chunks(MAX_RECORD) {
            bytes.extend_from_slice(&record(RECORD_HANDSHAKE, chunk));
        }
        let obs = flight(&bytes);
        assert_eq!(obs.leaf_der, None, "over the cap: hashed, not embedded");
        assert_eq!(obs.leaf_sha256, Some(sha256(&big)));
        assert_eq!(obs.leaf_len, Some(big.len() as u32));
        assert!(obs.to_json().get("leaf_der").is_none());
    }

    #[test]
    fn a_truncated_flight_keeps_what_it_learned() {
        let hs = server_hello(Some(b"http/1.1"));
        let mut bytes = record(RECORD_HANDSHAKE, &hs);
        bytes.extend_from_slice(&[RECORD_HANDSHAKE, 0x03, 0x03, 0x01]);
        let obs = flight(&bytes);
        assert_eq!(obs.negotiated, Some(0x0303));
        assert_eq!(obs.alpn.as_deref(), Some("http/1.1"));
        assert!(
            obs.error.as_deref().unwrap().contains("record header"),
            "{obs:?}"
        );
    }

    #[test]
    fn alpn_bytes_are_made_printable() {
        let mut hs = server_hello(Some(b"h\x1b2"));
        hs.extend_from_slice(&[HS_SERVER_HELLO_DONE, 0, 0, 0]);
        let obs = flight(&record(RECORD_HANDSHAKE, &hs));
        assert_eq!(obs.alpn.as_deref(), Some("h.2"));
    }

    #[test]
    fn the_wait_follows_the_connect_within_the_ceiling() {
        let t = TlsProbe::new(Duration::from_secs(1)).unwrap();
        assert_eq!(
            t.wait_for(Duration::from_millis(1)),
            Duration::from_millis(100)
        );
        assert_eq!(
            t.wait_for(Duration::from_millis(100)),
            Duration::from_millis(400)
        );
        assert_eq!(t.wait_for(Duration::from_secs(5)), Duration::from_secs(1));
        assert!(TlsProbe::new(Duration::ZERO).is_err());
    }
}

/// Behaviour through the in-process responder, on both transports.
#[cfg(test)]
mod fixture_tests {
    use std::time::{Duration, Instant};

    use crate::plan::types::{Banner, Fidelity, Timing};
    use crate::probe::State;
    use crate::testsupport::socks5::{Behavior as S, Socks5Fixture};
    use crate::testsupport::tls::{Behavior, FIXTURE_CERT_DER, TlsFixture};
    use crate::tls::{TlsProbe, sha256};
    use crate::transport::{Destination, DirectTransport, ProxyTransport, Transport};

    fn timing(tls: bool) -> Timing {
        Timing {
            concurrency: 1,
            rate: 0,
            proxy_connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            retries: 0,
            retry_delay: Duration::ZERO,
            banner: Some(Banner::new(1024, Duration::from_millis(300)).unwrap()),
            tls: tls.then(|| TlsProbe::new(Duration::from_secs(1)).unwrap()),
        }
    }

    fn direct(fx: &TlsFixture, tls: bool) -> crate::probe::ProbeOutcome {
        DirectTransport::new("d".into()).probe(&Destination::Addr(fx.addr()), &timing(tls))
    }

    #[test]
    fn a_tls12_server_yields_cipher_alpn_and_the_leaf_on_the_direct_path() {
        let fx = TlsFixture::start(Behavior::Tls12 { alpn: Some("h2") });
        let o = direct(&fx, true);
        assert_eq!(o.state, State::Open);
        assert_eq!(o.banner, None, "a TLS server says nothing first");
        let t = o.tls.expect("the probe ran");
        assert_eq!(t.error, None, "{t:?}");
        assert_eq!(t.negotiated, Some(0x0303));
        assert_eq!(t.cipher, Some(0xc02f));
        assert_eq!(t.alpn.as_deref(), Some("h2"));
        assert_eq!(t.leaf_der.as_deref(), Some(FIXTURE_CERT_DER));
        assert_eq!(t.leaf_sha256, Some(sha256(FIXTURE_CERT_DER)));
        assert_eq!(t.chain_len, Some(2));
        assert!(!t.sni, "an address target carries no name");
        assert!(t.sent_bytes > 100);
        assert!(
            t.display()
                .starts_with("tls1.2 h2 cn=fixture.scanr.invalid self-signed sha256:"),
            "{}",
            t.display()
        );
    }

    #[test]
    fn a_tls10_server_is_read_by_stepping_down() {
        let fx = TlsFixture::start(Behavior::Tls10);
        let o = direct(&fx, true);
        assert_eq!(o.state, State::Open);
        let t = o.tls.expect("the probe ran");
        assert_eq!(t.error, None, "{t:?}");
        assert_eq!(t.negotiated, Some(0x0301));
        assert_eq!(
            t.cert.as_ref().map(|c| c.sig_alg.as_str()),
            Some("ecdsa-sha256")
        );
        assert!(
            t.display().starts_with("tls1.0 cn=fixture.scanr.invalid"),
            "{}",
            t.display()
        );
    }

    #[test]
    fn a_resolved_name_travels_as_sni_on_the_direct_path() {
        let fx = TlsFixture::start(Behavior::Tls12 { alpn: Some("h2") });
        let dest = Destination::Resolved(fx.addr(), "fixture.scanr.invalid".into());
        let o = DirectTransport::new("d".into()).probe(&dest, &timing(true));
        let t = o.tls.expect("the probe ran");
        assert!(t.sni, "the name the planner resolved is sent as SNI");
        let cert = t.cert.expect("the fixture leaf parses");
        assert_eq!(cert.subject_cn.as_deref(), Some("fixture.scanr.invalid"));
        assert!(cert.self_signed);
        assert_eq!(cert.validity, Some(crate::x509::Validity::Valid));
        assert_eq!(t.cert_error, None);
    }

    #[test]
    fn off_by_default_sends_nothing() {
        let fx = TlsFixture::start(Behavior::Tls12 { alpn: None });
        let o = direct(&fx, false);
        assert_eq!(o.state, State::Open);
        assert_eq!(o.tls, None, "nothing must be sent unless asked for");
    }

    #[test]
    fn a_service_that_greets_is_never_probed() {
        let fx = TlsFixture::start(Behavior::Greets);
        let o = direct(&fx, true);
        assert_eq!(o.banner.as_deref(), Some(&b"SSH-2.0-fixture\r\n"[..]));
        assert_eq!(o.tls, None, "a banner means not TLS; the hello is not sent");
    }

    #[test]
    fn a_tls13_server_is_read_after_finishing_the_key_exchange() {
        let fx = TlsFixture::start(Behavior::Tls13 { alpn: Some("h2") });
        let o = direct(&fx, true);
        let t = o.tls.expect("the probe ran");
        assert_eq!(t.error, None, "{t:?}");
        assert_eq!(t.negotiated, Some(0x0304));
        assert_eq!(t.alpn.as_deref(), Some("h2"));
        assert_eq!(
            t.cert.as_ref().map(|c| c.subject_cn.as_deref()),
            Some(Some("fixture.scanr.invalid"))
        );
        assert_eq!(t.chain.len(), 1);
        assert!(
            t.display()
                .starts_with("tls1.3 h2 cn=fixture.scanr.invalid"),
            "{}",
            t.display()
        );
    }

    #[test]
    fn a_server_that_rejects_the_offer_is_recorded_as_a_protocol_version_alert() {
        let fx = TlsFixture::start(Behavior::RejectsVersion);
        let t = direct(&fx, true).tls.unwrap();
        assert_eq!(t.alert, Some((2, 70)));
        assert_eq!(t.display(), "tls alert protocol_version");
        assert_eq!(t.negotiated, None);
    }

    #[test]
    fn hostile_and_broken_flights_never_panic_and_say_what_happened() {
        for (b, expect) in [
            (Behavior::NotTls, "not TLS"),
            (Behavior::Oversize, "not TLS"),
            (Behavior::Truncated, "record"),
            (Behavior::Silent, "budget"),
            (
                Behavior::Alert {
                    level: 2,
                    description: 40,
                },
                "",
            ),
        ] {
            let fx = TlsFixture::start(b.clone());
            let t = direct(&fx, true)
                .tls
                .unwrap_or_else(|| panic!("{b:?}: probe did not run"));
            if expect.is_empty() {
                assert_eq!(t.alert, Some((2, 40)), "{b:?}");
            } else {
                let e = t.error.clone().unwrap_or_default();
                assert!(e.contains(expect), "{b:?}: {t:?}");
            }
            assert_eq!(t.leaf_der, None, "{b:?}");
        }
    }

    #[test]
    fn a_trickling_server_cannot_outrun_the_ceiling() {
        let fx = TlsFixture::start(Behavior::Trickle(Duration::from_millis(30)));
        let mut tm = timing(true);
        tm.tls = Some(TlsProbe::new(Duration::from_millis(200)).unwrap());
        let start = Instant::now();
        let o = DirectTransport::new("d".into()).probe(&Destination::Addr(fx.addr()), &tm);
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
        let t = o.tls.unwrap();
        assert!(t.error.is_some() || t.negotiated.is_some(), "{t:?}");
    }

    #[test]
    fn through_a_proxy_a_hostname_target_carries_sni() {
        let fx = TlsFixture::start(Behavior::Tls12 {
            alpn: Some("http/1.1"),
        });
        let proxy = Socks5Fixture::start(S::Faithful);
        let t = ProxyTransport::new("p".into(), proxy.addr(), None, None, Fidelity::Full);
        let o = t.probe(
            &Destination::Host("localhost".into(), fx.addr().port()),
            &timing(true),
        );
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
        let obs = o.tls.expect("the probe ran through the tunnel");
        assert_eq!(obs.error, None, "{obs:?}");
        assert!(
            obs.sni,
            "the hostname survives to the exit hop, so SNI is sent"
        );
        assert_eq!(obs.alpn.as_deref(), Some("http/1.1"));
        assert_eq!(obs.chain_len, Some(2));
    }
}

/// `docs/security.md` lists the exact bytes the probe sends; the source is the authority.
#[cfg(test)]
mod doc_tests {
    #[test]
    fn the_documented_client_hello_matches_the_bytes_sent() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/security.md"),
        )
        .expect("security.md is readable");
        let hello = super::client_hello(None);
        let hex: String = hello.iter().map(|b| format!("{b:02x}")).collect();
        // Wrapped in the document for width; compare with whitespace removed.
        let flat: String = doc.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            flat.contains(&hex),
            "docs/security.md must contain the ClientHello bytes ({} bytes):\n{hex}",
            hello.len()
        );
    }
}
