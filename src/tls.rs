//! The TLS ClientHello probe: the one active probe scanr sends (D35).
//!
//! Off by default. On an open port that volunteered no banner — TLS servers never speak
//! first — a fixed TLS 1.2 ClientHello is written on the same connection and the
//! server's first flight is read: ServerHello (version, cipher, ALPN), Certificate (the
//! leaf, hashed and kept), or an Alert. Then the socket is reset as every probe socket
//! is. No key exchange, no verification. The leaf's names, validity and key are read by
//! [`crate::x509`] — bounded and unverified — and the DER itself is kept for `tlsx`,
//! `openssl x509` and `nmap -sV`.
//!
//! TLS 1.2 only, on purpose. In 1.3 the Certificate and the ALPN answer are encrypted,
//! and reading them means a full handshake — a real TLS stack, which means C or assembly
//! in the tree and the end of the fully static musl build (D19, D28). Offering 1.2 gets
//! ServerHello and Certificate in the clear from every server that still permits it; a
//! 1.3-only server answers a `protocol_version` alert, which is itself evidence.
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
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;
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
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The cipher suites offered, strongest first. Wide enough that a server with any
/// modern or legacy TLS 1.2 configuration finds one it accepts, so a `handshake_failure`
/// means something.
const CIPHER_SUITES: &[(u16, &str)] = &[
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
    read_server_flight(&mut &*stream, Some(deadline), &mut obs);
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
            0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
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
pub fn read_server_flight<R: Read>(s: &mut R, deadline: Option<Instant>, obs: &mut TlsObservation) {
    let mut handshake: Vec<u8> = Vec::new();
    let mut total = 0usize;
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
                match drain_handshake(&mut handshake, obs) {
                    Flight::Continue => {}
                    Flight::Done => return,
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

/// Parse every complete handshake message buffered so far.
fn drain_handshake(buf: &mut Vec<u8>, obs: &mut TlsObservation) -> Flight {
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
        let msg: Vec<u8> = buf.drain(..4 + len).skip(4).collect();
        match kind {
            HS_SERVER_HELLO => {
                if let Err(e) = parse_server_hello(&msg, obs) {
                    obs.error = Some(e);
                    return Flight::Done;
                }
            }
            HS_CERTIFICATE => {
                if let Err(e) = parse_certificate(&msg, obs) {
                    obs.error = Some(e);
                    return Flight::Done;
                }
            }
            HS_SERVER_KEY_EXCHANGE => parse_server_key_exchange(&msg, obs),
            HS_SERVER_HELLO_DONE => return Flight::Done,
            _ => {}
        }
    }
}

/// On Linux an expired `SO_RCVTIMEO` surfaces as `WouldBlock`, not `TimedOut`.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn parse_server_hello(m: &[u8], obs: &mut TlsObservation) -> Result<(), String> {
    // version(2) random(32) session_id<0..32> cipher(2) compression(1) [extensions]
    let sid_len = *m.get(34).ok_or("ServerHello too short")? as usize;
    let at = 35 + sid_len;
    let cipher = m.get(at..at + 2).ok_or("ServerHello truncated at cipher")?;
    obs.negotiated = Some(u16::from_be_bytes([m[0], m[1]]));
    obs.cipher = Some(u16::from_be_bytes([cipher[0], cipher[1]]));
    obs.compression = m.get(at + 2).copied();
    let mut p = at + 3;
    if p + 2 > m.len() {
        return Ok(()); // no extensions
    }
    let ext_len = u16::from_be_bytes([m[p], m[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_len).min(m.len());
    while p + 4 <= end {
        let kind = u16::from_be_bytes([m[p], m[p + 1]]);
        let len = u16::from_be_bytes([m[p + 2], m[p + 3]]) as usize;
        p += 4;
        let body = m.get(p..(p + len).min(end)).unwrap_or(&[]);
        if obs.server_extensions.len() < MAX_SERVER_EXTENSIONS {
            obs.server_extensions.push(kind);
        }
        if kind == EXT_ALPN && body.len() >= 3 {
            let n = body[2] as usize;
            if let Some(proto) = body.get(3..3 + n) {
                obs.alpn = Some(
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
                );
            }
        }
        p += len;
    }
    Ok(())
}

fn parse_certificate(m: &[u8], obs: &mut TlsObservation) -> Result<(), String> {
    // certificate_list<0..2^24-1>: each entry length(3) + DER.
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
            "offered": "1.2",
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
    fn the_client_hello_is_a_well_formed_tls12_record() {
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
        assert_eq!(&h[9..11], &[0x03, 0x03], "offers TLS 1.2 and nothing newer");
        assert_eq!(&h[11..43], &CLIENT_RANDOM);
        assert_eq!(h[43], 0, "no session id");
        let suites = u16::from_be_bytes([h[44], h[45]]) as usize;
        assert_eq!(suites, CIPHER_SUITES.len() * 2);
        // No supported_versions extension (0x002b): that is what would invite 1.3.
        assert!(!h.windows(2).any(|w| w == [0x00, 0x2b]));
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
        read_server_flight(&mut std::io::Cursor::new(bytes), None, &mut obs);
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
    fn a_tls13_only_server_is_recorded_as_a_protocol_version_alert() {
        let fx = TlsFixture::start(Behavior::Tls13Only);
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
