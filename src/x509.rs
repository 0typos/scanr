//! A bounded reader for the leaf certificate the TLS probe captures (D35, amended).
//!
//! Not a validator: no signature check, no chain, no trust decision. It lifts the fields
//! a scanner wants from DER that is already in the record — subject, issuer,
//! alternative names, validity, key type — so a result line can say
//! `cn=nas.example self-signed` rather than only a hash, and `output results` can say
//! it again from an old record.
//!
//! Every byte here is peer-chosen. Every length is checked against what remains,
//! nesting is fixed by the walk rather than by the input, strings are reduced to
//! printable ASCII and bounded, and the fuzz target `x509_leaf` drives [`parse`].

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::timefmt::{civil_from_days, days_from_civil};

/// Alternative names kept per certificate; the rest are counted in `san_count`.
pub const MAX_NAMES: usize = 64;
/// Longest string kept from any attribute or name: the hostname bound.
const MAX_STRING: usize = 253;
/// Longest rendered distinguished name.
const MAX_DN: usize = 512;
/// Characters of a name shown on a result line.
const DISPLAY_NAME_W: usize = 40;

const TAG_BOOL: u8 = 0x01;
const TAG_INT: u8 = 0x02;
const TAG_BITS: u8 = 0x03;
const TAG_OCTETS: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQ: u8 = 0x30;
const TAG_SET: u8 = 0x31;
/// `[0] EXPLICIT version`, `[3] EXPLICIT extensions` in tbsCertificate.
const TAG_VERSION: u8 = 0xa0;
const TAG_EXTENSIONS: u8 = 0xa3;
/// GeneralName `dNSName [2]` and `iPAddress [7]`.
const TAG_DNS_NAME: u8 = 0x82;
const TAG_IP_ADDRESS: u8 = 0x87;

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_C: &[u8] = &[0x55, 0x04, 0x06];
const OID_L: &[u8] = &[0x55, 0x04, 0x07];
const OID_ST: &[u8] = &[0x55, 0x04, 0x08];
const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2b, 0x65, 0x71];
/// Longest serial kept, in bytes: RFC 5280 allows 20.
const MAX_SERIAL: usize = 20;

/// Where the probe's clock fell against the certificate's validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Expired,
    NotYetValid,
}

impl Validity {
    pub fn name(self) -> &'static str {
        match self {
            Validity::Valid => "valid",
            Validity::Expired => "expired",
            Validity::NotYetValid => "not_yet_valid",
        }
    }
}

/// What the leaf says. Strings are printable ASCII, bounded; nothing is verified.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Leaf {
    /// `C=US, O=Example, CN=host` — the recognised attributes, in certificate order.
    pub subject: String,
    pub subject_cn: Option<String>,
    pub issuer: String,
    /// Issuer and subject are byte-for-byte equal. Not a signature check.
    pub self_signed: bool,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// `dNSName` and `iPAddress` entries, in order, at most [`MAX_NAMES`].
    pub san: Vec<String>,
    /// Every alternative name the certificate carries, kept or not.
    pub san_count: u32,
    /// `rsa-2048`, `ec-p256`, `ed25519`, … or `unknown`.
    pub key: String,
    /// X.509 version: 1, 2 or 3.
    pub version: u8,
    /// Serial number, hex, at most 20 bytes of it.
    pub serial: String,
    /// `rsa-sha256`, `ecdsa-sha256`, `rsa-pss`, `ed25519`, `rsa-sha1`, … or `oid:…`.
    pub sig_alg: String,
    /// Set by the probe from its own clock; absent when read back from DER alone.
    pub validity: Option<Validity>,
}

struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    /// Tag, length and body: what "issuer equals subject" compares.
    raw: &'a [u8],
}

/// One DER element and what follows it. Definite lengths of up to four bytes only —
/// certificates use nothing else — and never past the end of the input.
fn tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8]), &'static str> {
    let (&tag, r) = b.split_first().ok_or("truncated")?;
    let (&l0, r) = r.split_first().ok_or("truncated")?;
    let (len, r) = if l0 < 0x80 {
        (l0 as usize, r)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("unsupported length encoding");
        }
        if r.len() < n {
            return Err("truncated");
        }
        let len = r[..n]
            .iter()
            .fold(0usize, |acc, &x| (acc << 8) | x as usize);
        (len, &r[n..])
    };
    if len > r.len() {
        return Err("length exceeds data");
    }
    let raw_len = b.len() - r.len() + len;
    Ok((
        Tlv {
            tag,
            body: &r[..len],
            raw: &b[..raw_len],
        },
        &r[len..],
    ))
}

fn expect<'a>(
    b: &'a [u8],
    tag: u8,
    what: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), &'static str> {
    let (t, r) = tlv(b).map_err(|_| what)?;
    if t.tag != tag {
        return Err(what);
    }
    Ok((t, r))
}

/// Printable ASCII only, bounded. A BMPString or a hostile attribute renders as dots
/// rather than as terminal control.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_STRING)
        .map(|b| match b {
            0x20..=0x7e => *b as char,
            _ => '.',
        })
        .collect()
}

/// Read the fields of a DER certificate. `Err` names the first thing that was not there.
pub fn parse(der: &[u8]) -> Result<Leaf, &'static str> {
    let (cert, _) = expect(der, TAG_SEQ, "not a certificate")?;
    let (tbs, _) = expect(cert.body, TAG_SEQ, "no tbsCertificate")?;
    let mut rest = tbs.body;
    let mut version = 1u8;
    if let Some((v, r)) = tlv(rest).ok().filter(|(v, _)| v.tag == TAG_VERSION) {
        rest = r;
        if let Ok((n, _)) = tlv(v.body) {
            if n.tag == TAG_INT && n.body.len() == 1 && n.body[0] <= 2 {
                version = n.body[0] + 1;
            }
        }
    }
    let (serial, r) = expect(rest, TAG_INT, "no serial number")?;
    let (sig, r) = expect(r, TAG_SEQ, "no signature algorithm")?;
    let (issuer, r) = expect(r, TAG_SEQ, "no issuer")?;
    let (validity, r) = expect(r, TAG_SEQ, "no validity")?;
    let (subject, r) = expect(r, TAG_SEQ, "no subject")?;
    let (spki, r) = expect(r, TAG_SEQ, "no public key")?;
    rest = r;

    let (not_before, r) = tlv(validity.body).map_err(|_| "no validity")?;
    let (not_after, _) = tlv(r).map_err(|_| "no validity")?;
    let mut leaf = Leaf {
        not_before: time(&not_before)?,
        not_after: time(&not_after)?,
        self_signed: issuer.raw == subject.raw,
        key: key(spki.body),
        version,
        serial: serial_hex(serial.body),
        sig_alg: sig_alg_name(sig.body),
        ..Default::default()
    };
    (leaf.subject, leaf.subject_cn) = name(subject.body);
    (leaf.issuer, _) = name(issuer.body);

    // issuerUniqueID and subjectUniqueID may sit before the extensions.
    while let Ok((t, r)) = tlv(rest) {
        rest = r;
        if t.tag == TAG_EXTENSIONS {
            extensions(t.body, &mut leaf);
            break;
        }
    }
    Ok(leaf)
}

/// `Name ::= SEQUENCE OF SET OF AttributeTypeAndValue`, rendered as `K=v, K=v` for the
/// attributes worth a column; anything else is skipped rather than guessed at.
fn name(body: &[u8]) -> (String, Option<String>) {
    let mut dn = String::new();
    let mut cn = None;
    let mut rest = body;
    while let Ok((set, r)) = tlv(rest) {
        rest = r;
        if set.tag != TAG_SET {
            continue;
        }
        let mut inner = set.body;
        while let Ok((atv, r)) = tlv(inner) {
            inner = r;
            if atv.tag != TAG_SEQ {
                continue;
            }
            let Ok((oid, r)) = tlv(atv.body) else {
                continue;
            };
            let Ok((value, _)) = tlv(r) else {
                continue;
            };
            if oid.tag != TAG_OID {
                continue;
            }
            let key = match oid.body {
                OID_CN => "CN",
                OID_O => "O",
                OID_OU => "OU",
                OID_C => "C",
                OID_ST => "ST",
                OID_L => "L",
                _ => continue,
            };
            let text = printable(value.body);
            if key == "CN" && cn.is_none() {
                cn = Some(text.clone());
            }
            if dn.len() >= MAX_DN {
                continue;
            }
            if !dn.is_empty() {
                dn.push_str(", ");
            }
            let _ = write!(dn, "{key}={text}");
        }
    }
    dn.truncate(MAX_DN);
    (dn, cn)
}

/// `UTCTime` (`YYMMDDHHMMSSZ`, 1950–2049) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`), the
/// two forms RFC 5280 allows, to Unix seconds.
fn time(t: &Tlv<'_>) -> Result<i64, &'static str> {
    let s = t.body;
    let year_digits = match t.tag {
        TAG_UTC_TIME => 2,
        TAG_GENERALIZED_TIME => 4,
        _ => return Err("validity is not a time"),
    };
    let need = year_digits + 10 + 1;
    if s.len() != need || s[need - 1] != b'Z' || !s[..need - 1].iter().all(u8::is_ascii_digit) {
        return Err("validity time is malformed");
    }
    let num = |i: usize, n: usize| -> i64 {
        s[i..i + n]
            .iter()
            .fold(0i64, |acc, b| acc * 10 + i64::from(b - b'0'))
    };
    let year = if year_digits == 4 {
        num(0, 4)
    } else {
        let yy = num(0, 2);
        if yy >= 50 { 1900 + yy } else { 2000 + yy }
    };
    let month = num(year_digits, 2);
    let day = num(year_digits + 2, 2);
    let hour = num(year_digits + 4, 2);
    let minute = num(year_digits + 6, 2);
    let second = num(year_digits + 8, 2);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err("validity time is out of range");
    }
    Ok(days_from_civil(year, month as u32, day as u32) * 86_400
        + hour * 3_600
        + minute * 60
        + second)
}

/// A positive INTEGER's bytes as hex, without the sign byte DER adds.
fn serial_hex(body: &[u8]) -> String {
    let body = match body {
        [0, rest @ ..] if !rest.is_empty() && rest[0] & 0x80 != 0 => rest,
        b => b,
    };
    body.iter()
        .take(MAX_SERIAL)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `AlgorithmIdentifier ::= SEQUENCE { OID, parameters }`, named the short way.
fn sig_alg_name(body: &[u8]) -> String {
    let Ok((oid, _)) = tlv(body) else {
        return "unknown".into();
    };
    if oid.tag != TAG_OID {
        return "unknown".into();
    }
    match oid.body {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, last] => match last {
            0x02 => "rsa-md2",
            0x04 => "rsa-md5",
            0x05 => "rsa-sha1",
            0x0a => "rsa-pss",
            0x0b => "rsa-sha256",
            0x0c => "rsa-sha384",
            0x0d => "rsa-sha512",
            _ => "rsa",
        }
        .into(),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01] => "ecdsa-sha1".into(),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, last] => match last {
            0x02 => "ecdsa-sha256",
            0x03 => "ecdsa-sha384",
            0x04 => "ecdsa-sha512",
            _ => "ecdsa",
        }
        .into(),
        OID_ED25519 => "ed25519".into(),
        OID_ED448 => "ed448".into(),
        other => format!(
            "oid:{}",
            other
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    }
}

/// `SubjectPublicKeyInfo`: the algorithm, and for RSA the modulus size.
fn key(spki: &[u8]) -> String {
    let unknown = || "unknown".to_string();
    let Ok((alg, r)) = tlv(spki) else {
        return unknown();
    };
    let Ok((bits, _)) = tlv(r) else {
        return unknown();
    };
    if alg.tag != TAG_SEQ || bits.tag != TAG_BITS {
        return unknown();
    }
    let Ok((oid, params)) = tlv(alg.body) else {
        return unknown();
    };
    match oid.body {
        OID_RSA => {
            // BIT STRING: one unused-bits byte, then RSAPublicKey { modulus, exponent }.
            let modulus = bits
                .body
                .get(1..)
                .and_then(|b| tlv(b).ok())
                .and_then(|(seq, _)| tlv(seq.body).ok())
                .map(|(m, _)| m.body);
            match modulus {
                Some(m) => format!("rsa-{}", m.iter().skip_while(|&&b| b == 0).count() * 8),
                None => "rsa".into(),
            }
        }
        OID_EC => match tlv(params).ok().map(|(p, _)| p.body) {
            Some(OID_P256) => "ec-p256".into(),
            Some(OID_P384) => "ec-p384".into(),
            Some(OID_P521) => "ec-p521".into(),
            _ => "ec".into(),
        },
        OID_ED25519 => "ed25519".into(),
        OID_ED448 => "ed448".into(),
        _ => unknown(),
    }
}

/// `[3] EXPLICIT Extensions`: only subjectAltName is read.
fn extensions(body: &[u8], leaf: &mut Leaf) {
    let Ok((seq, _)) = tlv(body) else {
        return;
    };
    let mut rest = seq.body;
    while let Ok((ext, r)) = tlv(rest) {
        rest = r;
        let Ok((oid, r)) = tlv(ext.body) else {
            continue;
        };
        if oid.tag != TAG_OID || oid.body != OID_SAN {
            continue;
        }
        let Ok((mut value, r)) = tlv(r) else {
            continue;
        };
        if value.tag == TAG_BOOL {
            // `critical` is present only when true.
            let Ok((v, _)) = tlv(r) else {
                continue;
            };
            value = v;
        }
        if value.tag == TAG_OCTETS {
            alternative_names(value.body, leaf);
        }
        return;
    }
}

/// `GeneralNames ::= SEQUENCE OF GeneralName`: names and addresses kept, everything counted.
fn alternative_names(body: &[u8], leaf: &mut Leaf) {
    let Ok((seq, _)) = tlv(body) else {
        return;
    };
    if seq.tag != TAG_SEQ {
        return;
    }
    let mut rest = seq.body;
    while let Ok((gn, r)) = tlv(rest) {
        rest = r;
        leaf.san_count = leaf.san_count.saturating_add(1);
        if leaf.san.len() >= MAX_NAMES {
            continue;
        }
        match (gn.tag, gn.body.len()) {
            (TAG_DNS_NAME, _) => leaf.san.push(printable(gn.body)),
            (TAG_IP_ADDRESS, 4) => {
                let o: [u8; 4] = gn.body.try_into().unwrap_or_default();
                leaf.san.push(Ipv4Addr::from(o).to_string());
            }
            (TAG_IP_ADDRESS, 16) => {
                let o: [u8; 16] = gn.body.try_into().unwrap_or_default();
                leaf.san.push(Ipv6Addr::from(o).to_string());
            }
            _ => {}
        }
    }
}

/// `2026-08-25T22:35:12Z` from Unix seconds.
pub fn rfc3339(epoch: i64) -> String {
    let (y, m, d) = civil_from_days(epoch.div_euclid(86_400));
    let s = epoch.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3_600,
        s % 3_600 / 60,
        s % 60
    )
}

fn clip(name: &str) -> String {
    let mut s: String = name.chars().take(DISPLAY_NAME_W).collect();
    if name.len() > DISPLAY_NAME_W {
        s.push('…');
    }
    s
}

/// `rsa-sha1` → `sha1`: the hashes a signature should no longer use.
fn weak_hash(sig_alg: &str) -> Option<&'static str> {
    ["sha1", "md5", "md2"]
        .into_iter()
        .find(|h| sig_alg.ends_with(&format!("-{h}")))
}

fn summary_parts(
    name: Option<(&str, &str)>,
    self_signed: bool,
    validity: Option<&str>,
    sig_alg: Option<&str>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some((key, value)) = name {
        parts.push(format!("{key}={}", clip(&printable(value.as_bytes()))));
    }
    if self_signed {
        parts.push("self-signed".into());
    }
    match validity {
        Some("expired") => parts.push("expired".into()),
        Some("not_yet_valid") => parts.push("not-yet-valid".into()),
        _ => {}
    }
    if let Some(h) = sig_alg.and_then(weak_hash) {
        parts.push(format!("{h}-signed"));
    }
    parts.join(" ")
}

impl Leaf {
    pub fn validity_at(&self, now: i64) -> Validity {
        if now < self.not_before {
            Validity::NotYetValid
        } else if now > self.not_after {
            Validity::Expired
        } else {
            Validity::Valid
        }
    }

    /// The name to show: the subject CN, else the first alternative name.
    fn shown_name(&self) -> Option<(&str, &str)> {
        match (&self.subject_cn, self.san.first()) {
            (Some(cn), _) => Some(("cn", cn)),
            (None, Some(san)) => Some(("san", san)),
            (None, None) => None,
        }
    }

    /// `cn=host self-signed expired` — the words a result line adds; empty when the
    /// certificate offers none of them.
    pub fn summary(&self) -> String {
        summary_parts(
            self.shown_name(),
            self.self_signed,
            self.validity.map(Validity::name),
            Some(&self.sig_alg),
        )
    }

    /// The record's `tls.cert` object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "subject": self.subject,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "self_signed": self.self_signed,
            "not_before": rfc3339(self.not_before),
            "not_after": rfc3339(self.not_after),
            "validity": self.validity.map(Validity::name),
            "san": self.san,
            "san_count": self.san_count,
            "key": self.key,
            "version": self.version,
            "serial": self.serial,
            "sig_alg": self.sig_alg,
        })
    }
}

/// [`Leaf::summary`] from a recorded `tls.cert` object, for readers of old records.
/// The values are treated as peer-chosen all over again.
pub fn summary_json(cert: &serde_json::Value) -> String {
    let name = match (cert["subject_cn"].as_str(), cert["san"][0].as_str()) {
        (Some(cn), _) => Some(("cn", cn)),
        (None, Some(san)) => Some(("san", san)),
        (None, None) => None,
    };
    summary_parts(
        name,
        cert["self_signed"].as_bool().unwrap_or(false),
        cert["validity"].as_str(),
        cert["sig_alg"].as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::tls::{EXPIRED_CERT_DER, FIXTURE_CERT_DER, SAN_CERT_DER};

    #[test]
    fn the_fixture_leaf_reads_as_openssl_prints_it() {
        let leaf = parse(FIXTURE_CERT_DER).unwrap();
        assert_eq!(leaf.subject, "CN=fixture.scanr.invalid");
        assert_eq!(leaf.subject_cn.as_deref(), Some("fixture.scanr.invalid"));
        assert_eq!(leaf.issuer, "CN=fixture.scanr.invalid");
        assert!(leaf.self_signed);
        assert_eq!(rfc3339(leaf.not_before), "2026-08-25T22:35:12Z");
        assert_eq!(rfc3339(leaf.not_after), "2036-08-22T22:35:12Z");
        assert!(leaf.san.is_empty());
        assert_eq!(leaf.san_count, 0);
        assert_eq!(leaf.key, "ec-p256");
        assert_eq!(leaf.validity, None);
        assert_eq!(leaf.version, 3);
        assert_eq!(leaf.serial, "33fa2a29649685df458ba05b4b1ceb0f77db2b16");
        assert_eq!(leaf.sig_alg, "ecdsa-sha256");
        assert_eq!(leaf.summary(), "cn=fixture.scanr.invalid self-signed");
    }

    #[test]
    fn alternative_names_and_a_full_dn_are_read() {
        let leaf = parse(SAN_CERT_DER).unwrap();
        assert_eq!(leaf.subject, "C=US, O=scanr fixtures, CN=san.scanr.invalid");
        assert_eq!(
            leaf.san,
            [
                "san.scanr.invalid",
                "*.alt.scanr.invalid",
                "10.0.0.1",
                "fd00::1"
            ]
        );
        assert_eq!(leaf.san_count, 5, "the email address is counted, not kept");
        assert_eq!(rfc3339(leaf.not_before), "2026-01-01T00:00:00Z");
        assert_eq!(rfc3339(leaf.not_after), "2036-01-01T00:00:00Z");
        assert!(leaf.self_signed);
        assert_eq!(leaf.key, "ec-p256");
    }

    #[test]
    fn an_expired_rsa_leaf_says_so_against_the_probe_clock() {
        let mut leaf = parse(EXPIRED_CERT_DER).unwrap();
        assert_eq!(leaf.subject, "CN=expired.scanr.invalid, O=Old Corp, OU=Ops");
        assert_eq!(leaf.key, "rsa-2048");
        assert_eq!(leaf.sig_alg, "rsa-sha256");
        assert_eq!(rfc3339(leaf.not_after), "2021-01-01T00:00:00Z");
        let day = 86_400;
        assert_eq!(
            leaf.validity_at(leaf.not_before - day),
            Validity::NotYetValid
        );
        assert_eq!(leaf.validity_at(leaf.not_before), Validity::Valid);
        assert_eq!(leaf.validity_at(leaf.not_after + day), Validity::Expired);
        leaf.validity = Some(leaf.validity_at(leaf.not_after + day));
        assert_eq!(
            leaf.summary(),
            "cn=expired.scanr.invalid self-signed expired"
        );
        assert_eq!(leaf.to_json()["validity"], "expired");
    }

    #[test]
    fn the_json_form_summarises_exactly_as_the_leaf_does() {
        for der in [FIXTURE_CERT_DER, SAN_CERT_DER, EXPIRED_CERT_DER] {
            let mut leaf = parse(der).unwrap();
            leaf.validity = Some(Validity::Expired);
            assert_eq!(summary_json(&leaf.to_json()), leaf.summary());
        }
        // A tampered record cannot reach the terminal through the summary either.
        let hostile = serde_json::json!({"subject_cn": "a\x1b[2Jb", "self_signed": true});
        assert_eq!(summary_json(&hostile), "cn=a.[2Jb self-signed");
        assert_eq!(summary_json(&serde_json::json!({})), "");
        let old = serde_json::json!({"subject_cn": "legacy", "sig_alg": "rsa-sha1"});
        assert_eq!(summary_json(&old), "cn=legacy sha1-signed");
        assert_eq!(weak_hash("rsa-md5"), Some("md5"));
        assert_eq!(weak_hash("rsa-sha256"), None);
    }

    #[test]
    fn every_prefix_and_every_single_byte_flip_is_survived() {
        for der in [FIXTURE_CERT_DER, SAN_CERT_DER, EXPIRED_CERT_DER] {
            for n in 0..der.len() {
                let _ = parse(&der[..n]);
            }
            let mut copy = der.to_vec();
            for i in 0..copy.len() {
                copy[i] ^= 0xff;
                if let Ok(leaf) = parse(&copy) {
                    let _ = leaf.to_json();
                    for s in [&leaf.subject, &leaf.issuer].into_iter().chain(&leaf.san) {
                        assert!(s.bytes().all(|b| (b' '..=b'~').contains(&b)), "{s:?}");
                    }
                }
                copy[i] ^= 0xff;
            }
        }
        assert_eq!(parse(&[]), Err("not a certificate"));
        assert_eq!(parse(&[0x30, 0x80]), Err("not a certificate"));
        assert_eq!(parse(&[0x30, 0x02, 0x02, 0x00]), Err("no tbsCertificate"));
    }

    #[test]
    fn times_follow_rfc_5280() {
        let utc = |s: &[u8]| {
            time(&Tlv {
                tag: TAG_UTC_TIME,
                body: s,
                raw: s,
            })
        };
        assert_eq!(
            rfc3339(utc(b"491231235959Z").unwrap()),
            "2049-12-31T23:59:59Z"
        );
        assert_eq!(
            rfc3339(utc(b"500101000000Z").unwrap()),
            "1950-01-01T00:00:00Z"
        );
        assert_eq!(
            rfc3339(utc(b"700101000000Z").unwrap()),
            "1970-01-01T00:00:00Z"
        );
        assert!(utc(b"2026-08-25T22").is_err());
        assert!(utc(b"261301000000Z").is_err());
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn long_names_are_clipped_on_screen_only() {
        let long = "x".repeat(80);
        let s = summary_parts(Some(("cn", &long)), false, None, None);
        assert_eq!(s, format!("cn={}…", "x".repeat(DISPLAY_NAME_W)));
    }
}
