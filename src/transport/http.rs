//! HTTP CONNECT proxy hop (RFC 9110 §9.3.6) with optional Basic authentication (RFC 7617).
//!
//! Written directly, as SOCKS5 is (D5): the request is one line and two headers, and the
//! response parser is the security-relevant part — every byte of it is chosen by a proxy
//! scanr does not control, including how long the header block is.
//!
//! Unlike SOCKS5, HTTP has no reply code that means "the destination refused". Which
//! status a proxy sends for a refused or unreachable destination is implementation
//! defined, so the mapping in [`classify`] is deliberately conservative: `2xx` is open,
//! `403` and `407` are named for what they are, and everything else is `error` carrying
//! the status line. `scanr transport test` reports the statuses a given proxy actually
//! uses.

use std::io::Read;
use std::net::IpAddr;
use std::time::Instant;

use super::{Destination, read_exact};
use crate::probe::{Phases, ProbeOutcome, Source, State};

/// The most header bytes a proxy may send before the response is refused. A CONNECT
/// response is a status line and a few headers; anything larger is not answering us.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// The bytes sent to a proxy to open a tunnel.
///
/// Minimal by design: `Host` is required by HTTP/1.1, `Proxy-Authorization` only when
/// credentials are configured, nothing else. No `User-Agent`, because the request is
/// for a tunnel and the proxy is the only party that reads it.
pub fn build_connect_request(
    dest: &Destination,
    username: Option<&str>,
    password: Option<&str>,
) -> Vec<u8> {
    let authority = authority(dest);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
    if let Some(u) = username {
        let cred = base64(format!("{u}:{}", password.unwrap_or("")).as_bytes());
        req.extend_from_slice(format!("Proxy-Authorization: Basic {cred}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req
}

/// `host:port` as the request line and `Host` header want it; IPv6 literals bracketed.
fn authority(dest: &Destination) -> String {
    match dest {
        Destination::Addr(a) | Destination::Resolved(a, _) => match a.ip() {
            IpAddr::V4(v4) => format!("{v4}:{}", a.port()),
            IpAddr::V6(v6) => format!("[{v6}]:{}", a.port()),
        },
        Destination::Host(h, p) => format!("{h}:{p}"),
    }
}

/// What the proxy answered, up to the end of the header block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// The status line, printable ASCII only, without the terminator.
    pub status_line: String,
    /// Header names lower-cased; values trimmed and printable-ASCII filtered. Bounded by
    /// [`MAX_RESPONSE_BYTES`].
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Read one HTTP response header block and parse the status line.
///
/// Reads up to and including the blank line and **not one byte further**: after a
/// `200` the stream is the destination's, and the next bytes may be its banner.
///
/// Generic over the reader so a fuzz harness can drive it. Bounded in bytes by
/// [`MAX_RESPONSE_BYTES`] and in time by `deadline`, so a proxy can neither flood the
/// parser nor trickle it past the budget.
pub fn read_response<R: Read>(s: &mut R, deadline: Option<Instant>) -> std::io::Result<Response> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= MAX_RESPONSE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("response headers exceed {MAX_RESPONSE_BYTES} bytes"),
            ));
        }
        read_exact(s, &mut byte, deadline)?;
        buf.push(byte[0]);
        // The first bytes must spell `HTTP/` before a whole header block is read from
        // something that is not an HTTP proxy at all — checked byte by byte, so a SOCKS5
        // server answering `05 00` is named for what it is rather than as a truncation.
        if buf.len() <= 5 && buf[..] != b"HTTP/"[..buf.len()] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not an HTTP proxy: response did not start with `HTTP/`",
            ));
        }
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
    }
    parse(&buf)
}

fn parse(buf: &[u8]) -> std::io::Result<Response> {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.lines();
    let status_line = printable(lines.next().unwrap_or_default());

    // `HTTP/1.x SP 3DIGIT SP reason`. The reason phrase may be empty (RFC 9112 §4).
    let status = status_line
        .strip_prefix("HTTP/1.")
        .and_then(|r| r.get(1..))
        .and_then(|r| r.strip_prefix(' '))
        .and_then(|r| r.get(..3))
        .and_then(|d| d.parse::<u16>().ok())
        .filter(|c| (100..1000).contains(c))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed HTTP status line `{status_line}`"),
            )
        })?;

    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let (n, v) = l.split_once(':')?;
            Some((n.trim().to_ascii_lowercase(), printable(v.trim())))
        })
        .collect();

    Ok(Response {
        status,
        status_line,
        headers,
    })
}

/// A proxy's bytes reach the screen and the record; a terminal acts on escape sequences.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '.' })
        .collect()
}

/// Map a CONNECT response to a result state.
///
/// Conservative on purpose. HTTP standardises no status for "the destination refused"
/// and proxies disagree — squid, tinyproxy and 3proxy each answer differently, and some
/// use one status for refused and unreachable alike. Guessing `closed` from a `503`
/// would fabricate a verdict; the status line is kept in `reason` instead, and
/// `scanr transport test` shows what this proxy actually sends.
pub fn classify(r: &Response, authenticating: bool, phases: Phases) -> ProbeOutcome {
    match r.status {
        200..=299 => ProbeOutcome::open(phases, Source::ProxyReply),
        407 => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            if authenticating {
                format!("proxy rejected credentials ({})", r.status_line)
            } else {
                let scheme = r
                    .header("proxy-authenticate")
                    .map(|v| format!("; it offers `{v}`"))
                    .unwrap_or_default();
                format!(
                    "proxy requires authentication but no credentials are configured ({}){scheme}",
                    r.status_line
                )
            },
            phases,
        ),
        403 => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            format!("denied by proxy policy ({})", r.status_line),
            phases,
        ),
        _ => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            format!(
                "HTTP proxy answered `{}` — no standard status means refused, so \
                 closed and filtered are not distinguished",
                r.status_line
            ),
            phases,
        ),
    }
}

/// RFC 4648 §4, unpadded input of any length. Hand-rolled: twenty lines against a
/// dependency for one header.
/// Decode standard base64 (the record's `leaf_der`); `None` on any byte outside the
/// alphabet. Padding ends the input.
pub fn unbase64(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> std::io::Result<Response> {
        read_response(&mut std::io::Cursor::new(s.as_bytes()), None)
    }

    #[test]
    fn request_is_minimal_and_names_the_authority_twice() {
        let r = build_connect_request(&Destination::Host("app.internal".into(), 8443), None, None);
        assert_eq!(
            String::from_utf8(r).unwrap(),
            "CONNECT app.internal:8443 HTTP/1.1\r\nHost: app.internal:8443\r\n\r\n"
        );
    }

    #[test]
    fn ipv6_literals_are_bracketed() {
        let r = build_connect_request(
            &Destination::Addr("[2001:db8::1]:443".parse().unwrap()),
            None,
            None,
        );
        assert!(
            String::from_utf8(r)
                .unwrap()
                .starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n")
        );
    }

    #[test]
    fn credentials_become_basic_auth() {
        let r = build_connect_request(
            &Destination::Addr("10.0.0.1:80".parse().unwrap()),
            Some("scanner"),
            Some("hunter2"),
        );
        let s = String::from_utf8(r).unwrap();
        assert!(
            s.contains("\r\nProxy-Authorization: Basic c2Nhbm5lcjpodW50ZXIy\r\n"),
            "{s}"
        );
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn unbase64_inverts_base64_and_rejects_strangers() {
        for input in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(unbase64(&base64(input)).as_deref(), Some(input));
        }
        assert_eq!(unbase64("Zm9v YmFy"), None);
        assert_eq!(unbase64("Zm9v\n"), None);
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn parses_a_squid_style_success() {
        let r = parse_str("HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.status_line, "HTTP/1.1 200 Connection established");
        assert!(r.headers.is_empty());
    }

    #[test]
    fn stops_at_the_blank_line_and_leaves_the_tunnel_bytes() {
        let bytes = b"HTTP/1.0 200 OK\r\nVia: fx\r\n\r\nSSH-2.0-banner\r\n";
        let mut c = std::io::Cursor::new(&bytes[..]);
        let r = read_response(&mut c, None).unwrap();
        assert_eq!(r.header("via"), Some("fx"));
        let mut rest = String::new();
        c.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "SSH-2.0-banner\r\n", "the banner must remain unread");
    }

    #[test]
    fn a_bare_lf_terminator_is_tolerated() {
        let r =
            parse_str("HTTP/1.1 503 Service Unavailable\nX-Squid-Error: ERR_CONNECT_FAIL 111\n\n")
                .unwrap();
        assert_eq!(r.status, 503);
        assert_eq!(r.header("x-squid-error"), Some("ERR_CONNECT_FAIL 111"));
    }

    #[test]
    fn an_empty_reason_phrase_is_a_valid_status_line() {
        assert_eq!(parse_str("HTTP/1.1 200 \r\n\r\n").unwrap().status, 200);
    }

    #[test]
    fn not_http_is_rejected_after_five_bytes() {
        // A SOCKS5 proxy answering our CONNECT text.
        let e = parse_str("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("not an HTTP proxy"), "{e}");
    }

    #[test]
    fn malformed_status_lines_are_rejected() {
        for bad in [
            "HTTP/1.1 2O0 OK\r\n\r\n",
            "HTTP/1.1 99 X\r\n\r\n",
            "HTTP/1.1\r\n\r\n",
            "HTTP/2 200\r\n\r\n",
        ] {
            let e = parse_str(bad).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{bad:?}");
        }
    }

    #[test]
    fn a_header_flood_is_bounded() {
        let mut s = String::from("HTTP/1.1 200 OK\r\n");
        while s.len() < MAX_RESPONSE_BYTES + 100 {
            s.push_str("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let e = parse_str(&s).unwrap_err();
        assert!(e.to_string().contains("exceed"), "{e}");
    }

    #[test]
    fn a_truncated_response_is_an_eof() {
        let e = parse_str("HTTP/1.1 20").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn peer_bytes_are_made_printable() {
        let r = parse_str("HTTP/1.1 200 \x1b[2JOK\r\nX-Evil: \x07bell\r\n\r\n").unwrap();
        assert_eq!(r.status_line, "HTTP/1.1 200 .[2JOK");
        assert_eq!(r.header("x-evil"), Some(".bell"));
    }

    #[test]
    fn classification_is_conservative() {
        let p = Phases::default();
        let r = |status: u16, line: &str| Response {
            status,
            status_line: line.into(),
            headers: vec![("proxy-authenticate".into(), "Basic realm=\"fx\"".into())],
        };
        assert_eq!(
            classify(&r(200, "HTTP/1.1 200 OK"), false, p).state,
            State::Open
        );
        let auth = classify(
            &r(407, "HTTP/1.1 407 Proxy Authentication Required"),
            false,
            p,
        );
        assert_eq!(auth.state, State::Error);
        assert!(
            auth.reason.as_deref().unwrap().contains("no credentials"),
            "{auth:?}"
        );
        assert!(
            auth.reason.as_deref().unwrap().contains("Basic"),
            "{auth:?}"
        );
        let bad = classify(
            &r(407, "HTTP/1.1 407 Proxy Authentication Required"),
            true,
            p,
        );
        assert!(
            bad.reason
                .as_deref()
                .unwrap()
                .contains("rejected credentials")
        );
        assert!(
            classify(&r(403, "HTTP/1.1 403 Forbidden"), false, p)
                .reason
                .unwrap()
                .contains("policy")
        );
        for s in [500, 502, 503, 504, 404] {
            let o = classify(&r(s, &format!("HTTP/1.1 {s} X")), false, p);
            assert_eq!(
                o.state,
                State::Error,
                "status {s} must not become a port verdict"
            );
            assert_eq!(o.source, Source::ProxyReply);
            assert!(!o.is_retryable(), "status {s}");
        }
    }
}

/// Behaviour through the in-process HTTP fixture, mirroring the SOCKS5 suite.
#[cfg(test)]
mod path_tests {
    use std::time::{Duration, Instant};

    use crate::plan::types::{Fidelity, Timing};
    use crate::probe::{Source, State};
    use crate::testsupport::http::{Behavior, HttpFixture};
    use crate::testsupport::socks5::{Behavior as S, Socks5Fixture};
    use crate::testsupport::{closed_port, open_listener};
    use crate::transport::{Destination, Hop, ProxyTransport, Reply, Transport};

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

    fn transport(fx: &HttpFixture) -> ProxyTransport {
        ProxyTransport::http("hx".into(), fx.addr(), None, None, Fidelity::OpenOnly)
    }

    #[test]
    fn open_through_an_http_proxy_with_all_three_phases_timed() {
        let (_g, open) = open_listener();
        let fx = HttpFixture::start(Behavior::Faithful);
        let t = transport(&fx);
        let d = t.probe_detailed(&Destination::Addr(open), &timing());
        assert_eq!(d.outcome.state, State::Open, "{:?}", d.outcome.reason);
        assert_eq!(d.outcome.source, Source::ProxyReply);
        assert_eq!(d.reply, Some(Reply::Http(200)));
        assert!(d.outcome.phases.proxy_connect.is_some());
        assert!(
            d.outcome.phases.handshake.is_some(),
            "reachability is judged on it"
        );
        assert!(d.outcome.phases.connect.is_some());
        assert_eq!(t.type_name(), "http");
        assert!(t.supports_remote_dns());
    }

    /// The honesty property for HTTP: a refused destination is `error`, never a
    /// `closed` inferred from a status HTTP does not define for it.
    #[test]
    fn a_refused_destination_is_error_carrying_the_status_line() {
        let fx = HttpFixture::start(Behavior::Faithful);
        let d = transport(&fx).probe_detailed(&Destination::Addr(closed_port()), &timing());
        assert_eq!(d.outcome.state, State::Error);
        assert_eq!(d.outcome.source, Source::ProxyReply);
        assert_eq!(d.reply, Some(Reply::Http(503)));
        let reason = d.outcome.reason.clone().unwrap();
        assert!(reason.contains("503 Service Unavailable"), "{reason}");
        assert!(
            !d.outcome.is_retryable(),
            "a proxy verdict is not a timeout"
        );
    }

    #[test]
    fn a_banner_travels_back_through_the_tunnel() {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let _ = (&s).write_all(b"SSH-2.0-fixture\r\n");
            }
        });
        let fx = HttpFixture::start(Behavior::Faithful);
        let mut t = timing();
        t.banner = Some(crate::plan::types::Banner::new(64, Duration::from_millis(500)).unwrap());
        let o = transport(&fx).probe(&Destination::Addr(addr), &t);
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
        assert_eq!(o.banner.as_deref(), Some(&b"SSH-2.0-fixture\r\n"[..]));
    }

    #[test]
    fn basic_auth_succeeds_and_a_bad_password_is_reported_without_leaking_it() {
        let (_g, open) = open_listener();
        let fx = HttpFixture::start(Behavior::RequireAuth {
            user: "scanner".into(),
            pass: "hunter2".into(),
        });
        let good = ProxyTransport::http(
            "hx".into(),
            fx.addr(),
            Some("scanner".into()),
            Some("hunter2".into()),
            Fidelity::OpenOnly,
        );
        assert_eq!(
            good.probe(&Destination::Addr(open), &timing()).state,
            State::Open
        );

        let bad = ProxyTransport::http(
            "hx".into(),
            fx.addr(),
            Some("scanner".into()),
            Some("wrong".into()),
            Fidelity::OpenOnly,
        );
        let o = bad.probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
        let reason = o.reason.unwrap();
        assert!(reason.contains("rejected credentials"), "{reason}");
        assert!(!reason.contains("wrong"), "password leaked: {reason}");
        assert!(
            !reason.contains("d3Jvbmc"),
            "password leaked base64-encoded: {reason}"
        );
    }

    #[test]
    fn missing_credentials_name_the_scheme_the_proxy_offers() {
        let (_g, open) = open_listener();
        let fx = HttpFixture::start(Behavior::RequireAuth {
            user: "u".into(),
            pass: "p".into(),
        });
        let o = transport(&fx).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
        let reason = o.reason.unwrap();
        assert!(reason.contains("requires authentication"), "{reason}");
        assert!(reason.contains("Basic realm"), "{reason}");
    }

    #[test]
    fn a_socks5_proxy_configured_as_http_is_an_error_not_a_verdict() {
        let fx = HttpFixture::start(Behavior::NotHttp);
        let o = transport(&fx).probe(&Destination::Addr(closed_port()), &timing());
        assert_eq!(o.state, State::Error);
        assert!(o.reason.unwrap().contains("not an HTTP proxy"));
    }

    #[test]
    fn malformed_and_missing_responses_never_panic_and_never_report_open() {
        for b in [
            Behavior::HeaderFlood,
            Behavior::Truncated,
            Behavior::DisconnectBeforeReply,
            Behavior::Status(999),
        ] {
            let fx = HttpFixture::start(b.clone());
            let o = transport(&fx).probe(&Destination::Addr(closed_port()), &timing());
            assert_ne!(o.state, State::Open, "{b:?}");
            assert!(o.reason.is_some(), "{b:?}");
        }
    }

    #[test]
    fn a_silent_proxy_times_out_as_filtered_within_budget() {
        let fx = HttpFixture::start(Behavior::Silent);
        let mut t = timing();
        t.connect_timeout = Duration::from_millis(250);
        let start = Instant::now();
        let o = transport(&fx).probe(&Destination::Addr(closed_port()), &t);
        assert_eq!(o.state, State::Filtered);
        assert_eq!(o.source, Source::Timeout);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_trickling_http_proxy_cannot_outrun_the_budget() {
        let fx = HttpFixture::start(Behavior::Trickle(Duration::from_millis(40)));
        let mut t = timing();
        t.handshake_timeout = Duration::from_millis(150);
        t.connect_timeout = Duration::from_millis(150);
        let started = Instant::now();
        let _ = transport(&fx).probe(&Destination::Addr(closed_port()), &t);
        // ~40 bytes at 40 ms each would be 1.6 s if each read reset the clock.
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn hostnames_are_handed_to_the_proxy_unresolved() {
        let (_g, open) = open_listener();
        let fx = HttpFixture::start(Behavior::Faithful);
        let o = transport(&fx).probe(
            &Destination::Host("localhost".into(), open.port()),
            &timing(),
        );
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
    }

    /// Either protocol's CONNECT yields a raw tunnel, so hops may mix in both orders.
    #[test]
    fn chains_mix_http_and_socks5_hops_in_either_order() {
        let (_g, open) = open_listener();
        let closed = closed_port();
        let h = HttpFixture::start(Behavior::Faithful);
        let s = Socks5Fixture::start(S::Faithful);

        let http_then_socks = ProxyTransport::chained(
            "c".into(),
            vec![Hop::http(h.addr()), Hop::socks5(s.addr())],
            Fidelity::Full,
        );
        assert_eq!(http_then_socks.type_name(), "chain");
        let o = http_then_socks.probe_detailed(&Destination::Addr(open), &timing());
        assert_eq!(o.outcome.state, State::Open, "{:?}", o.outcome.reason);
        // The SOCKS5 exit still says refused distinctly, through an HTTP first hop.
        let c = http_then_socks.probe_detailed(&Destination::Addr(closed), &timing());
        assert_eq!(c.outcome.state, State::Closed, "{:?}", c.outcome.reason);
        assert_eq!(c.reply, Some(Reply::Socks5(0x05)));

        let socks_then_http = ProxyTransport::chained(
            "c".into(),
            vec![Hop::socks5(s.addr()), Hop::http(h.addr())],
            Fidelity::OpenOnly,
        );
        let o = socks_then_http.probe_detailed(&Destination::Addr(open), &timing());
        assert_eq!(o.outcome.state, State::Open, "{:?}", o.outcome.reason);
        let c = socks_then_http.probe_detailed(&Destination::Addr(closed), &timing());
        assert_eq!(
            c.outcome.state,
            State::Error,
            "an HTTP exit cannot say closed"
        );
        assert_eq!(c.reply, Some(Reply::Http(503)));
    }

    #[test]
    fn a_failing_http_hop_is_blamed_by_index_not_reported_as_a_port_verdict() {
        let (_g, open) = open_listener();
        let h = HttpFixture::start(Behavior::Faithful);
        let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let t = ProxyTransport::chained(
            "c".into(),
            vec![Hop::http(h.addr()), Hop::socks5(dead)],
            Fidelity::Full,
        );
        let o = t.probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
        let reason = o.reason.clone().unwrap();
        assert!(reason.contains("hop 1"), "{reason}");
        assert!(reason.contains("503"), "the hop's own words: {reason}");
        assert!(!o.is_retryable());
    }
}
