//! SOCKS5 CONNECT transport (RFC 1928) with optional username/password auth (RFC 1929).
//!
//! Written directly rather than pulling a crate (D5). The protocol is small, and owning
//! it buys three things that matter here: exact control over reply-code mapping, which
//! is what the fidelity model is built on; per-phase timing; and auditable handling of
//! credentials.
//!
//! SOCKS4/4a are deliberately unsupported (D4) — four reply codes cannot express the
//! difference between a closed port and a filtered one.

// Several helpers here return a finished `ProbeOutcome` through the `Err` channel: a
// failed handshake still classifies the probe, which is the point. Boxing it to satisfy
// the size lint would allocate once per failed probe — once per probe, on a scan through
// a dead proxy.
#![allow(clippy::result_large_err)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::{Destination, Reply, Transport, close_without_time_wait, http, read_exact};
use crate::plan::types::{Fidelity, HopKind, Timing};
use crate::probe::{Phases, ProbeOutcome, Source, State};

pub const VERSION: u8 = 0x05;
pub const CMD_CONNECT: u8 = 0x01;
pub const METHOD_NONE: u8 = 0x00;
pub const METHOD_USERPASS: u8 = 0x02;
pub const METHOD_UNACCEPTABLE: u8 = 0xFF;
pub const AUTH_VERSION: u8 = 0x01;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// RFC 1928 section 6.
pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub fn reply_name(code: u8) -> &'static str {
    match code {
        REP_SUCCEEDED => "succeeded",
        REP_GENERAL_FAILURE => "general SOCKS server failure",
        REP_NOT_ALLOWED => "connection not allowed by ruleset",
        REP_NETWORK_UNREACHABLE => "network unreachable",
        REP_HOST_UNREACHABLE => "host unreachable",
        REP_CONNECTION_REFUSED => "connection refused",
        REP_TTL_EXPIRED => "TTL expired",
        REP_CMD_NOT_SUPPORTED => "command not supported",
        REP_ATYP_NOT_SUPPORTED => "address type not supported",
        _ => "unknown reply code",
    }
}

/// One proxy on the path to the destination.
#[derive(Clone)]
pub struct Hop {
    pub kind: HopKind,
    pub address: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Hop {
    pub fn new(
        kind: HopKind,
        address: SocketAddr,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            kind,
            address,
            username,
            password,
        }
    }

    /// An unauthenticated SOCKS5 hop.
    pub fn socks5(address: SocketAddr) -> Self {
        Self::new(HopKind::Socks5, address, None, None)
    }

    /// An unauthenticated HTTP CONNECT hop.
    pub fn http(address: SocketAddr) -> Self {
        Self::new(HopKind::Http, address, None, None)
    }
}

/// Hand-written so a credential cannot reach a log, a panic message or a fuzz dump.
///
/// `ResolvedHop` holds a `Secret`, whose own `Debug` redacts (D14). `build` unwraps that
/// into a bare `String` here, and a derived `Debug` handed it straight back out —
/// `ProxyTransport` had no `Debug` at all before this, so no `{:?}` could reach one.
impl std::fmt::Debug for Hop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hop")
            .field("kind", &self.kind)
            .field("address", &self.address)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// A proxy path: one server, or a chain of them, each SOCKS5 or HTTP CONNECT.
///
/// A chain is the general case and a single proxy is the one-hop degenerate case, so
/// there is one code path rather than two. Each hop is reached *through* the tunnel the
/// previous one opened: greet hop N, ask it to CONNECT to hop N+1, then speak to hop N+1
/// over that tunnel. The last CONNECT names the destination. Either protocol's CONNECT
/// yields a raw tunnel, so hops may mix (D34).
pub struct ProxyTransport {
    name: String,
    hops: Vec<Hop>,
    fidelity: Fidelity,
}

/// Outcome plus the raw reply, which `transport test` needs to judge fidelity.
pub struct DetailedOutcome {
    pub outcome: ProbeOutcome,
    pub reply: Option<Reply>,
}

/// A tunnel to the destination, with what the exit hop said about it.
struct Established {
    s: TcpStream,
    outcome: ProbeOutcome,
    reply: Reply,
    connect_elapsed: Duration,
}

/// What the last hop said to the CONNECT that named the destination.
enum Answer {
    Socks5(u8),
    Http(http::Response),
}

impl ProxyTransport {
    /// A single SOCKS5 proxy.
    pub fn new(
        name: String,
        address: SocketAddr,
        username: Option<String>,
        password: Option<String>,
        fidelity: Fidelity,
    ) -> Self {
        Self::chained(
            name,
            vec![Hop::new(HopKind::Socks5, address, username, password)],
            fidelity,
        )
    }

    /// A single HTTP CONNECT proxy.
    pub fn http(
        name: String,
        address: SocketAddr,
        username: Option<String>,
        password: Option<String>,
        fidelity: Fidelity,
    ) -> Self {
        Self::chained(
            name,
            vec![Hop::new(HopKind::Http, address, username, password)],
            fidelity,
        )
    }

    /// A path of one or more hops. Panics on an empty list, which the resolver refuses.
    pub fn chained(name: String, hops: Vec<Hop>, fidelity: Fidelity) -> Self {
        assert!(!hops.is_empty(), "a proxy path needs at least one hop");
        Self {
            name,
            hops,
            fidelity,
        }
    }

    pub fn hops(&self) -> &[Hop] {
        &self.hops
    }

    /// A second handle on the same proxy, for issuing concurrent probes.
    pub fn clone_for_probe(&self) -> Self {
        Self {
            name: self.name.clone(),
            hops: self.hops.clone(),
            fidelity: self.fidelity,
        }
    }

    fn establish(
        &self,
        dest: &Destination,
        timing: &Timing,
    ) -> Result<Established, DetailedOutcome> {
        let started = Instant::now();
        let first = self.hops[0].address;

        // ── reach the first hop ─────────────────────────────────────────────
        let stream = match TcpStream::connect_timeout(&first, timing.proxy_connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                let phases = Phases {
                    proxy_connect: Some(started.elapsed()),
                    handshake: None,
                    connect: None,
                    total: started.elapsed(),
                };
                return Err(detailed(proxy_unreachable(&e, first, phases), None));
            }
        };
        let proxy_connect = started.elapsed();
        close_without_time_wait(&stream);

        let mut s = stream;
        let _ = s.set_nodelay(true);

        let mut phases = Phases {
            proxy_connect: Some(proxy_connect),
            handshake: None,
            connect: None,
            total: started.elapsed(),
        };

        // ── walk the path ───────────────────────────────────────────────────
        //
        // Each hop is greeted over the tunnel the previous one opened, then asked to
        // CONNECT to the next. Only the final CONNECT names the destination, and only
        // its reply says anything about that destination — an intermediate failure is a
        // fact about the chain, so it is reported as such rather than as a verdict on a
        // port nothing ever reached.
        let handshake_start = Instant::now();
        let last = self.hops.len() - 1;
        for (i, hop) in self.hops.iter().enumerate() {
            if let Err(o) = set_timeouts(&s, timing.handshake_timeout) {
                return Err(detailed(o, None));
            }
            // Each phase gets its own wall-clock deadline, so a peer cannot extend the
            // budget by trickling. HTTP has no greeting to negotiate: its credentials
            // travel on the CONNECT itself.
            if hop.kind == HopKind::Socks5 {
                let hs_deadline = Some(Instant::now() + timing.handshake_timeout);
                if let Err(o) = self.negotiate(&mut s, hop, &mut phases, started, hs_deadline) {
                    return Err(detailed(self.blame_hop(o, i), None));
                }
            }
            if i == last {
                break;
            }
            // Ask this hop for a tunnel to the next one. That reply waits on a real TCP
            // connect from hop N to hop N+1, so it gets the destination budget — the
            // handshake budget is for a local exchange with a proxy already connected to,
            // and a chain across a WAN link exceeds it routinely.
            if let Err(o) = set_timeouts(&s, timing.connect_timeout) {
                return Err(detailed(o, None));
            }
            let next = Destination::Addr(self.hops[i + 1].address);
            if let Err(o) = self.open_tunnel(&mut s, &next, &mut phases, started, i, timing) {
                return Err(detailed(o, None));
            }
        }
        phases.handshake = Some(handshake_start.elapsed());

        // ── the CONNECT that names the destination ──────────────────────────
        // The reply waits on the proxy's own connection to the destination, so this
        // phase gets the destination budget rather than the handshake budget.
        if let Err(o) = set_timeouts(&s, timing.connect_timeout) {
            return Err(detailed(o, None));
        }
        let connect_start = Instant::now();
        let exit = &self.hops[last];
        if let Err(e) = s.write_all(&connect_request(exit, dest)) {
            phases.total = started.elapsed();
            return Err(detailed(
                io_failure(&e, "sending CONNECT request", phases),
                None,
            ));
        }

        let deadline = Some(connect_start + timing.connect_timeout);
        let answer = match exit.kind {
            HopKind::Socks5 => read_reply(&mut s, deadline).map(Answer::Socks5),
            HopKind::Http => http::read_response(&mut s, deadline).map(Answer::Http),
        };
        let connect_elapsed = connect_start.elapsed();
        phases.connect = Some(connect_elapsed);
        phases.total = started.elapsed();

        let (outcome, reply) = match answer {
            Ok(Answer::Socks5(code)) => (classify_reply(code, phases), Reply::Socks5(code)),
            Ok(Answer::Http(r)) => (
                http::classify(&r, exit.username.is_some(), phases),
                Reply::Http(r.status),
            ),
            Err(e) => {
                return Err(detailed(
                    io_failure(&e, "reading CONNECT reply", phases),
                    None,
                ));
            }
        };
        Ok(Established {
            s,
            outcome,
            reply,
            connect_elapsed,
        })
    }

    pub fn probe_detailed(&self, dest: &Destination, timing: &Timing) -> DetailedOutcome {
        let Established {
            s,
            outcome,
            reply,
            connect_elapsed,
        } = match self.establish(dest, timing) {
            Ok(e) => e,
            Err(d) => return d,
        };
        // Through a proxy the tunnel *is* the connection to the destination, so reading
        // a greeting off it works exactly as it does directly. Banner grabbing is one of
        // the few capabilities a proxy does not cost us.
        let banner = timing
            .banner
            .as_ref()
            .filter(|_| outcome.state == State::Open)
            .and_then(|o| super::read_banner(&s, o, connect_elapsed));
        // Through a proxy the hostname survives to here, so SNI can name it.
        let sni = dest.sni();
        let tls = timing
            .tls
            .as_ref()
            .filter(|_| outcome.state == State::Open && banner.is_none())
            .map(|o| {
                crate::tls::probe_with_survey(&s, o, connect_elapsed, sni, &|| {
                    self.connect_again(dest, timing)
                })
            });
        DetailedOutcome {
            outcome: outcome.with_banner(banner).with_tls(tls),
            reply: Some(reply),
        }
    }

    /// The path walked again to the same destination, handed over only when the exit
    /// hop said the port is open.
    pub fn connect_again(&self, dest: &Destination, timing: &Timing) -> Option<TcpStream> {
        self.establish(dest, timing)
            .ok()
            .filter(|e| e.outcome.state == State::Open)
            .map(|e| e.s)
    }

    /// CONNECT from one hop to the next, failing the whole path if it will not.
    fn open_tunnel<S: Read + Write>(
        &self,
        s: &mut S,
        next: &Destination,
        phases: &mut Phases,
        started: Instant,
        from: usize,
        timing: &Timing,
    ) -> Result<(), ProbeOutcome> {
        let hop = &self.hops[from];
        if let Err(e) = s.write_all(&connect_request(hop, next)) {
            phases.total = started.elapsed();
            return Err(self.blame_hop(io_failure(&e, "extending the chain", *phases), from));
        }
        let deadline = Some(Instant::now() + timing.connect_timeout);
        // Success, or the hop's own words for why not.
        let answer = match hop.kind {
            HopKind::Socks5 => {
                read_reply(s, deadline).map(|c| (c == REP_SUCCEEDED, format!("reply 0x{c:02x}")))
            }
            HopKind::Http => http::read_response(s, deadline)
                .map(|r| ((200..=299).contains(&r.status), r.status_line)),
        };
        match answer {
            Ok((true, _)) => Ok(()),
            Ok((false, said)) => {
                phases.total = started.elapsed();
                Err(ProbeOutcome::new(
                    State::Error,
                    Source::ProxyReply,
                    format!(
                        "hop {} ({}) refused to reach hop {} ({}): {said}",
                        from + 1,
                        hop.address,
                        from + 2,
                        self.hops[from + 1].address
                    ),
                    *phases,
                ))
            }
            Err(e) => {
                phases.total = started.elapsed();
                Err(self.blame_hop(
                    io_failure(&e, "reading the chain's CONNECT reply", *phases),
                    from,
                ))
            }
        }
    }

    /// Re-attribute a failure to the hop it happened at.
    ///
    /// **This must rewrite `state`, not just `reason`.** The classifiers underneath are
    /// written for a probe of a destination: a timeout becomes `filtered`, a refusal
    /// becomes `closed`. Applied to a chain that failed while being *established*, those
    /// verdicts are about a port nothing ever reached. Left alone, a single slow link
    /// reported every port in the scan as `filtered` — and because `Source::Timeout` is
    /// retryable and `filtered` is collapsible, each was retried and then folded into a
    /// span, which drops the reason string that held the only hint of the truth.
    ///
    /// A chain that could not be built is an `error` about the chain. Nothing else.
    fn blame_hop(&self, o: ProbeOutcome, index: usize) -> ProbeOutcome {
        let what = o
            .reason
            .unwrap_or_else(|| "the proxy handshake failed".into());
        // Single proxy and chain alike. The `hops.len() == 1` early return this replaces
        // was where the whole point of the function leaked away: a lone proxy that accepts
        // TCP and then stalls made `io_failure` classify the *destination* as `filtered`,
        // for a port nothing had reached. Retryable and span-collapsible, so a stalled
        // proxy produced a scan-wide sweep of confident false negatives.
        let at = if self.hops.len() == 1 {
            format!("with proxy {}", self.hops[0].address)
        } else {
            format!(
                "at hop {} of {}, {}",
                index + 1,
                self.hops.len(),
                self.hops[index].address
            )
        };
        ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            format!("{what} ({at})"),
            o.phases,
        )
    }

    /// Greeting, method selection, and optional authentication.
    ///
    /// Generic over the stream so a fuzz harness can drive the whole exchange with
    /// arbitrary peer bytes. Every byte read here comes from a proxy scanr does not
    /// control, and the auth reply is acted on, so this is worth fuzzing as a unit
    /// rather than only its final reply parser.
    pub fn negotiate<S: Read + Write>(
        &self,
        s: &mut S,
        hop: &Hop,
        phases: &mut Phases,
        started: Instant,
        deadline: Option<Instant>,
    ) -> Result<(), ProbeOutcome> {
        let want_auth = hop.username.is_some();
        let greeting: Vec<u8> = if want_auth {
            vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS]
        } else {
            vec![VERSION, 1, METHOD_NONE]
        };
        let fail = |e: &std::io::Error, what: &str, phases: &Phases| io_failure(e, what, *phases);

        s.write_all(&greeting)
            .map_err(|e| fail(&e, "sending SOCKS5 greeting", phases))?;

        let mut resp = [0u8; 2];
        read_exact(s, &mut resp, deadline)
            .map_err(|e| fail(&e, "reading method selection", phases))?;

        if resp[0] != VERSION {
            phases.total = started.elapsed();
            return Err(ProbeOutcome::new(
                State::Error,
                Source::ProxyReply,
                format!(
                    "not a SOCKS5 proxy: method selection returned version 0x{:02x}",
                    resp[0]
                ),
                *phases,
            ));
        }

        match resp[1] {
            METHOD_NONE => Ok(()),
            METHOD_USERPASS => {
                let (Some(user), pass) = (hop.username.as_ref(), hop.password.as_deref()) else {
                    phases.total = started.elapsed();
                    return Err(ProbeOutcome::new(
                        State::Error,
                        Source::ProxyReply,
                        "proxy requires username/password authentication but none is configured",
                        *phases,
                    ));
                };
                self.authenticate(s, user, pass.unwrap_or(""), phases, started, deadline)
            }
            METHOD_UNACCEPTABLE => {
                phases.total = started.elapsed();
                Err(ProbeOutcome::new(
                    State::Error,
                    Source::ProxyReply,
                    if want_auth {
                        "proxy rejected both no-auth and username/password methods"
                    } else {
                        "proxy requires authentication but no credentials are configured"
                    },
                    *phases,
                ))
            }
            other => {
                phases.total = started.elapsed();
                Err(ProbeOutcome::new(
                    State::Error,
                    Source::ProxyReply,
                    format!("proxy selected unsupported auth method 0x{other:02x}"),
                    *phases,
                ))
            }
        }
    }

    fn authenticate<S: Read + Write>(
        &self,
        s: &mut S,
        user: &str,
        pass: &str,
        phases: &mut Phases,
        started: Instant,
        deadline: Option<Instant>,
    ) -> Result<(), ProbeOutcome> {
        if user.len() > 255 || pass.len() > 255 {
            phases.total = started.elapsed();
            return Err(ProbeOutcome::new(
                State::Error,
                Source::Internal,
                "SOCKS5 username and password must each be at most 255 bytes",
                *phases,
            ));
        }

        let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
        msg.push(AUTH_VERSION);
        msg.push(user.len() as u8);
        msg.extend_from_slice(user.as_bytes());
        msg.push(pass.len() as u8);
        msg.extend_from_slice(pass.as_bytes());

        s.write_all(&msg)
            .map_err(|e| io_failure(&e, "sending SOCKS5 credentials", *phases))?;

        let mut resp = [0u8; 2];
        read_exact(s, &mut resp, deadline)
            .map_err(|e| io_failure(&e, "reading authentication reply", *phases))?;

        // RFC 1929: the reply is VER STATUS with VER = X'01'. Checking it matters because
        // "authenticated" is asserted here on a message not otherwise confirmed to be an
        // authentication reply — every other peer octet in this module is version-checked.
        if resp[0] != AUTH_VERSION {
            phases.total = started.elapsed();
            return Err(ProbeOutcome::new(
                State::Error,
                Source::ProxyReply,
                format!(
                    "authentication reply had version 0x{:02x}, expected 0x01 (RFC 1929)",
                    resp[0]
                ),
                *phases,
            ));
        }
        // RFC 1929: any non-zero status is a failure.
        if resp[1] != 0 {
            phases.total = started.elapsed();
            return Err(ProbeOutcome::new(
                State::Error,
                Source::ProxyReply,
                format!(
                    "proxy rejected credentials for user `{user}` (status 0x{:02x})",
                    resp[1]
                ),
                *phases,
            ));
        }
        Ok(())
    }
}

impl Transport for ProxyTransport {
    fn connect_again(&self, dest: &Destination, timing: &Timing) -> Option<TcpStream> {
        ProxyTransport::connect_again(self, dest, timing)
    }

    fn probe(&self, dest: &Destination, timing: &Timing) -> ProbeOutcome {
        self.probe_detailed(dest, timing).outcome
    }

    fn supports_remote_dns(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// What a single hop is; more than one is a chain whatever the hops speak.
    fn type_name(&self) -> &'static str {
        match self.hops.as_slice() {
            [one] => one.kind.as_str(),
            _ => "chain",
        }
    }

    fn fidelity(&self) -> Fidelity {
        self.fidelity
    }
}

fn detailed(outcome: ProbeOutcome, reply: Option<Reply>) -> DetailedOutcome {
    DetailedOutcome { outcome, reply }
}

/// The CONNECT this hop understands, naming `dest`.
fn connect_request(hop: &Hop, dest: &Destination) -> Vec<u8> {
    match hop.kind {
        HopKind::Socks5 => build_connect_request(dest),
        HopKind::Http => {
            http::build_connect_request(dest, hop.username.as_deref(), hop.password.as_deref())
        }
    }
}

fn set_timeouts(s: &TcpStream, d: Duration) -> Result<(), ProbeOutcome> {
    // Zero would mean "no timeout" to the kernel, which is never what we want.
    let d = if d.is_zero() {
        Duration::from_millis(1)
    } else {
        d
    };
    s.set_read_timeout(Some(d))
        .and_then(|_| s.set_write_timeout(Some(d)))
        .map_err(|e| {
            ProbeOutcome::new(
                State::Error,
                Source::Internal,
                format!("cannot set socket timeout: {e}"),
                Phases::default(),
            )
        })
}

fn proxy_unreachable(e: &std::io::Error, addr: SocketAddr, phases: Phases) -> ProbeOutcome {
    // A failure to reach the proxy is an infrastructure problem, never a statement
    // about the destination port. Reporting it as `filtered` would be a lie.
    let reason = match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => format!("proxy {addr} refused the connection (not listening?)"),
        Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => {
            format!("proxy {addr} is unreachable")
        }
        _ if e.kind() == std::io::ErrorKind::TimedOut => {
            format!("timed out connecting to proxy {addr}")
        }
        _ => format!("cannot reach proxy {addr}: {e}"),
    };
    let source = if e.kind() == std::io::ErrorKind::TimedOut {
        Source::Timeout
    } else {
        Source::LocalStack
    };
    let outcome = ProbeOutcome::new(State::Error, source, reason, phases);

    // Local resource exhaustion outranks saturation: if we ran out of ephemeral ports
    // the proxy never saw the attempt, and that is the condition worth reporting.
    match crate::diag::Pressure::from_os_error(e) {
        Some(p) => outcome.under_pressure(p),
        // Otherwise a refusal or timeout reaching the proxy means it stopped accepting
        // connections, which is unambiguous saturation rather than a destination verdict.
        None if matches!(
            e.raw_os_error(),
            Some(libc::ECONNREFUSED) | Some(libc::ETIMEDOUT)
        ) || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            outcome.under_pressure(crate::diag::Pressure::ProxySaturation)
        }
        None => outcome,
    }
}

fn io_failure(e: &std::io::Error, what: &str, phases: Phases) -> ProbeOutcome {
    use std::io::ErrorKind;
    // On Linux an expired SO_RCVTIMEO surfaces as WouldBlock, not TimedOut.
    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
        return ProbeOutcome::new(
            State::Filtered,
            Source::Timeout,
            format!("timed out {what}"),
            phases,
        );
    }
    if e.kind() == ErrorKind::UnexpectedEof {
        return ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            format!("proxy closed the connection while {what}"),
            phases,
        );
    }
    ProbeOutcome::new(
        State::Error,
        Source::ProxyReply,
        format!("{what}: {e}"),
        phases,
    )
}

pub fn build_connect_request(dest: &Destination) -> Vec<u8> {
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[VERSION, CMD_CONNECT, 0x00]);
    match dest {
        Destination::Addr(a) | Destination::Resolved(a, _) => match a.ip() {
            IpAddr::V4(v4) => {
                req.push(ATYP_IPV4);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(ATYP_IPV6);
                req.extend_from_slice(&v6.octets());
            }
        },
        Destination::Host(h, _) => {
            req.push(ATYP_DOMAIN);
            // Hostnames are validated to <= 253 bytes at parse time.
            let bytes = h.as_bytes();
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
    }
    req.extend_from_slice(&dest.port().to_be_bytes());
    req
}

/// Read a CONNECT reply, consuming the variable-length bound address so a malformed or
/// truncated response is detected rather than silently ignored.
///
/// Generic over the reader so a fuzz harness can drive it with arbitrary bytes. This
/// parses attacker-influenced input — the length byte of an `ATYP_DOMAIN` bound address
/// is supplied by the proxy — so it is the most security-relevant parser in the crate.
pub fn read_reply<R: Read>(s: &mut R, deadline: Option<Instant>) -> std::io::Result<u8> {
    let mut head = [0u8; 4];
    read_exact(s, &mut head, deadline)?;
    if head[0] != VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reply had version 0x{:02x}, expected 0x05", head[0]),
        ));
    }
    let rep = head[1];

    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            read_exact(s, &mut l, deadline)?;
            l[0] as usize
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("reply had unknown address type 0x{other:02x}"),
            ));
        }
    };
    let mut rest = vec![0u8; addr_len + 2];
    read_exact(s, &mut rest, deadline)?;
    Ok(rep)
}

/// Map a SOCKS5 reply code to a result state.
///
/// The precision of this mapping is entirely the proxy's. Many implementations return
/// `0x01` for every failure, which is why non-open results are recorded as `error` with
/// `source = proxy_reply` rather than being guessed into `closed` or `filtered`.
pub fn classify_reply(code: u8, phases: Phases) -> ProbeOutcome {
    match code {
        REP_SUCCEEDED => ProbeOutcome::open(phases, Source::ProxyReply),
        REP_CONNECTION_REFUSED => ProbeOutcome::new(
            State::Closed,
            Source::ProxyReply,
            "connection refused (proxy reply 0x05)",
            phases,
        ),
        REP_NETWORK_UNREACHABLE | REP_HOST_UNREACHABLE | REP_TTL_EXPIRED => ProbeOutcome::new(
            State::Filtered,
            Source::ProxyReply,
            format!("{} (proxy reply 0x{code:02x})", reply_name(code)),
            phases,
        ),
        // Deliberately NOT mapped to closed or filtered: a proxy that collapses every
        // failure into 0x01 would otherwise fabricate results we never observed.
        REP_GENERAL_FAILURE => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            "general SOCKS server failure (proxy reply 0x01) — \
             this proxy does not distinguish closed from filtered",
            phases,
        ),
        REP_NOT_ALLOWED => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            "denied by proxy policy (proxy reply 0x02)",
            phases,
        ),
        other => ProbeOutcome::new(
            State::Error,
            Source::ProxyReply,
            format!("{} (proxy reply 0x{other:02x})", reply_name(other)),
            phases,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::socks5::{Behavior, Socks5Fixture};
    use crate::testsupport::{closed_port, open_listener};

    fn timing() -> Timing {
        Timing {
            concurrency: 1,
            rate: 0,
            proxy_connect_timeout: Duration::from_millis(2000),
            handshake_timeout: Duration::from_millis(2000),
            connect_timeout: Duration::from_millis(2000),
            retries: 0,
            retry_delay: Duration::from_millis(0),
            banner: None,
            tls: None,
        }
    }

    fn transport(fx: &Socks5Fixture) -> ProxyTransport {
        ProxyTransport::new("fx".into(), fx.addr(), None, None, Fidelity::Unknown)
    }

    fn authed(fx: &Socks5Fixture, u: &str, p: &str) -> ProxyTransport {
        ProxyTransport::new(
            "fx".into(),
            fx.addr(),
            Some(u.into()),
            Some(p.into()),
            Fidelity::Unknown,
        )
    }

    fn chain(fixtures: &[&Socks5Fixture]) -> ProxyTransport {
        ProxyTransport::chained(
            "chain".into(),
            fixtures.iter().map(|f| Hop::socks5(f.addr())).collect(),
            Fidelity::Full,
        )
    }

    /// The whole point of a chain: hop two is greeted *through* hop one, and only the
    /// last CONNECT names the destination.
    #[test]
    fn a_two_hop_chain_reaches_the_destination() {
        let (_g, open) = open_listener();
        let a = Socks5Fixture::start(Behavior::Faithful);
        let b = Socks5Fixture::start(Behavior::Faithful);
        let o = chain(&[&a, &b]).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
        assert_eq!(o.source, Source::ProxyReply);
    }

    /// A closed port is still distinguishable through two faithful hops — the reply code
    /// travels back down the chain intact.
    #[test]
    fn a_chain_still_carries_the_refused_reply() {
        let closed = closed_port();
        let a = Socks5Fixture::start(Behavior::Faithful);
        let b = Socks5Fixture::start(Behavior::Faithful);
        let o = chain(&[&a, &b]).probe(&Destination::Addr(closed), &timing());
        assert_eq!(o.state, State::Closed, "{:?}", o.reason);
    }

    /// Three hops, because two could pass by accident on an off-by-one.
    #[test]
    fn a_three_hop_chain_reaches_the_destination() {
        let (_g, open) = open_listener();
        let a = Socks5Fixture::start(Behavior::Faithful);
        let b = Socks5Fixture::start(Behavior::Faithful);
        let c = Socks5Fixture::start(Behavior::Faithful);
        let o = chain(&[&a, &b, &c]).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
    }

    /// The common deployment, and the case the chain fix left behind: ONE proxy that
    /// accepts TCP then stalls. `io_failure` classifies a timeout as `filtered` because it
    /// is written for the destination probe — applied here it fabricates a verdict on a
    /// port nothing reached, retryable and span-collapsible, so a stalled proxy produced a
    /// scan-wide sweep of confident false negatives.
    #[test]
    fn a_single_proxy_that_stalls_is_an_error_not_a_filtered_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        // Accept and never speak.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in l.incoming() {
                held.push(s);
            }
        });
        let t = ProxyTransport::chained("one".into(), vec![Hop::socks5(addr)], Fidelity::Full);
        let mut tm = timing();
        tm.handshake_timeout = std::time::Duration::from_millis(200);

        let o = t.probe(&Destination::Addr("10.0.0.9:443".parse().unwrap()), &tm);
        assert_eq!(o.state, State::Error, "nothing reached 10.0.0.9:443");
        assert_eq!(o.source, Source::ProxyReply);
        assert!(!o.is_retryable(), "a stalled proxy is not worth retrying");
        let reason = o.reason.unwrap_or_default();
        assert!(
            reason.contains(&addr.to_string()),
            "must name the proxy: {reason}"
        );
    }

    /// A link that *times out* is the case that matters, and the one the original test
    /// missed: port 1 answers immediately, so it exercised the reply-code path and left
    /// the timeout path — where the underlying classifier says `filtered` — untested.
    /// A whole scan through one slow link reported every port as filtered.
    #[test]
    fn a_timed_out_link_is_not_a_verdict_on_the_destination() {
        let a = Socks5Fixture::start(Behavior::Faithful);
        // TEST-NET-1 never answers, so hop 1's CONNECT to hop 2 hangs.
        let t = ProxyTransport::chained(
            "c".into(),
            vec![
                Hop::socks5(a.addr()),
                Hop::socks5("192.0.2.1:1080".parse().expect("valid literal")),
            ],
            Fidelity::Full,
        );
        let mut t_ = timing();
        t_.handshake_timeout = std::time::Duration::from_millis(300);
        t_.connect_timeout = std::time::Duration::from_millis(300);

        let o = t.probe(&Destination::Addr("10.0.0.9:443".parse().unwrap()), &t_);
        assert_eq!(
            o.state,
            State::Error,
            "nothing reached 10.0.0.9:443, so nothing may be claimed about it"
        );
        assert_eq!(o.source, Source::ProxyReply);
        // ...and it must not look retryable or collapsible, or the truth in the reason
        // string is retried and then folded into a span.
        assert!(!o.is_retryable(), "a dead chain is not worth retrying");
        let reason = o.reason.clone().unwrap_or_default();
        assert!(reason.contains("hop 1"), "{reason}");
    }

    /// A broken link is a fact about the chain, not a verdict on a port nothing reached.
    /// Without the hop index every chain failure reads as one anonymous proxy error.
    #[test]
    fn a_failure_names_the_hop_it_happened_at() {
        let (_g, open) = open_listener();
        let a = Socks5Fixture::start(Behavior::Faithful);
        // Port 1 is reliably refused and, being privileged, cannot be claimed by another
        // test mid-run. Freeing a fixture's port instead raced: a parallel test could
        // bind it, and the failure then landed at hop two's *handshake* rather than hop
        // one's CONNECT. That passed most of the time, which is the worst kind of test.
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().expect("valid literal");

        let t = ProxyTransport::chained(
            "chain".into(),
            vec![Hop::socks5(a.addr()), Hop::socks5(dead_addr)],
            Fidelity::Full,
        );
        let o = t.probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error, "a dead link is not a port verdict");
        let reason = o.reason.unwrap_or_default();
        assert!(reason.contains("hop 1"), "must name the hop: {reason}");
        assert!(
            reason.contains(&dead_addr.to_string()),
            "and the next address: {reason}"
        );
    }

    #[test]
    fn connects_through_a_faithful_proxy_to_an_open_port() {
        let (_g, open) = open_listener();
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let o = transport(&fx).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
        assert_eq!(o.source, Source::ProxyReply);
        // All three phases must be measured separately through a proxy.
        assert!(o.phases.proxy_connect.is_some());
        assert!(o.phases.handshake.is_some());
        assert!(o.phases.connect.is_some());
    }

    #[test]
    fn faithful_proxy_reports_closed_for_a_refused_port() {
        let closed = closed_port();
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let d = transport(&fx).probe_detailed(&Destination::Addr(closed), &timing());
        assert_eq!(d.outcome.state, State::Closed);
        assert_eq!(d.reply, Some(Reply::Socks5(REP_CONNECTION_REFUSED)));
    }

    #[test]
    fn collapsing_proxy_yields_error_not_a_fabricated_closed() {
        // This is the honesty property: a proxy that returns 0x01 for everything must
        // never produce a `closed` we did not observe.
        let closed = closed_port();
        let fx = Socks5Fixture::start(Behavior::Collapsing);
        let d = transport(&fx).probe_detailed(&Destination::Addr(closed), &timing());
        assert_eq!(d.outcome.state, State::Error);
        assert_eq!(d.reply, Some(Reply::Socks5(REP_GENERAL_FAILURE)));
        assert!(
            d.outcome
                .reason
                .as_deref()
                .unwrap()
                .contains("does not distinguish")
        );
    }

    #[test]
    fn username_password_auth_succeeds() {
        let (_g, open) = open_listener();
        let fx = Socks5Fixture::start(Behavior::RequireAuth {
            user: "scanner".into(),
            pass: "hunter2".into(),
        });
        let o = authed(&fx, "scanner", "hunter2").probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Open, "{:?}", o.reason);
    }

    #[test]
    fn wrong_credentials_are_reported_clearly_without_leaking_the_password() {
        let (_g, open) = open_listener();
        let fx = Socks5Fixture::start(Behavior::RequireAuth {
            user: "scanner".into(),
            pass: "hunter2".into(),
        });
        let o = authed(&fx, "scanner", "wrong").probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
        let reason = o.reason.unwrap();
        assert!(reason.contains("rejected credentials"), "{reason}");
        assert!(!reason.contains("wrong"), "password leaked: {reason}");
    }

    #[test]
    fn missing_credentials_against_an_auth_proxy_says_so() {
        let (_g, open) = open_listener();
        let fx = Socks5Fixture::start(Behavior::RequireAuth {
            user: "u".into(),
            pass: "p".into(),
        });
        let o = transport(&fx).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
        assert!(
            o.reason.unwrap().contains("requires authentication"),
            "should name the actual problem"
        );
    }

    #[test]
    fn no_acceptable_methods_is_an_error() {
        let (_g, open) = open_listener();
        let fx = Socks5Fixture::start(Behavior::NoAcceptableMethods);
        let o = transport(&fx).probe(&Destination::Addr(open), &timing());
        assert_eq!(o.state, State::Error);
    }

    #[test]
    fn disconnect_mid_handshake_never_panics() {
        for phase in ["greeting", "auth", "request"] {
            let fx = Socks5Fixture::start(Behavior::DisconnectAt(phase.into()));
            let o = transport(&fx).probe(&Destination::Addr(closed_port()), &timing());
            assert_eq!(o.state, State::Error, "phase {phase}");
            assert!(o.reason.is_some(), "phase {phase}");
        }
    }

    #[test]
    fn malformed_replies_are_rejected_not_misread() {
        for b in [
            Behavior::WrongVersion,
            Behavior::TruncatedReply,
            Behavior::BadAddressType,
        ] {
            let fx = Socks5Fixture::start(b);
            let o = transport(&fx).probe(&Destination::Addr(closed_port()), &timing());
            assert_eq!(o.state, State::Error);
        }
    }

    /// A peer that answers correctly but slowly must not be able to choose how long a
    /// probe takes. `SO_RCVTIMEO` bounds each read, not the message, so before the
    /// message deadline a trickling proxy held a worker for 26x the configured budget —
    /// and concurrency here is the worker-thread count with no queue behind it.
    #[test]
    fn a_trickling_proxy_cannot_outrun_the_budget() {
        let fx = Socks5Fixture::start(Behavior::Trickle(Duration::from_millis(60)));
        let mut tm = timing();
        tm.handshake_timeout = Duration::from_millis(150);
        tm.connect_timeout = Duration::from_millis(150);

        let started = std::time::Instant::now();
        let o = transport(&fx).probe(&Destination::Addr(closed_port()), &tm);
        let elapsed = started.elapsed();

        // Ten bytes at 60ms each would be 600ms if each read reset the clock.
        assert!(
            elapsed < Duration::from_millis(450),
            "a peer chose the duration: {elapsed:?} against a 150ms budget ({:?})",
            o.state
        );
    }

    #[test]
    fn silent_proxy_times_out_as_filtered() {
        let fx = Socks5Fixture::start(Behavior::SilentAfterHandshake);
        let mut t = timing();
        t.connect_timeout = Duration::from_millis(250);
        let start = Instant::now();
        let o = transport(&fx).probe(&Destination::Addr(closed_port()), &t);
        assert_eq!(o.state, State::Filtered);
        assert_eq!(o.source, Source::Timeout, "must be recognised as a timeout");
        assert!(o.is_retryable());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn unreachable_proxy_is_an_error_never_a_port_verdict() {
        // Port 1, not a bound-then-released one: a parallel test can reuse that.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let t = ProxyTransport::new("dead".into(), dead, None, None, Fidelity::Unknown);
        let o = t.probe(
            &Destination::Addr("10.0.0.1:80".parse().unwrap()),
            &timing(),
        );
        assert_eq!(o.state, State::Error);
        assert!(o.reason.unwrap().contains("refused the connection"));
    }

    #[test]
    fn hostname_targets_are_sent_unresolved() {
        let req = build_connect_request(&Destination::Host("app.internal".into(), 8080));
        assert_eq!(req[0], VERSION);
        assert_eq!(req[1], CMD_CONNECT);
        assert_eq!(req[3], ATYP_DOMAIN);
        assert_eq!(req[4] as usize, "app.internal".len());
        assert_eq!(&req[5..5 + 12], b"app.internal");
        assert_eq!(&req[req.len() - 2..], &8080u16.to_be_bytes());
    }

    #[test]
    fn builds_ipv4_and_ipv6_requests() {
        let v4 = build_connect_request(&Destination::Addr("10.0.0.1:443".parse().unwrap()));
        assert_eq!(v4[3], ATYP_IPV4);
        assert_eq!(&v4[4..8], &[10, 0, 0, 1]);
        assert_eq!(v4.len(), 10);

        let v6 = build_connect_request(&Destination::Addr("[2001:db8::1]:443".parse().unwrap()));
        assert_eq!(v6[3], ATYP_IPV6);
        assert_eq!(v6.len(), 22);
    }

    #[test]
    fn reply_classification_covers_every_defined_code() {
        let p = Phases::default();
        assert_eq!(classify_reply(REP_SUCCEEDED, p).state, State::Open);
        assert_eq!(
            classify_reply(REP_CONNECTION_REFUSED, p).state,
            State::Closed
        );
        for c in [
            REP_NETWORK_UNREACHABLE,
            REP_HOST_UNREACHABLE,
            REP_TTL_EXPIRED,
        ] {
            assert_eq!(classify_reply(c, p).state, State::Filtered, "code {c}");
        }
        for c in [
            REP_GENERAL_FAILURE,
            REP_NOT_ALLOWED,
            REP_CMD_NOT_SUPPORTED,
            REP_ATYP_NOT_SUPPORTED,
            0x7F,
        ] {
            assert_eq!(classify_reply(c, p).state, State::Error, "code {c}");
        }
    }

    #[test]
    fn declares_remote_dns_support() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        assert!(transport(&fx).supports_remote_dns());
        assert_eq!(transport(&fx).type_name(), "socks5");
    }
}
