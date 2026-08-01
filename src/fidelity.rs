//! Measuring what a transport can actually tell us (D8).
//!
//! SOCKS5 defines distinct reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`)
//! and policy denial (`0x02`), but implementations vary in whether they use them.
//!
//! Measured against four real proxies rather than assumed:
//!
//! | proxy | refused destination | fidelity |
//! |---|---|---|
//! | microsocks | `0x05` | full |
//! | dante (sockd 1.4.3) | `0x05` | full |
//! | 3proxy | `0x05` | full |
//! | OpenSSH `ssh -D` | no reply; channel closed | open_only |
//!
//! So the awkward real case is not a proxy answering `0x01` for everything — none of the
//! four did that — it is OpenSSH answering *nothing at all*, which is unusable in the
//! same way and needs the same handling.
//!
//! Rather than assume, we probe three destinations whose expected outcomes we know and
//! report what came back. The user learns the fidelity of their results *before*
//! spending an hour on a scan, and non-open results are never guessed into a `closed`
//! we did not observe.

use std::net::SocketAddr;
use std::time::Duration;

use crate::plan::types::{Fidelity, ResolvedTransport, Timing, TransportKind};
use crate::probe::State;
use crate::transport::Destination;
use crate::transport::socks5::{
    REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, Socks5Transport, reply_name,
};

#[derive(Debug)]
pub struct Check {
    pub label: &'static str,
    pub dest: String,
    pub state: State,
    pub reply: Option<u8>,
    pub ms: f64,
    pub expectation: &'static str,
}

/// Loss measured at one concurrency level.
#[derive(Debug, Clone, Copy)]
pub struct Level {
    pub concurrency: u32,
    pub probes: u32,
    /// Probes the proxy refused or ignored, i.e. that never completed a handshake.
    pub refused: u32,
}

impl Level {
    pub fn loss_pct(&self) -> f64 {
        100.0 * self.refused as f64 / self.probes.max(1) as f64
    }
}

/// What concurrency a proxy tolerates, measured by reproducing a scan's churn.
///
/// This is worth measuring because the proxy's limit, not scanr's setting, decides
/// whether a scan succeeds — and it cannot be predicted from a burst. A 3proxy at its
/// default `maxconn 100` accepted 64 *simultaneous* connections happily while losing 48%
/// of probes in a churning scan at concurrency 64, because it holds closed connections in
/// its table long enough for a continuously-reconnecting scanner to exceed the cap. An
/// earlier burst-based probe here reported "64/64 accepted" for exactly that proxy, which
/// would have been false reassurance, so it was removed in favour of this.
#[derive(Debug, Clone)]
pub struct Calibration {
    pub levels: Vec<Level>,
}

impl Calibration {
    /// Highest tested concurrency that lost nothing.
    pub fn recommended(&self) -> Option<u32> {
        self.levels
            .iter()
            .take_while(|l| l.refused == 0)
            .last()
            .map(|l| l.concurrency)
    }

    pub fn degrades(&self) -> bool {
        self.levels.iter().any(|l| l.refused > 0)
    }
}

#[derive(Debug)]
pub struct FidelityReport {
    pub transport: String,
    pub kind: String,
    pub address: Option<String>,
    pub reachable: bool,
    pub auth: Option<String>,
    pub checks: Vec<Check>,
    pub fidelity: Fidelity,
    pub explanation: String,
    pub calibration: Option<Calibration>,
}

/// Probe a transport with destinations of known character.
///
/// Defaults need no user input. Port 1 on the proxy host is reliably closed, and
/// 192.0.2.1 (RFC 5737 TEST-NET-1) is guaranteed unroutable.
///
/// The known-open destination is the awkward one. Using the proxy's own listening socket
/// looked obvious and turned out to fail against half the proxies tested — dante refuses
/// it by ruleset (`0x02`) and 3proxy answers `0x09` — so for a loopback proxy we bind a
/// listener ourselves instead, which it is guaranteed to be able to reach.
pub fn measure(
    transport: &ResolvedTransport,
    timing: &Timing,
    known_open: Option<&str>,
    known_closed: Option<&str>,
    calibrate: bool,
) -> Result<FidelityReport, String> {
    // A pool is N independent paths with N fidelities; one report cannot describe it
    // honestly, and averaging them would be worse than refusing.
    if let TransportKind::Pool { members } = &transport.kind {
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        return Err(format!(
            "`{}` is a pool of {} transports, each with its own fidelity.\n\
             Test them individually: {}",
            transport.name,
            members.len(),
            names
                .iter()
                .map(|n| format!("scanr transport test {n}"))
                .collect::<Vec<_>>()
                .join("\n             ")
        ));
    }
    let (client, address) = match &transport.kind {
        TransportKind::Pool { .. } => unreachable!("refused above"),
        TransportKind::Direct => {
            return Ok(FidelityReport {
                transport: transport.name.clone(),
                kind: "direct".into(),
                address: None,
                reachable: true,
                auth: None,
                checks: Vec::new(),
                fidelity: Fidelity::Full,
                explanation: "Direct connections are classified by the local TCP stack, \
                              which distinguishes refused, unreachable, and timed out. \
                              No measurement is required."
                    .into(),
                calibration: None,
            });
        }
        TransportKind::Socks5 {
            address,
            username,
            password,
        } => (
            Socks5Transport::new(
                transport.name.clone(),
                *address,
                username.clone(),
                password.as_ref().map(|s| s.expose().to_string()),
                Fidelity::Unknown,
            ),
            *address,
        ),
        // End to end, through every hop. Testing only the first would report what that
        // proxy can distinguish, which is not what any result down the chain will show:
        // one collapsing link anywhere flattens everything behind it.
        TransportKind::Chain { hops } => (
            Socks5Transport::chained(
                transport.name.clone(),
                hops.iter()
                    .map(|h| crate::transport::socks5::Hop {
                        address: h.address,
                        username: h.username.clone(),
                        password: h.password.as_ref().map(|s| s.expose().to_string()),
                    })
                    .collect(),
                Fidelity::Unknown,
            ),
            // The *last* hop issues the CONNECT that reaches the calibration targets, so
            // reachability has to be judged from its vantage point. Using hop 1's address
            // made scanr bind a loopback listener and ask a remote exit node to reach it,
            // then report a working chain as unmeasurable.
            hops[hops.len() - 1].address,
        ),
    };

    // Calibration needs a destination the proxy can definitely reach. Using the proxy's
    // own listening socket seemed obvious and fails against real software: dante refuses
    // it by ruleset (reply 0x02) and 3proxy answers 0x09. Two of four proxies tested.
    //
    // When the proxy is on loopback we can do better than guessing — bind a listener
    // ourselves, which the proxy is guaranteed to be able to reach.
    let (open_dest, _own_listener) = known_open_destination(known_open, address)?;
    let closed_dest = parse_dest(known_closed, SocketAddr::new(address.ip(), 1))?;
    let blackhole: SocketAddr = "192.0.2.1:80".parse().expect("valid literal");

    // Give the blackhole check a short leash; waiting the full destination timeout
    // teaches us nothing extra.
    let mut short = timing.clone();
    short.connect_timeout = timing.connect_timeout.min(Duration::from_secs(3));

    let Probes {
        checks,
        reachable,
        auth,
    } = run_checks(
        &client,
        [
            ("known-open", open_dest, "open", timing),
            ("known-closed", closed_dest, "closed", timing),
            ("blackholed", blackhole, "filtered", &short),
        ],
        client.hops().iter().any(|h| h.username.is_some()),
    );

    let closed_reply = checks
        .iter()
        .find(|c| c.label == "known-closed")
        .and_then(|c| c.reply);
    let open_ok = checks
        .iter()
        .find(|c| c.label == "known-open")
        .is_some_and(|c| c.state == State::Open);

    let (fidelity, explanation) = judge(reachable, open_ok, closed_reply);

    // Opt-in: this generates real traffic and takes time, so it is not part of the
    // default check.
    let calibration = if calibrate && reachable && open_ok {
        Some(calibrate_concurrency(&client, timing, blackhole))
    } else {
        None
    };

    Ok(FidelityReport {
        transport: transport.name.clone(),
        kind: transport.type_name().into(),
        address: Some(address.to_string()),
        reachable,
        auth,
        checks,
        fidelity,
        explanation,
        calibration,
    })
}

/// What the three calibration probes established.
struct Probes {
    checks: Vec<Check>,
    reachable: bool,
    auth: Option<String>,
}

/// Probe each calibration destination once and record what came back.
fn run_checks(
    client: &Socks5Transport,
    destinations: [(&'static str, SocketAddr, &'static str, &Timing); 3],
    authenticating: bool,
) -> Probes {
    let mut checks = Vec::new();
    let mut reachable = true;
    let mut auth = None;

    for (label, dest, expectation, t) in destinations {
        let d = client.probe_detailed(&Destination::Addr(dest), t);
        let o = &d.outcome;

        // A failure to reach the proxy itself invalidates every later conclusion.
        //
        // This is decided structurally rather than by matching on message text: if the
        // handshake never completed, we never got a usable channel to the proxy. An
        // earlier string-matching version wrongly treated a *destination* result of
        // "host unreachable (proxy reply 0x04)" as a proxy failure, because the message
        // happens to contain both "proxy" and "unreachable".
        if o.phases.handshake.is_none() {
            reachable = false;
        }
        if let Some(r) = &o.reason
            && r.contains("credentials")
        {
            auth = Some(format!("rejected — {r}"));
            reachable = false;
        }
        if auth.is_none() && authenticating && o.phases.handshake.is_some() {
            auth = Some("accepted (username/password)".into());
        }

        checks.push(Check {
            label,
            dest: dest.to_string(),
            state: o.state,
            reply: d.reply_code,
            ms: o.phases.total.as_secs_f64() * 1000.0,
            expectation,
        });
    }
    Probes {
        checks,
        reachable,
        auth,
    }
}

/// A destination the proxy can definitely reach, plus the listener keeping it alive.
///
/// Using the proxy's own listening socket seemed obvious and fails against real
/// software: dante refuses it by ruleset (reply 0x02) and 3proxy answers 0x09. Two of
/// four proxies tested.
///
/// When the proxy is on loopback we can do better than guessing — bind a listener
/// ourselves, which the proxy is guaranteed to be able to reach. A remote proxy cannot
/// reach our loopback, so there we fall back to its own address and say plainly what to
/// do when that fails.
fn known_open_destination(
    known_open: Option<&str>,
    address: SocketAddr,
) -> Result<(SocketAddr, Option<std::net::TcpListener>), String> {
    if let Some(s) = known_open {
        return Ok((parse_dest(Some(s), address)?, None));
    }
    if !address.ip().is_loopback() {
        return Ok((address, None));
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("cannot bind a calibration listener: {e}"))?;
    let a = l
        .local_addr()
        .map_err(|e| format!("cannot read calibration listener address: {e}"))?;
    // Accept and drop, so the proxy's connection completes.
    let acceptor = l.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        for s in acceptor.incoming() {
            drop(s);
        }
    });
    Ok((a, Some(l)))
}

/// Decide fidelity from the reply to a destination we know is closed.
pub fn judge(reachable: bool, open_ok: bool, closed_reply: Option<u8>) -> (Fidelity, String) {
    if !reachable {
        return (
            Fidelity::Unknown,
            "The proxy could not be reached, so no conclusion about result fidelity \
             is possible."
                .into(),
        );
    }
    if !open_ok {
        // Say what the closed probe implied rather than discarding it. dante and 3proxy
        // both answer 0x05 for a refused destination and are in fact `full`, but both
        // refuse to connect to their own listening port, so a naive calibration reports
        // Unknown and looks like the tool is broken.
        let hint = match closed_reply {
            Some(REP_CONNECTION_REFUSED) => {
                " The known-closed probe did answer 0x05, which suggests full fidelity, \
                 but that is unconfirmed without a working open probe."
            }
            _ => "",
        };
        return (
            Fidelity::Unknown,
            format!(
                "The known-open destination did not report open, so this proxy's replies \
                 cannot be calibrated.{hint} Pass --known-open with a destination you are \
                 certain is reachable from the proxy."
            ),
        );
    }
    match closed_reply {
        Some(REP_CONNECTION_REFUSED) => (
            Fidelity::Full,
            "This proxy reports refused connections distinctly (0x05), so scanr can \
             tell `closed` apart from `filtered` in your results."
                .into(),
        ),
        Some(REP_GENERAL_FAILURE) => (
            Fidelity::OpenOnly,
            "This proxy reports a generic failure (0x01) for refused connections, so \
             scanr cannot distinguish `closed` from `filtered`. Non-open results will \
             be recorded as `error` with source `proxy_reply` rather than guessed."
                .into(),
        ),
        Some(other) => (
            Fidelity::OpenOnly,
            format!(
                "This proxy answered a known-closed destination with 0x{other:02x} ({}), \
                 which is not the refused code (0x05). scanr will treat non-open results \
                 as `error` rather than infer a state it did not observe.",
                reply_name(other)
            ),
        ),
        None => (
            Fidelity::OpenOnly,
            "The known-closed destination produced no usable reply code (the proxy may \
             have timed out or closed the connection, which is what OpenSSH's `ssh -D` \
             does), so closed and filtered cannot be distinguished."
                .into(),
        ),
    }
}

/// Concurrency levels tried, low to high. Stops early once loss appears.
pub const CALIBRATION_LEVELS: &[u32] = &[8, 16, 32, 64, 128, 256];
/// Probes each worker makes per level. More than one is essential: a single round holds
/// connections without ever reconnecting, which is what made the burst probe useless.
const ROUNDS_PER_WORKER: u32 = 4;

/// Reproduce a scan's connection churn at increasing concurrency and report where the
/// proxy starts refusing.
fn calibrate_concurrency(
    client: &Socks5Transport,
    timing: &Timing,
    dest: SocketAddr,
) -> Calibration {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // A destination that hangs is required, so connections are actually held while new
    // ones are made. Kept short so the sweep finishes in reasonable time.
    let mut t = timing.clone();
    let hold = Duration::from_millis(500);
    t.proxy_connect_timeout = timing.proxy_connect_timeout.min(hold);
    t.handshake_timeout = timing.handshake_timeout.min(hold);
    t.connect_timeout = hold;

    let mut levels = Vec::new();
    for &c in CALIBRATION_LEVELS {
        let refused = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(c as usize));
        let mut handles = Vec::with_capacity(c as usize);
        for _ in 0..c {
            let (refused, barrier) = (refused.clone(), barrier.clone());
            let cl = client.clone_for_probe();
            let t = t.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..ROUNDS_PER_WORKER {
                    let o = cl.probe_detailed(&Destination::Addr(dest), &t).outcome;
                    // No handshake means the proxy never took the connection.
                    if o.phases.handshake.is_none() {
                        refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        let level = Level {
            concurrency: c,
            probes: c * ROUNDS_PER_WORKER,
            refused: refused.load(Ordering::Relaxed),
        };
        let degraded = level.refused > 0;
        levels.push(level);
        // Once it starts refusing, higher levels only refuse harder.
        if degraded {
            break;
        }
    }
    Calibration { levels }
}

impl FidelityReport {
    pub fn render(&self) -> String {
        let mut s = String::new();
        match &self.address {
            Some(a) => s.push_str(&format!(
                "transport {} ({} {a})\n",
                self.transport, self.kind
            )),
            None => s.push_str(&format!("transport {} ({})\n", self.transport, self.kind)),
        }
        s.push_str(&format!(
            "  {:<18}{}\n",
            "reachable",
            if self.reachable { "yes" } else { "no" }
        ));
        if let Some(a) = &self.auth {
            s.push_str(&format!("  {:<18}{a}\n", "auth"));
        }
        for c in &self.checks {
            let reply = c
                .reply
                .map(|r| format!("reply 0x{r:02x}"))
                .unwrap_or_else(|| "no reply".into());
            let flag = if c.state.as_str() == c.expectation {
                String::new()
            } else {
                format!("   <- expected {}", c.expectation)
            };
            s.push_str(&format!(
                "  {:<18}{:<10}{:<14}{:>8.1}ms{flag}\n",
                c.label,
                c.state.as_str(),
                reply,
                c.ms
            ));
        }
        s.push_str(&format!("\n  {:<18}{}\n", "fidelity", self.fidelity));
        for line in wrap(&self.explanation, 72) {
            s.push_str(&format!("  {line}\n"));
        }
        if let Some(cal) = &self.calibration {
            s.push_str(&format!("\n  {:<18}\n", "concurrency"));
            for l in &cal.levels {
                s.push_str(&format!(
                    "  {:<18}{:>4} probes, {:>3} refused  {:>5.0}%\n",
                    format!("  at {}", l.concurrency),
                    l.probes,
                    l.refused,
                    l.loss_pct()
                ));
            }
            // Worded as "what this test observed" rather than "the maximum safe value".
            // The sweep holds connections for 500ms across four rounds, a harsher churn
            // profile than most scans, so the level it clears is a conservative floor:
            // a proxy measured clean to 8 here tolerated 24 in a real scan. Erring low is
            // the right direction, since what this replaced was a probe that cheerfully
            // reported 64/64 for a proxy that then lost half its probes.
            let advice = match (cal.recommended(), cal.degrades()) {
                (Some(r), true) => format!(
                    "Concurrency {r} was clean; it began refusing above that. Treat {r} as \
                     a conservative ceiling — a real scan may tolerate somewhat more, but \
                     past the limit probes are recorded as `error` rather than as port \
                     verdicts. This proxy has a connection cap, and raising it there (for \
                     example 3proxy's `maxconn`) is usually the better fix."
                ),
                (Some(r), false) => format!(
                    "No loss up to concurrency {r}, the highest level tested, so this \
                     proxy is not the constraint at that level."
                ),
                (None, _) => "This proxy refused connections even at the lowest level \
                              tested, which suggests a very low connection cap. Raise it \
                              on the proxy, or use --profile proxy-careful."
                    .into(),
            };
            for line in wrap(&advice, 72) {
                s.push_str(&format!("  {line}\n"));
            }
        }

        // Measuring is only half the job — recording it in config is what silences the
        // per-scan warning and puts the fact in version control (D8).
        //
        // Only for a single proxy. A chain's fidelity is its weakest hop's and a pool's
        // its weakest member's, both derived, and the config refuses a declared one — so
        // telling an operator to write it there would be advice that fails validation.
        if self.kind == "socks5" && self.fidelity != Fidelity::Unknown {
            s.push_str(&format!(
                "\n  to record this, add to [transports.{}]:\n      fidelity = \"{}\"\n",
                self.transport, self.fidelity
            ));
        } else if self.kind == "chain" && self.fidelity != Fidelity::Unknown {
            s.push_str(
                "\n  a chain's fidelity is derived from its hops; record it on the socks5\n                   transports the chain names, not on the chain itself.\n",
            );
        }
        s
    }
}

fn parse_dest(given: Option<&str>, default: SocketAddr) -> Result<SocketAddr, String> {
    match given {
        None => Ok(default),
        Some(s) => s
            .parse()
            .map_err(|_| format!("`{s}` is not a valid host:port")),
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::types::TransportKind;
    use crate::testsupport::socks5::{Behavior, Socks5Fixture};
    use crate::transport::socks5::REP_NOT_ALLOWED;

    fn timing() -> Timing {
        Timing {
            concurrency: 1,
            rate: 0,
            proxy_connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(600),
            retries: 0,
            retry_delay: Duration::ZERO,
            banner: None,
        }
    }

    fn socks_transport(addr: SocketAddr) -> ResolvedTransport {
        ResolvedTransport {
            name: "fx".into(),
            kind: TransportKind::Socks5 {
                address: addr,
                username: None,
                password: None,
            },
            fidelity: Fidelity::Unknown,
        }
    }

    #[test]
    fn direct_needs_no_measurement() {
        let t = ResolvedTransport {
            name: "direct".into(),
            kind: TransportKind::Direct,
            fidelity: Fidelity::Full,
        };
        let r = measure(&t, &timing(), None, None, false).unwrap();
        assert_eq!(r.fidelity, Fidelity::Full);
        assert!(r.checks.is_empty());
        assert!(r.reachable);
    }

    #[test]
    fn faithful_proxy_measures_as_full() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None, false).unwrap();
        assert!(r.reachable);
        assert_eq!(r.fidelity, Fidelity::Full, "{}", r.explanation);
        assert!(r.explanation.contains("tell `closed` apart"));
    }

    #[test]
    fn collapsing_proxy_measures_as_open_only() {
        // This is the ssh -D / commercial pool case.
        let fx = Socks5Fixture::start(Behavior::Collapsing);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None, false).unwrap();
        assert_eq!(r.fidelity, Fidelity::OpenOnly, "{}", r.explanation);
        assert!(r.explanation.contains("cannot distinguish"));
        assert!(r.explanation.contains("rather than guessed"));
    }

    #[test]
    fn unreachable_proxy_yields_unknown_not_a_guess() {
        let dead = crate::testsupport::closed_port();
        let r = measure(&socks_transport(dead), &timing(), None, None, false).unwrap();
        assert!(!r.reachable);
        assert_eq!(r.fidelity, Fidelity::Unknown);
    }

    #[test]
    fn checks_cover_open_closed_and_blackhole() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None, false).unwrap();
        let labels: Vec<&str> = r.checks.iter().map(|c| c.label).collect();
        assert_eq!(labels, ["known-open", "known-closed", "blackholed"]);
    }

    #[test]
    fn judgement_table_is_conservative() {
        assert_eq!(
            judge(true, true, Some(REP_CONNECTION_REFUSED)).0,
            Fidelity::Full
        );
        assert_eq!(
            judge(true, true, Some(REP_GENERAL_FAILURE)).0,
            Fidelity::OpenOnly
        );
        assert_eq!(
            judge(true, true, Some(REP_NOT_ALLOWED)).0,
            Fidelity::OpenOnly
        );
        assert_eq!(judge(true, true, None).0, Fidelity::OpenOnly);
        // Anything that invalidates calibration must report Unknown, never a guess.
        assert_eq!(
            judge(false, true, Some(REP_CONNECTION_REFUSED)).0,
            Fidelity::Unknown
        );
        assert_eq!(
            judge(true, false, Some(REP_CONNECTION_REFUSED)).0,
            Fidelity::Unknown
        );
    }

    #[test]
    fn report_renders_the_expectation_mismatch() {
        let fx = Socks5Fixture::start(Behavior::Collapsing);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None, false).unwrap();
        let out = r.render();
        assert!(out.contains("known-closed"), "{out}");
        assert!(out.contains("expected closed"), "{out}");
        assert!(out.contains("open_only"), "{out}");
    }

    #[test]
    fn custom_destinations_are_validated() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let e = measure(
            &socks_transport(fx.addr()),
            &timing(),
            Some("nonsense"),
            None,
            false,
        )
        .unwrap_err();
        assert!(e.contains("not a valid host:port"));
    }

    #[test]
    fn calibration_is_absent_unless_requested() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None, false).unwrap();
        assert!(r.calibration.is_none(), "sweeping should be opt-in");
        assert!(!r.render().contains("concurrency"));
    }

    #[test]
    fn calibration_recommends_the_highest_clean_level() {
        let cal = Calibration {
            levels: vec![
                Level {
                    concurrency: 8,
                    probes: 32,
                    refused: 0,
                },
                Level {
                    concurrency: 16,
                    probes: 64,
                    refused: 0,
                },
                Level {
                    concurrency: 32,
                    probes: 128,
                    refused: 9,
                },
            ],
        };
        assert_eq!(cal.recommended(), Some(16));
        assert!(cal.degrades());
        assert_eq!(cal.levels[2].loss_pct().round() as u32, 7);
    }

    #[test]
    fn calibration_with_no_loss_recommends_the_top_level() {
        let cal = Calibration {
            levels: vec![
                Level {
                    concurrency: 8,
                    probes: 32,
                    refused: 0,
                },
                Level {
                    concurrency: 16,
                    probes: 64,
                    refused: 0,
                },
            ],
        };
        assert_eq!(cal.recommended(), Some(16));
        assert!(!cal.degrades());
    }

    #[test]
    fn calibration_failing_at_the_lowest_level_recommends_nothing() {
        // Distinguished from "no data": the proxy answered, and refused anyway.
        let cal = Calibration {
            levels: vec![Level {
                concurrency: 8,
                probes: 32,
                refused: 4,
            }],
        };
        assert_eq!(cal.recommended(), None);
        assert!(cal.degrades());
    }

    #[test]
    fn wrap_breaks_on_word_boundaries() {
        let lines = wrap("the quick brown fox jumps over the lazy dog", 15);
        assert!(lines.iter().all(|l| l.len() <= 15), "{lines:?}");
        assert_eq!(
            lines.join(" "),
            "the quick brown fox jumps over the lazy dog"
        );
    }
}
