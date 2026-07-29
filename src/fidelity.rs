//! Measuring what a transport can actually tell us (D8).
//!
//! SOCKS5 defines distinct reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`)
//! and policy denial (`0x02`), but many implementations collapse everything into
//! `0x01 general failure`. `ssh -D` and most commercial pools appear to behave this way.
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
}

/// Probe a transport with destinations of known character.
///
/// Defaults need no user input: the proxy's own listening socket is reliably open from
/// the proxy's perspective, port 1 on the proxy host is reliably closed, and
/// 192.0.2.1 (RFC 5737 TEST-NET-1) is guaranteed unroutable.
pub fn measure(
    transport: &ResolvedTransport,
    timing: &Timing,
    known_open: Option<&str>,
    known_closed: Option<&str>,
) -> Result<FidelityReport, String> {
    let (address, username, password) = match &transport.kind {
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
            });
        }
        TransportKind::Socks5 {
            address,
            username,
            password,
        } => (
            *address,
            username.clone(),
            password.as_ref().map(|s| s.expose().to_string()),
        ),
    };

    let client = Socks5Transport::new(
        transport.name.clone(),
        address,
        username.clone(),
        password,
        Fidelity::Unknown,
    );

    let open_dest = parse_dest(known_open, address)?;
    let closed_dest = parse_dest(known_closed, SocketAddr::new(address.ip(), 1))?;
    let blackhole: SocketAddr = "192.0.2.1:80".parse().expect("valid literal");

    // Give the blackhole check a short leash; waiting the full destination timeout
    // teaches us nothing extra.
    let mut short = timing.clone();
    short.connect_timeout = timing.connect_timeout.min(Duration::from_secs(3));

    let mut checks = Vec::new();
    let mut reachable = true;
    let mut auth = None;

    for (label, dest, expectation, t) in [
        ("known-open", open_dest, "open", timing),
        ("known-closed", closed_dest, "closed", timing),
        ("blackholed", blackhole, "filtered", &short),
    ] {
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
        if auth.is_none() && username.is_some() && o.phases.handshake.is_some() {
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

    let closed_reply = checks
        .iter()
        .find(|c| c.label == "known-closed")
        .and_then(|c| c.reply);
    let open_ok = checks
        .iter()
        .find(|c| c.label == "known-open")
        .is_some_and(|c| c.state == State::Open);

    let (fidelity, explanation) = judge(reachable, open_ok, closed_reply);

    Ok(FidelityReport {
        transport: transport.name.clone(),
        kind: "socks5".into(),
        address: Some(address.to_string()),
        reachable,
        auth,
        checks,
        fidelity,
        explanation,
    })
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
        return (
            Fidelity::Unknown,
            "The known-open destination did not report open, so this proxy's replies \
             cannot be calibrated. Pass --known-open with a destination you are certain \
             is reachable from the proxy."
                .into(),
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
             have timed out or closed the connection), so closed and filtered cannot be \
             distinguished."
                .into(),
        ),
    }
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
        // Measuring is only half the job — recording it in config is what silences the
        // per-scan warning and puts the fact in version control (D8).
        if self.kind == "socks5" && self.fidelity != Fidelity::Unknown {
            s.push_str(&format!(
                "\n  to record this, add to [transports.{}]:\n      fidelity = \"{}\"\n",
                self.transport, self.fidelity
            ));
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
        let r = measure(&t, &timing(), None, None).unwrap();
        assert_eq!(r.fidelity, Fidelity::Full);
        assert!(r.checks.is_empty());
        assert!(r.reachable);
    }

    #[test]
    fn faithful_proxy_measures_as_full() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None).unwrap();
        assert!(r.reachable);
        assert_eq!(r.fidelity, Fidelity::Full, "{}", r.explanation);
        assert!(r.explanation.contains("tell `closed` apart"));
    }

    #[test]
    fn collapsing_proxy_measures_as_open_only() {
        // This is the ssh -D / commercial pool case.
        let fx = Socks5Fixture::start(Behavior::Collapsing);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None).unwrap();
        assert_eq!(r.fidelity, Fidelity::OpenOnly, "{}", r.explanation);
        assert!(r.explanation.contains("cannot distinguish"));
        assert!(r.explanation.contains("rather than guessed"));
    }

    #[test]
    fn unreachable_proxy_yields_unknown_not_a_guess() {
        let dead = crate::testsupport::closed_port();
        let r = measure(&socks_transport(dead), &timing(), None, None).unwrap();
        assert!(!r.reachable);
        assert_eq!(r.fidelity, Fidelity::Unknown);
    }

    #[test]
    fn checks_cover_open_closed_and_blackhole() {
        let fx = Socks5Fixture::start(Behavior::Faithful);
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None).unwrap();
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
        let r = measure(&socks_transport(fx.addr()), &timing(), None, None).unwrap();
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
        )
        .unwrap_err();
        assert!(e.contains("not a valid host:port"));
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
