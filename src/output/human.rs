//! Human-readable streaming output.
//!
//! stdout carries results and nothing else, so it stays pipe-safe. Everything
//! else — the header, progress, warnings — goes to stderr. Decoration is applied only
//! when the relevant stream is a terminal.

use std::io::{IsTerminal, Write};

use crate::probe::{ProbeOutcome, State};
use crate::services::service_label;

pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn for_stream(is_tty: bool, no_color: bool) -> Self {
        // Honour NO_COLOR (https://no-color.org) as well as the explicit flag.
        let forced_off = no_color || std::env::var_os("NO_COLOR").is_some();
        Self {
            color: is_tty && !forced_off,
        }
    }

    pub fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn state(&self, state: State) -> String {
        let code = match state {
            State::Open => "32",     // green
            State::Closed => "31",   // red
            State::Filtered => "33", // yellow
            State::Error => "35",    // magenta
        };
        self.paint(code, state.as_str())
    }

    /// Paint arbitrary text in a state's colour.
    ///
    /// Separate from `state` so a caller can pad to a column width *first* and colour
    /// after: ANSI escapes inflate `str::len`, so formatting a coloured string with
    /// `{:<9}` silently stops aligning (D22).
    pub fn paint_state(&self, state: State, text: &str) -> String {
        let code = match state {
            State::Open => "32",
            State::Closed => "31",
            State::Filtered => "33",
            State::Error => "35",
        };
        self.paint(code, text)
    }

    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

/// Bracket an IPv6 literal so `addr:port` is unambiguous.
///
/// Without this, `::1` and port 9601 render as `::1:9601`, which is itself a valid
/// IPv6 address — so the line cannot be parsed back apart. A hostname can never contain
/// a colon, which makes this test sufficient.
fn bracket_if_ipv6(target: &str) -> String {
    if target.contains(':') && !target.starts_with('[') {
        format!("[{target}]")
    } else {
        target.to_string()
    }
}

pub struct ResultPrinter {
    style: Style,
    aligned: bool,
    target_width: usize,
    open_only: bool,
    /// Characters of banner shown; `usize::MAX` for `--full`.
    banner_width: usize,
}

/// A banner rendered safe for a terminal.
///
/// **This is a security boundary, not cosmetics.** The bytes come from a service that
/// scanr does not control, and a terminal will act on what it is given: escape sequences
/// can move the cursor, rewrite lines that have already scrolled past, change the title,
/// or on some emulators trigger a reply the shell then reads as input. A scanner that
/// prints attacker bytes verbatim hands that control away.
///
/// So the display form is printable ASCII only — everything else becomes `.`, the way a
/// hex dump has always done it — collapsed onto one line and truncated. The record keeps
/// the bytes exactly as they arrived; this is only what reaches a screen.
pub(crate) fn safe_banner(bytes: &[u8], width: usize) -> String {
    let mut out: String = bytes
        .iter()
        .take(width)
        .map(|b| match b {
            0x20..=0x7e => *b as char,
            _ => '.',
        })
        .collect();
    if bytes.len() > width {
        out.push('…');
    }
    out
}

impl ResultPrinter {
    pub fn new(target_width: usize, open_only: bool, no_color: bool, full: bool) -> Self {
        let tty = std::io::stdout().is_terminal();
        Self {
            style: Style::for_stream(tty, no_color),
            // Padding is for humans; a pipe gets stable single-space separation.
            aligned: tty,
            target_width: target_width.clamp(8, 48),
            open_only,
            banner_width: if full { usize::MAX } else { Self::BANNER_W },
        }
    }

    /// A dim column header matching `format`'s aligned layout, for the caller to print
    /// on stderr under `Results`. `None` when stdout is a pipe: rows are then
    /// single-spaced and stdout carries results only.
    pub fn header(&self) -> Option<String> {
        if !self.aligned {
            return None;
        }
        let pad = |n: usize| " ".repeat(n);
        let mut line = String::new();
        for (name, w) in [
            ("endpoint", self.target_width + 10),
            ("state", Self::STATE_W),
            ("service", Self::LABEL_W),
        ] {
            line.push_str(name);
            line.push_str(&pad(w.saturating_sub(name.len()) + Self::GAP));
        }
        line.push_str(&pad(Self::LATENCY_W.saturating_sub("rtt".len())));
        line.push_str("rtt");
        line.push_str(&pad(Self::GAP));
        line.push_str("banner / tls");
        Some(self.style.dim(&line))
    }

    pub fn should_print(&self, outcome: &ProbeOutcome) -> bool {
        !self.open_only || outcome.is_open()
    }

    /// Widest state name (`filtered`).
    const STATE_W: usize = 8;
    /// Widest service label in the table (`kube-apiserver`).
    /// Wide enough for the compiled-in labels, which is all this could be sized to.
    ///
    /// Labels now come from `/etc/services` or a user file as well, so a longer one is
    /// possible and simply widens its own row — the explicit `GAP` below means a long
    /// value pushes the next column right rather than colliding with it.
    const LABEL_W: usize = 14;
    /// `99999.9ms`
    const LATENCY_W: usize = 9;
    /// Enough to recognise a greeting on one line; the record has all of it, and
    /// `--full` shows it.
    pub(crate) const BANNER_W: usize = 48;
    const GAP: usize = 2;

    /// One result line. Format:
    /// `10.20.30.40:443/tcp   open   https   21.4ms`
    ///
    /// Padding is computed from *visible* width and applied explicitly, never by
    /// handing pre-coloured strings to a format width. Escape sequences inflate
    /// `str::len`, so `{:>9}` on a coloured value silently stops aligning — and a
    /// service label wider than its column shifted every following field. Both showed
    /// up only once the output was rendered on a real terminal.
    pub fn format(&self, target: &str, port: u16, outcome: &ProbeOutcome) -> String {
        let endpoint = format!("{}:{port}/tcp", bracket_if_ipv6(target));
        let label = service_label(port).unwrap_or("");
        let ms = outcome.phases.total.as_secs_f64() * 1000.0;
        let latency = format!("{ms:.1}ms");

        if !self.aligned {
            let mut s = format!("{endpoint} {} {label}", outcome.state);
            if s.ends_with(' ') {
                s.pop();
            }
            let mut s = match &outcome.banner {
                Some(b) => format!("{s} {latency} {}", safe_banner(b, self.banner_width)),
                None => format!("{s} {latency}"),
            };
            if let Some(t) = &outcome.tls {
                s.push(' ');
                s.push_str(&t.display());
            }
            return s;
        }

        let pad = |n: usize| " ".repeat(n);
        let endpoint_w = self.target_width + 10;
        let state = outcome.state.as_str();

        let mut line = String::with_capacity(96);
        line.push_str(&endpoint);
        line.push_str(&pad(endpoint_w.saturating_sub(endpoint.len()) + Self::GAP));

        line.push_str(&self.style.state(outcome.state));
        line.push_str(&pad(Self::STATE_W.saturating_sub(state.len()) + Self::GAP));

        line.push_str(label);
        line.push_str(&pad(Self::LABEL_W.saturating_sub(label.len()) + Self::GAP));

        // Right-align the latency on its visible width.
        line.push_str(&pad(Self::LATENCY_W.saturating_sub(latency.len())));
        line.push_str(&self.style.dim(&latency));

        // Last, because it is the only field whose length a stranger chooses.
        if let Some(b) = &outcome.banner {
            line.push_str(&pad(Self::GAP));
            line.push_str(&self.style.dim(&safe_banner(b, self.banner_width)));
        }
        // Already printable ASCII: `TlsObservation` filters the one peer-chosen string.
        if let Some(t) = &outcome.tls {
            line.push_str(&pad(Self::GAP));
            line.push_str(&self.style.dim(&t.display()));
        }
        line
    }

    pub fn print(&self, out: &mut impl Write, target: &str, port: u16, outcome: &ProbeOutcome) {
        // A closed pipe (`| head`) is a normal way to stop reading, not an error.
        let _ = writeln!(out, "{}", self.format(target, port, outcome));
    }
}

/// Progress rendering on stderr: a single updating line on a terminal, periodic lines
/// otherwise so logs stay readable.
pub struct Progress {
    tty: bool,
    quiet: bool,
    style: Style,
    active: bool,
}

impl Progress {
    pub fn new(quiet: bool, no_color: bool) -> Self {
        let tty = std::io::stderr().is_terminal();
        Self {
            tty,
            quiet,
            style: Style::for_stream(tty, no_color),
            active: false,
        }
    }

    pub fn render(&mut self, completed: u64, planned: u64, open: u64, rate: f64, eta: Option<f64>) {
        if self.quiet {
            return;
        }
        let pct = if planned > 0 {
            completed as f64 / planned as f64 * 100.0
        } else {
            100.0
        };
        let eta_s = match eta {
            Some(s) if s.is_finite() && s >= 0.0 => {
                format!(
                    "  eta {}",
                    crate::units::HumanElapsed(std::time::Duration::from_secs_f64(s))
                )
            }
            _ => String::new(),
        };
        let line = format!(
            "  {:>5.1}%  {}/{}  {} open  {:.0}/s{eta_s}",
            pct,
            crate::units::commas(completed),
            crate::units::commas(planned),
            open,
            rate,
        );
        let mut err = std::io::stderr();
        if self.tty {
            let _ = write!(err, "\r\x1b[K{}", self.style.dim(&line));
            let _ = err.flush();
            self.active = true;
        } else {
            let _ = writeln!(err, "{line}");
        }
    }

    /// Clear the in-place line before printing anything else to stderr.
    pub fn clear(&mut self) {
        if self.active && self.tty {
            let _ = write!(std::io::stderr(), "\r\x1b[K");
            let _ = std::io::stderr().flush();
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::safe_banner;

    /// The security property, not a formatting preference.
    ///
    /// A banner is bytes chosen by a stranger, and a terminal acts on what it is given:
    /// `ESC [ 2J` clears the screen, `ESC ] 0 ; … BEL` rewrites the window title. Printing
    /// them verbatim hands a scanned host control of the operator's terminal.
    #[test]
    fn a_hostile_banner_cannot_reach_the_terminal() {
        let evil = b"\x1b[2J\x1b]0;pwned\x07EVIL";
        let shown = safe_banner(evil, 64);
        assert!(!shown.contains('\x1b'), "escape survived: {shown:?}");
        assert!(!shown.contains('\x07'), "bell survived: {shown:?}");
        assert_eq!(shown, ".[2J.]0;pwned.EVIL");
    }

    #[test]
    fn a_normal_banner_stays_readable() {
        let ssh = b"SSH-2.0-OpenSSH_9.6p1 Debian-2\r\n";
        assert_eq!(safe_banner(ssh, 64), "SSH-2.0-OpenSSH_9.6p1 Debian-2..");
    }

    /// A stranger also chooses the *length*, so the display width is ours, not theirs.
    #[test]
    fn a_long_banner_is_truncated_and_marked() {
        let long = vec![b'A'; 4096];
        let shown = safe_banner(&long, 48);
        assert_eq!(shown.chars().count(), 49, "48 plus the ellipsis: {shown:?}");
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn nothing_read_renders_as_nothing() {
        assert_eq!(safe_banner(b"", 48), "");
    }

    use super::*;
    use crate::probe::{Phases, Source};
    use std::time::Duration;

    fn outcome(state: State, ms: u64) -> ProbeOutcome {
        ProbeOutcome {
            state,
            source: Source::LocalStack,
            reason: None,
            phases: Phases {
                total: Duration::from_millis(ms),
                ..Default::default()
            },
            pressure: None,
            banner: None,
            via: None,
            tls: None,
        }
    }

    fn plain_printer(open_only: bool) -> ResultPrinter {
        ResultPrinter {
            style: Style { color: false },
            aligned: false,
            target_width: 15,
            open_only,
            banner_width: ResultPrinter::BANNER_W,
        }
    }

    #[test]
    fn plain_output_is_pipe_friendly() {
        let p = plain_printer(true);
        let line = p.format("10.20.30.40", 443, &outcome(State::Open, 21));
        assert_eq!(line, "10.20.30.40:443/tcp open https 21.0ms");
        // No escape sequences, no trailing padding.
        assert!(!line.contains('\x1b'));
        assert_eq!(line.trim_end(), line);
    }

    #[test]
    fn unlabelled_ports_do_not_leave_a_double_space() {
        let p = plain_printer(true);
        let line = p.format("10.0.0.1", 64321, &outcome(State::Open, 5));
        assert_eq!(line, "10.0.0.1:64321/tcp open 5.0ms");
        assert!(!line.contains("  "));
    }

    #[test]
    fn open_only_filters_non_open_results() {
        let p = plain_printer(true);
        assert!(p.should_print(&outcome(State::Open, 1)));
        assert!(!p.should_print(&outcome(State::Closed, 1)));
        assert!(!p.should_print(&outcome(State::Filtered, 1)));

        let all = plain_printer(false);
        assert!(all.should_print(&outcome(State::Closed, 1)));
    }

    #[test]
    fn ipv6_endpoints_are_bracketed() {
        // `::1` with port 9601 must not render as `::1:9601`, which is itself a valid
        // IPv6 address and therefore unparseable back into address and port.
        let p = plain_printer(false);
        let line = p.format("::1", 9601, &outcome(State::Open, 1));
        assert!(line.starts_with("[::1]:9601/tcp"), "{line}");

        let long = p.format("2001:db8::5", 443, &outcome(State::Open, 1));
        assert!(long.starts_with("[2001:db8::5]:443/tcp"), "{long}");

        // The bracketed form round-trips through a socket address parser.
        let endpoint = line.split('/').next().unwrap();
        assert!(
            endpoint.parse::<std::net::SocketAddr>().is_ok(),
            "{endpoint} should parse as a socket address"
        );
    }

    #[test]
    fn ipv4_and_hostnames_are_left_alone() {
        let p = plain_printer(false);
        assert!(
            p.format("10.0.0.1", 22, &outcome(State::Open, 1))
                .starts_with("10.0.0.1:22/tcp")
        );
        assert!(
            p.format("app.internal", 22, &outcome(State::Open, 1))
                .starts_with("app.internal:22/tcp")
        );
    }

    #[test]
    fn hostname_targets_render_as_given() {
        let p = plain_printer(true);
        let line = p.format("app.internal", 8080, &outcome(State::Open, 100));
        assert!(line.starts_with("app.internal:8080/tcp"), "{line}");
    }

    #[test]
    fn colour_is_off_when_not_a_terminal() {
        let s = Style::for_stream(false, false);
        assert!(!s.color);
        assert_eq!(s.state(State::Open), "open");
    }

    #[test]
    fn colour_is_off_when_explicitly_disabled() {
        let s = Style::for_stream(true, true);
        assert!(!s.color);
    }

    #[test]
    fn colour_wraps_state_when_enabled() {
        let s = Style { color: true };
        let painted = s.state(State::Open);
        assert!(painted.starts_with("\x1b[32m"));
        assert!(painted.ends_with("\x1b[0m"));
        assert!(painted.contains("open"));
    }

    /// Visible text, with ANSI escape sequences removed.
    fn visible(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn aligned_printer(color: bool) -> ResultPrinter {
        ResultPrinter {
            style: Style { color },
            aligned: true,
            target_width: 15,
            open_only: false,
            banner_width: ResultPrinter::BANNER_W,
        }
    }

    #[test]
    fn aligned_output_pads_consistently() {
        let p = aligned_printer(false);
        let a = p.format("10.0.0.1", 22, &outcome(State::Open, 1));
        let b = p.format("10.20.30.400", 443, &outcome(State::Closed, 2));
        let col_a = a.find("open").unwrap();
        let col_b = b.find("closed").unwrap();
        assert_eq!(col_a, col_b, "state column should line up:\n{a}\n{b}");
    }

    #[test]
    fn a_long_service_label_does_not_shift_later_columns() {
        // `elasticsearch` (13) and `kube-apiserver` (14) both overflowed a 10-wide
        // column, pushing the latency of those rows out of line with every other row.
        let p = aligned_printer(false);
        let rows = [
            p.format("127.0.0.1", 22, &outcome(State::Open, 1)), // ssh
            p.format("127.0.0.1", 9200, &outcome(State::Closed, 2)), // elasticsearch
            p.format("127.0.0.1", 6443, &outcome(State::Open, 3)), // kube-apiserver
            p.format("127.0.0.1", 64321, &outcome(State::Open, 4)), // no label
        ];
        let ends: Vec<usize> = rows.iter().map(|r| visible(r).trim_end().len()).collect();
        assert!(
            ends.windows(2).all(|w| w[0] == w[1]),
            "latency column ends at different offsets {ends:?}:\n{}",
            rows.join("\n")
        );
    }

    #[test]
    fn colour_does_not_disturb_alignment() {
        // Escape sequences inflate str::len, so any padding computed on the coloured
        // string silently stops aligning. Visible layout must be identical either way.
        let plain = aligned_printer(false);
        let colored = aligned_printer(true);
        for (port, state) in [
            (22, State::Open),
            (9200, State::Closed),
            (64321, State::Filtered),
        ] {
            let o = outcome(state, 21);
            let p = plain.format("10.20.30.40", port, &o);
            let c = visible(&colored.format("10.20.30.40", port, &o));
            assert_eq!(p, c, "colour changed the visible layout for port {port}");
        }
    }

    #[test]
    fn latency_is_right_aligned_on_visible_width() {
        let p = aligned_printer(true);
        let short = visible(&p.format("10.0.0.1", 22, &outcome(State::Open, 1)));
        let long = visible(&p.format("10.0.0.1", 22, &outcome(State::Open, 12345)));
        assert!(short.ends_with("1.0ms"), "{short:?}");
        assert!(long.ends_with("12345.0ms"), "{long:?}");
        assert_eq!(
            short.len(),
            long.len(),
            "latency should be right-aligned:\n{short}\n{long}"
        );
    }

    #[test]
    fn latency_has_one_decimal() {
        let p = plain_printer(false);
        assert!(
            p.format("h", 1, &outcome(State::Open, 1234))
                .contains("1234.0ms")
        );
    }

    #[test]
    fn quiet_progress_emits_nothing() {
        let mut p = Progress::new(true, true);
        p.render(1, 10, 0, 5.0, Some(2.0));
        p.clear();
        // No panic and no state change is the whole assertion.
        assert!(!p.active);
    }

    /// D22, applied to the `output` tables: pad to the column width first, then paint.
    ///
    /// Painting first and formatting the result with `{:<9}` silently stops aligning,
    /// because the escape bytes count toward `str::len`. This asserts the order that
    /// works and demonstrates the one that does not.
    #[test]
    fn padding_before_painting_keeps_columns_aligned() {
        let style = Style::for_stream(true, false);
        let visible = |s: &str| {
            // Strip SGR sequences the way a terminal does.
            let mut out = String::new();
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out.chars().count()
        };

        for st in State::ALL {
            let right = style.paint_state(st, &format!("{:<9}", st.as_str()));
            assert_eq!(
                visible(&right),
                9,
                "{st:?}: padded-then-painted must occupy exactly the column width"
            );

            // The other order: the escapes are counted, so short states never reach the
            // width and the column drifts.
            let wrong = format!("{:<9}", style.paint_state(st, st.as_str()));
            assert!(
                visible(&wrong) < 9,
                "{st:?}: painting first should under-fill the column, showing why the \
                 order matters"
            );
        }
    }

    #[test]
    fn colour_is_off_for_a_pipe_and_for_no_color() {
        assert!(!Style::for_stream(false, false).color, "not a terminal");
        assert!(!Style::for_stream(true, true).color, "--no-color");
        assert!(
            Style::for_stream(true, false).color,
            "a terminal, no override"
        );
    }
}
