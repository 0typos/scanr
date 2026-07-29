//! Human-readable streaming output.
//!
//! stdout carries results and nothing else, so it stays pipe-safe. Everything
//! else — the header, progress, warnings — goes to stderr. Decoration is applied only
//! when the relevant stream is a terminal.

use std::io::{IsTerminal, Write};

use crate::probe::{ProbeOutcome, State, service_label};

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

    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

pub struct ResultPrinter {
    style: Style,
    aligned: bool,
    target_width: usize,
    open_only: bool,
}

impl ResultPrinter {
    pub fn new(target_width: usize, open_only: bool, no_color: bool) -> Self {
        let tty = std::io::stdout().is_terminal();
        Self {
            style: Style::for_stream(tty, no_color),
            // Padding is for humans; a pipe gets stable single-space separation.
            aligned: tty,
            target_width: target_width.clamp(8, 48),
            open_only,
        }
    }

    pub fn should_print(&self, outcome: &ProbeOutcome) -> bool {
        !self.open_only || outcome.is_open()
    }

    /// One result line. Format:
    /// `10.20.30.40:443/tcp   open   https   21.4ms`
    pub fn format(&self, target: &str, port: u16, outcome: &ProbeOutcome) -> String {
        let endpoint = format!("{target}:{port}/tcp");
        let label = service_label(port).unwrap_or("");
        let ms = outcome.phases.total.as_secs_f64() * 1000.0;
        let latency = format!("{ms:.1}ms");

        if self.aligned {
            format!(
                "{:<ew$}  {:<w$}  {:<10}  {:>9}",
                endpoint,
                self.style.state(outcome.state),
                label,
                self.style.dim(&latency),
                ew = self.target_width + 10,
                // Colour codes inflate the string length, so pad the plain width.
                w = if self.style.color { 8 + 9 } else { 8 },
            )
            .trim_end()
            .to_string()
        } else {
            let mut s = format!("{endpoint} {} {label}", outcome.state);
            if s.ends_with(' ') {
                s.pop();
            }
            format!("{s} {latency}")
        }
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
        }
    }

    fn plain_printer(open_only: bool) -> ResultPrinter {
        ResultPrinter {
            style: Style { color: false },
            aligned: false,
            target_width: 15,
            open_only,
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

    #[test]
    fn aligned_output_pads_consistently() {
        let p = ResultPrinter {
            style: Style { color: false },
            aligned: true,
            target_width: 15,
            open_only: false,
        };
        let a = p.format("10.0.0.1", 22, &outcome(State::Open, 1));
        let b = p.format("10.20.30.400", 443, &outcome(State::Closed, 2));
        let col_a = a.find("open").unwrap();
        let col_b = b.find("closed").unwrap();
        assert_eq!(col_a, col_b, "state column should line up:\n{a}\n{b}");
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
}
