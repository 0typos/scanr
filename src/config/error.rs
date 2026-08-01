//! Configuration errors with caret-annotated source spans.
//!
//! `miette` was evaluated and rejected (D18): the one thing it would buy us is this
//! rendering, and `toml`'s own span information plus ~100 lines gets there without the
//! dependency tree.

use std::fmt;
use std::path::{Path, PathBuf};

/// A configuration problem, optionally anchored to a byte span in a source file.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub path: Option<PathBuf>,
    pub span: Option<std::ops::Range<usize>>,
    pub message: String,
    pub help: Option<String>,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            path: None,
            span: None,
            message: message.into(),
            help: None,
        }
    }

    pub fn at(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn span(mut self, span: std::ops::Range<usize>) -> Self {
        self.span = Some(span);
        self
    }

    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Render with a caret pointing at the offending span, when we have both the file
    /// contents and a span. Falls back to a plain message otherwise.
    pub fn render(&self, source: Option<&str>) -> String {
        let mut out = format!("error: {}", self.message);

        if let (Some(src), Some(span)) = (source, self.span.as_ref()) {
            let (line_no, col, line) = locate(src, span.start);
            let file = self
                .path
                .as_deref()
                .map(display_path)
                .unwrap_or_else(|| "<config>".into());

            // Pointing at a credential must not print it. Redaction happens here
            // rather than at each call site so no future error can leak one by
            // forgetting.
            let line = redact_secret_value(line);

            let gutter_w = line_no.to_string().len();
            let pad = " ".repeat(gutter_w);
            let width = span.len().max(1).min(line.len().saturating_sub(col) + 1);

            out.push_str(&format!("\n{pad}--> {file}:{line_no}:{}\n", col + 1));
            out.push_str(&format!("{pad} |\n"));
            out.push_str(&format!("{line_no} | {line}\n"));
            out.push_str(&format!(
                "{pad} | {}{}\n",
                " ".repeat(col),
                "^".repeat(width)
            ));
        } else if let Some(p) = &self.path {
            out.push_str(&format!("\n --> {}\n", display_path(p)));
        }

        if let Some(h) = &self.help {
            for (i, line) in h.lines().enumerate() {
                if i == 0 {
                    out.push_str(&format!("\nhelp: {line}"));
                } else {
                    out.push_str(&format!("\n      {line}"));
                }
            }
        }
        out
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render(None))
    }
}

impl std::error::Error for ConfigError {}

/// Mask the value of a credential-shaped assignment so an error that points at a
/// password line does not print the password.
fn redact_secret_value(line: &str) -> String {
    // Redacts every credential assignment on the line, not just one keyed off the first
    // `=`. In a TOML inline table the first `=` belongs to the table's own name, so
    // `lab = { ..., password = "hunter2" }` read as key `lab`, was judged non-credential,
    // and was echoed whole into the caret diagnostic — on stderr, on every command. The
    // single-key form redacted correctly, which is the form the test covered.
    let is_credential_key = |k: &str| {
        let k = k.trim().trim_matches('"').to_ascii_lowercase();
        k == "password" || k == "secret" || k.ends_with("_password") || k.ends_with("_secret")
    };

    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut key_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            // A separator ends whatever key was being accumulated.
            b'{' | b',' => {
                out.push_str(&line[key_start..=i]);
                key_start = i + 1;
                i += 1;
            }
            b'=' => {
                let key = &line[key_start..i];
                out.push_str(key);
                out.push('=');
                i += 1;
                // The value runs to the next top-level separator or the line's end.
                let mut end = i;
                let mut in_quotes = false;
                while end < bytes.len() {
                    match bytes[end] {
                        b'"' => in_quotes = !in_quotes,
                        b',' | b'}' if !in_quotes => break,
                        _ => {}
                    }
                    end += 1;
                }
                let value = &line[i..end];
                if is_credential_key(key) && !value.trim().is_empty() {
                    out.push_str(" \"[redacted]\"");
                } else {
                    out.push_str(value);
                }
                i = end;
                key_start = end;
            }
            _ => i += 1,
        }
    }
    out.push_str(&line[key_start..]);
    out
}

fn display_path(p: &Path) -> String {
    // Shorten $HOME to ~ so error output stays readable in a terminal.
    if let Some(home) = std::env::var_os("HOME")
        && let Ok(rest) = p.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    p.display().to_string()
}

/// Map a byte offset to (1-based line, 0-based column, line text).
fn locate(src: &str, offset: usize) -> (usize, usize, &str) {
    let offset = offset.min(src.len());
    let start = src[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = src[start..]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(src.len());
    let line_no = src[..start].bytes().filter(|&b| b == b'\n').count() + 1;
    (line_no, offset - start, &src[start..end])
}

/// Nearest-match suggestion for an unknown key, by edit distance.
pub fn suggest<'a>(unknown: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for c in candidates {
        let d = edit_distance(unknown, c);
        // Only suggest when the guess is plausibly a typo rather than a different word.
        let limit = (unknown.len().max(c.len()) / 3).max(1);
        if d <= limit && best.map(|(bd, _)| d < bd).unwrap_or(true) {
            best = Some((d, c));
        }
    }
    best.map(|(_, c)| c.to_string())
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_offsets() {
        let src = "alpha\nbeta\ngamma\n";
        assert_eq!(locate(src, 0), (1, 0, "alpha"));
        assert_eq!(locate(src, 6), (2, 0, "beta"));
        assert_eq!(locate(src, 8), (2, 2, "beta"));
        assert_eq!(locate(src, 11), (3, 0, "gamma"));
    }

    #[test]
    fn renders_caret_under_span() {
        let src = "version = 1\nconcurrency = -5\n";
        let err = ConfigError::new("concurrency must be positive")
            .at("/tmp/scanr.toml")
            .span(26..28)
            .help("use a value between 1 and 65535");
        let out = err.render(Some(src));
        assert!(out.contains("scanr.toml:2:15"), "{out}");
        assert!(out.contains("concurrency = -5"), "{out}");
        assert!(out.contains("^^"), "{out}");
        assert!(out.contains("help: use a value"), "{out}");
    }

    #[test]
    fn renders_without_span() {
        let err = ConfigError::new("no such profile `fast`");
        let out = err.render(None);
        assert_eq!(out, "error: no such profile `fast`");
    }

    #[test]
    fn suggests_near_misses() {
        let fields = ["concurrency", "connect_timeout", "retries", "rate"];
        assert_eq!(
            suggest("concurency", fields).as_deref(),
            Some("concurrency")
        );
        assert_eq!(suggest("retrys", fields).as_deref(), Some("retries"));
        assert_eq!(suggest("rat", fields).as_deref(), Some("rate"));
    }

    #[test]
    fn does_not_suggest_unrelated_words() {
        let fields = ["concurrency", "connect_timeout"];
        assert_eq!(suggest("bananas", fields), None);
    }

    #[test]
    fn caret_rendering_never_prints_a_credential() {
        // Pointing at the offending line must not echo the secret it contains.
        let src = "[transports.p]\npassword = \"hunter2\"\n";
        let err = ConfigError::new("inline `password` is not accepted")
            .at("/tmp/scanr.toml")
            .span(15..23);
        let out = err.render(Some(src));
        assert!(
            !out.contains("hunter2"),
            "the error leaked the password:\n{out}"
        );
        assert!(out.contains("[redacted]"), "{out}");
        assert!(out.contains('^'), "the caret should still be drawn: {out}");
    }

    /// The form that leaked: in a TOML inline table the first `=` belongs to the table's
    /// own name, so the old rule read the key as `lab`, judged the line non-credential,
    /// and echoed the password into the caret diagnostic on every command.
    #[test]
    fn an_inline_table_password_is_redacted_too() {
        let line = r#"lab = { type = "socks5", password = "hunter2", bogus = 1 }"#;
        let out = redact_secret_value(line);
        assert!(!out.contains("hunter2"), "credential survived: {out}");
        assert!(out.contains("[redacted]"), "{out}");
        // Everything else on the line is preserved, so the diagnostic stays useful.
        assert!(out.contains("socks5") && out.contains("bogus"), "{out}");
    }

    #[test]
    fn redaction_only_touches_credential_keys() {
        assert_eq!(
            redact_secret_value("concurrency = 512"),
            "concurrency = 512"
        );
        assert_eq!(
            redact_secret_value("address = \"1.2.3.4:1080\""),
            "address = \"1.2.3.4:1080\""
        );
        assert_eq!(
            redact_secret_value("password = \"x\""),
            "password = \"[redacted]\""
        );
        assert_eq!(
            redact_secret_value("  password  =  \"x\""),
            "  password  = \"[redacted]\""
        );
        assert_eq!(
            redact_secret_value("proxy_password = \"x\""),
            "proxy_password = \"[redacted]\""
        );
        // password_env names a variable, not a secret, so it stays readable.
        assert_eq!(
            redact_secret_value("password_env = \"VAR\""),
            "password_env = \"VAR\""
        );
        assert_eq!(redact_secret_value("no equals here"), "no equals here");
    }

    #[test]
    fn multiline_help_is_indented() {
        let err = ConfigError::new("x").help("first\nsecond");
        let out = err.render(None);
        assert!(out.contains("help: first"), "{out}");
        assert!(out.contains("\n      second"), "{out}");
    }
}
