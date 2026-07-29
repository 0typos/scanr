//! Duration parsing and rendering.
//!
//! Written directly rather than pulling a crate: we accept a deliberately small
//! grammar and want the error messages to name the accepted forms.

use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DurationParseError {
    #[error("empty duration")]
    Empty,
    #[error("missing unit in `{0}` (expected one of: ms, s, m, h)")]
    MissingUnit(String),
    #[error("unknown unit `{unit}` in `{input}` (expected one of: ms, s, m, h)")]
    UnknownUnit { input: String, unit: String },
    #[error("`{0}` is not a valid number")]
    BadNumber(String),
    #[error("duration `{0}` overflows")]
    Overflow(String),
}

/// Parse a duration of the form `<number><unit>`, e.g. `250ms`, `1s`, `2m`, `1h`.
///
/// A bare number is rejected on purpose: `connect_timeout = 5` is ambiguous enough
/// that guessing seconds would eventually cost someone a very long scan.
pub fn parse_duration(input: &str) -> Result<Duration, DurationParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(DurationParseError::Empty);
    }

    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .ok_or_else(|| DurationParseError::MissingUnit(s.to_string()))?;
    let (num, unit) = s.split_at(split);
    if num.is_empty() {
        return Err(DurationParseError::BadNumber(s.to_string()));
    }

    let value: f64 = num
        .parse()
        .map_err(|_| DurationParseError::BadNumber(s.to_string()))?;
    if !value.is_finite() || value < 0.0 {
        return Err(DurationParseError::BadNumber(s.to_string()));
    }

    let millis = match unit.trim() {
        "ms" => value,
        "s" => value * 1_000.0,
        "m" => value * 60_000.0,
        "h" => value * 3_600_000.0,
        other => {
            return Err(DurationParseError::UnknownUnit {
                input: s.to_string(),
                unit: other.to_string(),
            });
        }
    };

    if millis > u64::MAX as f64 {
        return Err(DurationParseError::Overflow(s.to_string()));
    }
    Ok(Duration::from_millis(millis as u64))
}

/// Render a duration the way we accept it, choosing the largest exact unit.
pub fn render_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms == 0 {
        return "0ms".into();
    }
    if ms.is_multiple_of(3_600_000) {
        format!("{}h", ms / 3_600_000)
    } else if ms.is_multiple_of(60_000) {
        format!("{}m", ms / 60_000)
    } else if ms.is_multiple_of(1_000) {
        format!("{}s", ms / 1_000)
    } else {
        format!("{ms}ms")
    }
}

/// Human-friendly elapsed rendering for summaries: `1h02m03s`, `2m03s`, `4.21s`.
pub struct HumanElapsed(pub Duration);

impl fmt::Display for HumanElapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.0.as_secs_f64();
        if total < 60.0 {
            write!(f, "{total:.2}s")
        } else {
            let secs = self.0.as_secs();
            let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
            if h > 0 {
                write!(f, "{h}h{m:02}m{s:02}s")
            } else {
                write!(f, "{m}m{s:02}s")
            }
        }
    }
}

/// Thousands separators, for counts that routinely reach seven figures.
pub fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn accepts_fractional() {
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("0.25s").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn tolerates_surrounding_space() {
        assert_eq!(parse_duration("  2s  ").unwrap(), Duration::from_secs(2));
    }

    #[test]
    fn rejects_bare_number() {
        // Guessing a unit here would eventually cost someone a very long scan.
        assert!(matches!(
            parse_duration("5"),
            Err(DurationParseError::MissingUnit(_))
        ));
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(matches!(
            parse_duration("5sec"),
            Err(DurationParseError::UnknownUnit { .. })
        ));
        assert!(matches!(
            parse_duration("5d"),
            Err(DurationParseError::UnknownUnit { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(matches!(parse_duration(""), Err(DurationParseError::Empty)));
        assert!(matches!(
            parse_duration("ms"),
            Err(DurationParseError::BadNumber(_))
        ));
        assert!(parse_duration("1.2.3s").is_err());
    }

    #[test]
    fn round_trips_through_render() {
        for s in ["250ms", "1s", "2m", "1h"] {
            assert_eq!(render_duration(parse_duration(s).unwrap()), s);
        }
    }

    #[test]
    fn renders_elapsed() {
        assert_eq!(
            HumanElapsed(Duration::from_millis(4210)).to_string(),
            "4.21s"
        );
        assert_eq!(HumanElapsed(Duration::from_secs(123)).to_string(), "2m03s");
        assert_eq!(
            HumanElapsed(Duration::from_secs(3723)).to_string(),
            "1h02m03s"
        );
    }

    #[test]
    fn commas_group_correctly() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(255510), "255,510");
        assert_eq!(commas(65535000), "65,535,000");
    }
}
