//! Port specification parsing.
//!
//! Grammar: comma-separated items, each one of `N`, `A-B`, or `all`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortParseError {
    #[error("empty port specification")]
    Empty,
    #[error("`{0}` is not a valid port number (expected 1-65535)")]
    BadPort(String),
    #[error("port range `{0}` is reversed (start is greater than end)")]
    ReversedRange(String),
    #[error("`{0}` is not a valid port item (expected `80`, `1-1024`, or `all`)")]
    Malformed(String),
}

/// Parse a port spec into a sorted, de-duplicated list.
///
/// Returns ports in ascending order. Probe ordering is applied later by the
/// permutation, so canonical order here keeps the resolved plan stable and diffable.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, PortParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(PortParseError::Empty);
    }

    let mut out = Vec::new();
    for raw in s.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if item.eq_ignore_ascii_case("all") {
            out.extend(1u16..=65535);
            continue;
        }

        match item.split_once('-') {
            Some((a, b)) => {
                let start = parse_one(a.trim())?;
                let end = parse_one(b.trim())?;
                if start > end {
                    return Err(PortParseError::ReversedRange(item.to_string()));
                }
                out.extend(start..=end);
            }
            None => {
                if item.chars().any(|c| !c.is_ascii_digit()) {
                    return Err(PortParseError::Malformed(item.to_string()));
                }
                out.push(parse_one(item)?);
            }
        }
    }

    if out.is_empty() {
        return Err(PortParseError::Empty);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn parse_one(s: &str) -> Result<u16, PortParseError> {
    if s.is_empty() {
        return Err(PortParseError::BadPort(s.to_string()));
    }
    let n: u32 = s
        .parse()
        .map_err(|_| PortParseError::BadPort(s.to_string()))?;
    if n == 0 || n > 65535 {
        return Err(PortParseError::BadPort(s.to_string()));
    }
    Ok(n as u16)
}

/// Render a port list back into the compact spec form, collapsing runs into ranges.
pub struct PortSummary<'a>(pub &'a [u16]);

impl fmt::Display for PortSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "(none)");
        }
        if self.0.len() == 65535 {
            return write!(f, "all");
        }
        let mut first = true;
        let mut i = 0;
        while i < self.0.len() {
            let start = self.0[i];
            let mut end = start;
            while i + 1 < self.0.len() && self.0[i + 1] == end + 1 {
                i += 1;
                end = self.0[i];
            }
            if !first {
                write!(f, ",")?;
            }
            first = false;
            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
            i += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
    }

    #[test]
    fn parses_list() {
        assert_eq!(parse_ports("80,443,8080").unwrap(), vec![80, 443, 8080]);
    }

    #[test]
    fn parses_range() {
        assert_eq!(parse_ports("20-25").unwrap(), vec![20, 21, 22, 23, 24, 25]);
    }

    #[test]
    fn parses_mixed_and_sorts() {
        assert_eq!(
            parse_ports("443,20-22,80").unwrap(),
            vec![20, 21, 22, 80, 443]
        );
    }

    #[test]
    fn deduplicates_overlaps() {
        assert_eq!(parse_ports("80,80,79-81").unwrap(), vec![79, 80, 81]);
    }

    #[test]
    fn parses_all() {
        let all = parse_ports("all").unwrap();
        assert_eq!(all.len(), 65535);
        assert_eq!(all[0], 1);
        assert_eq!(all[65534], 65535);
    }

    #[test]
    fn tolerates_whitespace() {
        assert_eq!(parse_ports(" 80 , 443 ").unwrap(), vec![80, 443]);
    }

    #[test]
    fn rejects_port_zero() {
        // Port 0 is not connectable and almost always indicates a typo.
        assert!(matches!(parse_ports("0"), Err(PortParseError::BadPort(_))));
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(matches!(
            parse_ports("65536"),
            Err(PortParseError::BadPort(_))
        ));
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(matches!(
            parse_ports("443-80"),
            Err(PortParseError::ReversedRange(_))
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_ports("http").is_err());
        assert!(parse_ports("").is_err());
        assert!(parse_ports("  ").is_err());
    }

    #[test]
    fn single_port_range_is_allowed() {
        assert_eq!(parse_ports("80-80").unwrap(), vec![80]);
    }

    #[test]
    fn summary_collapses_runs() {
        assert_eq!(PortSummary(&[80]).to_string(), "80");
        assert_eq!(PortSummary(&[80, 443]).to_string(), "80,443");
        assert_eq!(PortSummary(&[20, 21, 22, 80]).to_string(), "20-22,80");
        assert_eq!(PortSummary(&parse_ports("all").unwrap()).to_string(), "all");
    }

    #[test]
    fn summary_round_trips() {
        for spec in ["80", "80,443", "20-22,80", "1-1024"] {
            let parsed = parse_ports(spec).unwrap();
            let rendered = PortSummary(&parsed).to_string();
            assert_eq!(parse_ports(&rendered).unwrap(), parsed, "spec {spec}");
        }
    }
}
