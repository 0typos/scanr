//! RFC 3339 timestamp formatting from a Unix epoch.
//!
//! `chrono` and `time` were both considered and rejected (D18): we format one shape,
//! never parse, and need no timezone handling. This is ~40 lines against a dependency
//! tree that would otherwise be among the largest in the project.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Civil date from days since the Unix epoch (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn rfc3339_ms(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let ms = epoch_ms % 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

pub fn now_rfc3339() -> String {
    rfc3339_ms(now_epoch_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn formats_known_timestamps() {
        // Verified against `date -u -d @1785294704`.
        assert_eq!(rfc3339_ms(1_785_294_704_201), "2026-07-29T03:11:44.201Z");
        assert_eq!(rfc3339_ms(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
        assert_eq!(rfc3339_ms(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn handles_leap_days() {
        // 2024-02-29T12:00:00Z
        assert_eq!(rfc3339_ms(1_709_208_000_000), "2024-02-29T12:00:00.000Z");
        // 2000-02-29T00:00:00Z — the century leap year that trips naive implementations
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn handles_year_boundaries() {
        assert_eq!(rfc3339_ms(1_735_689_599_999), "2024-12-31T23:59:59.999Z");
        assert_eq!(rfc3339_ms(1_735_689_600_000), "2025-01-01T00:00:00.000Z");
    }

    #[test]
    fn milliseconds_are_zero_padded() {
        assert_eq!(&rfc3339_ms(5)[20..], "005Z");
        assert_eq!(&rfc3339_ms(50)[20..], "050Z");
        assert_eq!(&rfc3339_ms(500)[20..], "500Z");
    }

    #[test]
    fn now_is_plausible() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 24, "{s}");
        assert!(s.ends_with('Z'));
        // Somewhere after 2020 and before 2100.
        let year: i32 = s[..4].parse().unwrap();
        assert!((2020..2100).contains(&year), "{s}");
    }

    #[test]
    fn output_sorts_lexicographically_by_time() {
        let a = rfc3339_ms(1_700_000_000_000);
        let b = rfc3339_ms(1_700_000_000_001);
        let c = rfc3339_ms(1_800_000_000_000);
        assert!(a < b && b < c, "{a} {b} {c}");
    }
}
