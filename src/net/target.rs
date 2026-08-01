//! Target specification parsing and expansion.
//!
//! Accepted forms: IP literal, CIDR block, inclusive `start-end` range, and hostname.
//! CIDR and range arithmetic are written directly rather than pulling a crate — the
//! logic is small, and owning it lets the errors name the actual problem.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Expanded targets above this count require `--allow-large-range`. 4M addresses is
/// ~64 MB materialized, and anything larger is almost always a typo'd prefix.
pub const DEFAULT_MAX_TARGETS: u64 = 4_000_000;

/// IPv6 prefixes shorter than this are refused without an explicit opt-in. A /112 is
/// 65,536 addresses; a /64 is 18 quintillion and is never what someone meant.
pub const MIN_IPV6_PREFIX: u8 = 112;

/// The most addresses any expansion may materialise, opt-in or not.
///
/// `--allow-large-range` means "I know this is big", not "iterate 2^128 addresses".
/// Without this ceiling `::/0` under the flag entered a loop that cannot terminate and
/// cannot be interrupted, because expansion happens before the signal watcher exists.
/// 16,777,216 `Target`s is already ~400 MB.
const MAX_EXPANDABLE: u128 = 16_777_216;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetParseError {
    #[error("empty target")]
    Empty,
    #[error("`{0}` is not a valid IP address, CIDR block, range, or hostname")]
    Malformed(String),
    #[error("`{spec}` has an invalid prefix length /{prefix} (max /{max} for {family})")]
    BadPrefix {
        spec: String,
        prefix: u8,
        max: u8,
        family: &'static str,
    },
    #[error("range `{0}` mixes IPv4 and IPv6 addresses")]
    MixedFamilies(String),
    #[error("range `{0}` is reversed (start is greater than end)")]
    ReversedRange(String),
    #[error("`{0}` looks like a malformed IP address, not a hostname")]
    LooksLikeBadIp(String),
    #[error("hostname `{0}` is not valid")]
    BadHostname(String),
    // Endpoint parsing has its own variants because reusing `Malformed` produced
    // sentences that said the wrong thing: a bad port was reported as "not a valid IP
    // address", and the range case embedded its own explanation inside the quoted value,
    // yielding "`10.0.0.0/24:80 (a pair must name a single host...)` is not a valid IP
    // address, CIDR block, range, or hostname".
    #[error("`{0}` is not a `host:port` endpoint")]
    NotAnEndpoint(String),
    #[error("`{spec}` has an invalid port `{port}` (expected 1-65535)")]
    BadPort { spec: String, port: String },
    #[error("`{0}` names more than one host; an endpoint must name exactly one")]
    EndpointNotSingular(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpandError {
    #[error(
        "target set expands to {count} addresses, above the limit of {limit}\n\
         pass --allow-large-range if this is intentional"
    )]
    TooLarge { count: u64, limit: u64 },
    #[error(
        "`{spec}` expands to {approx} addresses, which no scan can hold in memory\n\
         --allow-large-range raises the review threshold, not this ceiling of {limit}"
    )]
    BeyondExpansion {
        spec: String,
        approx: String,
        limit: u128,
    },
    #[error(
        "IPv6 prefix /{prefix} in `{spec}` covers {approx} addresses\n\
         scanr refuses IPv6 prefixes shorter than /{min} unless --allow-large-range is set"
    )]
    Ipv6PrefixTooShort {
        spec: String,
        prefix: u8,
        approx: String,
        min: u8,
    },
}

/// A single target expression, before expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    Addr(IpAddr),
    /// Base is already masked to the prefix.
    Cidr {
        base: IpAddr,
        prefix: u8,
    },
    Range {
        start: IpAddr,
        end: IpAddr,
    },
    Host(String),
}

/// A single expanded probe target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    Addr(IpAddr),
    /// Retained unresolved — only valid when the transport resolves remotely (D15).
    Host(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Addr(a) => write!(f, "{a}"),
            Target::Host(h) => write!(f, "{h}"),
        }
    }
}

impl fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetSpec::Addr(a) => write!(f, "{a}"),
            TargetSpec::Cidr { base, prefix } => write!(f, "{base}/{prefix}"),
            TargetSpec::Range { start, end } => write!(f, "{start}-{end}"),
            TargetSpec::Host(h) => write!(f, "{h}"),
        }
    }
}

pub fn parse_target(input: &str) -> Result<TargetSpec, TargetParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(TargetParseError::Empty);
    }

    if let Some((base, prefix)) = s.split_once('/') {
        return parse_cidr(s, base.trim(), prefix.trim());
    }

    // A range needs both halves to parse as addresses. Checking that first keeps
    // hyphenated hostnames (`web-01.internal`) working.
    if let Some((a, b)) = s.split_once('-')
        && let (Ok(start), Ok(end)) = (a.trim().parse::<IpAddr>(), b.trim().parse::<IpAddr>())
    {
        return match (start, end) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                Err(TargetParseError::MixedFamilies(s.to_string()))
            }
            _ if to_u128(start) > to_u128(end) => {
                Err(TargetParseError::ReversedRange(s.to_string()))
            }
            _ => Ok(TargetSpec::Range { start, end }),
        };
    }

    if let Ok(addr) = s.parse::<IpAddr>() {
        return Ok(TargetSpec::Addr(addr));
    }

    validate_hostname(s)?;
    Ok(TargetSpec::Host(s.to_string()))
}

fn parse_cidr(spec: &str, base: &str, prefix: &str) -> Result<TargetSpec, TargetParseError> {
    let addr: IpAddr = base
        .parse()
        .map_err(|_| TargetParseError::Malformed(spec.to_string()))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| TargetParseError::Malformed(spec.to_string()))?;

    let (max, family) = match addr {
        IpAddr::V4(_) => (32u8, "IPv4"),
        IpAddr::V6(_) => (128u8, "IPv6"),
    };
    if prefix > max {
        return Err(TargetParseError::BadPrefix {
            spec: spec.to_string(),
            prefix,
            max,
            family,
        });
    }

    // Mask host bits rather than rejecting them: `10.0.0.5/24` meaning the whole /24 is
    // near-universal usage, and nmap accepts it.
    Ok(TargetSpec::Cidr {
        base: mask(addr, prefix),
        prefix,
    })
}

fn validate_hostname(s: &str) -> Result<(), TargetParseError> {
    if s.len() > 253 {
        return Err(TargetParseError::BadHostname(s.to_string()));
    }
    // `10.0.0.256` fails IP parsing and would otherwise be silently accepted as a
    // hostname, then fail at resolution with a confusing message.
    if s.split('.')
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(TargetParseError::LooksLikeBadIp(s.to_string()));
    }
    if s.split(':').count() > 1 && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return Err(TargetParseError::LooksLikeBadIp(s.to_string()));
    }

    let labels: Vec<&str> = s.trim_end_matches('.').split('.').collect();
    if labels.is_empty() || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return Err(TargetParseError::BadHostname(s.to_string()));
    }
    for label in &labels {
        if label.starts_with('-') || label.ends_with('-') {
            return Err(TargetParseError::BadHostname(s.to_string()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(TargetParseError::BadHostname(s.to_string()));
        }
    }
    Ok(())
}

fn to_u128(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn from_u128(v: u128, is_v4: bool) -> IpAddr {
    if is_v4 {
        IpAddr::V4(Ipv4Addr::from(v as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(v))
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

impl TargetSpec {
    /// Number of addresses this spec covers. Hostnames count as one until resolved.
    ///
    /// Saturates at `u128::MAX`, which is one short of the true count for `::/0`. That is
    /// the right trade: the value exists to be compared against an expansion limit, and
    /// no limit is anywhere near `2^128`.
    ///
    /// Both arms previously overflowed, found by fuzzing. `::/0` computed
    /// `1u128 << 128`, which panics in debug and — worse — silently wraps in release, so
    /// a release build reported that `::/0` "covers 1 addresses" and would have let it
    /// past a count-based limit check. The range arm had the same flaw for a range
    /// spanning the whole address space.
    /// Does this spec cover `target`, without expanding it?
    ///
    /// Matching rather than expanding is what lets a filter name a `/16` without
    /// materialising 65,536 addresses to compare against.
    pub fn matches(&self, target: &str) -> bool {
        if let TargetSpec::Host(h) = self {
            return h.eq_ignore_ascii_case(target);
        }
        let Ok(ip) = target.parse::<IpAddr>() else {
            return false;
        };
        match self {
            TargetSpec::Addr(a) => *a == ip,
            TargetSpec::Cidr { base, prefix } => {
                if base.is_ipv4() != ip.is_ipv4() {
                    return false;
                }
                let width = if ip.is_ipv4() { 32 } else { 128 };
                let host_bits = width - u32::from(*prefix);
                // A /0 shifts by the full width, which would overflow.
                let mask = if host_bits >= 128 {
                    0
                } else {
                    u128::MAX << host_bits
                };
                to_u128(ip) & mask == to_u128(*base) & mask
            }
            TargetSpec::Range { start, end } => {
                start.is_ipv4() == ip.is_ipv4()
                    && (to_u128(*start)..=to_u128(*end)).contains(&to_u128(ip))
            }
            TargetSpec::Host(_) => unreachable!("handled above"),
        }
    }

    pub fn count(&self) -> u128 {
        match self {
            TargetSpec::Addr(_) | TargetSpec::Host(_) => 1,
            TargetSpec::Cidr { base, prefix } => {
                let width: u32 = if base.is_ipv4() { 32 } else { 128 };
                let host_bits = width - *prefix as u32;
                1u128.checked_shl(host_bits).unwrap_or(u128::MAX)
            }
            TargetSpec::Range { start, end } => to_u128(*end)
                .saturating_sub(to_u128(*start))
                .saturating_add(1),
        }
    }

    /// Check expansion is permitted before doing it.
    fn check_expandable(&self, allow_large: bool) -> Result<(), ExpandError> {
        // The specific diagnostic first — it names the prefix and the remedy.
        if !allow_large
            && let TargetSpec::Cidr { base, prefix } = self
            && base.is_ipv6()
            && *prefix < MIN_IPV6_PREFIX
        {
            return Err(ExpandError::Ipv6PrefixTooShort {
                spec: self.to_string(),
                prefix: *prefix,
                approx: approx_count(self.count()),
                min: MIN_IPV6_PREFIX,
            });
        }
        // Then the ceiling, which applies even under the opt-in. `--allow-large-range`
        // means "I know this is big", not "iterate 2^128 addresses": before this, `::/0`
        // with the flag entered a loop that cannot terminate and cannot be interrupted,
        // because expansion happens before the signal watcher exists.
        if self.count() > MAX_EXPANDABLE {
            return Err(ExpandError::BeyondExpansion {
                spec: self.to_string(),
                approx: approx_count(self.count()),
                limit: MAX_EXPANDABLE,
            });
        }
        Ok(())
    }

    fn expand_into(&self, out: &mut Vec<Target>) {
        match self {
            TargetSpec::Addr(a) => out.push(Target::Addr(*a)),
            TargetSpec::Host(h) => out.push(Target::Host(h.clone())),
            TargetSpec::Cidr { base, .. } => {
                let is_v4 = base.is_ipv4();
                let start = to_u128(*base);
                // Through the checked path, as `count()` already does. `1u128 << 128` is
                // a debug panic and a release wrap, so `::/0` reported covering exactly
                // one address — the defect docs/security.md described in the past tense
                // while it was still live in this arm.
                let n = self.count();
                for i in 0..n {
                    out.push(Target::Addr(from_u128(start + i, is_v4)));
                }
            }
            TargetSpec::Range { start, end } => {
                let is_v4 = start.is_ipv4();
                for v in to_u128(*start)..=to_u128(*end) {
                    out.push(Target::Addr(from_u128(v, is_v4)));
                }
            }
        }
    }
}

fn approx_count(n: u128) -> String {
    if n >= 1_000_000_000_000 {
        format!("~{} trillion", n / 1_000_000_000_000)
    } else if n >= 1_000_000_000 {
        format!("~{} billion", n / 1_000_000_000)
    } else if n >= 1_000_000 {
        format!("~{} million", n / 1_000_000)
    } else {
        n.to_string()
    }
}

/// A set of include specs with exclusions applied.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    pub include: Vec<TargetSpec>,
    pub exclude: Vec<TargetSpec>,
}

impl TargetSet {
    /// Expand to concrete targets, applying exclusions and de-duplicating.
    ///
    /// Order is preserved from the include specs; probe order is randomized later by
    /// the permutation, so a stable canonical order here keeps plans diffable.
    pub fn expand(&self, allow_large: bool, limit: u64) -> Result<Vec<Target>, ExpandError> {
        let mut total: u128 = 0;
        for spec in &self.include {
            spec.check_expandable(allow_large)?;
            total += spec.count();
        }
        if !allow_large && total > limit as u128 {
            return Err(ExpandError::TooLarge {
                count: total.min(u64::MAX as u128) as u64,
                limit,
            });
        }

        let mut excluded: HashSet<Target> = HashSet::new();
        for spec in &self.exclude {
            spec.check_expandable(allow_large)?;
            let mut buf = Vec::new();
            spec.expand_into(&mut buf);
            excluded.extend(buf);
        }

        let mut seen: HashSet<Target> = HashSet::with_capacity(total.min(1 << 20) as usize);
        let mut out = Vec::with_capacity(total.min(1 << 20) as usize);
        let mut buf = Vec::new();
        for spec in &self.include {
            buf.clear();
            spec.expand_into(&mut buf);
            for t in buf.drain(..) {
                if !excluded.contains(&t) && seen.insert(t.clone()) {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }

    /// Total before exclusion, for plan projections that must not pay for expansion.
    pub fn approx_count(&self) -> u128 {
        self.include.iter().map(|s| s.count()).sum()
    }
}

/// Render a `host:port` pair, bracketing IPv6 so it can be parsed back.
pub fn format_pair(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parse a `host:port` pair as emitted by `scanr output remainder`.
///
/// IPv6 must be bracketed, because `::1:443` is itself a valid IPv6 address and cannot be
/// split unambiguously. That is the same reason result lines bracket them on output.
pub fn parse_pair(input: &str) -> Result<(TargetSpec, u16), TargetParseError> {
    let s = input.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        rest.split_once("]:")
            .ok_or_else(|| TargetParseError::NotAnEndpoint(s.to_string()))?
    } else {
        s.rsplit_once(':')
            .ok_or_else(|| TargetParseError::NotAnEndpoint(s.to_string()))?
    };

    let bad_port = || TargetParseError::BadPort {
        spec: s.to_string(),
        port: port.trim().to_string(),
    };
    let port: u32 = port.trim().parse().map_err(|_| bad_port())?;
    if port == 0 || port > 65535 {
        return Err(bad_port());
    }

    let spec = parse_target(host.trim())?;
    // An endpoint names one host; a range or CIDR would silently mean many.
    match spec {
        TargetSpec::Addr(_) | TargetSpec::Host(_) => Ok((spec, port as u16)),
        _ => Err(TargetParseError::EndpointNotSingular(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> TargetSpec {
        parse_target(s).unwrap()
    }

    fn expand(specs: &[&str]) -> Vec<String> {
        let set = TargetSet {
            include: specs.iter().map(|s| t(s)).collect(),
            exclude: vec![],
        };
        set.expand(false, DEFAULT_MAX_TARGETS)
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect()
    }

    #[test]
    fn parses_ipv4_literal() {
        assert_eq!(t("10.0.0.1"), TargetSpec::Addr("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_literal() {
        assert_eq!(t("::1"), TargetSpec::Addr("::1".parse().unwrap()));
        assert_eq!(
            t("2001:db8::5"),
            TargetSpec::Addr("2001:db8::5".parse().unwrap())
        );
    }

    #[test]
    fn parses_and_masks_cidr() {
        // Host bits set is near-universal usage; mask rather than reject.
        assert_eq!(
            t("10.20.30.5/24"),
            TargetSpec::Cidr {
                base: "10.20.30.0".parse().unwrap(),
                prefix: 24
            }
        );
    }

    #[test]
    fn parses_range() {
        assert_eq!(
            t("10.0.0.1-10.0.0.3"),
            TargetSpec::Range {
                start: "10.0.0.1".parse().unwrap(),
                end: "10.0.0.3".parse().unwrap()
            }
        );
    }

    #[test]
    fn parses_hostname_with_hyphen() {
        // Must not be mistaken for a range.
        assert_eq!(
            t("web-01.internal"),
            TargetSpec::Host("web-01.internal".into())
        );
    }

    #[test]
    fn expands_cidr_including_network_and_broadcast() {
        // nmap includes them; excluding them surprises people.
        let v = expand(&["10.0.0.0/30"]);
        assert_eq!(v, ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn expands_slash_32_and_slash_31() {
        assert_eq!(expand(&["10.0.0.7/32"]), ["10.0.0.7"]);
        assert_eq!(expand(&["10.0.0.6/31"]), ["10.0.0.6", "10.0.0.7"]);
    }

    #[test]
    fn expands_range_inclusively() {
        assert_eq!(
            expand(&["10.0.0.1-10.0.0.3"]),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        );
    }

    #[test]
    fn deduplicates_across_overlapping_includes() {
        let v = expand(&["10.0.0.0/31", "10.0.0.1", "10.0.0.0/31"]);
        assert_eq!(v, ["10.0.0.0", "10.0.0.1"]);
    }

    #[test]
    fn applies_exclusions_after_expansion() {
        let set = TargetSet {
            include: vec![t("10.0.0.0/29")],
            exclude: vec![t("10.0.0.1"), t("10.0.0.6-10.0.0.7")],
        };
        let v: Vec<String> = set
            .expand(false, DEFAULT_MAX_TARGETS)
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect();
        assert_eq!(
            v,
            ["10.0.0.0", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        );
    }

    #[test]
    fn counts_do_not_overflow_at_the_extremes() {
        // Found by fuzzing: `::/0` computed 1u128 << 128, which panics in debug and
        // silently wraps to 1 in release. A count of 1 for the entire address space
        // would sail past any limit check.
        assert_eq!(t("::/0").count(), u128::MAX);
        assert_eq!(t("::/1").count(), 1u128 << 127);
        assert_eq!(t("0.0.0.0/0").count(), 1u128 << 32);
        // Whole-space range, the same flaw in the other arm.
        assert_eq!(
            t("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").count(),
            u128::MAX
        );
        assert_eq!(t("0.0.0.0-255.255.255.255").count(), 1u128 << 32);
    }

    #[test]
    fn absurd_ranges_are_refused_not_iterated() {
        // The count must be truthful enough for the limit check to reject these.
        for spec in ["::/0", "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"] {
            let set = TargetSet {
                include: vec![t(spec)],
                exclude: vec![],
            };
            assert!(
                set.expand(false, DEFAULT_MAX_TARGETS).is_err(),
                "{spec} should be refused"
            );
        }
    }

    #[test]
    fn counts_without_expanding() {
        assert_eq!(t("10.0.0.0/24").count(), 256);
        assert_eq!(t("10.0.0.0/16").count(), 65536);
        assert_eq!(t("2001:db8::/112").count(), 65536);
        assert_eq!(t("10.0.0.1-10.0.0.10").count(), 10);
    }

    /// `--allow-large-range` raises the review threshold, not the memory ceiling. Before
    /// this, `::/0` under the flag shifted past `u128` (a debug panic, a release wrap to
    /// one address) and, once that was checked, entered a loop over 2^128 that cannot be
    /// interrupted — expansion happens before the signal watcher exists.
    #[test]
    fn expansion_is_bounded_even_under_the_opt_in() {
        let set = TargetSet {
            include: vec![t("::/0")],
            exclude: vec![],
        };
        assert!(matches!(
            set.expand(true, u64::MAX),
            Err(ExpandError::BeyondExpansion { .. })
        ));
        // And the count itself no longer overflows.
        assert_eq!(t("::/0").count(), u128::MAX);
    }

    #[test]
    fn refuses_short_ipv6_prefix() {
        let set = TargetSet {
            include: vec![t("2001:db8::/64")],
            exclude: vec![],
        };
        assert!(matches!(
            set.expand(false, DEFAULT_MAX_TARGETS),
            Err(ExpandError::Ipv6PrefixTooShort { .. })
        ));
        // /112 is fine.
        let ok = TargetSet {
            include: vec![t("2001:db8::/112")],
            exclude: vec![],
        };
        assert_eq!(ok.expand(false, DEFAULT_MAX_TARGETS).unwrap().len(), 65536);
    }

    #[test]
    fn refuses_oversized_expansion() {
        let set = TargetSet {
            include: vec![t("10.0.0.0/8")],
            exclude: vec![],
        };
        assert!(matches!(
            set.expand(false, DEFAULT_MAX_TARGETS),
            Err(ExpandError::TooLarge { .. })
        ));
        // The opt-in path is checked against a small limit rather than by actually
        // materializing 16.7M addresses, which dominated test runtime.
        let small = TargetSet {
            include: vec![t("10.0.0.0/24")],
            exclude: vec![],
        };
        assert!(matches!(
            small.expand(false, 10),
            Err(ExpandError::TooLarge {
                count: 256,
                limit: 10
            })
        ));
        assert_eq!(small.expand(true, 10).unwrap().len(), 256);
    }

    #[test]
    fn rejects_malformed_ip_masquerading_as_hostname() {
        // Would otherwise be accepted as a hostname and fail confusingly at resolution.
        assert!(matches!(
            parse_target("10.0.0.256"),
            Err(TargetParseError::LooksLikeBadIp(_))
        ));
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!(matches!(
            parse_target("10.0.0.0/33"),
            Err(TargetParseError::BadPrefix { .. })
        ));
        assert!(matches!(
            parse_target("::1/129"),
            Err(TargetParseError::BadPrefix { .. })
        ));
    }

    #[test]
    fn rejects_reversed_and_mixed_ranges() {
        assert!(matches!(
            parse_target("10.0.0.9-10.0.0.1"),
            Err(TargetParseError::ReversedRange(_))
        ));
        assert!(matches!(
            parse_target("10.0.0.1-::1"),
            Err(TargetParseError::MixedFamilies(_))
        ));
    }

    #[test]
    fn rejects_bad_hostnames() {
        assert!(parse_target("-leading.hyphen").is_err());
        assert!(parse_target("double..dot").is_err());
        assert!(parse_target("bad host").is_err());
        assert!(parse_target(&"a".repeat(300)).is_err());
    }

    #[test]
    fn accepts_reasonable_hostnames() {
        for h in [
            "app.internal",
            "web-01",
            "srv_1.corp.example.com",
            "localhost",
        ] {
            assert!(matches!(parse_target(h), Ok(TargetSpec::Host(_))), "{h}");
        }
    }

    #[test]
    fn specs_match_without_expanding() {
        let m = |spec: &str, t: &str| parse_target(spec).unwrap().matches(t);

        assert!(m("10.0.0.5", "10.0.0.5"));
        assert!(!m("10.0.0.5", "10.0.0.6"));

        assert!(m("10.0.0.0/24", "10.0.0.255"));
        assert!(!m("10.0.0.0/24", "10.0.1.0"));
        // A /16 must match by arithmetic, not by expanding 65,536 addresses.
        assert!(m("10.20.0.0/16", "10.20.30.40"));
        assert!(!m("10.20.0.0/16", "10.21.0.1"));
        // /0 shifts by the full width; it must not overflow.
        assert!(m("0.0.0.0/0", "203.0.113.9"));

        assert!(m("10.0.0.5-10.0.0.9", "10.0.0.7"));
        assert!(!m("10.0.0.5-10.0.0.9", "10.0.0.4"));

        assert!(m("app.internal", "app.internal"));
        assert!(
            m("APP.internal", "app.internal"),
            "hostnames are case-insensitive"
        );
        assert!(!m("app.internal", "10.0.0.1"));

        // Families never cross.
        assert!(!m("10.0.0.0/8", "::1"));
        assert!(m("2001:db8::/32", "2001:db8::dead"));
        assert!(!m("2001:db8::/32", "2001:db9::1"));
    }

    #[test]
    fn parses_endpoints_including_bracketed_ipv6() {
        let cases = [
            ("10.0.0.1:443", "10.0.0.1", 443u16),
            ("[2001:db8::1]:80", "2001:db8::1", 80),
            ("[::1]:22", "::1", 22),
            ("app.internal:8080", "app.internal", 8080),
            ("  10.0.0.1:1  ", "10.0.0.1", 1),
        ];
        for (input, host, port) in cases {
            let (spec, p) = parse_pair(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(spec.to_string(), host, "{input}");
            assert_eq!(p, port, "{input}");
        }
    }

    /// Each failure must name what is actually wrong.
    ///
    /// These all used to render through `Malformed`, so a bad port was reported as "not
    /// a valid IP address, CIDR block, range, or hostname", and the range case produced
    /// a sentence with its own explanation quoted inside the offending value.
    #[test]
    fn endpoint_errors_say_what_is_wrong() {
        let msg = |s: &str| parse_pair(s).unwrap_err().to_string();

        let m = msg("10.0.0.0/24:80");
        assert!(m.contains("names more than one host"), "{m}");
        assert!(!m.contains("is not a valid IP address"), "{m}");

        for bad in ["127.0.0.1:99999", "127.0.0.1:0", "127.0.0.1:http"] {
            let m = msg(bad);
            assert!(m.contains("invalid port"), "{bad}: {m}");
            assert!(m.contains("1-65535"), "{bad}: {m}");
        }

        let m = msg("nocolon");
        assert!(m.contains("is not a `host:port` endpoint"), "{m}");

        // A genuinely bad host still reports a host problem, not a port one.
        let m = msg("not a host:80");
        assert!(!m.contains("invalid port"), "{m}");
    }

    #[test]
    fn endpoints_round_trip_through_format_pair() {
        for s in ["10.0.0.1:443", "[2001:db8::1]:80", "app.internal:22"] {
            let (spec, port) = parse_pair(s).unwrap();
            assert_eq!(format_pair(&spec.to_string(), port), s, "{s}");
        }
    }
}
