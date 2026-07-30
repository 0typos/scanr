//! Target, port, and duration specs come from configuration, the command line, and from
//! files or stdin produced by other tools — so in practice they are attacker-adjacent
//! whenever a target list is generated upstream.
//!
//! Properties checked here go beyond "does not panic": expansion counts must match the
//! declared count, and parse/render must round-trip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanr::net::target::{DEFAULT_MAX_TARGETS, TargetSet};
use scanr::net::{parse_ports, parse_target, ports::PortSummary};
use scanr::units::parse_duration;

fuzz_target!(|data: &str| {
    // ── durations ────────────────────────────────────────────────────────────
    if let Ok(d) = parse_duration(data) {
        // Anything accepted must render back into something acceptable.
        let rendered = scanr::units::render_duration(d);
        assert_eq!(
            parse_duration(&rendered).ok(),
            Some(d),
            "duration {data:?} rendered as {rendered:?} and did not round-trip"
        );
    }

    // ── ports ────────────────────────────────────────────────────────────────
    if let Ok(ports) = parse_ports(data) {
        assert!(!ports.is_empty(), "accepted a spec yielding no ports");
        assert!(ports.windows(2).all(|w| w[0] < w[1]), "not sorted and deduped");
        assert!(ports.iter().all(|&p| p != 0), "port 0 is not connectable");
        // The compact rendering must parse back to the identical set.
        let summary = PortSummary(&ports).to_string();
        assert_eq!(
            parse_ports(&summary).ok().as_ref(),
            Some(&ports),
            "port spec {data:?} rendered as {summary:?} and did not round-trip"
        );
    }

    // ── targets ──────────────────────────────────────────────────────────────
    if let Ok(spec) = parse_target(data) {
        let declared = spec.count();
        // Display must round-trip through the parser.
        let shown = spec.to_string();
        assert_eq!(
            parse_target(&shown).ok(),
            Some(spec.clone()),
            "target {data:?} rendered as {shown:?} and did not round-trip"
        );

        // Only expand when it is cheap, but check the count is truthful when we do.
        if declared <= 4096 {
            let set = TargetSet {
                include: vec![spec],
                exclude: vec![],
            };
            if let Ok(expanded) = set.expand(false, DEFAULT_MAX_TARGETS) {
                assert_eq!(
                    expanded.len() as u128, declared,
                    "count() said {declared} but expansion produced {}",
                    expanded.len()
                );
            }
        }
    }
});
