//! Collapsing repetitive probe outcomes into spans.
//!
//! Measured on a real record: the bulk rows of a large scan carry exactly one distinct
//! `(state, source, reason)` tuple, with timings spanning 300.12–300.61 ms against a
//! 300 ms timeout. That is ~360 bytes per row to record "the timeout fired", for a
//! million rows. The information content is which endpoint, and which of a handful of
//! outcome classes — nothing else.
//!
//! A span keeps exactly that and drops the rest. What is preserved: precisely which
//! endpoints got which outcome, the three-bucket accounting, and `remainder`'s ability
//! to derive what was missed. What is lost: the per-probe timestamp, and exact timing
//! for probes whose timing was "the timeout fired". Aggregate timing is kept.
//!
//! Endpoints are recorded as ranges over `probe_index`, which is the target-major
//! position in the planned matrix — `probe_index / port_count` selects the target and
//! `probe_index % port_count` the port. The permutation decides only the *order* probes
//! are visited, never the mapping, so a consumer expands a span with arithmetic and the
//! specs already in `scan_config`. A scan whose results are uniform collapses to a
//! handful of ranges.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::output::ProbeRecord;
use crate::probe::{Source, State};

/// Distinct outcome classes to collapse before giving up.
///
/// A record with more than this many distinct `(state, source, reason)` tuples among its
/// bulk rows is not repetitive enough for spans to pay, and an unbounded group count
/// would defeat the memory bound. Beyond it every probe keeps its own row.
const MAX_GROUPS: usize = 64;

/// Attempts is part of the key so a span can state how many each probe took.
type GroupKey = (State, Source, Option<String>, u32);

/// One outcome class and the probes that shared it.
struct Group {
    /// A bit per planned probe: 128 KB per group for a million-probe scan.
    bits: Vec<u64>,
    count: u64,
    min_ms: f64,
    max_ms: f64,
    sum_ms: f64,
}

impl Group {
    fn new(planned: u64) -> Self {
        Self {
            bits: vec![0u64; (planned as usize).div_ceil(64).max(1)],
            count: 0,
            min_ms: f64::INFINITY,
            max_ms: 0.0,
            sum_ms: 0.0,
        }
    }

    fn add(&mut self, index: u64, ms: f64) {
        self.bits[(index / 64) as usize] |= 1 << (index % 64);
        self.count += 1;
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
        self.sum_ms += ms;
    }

    /// Set bits as inclusive `[start, end]` ranges.
    fn ranges(&self, planned: u64) -> Vec<[u64; 2]> {
        let mut out: Vec<[u64; 2]> = Vec::new();
        for i in 0..planned {
            let set = self.bits[(i / 64) as usize] & (1 << (i % 64)) != 0;
            if !set {
                continue;
            }
            match out.last_mut() {
                Some(r) if r[1] + 1 == i => r[1] = i,
                _ => out.push([i, i]),
            }
        }
        out
    }
}

/// Accumulates bulk outcomes so they can be written as spans instead of rows.
pub struct Spans {
    planned: u64,
    groups: BTreeMap<GroupKey, Group>,
    /// Set once `MAX_GROUPS` is reached; from then on nothing is absorbed.
    exhausted: bool,
}

impl Spans {
    pub fn new(planned: u64) -> Self {
        Self {
            planned,
            groups: BTreeMap::new(),
            exhausted: false,
        }
    }

    /// Is this outcome bulk — interchangeable with its neighbours?
    ///
    /// `open` is the result the scan exists to find and `error` names something that
    /// needs reading, so neither is ever bulk. A probe that hit resource pressure is
    /// evidence about the scanner's own health and keeps its row.
    ///
    /// Retries are bulk when they *agreed*. The first rule here excluded every retried
    /// probe, which sounded careful and was useless: `retries = 1` is the default and
    /// applies to timeouts, so in a scan of silent hosts — the case spans exist for —
    /// every single probe is retried and nothing would ever collapse. A probe that timed
    /// out twice has attempt history `["filtered", "filtered"]`, which says nothing the
    /// state does not. A probe whose attempts *disagreed* is a different matter: that is
    /// a flapping or slow host, and it keeps its row.
    pub fn is_bulk(record: &ProbeRecord) -> bool {
        record.outcome.pressure.is_none()
            && matches!(record.outcome.state, State::Closed | State::Filtered)
            && record
                .attempt_states
                .iter()
                .all(|s| *s == record.outcome.state)
    }

    /// Absorb a record, returning whether it was taken. A refused record must still be
    /// written as its own row.
    pub fn absorb(&mut self, record: &ProbeRecord) -> bool {
        if self.exhausted || !Self::is_bulk(record) || record.probe_index >= self.planned {
            return false;
        }
        let key = (
            record.outcome.state,
            record.outcome.source,
            record.outcome.reason.clone(),
            record.attempts,
        );
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_GROUPS {
            self.exhausted = true;
            return false;
        }
        let planned = self.planned;
        self.groups
            .entry(key)
            .or_insert_with(|| Group::new(planned))
            .add(
                record.probe_index,
                record.outcome.phases.total.as_secs_f64() * 1000.0,
            );
        true
    }

    /// Whether anything was absorbed, and so whether spans will be written.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Total probes represented, which the terminal counts must still account for.
    pub fn total(&self) -> u64 {
        self.groups.values().map(|g| g.count).sum()
    }

    /// One `probe_span` body per outcome class.
    pub fn into_events(self) -> Vec<Value> {
        let planned = self.planned;
        self.groups
            .into_iter()
            .map(|((state, source, reason, attempts), g)| {
                let round = |v: f64| (v * 100.0).round() / 100.0;
                json!({
                    "state": state.as_str(),
                    "source": source.as_str(),
                    "reason": reason,
                    "protocol": "tcp",
                    "attempts": attempts,
                    "count": g.count,
                    "probe_indices": g.ranges(planned),
                    "timing_ms": {
                        "min": round(g.min_ms),
                        "max": round(g.max_ms),
                        "mean": round(g.sum_ms / g.count as f64),
                    },
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Phases, ProbeOutcome};
    use std::time::Duration;

    fn record(index: u64, port: u16, state: State, ms: u64) -> ProbeRecord {
        ProbeRecord {
            probe_index: index,
            target: format!("10.0.0.{}", index / 4),
            resolved_address: None,
            port,
            outcome: ProbeOutcome {
                state,
                source: Source::Timeout,
                reason: Some("connect timed out".into()),
                phases: Phases {
                    proxy_connect: None,
                    handshake: None,
                    connect: Some(Duration::from_millis(ms)),
                    total: Duration::from_millis(ms),
                },
                pressure: None,
            },
            attempts: 1,
            attempt_states: vec![state],
        }
    }

    #[test]
    fn open_and_error_are_never_bulk() {
        for s in [State::Open, State::Error] {
            assert!(!Spans::is_bulk(&record(0, 80, s, 1)), "{s:?}");
        }
        for s in [State::Closed, State::Filtered] {
            assert!(Spans::is_bulk(&record(0, 80, s, 1)), "{s:?}");
        }
    }

    /// The case spans exist for: `retries = 1` is the default and applies to timeouts,
    /// so in a scan of silent hosts every probe is retried. Excluding retried probes
    /// meant nothing ever collapsed.
    #[test]
    fn a_retry_that_agreed_is_still_bulk() {
        let mut r = record(0, 80, State::Filtered, 300);
        r.attempts = 2;
        r.attempt_states = vec![State::Filtered, State::Filtered];
        assert!(
            Spans::is_bulk(&r),
            "a timeout that timed out again says nothing new"
        );
    }

    #[test]
    fn a_retry_that_disagreed_keeps_its_row() {
        let mut r = record(0, 80, State::Filtered, 300);
        r.attempts = 2;
        r.attempt_states = vec![State::Open, State::Filtered];
        assert!(
            !Spans::is_bulk(&r),
            "a flapping host is not interchangeable"
        );
    }

    #[test]
    fn a_pressured_probe_keeps_its_row() {
        let mut r = record(0, 80, State::Filtered, 300);
        r.outcome.pressure = Some(crate::diag::Pressure::FileDescriptorExhaustion);
        assert!(
            !Spans::is_bulk(&r),
            "pressure is evidence about the scanner"
        );
    }

    #[test]
    fn attempts_separate_spans_and_are_reported() {
        let mut s = Spans::new(10);
        s.absorb(&record(0, 80, State::Filtered, 300));
        let mut r = record(1, 80, State::Filtered, 300);
        r.attempts = 2;
        r.attempt_states = vec![State::Filtered, State::Filtered];
        s.absorb(&r);
        let events = s.into_events();
        assert_eq!(
            events.len(),
            2,
            "different attempt counts are different spans"
        );
        let mut a: Vec<u64> = events
            .iter()
            .map(|e| e["attempts"].as_u64().unwrap())
            .collect();
        a.sort_unstable();
        assert_eq!(a, [1, 2]);
    }

    #[test]
    fn contiguous_probes_collapse_to_one_range() {
        let mut s = Spans::new(100);
        for i in 0..100 {
            assert!(s.absorb(&record(i, 80, State::Filtered, 300)));
        }
        let events = s.into_events();
        assert_eq!(events.len(), 1, "one outcome class, one span");
        assert_eq!(events[0]["count"], 100);
        assert_eq!(events[0]["probe_indices"], json!([[0, 99]]));
        assert_eq!(events[0]["state"], "filtered");
    }

    #[test]
    fn a_hole_splits_the_range() {
        let mut s = Spans::new(10);
        for i in [0, 1, 2, 5, 6, 9] {
            s.absorb(&record(i, 80, State::Filtered, 300));
        }
        assert_eq!(
            s.into_events()[0]["probe_indices"],
            json!([[0, 2], [5, 6], [9, 9]])
        );
    }

    #[test]
    fn distinct_outcomes_get_distinct_spans() {
        let mut s = Spans::new(10);
        s.absorb(&record(0, 80, State::Filtered, 300));
        s.absorb(&record(1, 80, State::Closed, 1));
        let events = s.into_events();
        assert_eq!(events.len(), 2);
        let states: Vec<&str> = events
            .iter()
            .map(|e| e["state"].as_str().unwrap())
            .collect();
        assert!(
            states.contains(&"filtered") && states.contains(&"closed"),
            "{states:?}"
        );
    }

    #[test]
    fn timing_is_summarised_not_discarded() {
        let mut s = Spans::new(10);
        for (i, ms) in [(0u64, 100u64), (1, 200), (2, 300)] {
            s.absorb(&record(i, 80, State::Filtered, ms));
        }
        let t = &s.into_events()[0]["timing_ms"];
        assert_eq!(t["min"], 100.0);
        assert_eq!(t["max"], 300.0);
        assert_eq!(t["mean"], 200.0);
    }

    /// A record too varied to compress must fall back rather than allocate a group per
    /// distinct outcome.
    #[test]
    fn too_many_outcome_classes_stops_collapsing() {
        let mut s = Spans::new(1000);
        for i in 0..(MAX_GROUPS as u64 + 10) {
            let mut r = record(i, 80, State::Filtered, 300);
            r.outcome.reason = Some(format!("reason {i}"));
            let taken = s.absorb(&r);
            if i >= MAX_GROUPS as u64 {
                assert!(!taken, "group {i} should not have been absorbed");
            }
        }
        assert!(s.groups.len() <= MAX_GROUPS);
    }

    #[test]
    fn an_index_beyond_the_plan_is_refused_rather_than_panicking() {
        let mut s = Spans::new(10);
        assert!(!s.absorb(&record(10, 80, State::Filtered, 300)));
        assert!(!s.absorb(&record(u64::MAX, 80, State::Filtered, 300)));
        assert!(s.is_empty());
    }
}
