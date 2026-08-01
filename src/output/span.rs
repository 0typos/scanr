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
    /// Indices absorbed since the last drain, in arrival order.
    ///
    /// Sparse rather than a bit per planned probe. The bitset this replaced cost
    /// `planned / 8` bytes per outcome class no matter how few probes landed in it —
    /// 8.2 MB each for a 65M-probe scan, and ~200 MB each for a `/8 x 100`, which
    /// `--allow-large-range` permits. `Reported` in `run.rs` refuses to allocate its
    /// identically shaped bitset above `MAX_TRACKED_PROBES` for exactly that reason;
    /// this one had no ceiling at all, and spans are on by default.
    ///
    /// Draining on every progress tick is what makes sparse the better shape anyway: a
    /// group only ever holds one interval's worth of probes, so memory follows
    /// throughput rather than scan size. It beats the bitset whenever an interval
    /// absorbs fewer than `planned / 64` probes, which at any real scan rate it does by
    /// orders of magnitude.
    indices: Vec<u64>,
    min_ms: f64,
    max_ms: f64,
    sum_ms: f64,
}

impl Group {
    fn new() -> Self {
        Self {
            indices: Vec::new(),
            min_ms: f64::INFINITY,
            max_ms: 0.0,
            sum_ms: 0.0,
        }
    }

    fn add(&mut self, index: u64, ms: f64) {
        self.indices.push(index);
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
        self.sum_ms += ms;
    }

    /// Inclusive `[start, end]` ranges, and how many probes they cover.
    ///
    /// Probes complete out of order — the permutation decides visit order — so this
    /// sorts. `dedup` holds the invariant the bitset used to give for free: `count` is
    /// the number of indices the ranges actually cover, so a consumer expanding a span
    /// gets back exactly `count` endpoints. One record per probe means duplicates should
    /// not arise; if one ever did, the old code counted it twice while setting one bit,
    /// and the span's own count disagreed with its ranges.
    fn ranges(&mut self) -> (Vec<[u64; 2]>, u64) {
        self.indices.sort_unstable();
        self.indices.dedup();
        let mut out: Vec<[u64; 2]> = Vec::new();
        for &i in &self.indices {
            match out.last_mut() {
                Some(r) if r[1] + 1 == i => r[1] = i,
                _ => out.push([i, i]),
            }
        }
        (out, self.indices.len() as u64)
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
        self.groups.entry(key).or_insert_with(Group::new).add(
            record.probe_index,
            record.outcome.phases.total.as_secs_f64() * 1000.0,
        );
        true
    }

    /// One `probe_span` body per outcome class, emptying the accumulator.
    ///
    /// Called periodically as well as at the end, because a span held only in memory is
    /// a span a killed process loses. Before spans existed every probe was written as it
    /// completed, so a `.partial` record preserved real progress; accumulating for the
    /// whole scan and writing once would have made a SIGKILL lose every collapsed probe.
    /// Draining bounds that to one progress interval, and several spans of the same
    /// class are as valid as one — their ranges are disjoint and their counts add.
    pub fn drain_events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.groups)
            .into_iter()
            .map(|((state, source, reason, attempts), mut g)| {
                let round = |v: f64| (v * 100.0).round() / 100.0;
                let (ranges, count) = g.ranges();
                json!({
                    "state": state.as_str(),
                    "source": source.as_str(),
                    "reason": reason,
                    "protocol": "tcp",
                    "attempts": attempts,
                    "count": count,
                    "probe_indices": ranges,
                    "timing_ms": {
                        "min": round(g.min_ms),
                        "max": round(g.max_ms),
                        "mean": round(g.sum_ms / count as f64),
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
                banner: None,
                via: None,
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
        let events = s.drain_events();
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
        let events = s.drain_events();
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
            s.drain_events()[0]["probe_indices"],
            json!([[0, 2], [5, 6], [9, 9]])
        );
    }

    #[test]
    fn distinct_outcomes_get_distinct_spans() {
        let mut s = Spans::new(10);
        s.absorb(&record(0, 80, State::Filtered, 300));
        s.absorb(&record(1, 80, State::Closed, 1));
        let events = s.drain_events();
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
        let t = &s.drain_events()[0]["timing_ms"];
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

    /// Draining must empty the accumulator, or the periodic flush would re-emit every
    /// probe it already wrote and the counts would double.
    #[test]
    fn draining_empties_the_accumulator() {
        let mut s = Spans::new(100);
        for i in 0..10 {
            s.absorb(&record(i, 80, State::Filtered, 300));
        }
        let first = s.drain_events();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["count"], 10);
        assert!(
            s.groups.is_empty(),
            "the drained probes must not still be held"
        );
        assert!(
            s.drain_events().is_empty(),
            "a second drain has nothing to say"
        );

        // Probes after a drain form their own span, disjoint from the first.
        for i in 10..15 {
            s.absorb(&record(i, 80, State::Filtered, 300));
        }
        let second = s.drain_events();
        assert_eq!(second[0]["count"], 5);
        assert_eq!(second[0]["probe_indices"], json!([[10, 14]]));
    }

    /// The bit-per-planned-probe layout allocated up front, per outcome class, whether
    /// or not any probe ever landed in it. This plan would have asked for 2 exabytes and
    /// aborted the process before the first probe was absorbed.
    #[test]
    fn a_huge_plan_costs_nothing_until_probes_arrive() {
        let mut s = Spans::new(u64::MAX);
        assert!(s.absorb(&record(u64::MAX - 1, 80, State::Filtered, 300)));
        assert!(s.absorb(&record(7, 80, State::Filtered, 300)));
        let ev = s.drain_events();
        assert_eq!(ev[0]["count"], 2);
        assert_eq!(
            ev[0]["probe_indices"],
            json!([[7, 7], [u64::MAX - 1, u64::MAX - 1]]),
            "sorted, and sparse rather than one bit per planned probe"
        );
    }

    /// `/8 x 100`, which `--allow-large-range` permits, against the 64-class ceiling.
    /// The old layout wanted ~200 MB per class here — ~12 GB in total — for a scan that
    /// had so far reported sixty-four probes.
    #[test]
    fn a_billion_probe_plan_holds_only_what_it_absorbed() {
        let mut s = Spans::new(1_677_721_600);
        for i in 0..64u64 {
            // A distinct reason per probe, so each opens its own group.
            let mut r = record(i * 1_000_000, 80, State::Filtered, 300);
            r.outcome.reason = Some(format!("reason {i}"));
            assert!(s.absorb(&r));
        }
        assert_eq!(s.groups.len(), 64, "the class ceiling, all allocated");
        let total: u64 = s
            .drain_events()
            .iter()
            .map(|e| e["count"].as_u64().unwrap())
            .sum();
        assert_eq!(total, 64);
    }

    /// `count` has to be the number of endpoints the ranges cover, because that is what a
    /// consumer expanding the span gets back. The bitset gave this for free; a plain
    /// index list has to dedup to keep it.
    #[test]
    fn count_matches_the_ranges_it_reports() {
        let mut s = Spans::new(100);
        for i in [5u64, 1, 3, 2, 1, 5] {
            s.absorb(&record(i, 80, State::Filtered, 300));
        }
        let ev = s.drain_events();
        assert_eq!(ev[0]["probe_indices"], json!([[1, 3], [5, 5]]));
        assert_eq!(
            ev[0]["count"], 4,
            "four distinct endpoints, not six absorptions"
        );
    }

    #[test]
    fn an_index_beyond_the_plan_is_refused_rather_than_panicking() {
        let mut s = Spans::new(10);
        assert!(!s.absorb(&record(10, 80, State::Filtered, 300)));
        assert!(!s.absorb(&record(u64::MAX, 80, State::Filtered, 300)));
        assert!(s.groups.is_empty());
    }
}
