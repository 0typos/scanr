//! Reading scan records back: summarize, verify, and remainder.
//!
//! `remainder` is what replaces a `resume` feature (D12). The set of probes that never
//! ran is just a target list, so emitting it and piping it back gives resume-by-
//! composition without committing the schema to anything.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::net::target::{TargetSet, format_pair, parse_pair};
use crate::net::{parse_ports, parse_target};
use crate::units::{HumanElapsed, commas};

struct Record {
    events: Vec<Value>,
    raw_lines: usize,
    bad_lines: Vec<usize>,
    partial: bool,
}

fn read(path: &Path) -> Result<Record, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut events = Vec::new();
    let mut bad_lines = Vec::new();
    let mut raw_lines = 0;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        raw_lines += 1;
        match serde_json::from_str::<Value>(line) {
            Ok(v) => events.push(v),
            Err(_) => bad_lines.push(i + 1),
        }
    }
    Ok(Record {
        events,
        raw_lines,
        bad_lines,
        partial: path.to_string_lossy().ends_with(".partial"),
    })
}

fn kind(v: &Value) -> &str {
    v["type"].as_str().unwrap_or("")
}

const TERMINALS: [&str; 3] = ["scan_completed", "scan_interrupted", "scan_failed"];

#[derive(Debug)]
pub struct VerifyReport {
    pub file: String,
    pub events: usize,
    pub problems: Vec<String>,
    pub notes: Vec<String>,
}

impl VerifyReport {
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}", self.file);
        let _ = writeln!(s, "  {} events", commas(self.events as u64));
        for n in &self.notes {
            let _ = writeln!(s, "  {n}");
        }
        if self.problems.is_empty() {
            let _ = writeln!(s, "\nok — record is complete and internally consistent");
        } else {
            let _ = writeln!(s);
            for p in &self.problems {
                let _ = writeln!(s, "  problem: {p}");
            }
            let _ = writeln!(s, "\n{} problem(s) found", self.problems.len());
        }
        s
    }
}

pub fn verify(path: &Path) -> Result<VerifyReport, String> {
    let rec = read(path)?;
    let mut problems = Vec::new();
    let mut notes = Vec::new();

    for line in &rec.bad_lines {
        problems.push(format!("line {line} is not valid JSON"));
    }

    if rec.events.is_empty() {
        problems.push("file contains no events".into());
        return Ok(VerifyReport {
            file: path.display().to_string(),
            events: 0,
            problems,
            notes,
        });
    }

    // Header order.
    if kind(&rec.events[0]) != "scan_started" {
        problems.push(format!(
            "first event is `{}`, expected `scan_started`",
            kind(&rec.events[0])
        ));
    }
    if rec.events.len() > 1 && kind(&rec.events[1]) != "scan_config" {
        problems.push(format!(
            "second event is `{}`, expected `scan_config`",
            kind(&rec.events[1])
        ));
    }

    // Schema version.
    if let Some(v) = rec.events[0]["schema_version"].as_u64()
        && v != crate::output::SCHEMA_VERSION as u64
    {
        problems.push(format!(
            "schema_version {v} is not supported by this build ({})",
            crate::output::SCHEMA_VERSION
        ));
    }

    // Consistent scan id and strictly increasing sequence.
    let scan_id = rec.events[0]["scan_id"].as_str().unwrap_or("").to_string();
    let mut last_seq: Option<u64> = None;
    for (i, e) in rec.events.iter().enumerate() {
        if e["scan_id"].as_str().unwrap_or("") != scan_id {
            problems.push(format!("event {i} has a different scan_id"));
            break;
        }
        match (e["seq"].as_u64(), last_seq) {
            (Some(s), Some(prev)) if s <= prev => {
                problems.push(format!(
                    "seq is not strictly increasing at event {i}: {prev} -> {s}"
                ));
                last_seq = Some(s);
            }
            (Some(s), _) => last_seq = Some(s),
            (None, _) => problems.push(format!("event {i} has no seq")),
        }
    }

    // Exactly one terminal event, and it must be last.
    let terminal_positions: Vec<usize> = rec
        .events
        .iter()
        .enumerate()
        .filter(|(_, e)| TERMINALS.contains(&kind(e)))
        .map(|(i, _)| i)
        .collect();

    match terminal_positions.len() {
        0 => {
            problems
                .push("no terminal event — the scan did not finish writing (process died?)".into());
        }
        1 => {
            let pos = terminal_positions[0];
            if pos != rec.events.len() - 1 {
                problems.push(format!(
                    "{} events follow the terminal event",
                    rec.events.len() - 1 - pos
                ));
            }
            notes.push(format!("terminal: {}", kind(&rec.events[pos])));
        }
        n => problems.push(format!("{n} terminal events; exactly one is allowed")),
    }

    if rec.partial {
        problems.push(
            "file still has the .partial suffix, meaning the process never finalized it".into(),
        );
    }

    // Counts must reconcile with the rows actually present.
    let observed = rec
        .events
        .iter()
        .filter(|e| kind(e) == "probe_result")
        .count() as u64;
    if let Some(term) = terminal_positions.first().map(|&i| &rec.events[i])
        && let Some(completed) = term["counts"]["completed"].as_u64()
    {
        if completed != observed {
            problems.push(format!(
                "terminal event claims {completed} completed probes but {observed} probe_result \
                 events are present"
            ));
        }
        let parts = ["open", "closed", "filtered", "error"]
            .iter()
            .filter_map(|k| term["counts"][k].as_u64())
            .sum::<u64>();
        if parts != completed {
            problems.push(format!(
                "state counts sum to {parts} but completed is {completed}"
            ));
        }
        // Every planned probe must land in exactly one bucket.
        if let (Some(planned), Some(not_started)) = (
            term["counts"]["planned"].as_u64(),
            term["counts"]["not_started"].as_u64(),
        ) {
            let abandoned = term["counts"]["abandoned"].as_u64().unwrap_or(0);
            if planned != completed + abandoned + not_started {
                problems.push(format!(
                    "planned ({planned}) != completed ({completed}) + abandoned \
                     ({abandoned}) + not_started ({not_started})"
                ));
            }
        }
    }

    // Credentials must never appear.
    for (i, e) in rec.events.iter().enumerate() {
        if let Some(found) = find_exposed_secret(e) {
            problems.push(format!(
                "event {i} may contain an unredacted credential at `{found}`"
            ));
        }
    }

    notes.push(format!("{} probe results", commas(observed)));
    if rec.raw_lines != rec.events.len() {
        notes.push(format!("{} unparseable lines", rec.bad_lines.len()));
    }

    Ok(VerifyReport {
        file: path.display().to_string(),
        events: rec.events.len(),
        problems,
        notes,
    })
}

/// Walk a JSON value looking for a credential-shaped key with a real value.
fn find_exposed_secret(v: &Value) -> Option<String> {
    fn walk(v: &Value, path: &str) -> Option<String> {
        match v {
            Value::Object(map) => {
                for (k, val) in map {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    let sensitive = k == "password" || k == "secret" || k.ends_with("_password");
                    if sensitive {
                        match val {
                            Value::Null => {}
                            Value::String(s) if s == "[redacted]" => {}
                            _ => return Some(p),
                        }
                    }
                    if let Some(found) = walk(val, &p) {
                        return Some(found);
                    }
                }
                None
            }
            Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(i, item)| walk(item, &format!("{path}[{i}]"))),
            _ => None,
        }
    }
    walk(v, "")
}

pub fn summarize(path: &Path) -> Result<String, String> {
    let rec = read(path)?;
    if rec.events.is_empty() {
        return Err(format!("{} contains no events", path.display()));
    }
    let start = &rec.events[0];
    let config = rec.events.iter().find(|e| kind(e) == "scan_config");
    let terminal = rec.events.iter().find(|e| TERMINALS.contains(&kind(e)));

    let mut s = String::new();
    let _ = writeln!(s, "{}", path.display());
    let _ = writeln!(
        s,
        "  {:<16}{}",
        "scan",
        config
            .and_then(|c| c["scan_name"].as_str())
            .unwrap_or("(unknown)")
    );
    let _ = writeln!(
        s,
        "  {:<16}{}  (scanr {})",
        "started",
        start["ts"].as_str().unwrap_or("?"),
        start["tool_version"].as_str().unwrap_or("?")
    );
    if let Some(c) = config {
        let _ = writeln!(
            s,
            "  {:<16}{} via {} ({})",
            "transport",
            c["transport"]["name"].as_str().unwrap_or("?"),
            c["transport"]["type"].as_str().unwrap_or("?"),
            c["transport"]["measured_fidelity"].as_str().unwrap_or("?")
        );
        let _ = writeln!(
            s,
            "  {:<16}{} targets x {} ports = {} probes",
            "scope",
            commas(c["targets"]["count"].as_u64().unwrap_or(0)),
            commas(c["ports"]["count"].as_u64().unwrap_or(0)),
            commas(c["probes_planned"].as_u64().unwrap_or(0))
        );
        let _ = writeln!(
            s,
            "  {:<16}{}",
            "seed",
            c["permutation"]["seed"].as_str().unwrap_or("?")
        );
    }

    match terminal {
        None => {
            let _ = writeln!(s, "  {:<16}INCOMPLETE — no terminal event", "result");
        }
        Some(t) => {
            let c = &t["counts"];
            let _ = writeln!(
                s,
                "  {:<16}{} ({})",
                "result",
                kind(t),
                t["termination"].as_str().unwrap_or("?")
            );
            let _ = writeln!(
                s,
                "  {:<16}{}",
                "duration",
                HumanElapsed(std::time::Duration::from_millis(
                    t["duration_ms"].as_u64().unwrap_or(0)
                ))
            );
            let _ = writeln!(
                s,
                "  {:<16}{} open, {} closed, {} filtered, {} error",
                "states",
                c["open"].as_u64().unwrap_or(0),
                c["closed"].as_u64().unwrap_or(0),
                c["filtered"].as_u64().unwrap_or(0),
                c["error"].as_u64().unwrap_or(0)
            );
            if c["not_started"].as_u64().unwrap_or(0) > 0 {
                let _ = writeln!(
                    s,
                    "  {:<16}{} probes never started",
                    "incomplete",
                    commas(c["not_started"].as_u64().unwrap_or(0))
                );
            }
        }
    }

    let open: Vec<&Value> = rec
        .events
        .iter()
        .filter(|e| kind(e) == "probe_result" && e["state"] == "open")
        .collect();
    if !open.is_empty() {
        let _ = writeln!(s, "\nopen ports:");
        let mut lines: Vec<String> = open
            .iter()
            .map(|e| {
                format!(
                    "  {}:{}/tcp  {}",
                    e["target"].as_str().unwrap_or("?"),
                    e["port"].as_u64().unwrap_or(0),
                    e["service_label"].as_str().unwrap_or("")
                )
                .trim_end()
                .to_string()
            })
            .collect();
        lines.sort();
        for l in lines {
            let _ = writeln!(s, "{l}");
        }
    }
    Ok(s)
}

/// Endpoints that were not probed, suitable for `scanr run --pairs -`.
///
/// This is what replaces a `resume` feature (D12). It used to emit whole targets, which
/// re-probed ports that had already completed — a weakness that undermined the argument
/// for dropping resume in the first place. The record contains every probed pair, so the
/// exact remainder was always derivable; only a way to express it was missing.
pub fn remainder(path: &Path) -> Result<(Vec<String>, String), String> {
    let rec = read(path)?;
    let config = rec
        .events
        .iter()
        .find(|e| kind(e) == "scan_config")
        .ok_or_else(|| format!("{} has no scan_config event", path.display()))?;

    // Every endpoint the scan intended to probe.
    let expected: Vec<(String, u16)> = if config["targets"]["mode"] == "pairs" {
        if config["targets"]["pairs_truncated"] == true {
            return Err(format!(
                "{} recorded too many explicit pairs to embed, so its remainder cannot be \
                 derived from the record alone",
                path.display()
            ));
        }
        let pairs = config["targets"]["pairs"]
            .as_array()
            .ok_or("pair-mode record has no embedded pair list")?;
        let mut out = Vec::with_capacity(pairs.len());
        for v in pairs {
            let line = v.as_str().ok_or("malformed embedded pair")?;
            let (spec, port) =
                parse_pair(line).map_err(|e| format!("recorded pair `{line}` is invalid: {e}"))?;
            out.push((spec.to_string(), port));
        }
        out
    } else {
        let specs: Vec<String> = config["targets"]["spec"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let excludes: Vec<String> = config["targets"]["exclude"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let port_spec = config["ports"]["spec"].as_str().unwrap_or("");
        let ports =
            parse_ports(port_spec).map_err(|e| format!("recorded port spec is invalid: {e}"))?;

        let mut set = TargetSet::default();
        for s in &specs {
            if s.starts_with("file:") {
                return Err(format!(
                    "this scan's targets came from {s}, which is not reproducible from the \
                     record alone; re-run with the same file"
                ));
            }
            set.include.push(
                parse_target(s).map_err(|e| format!("recorded target spec is invalid: {e}"))?,
            );
        }
        for s in &excludes {
            set.exclude.push(
                parse_target(s).map_err(|e| format!("recorded exclude spec is invalid: {e}"))?,
            );
        }
        let targets = set
            .expand(true, u64::MAX)
            .map_err(|e| format!("cannot re-expand targets: {e}"))?;

        let mut out = Vec::with_capacity(targets.len() * ports.len());
        for t in &targets {
            for p in &ports {
                out.push((t.to_string(), *p));
            }
        }
        out
    };

    // Exactly what was reported, pair by pair.
    let mut probed: BTreeSet<(String, u16)> = BTreeSet::new();
    for e in rec.events.iter().filter(|e| kind(e) == "probe_result") {
        if let (Some(t), Some(p)) = (e["target"].as_str(), e["port"].as_u64()) {
            probed.insert((t.to_string(), p as u16));
        }
    }

    let remaining: Vec<String> = expected
        .iter()
        .filter(|pair| !probed.contains(*pair))
        .map(|(t, p)| format_pair(t, *p))
        .collect();

    let note = format!(
        "{} of {} endpoints were not probed; re-run exactly those with:\n  \
         scanr output remainder {} | scanr run --pairs -",
        commas(remaining.len() as u64),
        commas(expected.len() as u64),
        path.display()
    );
    Ok((remaining, note))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write(dir: &Path, name: &str, events: &[Value]) -> std::path::PathBuf {
        let p = dir.join(name);
        let body: String = events
            .iter()
            .map(|e| format!("{e}\n"))
            .collect::<Vec<_>>()
            .concat();
        std::fs::write(&p, body).unwrap();
        p
    }

    fn good_events() -> Vec<Value> {
        vec![
            json!({"type":"scan_started","seq":0,"ts":"t","scan_id":"a1","schema_version":1,"tool_version":"0.1.0"}),
            json!({"type":"scan_config","seq":1,"ts":"t","scan_id":"a1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/30"],"exclude":[],"count":4},
                   "ports":{"spec":"80","count":1},"probes_planned":4,
                   "permutation":{"seed":"00000000000000ff"},
                   "transport":{"name":"direct","type":"direct","measured_fidelity":"full","password":null}}),
            json!({"type":"probe_result","seq":2,"ts":"t","scan_id":"a1","target":"10.0.0.0","port":80,"state":"open","service_label":"http"}),
            json!({"type":"probe_result","seq":3,"ts":"t","scan_id":"a1","target":"10.0.0.1","port":80,"state":"closed"}),
            json!({"type":"probe_result","seq":4,"ts":"t","scan_id":"a1","target":"10.0.0.2","port":80,"state":"filtered"}),
            json!({"type":"probe_result","seq":5,"ts":"t","scan_id":"a1","target":"10.0.0.3","port":80,"state":"error"}),
            json!({"type":"scan_completed","seq":6,"ts":"t","scan_id":"a1","termination":"natural",
                   "duration_ms":1234,
                   "counts":{"planned":4,"started":4,"completed":4,"not_started":0,
                             "open":1,"closed":1,"filtered":1,"error":1,"retried":0}}),
        ]
    }

    #[test]
    fn accepts_a_well_formed_record() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "ok.jsonl", &good_events());
        let r = verify(&p).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(r.render().contains("ok — record is complete"));
    }

    #[test]
    fn detects_a_missing_terminal_event() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.pop();
        let p = write(d.path(), "trunc.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("no terminal event")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_events_after_the_terminal() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.push(json!({"type":"probe_result","seq":7,"scan_id":"a1","target":"x","port":1,"state":"open"}));
        let p = write(d.path(), "after.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|x| x.contains("follow the terminal event")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_two_terminal_events() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.push(json!({"type":"scan_failed","seq":7,"scan_id":"a1","counts":{}}));
        let p = write(d.path(), "two.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("2 terminal events")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_non_monotonic_sequence() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[3]["seq"] = json!(2);
        let p = write(d.path(), "seq.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("strictly increasing")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_count_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[6]["counts"]["completed"] = json!(99);
        let p = write(d.path(), "counts.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("99 completed")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_inconsistent_state_totals() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[6]["counts"]["open"] = json!(5);
        let p = write(d.path(), "states.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("state counts sum")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_invalid_json_lines() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("bad.jsonl");
        std::fs::write(
            &p,
            "{\"type\":\"scan_started\",\"seq\":0,\"scan_id\":\"a\"}\nnot json\n",
        )
        .unwrap();
        let r = verify(&p).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|x| x.contains("line 2 is not valid JSON")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn detects_an_unredacted_credential() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[1]["transport"]["password"] = json!("hunter2");
        let p = write(d.path(), "leak.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|x| x.contains("unredacted credential")),
            "a leaked password must be caught: {:?}",
            r.problems
        );
    }

    #[test]
    fn redacted_and_null_passwords_are_accepted() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[1]["transport"]["password"] = json!("[redacted]");
        let p = write(d.path(), "ok2.jsonl", &e);
        assert!(verify(&p).unwrap().problems.is_empty());
    }

    #[test]
    fn flags_a_partial_file() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "x.jsonl.partial", &good_events());
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains(".partial suffix")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn summarize_lists_open_ports() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "s.jsonl", &good_events());
        let out = summarize(&p).unwrap();
        assert!(out.contains("open ports:"), "{out}");
        assert!(out.contains("10.0.0.0:80/tcp  http"), "{out}");
        assert!(
            out.contains("1 open, 1 closed, 1 filtered, 1 error"),
            "{out}"
        );
    }

    #[test]
    fn remainder_reports_unprobed_targets() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        // Drop two results and mark the scan interrupted.
        e.remove(5);
        e.remove(4);
        e[4] = json!({"type":"scan_interrupted","seq":6,"scan_id":"a1","termination":"signal",
                      "counts":{"planned":4,"started":4,"completed":2,"not_started":2,
                                "open":1,"closed":1,"filtered":0,"error":0,"retried":0}});
        let p = write(d.path(), "part.jsonl", &e);
        let (endpoints, note) = remainder(&p).unwrap();
        // Exact endpoints now, not whole targets: the port is part of the answer.
        assert_eq!(endpoints, ["10.0.0.2:80", "10.0.0.3:80"]);
        assert!(note.contains("2 of 4 endpoints"), "{note}");
        assert!(
            note.contains("--pairs -"),
            "the round trip must be shown: {note}"
        );
    }

    #[test]
    fn remainder_is_empty_for_a_complete_scan() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "full.jsonl", &good_events());
        let (targets, _) = remainder(&p).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn remainder_is_exact_when_a_target_is_only_partly_probed() {
        // The whole point of the change: a target with some ports done must yield only
        // the ports that are outstanding, not the target as a whole.
        let d = tempfile::tempdir().unwrap();
        let mut e = vec![
            json!({"type":"scan_started","seq":0,"scan_id":"a1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"scan_id":"a1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/31"],"exclude":[],"count":2,"mode":"matrix"},
                   "ports":{"spec":"80,443,8080","count":3},"probes_planned":6,
                   "transport":{"name":"direct","type":"direct","password":null}}),
        ];
        // 10.0.0.0 fully probed; 10.0.0.1 only port 80.
        let mut seq = 2;
        for (t, p) in [
            ("10.0.0.0", 80),
            ("10.0.0.0", 443),
            ("10.0.0.0", 8080),
            ("10.0.0.1", 80),
        ] {
            e.push(json!({"type":"probe_result","seq":seq,"scan_id":"a1",
                          "target":t,"port":p,"state":"closed"}));
            seq += 1;
        }
        e.push(json!({"type":"scan_interrupted","seq":seq,"scan_id":"a1",
                      "termination":"signal",
                      "counts":{"planned":6,"started":6,"completed":4,"abandoned":2,
                                "not_started":0,"open":0,"closed":4,"filtered":0,
                                "error":0,"retried":0}}));
        let p = write(d.path(), "partial.jsonl", &e);

        let (rem, _) = remainder(&p).unwrap();
        assert_eq!(
            rem,
            ["10.0.0.1:443", "10.0.0.1:8080"],
            "only the outstanding ports of a partly-probed target should remain"
        );
    }

    #[test]
    fn remainder_of_a_pair_scan_round_trips() {
        // A pair scan has no compact spec, so the record embeds the list. Its remainder
        // must still be derivable, or resuming twice would be impossible.
        let d = tempfile::tempdir().unwrap();
        let e = vec![
            json!({"type":"scan_started","seq":0,"scan_id":"b1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"scan_id":"b1","scan_name":"s",
                   "targets":{"spec":["3 explicit host:port pairs"],"exclude":[],"count":2,
                              "mode":"pairs","pairs_truncated":false,
                              "pairs":["10.0.0.1:443","10.0.0.1:8080","[::1]:22"]},
                   "ports":{"spec":"(explicit pairs)","count":3},"probes_planned":3,
                   "transport":{"name":"direct","type":"direct","password":null}}),
            json!({"type":"probe_result","seq":2,"scan_id":"b1","target":"10.0.0.1",
                   "port":443,"state":"closed"}),
            json!({"type":"scan_interrupted","seq":3,"scan_id":"b1","termination":"signal",
                   "counts":{"planned":3,"started":3,"completed":1,"abandoned":2,
                             "not_started":0,"open":0,"closed":1,"filtered":0,
                             "error":0,"retried":0}}),
        ];
        let p = write(d.path(), "pairs.jsonl", &e);
        let (rem, _) = remainder(&p).unwrap();
        // IPv6 stays bracketed so the output can be parsed back.
        assert_eq!(rem, ["10.0.0.1:8080", "[::1]:22"]);
    }

    #[test]
    fn remainder_refuses_a_pair_scan_that_was_too_large_to_embed() {
        let d = tempfile::tempdir().unwrap();
        let e = vec![
            json!({"type":"scan_started","seq":0,"scan_id":"c1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"scan_id":"c1","scan_name":"s",
                   "targets":{"spec":["999999 explicit host:port pairs"],"exclude":[],
                              "count":1,"mode":"pairs","pairs_truncated":true,"pairs":null},
                   "ports":{"spec":"(explicit pairs)","count":1},"probes_planned":999999,
                   "transport":{"name":"direct","type":"direct","password":null}}),
            json!({"type":"scan_completed","seq":2,"scan_id":"c1","termination":"natural",
                   "counts":{"planned":0,"started":0,"completed":0,"abandoned":0,
                             "not_started":0,"open":0,"closed":0,"filtered":0,
                             "error":0,"retried":0}}),
        ];
        let p = write(d.path(), "big.jsonl", &e);
        let err = remainder(&p).unwrap_err();
        assert!(err.contains("too many explicit pairs"), "{err}");
    }

    #[test]
    fn remainder_refuses_file_sourced_targets() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[1]["targets"]["spec"] = json!(["file:hosts.txt"]);
        let p = write(d.path(), "f.jsonl", &e);
        let err = remainder(&p).unwrap_err();
        assert!(err.contains("not reproducible from the record"), "{err}");
    }

    #[test]
    fn empty_file_is_reported_not_panicked_on() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("empty.jsonl");
        std::fs::write(&p, "").unwrap();
        let r = verify(&p).unwrap();
        assert!(r.problems.iter().any(|x| x.contains("no events")));
        assert!(summarize(&p).is_err());
    }

    #[test]
    fn missing_file_is_a_clean_error() {
        let e = verify(Path::new("/nonexistent/x.jsonl")).unwrap_err();
        assert!(e.contains("cannot read"));
    }
}
