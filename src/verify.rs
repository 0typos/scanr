//! Reading scan records back: summarize, verify, and remainder.
//!
//! `remainder` is what replaces a `resume` feature (D12). The set of probes that never
//! ran is just a target list, so emitting it and piping it back gives resume-by-
//! composition without committing the schema to anything.
//!
//! Everything here streams. Records are large by design — the tuning guide's headline
//! workload writes 374 MB while the scan holds 11 MB resident — and holding one in a
//! `Vec<Value>` cost about 11x the file size, so reading that record back took 4.2 GB.
//! The commands for inspecting a big scan were the ones a big scan broke.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use crate::net::target::{TargetSet, format_pair, parse_pair};
use crate::net::{Target, parse_ports, parse_target};
use crate::units::{HumanElapsed, commas};

/// One line of a record, as streamed.
struct RecordLine {
    /// 1-based line number in the file, for pointing at unparseable input.
    line_no: usize,
    /// 0-based position among the events that parsed. Blank and bad lines do not
    /// consume one, so this matches the numbering a reader sees in the record.
    index: usize,
    /// `None` when the line could not be read or parsed as JSON.
    event: Option<Value>,
}

/// Open a record, transparently decompressing a gzip one.
///
/// Detected by magic bytes rather than by extension, so a renamed file still reads and a
/// `.gz` name that is not gzip does not silently produce nonsense.
fn open_record(path: &Path) -> Result<Box<dyn BufRead>, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut magic = [0u8; 2];
    let n = file
        .read(&mut magic)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    file.rewind()
        .or_else(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if n == 2 && magic == [0x1f, 0x8b] {
        // MultiGzDecoder, not GzDecoder: the writer emits one member per frame and a
        // single-member decoder would stop after the first.
        Ok(Box::new(BufReader::new(flate2::read::MultiGzDecoder::new(
            file,
        ))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

/// Iterate a record's events, parsing one line at a time and retaining none.
///
/// A read failure — most often invalid UTF-8 — rejects the whole file rather than
/// becoming a skipped line. Reading it as a bad line would be worse than it sounds:
/// `remainder` would then emit a confident endpoint list derived from a file it could
/// not fully read, and exit 0 doing it. This matches what loading the whole file into a
/// `String` did before.
///
/// The exception is a `.partial` file, which by definition the process never finished
/// writing. There a stream that stops mid-way is the expected shape, and refusing it
/// would defeat framing: the point of writing gzip in frames is that a killed scan still
/// decodes up to its last completed frame.
fn stream(path: &Path) -> Result<impl Iterator<Item = Result<RecordLine, String>>, String> {
    let mut lines = open_record(path)?.lines().enumerate();
    let shown = path.display().to_string();
    let truncation_expected = is_partial(path);
    let mut index = 0usize;
    let mut finished = false;

    Ok(std::iter::from_fn(move || {
        if finished {
            return None;
        }
        loop {
            let (i, line) = lines.next()?;
            match line {
                Ok(text) => {
                    if text.trim().is_empty() {
                        continue;
                    }
                    let event = serde_json::from_str::<Value>(&text).ok();
                    let this = index;
                    if event.is_some() {
                        index += 1;
                    }
                    return Some(Ok(RecordLine {
                        line_no: i + 1,
                        index: this,
                        event,
                    }));
                }
                Err(e) => {
                    // Stop either way. A reader that has failed once keeps failing, and
                    // polling it forever would hang instead of reporting.
                    finished = true;
                    let cut_short = matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData
                    );
                    // `index > 0` so a file that is unreadable from the very first byte
                    // is still an error rather than an empty success.
                    if truncation_expected && cut_short && index > 0 {
                        return None;
                    }
                    return Some(Err(format!("cannot read {shown}: {e}")));
                }
            }
        }
    }))
}

/// A file still named `.partial` means the process died before finalizing it.
fn is_partial(path: &Path) -> bool {
    path.to_string_lossy().ends_with(".partial")
}

/// How much of the file's tail to read when looking for the terminal event.
///
/// The terminal event is the last line by construction, so this only has to be larger
/// than one event. Generous, and still nothing next to the record.
const TAIL_BYTES: u64 = 64 * 1024;

/// The last event in the file, read from the end rather than by scanning forward.
///
/// Returns `None` for anything unexpected — a short file, a truncated last line, an
/// unreadable tail. Every caller treats that as "no hint available" and falls back.
fn read_last_event(path: &Path) -> Option<Value> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path).ok()?;
    {
        // A gzip record cannot be seeked into, so its last line is found by decoding
        // through. That is still far cheaper than parsing every event as JSON.
        let mut magic = [0u8; 2];
        if f.read(&mut magic).ok()? == 2 && magic == [0x1f, 0x8b] {
            let mut last = None;
            for line in open_record(path).ok()?.lines() {
                let line = line.ok()?;
                if !line.trim().is_empty() {
                    last = Some(line);
                }
            }
            return serde_json::from_str(&last?).ok();
        }
        f.rewind().ok()?;
    }
    let len = f.metadata().ok()?.len();
    let take = len.min(TAIL_BYTES);
    f.seek(SeekFrom::Start(len - take)).ok()?;
    let mut buf = Vec::with_capacity(take as usize);
    f.take(take).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    // If the window started mid-line, the first fragment is discarded by taking the
    // last complete line rather than the first.
    let last = text.lines().rev().find(|l| !l.trim().is_empty())?;
    serde_json::from_str(last).ok()
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

/// Check a record against every rule the specification states.
///
/// One pass, retaining only what a later rule needs: counts, the last `seq`, and a few
/// small fields lifted out of `scan_config` and the terminal event.
pub fn verify(path: &Path) -> Result<VerifyReport, String> {
    let mut v = Verifier::default();
    for line in stream(path)? {
        v.observe(line?);
    }
    Ok(v.finish(path))
}

/// Single-pass state for `verify`.
///
/// Problems are grouped by rule family and concatenated at the end, so the report reads
/// in the order it did when each rule got its own pass over a fully loaded record.
#[derive(Default)]
struct Verifier {
    events: usize,
    last_index: usize,
    observed_probes: u64,
    bad_lines: Vec<usize>,

    first_kind: Option<String>,
    second_kind: Option<String>,
    scan_id: Option<String>,
    schema_version: Option<u64>,

    last_seq: Option<u64>,
    /// The whole-record scan-id and sequence walk stopped at the first id mismatch, and
    /// still does: past that point the file is a different scan and later `seq` values
    /// say nothing.
    sequence_done: bool,
    sequence_problems: Vec<String>,

    terminals: usize,
    first_terminal: Option<(usize, String)>,
    terminal_counts: Option<Value>,

    saw_config: bool,
    planned: Option<u64>,
    /// Probes represented by `probe_span` events rather than by their own row.
    span_probes: u64,
    spans: u64,
    resumed_from: Option<String>,

    credential_problems: Vec<String>,
    values: ValueProblems,
}

impl Verifier {
    fn observe(&mut self, line: RecordLine) {
        let Some(e) = line.event else {
            self.bad_lines.push(line.line_no);
            return;
        };
        let i = line.index;
        self.events += 1;
        self.last_index = i;
        let k = kind(&e);

        if i == 0 {
            self.first_kind = Some(k.to_string());
            self.scan_id = Some(e["scan_id"].as_str().unwrap_or("").to_string());
            self.schema_version = e["schema_version"].as_u64();
        } else if i == 1 {
            self.second_kind = Some(k.to_string());
        }

        self.check_identity(&e, i);

        if TERMINALS.contains(&k) {
            self.terminals += 1;
            if self.first_terminal.is_none() {
                self.first_terminal = Some((i, k.to_string()));
                self.terminal_counts = Some(e["counts"].clone());
            }
        }

        // `probes_planned` is read from the first `scan_config`, which the ordering rule
        // puts at index 1 — so it is always known before any probe row arrives.
        if k == "scan_config" && !self.saw_config {
            self.saw_config = true;
            self.planned = e["probes_planned"].as_u64();
            self.resumed_from = e["resumed_from"].as_str().map(str::to_string);
        }
        if k == "probe_result" {
            self.observed_probes += 1;
        }
        if k == "probe_span" {
            self.spans += 1;
            self.span_probes += e["count"].as_u64().unwrap_or(0);
        }

        if let Some(found) = find_exposed_secret(&e) {
            self.credential_problems.push(format!(
                "event {i} may contain an unredacted credential at `{found}`"
            ));
        }

        self.check_values(&e, i);
    }

    /// One scan id throughout, and `seq` strictly increasing.
    fn check_identity(&mut self, e: &Value, i: usize) {
        if self.sequence_done {
            return;
        }
        if e["scan_id"].as_str().unwrap_or("") != self.scan_id.as_deref().unwrap_or("") {
            self.sequence_problems
                .push(format!("event {i} has a different scan_id"));
            self.sequence_done = true;
            return;
        }
        match (e["seq"].as_u64(), self.last_seq) {
            (Some(s), Some(prev)) if s <= prev => {
                self.sequence_problems.push(format!(
                    "seq is not strictly increasing at event {i}: {prev} -> {s}"
                ));
                self.last_seq = Some(s);
            }
            (Some(s), _) => self.last_seq = Some(s),
            (None, _) => self.sequence_problems.push(format!("event {i} has no seq")),
        }
    }

    /// Validate the *values* in an event, not just the shape of the record.
    ///
    /// `verify` originally checked structure alone — ordering, `seq`, count
    /// reconciliation, terminal uniqueness, credentials. A row carrying
    /// `"port": 65616` or `"state": "banana"` passed as "complete and internally
    /// consistent", and `remainder` then truncated that port and silently dropped a real
    /// endpoint from the resume set. Structure being right is not the same as the record
    /// being true.
    fn check_values(&mut self, e: &Value, i: usize) {
        match e["ts"].as_str() {
            None => self.values.note("have no `ts`", i, kind(e)),
            Some(ts) if !crate::timefmt::is_rfc3339_ms(ts) => {
                self.values.note("have a `ts` that is not RFC 3339", i, ts);
            }
            Some(_) => {}
        }
        match kind(e) {
            "probe_result" => check_probe_row(e, i, self.planned, &mut self.values),
            "probe_span" => check_span_row(e, i, self.planned, &mut self.values),
            _ => {}
        }
    }

    fn finish(self, path: &Path) -> VerifyReport {
        let mut problems = Vec::new();
        let mut notes = Vec::new();

        for line in &self.bad_lines {
            problems.push(format!("line {line} is not valid JSON"));
        }
        if self.events == 0 {
            problems.push("file contains no events".into());
            return VerifyReport {
                file: path.display().to_string(),
                events: 0,
                problems,
                notes,
            };
        }

        self.report_header(&mut problems);
        problems.extend(self.sequence_problems.iter().cloned());
        self.report_terminal(&mut problems, &mut notes);

        if is_partial(path) {
            problems.push(
                "file still has the .partial suffix, meaning the process never finalized it".into(),
            );
        }

        self.report_counts(&mut problems);
        problems.extend(self.credential_problems.iter().cloned());
        self.values.drain_into(&mut problems);

        if let Some(parent) = &self.resumed_from {
            notes.push(format!("resumed from scan {parent}"));
        }
        notes.push(format!("{} probe results", commas(self.observed_probes)));
        if self.spans > 0 {
            notes.push(format!(
                "{} further probes collapsed into {} span(s)",
                commas(self.span_probes),
                commas(self.spans)
            ));
        }
        if !self.bad_lines.is_empty() {
            notes.push(format!("{} unparseable lines", self.bad_lines.len()));
        }

        VerifyReport {
            file: path.display().to_string(),
            events: self.events,
            problems,
            notes,
        }
    }

    /// `scan_started` first, `scan_config` second, and a schema this build understands.
    fn report_header(&self, problems: &mut Vec<String>) {
        if self.first_kind.as_deref() != Some("scan_started") {
            problems.push(format!(
                "first event is `{}`, expected `scan_started`",
                self.first_kind.as_deref().unwrap_or("")
            ));
        }
        if self.events > 1 && self.second_kind.as_deref() != Some("scan_config") {
            problems.push(format!(
                "second event is `{}`, expected `scan_config`",
                self.second_kind.as_deref().unwrap_or("")
            ));
        }
        if let Some(v) = self.schema_version
            && v != crate::output::SCHEMA_VERSION as u64
        {
            problems.push(format!(
                "schema_version {v} is not supported by this build ({})",
                crate::output::SCHEMA_VERSION
            ));
        }
    }

    /// Exactly one terminal event, and it must be last.
    fn report_terminal(&self, problems: &mut Vec<String>, notes: &mut Vec<String>) {
        match self.terminals {
            0 => problems
                .push("no terminal event — the scan did not finish writing (process died?)".into()),
            1 => {
                let (pos, k) = self.first_terminal.as_ref().expect("counted one");
                if *pos != self.last_index {
                    problems.push(format!(
                        "{} events follow the terminal event",
                        self.last_index - pos
                    ));
                }
                notes.push(format!("terminal: {k}"));
            }
            n => problems.push(format!("{n} terminal events; exactly one is allowed")),
        }
    }

    /// The terminal counts must reconcile with the rows actually present, and every
    /// planned probe must land in exactly one of the three buckets.
    fn report_counts(&self, problems: &mut Vec<String>) {
        let Some(counts) = &self.terminal_counts else {
            return;
        };
        let Some(completed) = counts["completed"].as_u64() else {
            return;
        };
        // A collapsed probe is still a completed probe; it is just recorded once per
        // outcome class rather than once per probe.
        let observed = self.observed_probes + self.span_probes;
        if completed != observed {
            let detail = if self.spans > 0 {
                format!(
                    "{} probe_result events plus {} probes across {} probe_span events",
                    commas(self.observed_probes),
                    commas(self.span_probes),
                    commas(self.spans)
                )
            } else {
                format!("{} probe_result events are", commas(self.observed_probes))
            };
            problems.push(format!(
                "terminal event claims {completed} completed probes but {detail} present"
            ));
        }
        let parts = ["open", "closed", "filtered", "error"]
            .iter()
            .filter_map(|k| counts[k].as_u64())
            .sum::<u64>();
        if parts != completed {
            problems.push(format!(
                "state counts sum to {parts} but completed is {completed}"
            ));
        }
        if let (Some(planned), Some(not_started)) =
            (counts["planned"].as_u64(), counts["not_started"].as_u64())
        {
            let abandoned = counts["abandoned"].as_u64().unwrap_or(0);
            if planned != completed + abandoned + not_started {
                problems.push(format!(
                    "planned ({planned}) != completed ({completed}) + abandoned \
                     ({abandoned}) + not_started ({not_started})"
                ));
            }
        }
    }
}

/// A systematically corrupt record — every row carrying the same defect — would
/// otherwise emit one problem line per probe, which for a million-probe record is
/// worse than useless.
#[derive(Default)]
struct ValueProblems {
    /// kind -> (occurrences, first event index, first offending value)
    seen: std::collections::BTreeMap<&'static str, (u64, usize, String)>,
}

impl ValueProblems {
    fn note(&mut self, kind: &'static str, index: usize, value: impl std::fmt::Display) {
        self.seen
            .entry(kind)
            .and_modify(|e| e.0 += 1)
            .or_insert_with(|| (1, index, value.to_string()));
    }

    fn drain_into(self, problems: &mut Vec<String>) {
        for (kind, (n, index, example)) in self.seen {
            problems.push(format!(
                "{} event(s) {kind} — first at event {index}: {example}",
                commas(n)
            ));
        }
    }
}

/// The defined values of `state` and `source`, taken from the enums so the two cannot
/// drift apart.
fn defined_states() -> Vec<&'static str> {
    use crate::probe::State;
    [State::Open, State::Closed, State::Filtered, State::Error]
        .iter()
        .map(State::as_str)
        .collect()
}

fn defined_sources() -> Vec<&'static str> {
    use crate::probe::Source;
    [
        Source::LocalStack,
        Source::ProxyReply,
        Source::Timeout,
        Source::Internal,
    ]
    .iter()
    .map(Source::as_str)
    .collect()
}

fn check_probe_row(e: &Value, i: usize, planned: Option<u64>, found: &mut ValueProblems) {
    let states = defined_states();
    let sources = defined_sources();

    match e["port"].as_u64() {
        None => found.note("have a missing or non-numeric `port`", i, &e["port"]),
        Some(p) if p == 0 || p > u64::from(u16::MAX) => {
            found.note("have a `port` outside 1-65535", i, p);
        }
        Some(_) => {}
    }

    match e["state"].as_str() {
        Some(s) if states.contains(&s) => {}
        other => found.note(
            "have an unrecognised `state`",
            i,
            other.unwrap_or("(absent)"),
        ),
    }
    match e["source"].as_str() {
        Some(s) if sources.contains(&s) => {}
        other => found.note(
            "have an unrecognised `source`",
            i,
            other.unwrap_or("(absent)"),
        ),
    }
    if e["protocol"].as_str() != Some("tcp") {
        found.note("have a `protocol` other than `tcp`", i, &e["protocol"]);
    }

    // Retries are merged into one row (D10), so attempts is at least the one probe that
    // produced it, and attempt_states holds exactly that many entries.
    match e["attempts"].as_u64() {
        None => found.note(
            "have a missing or non-numeric `attempts`",
            i,
            &e["attempts"],
        ),
        Some(0) => found.note("have `attempts` of 0", i, 0),
        Some(n) => {
            if let Some(a) = e["attempt_states"].as_array()
                && a.len() as u64 != n
            {
                found.note(
                    "have an `attempt_states` length that disagrees with `attempts`",
                    i,
                    format!("attempts {n}, {} states", a.len()),
                );
            }
        }
    }
    if let Some(a) = e["attempt_states"].as_array()
        && let Some(bad) = a
            .iter()
            .find(|s| !s.as_str().is_some_and(|s| states.contains(&s)))
    {
        found.note("have an unrecognised entry in `attempt_states`", i, bad);
    }

    // probe_index addresses a slot in the planned matrix, so it cannot name one outside
    // it.
    if let (Some(idx), Some(planned)) = (e["probe_index"].as_u64(), planned)
        && idx >= planned
    {
        found.note(
            "have a `probe_index` at or beyond `probes_planned`",
            i,
            format!("{idx} >= {planned}"),
        );
    }

    check_timings(e, i, found);
}

/// A span stands for many probes, so a malformed one silently misrepresents all of
/// them. Its ranges must be ordered, disjoint, inside the plan, and add up to its count.
fn check_span_row(e: &Value, i: usize, planned: Option<u64>, found: &mut ValueProblems) {
    let states = defined_states();
    let sources = defined_sources();

    match e["state"].as_str() {
        Some(s) if states.contains(&s) => {}
        other => found.note(
            "have an unrecognised `state`",
            i,
            other.unwrap_or("(absent)"),
        ),
    }
    match e["source"].as_str() {
        Some(s) if sources.contains(&s) => {}
        other => found.note(
            "have an unrecognised `source`",
            i,
            other.unwrap_or("(absent)"),
        ),
    }

    let Some(count) = e["count"].as_u64() else {
        found.note("have a missing or non-numeric span `count`", i, &e["count"]);
        return;
    };
    if count == 0 {
        found.note("are a span covering no probes", i, 0);
    }

    let Some(ranges) = e["probe_indices"].as_array() else {
        found.note(
            "have a missing or malformed `probe_indices`",
            i,
            &e["probe_indices"],
        );
        return;
    };

    let mut covered: u64 = 0;
    let mut previous_end: Option<u64> = None;
    for r in ranges {
        let (Some(start), Some(end)) = (r[0].as_u64(), r[1].as_u64()) else {
            found.note("have a malformed range in `probe_indices`", i, r);
            return;
        };
        if start > end {
            found.note("have a reversed range in `probe_indices`", i, r);
            return;
        }
        if let Some(p) = previous_end
            && start <= p
        {
            found.note("have overlapping or unsorted `probe_indices`", i, r);
            return;
        }
        if let Some(planned) = planned
            && end >= planned
        {
            found.note(
                "have a `probe_indices` range beyond `probes_planned`",
                i,
                format!("{end} >= {planned}"),
            );
            return;
        }
        previous_end = Some(end);
        covered += end - start + 1;
    }
    if covered != count {
        found.note(
            "have a span `count` that disagrees with its ranges",
            i,
            format!("count {count}, ranges cover {covered}"),
        );
    }

    if let Some(t) = e["timing_ms"].as_object() {
        let g = |k: &str| t.get(k).and_then(Value::as_f64);
        if let (Some(lo), Some(mean), Some(hi)) = (g("min"), g("mean"), g("max"))
            && !(lo <= mean && mean <= hi && lo >= 0.0)
        {
            found.note(
                "have span timings that are not min <= mean <= max",
                i,
                format!("{lo}/{mean}/{hi}"),
            );
        }
    } else {
        found.note("have a missing span `timing_ms`", i, &e["timing_ms"]);
    }
}

fn check_timings(e: &Value, i: usize, found: &mut ValueProblems) {
    let Some(timing) = e["timing_ms"].as_object() else {
        found.note(
            "have a missing or malformed `timing_ms`",
            i,
            &e["timing_ms"],
        );
        return;
    };
    for (phase, v) in timing {
        match v.as_f64() {
            None => found.note("have a non-numeric timing", i, format!("{phase}={v}")),
            Some(ms) if ms < 0.0 || !ms.is_finite() => {
                found.note("have an impossible timing", i, format!("{phase}={ms}"));
            }
            Some(_) => {}
        }
    }
    if !timing.contains_key("total") {
        found.note("have no `timing_ms.total`", i, kind(e));
    }
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
    // Retains the header, the config, the terminal event, and one formatted line per
    // *open* port. Everything else is dropped as it goes by: the closed and filtered
    // rows are the bulk of a large record and none of them are printed.
    let mut start: Option<Value> = None;
    let mut config: Option<Value> = None;
    let mut terminal: Option<Value> = None;
    let mut open: Vec<String> = Vec::new();

    for line in stream(path)? {
        let line = line?;
        let Some(e) = line.event else { continue };
        if line.index == 0 {
            start = Some(e.clone());
        }
        let k = kind(&e);
        if k == "scan_config" && config.is_none() {
            config = Some(e.clone());
        }
        if TERMINALS.contains(&k) && terminal.is_none() {
            terminal = Some(e.clone());
        }
        if k == "probe_result" && e["state"] == "open" {
            open.push(
                format!(
                    "  {}:{}/tcp  {}",
                    e["target"].as_str().unwrap_or("?"),
                    e["port"].as_u64().unwrap_or(0),
                    e["service_label"].as_str().unwrap_or("")
                )
                .trim_end()
                .to_string(),
            );
        }
    }

    let Some(start) = start else {
        return Err(format!("{} contains no events", path.display()));
    };

    let mut s = String::new();
    let _ = writeln!(s, "{}", path.display());
    let _ = writeln!(
        s,
        "  {:<16}{}",
        "scan",
        config
            .as_ref()
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
    if let Some(c) = &config {
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

    match &terminal {
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

    if !open.is_empty() {
        let _ = writeln!(s, "\nopen ports:");
        open.sort();
        for l in open {
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
pub fn remainder(path: &Path) -> Result<Remainder, String> {
    // Fast path: the scan already knew what it had not done, so ask it rather than
    // re-deriving the answer from a million probe rows.
    if let Some(r) = remainder_from_hint(path)? {
        return Ok(r);
    }
    remainder_by_scanning(path)
}

/// Reconstruct the outstanding endpoints from the terminal event alone.
///
/// The work counter issues indices in order, so everything never started is the
/// contiguous range `[not_started_from, planned)`, and the only scattered part is the
/// handful of probes that were in flight when the scan stopped. With the seed from
/// `scan_config` that reproduces the outstanding endpoints exactly, reading two events
/// instead of the whole record.
///
/// Returns `Ok(None)` whenever the hint is absent or does not agree with the counts —
/// an older record, a scan too large to have tracked it, or a file whose terminal event
/// cannot be trusted. The caller then does it the long way.
fn remainder_from_hint(path: &Path) -> Result<Option<Remainder>, String> {
    let Some(terminal) = read_last_event(path).filter(|e| TERMINALS.contains(&kind(e))) else {
        return Ok(None);
    };
    let (Some(from), Some(abandoned)) = (
        terminal["not_started_from"].as_u64(),
        terminal["abandoned_indices"].as_array(),
    ) else {
        return Ok(None);
    };
    let counts = &terminal["counts"];
    let (Some(planned), Some(not_started), Some(completed)) = (
        counts["planned"].as_u64(),
        counts["not_started"].as_u64(),
        counts["completed"].as_u64(),
    ) else {
        return Ok(None);
    };
    // The hint has to agree with the accounting, or it is not a hint worth taking.
    if planned.saturating_sub(from) != not_started
        || abandoned.len() as u64 != counts["abandoned"].as_u64().unwrap_or(u64::MAX)
    {
        return Ok(None);
    }
    // And the accounting has to agree with the file.
    //
    // The hint records what the *scanner* did. If the file has since lost rows —
    // truncated, corrupted, edited — the hint still claims those probes completed, and
    // the remainder would omit endpoints that were never actually probed. Silently
    // under-reporting a resume set is the failure this tool exists to prevent, so the
    // hint is believed only when the rows are still there to back it.
    if count_probe_rows(path)? != completed {
        return Ok(None);
    }

    // Only the header is read from the front, and it is the first two lines.
    let mut header = Vec::new();
    for line in stream(path)?.take(4) {
        if let Some(e) = line?.event {
            header.push(e);
        }
    }
    let Some(config) = header.into_iter().find(|e| kind(e) == "scan_config") else {
        return Ok(None);
    };
    let Some(seed) = config["permutation"]["seed"]
        .as_str()
        .and_then(|s| u64::from_str_radix(s, 16).ok())
    else {
        return Ok(None);
    };

    let expected = expected_endpoints(&config, path)?;
    if expected.len() as u64 != planned {
        return Ok(None);
    }

    // Walk counter space, map through the permutation, then sort so the output matches
    // the order the scanning path produces.
    let perm = crate::plan::Permutation::new(planned.max(1), seed);
    let mut indices: Vec<u64> = (from..planned)
        .chain(abandoned.iter().filter_map(Value::as_u64))
        .map(|raw| perm.apply(raw))
        .collect();
    indices.sort_unstable();

    let mut endpoints = Vec::with_capacity(indices.len());
    for i in indices {
        let Some((t, p)) = expected.at(i) else {
            return Ok(None);
        };
        endpoints.push(format_pair(&t, p));
    }

    let note = format!(
        "{} of {} endpoints were not probed; re-run exactly those with:\n  \
         scanr output remainder {} | scanr run --pairs -",
        commas(endpoints.len() as u64),
        commas(planned),
        path.display()
    );
    Ok(Some(Remainder {
        endpoints,
        scan_id: config["scan_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        note,
    }))
}

/// Count `probe_result` rows without parsing them.
///
/// A byte-level scan: far cheaper than the full read it guards, and any miscount can
/// only disagree with the terminal event, which falls back to the full read. Wrong in
/// the safe direction by construction.
fn count_probe_rows(path: &Path) -> Result<u64, String> {
    const ROW: &str = "\"type\":\"probe_result\"";
    const SPAN: &str = "\"type\":\"probe_span\"";
    let mut n = 0u64;
    let truncation_expected = is_partial(path);
    for line in open_record(path)?.lines() {
        match line {
            Ok(text) => {
                if text.contains(ROW) {
                    n += 1;
                } else if text.contains(SPAN) {
                    // A span stands for many probes; its count is the only part needed
                    // here, so only this line is parsed.
                    n += serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|v| v["count"].as_u64())
                        .unwrap_or(0);
                }
            }
            // Mirrors `stream`: a `.partial` file is expected to stop mid-way, and
            // anything else means we cannot vouch for the count.
            Err(_) if truncation_expected && n > 0 => break,
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
    }
    Ok(n)
}

fn remainder_by_scanning(path: &Path) -> Result<Remainder, String> {
    // Only the probed set is retained, which is inherent to the question being asked.
    // The expected matrix is walked lazily rather than materialised: a /16 x 16 ports is
    // a million endpoints, and building that list to subtract from it was most of the
    // memory this command used.
    let mut config: Option<Value> = None;
    let mut probed: BTreeSet<(String, u16)> = BTreeSet::new();
    // Collected during the pass and expanded after it: expanding needs the target list,
    // and spans arrive at the end of a record while the config arrives at the start.
    let mut span_ranges: Vec<[u64; 2]> = Vec::new();

    for line in stream(path)? {
        let Some(e) = line?.event else { continue };
        let k = kind(&e);
        if k == "scan_config" && config.is_none() {
            config = Some(e);
            continue;
        }
        if k == "probe_span" {
            if let Some(ranges) = e["probe_indices"].as_array() {
                for r in ranges {
                    if let (Some(a), Some(b)) = (r[0].as_u64(), r[1].as_u64()) {
                        span_ranges.push([a, b]);
                    }
                }
            }
            continue;
        }
        if k != "probe_result" {
            continue;
        }
        if let (Some(t), Some(p)) = (e["target"].as_str(), e["port"].as_u64()) {
            // An out-of-range port means the record is corrupt, and it must be refused
            // rather than narrowed: `p as u16` silently wrapped 65616 to 80, which both
            // marked an endpoint as probed that never was and dropped the real one from
            // the remainder. A resume driven by that output skipped endpoints with no
            // indication.
            let port = u16::try_from(p).map_err(|_| {
                format!(
                    "{} records a probe of `{t}` on port {p}, which is not a valid TCP port; \
                     the record is corrupt and its remainder cannot be derived safely \
                     (run `scanr output verify` for the full picture)",
                    path.display()
                )
            })?;
            probed.insert((t.to_string(), port));
        }
    }

    let config = config.ok_or_else(|| format!("{} has no scan_config event", path.display()))?;
    let expected = expected_endpoints(&config, path)?;
    let planned = expected.len();

    // A collapsed probe was still probed. Missing this would send a resume back over
    // every endpoint a span covered.
    for [start, end] in span_ranges {
        for i in start..=end {
            let Some(pair) = expected.at(i) else {
                return Err(format!(
                    "{} has a probe_span covering index {i}, which is outside its own \
                     planned matrix; the record is inconsistent and its remainder cannot \
                     be derived safely",
                    path.display()
                ));
            };
            probed.insert(pair);
        }
    }

    let endpoints = expected.outstanding(&probed);

    let note = format!(
        "{} of {} endpoints were not probed; re-run exactly those with:\n  \
         scanr output remainder {} | scanr run --pairs -",
        commas(endpoints.len() as u64),
        commas(planned as u64),
        path.display()
    );
    Ok(Remainder {
        endpoints,
        // Carried separately rather than prepended to `endpoints`, so the list stays a
        // list of endpoints and the count cannot be inflated by its own provenance.
        scan_id: config["scan_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        note,
    })
}

/// Every endpoint the scan intended to probe, kept in the compact form it was recorded
/// in rather than expanded.
enum Expected {
    /// A pair scan embeds its list, bounded by `MAX_EMBEDDED_PAIRS`.
    Pairs(Vec<(String, u16)>),
    /// A matrix scan records specs; the cross product is walked, never stored.
    Matrix {
        targets: Vec<Target>,
        ports: Vec<u16>,
    },
}

impl Expected {
    fn len(&self) -> usize {
        match self {
            Expected::Pairs(p) => p.len(),
            Expected::Matrix { targets, ports } => targets.len() * ports.len(),
        }
    }

    /// The endpoint at a permuted probe index. Mirrors `ScanPlan::probe_at`, which is
    /// what assigned the index in the first place.
    fn at(&self, index: u64) -> Option<(String, u16)> {
        match self {
            Expected::Pairs(p) => p.get(index as usize).cloned(),
            Expected::Matrix { targets, ports } => {
                let per = ports.len() as u64;
                if per == 0 {
                    return None;
                }
                let t = targets.get((index / per) as usize)?;
                let p = ports.get((index % per) as usize)?;
                Some((t.to_string(), *p))
            }
        }
    }

    /// The endpoints not present in `probed`, formatted for `run --pairs`.
    fn outstanding(&self, probed: &BTreeSet<(String, u16)>) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            Expected::Pairs(pairs) => {
                for (t, p) in pairs {
                    if !probed.contains(&(t.clone(), *p)) {
                        out.push(format_pair(t, *p));
                    }
                }
            }
            Expected::Matrix { targets, ports } => {
                for t in targets {
                    let name = t.to_string();
                    for p in ports {
                        if !probed.contains(&(name.clone(), *p)) {
                            out.push(format_pair(&name, *p));
                        }
                    }
                }
            }
        }
        out
    }
}

fn expected_endpoints(config: &Value, path: &Path) -> Result<Expected, String> {
    if config["targets"]["mode"] == "pairs" {
        return Ok(Expected::Pairs(expected_from_pairs(config, path)?));
    }
    expected_from_matrix(config)
}

/// Re-expand the target x port matrix from the canonical specs plus the seed.
fn expected_from_matrix(config: &Value) -> Result<Expected, String> {
    let list = |key: &str| -> Vec<String> {
        config["targets"][key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let specs = list("spec");
    let excludes = list("exclude");
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
        set.include
            .push(parse_target(s).map_err(|e| format!("recorded target spec is invalid: {e}"))?);
    }
    for s in &excludes {
        set.exclude
            .push(parse_target(s).map_err(|e| format!("recorded exclude spec is invalid: {e}"))?);
    }
    let targets = set
        .expand(true, u64::MAX)
        .map_err(|e| format!("cannot re-expand targets: {e}"))?;

    Ok(Expected::Matrix { targets, ports })
}

/// A pair scan has no compact spec, so the record embeds the list and it *is* the spec.
fn expected_from_pairs(config: &Value, path: &Path) -> Result<Vec<(String, u16)>, String> {
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
    Ok(out)
}

/// What `scanr output remainder` produces.
#[derive(Debug)]
pub struct Remainder {
    /// Endpoints the scan intended to probe but never reported.
    pub endpoints: Vec<String>,
    /// The scan these came from, rendered as a leading `# resumed-from:` comment so
    /// that piping into `--pairs` carries the link with no extra flag. Before this, a
    /// scan split across an interruption left two records nothing could connect.
    pub scan_id: Option<String>,
    /// Human-facing summary, for stderr.
    pub note: String,
}

impl Remainder {
    /// The stdout form: directive first, then one endpoint per line.
    pub fn render(&self) -> String {
        let mut s = String::new();
        if let Some(id) = &self.scan_id
            && !self.endpoints.is_empty()
        {
            let _ = writeln!(s, "# resumed-from: {id}");
        }
        for e in &self.endpoints {
            let _ = writeln!(s, "{e}");
        }
        s
    }
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

    /// A record with every field a real one carries.
    ///
    /// It used to omit `source`, `protocol`, `attempts`, `attempt_states` and
    /// `timing_ms`, and to use `"ts":"t"` — which was invisible while `verify` checked
    /// structure only. A fixture that a real scan would never produce cannot support a
    /// test called `accepts_a_well_formed_record`.
    fn good_events() -> Vec<Value> {
        let probe = |seq: u64, idx: u64, target: &str, state: &str, source: &str| {
            json!({"type":"probe_result","seq":seq,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1",
                   "probe_index":idx,"target":target,"port":80,"protocol":"tcp",
                   "state":state,"source":source,"service_label":"http",
                   "attempts":1,"attempt_states":[state],
                   "timing_ms":{"connect":1.5,"total":1.5}})
        };
        vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1","schema_version":1,"tool_version":"0.1.0"}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/30"],"exclude":[],"count":4},
                   "ports":{"spec":"80","count":1},"probes_planned":4,
                   "permutation":{"seed":"00000000000000ff"},
                   "transport":{"name":"direct","type":"direct","measured_fidelity":"full","password":null}}),
            probe(2, 0, "10.0.0.0", "open", "local_stack"),
            probe(3, 1, "10.0.0.1", "closed", "local_stack"),
            probe(4, 2, "10.0.0.2", "filtered", "timeout"),
            probe(5, 3, "10.0.0.3", "error", "internal"),
            json!({"type":"scan_completed","seq":6,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1","termination":"natural",
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

    /// The defect this guards: `verify` checked structure only, so a record could carry
    /// an impossible port and be reported as "complete and internally consistent".
    #[test]
    fn rejects_a_port_outside_the_valid_range() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[2]["port"] = json!(65616);
        let p = write(d.path(), "badport.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("`port` outside")),
            "{:?}",
            r.problems
        );
        assert!(!r.render().contains("ok — record is complete"));
    }

    /// The other half of the same defect: `remainder` truncated that port to `u16`,
    /// 65616 became 80, and the endpoint that really was unprobed vanished from the
    /// resume set with no indication.
    #[test]
    fn remainder_refuses_a_record_with_an_impossible_port() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[2]["port"] = json!(65616);
        let p = write(d.path(), "badport2.jsonl", &e);
        let err = remainder(&p).expect_err("a corrupt port must not be silently narrowed");
        assert!(err.contains("65616"), "{err}");
        assert!(err.contains("not a valid TCP port"), "{err}");
    }

    #[test]
    fn rejects_unrecognised_state_and_source() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[2]["state"] = json!("banana");
        e[3]["source"] = json!("vibes");
        let p = write(d.path(), "badenum.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|x| x.contains("unrecognised `state`")),
            "{:?}",
            r.problems
        );
        assert!(
            r.problems
                .iter()
                .any(|x| x.contains("unrecognised `source`")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn rejects_impossible_attempts_and_timings() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[2]["attempts"] = json!(0);
        e[3]["timing_ms"]["total"] = json!(-5.0);
        e[4]["probe_index"] = json!(99);
        let p = write(d.path(), "badvals.jsonl", &e);
        let r = verify(&p).unwrap();
        for expected in [
            "`attempts` of 0",
            "impossible timing",
            "`probe_index` at or beyond",
        ] {
            assert!(
                r.problems.iter().any(|x| x.contains(expected)),
                "expected {expected:?} in {:?}",
                r.problems
            );
        }
    }

    #[test]
    fn rejects_an_unreadable_timestamp() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[2]["ts"] = json!("yesterday");
        let p = write(d.path(), "badts.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(
            r.problems.iter().any(|x| x.contains("not RFC 3339")),
            "{:?}",
            r.problems
        );
    }

    /// A systematically corrupt record must not print one line per row.
    #[test]
    fn value_problems_are_aggregated_not_listed_per_row() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        for (i, probe) in e.iter_mut().enumerate().skip(2).take(4) {
            probe["port"] = json!(70000 + i as u64);
        }
        let p = write(d.path(), "manybad.jsonl", &e);
        let r = verify(&p).unwrap();
        let port_problems: Vec<_> = r
            .problems
            .iter()
            .filter(|x| x.contains("`port` outside"))
            .collect();
        assert_eq!(port_problems.len(), 1, "{:?}", r.problems);
        assert!(port_problems[0].contains('4'), "{}", port_problems[0]);
    }

    /// Without this a scan split across an interruption leaves two records that nothing
    /// connects — the open question the original brief raised about resume linkage.
    #[test]
    fn remainder_leads_with_the_scan_it_came_from() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.remove(5);
        e.remove(4);
        e[4]["counts"] = json!({"planned":4,"started":2,"completed":2,"not_started":2,
                                "open":1,"closed":1,"filtered":0,"error":0,"retried":0});
        let p = write(d.path(), "part.jsonl", &e);
        let r = remainder(&p).unwrap();
        let rendered: Vec<String> = r.render().lines().map(str::to_string).collect();
        assert_eq!(rendered[0], "# resumed-from: a1");
        // A directive, not an endpoint: it must not be counted as one.
        assert_eq!(&rendered[1..], ["10.0.0.2:80", "10.0.0.3:80"]);
        assert_eq!(r.endpoints, ["10.0.0.2:80", "10.0.0.3:80"]);
        assert!(r.note.starts_with("2 of 4 endpoints"), "{}", r.note);
    }

    #[test]
    fn a_complete_scan_emits_no_directive() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "done.jsonl", &good_events());
        let r = remainder(&p).unwrap();
        assert!(r.endpoints.is_empty(), "{:?}", r.endpoints);
        assert!(r.scan_id.is_some(), "the origin is still known");
        assert_eq!(r.render(), "", "nothing outstanding means no directive");
        assert!(r.note.starts_with("0 of 4 endpoints"), "{}", r.note);
    }

    /// A file we cannot fully read is refused outright, by all three readers.
    ///
    /// Streaming made this a live question. Treating an unreadable line like unparseable
    /// JSON looks tolerant and is not: `remainder` would then print a confident endpoint
    /// list derived from a file it could not read, and exit 0 doing it. A malformed
    /// *JSON* line stays tolerated, as it always was — that one we can at least see.
    #[test]
    fn an_unreadable_file_is_refused_by_every_reader() {
        use std::io::Write as _;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("badutf8.jsonl");
        {
            let mut f = std::fs::File::create(&p).unwrap();
            for e in &good_events()[..2] {
                writeln!(f, "{e}").unwrap();
            }
            f.write_all(b"\xff\xfe not utf-8\n").unwrap();
        }
        for err in [
            verify(&p).err(),
            summarize(&p).err(),
            remainder(&p).err().map(|e| e.to_string()),
        ] {
            let err = err.expect("an unreadable file must be an error, not a partial answer");
            assert!(err.contains("cannot read"), "{err}");
            assert!(err.contains("valid UTF-8"), "{err}");
        }
    }

    /// The terminal event's resume hint must produce exactly what re-reading every probe
    /// row produces. If the two ever disagree the fast path is a liability, not a
    /// shortcut.
    #[test]
    fn the_resume_hint_agrees_with_reading_every_row() {
        const SEED: u64 = 0x00ff;
        const PLANNED: u64 = 8;
        let perm = crate::plan::Permutation::new(PLANNED, SEED);

        // Raw indices 0..=3 completed, 4 was abandoned in flight, 5..8 never started.
        let mut events = vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-30T12:00:00.000Z","scan_id":"c1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-30T12:00:00.000Z","scan_id":"c1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/29"],"exclude":[],"count":8,"mode":"matrix"},
                   "ports":{"spec":"80","count":1},"probes_planned":8,
                   "permutation":{"algorithm":"feistel4","seed":format!("{SEED:016x}")}}),
        ];
        for (n, raw) in (0..4u64).enumerate() {
            let permuted = perm.apply(raw);
            events.push(json!({
                "type":"probe_result","seq":2+n,"ts":"2026-07-30T12:00:00.000Z","scan_id":"c1",
                "probe_index":permuted,"target":format!("10.0.0.{permuted}"),"port":80,
                "protocol":"tcp","state":"closed","source":"local_stack","attempts":1,
                "attempt_states":["closed"],"timing_ms":{"total":1.0}
            }));
        }
        events.push(
            json!({"type":"scan_interrupted","seq":6,"ts":"2026-07-30T12:00:00.000Z","scan_id":"c1",
               "termination":"signal",
               "counts":{"planned":8,"started":5,"completed":4,"abandoned":1,"not_started":3,
                         "open":0,"closed":4,"filtered":0,"error":0,"retried":0},
               "not_started_from":5,"abandoned_indices":[4]}),
        );

        let d = tempfile::tempdir().unwrap();
        let with_hint = write(d.path(), "hint.jsonl", &events);

        // The same record with the hint removed, forcing the scanning path.
        let mut stripped = events.clone();
        let last = stripped.len() - 1;
        stripped[last]
            .as_object_mut()
            .unwrap()
            .retain(|k, _| k != "not_started_from" && k != "abandoned_indices");
        let without = write(d.path(), "nohint.jsonl", &stripped);

        let fast = remainder(&with_hint).unwrap();
        let slow = remainder(&without).unwrap();
        assert_eq!(fast.endpoints, slow.endpoints, "the two paths must agree");
        assert_eq!(
            fast.endpoints.len(),
            4,
            "one abandoned plus three never started"
        );
        // The notes differ only in the filename each was asked about.
        let counted = |n: &str| n.split(';').next().unwrap().to_string();
        assert_eq!(counted(&fast.note), counted(&slow.note));
        assert!(fast.note.starts_with("4 of 8 endpoints"), "{}", fast.note);
    }

    /// A record that has lost rows must not be told it is complete.
    ///
    /// The terminal hint records what the scanner did, and stays internally consistent
    /// even after rows are removed from the file. Trusting it alone made `remainder`
    /// report nothing outstanding for a record missing two probes — a resume that
    /// silently skips endpoints, which is the whole failure class this tool exists to
    /// prevent. CI caught this; the local suite had caught it too and I misread the
    /// output.
    #[test]
    fn a_hint_is_not_trusted_when_rows_are_missing_from_the_file() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        // A completed scan: nothing outstanding, and the hint says so truthfully.
        e[6]["not_started_from"] = json!(4);
        e[6]["abandoned_indices"] = json!([]);
        let complete = write(d.path(), "complete.jsonl", &e);
        assert!(
            remainder(&complete).unwrap().endpoints.is_empty(),
            "a genuinely complete scan has no remainder"
        );

        // The same terminal event, but two probe rows have gone missing.
        e.remove(5);
        e.remove(4);
        let lossy = write(d.path(), "lossy.jsonl", &e);
        let r = remainder(&lossy).unwrap();
        assert_eq!(
            r.endpoints,
            ["10.0.0.2:80", "10.0.0.3:80"],
            "rows absent from the file must be treated as unprobed, not as done"
        );
    }

    /// A span stands for probes that were made. `remainder` must treat them as probed,
    /// or a resume goes back over every endpoint the span covered.
    ///
    /// Built as two records describing the *same* scan — one with rows, one with the
    /// equivalent span — because comparing two live interrupted scans compares two
    /// different seeds and two different interrupt points, which proves nothing.
    #[test]
    fn a_span_covers_exactly_the_endpoints_its_rows_would_have() {
        let d = tempfile::tempdir().unwrap();
        let header = vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/29"],"exclude":[],"count":8,"mode":"matrix"},
                   "ports":{"spec":"80,443","count":2},"probes_planned":16,
                   "permutation":{"algorithm":"feistel4","seed":"00000000000000ff"}}),
        ];
        let terminal = json!({"type":"scan_interrupted","seq":99,"ts":"2026-07-31T12:00:01.000Z",
               "scan_id":"s1","termination":"signal",
               "counts":{"planned":16,"started":10,"completed":10,"abandoned":0,"not_started":6,
                         "open":0,"closed":10,"filtered":0,"error":0,"retried":0}});

        // Indices 0..=9 probed and closed, expressed as ten rows.
        let mut rows = header.clone();
        for i in 0..10u64 {
            rows.push(json!({"type":"probe_result","seq":2+i,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s1",
                   "probe_index":i,"target":format!("10.0.0.{}", i/2),"port":if i%2==0 {80} else {443},
                   "protocol":"tcp","state":"closed","source":"local_stack","attempts":1,
                   "attempt_states":["closed"],"timing_ms":{"total":1.0}}));
        }
        rows.push(terminal.clone());

        // The same ten probes, expressed as one span.
        let spans = vec![
            header[0].clone(),
            header[1].clone(),
            json!({"type":"probe_span","seq":2,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s1",
                   "state":"closed","source":"local_stack","reason":null,"protocol":"tcp",
                   "attempts":1,"count":10,"probe_indices":[[0,9]],
                   "timing_ms":{"min":1.0,"mean":1.0,"max":1.0}}),
            terminal,
        ];

        let a = remainder(&write(d.path(), "rows.jsonl", &rows)).unwrap();
        let b = remainder(&write(d.path(), "span.jsonl", &spans)).unwrap();
        assert_eq!(
            a.endpoints, b.endpoints,
            "a span must cover what its rows covered"
        );
        assert_eq!(
            b.endpoints,
            [
                "10.0.0.5:80",
                "10.0.0.5:443",
                "10.0.0.6:80",
                "10.0.0.6:443",
                "10.0.0.7:80",
                "10.0.0.7:443"
            ],
            "indices 10..15 are the outstanding ones"
        );
    }

    /// Both forms of the same scan must also verify identically.
    #[test]
    fn a_span_record_reconciles_its_counts() {
        let d = tempfile::tempdir().unwrap();
        let e = vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s2","schema_version":1}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s2","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/30"],"exclude":[],"count":4,"mode":"matrix"},
                   "ports":{"spec":"80","count":1},"probes_planned":4}),
            json!({"type":"probe_result","seq":2,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s2",
                   "probe_index":0,"target":"10.0.0.0","port":80,"protocol":"tcp","state":"open",
                   "source":"local_stack","attempts":1,"attempt_states":["open"],"timing_ms":{"total":1.0}}),
            json!({"type":"probe_span","seq":3,"ts":"2026-07-31T12:00:00.000Z","scan_id":"s2",
                   "state":"closed","source":"local_stack","reason":null,"protocol":"tcp",
                   "attempts":1,"count":3,"probe_indices":[[1,3]],
                   "timing_ms":{"min":0.5,"mean":0.7,"max":1.0}}),
            json!({"type":"scan_completed","seq":4,"ts":"2026-07-31T12:00:01.000Z","scan_id":"s2",
                   "termination":"natural",
                   "counts":{"planned":4,"started":4,"completed":4,"abandoned":0,"not_started":0,
                             "open":1,"closed":3,"filtered":0,"error":0,"retried":0}}),
        ];
        let r = verify(&write(d.path(), "mixed.jsonl", &e)).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(
            r.notes.iter().any(|n| n.contains("collapsed into 1 span")),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn a_span_that_disagrees_with_its_own_ranges_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.insert(
            6,
            json!({"type":"probe_span","seq":6,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1",
                   "state":"closed","source":"local_stack","protocol":"tcp","attempts":1,
                   "count":99,"probe_indices":[[0,1]],
                   "timing_ms":{"min":1.0,"mean":1.0,"max":1.0}}),
        );
        let r = verify(&write(d.path(), "badspan.jsonl", &e)).unwrap();
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("disagrees with its ranges")),
            "{:?}",
            r.problems
        );
    }

    /// A hint that disagrees with the counts is not trusted.
    #[test]
    fn an_inconsistent_resume_hint_falls_back_to_scanning() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e.remove(5);
        e.remove(4);
        e[4]["counts"] = json!({"planned":4,"started":2,"completed":2,"not_started":2,
                                "abandoned":0,"open":1,"closed":1,"filtered":0,"error":0,"retried":0});
        // Claims nothing is outstanding, which the counts contradict.
        e[4]["not_started_from"] = json!(4);
        e[4]["abandoned_indices"] = json!([]);
        let p = write(d.path(), "bad_hint.jsonl", &e);
        let r = remainder(&p).unwrap();
        assert_eq!(
            r.endpoints,
            ["10.0.0.2:80", "10.0.0.3:80"],
            "an untrustworthy hint must be ignored, not obeyed"
        );
    }

    /// A killed scan's compressed record must still be readable up to its last frame.
    ///
    /// This is the whole reason the writer emits gzip in frames rather than as one
    /// stream. Without it, turning on compression would quietly cost the `.partial`
    /// guarantee — the record would be unreadable in exactly the case it matters.
    #[test]
    fn a_truncated_compressed_partial_reads_up_to_its_last_frame() {
        use crate::output::JsonlWriter;

        let d = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(d.path(), "cut01", 1_700_000_000_000, true).unwrap();
        w.emit("scan_started", json!({"schema_version": 1}))
            .unwrap();
        w.emit("scan_config", json!({"probes_planned": 20_000}))
            .unwrap();
        for i in 0..20_000u64 {
            w.emit(
                "probe_result",
                json!({"target": format!("10.0.{}.{}", i / 256, i % 256), "port": 443,
                       "state": "closed", "source": "local_stack", "protocol": "tcp",
                       "attempts": 1, "attempt_states": ["closed"],
                       "timing_ms": {"total": 1.0}, "probe_index": i}),
            )
            .unwrap();
        }
        let partial = w.partial_path().to_path_buf();
        drop(w);

        // Cut mid-frame, as a killed process would leave it.
        let full = std::fs::read(&partial).unwrap();
        let cut = d.path().join("cut.jsonl.gz.partial");
        std::fs::write(&cut, &full[..full.len() - 4096]).unwrap();

        let r = verify(&cut).expect("a truncated .partial must still be readable");
        assert!(
            r.events > 100,
            "expected the earlier frames back, got {}",
            r.events
        );
        assert!(
            r.problems.iter().any(|p| p.contains(".partial suffix")),
            "{:?}",
            r.problems
        );

        // The same bytes under a finalized name are a corrupt record, not a partial one.
        let final_name = d.path().join("cut.jsonl.gz");
        std::fs::write(&final_name, &full[..full.len() - 4096]).unwrap();
        let err = verify(&final_name).expect_err("a finalized record must decode fully");
        assert!(err.contains("cannot read"), "{err}");
    }

    #[test]
    fn verify_surfaces_the_resume_link() {
        let d = tempfile::tempdir().unwrap();
        let mut e = good_events();
        e[1]["resumed_from"] = json!("beef1234");
        let p = write(d.path(), "chained.jsonl", &e);
        let r = verify(&p).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        assert!(
            r.notes.iter().any(|n| n == "resumed from scan beef1234"),
            "{:?}",
            r.notes
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
        let r = remainder(&p).unwrap();
        let (endpoints, note) = (r.endpoints, r.note);
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
        let targets = remainder(&p).unwrap().endpoints;
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

        let rem = remainder(&p).unwrap().endpoints;
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
        let rem = remainder(&p).unwrap().endpoints;
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
