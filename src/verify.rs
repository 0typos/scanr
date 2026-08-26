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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::{Value, json};

use crate::net::target::{TargetSet, TargetSpec, format_pair, parse_pair};
use crate::net::{Target, parse_ports, parse_target};
use crate::output::human::Style;
use crate::plan::Permutation;
use crate::probe::State;
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

/// Is this record gzip? Decided by magic bytes, like `open_record`, so the two cannot
/// disagree about the same file.
fn is_gzip(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 2];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == [0x1f, 0x8b]
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

/// Write a record out as plain JSONL, decompressing a gzip one on the way.
///
/// Exists because compression is the default, and the shell tool that would otherwise do
/// this is not portable: `zcat -f`'s pass-through of uncompressed input is a GNU
/// extension, and macOS ships BSD gzip. The tool already sniffs the format for its own
/// commands, so exposing that costs nothing and makes every documented `jq` recipe work
/// the same everywhere.
///
/// Byte-faithful and streaming: the record is copied through, not parsed and re-emitted,
/// so it stays valid for a consumer even if this build would not have written it that
/// way.
pub fn cat(path: &Path, out: &mut dyn std::io::Write) -> Result<(), String> {
    use std::io::Read;

    let mut reader = open_record(path)?;
    let truncation_expected = is_partial(path);
    let mut buf = vec![0u8; 64 * 1024];
    let mut wrote = false;

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // A `.partial` file is expected to stop mid-way; see `stream`.
            Err(e)
                if truncation_expected
                    && wrote
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData
                    ) =>
            {
                break;
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        match out.write_all(&buf[..n]) {
            Ok(()) => wrote = true,
            // `scanr output events big.jsonl.gz | head` closes the pipe early. That is the
            // reader saying "enough", not a failure of ours.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(e) => return Err(format!("cannot write: {e}")),
        }
    }
    Ok(())
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
    /// Whether `scan_config` carried a parseable permutation seed.
    ///
    /// From schema 2 on, span ranges are counter indices and the seed is what turns them
    /// back into endpoints. Without it a reader cannot expand a span at all — and the way
    /// it fails is silent, producing plausible endpoints that are simply the wrong ones.
    seed_usable: bool,

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
            self.seed_usable = e["permutation"]["seed"]
                .as_str()
                .is_some_and(|s| u64::from_str_radix(s, 16).is_ok());
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
        // Every version this build knows how to read, not just the one it writes.
        // Bumping the writer must not make yesterday's records unreadable — the whole
        // point of the field is that a reader can tell which shape it has and act on it,
        // and `walk_results` does exactly that for span index space.
        if let Some(v) = self.schema_version
            && !crate::output::SUPPORTED_SCHEMA_VERSIONS.contains(&(v as u32))
        {
            problems.push(format!(
                "schema_version {v} is not supported by this build (reads {})",
                crate::output::SUPPORTED_SCHEMA_VERSIONS
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // From schema 2 on, span ranges are counter indices and only the seed maps them
        // back to endpoints. Say so rather than expanding without it: the result would be
        // the right *number* of well-formed endpoints, all of them wrong, with nothing in
        // the file to show for it.
        if self.spans > 0
            && self.saw_config
            && !self.seed_usable
            && self.schema_version.is_some_and(|v| v >= 2)
        {
            problems.push(format!(
                "{} probe_span event(s) need the permutation seed to expand, \
                 but scan_config has none that parses",
                self.spans
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

/// Ordering key for a host: family, then address bytes, then name.
type HostKey = (u8, [u8; 16], String);

/// Sort hosts the way a reader expects: numerically when they are addresses.
///
/// Sorting the formatted strings put `10.0.0.10` before `10.0.0.2`, which looks like a
/// bug in the scan rather than in the sort.
fn host_key(target: &str) -> HostKey {
    match target.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let mut k = [0u8; 16];
            k[12..].copy_from_slice(&a.octets());
            (0, k, String::new())
        }
        Ok(std::net::IpAddr::V6(a)) => (1, a.octets(), String::new()),
        // Hostnames sort after addresses, among themselves alphabetically.
        Err(_) => (2, [0u8; 16], target.to_string()),
    }
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

fn label(service: &str) -> &str {
    if service.is_empty() { "-" } else { service }
}

/// Which section of the summary to show. Absent means all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grouping {
    /// Totals only.
    Scan,
    /// What is each machine running?
    Host,
    /// Rolled up per /24, for a scan wide enough that hosts are too many to read.
    Network,
    /// Who is running this port?
    Port,
    /// Same, keyed by the service label, so `http` gathers 80 and 8080.
    Service,
}

impl Grouping {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "scan" => Some(Self::Scan),
            "host" => Some(Self::Host),
            "network" => Some(Self::Network),
            "port" => Some(Self::Port),
            "service" => Some(Self::Service),
            _ => None,
        }
    }

    pub const ALL: &'static [&'static str] = &["scan", "host", "network", "port", "service"];
}

/// Aggregate a record: totals, then counts by host, network, and service.
///
/// Folds into counters rather than collecting results, so summarising a /16 costs hosts
/// plus ports rather than probes. The earlier version listed open endpoints and offered
/// `--by` to rearrange that one list; it could not answer "how many hosts had 445
/// filtered", because it only ever looked at `open` rows.
pub fn summarize(
    path: &Path,
    by: Option<Grouping>,
    json: bool,
    style: &Style,
) -> Result<String, String> {
    let mut hosts: BTreeMap<HostKey, HostAgg> = BTreeMap::new();
    let mut ports: BTreeMap<u16, PortAgg> = BTreeMap::new();
    let mut unknown_state: u64 = 0;
    // Results arrive host-major within a span, so the map slot is almost always the one
    // used last. Skipping the lookup saves parsing the address back out of the formatted
    // target and descending a 65k-entry map, per probe.
    let mut last: Option<(String, HostKey)> = None;
    let scan = walk_results(path, |r| {
        if last.as_ref().is_none_or(|(t, _)| t != r.target) {
            last = Some((r.target.to_string(), host_key(r.target)));
        }
        let key = &last.as_ref().expect("just set").1;
        let h = hosts.entry(key.clone()).or_insert_with(|| HostAgg {
            name: r.target.to_string(),
            ..HostAgg::default()
        });
        h.states.add(r.state);
        if r.state == State::Open.as_str() {
            h.open_ports.push(r.port);
        }

        let p = ports.entry(r.port).or_default();
        p.states.add(r.state);
        if p.service.is_empty()
            && let Some(s) = r.service
        {
            p.service = s.to_string();
        }
        if State::parse(r.state).is_none() {
            unknown_state += 1;
        }
    })?;
    let Some(header) = scan.header else {
        return Err(format!("{} contains no events", path.display()));
    };

    for h in hosts.values_mut() {
        h.open_ports.sort_unstable();
    }

    let summary = Summary {
        path: path.display().to_string(),
        unreadable: scan.unreadable,
        unknown_state,
        header,
        config: scan.config,
        terminal: scan.terminal,
        hosts,
        ports,
    };
    Ok(if json {
        format!("{}\n", summary.to_json(by))
    } else {
        summary.render(by, style)
    })
}

/// Per-host totals, and which ports were open.
#[derive(Default)]
struct HostAgg {
    name: String,
    states: States,
    /// Ports only. The label is a pure function of the port and `Summary::ports` already
    /// carries it, so storing it per host cost a `String` per open result — memory
    /// proportional to *probes*, which is exactly what this aggregation exists to avoid.
    open_ports: Vec<u16>,
}

/// Per-port totals across hosts. One probe per (host, port), so `states.open` *is* the
/// number of hosts with that port open — no separate host counter to keep in step.
#[derive(Default)]
struct PortAgg {
    states: States,
    service: String,
}

#[derive(Default, Clone, Copy)]
struct States {
    open: u64,
    closed: u64,
    filtered: u64,
    error: u64,
    /// A state string that is none of the four. Kept apart rather than folded into
    /// `error`, which would have invented error counts that contradict the totals line
    /// printed directly above them — `verify` is what judges a record, and a summary
    /// that quietly reinterprets one is worse than a summary that says it cannot.
    other: u64,
}

impl States {
    fn add(&mut self, state: &str) {
        // Through `State::parse` rather than a second copy of the four strings. The
        // caveat line calls `other` "a state this build does not recognise", which a
        // hardcoded list can make false: a fifth `State` variant would be reported as
        // unrecognised by the same build that defines it. This way it is a compile error.
        match State::parse(state) {
            Some(State::Open) => self.open += 1,
            Some(State::Closed) => self.closed += 1,
            Some(State::Filtered) => self.filtered += 1,
            Some(State::Error) => self.error += 1,
            None => self.other += 1,
        }
    }

    fn merge(&mut self, o: &States) {
        self.open += o.open;
        self.closed += o.closed;
        self.filtered += o.filtered;
        self.error += o.error;
        self.other += o.other;
    }

    /// Header cells for the four state columns, so a header and its rows cannot drift.
    fn head() -> String {
        format!(
            "{:>6} {:>6} {:>8} {:>6}",
            State::Open.as_str(),
            State::Closed.as_str(),
            State::Filtered.as_str(),
            State::Error.as_str()
        )
    }

    /// The matching data cells.
    fn cols(&self) -> String {
        format!(
            "{:>6} {:>6} {:>8} {:>6}",
            self.open, self.closed, self.filtered, self.error
        )
    }

    fn to_json(self) -> Value {
        json!({
            "open": self.open,
            "closed": self.closed,
            "filtered": self.filtered,
            "error": self.error,
            "unrecognized": self.other,
        })
    }
}

/// The `/24` (or IPv6 `/64`) a target belongs to.
///
/// Fixed rather than derived from the scan's own target specs: those can overlap, nest,
/// or be a bare list, so there is no single "the network" a host belongs to. A fixed
/// mask gives every record the same buckets, which is what makes two of them comparable.
fn network_of(target: &str) -> String {
    match target.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(a)) => {
            // Masked and re-rendered by `Ipv6Addr`'s own `Display`, so it elides the way
            // every other address in the tool does: `::/64`, not `0:0:0:0::/64`.
            let s = a.segments();
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            format!("{net}/64")
        }
        Err(_) => "(hostnames)".to_string(),
    }
}

/// Rows per section in the unnarrowed view. A /16 has 65,536 hosts and 65,535 ports;
/// the default invocation is a first look, not a data dump.
const SECTION_ROWS: usize = 25;

struct Summary {
    path: String,
    /// Results whose port the record states as unusable, so they are in no section.
    unreadable: u64,
    /// Results whose `state` is none of the four. Counted where they are seen rather
    /// than re-derived by summing the host map, which coupled the figure to whatever
    /// happened to be in that map.
    unknown_state: u64,
    /// Not an `Option`: `summarize` refuses a record with no events before building this.
    header: Value,
    config: Option<Value>,
    terminal: Option<Value>,
    hosts: BTreeMap<HostKey, HostAgg>,
    ports: BTreeMap<u16, PortAgg>,
}

/// Rolled up by network: how much was looked at, and how much answered.
struct NetAgg {
    /// Carried because the map is keyed for *ordering*, not for display.
    name: String,
    hosts: u64,
    hosts_with_open: u64,
    states: States,
}

/// Rolled up by service label, so `http` gathers 80, 8080 and 8000.
struct SvcAgg {
    ports: Vec<u16>,
    states: States,
}

impl Summary {
    /// Keyed by `host_key` of the prefix address, not by its string: sorting the text
    /// put `10.0.0.0/24` before `2.2.2.0/24`, which is exactly the defect `host_key`
    /// exists to prevent — and it was doing it in the section directly below the
    /// correctly sorted host table.
    /// `80/http`, or bare `9099` when nothing labels the port.
    fn port_label(&self, port: u16) -> String {
        match self.ports.get(&port).map(|p| p.service.as_str()) {
            Some(s) if !s.is_empty() => format!("{port}/{s}"),
            _ => port.to_string(),
        }
    }

    /// The label as JSON, `null` when there is none.
    fn service_of(&self, port: u16) -> Value {
        match self.ports.get(&port).map(|p| p.service.as_str()) {
            Some(s) if !s.is_empty() => json!(s),
            _ => Value::Null,
        }
    }

    fn networks(&self) -> BTreeMap<HostKey, NetAgg> {
        let mut out: BTreeMap<HostKey, NetAgg> = BTreeMap::new();
        for h in self.hosts.values() {
            let name = network_of(&h.name);
            let key = host_key(name.split('/').next().unwrap_or(&name));
            let e = out.entry(key).or_insert(NetAgg {
                name,
                hosts: 0,
                hosts_with_open: 0,
                states: States::default(),
            });
            e.hosts += 1;
            if h.states.open > 0 {
                e.hosts_with_open += 1;
            }
            e.states.merge(&h.states);
        }
        out
    }

    fn services(&self) -> BTreeMap<String, SvcAgg> {
        let mut out: BTreeMap<String, SvcAgg> = BTreeMap::new();
        for (port, p) in &self.ports {
            let key = if p.service.is_empty() {
                format!("({port})")
            } else {
                p.service.clone()
            };
            let e = out.entry(key).or_insert(SvcAgg {
                ports: Vec::new(),
                states: States::default(),
            });
            e.ports.push(*port);
            e.states.merge(&p.states);
        }
        out
    }

    /// Ports something was recorded for, most interesting first.
    ///
    /// Ranked rather than filtered to `open`. Filtering to open made a port that was
    /// only ever *filtered* invisible — and "445 was filtered on 200 hosts" is exactly
    /// the finding this section exists to surface, so the first version answered every
    /// question except the one it was written for.
    fn interesting_ports(&self) -> Vec<(u16, &PortAgg)> {
        // No filter: every entry in `self.ports` was created by a result and immediately
        // counted, so there is nothing here that had no outcome.
        let mut v: Vec<(u16, &PortAgg)> = self.ports.iter().map(|(k, p)| (*k, p)).collect();
        v.sort_by_key(|(port, p)| {
            (
                std::cmp::Reverse(p.states.open),
                std::cmp::Reverse(p.states.filtered),
                std::cmp::Reverse(p.states.error),
                *port,
            )
        });
        v
    }

    fn render(&self, by: Option<Grouping>, style: &Style) -> String {
        let mut s = String::new();
        let show = |g: Grouping| by.is_none_or(|b| b == g);
        // The all-sections view is a first look, so each section is bounded and says
        // what it left out. Asking for one section with `--by` asks for all of it.
        let limit = if by.is_none() {
            Some(SECTION_ROWS)
        } else {
            None
        };

        let _ = writeln!(&mut s, "{}", self.path);
        self.render_scan(&mut s, style);
        self.render_caveats(&mut s);
        if show(Grouping::Host) {
            self.render_hosts(&mut s, limit);
        }
        if show(Grouping::Network) {
            self.render_networks(&mut s, limit);
        }
        if show(Grouping::Port) {
            self.render_ports(&mut s, limit);
        }
        if show(Grouping::Service) {
            self.render_services(&mut s, limit);
        }
        s
    }

    /// Anything that would make the tables below disagree with the totals above.
    ///
    /// Both of these used to be silent. A result whose port the record states as out of
    /// range simply vanished from every section, leaving a totals line with no rows to
    /// support it; an unrecognised state was counted as `error`, so the host table
    /// reported errors the terminal event said did not happen.
    fn render_caveats(&self, s: &mut String) {
        if self.unreadable > 0 {
            let _ = writeln!(
                s,
                "  {:<16}{} result(s) had an unusable port and are not counted below",
                "note",
                commas(self.unreadable)
            );
        }
        if self.unknown_state > 0 {
            let _ = writeln!(
                s,
                "  {:<16}{} result(s) had a state this build does not recognise",
                "note",
                commas(self.unknown_state)
            );
        }
    }

    /// `... and N more (--by X to see them all)`, or nothing when nothing was dropped.
    fn elided(s: &mut String, shown: usize, total: usize, by: &str) {
        if total > shown {
            let _ = writeln!(
                s,
                "  ... and {} more (--by {by} for all)",
                commas((total - shown) as u64)
            );
        }
    }

    fn render_scan(&self, s: &mut String, style: &Style) {
        let _ = writeln!(
            s,
            "  {:<16}{}",
            "scan",
            self.config
                .as_ref()
                .and_then(|c| c["scan_name"].as_str())
                .unwrap_or("(unknown)")
        );
        let _ = writeln!(
            s,
            "  {:<16}{}  (scanr {})",
            "started",
            self.header["ts"].as_str().unwrap_or("?"),
            self.header["tool_version"].as_str().unwrap_or("?")
        );
        if let Some(c) = &self.config {
            let t = &c["transport"];
            let _ = writeln!(
                s,
                "  {:<16}{} via {} ({})",
                "transport",
                t["name"].as_str().unwrap_or("?"),
                t["type"].as_str().unwrap_or("?"),
                t["measured_fidelity"].as_str().unwrap_or("?")
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
        match &self.terminal {
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
                let count = |k: &str, st: State| {
                    style.paint_state(
                        st,
                        &format!("{} {}", commas(c[k].as_u64().unwrap_or(0)), st.as_str()),
                    )
                };
                let _ = writeln!(
                    s,
                    "  {:<16}{}, {}, {}, {}",
                    "states",
                    count("open", State::Open),
                    count("closed", State::Closed),
                    count("filtered", State::Filtered),
                    count("error", State::Error)
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
    }

    fn render_hosts(&self, s: &mut String, limit: Option<usize>) {
        if self.hosts.is_empty() {
            return;
        }
        // Numeric order, but hosts that answered come first when the list is bounded:
        // on a sweep the interesting rows are a handful among tens of thousands.
        let mut rows: Vec<&HostAgg> = self.hosts.values().collect();
        if limit.is_some() {
            // Stable, and `self.hosts` is already keyed by `host_key`, so this is the
            // same order the full key would give — without parsing every address again
            // on every comparison, to print twenty-five rows.
            rows.sort_by_key(|h| h.states.open == 0);
        }
        let shown = limit.unwrap_or(rows.len()).min(rows.len());
        let w = rows[..shown]
            .iter()
            .map(|h| h.name.chars().count())
            .max()
            .unwrap_or(15)
            .max(15);

        let _ = writeln!(s, "\nby host ({}):", plural(self.hosts.len(), "host"));
        let _ = writeln!(s, "  {:<w$}  {}  open ports", "host", States::head(), w = w);
        for h in &rows[..shown] {
            let list: Vec<String> = h.open_ports.iter().map(|p| self.port_label(*p)).collect();
            let line = format!(
                "  {:<w$}  {}  {}",
                h.name,
                h.states.cols(),
                list.join(" "),
                w = w
            );
            let _ = writeln!(s, "{}", line.trim_end());
        }
        Self::elided(s, shown, rows.len(), "host");
    }

    fn render_networks(&self, s: &mut String, limit: Option<usize>) {
        let nets = self.networks();
        if nets.is_empty() {
            return;
        }
        let mut rows: Vec<&NetAgg> = nets.values().collect();
        if limit.is_some() {
            // Same rule the host table uses when bounded: prefixes that answered first.
            // Without it the default view showed the interesting hosts beside an
            // arbitrary twenty-five prefixes, truncated by numeric order.
            rows.sort_by_key(|n| n.hosts_with_open == 0);
        }
        let shown = limit.unwrap_or(rows.len()).min(rows.len());
        let w = rows[..shown]
            .iter()
            .map(|n| n.name.chars().count())
            .max()
            .unwrap_or(18)
            .max(18);

        let _ = writeln!(s, "\nby network ({}):", plural(nets.len(), "network"));
        let _ = writeln!(
            s,
            "  {:<w$}  {:>6} {:>10} {:>6} {:>8}",
            "network",
            "hosts",
            "with-open",
            "open",
            "filtered",
            w = w
        );
        for n in &rows[..shown] {
            let _ = writeln!(
                s,
                "  {:<w$}  {:>6} {:>10} {:>6} {:>8}",
                n.name,
                n.hosts,
                n.hosts_with_open,
                n.states.open,
                n.states.filtered,
                w = w
            );
        }
        Self::elided(s, shown, rows.len(), "network");
    }

    fn render_ports(&self, s: &mut String, limit: Option<usize>) {
        let ports = self.interesting_ports();
        if ports.is_empty() {
            return;
        }
        let shown = limit.unwrap_or(ports.len()).min(ports.len());
        let _ = writeln!(s, "\nby port ({}):", plural(ports.len(), "port"));
        let _ = writeln!(s, "  {:<8} {:<16} {}", "port", "service", States::head());
        for (port, p) in &ports[..shown] {
            let _ = writeln!(
                s,
                "  {:<8} {:<16} {}",
                port,
                label(&p.service),
                p.states.cols()
            );
        }
        Self::elided(s, shown, ports.len(), "port");
    }

    fn render_services(&self, s: &mut String, limit: Option<usize>) {
        let svcs = self.services();
        let mut rows: Vec<(&String, &SvcAgg)> = svcs.iter().collect();
        if rows.is_empty() {
            return;
        }
        // Same ranking as ports: a service that is only ever filtered still matters.
        // `sort_by` rather than `sort_by_key`: the latter would clone the name on every
        // comparison just to break ties.
        rows.sort_by(|(an, a), (bn, b)| {
            b.states
                .open
                .cmp(&a.states.open)
                .then(b.states.filtered.cmp(&a.states.filtered))
                .then(an.cmp(bn))
        });
        let shown = limit.unwrap_or(rows.len()).min(rows.len());

        let _ = writeln!(s, "\nby service ({}):", plural(rows.len(), "service"));
        let _ = writeln!(s, "  {:<16} {}  ports", "service", States::head());
        for (name, v) in &rows[..shown] {
            let ports: Vec<String> = v.ports.iter().map(u16::to_string).collect();
            let _ = writeln!(s, "  {:<16} {}  {}", name, v.states.cols(), ports.join(","));
        }
        Self::elided(s, shown, rows.len(), "service");
    }

    fn hosts_json(&self) -> Vec<Value> {
        self.hosts
            .values()
            .map(|h| {
                json!({
                    "host": h.name,
                    "states": h.states.to_json(),
                    "open_ports": h.open_ports.iter().map(|p| json!({
                        "port": p,
                        "service_label": self.service_of(*p),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    fn networks_json(&self) -> Vec<Value> {
        self.networks()
            .into_values()
            .map(|n| {
                json!({
                    "network": n.name,
                    "hosts": n.hosts,
                    "hosts_with_open": n.hosts_with_open,
                    "states": n.states.to_json(),
                })
            })
            .collect()
    }

    fn ports_json(&self) -> Vec<Value> {
        self.ports
            .iter()
            .map(|(port, p)| {
                json!({
                    "port": port,
                    "service_label": self.service_of(*port),
                    "states": p.states.to_json(),
                })
            })
            .collect()
    }

    fn services_json(&self) -> Vec<Value> {
        self.services()
            .into_iter()
            .map(|(name, v)| {
                json!({ "service": name, "ports": v.ports, "states": v.states.to_json() })
            })
            .collect()
    }

    fn to_json(&self, by: Option<Grouping>) -> Value {
        let show = |g: Grouping| by.is_none_or(|b| b == g);

        let mut v = json!({
            "file": self.path,
            // The identity the text render prints in its `started` line. Without it a
            // consumer comparing two summaries cannot say when either scan ran or which
            // build produced it.
            // `Value`'s `Index` already yields `Null` for a missing key.
            "started": self.header["ts"].clone(),
            "tool_version": self.header["tool_version"].clone(),
            "scan_id": self.header["scan_id"].clone(),
            "scan": self.config.clone().unwrap_or(Value::Null),
            "terminal": self.terminal.clone().unwrap_or(Value::Null),
            "unreadable_ports": self.unreadable,
            "unrecognized_states": self.unknown_state,
        });
        // `--by` narrows JSON exactly as it narrows the table, and each section is built
        // only if it will be emitted: `--by port --json` on a /16
        // was materialising 65,536 host objects and two roll-up maps to discard them.
        // `Value::Array` moves the vector; `json!(v)` would re-serialise it whole.
        let m = v.as_object_mut().expect("just built an object");
        if show(Grouping::Host) {
            m.insert("hosts".into(), Value::Array(self.hosts_json()));
        }
        if show(Grouping::Network) {
            m.insert("networks".into(), Value::Array(self.networks_json()));
        }
        if show(Grouping::Port) {
            m.insert("ports".into(), Value::Array(self.ports_json()));
        }
        if show(Grouping::Service) {
            m.insert("services".into(), Value::Array(self.services_json()));
        }
        v
    }
}

/// A filter over the results in a record.
///
/// An empty field matches everything, so `get` with no flags is every result.
#[derive(Default)]
pub struct Query {
    pub hosts: Vec<TargetSpec>,
    pub ports: BTreeSet<u16>,
    pub states: BTreeSet<String>,
}

impl Query {
    fn wants(&self, target: &str, port: u16, state: &str) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| h.matches(target)))
            && (self.ports.is_empty() || self.ports.contains(&port))
            && (self.states.is_empty() || self.states.contains(state))
    }
}

/// One matching result.
pub struct Hit {
    pub target: String,
    pub port: u16,
    pub state: String,
    pub source: String,
    pub reason: Option<String>,
    pub service: Option<String>,
    /// Which pool member produced it, when the transport was a pool.
    pub via: Option<String>,
    /// Reconstructed from a `probe_span`, so it has no per-probe timing or timestamp.
    pub collapsed: bool,
    pub total_ms: Option<f64>,
    /// What the probe learned beyond the verdict — `banner`/`banner_hex`/`banner_bytes`
    /// and `tls` — carried through as recorded. `results --format json` dropped these,
    /// so the one reader built for other tools hid exactly the fields those tools want.
    pub extras: Option<Value>,
}

impl Hit {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "target": self.target,
            "port": self.port,
            "protocol": "tcp",
            "state": self.state,
            "source": self.source,
            "reason": self.reason,
            "service_label": self.service,
        });
        if let Some(member) = &self.via {
            v["via"] = json!(member);
        }
        // Marked rather than silently absent: a consumer that sees no timing should know
        // whether the probe was fast or the detail was collapsed away.
        if self.collapsed {
            v["collapsed"] = json!(true);
        } else {
            v["timing_ms"] = json!({ "total": self.total_ms });
        }
        if let Some(Value::Object(extras)) = &self.extras {
            for (k, val) in extras {
                v[k] = val.clone();
            }
        }
        v
    }
}

/// The evidence fields of a `probe_result` row, when it has any.
fn row_extras(e: &Value) -> Option<Value> {
    let mut out = serde_json::Map::new();
    for k in ["banner", "banner_hex", "banner_bytes", "tls"] {
        if let Some(val) = e.get(k) {
            out.insert(k.into(), val.clone());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

/// What one pass over a record yields besides its results.
///
/// Returned so a caller needing both the framing events and the results pays for a
/// single decode. `summarize` used to make two full passes over the file — on a 374 MB
/// record that is a second decompress and reparse of every line, to re-find three
/// events this pass already saw.
#[derive(Default)]
struct RecordScan {
    header: Option<Value>,
    config: Option<Value>,
    terminal: Option<Value>,
    unreadable: u64,
}

/// One probe result, whether it had a row of its own or came out of a span.
struct ResultRow<'a> {
    target: &'a str,
    port: u16,
    state: &'a str,
    source: &'a str,
    reason: Option<&'a str>,
    service: Option<&'a str>,
    via: Option<&'a str>,
    collapsed: bool,
    total_ms: Option<f64>,
    extras: Option<Value>,
}

/// The permutation a v2 record's span indices must be run through, if any.
///
/// `None` means the ranges are already matrix indices, which is what version 1 wrote.
///
/// Pair scans are *not* an exception: `run` builds the permutation unconditionally and
/// indexes the pair list with the permuted value, so a pair scan's counter index needs the
/// same round trip as a matrix scan's. Only the final step differs — the permuted value
/// indexes `targets.pairs` directly instead of being divided by the port count.
fn span_permutation(cfg: &Value, scan: &RecordScan) -> Option<Permutation> {
    let version = scan
        .header
        .as_ref()
        .and_then(|h| h["schema_version"].as_u64())
        .unwrap_or(1);
    if version < 2 {
        return None;
    }
    let planned = cfg["probes_planned"].as_u64()?;
    let seed = cfg["permutation"]["seed"].as_str()?;
    let seed = u64::from_str_radix(seed, 16).ok()?;
    Some(Permutation::new(planned.max(1), seed))
}

/// Walk every probe result in a record — rows and span-expanded alike.
///
/// The shared spine of `results` and `summarize`, and the reason either can be trusted:
/// with collapsing on by default a `closed` result usually has no row of its own, so
/// `jq` over `probe_result` sees only a fraction of the scan and this sees all of it.
///
/// Callback-driven rather than returning a `Vec` so a caller that only needs counters
/// never materialises the results. That is what lets `summarize` fold a /16 into hosts
/// plus ports instead of holding 65 million rows.
fn walk_results(path: &Path, mut f: impl FnMut(ResultRow<'_>)) -> Result<RecordScan, String> {
    let mut scan = RecordScan::default();
    let mut expected: Option<Expected> = None;
    // v2 records write span ranges in counter space, so expanding one means undoing the
    // permutation. v1 wrote permuted indices directly. Both are readable; which applies is
    // decided by the record, not by this build.
    let mut unpermute: Option<Option<Permutation>> = None;

    for line in stream(path)? {
        let line = line?;
        let Some(e) = line.event else { continue };
        if line.index == 0 {
            scan.header = Some(e.clone());
        }
        let k = kind(&e);
        if TERMINALS.contains(&k) && scan.terminal.is_none() {
            scan.terminal = Some(e.clone());
        }
        match k {
            "scan_config" if scan.config.is_none() => scan.config = Some(e),
            "probe_result" => {
                let Some(st) = e["state"].as_str() else {
                    continue;
                };
                let Some(t) = e["target"].as_str() else {
                    continue;
                };
                // A port the record states but this build cannot express. Counted rather
                // than dropped: a section that silently omits rows leaves a totals line
                // with nothing to support it, and no way to tell that from a quiet scan.
                let Some(p) = e["port"].as_u64().and_then(|p| u16::try_from(p).ok()) else {
                    scan.unreadable += 1;
                    continue;
                };
                f(ResultRow {
                    target: t,
                    port: p,
                    state: st,
                    source: e["source"].as_str().unwrap_or(""),
                    reason: e["reason"].as_str(),
                    service: e["service_label"].as_str(),
                    via: e["via"].as_str(),
                    collapsed: false,
                    total_ms: e["timing_ms"]["total"].as_f64(),
                    extras: row_extras(&e),
                });
            }
            "probe_span" => {
                let Some(state) = e["state"].as_str() else {
                    continue;
                };
                // Only pay for expansion once, and only if a span is actually present.
                if expected.is_none() {
                    let cfg = scan.config.as_ref().ok_or_else(|| {
                        format!("{} has a probe_span before its scan_config", path.display())
                    })?;
                    expected = Some(expected_endpoints(cfg, path)?);
                    unpermute = Some(span_permutation(cfg, &scan));
                }
                let exp = expected.as_ref().expect("just built");
                let perm = unpermute.as_ref().expect("just built").as_ref();
                let source = e["source"].as_str().unwrap_or("");
                let reason = e["reason"].as_str();
                let stride = exp.stride();
                // The target is constant across each run of `stride` indices; formatting
                // it per probe made expanding a 65M-probe record almost entirely
                // `IpAddr::to_string`.
                let mut cached: Option<(u64, String)> = None;
                for r in e["probe_indices"].as_array().into_iter().flatten() {
                    let (Some(a), Some(b)) = (r[0].as_u64(), r[1].as_u64()) else {
                        continue;
                    };
                    for raw in a..=b {
                        // Counter index in, matrix index out.
                        let i = perm.map_or(raw, |p| p.apply(raw));
                        let slot = i / stride;
                        if cached.as_ref().is_none_or(|(s, _)| *s != slot) {
                            let Some((name, _)) = exp.at(i) else { continue };
                            cached = Some((slot, name));
                        }
                        let Some(p) = exp.port_at(i) else { continue };
                        let t = &cached.as_ref().expect("just set").1;
                        f(ResultRow {
                            target: t,
                            port: p,
                            state,
                            source,
                            reason,
                            service: crate::services::service_label(p),
                            // Spans carry it too, now that it is part of their key.
                            via: e["via"].as_str(),
                            collapsed: true,
                            total_ms: None,
                            extras: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(scan)
}

/// Query the results in a record.
///
/// Reads rows *and* expands spans, which is the whole point: with collapsing on by
/// default a `closed` result usually has no row of its own, so `jq` over `probe_result`
/// cannot answer "what was 10.0.0.5:443?" and this can.
///
/// Streams. Memory is the matches plus, for a matrix scan containing spans, the expanded
/// target list needed to turn a span index back into an endpoint.
pub fn get(path: &Path, q: &Query) -> Result<Vec<Hit>, String> {
    let mut hits = Vec::new();
    walk_results(path, |r| {
        if q.wants(r.target, r.port, r.state) {
            hits.push(Hit {
                target: r.target.to_string(),
                port: r.port,
                state: r.state.to_string(),
                source: r.source.to_string(),
                reason: r.reason.map(str::to_string),
                service: r.service.map(str::to_string),
                via: r.via.map(str::to_string),
                collapsed: r.collapsed,
                total_ms: r.total_ms,
                extras: r.extras,
            });
        }
    })?;

    hits.sort_by(|a, b| {
        host_key(&a.target)
            .cmp(&host_key(&b.target))
            .then(a.port.cmp(&b.port))
    });
    Ok(hits)
}

/// The line `remainder` prints to stderr.
///
/// A complete scan used to be told to "re-run exactly those with:" and handed a pipeline
/// that would have probed nothing — a suggestion is only useful when there is something
/// to act on.
fn remainder_note(outstanding: usize, planned: u64, path: &Path) -> String {
    if outstanding == 0 {
        return format!(
            "all {} endpoints were probed; nothing to re-run",
            commas(planned)
        );
    }
    format!(
        "{} of {} endpoints were not probed; re-run exactly those with:\n  \
         scanr output remainder {} | scanr run --pairs -",
        commas(outstanding as u64),
        commas(planned),
        path.display()
    )
}

/// A shape for handing results to another tool.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Handoff {
    /// One JSON object per result.
    Json,
    /// `host:port` per line — what `httpx`, `tlsx` and `nuclei` all read from stdin.
    List,
    /// Runnable `nmap -sV` commands.
    Nmap,
}

impl Handoff {
    /// Whether this shape is meant to be piped into another scanner.
    ///
    /// Lives beside the shapes rather than at the call site, so a second caller of
    /// `handoff` inherits the "you probably wanted --states open" warning instead of
    /// having to remember it. `Json` is data, and filtering it is the reader's business.
    pub fn feeds_a_tool(self) -> bool {
        matches!(self, Handoff::Nmap | Handoff::List)
    }
}

/// Write results for another tool to consume.
///
/// Streams to the sink rather than returning a `String`: `get` already holds every
/// matching row, and buffering the rendered form beside it doubled that for no gain —
/// a locked stdout flushes per line anyway.
///
/// The point of this is division of labour, not completeness. `scanr` is good at finding
/// open ports quickly through a proxy; `nmap -sV` is good at saying what is behind them,
/// on the strength of a signature database two decades deep. Handing it the ~0.1% of
/// endpoints that answered is far faster than letting it scan everything, and far better
/// than reimplementing its database badly (D32).
pub fn handoff(hits: &[Hit], how: Handoff, out: &mut impl std::io::Write) -> std::io::Result<()> {
    match how {
        Handoff::Json => {
            for h in hits {
                writeln!(out, "{}", h.to_json())?;
            }
        }
        Handoff::List => {
            for h in hits {
                writeln!(out, "{}", format_pair(&h.target, h.port))?;
            }
        }
        Handoff::Nmap => {
            // Grouped by the exact set of ports found on a host, so no host is offered a
            // port that was never open on it. One command per distinct set — on a real
            // sweep that is a handful, because hosts of a kind look alike.
            let mut by_ports: BTreeMap<Vec<u16>, Vec<&str>> = BTreeMap::new();
            let mut hosts: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
            for h in hits {
                hosts.entry(h.target.as_str()).or_default().push(h.port);
            }
            for (host, mut ports) in hosts {
                ports.sort_unstable();
                ports.dedup();
                by_ports.entry(ports).or_default().push(host);
            }
            for (ports, mut group) in by_ports {
                group.sort_by_key(|h| host_key(h));
                let p: Vec<String> = ports.iter().map(u16::to_string).collect();
                // -Pn because scanr already established these are up; -n because it
                // already resolved them. Both stop nmap redoing finished work.
                writeln!(
                    out,
                    "nmap -sV -Pn -n -p {} {}",
                    p.join(","),
                    group.join(" ")
                )?;
            }
        }
    }
    Ok(())
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
    // Cheap rejection first, and only where it is cheap. An uncompressed record can be
    // seeked, so a file with no hint — an older record, or a scan too large to have
    // tracked one — costs a 64 KiB tail read rather than a full pass before falling back.
    // A gzip stream cannot be seeked into, so there the digest below is the first look.
    if !is_gzip(path) && read_last_event(path).is_none_or(|e| e["not_started_from"].is_null()) {
        return Ok(None);
    }

    let digest = Digest::read(path)?;
    let Some(terminal) = digest.terminal.filter(|e| TERMINALS.contains(&kind(e))) else {
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
    if digest.probes != completed {
        return Ok(None);
    }

    let Some(config) = digest.config else {
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

    let note = remainder_note(endpoints.len(), planned, path);
    Ok(Some(Remainder {
        endpoints,
        scan_id: config["scan_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        note,
    }))
}

/// The config event, the last event, and how many probes the record accounts for —
/// gathered in a single pass.
///
/// Previously three: a tail read for the terminal event, a full scan to count rows, and
/// a third open for the header. On an uncompressed record two of those were cheap; on a
/// gzip one — which is now the default — each meant decompressing the whole file.
struct Digest {
    config: Option<Value>,
    terminal: Option<Value>,
    /// `probe_result` rows plus the probes covered by `probe_span` events. A collapsed
    /// probe is still a probe the record accounts for.
    probes: u64,
}

impl Digest {
    fn read(path: &Path) -> Result<Self, String> {
        const ROW: &str = "\"type\":\"probe_result\"";
        const SPAN: &str = "\"type\":\"probe_span\"";
        const CONFIG: &str = "\"type\":\"scan_config\"";

        let mut d = Self {
            config: None,
            terminal: None,
            probes: 0,
        };
        let truncation_expected = is_partial(path);
        let mut last: Option<String> = None;
        let mut seen = 0usize;

        for line in open_record(path)?.lines() {
            let text = match line {
                Ok(t) => t,
                // Mirrors `stream`: a `.partial` file is expected to stop mid-way, and
                // anything else means the count cannot be vouched for.
                Err(_) if truncation_expected && seen > 0 => break,
                Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
            };
            if text.trim().is_empty() {
                continue;
            }
            seen += 1;
            // Substring tests rather than parsing: only spans and the two singleton
            // events need their fields, and the rows are the overwhelming majority.
            if text.contains(ROW) {
                d.probes += 1;
            } else if text.contains(SPAN) {
                d.probes += serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v["count"].as_u64())
                    .unwrap_or(0);
            } else if d.config.is_none() && text.contains(CONFIG) {
                d.config = serde_json::from_str(&text).ok();
            }
            last = Some(text);
        }

        d.terminal = last.and_then(|l| serde_json::from_str(&l).ok());
        Ok(d)
    }
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

    let note = remainder_note(endpoints.len(), planned as u64, path);
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

    /// How many consecutive indices share one target.
    ///
    /// A span expands a *contiguous* range of indices, and a matrix scan lays them out
    /// target-major, so every `stride` indices name the same host. A caller walking a
    /// range can format that host once instead of once per probe — on a 1,000-port scan
    /// that is 999 of every 1,000 allocations avoided.
    fn stride(&self) -> u64 {
        match self {
            Expected::Pairs(_) => 1,
            Expected::Matrix { ports, .. } => (ports.len() as u64).max(1),
        }
    }

    /// The port at an index, without formatting the target.
    fn port_at(&self, index: u64) -> Option<u16> {
        match self {
            Expected::Pairs(p) => p.get(index as usize).map(|(_, port)| *port),
            Expected::Matrix { ports, .. } => {
                let per = ports.len() as u64;
                (per > 0)
                    .then(|| ports.get((index % per) as usize).copied())
                    .flatten()
            }
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

    /// Plain, uncoloured output: these assert on text, not on escape sequences.
    fn st() -> Style {
        Style::for_stream(false, true)
    }
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

    /// A version 2 record whose seed is missing or unparseable cannot have its spans
    /// expanded, and the failure mode is silent: without this check the reader falls back
    /// to treating counter indices as matrix indices and emits the right *number* of
    /// well-formed endpoints, every one of them wrong.
    #[test]
    fn a_v2_span_without_a_usable_seed_is_reported() {
        let d = tempfile::tempdir().unwrap();
        for (label, seed) in [("missing", None), ("unparseable", Some("not-hex"))] {
            let mut events = good_events();
            events[0]["schema_version"] = json!(2);
            match seed {
                Some(v) => events[1]["permutation"]["seed"] = json!(v),
                None => {
                    events[1]["permutation"] = json!({});
                }
            }
            // Replace the four rows with one span covering them.
            events.splice(
                2..6,
                [json!({"type":"probe_span","seq":2,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1",
                        "state":"closed","source":"local_stack","protocol":"tcp","attempts":1,
                        "count":4,"probe_indices":[[0,3]],
                        "timing_ms":{"min":1.0,"mean":1.0,"max":1.0}})],
            );
            events[3]["counts"] = json!({"planned":4,"started":4,"completed":4,"not_started":0,
                                         "open":0,"closed":4,"filtered":0,"error":0,"retried":0});
            let p = write(d.path(), &format!("seed-{label}.jsonl"), &events);
            let r = verify(&p).unwrap();
            assert!(
                r.problems.iter().any(|p| p.contains("permutation seed")),
                "{label} seed went unreported: {:?}",
                r.problems
            );
        }
    }

    /// ...and the same record with a good seed must stay clean, or the check above is
    /// just firing on every spanned record.
    #[test]
    fn a_v2_span_with_a_usable_seed_is_accepted() {
        let d = tempfile::tempdir().unwrap();
        let mut events = good_events();
        events[0]["schema_version"] = json!(2);
        events.splice(
            2..6,
            [
                json!({"type":"probe_span","seq":2,"ts":"2026-07-30T12:00:00.000Z","scan_id":"a1",
                    "state":"closed","source":"local_stack","protocol":"tcp","attempts":1,
                    "count":4,"probe_indices":[[0,3]],
                    "timing_ms":{"min":1.0,"mean":1.0,"max":1.0}}),
            ],
        );
        events[3]["counts"] = json!({"planned":4,"started":4,"completed":4,"not_started":0,
                                     "open":0,"closed":4,"filtered":0,"error":0,"retried":0});
        let p = write(d.path(), "seed-ok.jsonl", &events);
        let r = verify(&p).unwrap();
        assert!(r.problems.is_empty(), "{:?}", r.problems);
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
        // A complete scan is told so, not handed a pipeline that would probe nothing.
        assert!(
            r.note.starts_with("all 4 endpoints were probed"),
            "{}",
            r.note
        );
        assert!(
            !r.note.contains("--pairs"),
            "no directive to run: {}",
            r.note
        );
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
            summarize(&p, None, false, &st()).err(),
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
    fn summarize_reports_scan_totals_and_the_open_port() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "s.jsonl", &good_events());
        let out = summarize(&p, None, false, &st()).unwrap();
        assert!(
            out.contains("1 open, 1 closed, 1 filtered, 1 error"),
            "{out}"
        );
        // The open port is reachable from the per-host row rather than a separate list.
        let line = out
            .lines()
            .find(|l| l.contains("10.0.0.0"))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(line.contains("80/http"), "{line}");
    }

    fn multi_host_record() -> Vec<Value> {
        let mut e = vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-31T12:00:00.000Z","scan_id":"g1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-31T12:00:00.000Z","scan_id":"g1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/28"],"exclude":[],"count":16,"mode":"matrix"},
                   "ports":{"spec":"22,80","count":2},"probes_planned":32}),
        ];
        // Deliberately out of order, and including .2 and .10 so the sort is visible.
        let rows = [
            ("10.0.0.10", 22, "ssh"),
            ("10.0.0.2", 80, "http"),
            ("10.0.0.2", 22, "ssh"),
            ("10.0.0.9", 80, "http"),
        ];
        for (i, (t, p, svc)) in rows.iter().enumerate() {
            e.push(json!({"type":"probe_result","seq":2+i,"ts":"2026-07-31T12:00:00.000Z","scan_id":"g1",
                   "probe_index":i,"target":t,"port":p,"protocol":"tcp","state":"open",
                   "source":"local_stack","service_label":svc,"attempts":1,
                   "attempt_states":["open"],"timing_ms":{"total":1.0}}));
        }
        e.push(
            json!({"type":"scan_completed","seq":9,"ts":"2026-07-31T12:00:01.000Z","scan_id":"g1",
               "termination":"natural",
               "counts":{"planned":32,"started":32,"completed":4,"abandoned":0,"not_started":28,
                         "open":4,"closed":0,"filtered":0,"error":0,"retried":0}}),
        );
        e
    }

    /// Mixed states across several prefixes — what a real sweep looks like, and what
    /// `multi_host_record` is not: that fixture is four `open` rows, so it could not
    /// exercise a single one of the counts this section exists to report.
    fn mixed_states_record() -> Vec<Value> {
        let mut e = vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-31T12:00:00.000Z","scan_id":"m1",
                   "schema_version":1,"tool_version":"0.1.0"}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-31T12:00:00.000Z","scan_id":"m1","scan_name":"s",
                   "transport":{"name":"office-proxy","type":"socks5","measured_fidelity":"full"},
                   "targets":{"spec":["x"],"exclude":[],"count":4,"mode":"matrix"},
                   "ports":{"spec":"80,445","count":2},"probes_planned":8}),
        ];
        // Prefixes deliberately out of numeric order, and 445 is *never* open — the
        // case that used to vanish from the port and service sections entirely.
        let hosts = ["2.2.2.2", "9.0.0.1", "10.0.0.1", "192.168.1.1"];
        let mut seq = 2;
        for h in hosts {
            for (port, state, svc) in [(80, "open", "http"), (445, "filtered", "microsoft-ds")] {
                e.push(
                    json!({"type":"probe_result","seq":seq,"ts":"2026-07-31T12:00:00.000Z",
                       "scan_id":"m1","probe_index":seq,"target":h,"port":port,"protocol":"tcp",
                       "state":state,"source":"local_stack","service_label":svc,"attempts":1,
                       "attempt_states":[state],"timing_ms":{"total":1.0}}),
                );
                seq += 1;
            }
        }
        e.push(
            json!({"type":"scan_completed","seq":seq,"ts":"2026-07-31T12:00:01.000Z","scan_id":"m1",
               "termination":"natural","duration_ms":10,
               "counts":{"planned":8,"started":8,"completed":8,"abandoned":0,"not_started":0,
                         "open":4,"closed":0,"filtered":4,"error":0,"retried":0}}),
        );
        e
    }

    /// The headline claim of the aggregate rewrite, and the one thing the first version
    /// got wrong: a port that is only ever *filtered* must still appear. Filtering the
    /// section to `open > 0` made "445 was filtered on every host" invisible — the exact
    /// question the section was written to answer.
    #[test]
    fn a_port_that_was_never_open_is_still_reported() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "m.jsonl", &mixed_states_record());
        let out = summarize(&p, None, false, &st()).unwrap();

        let port = out
            .lines()
            .find(|l| l.trim_start().starts_with("445"))
            .unwrap_or_else(|| panic!("445 missing from:\n{out}"));
        assert!(port.contains("microsoft-ds"), "{port}");
        let svc = out
            .lines()
            .find(|l| l.trim_start().starts_with("microsoft-ds"))
            .unwrap_or_else(|| panic!("service row missing from:\n{out}"));
        assert!(svc.contains("445"), "{svc}");
    }

    /// The defect `host_key` exists to prevent, reintroduced one section lower down.
    #[test]
    fn networks_sort_numerically_like_hosts() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "m.jsonl", &mixed_states_record());
        let out = summarize(&p, Some(Grouping::Network), false, &st()).unwrap();
        let order: Vec<usize> = ["2.2.2.0/24", "9.0.0.0/24", "10.0.0.0/24", "192.168.1.0/24"]
            .iter()
            .map(|n| {
                out.find(n)
                    .unwrap_or_else(|| panic!("{n} missing from {out}"))
            })
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "prefixes out of numeric order:\n{out}"
        );
    }

    #[test]
    fn the_transport_reads_name_then_type() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "m.jsonl", &mixed_states_record());
        let out = summarize(&p, Some(Grouping::Scan), false, &st()).unwrap();
        // `office-proxy via socks5`, not `socks5 via office-proxy` — the named transport
        // is the thing being used, not the medium.
        assert!(out.contains("office-proxy via socks5"), "{out}");
    }

    /// A row the record states with a port this build cannot express reached no section,
    /// leaving a totals line with nothing under it and no way to tell that from a quiet
    /// scan.
    #[test]
    fn an_unusable_port_is_noted_rather_than_silently_dropped() {
        let d = tempfile::tempdir().unwrap();
        let mut ev = mixed_states_record();
        for e in ev.iter_mut() {
            if e["type"] == "probe_result" && e["port"] == 80 && e["target"] == "2.2.2.2" {
                e["port"] = json!(65616);
            }
        }
        let p = write(d.path(), "m.jsonl", &ev);
        let out = summarize(&p, None, false, &st()).unwrap();
        assert!(out.contains("1 result(s) had an unusable port"), "{out}");
    }

    /// `verify` judges a record; `summarize` reports one. Counting an unknown state as
    /// `error` had the host table claiming errors the terminal event said never happened.
    #[test]
    fn an_unrecognised_state_is_not_counted_as_an_error() {
        let d = tempfile::tempdir().unwrap();
        let mut ev = mixed_states_record();
        for e in ev.iter_mut() {
            if e["type"] == "probe_result" && e["state"] == "filtered" {
                e["state"] = json!("banana");
            }
        }
        let p = write(d.path(), "m.jsonl", &ev);
        let out = summarize(&p, None, false, &st()).unwrap();
        assert!(out.contains("4 result(s) had a state"), "{out}");
        let host = out
            .lines()
            .find(|l| l.contains("2.2.2.2"))
            .unwrap_or_else(|| panic!("{out}"));
        let nums: Vec<&str> = host.split_whitespace().skip(1).take(4).collect();
        assert_eq!(nums[3], "0", "error column must stay 0 on {host}");
    }

    #[test]
    fn json_honours_by_the_same_way_the_table_does() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "m.jsonl", &mixed_states_record());
        let narrowed: Value = serde_json::from_str(
            summarize(&p, Some(Grouping::Port), true, &st())
                .unwrap()
                .trim(),
        )
        .expect("valid JSON");
        assert!(narrowed.get("ports").is_some(), "{narrowed}");
        for absent in ["hosts", "networks", "services"] {
            assert!(
                narrowed.get(absent).is_none(),
                "--by port should not emit `{absent}`: {narrowed}"
            );
        }
        // ...and the identity fields travel regardless, so two summaries are comparable.
        assert_eq!(narrowed["scan_id"], "m1");
        assert_eq!(narrowed["tool_version"], "0.1.0");
    }

    /// Spans are the default shape, and every non-open result in one has no row. If
    /// `summarize` did not expand them its per-host counts would be nearly all zero —
    /// untested until now, which is how a missing service-label table shipped.
    #[test]
    fn summarize_expands_spans_like_results_does() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "sp.jsonl", &spanned_record());
        let out = summarize(&p, None, false, &st()).unwrap();

        // The fixture is one open row plus seven collapsed `closed` probes over 4 hosts.
        // Scoped to the host section: `10.0.0.0/24` in the network table below it starts
        // with the same text and its third column means something else entirely.
        let host_section = out
            .split("by host")
            .nth(1)
            .and_then(|s| s.split("\nby ").next())
            .unwrap_or_else(|| panic!("no host section in:\n{out}"));
        let closed: u64 = host_section
            .lines()
            .filter(|l| l.trim_start().starts_with("10.0.0."))
            .filter_map(|l| l.split_whitespace().nth(2))
            .filter_map(|n| n.parse::<u64>().ok())
            .sum();
        assert_eq!(closed, 7, "collapsed probes must be counted:\n{out}");

        // And the labels come from the table, not from the span, which carries none.
        assert!(host_section.contains("22/ssh"), "{out}");
    }

    /// Sorting the formatted strings put `10.0.0.10` before `10.0.0.2`, which reads as a
    /// bug in the scan rather than in the sort.
    #[test]
    fn hosts_sort_numerically_not_lexicographically() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, Some(Grouping::Host), false, &st()).unwrap();
        let order: Vec<usize> = ["10.0.0.2", "10.0.0.9", "10.0.0.10"]
            .iter()
            .map(|h| {
                out.find(h)
                    .unwrap_or_else(|| panic!("{h} missing from {out}"))
            })
            .collect();
        assert!(
            order[0] < order[1] && order[1] < order[2],
            "hosts out of numeric order:\n{out}"
        );
    }

    /// The point of the rewrite: a per-host row carries counts for *every* state, not
    /// just a list of the open ones. The old `--by host` could not have answered this.
    #[test]
    fn by_host_counts_every_state_not_only_open() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, Some(Grouping::Host), false, &st()).unwrap();
        assert!(out.contains("by host (3 hosts)"), "{out}");

        let line = out
            .lines()
            .find(|l| l.contains("10.0.0.2"))
            .unwrap_or_else(|| panic!("{out}"));
        // Two open, and the closed probe on the same host counted beside them.
        assert!(
            line.contains("22/ssh") && line.contains("80/http"),
            "{line}"
        );
        assert!(line.find("22/ssh") < line.find("80/http"), "{line}");
        let nums: Vec<&str> = line.split_whitespace().skip(1).take(4).collect();
        assert_eq!(nums[0], "2", "open count on {line}");
    }

    #[test]
    fn by_network_rolls_hosts_up_into_prefixes() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, Some(Grouping::Network), false, &st()).unwrap();
        assert!(out.contains("by network"), "{out}");
        let line = out
            .lines()
            .find(|l| l.contains("10.0.0.0/24"))
            .unwrap_or_else(|| panic!("{out}"));
        // Three hosts in the prefix, all three with something open.
        let nums: Vec<&str> = line.split_whitespace().skip(1).take(3).collect();
        assert_eq!(nums[0], "3", "host count on {line}");
        assert_eq!(nums[1], "3", "with-open on {line}");
    }

    #[test]
    fn by_port_counts_hosts_per_port() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, Some(Grouping::Port), false, &st()).unwrap();
        assert!(out.contains("by port"), "{out}");
        let http = out
            .lines()
            .find(|l| l.trim_start().starts_with("80 "))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(http.contains("http"), "{http}");
    }

    #[test]
    fn by_service_gathers_ports_under_one_label() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, Some(Grouping::Service), false, &st()).unwrap();
        assert!(out.contains("by service"), "{out}");
        let ssh = out
            .lines()
            .find(|l| l.trim_start().starts_with("ssh"))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(ssh.contains("22"), "{ssh}");
    }

    /// With no `--by`, every section is present — the first look at a record should not
    /// require knowing which question to ask.
    #[test]
    fn no_grouping_shows_all_the_sections() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, None, false, &st()).unwrap();
        for section in ["by host", "by network", "by port", "by service"] {
            assert!(out.contains(section), "{section} missing from:\n{out}");
        }
        // ...and `--by` narrows to exactly one of them.
        let only = summarize(&p, Some(Grouping::Network), false, &st()).unwrap();
        assert!(only.contains("by network"), "{only}");
        assert!(!only.contains("by host"), "{only}");
    }

    #[test]
    fn json_carries_the_same_aggregates() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "g.jsonl", &multi_host_record());
        let out = summarize(&p, None, true, &st()).unwrap();
        let v: Value = serde_json::from_str(out.trim()).expect("summarize --json must parse");
        assert_eq!(v["hosts"].as_array().unwrap().len(), 3);
        assert_eq!(v["networks"][0]["network"], "10.0.0.0/24");
        assert_eq!(v["networks"][0]["hosts"], 3);
        let ssh = v["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["service"] == "ssh")
            .expect("an ssh service entry");
        assert_eq!(ssh["ports"][0], 22);
    }

    /// `handoff` writes to a sink; the tests want the text.
    fn rendered(hits: &[Hit], how: Handoff) -> String {
        let mut buf = Vec::new();
        handoff(hits, how, &mut buf).expect("a Vec sink cannot fail");
        String::from_utf8(buf).expect("handoff output is UTF-8")
    }

    fn hit(target: &str, port: u16, state: &str) -> Hit {
        Hit {
            target: target.into(),
            port,
            state: state.into(),
            source: "local_stack".into(),
            reason: None,
            service: None,
            via: None,
            collapsed: false,
            extras: None,
            total_ms: Some(1.0),
        }
    }

    /// One command per distinct port set, so no host is offered a port that was never
    /// open on it — the whole reason to hand off precisely rather than a union.
    #[test]
    fn the_nmap_handoff_groups_hosts_by_their_open_ports() {
        let hits = vec![
            hit("10.0.0.2", 22, "open"),
            hit("10.0.0.2", 80, "open"),
            hit("10.0.0.9", 22, "open"),
            hit("10.0.0.10", 22, "open"),
            hit("10.0.0.10", 80, "open"),
        ];
        let out = rendered(&hits, Handoff::Nmap);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "two distinct port sets: {out}");
        assert!(
            lines.iter().any(|l| l.contains("-p 22 10.0.0.9")),
            "the single-port host on its own: {out}"
        );
        let pair = lines
            .iter()
            .find(|l| l.contains("-p 22,80"))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(
            pair.contains("10.0.0.2") && pair.contains("10.0.0.10"),
            "{pair}"
        );
        // -Pn and -n stop nmap redoing work scanr already did.
        assert!(pair.contains("-sV -Pn -n"), "{pair}");
    }

    #[test]
    fn the_list_handoff_is_one_endpoint_per_line() {
        let hits = vec![hit("10.0.0.2", 443, "open"), hit("::1", 22, "open")];
        let out = rendered(&hits, Handoff::List);
        assert_eq!(out, "10.0.0.2:443\n[::1]:22\n", "IPv6 must be bracketed");
    }

    #[test]
    fn an_unknown_grouping_is_rejected() {
        assert!(Grouping::parse("hosts").is_none());
        // Every name the CLI advertises must parse, or `--by` rejects its own help text.
        for name in Grouping::ALL {
            assert!(
                Grouping::parse(name).is_some(),
                "`{name}` is advertised but unparseable"
            );
        }
    }

    /// A record whose `closed` results live only in a span — the default shape. The
    /// point of `results` is that they are still findable.
    fn spanned_record() -> Vec<Value> {
        vec![
            json!({"type":"scan_started","seq":0,"ts":"2026-07-31T12:00:00.000Z","scan_id":"q1","schema_version":1}),
            json!({"type":"scan_config","seq":1,"ts":"2026-07-31T12:00:00.000Z","scan_id":"q1","scan_name":"s",
                   "targets":{"spec":["10.0.0.0/30"],"exclude":[],"count":4,"mode":"matrix"},
                   "ports":{"spec":"22,80","count":2},"probes_planned":8}),
            // Index 0 = 10.0.0.0:22, open, with its own row.
            json!({"type":"probe_result","seq":2,"ts":"2026-07-31T12:00:00.000Z","scan_id":"q1",
                   "probe_index":0,"target":"10.0.0.0","port":22,"protocol":"tcp","state":"open",
                   "source":"local_stack","service_label":"ssh","attempts":1,
                   "attempt_states":["open"],"timing_ms":{"total":1.5}}),
            // Indices 1..=7 collapsed: no rows at all.
            json!({"type":"probe_span","seq":3,"ts":"2026-07-31T12:00:00.000Z","scan_id":"q1",
                   "state":"closed","source":"local_stack","reason":"connection refused",
                   "protocol":"tcp","attempts":1,"count":7,"probe_indices":[[1,7]],
                   "timing_ms":{"min":0.1,"mean":0.2,"max":0.3}}),
            json!({"type":"scan_completed","seq":4,"ts":"2026-07-31T12:00:01.000Z","scan_id":"q1",
                   "termination":"natural",
                   "counts":{"planned":8,"started":8,"completed":8,"abandoned":0,"not_started":0,
                             "open":1,"closed":7,"filtered":0,"error":0,"retried":0}}),
        ]
    }

    #[test]
    fn get_finds_results_that_only_exist_inside_a_span() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "q.jsonl", &spanned_record());

        let all = get(&p, &Query::default()).unwrap();
        assert_eq!(all.len(), 8, "every probe, rows and spans alike");

        let closed = get(
            &p,
            &Query {
                states: ["closed".to_string()].into_iter().collect(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(closed.len(), 7, "all seven live in the span");
        assert!(closed.iter().all(|h| h.collapsed));
        assert!(
            closed.iter().all(|h| h.total_ms.is_none()),
            "a collapsed hit has no per-probe timing, and must not invent one"
        );
        // The span's reason survives expansion.
        assert_eq!(closed[0].reason.as_deref(), Some("connection refused"));
    }

    #[test]
    fn get_filters_by_host_port_and_state() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "q.jsonl", &spanned_record());
        let q = |h: &str, ports: &[u16], st: &[&str]| Query {
            hosts: if h.is_empty() {
                vec![]
            } else {
                vec![parse_target(h).unwrap()]
            },
            ports: ports.iter().copied().collect(),
            states: st.iter().map(|s| s.to_string()).collect(),
        };

        // A CIDR filter matches without expanding.
        assert_eq!(get(&p, &q("10.0.0.0/31", &[], &[])).unwrap().len(), 4);
        assert_eq!(get(&p, &q("10.0.0.3", &[], &[])).unwrap().len(), 2);
        assert_eq!(get(&p, &q("", &[22], &[])).unwrap().len(), 4);
        assert_eq!(get(&p, &q("", &[22], &["open"])).unwrap().len(), 1);
        assert_eq!(get(&p, &q("10.0.0.0", &[22], &["open"])).unwrap().len(), 1);
        // A filter that matches nothing is empty, not an error.
        assert!(get(&p, &q("192.0.2.0/24", &[], &[])).unwrap().is_empty());
    }

    #[test]
    fn get_marks_collapsed_hits_in_json() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "q.jsonl", &spanned_record());
        let hits = get(&p, &Query::default()).unwrap();

        let row = hits.iter().find(|h| !h.collapsed).unwrap().to_json();
        assert_eq!(row["timing_ms"]["total"], 1.5);
        assert!(row.get("collapsed").is_none());

        let span = hits.iter().find(|h| h.collapsed).unwrap().to_json();
        assert_eq!(span["collapsed"], true);
        assert!(
            span.get("timing_ms").is_none(),
            "no timing rather than a fabricated one: {span}"
        );
    }

    #[test]
    fn get_returns_results_in_host_then_port_order() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "q.jsonl", &spanned_record());
        let hits = get(&p, &Query::default()).unwrap();
        let seen: Vec<String> = hits
            .iter()
            .map(|h| format!("{}:{}", h.target, h.port))
            .collect();
        let mut sorted = seen.clone();
        sorted.sort_by_key(|s| {
            let (h, p) = s.rsplit_once(':').unwrap();
            (host_key(h), p.parse::<u16>().unwrap())
        });
        assert_eq!(seen, sorted, "{seen:?}");
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
        assert!(summarize(&p, None, false, &st()).is_err());
    }

    #[test]
    fn missing_file_is_a_clean_error() {
        let e = verify(Path::new("/nonexistent/x.jsonl")).unwrap_err();
        assert!(e.contains("cannot read"));
    }
}
