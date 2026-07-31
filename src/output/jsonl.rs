//! The JSONL scan record.
//!
//! Guarantees this writer exists to provide:
//!
//! * `scan_started` first, `scan_config` second, exactly one terminal event last.
//! * `seq` strictly increasing, assigned here so it is monotonic in *write* order
//!   regardless of the order workers finish in (probes are randomized and concurrent).
//! * The file is `.jsonl.partial` until a terminal event is persisted, so a file still
//!   named `.partial` means the process died without finalizing.
//! * Credentials never appear.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::timefmt::{now_epoch_ms, rfc3339_ms};

pub const SCHEMA_VERSION: u32 = 1;
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Events whose loss would make the file uninterpretable are flushed immediately.
///
/// `probe_span` is here because it is the only record that many probes happened at all.
/// The time-based flush cannot cover it: when spans are on, `emit` is called only at
/// progress ticks, so the 250 ms rule — which is checked inside `emit` — never fires
/// between them, and a span written at one tick sat unflushed until the next. A scan
/// killed in between lost every probe it stood for.
fn is_critical(kind: &str) -> bool {
    matches!(
        kind,
        "scan_started"
            | "scan_config"
            | "scan_completed"
            | "scan_interrupted"
            | "scan_failed"
            | "scan_warning"
            | "probe_span"
    )
}

/// Where a record is written. Boxed rather than generic so `JsonlWriter` stays a plain
/// type in every signature that mentions it.
///
/// The indirection costs nothing on the hot path: per-event writes land in the
/// `BufWriter`, so the virtual call happens once per 64 KiB flush rather than once per
/// probe.
type Sink = BufWriter<Box<dyn Write + Send>>;

pub struct JsonlWriter {
    file: Option<Sink>,
    partial_path: PathBuf,
    final_path: PathBuf,
    /// Whether `finalize` should rename. False for an injected sink, which has no file.
    renames: bool,
    scan_id: String,
    seq: u64,
    last_flush: Instant,
    terminal_written: bool,
    error: Option<String>,
}

/// Plaintext accumulated before a gzip member is emitted.
///
/// Large enough that the compressor sees repetition — the whole reason a record
/// compresses ~20x is that consecutive lines are near-identical — and small enough that
/// a killed process loses little.
const FRAME_BYTES: usize = 256 * 1024;

/// Appends gzip members to an inner writer, one per flush or per `FRAME_BYTES` of input.
///
/// Concatenated gzip members are themselves a valid gzip stream, so `zcat`, `gzip -d`
/// and `zless` read the file with no special handling.
///
/// Framing is what preserves the `.partial` contract. A single gzip stream truncated by
/// a killed process is unreadable past its start; framed, the record decodes up to the
/// last completed member — the same guarantee an uncompressed buffer gives, and the
/// reason critical events flush.
struct GzFrames<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> GzFrames<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(FRAME_BYTES),
        }
    }

    fn emit_frame(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&self.buf)?;
        let frame = enc.finish()?;
        // Cleared before the write, not after. On a failed write those bytes are lost
        // either way, and keeping them would re-emit the whole frame on the next flush
        // and again on drop — appending duplicate members after a truncated one, which
        // stops `MultiGzDecoder` at the truncation and buries the rest.
        self.buf.clear();
        self.inner.write_all(&frame)
    }
}

impl<W: Write> Write for GzFrames<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= FRAME_BYTES {
            self.emit_frame()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.emit_frame()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for GzFrames<W> {
    fn drop(&mut self) {
        // Without this a record whose writer is dropped without a final flush would end
        // mid-frame and lose its tail.
        let _ = self.emit_frame();
    }
}

impl JsonlWriter {
    pub fn create(
        dir: &Path,
        scan_id: &str,
        epoch_ms: u64,
        compress: bool,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let name = if compress {
            format!("scan-{epoch_ms}-{scan_id}.jsonl.gz")
        } else {
            format!("scan-{epoch_ms}-{scan_id}.jsonl")
        };
        let final_path = dir.join(&name);
        let partial_path = dir.join(format!("{name}.partial"));
        let file = File::create(&partial_path)?;
        let sink: Box<dyn Write + Send> = if compress {
            Box::new(GzFrames::new(file))
        } else {
            Box::new(file)
        };
        Ok(Self {
            file: Some(BufWriter::with_capacity(64 * 1024, sink)),
            partial_path,
            final_path,
            renames: true,
            scan_id: scan_id.to_string(),
            seq: 0,
            last_flush: Instant::now(),
            terminal_written: false,
            error: None,
        })
    }

    /// A writer over an arbitrary sink, for driving writer failure in tests.
    ///
    /// This exists because writer failure was previously only reachable by spawning the
    /// binary under an `RLIMIT_FSIZE`, which is slow, Linux-specific, and cannot choose
    /// *which* event fails — so the bug where only `probe_result` recorded a failure
    /// stayed invisible.
    #[cfg(test)]
    pub(crate) fn with_sink(sink: Box<dyn Write + Send>, scan_id: &str) -> Self {
        Self {
            // Unbuffered: `BufWriter` passes any write at or above its capacity straight
            // through, so a zero-capacity buffer makes each event reach the sink as its
            // own call. A test can then fail one specific event instead of whichever one
            // happened to cross a 64 KiB boundary.
            file: Some(BufWriter::with_capacity(0, sink)),
            partial_path: PathBuf::from("(sink)"),
            final_path: PathBuf::from("(sink)"),
            renames: false,
            scan_id: scan_id.to_string(),
            seq: 0,
            last_flush: Instant::now(),
            terminal_written: false,
            error: None,
        }
    }

    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Emit one event. `body` supplies the type-specific fields; the envelope
    /// (`type`, `seq`, `ts`, `scan_id`) is added here so it cannot be forgotten.
    pub fn emit(&mut self, kind: &str, body: Value) -> std::io::Result<()> {
        if self.terminal_written {
            // Nothing may follow a terminal event — that invariant is what lets a
            // consumer trust the counts.
            return Ok(());
        }
        let mut obj = Map::new();
        obj.insert("type".into(), json!(kind));
        obj.insert("seq".into(), json!(self.seq));
        obj.insert("ts".into(), json!(rfc3339_ms(now_epoch_ms())));
        obj.insert("scan_id".into(), json!(self.scan_id));
        if let Value::Object(map) = body {
            for (k, v) in map {
                obj.insert(k, v);
            }
        }
        self.seq += 1;

        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let line = Value::Object(obj).to_string();
        if let Err(e) = file
            .write_all(line.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
        {
            self.error = Some(e.to_string());
            return Err(e);
        }

        if is_critical(kind) || self.last_flush.elapsed() >= FLUSH_INTERVAL {
            if let Err(e) = file.flush() {
                self.error = Some(e.to_string());
                return Err(e);
            }
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    /// Write the single terminal event. Further events are ignored after this.
    pub fn emit_terminal(&mut self, kind: &str, body: Value) -> std::io::Result<()> {
        self.emit(kind, body)?;
        self.terminal_written = true;
        if let Some(f) = self.file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }

    /// Rename `.partial` to its final name. Only valid once a terminal event exists.
    ///
    /// An interrupted-but-finalized scan *is* renamed — the terminal event says it was
    /// interrupted, so `.partial` is reserved for "the process died".
    pub fn finalize(mut self) -> std::io::Result<PathBuf> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            drop(f);
        }
        if !self.terminal_written || !self.renames {
            return Ok(self.partial_path.clone());
        }
        std::fs::rename(&self.partial_path, &self.final_path)?;
        Ok(self.final_path.clone())
    }
}

/// Running tallies. Kept as plain fields so the terminal event and the summary line
/// cannot disagree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub planned: u64,
    pub started: u64,
    pub completed: u64,
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub error: u64,
    pub retried: u64,
}

impl Counts {
    pub fn record(&mut self, state: crate::probe::State, attempts: u32) {
        use crate::probe::State::*;
        self.completed += 1;
        if attempts > 1 {
            self.retried += 1;
        }
        match state {
            Open => self.open += 1,
            Closed => self.closed += 1,
            Filtered => self.filtered += 1,
            Error => self.error += 1,
        }
    }

    /// Probes that were never handed to a worker.
    pub fn not_started(&self) -> u64 {
        self.planned.saturating_sub(self.started)
    }

    /// Probes a worker picked up but never reported, because an interrupt cut the
    /// drain short. Distinguishing these from `not_started` matters: they may have
    /// touched the network, so a consumer cannot assume they are untried.
    pub fn abandoned(&self) -> u64 {
        self.started.saturating_sub(self.completed)
    }

    pub fn to_json(self) -> Value {
        json!({
            "planned": self.planned,
            "started": self.started,
            "completed": self.completed,
            "abandoned": self.abandoned(),
            "not_started": self.not_started(),
            "open": self.open,
            "closed": self.closed,
            "filtered": self.filtered,
            "error": self.error,
            "retried": self.retried,
        })
    }
}

/// Generate a scan id: 32 bits of OS randomness as 8 lowercase hex characters.
///
/// UUID and ULID were both considered and rejected (D18) — sortability is already
/// provided by the epoch prefix in the filename, and 32 bits is ample against
/// same-millisecond collision on a single host.
pub fn new_scan_id() -> String {
    let seed = crate::plan::permute::random_seed();
    format!("{:08x}", seed as u32)
}

#[cfg(test)]
mod compression_tests {
    use super::*;
    use std::io::Read as _;

    fn write_record(dir: &Path, events: usize) -> PathBuf {
        let mut w = JsonlWriter::create(dir, "gz001", 1_700_000_000_000, true).unwrap();
        w.emit("scan_started", json!({"schema_version": SCHEMA_VERSION}))
            .unwrap();
        for i in 0..events {
            // Repetitive by nature, which is why a record compresses at all.
            w.emit(
                "probe_result",
                json!({"target": format!("10.0.{}.{}", i / 256, i % 256),
                       "port": 443, "state": "closed", "source": "local_stack"}),
            )
            .unwrap();
        }
        w.emit_terminal("scan_completed", json!({"counts": {}}))
            .unwrap();
        w.finalize().unwrap()
    }

    #[test]
    fn a_compressed_record_is_named_gz_and_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let p = write_record(d.path(), 2000);
        assert!(
            p.to_string_lossy().ends_with(".jsonl.gz"),
            "compressed records are named for what they are: {}",
            p.display()
        );

        let mut out = String::new();
        flate2::read::MultiGzDecoder::new(File::open(&p).unwrap())
            .read_to_string(&mut out)
            .expect("a finalized record decodes completely");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2002, "header + probes + terminal");
        for l in &lines {
            serde_json::from_str::<Value>(l).expect("every line is one JSON object");
        }
    }

    /// The record must be written as several gzip members, not one stream. That is what
    /// lets a killed scan still decode up to its last completed frame.
    #[test]
    fn the_record_is_written_in_frames() {
        let d = tempfile::tempdir().unwrap();
        let p = write_record(d.path(), 20_000);
        let bytes = std::fs::read(&p).unwrap();
        let members = bytes
            .windows(3)
            // gzip member header: magic 1f 8b, method 08 (deflate).
            .filter(|w| w == b"\x1f\x8b\x08")
            .count();
        assert!(
            members > 1,
            "expected several frames, found {members} in {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn compression_actually_shrinks_the_record() {
        let d = tempfile::tempdir().unwrap();
        let gz = std::fs::metadata(write_record(d.path(), 5000))
            .unwrap()
            .len();

        let d2 = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(d2.path(), "pl001", 1_700_000_000_000, false).unwrap();
        w.emit("scan_started", json!({"schema_version": SCHEMA_VERSION}))
            .unwrap();
        for i in 0..5000 {
            w.emit(
                "probe_result",
                json!({"target": format!("10.0.{}.{}", i / 256, i % 256),
                       "port": 443, "state": "closed", "source": "local_stack"}),
            )
            .unwrap();
        }
        w.emit_terminal("scan_completed", json!({"counts": {}}))
            .unwrap();
        let plain = std::fs::metadata(w.finalize().unwrap()).unwrap().len();

        assert!(
            plain > gz * 4,
            "expected a large reduction, got {plain} -> {gz}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::State;
    use serde_json::Value;

    fn lines(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line must be valid JSON"))
            .collect()
    }

    #[test]
    fn writes_partial_then_renames_on_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "abcd1234", 1_700_000_000_000, false).unwrap();
        assert!(w.partial_path().exists());
        assert!(
            w.partial_path()
                .to_string_lossy()
                .ends_with(".jsonl.partial")
        );

        w.emit("scan_started", json!({"tool_version": "0.1.0"}))
            .unwrap();
        w.emit_terminal("scan_completed", json!({"termination": "natural"}))
            .unwrap();
        let final_path = w.finalize().unwrap();

        assert!(final_path.exists());
        assert!(final_path.to_string_lossy().ends_with(".jsonl"));
        assert!(!final_path.to_string_lossy().ends_with(".partial"));
        assert!(
            !dir.path()
                .join("scan-1700000000000-abcd1234.jsonl.partial")
                .exists()
        );
    }

    #[test]
    fn stays_partial_without_a_terminal_event() {
        // This is how a consumer detects that the process died mid-scan.
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "dead", 1, false).unwrap();
        w.emit("scan_started", json!({})).unwrap();
        let p = w.finalize().unwrap();
        assert!(p.to_string_lossy().ends_with(".partial"));
    }

    #[test]
    fn filename_carries_epoch_and_scan_id() {
        let dir = tempfile::tempdir().unwrap();
        let w = JsonlWriter::create(dir.path(), "a3f19c02", 1_785_294_704_201, false).unwrap();
        assert_eq!(
            w.final_path().file_name().unwrap(),
            "scan-1785294704201-a3f19c02.jsonl"
        );
    }

    #[test]
    fn sequence_is_strictly_increasing() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "s", 1, false).unwrap();
        for i in 0..50 {
            w.emit("probe_result", json!({"port": i})).unwrap();
        }
        w.emit_terminal("scan_completed", json!({})).unwrap();
        let path = w.finalize().unwrap();

        let seqs: Vec<u64> = lines(&path)
            .iter()
            .map(|v| v["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs.len(), 51);
        for pair in seqs.windows(2) {
            assert!(pair[1] > pair[0], "seq must strictly increase: {pair:?}");
        }
    }

    #[test]
    fn envelope_is_present_on_every_event() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "envtest", 1, false).unwrap();
        w.emit("scan_started", json!({"x": 1})).unwrap();
        w.emit_terminal("scan_completed", json!({})).unwrap();
        let path = w.finalize().unwrap();

        for v in lines(&path) {
            assert!(v["type"].is_string());
            assert!(v["seq"].is_u64());
            assert_eq!(v["scan_id"], "envtest");
            let ts = v["ts"].as_str().unwrap();
            assert!(ts.ends_with('Z') && ts.len() == 24, "{ts}");
        }
    }

    #[test]
    fn nothing_is_written_after_the_terminal_event() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "t", 1, false).unwrap();
        w.emit_terminal("scan_interrupted", json!({"signal": "SIGINT"}))
            .unwrap();
        w.emit("probe_result", json!({"port": 80})).unwrap();
        w.emit("scan_warning", json!({"code": "late"})).unwrap();
        let path = w.finalize().unwrap();

        let all = lines(&path);
        assert_eq!(all.len(), 1, "events leaked past the terminal event");
        assert_eq!(all[0]["type"], "scan_interrupted");
    }

    #[test]
    fn counts_reconcile() {
        let mut c = Counts {
            planned: 10,
            started: 10,
            ..Default::default()
        };
        c.record(State::Open, 1);
        c.record(State::Closed, 1);
        c.record(State::Filtered, 2);
        c.record(State::Error, 1);
        assert_eq!(c.completed, 4);
        assert_eq!(c.open + c.closed + c.filtered + c.error, c.completed);
        assert_eq!(c.retried, 1);
        // All 10 were issued, 4 reported: none untried, 6 abandoned.
        assert_eq!(c.not_started(), 0);
        assert_eq!(c.abandoned(), 6);

        let j = c.to_json();
        assert_eq!(j["not_started"], 0);
        assert_eq!(j["abandoned"], 6);
        assert_eq!(j["retried"], 1);
    }

    #[test]
    fn abandoned_is_distinct_from_never_started() {
        // An interrupt leaves probes that a worker picked up but never reported. They
        // may have touched the network, so they must not be reported as untried.
        let mut c = Counts {
            planned: 1000,
            started: 120,
            ..Default::default()
        };
        for _ in 0..56 {
            c.record(State::Filtered, 1);
        }
        assert_eq!(c.completed, 56);
        assert_eq!(c.abandoned(), 64, "120 issued - 56 reported");
        assert_eq!(c.not_started(), 880, "1000 planned - 120 issued");
        assert_eq!(
            c.completed + c.abandoned() + c.not_started(),
            c.planned,
            "the three buckets must account for every planned probe"
        );
    }

    #[test]
    fn scan_ids_are_eight_hex_chars_and_vary() {
        let a = new_scan_id();
        let b = new_scan_id();
        assert_eq!(a.len(), 8);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        assert_ne!(a, b, "scan ids should not repeat");
    }

    #[test]
    fn critical_events_are_flushed_immediately() {
        // A reader must be able to see the header while the scan is still running.
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "flush", 1, false).unwrap();
        w.emit("scan_started", json!({})).unwrap();
        w.emit("scan_config", json!({"scan_name": "x"})).unwrap();
        let observed = std::fs::read_to_string(w.partial_path()).unwrap();
        assert_eq!(
            observed.lines().count(),
            2,
            "header should already be on disk"
        );
    }

    #[test]
    fn body_fields_merge_into_the_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "m", 1, false).unwrap();
        w.emit_terminal(
            "scan_completed",
            json!({"duration_ms": 1234, "counts": {"open": 2}}),
        )
        .unwrap();
        let path = w.finalize().unwrap();
        let v = &lines(&path)[0];
        assert_eq!(v["duration_ms"], 1234);
        assert_eq!(v["counts"]["open"], 2);
    }
}
