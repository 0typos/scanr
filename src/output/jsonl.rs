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
fn is_critical(kind: &str) -> bool {
    matches!(
        kind,
        "scan_started"
            | "scan_config"
            | "scan_completed"
            | "scan_interrupted"
            | "scan_failed"
            | "scan_warning"
    )
}

pub struct JsonlWriter {
    file: Option<BufWriter<File>>,
    partial_path: PathBuf,
    final_path: PathBuf,
    scan_id: String,
    seq: u64,
    last_flush: Instant,
    terminal_written: bool,
    error: Option<String>,
}

impl JsonlWriter {
    pub fn create(dir: &Path, scan_id: &str, epoch_ms: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let name = format!("scan-{epoch_ms}-{scan_id}.jsonl");
        let final_path = dir.join(&name);
        let partial_path = dir.join(format!("{name}.partial"));
        let file = File::create(&partial_path)?;
        Ok(Self {
            file: Some(BufWriter::with_capacity(64 * 1024, file)),
            partial_path,
            final_path,
            scan_id: scan_id.to_string(),
            seq: 0,
            last_flush: Instant::now(),
            terminal_written: false,
            error: None,
        })
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
        if !self.terminal_written {
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
        let mut w = JsonlWriter::create(dir.path(), "abcd1234", 1_700_000_000_000).unwrap();
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
        let mut w = JsonlWriter::create(dir.path(), "dead", 1).unwrap();
        w.emit("scan_started", json!({})).unwrap();
        let p = w.finalize().unwrap();
        assert!(p.to_string_lossy().ends_with(".partial"));
    }

    #[test]
    fn filename_carries_epoch_and_scan_id() {
        let dir = tempfile::tempdir().unwrap();
        let w = JsonlWriter::create(dir.path(), "a3f19c02", 1_785_294_704_201).unwrap();
        assert_eq!(
            w.final_path().file_name().unwrap(),
            "scan-1785294704201-a3f19c02.jsonl"
        );
    }

    #[test]
    fn sequence_is_strictly_increasing() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = JsonlWriter::create(dir.path(), "s", 1).unwrap();
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
        let mut w = JsonlWriter::create(dir.path(), "envtest", 1).unwrap();
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
        let mut w = JsonlWriter::create(dir.path(), "t", 1).unwrap();
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
        let mut w = JsonlWriter::create(dir.path(), "flush", 1).unwrap();
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
        let mut w = JsonlWriter::create(dir.path(), "m", 1).unwrap();
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
