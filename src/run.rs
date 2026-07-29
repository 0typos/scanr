//! Scan execution: workers, result collection, and the JSONL lifecycle.
//!
//! The main thread *is* the writer. Workers send results into a bounded channel and
//! block when it fills, which is where output backpressure comes from. Keeping the
//! writer on one thread is also what makes `seq` monotonic and stdout consistent with
//! the JSONL without any coordination.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::cancel::Cancel;
use crate::diag::HostFacts;
use crate::net::Target;
use crate::output::{Counts, JsonlWriter, ProbeRecord, Progress, ResultPrinter, SCHEMA_VERSION};
use crate::plan::types::{ScanPlan, TransportKind};
use crate::plan::{Permutation, types::Fidelity};
use crate::probe::State;
use crate::sched::{RateLimiter, WORKER_STACK_BYTES, WorkCounter, worker_count};
use crate::timefmt::{now_epoch_ms, rfc3339_ms};
use crate::transport::{Destination, Transport};
use crate::units::{HumanElapsed, commas};

const CHANNEL_DEPTH: usize = 4096;
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
/// Upper bound on how long we wait for in-flight probes after an interrupt. The real
/// bound is the connect timeout; this stops a very long timeout from feeling hung.
const MAX_DRAIN: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Completed,
    Interrupted,
    Failed,
}

impl Termination {
    pub fn event_name(&self) -> &'static str {
        match self {
            Termination::Completed => "scan_completed",
            Termination::Interrupted => "scan_interrupted",
            Termination::Failed => "scan_failed",
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Termination::Completed => 0,
            Termination::Failed => 2,
            Termination::Interrupted => 130,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub scan_id: String,
    pub counts: Counts,
    pub termination: Termination,
    pub duration: Duration,
    pub path: PathBuf,
    pub writer_failed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("cannot create output at {path}: {source}")]
    Output {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("output writer failed: {0}")]
    Writer(#[source] std::io::Error),
}

pub struct RunOptions {
    pub quiet: bool,
    pub no_color: bool,
    pub verbose: bool,
}

/// One completed probe on its way from a worker to the writer.
struct Completed {
    record: ProbeRecord,
}

pub fn execute(
    plan: Arc<ScanPlan>,
    cancel: Cancel,
    opts: &RunOptions,
) -> Result<ScanSummary, ScanError> {
    let facts = HostFacts::probe();
    let scan_id = crate::output::new_scan_id();
    let started_ms = now_epoch_ms();
    let started = Instant::now();

    let mut writer = JsonlWriter::create(&plan.output_dir, &scan_id, started_ms).map_err(|e| {
        ScanError::Output {
            path: plan.output_dir.clone(),
            source: e,
        }
    })?;

    writer
        .emit("scan_started", started_event(started_ms))
        .map_err(ScanError::Writer)?;
    writer
        .emit("scan_config", config_event(&plan, &facts))
        .map_err(ScanError::Writer)?;

    for h in &plan.resolved_hosts {
        let _ = writer.emit(
            "target_resolved",
            json!({
                "target": h.hostname,
                "addresses": h.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "mode": plan.dns_effective.to_string(),
                "expanded_to_probes": !h.addresses.is_empty(),
            }),
        );
    }
    for w in &plan.warnings {
        let _ = writer.emit(
            "scan_warning",
            json!({ "code": w.code, "message": w.message }),
        );
    }

    let total = plan.probe_count();
    let mut counts = Counts {
        planned: total,
        ..Default::default()
    };

    let target_width = plan
        .targets
        .iter()
        .map(|t| t.to_string().len())
        .max()
        .unwrap_or(15);
    let printer = ResultPrinter::new(target_width, plan.open_only, opts.no_color);
    let mut progress = Progress::new(opts.quiet, opts.no_color);

    if !opts.quiet {
        print_header(&plan, &scan_id, writer.partial_path());
    }

    // ── workers ─────────────────────────────────────────────────────────────
    let transport: Arc<dyn Transport> = Arc::from(crate::transport::build(&plan.transport));
    let permutation = Arc::new(Permutation::new(total.max(1), plan.seed));
    let counter = Arc::new(WorkCounter::new(total));
    let limiter = Arc::new(RateLimiter::new(plan.timing.rate));
    let (tx, rx) = sync_channel::<Completed>(CHANNEL_DEPTH);

    let n_workers = worker_count(plan.timing.concurrency, total);
    let out_dir = plan.output_dir.clone();
    let mut handles = Vec::with_capacity(n_workers);
    for i in 0..n_workers {
        let (plan, transport, permutation, counter, limiter, cancel, tx) = (
            plan.clone(),
            transport.clone(),
            permutation.clone(),
            counter.clone(),
            limiter.clone(),
            cancel.clone(),
            tx.clone(),
        );
        let handle = std::thread::Builder::new()
            .name(format!("scanr-w{i}"))
            .stack_size(WORKER_STACK_BYTES)
            .spawn(move || {
                worker(
                    &plan,
                    &*transport,
                    &permutation,
                    &counter,
                    &limiter,
                    &cancel,
                    &tx,
                );
            })
            .map_err(|e| ScanError::Output {
                path: out_dir.clone(),
                source: e,
            })?;
        handles.push(handle);
    }
    drop(tx);

    // ── collection ──────────────────────────────────────────────────────────
    let mut stdout = std::io::stdout().lock();
    let mut last_progress = Instant::now();
    let mut last_count = 0u64;
    let mut writer_error: Option<std::io::Error> = None;
    let mut interrupt_requested_at: Option<u64> = None;
    let mut interrupt_at: Option<Instant> = None;
    // The real bound on drain is the connect timeout, since a blocking connect cannot
    // be interrupted. MAX_DRAIN keeps a very long timeout from feeling hung.
    let drain_budget = plan.timing.connect_timeout.min(MAX_DRAIN);

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Completed { record }) => {
                counts.record(record.outcome.state, record.attempts);
                if printer.should_print(&record.outcome) {
                    progress.clear();
                    printer.print(&mut stdout, &record.target, record.port, &record.outcome);
                }
                if writer_error.is_none()
                    && let Err(e) = writer.emit("probe_result", record.to_json())
                {
                    writer_error = Some(e);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        if cancel.is_cancelled() && interrupt_requested_at.is_none() {
            interrupt_requested_at = Some(now_epoch_ms());
            interrupt_at = Some(Instant::now());
            progress.clear();
            if !opts.quiet {
                let _ = writeln!(
                    std::io::stderr(),
                    "\ninterrupt: no new probes will start; draining in-flight work \
                     (interrupt again to exit immediately)"
                );
            }
        }
        if cancel.is_forced() {
            break;
        }
        // Stop waiting on stragglers once the drain budget is spent; anything still
        // outstanding is accounted for as not_started in the terminal event.
        if let Some(t) = interrupt_at
            && t.elapsed() >= drain_budget
        {
            break;
        }

        if last_progress.elapsed() >= PROGRESS_INTERVAL {
            let elapsed = last_progress.elapsed().as_secs_f64();
            let rate = (counts.completed - last_count) as f64 / elapsed;
            let remaining = total.saturating_sub(counts.completed) as f64;
            let eta = (rate > 0.01).then(|| remaining / rate);
            progress.render(counts.completed, total, counts.open, rate, eta);
            if writer_error.is_none() {
                let _ = writer.emit(
                    "scan_progress",
                    json!({
                        "completed": counts.completed,
                        "planned": total,
                        "open": counts.open,
                        "rate_per_s": (rate * 10.0).round() / 10.0,
                        "eta_s": eta.map(|e| e.round()),
                    }),
                );
            }
            last_progress = Instant::now();
            last_count = counts.completed;
        }
    }
    progress.clear();

    counts.started = counter.issued();

    // Workers exit on their own once the counter is exhausted or cancellation is seen.
    // A forced stop skips the join: process exit will reap them.
    if !cancel.is_forced() {
        for h in handles {
            let _ = h.join();
        }
    }

    // ── terminal event ──────────────────────────────────────────────────────
    let duration = started.elapsed();
    let termination = if writer_error.is_some() {
        Termination::Failed
    } else if cancel.is_cancelled() {
        Termination::Interrupted
    } else {
        Termination::Completed
    };

    let mut body = json!({
        "termination": match termination {
            Termination::Completed => "natural",
            Termination::Interrupted => "signal",
            Termination::Failed => "error",
        },
        "graceful": !cancel.is_forced(),
        "counts": counts.to_json(),
        "duration_ms": duration.as_millis() as u64,
        "exit_code": termination.exit_code(),
    });
    if termination == Termination::Interrupted {
        body["signal"] = json!("SIGINT");
        body["forced"] = json!(cancel.is_forced());
        if let Some(at) = interrupt_requested_at {
            body["requested_at"] = json!(rfc3339_ms(at));
        }
    }
    if let Some(e) = &writer_error {
        body["error"] = json!(e.to_string());
        body["error_code"] = json!("writer_failure");
    }

    let terminal_ok = writer.emit_terminal(termination.event_name(), body).is_ok();
    let path = writer.finalize().unwrap_or_else(|_| PathBuf::new());

    Ok(ScanSummary {
        scan_id,
        counts,
        termination,
        duration,
        path,
        writer_failed: writer_error.is_some() || !terminal_ok,
    })
}

fn worker(
    plan: &ScanPlan,
    transport: &dyn Transport,
    permutation: &Permutation,
    counter: &WorkCounter,
    limiter: &RateLimiter,
    cancel: &Cancel,
    tx: &std::sync::mpsc::SyncSender<Completed>,
) {
    while let Some(index) = counter.take() {
        if cancel.is_cancelled() {
            return;
        }
        limiter.acquire(cancel);
        if cancel.is_cancelled() {
            return;
        }

        let permuted = permutation.apply(index);
        let (target, port) = plan.probe_at(permuted);
        let (dest, resolved) = match target {
            Target::Addr(ip) => (Destination::Addr(SocketAddr::new(*ip, port)), Some(*ip)),
            Target::Host(h) => (Destination::Host(h.clone(), port), None),
        };

        let mut attempt_states = Vec::with_capacity(1);
        let mut outcome = transport.probe(&dest, &plan.timing);
        attempt_states.push(outcome.state);
        let mut attempts = 1u32;

        // Only timeouts are retried: a refusal is definitive, a timeout is not (D10).
        while outcome.is_retryable() && attempts <= plan.timing.retries {
            if cancel.is_cancelled() {
                break;
            }
            if !plan.timing.retry_delay.is_zero() {
                std::thread::sleep(plan.timing.retry_delay);
            }
            if cancel.is_cancelled() {
                break;
            }
            outcome = transport.probe(&dest, &plan.timing);
            attempt_states.push(outcome.state);
            attempts += 1;
        }

        let record = ProbeRecord {
            probe_index: permuted,
            target: target.to_string(),
            resolved_address: resolved,
            port,
            outcome,
            attempts,
            attempt_states,
        };
        // A send failure means the collector has gone; stop rather than spin.
        if tx.send(Completed { record }).is_err() {
            return;
        }
    }
}

fn started_event(epoch_ms: u64) -> serde_json::Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "target_triple": current_triple(),
        "started_at_epoch_ms": epoch_ms,
        "pid": std::process::id(),
    })
}

fn current_triple() -> &'static str {
    // Enough to tell a glibc build from a static musl one in a result file.
    if cfg!(target_env = "musl") {
        "x86_64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

fn config_event(plan: &ScanPlan, facts: &HostFacts) -> serde_json::Value {
    let transport = match &plan.transport.kind {
        TransportKind::Direct => json!({
            "name": plan.transport.name,
            "type": "direct",
            "measured_fidelity": Fidelity::Full.to_string(),
        }),
        TransportKind::Socks5 {
            address,
            username,
            password,
        } => json!({
            "name": plan.transport.name,
            "type": "socks5",
            "address": address.to_string(),
            "username": username,
            // Credentials are never written, only their source.
            "password": password.as_ref().map(|_| "[redacted]"),
            "password_source": password
                .as_ref()
                .and_then(|s| s.origin.as_ref())
                .map(|o| o.to_string()),
            "measured_fidelity": plan.transport.fidelity.to_string(),
        }),
    };

    let mut provenance = serde_json::Map::new();
    for (field, origin) in plan.provenance.iter() {
        provenance.insert(field.clone(), json!(origin.to_string()));
    }

    json!({
        "scan_name": plan.scan_name,
        "description": plan.description,
        "profile": plan.profile,
        "targets": {
            // The expanded matrix is deliberately not embedded: a /16 x 1000 ports is
            // 65M probes. The canonical spec plus the seed reproduces the scan exactly.
            "spec": plan.target_specs,
            "exclude": plan.exclude_specs,
            "count": plan.targets.len(),
            "expanded": false,
        },
        "ports": { "spec": plan.port_spec, "count": plan.ports.len() },
        "probes_planned": plan.probe_count(),
        "permutation": { "algorithm": "feistel4", "seed": format!("{:016x}", plan.seed) },
        "transport": transport,
        "dns": {
            "requested": plan.dns_requested.to_string(),
            "effective": plan.dns_effective.to_string(),
        },
        "timing": {
            "concurrency": plan.timing.concurrency,
            "rate": plan.timing.rate,
            "proxy_connect_timeout_ms": plan.timing.proxy_connect_timeout.as_millis() as u64,
            "handshake_timeout_ms": plan.timing.handshake_timeout.as_millis() as u64,
            "connect_timeout_ms": plan.timing.connect_timeout.as_millis() as u64,
            "retries": plan.timing.retries,
            "retry_delay_ms": plan.timing.retry_delay.as_millis() as u64,
        },
        "output": { "dir": plan.output_dir.to_string_lossy(), "open_only": plan.open_only },
        "provenance": provenance,
        "host": {
            "ephemeral_range": facts.ephemeral_range.map(|(a, b)| vec![a, b]),
            "tcp_tw_reuse": facts.tcp_tw_reuse,
            "rlimit_nofile": facts.rlimit_nofile,
            "so_linger_zero": true,
        },
    })
}

fn print_header(plan: &ScanPlan, scan_id: &str, partial: &std::path::Path) {
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "scanr {} — {} via {} — {} probes ({} targets x {} ports)",
        env!("CARGO_PKG_VERSION"),
        plan.scan_name,
        plan.transport.describe(),
        commas(plan.probe_count()),
        commas(plan.targets.len() as u64),
        commas(plan.ports.len() as u64),
    );
    let _ = writeln!(
        err,
        "  scan {scan_id}  seed {:016x}  concurrency {}  -> {}",
        plan.seed,
        plan.timing.concurrency,
        partial.display()
    );
    for w in &plan.warnings {
        let _ = writeln!(
            err,
            "  warning: {}",
            w.message.replace('\n', "\n           ")
        );
    }
}

/// Final one-line summary on stderr.
pub fn print_summary(summary: &ScanSummary, quiet: bool) {
    if quiet {
        return;
    }
    let c = &summary.counts;
    let verb = match summary.termination {
        Termination::Completed => "completed",
        Termination::Interrupted => "interrupted",
        Termination::Failed => "failed",
    };
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\n{verb} in {} — {} open, {} closed, {} filtered, {} error ({} of {} probed)",
        HumanElapsed(summary.duration),
        c.open,
        c.closed,
        c.filtered,
        c.error,
        commas(c.completed),
        commas(c.planned),
    );
    if c.abandoned() > 0 {
        let _ = writeln!(
            err,
            "  {} probes were started but abandoned mid-flight",
            commas(c.abandoned())
        );
    }
    if c.not_started() > 0 {
        let _ = writeln!(
            err,
            "  {} probes were never started",
            commas(c.not_started())
        );
    }
    if c.retried > 0 {
        let _ = writeln!(
            err,
            "  {} probes were retried after a timeout",
            commas(c.retried)
        );
    }
    let _ = writeln!(err, "  record: {}", summary.path.display());
}

/// Distinct state counts, used by tests and the summary command.
pub fn tally(records: &[ProbeRecord]) -> Vec<(State, usize)> {
    let mut out = Vec::new();
    for s in [State::Open, State::Closed, State::Filtered, State::Error] {
        let n = records.iter().filter(|r| r.outcome.state == s).count();
        if n > 0 {
            out.push((s, n));
        }
    }
    out
}
