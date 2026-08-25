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
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::cancel::Cancel;
use crate::diag::HostFacts;
use crate::net::Target;
use crate::output::{
    Counts, JsonlWriter, ProbeRecord, Progress, ResultPrinter, SCHEMA_VERSION, Spans,
};
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
/// How long the *collector* keeps reading results after an interrupt.
///
/// Not a bound on shutdown. Once this expires the collector stops, but workers already
/// inside a blocking `connect` are still joined, and that can take the full phase budget
/// — 21s on `proxy-careful`. The bound on shutdown is the second interrupt, which
/// `join_workers` now observes while waiting; the first one drains, as the tool says.
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
    /// Workers that terminated abnormally. Non-zero forces `scan_failed`.
    pub worker_panics: u32,
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
    /// The index the work counter issued, before the permutation was applied. Needed
    /// alongside the permuted index in the record because the resume set is expressed in
    /// counter space: the counter hands indices out in order, so what was never started
    /// is a contiguous range there and a scattered mess anywhere else.
    raw_index: u64,
    record: ProbeRecord,
}

/// Which issued probes reported back.
///
/// A bit per planned probe — 128 KB for a million-probe scan, against the 11 MB the scan
/// already holds — so the terminal event can name exactly which probes were abandoned
/// rather than only how many. `output remainder` then reconstructs the resume set from
/// two events instead of re-reading the whole record.
struct Reported {
    bits: Vec<u64>,
    planned: u64,
}

/// Above this the bitset would cost more than ~32 MB, so the terminal event omits the
/// resume hint and `remainder` falls back to reading the probe rows.
const MAX_TRACKED_PROBES: u64 = 256_000_000;

impl Reported {
    fn new(planned: u64) -> Option<Self> {
        if planned > MAX_TRACKED_PROBES {
            return None;
        }
        Some(Self {
            bits: vec![0u64; (planned as usize).div_ceil(64).max(1)],
            planned,
        })
    }

    fn mark(&mut self, index: u64) {
        if index < self.planned {
            self.bits[(index / 64) as usize] |= 1 << (index % 64);
        }
    }

    fn saw(&self, index: u64) -> bool {
        index < self.planned && self.bits[(index / 64) as usize] & (1 << (index % 64)) != 0
    }

    /// Issued but never reported. Bounded in practice by how many probes were in flight
    /// when the scan stopped, so this stays short even for a huge scan.
    fn abandoned(&self, issued: u64) -> Vec<u64> {
        (0..issued.min(self.planned))
            .filter(|i| !self.saw(*i))
            .collect()
    }
}

/// Overrides for the two things `execute` would otherwise construct itself.
///
/// The scan's failure paths — a worker dying, the writer failing on a particular event
/// type — were unreachable from a test without this, which is why defects lived in them.
#[derive(Default)]
pub(crate) struct Harness {
    pub transport: Option<Arc<dyn Transport>>,
    pub writer: Option<JsonlWriter>,
    /// Shortens the 5s progress cadence so the progress path is reachable in a test
    /// without a five-second test.
    pub progress_interval: Option<Duration>,
}

pub fn execute(
    plan: Arc<ScanPlan>,
    cancel: Cancel,
    opts: &RunOptions,
) -> Result<ScanSummary, ScanError> {
    execute_with(plan, cancel, opts, Harness::default())
}

pub(crate) fn execute_with(
    plan: Arc<ScanPlan>,
    cancel: Cancel,
    opts: &RunOptions,
    harness: Harness,
) -> Result<ScanSummary, ScanError> {
    // Both the record's `service_label` fields and the live result lines read the
    // process-wide table, so it has to be installed before either is written. Here
    // rather than in the CLI's plan builder: any caller of `execute` should get the
    // labels its own plan resolved, and a function that builds a value should not also
    // be reaching into a global.
    crate::services::install(plan.services.clone());

    let facts = HostFacts::probe();
    let scan_id = crate::output::new_scan_id();
    let started_ms = now_epoch_ms();
    let started = Instant::now();

    let mut writer = match harness.writer {
        Some(w) => w,
        None => JsonlWriter::create(&plan.output_dir, &scan_id, started_ms, plan.compress)
            .map_err(|e| ScanError::Output {
                path: plan.output_dir.clone(),
                source: e,
            })?,
    };

    // The header is a hard failure: a record without it cannot be interpreted, so there
    // is nothing to salvage by continuing.
    writer
        .emit("scan_started", started_event(started_ms))
        .map_err(ScanError::Writer)?;
    writer
        .emit("scan_config", config_event(&plan, &facts))
        .map_err(ScanError::Writer)?;

    // Every event from here on goes through `emit`, which remembers the first failure.
    // Only `probe_result` used to record one; the other five discarded it, so a disk
    // filling during the warning phase produced a record missing events and still
    // labelled `scan_completed`.
    let mut writer_error: Option<std::io::Error> = None;
    emit_plan_diagnostics(&mut writer, &mut writer_error, &plan);

    if !opts.quiet {
        print_header(&plan, &scan_id, writer.partial_path());
    }

    let total = plan.probe_count();
    let transport: Arc<dyn Transport> = match harness.transport {
        Some(t) => t,
        None => Arc::from(crate::transport::build(&plan.transport)),
    };
    let counter = Arc::new(WorkCounter::new(total));
    let n_workers = worker_count(plan.timing.concurrency, total);
    let (handles, rx) = spawn_workers(&plan, &transport, &counter, &cancel, n_workers, total)?;

    let collected = Collector {
        plan: &plan,
        facts: &facts,
        opts,
        cancel: &cancel,
        printer: ResultPrinter::new(target_width(&plan), plan.open_only, opts.no_color),
        progress: Progress::new(opts.quiet, opts.no_color),
        // The real bound on drain is the connect timeout, since a blocking connect
        // cannot be interrupted. MAX_DRAIN keeps a very long timeout from feeling hung.
        drain_budget: plan.timing.connect_timeout.min(MAX_DRAIN),
        progress_interval: harness.progress_interval.unwrap_or(PROGRESS_INTERVAL),
        total,
        reported: Reported::new(total),
        spans: plan.spans.then(|| Spans::new(total)),
    }
    .run(&rx, &mut writer, &mut writer_error);

    // Before joining. The collector can stop while workers are still parked in
    // `SyncSender::send` — that is exactly what the drain budget expiring means when the
    // channel is full — and nothing receives again, so `join` waited forever. Dropping
    // the receiver makes those sends fail, which `worker` already treats as "stop"
    // (a `SendError` means nobody is listening). The buffered results discarded here are
    // already accounted as `abandoned`, which the drain-budget break had implied anyway.
    drop(rx);

    let mut counts = collected.counts;
    counts.started = counter.issued();

    let worker_panics = join_workers(handles, &cancel);
    if worker_panics > 0 {
        emit(
            &mut writer,
            &mut writer_error,
            "scan_warning",
            json!({
                "code": "worker_panic",
                "message": format!(
                    "{worker_panics} of {n_workers} scan workers terminated abnormally; \
                     the probes they held were abandoned and these results are incomplete"
                ),
            }),
        );
    }

    // The last drain, not the only one: ticks flush spans as the scan runs so a killed
    // process keeps them (see the progress branch). This picks up whatever accumulated
    // since the final tick.
    if let Some(mut spans) = collected.spans {
        for body in spans.drain_events() {
            emit(&mut writer, &mut writer_error, "probe_span", body);
        }
    }

    let duration = started.elapsed();
    // A crashed worker outranks an interrupt: the user asked for the interrupt and did
    // not ask for the crash, and only one of the two needs investigating.
    let termination = if writer_error.is_some() || worker_panics > 0 {
        Termination::Failed
    } else if cancel.is_cancelled() {
        Termination::Interrupted
    } else {
        Termination::Completed
    };

    let body = terminal_body(&Terminal {
        termination,
        counts,
        duration,
        cancel: &cancel,
        interrupt_requested_at: collected.interrupt_requested_at,
        worker_panics,
        writer_error: writer_error.as_ref(),
        resume: collected.reported.as_ref().map(|r| Resume {
            not_started_from: counts.started,
            abandoned_indices: r.abandoned(counts.started),
        }),
    });

    let terminal_ok = writer.emit_terminal(termination.event_name(), body).is_ok();
    let path = writer.finalize().unwrap_or_else(|_| PathBuf::new());

    Ok(ScanSummary {
        scan_id,
        counts,
        termination,
        duration,
        path,
        writer_failed: writer_error.is_some() || !terminal_ok,
        worker_panics,
    })
}

/// Widest target label, so result columns line up without a second pass.
fn target_width(plan: &ScanPlan) -> usize {
    plan.targets
        .iter()
        .map(|t| t.to_string().len())
        .max()
        .unwrap_or(15)
}

/// What resolution and planning found out before any probe ran.
fn emit_plan_diagnostics(
    writer: &mut JsonlWriter,
    writer_error: &mut Option<std::io::Error>,
    plan: &ScanPlan,
) {
    for h in &plan.resolved_hosts {
        emit(
            writer,
            writer_error,
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
        emit(
            writer,
            writer_error,
            "scan_warning",
            json!({ "code": w.code, "message": w.message }),
        );
    }
}

/// Start the worker pool and hand back their handles and the result channel.
///
/// Concurrency *is* the thread count — there is no queue, so a probe is either in flight
/// or not yet issued, which is what makes the three-bucket accounting exact.
fn spawn_workers(
    plan: &Arc<ScanPlan>,
    transport: &Arc<dyn Transport>,
    counter: &Arc<WorkCounter>,
    cancel: &Cancel,
    n_workers: usize,
    total: u64,
) -> Result<(Vec<std::thread::JoinHandle<()>>, Receiver<Completed>), ScanError> {
    let permutation = Arc::new(Permutation::new(total.max(1), plan.seed));
    let limiter = Arc::new(RateLimiter::new(plan.timing.rate));
    let (tx, rx) = sync_channel::<Completed>(CHANNEL_DEPTH);

    // Hoisted: the loop shadows `plan`, `cancel` and `tx` with clones that move into the
    // worker closure, so the error path cannot reach the outer ones.
    let out_dir = plan.output_dir.clone();
    let outer_cancel = cancel.clone();
    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(n_workers);
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
            });
        // A `?` here dropped `handles`, detaching every worker already spawned: no
        // cancellation, no join, and the process exits from `main` moments later — killing
        // them mid-`connect`. So connections were made to real hosts and never recorded,
        // in a tool whose purpose is an auditable account of exactly that. Reachable via
        // `RLIMIT_NPROC` or a container `pids.max`, since concurrency validates to 65535
        // while D1 documents a ~10k thread ceiling.
        let handle = match handle {
            Ok(h) => h,
            Err(e) => {
                // Tell the running workers to stop, release anything parked in `send`,
                // then wait for them before surfacing the error.
                outer_cancel.request_graceful();
                drop(rx);
                for h in handles {
                    let _ = h.join();
                }
                return Err(e);
            }
        };
        handles.push(handle);
    }
    // The collector's loop ends on channel disconnect, which cannot happen while this
    // original sender is alive.
    drop(tx);
    Ok((handles, rx))
}

/// Wait for workers and count the ones that died.
///
/// The join result is not discarded. `panic = "unwind"` is deliberate (D1) so that a
/// panicking worker cannot take the writer down with it — but that only helps if we
/// then notice. Discarding it meant a crashed worker produced a short scan labelled
/// `scan_completed` with `termination: natural` and exit 0, which is precisely the
/// outcome this tool exists to make impossible.
///
/// A forced stop skips the join entirely: process exit will reap them.
///
/// The flag is re-read while waiting, not sampled once. `MAX_DRAIN` bounds the collector
/// loop and nothing else, so a worker inside a blocking `connect` can hold this for the
/// full phase budget — 21s on `proxy-careful`, 15s on `ssh-slow`. Sampling once meant the
/// second Ctrl-C the tool explicitly promises ("interrupt again to exit immediately")
/// arrived after the check and was ignored for that whole window.
fn join_workers(handles: Vec<std::thread::JoinHandle<()>>, cancel: &Cancel) -> u32 {
    let mut pending = handles;
    let mut panics = 0;
    while !pending.is_empty() {
        if cancel.is_forced() {
            return panics;
        }
        // Reap whatever has finished; keep waiting on the rest.
        let (done, still_running): (Vec<_>, Vec<_>) =
            pending.into_iter().partition(|h| h.is_finished());
        for h in done {
            panics += u32::from(h.join().is_err());
        }
        pending = still_running;
        if !pending.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    panics
}

/// The collection loop's inputs. Bundled rather than passed individually because the
/// loop is where a running scan's state lives, and a dozen parameters obscured that.
struct Collector<'a> {
    plan: &'a ScanPlan,
    facts: &'a HostFacts,
    opts: &'a RunOptions,
    cancel: &'a Cancel,
    printer: ResultPrinter,
    progress: Progress,
    drain_budget: Duration,
    progress_interval: Duration,
    total: u64,
    /// `None` once the scan is too large to track a bit per probe.
    reported: Option<Reported>,
    /// `None` unless the scan asked for spans.
    spans: Option<Spans>,
}

/// What the collection loop produced.
struct Collected {
    counts: Counts,
    interrupt_requested_at: Option<u64>,
    reported: Option<Reported>,
    spans: Option<Spans>,
}

impl Collector<'_> {
    fn run(
        mut self,
        rx: &Receiver<Completed>,
        writer: &mut JsonlWriter,
        writer_error: &mut Option<std::io::Error>,
    ) -> Collected {
        let mut stdout = std::io::stdout().lock();
        let mut counts = Counts {
            planned: self.total,
            ..Default::default()
        };
        let mut last_progress = Instant::now();
        let mut last_count = 0u64;
        // Pressure conditions are reported once each. A saturated host would otherwise
        // produce one warning per failing probe, which is tens of thousands of them.
        let mut pressure_seen: std::collections::BTreeSet<&'static str> = Default::default();
        let mut interrupt_requested_at: Option<u64> = None;
        let mut interrupt_at: Option<Instant> = None;

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Completed { raw_index, record }) => {
                    counts.record(record.outcome.state, record.attempts);
                    if let Some(r) = self.reported.as_mut() {
                        r.mark(raw_index);
                    }
                    if self.printer.should_print(&record.outcome) {
                        self.progress.clear();
                        self.printer.print(
                            &mut stdout,
                            &record.target,
                            record.port,
                            &record.outcome,
                        );
                    }
                    if let Some(p) = record.outcome.pressure
                        && pressure_seen.insert(p.code())
                    {
                        self.report_pressure(p, writer, writer_error);
                    }
                    // A bulk outcome goes into the span accumulator instead of getting
                    // a row, and is written out at the next progress tick alongside
                    // every probe that shared its outcome.
                    let absorbed = self
                        .spans
                        .as_mut()
                        .is_some_and(|s| s.absorb(raw_index, &record));
                    if !absorbed {
                        emit(writer, writer_error, "probe_result", record.to_json());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if self.cancel.is_cancelled() && interrupt_requested_at.is_none() {
                interrupt_requested_at = Some(now_epoch_ms());
                interrupt_at = Some(Instant::now());
                self.progress.clear();
                if !self.opts.quiet {
                    let _ = writeln!(
                        std::io::stderr(),
                        "\ninterrupt: no new probes will start; draining in-flight work \
                         (interrupt again to exit immediately)"
                    );
                }
            }
            if self.cancel.is_forced() {
                break;
            }
            // Stop waiting on stragglers once the drain budget is spent; anything still
            // outstanding is accounted for as not_started in the terminal event.
            if let Some(t) = interrupt_at
                && t.elapsed() >= self.drain_budget
            {
                break;
            }

            if last_progress.elapsed() >= self.progress_interval {
                self.tick_progress(&counts, last_progress, last_count, writer, writer_error);
                // Durability, not size: spans held only in memory are lost outright if
                // the process is killed, where streamed rows were not.
                if let Some(spans) = self.spans.as_mut() {
                    for body in spans.drain_events() {
                        emit(writer, writer_error, "probe_span", body);
                    }
                }
                last_progress = Instant::now();
                last_count = counts.completed;
            }
        }
        self.progress.clear();

        Collected {
            counts,
            interrupt_requested_at,
            reported: self.reported,
            spans: self.spans,
        }
    }

    /// Surface a degrading condition the first time it appears, with the remediation
    /// derived from this host.
    ///
    /// Before this was wired up the diagnostics in `diag` were unreachable, so the most
    /// likely real failure of a proxied scan produced only a reason string.
    fn report_pressure(
        &mut self,
        p: crate::diag::Pressure,
        writer: &mut JsonlWriter,
        writer_error: &mut Option<std::io::Error>,
    ) {
        let remediation = p.remediation(self.facts, self.plan.timing.concurrency);
        emit(
            writer,
            writer_error,
            "scan_warning",
            json!({
                "code": p.code(),
                "message": p.summary(),
                "detail": { "remediation": remediation },
            }),
        );
        if !self.opts.quiet {
            self.progress.clear();
            let _ = writeln!(
                std::io::stderr(),
                "\nwarning: {}\n{}",
                p.summary(),
                remediation
                    .lines()
                    .map(|l| format!("  {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    fn tick_progress(
        &mut self,
        counts: &Counts,
        last_progress: Instant,
        last_count: u64,
        writer: &mut JsonlWriter,
        writer_error: &mut Option<std::io::Error>,
    ) {
        let elapsed = last_progress.elapsed().as_secs_f64();
        let rate = (counts.completed - last_count) as f64 / elapsed;
        let remaining = self.total.saturating_sub(counts.completed) as f64;
        let eta = (rate > 0.01).then(|| remaining / rate);
        self.progress
            .render(counts.completed, self.total, counts.open, rate, eta);
        emit(
            writer,
            writer_error,
            "scan_progress",
            json!({
                "completed": counts.completed,
                "planned": self.total,
                "open": counts.open,
                "rate_per_s": (rate * 10.0).round() / 10.0,
                "eta_s": eta.map(|e| e.round()),
            }),
        );
    }
}

/// Everything the terminal event reports.
struct Terminal<'a> {
    termination: Termination,
    counts: Counts,
    duration: Duration,
    cancel: &'a Cancel,
    interrupt_requested_at: Option<u64>,
    worker_panics: u32,
    writer_error: Option<&'a std::io::Error>,
    /// Where the resume set starts, and which issued probes never reported.
    resume: Option<Resume>,
}

/// Enough to reconstruct exactly what was not probed, without reading the probe rows.
///
/// The work counter hands indices out in order, so everything never started is the
/// contiguous range `[not_started_from, planned)`. Only the probes that were issued and
/// never reported are scattered, and there are at most as many of those as were in
/// flight when the scan stopped. Together with the seed already in `scan_config`, this
/// reproduces the outstanding endpoints exactly.
struct Resume {
    not_started_from: u64,
    abandoned_indices: Vec<u64>,
}

fn terminal_body(t: &Terminal) -> serde_json::Value {
    let mut body = json!({
        "termination": match t.termination {
            Termination::Completed => "natural",
            Termination::Interrupted => "signal",
            Termination::Failed => "error",
        },
        "graceful": !t.cancel.is_forced(),
        "counts": t.counts.to_json(),
        "duration_ms": t.duration.as_millis() as u64,
        // Through the same helper the process exits by, and fed the writer failure, so a
        // reader comparing `$?` against the record does not find them disagreeing. A
        // writer that failed and then recovered enough to emit this event would otherwise
        // record `0` for a run the shell saw exit `3`.
        "exit_code": crate::cli::exit_code_for(t.termination, t.writer_error.is_some()),
    });
    // Recorded whenever an interrupt actually happened, not only when it won the label.
    // `Failed` outranks `Interrupted` deliberately — a crash needs investigating and the
    // user asked for the interrupt — but that is an argument about which *name* to print,
    // not a reason to delete the evidence. A scan the operator stopped that also hit a
    // worker panic previously emitted `scan_failed` with no signal, no forced flag, and no
    // requested_at, so "was this abandoned or aborted" became unanswerable.
    if t.interrupt_requested_at.is_some() || t.cancel.is_cancelled() {
        body["signal"] = json!("SIGINT");
        body["forced"] = json!(t.cancel.is_forced());
        if let Some(at) = t.interrupt_requested_at {
            body["requested_at"] = json!(rfc3339_ms(at));
        }
    }
    // Recorded numerically as well as in the reason, so a consumer can detect it
    // without string-matching. A writer failure is the more fundamental fault, so it
    // takes the `error_code` when both happened; the panic count survives regardless.
    if t.worker_panics > 0 {
        body["worker_panics"] = json!(t.worker_panics);
        body["error"] = json!(format!("{} scan worker(s) panicked", t.worker_panics));
        body["error_code"] = json!("worker_panic");
    }
    if let Some(e) = t.writer_error {
        body["error"] = json!(e.to_string());
        body["error_code"] = json!("writer_failure");
    }
    // Omitted for a scan too large to have tracked it, in which case `output remainder`
    // falls back to reading every probe row.
    if let Some(r) = &t.resume {
        body["not_started_from"] = json!(r.not_started_from);
        body["abandoned_indices"] = json!(r.abandoned_indices);
    }
    body
}

/// Emit an event, remembering the first write failure and going quiet after it.
///
/// Once the writer has failed the record is already incomplete, so continuing to push
/// events at it only risks partial lines. The single remembered error is what turns the
/// terminal event into `scan_failed`.
fn emit(
    writer: &mut JsonlWriter,
    writer_error: &mut Option<std::io::Error>,
    event: &str,
    body: serde_json::Value,
) {
    if writer_error.is_some() {
        return;
    }
    if let Err(e) = writer.emit(event, body) {
        *writer_error = Some(e);
    }
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
        if tx
            .send(Completed {
                raw_index: index,
                record,
            })
            .is_err()
        {
            return;
        }
    }
}

fn started_event(epoch_ms: u64) -> serde_json::Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "git_commit": env!("SCANR_GIT_SHA"),
        "rustc": env!("SCANR_RUSTC"),
        "target_triple": env!("SCANR_TARGET"),
        "started_at_epoch_ms": epoch_ms,
        "hostname": hostname(),
        "pid": std::process::id(),
    })
}

/// The scanning host, so a record identifies where the connections originated.
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a live 256-byte array and we pass its exact length, so the write
    // cannot overrun. POSIX permits truncation without a trailing NUL when the name does
    // not fit, which is why the caller below scans for a NUL and falls back to the full
    // length rather than trusting one to be there.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Build identity, for `--version` and diagnostics.
pub fn build_info() -> String {
    format!(
        "{} ({} {})\n{}",
        env!("CARGO_PKG_VERSION"),
        env!("SCANR_GIT_SHA"),
        env!("SCANR_TARGET"),
        env!("SCANR_RUSTC"),
    )
}

fn config_event(plan: &ScanPlan, facts: &HostFacts) -> serde_json::Value {
    let transport = match &plan.transport.kind {
        TransportKind::Direct => json!({
            "name": plan.transport.name,
            "type": "direct",
            "measured_fidelity": Fidelity::Full.to_string(),
            // Direct needs no measurement: the local TCP stack distinguishes refused,
            // unreachable, and timed out inherently. Emitted unconditionally so a
            // consumer can rely on the field existing for every transport type.
            "fidelity_source": "builtin",
        }),
        TransportKind::Socks5 {
            address,
            username,
            password,
        }
        | TransportKind::Http {
            address,
            username,
            password,
        } => json!({
            "name": plan.transport.name,
            "type": plan.transport.type_name(),
            "address": address.to_string(),
            "username": username,
            // Credentials are never written, only their source.
            "password": password.as_ref().map(|_| "[redacted]"),
            "password_source": password
                .as_ref()
                .and_then(|s| s.origin.as_ref())
                .map(|o| o.to_string()),
            "measured_fidelity": plan.transport.fidelity.to_string(),
            // Where the fidelity came from. Replaces the specified-but-never-emitted
            // `fidelity_measured_at`, which stopped meaning anything once fidelity
            // became a declared config value rather than a scan-time measurement.
            "fidelity_source": match (&plan.transport.kind, plan.transport.fidelity) {
                // HTTP has no status meaning refused; open_only is a property of the
                // protocol, not a measurement or a declaration.
                (TransportKind::Http { .. }, _) => "inherent",
                (_, Fidelity::Unknown) => "unmeasured",
                _ => "config",
            },
        }),
        // A chain records every hop, because "which link failed" is unanswerable
        // afterwards otherwise. Credentials are never written, only their presence.
        TransportKind::Chain { hops } => json!({
            "name": plan.transport.name,
            "type": "chain",
            "hops": hops.iter().map(|h| json!({
                "name": h.name,
                "type": h.kind.as_str(),
                "address": h.address.to_string(),
                "username": h.username,
                "password": h.password.as_ref().map(|_| "[redacted]"),
            })).collect::<Vec<_>>(),
            "measured_fidelity": plan.transport.fidelity.to_string(),
            // The exit hop issues the CONNECT that names the destination, so its reply
            // decides what the whole path can distinguish.
            "fidelity_source": "exit_hop",
        }),
        // Every member by name, so the `via` on each result can be resolved back to the
        // proxy that produced it.
        TransportKind::Pool { members } => json!({
            "name": plan.transport.name,
            "type": "pool",
            "members": members.iter().map(|m| json!({
                "name": m.name,
                "type": m.type_name(),
                "measured_fidelity": m.fidelity.to_string(),
            })).collect::<Vec<_>>(),
            "measured_fidelity": plan.transport.fidelity.to_string(),
            "fidelity_source": "weakest_member",
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
        // The scan this one continues, when it was built from another's remainder.
        // Null for an ordinary scan; a chain of these reconstructs a scan that was
        // split across one or more interruptions.
        "resumed_from": plan.resumed_from,
        "targets": {
            // The expanded matrix is deliberately not embedded: a /16 x 1000 ports is
            // 65M probes. The canonical spec plus the seed reproduces the scan exactly.
            //
            // A pair scan is the exception: an explicit endpoint list has no compact
            // form, so the list *is* the spec and is embedded. Bounded because it can
            // only have come from a prior scan's remainder.
            "spec": plan.target_specs,
            "exclude": plan.exclude_specs,
            "count": plan.targets.len(),
            "expanded": false,
            "mode": if plan.is_pair_scan() { "pairs" } else { "matrix" },
            "pairs": pair_list(plan),
            "pairs_truncated": pairs_truncated(plan),
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
        // Where `service_label` came from. Labels can now differ between machines,
        // because /etc/services does; this is what makes such a difference explainable
        // from the record alone rather than a mystery (D31).
        //
        // Read from the installed table rather than from `plan.services`, because the
        // installed one is what `service_label` actually consults. They are the same
        // object in every current path — the CLI installs the plan's — but nothing
        // enforced it, and a field whose whole job is to be trustworthy should not
        // depend on two things staying in step.
        "service_labels": crate::services::active().provenance(),
        // What was read from open services, if anything. Recorded because it changes
        // what the scan *did*, not merely what it reported.
        "banner": match &plan.timing.banner {
            None => json!({ "enabled": false }),
            Some(b) => json!({
                "enabled": true,
                // Sourced from the read itself, so the claim and the code that would
                // falsify it live in one file.
                "sent_bytes": crate::transport::BANNER_SENT_BYTES,
                "max_bytes": b.bytes(),
                "timeout_ms": b.timeout().as_millis() as u64,
            }),
        },
        "output": {
            "dir": plan.output_dir.to_string_lossy(),
            "open_only": plan.open_only,
            "compressed": plan.compress,
            "spans": plan.spans,
        },
        "provenance": provenance,
        "host": {
            "ephemeral_range": facts.ephemeral_range.map(|(a, b)| vec![a, b]),
            "tcp_tw_reuse": facts.tcp_tw_reuse,
            "rlimit_nofile": facts.rlimit_nofile,
            "so_linger_zero": true,
        },
    })
}

/// Cap on embedding an explicit pair list in the record. Beyond this the list is a
/// liability rather than an aid, and `output remainder` says so rather than lying.
const MAX_EMBEDDED_PAIRS: usize = 50_000;

fn pair_list(plan: &ScanPlan) -> Option<Vec<String>> {
    let pairs = plan.pairs.as_ref()?;
    if pairs.len() > MAX_EMBEDDED_PAIRS {
        return None;
    }
    Some(
        pairs
            .iter()
            .map(|(t, p)| crate::net::target::format_pair(&t.to_string(), *p))
            .collect(),
    )
}

fn pairs_truncated(plan: &ScanPlan) -> bool {
    plan.pairs
        .as_ref()
        .is_some_and(|p| p.len() > MAX_EMBEDDED_PAIRS)
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
    let _ = write!(std::io::stderr(), "{}", render_summary(summary));
}

/// The summary text, separated from the act of writing it so that what the user is told
/// at the end of a scan can be asserted on rather than merely executed.
pub fn render_summary(summary: &ScanSummary) -> String {
    use std::fmt::Write as _;
    let c = &summary.counts;
    let verb = match summary.termination {
        Termination::Completed => "completed",
        Termination::Interrupted => "interrupted",
        Termination::Failed => "failed",
    };
    let mut s = String::new();
    let _ = writeln!(
        s,
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
            s,
            "  {} probes were started but abandoned mid-flight",
            commas(c.abandoned())
        );
    }
    if c.not_started() > 0 {
        let _ = writeln!(s, "  {} probes were never started", commas(c.not_started()));
    }
    if c.retried > 0 {
        let _ = writeln!(
            s,
            "  {} probes were retried after a timeout",
            commas(c.retried)
        );
    }
    if summary.worker_panics > 0 {
        let _ = writeln!(
            s,
            "  {} scan worker(s) crashed — this is a bug in scanr, and these results are \
             incomplete; the record's terminal event records it as `worker_panic`",
            summary.worker_panics
        );
    }
    // A run that "completed" while most probes errored is not a useful result, and the
    // word `completed` on its own invites reading it as one.
    if c.completed > 0 && c.error * 2 > c.completed {
        let _ = writeln!(
            s,
            "  note: {} of {} probes returned `error`, so these results describe the \
             scanner's environment more than the target",
            commas(c.error),
            commas(c.completed)
        );
    }
    let _ = writeln!(s, "  record: {}", summary.path.display());
    s
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::types::Timing;
    use crate::probe::{Phases, ProbeOutcome, Source};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Collects the record in memory so a test can assert on the events themselves.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn events(&self) -> Vec<serde_json::Value> {
            let buf = self.0.lock().unwrap();
            String::from_utf8_lossy(&buf)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
                .collect()
        }
    }

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Fails exactly the writes carrying `needle`, and lets everything else through.
    ///
    /// Deliberately *not* sticky. A sticky sink cannot prove anything here: if the
    /// warning's failure is discarded, the very next event fails too and records it, so
    /// the scan is marked failed either way and the bug stays hidden. Striking one event
    /// and then recovering is what isolates "did *this* event type record its failure".
    struct FailsOn {
        inner: Captured,
        needle: &'static str,
        hits: u32,
    }

    impl FailsOn {
        fn new(inner: Captured, needle: &'static str) -> Self {
            Self {
                inner,
                needle,
                hits: 0,
            }
        }
    }

    impl Write for FailsOn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if String::from_utf8_lossy(buf).contains(self.needle) {
                self.hits += 1;
                return Err(std::io::Error::other("no space left on device"));
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Panics on the `panic_on`-th probe, then answers normally.
    struct PanickingTransport {
        seen: AtomicU32,
        panic_on: u32,
    }

    impl Transport for PanickingTransport {
        fn probe(&self, _dest: &Destination, _timing: &Timing) -> ProbeOutcome {
            let n = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(n != self.panic_on, "deliberate worker panic for the test");
            ProbeOutcome::open(
                Phases {
                    proxy_connect: None,
                    handshake: None,
                    connect: Some(Duration::from_millis(1)),
                    total: Duration::from_millis(1),
                },
                Source::LocalStack,
            )
        }
        fn supports_remote_dns(&self) -> bool {
            false
        }
        fn name(&self) -> &str {
            "test"
        }
        fn type_name(&self) -> &'static str {
            "direct"
        }
        fn fidelity(&self) -> Fidelity {
            Fidelity::Full
        }
    }

    /// Answers open, and trips cancellation once `after` probes have been served — the
    /// only way to reach the mid-scan interrupt branches, which a pre-cancelled scan
    /// skips entirely because no probe ever completes.
    struct CancelsAfter {
        seen: AtomicU32,
        after: u32,
        cancel: Cancel,
        forced: bool,
    }

    impl Transport for CancelsAfter {
        fn probe(&self, _dest: &Destination, _timing: &Timing) -> ProbeOutcome {
            if self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.after {
                if self.forced {
                    self.cancel.request_graceful();
                    self.cancel.request_forced();
                } else {
                    self.cancel.request_graceful();
                }
            }
            ProbeOutcome::open(
                Phases {
                    proxy_connect: None,
                    handshake: None,
                    connect: Some(Duration::from_millis(1)),
                    total: Duration::from_millis(1),
                },
                Source::LocalStack,
            )
        }
        fn supports_remote_dns(&self) -> bool {
            false
        }
        fn name(&self) -> &str {
            "test"
        }
        fn type_name(&self) -> &'static str {
            "direct"
        }
        fn fidelity(&self) -> Fidelity {
            Fidelity::Full
        }
    }

    /// Always answers open, without touching the network.
    struct StubTransport;

    impl Transport for StubTransport {
        fn probe(&self, _dest: &Destination, _timing: &Timing) -> ProbeOutcome {
            ProbeOutcome::open(
                Phases {
                    proxy_connect: None,
                    handshake: None,
                    connect: Some(Duration::from_millis(1)),
                    total: Duration::from_millis(1),
                },
                Source::LocalStack,
            )
        }
        fn supports_remote_dns(&self) -> bool {
            false
        }
        fn name(&self) -> &str {
            "test"
        }
        fn type_name(&self) -> &'static str {
            "direct"
        }
        fn fidelity(&self) -> Fidelity {
            Fidelity::Full
        }
    }

    fn quiet() -> RunOptions {
        RunOptions {
            quiet: true,
            no_color: true,
            verbose: false,
        }
    }

    fn terminal(events: &[serde_json::Value]) -> &serde_json::Value {
        events
            .last()
            .filter(|e| {
                let t = e["type"].as_str().unwrap_or("");
                t.starts_with("scan_") && t != "scan_started"
            })
            .expect("a terminal event is last")
    }

    #[test]
    fn a_panicking_worker_is_not_reported_as_a_clean_completion() {
        // The join result used to be discarded, so a crashed worker produced
        // `scan_completed` / `termination: natural` / exit 0 on a short scan.
        let sink = Captured::default();
        let plan = Arc::new(ScanPlan::for_test((1..=40).collect(), 4));
        let summary = execute_with(
            plan,
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(PanickingTransport {
                    seen: AtomicU32::new(0),
                    panic_on: 3,
                })),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-panic")),
                progress_interval: None,
            },
        )
        .expect("the scan itself still returns");

        assert_eq!(summary.worker_panics, 1);
        assert_eq!(summary.termination, Termination::Failed);
        assert_eq!(summary.termination.exit_code(), 2);

        let events = sink.events();
        let t = terminal(&events);
        assert_eq!(t["type"], "scan_failed");
        assert_eq!(t["termination"], "error");
        assert_eq!(t["error_code"], "worker_panic");
        assert_eq!(t["worker_panics"], 1);

        // And it is described in the record, not only in the terminal counts.
        assert!(
            events
                .iter()
                .any(|e| e["type"] == "scan_warning" && e["code"] == "worker_panic"),
            "a worker_panic warning is emitted"
        );
    }

    #[test]
    fn a_clean_scan_still_completes_naturally() {
        // Guards the above against over-reach: no panic must mean no worker_panics.
        let sink = Captured::default();
        let plan = Arc::new(ScanPlan::for_test((1..=20).collect(), 4));
        let summary = execute_with(
            plan,
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-clean")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.worker_panics, 0);
        assert_eq!(summary.termination, Termination::Completed);
        assert_eq!(summary.counts.completed, 20);
        let events = sink.events();
        assert_eq!(terminal(&events)["type"], "scan_completed");
        assert!(terminal(&events).get("worker_panics").is_none());
    }

    /// A writer failure during the *warning* phase, which is the case that used to be
    /// discarded: only `probe_result` recorded one.
    #[test]
    fn a_writer_failure_on_a_warning_is_not_swallowed() {
        let sink = Captured::default();
        let mut plan = ScanPlan::for_test(vec![80], 1);
        plan.warnings = vec![crate::plan::types::PlanWarning {
            code: "fidelity_unknown",
            message: "measure this proxy".into(),
        }];

        // Strikes the warning event specifically, leaving the header intact.
        let failing = FailsOn::new(sink.clone(), "fidelity_unknown");
        let summary = execute_with(
            Arc::new(plan),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(failing), "s-writer")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert!(
            summary.writer_failed,
            "a failed write during the warning phase must be recorded"
        );
        assert_eq!(summary.termination, Termination::Failed);
        assert_eq!(summary.termination.exit_code(), 2);
    }

    #[test]
    fn a_writer_failure_on_a_probe_result_is_not_swallowed() {
        let sink = Captured::default();
        let failing = FailsOn::new(sink.clone(), "probe_result");
        let summary = execute_with(
            Arc::new(ScanPlan::for_test((1..=200).collect(), 2)),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(failing), "s-writer2")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert!(summary.writer_failed);
        assert_eq!(summary.termination, Termination::Failed);
    }

    #[test]
    fn an_interrupt_mid_scan_drains_and_reconciles() {
        let sink = Captured::default();
        let cancel = Cancel::new();
        let summary = execute_with(
            // A short connect timeout keeps the drain budget short.
            Arc::new(ScanPlan::for_test((1..=400).collect(), 4)),
            cancel.clone(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(CancelsAfter {
                    seen: AtomicU32::new(0),
                    after: 20,
                    cancel,
                    forced: false,
                })),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-mid")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.termination, Termination::Interrupted);
        assert_eq!(summary.worker_panics, 0);
        // It stopped early — the whole point of an interrupt.
        assert!(
            summary.counts.completed < 400,
            "completed {}",
            summary.counts.completed
        );
        let events = sink.events();
        let t = terminal(&events);
        assert_eq!(t["type"], "scan_interrupted");
        assert!(t["requested_at"].is_string(), "{t}");
        assert_eq!(t["forced"], false);
        assert_eq!(t["graceful"], true);
        let c = &t["counts"];
        assert_eq!(
            c["planned"].as_u64().unwrap(),
            c["completed"].as_u64().unwrap()
                + c["abandoned"].as_u64().unwrap()
                + c["not_started"].as_u64().unwrap(),
            "the three buckets must still account for every planned probe: {c}"
        );
    }

    #[test]
    fn a_forced_interrupt_is_recorded_as_not_graceful() {
        let sink = Captured::default();
        let cancel = Cancel::new();
        let summary = execute_with(
            Arc::new(ScanPlan::for_test((1..=400).collect(), 4)),
            cancel.clone(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(CancelsAfter {
                    seen: AtomicU32::new(0),
                    after: 10,
                    cancel,
                    forced: true,
                })),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-forced")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.termination, Termination::Interrupted);
        let events = sink.events();
        let t = terminal(&events);
        assert_eq!(t["forced"], true);
        assert_eq!(t["graceful"], false);
        // A forced stop skips the join, so nothing may be miscounted as a panic.
        assert_eq!(summary.worker_panics, 0);
    }

    #[test]
    fn progress_events_are_emitted_during_a_long_scan() {
        let sink = Captured::default();
        let summary = execute_with(
            Arc::new(ScanPlan::for_test((1..=400).collect(), 2)),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-prog")),
                // Zero, not "short": a wall-clock threshold makes whether the path is
                // exercised at all depend on machine load, which is how a test comes to
                // pass and fail on the same code.
                progress_interval: Some(Duration::ZERO),
            },
        )
        .unwrap();

        assert_eq!(summary.termination, Termination::Completed);
        let events = sink.events();
        let progress: Vec<_> = events
            .iter()
            .filter(|e| e["type"] == "scan_progress")
            .collect();
        assert!(!progress.is_empty(), "expected at least one scan_progress");
        for p in &progress {
            assert_eq!(p["planned"], 400);
            assert!(p["completed"].as_u64().unwrap() <= 400);
        }
    }

    #[test]
    fn resolved_hostnames_are_recorded() {
        let sink = Captured::default();
        let mut plan = ScanPlan::for_test(vec![80], 1);
        plan.resolved_hosts = vec![crate::plan::types::ResolvedHost {
            hostname: "app.internal".into(),
            addresses: vec!["10.0.0.7".parse().unwrap()],
        }];
        execute_with(
            Arc::new(plan),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-dns")),
                progress_interval: None,
            },
        )
        .unwrap();

        let events = sink.events();
        let r = events
            .iter()
            .find(|e| e["type"] == "target_resolved")
            .expect("a resolved hostname is recorded");
        assert_eq!(r["target"], "app.internal");
        assert_eq!(r["addresses"][0], "10.0.0.7");
        assert_eq!(r["expanded_to_probes"], true);
    }

    #[test]
    fn a_writer_failure_on_target_resolved_is_not_swallowed() {
        let sink = Captured::default();
        let mut plan = ScanPlan::for_test(vec![80], 1);
        plan.resolved_hosts = vec![crate::plan::types::ResolvedHost {
            hostname: "app.internal".into(),
            addresses: vec!["10.0.0.7".parse().unwrap()],
        }];
        let summary = execute_with(
            Arc::new(plan),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(
                    Box::new(FailsOn::new(sink.clone(), "target_resolved")),
                    "s-dnsfail",
                )),
                progress_interval: None,
            },
        )
        .unwrap();

        assert!(summary.writer_failed);
        assert_eq!(summary.termination, Termination::Failed);
    }

    #[test]
    fn a_writer_failure_on_progress_is_not_swallowed() {
        let sink = Captured::default();
        let summary = execute_with(
            Arc::new(ScanPlan::for_test((1..=400).collect(), 2)),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(
                    Box::new(FailsOn::new(sink.clone(), "scan_progress")),
                    "s-progfail",
                )),
                progress_interval: Some(Duration::ZERO),
            },
        )
        .unwrap();

        assert!(
            summary.writer_failed,
            "a failed progress write must be recorded like any other"
        );
        assert_eq!(summary.termination, Termination::Failed);
    }

    /// Times out `fail_first` times per probe, then answers open — the retry path (D10).
    struct FlakyTransport {
        seen: Mutex<std::collections::HashMap<u16, u32>>,
        fail_first: u32,
    }

    impl Transport for FlakyTransport {
        fn probe(&self, dest: &Destination, _timing: &Timing) -> ProbeOutcome {
            let port = match dest {
                Destination::Addr(a) => a.port(),
                Destination::Host(_, p) => *p,
            };
            let mut seen = self.seen.lock().unwrap();
            let n = seen.entry(port).or_insert(0);
            *n += 1;
            let phases = Phases {
                proxy_connect: None,
                handshake: None,
                connect: Some(Duration::from_millis(1)),
                total: Duration::from_millis(1),
            };
            if *n <= self.fail_first {
                // Source::Timeout is what makes it retryable (D10).
                ProbeOutcome::new(State::Filtered, Source::Timeout, "timed out", phases)
            } else {
                ProbeOutcome::open(phases, Source::LocalStack)
            }
        }
        fn supports_remote_dns(&self) -> bool {
            true
        }
        fn name(&self) -> &str {
            "test"
        }
        fn type_name(&self) -> &'static str {
            "socks5"
        }
        fn fidelity(&self) -> Fidelity {
            Fidelity::Full
        }
    }

    #[test]
    fn a_retried_probe_is_one_row_carrying_both_attempts() {
        // Retries are merged (D10): one row per endpoint, with the per-attempt detail
        // kept so the forensic story survives the merge.
        let sink = Captured::default();
        let mut plan = ScanPlan::for_test(vec![80, 443], 2);
        plan.timing.retries = 1;
        let summary = execute_with(
            Arc::new(plan),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(FlakyTransport {
                    seen: Mutex::new(Default::default()),
                    fail_first: 1,
                })),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-retry")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.counts.completed, 2, "one row per endpoint");
        assert_eq!(summary.counts.open, 2, "the retry succeeded");
        assert_eq!(summary.counts.retried, 2);
        let events = sink.events();
        for e in events.iter().filter(|e| e["type"] == "probe_result") {
            assert_eq!(e["attempts"], 2);
            assert_eq!(e["attempt_states"][0], "filtered");
            assert_eq!(e["attempt_states"][1], "open");
        }
    }

    #[test]
    fn a_hostname_target_is_handed_over_unresolved() {
        let sink = Captured::default();
        let mut plan = ScanPlan::for_test(vec![80], 1);
        plan.targets = vec![Target::Host("app.internal".into())];
        let summary = execute_with(
            Arc::new(plan),
            Cancel::new(),
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-host")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.counts.completed, 1);
        let events = sink.events();
        let r = events
            .iter()
            .find(|e| e["type"] == "probe_result")
            .expect("one result");
        assert_eq!(r["target"], "app.internal");
        // The proxy resolved it, so no address can honestly be recorded (D15).
        assert!(r["resolved_address"].is_null(), "{r}");
    }

    fn summary_of(counts: Counts, termination: Termination, worker_panics: u32) -> ScanSummary {
        ScanSummary {
            scan_id: "abc".into(),
            counts,
            termination,
            duration: Duration::from_secs(3),
            path: PathBuf::from("/tmp/scan.jsonl"),
            writer_failed: false,
            worker_panics,
        }
    }

    #[test]
    fn the_closing_summary_states_every_incomplete_bucket() {
        let counts = Counts {
            planned: 100,
            started: 90,
            completed: 80,
            open: 10,
            closed: 60,
            filtered: 5,
            error: 5,
            retried: 7,
        };
        let s = render_summary(&summary_of(counts, Termination::Interrupted, 2));
        assert!(s.contains("interrupted in 3.00s"), "{s}");
        assert!(s.contains("80 of 100 probed"), "{s}");
        assert!(s.contains("10 probes were started but abandoned"), "{s}");
        assert!(s.contains("10 probes were never started"), "{s}");
        assert!(s.contains("7 probes were retried"), "{s}");
        assert!(s.contains("2 scan worker(s) crashed"), "{s}");
        assert!(s.contains("record: /tmp/scan.jsonl"), "{s}");
    }

    #[test]
    fn a_mostly_errored_scan_says_so_rather_than_just_completed() {
        // "completed" on its own invites reading a broken scan as a result.
        let counts = Counts {
            planned: 10,
            started: 10,
            completed: 10,
            open: 0,
            closed: 2,
            filtered: 0,
            error: 8,
            retried: 0,
        };
        let s = render_summary(&summary_of(counts, Termination::Completed, 0));
        assert!(s.contains("describe the scanner's environment"), "{s}");

        // And a healthy scan does not carry the note.
        let healthy = Counts {
            error: 1,
            closed: 9,
            ..counts
        };
        let s = render_summary(&summary_of(healthy, Termination::Completed, 0));
        assert!(!s.contains("describe the scanner's environment"), "{s}");
        assert!(!s.contains("crashed"), "{s}");
    }

    #[test]
    fn tally_counts_each_state_present() {
        use crate::probe::Phases;
        let mk = |state: State| ProbeRecord {
            probe_index: 0,
            target: "10.0.0.1".into(),
            resolved_address: None,
            port: 80,
            outcome: ProbeOutcome {
                state,
                source: Source::LocalStack,
                reason: None,
                phases: Phases {
                    proxy_connect: None,
                    handshake: None,
                    connect: None,
                    total: Duration::from_millis(1),
                },
                pressure: None,
                banner: None,
                via: None,
            },
            attempts: 1,
            attempt_states: vec![state],
        };
        let records = vec![mk(State::Open), mk(State::Open), mk(State::Closed)];
        assert_eq!(tally(&records), vec![(State::Open, 2), (State::Closed, 1)]);
        // States that did not occur are omitted rather than reported as zero.
        assert_eq!(tally(&[]), vec![]);
    }

    #[test]
    fn cancellation_before_any_probe_reports_interrupted() {
        let sink = Captured::default();
        let cancel = Cancel::new();
        cancel.request_graceful();
        let summary = execute_with(
            Arc::new(ScanPlan::for_test((1..=50).collect(), 2)),
            cancel,
            &quiet(),
            Harness {
                transport: Some(Arc::new(StubTransport)),
                writer: Some(JsonlWriter::with_sink(Box::new(sink.clone()), "s-cancel")),
                progress_interval: None,
            },
        )
        .unwrap();

        assert_eq!(summary.termination, Termination::Interrupted);
        assert_eq!(summary.termination.exit_code(), 130);
        let events = sink.events();
        let t = terminal(&events);
        assert_eq!(t["type"], "scan_interrupted");
        assert_eq!(t["signal"], "SIGINT");
        // The three buckets must still reconcile.
        let c = &t["counts"];
        assert_eq!(
            c["planned"].as_u64().unwrap(),
            c["completed"].as_u64().unwrap()
                + c["abandoned"].as_u64().unwrap()
                + c["not_started"].as_u64().unwrap()
        );
    }
    /// The record must describe the table `service_label` actually consulted, not
    /// whatever the plan happens to be carrying.
    ///
    /// Discriminating because the two are deliberately different here: the plan holds a
    /// two-layer table while nothing is installed, so the process is still labelling
    /// from the builtin. Reporting the plan's would claim a provenance the labels in the
    /// very same record did not come from.
    #[test]
    fn the_config_event_reports_the_table_the_labels_came_from() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("services");
        std::fs::write(&path, "internal-api 8080/tcp\n").expect("write fixture");

        let mut plan = ScanPlan::for_test(vec![80], 4);
        plan.services =
            crate::services::ServiceTable::resolve(Some(&path), None).expect("fixture reads");
        assert_eq!(
            plan.services.layers().len(),
            1,
            "the plan carries a file layer"
        );

        let ev = config_event(&plan, &HostFacts::probe());
        let layers = ev["service_labels"]["layers"]
            .as_array()
            .expect("layers array");
        assert_eq!(
            layers.len(),
            1,
            "nothing was installed, so only the builtin can have produced labels: {layers:?}"
        );
        assert_eq!(layers[0]["source"], "builtin");
    }
}
