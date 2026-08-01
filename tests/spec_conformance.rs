//! Guards against the specification and the implementation drifting apart.
//!
//! Both directions of drift actually happened during development and were found by
//! ad-hoc scripts rather than tests: the spec documented `scan_started` fields the code
//! never emitted, and listed three `scan_warning` codes that could not occur. These
//! tests make that class of mistake fail the build.
//!
//! Field-level checks are a hardcoded contract here rather than parsed out of the
//! markdown. Parsing prose is brittle; keeping the contract in one place that the spec
//! is written against is the honest trade.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_scanr");

fn spec_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join(name)
}

fn spec(name: &str) -> String {
    std::fs::read_to_string(spec_path(name)).expect("specification should be readable")
}

/// Run a scan that produces at least one of every unconditional event type.
fn record() -> Vec<Value> {
    let dir = tempfile::tempdir().expect("tempdir");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let l2 = listener.try_clone().unwrap();
    std::thread::spawn(move || {
        for s in l2.incoming() {
            drop(s);
        }
    });

    // A closed port as well as an open one, so the record contains a `probe_span`. With
    // only an open port there is nothing to collapse, and the assertion that `counts` —
    // not line counts — is the authority on totals would hold trivially.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let ports = format!("{},{}", addr.port(), closed);

    let out = Command::new(BIN)
        .args([
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
            "-q",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .env("NO_COLOR", "1")
        .output()
        .expect("scanr should run");
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let file =
        scanr::testsupport::find_record(&dir.path().join("out")).expect("a finalized record");
    scanr::testsupport::record_text(&file)
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON per line"))
        .collect()
}

fn event<'a>(events: &'a [Value], kind: &str) -> &'a Value {
    events
        .iter()
        .find(|e| e["type"] == kind)
        .unwrap_or_else(|| panic!("no `{kind}` event in the record"))
}

/// Look up a dotted path, so nested contracts can be asserted too.
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn assert_present(v: &Value, kind: &str, paths: &[&str]) {
    let missing: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|p| at(v, p).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "`{kind}` is missing documented field(s) {missing:?}\ngot: {v}"
    );
}

#[test]
fn scan_started_carries_the_documented_provenance() {
    let events = record();
    assert_present(
        event(&events, "scan_started"),
        "scan_started",
        &[
            "schema_version",
            "tool_version",
            "git_commit",
            "rustc",
            "target_triple",
            "started_at_epoch_ms",
            "hostname",
            "pid",
        ],
    );
}

#[test]
fn git_commit_identifies_a_real_build() {
    let events = record();
    let sha = event(&events, "scan_started")["git_commit"]
        .as_str()
        .expect("git_commit should be a string");
    // Either a short hash (optionally -dirty) or the honest "unknown" of a packaged
    // source tree with no .git. Never empty, never a placeholder.
    let core = sha.trim_end_matches("-dirty");
    assert!(
        sha == "unknown" || (core.len() >= 7 && core.chars().all(|c| c.is_ascii_hexdigit())),
        "git_commit {sha:?} is neither a hash nor `unknown`"
    );
}

#[test]
fn scan_config_carries_the_documented_shape() {
    let events = record();
    assert_present(
        event(&events, "scan_config"),
        "scan_config",
        &[
            "scan_name",
            "profile",
            "probes_planned",
            "targets.spec",
            "targets.exclude",
            "targets.count",
            "targets.expanded",
            "ports.spec",
            "ports.count",
            "permutation.algorithm",
            "permutation.seed",
            "transport.name",
            "transport.type",
            "transport.measured_fidelity",
            "transport.fidelity_source",
            "dns.requested",
            "dns.effective",
            "timing.concurrency",
            "timing.rate",
            "timing.proxy_connect_timeout_ms",
            "timing.handshake_timeout_ms",
            "timing.connect_timeout_ms",
            "timing.retries",
            "timing.retry_delay_ms",
            "provenance",
            "output.dir",
            "output.open_only",
            "host.ephemeral_range",
            "host.tcp_tw_reuse",
            "host.rlimit_nofile",
            "host.so_linger_zero",
        ],
    );
}

#[test]
fn probe_result_carries_the_documented_shape() {
    let events = record();
    assert_present(
        event(&events, "probe_result"),
        "probe_result",
        &[
            "probe_index",
            "target",
            "port",
            "protocol",
            "state",
            "source",
            "attempts",
            "attempt_states",
            "timing_ms.total",
        ],
    );
    // Documented as always present, even when null.
    for f in ["resolved_address", "reason", "service_label"] {
        assert!(
            event(&events, "probe_result").get(f).is_some(),
            "probe_result should always carry `{f}`, even as null"
        );
    }
}

#[test]
fn terminal_event_counts_account_for_every_probe() {
    let events = record();
    let t = event(&events, "scan_completed");
    assert_present(
        t,
        "scan_completed",
        &[
            "termination",
            "graceful",
            "duration_ms",
            "exit_code",
            "counts.planned",
            "counts.started",
            "counts.completed",
            "counts.abandoned",
            "counts.not_started",
            "counts.open",
            "counts.closed",
            "counts.filtered",
            "counts.error",
            "counts.retried",
        ],
    );
    let c = &t["counts"];
    let g = |k: &str| c[k].as_u64().unwrap();
    assert_eq!(
        g("planned"),
        g("completed") + g("abandoned") + g("not_started"),
        "the three buckets must sum to planned: {c}"
    );

    // The documented promise: `counts` is the authority on totals, and counting lines of
    // any one event type is not. A collapsed probe has no `probe_result` row, so a
    // consumer that counts them alone under-reports — which is exactly what the old
    // "new optional fields may appear" wording would have licensed it to do.
    let rows = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .count() as u64;
    let spanned: u64 = events
        .iter()
        .filter(|e| e["type"] == "probe_span")
        .filter_map(|e| e["count"].as_u64())
        .sum();
    assert_eq!(
        g("completed"),
        rows + spanned,
        "completed must equal probe_result rows plus the probes their spans stand for"
    );
    assert!(
        spanned > 0,
        "the fixture must actually produce a span, or this proves nothing"
    );
    assert!(
        rows < g("completed"),
        "and counting rows alone must under-report, which is the whole point"
    );
    assert_eq!(
        g("completed"),
        g("open") + g("closed") + g("filtered") + g("error"),
        "state counts must sum to completed: {c}"
    );
}

#[test]
fn spec_warning_codes_match_the_code() {
    let doc = spec("output-schema.md");
    for code in scanr::diag::WARNING_CODES {
        assert!(
            doc.contains(&format!("`{code}`")),
            "warning code `{code}` is emitted but undocumented in docs/output-schema.md"
        );
    }
    // The other direction: these three were documented for a while and never existed.
    // They may appear only in the historical note explaining that.
    for phantom in ["fidelity_degraded", "dns_mode_changed", "slow_writer"] {
        let mentions = doc.matches(phantom).count();
        assert!(
            mentions <= 1,
            "`{phantom}` is documented as if real ({mentions} mentions) but cannot be emitted"
        );
    }
}

/// The closed enumerations must stay closed, and the spec must list exactly them.
///
/// `state` and `source` are the two fields a consumer is invited to `match` on
/// exhaustively, so widening either is a schema break rather than a normal additive
/// change. This fails in both directions: adding a variant without bumping the version,
/// and documenting a value the code cannot emit. The open-ended sets are deliberately not
/// pinned here — `transport.type` gained `chain` and `pool` within version 1, which is the
/// distinction the spec table exists to draw.
#[test]
fn the_closed_enumerations_match_the_spec() {
    use scanr::probe::{Source, State};
    let doc = spec("output-schema.md");

    let states: Vec<&str> = State::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        states,
        ["open", "closed", "filtered", "error"],
        "`state` is documented as a closed set; widening it is a schema_version bump"
    );

    let sources = [
        Source::LocalStack,
        Source::ProxyReply,
        Source::Timeout,
        Source::Internal,
    ];
    let sources: Vec<&str> = sources.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        sources,
        ["local_stack", "proxy_reply", "timeout", "internal"],
        "`source` is documented as a closed set; widening it is a schema_version bump"
    );

    for v in states.iter().chain(sources.iter()) {
        assert!(
            doc.contains(&format!("`{v}`")),
            "closed-set value `{v}` is not documented in docs/output-schema.md"
        );
    }
}

/// `docs/security.md` enumerates every `unsafe` block; the source is the authority.
///
/// The claim had drifted to "three narrowly-scoped FFI calls" while there were five —
/// `getentropy` and `signal` were added later and nobody updated the prose. A reader
/// auditing the crate would have stopped looking after finding the three named.
#[test]
fn security_doc_accounts_for_every_unsafe_block() {
    const CALLS: [&str; 5] = [
        "getrandom",
        "getentropy",
        "gethostname",
        "getrlimit",
        "signal",
    ];
    let doc = spec("security.md");
    let mut found: Vec<String> = Vec::new();

    for path in walk_rust_sources() {
        let text = std::fs::read_to_string(&path).unwrap();
        for (offset, _) in text.match_indices("unsafe {") {
            // Skip the word appearing in prose or in the lint attribute.
            let line_start = text[..offset].rfind('\n').map_or(0, |i| i + 1);
            let line = &text[line_start..];
            if line.trim_start().starts_with("//") {
                continue;
            }
            // The libc call is on the same line or just inside the block, so look at the
            // statement and a short window after it.
            let window = &text[offset..text.len().min(offset + 240)];
            let call = CALLS
                .iter()
                .find(|c| window.contains(&format!("libc::{c}")))
                .unwrap_or_else(|| {
                    panic!(
                        "unrecognised unsafe block in {}:\n{}",
                        path.display(),
                        &window[..window.len().min(120)]
                    )
                });
            found.push((*call).to_string());
        }
    }

    found.sort();
    let mut expected: Vec<String> = CALLS.iter().map(|c| (*c).to_string()).collect();
    expected.sort();
    assert_eq!(
        found, expected,
        "the unsafe blocks in src/ do not match the five documented in docs/security.md"
    );
    for call in &found {
        assert!(
            doc.contains(&format!("`{call}`")),
            "unsafe call `{call}` is not listed in docs/security.md"
        );
    }
}

/// Every `.rs` file under `src/`, plus `build.rs`.
fn walk_rust_sources() -> Vec<std::path::PathBuf> {
    fn go(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                go(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = vec![root.join("build.rs")];
    go(&root.join("src"), &mut out);
    out
}

#[test]
fn spec_json_examples_are_valid_json() {
    // A spec whose examples do not parse cannot be trusted by someone writing a
    // consumer against it.
    let doc = spec("output-schema.md");
    let mut checked = 0;
    let mut rest = doc.as_str();
    while let Some(start) = rest.find("```json") {
        let after = &rest[start + 7..];
        let Some(end) = after.find("```") else { break };
        let body = &after[..end];
        serde_json::from_str::<Value>(body.trim())
            .unwrap_or_else(|e| panic!("spec JSON example does not parse: {e}\n{body}"));
        checked += 1;
        rest = &after[end..];
    }
    assert!(
        checked >= 5,
        "expected several JSON examples, found {checked}"
    );
}

#[test]
fn every_documented_event_type_is_reachable() {
    // Guards against the spec growing an event the code cannot produce, which is what
    // happened with `scan_plan` and `scan_error` before they were explicitly dropped.
    let doc = spec("output-schema.md");
    let known = [
        "scan_started",
        "scan_config",
        "target_resolved",
        "probe_result",
        "scan_progress",
        "scan_warning",
        "scan_completed",
        "scan_interrupted",
        "scan_failed",
    ];
    for t in &known {
        assert!(doc.contains(t), "spec omits event type `{t}`");
    }
    // These three were specified and deliberately never built. They may appear, but only
    // in the section that says so — otherwise a consumer waits forever for an event that
    // cannot arrive.
    //
    // The loop used to discard `dropped` and assert the heading existed three times over,
    // so a name reintroduced anywhere in the document would have gone unnoticed.
    let (_, dropped_section) = doc
        .split_once("### Dropped and why")
        .expect("the schema should explain the events it does not emit");
    for dropped in ["scan_plan", "scan_error", "scan_interrupt_requested"] {
        assert_eq!(
            doc.matches(dropped).count(),
            dropped_section.matches(dropped).count(),
            "`{dropped}` is named outside the section explaining that it does not exist"
        );
    }
}
