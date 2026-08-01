//! End-to-end tests that drive the real binary.
//!
//! These cover the seams unit tests cannot: argument parsing through to a written file,
//! exit codes, stdout/stderr separation, and the JSONL lifecycle as a whole.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_scanr");

/// An IPv6 loopback listener, for the paths that only IPv6 reaches.
fn open_port_v6() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("[::1]:0").expect("IPv6 loopback should be available");
    let a = l.local_addr().unwrap();
    let l2 = l.try_clone().unwrap();
    std::thread::spawn(move || {
        for s in l2.incoming() {
            drop(s);
        }
    });
    (l, a)
}

fn closed_port_v6() -> SocketAddr {
    let l = TcpListener::bind("[::1]:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

fn scanr(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        // Keep the developer's real config out of the test.
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env("NO_COLOR", "1")
        .output()
        .expect("scanr should run")
}

/// Discard the child's coverage profile.
///
/// Two tests below constrain the child with `setrlimit` to force a failure. Those limits
/// apply to everything the child does, including the `.profraw` the instrumented binary
/// writes as it exits: `RLIMIT_FSIZE` truncates it, and `RLIMIT_NOFILE` can deny the
/// descriptor to open it. Either way `llvm-profdata` then refuses to merge *any* profile
/// and the whole coverage run fails.
///
/// Sending the profile to `/dev/null` costs these two children's coverage — a character
/// device is exempt from `RLIMIT_FSIZE`, so nothing is truncated — and the paths they
/// exercise are covered in-process by the `run::tests` harness anyway. The alternative
/// was excluding the tests by name in CI, which silently stops matching the moment
/// somebody renames one.
///
/// Harmless outside a coverage run: an uninstrumented binary ignores the variable.
fn discard_coverage_profile(cmd: &mut Command) {
    cmd.env("LLVM_PROFILE_FILE", "/dev/null");
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// An accepting listener held open for the duration of the test.
fn open_port() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let l2 = l.try_clone().unwrap();
    std::thread::spawn(move || {
        for s in l2.incoming() {
            drop(s);
        }
    });
    (l, a)
}

fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

fn read_events(dir: &Path) -> Vec<Value> {
    let results = dir.join("out");
    let file = scanr::testsupport::find_record(&results).expect("a finalized .jsonl should exist");
    scanr::testsupport::record_text(&file)
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON per line"))
        .collect()
}

#[test]
fn config_init_output_validates_and_plans() {
    let d = tempfile::tempdir().unwrap();
    let init = scanr(d.path(), &["config", "init"]);
    assert_eq!(code(&init), 0, "{}", stderr(&init));
    assert!(d.path().join("scanr.toml").exists());

    // The generated template must be valid against the very code that generated it.
    let v = scanr(d.path(), &["config", "validate"]);
    assert_eq!(code(&v), 0, "{}", stderr(&v));

    // And the scan it documents must resolve without touching the network.
    let p = scanr(d.path(), &["plan", "internal-web"]);
    assert_eq!(code(&p), 0, "{}", stderr(&p));
    assert!(stdout(&p).contains("probes"), "{}", stdout(&p));
}

#[test]
fn config_init_refuses_to_clobber_without_force() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(code(&scanr(d.path(), &["config", "init"])), 0);
    let again = scanr(d.path(), &["config", "init"]);
    assert_eq!(code(&again), 1);
    assert!(stderr(&again).contains("already exists"));
    assert_eq!(code(&scanr(d.path(), &["config", "init", "--force"])), 0);
}

#[test]
fn adhoc_scan_writes_a_verifiable_record() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let closed = closed_port();

    let ports = format!("{},{}", open.port(), closed.port());
    let out = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let events = read_events(d.path());
    assert_eq!(events[0]["type"], "scan_started");
    assert_eq!(events[1]["type"], "scan_config");
    assert_eq!(events.last().unwrap()["type"], "scan_completed");

    let results: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .collect();
    assert_eq!(results.len(), 2);
    let states: Vec<&str> = results.iter().filter_map(|r| r["state"].as_str()).collect();
    assert!(states.contains(&"open"), "{states:?}");
    assert!(states.contains(&"closed"), "{states:?}");

    // And the tool agrees the file is sound.
    let results_dir = d.path().join("out");
    let f = scanr::testsupport::find_record(&results_dir).unwrap();
    let v = scanr(d.path(), &["output", "verify", f.to_str().unwrap()]);
    assert_eq!(code(&v), 0, "{}", stdout(&v));
    assert!(stdout(&v).contains("ok — record is complete"));
}

#[test]
fn stdout_carries_only_results_and_stderr_the_rest() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &open.port().to_string(),
            "--output-dir",
            "out",
        ],
    );
    assert_eq!(code(&out), 0);

    // stdout: exactly one result line, pipe-safe.
    let so = stdout(&out);
    let lines: Vec<&str> = so.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "stdout should carry results only: {so:?}");
    assert!(lines[0].contains(&format!("127.0.0.1:{}/tcp", open.port())));
    assert!(lines[0].contains("open"));
    assert!(!so.contains('\x1b'), "no escapes when not a terminal");

    // stderr: the header and summary.
    let se = stderr(&out);
    assert!(se.contains("scanr"), "{se}");
    assert!(se.contains("completed in"), "{se}");
    assert!(se.contains("record:"), "{se}");
}

#[test]
fn open_only_is_the_default_and_all_widens_it() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let closed = closed_port();
    let ports = format!("{},{}", open.port(), closed.port());

    let default = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
        ],
    );
    assert_eq!(
        stdout(&default).lines().filter(|l| !l.is_empty()).count(),
        1
    );

    let all = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            "out2",
            "--all",
        ],
    );
    assert_eq!(stdout(&all).lines().filter(|l| !l.is_empty()).count(), 2);

    // Either way the record keeps everything.
    let events = read_events(d.path());
    assert_eq!(
        events
            .iter()
            .filter(|e| e["type"] == "probe_result")
            .count(),
        2,
        "the JSONL must record every probe regardless of --open-only"
    );
}

#[test]
fn a_seed_makes_probe_order_reproducible() {
    let d = tempfile::tempdir().unwrap();
    let mut mappings = Vec::new();
    for (i, dir) in ["a", "b"].iter().enumerate() {
        let out = scanr(
            d.path(),
            &[
                "run",
                "--no-spans",
                "--targets",
                "127.0.0.1",
                "--ports",
                "20000-20049",
                "--output-dir",
                dir,
                "--seed",
                "9f2c00a1b4de7731",
                "--all",
                "-q",
            ],
        );
        assert_eq!(code(&out), 0, "run {i}: {}", stderr(&out));

        let file = scanr::testsupport::find_record(&d.path().join(dir)).unwrap();
        let mut m: Vec<(u64, u64)> = scanr::testsupport::record_text(&file)
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|e| e["type"] == "probe_result")
            .map(|e| {
                (
                    e["port"].as_u64().unwrap(),
                    e["probe_index"].as_u64().unwrap(),
                )
            })
            .collect();
        m.sort();
        mappings.push(m);
    }
    assert_eq!(
        mappings[0], mappings[1],
        "the same seed must map each port to the same probe index"
    );
    assert_eq!(mappings[0].len(), 50);
}

#[test]
fn plan_touches_no_network_and_shows_provenance() {
    let d = tempfile::tempdir().unwrap();
    // A blackholed target would hang if plan actually probed.
    let out = scanr(
        d.path(),
        &[
            "plan",
            "--targets",
            "192.0.2.0/24",
            "--ports",
            "1-100",
            "--concurrency",
            "7",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("25,600"), "probe count: {so}");
    assert!(so.contains("concurrency"), "{so}");
    assert!(
        so.contains("cli"),
        "provenance should mark the override: {so}"
    );
    assert!(
        !d.path().join("scanr-results").exists(),
        "plan must not write a record"
    );
}

#[test]
fn unknown_scan_name_exits_one_with_a_suggestion() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        "version = 1\n[scans.internal-web]\ntargets = [\"10.0.0.1\"]\nports = [\"80\"]\n",
    )
    .unwrap();
    let out = scanr(d.path(), &["run", "internal-webb"]);
    assert_eq!(code(&out), 1);
    let se = stderr(&out);
    assert!(se.contains("no such scan"), "{se}");
    assert!(se.contains("did you mean `internal-web`?"), "{se}");
}

#[test]
fn config_errors_render_with_a_caret() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        "version = 1\n[profiles.p]\nconcurrency = 0\n",
    )
    .unwrap();
    let out = scanr(d.path(), &["config", "validate"]);
    assert_eq!(code(&out), 1);
    let se = stderr(&out);
    assert!(se.contains("concurrency 0 is out of range"), "{se}");
    assert!(
        se.contains("scanr.toml:3:1"),
        "should point at the line: {se}"
    );
    assert!(se.contains('^'), "should render a caret: {se}");
}

#[test]
fn inline_password_is_rejected_with_alternatives() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        "version = 1\n[transports.p]\ntype = \"socks5\"\naddress = \"127.0.0.1:1080\"\npassword = \"hunter2\"\n",
    )
    .unwrap();
    let out = scanr(d.path(), &["config", "validate"]);
    assert_eq!(code(&out), 1);
    let se = stderr(&out);
    assert!(se.contains("inline `password`"), "{se}");
    assert!(se.contains("password_env"), "{se}");
    // The rejection message must not echo the secret back.
    assert!(
        !se.contains("hunter2"),
        "the error leaked the password: {se}"
    );
}

#[test]
fn credentials_never_reach_the_record() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        "version = 1\n[transports.p]\ntype = \"socks5\"\naddress = \"127.0.0.1:1\"\n\
         username = \"scanner\"\npassword_env = \"SCANR_IT_PASSWORD\"\n",
    )
    .unwrap();
    let out = Command::new(BIN)
        .args([
            "run",
            "--transport",
            "p",
            "--targets",
            "127.0.0.1",
            "--ports",
            "80",
            "--output-dir",
            "out",
            "--all",
            "-q",
        ])
        .current_dir(d.path())
        .env("XDG_CONFIG_HOME", d.path().join("xdg"))
        .env("SCANR_IT_PASSWORD", "s3cr3t-do-not-log")
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let results = d.path().join("out");
    let file = scanr::testsupport::find_record(&results).unwrap();
    let body = scanr::testsupport::record_text(&file);
    assert!(
        !body.contains("s3cr3t-do-not-log"),
        "the password leaked into the scan record"
    );
    assert!(body.contains("[redacted]"));
    assert!(
        body.contains("env:SCANR_IT_PASSWORD"),
        "the source should be recorded"
    );
    assert!(!stdout(&out).contains("s3cr3t") && !stderr(&out).contains("s3cr3t"));
}

#[test]
fn targets_can_come_from_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let mut child = Command::new(BIN)
        .args([
            "run",
            "--targets",
            "-",
            "--ports",
            &open.port().to_string(),
            "--output-dir",
            "out",
            "-q",
        ])
        .current_dir(d.path())
        .env("XDG_CONFIG_HOME", d.path().join("xdg"))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"# a comment\n127.0.0.1\n\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("127.0.0.1"), "{}", stdout(&out));
}

#[test]
fn targets_can_come_from_a_file() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    std::fs::write(d.path().join("hosts.txt"), "# hosts\n127.0.0.1\n").unwrap();
    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "hosts.txt",
            "--ports",
            &open.port().to_string(),
            "--output-dir",
            "out",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("127.0.0.1"));
}

#[test]
fn dns_disabled_rejects_hostnames_before_scanning() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(
        d.path(),
        &[
            "plan",
            "--targets",
            "example.invalid",
            "--ports",
            "80",
            "--dns",
            "disabled",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("dns is disabled"), "{}", stderr(&out));
}

#[test]
fn oversized_range_is_refused_until_opted_in() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(
        d.path(),
        &["plan", "--targets", "10.0.0.0/8", "--ports", "80"],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("--allow-large-range"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn ipv6_prefix_guard_names_the_limit() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(
        d.path(),
        &["plan", "--targets", "2001:db8::/64", "--ports", "80"],
    );
    assert_eq!(code(&out), 1);
    let se = stderr(&out);
    assert!(se.contains("/112"), "{se}");
}

#[test]
fn transport_test_reports_direct_needs_no_measurement() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(d.path(), &["transport", "test", "direct"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("full"), "{so}");
    assert!(so.to_lowercase().contains("measurement"), "{so}");
}

#[test]
fn completions_generate_for_every_supported_shell() {
    let d = tempfile::tempdir().unwrap();
    for sh in ["bash", "zsh", "fish", "elvish", "power-shell"] {
        let out = scanr(d.path(), &["completion", sh]);
        assert_eq!(code(&out), 0, "{sh}: {}", stderr(&out));
        assert!(
            stdout(&out).len() > 200,
            "{sh} produced no completion script"
        );
    }
}

#[test]
fn output_remainder_round_trips_into_a_rescan() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let closed = closed_port();
    let ports = format!("{},{}", open.port(), closed.port());

    // A complete scan leaves nothing outstanding.
    let out = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--targets",
            "127.0.0.1,127.0.0.2",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let file = scanr::testsupport::find_record(&d.path().join("out")).unwrap();
    let rem = scanr(d.path(), &["output", "remainder", file.to_str().unwrap()]);
    assert_eq!(code(&rem), 0, "{}", stderr(&rem));
    assert!(stdout(&rem).trim().is_empty(), "{}", stdout(&rem));
    assert!(
        stderr(&rem).contains("all 4 endpoints were probed"),
        "{}",
        stderr(&rem)
    );

    // Now simulate an interrupted scan by dropping two probe_result lines, and check the
    // round trip re-probes exactly those endpoints and nothing else. This is the property
    // that justifies not having a `resume` command at all.
    let text = scanr::testsupport::record_text(&file);
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if v["type"] == "probe_result" && dropped.len() < 2 {
            dropped.push((
                v["target"].as_str().unwrap().to_string(),
                v["port"].as_u64().unwrap() as u16,
            ));
        } else {
            kept.push(line.to_string());
        }
    }
    assert_eq!(dropped.len(), 2);
    let partial = d.path().join("out").join("partial.jsonl");
    std::fs::write(&partial, kept.join("\n") + "\n").unwrap();

    let rem = scanr(
        d.path(),
        &["output", "remainder", partial.to_str().unwrap()],
    );
    assert_eq!(code(&rem), 0, "{}", stderr(&rem));
    let all: Vec<String> = stdout(&rem).lines().map(|l| l.trim().to_string()).collect();

    // The remainder leads with where it came from, so the pipe carries the link.
    let original_id =
        serde_json::from_str::<Value>(text.lines().next().unwrap()).unwrap()["scan_id"]
            .as_str()
            .unwrap()
            .to_string();
    assert_eq!(
        all[0],
        format!("# resumed-from: {original_id}"),
        "got {all:?}"
    );

    let listed: Vec<String> = all
        .iter()
        .filter(|l| !l.starts_with('#'))
        .cloned()
        .collect();
    assert_eq!(
        listed.len(),
        2,
        "expected exactly the dropped endpoints: {listed:?}"
    );
    for (t, p) in &dropped {
        assert!(
            listed.contains(&format!("{t}:{p}")),
            "remainder omitted {t}:{p}, got {listed:?}"
        );
    }

    // Feed it back verbatim, directive included. Exactly two probes should run — not
    // two whole targets.
    std::fs::write(d.path().join("resume.txt"), all.join("\n") + "\n").unwrap();
    let again = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--pairs",
            "resume.txt",
            "--output-dir",
            "out2",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&again), 0, "{}", stderr(&again));

    let file2 = scanr::testsupport::find_record(&d.path().join("out2")).unwrap();
    let events: Vec<Value> = scanr::testsupport::record_text(&file2)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let results: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .collect();
    assert_eq!(
        results.len(),
        2,
        "resuming should probe exactly the outstanding endpoints, not re-probe whole targets"
    );
    for r in &results {
        let pair = (
            r["target"].as_str().unwrap().to_string(),
            r["port"].as_u64().unwrap() as u16,
        );
        assert!(
            dropped.contains(&pair),
            "unexpected endpoint probed: {pair:?}"
        );
    }
    // And the record says it was a pair scan, so its own remainder works too.
    let config = events.iter().find(|e| e["type"] == "scan_config").unwrap();
    assert_eq!(config["targets"]["mode"], "pairs");

    // The chain is reconstructible: this record names the scan it continues, which is
    // what makes an interrupted-then-resumed scan a single traceable thing rather than
    // two unrelated files.
    assert_eq!(
        config["resumed_from"].as_str(),
        Some(original_id.as_str()),
        "the resumed scan must name its origin"
    );
}

/// `plan` is the "look before you scan" surface, so it must describe a pair scan as the
/// endpoint list it is. It used to render the matrix fields regardless, producing
/// `targets 2 (3 explicit host:port pairs)` and `ports 3 ((explicit pairs))`.
#[test]
fn plan_describes_a_pair_scan_as_endpoints_not_a_matrix() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("pairs.txt"),
        "# resumed-from: a7b012c0\n10.0.0.1:22\n10.0.0.1:443\n[::1]:80\n",
    )
    .unwrap();

    let out = scanr(d.path(), &["plan", "--pairs", "pairs.txt"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let s = stdout(&out);

    assert!(s.contains("mode            explicit endpoints"), "{s}");
    assert!(s.contains("resumed from  scan a7b012c0"), "{s}");
    assert!(
        s.contains("3 across 2 host(s), 3 distinct port(s)"),
        "endpoint counts should read as a sentence: {s}"
    );
    assert!(!s.contains("(("), "no doubled parentheses: {s}");
    assert!(
        !s.contains("explicit host:port pairs)"),
        "the matrix rendering must not leak through: {s}"
    );
}

/// The defaults are compressed and span-collapsed, and both must survive a round trip
/// through the tools that read a record back.
#[test]
fn the_default_record_is_compressed_and_collapsed_and_still_verifies() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let ports = format!("{},20000-20200", open.port());
    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let file = scanr::testsupport::find_record(&d.path().join("out")).expect("a finalized record");

    assert!(
        file.to_string_lossy().ends_with(".jsonl.gz"),
        "the default record is compressed: {}",
        file.display()
    );
    assert_eq!(
        &std::fs::read(&file).unwrap()[..2],
        &[0x1f, 0x8b],
        "and is really gzip, not just named so"
    );

    let events: Vec<Value> = scanr::testsupport::record_text(&file)
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON per line"))
        .collect();
    let spans: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "probe_span")
        .collect();
    assert!(!spans.is_empty(), "the closed ports should have collapsed");

    // The open port is never collapsed, so it is still a row of its own.
    let rows: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .collect();
    assert!(
        rows.iter().any(|r| r["state"] == "open"),
        "an open result always keeps its row"
    );

    // And the tools still agree the record is sound and complete.
    let p = file.to_str().unwrap();
    let v = scanr(d.path(), &["output", "verify", p]);
    assert_eq!(code(&v), 0, "{}", stdout(&v));
    assert!(
        stdout(&v).contains("ok — record is complete"),
        "{}",
        stdout(&v)
    );

    let rem = scanr(d.path(), &["output", "remainder", p]);
    assert_eq!(code(&rem), 0, "{}", stderr(&rem));
    let note = stderr(&rem);
    assert!(
        note.contains("all 202 endpoints were probed"),
        "a complete scan has nothing outstanding: {note}"
    );
    assert!(
        !note.contains("--pairs"),
        "and is not told to re-run: {note}"
    );
}

/// A hard kill must not lose the probes a span stands for.
///
/// Spans accumulate in memory, so the first version wrote them once at the end: a
/// SIGKILLed scan recovered its header and nothing else, where every streamed
/// `probe_result` used to survive. They are now drained on the progress cadence and
/// flushed as critical events.
#[test]
fn a_sigkilled_scan_keeps_the_probes_its_spans_stood_for() {
    use std::process::Stdio;

    let d = tempfile::tempdir().unwrap();
    let mut child = Command::new(BIN)
        .args([
            "run",
            "--targets",
            "192.0.2.0/24",
            "--ports",
            "80,443",
            "--connect-timeout",
            "400ms",
            "--concurrency",
            "64",
            "--output-dir",
            "out",
            "-q",
        ])
        .current_dir(d.path())
        .env("XDG_CONFIG_HOME", d.path().join("xdg"))
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("scanr should start");

    // Past the first progress tick, which is when spans are drained.
    std::thread::sleep(std::time::Duration::from_millis(6_500));
    let _ = child.kill();
    let _ = child.wait();

    let partial = std::fs::read_dir(d.path().join("out"))
        .expect("output dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".partial"))
        .expect("a killed scan leaves a .partial record");

    let covered: u64 = scanr::testsupport::record_text(&partial)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["type"] == "probe_span")
        .filter_map(|e| e["count"].as_u64())
        .sum();
    assert!(
        covered > 0,
        "a killed scan must retain the probes it already made, got none in {}",
        partial.display()
    );
}

/// `output cat` exists so a documented `jq` recipe works the same on every platform:
/// `zcat -f`'s pass-through of uncompressed input is a GNU extension, and macOS ships
/// BSD gzip. It must be byte-faithful on both record formats.
#[test]
fn output_cat_emits_plain_jsonl_for_either_format() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port();
    let ports = format!("{},20000-20020", open.port());

    for (dir, extra) in [("gz", vec![]), ("plain", vec!["--no-compress"])] {
        let mut args = vec![
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &ports,
            "--output-dir",
            dir,
            "--all",
            "-q",
        ];
        args.extend(extra);
        assert_eq!(code(&scanr(d.path(), &args)), 0);
    }

    for dir in ["gz", "plain"] {
        let f = scanr::testsupport::find_record(&d.path().join(dir)).expect("a record");
        let out = scanr(d.path(), &["output", "events", f.to_str().unwrap()]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));

        // Byte-for-byte what the file holds once decompressed.
        assert_eq!(
            stdout(&out),
            scanr::testsupport::record_text(&f),
            "{dir}: cat must not reformat the record"
        );
        // And every line is still one JSON object.
        for line in stdout(&out).lines() {
            serde_json::from_str::<Value>(line).expect("valid JSON per line");
        }
        assert!(
            stdout(&out).contains("\"type\":\"scan_started\""),
            "{dir}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn declared_fidelity_is_honoured_end_to_end() {
    let d = tempfile::tempdir().unwrap();
    let base = "version = 1\n[transports.p]\ntype = \"socks5\"\naddress = \"127.0.0.1:1080\"\n";

    // Undeclared: every scan warns that fidelity is unknown.
    std::fs::write(d.path().join("scanr.toml"), base).unwrap();
    let out = scanr(
        d.path(),
        &[
            "plan",
            "--transport",
            "p",
            "--targets",
            "10.0.0.1",
            "--ports",
            "80",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("not measured"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("has not been measured"),
        "{}",
        stdout(&out)
    );

    // Declared: the warning goes away and the plan shows where it came from.
    std::fs::write(
        d.path().join("scanr.toml"),
        format!("{base}fidelity = \"full\"\n"),
    )
    .unwrap();
    let out = scanr(
        d.path(),
        &[
            "plan",
            "--transport",
            "p",
            "--targets",
            "10.0.0.1",
            "--ports",
            "80",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let so = stdout(&out);
    assert!(so.contains("declared in config"), "{so}");
    assert!(!so.contains("has not been measured"), "{so}");

    // A bogus value is rejected rather than silently ignored.
    std::fs::write(
        d.path().join("scanr.toml"),
        format!("{base}fidelity = \"probably\"\n"),
    )
    .unwrap();
    let out = scanr(d.path(), &["config", "validate"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("unknown fidelity"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn plan_output_has_no_trailing_whitespace() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(
        d.path(),
        &["plan", "--targets", "10.0.0.1", "--ports", "80"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    for (i, line) in stdout(&out).lines().enumerate() {
        assert_eq!(
            line,
            line.trim_end(),
            "line {i} has trailing whitespace: {line:?}"
        );
    }
}

/// Force a mid-scan write failure by capping the child's file size, so the writer
/// hits EFBIG partway through. This is the closest reachable analogue of a full disk
/// without needing root to mount a small filesystem.
#[test]
fn writer_failure_exits_three_and_leaves_a_partial_file() {
    use std::os::unix::process::CommandExt;

    let d = tempfile::tempdir().unwrap();

    let mut cmd = Command::new(BIN);
    cmd.args([
        "run",
        "--no-spans",
        // The RLIMIT_FSIZE cap below only bites on a plain record; a compressed one
        // of this size fits inside 4096 bytes and the write never fails.
        "--no-compress",
        "--targets",
        "127.0.0.1",
        "--ports",
        "9300-9400",
        "--output-dir",
        "out",
        "--all",
        "-q",
        "--transport",
        "direct",
        // one worker keeps the failure deterministic rather than racing the drain
        "--concurrency",
        "1",
    ])
    .current_dir(d.path())
    .env("XDG_CONFIG_HOME", d.path().join("xdg"))
    .env("NO_COLOR", "1");
    discard_coverage_profile(&mut cmd);

    // SAFETY: setrlimit is async-signal-safe and this runs in the forked child
    // between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                // Enough for the header, not enough for 101 probe results.
                rlim_cur: 4096,
                rlim_max: 4096,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("scanr should run");

    assert_eq!(
        code(&out),
        3,
        "a writer failure must exit 3, got {:?}\nstderr: {}",
        out.status,
        stderr(&out)
    );
    assert!(
        out.status.code().is_some(),
        "the process must report the failure, not die from SIGXFSZ"
    );

    // The record must remain .partial: no terminal event could be written, and that is
    // precisely the signal a consumer relies on.
    let entries: Vec<_> = std::fs::read_dir(d.path().join("out"))
        .expect("output dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n.ends_with(".jsonl.partial")),
        "expected a .partial file, found {entries:?}"
    );
    assert!(
        !entries.iter().any(|n| n.ends_with(".jsonl")),
        "a failed scan must not be finalized: {entries:?}"
    );

    // And verify must call it out rather than accepting a truncated record.
    let partial = entries.iter().find(|n| n.ends_with(".partial")).unwrap();
    let path = d.path().join("out").join(partial);
    let v = scanr(d.path(), &["output", "verify", path.to_str().unwrap()]);
    assert_eq!(code(&v), 1, "verify should reject it: {}", stdout(&v));
    let so = stdout(&v);
    assert!(so.contains(".partial suffix"), "{so}");
    assert!(so.contains("no terminal event"), "{so}");
}

/// Resource-pressure diagnostics were dead code: classified, tested, and never
/// surfaced, so the most likely real failure of a proxied scan produced only a reason
/// string. Force descriptor exhaustion and assert the operator actually gets told.
#[test]
fn resource_pressure_is_reported_once_with_remediation() {
    use std::os::unix::process::CommandExt;

    let d = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(BIN);
    cmd.args([
        "run",
        "--transport",
        "direct",
        // Blackholed targets hold a socket for the whole timeout, so descriptors
        // accumulate. Loopback refusals release instantly and never pile up.
        "--targets",
        "192.0.2.0/26",
        "--ports",
        "80",
        "--concurrency",
        "64",
        "--connect-timeout",
        "2s",
        "--output-dir",
        "out",
        "--all",
    ])
    .current_dir(d.path())
    .env("XDG_CONFIG_HOME", d.path().join("xdg"))
    .env("NO_COLOR", "1");
    discard_coverage_profile(&mut cmd);

    // SAFETY: setrlimit is async-signal-safe and runs between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 24,
                rlim_max: 24,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("scanr should run");
    let se = stderr(&out);

    assert!(
        se.contains("out of file descriptors"),
        "the operator must be told what went wrong, got:\n{se}"
    );
    assert!(
        se.contains("ulimit -n"),
        "the warning must carry actionable remediation, got:\n{se}"
    );
    assert!(
        se.contains("returned `error`"),
        "a scan that mostly errored must say so rather than just 'completed':\n{se}"
    );

    let events = read_events(d.path());
    let warnings: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "scan_warning" && e["code"] == "fd_pressure")
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "pressure must be reported exactly once, not once per failing probe"
    );
    assert!(
        warnings[0]["detail"]["remediation"]
            .as_str()
            .is_some_and(|r| r.contains("RLIMIT_NOFILE")),
        "remediation should name the actual limit: {}",
        warnings[0]
    );
}

/// IPv6 was supported in code and had never once been executed: only the /112 prefix
/// guard was tested. An entire untested address family is a real risk for a tool whose
/// failure mode is silently misreporting reachability.
#[test]
fn ipv6_direct_scan_classifies_correctly() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port_v6();
    let closed = closed_port_v6();

    let ports = format!("{},{}", open.port(), closed.port());
    let out = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--transport",
            "direct",
            "--targets",
            "::1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let so = stdout(&out);
    // Endpoints must be bracketed: `::1:9601` is itself a valid IPv6 address.
    assert!(
        so.contains(&format!("[::1]:{}/tcp open", open.port())),
        "{so}"
    );
    assert!(
        so.contains(&format!("[::1]:{}/tcp closed", closed.port())),
        "{so}"
    );

    let events = read_events(d.path());
    let states: Vec<&str> = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .filter_map(|e| e["state"].as_str())
        .collect();
    assert!(
        states.contains(&"open") && states.contains(&"closed"),
        "{states:?}"
    );
    // The record keeps address and port separate, so it is unambiguous regardless.
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "probe_result" && e["target"] == "::1")
    );
}

#[test]
fn ipv6_through_socks5_uses_the_atyp_ipv6_request() {
    use scanr::testsupport::socks5::{Behavior, Socks5Fixture};

    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port_v6();
    let closed = closed_port_v6();
    // The fixture reads a 16-byte address for ATYP_IPV6 and connects for real, so a
    // wrong request encoding shows up as a wrong verdict rather than passing silently.
    let fx = Socks5Fixture::start(Behavior::Faithful);

    std::fs::write(
        d.path().join("scanr.toml"),
        format!(
            "version = 1\n[transports.fx]\ntype = \"socks5\"\naddress = \"{}\"\nfidelity = \"full\"\n",
            fx.addr()
        ),
    )
    .unwrap();

    let ports = format!("{},{}", open.port(), closed.port());
    let out = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--transport",
            "fx",
            "--targets",
            "::1",
            "--ports",
            &ports,
            "--output-dir",
            "out",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let events = read_events(d.path());
    let by_port = |p: u16| {
        events
            .iter()
            .find(|e| e["type"] == "probe_result" && e["port"] == p)
            .unwrap_or_else(|| panic!("no result for port {p}"))
    };
    assert_eq!(by_port(open.port())["state"], "open");
    assert_eq!(by_port(open.port())["source"], "proxy_reply");
    assert_eq!(by_port(closed.port())["state"], "closed");
}

#[test]
fn ipv6_cidr_expands_and_scans() {
    let d = tempfile::tempdir().unwrap();
    let (_l, open) = open_port_v6();
    // /125 is 8 addresses, comfortably inside the /112 guard.
    let out = scanr(
        d.path(),
        &[
            "run",
            "--no-spans",
            "--transport",
            "direct",
            "--targets",
            "::1/125",
            "--ports",
            &open.port().to_string(),
            "--connect-timeout",
            "200ms",
            "--output-dir",
            "out",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let events = read_events(d.path());
    let results: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "probe_result")
        .collect();
    assert_eq!(results.len(), 8, "a /125 should expand to 8 addresses");
    assert!(
        results
            .iter()
            .any(|r| r["target"] == "::1" && r["state"] == "open"),
        "::1 should be open"
    );
    // Every emitted line must be bracketed and reparseable.
    for line in stdout(&out).lines().filter(|l| l.contains("/tcp")) {
        let endpoint = line.split('/').next().unwrap();
        assert!(
            endpoint.parse::<SocketAddr>().is_ok(),
            "{endpoint:?} is not a parseable socket address"
        );
    }
}

#[test]
fn help_lists_the_documented_command_tree() {
    let d = tempfile::tempdir().unwrap();
    let out = scanr(d.path(), &["--help"]);
    assert_eq!(code(&out), 0);
    let so = stdout(&out);
    for cmd in ["run", "plan", "config", "transport", "output", "completion"] {
        assert!(so.contains(cmd), "help should mention `{cmd}`: {so}");
    }
}

// ── service labels (D31) ────────────────────────────────────────────────────

/// Write a config whose `services_file` renames a port the builtin table already knows,
/// so a wrong precedence order is visible rather than merely unproven.
fn services_fixture(d: &Path, extra: &str) -> (TcpListener, SocketAddr) {
    let (listener, addr) = open_port();
    std::fs::write(
        d.join("my-services"),
        // 8080 is `http-proxy` in the builtin table and usually `http-alt` in
        // /etc/services; naming it a third thing pins which layer answered.
        format!(
            "internal-api  8080/tcp\nprobe-target  {}/tcp\n",
            addr.port()
        ),
    )
    .unwrap();
    std::fs::write(
        d.join("scanr.toml"),
        format!(
            "version = 1\n[defaults]\noutput_dir = \"out\"\nservices_file = \"{}\"\n{extra}",
            d.join("my-services").display()
        ),
    )
    .unwrap();
    (listener, addr)
}

#[test]
fn a_configured_services_file_outranks_the_builtin_end_to_end() {
    let d = tempfile::tempdir().unwrap();
    let (_l, addr) = services_fixture(d.path(), "");

    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &format!("{},8080", addr.port()),
            "--no-spans",
            "--all",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let events = read_events(d.path());
    let probe = events
        .iter()
        .find(|e| e["type"] == "probe_result" && e["port"] == addr.port())
        .expect("the open port was probed");
    assert_eq!(
        probe["service_label"], "probe-target",
        "the configured file should have supplied this label"
    );

    let eight = events
        .iter()
        .find(|e| e["type"] == "probe_result" && e["port"] == 8080)
        .expect("8080 was probed");
    assert_eq!(
        eight["service_label"], "internal-api",
        "the configured file outranks both /etc/services and the builtin"
    );

    // Provenance: the record has to explain where those labels came from, because the
    // middle layer differs between machines.
    let cfg = events
        .iter()
        .find(|e| e["type"] == "scan_config")
        .expect("config event");
    let layers = cfg["service_labels"]["layers"]
        .as_array()
        .expect("layers array");
    assert!(
        layers[0]["source"]
            .as_str()
            .unwrap()
            .ends_with("my-services"),
        "most specific layer first: {layers:?}"
    );
    assert_eq!(layers[0]["entries"], 2);
    assert_eq!(
        layers.last().unwrap()["source"],
        "builtin",
        "every table ends at the builtin"
    );
}

#[test]
fn a_services_file_that_is_not_there_stops_the_scan() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        "version = 1\n[defaults]\noutput_dir = \"out\"\nservices_file = \"/nonexistent/services\"\n",
    )
    .unwrap();
    let out = scanr(
        d.path(),
        &["run", "--targets", "127.0.0.1", "--ports", "80"],
    );
    assert_eq!(code(&out), 1, "a named file that is absent is a mistake");
    let se = stderr(&out);
    assert!(se.contains("services_file"), "{se}");
    assert!(se.contains("cannot read"), "{se}");
}

#[test]
fn unparseable_services_lines_warn_but_still_scan() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("my-services"), "ssh 22/tcp\nlonely\n").unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        format!(
            "version = 1\n[defaults]\noutput_dir = \"out\"\nservices_file = \"{}\"\n",
            d.path().join("my-services").display()
        ),
    )
    .unwrap();

    let out = scanr(
        d.path(),
        &["plan", "--targets", "127.0.0.1", "--ports", "22"],
    );
    assert_eq!(code(&out), 0, "a stray line must not block a scan");
    let so = stdout(&out);
    assert!(so.contains("skipped 1 unparseable line"), "{so}");
}

#[test]
fn the_plan_names_its_label_sources() {
    let d = tempfile::tempdir().unwrap();
    let _l = services_fixture(d.path(), "");
    let out = scanr(
        d.path(),
        &["plan", "--targets", "127.0.0.1", "--ports", "8080"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let so = stdout(&out);
    let line = so
        .lines()
        .find(|l| l.starts_with("labels"))
        .expect("a labels row");
    assert!(line.contains("my-services (2)"), "{line}");
    assert!(line.contains("builtin ("), "{line}");
    // The provenance column must not run into the value; it did, for exactly this row.
    assert!(
        line.ends_with(" defaults"),
        "value and provenance need a separator: {line:?}"
    );
}

#[test]
fn use_etc_services_false_makes_labels_host_independent() {
    let d = tempfile::tempdir().unwrap();
    let _l = services_fixture(d.path(), "use_etc_services = false\n");

    // 8080 is `internal-api` in the fixture, `http-proxy` in the builtin, and usually
    // `http-alt` in /etc/services. 5432 is in the builtin. 70 is normally only in
    // /etc/services, so its label is the tell that the host file was skipped.
    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            "70,5432,8080",
            "--no-spans",
            "--all",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let events = read_events(d.path());
    let label = |port: u64| -> Value {
        events
            .iter()
            .find(|e| e["type"] == "probe_result" && e["port"] == port)
            .expect("probed")["service_label"]
            .clone()
    };
    assert_eq!(
        label(8080),
        "internal-api",
        "the configured file still wins"
    );
    assert_eq!(label(5432), "postgresql", "the builtin still answers");
    assert_eq!(
        label(70),
        Value::Null,
        "gopher comes from /etc/services, which was declined"
    );

    let cfg = events
        .iter()
        .find(|e| e["type"] == "scan_config")
        .expect("config event");
    let sl = &cfg["service_labels"];
    assert_eq!(sl["use_etc_services"], false);
    let sources: Vec<&str> = sl["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["source"].as_str().unwrap())
        .collect();
    assert!(
        !sources.contains(&"/etc/services"),
        "the host layer must not appear: {sources:?}"
    );
    assert_eq!(
        cfg["provenance"]["use_etc_services"], "defaults",
        "and the plan should say the config asked for it"
    );
}

#[test]
fn the_plan_marks_etc_services_as_declined() {
    let d = tempfile::tempdir().unwrap();
    let _l = services_fixture(d.path(), "use_etc_services = false\n");
    let out = scanr(
        d.path(),
        &["plan", "--targets", "127.0.0.1", "--ports", "8080"],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let so = stdout(&out);
    let line = so
        .lines()
        .find(|l| l.starts_with("labels"))
        .expect("a labels row");
    // "off" rather than merely absent: a container with no /etc/services and a config
    // that declined it would otherwise render identically.
    assert!(line.contains("[/etc/services off]"), "{line}");
    // And the marker has to agree with what was actually read. Asserting only the
    // marker let a build that ignored the flag entirely still pass this test, printing
    // `/etc/services (5862) ... [/etc/services off]` — a row contradicting itself.
    assert!(
        !line.contains("/etc/services ("),
        "declined, yet the layer contributed: {line}"
    );
}

#[test]
fn output_results_labels_span_rows_from_the_configured_table() {
    // Rows that were collapsed into a `probe_span` have no `service_label` in the record,
    // so `get` synthesises one. That is the only reason a read-only command needs a label
    // table at all, and moving the install out of the shared `output` entry point once
    // dropped it entirely without a single test noticing.
    let d = tempfile::tempdir().unwrap();
    let closed = closed_port();
    std::fs::write(
        d.path().join("my-services"),
        format!("collapsed-svc  {}/tcp\n", closed.port()),
    )
    .unwrap();
    std::fs::write(
        d.path().join("scanr.toml"),
        format!(
            "version = 1\n[defaults]\noutput_dir = \"out\"\nservices_file = \"{}\"\n",
            d.path().join("my-services").display()
        ),
    )
    .unwrap();

    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            &closed.port().to_string(),
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let record = scanr::testsupport::find_record(&d.path().join("out")).expect("a record");
    let got = scanr(
        d.path(),
        &[
            "output",
            "results",
            "--states",
            "closed",
            record.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&got), 0, "{}", stderr(&got));
    assert!(
        stdout(&got).contains("collapsed-svc"),
        "the span row should be labelled from the configured table: {}",
        stdout(&got)
    );
}
