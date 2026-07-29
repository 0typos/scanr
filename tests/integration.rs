//! End-to-end tests that drive the real binary.
//!
//! These cover the seams unit tests cannot: argument parsing through to a written file,
//! exit codes, stdout/stderr separation, and the JSONL lifecycle as a whole.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_scanr");

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
    let file = std::fs::read_dir(&results)
        .expect("output dir should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .expect("a finalized .jsonl should exist");
    std::fs::read_to_string(file)
        .unwrap()
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
    let f = std::fs::read_dir(&results_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
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

        let file = std::fs::read_dir(d.path().join(dir))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .unwrap();
        let mut m: Vec<(u64, u64)> = std::fs::read_to_string(file)
            .unwrap()
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
    let file = std::fs::read_dir(&results)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let body = std::fs::read_to_string(&file).unwrap();
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
    let out = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1,127.0.0.2",
            "--ports",
            &open.port().to_string(),
            "--output-dir",
            "out",
            "--all",
            "-q",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let file = std::fs::read_dir(d.path().join("out"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let rem = scanr(d.path(), &["output", "remainder", file.to_str().unwrap()]);
    assert_eq!(code(&rem), 0, "{}", stderr(&rem));
    // A complete scan leaves nothing behind.
    assert!(stdout(&rem).trim().is_empty(), "{}", stdout(&rem));
    assert!(stderr(&rem).contains("0 of 2 targets"), "{}", stderr(&rem));
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
