//! `docs/tutorial.md` is held to the code: every `scanr` command in it must parse against
//! the current CLI, the lab kit it points at must exist and validate, and the use cases
//! must still produce what the document shows — the non-proxied ones against the real
//! lab (`docs/tutorial/lab.py`, spawned here), the proxied ones against the in-process
//! fixtures that model the same proxies (a faithful SOCKS5, a collapsing one, `ssh -D`'s
//! silent close, HTTP CONNECT).
//!
//! Needs `python3` and `openssl` on PATH for the lab. The lab-backed tests run on Linux
//! only: macOS is not a promised platform (`docs/stability.md`), and its CI job exists
//! to prove the binary builds and its own suite passes there, not the tutorial's lab.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use clap::CommandFactory;
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_scanr");

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn tutorial() -> String {
    std::fs::read_to_string(root().join("docs/tutorial.md")).expect("docs/tutorial.md")
}

fn scanr(cwd: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", cwd.join(".xdg"))
        .stdin(Stdio::null())
        .output()
        .expect("scanr runs")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn record_in(dir: &Path) -> PathBuf {
    scanr::testsupport::find_record(dir).expect("a finalised record")
}

// ── the document ──────────────────────────────────────────────────────────────

/// Shell-ish tokenizer: whitespace-separated, single and double quotes group.
fn tokens(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in cmd.chars() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => cur.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every `$ …` command line in the document's console blocks, continuations joined.
fn shell_lines(doc: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending: Option<String> = None;
    for raw in doc.lines() {
        if let Some(cont) = pending.take() {
            let joined = format!("{} {}", cont.trim_end_matches('\\').trim_end(), raw.trim());
            if raw.trim_end().ends_with('\\') {
                pending = Some(joined);
            } else {
                lines.push(joined);
            }
            continue;
        }
        if let Some(cmd) = raw.strip_prefix("$ ") {
            if cmd.trim_end().ends_with('\\') {
                pending = Some(cmd.to_string());
            } else {
                lines.push(cmd.to_string());
            }
        }
    }
    lines
}

#[test]
fn every_scanr_command_in_the_tutorial_parses() {
    let doc = tutorial();
    let mut checked = 0;
    let mut bad = Vec::new();
    for line in shell_lines(&doc) {
        for segment in line.split('|') {
            let toks = tokens(segment.trim());
            if toks.first().map(String::as_str) != Some("scanr") {
                continue;
            }
            checked += 1;
            let mut cmd = scanr::cli::Cli::command();
            if let Err(e) = cmd.try_get_matches_from_mut(&toks) {
                bad.push(format!(
                    "{segment}\n    {}",
                    e.to_string().lines().next().unwrap_or("")
                ));
            }
        }
    }
    assert!(
        checked >= 25,
        "expected many scanr commands in the tutorial, found {checked}"
    );
    assert!(
        bad.is_empty(),
        "tutorial commands that no longer parse:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_lab_kit_is_present_and_its_config_validates() {
    let kit = root().join("docs/tutorial");
    for f in [
        "lab",
        "lab.py",
        "scanr.toml",
        "README.md",
        "proxies/Containerfile",
        "proxies/squid.conf",
        "proxies/sockd.conf",
    ] {
        assert!(kit.join(f).exists(), "docs/tutorial/{f} is missing");
    }
    let doc = tutorial();
    for reference in ["docs/tutorial/lab.py", "./lab up"] {
        assert!(
            doc.contains(reference),
            "the tutorial no longer mentions `{reference}`"
        );
    }
    // The config the tutorial shows is the one in the kit, and it resolves.
    let cfg = kit.join("scanr.toml");
    let tmp = tempfile::tempdir().unwrap();
    let v = scanr(
        tmp.path(),
        &["--config", cfg.to_str().unwrap(), "config", "validate"],
    );
    assert_eq!(code(&v), 0, "{}", err(&v));
    let p = scanr(
        tmp.path(),
        &["--config", cfg.to_str().unwrap(), "plan", "lab-audit"],
    );
    assert_eq!(code(&p), 0, "{}", err(&p));
    assert!(out(&p).contains("dante (socks5)"), "{}", out(&p));
    let shown = doc
        [doc.find("[transports.dante]").unwrap()..doc.find("[scans.lab-audit]").unwrap()]
        .to_string();
    let actual = std::fs::read_to_string(&cfg).unwrap();
    for line in shown
        .lines()
        .filter(|l| l.starts_with("address") || l.starts_with("type"))
    {
        assert!(
            actual.contains(line.split('#').next().unwrap().trim()),
            "tutorial shows `{line}` but scanr.toml differs"
        );
    }
}

// ── the lab ───────────────────────────────────────────────────────────────────

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    )
    .is_ok()
}

/// The tutorial's services: one per test process, shared by every test that needs them,
/// or borrowed if `./lab up` is already running.
///
/// Never killed by a test. Tests run in parallel, and a lab owned by the first test to
/// finish was torn down under the others — a scan then reported every port closed. The
/// child is told `--exit-with-parent` and leaves when this process does.
struct Lab {
    _child: Option<Child>,
}

static LAB: std::sync::OnceLock<Lab> = std::sync::OnceLock::new();

impl Lab {
    fn start() -> &'static Lab {
        LAB.get_or_init(|| {
            if listening(28443) && listening(25025) {
                return Lab { _child: None };
            }
            let log =
                std::env::temp_dir().join(format!("scanr-tutorial-lab-{}.log", std::process::id()));
            let stderr = std::fs::File::create(&log).expect("lab log");
            let mut child = Command::new("python3")
                .arg(root().join("docs/tutorial/lab.py"))
                .arg("--exit-with-parent")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(stderr)
                .spawn()
                .expect("python3 is required to run the tutorial lab");
            let start = Instant::now();
            while !(listening(28443) && listening(25025) && listening(28080)) {
                let exited = child.try_wait().ok().flatten();
                assert!(
                    exited.is_none() && start.elapsed() < Duration::from_secs(20),
                    "the lab did not come up (child: {}; python3: {}; openssl: {}); its stderr:\n{}",
                    exited.map_or("still running".to_string(), |s| s.to_string()),
                    which("python3"),
                    which("openssl"),
                    std::fs::read_to_string(&log).unwrap_or_default()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Lab {
                _child: Some(child),
            }
        })
    }
}

/// Where a command resolves, for the diagnostic when the lab does not start.
fn which(name: &str) -> String {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "not found".into())
}

const LAB_PORTS: &str = "25025,28080,28443,29000,29001";

#[test]
#[cfg(target_os = "linux")]
fn the_direct_use_cases_hold_against_the_lab() {
    let _lab = Lab::start();
    let d = tempfile::tempdir().unwrap();

    // 1. A first scan, and the file it leaves behind.
    let run = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            LAB_PORTS,
            "--all",
            "--output-dir",
            "results",
        ],
    );
    assert_eq!(code(&run), 0, "{}", err(&run));
    let shown = out(&run);
    assert!(
        shown.contains("220 mail.lab.internal ESMTP ready"),
        "banner on the line: {shown}"
    );
    assert!(
        err(&run).contains("3 open, 2 closed, 0 filtered, 0 error (5 of 5 probed)"),
        "{}",
        err(&run)
    );
    let rec = record_in(&d.path().join("results"));
    let rec_s = rec.to_str().unwrap();

    // 2. Reading the record.
    let v = scanr(d.path(), &["output", "verify", rec_s]);
    assert_eq!(code(&v), 0);
    assert!(out(&v).contains("ok — record is complete and internally consistent"));
    let s = scanr(d.path(), &["output", "summarize", rec_s]);
    assert!(
        out(&s).contains("3 open, 2 closed, 0 filtered, 0 error"),
        "{}",
        out(&s)
    );
    let n = scanr(
        d.path(),
        &[
            "output", "results", "--states", "open", "--format", "nmap", rec_s,
        ],
    );
    assert_eq!(
        out(&n).trim(),
        "nmap -sV -Pn -n -p 25025,28080,28443 127.0.0.1"
    );
    let l = scanr(
        d.path(),
        &[
            "output", "results", "--states", "open", "--format", "list", rec_s,
        ],
    );
    assert_eq!(
        out(&l),
        "127.0.0.1:25025\n127.0.0.1:28080\n127.0.0.1:28443\n"
    );

    // Try to fool verify: drop the open row for 25025, then truncate.
    let text = scanr::testsupport::record_text(&rec);
    let tampered: String = text
        .lines()
        .filter(|l| !l.contains("\"port\":25025"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_ne!(tampered, text, "the tamper must remove a row");
    std::fs::write(d.path().join("tampered.jsonl"), tampered).unwrap();
    let t = scanr(d.path(), &["output", "verify", "tampered.jsonl"]);
    assert_eq!(code(&t), 2, "{}", out(&t));
    assert!(
        out(&t).contains("terminal event claims 5 completed probes"),
        "{}",
        out(&t)
    );
    let truncated: String = text
        .lines()
        .take(text.lines().count() - 1)
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(d.path().join("truncated.jsonl"), truncated).unwrap();
    let t = scanr(d.path(), &["output", "verify", "truncated.jsonl"]);
    assert_eq!(code(&t), 2);
    assert!(out(&t).contains("no terminal event"), "{}", out(&t));

    // 3. Look before you scan: both projection lines.
    let p = scanr(
        d.path(),
        &[
            "plan",
            "--targets",
            "10.0.0.0/24",
            "--ports",
            "1-65535",
            "--profile",
            "proxy",
        ],
    );
    assert!(out(&p).contains("16,776,960"), "{}", out(&p));
    assert!(
        out(&p).contains("if every probe answers") && out(&p).contains("if every probe times out"),
        "{}",
        out(&p)
    );

    // 9. Banners and the TLS probe.
    let tls = scanr(
        d.path(),
        &[
            "run",
            "--targets",
            "127.0.0.1",
            "--ports",
            "25025,28080,28443",
            "--tls",
            "--output-dir",
            "results-tls",
        ],
    );
    assert_eq!(code(&tls), 0, "{}", err(&tls));
    let shown = out(&tls);
    assert!(shown.contains("tls no reply"), "{shown}");
    assert!(shown.contains("tls1.2 h2 sha256:"), "{shown}");
    let rec = record_in(&d.path().join("results-tls"));
    let rows = scanr(
        d.path(),
        &[
            "output",
            "results",
            "--format",
            "json",
            rec.to_str().unwrap(),
        ],
    );
    let rows: Vec<Value> = out(&rows)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let tls_row = rows.iter().find(|r| r["port"] == 28443).unwrap();
    assert_eq!(tls_row["tls"]["negotiated"], "1.2");
    assert_eq!(tls_row["tls"]["alpn"], "h2");
    assert!(tls_row["tls"]["leaf_der"].is_string());
    let smtp = rows.iter().find(|r| r["port"] == 25025).unwrap();
    assert_eq!(smtp["banner"], "220 mail.lab.internal ESMTP ready\r\n");
    assert!(
        smtp.get("tls").is_none(),
        "a greeting service is never probed"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn the_interrupt_and_resume_use_case_holds_against_the_lab() {
    let _lab = Lab::start();
    let d = tempfile::tempdir().unwrap();

    // 8. Interruption: three hosts, two silent, two in flight; Ctrl-C after 1.5 s.
    let child = Command::new(BIN)
        .args([
            "run",
            "--targets",
            "127.0.0.1,192.0.2.1,192.0.2.2",
            "--ports",
            "25025,28080,29000,80,443,8080",
            "--all",
            "--concurrency",
            "2",
            "--connect-timeout",
            "2s",
            "--seed",
            "7",
            "--no-spans",
            "--output-dir",
            "results-int",
        ])
        .current_dir(d.path())
        .env("NO_COLOR", "1")
        .env("XDG_CONFIG_HOME", d.path().join(".xdg"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    // SAFETY-free: a plain libc call on a pid this test spawned.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(130), "{}", err(&o));
    let stderr = err(&o);
    assert!(stderr.contains("interrupted in"), "{stderr}");
    assert!(stderr.contains("of 18 probed"), "{stderr}");
    let rec = record_in(&d.path().join("results-int"));
    let v = scanr(d.path(), &["output", "verify", rec.to_str().unwrap()]);
    assert_eq!(code(&v), 0, "{}", out(&v));
    assert!(out(&v).contains("terminal: scan_interrupted"));

    // Exact resume: what remainder prints is what --pairs probes, and the records link.
    let rem = scanr(d.path(), &["output", "remainder", rec.to_str().unwrap()]);
    assert_eq!(code(&rem), 0);
    let remainder = out(&rem);
    assert!(remainder.starts_with("# resumed-from:"), "{remainder}");
    let outstanding = remainder
        .lines()
        .filter(|l| l.contains(':') && !l.starts_with('#'))
        .count();
    assert!(outstanding > 0 && outstanding < 18, "{remainder}");
    std::fs::write(d.path().join("pairs.txt"), &remainder).unwrap();
    let r = scanr(
        d.path(),
        &[
            "run",
            "--pairs",
            "pairs.txt",
            "--all",
            "--connect-timeout",
            "1s",
            "--output-dir",
            "results-resumed",
        ],
    );
    assert_eq!(code(&r), 0, "{}", err(&r));
    assert!(
        err(&r).contains(&format!("({outstanding} of {outstanding} probed)")),
        "{}",
        err(&r)
    );
    let rec2 = record_in(&d.path().join("results-resumed"));
    let v2 = scanr(d.path(), &["output", "verify", rec2.to_str().unwrap()]);
    assert_eq!(code(&v2), 0);
    assert!(out(&v2).contains("resumed from scan"), "{}", out(&v2));
}

// ── the proxied use cases, against the fixtures that model the real proxies ───

fn with_config(d: &Path, toml: &str) {
    std::fs::write(d.join("scanr.toml"), toml).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn the_proxied_use_cases_hold_against_the_fixtures() {
    use scanr::testsupport::http::{Behavior as H, HttpFixture};
    use scanr::testsupport::socks5::{Behavior as S, Socks5Fixture};
    let _lab = Lab::start();

    // 5. A faithful SOCKS5 proxy (dante) measures full; the scan keeps `closed`.
    let dante = Socks5Fixture::start(S::Faithful);
    let d = tempfile::tempdir().unwrap();
    with_config(
        d.path(),
        &format!(
            "version = 1\n[transports.dante]\ntype = \"socks5\"\naddress = \"{}\"\n",
            dante.addr()
        ),
    );
    let t = scanr(d.path(), &["transport", "test", "dante"]);
    assert!(out(&t).contains("fidelity          full"), "{}", out(&t));
    assert!(out(&t).contains("reply 0x05"), "{}", out(&t));
    let run = scanr(
        d.path(),
        &[
            "run",
            "--transport",
            "dante",
            "--targets",
            "127.0.0.1",
            "--ports",
            LAB_PORTS,
            "--all",
            "--output-dir",
            "out",
        ],
    );
    assert!(
        err(&run).contains("3 open, 2 closed, 0 filtered, 0 error"),
        "{}",
        err(&run)
    );

    // 5. `ssh -D`: no reply for a refused port; open_only; closed ports become error.
    let tunnel = Socks5Fixture::start(S::SilentOnFailure);
    let d = tempfile::tempdir().unwrap();
    with_config(
        d.path(),
        &format!(
            "version = 1\n[transports.tunnel]\ntype = \"socks5\"\naddress = \"{}\"\n",
            tunnel.addr()
        ),
    );
    let t = scanr(d.path(), &["transport", "test", "tunnel"]);
    assert!(
        out(&t).contains("fidelity          open_only"),
        "{}",
        out(&t)
    );
    assert!(out(&t).contains("no reply"), "{}", out(&t));
    let run = scanr(
        d.path(),
        &[
            "run",
            "--transport",
            "tunnel",
            "--profile",
            "ssh",
            "--targets",
            "127.0.0.1",
            "--ports",
            LAB_PORTS,
            "--all",
            "--output-dir",
            "out",
        ],
    );
    assert!(
        err(&run).contains("3 open, 0 closed, 0 filtered, 2 error"),
        "{}",
        err(&run)
    );

    // 6. HTTP CONNECT: open_only by construction, status lines in the errors.
    let corp = HttpFixture::start(H::Faithful);
    let d = tempfile::tempdir().unwrap();
    with_config(
        d.path(),
        &format!(
            "version = 1\n[transports.corp]\ntype = \"http\"\naddress = \"{}\"\n",
            corp.addr()
        ),
    );
    let t = scanr(d.path(), &["transport", "test", "corp"]);
    assert!(
        out(&t).contains("fidelity          open_only"),
        "{}",
        out(&t)
    );
    assert!(out(&t).contains("status 503"), "{}", out(&t));
    let run = scanr(
        d.path(),
        &[
            "run",
            "--transport",
            "corp",
            "--targets",
            "127.0.0.1",
            "--ports",
            LAB_PORTS,
            "--all",
            "--output-dir",
            "out",
        ],
    );
    assert!(
        err(&run).contains("3 open, 0 closed, 0 filtered, 2 error"),
        "{}",
        err(&run)
    );

    // 7. A chain http -> socks5 keeps the exit's `full`; a pool records `via`.
    let d = tempfile::tempdir().unwrap();
    let exit_b = Socks5Fixture::start(S::Faithful);
    with_config(
        d.path(),
        &format!(
            "version = 1\n[transports.corp]\ntype = \"http\"\naddress = \"{}\"\n\
         [transports.dante]\ntype = \"socks5\"\naddress = \"{}\"\nfidelity = \"full\"\n\
         [transports.exit-b]\ntype = \"socks5\"\naddress = \"{}\"\nfidelity = \"full\"\n\
         [transports.path]\ntype = \"chain\"\nhops = [\"corp\", \"dante\"]\n\
         [transports.spread]\ntype = \"pool\"\nmembers = [\"dante\", \"exit-b\"]\n",
            corp.addr(),
            dante.addr(),
            exit_b.addr()
        ),
    );
    let t = scanr(d.path(), &["transport", "test", "path"]);
    assert!(out(&t).contains("fidelity          full"), "{}", out(&t));
    assert!(
        out(&t).contains("a chain's fidelity is its exit hop's"),
        "{}",
        out(&t)
    );
    let run = scanr(
        d.path(),
        &[
            "run",
            "--transport",
            "spread",
            "--targets",
            "127.0.0.1",
            "--ports",
            LAB_PORTS,
            "--all",
            "--no-spans",
            "--output-dir",
            "out",
        ],
    );
    assert_eq!(code(&run), 0, "{}", err(&run));
    let rec = record_in(&d.path().join("out"));
    let rows = scanr(
        d.path(),
        &[
            "output",
            "results",
            "--format",
            "json",
            rec.to_str().unwrap(),
        ],
    );
    let rows: Vec<Value> = out(&rows)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 5);
    let members: std::collections::BTreeSet<&str> =
        rows.iter().filter_map(|r| r["via"].as_str()).collect();
    assert_eq!(
        members.len(),
        2,
        "both members must appear in `via`: {members:?}"
    );
}
