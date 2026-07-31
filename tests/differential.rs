//! Differential testing against nmap.
//!
//! Every other test in this repository checks scanr against scanr's own fixtures and my
//! own model of how a proxy behaves. That catches inconsistency, not a systematically
//! wrong idea. These tests compare verdicts against an independent implementation on
//! identical targets, which is the only check here that could catch the classification
//! logic being wrong in the same way everywhere.
//!
//! Ignored by default: they need nmap installed and take a few seconds. Run with
//!
//!     cargo test --test differential -- --ignored --nocapture
//!
//! They skip rather than fail when nmap is absent, so they are safe to leave enabled in
//! an environment that does not have it.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_scanr");

fn nmap_available() -> bool {
    Command::new("nmap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Hold listeners open for the life of the test, and report which ports they occupy.
struct Fixture {
    _listeners: Vec<TcpListener>,
    open: Vec<u16>,
    closed: Vec<u16>,
}

impl Fixture {
    fn build(open_count: usize, closed_count: usize) -> Self {
        let mut listeners = Vec::new();
        let mut open = Vec::new();
        for _ in 0..open_count {
            // Open ports may come from anywhere; a live listener cannot be displaced.
            let l = TcpListener::bind("127.0.0.1:0").expect("bind");
            open.push(l.local_addr().unwrap().port());
            let acceptor = l.try_clone().unwrap();
            std::thread::spawn(move || {
                for s in acceptor.incoming() {
                    drop(s);
                }
            });
            listeners.push(l);
        }
        // Known-closed ports are taken from *below* the ephemeral range, deliberately.
        //
        // Binding port 0 and releasing looks equivalent and is not: those ports come from
        // the same sequentially-rotating allocator that supplies the scanner's own
        // outbound source ports, so the two clusters overlap and a "closed" port can end
        // up occupied mid-scan. That produced a genuine open verdict, agreed on by both
        // scanr and nmap, for a port this fixture had declared closed.
        let mut closed = Vec::new();
        let mut candidate = 20_000u16;
        while closed.len() < closed_count {
            assert!(candidate < 30_000, "ran out of low ports for the fixture");
            // Bind then release, so the port is known-closed rather than merely unused,
            // and confirmed free rather than assumed.
            if let Ok(l) = TcpListener::bind(("127.0.0.1", candidate)) {
                drop(l);
                closed.push(candidate);
            }
            candidate += 1;
        }
        Self {
            _listeners: listeners,
            open,
            closed,
        }
    }

    fn all_ports(&self) -> String {
        let mut all: Vec<u16> = self.open.iter().chain(&self.closed).copied().collect();
        all.sort_unstable();
        all.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// port -> state, as scanr reports it.
fn scanr_states(
    target: &str,
    ports: &str,
    transport: &str,
    extra: &[&str],
) -> BTreeMap<u16, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut args: Vec<&str> = vec![
        "run",
        "--transport",
        transport,
        "--targets",
        target,
        "--ports",
        ports,
        "--output-dir",
        "out",
        "--all",
        "-q",
    ];
    args.extend_from_slice(extra);

    let out = Command::new(BIN)
        .args(&args)
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .env("NO_COLOR", "1")
        .output()
        .expect("scanr should run");
    assert!(
        out.status.success(),
        "scanr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let file =
        scanr::testsupport::find_record(&dir.path().join("out")).expect("a finalized record");

    scanr::testsupport::record_text(&file)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["type"] == "probe_result")
        .filter_map(|e| Some((e["port"].as_u64()? as u16, e["state"].as_str()?.to_string())))
        .collect()
}

/// port -> state, as nmap reports it, from greppable output.
fn nmap_states(target: &str, ports: &str) -> BTreeMap<u16, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("scan.gnmap");
    let out = Command::new("nmap")
        .args([
            "-sT", // connect scan, the same primitive scanr uses
            "-Pn", // no host discovery
            "-n",  // no DNS
            "-T4",
            "--host-timeout",
            "60s",
            "-p",
            ports,
            target,
            "-oG",
        ])
        .arg(&out_path)
        .output()
        .expect("nmap should run");
    assert!(
        out.status.success(),
        "nmap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&out_path).expect("nmap output");
    let mut states = BTreeMap::new();
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("Ports:") else {
            continue;
        };
        let ports_part = rest.split("Ignored").next().unwrap_or("");
        for entry in ports_part.split(',') {
            let fields: Vec<&str> = entry.trim().split('/').collect();
            if fields.len() >= 2
                && let Ok(p) = fields[0].parse::<u16>()
            {
                states.insert(p, fields[1].to_string());
            }
        }
    }
    states
}

fn compare(label: &str, a: &BTreeMap<u16, String>, b: &BTreeMap<u16, String>) {
    assert!(
        !a.is_empty() && !b.is_empty(),
        "{label}: no results to compare"
    );
    // Both sides key by port, so every comparison must involve exactly one host or
    // results would be silently overwritten and the count would flatter the test.
    assert_eq!(
        a.len(),
        b.len(),
        "{label}: different result counts, {} vs {}",
        a.len(),
        b.len()
    );
    let mut disagreements = Vec::new();
    for (port, left) in a {
        match b.get(port) {
            Some(right) if right == left => {}
            Some(right) => disagreements.push(format!("port {port}: {left} vs {right}")),
            None => disagreements.push(format!("port {port}: missing on one side")),
        }
    }
    assert!(
        disagreements.is_empty(),
        "{label}: {} of {} ports disagree:\n  {}",
        disagreements.len(),
        a.len(),
        disagreements.join("\n  ")
    );
    eprintln!("  {label}: {}/{} agree", a.len(), a.len());
}

#[test]
#[ignore = "needs nmap installed; run with --ignored"]
fn agrees_with_nmap_on_open_and_closed() {
    if !nmap_available() {
        eprintln!("nmap not installed; skipping");
        return;
    }
    let fx = Fixture::build(12, 20);
    let ports = fx.all_ports();

    let ours = scanr_states("127.0.0.1", &ports, "direct", &[]);
    let theirs = nmap_states("127.0.0.1", &ports);
    compare("scanr vs nmap (direct)", &ours, &theirs);

    // And the verdicts must match the fixture we constructed, not merely each other:
    // two implementations can agree and both be wrong.
    for p in &fx.open {
        assert_eq!(ours.get(p).map(String::as_str), Some("open"), "port {p}");
    }
    for p in &fx.closed {
        assert_eq!(ours.get(p).map(String::as_str), Some("closed"), "port {p}");
    }
}

#[test]
#[ignore = "needs nmap installed; run with --ignored"]
fn agrees_with_nmap_on_filtered() {
    if !nmap_available() {
        eprintln!("nmap not installed; skipping");
        return;
    }
    // RFC 5737 TEST-NET-1 is guaranteed unroutable, so both tools should see a timeout
    // rather than a refusal. This is the classification most likely to diverge.
    //
    // One host, several ports. Both helpers key by port, so a multi-host target would
    // collapse hosts together and silently compare far fewer results than it appeared to.
    let ours = scanr_states(
        "192.0.2.1",
        "80,443,8080,9090",
        "direct",
        &["--connect-timeout", "3s"],
    );
    let theirs = nmap_states("192.0.2.1", "80,443,8080,9090");
    assert!(
        ours.values().all(|s| s == "filtered"),
        "scanr should see unroutable targets as filtered, got {ours:?}"
    );
    compare("scanr vs nmap (filtered)", &ours, &theirs);
}

#[test]
#[ignore = "needs nmap installed; run with --ignored"]
fn a_proxied_scan_agrees_with_nmap_direct() {
    if !nmap_available() {
        eprintln!("nmap not installed; skipping");
        return;
    }
    use scanr::testsupport::socks5::{Behavior, Socks5Fixture};

    let fx = Fixture::build(10, 14);
    let ports = fx.all_ports();
    let proxy = Socks5Fixture::start(Behavior::Faithful);

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("scanr.toml"),
        format!(
            "version = 1\n[transports.fx]\ntype = \"socks5\"\naddress = \"{}\"\nfidelity = \"full\"\n",
            proxy.addr()
        ),
    )
    .unwrap();

    // Run scanr from that directory so it picks up the transport definition.
    let out = Command::new(BIN)
        .args([
            "run",
            "--transport",
            "fx",
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
        "proxied scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let file = scanr::testsupport::find_record(&dir.path().join("out")).unwrap();
    let proxied: BTreeMap<u16, String> = scanr::testsupport::record_text(&file)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["type"] == "probe_result")
        .filter_map(|e| Some((e["port"].as_u64()? as u16, e["state"].as_str()?.to_string())))
        .collect();

    // The claim being tested: scanning through a faithful proxy gives the same answers
    // as scanning directly with an independent tool.
    let theirs = nmap_states("127.0.0.1", &ports);
    compare("scanr via SOCKS5 vs nmap direct", &proxied, &theirs);
}
