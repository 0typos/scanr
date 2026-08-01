//! Capture build provenance so a scan record can say which binary produced it.
//!
//! For a tool whose value is a forensic record, "which build wrote this file" is not
//! optional. Done here with `std::process::Command` rather than a crate: it is a dozen
//! lines and adds nothing to the dependency tree.

use std::process::Command;

fn main() {
    println!("cargo:rustc-env=SCANR_GIT_SHA={}", git_sha());
    println!("cargo:rustc-env=SCANR_RUSTC={}", rustc_version());
    println!(
        "cargo:rustc-env=SCANR_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );

    // Rebuild when the checked-out commit changes. Both paths are needed: HEAD moves on
    // checkout, the ref file moves on commit.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Some(r) = head_ref() {
        println!("cargo:rerun-if-changed=.git/{r}");
    }
}

fn capture(cmd: &mut Command) -> Option<String> {
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn git_sha() -> String {
    // A packaged or exported source tree has no `.git`, which is expected rather than an
    // error; the record then says "unknown" instead of carrying a stale value.
    //
    // But `git` searches *upwards*, so a source tree vendored inside another repository
    // answers with that repository's commit — measured: a copy of this crate dropped into
    // an unrelated repo stamped its HEAD, and every record claimed provenance from a
    // commit that never contained scanr. Only trust the answer when the repository git
    // found is this crate, which is what comparing toplevel to the manifest directory
    // establishes.
    if !git_repo_is_this_crate() {
        return "unknown".into();
    }
    let Some(sha) = capture(Command::new("git").args(["rev-parse", "--short=9", "HEAD"])) else {
        return "unknown".into();
    };
    let dirty = capture(Command::new("git").args(["status", "--porcelain"])).is_some();
    if dirty { format!("{sha}-dirty") } else { sha }
}

/// Whether the repository `git` resolves from here is this crate rather than one
/// containing it.
///
/// Canonicalized on both sides so a symlinked checkout compares equal.
fn git_repo_is_this_crate() -> bool {
    let Some(top) = capture(Command::new("git").args(["rev-parse", "--show-toplevel"])) else {
        return false;
    };
    let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    match (
        std::fs::canonicalize(&top),
        std::fs::canonicalize(&manifest),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn rustc_version() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    capture(Command::new(rustc).arg("--version")).unwrap_or_else(|| "unknown".into())
}

fn head_ref() -> Option<String> {
    let head = std::fs::read_to_string(".git/HEAD").ok()?;
    head.strip_prefix("ref: ").map(|r| r.trim().to_string())
}
