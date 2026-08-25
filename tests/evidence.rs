//! `docs/evidence.md` maps every claim to the test, corpus scenario or measured decision
//! that backs it. A claim whose evidence has been renamed or deleted is a claim with no
//! evidence, so each reference is checked against what exists.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn rust_sources() -> Vec<PathBuf> {
    fn go(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                go(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    go(&root().join("src"), &mut out);
    go(&root().join("tests"), &mut out);
    out
}

/// Every `fn name` defined anywhere in the crate or its tests.
fn defined_fns() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for p in rust_sources() {
        let text = std::fs::read_to_string(&p).unwrap();
        for line in text.lines() {
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix("fn ").or_else(|| t.strip_prefix("pub fn ")) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
    }
    names
}

fn references(doc: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(i) = rest.find(prefix) {
        let after = &rest[i + prefix.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        out.push(name);
        rest = after;
    }
    out
}

#[test]
fn every_cited_test_exists() {
    let doc = std::fs::read_to_string(root().join("docs/evidence.md")).unwrap();
    let fns = defined_fns();
    let cited = references(&doc, "test:");
    assert!(
        cited.len() >= 60,
        "expected a substantial evidence map, found {} test citations",
        cited.len()
    );
    let missing: Vec<&String> = cited.iter().filter(|n| !fns.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "docs/evidence.md cites tests that do not exist: {missing:?}"
    );
}

#[test]
fn every_cited_corpus_scenario_exists() {
    let doc = std::fs::read_to_string(root().join("docs/evidence.md")).unwrap();
    let records = root().join("tests/compat/records");
    let missing: Vec<String> = references(&doc, "corpus:")
        .into_iter()
        .filter(|n| !records.join(n).is_dir())
        .collect();
    assert!(
        missing.is_empty(),
        "docs/evidence.md cites corpus scenarios that do not exist: {missing:?}"
    );
}

#[test]
fn every_cited_decision_exists() {
    let doc = std::fs::read_to_string(root().join("docs/evidence.md")).unwrap();
    let register = std::fs::read_to_string(root().join("docs/design/decisions.md")).unwrap();
    let mut missing = Vec::new();
    for token in doc.split(|c: char| !c.is_ascii_alphanumeric()) {
        if let Some(n) = token.strip_prefix('D')
            && !n.is_empty()
            && n.chars().all(|c| c.is_ascii_digit())
            && !register.contains(&format!("### D{n} "))
        {
            missing.push(token.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "docs/evidence.md cites decisions that do not exist: {missing:?}"
    );
}
