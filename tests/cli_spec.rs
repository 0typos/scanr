//! The CLI specification must describe the CLI that exists.
//!
//! The JSONL spec and the man pages both had drift guards; this one did not, and it
//! drifted — `--pairs` and `--calibrate` were added and the specification never
//! mentioned either. A design document nobody can trust is worse than none, because it
//! is read as authoritative.

use std::collections::BTreeSet;
use std::path::Path;

use clap::CommandFactory;

fn spec() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/design/06-cli-spec.md");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The fenced block introduced by `<!-- MARKER: ... -->`.
///
/// Anchored to a marker comment rather than to a heading or an ordinal, so the document
/// can be reorganised without silently detaching the test from what it checks.
fn marked_block(text: &str, marker: &str) -> String {
    let after = text
        .split_once(&format!("<!-- {marker}"))
        .unwrap_or_else(|| panic!("the spec has no `{marker}` marker"))
        .1;
    let body = after
        .split_once("```")
        .expect("a marked block must be followed by a fence")
        .1;
    body.split_once("```")
        .expect("the fence must be closed")
        .0
        .to_string()
}

/// Every runnable command path in the clap tree, e.g. `config init`.
fn actual_commands() -> BTreeSet<String> {
    fn walk(cmd: &clap::Command, prefix: &str, out: &mut BTreeSet<String>) {
        let mut leaf = true;
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            leaf = false;
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            walk(sub, &path, out);
        }
        if leaf && !prefix.is_empty() {
            out.insert(prefix.to_string());
        }
    }
    let mut out = BTreeSet::new();
    walk(&scanr::cli::Cli::command(), "", &mut out);
    out
}

fn documented_commands() -> BTreeSet<String> {
    marked_block(&spec(), "COMMAND TREE")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Long flags accepted by `scanr run`, which carries the override allowlist.
///
/// Includes the top-level globals: clap propagates them into every subcommand, so
/// `scanr run --config x` is valid and the allowlist rightly lists them.
fn actual_run_flags() -> BTreeSet<String> {
    let cli = scanr::cli::Cli::command();
    let run = cli
        .get_subcommands()
        .find(|c| c.get_name() == "run")
        .expect("`run` exists");
    run.get_arguments()
        .chain(cli.get_arguments().filter(|a| a.is_global_set()))
        .filter_map(|a| a.get_long())
        // `--help` is clap's, not ours, and documenting it would be noise.
        .filter(|l| *l != "help")
        .map(|l| format!("--{l}"))
        .collect()
}

fn documented_run_flags() -> BTreeSet<String> {
    let block = marked_block(&spec(), "RUN FLAGS");
    let mut out = BTreeSet::new();
    for token in block.split_whitespace() {
        if let Some(name) = token.strip_prefix("--") {
            let name: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if !name.is_empty() {
                out.insert(format!("--{name}"));
            }
        }
    }
    out
}

#[test]
fn every_command_is_in_the_spec() {
    let (actual, documented) = (actual_commands(), documented_commands());
    let missing: Vec<_> = actual.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "these commands exist but are undocumented in docs/design/06-cli-spec.md: {missing:?}"
    );
}

#[test]
fn the_spec_describes_no_command_that_was_removed() {
    let (actual, documented) = (actual_commands(), documented_commands());
    let extra: Vec<_> = documented.difference(&actual).collect();
    assert!(
        extra.is_empty(),
        "docs/design/06-cli-spec.md documents commands that do not exist: {extra:?}"
    );
}

#[test]
fn every_run_flag_is_in_the_override_allowlist() {
    let (actual, documented) = (actual_run_flags(), documented_run_flags());
    let missing: Vec<_> = actual.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "`scanr run` accepts these flags but the override allowlist omits them: {missing:?}\n\
         The allowlist is the argument for why runs stay reproducible from a file, so a \
         flag missing from it is a hole in that argument."
    );
}

#[test]
fn the_allowlist_promises_no_flag_that_does_not_exist() {
    let (actual, documented) = (actual_run_flags(), documented_run_flags());
    let extra: Vec<_> = documented.difference(&actual).collect();
    assert!(
        extra.is_empty(),
        "the override allowlist names flags `scanr run` does not accept: {extra:?}"
    );
}

#[test]
fn the_documented_exit_codes_match_the_code() {
    use scanr::run::Termination;
    let text = spec();
    for (code, meaning) in [
        (Termination::Completed.exit_code(), "0"),
        (Termination::Failed.exit_code(), "2"),
        (Termination::Interrupted.exit_code(), "130"),
    ] {
        assert_eq!(code.to_string(), meaning);
        assert!(
            text.contains(&format!("| {meaning} |")) || text.contains(&format!("`{meaning}`")),
            "exit code {meaning} is not documented in the CLI spec"
        );
    }
}
