//! The command reference must describe the CLI that exists.
//!
//! The record schema and the man pages both had drift guards; this one did not, and it
//! drifted — `--pairs` and `--calibrate` were added and the reference never mentioned
//! either. Documentation nobody can trust is worse than none, because it is read as
//! authoritative anyway.
//!
//! This now points at `docs/cli.md`, a page users read, rather than at a design-only
//! specification. Holding a private document still while the public one drifts had the
//! guarantee backwards.

use std::collections::BTreeSet;
use std::path::Path;

use clap::CommandFactory;

fn spec() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/cli.md");
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

/// Every long flag on every subcommand, not just `run`'s.
///
/// `docs/cli.md` opens by claiming it lists "every command and every command-line flag",
/// but the only guard was over `run`'s override allowlist — so a flag added to
/// `output summarize` or `config init` could go undocumented indefinitely while the page
/// still claimed completeness. Five had.
fn actual_flags_everywhere() -> BTreeSet<(String, String)> {
    fn walk(cmd: &clap::Command, prefix: &str, out: &mut BTreeSet<(String, String)>) {
        for sub in cmd.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_string()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            for a in sub.get_arguments() {
                if let Some(l) = a.get_long()
                    && l != "help"
                    && !a.is_global_set()
                {
                    out.insert((path.clone(), format!("--{l}")));
                }
            }
            walk(sub, &path, out);
        }
    }
    let mut out = BTreeSet::new();
    walk(&scanr::cli::Cli::command(), "", &mut out);
    out
}

#[test]
fn every_flag_on_every_command_is_documented() {
    let text = spec();
    let missing: Vec<_> = actual_flags_everywhere()
        .into_iter()
        .filter(|(_, flag)| !text.contains(flag.as_str()))
        .map(|(cmd, flag)| format!("{cmd} {flag}"))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/cli.md claims to list every flag but omits these: {missing:?}"
    );
}

#[test]
fn every_command_is_in_the_spec() {
    let (actual, documented) = (actual_commands(), documented_commands());
    let missing: Vec<_> = actual.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "these commands exist but are undocumented in docs/cli.md: {missing:?}"
    );
}

#[test]
fn the_spec_describes_no_command_that_was_removed() {
    let (actual, documented) = (actual_commands(), documented_commands());
    let extra: Vec<_> = documented.difference(&actual).collect();
    assert!(
        extra.is_empty(),
        "docs/cli.md documents commands that do not exist: {extra:?}"
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

/// A usage error must exit `1`, not clap's default `2`.
///
/// `2` means "the scan failed after starting", so the two are not interchangeable: a
/// wrapper that retries on 2 would retry a misspelled flag forever, and one that treats 2
/// as a network fault would report a typo as an outage. `--help` and `--version` are a
/// success. These run the real binary, because the collision lived in `main`'s use of
/// `Cli::parse` and no amount of testing the parser would have shown it.
#[test]
fn usage_errors_exit_one_and_help_exits_zero() {
    const BIN: &str = env!("CARGO_BIN_EXE_scanr");
    for (args, want, what) in [
        (vec!["--help"], 0, "--help"),
        (vec!["--version"], 0, "--version"),
        (vec!["run", "--no-such-flag"], 1, "an unknown flag"),
        (vec!["no-such-subcommand"], 1, "an unknown subcommand"),
        (vec![], 1, "no arguments"),
        (vec!["run", "--ports"], 1, "a flag missing its value"),
    ] {
        let out = std::process::Command::new(BIN)
            .args(&args)
            .output()
            .expect("binary should run");
        assert_eq!(
            out.status.code(),
            Some(want),
            "{what} exited {:?}, expected {want}",
            out.status.code()
        );
    }
}

// ── the profile table ───────────────────────────────────────────────────────

/// `docs/configuration.md` must describe the profiles that exist, with their real values.
///
/// This is the drift that prompted the check. The table said "Four built-ins" long after
/// `ssh-fast`, `ssh` and `ssh-slow` were added, and listed `direct-fast` at a 1 s timeout
/// with `retries = 0` when it had become 300 ms with `retries = 1` — the retry being the
/// entire reason a sub-second timeout is safe. Three of the six columns were wrong on the
/// one row a reader is most likely to copy.
///
/// The same figures had also been duplicated into the README, where they drifted
/// independently. There is now one table, and this holds it to the code.
#[test]
fn the_documented_profiles_match_the_builtins() {
    use scanr::config::builtin::builtin_profiles;

    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/configuration.md"),
    )
    .expect("configuration.md should be readable");

    // Rows look like: | `direct` | 512 | unlimited | 2s | 1 | routed networks |
    let rows: std::collections::BTreeMap<String, Vec<String>> = doc
        .lines()
        .filter(|l| l.starts_with("| `"))
        .filter_map(|l| {
            let cells: Vec<String> = l
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().trim_matches('`').to_string())
                .collect();
            (cells.len() == 6).then(|| (cells[0].clone(), cells))
        })
        .collect();

    for p in builtin_profiles() {
        let row = rows.get(p.name).unwrap_or_else(|| {
            panic!(
                "docs/configuration.md has no row for the `{}` profile",
                p.name
            )
        });
        assert_eq!(
            row[1],
            p.timing.concurrency.to_string(),
            "{}: concurrency",
            p.name
        );
        let rate = if p.timing.rate == 0 {
            "unlimited".to_string()
        } else {
            format!("{}/s", p.timing.rate)
        };
        assert_eq!(row[2], rate, "{}: rate", p.name);
        // The same renderer `scanr plan` prints these with, so the table cannot
        // agree with the test while disagreeing with the tool.
        assert_eq!(
            row[3],
            scanr::units::render_duration(p.timing.connect_timeout),
            "{}: connect",
            p.name
        );
        assert_eq!(row[4], p.timing.retries.to_string(), "{}: retries", p.name);
    }

    let documented: std::collections::BTreeSet<&str> = rows.keys().map(String::as_str).collect();
    let actual: std::collections::BTreeSet<&str> =
        builtin_profiles().iter().map(|p| p.name).collect();
    let extra: Vec<_> = documented.difference(&actual).collect();
    assert!(
        extra.is_empty(),
        "docs/configuration.md documents profiles that do not exist: {extra:?}"
    );

    // The prose counts them, and that count drifted too.
    assert!(
        doc.contains(&format!("{} built-ins", spell(actual.len()))),
        "the profile count in the prose does not match the {} that exist",
        actual.len()
    );
}

fn spell(n: usize) -> &'static str {
    match n {
        4 => "Four",
        5 => "Five",
        6 => "Six",
        7 => "Seven",
        8 => "Eight",
        9 => "Nine",
        // A fallback that returned a word the document would never contain made the
        // failure read as "the prose is wrong" when the real cause is this list.
        _ => panic!("add {n} to `spell` so the profile-count assertion stays meaningful"),
    }
}
