//! The committed man pages must match the CLI definition.
//!
//! Generated documentation that is committed will drift the moment someone adds a flag,
//! and nothing would notice. This makes that a test failure with the fix in the message.

use std::path::Path;

use clap::CommandFactory;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn render(cmd: &clap::Command) -> String {
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .render(&mut buf)
        .expect("rendering a man page should not fail");
    String::from_utf8(buf).expect("roff output should be UTF-8")
}

/// Every page the generator would write, as (filename, contents).
fn expected() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let top = scanr::cli::Cli::command();
    out.push(("scanr.1".to_string(), render(&top)));

    for sub in top.get_subcommands() {
        let name: &'static str = format!("scanr-{}", sub.get_name()).leak();
        let page = sub.clone().name(name).display_name(name);
        out.push((format!("{name}.1"), render(&page)));
        for leaf in page.get_subcommands() {
            let leaf_name: &'static str = format!("{name}-{}", leaf.get_name()).leak();
            let leaf_page = leaf.clone().name(leaf_name).display_name(leaf_name);
            out.push((format!("{leaf_name}.1"), render(&leaf_page)));
        }
    }
    out
}

#[test]
fn committed_man_pages_are_current() {
    let dir = manifest_dir().join("man");
    let mut stale = Vec::new();

    for (name, contents) in expected() {
        let path = dir.join(&name);
        match std::fs::read_to_string(&path) {
            Ok(on_disk) if on_disk == contents => {}
            Ok(_) => stale.push(format!("{name} (differs)")),
            Err(_) => stale.push(format!("{name} (missing)")),
        }
    }

    assert!(
        stale.is_empty(),
        "man pages are out of date: {stale:?}\nrun: cargo run --example gen_man"
    );
}

#[test]
fn no_orphaned_man_pages() {
    // A renamed or removed subcommand should not leave a page documenting something the
    // tool no longer has.
    let dir = manifest_dir().join("man");
    let known: Vec<String> = expected().into_iter().map(|(n, _)| n).collect();
    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("man directory should exist") {
        let name = entry.expect("readable entry").file_name();
        let name = name.to_string_lossy().into_owned();
        if name.ends_with(".1") && !known.contains(&name) {
            orphans.push(name);
        }
    }
    assert!(
        orphans.is_empty(),
        "man pages document commands that no longer exist: {orphans:?}"
    );
}

#[test]
fn every_command_in_the_tree_has_a_page() {
    // Guards the generator itself: if the tree grows a level, the generator must be
    // taught about it rather than silently skipping the new commands.
    let top = scanr::cli::Cli::command();
    let mut expected_count = 1;
    for sub in top.get_subcommands() {
        expected_count += 1;
        expected_count += sub.get_subcommands().count();
        for leaf in sub.get_subcommands() {
            assert_eq!(
                leaf.get_subcommands().count(),
                0,
                "`{}` has a third level of subcommands, which gen_man does not emit",
                leaf.get_name()
            );
        }
    }
    assert_eq!(
        expected().len(),
        expected_count,
        "the generator did not produce one page per command"
    );
}
