//! Regenerate the man pages from the CLI definition.
//!
//!     cargo run --example gen_man
//!
//! A test asserts the committed pages match what this produces, so the two cannot drift.
//! Generating from the clap definition means every flag and its help text is documented
//! by construction rather than by remembering.
//!
//! One page per subcommand, `scanr-run.1` and so on, which is the conventional layout
//! for a tool with a command tree.

use clap::CommandFactory;

fn main() -> std::io::Result<()> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("man");
    std::fs::create_dir_all(&dir)?;

    let top = scanr::cli::Cli::command();
    let mut written = write_page(&dir, "scanr", &top)?;

    for sub in top.get_subcommands() {
        // Give the page its own name so the header reads `scanr-run` rather than `run`.
        // clap's builder wants a 'static str; leaking in a one-shot generator is fine.
        let name: &'static str = format!("scanr-{}", sub.get_name()).leak();
        let page = sub.clone().name(name).display_name(name);
        written += write_page(&dir, name, &page)?;

        // A second level exists for the noun groups: `scanr config init` and friends.
        for leaf in page.get_subcommands() {
            let leaf_name: &'static str = format!("{name}-{}", leaf.get_name()).leak();
            let leaf_page = leaf.clone().name(leaf_name).display_name(leaf_name);
            written += write_page(&dir, leaf_name, &leaf_page)?;
        }
    }
    eprintln!("wrote {written} pages to {}", dir.display());
    Ok(())
}

fn write_page(dir: &std::path::Path, name: &str, cmd: &clap::Command) -> std::io::Result<usize> {
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone()).render(&mut buf)?;
    std::fs::write(dir.join(format!("{name}.1")), buf)?;
    Ok(1)
}
