//! Command-line interface.
//!
//! Verbs at top level for the two daily drivers (`run`, `plan`); noun groups for
//! everything else. Twelve commands, down from the twenty-four originally sketched —
//! each remaining one maps to a stated workflow.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::cancel::Cancel;
use crate::config::{self, ConfigError};
use crate::diag::HostFacts;
use crate::output::human::Style;
use crate::plan::types::{DnsMode, Fidelity, ScanPlan, TransportKind};
use crate::plan::{Overrides, resolve};
use crate::run::{RunOptions, Termination};
use crate::units::{HumanElapsed, commas, parse_duration, render_duration};
use crate::verify::Grouping;

/// `--version` reports the commit the binary was built from, so a result file can be
/// traced back to an exact build.
fn build_version() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(crate::run::build_info)
}

/// Exit codes are part of the interface; see docs/design/06-cli-spec.md.
pub const EXIT_OK: u8 = 0;
pub const EXIT_USAGE: u8 = 1;
pub const EXIT_SCAN_FAILED: u8 = 2;
pub const EXIT_WRITER_FAILED: u8 = 3;
pub const EXIT_INTERRUPTED: u8 = 130;

#[derive(Parser)]
#[command(
    name = "scanr",
    version,
    long_version = build_version(),
    about = "Proxy-aware TCP connect scanner with reproducible, durable scan records",
    long_about = "scanr performs unprivileged TCP connect() probes directly or through a \
                  SOCKS5 proxy, streams open ports to stdout as they are found, and always \
                  writes a JSONL record containing the fully resolved configuration and a \
                  single terminal event stating whether the run completed, was interrupted, \
                  or failed.",
    after_help = "EXAMPLES:\n  \
        scanr config init\n  \
        scanr plan internal-web\n  \
        scanr run internal-web\n  \
        scanr run internal-web --profile proxy-careful\n  \
        scanr run --targets 10.20.30.0/24 --ports 22,80,443\n  \
        subfinder -d example.com | scanr run --targets - --ports web\n  \
        scanr transport test lab\n  \
        scanr output verify scanr-results/scan-*.jsonl.gz",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Use this config file instead of the discovered user and project files
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Suppress the header, progress, and summary on stderr
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Show additional detail
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable coloured output (also honours NO_COLOR)
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Execute a scan
    Run {
        /// Name of a scan defined in configuration; omit for an ad-hoc scan
        scan: Option<String>,
        #[command(flatten)]
        overrides: OverrideArgs,
    },
    /// Resolve a scan and show the plan without touching the network
    Plan {
        /// Name of a scan defined in configuration; omit for an ad-hoc scan
        scan: Option<String>,
        #[command(flatten)]
        overrides: OverrideArgs,
    },
    /// Inspect and manage configuration
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Inspect and test transports
    #[command(subcommand)]
    Transport(TransportCmd),
    /// Inspect prior scan records
    #[command(subcommand)]
    Output(OutputCmd),
    /// Generate a shell completion script
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Write an annotated scanr.toml documenting every field
    Init {
        /// Where to write it
        #[arg(default_value = "scanr.toml")]
        path: PathBuf,
        /// Overwrite an existing file
        #[arg(long)]
        force: bool,
    },
    /// Show the merged configuration
    Show,
    /// Check configuration without running anything
    Validate,
    /// Show which configuration files were discovered
    Path,
}

#[derive(Subcommand)]
enum TransportCmd {
    /// List defined transports
    List,
    /// Show one transport's resolved settings
    Show { name: String },
    /// Measure a proxy's reachability, authentication, and result fidelity
    Test {
        name: String,
        /// Destination expected to be open; defaults to the proxy's own address
        #[arg(long, value_name = "HOST:PORT")]
        known_open: Option<String>,
        /// Destination expected to be closed; defaults to port 1 on the proxy host
        #[arg(long, value_name = "HOST:PORT")]
        known_closed: Option<String>,
        /// Also sweep concurrency to find where this proxy starts refusing connections.
        /// Generates real traffic and takes about a minute.
        #[arg(long)]
        calibrate: bool,
    },
}

#[derive(Subcommand)]
enum OutputCmd {
    /// Summarize a scan record
    Summarize {
        file: PathBuf,
        /// Arrange the open ports: flat, by host, by port, or by service
        #[arg(long, value_name = "FIELD", default_value = "flat", value_parser = grouping_arg)]
        by: Grouping,
    },
    /// Check a scan record for integrity and completeness
    Verify { file: PathBuf },
    /// Print targets that were not fully probed, for feeding back into --targets
    Remainder { file: PathBuf },
    /// Write the record as plain JSONL, decompressing it if needed
    Cat { file: PathBuf },
}

// `PowerShell` trips enum_variant_names, but the name is the shell's, not ours.
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

/// The CLI override allowlist. Anything not here lives in configuration, which is what
/// keeps a run reproducible from a file rather than from shell history.
#[derive(Args, Clone, Default)]
struct OverrideArgs {
    /// Timing profile: proxy-careful, proxy, direct, direct-fast, or one you defined
    #[arg(long)]
    profile: Option<String>,

    /// Transport name
    #[arg(long)]
    transport: Option<String>,

    /// Targets: specs, a named set, a file path, or `-` for stdin (repeatable)
    #[arg(long, value_name = "SPEC|FILE|-", action = clap::ArgAction::Append)]
    targets: Option<Vec<String>>,

    /// Ports: `80`, `1-1024`, `all`, or a named set (repeatable)
    #[arg(long, value_name = "SPEC", action = clap::ArgAction::Append)]
    ports: Option<Vec<String>>,

    /// Exact `host:port` endpoints from `scanr output remainder`; a file, or `-` for
    /// stdin. IPv6 must be bracketed. Cannot be combined with --targets or --ports.
    #[arg(
        long,
        value_name = "FILE|-",
        action = clap::ArgAction::Append,
        conflicts_with_all = ["targets", "ports"]
    )]
    pairs: Option<Vec<String>>,

    /// The scan_id this run continues, recorded in the record so a resumed scan can be
    /// traced back. Picked up automatically from `scanr output remainder`.
    #[arg(long, value_name = "SCAN_ID", requires = "pairs")]
    resumed_from: Option<String>,

    /// Targets to exclude after expansion (repeatable)
    #[arg(long, value_name = "SPEC|FILE", action = clap::ArgAction::Append)]
    exclude: Option<Vec<String>>,

    /// In-flight probes; also the worker thread count
    #[arg(long, value_name = "N")]
    concurrency: Option<u32>,

    /// Launch rate ceiling in probes/second, 0 for unlimited
    #[arg(long, value_name = "N")]
    rate: Option<u32>,

    /// Destination connection timeout, e.g. 2s or 500ms
    #[arg(long, value_name = "DURATION", value_parser = duration_arg)]
    connect_timeout: Option<Duration>,

    /// Retries for probes that time out
    #[arg(long, value_name = "N")]
    retries: Option<u32>,

    /// Who resolves hostnames
    #[arg(long, value_name = "MODE", value_parser = dns_arg)]
    dns: Option<DnsMode>,

    /// Directory for JSONL scan records
    #[arg(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// Permutation seed, so a randomized scan can be replayed exactly
    #[arg(long, value_name = "HEX", value_parser = seed_arg)]
    seed: Option<u64>,

    /// Print only open ports (default)
    #[arg(long, conflicts_with = "all")]
    open_only: bool,

    /// Print every probe result, not just open ports
    #[arg(long)]
    all: bool,

    /// Write the record as gzip (default). Roughly 20x smaller; `zcat`, `zless` and
    /// `scanr output` read it unchanged.
    #[arg(long)]
    compress: bool,

    /// Write the record as plain JSONL, so it can be grepped directly
    #[arg(long, conflicts_with = "compress")]
    no_compress: bool,

    /// Collapse repetitive closed/filtered results into span events instead of one row
    /// each (default). Much smaller records; drops per-probe timestamps for those.
    #[arg(long)]
    spans: bool,

    /// Write one row per probe, keeping every timestamp
    #[arg(long, conflicts_with = "spans")]
    no_spans: bool,

    /// Permit target sets larger than 4,000,000 addresses
    #[arg(long)]
    allow_large_range: bool,
}

/// Resolve a `--thing` / `--no-thing` pair. `None` leaves it to configuration, which is
/// what keeps the CLI an override layer rather than a second source of defaults.
fn flag(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

fn duration_arg(s: &str) -> Result<Duration, String> {
    parse_duration(s).map_err(|e| e.to_string())
}

fn grouping_arg(s: &str) -> Result<Grouping, String> {
    Grouping::parse(s).ok_or_else(|| format!("expected one of: {}", Grouping::ALL.join(", ")))
}

fn dns_arg(s: &str) -> Result<DnsMode, String> {
    DnsMode::parse(s).ok_or_else(|| format!("expected one of: {}", DnsMode::ALL.join(", ")))
}

fn seed_arg(s: &str) -> Result<u64, String> {
    let t = s.trim_start_matches("0x");
    u64::from_str_radix(t, 16)
        .or_else(|_| s.parse::<u64>())
        .map_err(|_| "expected a 64-bit value in hex (e.g. 9f2c00a1b4de7731) or decimal".into())
}

impl OverrideArgs {
    fn to_overrides(&self) -> Overrides {
        Overrides {
            profile: self.profile.clone(),
            transport: self.transport.clone(),
            targets: self.targets.clone(),
            ports: self.ports.clone(),
            pairs: self.pairs.clone(),
            resumed_from: self.resumed_from.clone(),
            exclude: self.exclude.clone(),
            concurrency: self.concurrency,
            rate: self.rate,
            connect_timeout: self.connect_timeout,
            retries: self.retries,
            dns: self.dns,
            output_dir: self.output_dir.clone(),
            seed: self.seed,
            compress: flag(self.compress, self.no_compress),
            spans: flag(self.spans, self.no_spans),
            open_only: flag(self.open_only, self.all),
            allow_large_range: self.allow_large_range,
        }
    }
}

// ── signal handling ─────────────────────────────────────────────────────────

static SIGINT_COUNT: AtomicU8 = AtomicU8::new(0);

/// Async-signal-safe: touches one atomic and nothing else. No allocation, no locks,
/// no formatting.
extern "C" fn on_sigint(_sig: libc::c_int) {
    let n = SIGINT_COUNT.load(Ordering::Relaxed);
    if n < 2 {
        SIGINT_COUNT.store(n + 1, Ordering::SeqCst);
    }
}

fn install_signal_handler() {
    // SAFETY: `on_sigint` performs only atomic stores, which is permitted in a handler.
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_sigint as *const () as libc::sighandler_t);
        // A closed stdout (`| head`) must not kill the scan before it finalizes.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        // Likewise for exceeding RLIMIT_FSIZE: the write should fail with EFBIG so we
        // can report it and leave a .partial file, rather than the process dying.
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
}

/// Watches the signal counter and escalates the scan's cancellation state, keeping
/// signal handling out of the scan engine so it stays testable.
fn spawn_signal_watcher(cancel: Cancel) {
    std::thread::Builder::new()
        .name("scanr-signals".into())
        .spawn(move || {
            loop {
                match SIGINT_COUNT.load(Ordering::SeqCst) {
                    0 => {}
                    1 => cancel.request_graceful(),
                    _ => {
                        cancel.request_forced();
                        return;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
        .ok();
}

// ── entry point ─────────────────────────────────────────────────────────────

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    install_signal_handler();
    ExitCode::from(dispatch(cli))
}

fn dispatch(cli: Cli) -> u8 {
    let style = Style::for_stream(std::io::stderr().is_terminal_like(), cli.no_color);
    match run_command(&cli) {
        Ok(code) => code,
        Err(e) => {
            let source = e
                .path
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok());
            let rendered = e.render(source.as_deref());
            let _ = writeln!(std::io::stderr(), "{}", colorize_error(&rendered, &style));
            EXIT_USAGE
        }
    }
}

/// Small helper so `Style::for_stream` reads clearly at the call site.
trait TerminalLike {
    fn is_terminal_like(&self) -> bool;
}
impl TerminalLike for std::io::Stderr {
    fn is_terminal_like(&self) -> bool {
        use std::io::IsTerminal;
        self.is_terminal()
    }
}

fn colorize_error(s: &str, style: &Style) -> String {
    if !style.color {
        return s.to_string();
    }
    s.lines()
        .map(|l| {
            if let Some(rest) = l.strip_prefix("error: ") {
                format!("{} {rest}", style.paint("1;31", "error:"))
            } else if let Some(rest) = l.strip_prefix("help: ") {
                format!("{} {rest}", style.paint("1;36", "help:"))
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_command(cli: &Cli) -> Result<u8, ConfigError> {
    match &cli.command {
        Command::Run { scan, overrides } => cmd_run(cli, scan.as_deref(), overrides),
        Command::Plan { scan, overrides } => cmd_plan(cli, scan.as_deref(), overrides),
        Command::Config(c) => cmd_config(cli, c),
        Command::Transport(t) => cmd_transport(cli, t),
        Command::Output(o) => cmd_output(cli, o),
        Command::Completion { shell } => {
            let mut cmd = Cli::command();
            let shell = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
                Shell::Elvish => clap_complete::Shell::Elvish,
                Shell::PowerShell => clap_complete::Shell::PowerShell,
            };
            clap_complete::generate(shell, &mut cmd, "scanr", &mut std::io::stdout());
            Ok(EXIT_OK)
        }
    }
}

fn load_config(cli: &Cli) -> Result<crate::config::raw::Layered, ConfigError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let discovery = config::discover(cli.config.as_deref(), &cwd);
    let files = config::load(&discovery)?;
    let errors = config::validate(&files);
    if let Some(first) = errors.into_iter().next() {
        return Err(first);
    }
    Ok(files)
}

fn build_plan(
    cli: &Cli,
    scan: Option<&str>,
    overrides: &OverrideArgs,
) -> Result<ScanPlan, ConfigError> {
    let files = load_config(cli)?;
    let facts = HostFacts::probe();
    resolve(&files, scan, &overrides.to_overrides(), &facts)
}

// ── run ─────────────────────────────────────────────────────────────────────

fn cmd_run(cli: &Cli, scan: Option<&str>, overrides: &OverrideArgs) -> Result<u8, ConfigError> {
    let plan = Arc::new(build_plan(cli, scan, overrides)?);
    let cancel = Cancel::new();
    spawn_signal_watcher(cancel.clone());

    let opts = RunOptions {
        quiet: cli.quiet,
        no_color: cli.no_color,
        verbose: cli.verbose,
    };

    match crate::run::execute(plan, cancel, &opts) {
        Ok(summary) => {
            crate::run::print_summary(&summary, cli.quiet);
            if summary.writer_failed {
                return Ok(EXIT_WRITER_FAILED);
            }
            Ok(summary.termination.exit_code())
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "error: {e}");
            // A writer failure is reported as such wherever it happens. Previously a
            // failure while writing the header returned 2 while the identical failure
            // one event later returned 3, which made the exit code depend on timing.
            Ok(match e {
                crate::run::ScanError::Writer(_) => EXIT_WRITER_FAILED,
                crate::run::ScanError::Output { .. } => EXIT_SCAN_FAILED,
            })
        }
    }
}

// ── plan ────────────────────────────────────────────────────────────────────

fn cmd_plan(cli: &Cli, scan: Option<&str>, overrides: &OverrideArgs) -> Result<u8, ConfigError> {
    let plan = build_plan(cli, scan, overrides)?;
    let facts = HostFacts::probe();
    let mut out = std::io::stdout();
    let _ = write!(out, "{}", render_plan(&plan, &facts, cli.no_color));
    Ok(EXIT_OK)
}

/// Three columns: field, effective value, provenance. The warnings are the point — they
/// say what the run cannot tell you before it is spent.
pub fn render_plan(plan: &ScanPlan, facts: &HostFacts, no_color: bool) -> String {
    use std::io::IsTerminal;
    let style = Style::for_stream(std::io::stdout().is_terminal() && !no_color, no_color);
    let mut s = String::new();

    let mut row = |k: &str, v: String, src: &str| plan_row(&mut s, &style, k, v, src);

    row("scan", plan.scan_name.clone(), "");
    if let Some(d) = &plan.description {
        row("description", d.clone(), "");
    }
    row(
        "profile",
        plan.profile.clone(),
        &plan.provenance.render("profile"),
    );
    row(
        "transport",
        format!("{} ({})", plan.transport.name, plan.transport.type_name()),
        &plan.provenance.render("transport"),
    );
    if let TransportKind::Socks5 {
        address, username, ..
    } = &plan.transport.kind
    {
        row("  address", address.to_string(), "");
        if let Some(u) = username {
            row("  username", format!("{u} (password [redacted])"), "");
        }
        row(
            "  fidelity",
            plan.transport.fidelity.to_string(),
            if plan.transport.fidelity == Fidelity::Unknown {
                "not measured"
            } else {
                "declared in config"
            },
        );
    }
    row(
        "dns",
        format!("{} -> {}", plan.dns_requested, plan.dns_effective),
        &plan.provenance.render("dns"),
    );
    // A pair scan is an explicit endpoint list, not a matrix, and describing it as one
    // reads as nonsense: the old rendering produced `targets 2 (3 explicit host:port
    // pairs)` and `ports 3 ((explicit pairs))`. `plan` is the "look before you scan"
    // surface, so it should be the last place the tool is unclear about what it will do.
    if plan.is_pair_scan() {
        row("mode", "explicit endpoints".into(), "");
        if let Some(id) = &plan.resumed_from {
            row("  resumed from", format!("scan {id}"), "");
        }
        row(
            "endpoints",
            format!(
                "{} across {} host(s), {} distinct port(s)",
                commas(plan.probe_count()),
                commas(plan.targets.len() as u64),
                plan.ports.len()
            ),
            "",
        );
    } else {
        row(
            "targets",
            format!(
                "{} ({})",
                commas(plan.targets.len() as u64),
                truncate(&plan.target_specs.join(", "), 34)
            ),
            "",
        );
        if !plan.exclude_specs.is_empty() {
            row(
                "  exclude",
                truncate(&plan.exclude_specs.join(", "), 38),
                "",
            );
        }
        row(
            "ports",
            format!("{} ({})", plan.ports.len(), truncate(&plan.port_spec, 30)),
            "",
        );
    }
    row("probes", commas(plan.probe_count()), "");
    row(
        "order",
        format!("randomized, seed {:016x}", plan.seed),
        &plan.provenance.render("seed"),
    );
    render_plan_timing(&mut s, plan, &style);

    render_plan_footer(&mut s, plan, facts, &style);
    s
}

/// Projection, host facts, and any planning warnings — everything below the value rows.
/// One aligned `key  value  provenance` line.
///
/// Free rather than a closure so the plan can be rendered in sections without each one
/// re-deriving the layout.
fn plan_row(s: &mut String, style: &Style, k: &str, v: String, src: &str) {
    // Only pad the value column when there is a provenance column to align to,
    // otherwise every row without one carries trailing whitespace.
    let line = if src.is_empty() {
        format!("{k:<16}{v}")
    } else {
        format!("{k:<16}{v:<40}{}", style.dim(src))
    };
    s.push_str(line.trim_end());
    s.push('\n');
}

/// The knobs that decide how hard the scan pushes, and where each came from.
fn render_plan_timing(s: &mut String, plan: &ScanPlan, style: &Style) {
    let mut row = |k: &str, v: String, src: &str| plan_row(s, style, k, v, src);
    row(
        "concurrency",
        plan.timing.concurrency.to_string(),
        &plan.provenance.render("concurrency"),
    );
    row(
        "rate",
        if plan.timing.rate == 0 {
            "unlimited".into()
        } else {
            format!("{}/s", plan.timing.rate)
        },
        &plan.provenance.render("rate"),
    );
    row(
        "connect_timeout",
        render_duration(plan.timing.connect_timeout),
        &plan.provenance.render("connect_timeout"),
    );
    if plan.transport.supports_remote_dns() {
        row(
            "proxy_timeouts",
            format!(
                "connect {}, handshake {}",
                render_duration(plan.timing.proxy_connect_timeout),
                render_duration(plan.timing.handshake_timeout)
            ),
            &plan.provenance.render("proxy_connect_timeout"),
        );
    }
    row(
        "retries",
        format!(
            "{} (timeouts only, delay {})",
            plan.timing.retries,
            render_duration(plan.timing.retry_delay)
        ),
        &plan.provenance.render("retries"),
    );
    row(
        "output",
        plan.output_dir.display().to_string(),
        &plan.provenance.render("output_dir"),
    );
    // Both change what the record contains, so they belong on the surface whose job is
    // to say what the run will do before it does it.
    // Two rows, not one: they are separate decisions from possibly separate layers, and
    // a single row can only carry one provenance while displaying both.
    row(
        "  format",
        if plan.compress {
            "gzip".into()
        } else {
            "plain jsonl".into()
        },
        &plan.provenance.render("compress"),
    );
    row(
        "  detail",
        if plan.spans {
            "repeated outcomes collapsed".into()
        } else {
            "one row per probe".into()
        },
        &plan.provenance.render("spans"),
    );
}

fn render_plan_footer(s: &mut String, plan: &ScanPlan, facts: &HostFacts, style: &Style) {
    s.push('\n');
    match plan.projected_duration() {
        Some(d) => s.push_str(&format!(
            "{:<16}~{} at {}/s\n",
            "projection",
            HumanElapsed(d),
            plan.timing.rate
        )),
        None => s.push_str(&format!(
            "{:<16}unbounded rate; duration depends on how many probes time out\n",
            "projection"
        )),
    }
    s.push_str(&format!("{:<16}{}\n", "host", facts));

    if !plan.warnings.is_empty() {
        s.push('\n');
        for w in &plan.warnings {
            let head = style.paint("33", "warning");
            s.push_str(&format!(
                "{head}  {}\n",
                w.message.replace('\n', "\n         ")
            ));
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

// ── config ──────────────────────────────────────────────────────────────────

fn cmd_config(cli: &Cli, cmd: &ConfigCmd) -> Result<u8, ConfigError> {
    match cmd {
        ConfigCmd::Init { path, force } => {
            if path.exists() && !force {
                return Err(
                    ConfigError::new(format!("{} already exists", path.display()))
                        .help("pass --force to overwrite it"),
                );
            }
            std::fs::write(path, config::builtin::ANNOTATED_TEMPLATE)
                .map_err(|e| ConfigError::new(format!("cannot write {}: {e}", path.display())))?;
            let _ = writeln!(
                std::io::stderr(),
                "wrote {} — every field documented with its default and range\nnext: scanr config validate && scanr plan internal-web",
                path.display()
            );
            Ok(EXIT_OK)
        }
        ConfigCmd::Path => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let d = config::discover(cli.config.as_deref(), &cwd);
            let mut out = std::io::stdout();
            for (layer, path, exists) in &d.candidates {
                let _ = writeln!(
                    out,
                    "{:<10}{:<52}  {}",
                    layer.to_string(),
                    path.display(),
                    if *exists { "found" } else { "not present" }
                );
            }
            Ok(EXIT_OK)
        }
        ConfigCmd::Validate => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let discovery = config::discover(cli.config.as_deref(), &cwd);
            let files = config::load(&discovery)?;
            let errors = config::validate(&files);
            let mut err = std::io::stderr();
            if errors.is_empty() {
                if files.files.is_empty() {
                    let _ = writeln!(err, "no configuration files found (nothing to validate)");
                } else {
                    let _ = writeln!(
                        err,
                        "ok — {} file(s), {} scan(s), {} transport(s)",
                        files.files.len(),
                        files.scan_names().len(),
                        files.transport_names().len()
                    );
                }
                return Ok(EXIT_OK);
            }
            let style = Style::for_stream(false, cli.no_color);
            for e in &errors {
                let src = e.path.as_ref().and_then(|p| files.source_of(p));
                let _ = writeln!(err, "{}\n", colorize_error(&e.render(src), &style));
            }
            let _ = writeln!(err, "{} problem(s) found", errors.len());
            Ok(EXIT_USAGE)
        }
        ConfigCmd::Show => {
            let files = load_config(cli)?;
            let mut out = std::io::stdout();
            for f in &files.files {
                let _ = writeln!(out, "# {} ({})", f.path.display(), f.layer);
            }
            let _ = writeln!(out, "\n# profiles");
            for p in config::builtin::builtin_profiles() {
                let _ = writeln!(
                    out,
                    "  {:<16}{:<8}concurrency {:<6} rate {:<7} connect {:<6} — {}",
                    p.name,
                    "builtin",
                    p.timing.concurrency,
                    if p.timing.rate == 0 {
                        "none".into()
                    } else {
                        p.timing.rate.to_string()
                    },
                    render_duration(p.timing.connect_timeout),
                    p.summary
                );
            }
            for name in files.profile_names() {
                let _ = writeln!(out, "  {name:<16}defined");
            }
            let _ = writeln!(out, "\n# transports");
            let _ = writeln!(out, "  {:<16}builtin", "direct");
            for name in files.transport_names() {
                let kind = files
                    .pick(|c| c.transports.get(&name).and_then(|t| t.kind.clone()))
                    .map(|(k, _)| k)
                    .unwrap_or_default();
                let _ = writeln!(out, "  {name:<16}{kind}");
            }
            let _ = writeln!(out, "\n# scans");
            for name in files.scan_names() {
                let desc = files
                    .pick(|c| c.scans.get(&name).and_then(|s| s.description.clone()))
                    .map(|(d, _)| d)
                    .unwrap_or_default();
                let _ = writeln!(out, "  {name:<24}{desc}");
            }
            Ok(EXIT_OK)
        }
    }
}

// ── transport ───────────────────────────────────────────────────────────────

fn cmd_transport(cli: &Cli, cmd: &TransportCmd) -> Result<u8, ConfigError> {
    let files = load_config(cli)?;
    match cmd {
        TransportCmd::List => {
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{:<16}{:<10}ADDRESS", "NAME", "TYPE");
            let _ = writeln!(out, "{:<16}{:<10}-", "direct", "direct");
            for name in files.transport_names() {
                let raw = files.pick(|c| c.transports.get(&name).cloned());
                if let Some((t, _)) = raw {
                    let _ = writeln!(
                        out,
                        "{:<16}{:<10}{}",
                        name,
                        t.kind.unwrap_or_default(),
                        t.address.unwrap_or_else(|| "-".into())
                    );
                }
            }
            Ok(EXIT_OK)
        }
        TransportCmd::Show { name } => {
            let facts = HostFacts::probe();
            let ov = Overrides {
                transport: Some(name.clone()),
                targets: Some(vec!["127.0.0.1".into()]),
                ports: Some(vec!["1".into()]),
                ..Default::default()
            };
            let plan = resolve(&files, None, &ov, &facts)?;
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{:<16}{}", "name", plan.transport.name);
            let _ = writeln!(out, "{:<16}{}", "type", plan.transport.type_name());
            let _ = writeln!(out, "{:<16}{}", "description", plan.transport.describe());
            let _ = writeln!(
                out,
                "{:<16}{}",
                "remote dns",
                plan.transport.supports_remote_dns()
            );
            let _ = writeln!(out, "{:<16}{}", "fidelity", plan.transport.fidelity);
            if plan.transport.supports_remote_dns() {
                let _ = writeln!(
                    out,
                    "\nfidelity has not been measured; run `scanr transport test {name}`"
                );
            }
            Ok(EXIT_OK)
        }
        TransportCmd::Test {
            name,
            known_open,
            known_closed,
            calibrate,
        } => cmd_transport_test(
            &files,
            name,
            known_open.as_deref(),
            known_closed.as_deref(),
            *calibrate,
        ),
    }
}

fn cmd_transport_test(
    files: &crate::config::raw::Layered,
    name: &str,
    known_open: Option<&str>,
    known_closed: Option<&str>,
    calibrate: bool,
) -> Result<u8, ConfigError> {
    let facts = HostFacts::probe();
    let ov = Overrides {
        transport: Some(name.to_string()),
        targets: Some(vec!["127.0.0.1".into()]),
        ports: Some(vec!["1".into()]),
        ..Default::default()
    };
    let plan = resolve(files, None, &ov, &facts)?;
    let report = crate::fidelity::measure(
        &plan.transport,
        &plan.timing,
        known_open,
        known_closed,
        calibrate,
    )
    .map_err(ConfigError::new)?;
    let mut out = std::io::stdout();
    let _ = write!(out, "{}", report.render());
    Ok(if report.reachable {
        EXIT_OK
    } else {
        EXIT_USAGE
    })
}

// ── output ──────────────────────────────────────────────────────────────────

fn cmd_output(_cli: &Cli, cmd: &OutputCmd) -> Result<u8, ConfigError> {
    match cmd {
        OutputCmd::Summarize { file, by } => {
            let report = crate::verify::summarize(file, *by).map_err(ConfigError::new)?;
            let _ = write!(std::io::stdout(), "{}", report);
            Ok(EXIT_OK)
        }
        OutputCmd::Verify { file } => {
            let report = crate::verify::verify(file).map_err(ConfigError::new)?;
            let _ = write!(std::io::stdout(), "{}", report.render());
            Ok(if report.problems.is_empty() {
                EXIT_OK
            } else {
                EXIT_USAGE
            })
        }
        OutputCmd::Cat { file } => {
            let mut out = std::io::stdout().lock();
            crate::verify::cat(file, &mut out).map_err(ConfigError::new)?;
            Ok(EXIT_OK)
        }
        OutputCmd::Remainder { file } => {
            let rem = crate::verify::remainder(file).map_err(ConfigError::new)?;
            let _ = write!(std::io::stdout(), "{}", rem.render());
            let _ = writeln!(std::io::stderr(), "{}", rem.note);
            Ok(EXIT_OK)
        }
    }
}

/// Map a scan termination to a process exit code.
pub fn exit_code_for(t: Termination, writer_failed: bool) -> u8 {
    if writer_failed {
        EXIT_WRITER_FAILED
    } else {
        t.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("args should parse")
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_accepts_a_bare_scan_name() {
        let cli = parse(&["scanr", "run", "internal-web"]);
        match cli.command {
            Command::Run { scan, .. } => assert_eq!(scan.as_deref(), Some("internal-web")),
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn run_works_with_no_scan_name_for_adhoc() {
        let cli = parse(&["scanr", "run", "--targets", "10.0.0.0/24", "--ports", "80"]);
        match cli.command {
            Command::Run { scan, overrides } => {
                assert!(scan.is_none());
                assert_eq!(overrides.targets.unwrap(), ["10.0.0.0/24"]);
                assert_eq!(overrides.ports.unwrap(), ["80"]);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn targets_and_ports_are_repeatable() {
        let cli = parse(&[
            "scanr",
            "run",
            "--targets",
            "a.internal",
            "--targets",
            "10.0.0.1",
            "--ports",
            "80",
            "--ports",
            "443",
        ]);
        match cli.command {
            Command::Run { overrides, .. } => {
                assert_eq!(overrides.targets.unwrap().len(), 2);
                assert_eq!(overrides.ports.unwrap().len(), 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn stdin_target_is_a_single_value() {
        let cli = parse(&["scanr", "run", "--targets", "-", "--ports", "80"]);
        match cli.command {
            Command::Run { overrides, .. } => assert_eq!(overrides.targets.unwrap(), ["-"]),
            _ => panic!(),
        }
    }

    #[test]
    fn durations_parse_through_the_value_parser() {
        let cli = parse(&["scanr", "run", "s", "--connect-timeout", "2500ms"]);
        match cli.command {
            Command::Run { overrides, .. } => {
                assert_eq!(overrides.connect_timeout, Some(Duration::from_millis(2500)));
            }
            _ => panic!(),
        }
        // A bare number is rejected rather than guessed.
        assert!(Cli::try_parse_from(["scanr", "run", "s", "--connect-timeout", "5"]).is_err());
    }

    #[test]
    fn seed_accepts_hex_and_decimal() {
        assert_eq!(seed_arg("9f2c00a1b4de7731").unwrap(), 0x9f2c_00a1_b4de_7731);
        assert_eq!(seed_arg("0xff").unwrap(), 255);
        assert!(seed_arg("zzz").is_err());
    }

    #[test]
    fn dns_mode_is_validated_at_parse_time() {
        assert_eq!(dns_arg("transport").unwrap(), DnsMode::Transport);
        let e = dns_arg("remote").unwrap_err();
        assert!(e.contains("auto"), "{e}");
        assert!(Cli::try_parse_from(["scanr", "run", "s", "--dns", "remote"]).is_err());
    }

    #[test]
    fn open_only_and_all_conflict() {
        assert!(Cli::try_parse_from(["scanr", "run", "s", "--open-only", "--all"]).is_err());
    }

    #[test]
    fn all_flag_disables_open_only() {
        let cli = parse(&["scanr", "run", "s", "--all"]);
        match cli.command {
            Command::Run { overrides, .. } => {
                assert_eq!(overrides.to_overrides().open_only, Some(false));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unset_open_only_leaves_it_to_config() {
        let cli = parse(&["scanr", "run", "s"]);
        match cli.command {
            Command::Run { overrides, .. } => {
                assert_eq!(overrides.to_overrides().open_only, None);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = parse(&["scanr", "run", "s", "--quiet", "--no-color"]);
        assert!(cli.quiet);
        assert!(cli.no_color);
    }

    #[test]
    fn overrides_are_an_allowlist_not_a_free_for_all() {
        // Timing knobs that belong in config are deliberately absent from the CLI.
        for flag in [
            "--handshake-timeout",
            "--proxy-connect-timeout",
            "--retry-delay",
        ] {
            assert!(
                Cli::try_parse_from(["scanr", "run", "s", flag, "1s"]).is_err(),
                "{flag} should not be a CLI override"
            );
        }
    }

    #[test]
    fn subcommand_tree_matches_the_spec() {
        for args in [
            vec!["scanr", "plan", "s"],
            vec!["scanr", "config", "init"],
            vec!["scanr", "config", "show"],
            vec!["scanr", "config", "validate"],
            vec!["scanr", "config", "path"],
            vec!["scanr", "transport", "list"],
            vec!["scanr", "transport", "show", "lab"],
            vec!["scanr", "transport", "test", "lab"],
            vec!["scanr", "output", "summarize", "f.jsonl"],
            vec!["scanr", "output", "verify", "f.jsonl"],
            vec!["scanr", "output", "remainder", "f.jsonl"],
            vec!["scanr", "completion", "bash"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?} should parse");
        }
    }

    #[test]
    fn removed_commands_are_actually_gone() {
        for args in [
            vec!["scanr", "scan", "run", "s"],
            vec!["scanr", "profile", "list"],
            vec!["scanr", "output", "convert", "f.jsonl"],
            vec!["scanr", "scan", "resume", "f.jsonl"],
        ] {
            assert!(
                Cli::try_parse_from(&args).is_err(),
                "{args:?} should not exist"
            );
        }
    }

    #[test]
    fn truncate_preserves_short_strings() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 5), "ab...");
    }

    #[test]
    fn exit_codes_follow_the_spec() {
        assert_eq!(exit_code_for(Termination::Completed, false), 0);
        assert_eq!(exit_code_for(Termination::Failed, false), 2);
        assert_eq!(exit_code_for(Termination::Interrupted, false), 130);
        assert_eq!(exit_code_for(Termination::Completed, true), 3);
    }
}
