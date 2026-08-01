# Command reference

Every command and every command-line flag. `scanr <command> --help` has the detail; this
page is the whole surface on one screen, and a test checks it against the binary so it
cannot quietly fall behind.

For what the commands *do*, start with [getting-started.md](getting-started.md).

## Commands

<!-- COMMAND TREE: checked against the clap definition by tests/cli_spec.rs -->
```
run
plan
config init
config show
config validate
config path
transport list
transport show
transport test
output summarize
output verify
output remainder
output events
output results
completion
```

As a tree:

```
scanr
├── run <scan>                 execute a named scan
├── plan <scan>                resolve and print the plan; touches no network
├── config
│   ├── init                   write an annotated scanr.toml
│   ├── show                   resolved config, credentials redacted
│   ├── validate               check without running
│   └── path                   which files were discovered
├── transport
│   ├── list
│   ├── show <name>
│   └── test <name>            measure proxy reachability and result fidelity
├── output
│   ├── summarize <file>       totals, and counts by host, network, service
│   ├── verify <file>          integrity and completeness checks
│   ├── remainder <file>       endpoints that were never probed
│   ├── events <file>          the raw JSONL event stream, verbatim
│   └── results <file>         every probe result, filterable
└── completion <shell>
```

## Flags

These are the only settings that can be given on the command line. Everything else lives
in the config file, which is what makes a run reproducible from a file rather than from
your shell history.

<!-- RUN FLAGS: checked against the clap definition by tests/cli_spec.rs -->
```
--profile <name>            --transport <name>
--targets <spec|file|->     --ports <spec>          --exclude <spec>
--pairs <file|->            --resumed-from <scan-id>
--concurrency <n>           --rate <n>
--connect-timeout <dur>     --retries <n>
--dns <auto|transport|local|disabled>
--output-dir <path>         --seed <hex>
--open-only / --all         --compress / --no-compress
--spans / --no-spans
--banner / --no-banner
--config <path>
--verbose / -v              --quiet / -q
--no-color                  --allow-large-range
```

A few that are not self-explanatory:

- `--seed` replays a randomized scan exactly. Probe order is randomized by default; the
  seed is recorded, so passing it back reproduces the same order.
- `--pairs` takes exact `host:port` endpoints instead of a target × port matrix. This is
  what makes `scanr output remainder … | scanr run --pairs -` resume without re-probing
  anything that already finished.
- `--banner` / `--no-banner` controls reading what open services volunteer on connect,
  **without sending anything**. On by default. Only services that greet first say anything — SSH, SMTP, FTP, POP3,
  IMAP, MySQL — so an empty banner means "said nothing unprompted", not "nothing there".
  HTTP and anything behind TLS greet nobody.

  `banner_timeout` (default 500ms) is the *ceiling*, not the wait. A greeting arrives
  about one round trip after connect, so the actual wait scales off this host's measured
  connect time and only approaches the ceiling on genuinely slow paths. That matters:
  concurrency is the worker-thread count with no queue, so a worker waiting on a silent
  port is a worker issuing no probes.
- `--resumed-from` records which scan is being continued. You rarely type it: `remainder`
  emits it as a `# resumed-from:` comment and `run` picks it up from the pipe.

### Flags on the other commands

The block above is the scan-override allowlist — the settings that change *how a scan
runs*, and the reason a run is reproducible from a file. Everything below describes what a
command should print or measure, so none of it belongs in that allowlist.

<!-- OTHER FLAGS: checked against the clap definition by tests/cli_spec.rs -->
| command | flags |
|---|---|
| `config init` | `--force` overwrite an existing `scanr.toml` |
| `transport test` | `--known-open`, `--known-closed` name endpoints with a known state to measure against; `--calibrate` finds the proxy's connection cap |
| `output summarize` | `--by <section>` narrows to one of `totals`, `host`, `network`, `port`, `service`; `--json` emits the aggregates as one object |
| `output results` | `--hosts`, `--ports`, `--states` filter; `--format` picks the shape (see below) |

`plan`, `config show`, `config validate`, `config path`, `transport list`,
`transport show`, `output verify`, `output remainder`, `output events` and `completion`
take no flags of their own beyond the globals.

## Handing results to another tool

`scanr` is good at finding open ports quickly through a proxy. `nmap -sV` is good at
saying what is behind them. `output results --format` hands one to the other:

```console
$ scanr output results --states open --format nmap scan-*.jsonl.gz
nmap -sV -Pn -n -p 22 10.0.0.9 10.0.0.10
nmap -sV -Pn -n -p 22,80,443 10.0.0.2

$ scanr output results --states open --format list scan-*.jsonl.gz | httpx
10.0.0.2:80
10.0.0.2:443
```

| format | for |
|---|---|
| `table` | reading (default) |
| `json` | one JSON object per result |
| `nmap` | runnable `nmap -sV` commands, one per distinct set of open ports |
| `list` | `host:port` per line — what `httpx`, `tlsx` and `nuclei` read from stdin |

The `nmap` form groups hosts by the exact ports found open on them, so no host is handed
a port that was never open on it, and `-Pn -n` stop nmap repeating the liveness and DNS
work `scanr` already did. Pointing nmap at the fraction of endpoints that answered is far
faster than letting it scan everything, and it keeps nmap's signature database rather
than reimplementing it badly.

Filter to `--states open` — the other states are rarely what you want to hand on, and
`scanr` will say so on stderr if you forget.

## stdout and stderr

**stdout is results only**, one per line, safe to pipe:

```
10.20.30.40:22/tcp    open   ssh      18.2ms
10.20.30.40:443/tcp   open   https    21.4ms
```

Columns are `target:port/proto`, state, service label, elapsed. Hostname targets show the
hostname; `-v` appends the resolved address. The transport name and scan ID are not on
these lines — they are the same for every row and belong in the header.

**stderr is everything else**: the header, progress, warnings, errors.

Alignment and colour appear only when the stream is a terminal. Redirect either one and
you get plain, unaligned text; `--no-color` and `NO_COLOR` turn colour off explicitly.

## Exit codes

| code | meaning |
|---|---|
| 0 | completed naturally, including when nothing was open |
| 1 | usage or configuration error; nothing was scanned |
| 2 | the scan failed after starting |
| 3 | the record could not be written |
| 130 | interrupted by SIGINT; the record was finalized |

Finding no open ports is a successful scan, not an error.

## Non-interactive by default

No terminal means no colour, no alignment, no progress line, and no prompts. Nothing ever
waits for input: a missing credential is an error naming the environment variable it
wanted, never a password prompt.
