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
output cat
output get
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
│   ├── summarize <file>       counts, duration, open ports
│   ├── verify <file>          integrity and completeness checks
│   ├── remainder <file>       endpoints that were never probed
│   ├── cat <file>             the record as plain JSONL, decompressing it
│   └── get <file>             look up results, filtering by host/port/state
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
- `--resumed-from` records which scan is being continued. You rarely type it: `remainder`
  emits it as a `# resumed-from:` comment and `run` picks it up from the pipe.

`transport test` also takes `--known-open`, `--known-closed` and `--calibrate`. Those
describe what to measure rather than how to scan, so they are not scan overrides.

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
