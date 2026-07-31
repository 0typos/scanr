# CLI Specification

Verbs at top level for the daily drivers; noun groups for everything else (D-session).

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
completion
```

Read as a tree:

```
scanr
├── run <scan>                 execute a named scan
├── plan <scan>                resolve and print the plan; no network
├── config
│   ├── init                   write an annotated scanr.toml
│   ├── show                   resolved config, credentials redacted
│   ├── validate               check without running
│   └── path                   which files were discovered
├── transport
│   ├── list
│   ├── show <name>
│   └── test <name>            measure proxy reachability AND result fidelity
├── output
│   ├── summarize <file>       counts, duration, open ports
│   ├── verify <file>          integrity and completeness checks
│   └── remainder <file>       emit un-probed targets as a target list
└── completion <shell>
```

## Cut from the original brief

| Command | Disposition |
|---|---|
| `scan run` / `scan plan` | Promoted to top level — typed constantly |
| `scan inspect` | Merged into `plan` |
| `scan resume` | Replaced by `output remainder` (D12) |
| `config explain` | Merged into `plan` provenance output |
| `config schema` | Dropped; `config init` is the reference (04-config-spec) |
| `profile list/show/resolve/compare` | Profiles are a config concern — `config show --profile` |
| `transport explain` | Merged into `transport show` |
| `output inspect` | Redundant with `summarize` |
| `output convert` | Dropped; JSONL plus `jq` beats a bespoke converter |

Twenty-four commands became twelve. Each remaining one maps to a stated workflow.

## Override allowlist

Only these may be set on the command line. Anything else lives in config — this is what
keeps runs reproducible from a file rather than from shell history.

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

`--seed` exists so a randomized scan can be replayed exactly (D16).

`--pairs` names exact `host:port` endpoints rather than a matrix, which is what makes
`output remainder | run --pairs -` an exact resume (D12). `--resumed-from` records which
scan is being continued; it is normally picked up from the remainder's leading
`# resumed-from:` comment rather than typed.

`transport test` additionally takes `--known-open`, `--known-closed` and `--calibrate`,
which describe what to measure rather than how to scan, so they are not part of the
override allowlist.

## Zero-config path

Secondary but supported. Synthesizes an anonymous scan from `direct` + the `direct`
profile, and still writes JSONL:

```bash
scanr run --targets 10.20.30.0/24 --ports 22,80,443
subfinder -d example.com | scanr run --targets - --ports web --transport lab
```

## Streams

**stdout** — results only, one per line, pipe-safe:

```
10.20.30.40:22/tcp    open   ssh      18.2ms
10.20.30.40:443/tcp   open   https    21.4ms
```

Columns: `target:port/proto`, state, service label, total elapsed. Aligned and coloured
only when stdout is a TTY; plain and unaligned otherwise. Hostname targets show the
hostname, with the resolved address appended under `-v`. Transport name and scan ID are
*not* in the default line — they are constant for the run and belong in the header
(stderr) and the JSONL.

**stderr** — everything else: the run header, progress, warnings, errors. Progress
renders as a single updating line on a TTY and as periodic lines otherwise.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed naturally (including zero open ports) |
| 1 | Usage or configuration error; nothing was scanned |
| 2 | Scan failed after starting |
| 3 | Output writer failure |
| 130 | Interrupted by SIGINT; results finalized |

Finding no open ports is not an error. A `--exit-nonzero-on-empty` flag can be added if
a pipeline wants it, but it is not the default.

## Non-interactive behaviour

No TTY means: no colour, no alignment, no progress line, no prompts. Nothing ever waits
for input — a missing credential is an error naming the environment variable, not a
password prompt. Interactive prompting is deferred; it interacts badly with the
automation this tool is aimed at.

## `scanr plan` output

```
scan            internal-web            scan.internal-web
profile         proxy                   builtin
transport       lab (socks5)            scan.internal-web
  address       127.0.0.1:1080          config.user
  fidelity      open_only               measured 2026-07-29T14:02:11Z
dns             transport               auto → transport (proxy supports it)
targets         255 hosts               scan.internal-web → targets.lab
ports           1002                    scan.internal-web → ports.web
probes          255,510
order           randomized, seed 9f2c00a1b4de7731
concurrency     512                     profile.proxy
rate            400/s                   builtin.proxy
connect_timeout 8s                      cli
retries         1                       profile.proxy

projection      ~10m39s at 400/s

warning  proxy 'lab' reports open_only fidelity: closed and filtered
         will be indistinguishable in results
warning  rate 400/s is within the ephemeral budget (~470/s for a remote
         proxy); SO_LINGER close is enabled, raising the effective ceiling
```

Three columns: field, effective value, provenance. The warnings are the point — they
tell you what the run cannot tell you *before* you spend ten minutes on it.

## `scanr transport test` output

```
transport lab (socks5 127.0.0.1:1080)
  reachable          yes         2.1ms
  auth               accepted    username/password
  known-open  :22    open        reply 0x00    4.2ms
  known-closed:1     error       reply 0x01    3.8ms   ← expected 0x05
  blackholed         filtered    timeout       5000ms

  fidelity  open_only
  This proxy reports a generic failure for refused connections, so scanr
  cannot distinguish 'closed' from 'filtered'. Non-open results will be
  recorded as 'error' with source 'proxy_reply'.
```
