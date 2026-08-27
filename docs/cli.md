# Command reference

Checked against the binary by `tests/cli_spec.rs`. Workflows: [getting-started.md](getting-started.md).

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

| | |
|---|---|
| `run [scan]` | execute; no name means an ad-hoc scan from flags |
| `plan [scan]` | resolve and print the plan; no network |
| `config init [path]` | write an annotated `scanr.toml` |
| `config show` | resolved config, credentials redacted |
| `config validate` | check without running |
| `config path` | files discovered |
| `transport list` / `show <name>` | defined transports / one transport's resolved settings |
| `transport test <name>` | measure proxy reachability and result fidelity |
| `output summarize <file>` | totals; counts by host, network, port, service |
| `output verify <file>` | integrity and completeness |
| `output remainder <file>` | endpoints never probed, as `--pairs` input |
| `output events <file>` | raw JSONL event stream, verbatim |
| `output results <file>` | every probe result, filterable; the table ends with what the service said (banner, TLS summary) when the record has it |
| `completion <shell>` | `bash` `zsh` `fish` `elvish` `power-shell` |

## Flags

The only command-line settings; all else is config, so a run is reproducible from a file.

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
--tls / --no-tls
--tls-versions / --no-tls-versions
--config <path>
--verbose / -v              --quiet / -q
--no-color                  --allow-large-range
--full
```

- `--full`: banners untruncated as they arrive (default cuts at 48 characters); display only, not recorded.
- `--seed`: replay a randomized scan; order is randomized by default and the seed recorded.
- `--pairs`: exact `host:port` endpoints, not target × port. `output remainder … | run --pairs -` resumes without re-probing.
- `--resumed-from`: scan being continued. `remainder` emits `# resumed-from:`; `run` reads it from the pipe.
- `--banner` (default on): read what an open service volunteers, sending nothing. Only SSH, SMTP, FTP, POP3, IMAP, MySQL greet first; HTTP and TLS do not, so empty means "said nothing unprompted". `banner_timeout` (500ms) is a ceiling; the wait scales off measured connect time. A worker waiting on a silent port issues no probes.
- `--tls` (default off): send one ClientHello offering TLS 1.3 and 1.2 to open ports that volunteered no banner, on the same connection — finishing the 1.3 key exchange to read the encrypted flight, taking older servers' flights in the clear — and record the certificate (leaf DER, SHA-256, and what it says: subject, issuer, alternative names, validity, key type — read, not verified), cipher and ALPN the server answers with; SNI is sent when the target was given as a name; a server wanting a version or key-share group the hello lacks answers an alert or HelloRetryRequest, recorded as such. The one active probe scanr has — `scan_config.tls.sent_bytes` states what was sent. `tls_timeout` (1s) is the ceiling on the wait.
- `--tls-versions` (default off, needs `--tls`): after the hello, ask SSLv2, SSLv3, TLS 1.0, 1.1 and — when the server took 1.3 — 1.2 for themselves, each on its own connection with a hello of its era, and record which the server accepts. The line ends `versions:ssl3..1.3`, or `legacy-only:tls1.0` when nothing a current client speaks is accepted; the record's `tls.versions.advice` says what will reach it. Up to five more connections per silent open port.

### Flags on the other commands

These change what a command prints or measures, not how a scan runs.

<!-- OTHER FLAGS: checked against the clap definition by tests/cli_spec.rs -->
| command | flags |
|---|---|
| `config init` | `--force` overwrite an existing `scanr.toml` |
| `transport test` | `--known-open`, `--known-closed` endpoints of known state to measure against; `--calibrate` finds the proxy's connection cap |
| `output summarize` | `--by <section>`: `scan`, `host`, `network`, `port`, `service`; `--format table\|json` (`--json` is a deprecated alias that warns) |
| `output results` | `--hosts`, `--ports`, `--states` filter; `--format` (below); `--full` shows banners untruncated in the table (default 48 characters; always printable ASCII only) |

All other commands take only the globals.

## Handing results to another tool

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
| `list` | `host:port` per line, for `httpx`, `tlsx`, `nuclei` |

`nmap` groups hosts by exact open-port set; `-Pn -n` skip repeated liveness and DNS work.
Use `--states open`; stderr warns otherwise.

## stdout and stderr

stdout: results only — `target:port/proto`, state, service label, elapsed. Hostname
targets show the hostname; `-v` appends the resolved address.

```
10.20.30.40:22/tcp    open   ssh      18.2ms
10.20.30.40:443/tcp   open   https    21.4ms
```

stderr: header (transport, scan ID), progress, warnings, errors.

Colour, alignment and the progress line only on a terminal; `--no-color` or `NO_COLOR`
disables colour. Never prompts: a missing credential is an error naming its environment
variable.

## Exit codes

| code | meaning |
|---|---|
| 0 | completed naturally, including nothing open |
| 1 | usage or configuration error; nothing scanned. `output verify`: record unreadable |
| 2 | scan failed after starting. `output verify`: record read, has problems |
| 3 | record could not be written |
| 130 | SIGINT; record finalized |
