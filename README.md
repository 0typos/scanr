# scanr

Proxy-aware TCP connect scanner with reproducible, durable scan records.

`scanr` performs unprivileged TCP `connect()` probes — directly or through a SOCKS5
proxy — streams open ports to stdout as it finds them, and **always** writes a JSON Lines
record containing the fully resolved configuration and exactly one terminal event saying
whether the run completed, was interrupted, or failed.

Roughly the workflow of `nmap -Pn -sT -n -v --open -T4 -p <ports> <targets>`, but
proxy-native, config-first, and forensically complete.

```console
$ scanr run internal-web
scanr 0.1.0 — internal-web via socks5 127.0.0.1:1080 — 255,510 probes (255 targets x 1002 ports)
  scan a3f19c02  seed 9f2c00a1b4de7731  concurrency 512  -> ./scanr-results/scan-1785294704201-a3f19c02.jsonl.partial
10.20.30.40:22/tcp    open   ssh          18.2ms
10.20.30.40:443/tcp   open   https        21.4ms
...
completed in 10m41s — 38 open, 1204 closed, 254210 filtered, 58 error (255,510 of 255,510 probed)
  record: ./scanr-results/scan-1785294704201-a3f19c02.jsonl
```

## Why this and not something else

The gap it fills is narrow and specific: **enumerating reachable TCP services through a
SOCKS proxy, with results you can trust and reproduce.**

| tool | why it does not cover this |
|---|---|
| `nmap` + `proxychains` | `LD_PRELOAD` interception is fragile, leaks DNS, and fights nmap's parallelism |
| `masscan` / `ZMap` | stateless SYN cannot traverse a proxy, and needs privileges |
| `RustScan` / `naabu` | fast, but proxy support is absent or marginal and no durable record |
| `nc -z` in a loop | works, but no concurrency control, no structure, no record |

`scanr` is **not** a replacement for any of them. No SYN scanning, no UDP, no service or
OS fingerprinting, no scripting, no evasion. It does one thing.

## Install

```console
cargo build --release                                     # ./target/release/scanr
cargo build --release --target x86_64-unknown-linux-musl   # static, no libc dependency
```

Linux x86_64 is the supported platform — the performance numbers are measured there and
it is the only target with a static musl build (`static-pie`, ~2 MB, no C toolchain).

**macOS** builds and passes its test suite in CI:

```console
cargo install --path .          # Apple Silicon or Intel
ulimit -n 8192                  # macOS defaults to 256, under the default concurrency
```

Two caveats there. The host diagnostics that read `/proc` — the ephemeral-port range and
`tcp_tw_reuse` — report as unknown, so the `ephemeral_budget` warning cannot fire; the
`fd_budget` one still does. And there is no static build.

Windows is deferred, not planned.

## Quick start

```console
scanr config init          # writes an annotated scanr.toml documenting every field
scanr config validate      # check it
scanr plan internal-web    # resolve the scan and show it — no network traffic
scanr run internal-web
```

Ad-hoc scanning works too, though the tool is built around named scans:

```console
scanr run --targets 10.20.30.0/24 --ports 22,80,443
scanr run --targets hosts.txt --ports 1-1024 --transport lab
subfinder -d example.com | scanr run --targets - --ports web
```

New here? [docs/getting-started.md](docs/getting-started.md) walks from install to a
verified record with real output.

## Know what your proxy can actually tell you

This is the part most worth understanding, and the reason the tool exists.

SOCKS5 defines separate reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`) and
policy denial (`0x02`) — but not every proxy uses them. Measured against four:

| proxy | refused destination | fidelity |
|---|---|---|
| microsocks | `0x05` | full |
| dante (sockd 1.4.3) | `0x05` | full |
| 3proxy | `0x05` | full |
| OpenSSH `ssh -D` | **no reply**, channel closed | open_only |

OpenSSH is the awkward one: it sends no SOCKS5 reply at all and closes the channel. Its
own log says `connect failed: Connection refused`, so it knows the reason and has no way
to convey it. Through a proxy like that, **a closed port and a filtered port are
indistinguishable**.

`scanr` measures this rather than assuming it:

```console
$ scanr transport test lab
transport lab (socks5 127.0.0.1:1080)
  reachable         yes
  known-open        open      reply 0x00         1.7ms
  known-closed      closed    reply 0x05         0.6ms
  blackholed        filtered  reply 0x04      3003.5ms

  fidelity          full
  This proxy reports refused connections distinctly (0x05), so scanr can
  tell `closed` apart from `filtered` in your results.
```

When a proxy cannot tell the difference, `scanr` records `error` with
`source: proxy_reply` — it will not invent a `closed` it never observed. Every result
carries where its classification came from (`local_stack`, `proxy_reply`, `timeout`).

`transport test --calibrate` additionally finds the proxy's connection cap, which is
usually what decides whether a scan succeeds — not scanr's `concurrency` setting.

Full detail, including what each fidelity level costs you and the per-proxy measurements:
**[docs/transports.md](docs/transports.md)**.

## The scan record

Every run writes `scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz`, carrying `.partial`
while running and renamed on the terminal event — so a file still named `.partial` means
the process died without finalizing.

`scan_started` is first, `scan_config` second, and exactly one terminal event
(`scan_completed` / `scan_interrupted` / `scan_failed`) is last with nothing after it.

```console
$ scanr output verify scanr-results/scan-1785294704201-a3f19c02.jsonl.gz
  61 events
  terminal: scan_interrupted
  56 probe results
ok — record is complete and internally consistent

$ scanr output summarize scanr-results/scan-*.jsonl.gz
$ scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -
```

That last line is an exact resume: `remainder` emits the endpoints that were never
reported, and `run --pairs` probes only those.

Records are gzip with repeated outcomes collapsed into spans by default; `--no-compress`
and `--no-spans` give plain JSONL with one row per probe. `zcat`, `zless` and every
`scanr output` command read either form.

The config event stores the **canonical unexpanded** target spec plus counts, never the
expanded matrix — a /16 × 1000 ports is 65M probes. With the recorded permutation seed,
that is enough to reproduce the scan exactly.

Schema, guarantees and `jq` recipes: **[docs/output-schema.md](docs/output-schema.md)**.

## Interruption

First Ctrl-C stops scheduling and drains in-flight probes, bounded by the connect
timeout. Second Ctrl-C exits immediately. Either way the record is finalized with
accurate accounting and the exit code is 130.

Counts distinguish three buckets that sum to `planned`: `completed` reported a result,
`abandoned` was picked up by a worker before the drain ended and **may have touched the
network**, and `not_started` was never issued.

## How fast, next to nmap

A `/24` × nmap's top 100 ports — 25,600 probes. Both doing **unprivileged TCP connect
scans**, so the technique is identical. nmap 7.92, `-sT -T5 --min-rate 10000
--max-retries 0 -Pn -n`.

| responsive hosts (every port refused) | wall | probes/s |
|---|---|---|
| `scanr`, default profile | **0.17 s** | ~150,000 |
| nmap `-T5` | 0.52 s | ~49,000 |

Both reported exactly the same 259 open ports — the gap is not `scanr` cutting corners.

Against unresponsive hosts the comparison is really about timeout policy, and nmap wins
until you match its terms: told `--max-retries 0` it makes one attempt, while
`direct-fast` deliberately makes two, because a single 300 ms attempt cannot survive a
dropped SYN. Given the same single-attempt budget, `scanr` is again ~3.2× quicker.

The real difference is that **nmap adapts its timeout from observed round-trip times and
`scanr` does not**. That is deliberate — clear limits over hidden magic — and it has a
cost: on an unfamiliar network nmap self-tunes and you have to set `--connect-timeout`.
`scanr plan` projects the duration so the consequence is visible before you spend it.

Measured on loopback and TEST-NET on one machine, so it compares the tools rather than a
network. As root, nmap's `-sS` SYN scan is a different and faster technique that `scanr`
does not implement. And `scanr` is writing a complete JSONL record throughout, which nmap
is not.

Numbers, methodology, and the knobs that actually matter:
**[docs/tuning.md](docs/tuning.md)**.

## Documentation

| | |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | **start here** — install to verified record, with real output |
| [docs/cli.md](docs/cli.md) | every command and flag, stream behaviour, exit codes |
| [docs/configuration.md](docs/configuration.md) | precedence, profiles, target and port sets, DNS, service labels |
| [docs/transports.md](docs/transports.md) | what your proxy can tell you, and how much concurrency it takes |
| [docs/output-schema.md](docs/output-schema.md) | the record, its guarantees, `jq` recipes |
| [docs/tuning.md](docs/tuning.md) | where the real limits are, with measured numbers |
| [docs/troubleshooting.md](docs/troubleshooting.md) | keyed to the diagnostics the tool emits |
| [docs/security.md](docs/security.md) | trust boundaries, credentials, DNS leakage |

Man pages are in `man/`, one per command, generated from the CLI definition.

## Development

```console
cargo test
cargo clippy --all-targets
cargo fmt --check
```

Tests use in-process fixtures only — including a SOCKS5 server with injectable behaviour
(faithful, collapsing, auth, malformed replies, mid-handshake disconnects). Nothing
reaches the public internet and no daemon needs installing.

Architecture is blocking sockets on a bounded thread pool: no async runtime, no `mio`.
[`docs/design/decisions.md`](docs/design/decisions.md) records every significant decision
with its alternatives, rationale, and the trigger that would justify revisiting it —
including the assumptions that turned out to be wrong.
[`docs/design/architecture.md`](docs/design/architecture.md) is the module map.

## Authorization

`scanr` is for systems you are authorized to scan. Port scanning without permission is
unlawful in many jurisdictions.
