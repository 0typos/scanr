# scanr

Proxy-aware TCP connect scanner with reproducible, durable scan records.

Unprivileged `connect()` probes, directly or through SOCKS5 or HTTP CONNECT proxies
(single proxy, chain, or pool). Open ports stream to stdout; every run writes a JSON Lines record holding the
fully resolved configuration and exactly one terminal event saying whether it completed,
was interrupted, or failed. Roughly `nmap -Pn -sT -n -v --open -T4 -p <ports> <targets>`,
proxy-native, config-first, forensically complete.

```console
$ scanr run internal-web
scanr 0.3.0 — internal-web via socks5 127.0.0.1:1080 — 255,510 probes (255 targets x 1002 ports)
  scan a3f19c02  seed 9f2c00a1b4de7731  concurrency 512  -> ./scanr-results/scan-1785294704201-a3f19c02.jsonl.partial
10.20.30.40:22/tcp    open   ssh          18.2ms
10.20.30.40:443/tcp   open   https        21.4ms
...
completed in 10m41s — 38 open, 1204 closed, 254210 filtered, 58 error (255,510 of 255,510 probed)
  record: ./scanr-results/scan-1785294704201-a3f19c02.jsonl
```

## Why

Enumerating reachable TCP services through a SOCKS proxy, with results you can trust
and reproduce.

| tool | gap |
|---|---|
| `nmap` + `proxychains` | `LD_PRELOAD` is fragile, leaks DNS, fights nmap's parallelism |
| `masscan` / `ZMap` | stateless SYN cannot traverse a proxy; needs privileges |
| `RustScan` / `naabu` | proxy support absent or marginal; no durable record |
| `nc -z` in a loop | no concurrency control, structure, or record |

Not a replacement for any of them: no SYN, no UDP, no fingerprinting, no scripting, no
evasion.

## Install

```console
cargo build --release                                      # ./target/release/scanr
cargo build --release --target x86_64-unknown-linux-musl   # static-pie, ~2 MB, no libc
```

Linux x86_64 is the supported platform. macOS builds and passes CI (`cargo install
--path .`, then `ulimit -n 8192`); its `/proc` diagnostics report unknown and there is
no static build. Windows is not planned. Prebuilt binaries are on the GitHub releases.

## Quick start

```console
scanr config init          # annotated scanr.toml documenting every field
scanr config validate
scanr plan internal-web    # resolve and show the scan — no traffic
scanr run internal-web
```

Ad hoc:

```console
scanr run --targets 10.20.30.0/24 --ports 22,80,443
scanr run --targets hosts.txt --ports 1-1024 --transport lab
subfinder -d example.com | scanr run --targets - --ports web
```

[docs/getting-started.md](docs/getting-started.md) walks from install to a verified
record.

## What your proxy can tell you

SOCKS5 has distinct reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`) and
policy denial (`0x02`); not every proxy uses them.

| proxy | refused destination | fidelity |
|---|---|---|
| microsocks | `0x05` | full |
| dante (sockd 1.4.3) | `0x05` | full |
| 3proxy | `0x05` | full |
| OpenSSH `ssh -D` | no reply, channel closed | open_only |

Through `ssh -D` a closed port and a filtered port are indistinguishable. `scanr`
measures this rather than assuming it:

```console
$ scanr transport test lab
transport lab (socks5 127.0.0.1:1080)
  reachable         yes
  known-open        open      reply 0x00         1.7ms
  known-closed      closed    reply 0x05         0.6ms
  blackholed        filtered  reply 0x04      3003.5ms

  fidelity          full
```

When a proxy cannot tell the difference, the result is `error` with
`source: proxy_reply` — never an invented `closed`. HTTP CONNECT proxies never can: HTTP
has no status meaning refused (squid, tinyproxy and 3proxy each pick a different one and
use it for timeouts too), so they are `open_only` by construction. Every result records where its
classification came from. `transport test --calibrate` finds the proxy's connection
cap, which usually decides whether a scan succeeds. Detail:
[docs/transports.md](docs/transports.md).

## The record

`scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz`, `.partial` while running and renamed
on the terminal event. `scan_started` first, `scan_config` second, one terminal event
last. Mode 0600.

```console
scanr output verify    scanr-results/scan-*.jsonl.gz
scanr output summarize scanr-results/scan-*.jsonl.gz
scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -   # exact resume
```

`--tls` adds the one active probe: a fixed TLS 1.2 ClientHello to silent open ports,
recording the certificate (subject, chain, alternative names, validity, key type, the DER itself), cipher and ALPN, TLS 1.3 included; `--tls-versions` asks SSLv2 through TLS 1.2 for themselves and names a server only an old client can reach (off by default; the record says what was sent).

gzip-framed and span-collapsed by default (`--no-compress`, `--no-spans` for one row per
probe); `zcat`, `zless` and every `scanr output` command read either. The config event
stores the canonical target spec and the permutation seed, which is enough to reproduce
the scan exactly. Schema and `jq` recipes:
[docs/output-schema.md](docs/output-schema.md).

## Interruption

First Ctrl-C stops scheduling and drains in-flight probes, bounded by the connect
timeout; second exits immediately. Either way the record is finalised and the exit code
is 130. `completed` + `abandoned` (may have touched the network) + `not_started` =
`planned`.

## Speed, next to nmap

A loopback `/24`, every port refused except the real listeners, both tools doing
unprivileged connect scans. nmap 7.92, `-sT -T5 --min-rate 10000 --max-retries 0 -Pn -n`.
Measured 2026-08-25 on a 64-core machine; same open ports from both.

| responsive hosts | probes | scanr (default profile) | nmap `-T5` | ratio |
|---|---|---|---|---|
| `/24` × 1,000 ports | 256,000 | **0.40 s** (~640,000/s) | 4.82 s | 12× |
| `/24` × 10,000 ports | 2,560,000 | **4.3 s** (~600,000/s) | 48.4 s | 11× |

Peak RSS 18 MB against 105 MB, and the 2.56M-probe record is 36 KB. Against
unresponsive hosts nmap adapts its timeout from observed RTTs and `scanr` does not —
`--connect-timeout` is yours to set and `scanr plan` projects the cost; on equal
single-attempt terms `scanr` is ~3× quicker there. Loopback measures the engines, not a
network; through a proxy the proxy's cap decides for both. Methodology and knobs:
[docs/tuning.md](docs/tuning.md).

## Documentation

| | |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | install to verified record |
| [docs/tutorial.md](docs/tutorial.md) | learn it by using it: ten use cases, real output, and where nmap fits |
| [docs/cli.md](docs/cli.md) | every command and flag, streams, exit codes |
| [docs/configuration.md](docs/configuration.md) | precedence, profiles, targets, ports, DNS, labels |
| [docs/transports.md](docs/transports.md) | proxies, fidelity, concurrency |
| [docs/output-schema.md](docs/output-schema.md) | the record and its guarantees |
| [docs/tuning.md](docs/tuning.md) | limits, with numbers |
| [docs/troubleshooting.md](docs/troubleshooting.md) | keyed to emitted diagnostics |
| [docs/security.md](docs/security.md) | trust boundaries, credentials, DNS |
| [docs/stability.md](docs/stability.md) | what 1.x promises and what it does not |
| [docs/evidence.md](docs/evidence.md) | every claim, and the test or measurement behind it |
| [ROADMAP.md](ROADMAP.md) | the path to 1.0 |
| [docs/design/decisions.md](docs/design/decisions.md) | decision register with measurements |

Man pages in `man/`, generated from the CLI definition.

## Development

```console
cargo test
cargo clippy --all-targets
cargo fmt --check
```

Tests use in-process fixtures only, including SOCKS5, HTTP CONNECT and TLS responders with
injectable behaviour; nothing reaches the internet. Region coverage is 91% (CI floor 85%),
and `tests/compat/` pins every reader's output on a record from each release.

## Authorization

For systems you are authorized to scan. Port scanning without permission is unlawful in
many jurisdictions.
