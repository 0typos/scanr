# scanr

Proxy-aware TCP connect scanner with reproducible, durable scan records.

Unprivileged `connect()` probes, direct or through SOCKS5 and HTTP CONNECT proxies
(single proxy, chain, or pool). Open ports stream to stdout. Every run writes a JSON
Lines record holding the fully resolved configuration and exactly one terminal event
saying whether it completed, was interrupted, or failed. Roughly
`nmap -Pn -sT -n -v --open -T4 -p <ports> <targets>`, proxy-native and config-first.

```console
$ scanr run internal-web
Overview
scan            internal-web
transport       bastion (socks5 127.0.0.1:1080)  fidelity full
scope           255,510 probes (255 targets x 1002 ports)
timing          concurrency 512, rate 400/s, connect_timeout 5s
scan id         a3f19c02  seed 9f2c00a1b4de7731

Results
10.20.30.40:22/tcp    open   ssh          18.2ms
10.20.30.40:443/tcp   open   https        21.4ms
...

Summary
result          completed in 10m41s
states          38 open, 1,204 closed, 254,210 filtered, 58 error
probed          255,510 of 255,510
record          ./scanr-results/scan-internal_web-2026_07_29T03_11_44Z-a3f19c02.jsonl.gz
```

## Why

Enumerate reachable TCP services through a SOCKS proxy, with results you can verify
and reproduce.

| tool | gap |
|---|---|
| `nmap` + `proxychains` | `LD_PRELOAD` is fragile, leaks DNS, fights nmap's parallelism |
| `masscan` / `ZMap` | stateless SYN cannot traverse a proxy; needs privileges |
| `RustScan` / `naabu` | proxy support absent or marginal; no durable record |
| `nc -z` in a loop | no concurrency control, structure, or record |

Not a replacement for any of them. No SYN, no UDP, no fingerprinting, no scripting, no
evasion.

## Install

Prebuilt binaries are attached to each
[GitHub release](https://github.com/0typos/scanr/releases) as
`scanr-<tag>-<target>.tar.gz` with a `.sha256` beside it. Each tarball holds the
binary, shell completions, README, CHANGELOG and licences.

```console
tag=v1.0.0-rc.7 target=x86_64-unknown-linux-musl
curl -LO "https://github.com/0typos/scanr/releases/download/$tag/scanr-$tag-$target.tar.gz"{,.sha256}
sha256sum -c "scanr-$tag-$target.tar.gz.sha256" && tar -xzf "scanr-$tag-$target.tar.gz"
./scanr-$tag-$target/scanr --version
```

```console
cargo install --git https://github.com/0typos/scanr --locked   # from source, current main

cargo build --release                                      # ./target/release/scanr
cargo build --release --target x86_64-unknown-linux-musl   # static-pie, ~2 MB, no libc
```

Eight release targets, cross-compiled with `cargo-zigbuild` (`scripts/build-all.sh`
does the same locally):

| target | libc |
|---|---|
| x86_64, aarch64 | glibc and static musl |
| armv7, i686, riscv64, ppc64le | static musl |

Linux x86_64 (gnu and musl) is the tested platform; the full suite runs there. The other
targets are smoke-run under emulation and provided best-effort. macOS builds and passes CI
(`cargo install --path .`, then `ulimit -n 8192`); its `/proc` diagnostics report unknown
and there is no static build. Windows is not planned.

## Quick start

```console
scanr config init          # annotated scanr.toml documenting every field
scanr config validate
scanr plan internal-web    # resolve and show the scan, no traffic
scanr run internal-web
```

Ad hoc:

```console
scanr run --targets 10.20.30.0/24 --ports 22,80,443
scanr run --targets hosts.txt --ports 1-1024 --transport lab
subfinder -d example.com | scanr run --targets - --ports web
```

[docs/getting-started.md](docs/getting-started.md) walks from install to a verified
record; [docs/tutorial.md](docs/tutorial.md) runs ten use cases against a local lab, with
recorded terminal sessions in `docs/tutorial/demos/`.

## What your proxy can tell you

SOCKS5 has distinct reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`) and
policy denial (`0x02`). Not every proxy uses them.

| proxy | refused destination | fidelity |
|---|---|---|
| microsocks | `0x05` | full |
| dante (sockd 1.4.3) | `0x05` | full |
| 3proxy | `0x05` | full |
| OpenSSH `ssh -D` | no reply, channel closed | open_only |

Through `ssh -D` a closed port and a filtered port are indistinguishable. `scanr`
measures this instead of assuming it:

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
`source: proxy_reply`, never an invented `closed`. HTTP CONNECT proxies never can. HTTP
has no status meaning refused, and squid, tinyproxy and 3proxy each pick a different one
and use it for timeouts too, so they are `open_only` by construction. Every result records
where its classification came from. `transport test --calibrate` finds the proxy's
connection cap, which usually decides whether a scan succeeds. Detail:
[docs/transports.md](docs/transports.md).

## The record

`scanr-results/scan-<name>-<UTC time>-<scan_id>.jsonl.gz`, `.partial` while running
and renamed on the terminal event. `scan_started` first, `scan_config` second, one
terminal event last. Mode 0600.

```console
scanr output verify    scanr-results/scan-*.jsonl.gz
scanr output summarize scanr-results/scan-*.jsonl.gz
scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -   # exact resume
```

`--tls` adds the one active probe, a ClientHello offering TLS 1.3 and 1.2 to open ports
that sent no banner. It records the certificate (subject, chain, alternative names,
validity, key type, the DER itself), cipher and ALPN. `--tls-versions` (needs `--tls`)
then asks SSLv2 through TLS 1.2 for themselves, each on its own connection, and names a
server only an old client can reach. Both are off by default, and the record says what
was sent.

Records are gzip-framed and span-collapsed by default (`--no-compress`, `--no-spans` for
one row per probe); `zcat`, `zless` and every `scanr output` command read either. The
config event stores the canonical target spec and the permutation seed, enough to
reproduce the scan exactly. Schema and `jq` recipes:
[docs/output-schema.md](docs/output-schema.md).

## Interruption

The first Ctrl-C stops scheduling and drains in-flight probes, bounded by the connect
timeout. The second exits immediately. Either way `scanr` finalises the record and exits
130. `completed` + `abandoned` (may have touched the network) + `not_started` =
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
unresponsive hosts nmap adapts its timeout from observed RTTs and `scanr` does not:
`--connect-timeout` is yours to set and `scanr plan` projects the cost. On equal
single-attempt terms `scanr` is ~3× quicker there. Loopback measures the engines, not a
network; through a proxy the proxy's cap decides for both. Methodology and knobs:
[docs/tuning.md](docs/tuning.md).

## Documentation

| | |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | install to verified record |
| [docs/tutorial.md](docs/tutorial.md) | ten use cases with captured output and recorded sessions, and where nmap fits |
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

Tests use in-process fixtures only, including SOCKS5, HTTP CONNECT and TLS responders
with injectable behaviour; nothing reaches the internet. Region coverage is 91% (CI floor
85%), and `tests/compat/` pins every reader's output on a record from each release.
Release process: [RELEASING.md](RELEASING.md).

## Authorization

Scan only systems you are authorized to scan. Port scanning without permission is
unlawful in many jurisdictions.
