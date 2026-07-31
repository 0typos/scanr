# scanr

Proxy-aware TCP connect scanner with reproducible, durable scan records.

`scanr` performs unprivileged TCP `connect()` probes — directly or through a SOCKS5
proxy — streams open ports to stdout as it finds them, and **always** writes a JSON
Lines record containing the fully resolved configuration and exactly one terminal event
saying whether the run completed, was interrupted, or failed.

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

`scanr` is **not** a replacement for any of them. No SYN scanning, no UDP, no service
or OS fingerprinting, no scripting, no evasion. It does one thing.

## Install

```console
cargo build --release                                    # ./target/release/scanr
cargo build --release --target x86_64-unknown-linux-musl  # static, no libc dependency
```

Linux x86_64 only for now. The musl build is fully static (`static-pie`, ~2 MB) and
needs no C toolchain.

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

## Know what your proxy can actually tell you

This is the part most worth understanding.

SOCKS5 defines separate reply codes for refused (`0x05`), unreachable (`0x03`/`0x04`)
and policy denial (`0x02`), but not every proxy uses them. Measured against real
software:

| proxy | refused destination | usable? |
|---|---|---|
| microsocks | `05 05 ...` — reply `0x05` | yes, `closed` is distinguishable |
| `ssh -D` (OpenSSH) | **no reply at all**; connection closed | no |

OpenSSH is the more awkward case, and worse than merely collapsing codes: it sends *no
SOCKS5 reply whatsoever* and closes the channel. Its own log says
`connect failed: Connection refused`, so it knows the reason and simply has no way to
convey it. Some proxies instead answer `0x01 general failure` for everything, which is
equally unusable. Through any of these, **a closed port and a filtered port are
indistinguishable**.

Measured against four real proxies:

| proxy | refused destination | fidelity |
|---|---|---|
| microsocks | `0x05` | full |
| dante (sockd 1.4.3) | `0x05` | full |
| 3proxy | `0x05` | full |
| OpenSSH `ssh -D` | **no reply**, channel closed | open_only |

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

versus a real `ssh -D` forward:

```console
$ scanr transport test sshd
  known-open        open      reply 0x00         0.4ms
  known-closed      error     no reply           0.3ms   <- expected closed
  blackholed        filtered  no reply        3058.7ms

  fidelity          open_only
  The known-closed destination produced no usable reply code (the proxy
  may have timed out or closed the connection, which is what OpenSSH's
  `ssh -D` does), so closed and filtered cannot be distinguished.
```

Scanning the same 16 ports three ways shows exactly what that costs. Direct and
microsocks agree on every port; through `ssh -D` the open ports still agree and
everything else becomes `error` with the reason recorded:

```
PORT                       direct    microsocks  ssh -D
127.0.0.1:9201/tcp         open      open        open
127.0.0.1:9195/tcp         closed    closed      error     "proxy closed the connection
                                                             while reading CONNECT reply"
```

When a proxy cannot tell the difference, `scanr` records `error` with
`source: proxy_reply` — it will not invent a `closed` it never observed. Every result
carries where its classification came from (`local_stack`, `proxy_reply`, `timeout`).

Record the measurement so it stops warning on every scan, and so the fact lives in
version control rather than a hidden cache. `transport test` prints the exact line:

```console
  to record this, add to [transports.pool]:
      fidelity = "open_only"
```

Once declared, `plan` shows `declared in config` and the warning becomes specific:
*"proxy `pool` is recorded as open_only: it cannot distinguish a closed port from a
filtered one, so non-open results will be `error`"*.

### How much concurrency will your proxy take?

Also measurable, and worth knowing: the proxy's own connection cap is usually what
decides whether a scan succeeds, not scanr's `concurrency` setting.

```console
$ scanr transport test lab --calibrate
  concurrency
    at 8              32 probes,   0 refused      0%
    at 16             64 probes,   0 refused      0%
    at 32            128 probes, 125 refused     98%
  Concurrency 16 was clean; it began refusing above that. [...] This proxy has a
  connection cap, and raising it there (for example 3proxy's `maxconn`) is usually
  the better fix.
```

That sweep is opt-in — it generates real traffic and takes about a minute. It is also
deliberately conservative: it uses a harsher connection-churn profile than a real scan,
so the level it clears is a floor rather than a maximum.

A 3proxy left at its default `maxconn 100` loses 7% of probes at concurrency 32 and 48%
at 64, while the same binary with `maxconn 2000` loses nothing at 512. microsocks and
`ssh -D` both handled 512 cleanly. When a proxy does saturate mid-scan, `scanr` says so
once, with remediation, rather than silently filling the record with `error`.

## Configuration

Two optional files, project wins per key:

1. `~/.config/scanr/config.toml` — transports and credentials
2. `./scanr.toml` — scan definitions, version-controlled

`scanr config init` generates a fully annotated file. Resolution order:

```
compiled default -> builtin profile -> user config -> project config
  -> selected profile -> named scan -> environment (credentials) -> CLI override
```

`scanr plan` shows the final value of every field **and where it came from**:

```console
$ scanr plan internal-web
scan            internal-web
profile         proxy                                   builtin
transport       lab (socks5)                            scan.internal-web
  address       127.0.0.1:1080
  fidelity      full                                    declared in config
dns             auto -> transport                       transport.lab
targets         255 (10.20.30.0/24)
ports           1002 (80,443,8000-8999)
probes          255,510
order           randomized, seed 9f2c00a1b4de7731       builtin
concurrency     512                                     profile.proxy
rate            400/s                                   builtin.proxy
connect_timeout 8s                                      cli
retries         1 (timeouts only, delay 250ms)          profile.proxy

projection      ~10m39s at 400/s
host            ephemeral 32768-60999 (28232 ports), tcp_tw_reuse=2 (loopback only), nofile=1048576
```

### Credentials

Inline passwords are **rejected**, not warned about — project config normally gets
committed. Use `password_env` or a mode-0600 `password_file`. Credentials never appear
in the record, in `plan`, or in error output (including when an error points at the
line that contains one).

### Profiles

Four built-ins, flat and complete — no inheritance, so what you read is what runs.

| profile | concurrency | rate | connect timeout | for |
|---|---|---|---|---|
| `proxy-careful` | 64 | 50/s | 8s | rotating pools, `ssh -D`, unknown limits |
| `proxy` | 512 | 400/s | 5s | self-hosted dante/microsocks |
| `direct` | 512 | unlimited | 2s | routed networks, no proxy |
| `direct-fast` | 2048 | unlimited | 1s | LAN, latency known low |

With no profile selected, the default follows the transport: `proxy` for SOCKS5,
`direct` otherwise.

## The scan record

Every run writes `scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz`, carrying `.partial`
while running and renamed on the terminal event — so a file still named `.partial` means
the process died without finalizing.

Records are gzip and repeated outcomes are collapsed by default; `--no-compress` and
`--no-spans` give plain JSONL with one row per probe. `zcat`, `zless` and every
`scanr output` command read either form. Note that with spans on, `probe_result` does not
cover every probe — see [docs/output-schema.md](docs/output-schema.md).

Eight event types; `scan_started` first, `scan_config` second, exactly one terminal
event (`scan_completed` / `scan_interrupted` / `scan_failed`) last, and nothing after it.

```console
$ scanr output verify scanr-results/scan-1785294704201-a3f19c02.jsonl.gz
  61 events
  terminal: scan_interrupted
  56 probe results
ok — record is complete and internally consistent

$ scanr output summarize scanr-results/scan-*.jsonl.gz
$ scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -
```

The config event embeds the **canonical unexpanded** target spec plus counts, never the
expanded matrix — a /16 × 1000 ports is 65M probes. Combined with the recorded
permutation seed, that is enough to reproduce the scan exactly.

Probe order is randomized across the whole target×port matrix (a seeded Feistel
permutation, O(1) memory), so a scan is randomized *and* replayable via `--seed`.

## Interruption

First Ctrl-C stops scheduling and drains in-flight probes, bounded by the connect
timeout. Second Ctrl-C exits immediately. Either way the record is finalized with
accurate accounting, and exit code is 130.

Counts distinguish three buckets, which sum to `planned`:

- `completed` — reported a result
- `abandoned` — a worker picked it up but the drain ended first (may have touched the network)
- `not_started` — never issued

## Exit codes

| code | meaning |
|---|---|
| 0 | completed naturally (including zero open ports) |
| 1 | usage or configuration error; nothing was scanned |
| 2 | scan failed after starting |
| 3 | output writer failure |
| 130 | interrupted by SIGINT; results finalized |

## How fast, next to nmap

A `/24` × nmap's top 100 ports — 25,600 probes. Both doing **unprivileged TCP connect
scans**, so the technique is identical. nmap 7.92, `-sT -T5 --min-rate 10000
--max-retries 0 -Pn -n`.

**Responsive hosts** (every port refused):

| | wall | probes/s |
|---|---|---|
| `scanr`, default profile | **0.17 s** | ~150,000 |
| nmap `-T5` | 0.52 s | ~49,000 |

Both reported exactly the same 259 open ports — the gap is not `scanr` cutting corners.

**Unresponsive hosts** (every probe times out), where the comparison is really about
timeouts:

| | wall |
|---|---|
| `scanr --profile direct-fast` (1 s timeout) | 13.10 s |
| nmap `-T5` | 7.16 s |
| `scanr --connect-timeout 300ms --concurrency 4096` | **2.23 s** |

nmap wins the first line and it is not mysterious: `-T5` caps its retransmit timeout at
300 ms while `direct-fast` waits a full second. Told to give up as fast as nmap does,
`scanr` is **3.2× quicker** — the same ratio as the responsive case.

The real difference is that **nmap adapts its timeout from observed round-trip times and
`scanr` does not**. That is deliberate (clear limits over hidden magic), and it has a
cost: on an unfamiliar network nmap self-tunes and you have to set `--connect-timeout`.
`scanr plan` projects the duration so the consequence is visible before you spend it.

Measured on loopback and TEST-NET on one machine, so it compares the tools rather than a
network. As root, nmap's `-sS` SYN scan is a different and faster technique that `scanr`
does not implement. And `scanr` is writing a complete JSONL record throughout, which
nmap is not.

## Performance notes

Probe sockets are closed with `SO_LINGER{on,0}`, sending RST instead of FIN and
skipping `TIME_WAIT` entirely. This matters more than it sounds: measured at a **7.5×
sustained-throughput multiplier** (9,189 → 68,949 probes/s), with TIME_WAIT
accumulation falling from 21,931 sockets to 1.

Without it, a proxied scan is capped near **470 probes/s** — every probe consumes a
local ephemeral port, and Linux holds `TIME_WAIT` for a hardcoded 60s against a default
range of 28,232 ports. `tcp_tw_reuse=2` (the modern default) exempts loopback only, so
a *local* proxy escapes this and a *remote* one does not. `scanr plan` reads these
sysctls and tells you which regime you are in.

Concurrency is the worker thread count — there is no queue, so it is a hard ceiling
rather than a target. Higher is not monotonically better: measured throughput peaked
near 512 threads and declined at 2048.

glibc builds run ~1.7× faster than musl on a loopback microbenchmark (128k vs 75k
probes/s). This is irrelevant for real work — any proxied scan is orders of magnitude
below either figure — so the static musl build is recommended whenever portability
matters.

## Architecture in one paragraph

Blocking sockets on a bounded thread pool. No async runtime, no `mio`. The full
reasoning is in `docs/design/02-runtime-evaluation.md`, but the short version: SOCKS5 is
the primary path and its handshake is straight-line code when blocking versus a
resumable state machine under any readiness loop; `TcpStream::connect_timeout` already
*is* this tool's core primitive; and Linux-only removes the portability argument for a
readiness abstraction. Tokio is the documented fallback and the port would be largely
mechanical.

## Documentation

| | |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | **start here** — install to verified record, with real output |
| [docs/configuration.md](docs/configuration.md) | precedence, profiles, target and port sets, DNS modes |
| [docs/transports.md](docs/transports.md) | what your proxy can tell you, and how much concurrency it takes |
| [docs/output-schema.md](docs/output-schema.md) | the record, its guarantees, `jq` recipes |
| [docs/tuning.md](docs/tuning.md) | where the real limits are, with measured numbers |
| [docs/troubleshooting.md](docs/troubleshooting.md) | keyed to the diagnostics the tool emits |
| [docs/security.md](docs/security.md) | trust boundaries, credentials, DNS leakage |

Man pages are in `man/`, one per command, generated from the CLI definition.

`docs/design/` holds the decision register and the specifications. Every significant
decision is recorded there with its alternatives, rationale, and revisit trigger —
including the assumptions that turned out to be wrong.

## Development

```console
cargo test              # 253 unit + 20 end-to-end
cargo clippy --all-targets
cargo fmt --check
```

Tests use in-process fixtures only — including a SOCKS5 server with injectable
behaviour (faithful, collapsing, auth, malformed replies, mid-handshake disconnects).
Nothing reaches the public internet and no daemon needs installing.

## Authorization

`scanr` is for systems you are authorized to scan. Port scanning without permission is
unlawful in many jurisdictions.
