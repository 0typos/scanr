# Getting started

Install, configure, measure the proxy, run, check the record. Every output is real.

## Install

```console
cargo build --release --target x86_64-unknown-linux-musl
sudo install -m755 target/x86_64-unknown-linux-musl/release/scanr /usr/local/bin/
```

The musl build is static; `cargo install --path .` also works.

```console
$ scanr --version
scanr 0.3.0 (c6f0274ab x86_64-unknown-linux-gnu)
rustc 1.97.1 (8bab26f4f 2026-07-14)
```

The commit is recorded in every scan record.

## 1. Write a configuration

```console
$ scanr config init
wrote scanr.toml — every field documented with its default and range
next: scanr config validate && scanr plan internal-web
```

Edit the `[transports.lab]` address and `[targets.*]` / `[ports.*]`, then:

```console
$ scanr config validate
ok — 1 file(s), 1 scan(s), 2 transport(s)
```

All problems at once, with line and suggestion:

```
error: unknown field `concurency`, expected one of `concurrency`, `rate`, ...
 --> ./scanr.toml:3:1
  |
3 | concurency = 512
  | ^^^^^^^^^^

help: did you mean `concurrency`?
```

## 2. Find out what your proxy can tell you

Do this before trusting a proxied scan: a proxy not using SOCKS5's distinct
refused/unreachable replies cannot separate closed from filtered.

```console
$ scanr transport test lab
transport lab (socks5 127.0.0.1:1080)
  reachable         yes
  known-open        open      reply 0x00         1.1ms
  known-closed      closed    reply 0x05         0.6ms
  blackholed        filtered  reply 0x04      3003.7ms

  fidelity          full
  This proxy reports refused connections distinctly (0x05), so scanr can
  tell `closed` apart from `filtered` in your results.

  to record this, add to [transports.lab]:
      fidelity = "full"
```

Paste that line into the config; it silences the per-scan "not measured" warning.
`open_only` (OpenSSH `ssh -D`) gives open vs not-open only; non-open is recorded as `error`.

`--calibrate` finds the proxy's concurrency cap (real traffic, about a minute):

```console
$ scanr transport test lab --calibrate
  concurrency
    at 8              32 probes,   0 refused      0%
    at 16             64 probes,   0 refused      0%
    at 32            128 probes, 125 refused     98%
  Concurrency 16 was clean; it began refusing above that. [...]
```

## 3. Look before you scan

No network. Right-hand column: the configuration layer that supplied each value.

```console
$ scanr plan internal-web
scan            internal-web
description     Internal web services through the lab proxy
profile         proxy                                   scan.internal-web
transport       lab (socks5)                            scan.internal-web
  address       127.0.0.1:1080
  fidelity      full                                    declared in config
dns             auto -> transport                       transport.lab
targets         1 (127.0.0.1)
ports           3 (8080,8443,9999)
probes          3
order           randomized, seed 5e160d294c394b1d       builtin
concurrency     512                                     builtin.proxy
rate            400/s                                   builtin.proxy
connect_timeout 8s                                      scan.internal-web
proxy_timeouts  connect 3s, handshake 5s                builtin.proxy
retries         1 (timeouts only, delay 250ms)          builtin.proxy
output          ./scanr-results                         defaults
```

Warns on unmeasured fidelity, rate above the ephemeral-port budget, concurrency above
`RLIMIT_NOFILE`.

## 4. Run it

```console
$ scanr run internal-web --all
scanr 0.3.0 — internal-web via socks5 127.0.0.1:1080 — 3 probes (1 targets x 3 ports)
  scan 0e1a180b  seed 950f58a8b869db32  concurrency 512  -> ./scanr-results/scan-1785455411611-0e1a180b.jsonl.gz.partial
127.0.0.1:8080/tcp open http-proxy 0.6ms
127.0.0.1:8443/tcp open https-alt 0.5ms
127.0.0.1:9999/tcp closed 0.4ms

completed in 0.01s — 2 open, 1 closed, 0 filtered, 0 error (3 of 3 probed)
  record: ./scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
```

Without `--all` only open ports print; the record keeps every outcome. stdout is results
only: `scanr run internal-web | awk '{print $1}' > open-ports.txt`. Ctrl-C drains
in-flight probes and writes a complete record marked interrupted.

## 5. Check the record

```console
$ scanr output verify scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
  6 events
  terminal: scan_completed
  3 probe results

ok — record is complete and internally consistent
```

Checks structure, count reconciliation, and credential leakage. A file still named
`scan-<...>.jsonl.gz.partial` died before finalizing: results valid, `verify` says truncated.

```console
$ scanr output summarize scanr-results/scan-*.jsonl.gz
  seed            950f58a8b869db32
  result          scan_completed (natural)
  duration        0.01s
  states          2 open, 1 closed, 0 filtered, 0 error

by host (1 host):
  host               open closed filtered  error  open ports
  127.0.0.1             2      1        0      0  8080/http-proxy 8443/https-alt
```

`summarize` also breaks down by network, port, service (`--by`, `--json`). `output
results` filters by host, port, state; `--format nmap` / `list` hand on:
[cli.md](cli.md#handing-results-to-another-tool).

## 6. If it was interrupted

```console
scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -
```

Re-probes only endpoints never reported. The new record names the one it continues:

```console
$ scanr output verify scanr-results/scan-*.jsonl.gz | grep resumed
  resumed from scan a7b012c0
```

## Next

Commands and global flags: [cli.md](cli.md). Doc index: [README.md](README.md). Man
pages: `man scanr`, `man scanr-run`, etc.
