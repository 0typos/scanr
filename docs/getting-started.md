# Getting started

A complete first session: install, define a scan, learn what your proxy can tell you, run
it, and check the record. Every output below is real.

## Install

```console
cargo build --release --target x86_64-unknown-linux-musl
sudo install -m755 target/x86_64-unknown-linux-musl/release/scanr /usr/local/bin/
```

The musl build is fully static and needs no C toolchain. `cargo install --path .` works
too. Check what you have:

```console
$ scanr --version
scanr 0.1.0 (c6f0274ab x86_64-unknown-linux-gnu)
rustc 1.97.1 (8bab26f4f 2026-07-14)
```

The commit is not decoration — it also goes into every scan record, so a result file can
be traced back to the exact binary that produced it.

## 1. Write a configuration

```console
$ scanr config init
wrote scanr.toml — every field documented with its default and range
next: scanr config validate && scanr plan internal-web
```

That file is the reference: every field with its default, valid range, and whether the
command line can override it. Edit the `[transports.lab]` address to point at your proxy
and the `[targets.*]` / `[ports.*]` sets at what you want to scan.

```console
$ scanr config validate
ok — 1 file(s), 1 scan(s), 2 transport(s)
```

Validation reports every problem at once, points at the line, and suggests a fix:

```
error: unknown field `concurency`, expected one of `concurrency`, `rate`, ...
 --> ./scanr.toml:3:1
  |
3 | concurency = 512
  | ^^^^^^^^^^

help: did you mean `concurrency`?
```

## 2. Find out what your proxy can tell you

**Do this before trusting any proxied scan.** SOCKS5 defines distinct reply codes for
refused and unreachable, but not every proxy uses them, and one that does not cannot
distinguish a closed port from a filtered one.

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

Paste that line into your config. It silences the per-scan "not measured" warning and puts
the fact in version control next to the transport it describes.

If instead it reports `open_only` — which is what an OpenSSH `ssh -D` forward gives you —
then your results will distinguish open from not-open and nothing more. `scanr` will
record non-open results as `error` rather than guessing, which is the honest answer.

Optionally, find out how much concurrency the proxy will take. This generates real traffic
and takes about a minute:

```console
$ scanr transport test lab --calibrate
  concurrency
    at 8              32 probes,   0 refused      0%
    at 16             64 probes,   0 refused      0%
    at 32            128 probes, 125 refused     98%
  Concurrency 16 was clean; it began refusing above that. [...]
```

## 3. Look before you scan

`plan` resolves everything and shows you the result **without touching the network**:

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

The right-hand column is provenance: which configuration layer supplied each value. When
something is not what you expected, this tells you where it came from rather than leaving
you to guess.

`plan` also warns here — about unmeasured proxy fidelity, a rate above what your ephemeral
port budget sustains, or concurrency above `RLIMIT_NOFILE` — while it is still cheap to
act on.

## 4. Run it

```console
$ scanr run internal-web --all
scanr 0.1.0 — internal-web via socks5 127.0.0.1:1080 — 3 probes (1 targets x 3 ports)
  scan 0e1a180b  seed 950f58a8b869db32  concurrency 512  -> ./scanr-results/scan-1785455411611-0e1a180b.jsonl.gz.partial
127.0.0.1:8080/tcp open http-proxy 0.6ms
127.0.0.1:8443/tcp open https-alt 0.5ms
127.0.0.1:9999/tcp closed 0.4ms

completed in 0.01s — 2 open, 1 closed, 0 filtered, 0 error (3 of 3 probed)
  record: ./scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
```

Without `--all` only open ports print, which is the default. Either way **the record keeps
every probe outcome**.

stdout carries results and nothing else, so it pipes cleanly:

```console
scanr run internal-web | awk '{print $1}' > open-ports.txt
```

Press Ctrl-C and the scan stops scheduling, drains what is in flight, and still writes a
complete record saying it was interrupted and exactly how much it got through.

## 5. Check the record

Every run writes one, without being asked.

```console
$ scanr output verify scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
scanr-results/scan-1785455411611-0e1a180b.jsonl.gz
  6 events
  terminal: scan_completed
  3 probe results

ok — record is complete and internally consistent
```

That checks the file is structurally sound, that the counts reconcile, and that no
credential leaked into it.

```console
$ scanr output summarize scanr-results/scan-*.jsonl.gz
  seed            950f58a8b869db32
  result          scan_completed (natural)
  duration        0.01s
  states          2 open, 1 closed, 0 filtered, 0 error

open ports:
  127.0.0.1:8080/tcp  http-proxy
  127.0.0.1:8443/tcp  https-alt
```

A file still named `.partial` means the process died before finalizing. The results in it
are valid; `verify` will tell you it was truncated. With the default settings that is
`scan-<...>.jsonl.gz.partial`.

## 6. If it was interrupted

```console
scanr output remainder scanr-results/scan-*.jsonl.gz | scanr run --pairs -
```

That re-probes precisely the endpoints that were never reported — not whole targets — so a
host whose first two ports completed resumes with only the rest.

The new record names the one it continues, so the two halves stay connected:

```console
$ scanr output verify scanr-results/scan-*.jsonl.gz | grep resumed
  resumed from scan a7b012c0
```

## Where to go next

| | |
|---|---|
| [configuration.md](configuration.md) | precedence, profiles, target and port sets, DNS modes |
| [transports.md](transports.md) | proxy fidelity in depth, measured against real software |
| [output-schema.md](output-schema.md) | the record format, with `jq` recipes |
| [tuning.md](tuning.md) | where the real limits are |
| [troubleshooting.md](troubleshooting.md) | keyed to the diagnostics you will actually see |
| [security.md](security.md) | trust boundaries, credentials, DNS leakage |

Man pages cover every command and flag: `man scanr`, `man scanr-run`, and so on.

## Other commands

Not needed for a first scan, but they exist:

```console
scanr config show                # merged configuration: profiles, transports, scans
scanr config path                # which configuration files were found
scanr transport list             # defined transports at a glance
scanr transport show lab         # one transport's resolved settings
scanr completion bash            # shell completions; also zsh, fish, elvish, power-shell
```

Global flags: `--config PATH` to override discovery, `-q` to suppress progress, `-v` for
more detail, `--no-color` to disable colour (`NO_COLOR` is honoured too).
