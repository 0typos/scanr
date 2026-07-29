# scanr — Product Brief

Status: draft for review (2026-07-29)

## Problem

Operators who need to enumerate reachable TCP services *through a SOCKS proxy* have no
good tool. The options all fail in a specific way:

- **nmap + proxychains** — `LD_PRELOAD` interception is fragile, silently leaks DNS,
  mishandles nmap's parallelism, and produces results that cannot be trusted or
  reproduced. nmap's own `--proxies` support is documented as incomplete.
- **masscan / ZMap** — stateless SYN scanning cannot traverse a proxy at all, and
  requires privileges.
- **RustScan / naabu** — fast, but proxy support is absent or marginal, and neither
  produces a durable record of *what settings produced this result*.
- **`nc -z` in a loop** — works, but no concurrency control, no record, no structure.

The gap is not speed. It is **proxy-aware TCP connect scanning that produces a
trustworthy, reproducible artifact.**

## What scanr is

An unprivileged TCP `connect()` scanner that probes a target×port matrix directly or
through a SOCKS5 proxy, streams open ports to stdout as they are found, and
unconditionally writes a self-describing JSONL record containing the fully resolved
configuration and a single terminal event stating whether the run completed, was
interrupted, or failed.

Roughly the workflow of:

```
nmap -Pn -sT -n -v --open -T4 -p <ports> <targets>
```

but proxy-native, config-first, and forensically complete.

## Primary user

An operator running authorized internal assessment or infrastructure verification, who:

- reaches target networks predominantly through SOCKS5 (rotating pools, self-hosted
  dante/microsocks, or `ssh -D` dynamic forwards),
- re-runs the same named scans repeatedly and cares whether results changed,
- needs to prove after the fact exactly what was scanned, how, and whether the run
  finished.

## Core workflows

1. Define a scan once in TOML; run it by name. `scanr run internal-web`
2. Inspect the fully resolved plan without touching the network. `scanr plan internal-web`
3. Learn what result fidelity a proxy can actually provide, before scanning.
   `scanr transport test lab`
4. Watch open ports appear immediately; collect the JSONL afterward.
5. Verify a prior result file is complete and untruncated. `scanr output verify <file>`
6. Feed the un-probed remainder of an interrupted scan back in as a target list.

## Success criteria

- A scan through a SOCKS5 proxy produces results that are correct and *known* to be
  correct — including an explicit statement of what the proxy could not tell us.
- Every run leaves a file that answers "what was scanned, with what settings, and did
  it finish?" without consulting shell history.
- Ctrl-C leaves a valid, finalized file with accurate accounting of what was and was
  not probed.
- Errors name the actual operational cause (ephemeral port exhaustion, proxy auth
  failure, proxy policy denial) with the remediation, not an errno.
- Predictable, bounded resource use across repeated runs.

## Non-goals (v1 and likely permanently)

Raw SYN scanning · UDP · OS fingerprinting · service-version detection · vulnerability
checks · NSE · packet crafting or capture · internet-scale stateless scanning · full
nmap CLI compatibility · evasion features · GUI · distributed control plane.

## Non-goals (v1, revisit later)

SOCKS4/4a · HTTP CONNECT · SSH-native transport · proxy chains · multiple proxies per
scan · banner grabbing · Windows and macOS support · library/API surface · plugins.

## Explicitly not a replacement for

nmap (service detection, scripting, protocol breadth), masscan/ZMap (internet scale),
RustScan (raw local speed), proxychains (transparent interception of arbitrary
programs). scanr does one thing: controlled, recorded, proxy-aware connect scanning.
