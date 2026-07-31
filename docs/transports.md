# Transports

A transport is how `scanr` reaches a destination. Two exist: `direct` and `socks5`.

One transport per scan. Multiple proxies and proxy chains are deferred, not planned.

## Why SOCKS4 is not supported

SOCKS4 defines four reply codes: `0x5A` granted, `0x5B` rejected-or-failed, and
`0x5C`/`0x5D` for identd. There is no code for "connection refused" as distinct from
anything else, so a closed port and a filtered port are **indistinguishable under any
circumstance**. Supporting it would mean either fabricating states or carrying a
permanently degraded path through the result schema. SOCKS5 does the same job properly.

## What your proxy can actually tell you

This is the thing most worth understanding before trusting a proxied scan.

SOCKS5 (RFC 1928) defines distinct reply codes — `0x05` refused, `0x03`/`0x04`
unreachable, `0x02` denied by ruleset — but implementations differ in whether they use
them. Measured by capturing raw bytes:

| proxy | known-open | refused destination | unroutable destination | fidelity |
|---|---|---|---|---|
| microsocks | `0x00` | `0x05` | no reply, timeout | **full** |
| dante (sockd 1.4.3) | `0x00` | `0x05` | `0x01` | **full** |
| 3proxy | `0x00` | `0x05` | no reply, timeout | **full** |
| OpenSSH `ssh -D` | `0x00` | **no reply**, channel closed | no reply, timeout | **open_only** |

OpenSSH is the awkward one, and worse than merely collapsing codes: it sends *no SOCKS5
reply at all* and closes the channel. Its own client log records
`channel N: open failed: connect failed: Connection refused`, so it knows the reason and
has no way to express it in its SOCKS5 layer.

Note also that the `BND.ADDR` in a successful `ssh -D` reply is `0.0.0.0`. That is why a
hostname resolved by the proxy can never have its address recorded — see
[configuration](configuration.md#dns).

### Measuring it

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

  to record this, add to [transports.lab]:
      fidelity = "full"
```

Three destinations are probed: one that should be open, one that should be refused, and
`192.0.2.1` (RFC 5737 TEST-NET-1, guaranteed unroutable).

For the known-open target, a loopback proxy gets a listener `scanr` binds itself, which
it is guaranteed to be able to reach. This matters: the obvious choice of "the proxy's own
listening socket" fails on **half** the proxies measured — dante refuses it by ruleset
(`0x02`) and 3proxy answers `0x09`, which is not even a defined reply code.

For a remote proxy, name destinations it can reach:

```console
scanr transport test lab --known-open 10.1.1.5:443 --known-closed 10.1.1.5:1
```

`--known-closed` defaults to port 1 on the proxy host, which is reliably refused in most
deployments but not all.

### Recording it

Declaring the measurement in configuration turns off the per-scan "not measured" warning
and puts the fact in version control:

```toml
[transports.lab]
type = "socks5"
address = "127.0.0.1:1080"
fidelity = "full"     # or "open_only"
```

Deliberately not cached automatically. It is a property of a proxy that rarely changes, it
belongs alongside the transport it describes, and it appears in the scan record with its
provenance — which a hidden cache could not provide.

### What `open_only` means for your results

Nothing is guessed. A non-open result through such a proxy is recorded as `error` with
`source: proxy_reply` and a reason, never as a fabricated `closed` or `filtered`. Scanning
the same 16 ports three ways:

```
PORT                       direct    microsocks  ssh -D
127.0.0.1:9201/tcp         open      open        open
127.0.0.1:9195/tcp         closed    closed      error   "proxy closed the connection
                                                          while reading CONNECT reply"
```

Direct and microsocks agreed on every port. Through `ssh -D` the open ports still agreed
exactly; everything else became `error`.

## How much concurrency will it take?

Usually the proxy's own connection cap, not scanr's `concurrency`, decides whether a scan
succeeds.

```console
$ scanr transport test lab --calibrate
  concurrency
    at 8              32 probes,   0 refused      0%
    at 16             64 probes,   0 refused      0%
    at 32            128 probes, 125 refused     98%
  Concurrency 16 was clean; it began refusing above that. [...]
```

Opt-in, because it generates real traffic and takes about a minute. Deliberately
conservative: it holds connections across repeated rounds, a harsher churn profile than
most scans, so the level it clears is a floor rather than a maximum.

Measured loss against 64 unroutable targets × 4 ports:

| proxy | c=16 | c=24 | c=32 | c=48 | c=64 | c=256 | c=512 |
|---|---|---|---|---|---|---|---|
| microsocks | 0% | — | 0% | — | 0% | 0% | 0% |
| `ssh -D` | 0% | — | 0% | — | 0% | 0% | 0% |
| 3proxy, default `maxconn 100` | 0% | 0% | 7% | 37% | 48% | 95% | 80% |
| 3proxy, `maxconn 2000` | 0% | — | 0% | — | 0% | 0% | 0% |

The same 3proxy binary loses nothing at 512 once its cap is raised. **Raising the cap on
the proxy is usually the better fix than lowering concurrency.**

Note that a burst of simultaneous connections does *not* predict this. 3proxy accepts 64
held connections without complaint while losing 48% of probes in a churning scan at the
same concurrency, because it keeps closed connections in its table long enough for a
continuously-reconnecting scanner to exceed the cap.

## Authentication

RFC 1929 username/password. It authenticates you to the proxy; **it does not encrypt
anything**, and the credentials cross the wire in cleartext.

```toml
[transports.lab]
type = "socks5"
address = "10.1.1.1:1080"
username = "scanner"
password_env = "SCANR_LAB_PASSWORD"
```

Inline passwords are rejected — see [security](security.md#credentials).

## `ssh -D` specifically

Convenient and widely available. Use one of the `ssh` profiles rather than the proxy
ones — measured against OpenSSH 10.2p1, 4,000 probes took **80 s** under `proxy-careful`
and **0.16 s** under `ssh`, with every probe reported either way:

```console
scanr run --transport tunnel --profile ssh        # typical internet link
scanr run --transport tunnel --profile ssh-fast   # nearby server, low latency
scanr run --transport tunnel --profile ssh-slow   # high-latency or congested
```

Three things make `ssh -D` different from a normal SOCKS5 proxy:

**The listener is local.** Every probe connects to `127.0.0.1`, which `tcp_tw_reuse = 2`
exempts from the TIME_WAIT restriction, so the ~470/s ephemeral ceiling behind `proxy`'s
`rate = 400` does not apply. That cap is the whole 80 s above: 4,000 probes at 50/s under
`proxy-careful` is 80 s exactly, and at 400/s under `proxy` it is 10 s exactly. The `ssh`
profiles set `rate = 0`.

**The local round trip is free.** SOCKS negotiation measured 0.4–0.5 ms, and a *refused*
destination also returns in 0.4 ms because `ssh -D` simply closes the channel. Only
genuinely silent hosts ever cost `connect_timeout`. The `ssh` profiles keep the local
timeouts short and spend the budget on the destination leg, which is the only one
crossing the wire.

**Concurrency saturates early, then falls off a cliff.** Every channel shares one TCP
connection. Throughput was flat at ~28,500 probes/s from concurrency 32 through 128, then
collapsed at 160 — three runs at each level, reproducible:

| concurrency | 32 | 64 | 96 | 128 | 160 | 256 | 512 |
|---|---|---|---|---|---|---|---|
| probes/s | 28,571 | 28,571 | 28,571 | 25,000 | 1,852 | 1,869 | 1,770 |

The cliff is a fixed ~1 s stall rather than a slower rate: at concurrency 160, scans of
2,000 / 4,000 / 8,000 probes all cost about 1.1 s. So it amortises away on a big scan and
dominates a small one — but since nothing above ~128 buys throughput, there is no reason
to go there. All three `ssh` profiles stay under it, and a test enforces that.

Concurrency across the three rises as the link gets *slower*, which is the opposite of
the instinct: in-flight probes needed is roughly rate × RTT, so a long round trip needs
more outstanding work to stay busy, not less. The cliff is the ceiling on that.

**`open_only` fidelity** still applies: you learn which ports are open and nothing about
why the others are not.
