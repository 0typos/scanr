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
(`0x02`) and 3proxy answers `0x09`, which is not even a defined reply code. For a remote
proxy, pass `--known-open HOST:PORT` naming something you know it can reach.

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

Convenient and widely available, with two caveats worth knowing:

- **`open_only` fidelity.** You learn which ports are open and nothing about why the
  others are not.
- It handled concurrency 512 with zero loss in testing, which was not expected. It is not
  necessarily the weak link.

Everything multiplexes as channels over a single TCP connection, so the SSH client can
become CPU-bound on crypto before the proxy protocol is the constraint.
