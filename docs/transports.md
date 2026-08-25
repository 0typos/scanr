# Transports

Kinds: `direct`, `socks5`, `http` (CONNECT). One per scan; a `chain` traverses proxies of
either kind in order, a `pool` spreads probes across them.

## SOCKS4

Unsupported: replies `0x5A` granted, `0x5B` rejected-or-failed, `0x5C`/`0x5D` identd
have no distinct refused, so `closed` and `filtered` are indistinguishable.

## Proxy fidelity

SOCKS5 (RFC 1928) defines `0x05` refused, `0x03`/`0x04` unreachable, `0x02` denied by
ruleset. Raw bytes measured:

| proxy | known-open | refused destination | unroutable destination | fidelity |
|---|---|---|---|---|
| microsocks | `0x00` | `0x05` | no reply, timeout | full |
| dante (sockd 1.4.4) | `0x00` | `0x05` | `0x01` | full |
| 3proxy 0.9.7 | `0x00` | `0x05` | no reply, timeout; `0x05` once its own connect timeout fires | full, with a caveat |
| OpenSSH `ssh -D` | `0x00` | no reply, channel closed | no reply, timeout | open_only |

3proxy's `0x05` means "connect failed", not "refused": with `timeouts` set so its connect
timeout (2 s) is shorter than scanr's, a blackholed destination also came back `0x05` and
would be recorded `closed`. Keep `connect_timeout` below the proxy's own connect timeout,
or the proxy answers first and the distinction is lost.

OpenSSH sends no reply for a refused destination (client log: `channel N: open failed:
connect failed: Connection refused`), and its `BND.ADDR` is `0.0.0.0`, so a
proxy-resolved hostname never has its address recorded — see
[configuration](configuration.md#dns).

### Measuring

```console
$ scanr transport test lab
transport lab (socks5 127.0.0.1:1080)
  reachable         yes
  known-open        open      reply 0x00         1.7ms
  known-closed      closed    reply 0x05         0.6ms
  blackholed        filtered  reply 0x04      3003.5ms

  fidelity          full
  to record this, add to [transports.lab]:
      fidelity = "full"
```

| probe | default | override |
|---|---|---|
| known-open | loopback proxy: a listener scanr binds; remote: the proxy's own address | `--known-open host:port` |
| known-closed | port 1 on the proxy host (refused in most deployments, not all) | `--known-closed host:port` |
| blackholed | `192.0.2.1` (RFC 5737 TEST-NET-1) | — |

The proxy's own socket fails as known-open on half the proxies measured: dante `0x02`
(ruleset), 3proxy `0x09` (undefined code). Remote proxy:

```console
scanr transport test lab --known-open 10.1.1.5:443 --known-closed 10.1.1.5:1
```

### Recording

Silences the `fidelity_unknown` ("not measured") warning; kept in the scan record with
provenance. Never cached automatically.

```toml
[transports.lab]
type = "socks5"
address = "127.0.0.1:1080"
fidelity = "full"     # or "open_only"
```

### `open_only`

Non-open results become `error` with `source: proxy_reply` and a reason, never a guessed
`closed`/`filtered`:

```
PORT                       direct    microsocks  ssh -D
127.0.0.1:9201/tcp         open      open        open
127.0.0.1:9195/tcp         closed    closed      error   "proxy closed the connection
                                                          while reading CONNECT reply"
```

Across 16 ports, open agreed on all three; everything else via `ssh -D` was `error`.

## How much concurrency will it take?

The proxy's connection cap usually decides, not `concurrency`.

```console
$ scanr transport test lab --calibrate
  concurrency
    at 8              32 probes,   0 refused      0%
    at 16             64 probes,   0 refused      0%
    at 32            128 probes, 125 refused     98%
  Concurrency 16 was clean; it began refusing above that. [...]
```

Opt-in (real traffic, ~1 min). Levels 8–256, four rounds per worker, stops at first loss.
Holds connections across rounds, harsher than most scans: the cleared level is a floor.

Loss against 64 unroutable targets × 4 ports:

| proxy | c=16 | c=24 | c=32 | c=48 | c=64 | c=256 | c=512 |
|---|---|---|---|---|---|---|---|
| microsocks | 0% | — | 0% | — | 0% | 0% | 0% |
| `ssh -D` | 0% | — | 0% | — | 0% | 0% | 0% |
| 3proxy, default `maxconn 100` | 0% | 0% | 7% | 37% | 48% | 95% | 80% |
| 3proxy, `maxconn 2000` | 0% | — | 0% | — | 0% | 0% | 0% |

Raise the proxy's cap rather than lower concurrency. A burst does not predict this:
3proxy accepts 64 held connections yet loses 48% of a churning scan at 64, since closed
connections linger in its table.

## HTTP CONNECT

`type = "http"`, same keys as `socks5`; credentials become `Proxy-Authorization: Basic`
(base64, cleartext — the same protection as RFC 1929). Hostnames are handed to the proxy
unresolved.

HTTP standardises no status meaning "the destination refused", so an HTTP proxy is
`open_only` by construction: `2xx` is open, `407` and `403` are named, every other
status is `error` carrying the status line. `fidelity` is not declared on an http
transport (`full` is refused). Measured, raw status lines:

| proxy | known-open | refused destination | unroutable destination | tells them apart |
|---|---|---|---|---|
| squid 7.6 | `HTTP/1.1 200 Connection established` | `503 Service Unavailable`, `X-Squid-Error: ERR_CONNECT_FAIL 111` | `503`, `X-Squid-Error: ERR_CONNECT_FAIL 110` (with `connect_timeout 2 seconds`; no reply under the 60 s default) | only in a private header |
| tinyproxy 1.11.2 | `200 Connection established` | `500 Unable to connect` | `500 Unable to connect` | no |
| 3proxy 0.9.7 | `HTTP/1.0 200 Connection established` | `502 Bad Gateway` | `502 Bad Gateway` | no |

squid's `X-Squid-Error` carries the errno (`111` ECONNREFUSED, `110` ETIMEDOUT) and could
support `full` fidelity for squid alone; not implemented, since it is one vendor's
private header.

```console
$ scanr transport test corp
transport corp (http 127.0.0.1:3128)
  reachable         yes
  known-open        open      status 200         0.5ms
  known-closed      error     status 503         0.4ms   <- expected closed
  blackholed        error     status 503      2815.2ms   <- expected filtered

  fidelity          open_only
```

## Chains

```toml
[transports.bastion]
type = "socks5"
address = "10.0.0.1:1080"

[transports.inner]
type = "socks5"
address = "192.168.50.1:1080"

[transports.deep]
type = "chain"
hops = ["bastion", "inner"]     # traversed left to right
```

- Hops must be `socks5` or `http` (`direct` has nothing to CONNECT through) and may mix;
  each has its own credentials.
- Fidelity: the exit hop's, measured end to end. An intermediate CONNECT either succeeds
  or fails the chain as `error`; the exit's reply travels back untouched. Measured: squid
  → 3proxy SOCKS5 is `full`, dante → tinyproxy is `open_only`. Record it on the exit
  hop, not the chain.
- Failures name the link; the record stores every hop:

```
hop 1 (10.0.0.1:1080) refused to reach hop 2 (192.168.50.1:1080): reply 0x02
```

## Pools

```toml
[transports.spread]
type = "pool"
members = ["exit-a", "exit-b", "exit-c"]
```

- Ephemeral ports are per four-tuple: distinct proxy addresses multiply the ~470/s
  ceiling roughly linearly, and each member brings its own connection cap.
- Deterministic: an endpoint hashes to a member, the same on every run. Result field
  `via` names it:

```console
$ scanr output results --states open --format json rec.jsonl.gz | jq -r .via
exit-a
exit-c
```

- Not failover: a down member fails its share; reproducibility is the protected property.
- Fidelity: weakest member's. `transport test` refuses pools; test members individually.
- Members must be proxies; `direct` is rejected.

## Authentication

RFC 1929 username/password (`socks5`) and Basic (`http`): cleartext, encrypt nothing.

```toml
[transports.lab]
type = "socks5"
address = "10.1.1.1:1080"
username = "scanner"
password_env = "SCANR_LAB_PASSWORD"
```

Inline passwords are rejected — see [security](security.md#credentials).

## `ssh -D`

Use the `ssh` profiles. OpenSSH 10.2p1, 4,000 probes: 80 s under `proxy-careful`, 0.16 s
under `ssh`, all probes reported either way.

```console
scanr run --transport tunnel --profile ssh        # typical internet link
scanr run --transport tunnel --profile ssh-fast   # nearby server, low latency
scanr run --transport tunnel --profile ssh-slow   # high-latency or congested
```

- **Local listener.** `127.0.0.1` is exempt under `tcp_tw_reuse = 2`, so the ~470/s
  ceiling behind `proxy`'s `rate = 400` does not apply; the 80 s is exactly 4,000 probes
  at `proxy-careful`'s 50/s (10 s at 400/s). `ssh` profiles set `rate = 0`.
- **Free local round trip.** Negotiation 0.4–0.5 ms; a refused destination also returns
  in 0.4 ms. Only silent hosts cost `connect_timeout`, so the `ssh` profiles keep local
  timeouts short and spend the budget on the destination leg.
- **Concurrency cliff.** One TCP connection carries every channel. Flat ~28,500 probes/s
  from 32 to 128, collapse at 160 (three runs per level):

| concurrency | 32 | 64 | 96 | 128 | 160 | 256 | 512 |
|---|---|---|---|---|---|---|---|
| probes/s | 28,571 | 28,571 | 28,571 | 25,000 | 1,852 | 1,869 | 1,770 |

The cliff is a fixed ~1 s stall (at 160, 2,000 / 4,000 / 8,000 probes all ~1.1 s).
`ssh-fast` 64, `ssh` 96, `ssh-slow` 128, all under it (test-enforced); concurrency rises
with latency since in-flight ≈ rate × RTT.

`open_only` still applies.
