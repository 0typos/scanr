# Performance tuning

Every number here was measured on the development machine (64 cores, `RLIMIT_NOFILE`
1,048,576) against local fixtures. Treat them as shapes to expect, not guarantees.

## Start by finding what is actually limiting you

`scanr plan` projects the run and reports the host conditions that bound it:

```
concurrency     512                                     builtin.proxy
rate            400/s                                   builtin.proxy
projection      ~10m39s at 400/s
host            ephemeral 32768-60999 (28232 ports), tcp_tw_reuse=2 (loopback only), nofile=1048576
```

In rough order of how often each is the real constraint:

1. **The proxy's connection cap** — usually first, and usually invisible until measured.
2. **Timeouts against unresponsive hosts** — a `/24` of silent hosts costs
   `connect_timeout` per probe divided by concurrency.
3. **Local ephemeral ports** — only for a remote proxy, and largely mitigated (below).
4. **`scanr` itself** — rarely. It sustained ~128,000 probes/s against loopback.

## `SO_LINGER`: the single biggest factor

Probe sockets are closed with `SO_LINGER{on,0}`, sending RST instead of FIN and skipping
`TIME_WAIT`. This is not tunable and not optional; it is measured as a **7.5× sustained
throughput multiplier**:

| | probes/s | TIME_WAIT sockets after 5s |
|---|---|---|
| without | 9,189 | 21,931 |
| with | 68,949 | 1 |

Against a 28,232-port ephemeral range, the no-linger path was on course to exhaust local
ports in about seven seconds. The cost is that some proxies log RSTs as errors, and it is
marginally more detectable.

## The ephemeral port ceiling

With one proxy per scan every probe connects to the *same* socket address, so only the
source port varies. Default range 28,232 ports, `TIME_WAIT` hardcoded at 60s:

```
28232 / 60 ≈ 470 probes/sec sustained
```

`tcp_tw_reuse = 2` is the modern default and exempts **loopback only** — a local proxy
escapes this, a remote one does not. `SO_LINGER` lifts it substantially either way. If you
still hit it:

```console
sysctl -w net.ipv4.ip_local_port_range="10000 65535"   # 55,536 ports
sysctl -w net.ipv4.tcp_tw_reuse=1                       # also non-loopback
```

## Concurrency

**Concurrency is the worker thread count.** There is no queue, so it is a hard ceiling
rather than a target.

Higher is not monotonically better. Measured against a local listener:

| threads | probes/s | RSS |
|---|---|---|
| 512 | 68,949 | ~13 MB |
| 2,048 | 62,805 | ~43 MB |

Thread cost is low — 64 KiB stacks, 40.6 MB resident at 5,000 threads and 81 MB at
10,000, with spawn costing ~227 ms once at 10,000 — so the limit is contention and the
destination, not the threads.

**Above about 10,000 the design runs out.** If you need more, the architecture would have
to change; see [`design/02-runtime-evaluation.md`](design/02-runtime-evaluation.md).

For a proxied scan, measure the proxy instead of guessing:

```console
scanr transport test lab --calibrate
```

## Rate limiting

`rate` caps launches per second; `0` disables it. Use it when you do not own the proxy or
the network, not to improve throughput.

`concurrency` and `rate` constrain the same quantity from different directions, and by
Little's law an unreachable combination is easy to write: 2,000/s with a 1s timeout needs
2,000 in flight, so `concurrency = 512` makes the rate unreachable against silent hosts.
`plan` projects the duration so the binding constraint is visible.

## Timeouts

| profile | connect | for |
|---|---|---|
| `direct-fast` | 1s | LAN, latency known low |
| `direct` | 2s | routed networks |
| `proxy` | 5s | self-hosted proxy |
| `proxy-careful` | 8s | rotating pools, `ssh -D`, unknown limits |

Through a proxy the destination timeout covers *the proxy's* attempt to reach the
destination, so it needs to exceed the round trip to the proxy plus whatever the proxy
allows. Per-phase timings in the record show where the time actually went:

```console
jq -r 'select(.type=="probe_result") | .timing_ms' scan-*.jsonl | head
```

Shortening `connect_timeout` is the most effective lever on a scan dominated by silent
hosts, at the cost of false negatives on slow ones. `retries = 1` (the default, timeouts
only) partly compensates.

## glibc versus musl

| build | probes/s | RSS |
|---|---|---|
| glibc | ~128,000 | 12.4 MB |
| static musl | ~75,000 | 8.7 MB |

musl is ~1.7× slower on a loopback microbenchmark, and this is almost certainly irrelevant
to you: 75,000 probes/s is far above what any proxied scan reaches, and the gap only
appears where neither the network nor a proxy is the bottleneck. musl also uses less
memory. Prefer glibc when you control the host, musl when portability matters.

## File descriptors

One per in-flight probe. `plan` warns when `concurrency` approaches `RLIMIT_NOFILE`:

```console
ulimit -n 65536
```

## Output

The writer is not usually a factor: results go through a bounded channel to a single
buffered writer, flushed on lifecycle events and every 250 ms. If it ever were, workers
block on the channel rather than dropping results.

Records are larger than people expect, because every probe outcome is kept. Measured:

| scan | probes | record | rate |
|---|---|---|---|
| 1 host × all 65,535 ports | 65,535 | 24 MB | ~156,000/s |
| /16 × 16 ports | 1,048,576 | 377 MB | ~15,200/s |

About 377 bytes per probe. Extrapolating, a 10M-probe scan is roughly 3.9 GB.

The lines are highly repetitive and compress **16.8×** — that 377 MB record gzips to
23.6 MB in 1.5 s. Built-in compression is deferred rather than rejected; if you are
routinely scanning at this scale, piping through `gzip` afterwards is worth it.

Memory is stable across a run: the million-probe scan held 17 MB resident from start to
finish, the growth over the 5.8 MB baseline being the materialized target list.

## Things that will not help

- **More concurrency against a capped proxy.** It makes the loss worse; 3proxy at its
  default cap went from 7% loss at 32 to 48% at 64.
- **Adaptive tuning.** Deliberately absent. Clear limits with good diagnostics beat hidden
  automatic behaviour, and adaptive changes make a record hard to interpret afterwards.
- **Raising concurrency past ~512** on most workloads, per the measurements above.
