# Performance tuning

Measured on one machine (64 cores, `RLIMIT_NOFILE` 1,048,576) against local fixtures:
shapes, not guarantees.

## The binding limit

`scanr plan` projects the run and the host conditions bounding it:

```
concurrency     512                                     builtin.proxy
rate            400/s                                   builtin.proxy
projection      ~10m39s at 400/s
host            ephemeral 32768-60999 (28232 ports), tcp_tw_reuse=2 (loopback only), nofile=1048576
```

| constraint (most common first) | notes |
|---|---|
| proxy connection cap | invisible until measured: `scanr transport test <name> --calibrate` |
| timeouts against silent hosts | a silent `/24` costs `connect_timeout` per probe ÷ concurrency |
| local ephemeral ports | remote proxy only; largely mitigated by `SO_LINGER` |
| scanr itself | rarely: ~128,000 probes/s against loopback |

## `SO_LINGER`

Probe sockets close with `SO_LINGER{on,0}` (RST, no `TIME_WAIT`). Not tunable. 7.5×
sustained throughput:

| | probes/s | TIME_WAIT sockets after 5s |
|---|---|---|
| without | 9,189 | 21,931 |
| with | 68,949 | 1 |

Without it a 28,232-port range exhausts in ~7 s. Cost: some proxies log RSTs as errors;
marginally more detectable.

## Ephemeral port ceiling

One proxy per scan means only the source port varies. Default 28,232 ports, `TIME_WAIT`
hardcoded 60 s:

```
28232 / 60 ≈ 470 probes/sec sustained
```

`tcp_tw_reuse = 2` (modern default) exempts loopback only: a local proxy escapes, a
remote one does not. If `SO_LINGER` is not enough:

```console
sysctl -w net.ipv4.ip_local_port_range="10000 65535"   # 55,536 ports
sysctl -w net.ipv4.tcp_tw_reuse=1                       # also non-loopback
```

## Concurrency

Worker thread count; no queue, so a hard ceiling. Not monotonic (local listener):

| threads | probes/s | RSS |
|---|---|---|
| 512 | 68,949 | ~13 MB |
| 2,048 | 62,805 | ~43 MB |

Threads are cheap (64 KiB stacks; 40.6 MB resident at 5,000, 81 MB at 10,000, ~227 ms
one-off spawn at 10,000): contention and the destination limit first. Above ~10,000 the
design runs out — [`design/decisions.md`](design/decisions.md), D1. For a proxy:
`scanr transport test lab --calibrate`.

## Rate limiting

`rate` caps launches/s; `0` disables. For proxies and networks not under your control,
not for throughput. `concurrency` and `rate` bound the same quantity (Little's law):
2,000/s at a 1 s timeout needs 2,000 in flight, unreachable at `concurrency = 512`
against silent hosts. `plan` projects the duration.

## Timeouts

| profile | connect | for |
|---|---|---|
| `direct-fast` | 300ms x2 | LAN, round trip known under ~100ms |
| `direct` | 2s | routed networks |
| `proxy` | 5s | self-hosted proxy |
| `proxy-careful` | 8s | rotating pools, unknown limits |
| `ssh-fast` | 2s | `ssh -D` to a nearby server |
| `ssh` | 6s | `ssh -D` over a typical internet link |
| `ssh-slow` | 15s | `ssh -D` over a high-latency or congested link |

Through a proxy, `connect_timeout` covers the proxy's attempt at the destination: proxy
round trip plus whatever the proxy allows. Per-phase timings:

```console
# open and error results, which always keep their own row
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result") | .timing_ms' | head

# the collapsed bulk, per outcome class
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_span") | {state, count, timing_ms}'

# or scan with --no-spans for a per-probe timing on every result
```

Shortening `connect_timeout` is the main lever against silent hosts (false negatives on
slow ones). Below 1 s needs a retry: TCP's initial RTO is ~1 s (RFC 6298), so one shorter
attempt gives up before the first SYN retransmit and a dropped packet becomes `filtered`.
`direct-fast` (300 ms × 2) measured 9.22 s against 13.13 s for 1 s × 1. No built-in
profile pairs a sub-second timeout with `retries = 0` (test-enforced). Past 300 ms RTT
both attempts fail, hence `direct` at 2 s.

## glibc versus musl

| build | probes/s | RSS |
|---|---|---|
| glibc | ~128,000 | 12.4 MB |
| static musl | ~75,000 | 8.7 MB |

musl ~1.7× slower on loopback (irrelevant to any proxied scan), less memory. glibc when
the host is controlled, musl for portability.

## File descriptors

One per in-flight probe. `plan` warns when `concurrency` approaches `RLIMIT_NOFILE`:

```console
ulimit -n 65536
```

## Output

Bounded channel to one buffered writer, flushed on lifecycle events and every 250 ms;
workers block rather than drop. Every outcome is kept:

| scan | probes | record | rate |
|---|---|---|---|
| 1 host × all 65,535 ports | 65,535 | 24 MB | ~156,000/s |
| /16 × 16 ports | 1,048,576 | 377 MB | ~15,200/s |

~377 bytes/probe; 10M probes ≈ 3.9 GB.

### Spans

`--spans` (default) collapses runs of identical `closed`/`filtered` outcomes into one
event each. On the `/16 × 16 ports` scan:

| | record | events | scan wall |
|---|---|---|---|
| full | 391,618,401 B | 1,048,580 | 5.73 s |
| `--spans` | 2,582 B | 5 | 5.59 s |
| `--spans --compress` | 1,595 B | 5 | 5.53 s |

151,000× at no cost; `output verify` and `output remainder` (0 of 1,048,576) answer
identically, verify dropping from 1.91 s to instant. Above 64 distinct outcome classes
collapsing stops. Collapsed results lose per-probe timestamp and exact timing (span
keeps min/mean/max); `open`, `error`, resource-pressure and retry-disagreement results
always keep their row. `--no-spans`, or:

```toml
[defaults]
spans = false
```

### Compression

`--compress` (default) writes `.jsonl.gz`; `zcat`, `zless`, `gzip -d` and `scanr output`
read it unchanged:

```console
scanr run --targets 10.0.0.0/16 --ports web --compress
```

20–23× on real records at ~0.04 s per 12 MB (374 MB → ~17 MB). Gzip frames, not one
stream: a killed scan decodes to its last completed frame, as `.partial` guarantees for
plain JSONL. Pure Rust (`flate2`, `rust_backend`/`miniz_oxide`): static musl unaffected.
`--no-compress`, or:

```toml
[defaults]
compress = false
```

zstd versus gzip on one 12 MB record:

| | ratio | time |
|---|---|---|
| gzip -6 | 20.1× | 0.04 s |
| zstd -3 | 18.0× | 0.01 s |
| zstd -9 | 22.4× | 0.06 s |
| zstd -19 | 26.1× | 4.29 s |

~11% at comparable speed. The `zstd` crate vendors C, breaking static musl (D19);
pure-Rust encoders are immature, and a compressor defect in a forensic record is
unreadable evidence. Revisit when one is widely deployed.

### Memory

Stable: the million-probe scan held 17 MB resident throughout (5.8 MB baseline plus the
target list). `output` streams; peak resident on the 374 MB record:

| command | peak | holds |
|---|---|---|
| `output verify` | 3.1 MB | counters and the config event |
| `output events` | negligible | decompressing pipe |
| `output summarize` | follows scan shape | per-host and per-port counters (/16 × 1,000 ports: 65,536 host + ≤65,535 port entries), open ports at two bytes each; `--format json` builds only requested sections (`--by port --format json` skips the host array) |
| `output results` | matching rows | unfiltered is the whole scan; `events` streams |
| `output remainder` | 96 MB | the set of endpoints already probed |

## Versus nmap

`/24` × nmap's top 100 ports, 25,600 probes, both unprivileged TCP connect. nmap 7.92,
`-sT -T5 --min-rate 10000 --max-retries 0 -Pn -n`.

Responsive (`127.0.0.0/24`, every port refused):

| | wall | probes/s |
|---|---|---|
| scanr, default `direct` profile | 0.17 s | 150,000 |
| nmap `-T5` | 0.52 s | 49,000 |

Identical 259 open ports. Six scanr runs 2 s apart: 0.17–0.18 s; back to back, one hit
1.19 s (teardown pressure from the previous run).

Unresponsive (`192.0.2.0/24`, every probe times out):

| | wall |
|---|---|
| scanr `--profile direct-fast` (300ms, twice) | 9.22 s |
| nmap `-T5` | 7.16 s |
| scanr `--connect-timeout 300ms --concurrency 4096`, single attempt | 2.23 s |
| scanr `--connect-timeout 150ms --concurrency 4096`, single attempt | 1.18 s |

nmap wins line one because `--max-retries 0` is one attempt and `direct-fast` makes two
([Timeouts](#timeouts)); on equal terms scanr is 3.2× faster, the same ratio as the
responsive case. Neither reported anything open.

nmap adapts its timeout from observed RTT; scanr does not (below): on an unfamiliar
network set `--connect-timeout` by hand and let `scanr plan` show the consequence.

Caveats: loopback and TEST-NET on one machine measure the tools, not a network; nmap's
root `-sS` is a different, faster technique scanr lacks; scanr writes a full JSONL
record throughout.

## What will not help

- More concurrency against a capped proxy: 3proxy at default cap went from 7% loss at
  32 to 48% at 64.
- Adaptive tuning: deliberately absent. Clear limits and diagnostics beat hidden
  behaviour that also makes a record hard to interpret afterwards.
- Concurrency past ~512 on most workloads.
