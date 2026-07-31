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
| `direct-fast` | 300ms x2 | LAN, round trip known under ~100ms |
| `direct` | 2s | routed networks |
| `proxy` | 5s | self-hosted proxy |
| `proxy-careful` | 8s | rotating pools, unknown limits |
| `ssh-fast` | 2s | `ssh -D` to a nearby server |
| `ssh` | 6s | `ssh -D` over a typical internet link |
| `ssh-slow` | 15s | `ssh -D` over a high-latency or congested link |

Through a proxy the destination timeout covers *the proxy's* attempt to reach the
destination, so it needs to exceed the round trip to the proxy plus whatever the proxy
allows. Per-phase timings in the record show where the time actually went:

```console
# open and error results, which always keep their own row
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="probe_result") | .timing_ms' | head

# the collapsed bulk, summarised per outcome class
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="probe_span") | {state, count, timing_ms}'

# or scan with --no-spans for a per-probe timing on every result
```

Shortening `connect_timeout` is the most effective lever on a scan dominated by silent
hosts, at the cost of false negatives on slow ones.

**Do not take it below a second without a retry.** TCP's initial retransmission timeout
is about one second (RFC 6298), so a single attempt with a shorter budget gives up before
the first SYN retransmit — one dropped packet, routine on wifi, silently becomes
`filtered`. A retry is a *fresh* SYN rather than a longer wait, which is the cheaper way
to survive that: `direct-fast` is 300ms twice, measured at 9.22s against the 13.13s of
the 1s-once it replaced, with two independent chances instead of one. A test enforces
that no built-in profile pairs a sub-second timeout with `retries = 0`.

That still assumes a LAN. On a path whose round trip genuinely exceeds 300ms both
attempts fail and the host is reported `filtered`, which is why `direct` stays at 2s.

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

### Collapsing repetitive outcomes

Most of a large record is the same answer written a million times. `--spans` replaces
runs of identical `closed`/`filtered` outcomes with one event each. Measured on the
`/16 × 16 ports` scan above:

| | record | events | scan wall |
|---|---|---|---|
| full | 391,618,401 B | 1,048,580 | 5.73 s |
| `--spans` | **2,582 B** | 5 | 5.59 s |
| `--spans --compress` | 1,595 B | 5 | 5.53 s |

That is **151,000×**, and it costs nothing — the scan is marginally *faster* for writing
less. Both records answer identically: `output verify` reports the same conclusion and
`output remainder` the same 0 of 1,048,576. Verify drops from 1.91 s to instant.

The catch is that it only pays when results are uniform. A varied network collapses far
less, and above 64 distinct outcome classes it stops collapsing entirely and every probe
keeps its row.

**What you give up** is the per-probe timestamp and exact per-probe timing for collapsed
results — the span keeps min/mean/max. `open` and `error` results always keep their own
row, as does anything that hit resource pressure or whose retry disagreed with its first
attempt. So the results you are likely to actually read are untouched; what collapses is
the "nothing there" bulk.

On by default. `--no-spans` keeps one row per probe:

```toml
[defaults]
spans = false
```

The lines are also highly repetitive, which `--compress` exploits:

```console
scanr run --targets 10.0.0.0/16 --ports web --compress
```

Measured **20–23×** on real records, at about 0.04 s per 12 MB — so a 374 MB record
becomes roughly 17 MB and the compression is free next to the scan. The file is named
`.jsonl.gz` and `zcat`, `zless`, `gzip -d` and `scanr output` all read it unchanged.

It is written as a sequence of gzip **frames**, not one stream, so a scan that is killed
still decodes up to its last completed frame — the same guarantee the `.partial` suffix
carries for an uncompressed record. A single-stream gzip would be unreadable past its
start, which would mean paying for compression exactly when you could least afford to.

On by default. `--no-compress` writes plain JSONL when you want to grep the file
directly, or:

```toml
[defaults]
compress = false
```

The compressor is pure Rust — `flate2` on the `rust_backend` (`miniz_oxide`) — so the
dependency tree contains no C and the fully static musl build is unaffected.

**On zstd.** Measured against gzip on one genuine 12 MB record:

| | ratio | time |
|---|---|---|
| gzip -6 | 20.1× | 0.04 s |
| zstd -3 | 18.0× | 0.01 s |
| zstd -9 | 22.4× | 0.06 s |
| zstd -19 | 26.1× | 4.29 s |

At comparable speed zstd buys about 11%. The mainstream `zstd` crate binds a vendored C
library, and a musl-targeting C toolchain would destroy the static build (D19). Pure-Rust
zstd encoders now exist but are young and little-used; a compressor defect in a forensic
record tool means unreadable evidence, so 11% is not the trade to take on an immature
implementation. Revisit when one is widely deployed.

Writing one is not the answer either: a competitive zstd encoder is FSE and Huffman
entropy coding, match finding, sequence encoding and frame handling — a long correctness
tail for 11%. The same effort spent collapsing homogeneous outcomes into span events
would be worth orders of magnitude more on the scans where size actually hurts.

Memory is stable across a run: the million-probe scan held 17 MB resident from start to
finish, the growth over the 5.8 MB baseline being the materialized target list.

Reading a record back is also bounded, which took a fix to become true. `output`
streams, so it does not matter how large the file is:

| command | peak resident on the 374 MB record |
|---|---|
| `output summarize` | 2.7 MB |
| `output verify` | 3.1 MB |
| `output remainder` | 96 MB |

`remainder` is the outlier because it must hold the set of endpoints already probed in
order to subtract it — that set is the question being asked. The other two retain
nothing but their counters, the config event, and, for `summarize`, the open ports it is
about to print.

Before this was fixed, all three loaded the whole record into memory first and needed
**4.2 GB** for that 374 MB file — about 11× the file size. The tool could write a
million-probe record on a laptop and then fail to read it back.

## How it compares to nmap

A `/24` × nmap's top 100 ports — 25,600 probes — with both tools doing unprivileged TCP
connect scans, so the technique is identical. nmap 7.92, `-sT -T5 --min-rate 10000
--max-retries 0 -Pn -n`.

**Responsive hosts** (`127.0.0.0/24`, every port refused):

| | wall | probes/s |
|---|---|---|
| scanr, default `direct` profile | **0.17 s** | 150,000 |
| nmap `-T5` | 0.52 s | 49,000 |

Both reported exactly the same 259 open ports. Six scanr runs spaced 2 s apart were
0.17–0.18 s; run them back to back with no gap and one landed at 1.19 s, which is
teardown pressure from the previous run rather than the scan itself.

**Unresponsive hosts** (`192.0.2.0/24`, every probe times out) — here the comparison is
really about timeouts, so it is worth being careful:

| | wall |
|---|---|
| scanr `--profile direct-fast` (1 s timeout) | 13.10 s |
| nmap `-T5` | 7.16 s |
| scanr `--connect-timeout 300ms --concurrency 4096` | **2.23 s** |
| scanr `--connect-timeout 150ms --concurrency 4096` | 1.18 s |

nmap wins on the first line and it is not mysterious: `-T5` caps `max-rtt-timeout` at
300 ms, while `direct-fast` waits a full second. Told to give up as fast as nmap does,
scanr is **3.2× faster** — the same ratio as the responsive case. Neither tool reported
anything open, which is correct for TEST-NET.

The real difference is that **nmap adapts its timeout from observed round-trip times and
scanr does not**. That is a deliberate choice — see "Adaptive tuning" under
*Things that will not help* below — and it has a real cost — on an unfamiliar network nmap self-tunes and
scanr needs you to set `--connect-timeout`. `scanr plan` projects the duration so the
consequence is visible before you spend it.

Caveats worth stating: this is loopback and TEST-NET on one machine, so it measures the
tools rather than a network. As root, nmap's `-sS` SYN scan is a different and faster
technique that scanr does not implement. And scanr is writing a complete JSONL record
throughout, which nmap is not.

## Things that will not help

- **More concurrency against a capped proxy.** It makes the loss worse; 3proxy at its
  default cap went from 7% loss at 32 to 48% at 64.
- **Adaptive tuning.** Deliberately absent. Clear limits with good diagnostics beat hidden
  automatic behaviour, and adaptive changes make a record hard to interpret afterwards.
- **Raising concurrency past ~512** on most workloads, per the measurements above.
