# JSONL Event Specification

`schema_version = 1`. One JSON object per line, UTF-8, LF-terminated.

## File naming

```
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz   # default
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl      # --no-compress
```

`scan_id` is 8 lowercase hex characters (32 bits from `getrandom`). Epoch milliseconds
sort lexicographically within the same digit count and are readable enough to grep.
Nanoseconds were rejected as false precision — the clock source does not justify them
and it lengthens every filename.

Written as `.jsonl.partial`, renamed on terminal event (D-register / architecture).
A file still named `.partial` means the process died without finalizing.

## Event types

Seven, trimmed from the thirteen in the original brief.

| Event | Count | Purpose |
|---|---|---|
| `scan_started` | exactly 1, first | Identity and provenance of the run |
| `scan_config` | exactly 1, second | Fully resolved configuration |
| `probe_span` | 0..n, before the terminal | Many probes that shared one outcome |
| `target_resolved` | 0..n | Emitted only when DNS actually resolved something |
| `probe_result` | 1 per uncollapsed probe | The results |
| `scan_progress` | 0..n | Periodic counters |
| `scan_warning` | 0..n | Non-fatal operational conditions |
| `scan_completed` \| `scan_interrupted` \| `scan_failed` | exactly 1, last | Terminal |

**Dropped and why.** `scan_plan` — folded into `scan_config`; two events describing the
same immutable object invites divergence. `scan_error` — non-fatal errors are
`scan_warning`, fatal ones are `scan_failed`. `scan_interrupt_requested` — a
`requested_at` field on `scan_interrupted` carries the same information without a second
write during shutdown, which is exactly when writes are least reliable.

Per-probe *start* events are not emitted. At 5,000 concurrent they would double file
size to record something derivable.

Every event carries `type`, `seq`, `ts` (RFC 3339, ms precision), and `scan_id`.
`seq` is assigned by the writer thread and is monotonic in **write** order, which is not
probe order — probes are randomized (D16) and complete concurrently.

## `scan_started`

`git_commit` carries a `-dirty` suffix when the working tree had uncommitted changes,
and is `unknown` when built from a source tree with no `.git` (a packaged release). The
same information is available from `scanr --version`.

```json
{"type":"scan_started","seq":0,"ts":"2026-07-29T14:31:44.201Z","scan_id":"a3f19c02",
 "schema_version":1,"tool_version":"0.1.0","git_commit":"9e27d4cda",
 "rustc":"rustc 1.97.1 (8bab26f4f 2026-07-14)",
 "target_triple":"x86_64-unknown-linux-musl","started_at_epoch_ms":1785294704201,
 "hostname":"scanner-01","pid":48812}
```

## `scan_config`

The fully resolved plan, credentials redacted, each field tagged with provenance.

```json
{"type":"scan_config","seq":1,"ts":"...","scan_id":"a3f19c02",
 "scan_name":"internal-web","profile":"proxy","resumed_from":null,
 "targets":{"spec":["10.20.30.0/24"],"exclude":["10.20.30.1"],"count":255,
            "expanded":false},
 "ports":{"spec":["80","443","8000-8999"],"count":1002},
 "probes_planned":255510,
 "permutation":{"algorithm":"feistel4","seed":"9f2c00a1b4de7731"},
 "transport":{"name":"lab","type":"socks5","address":"127.0.0.1:1080",
              "username":"scanner","password":"[redacted]",
              "password_source":"env:SCANR_LAB_PASSWORD",
              "measured_fidelity":"open_only","fidelity_source":"config"},
 "dns":{"requested":"auto","effective":"transport"},
 "timing":{"concurrency":512,"rate":400,"proxy_connect_timeout_ms":3000,
           "handshake_timeout_ms":5000,"connect_timeout_ms":5000,
           "retries":1,"retry_delay_ms":250},
 "output":{"dir":"./scanr-results","open_only":true},
 "provenance":{"concurrency":"profile.proxy","connect_timeout_ms":"cli",
               "transport":"scan.internal-web","rate":"builtin.proxy"},
 "host":{"ephemeral_range":[32768,60999],"tcp_tw_reuse":2,"rlimit_nofile":1048576,
         "so_linger_zero":true}}
```

**The expanded target set is never embedded.** A /16 × 1000 ports is 65M probes; the
canonical *spec* plus counts is what makes the scan reproducible, and the permutation
seed makes the order reproducible too. `expanded: false` states this explicitly.

### `resumed_from`

The `scan_id` this scan continues, or `null` for a scan that continues nothing.

A scan interrupted and then resumed produces two records. Without this field nothing
connects them, and the record — the whole point of which is to answer what happened —
cannot answer it across the join. Chasing `resumed_from` back through records
reconstructs a scan split across any number of interruptions.

It is populated without the user having to do anything: `scanr output remainder` emits a
leading `# resumed-from: <scan-id>` comment, and `--pairs` reads it.

```console
$ scanr output remainder scan-...-a7b012c0.jsonl
# resumed-from: a7b012c0
192.0.2.0:80
192.0.2.0:443
```

```console
$ scanr output remainder old.jsonl | scanr run --pairs -   # link carried by the pipe
```

Every other consumer ignores it, because it is a comment in a list that already strips
them. `--resumed-from <scan-id>` sets it by hand for a list that has been edited or
reassembled, and takes precedence over the directive. Concatenating two remainders keeps
the first origin: there is no single right answer, and preferring the last would be no
better a guess.

`transport.fidelity_source` is present for every transport type and is one of:

| value | meaning |
|---|---|
| `builtin` | direct transport; the local stack distinguishes states inherently |
| `config` | declared in configuration from a `scanr transport test` measurement |
| `unmeasured` | a proxy whose fidelity has not been measured — results may be degraded |

The `host` block records the conditions that bound throughput (D9), so a slow scan can
be explained months later.

## `target_resolved`

Only when local DNS ran. Absent entirely under `dns = "transport"`, which is itself the
signal that the proxy resolved.

```json
{"type":"target_resolved","seq":2,"ts":"...","scan_id":"a3f19c02",
 "target":"app.internal","addresses":["10.20.30.40","10.20.30.41"],
 "mode":"local","expanded_to_probes":true}
```

## `probe_result`

One per host:port, retries merged (D10).

```json
{"type":"probe_result","seq":118,"ts":"...","scan_id":"a3f19c02","probe_index":90412,
 "target":"10.20.30.40","resolved_address":"10.20.30.40","port":443,"protocol":"tcp",
 "state":"open","source":"proxy_reply","service_label":"https",
 "attempts":2,"attempt_states":["timed_out","open"],
 "timing_ms":{"proxy_connect":1.8,"handshake":12.4,"connect":21.4,"total":35.6}}
```

- `state` ∈ `open` · `closed` · `filtered` · `error` (D7).
- `source` ∈ `local_stack` · `proxy_reply` · `timeout` — where the classification came
  from. Through a proxy that collapses failures to `0x01`, non-open results carry
  `state: "error"` with `reason`, not a fabricated `closed`.
- `resolved_address` is `null` for hostname targets under transport DNS — the SOCKS5
  reply's `BND.ADDR` is the proxy's bound address, not the destination's (D15).
- `service_label` is an IANA port-number lookup and is documented as **a guess from the
  port number, not a fingerprint**.
- Timing phases are separate because through a proxy a single latency number is
  misleading.

## `scan_progress`

Every `progress_interval` (default 5s), TTY or not — it is cheap and useful in logs.

```json
{"type":"scan_progress","seq":900,"ts":"...","scan_id":"a3f19c02",
 "completed":41002,"planned":255510,"in_flight":512,"open":38,
 "rate_1s":396.2,"eta_s":540}
```

## `scan_warning`

```json
{"type":"scan_warning","seq":204,"ts":"...","scan_id":"a3f19c02",
 "code":"ephemeral_pressure","message":"local ephemeral ports exhausted",
 "detail":{"remediation":"the local ephemeral port range (28232 ports) is exhausted.\n..."}}
```

Codes are owned by `diag::WARNING_CODES` and a test asserts this list matches it, so
the two cannot drift. An earlier version of this section listed `fidelity_degraded`,
`dns_mode_changed`, and `slow_writer`, none of which the code could ever emit.

Emitted before probing starts, from plan resolution:

| code | meaning |
|---|---|
| `dns_failure` | a hostname target did not resolve and will not be probed |
| `dns_mode_auto` | `auto` resolved to a specific mode; switching transports would change it |
| `fidelity_unknown` | proxy fidelity has not been measured; run `transport test` |
| `fidelity_open_only` | proxy cannot distinguish closed from filtered |
| `ephemeral_budget` | configured rate exceeds the sustained ephemeral-port ceiling |
| `fd_budget` | concurrency exceeds `RLIMIT_NOFILE` |

Emitted during the scan, at most once each, carrying host-specific remediation under
`detail.remediation`:

| code | meaning |
|---|---|
| `ephemeral_pressure` | source ports actually ran out mid-scan |
| `fd_pressure` | descriptors actually ran out mid-scan |
| `proxy_saturation` | the proxy stopped accepting connections |

The runtime three are rate-limited to one per code per scan: a saturated host would
otherwise emit one warning per failing probe.

Emitted immediately before the terminal event, and unlike the rest a report of a scanr
bug rather than an environmental condition:

| code | meaning |
|---|---|
| `worker_panic` | one or more scan workers terminated abnormally; results are incomplete |

## `probe_span`

Written by default; `--no-spans` (or `spans = false`) suppresses them. Each one stands
for many probes that shared an outcome, in place of one `probe_result` row each.

```json
{"type":"probe_span","seq":41,"ts":"...","scan_id":"a3f19c02",
 "state":"filtered","source":"timeout","reason":"connect timed out","protocol":"tcp",
 "attempts":2,"count":1048575,"probe_indices":[[0,523],[525,1048575]],
 "timing_ms":{"min":300.1,"mean":300.4,"max":300.9}}
```

`probe_indices` are **inclusive ranges over `probe_index`**, sorted and disjoint. That
index is the target-major position in the planned matrix, so a consumer expands a span
with arithmetic and the specs already in `scan_config`:

```
target = targets[probe_index / ports.count]
port   = ports[probe_index % ports.count]
```

The permutation decides only the order probes are *visited*, never this mapping, so the
seed is not needed to expand a span.

That form applies to a matrix scan. When `targets.mode` is `"pairs"` — which is what a
resumed scan writes — `probe_index` indexes the embedded `targets.pairs` list directly:

```
endpoint = targets.pairs[probe_index]
```

The permutation decides only the order probes are *visited*, never either mapping, so the
seed is not needed to expand a span.

**What is kept:** exactly which endpoints got which outcome, `attempts`, aggregate
timing, and the three-bucket accounting — a collapsed probe still counts as `completed`.
`output remainder` expands spans, so resuming works identically either way.

**What is lost:** the per-probe `ts`, and exact per-probe timing. That is the trade;
`--no-spans` declines it.

Spans are drained on the progress cadence rather than held to the end, and flushed as
critical events. Held in memory they would be lost outright by a killed process, where a
streamed `probe_result` was not — so a `.partial` record retains the probes its spans
stood for, bounded by one progress interval.

**What is never collapsed:** `open` (the result the scan exists to find), `error`
(something that needs reading), any probe that hit resource pressure, and any probe whose
retry *disagreed* with its first attempt — a flapping host is not interchangeable with its
neighbours. A retry that agreed is collapsed, because `["filtered","filtered"]` says
nothing the state does not; excluding those would collapse nothing at all in a scan of
silent hosts, since `retries = 1` is the default.

Above 64 distinct `(state, source, reason, attempts)` classes the record is not
repetitive enough for spans to pay, and every probe keeps its own row from that point.

`output verify` checks each span: `state` and `source` defined, ranges sorted, disjoint,
inside `probes_planned`, and summing to `count`; `min <= mean <= max`.

## Terminal events

Exactly one, last. Nothing may follow it.

```json
{"type":"scan_completed","seq":255514,"ts":"...","scan_id":"a3f19c02",
 "termination":"natural","graceful":true,
 "counts":{"planned":255510,"started":255510,"completed":255510,"not_started":0,
           "cancelled":0,"open":38,"closed":1204,"filtered":254210,"error":58},
 "duration_ms":641200,"exit_code":0}
```

`counts` places every planned probe in exactly one of three buckets, and
`planned == completed + abandoned + not_started` is checked by `output verify`:

* `completed` — reported a result
* `abandoned` — a worker picked it up but an interrupt ended the drain first, so it may
  have touched the network and must not be assumed untried
* `not_started` — never issued to a worker

`scan_interrupted` adds `signal:"SIGINT"`, `requested_at`, `forced`, and non-zero
`abandoned`/`not_started`. `scan_failed` adds `error` and `error_code`. All three flush immediately.

If the writer itself fails, one attempt is made to emit `scan_failed` with
`error_code: "writer_failure"`; if that also fails the file stays `.partial`, which is
the correct signal. A write failure on *any* event type sets this, not only on
`probe_result`.

If a scan worker panics, the terminal event is `scan_failed` with
`error_code: "worker_panic"` and a `worker_panics` count. Workers unwind rather than
abort (D1) so that a crash cannot take the writer with it and lose the record — but a
crashed worker still means the results are incomplete, so it can never be reported as a
natural completion. The probes it was holding are accounted for as `abandoned`.

## `scanr output verify` checks

**Structure.** Valid JSON per line · consistent `scan_id` · strictly increasing `seq` ·
`scan_started` first and `scan_config` second · exactly one terminal event, last ·
nothing after it · `counts` internally consistent and matching observed `probe_result`
rows · supported `schema_version` · no unredacted credential-shaped values · `.partial`
suffix reported as abrupt termination.

**Values.** Every event's `ts` readable as RFC 3339; and for each `probe_result`:
`port` within 1–65535 · `state` and `source` among the values defined above ·
`protocol` is `tcp` · `attempts` at least 1 and matching the length of `attempt_states`
· each `attempt_states` entry a defined state · `probe_index` below `probes_planned` ·
`timing_ms` present, numeric, non-negative, and carrying `total`.

Structure being right is not the same as the record being true: a row carrying
`"port": 65616` satisfies every structural rule above, and `output remainder` would then
narrow it to 80 and drop a genuinely unprobed endpoint from the resume set. Value
problems are aggregated by kind rather than listed per row, so a systematically corrupt
record reports one line per defect and not one per probe.

## Stability

`schema_version` 1 is additive-stable in both directions that matter: new optional
fields may appear on existing events, **and new event types may appear**. Existing fields
will not change type or meaning, existing fields will not be removed, and an existing
event type will not be renamed. Any of those requires a version bump.

Consumers must therefore ignore unknown fields *and* unknown event types, and must not
treat any single event type as covering every probe — `probe_span` does not, and it is
the default.

The totals live in the terminal event's `counts`, which `output verify` reconciles
against the rows and spans actually present. That reconciliation is what makes `counts`
safe to trust and line-counting unsafe.

Adding `probe_span` under version 1 is deliberate and is the reason this clause is
explicit. The narrower promise — new *fields* only — was written before spans existed and
would have licensed a consumer to count `probe_result` lines and believe the total.
