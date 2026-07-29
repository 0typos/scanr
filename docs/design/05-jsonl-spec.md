# JSONL Event Specification

`schema_version = 1`. One JSON object per line, UTF-8, LF-terminated.

## File naming

```
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl
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
| `target_resolved` | 0..n | Emitted only when DNS actually resolved something |
| `probe_result` | 1 per host:port | The results |
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

```json
{"type":"scan_started","seq":0,"ts":"2026-07-29T14:31:44.201Z","scan_id":"a3f19c02",
 "schema_version":1,"tool_version":"0.1.0","git_commit":"e4a1b9c","rustc":"1.97.1",
 "target_triple":"x86_64-unknown-linux-musl","started_at_epoch_ms":1785294704201,
 "hostname":"scanner-01","pid":48812}
```

## `scan_config`

The fully resolved plan, credentials redacted, each field tagged with provenance.

```json
{"type":"scan_config","seq":1,"ts":"...","scan_id":"a3f19c02",
 "scan_name":"internal-web","profile":"proxy",
 "targets":{"spec":["10.20.30.0/24"],"exclude":["10.20.30.1"],"count":255,
            "expanded":false},
 "ports":{"spec":["80","443","8000-8999"],"count":1002},
 "probes_planned":255510,
 "permutation":{"algorithm":"feistel4","seed":"9f2c00a1b4de7731"},
 "transport":{"name":"lab","type":"socks5","address":"127.0.0.1:1080",
              "username":"scanner","password":"[redacted]",
              "password_source":"env:SCANR_LAB_PASSWORD",
              "measured_fidelity":"open_only","fidelity_measured_at":"..."},
 "dns":{"requested":"auto","effective":"transport"},
 "timing":{"concurrency":512,"rate":400,"proxy_connect_timeout_ms":3000,
           "handshake_timeout_ms":5000,"connect_timeout_ms":5000,
           "retries":1,"retry_delay_ms":250},
 "provenance":{"concurrency":"profile.proxy","connect_timeout_ms":"cli",
               "transport":"scan.internal-web","rate":"builtin.proxy"},
 "host":{"ephemeral_range":[32768,60999],"tcp_tw_reuse":2,"rlimit_nofile":1048576,
         "so_linger_zero":true}}
```

**The expanded target set is never embedded.** A /16 × 1000 ports is 65M probes; the
canonical *spec* plus counts is what makes the scan reproducible, and the permutation
seed makes the order reproducible too. `expanded: false` states this explicitly.

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
 "code":"ephemeral_pressure","message":"source port allocation failures detected",
 "detail":{"failures":17,"remediation":"lower rate, or set net.ipv4.tcp_tw_reuse=1"}}
```

Codes: `ephemeral_pressure` · `fd_pressure` · `proxy_saturation` ·
`fidelity_degraded` · `dns_mode_changed` · `slow_writer`.

## Terminal events

Exactly one, last. Nothing may follow it.

```json
{"type":"scan_completed","seq":255514,"ts":"...","scan_id":"a3f19c02",
 "termination":"natural","graceful":true,
 "counts":{"planned":255510,"started":255510,"completed":255510,"not_started":0,
           "cancelled":0,"open":38,"closed":1204,"filtered":254210,"error":58},
 "duration_ms":641200,"exit_code":0}
```

`scan_interrupted` adds `signal:"SIGINT"`, `requested_at`, `drain_ms`, and non-zero
`not_started`. `scan_failed` adds `error` and `error_code`. All three flush immediately.

If the writer itself fails, one attempt is made to emit `scan_failed` with
`error_code: "writer_failure"`; if that also fails the file stays `.partial`, which is
the correct signal.

## `scanr output verify` checks

Valid JSON per line · consistent `scan_id` · strictly increasing `seq` · `scan_started`
first and `scan_config` second · exactly one terminal event, last · nothing after it ·
`counts` internally consistent and matching observed `probe_result` rows · supported
`schema_version` · no unredacted credential-shaped values · `.partial` suffix reported
as abrupt termination.

## Stability

`schema_version` 1 is additive-stable: new optional fields may appear; existing fields
will not change type or meaning. Consumers must ignore unknown fields. Removing or
retyping a field requires a major bump.
