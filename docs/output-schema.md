# Scan record schema

Consumer-facing reference for the JSONL file every run produces. For the design rationale
see [`design/05-jsonl-spec.md`](design/05-jsonl-spec.md).

## Stability

`schema_version` is `1`, and within it the format is **additive-stable**. Concretely,
what will not change without a version bump:

- an existing field will not change type or meaning
- an existing field will not be removed
- an event type that exists will not be renamed

And what may change within version 1:

- **new optional fields** may appear on any event
- **new event types** may appear

So a consumer must dispatch on `type` and ignore both unknown fields and unknown event
types. It must **not** assume any one event type accounts for every probe — `probe_span`
already breaks that assumption, and it is on by default.

**The terminal event's `counts` are the authority on totals**, not the number of lines of
any given type. `scanr output verify` reconciles the two and fails if they disagree, so
if you need "how many probes were there", read `counts`.

This is a wider promise than the one this document made before spans existed, which
covered only new *fields*. That wording would have let a consumer count `probe_result`
lines and believe it had them all.

`scanr` itself is `0.x` — see the note in `CHANGELOG.md`. Schema feedback is explicitly
wanted before `1.0` hardens this into a semver commitment.

## File

```
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz     # default
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl        # with --no-compress
```

Records are gzip by default. It is written as concatenated gzip **members**, so `zcat`,
`zless` and `gzip -d` read it normally and a killed scan still decodes up to its last
completed frame. Every `scanr output` command reads either form without being told which.

`.partial` is appended while running and dropped once a terminal event is written. **A
file still named `.partial` means the process died without finalizing** — the results in
it are valid but incomplete.

One JSON object per line, UTF-8, LF-terminated. Every line carries `type`, `seq`, `ts`
(RFC 3339, ms) and `scan_id`.

`seq` is monotonic in **write** order, which is not probe order: probes are randomized and
complete concurrently.

## Guaranteed structure

`scanr output verify` checks all of this:

1. `scan_started` first, `scan_config` second.
2. Exactly one terminal event (`scan_completed` / `scan_interrupted` / `scan_failed`),
   last, with nothing after it.
3. `seq` strictly increasing, one `scan_id` throughout.
4. `planned == completed + abandoned + not_started`.
5. `completed == open + closed + filtered + error`.
6. No unredacted credentials.

## Events

| type | count | purpose |
|---|---|---|
| `scan_started` | 1, first | identity and build provenance |
| `scan_config` | 1, second | fully resolved configuration |
| `target_resolved` | 0..n | only when local DNS ran |
| `probe_result` | 1 per uncollapsed probe | the results |
| `probe_span` | 0..n | many probes that shared one outcome |
| `scan_progress` | 0..n | periodic counters |
| `scan_warning` | 0..n | non-fatal conditions |
| terminal | 1, last | outcome and counts |

There is no per-probe *start* event. At high concurrency it would double file size to
record something derivable.

## `probe_result`

The one you will mostly consume.

```json
{"type":"probe_result","seq":118,"ts":"2026-07-30T12:42:16.049Z","scan_id":"a3f19c02",
 "probe_index":90412,"target":"10.20.30.40","resolved_address":"10.20.30.40",
 "port":443,"protocol":"tcp","state":"open","source":"proxy_reply","reason":null,
 "service_label":"https","attempts":2,"attempt_states":["filtered","open"],
 "timing_ms":{"proxy_connect":1.8,"handshake":12.4,"connect":21.4,"total":35.6}}
```

| field | notes |
|---|---|
| `state` | `open` · `closed` · `filtered` · `error` |
| `source` | `local_stack` · `proxy_reply` · `timeout` · `internal` — **where the verdict came from** |
| `reason` | free text when not open; `null` when open |
| `resolved_address` | `null` for hostname targets under transport DNS |
| `service_label` | a guess from the port number, **not a fingerprint**; `null` if unknown |
| `attempts` | retries are merged into one row (timeouts only) |
| `attempt_states` | per-attempt states, so the merge loses nothing |
| `timing_ms` | `proxy_connect` and `handshake` absent on the direct path |

`scan_config.transport.fidelity_source` says where the fidelity claim came from:
`builtin` (direct, where the local stack separates states inherently), `config` (declared
from a `transport test` measurement), or `unmeasured`.

**Read `source` before trusting a non-open `state`.** Through a proxy that cannot
distinguish refused from filtered, non-open results are `error` with
`source: "proxy_reply"` rather than a fabricated verdict. `transport.measured_fidelity` in
`scan_config` tells you which situation you are in.

**By default, `probe_result` does not cover every probe.** Runs of identical
`closed`/`filtered` outcomes are collapsed into `probe_span` events, so counting
`probe_result` lines under-reports. Either handle both event types, or scan with
`--no-spans` for one row per probe.

`open` and `error` results are never collapsed, nor is anything that hit resource
pressure or whose retry disagreed with its first attempt — so if you only care about
what was found, `probe_result` is still the whole answer.

## `probe_span`

Stands for many probes that shared an outcome.

```json
{"type":"probe_span","seq":41,"ts":"2026-07-31T12:42:16.049Z","scan_id":"a3f19c02",
 "state":"filtered","source":"timeout","reason":"connect timed out","protocol":"tcp",
 "attempts":2,"count":1048575,"probe_indices":[[0,523],[525,1048575]],
 "timing_ms":{"min":300.1,"mean":300.4,"max":300.9}}
```

`probe_indices` are inclusive, sorted, disjoint ranges over `probe_index`, which is the
target-major position in the planned matrix:

```
target = targets[probe_index / ports.count]
port   = ports[probe_index % ports.count]
```

The permutation seed affects only the order probes were *visited*, never that mapping, so
expanding a span needs nothing but `scan_config`.

That form applies to a matrix scan. When `targets.mode` is `"pairs"` — which is what a
resumed scan writes — `probe_index` indexes the embedded `targets.pairs` list directly:

```
endpoint = targets.pairs[probe_index]
```

The permutation decides only the order probes are *visited*, never either mapping, so the
seed is not needed to expand a span.

A collapsed probe still counts as `completed` in the terminal event, and
`scanr output remainder` expands spans, so resuming works the same either way. What you
lose is the per-probe `ts` and exact per-probe timing — the span keeps min/mean/max.

## `scan_warning`

Non-fatal conditions, each with a stable `code`. Worth filtering on: several of them mean
the results are less trustworthy than they look.

Emitted before probing, from plan resolution:

| code | meaning |
|---|---|
| `dns_failure` | a hostname did not resolve and will not be probed |
| `dns_mode_auto` | `auto` resolved to a specific mode; switching transports would change it |
| `fidelity_unknown` | proxy fidelity has not been measured |
| `fidelity_open_only` | the proxy cannot distinguish closed from filtered |
| `ephemeral_budget` | configured rate exceeds the sustainable ephemeral-port ceiling |
| `fd_budget` | concurrency exceeds `RLIMIT_NOFILE` |

Emitted during the scan, at most once each, with `detail.remediation`:

| code | meaning |
|---|---|
| `ephemeral_pressure` | source ports actually ran out mid-scan |
| `fd_pressure` | descriptors actually ran out mid-scan |
| `proxy_saturation` | the proxy stopped accepting connections |

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="scan_warning") | "\(.code)\t\(.message)"'
```

Seeing `fidelity_open_only`, `proxy_saturation`, or either `*_pressure` code means some
non-open results describe the scanning environment rather than the target.

## Terminal event

```json
{"type":"scan_completed","seq":255514,"termination":"natural","graceful":true,
 "duration_ms":641200,"exit_code":0,
 "counts":{"planned":255510,"started":255510,"completed":255510,"abandoned":0,
           "not_started":0,"open":38,"closed":1204,"filtered":254210,"error":58,
           "retried":0}}
```

Three buckets, summing to `planned`:

- `completed` — reported a result
- `abandoned` — a worker picked it up but an interrupt ended the drain first, so it **may
  have touched the network**; do not treat these as untried
- `not_started` — never issued

`scan_interrupted` adds `signal`, `requested_at`, `forced`. `scan_failed` adds `error` and
`error_code`.

## Reading a record without `jq`

`output summarize` arranges the open ports for you. The default is one line per endpoint;
`--by` regroups them:

```console
$ scanr output summarize scan-*.jsonl.gz --by host
open ports by host (3 hosts):
  10.0.0.2         22/ssh  80/http
  10.0.0.9         80/http
  10.0.0.10        22/ssh

$ scanr output summarize scan-*.jsonl.gz --by port
open ports by port (2 distinct):
  22/ssh              2  10.0.0.2  10.0.0.10
  80/http             2  10.0.0.2  10.0.0.9
```

`--by host` answers "what is this machine running", `--by port` and `--by service`
answer "who is running this" — the latter keyed on the service label rather than the
number, so `http` gathers 80 and 8080 together. `--by port` and `--by service` list the
commonest first, which is usually the question on a sweep.

Only **open** results are grouped. That is the shape of the record rather than a
limitation: `open` is never collapsed into a span, so it is the one state guaranteed to
have a row per probe. Totals for the other states come from the terminal event's
`counts`, which `summarize` already prints.

## Recipes

Open ports, as `host:port`:

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open") | "\(.target):\(.port)"'
```

Only verdicts you can trust as `closed`:

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="closed" and .source=="local_stack")
       | "\(.target):\(.port)"'
```

Did it finish, and what settings produced it?

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.counts)
       | "\(.type) \(.termination) \(.counts.completed)/\(.counts.planned)"'
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="scan_config") | .timing, .transport, .permutation'
```

Diff two scans for ports that changed:

```console
for f in old.jsonl.gz new.jsonl.gz; do
  zcat -f "$f" | jq -r 'select(.type=="probe_result") | "\(.target):\(.port) \(.state)"' \
    | sort > "$f.st"
done
diff old.jsonl.gz.st new.jsonl.gz.st
```

Which build produced this record:

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="scan_started") | "\(.tool_version) \(.git_commit) \(.target_triple)"'
```

Slowest responders:

```console
zcat -f scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open")
       | [.timing_ms.total, "\(.target):\(.port)"] | @tsv' | sort -rn | head
```

## Reproducing a scan

`scan_config` records the **canonical unexpanded** target spec plus counts, never the
expanded matrix — a /16 × 1000 ports is 65M probes. With the recorded permutation seed
that is enough to reproduce the scan exactly:

```console
cfg() { zcat -f scan-*.jsonl.gz | jq -r "select(.type==\"scan_config\")|$1"; }
scanr run --targets "$(cfg '.targets.spec[]')" \
          --ports   "$(cfg '.ports.spec')" \
          --seed    "$(cfg '.permutation.seed')"
```

`provenance` records which configuration layer supplied each value, so a record explains
not just what ran but why.

## Resuming an interrupted scan

`output remainder` emits the endpoints that were never reported, as exact `host:port`
lines, which `run --pairs` consumes:

```console
scanr output remainder scan-*.jsonl.gz | scanr run --pairs -
```

This probes precisely what is outstanding — not whole targets — so a target whose first
two ports completed resumes with only its remaining ports.

`abandoned` probes are included in the remainder. They were issued to a worker but never
reported, so whether they reached the network is unknown and re-probing is the safe
choice.

### The two records stay connected

A resumed scan writes its own record, and that record names the one it continues:

```console
$ scanr output remainder scan-...-a7b012c0.jsonl | head -3
# resumed-from: a7b012c0
192.0.2.0:80
192.0.2.0:443

$ jq -r 'select(.type=="scan_config") | .resumed_from' scan-...-441e1980.jsonl
a7b012c0
```

The link travels through the pipe on its own — the leading comment is provenance, not an
endpoint, and `--pairs` reads it. `scanr output verify` prints it back:

```
  terminal: scan_completed
  resumed from scan a7b012c0
```

Without this a scan split across an interruption would leave two files that only a human
memory connects, which is a poor answer from a tool whose point is the record. If you
have edited or reassembled a list and want to state its origin yourself, pass
`--resumed-from <scan-id>`; it wins over the directive.

A pair scan records `targets.mode = "pairs"` and embeds its endpoint list, since an
explicit list has no compact spec. Above 50,000 pairs the list is omitted and
`pairs_truncated` is set; `remainder` then refuses rather than returning a wrong answer.
