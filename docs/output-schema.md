# Scan record schema

Consumer-facing reference for the JSONL file every run produces. For the design rationale
see [`design/05-jsonl-spec.md`](design/05-jsonl-spec.md).

## Stability

`schema_version` is `1`, and within it the format is **additive-stable**: new optional
fields may appear, existing fields will not change type or meaning. Consumers must ignore
unknown fields.

`scanr` itself is `0.x` — see the note in `CHANGELOG.md`. Schema feedback is explicitly
wanted before `1.0` hardens this into a semver commitment.

## File

```
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl
```

`.jsonl.partial` while running, renamed once a terminal event is written. **A file still
named `.partial` means the process died without finalizing** — the results in it are valid
but incomplete.

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
| `probe_result` | 1 per host:port | the results |
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

**Read `source` before trusting a non-open `state`.** Through a proxy that cannot
distinguish refused from filtered, non-open results are `error` with
`source: "proxy_reply"` rather than a fabricated verdict. `transport.measured_fidelity` in
`scan_config` tells you which situation you are in.

Row count equals probe count, so `wc -l` on `probe_result` lines is meaningful.

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

## Recipes

Open ports, as `host:port`:

```console
jq -r 'select(.type=="probe_result" and .state=="open") | "\(.target):\(.port)"' scan-*.jsonl
```

Only verdicts you can trust as `closed`:

```console
jq -r 'select(.type=="probe_result" and .state=="closed" and .source=="local_stack")
       | "\(.target):\(.port)"' scan-*.jsonl
```

Did it finish, and what settings produced it?

```console
jq -r 'select(.type|startswith("scan_")) | select(.type|endswith("ed") or endswith("ted"))
       | "\(.type) \(.termination) \(.counts.completed)/\(.counts.planned)"' scan-*.jsonl
jq -r 'select(.type=="scan_config") | .timing, .transport, .permutation' scan-*.jsonl
```

Diff two scans for ports that changed:

```console
for f in old.jsonl new.jsonl; do
  jq -r 'select(.type=="probe_result") | "\(.target):\(.port) \(.state)"' "$f" | sort > "$f.st"
done
diff old.jsonl.st new.jsonl.st
```

Which build produced this record:

```console
jq -r 'select(.type=="scan_started") | "\(.tool_version) \(.git_commit) \(.target_triple)"' scan-*.jsonl
```

Slowest responders:

```console
jq -r 'select(.type=="probe_result" and .state=="open")
       | [.timing_ms.total, "\(.target):\(.port)"] | @tsv' scan-*.jsonl | sort -rn | head
```

## Reproducing a scan

`scan_config` records the **canonical unexpanded** target spec plus counts, never the
expanded matrix — a /16 × 1000 ports is 65M probes. With the recorded permutation seed
that is enough to reproduce the scan exactly:

```console
scanr run --targets "$(jq -r 'select(.type=="scan_config")|.targets.spec[]' scan-*.jsonl)" \
          --ports "$(jq -r 'select(.type=="scan_config")|.ports.spec' scan-*.jsonl)" \
          --seed "$(jq -r 'select(.type=="scan_config")|.permutation.seed' scan-*.jsonl)"
```

`provenance` records which configuration layer supplied each value, so a record explains
not just what ran but why.
