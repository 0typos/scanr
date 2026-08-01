# Scan record schema

Reference for the JSONL file every run produces. This is the normative description of the
format — tests check the running code against this page, so what it says is what you get.

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

Every event carries `type`, `seq`, `ts` (RFC 3339, millisecond precision) and `scan_id`.
`seq` is assigned by the writer and is monotonic in **write** order, which is not probe
order — probes are randomized and complete concurrently.

### Dropped and why

Three event types were specified at one point and deliberately do not exist, so a
consumer written against an early draft is not waiting for them:

| type | why not |
|---|---|
| `scan_plan` | folded into `scan_config`; two events describing the same immutable object invites divergence |
| `scan_error` | non-fatal errors are `scan_warning`, fatal ones are the `scan_failed` terminal |
| `scan_interrupt_requested` | `scan_interrupted` carries `requested_at`, which says the same thing without a second write during shutdown — exactly when writes are least reliable |

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
| `service_label` | a guess from the port number, **not a fingerprint**; `null` if unknown. Layered — see below |
| `via` | which pool member produced this result; absent unless the transport was a pool |
| `banner` | what the service volunteered, when `--banner` is on and it said anything. Absent otherwise |
| `banner_hex` | the same bytes in hex, used instead of `banner` when they are not valid UTF-8 |
| `banner_bytes` | how many bytes were read |
| `attempts` | retries are merged into one row (timeouts only) |
| `attempt_states` | per-attempt states, so the merge loses nothing |
| `timing_ms` | `proxy_connect` and `handshake` absent on the direct path |

### Banners

Banners are read by default: what an open service volunteers on connect is recorded.
**Nothing is sent** — the
`scan_config` event records `banner.sent_bytes: 0` to say so — which is what keeps
"scanr connected and listened" a true description of the scan.

Only services that greet first say anything: SSH, SMTP, FTP, POP3, IMAP, MySQL, Telnet.
HTTP does not, and neither does anything behind TLS. **An absent `banner` means the
service said nothing unprompted, never that nothing is there.**

The bytes are recorded as sent. Valid UTF-8 goes in `banner`, where JSON escaping renders
control characters inertly (`\u001b`); anything else goes in `banner_hex`. Nothing is
normalised away, because a record that quietly replaced bytes would be evidence of
nothing.

> **Do not print a banner straight to a terminal.** The bytes are chosen by the scanned
> host, and a terminal acts on what it is given — `ESC [ 2J` clears the screen, `ESC ] 0 ;`
> rewrites the window title. `scanr` renders banners as printable ASCII only, replacing
> everything else with `.`; anything consuming the record should do the same.

`timeout_ms` is the ceiling. The wait scales off each host's measured connect time — a
greeting arrives about a round trip after the connection is established — so a fast host
is not waited on for half a second. `scan_config.banner` records the settings the scan
ran with:

```json
{"banner": {"enabled": true, "sent_bytes": 0, "max_bytes": 1024, "timeout_ms": 500}}
```

### Where `service_label` comes from

Three layers, most specific first: a file named by `defaults.services_file`, then
`/etc/services` if the host has one, then a compiled-in table of 59 well-known ports.
The first layer with an answer wins, so a two-line custom file still inherits the rest.

None of them is a fingerprint. Nothing connects to the service or reads a banner — the
port answered, and a table says what usually sits on that number. Port 4444 is `krb524`
to all three layers and is essentially never Kerberos. Key automation on `state`,
`source` and `reason`, which are unaffected by any of this.

Because `/etc/services` differs between machines, so can the labels. `scan_config`
therefore records exactly which layers produced them:

```json
{"service_labels": {
  "layers": [
    {"source": "/home/me/.config/scanr/services", "entries": 12,   "malformed": 0},
    {"source": "/etc/services",                   "entries": 5862, "malformed": 0},
    {"source": "builtin",                         "entries": 2,    "malformed": 0}
  ],
  "use_etc_services": true
}}
```

`entries` counts the tcp ports that layer was the first to claim, so the rows sum to the
number of ports the table can answer for, with no port counted twice. Note what that
means for the builtin row: it holds 59 ports but reports only those no file above it
claimed, and a stock Linux `/etc/services` names 57 of them. A small number there is the
normal case, not a sign that something is missing — it is the count of ports the builtin
is still the answer for. `malformed`
counts lines the parser gave up on; UDP and SCTP rows are skipped without being counted,
since roughly half of a real `/etc/services` is UDP. A layer that contributed nothing is
absent; `builtin` is always last and always present.

`use_etc_services` is `false` only when the config declined the host layer. A machine
that simply has no `/etc/services` still reports `true`, and the layer's absence from
the list says the rest — the two cases are otherwise indistinguishable.

Two records that label a port differently can be reconciled from this field alone.

`scan_config.transport.fidelity_source` says where the fidelity claim came from:
`builtin` (direct, where the local stack separates states inherently), `config` (declared
from a `transport test` measurement), `unmeasured`, `weakest_hop` (a chain, which can only
claim what its least capable hop can) or `weakest_member` (a pool). A chain or pool whose
underlying proxies were never measured reports `measured_fidelity: "unknown"` alongside
the derived source, so "nothing was measured" is still visible.

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

```json
{"type":"scan_warning","seq":204,"ts":"2026-07-31T12:00:04.100Z","scan_id":"a3f19c02",
 "code":"ephemeral_pressure","message":"local ephemeral ports exhausted",
 "detail":{"remediation":"the local ephemeral port range (28232 ports) is exhausted"}}
```

Emitted during the scan, at most once each, with `detail.remediation`. Rate-limited to
one per code per scan, or a saturated host would emit one warning per failing probe:

| code | meaning |
|---|---|
| `ephemeral_pressure` | source ports actually ran out mid-scan |
| `fd_pressure` | descriptors actually ran out mid-scan |
| `proxy_saturation` | the proxy stopped accepting connections |

Emitted just before the terminal event, and unlike the rest a report of a `scanr` bug
rather than an environmental condition:

| code | meaning |
|---|---|
| `worker_panic` | a scan worker died; the probes it held were abandoned and the results are incomplete |

The codes are owned by `diag::WARNING_CODES` and a test asserts this list matches it, so
the two cannot drift. An earlier version listed `fidelity_degraded`, `dns_mode_changed`
and `slow_writer`, none of which the code could ever emit — which is why the test now
also checks the reverse direction.

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_warning") | "\(.code)\t\(.message)"'
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

`output summarize` aggregates the whole record: totals, then counts per host, per
network, and per service. With no `--by` you get every section, which is the right first
look at a record you have not seen.

```console
$ scanr output summarize scan-*.jsonl.gz
  scan            internal-web
  started         2026-08-01T09:14:02.117Z  (scanr 0.1.0)
  transport       lab via socks5 (full)
  scope           3 targets x 3 ports = 9 probes
  seed            9f2c00a1b4de7731
  result          scan_completed (natural)
  duration        0.98s
  states          4 open, 2 closed, 3 filtered, 0 error

by host (3 hosts):
  host               open closed filtered  error  open ports
  10.0.0.2              2      0        1      0  22/ssh 80/http
  10.0.0.9              1      1        1      0  80/http
  10.0.0.10             1      1        1      0  22/ssh

by network (1 network):
  network              hosts  with-open   open filtered
  10.0.0.0/24              3          3      4        3

by port (3 ports):
  port     service            open closed filtered  error
  22       ssh                   2      1        0      0
  80       http                  2      1        0      0
  445      microsoft-ds          0      0        3      0

by service (3 services):
  service            open closed filtered  error  ports
  http                  2      1        0      0  80
  ssh                   2      1        0      0  22
  microsoft-ds          0      0        3      0  445
```

`--by host`, `--by network`, `--by port`, `--by service` or `--by scan` narrows to one
section. `--json` emits the same aggregates as one object, for anything that wants to
compare two scans.

Every state is counted, not just `open` — which is the point. Port 445 above was never
open on any host and is still reported, because "445 was filtered on every host" is
usually the finding. Ports and services are ranked by open, then filtered, so what
answered comes first.

Getting those counts means expanding spans, so `summarize` sees every probe even though
most have no row of their own.

Networks are fixed `/24` (IPv6 `/64`) buckets rather than your target specs: specs can
overlap or nest, so there is no single network a host belongs to, and fixed buckets are
what let two records be compared.

The unnarrowed view caps each section at 25 rows and says what it left out — a /16 has
65,536 hosts. `--by <section>` shows that section in full. Counting streams into
counters, so a summary costs hosts plus ports rather than probes.

Two things are reported rather than hidden. A result whose port the record states as out
of range is counted in a `note` line and left out of the tables, instead of vanishing
and leaving the totals unsupported. A state that is none of the four is counted
separately rather than as `error`, so the tables cannot contradict the totals above
them.

## Looking up results

`output results` filters the record, and — unlike `jq` over `probe_result` — it expands
spans, so a collapsed `closed` is still findable:

```console
$ scanr output results scan-*.jsonl.gz --states open
10.0.0.2:8080/tcp   open      local_stack  http-proxy
10.0.0.3:8080/tcp   open      local_stack  http-proxy
2 result(s)

$ scanr output results scan-*.jsonl.gz --hosts 10.0.0.0/24 --ports 22,443 --states closed,filtered
$ scanr output results scan-*.jsonl.gz --states open --format json | jq -r .target
```

| flag | accepts |
|---|---|
| `--hosts` | IPs, CIDR blocks, ranges, hostnames — the same forms as `--targets`, repeatable |
| `--ports` | `80`, `1-1024`, lists — the same forms as `--ports` |
| `--states` | `open`, `closed`, `filtered`, `error`, comma-separated |
| `--json` | JSON Lines instead of the table |

Omit a flag and it matches everything. An unknown state is an error rather than a query
that silently matches nothing.

Host filters match **without expanding**, so `--hosts 10.0.0.0/8` costs nothing.

States are coloured when stdout is a terminal — the same palette `run` uses, so `open`
looks the same wherever you see it. Redirect or pipe the output and it is plain text;
`--no-color` and `NO_COLOR` turn it off explicitly. `--json` is never coloured, and
neither is `output events`: both are data, and an escape sequence in them would be a bug.

Results reconstructed from a span carry `"collapsed": true` in JSON output and have no
`timing_ms` — the span keeps only aggregate timing, and inventing a per-probe number
would be worse than omitting it. The count goes to stderr, so stdout stays pipe-clean.

## Recipes

`scanr output events` writes the record as plain JSONL whichever format it is in, so these
work unchanged on a compressed or uncompressed record and on any platform. `zcat -f`
does the same on GNU systems, but its pass-through of uncompressed input is a GNU
extension and macOS ships BSD gzip — hence the built-in.


Open ports, as `host:port`:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open") | "\(.target):\(.port)"'
```

Only verdicts you can trust as `closed`:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="closed" and .source=="local_stack")
       | "\(.target):\(.port)"'
```

Did it finish, and what settings produced it?

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.counts)
       | "\(.type) \(.termination) \(.counts.completed)/\(.counts.planned)"'
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_config") | .timing, .transport, .permutation'
```

Diff two scans for ports that changed:

```console
for f in old.jsonl.gz new.jsonl.gz; do
  scanr output events "$f" | jq -r 'select(.type=="probe_result") | "\(.target):\(.port) \(.state)"' \
    | sort > "$f.st"
done
diff old.jsonl.gz.st new.jsonl.gz.st
```

Which build produced this record:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_started") | "\(.tool_version) \(.git_commit) \(.target_triple)"'
```

Slowest responders:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open")
       | [.timing_ms.total, "\(.target):\(.port)"] | @tsv' | sort -rn | head
```

## Reproducing a scan

`scan_config` records the **canonical unexpanded** target spec plus counts, never the
expanded matrix — a /16 × 1000 ports is 65M probes. With the recorded permutation seed
that is enough to reproduce the scan exactly:

```console
cfg() { scanr output events scan-*.jsonl.gz | jq -r "select(.type==\"scan_config\")|$1"; }
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
