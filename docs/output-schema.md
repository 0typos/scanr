# Scan record schema

Normative reference for the JSONL record every run writes; tests check the binary against it.

## Stability

Within a major version of scanr the record is additive-stable: new optional fields and new
event types may appear; existing fields keep their type and meaning and are not removed;
`state` and `source` are closed sets. Consumers dispatch on `type`, ignore unknown types
and fields, and read totals from the terminal event's `counts`. Widening a closed set or
changing any existing field's meaning bumps `schema_version`, and a `schema_version` bump
is a major version of scanr. This build writes version 2 and reads 1 and 2.

| field | set | closed |
|---|---|---|
| `state` | `open`, `closed`, `filtered`, `error` | yes |
| `source` | `local_stack`, `proxy_reply`, `timeout`, `internal` | yes |
| `transport.type` | `direct`, `socks5`, `http`, `chain`, `pool` | no |
| `fidelity`, `measured_fidelity` | `full`, `open_only`, `unknown` | no |
| `fidelity_source` | [Fidelity](#fidelity) | no |
| `scan_warning.code` | [`scan_warning`](#scan_warning) | no |
| terminal `error_code` | [Terminal event](#terminal-event) | no |

Open sets need a default branch. Never total by counting lines of one type:
`probe_span` (default on) collapses probes, and `scanr output verify` fails a record
whose `counts` disagree with its lines.

| version | change |
|---|---|
| 2 | `probe_span.probe_indices` in counter space; version 1 used matrix space — see [`probe_span`](#probe_span) |
| 1 | initial |

Reading never drops a version. An unknown version is refused, not guessed (a version 1
reader given version 2 spans expands them to wrong endpoints with nothing looking
malformed); `verify` names the accepted versions.

## File

```
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl.gz     # default
scanr-results/scan-<epoch_ms>-<scan_id>.jsonl        # --no-compress
```

- gzip as concatenated members: `zcat`, `zless`, `gzip -d` work; a killed scan decodes
  to its last frame. `scanr output` reads either form.
- `.partial` suffix until the terminal event; if it remains, the process died — contents
  valid, incomplete.
- One object per line, UTF-8, LF. Every line: `type`, `seq`, `ts` (RFC 3339, ms), `scan_id`.
- `seq` is write order, not probe order.

## Guaranteed structure

Checked by `scanr output verify`:

1. `scan_started` first, `scan_config` second.
2. One terminal event (`scan_completed` / `scan_interrupted` / `scan_failed`), last.
3. `seq` strictly increasing; one `scan_id`.
4. `planned == completed + abandoned + not_started`.
5. `completed == open + closed + filtered + error`.
6. No unredacted credentials.

## Events

| type | count | purpose |
|---|---|---|
| `scan_started` | 1, first | identity, build provenance |
| `scan_config` | 1, second | resolved configuration |
| `target_resolved` | 0..n | only when local DNS ran |
| `probe_result` | 1 per uncollapsed probe | results |
| `probe_span` | 0..n | probes sharing one outcome |
| `scan_progress` | 0..n | periodic counters |
| `scan_warning` | 0..n | non-fatal conditions |
| `scan_completed` / `scan_interrupted` / `scan_failed` | 1, last | outcome, counts |

No per-probe start event: derivable, and it would double file size.

### Dropped and why

| type | why not |
|---|---|
| `scan_plan` | folded into `scan_config` |
| `scan_error` | non-fatal is `scan_warning`, fatal is `scan_failed` |
| `scan_interrupt_requested` | `scan_interrupted.requested_at`, with no write during shutdown |

## `probe_result`

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
| `source` | `local_stack` · `proxy_reply` · `timeout` · `internal`: where the verdict came from |
| `reason` | free text; `null` when open |
| `resolved_address` | `null` for hostnames under transport DNS |
| `service_label` | port-number guess, not a fingerprint; `null` if unknown |
| `via` | pool member; only under a pool |
| `banner` | bytes volunteered; absent if none or `--banner` off |
| `banner_hex` | replaces `banner` when not valid UTF-8 |
| `banner_bytes` | bytes read |
| `tls` | present exactly when the TLS probe ran (open, no banner, `--tls`): `offered` (`"1.2"`), `sent_bytes`, `read_bytes`, `sni`, `negotiated` (`"1.2"` … or `null`), `cipher` (`"0xc02f"`), `cipher_name`, `alpn`, `alert` (`{level, description, name}` or `null`), `leaf_sha256` (hex), `leaf_len`, `leaf_der` (base64, only when ≤ 8 KiB), `chain_len`, `cert` (what the leaf says, read not verified: `subject` and `issuer` as `C=…, O=…, CN=…`, `subject_cn`, `self_signed` — issuer equals subject — `not_before`, `not_after`, `validity` at probe time: `valid`, `expired`, `not_yet_valid`; `san` — up to 64 dNSName/iPAddress entries — `san_count`, `key` such as `rsa-2048`, `ec-p256`), `cert_error` (why the leaf did not parse), `error` (why the flight stopped, when it did) |
| `attempts` | timeout retries merged into one row |
| `attempt_states` | per-attempt states |
| `timing_ms` | `proxy_connect`, `handshake` absent on the direct path |

- Read `source` before trusting a non-open `state`: a proxy that cannot separate refused
  from filtered yields `error` / `proxy_reply`, never a fabricated verdict;
  `scan_config.transport.measured_fidelity` says which applies.
- Runs of identical `closed`/`filtered` outcomes collapse into `probe_span`; handle both
  or use `--no-spans`. `open`, `error`, resource-pressure hits and disagreeing retries
  never collapse.

### Banners

- Read by default; nothing is sent (`sent_bytes` is `0`).
- Only greet-first services produce one (SSH, SMTP, FTP, POP3, IMAP, MySQL, Telnet); HTTP
  and anything behind TLS do not. Absent means nothing volunteered, not nothing there.
- Recorded as sent: UTF-8 in `banner` (control characters JSON-escaped, `\u001b`), else
  `banner_hex`.
- Never print raw to a terminal: `ESC [ 2J` clears the screen, `ESC ] 0 ;` rewrites the
  title. `scanr` shows printable ASCII, `.` for the rest.
- `timeout_ms` is a ceiling; the wait scales off the host's measured connect time.

```json
{"banner": {"enabled": true, "sent_bytes": 0, "max_bytes": 1024, "timeout_ms": 500},
 "tls": {"enabled": false, "sent_bytes": 0}}
```

### `service_label`

First answer wins: `defaults.services_file`, `/etc/services`, 59 builtin ports — see
[configuration](configuration.md#service-labels). Port 4444 is `krb524` to all three;
key automation on `state`, `source`, `reason`. `/etc/services` varies by host, so
`scan_config.service_labels` records the layers:

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

- `entries`: tcp ports the layer claimed first; no port counted twice. `builtin` holds 59
  but reports only those no file claimed (a stock Linux `/etc/services` names 57).
- `malformed`: lines the parser gave up on. UDP/SCTP rows skipped, uncounted.
- Empty layers are absent; `builtin` is always last and present.
- `use_etc_services` is `false` only when config declined the host layer; a host without
  `/etc/services` reports `true` with the layer absent.

### Fidelity

`scan_config.transport.fidelity_source`: `builtin` (direct: the local stack separates
states), `config` (declared from a `transport test` measurement), `unmeasured`,
`inherent` (http: the protocol has no status meaning refused, so `open_only` by
construction), `exit_hop` (chain: the last hop's — `weakest_hop` in records before
0.4.0), `weakest_member` (pool). Unmeasured chain or pool members give
`measured_fidelity: "unknown"` beside the derived source. A chain's `hops[]` and a pool's
`members[]` each carry `type`.

## `probe_span`

```json
{"type":"probe_span","seq":41,"ts":"2026-07-31T12:42:16.049Z","scan_id":"a3f19c02",
 "state":"filtered","source":"timeout","reason":"connect timed out","protocol":"tcp",
 "attempts":2,"count":1048575,"probe_indices":[[0,523],[525,1048575]],
 "timing_ms":{"min":300.1,"mean":300.4,"max":300.9}}
```

`probe_indices`: inclusive, sorted, disjoint ranges of counter indices (issue order).
Expanding:

```
probe_index = permute(counter_index, permutation.seed, probes_planned)
target      = targets[probe_index / ports.count]
port        = ports[probe_index % ports.count]
```

Under `targets.mode = "pairs"` (a resumed scan) the last step is instead:

```
endpoint    = targets.pairs[probe_index]
```

- The seed is required; `scan_config` carries everything. The permutation is the 4-round
  Feistel network named by `permutation.algorithm`. `output results` and `remainder`
  expand for you.
- Counter space is why the collapse works: order is randomised, so matrix-space ranges
  degenerate to about one per probe. Measured on a rate-limited 20,001-probe scan that
  drained repeatedly: 10,023 matrix-space ranges, 595 counter-space, 11× smaller.
  Version 1 wrote matrix indices; expand those by skipping the permutation.
- Collapsed probes count as `completed`; `remainder` expands them. Lost: per-probe `ts`
  and exact timing (min/mean/max kept).

## `scan_warning`

Stable `code`. Before probing, from plan resolution:

| code | meaning |
|---|---|
| `dns_failure` | hostname did not resolve; not probed |
| `dns_mode_auto` | `auto` picked a mode; another transport would change it |
| `fidelity_unknown` | proxy fidelity not measured |
| `fidelity_open_only` | proxy cannot separate closed from filtered |
| `ephemeral_budget` | rate exceeds the ephemeral-port ceiling |
| `fd_budget` | concurrency exceeds `RLIMIT_NOFILE` |

During the scan, at most once per code, with `detail.remediation`:

| code | meaning |
|---|---|
| `ephemeral_pressure` | source ports ran out |
| `fd_pressure` | descriptors ran out |
| `proxy_saturation` | proxy stopped accepting connections |

Just before the terminal event; a `scanr` bug, not the environment:

| code | meaning |
|---|---|
| `worker_panic` | a worker died; its probes abandoned, results incomplete |

```json
{"type":"scan_warning","seq":204,"ts":"2026-07-31T12:00:04.100Z","scan_id":"a3f19c02",
 "code":"ephemeral_pressure","message":"local ephemeral ports exhausted",
 "detail":{"remediation":"the local ephemeral port range (28232 ports) is exhausted"}}
```

Codes are owned by `diag::WARNING_CODES`; a test checks this list against it both ways.
`fidelity_open_only`, `proxy_saturation` or either `*_pressure` means some non-open
results describe the scanning environment, not the target.

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_warning") | "\(.code)\t\(.message)"'
```

## Terminal event

```json
{"type":"scan_completed","seq":255514,"termination":"natural","graceful":true,
 "duration_ms":641200,"exit_code":0,
 "counts":{"planned":255510,"started":255510,"completed":255510,"abandoned":0,
           "not_started":0,"open":38,"closed":1204,"filtered":254210,"error":58,
           "retried":0}}
```

| bucket (sum = `planned`) | meaning |
|---|---|
| `completed` | reported a result |
| `abandoned` | issued, interrupt ended the drain first; may have touched the network |
| `not_started` | never issued |

`scan_interrupted` adds `signal`, `requested_at`, `forced`; `scan_failed` adds `error`,
`error_code` (currently `worker_panic`, `writer_failure`; open set — `worker_panic` wins when both
occurred, and `counts.worker_panics` survives either way).

## `output summarize`

Totals, then per host, network, port, service; spans expanded. Flags:
[cli.md](cli.md#flags-on-the-other-commands).

```console
$ scanr output summarize scan-*.jsonl.gz
  scan            internal-web
  started         2026-08-01T09:14:02.117Z  (scanr 0.3.0)
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

- Every state counted; ports and services rank by open, then filtered.
- Networks are fixed `/24` (IPv6 `/64`) buckets, not target specs, so records compare.
- Unnarrowed view caps sections at 25 rows; `--by <section>` is full. Cost is hosts plus
  ports, not probes.
- Out-of-range ports go to a `note` line; a state outside the four is counted separately,
  not as `error`.

## `output results`

Filters with spans expanded, so a collapsed `closed` is findable:

```console
$ scanr output results scan-*.jsonl.gz --states open
10.0.0.2:8080/tcp   open      local_stack  http-proxy
10.0.0.3:8080/tcp   open      local_stack  http-proxy
2 result(s)

$ scanr output results scan-*.jsonl.gz --hosts 10.0.0.0/24 --ports 22,443 --states closed,filtered
$ scanr output results scan-*.jsonl.gz --states open --format json | jq -r .target
```

`--hosts` takes `--targets` forms, repeatable, matched without expanding; `--ports` takes
`--ports` forms; `--states` is a comma list of `open`, `closed`, `filtered`, `error`
(unknown is an error); `--format` is `table` (default), `json`, `nmap`, `list` — see
[cli.md](cli.md#handing-results-to-another-tool). Only `table` is coloured, only on a
terminal (`--no-color`, `NO_COLOR` disable). Span-reconstructed results carry
`"collapsed": true` in JSON and no `timing_ms`. The count goes to stderr.

## Recipes

`scanr output events` emits plain JSONL from either form on any platform (`zcat -f`
pass-through is a GNU extension).

Open ports as `host:port`:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open") | "\(.target):\(.port)"'
```

Trustworthy `closed`:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="closed" and .source=="local_stack")
       | "\(.target):\(.port)"'
```

Outcome and settings:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.counts)
       | "\(.type) \(.termination) \(.counts.completed)/\(.counts.planned)"'
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_config") | .timing, .transport, .permutation'
```

Ports that changed:

```console
for f in old.jsonl.gz new.jsonl.gz; do
  scanr output events "$f" | jq -r 'select(.type=="probe_result") | "\(.target):\(.port) \(.state)"' \
    | sort > "$f.st"
done
diff old.jsonl.gz.st new.jsonl.gz.st
```

Producing build:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="scan_started") | "\(.tool_version) \(.git_commit) \(.target_triple)"'
```

Slowest responders:

```console
scanr output events scan-*.jsonl.gz | jq -r 'select(.type=="probe_result" and .state=="open")
       | [.timing_ms.total, "\(.target):\(.port)"] | @tsv' | sort -rn | head
```

## Reproducing a scan

`scan_config` records the unexpanded spec plus counts, never the matrix (a /16 × 1000
ports is 65M probes); `provenance` records which layer supplied each value.

```console
cfg() { scanr output events scan-*.jsonl.gz | jq -r "select(.type==\"scan_config\")|$1"; }
scanr run --targets "$(cfg '.targets.spec[]')" \
          --ports   "$(cfg '.ports.spec')" \
          --seed    "$(cfg '.permutation.seed')"
```

## Resuming an interrupted scan

```console
scanr output remainder scan-*.jsonl.gz | scanr run --pairs -
```

- `remainder` emits exactly the outstanding `host:port` endpoints, `abandoned` included.
- Its `# resumed-from:` comment is provenance, not an endpoint; `--pairs` reads it,
  `--resumed-from <scan-id>` overrides it, and `verify` prints `resumed from scan <id>`.
- A pair scan records `targets.mode = "pairs"` and embeds its list; above 50,000 pairs
  the list is omitted, `pairs_truncated` is set, and `remainder` refuses.

```console
$ scanr output remainder scan-...-a7b012c0.jsonl | head -3
# resumed-from: a7b012c0
192.0.2.0:80
192.0.2.0:443

$ jq -r 'select(.type=="scan_config") | .resumed_from' scan-...-441e1980.jsonl
a7b012c0
```
