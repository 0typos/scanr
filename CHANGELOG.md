# Changelog

All notable changes to `scanr` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## About the version number

`scanr` is released at `0.x` deliberately. The JSONL scan record is additive-stable
within a `schema_version` — new optional fields **and new event types** may appear, while
existing fields keep their type and meaning and are not removed. Consumers dispatch on
`type`, ignore what they do not recognise, and read totals from the terminal event's
`counts` rather than by counting lines of any one type. That promise is not yet hardened
into a semver `1.0` commitment. `1.0.0` is reserved until at least one external consumer has
parsed a record and told us what the format is missing. Schema feedback is explicitly
invited before then.

## [Unreleased]

### Changed

- **Span ranges are now counter indices, and `schema_version` is `2`.** `probe_span.probe_indices`
  encoded matrix positions, which meant the run-length encoding depended on probe *order*:
  order is randomised, so each drain window covered a scattered subset of the matrix and
  the ranges degenerated toward one per probe. Measured on a rate-limited 20,001-probe scan
  long enough to drain repeatedly, matrix space produced 10,023 ranges against counter
  space's 595 — an 11x smaller record (53,765 B to 4,893 B). Counter space is contiguous by
  construction, so the collapse no longer decays with scan duration.

  Expanding a span now requires the permutation seed, which `scan_config` has always
  recorded; run a counter index through the permutation to get the old `probe_index`, then
  map it as before. `scanr output results`, `summarize` and `remainder` do this for you.
  This build **writes** version 2 and **reads** versions 1 and 2 — older records keep
  working unchanged. A version 1 reader correctly refuses a version 2 record rather than
  expanding it to the wrong endpoints, which is why the version was bumped.

- **The schema now says which enumerations are closed.** `state` and `source` are fixed
  within a version and safe to match exhaustively; `transport.type`, the fidelity fields,
  `scan_warning.code` and the terminal `error_code` are open and need a default branch.
  `chain` and `pool` joined `transport.type` within version 1 without a bump, which is the
  distinction the new table draws. A test pins the closed sets in both directions.

### Fixed

- **`config init` omitted nine keys the parser accepts**: `banner`, `compress`, `spans`,
  `services_file` and `use_etc_services` under `[defaults]`; `banner_bytes` and
  `banner_timeout` on a profile; `hops` and `members` on a transport — so the generated
  file documented no way to reach either transport type added after it was written. It
  also named four built-in profiles when there are seven, and offered only "direct or
  socks5" as transport types. The drift guards are now exhaustive destructurings of
  `RawDefaults`, `RawProfile` and `RawTransport`, so a new key stops the build until it
  is documented.
- **`transport list` printed `direct` twice** for any config that redefines it — which is
  what `config init` generates, so every freshly initialised config reported two
  transports where there is one.
- **`docs/cli.md` claimed to list every flag but guarded only `run`'s**, and omitted
  `config init --force`, `output summarize --by` / `--json`, and `output results --hosts`.
  The guard now covers every subcommand.
- **`docs/output-schema.md` documented `--json` on `output results`**, which is
  `--format json`; `--json` remains correct for `output summarize`.
- **`RawDefaults::banner` documented itself as off by default.** It is on.
- **A usage error exited `2`, colliding with "the scan failed after starting".** clap's
  default exit code was never overridden, so a misspelled flag was indistinguishable from
  a scan that broke mid-run — a wrapper retrying on 2 would retry the typo forever.
  Usage errors now exit `1` as `docs/cli.md` has always said; `--help` and `--version`
  exit `0`.
- **The record's `exit_code` ignored writer failures**, so a run the shell saw exit `3`
  could record `0`. It now goes through the same helper the process exits by.
- **`output verify` accepted only the exact schema version this build writes**, so it
  would have rejected every older record the moment the version moved. It now accepts any
  version the build can read and names them when it refuses.
- **A version 2 record with a missing or unparseable permutation seed is now reported.**
  Its spans cannot be expanded, and the failure was silent: the reader produced the right
  number of well-formed endpoints, all of them wrong.

## [0.2.2] - 2026-08-01

### Fixed

- **A trickling proxy could choose how long a probe took.** `SO_RCVTIMEO` bounds each
  `read` syscall, not the message, so a peer delivering one byte just inside the timeout
  reset the clock every iteration — measured at 26x the configured budget. Reads now have
  a message-level deadline. Concurrency is the worker-thread count with no queue, so this
  was a whole-scan stall, not one slow probe.
- **`Spans::exhausted` latched permanently.** One five-second window exceeding the 64-class
  ceiling disabled span collapsing for the rest of the scan, silently. An 8-member pool
  reaches 64 classes easily, since the member is part of the key. It is now per-window.
- **A failed worker spawn detached the workers already running** — no cancellation, no
  join, process exit moments later. Connections were made to real hosts and never
  recorded. Reachable under `RLIMIT_NPROC` or a container `pids.max`.
- **An interrupt left no trace** when a worker panic or writer failure co-occurred: the
  terminal event dropped `signal`, `forced` and `requested_at` because `Failed` outranks
  `Interrupted`. That is an argument about which name to print, not a reason to delete the
  evidence.
- The signal handler's read-modify-write was not atomic, so a SIGTERM nesting inside a
  SIGINT handler could lose the escalation to forced.

## [0.2.1] - 2026-08-01

### Fixed

- A chain that failed while being *established* reported the destination port as
  `filtered` rather than reporting the chain as broken — a verdict on a port nothing
  reached. Because `filtered` is retryable and collapsible, a single slow link had every
  port in the scan retried and then folded into a span, discarding the reason string that
  held the only hint. A chain that cannot be built is now an `error` about the chain.
- Spans dropped `via`, so a pooled scan lost member attribution for exactly the results
  that reveal a broken member — with spans on by default.
- `output results` did not emit `via`, so the documented `jq -r .via` recipe printed null.
- A chain's calibration targets were judged from the first hop's vantage point although
  the last hop issues the CONNECT, so a working chain could report as unmeasurable.
- `transport test` reported authentication only if the *first* hop had credentials.
- A pool of pools overwrote the inner member's name with the container's.
- A declared `fidelity` on a chain or pool was silently discarded; it is now refused, and
  `transport test` no longer advises writing one.
- `scanr plan` showed no hops, members, or fidelity for a chain or pool — hiding the
  "not measured" warning for the transports whose fidelity is least certain.
- `Hop`'s derived `Debug` printed a password in the clear.
- Hop-to-hop CONNECT ran under the handshake budget although it waits on a real TCP
  connect, and each hop was resolved twice.

## [0.2.0] - 2026-08-01

### Added

- **Proxy chains.** `type = "chain"` with `hops = [...]` traverses several SOCKS5 servers
  in order, each reached through the one before. The chain reports its weakest hop's
  fidelity, `transport test` measures the path end to end, and a failure names the hop it
  happened at rather than reading as one anonymous proxy error.
- **Proxy pools.** `type = "pool"` with `members = [...]` spreads probes across several
  proxies, multiplying both the local ephemeral-port budget and the per-proxy connection
  cap. Assignment is deterministic — an endpoint always goes via the same member, so a
  scan stays reproducible — and every result records which member produced it. Not
  failover: a dead member fails its share rather than having it taken over.

### Changed

- The one-proxy-per-scan limitation is lifted; the note about it under 0.1.0's known
  limitations no longer applies.

## [0.1.0] - 2026-08-01

### Added

- Direct and SOCKS5 TCP connect scanning, unprivileged, with per-phase timing
  (proxy connect, handshake, destination connect) recorded separately.
- **Transport fidelity measurement.** `scanr transport test` probes a known-open, a
  known-closed, and an unroutable destination through a proxy and reports which reply
  codes came back, so you learn what your results can mean *before* spending a scan.
  The measurement is recorded in configuration and appears in the scan record.
- Layered TOML configuration (user then project, per-key) with full provenance:
  `scanr plan` shows every effective value and which layer supplied it.
- Automatic JSON Lines scan record with enforced invariants — `scan_started` first,
  `scan_config` second, exactly one terminal event last, nothing after it. Written as
  `.jsonl.partial` and renamed only once finalized.
- `scanr output verify` to check a record for integrity, count consistency, and
  accidentally recorded credentials; `summarize` and `remainder` alongside it.
- Exact resumption: `output remainder` emits the endpoints that were never reported and
  `run --pairs` consumes them, so an interrupted scan resumes without re-probing ports
  that already completed. The resumed scan records `resumed_from`, so a scan split across
  an interruption stays traceable as one thing; the link travels through the pipe on its
  own, and `--resumed-from` sets it by hand for an edited list.
- **Records are gzip-compressed and span-collapsed by default.** `--no-compress` and
  `--no-spans` restore the plain, one-row-per-probe form; `scanr plan` states which you
  are getting. Note that `probe_result` no longer covers every probe by default, so a
  `jq 'select(.type=="probe_result")'` recipe under-reports unless it also handles
  `probe_span` — see `docs/output-schema.md`.
- `--spans` collapses runs of identical `closed`/`filtered` outcomes into `probe_span`
  events instead of one row each. Measured on a million-probe scan: 391 MB and 1,048,580
  events become **2.6 KB and 5 events**, with the scan marginally faster for writing less
  and `verify`/`remainder` giving identical answers. `open` and `error` always keep their
  own row, as does anything under resource pressure or whose retry disagreed. Costs the
  per-probe timestamp and exact timing for collapsed results.
- `--compress` writes the record as framed gzip, 20–23x smaller. `zcat`, `zless` and
  `scanr output` read it unchanged, and the frames mean a killed scan still decodes up
  to its last completed frame rather than being lost.
- `output remainder` reconstructs the outstanding endpoints from the terminal event
  rather than by re-reading every probe row. The work counter issues indices in order,
  so what was never started is a contiguous range and only the in-flight probes are
  scattered; the terminal event records both. Falls back to the full read when the hint
  is missing or disagrees with the counts.
- Record readers stream. `summarize`, `verify` and `remainder` hold single-digit
  megabytes regardless of record size (96 MB for `remainder`, which must retain the
  probed set), so the commands for inspecting a large scan work on a large scan.
- `output verify` checks field *values* as well as structure — port range, `state` and
  `source` against their defined sets, `attempts` against `attempt_states`, `probe_index`
  against `probes_planned`, timings, and timestamps. A structurally perfect record can
  still be untrue, and `remainder` would act on it.
- Randomized probe order via a seeded Feistel permutation: O(1) memory, and exactly
  reproducible from the recorded seed via `--seed`.
- Graceful interruption. First SIGINT stops scheduling and drains in-flight probes
  bounded by the connect timeout; second exits immediately. Either way the record is
  finalized, with `completed` / `abandoned` / `not_started` accounted separately.
- A scan that fails says so. A write failure on any event type, and a scan worker dying,
  both force `scan_failed` with a distinguishing `error_code` rather than being reported
  as a natural completion.
- Host diagnostics that name operational causes rather than errnos, with remediation
  derived from the sysctls actually present on the machine.
- Seven built-in profiles; the default follows the transport rather than being fixed.
  Three are for `ssh -D` (`ssh`, `ssh-fast`, `ssh-slow`), which behaves unlike a normal
  SOCKS5 proxy: its listener is local, so the ephemeral-port rate cap does not apply, and
  measured against OpenSSH 10.2p1 that cap alone made 4,000 probes take 80 s under
  `proxy-careful` versus 0.16 s under `ssh`.
- **Port labels read `/etc/services`**, and `defaults.services_file` points at a file of
  your own that outranks it. Layered per port, so a three-line internal port map still
  inherits the other ~5,800 entries; a compiled-in table of 59 well-known ports is the
  floor when neither file exists. Because labels can now differ between machines, every
  record's `scan_config` states which layers produced them and how many entries each
  contributed. Still a guess from the port number and never a fingerprint — nothing
  connects to the service or reads a banner. `defaults.use_etc_services = false` drops
  the host layer for labels that match on every machine, and the record distinguishes
  declining it from the file being absent.
- `output results` and `output summarize` colour their state columns on a terminal, using the
  same palette as `run`. Never when redirected, and never in `--json` or `output events`,
  which are data.
- Shell completions for bash, zsh, fish, elvish, and PowerShell.

- **Banners are read from open services by default**, without sending anything — the
  record states `banner.sent_bytes: 0`. `--no-banner` or `banner = false` turns it off.
  1024 bytes and 500 ms by default,
  tunable per profile via `banner_bytes` and `banner_timeout` — which is a ceiling, not a
  fixed wait: the read scales off each host's measured connect time, because a worker
  waiting on a silent port is a worker issuing no probes. Only services that greet
  first say anything, so HTTP and anything behind TLS stay silent; an absent banner means
  "said nothing unprompted", not "nothing there". Banners reach the screen as printable
  ASCII only, because a terminal acts on escape sequences and the bytes belong to the
  scanned host; the record keeps them verbatim.
- **`output results --format nmap|list`** hands the open endpoints to a tool that can
  interrogate them. The `nmap` form emits runnable `nmap -sV` commands grouped by each
  host's exact open ports; `list` emits `host:port` for `httpx`, `tlsx` and `nuclei`.
  Replaces `--json` on that command with `--format json`.

### Changed

- **`output cat` is now `output events`, and `output get` is now `output results`.** The
  old names said the opposite of the truth: with spans on by default, `cat` emitted the
  file verbatim and so showed only a fraction of the probes, while `get` — which expands
  spans — was the one that showed all of them. On a 21-probe record, `cat | jq
  'select(.type=="probe_result")'` returned 4 and `get` returned 21.
- **`output summarize` aggregates instead of listing.** It now reports counts per host,
  per network and per service, for *every* state rather than only `open`, and prints all
  sections by default with `--by` to narrow. `--json` emits the same aggregates. The old
  `--by` only rearranged one list of open ports and could not answer "how many hosts had
  445 filtered".
- `output remainder` on a complete scan says so, instead of suggesting a re-run pipeline
  that would have probed nothing.

### Fixed

- The documented built-in profiles now match the code. The table said "Four built-ins"
  after three `ssh -D` profiles were added, and listed `direct-fast` at a 1s timeout with
  `retries = 0` when it had become 300ms with `retries = 1` — the retry being the whole
  reason a sub-second timeout is safe. A test now checks the table against the builtins.
- `docs/tuning.md` no longer contradicts itself about `direct-fast`, describing it as
  300ms twice in one section and "a full second" in another.

- The span accumulator no longer sizes itself from the *planned* probe count. It held one
  bit per planned probe per outcome class, so a `/8 x 100` scan wanted ~200 MB per class
  against a 64-class ceiling; it now keeps only the indices it absorbed, which one
  progress interval bounds.
- `output summarize` reports a record's port as the record states it. An out-of-range
  port was truncated to a plausible one (65616 printed as 80) and a missing port printed
  as 0, on the surface whose job is to make a bad record obvious.
- A record's `service_labels` provenance now describes the table that actually produced
  its labels, rather than the one the plan was carrying. They agree in every current
  path, but nothing enforced it.
- The `builtin` row of `service_labels` reports the ports it still answers for rather than
  its full size, so the layer counts sum to the table without double-counting ports that
  a file layer above shadowed.

### Security

- Inline passwords in configuration are a hard validation error, not a warning, since
  project config is normally committed. Only `password_env` and a mode-0600
  `password_file` are accepted.
- Credentials are redacted everywhere, including in the source line an error points at.
- Probe sockets close with `SO_LINGER{on,0}`, which avoids `TIME_WAIT` exhaustion and was
  measured as a 7.5x sustained-throughput multiplier.

### Known limitations

- Linux x86_64 is the supported platform; the performance numbers are measured there and
  it is the only target with a static musl build. macOS builds and its test suite runs in
  CI, but the host diagnostics that read `/proc` — the ephemeral-port range and
  `tcp_tw_reuse` — report as unknown there, so the `ephemeral_budget` warning cannot
  fire. Windows is deferred, not planned.
- SOCKS4 and SOCKS4a are unsupported by design: four reply codes cannot distinguish a
  closed port from a filtered one.
- One proxy per scan. Multiple proxies and proxy chains are deferred. *(Lifted in 0.2.0.)*
- Through a proxy that does not report refused connections distinctly, `closed` and
  `filtered` are indistinguishable and non-open results are recorded as `error` rather
  than guessed. `transport test` tells you whether yours is such a proxy.

