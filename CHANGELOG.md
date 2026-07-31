# Changelog

All notable changes to `scanr` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## About the version number

`scanr` is released at `0.x` deliberately. The JSONL scan record is
additive-stable within `schema_version 1` — new optional fields may appear, existing
fields will not change type or meaning — but that promise is not yet hardened into a
semver `1.0` commitment. `1.0.0` is reserved until at least one external consumer has
parsed a record and told us what the format is missing. Schema feedback is explicitly
invited before then.

## [Unreleased]

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
- Shell completions for bash, zsh, fish, elvish, and PowerShell.

### Security

- Inline passwords in configuration are a hard validation error, not a warning, since
  project config is normally committed. Only `password_env` and a mode-0600
  `password_file` are accepted.
- Credentials are redacted everywhere, including in the source line an error points at.
- Probe sockets close with `SO_LINGER{on,0}`, which avoids `TIME_WAIT` exhaustion and was
  measured as a 7.5x sustained-throughput multiplier.

### Known limitations

- Linux x86_64 only. Windows and macOS are deferred, not planned.
- SOCKS4 and SOCKS4a are unsupported by design: four reply codes cannot distinguish a
  closed port from a filtered one.
- One proxy per scan. Multiple proxies and proxy chains are deferred.
- Through a proxy that does not report refused connections distinctly, `closed` and
  `filtered` are indistinguishable and non-open results are recorded as `error` rather
  than guessed. `transport test` tells you whether yours is such a proxy.

