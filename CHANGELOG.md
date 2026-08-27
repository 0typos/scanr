# Changelog

[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format,
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Compacted 2026-08-25; the
long-form entries are in git history before that date.

## About the version number

Within a major version the JSONL record is additive-stable: new optional fields and new
event types may appear; existing fields keep their type and meaning; `state` and `source`
are closed sets. Widening a closed set or changing a field's meaning bumps
`schema_version`, and that is a major version of scanr. The CLI and config format carry
the same promise from 1.0. The path there is `ROADMAP.md`.

## [Unreleased]

### Changed

- `RELEASING.md` records the release cadence: batch small non-surface changes into
  `[Unreleased]` rather than cutting a release candidate for each; tag when a promised
  surface moves or a batch is worth a build.

## [1.0.0-rc.4] - 2026-08-27

### Changed

- `plan`'s `dns` row names the effective mode's resolver, not just the mode:
  `auto -> local (names resolved on this host)`, `transport (names handed to the proxy
  to resolve)`, `disabled (hostname targets rejected)`. A pinned mode shows only itself;
  `auto` shows both the request and what it resolved to, so it never leaves the reader
  guessing which resolver a scan used.

## [1.0.0-rc.3] - 2026-08-27

### Added

- `scan_config.tls` now records the hello's offer, not just the versions:
  `offered_ciphers` (suite names, the 1.3 suite first), `offered_alpn`, `offered_groups`
  and `offered_sigalgs`. The offer is fixed for every probe, so it is recorded once in
  the config event; a record now states both what was offered and what each server
  chose, without cross-referencing `docs/security.md`. With `--tls-versions`,
  `version_hellos` becomes one object per survey version (`ssl2`, `ssl3`, `1.0`, `1.1`,
  `1.2`) carrying that hello's `sent_bytes` and the era-appropriate `ciphers` it offers,
  in place of the bare sizes.

## [1.0.0-rc.2] - 2026-08-27

### Added

- `docs/tutorial.md`, a learn-by-using guide with real output, and `docs/tutorial/`, its
  lab: `./lab up|tunnel|check|down` brings up three loopback services (`lab.py`,
  standard library), squid/tinyproxy/3proxy/dante in rootless podman, and an `ssh -D`
  through a throwaway `sshd`. `tests/tutorial.rs` parses every `scanr` command in the
  document against the CLI and re-runs its use cases — direct ones against the lab,
  proxied ones against the fixtures — so the guide cannot rot.
- The TLS probe reads the leaf certificate. `tls.cert` carries subject, issuer,
  alternative names, validity at probe time (`valid`, `expired`, `not_yet_valid`),
  whether issuer equals subject (`self_signed`) and the key type; result lines and
  `output results` say `cn=host self-signed expired` — for records written before this
  too, from the DER they already hold. Read, never verified; bounded and fuzzed
  (`x509_leaf`). The leaf also carries `serial`, `sig_alg` and `version`; a SHA-1 or
  MD5 signature is flagged `sha1-signed` / `md5-signed` on the line.
- The TLS flight is read to ServerHelloDone rather than stopping at the leaf, so the
  record gains `chain` (the certificates after the leaf, hashed and read, up to 8), the
  ECDHE `kx_group` and `sig_scheme` from ServerKeyExchange, `compression`, and the
  ServerHello's `server_extensions` with `secure_renegotiation`, `extended_master_secret`
  and `session_ticket` derived from it. `negotiated` says `ssl3` for an SSLv3 answer.
- The TLS probe reads TLS 1.3 servers. The hello (now 218 bytes) offers 1.3 and 1.2;
  when a server takes 1.3 the probe finishes the key exchange with a published X25519
  key and decrypts the flight — certificate, chain, ALPN, signature scheme — instead of
  recording a `protocol_version` alert. `offered` says `"1.3,1.2"`; a HelloRetryRequest
  is recorded as `hello_retry_request` and not pursued. X25519, HKDF and AES-128-GCM are
  hand-rolled in `src/crypto.rs`, each held to an RFC or NIST vector; nothing is sent
  after the hello.
- `--tls-versions` (`tls_versions = true`, needs `tls`): after the hello, ask SSLv2,
  SSLv3, TLS 1.0, 1.1 and — when the server took 1.3 — 1.2 for themselves, each on its
  own connection with a hello of its era. The record's `tls.versions` says which are
  accepted, `legacy_only` when the newest is older than 1.2, and `advice` naming a client
  that can still reach it; the result line ends `versions:ssl3..1.3` or
  `legacy-only:tls1.0`. An SSLv2-only server's certificate is taken from its
  SERVER-HELLO. Up to five more connections per silent open port; `scan_config.tls`
  lists the hellos' sizes and `docs/security.md` their bytes.
- SNI travels on the direct path when the target was given as a name: a locally resolved
  address now keeps its hostname, so a virtual-hosting server answers with its certificate
  instead of an alert. A real 443 answered `internal_error` to the nameless hello.
- `scanr plan` projects the timeout-bound duration beside the rate-bound one: `~3d21h17m if
  every probe times out (5s x 2 attempts / 512 in flight)`. The rate cap never binds on a
  network of silent ports; this is the number that does.

### Changed

- **Direct scans are 2.5–4× faster.** Workers hand results to the collector in batches
  of up to 64 (an `open` or a pressure event still flushes at once), and the hot path no
  longer allocates per probe: target names are formatted once, reasons are borrowed,
  attempt states live inline, the TLS observation is boxed. Measured on a 64-core box,
  loopback `/24`, every port refused: 256k probes 1.54 s → 0.40 s at the default
  concurrency (166k → 640k probes/s); 2.56M probes 14.1 s → 4.3 s. Throughput no longer
  falls with concurrency (512 was 40% slower than 64; now within 5%). Record contents,
  order and every reader output are unchanged — the compat corpus passes as pinned.

### Fixed

- `output results` shows the banner and the TLS summary as a trailing column of its
  table, exactly as `run` printed them live; replaying a record no longer hides the
  evidence it was kept for. `--full`, on `run` and on `output results`, shows banners
  untruncated (the default cuts at 48 characters; the printable-ASCII filter applies
  either way).
- `output results --format json` now carries `banner`, `banner_hex`, `banner_bytes` and
  `tls` when the record has them. The reader built for handing results to other tools
  dropped exactly the evidence those tools want; `events` always had it.

## [1.0.0-rc.1] - 2026-08-25

### Added

- `docs/stability.md`: what 1.x promises (record, CLI, config), what it does not, and
  the deprecation rule.
- `tests/compat/`: eleven scenario records — direct (spans and rows), SOCKS5 full and
  open-only, HTTP CONNECT, a mixed chain, a pool, banner + TLS, interrupted and resumed,
  and a schema-1 record written by the 0.2.2 binary — with the exact output of every
  reader pinned, plus the `config init` template of every release, which must still
  validate and plan. `tests/compat.rs` holds the build to all of it.
- `docs/evidence.md` maps every claim in the docs to the test, corpus scenario or
  measured decision behind it; `tests/evidence.rs` fails if a cited test disappears.
- The nmap differential now covers HTTP CONNECT, and CI checks the TLS probe against
  `openssl s_server`.

### Changed

- `output summarize` takes `--format table|json`, the same flag as `output results`.

### Deprecated

- `output summarize --json`: still works, warns on stderr, removed in 2.0.

## [0.5.0] - 2026-08-25

### Added

- **The TLS ClientHello probe**, `--tls` / `tls = true` — off by default, the one active
  probe scanr has. On open ports that volunteered no banner it sends a fixed 163-byte TLS
  1.2 ClientHello on the same connection and records what comes back: negotiated version,
  cipher, ALPN, the leaf certificate (SHA-256, and the DER when ≤ 8 KiB) and chain length,
  or the alert — a 1.3-only server answers `protocol_version`. Verified against `openssl
  s_server`. `scan_config.tls.sent_bytes` states what was sent (`0` when off);
  `docs/security.md` lists the exact bytes and a test holds it to them. `tls_timeout` (1s)
  is the profile ceiling. Fuzz target `tls_reply`. No new dependencies.

## [0.4.0] - 2026-08-25

### Added

- **HTTP CONNECT proxies**: `type = "http"` with the same keys as `socks5`; Basic
  authentication; usable as a chain hop (mixed with `socks5` in either order) and a pool
  member. Measured against squid 7.6, tinyproxy 1.11.2 and 3proxy 0.9.7: none has a
  status meaning "refused" (`503`/`500`/`502`, the same for a timeout), so an http
  transport is `open_only` by construction — non-open results are `error` carrying the
  status line, `fidelity_source` is `inherent`, and declaring `fidelity = "full"` is
  refused. Fuzz target `http_connect_reply` covers the response parser.

### Changed

- **A chain's fidelity is its exit hop's, not its weakest hop's.** Only the last CONNECT
  names the destination and its reply travels back untouched; measured `full` through
  squid → 3proxy SOCKS5. `fidelity_source` for a chain is `exit_hop` (was `weakest_hop`);
  chain `hops[]` and pool `members[]` entries now carry `type`.
- `transport test` prints `status NNN` for HTTP replies beside `reply 0xNN` for SOCKS5.

### Fixed

- **A chain or pool resolved hostnames locally and took the `direct` default profile.**
  `supports_remote_dns` was true only for a single `socks5`, so `dns = "auto"` through a
  chain leaked DNS from the host and the scan ran with no rate limit. Every proxied kind
  now resolves through the transport; a pool does when every member does.
- Chains and pools with `unknown` or `open_only` fidelity now get the `fidelity_unknown`
  / `fidelity_open_only` plan warnings; only a single `socks5` did.

## [0.3.0] - 2026-08-25

### Changed

- `schema_version` is `2`: `probe_span` ranges are counter indices, not matrix positions, so
  collapse no longer decays with scan duration (10,023 → 595 ranges, 53,765 → 4,893 B on a
  rate-limited 20,001-probe scan). Expansion needs the recorded seed. Writes 2, reads 1 and 2.
- `docs/output-schema.md` states which enumerations are closed (`state`, `source`) and which
  are open (`transport.type`, fidelity fields, warning and error codes); a test pins the closed sets.
- Docs compacted; `docs/design/decisions.md` is a terse register; `ROADMAP.md` added with
  the 1.0 policy and plan.

### Security

- The record is created mode 0600, including the `.partial` file.
- `password_file` mode is checked on the descriptor it is read from.
- All 31 GitHub Actions references pinned to commit SHAs; `contents: write` scoped to the
  publish job; CI declares `contents: read`.
- `unsafe_code` denied crate-wide; each of the five blocks carries `#[allow]` and a safety
  comment; `docs/security.md` lists them and a test checks both directions.
- Threat model covers chains: every hop sees the credentials of every hop after it.
- `build.rs` no longer stamps an enclosing repository's commit when the tree has no `.git`.
- `deny.toml` `multiple-versions = "deny"`, with the one known duplicate listed.

### Fixed

- `output verify` exits 2 for a bad record and 1 for an unreadable file.
- `output results --hosts <name>` says on stderr when a name cannot match an address record.
- `config init` documents all keys (`banner`, `compress`, `spans`, `services_file`,
  `use_etc_services`, `banner_bytes`, `banner_timeout`, `hops`, `members`), seven profiles,
  and four transport types; drift guards are exhaustive destructurings.
- `transport list` no longer prints `direct` twice when a config redefines it.
- `docs/cli.md` guards every subcommand's flags, not only `run`'s.
- `output results` takes `--format json`, not `--json` (docs corrected).
- `RawDefaults::banner` documented as on by default.
- Usage errors exit 1, not 2; `--help` and `--version` exit 0.
- The record's `exit_code` reflects writer failures.
- `output verify` accepts every schema version the build can read.
- A version-2 record with a missing or unparseable seed is reported, not expanded wrongly.

## [0.2.2] - 2026-08-01

### Fixed

- Reads have a message-level deadline; a byte-trickling proxy could stretch a probe to 26× its budget and stall the scan.
- `Spans::exhausted` is per window, not latched for the scan.
- A failed worker spawn cancels and joins the workers already running.
- An interrupt co-occurring with a panic or writer failure keeps `signal`, `forced` and `requested_at` in the terminal event.
- The signal handler's escalation to forced is atomic.

## [0.2.1] - 2026-08-01

### Fixed

- A chain that fails while being established is an `error` about the chain, not `filtered` on the destination.
- Spans and `output results` carry `via`.
- Chain calibration is judged from the last hop; `transport test` reports auth on any hop.
- A pool of pools keeps the inner member's name.
- A declared `fidelity` on a chain or pool is refused, not dropped; `plan` shows hops, members and fidelity.
- `Hop`'s `Debug` no longer prints a password.
- Hop-to-hop CONNECT uses the connect budget; each hop resolves once.

## [0.2.0] - 2026-08-01

### Added

- Proxy chains: `type = "chain"`, `hops = [...]`; weakest-hop fidelity; failures name the hop.
- Proxy pools: `type = "pool"`, `members = [...]`; deterministic assignment; `via` on every result; not failover.

## [0.1.0] - 2026-08-01

### Added

- Direct and SOCKS5 connect scanning, unprivileged, with per-phase timing.
- `transport test`: fidelity measurement (`full` / `open_only` / `unknown`) recorded in config and the record; `--calibrate` finds the proxy's connection cap by churn.
- Layered TOML config with provenance; `plan` shows every value and its layer.
- JSONL record with enforced invariants: `scan_started`, `scan_config`, one terminal event last; `.partial` until finalised.
- `output verify` (structure, values, counts, credential leaks), `summarize` (per host, network, service, every state), `remainder`, `events`, `results` (`--format json|nmap|list`).
- Exact resumption: `output remainder | run --pairs -`, with `resumed_from` carried through the pipe.
- Records gzip-framed and span-collapsed by default (`--no-compress`, `--no-spans`); streaming readers.
- Seeded Feistel probe order, reproducible with `--seed`.
- Graceful interruption: drain on first SIGINT, immediate on second; `completed` / `abandoned` / `not_started` accounted; exit 130.
- Writer failure and worker panic force `scan_failed` with a distinguishing `error_code`.
- Host diagnostics naming operational causes with sysctl remediation.
- Seven built-in profiles, including `ssh`, `ssh-fast`, `ssh-slow` for `ssh -D`.
- Service labels layered over `defaults.services_file`, `/etc/services` and a builtin table, with provenance; `use_etc_services = false` for machine-independent labels.
- Passive banners on by default (`--no-banner`); 1024 bytes / 500 ms ceiling scaled off connect time; printable ASCII on screen, verbatim in the record.
- Colour on a terminal only; shell completions for bash, zsh, fish, elvish, PowerShell; man pages.

### Security

- Inline passwords are a hard error; only `password_env` and a 0600 `password_file`.
- Credentials redacted everywhere, including echoed source lines.
- Probe sockets close with `SO_LINGER{on,0}` (7.5× sustained throughput).

### Known limitations

- Linux x86_64 supported; macOS builds and tests without `/proc` diagnostics; Windows not planned.
- SOCKS4/4a unsupported by design.
- Through an `open_only` proxy, non-open results are `error`, never a guessed `closed`.
