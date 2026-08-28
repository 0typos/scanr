# Roadmap to 1.0

Status 2026-08-27. **1.0.0-rc.6 is released** (rc.1 with 0.3.0–0.5.0 on 2026-08-26;
rc.2 through rc.6 on 2026-08-27; binaries on GitHub, now nine cross-compiled targets).
P0–P3 are done.

The promised surface last moved in rc.2/rc.3, which expanded the TLS probe (D35 amended):
the full leaf certificate read (unverified) into `tls.cert`, the whole flight including
the chain, TLS 1.3 read by finishing the key exchange, `--tls-versions` surveying SSLv2
through 1.2 to name a server only an old client can reach, and the hello's whole offer
recorded in `scan_config.tls`. All additive — every earlier record still reads back — but
new surface, so it restarted the soak: P4 runs from 2026-08-27, earliest 1.0 no sooner
than 2026-09-24 or three engagements. rc.4-rc.6 carry only non-promised changes — the
`plan` `dns` row naming its resolver (rc.4); output record filenames now
`scan-<name>-<UTC time>-<id>` (rc.5); the `plan` output grouped into coloured sections,
release binaries cross-compiled for six more architectures (best-effort), and the tutorial
lab as an installable uv script (rc.6) — so the soak clock is unchanged. The rc.1-only additions (D37 batched collector, D38 deferred, the
timeout-bound plan projection, `results --format json` evidence fields) carried no
surface change.

## What 1.0 promises

| surface | promise within 1.x | pinned by |
|---|---|---|
| JSONL record | additive only: new optional fields and event types may appear; existing fields keep type and meaning; `state` and `source` are closed sets; a `schema_version` bump is a major version | `tests/spec_conformance.rs`, compat corpus (P3) |
| CLI | commands, flags, exit codes and stdout formats stable; removal needs a deprecation warning for at least one minor | `tests/cli_spec.rs`, `man/` drift test |
| Config | keys and semantics stable; new keys additive; unknown keys stay errors | `config init` drift guard (exhaustive destructure of every raw type) |

Not promised: the library API (`lib.rs` disclaims it), stderr text, `plan` and human
rendering, performance figures, platforms other than Linux x86_64 gnu and musl, MSRV (a
bump is a minor).

## The gate

The previous gate — an external consumer parses a record and reports what is missing —
was outside the project's control and is withdrawn (D36). 1.0.0 is tagged when:

1. **The surface is complete.** HTTP CONNECT (P1) and the TLS probe (P2) both add
   config keys and record fields; freezing before them means carrying an interim shape.
2. **The surface is pinned.** P3 done.
3. **The surface has soaked.** `1.0.0-rc.1` used on real engagements for four weeks or
   three engagements, whichever is longer, with no change to a promised surface. A
   surface change ships a new rc and restarts the clock; a fix outside the surface does
   not.

## Phases

### P0 — release 0.3.0 · done 2026-08-26

- Shipped as v0.3.0 (tagged 2026-08-26 together with 0.4.0, 0.5.0 and rc.1).
- Docs compacted and drift fixed (done 2026-08-25).

### P1 — HTTP CONNECT transport → 0.4.0 · D34 · done 2026-08-25

Shipped as designed below, with two corrections the measurement forced: HTTP proxies
are `open_only` by construction (no vendor has a refused status; `fidelity = "full"` is
refused rather than "measured"), and a chain's fidelity is its exit hop's, not its
weakest hop's (D33 amended). Real-proxy rows are in `docs/transports.md`.

| | |
|---|---|
| config | `type = "http"`, `address`, `username`, `password_env` \| `password_file` (→ `Proxy-Authorization: Basic`), `fidelity`; valid as a chain hop and a pool member — a `200` yields a raw tunnel, so hop types may mix |
| wire | `CONNECT host:port HTTP/1.1`, `Host`, auth header; response read to `\r\n\r\n`, bounded 8 KiB (peer-controlled length) |
| mapping | `200` open · `407` auth failure (error; one `scan_warning`) · `403` policy denial (error) · every other status: per proxy, measured by `transport test`, never assumed (D8). `source: proxy_reply`; `reason` carries the status line |
| DNS | `supports_remote_dns = true` |
| schema | `transport.type` gains `http` (open set); fidelity fields carry status codes where SOCKS5 carries reply bytes. Additive, no bump |
| fixture | in-process CONNECT server: injectable status, auth, malformed status line, header overflow, disconnect mid-header, byte trickle |
| fuzz | `http_connect_reply` target and seeds |
| measure | squid, tinyproxy, 3proxy (`proxy` service): raw status lines into `docs/transports.md` |
| security | Basic is base64 in the clear — same class as RFC 1929; the chain-credentials table applies unchanged |
| done when | fidelity rows for three real proxies; `http→socks5` and `socks5→http` chains tested; fuzz clean |

### P2 — TLS ClientHello probe → 0.5.0 · D35 · done 2026-08-25

Shipped as designed below and verified against `openssl s_server` in `-tls1_2` and
`-tls1_3` modes. One limit recorded: no SNI on the direct path for locally resolved
names (deferred, decisions table). SHA-256 hand-rolled rather than `sha2`.

| | |
|---|---|
| switch | `--tls` / `tls = true` under `[defaults]` or a scan. **Off by default.** `scan_config.tls.{enabled, sent_bytes}`; `banner.sent_bytes` stays 0 |
| when | open ports that volunteered no banner — TLS servers never speak first — on the same connection, after the banner wait |
| sent | a fixed TLS 1.2 ClientHello: SNI when the target is a hostname, ALPN `h2, http/1.1`. Deterministic bytes, listed in `docs/security.md` |
| why 1.2 | in 1.3 the Certificate and ALPN are encrypted; reading them needs a full handshake, which means a real TLS stack, which means C/asm (`ring`, `aws-lc`) and the end of the static musl build (D19, D28). Offering 1.2 gets ServerHello and Certificate in the clear from any server that still permits it; a 1.3-only server answers a `protocol_version` alert, which is itself evidence |
| parsed | ServerHello (version, cipher, ALPN) · Certificate (leaf DER, chain length) · Alert (level, description). Then stop and RST-close. No key exchange, no verification, no x509 parsing (D32: do not build a worse `tlsx`) |
| record | on `probe_result`, additive: `tls: {offered, negotiated, cipher, alpn, sni, alert, leaf_sha256, leaf_der (base64, ≤ 8 KiB), chain_len}` |
| display | `tls1.2 h2 sha256:ab12…`; ALPN is peer bytes → printable ASCII only, as banners |
| deps | `sha2` (pure Rust) or a ~100-line SHA-256. Nothing with C |
| timeout | `tls_timeout` ceiling scaled off the measured connect, same shape as `banner_timeout` |
| fixture | in-process responder replaying captured handshakes (`openssl s_server` 1.2 and 1.3-only) with injectable alerts, truncation and oversize length fields |
| fuzz | `tls_reply` target — every structure is length-prefixed and peer-controlled |
| security | new "Active probes" section: exact bytes, that it addresses the service, default off, the record states it |
| done when | correct against `openssl s_server` in 1.2 and 1.3-only modes; fuzz clean; a test proves zero bytes sent when off; musl binary still has 0 `NEEDED` |
| revisit | a mature pure-Rust rustls provider makes a 1.3 handshake possible without C |

### P3 — freeze → 1.0.0-rc.1 · done 2026-08-25

Done: `docs/stability.md`; `output summarize --format` (with `--json` as a warning alias);
exit codes were already pinned; `tests/compat/` holds 11 scenario records (one written by
the real 0.2.2 binary) and the `config init` template of every release, with the exact
reader output pinned; `docs/evidence.md` maps every claim to its test, corpus scenario or
measurement and `tests/evidence.rs` keeps the map honest; the nmap differential covers
HTTP CONNECT and the TLS probe is checked against `openssl s_server` in CI.

- `docs/stability.md`: the promise table above plus deprecation and MSRV policy.
- Surface audit — free now, a major later:
  - `output summarize --json` vs `output results --format json`: `--format` on both, `--json` kept as a hidden alias that warns.
  - exit codes `0/1/2/3/130` pinned by one test.
  - everything in the backlog marked "before freeze".
- Compat corpus `tests/compat/`: records from 0.2.2 (v1) and 0.3.0+ (v2) — gzip and plain, spans and rows, complete and interrupted — with expected output for `events`, `results`, `summarize`, `verify`, `remainder`; `config init` output from each 0.x that must still load. A read regression fails the build.
- `CHANGELOG.md` "About the version number" states the policy.

### P4 — soak → 1.0.0 · in progress since 2026-08-26

- Run the rc on real work. Record one long run's RSS over time (the multi-hour gap) and
  add a fidelity row for any proxy not yet in the table.
- Surface finding → fix, new rc, clock restarts. Otherwise tag 1.0.0 after the soak.

Total: roughly 8–12 working days plus the soak.

## Backlog — findings from real engagements

Fill in. Anything touching a promised surface is "before freeze".

| finding | surface | before freeze? | notes |
|---|---|---|---|
| | | | |

## Known gaps accepted for 1.0

- Commercial rotating pools: unmeasured. Add rows during soak if one is reachable.
- Sustained multi-hour run: unmeasured (longest: 69 s, 10⁶ probes). Measure during soak.
- aarch64: not built. Post-1.0, additive.
- Windows: not planned.

## Out of 1.0

SOCKS4/4a (rejected, D4) · SSH-native transport · adaptive concurrency · UDP and SYN ·
library API · aarch64 and macOS as supported platforms · TLS 1.3 handshake. Revisit
triggers live in `docs/design/decisions.md`.

## Definition of done

- [x] 0.3.0 released from `main` (2026-08-26)
- [x] HTTP CONNECT: three-proxy fidelity table, mixed chains tested, fuzz clean (released as 0.4.0, 2026-08-26)
- [x] TLS probe: 1.2 and 1.3-only verified, off-by-default proven, musl static (released as 0.5.0, 2026-08-26)
- [x] `--format` unified; exit codes pinned; backlog "before freeze" items closed (backlog was empty)
- [x] `docs/stability.md` and compat corpus in place; `docs/evidence.md` added
- [x] `1.0.0-rc.1` tagged and released (2026-08-26)
- [ ] soak period completed with no surface change (earliest 2026-09-23)
- [ ] `1.0.0`
