# Release Plan

Status: proposed (2026-07-29)

Target: a tool a stranger can install, trust, and operate without reading the source.

The gap between where `scanr` is now and releasable is **not features**. The scope is
right and the architecture is validated. The gap is in four things: legal and packaging
basics that are simply absent, code that exists but never runs, claims that still exceed
evidence, and no automation to keep any of it true tomorrow.

Phases are ordered by what blocks what. Effort is rough and assumes no surprises.

---

## Phase 0 — Blockers that are pure absence

Nothing here is hard; all of it is disqualifying if missing.

| Item | Why it blocks |
|---|---|
| `LICENSE-MIT` + `LICENSE-APACHE` files | `Cargo.toml` claims `MIT OR Apache-2.0` and neither file exists. Shipping a licence claim with no licence text is a legal defect, not an oversight. |
| `CHANGELOG.md` | A released tool needs a record of what changed between versions. |
| `Cargo.toml` metadata | `repository`, `homepage`, `documentation`, `keywords`, `categories`, `readme`, `exclude`. Required for a credible crates.io listing. |
| Name availability | Confirm `scanr` is free on crates.io before committing to it. If taken, decide now rather than after publishing docs. |
| `cargo package` / `publish --dry-run` | Verify the crate builds from its packaged form, with `docs/` and `tests/` handled sensibly by `exclude`. |
| `cargo install --path .` | Never verified. The documented install path must work. |

**Exit criteria.** `cargo publish --dry-run` succeeds; `cargo install` from a clean
checkout produces a working binary; licence files match the declared SPDX expression.

**Effort:** half a day. **Needs from you:** the repository URL, and a decision on the
crate name if `scanr` is taken.

---

## Phase 1 — Wire up code that exists but never executes

This is the most important phase, because it is the difference between a documented
capability and a real one.

### 1.1 Resource-pressure diagnostics are unreachable

`diag::ResourceProblem` classifies `EADDRNOTAVAIL` and `EMFILE` and produces
host-specific remediation text. It has tests. **It is never called outside its own
module.** The JSONL spec lists `ephemeral_pressure` and `fd_pressure` warning codes that
cannot currently occur.

The consequence is specific and bad: ephemeral port exhaustion is the single most likely
real-world failure of a proxied scan, the tool already recognises it in
`probe::classify_os_error`, and the remediation that would tell the operator what to do
never reaches them. They get a scan full of `error` results and a reason string.

**Do:** on the first occurrence of each resource problem in a scan, emit a
`scan_warning` carrying the remediation, and surface it once on stderr. Rate-limit to
one warning per code per scan so a saturated host does not produce 50,000 of them.

Deliberately *not* doing adaptive concurrency reduction. The brief's instinct was right:
clear limits and excellent diagnostics beat hidden automatic tuning, and adaptive
behaviour is unfalsifiable in a record.

### 1.2 Build provenance is documented but absent

`scan_started` is specified with `git_commit`, `rustc`, and `hostname`. It emits none of
them. For a tool whose value proposition is a forensic record, "which build produced
this file" is not optional.

**Do:** a small `build.rs` capturing git SHA and rustc version into `option_env!` — no
dependency needed. Add `hostname` via `libc::gethostname`. Surface the same in
`--version`.

### 1.3 Spec drift needs a test, not vigilance

`fidelity_measured_at` is specified and never emitted, and is now semantically wrong
anyway: fidelity is declared in config, not measured at scan time. Replace it with
`fidelity_source` (`config` or `unmeasured`).

**Do:** add a conformance test that runs a scan and asserts every field the JSONL spec
documents is actually present, including nested ones. Drift in either direction should
fail the build. I found this drift with an ad-hoc script; that should be a test.

**Exit criteria.** Every warning code in the spec is reachable and has a test that
triggers it. Every documented field is emitted, enforced by a test. `--version` reports
the commit it was built from.

**Effort:** 1–1.5 days.

---

## Phase 2 — CI, so today's guarantees survive tomorrow

Every claim in the README currently holds on one machine, verified by hand.

**Do:**
- GitHub Actions on push and PR: `fmt --check`, `clippy --all-targets -D warnings`,
  `test` on `x86_64-unknown-linux-gnu` **and** `x86_64-unknown-linux-musl`, and an MSRV
  job pinned to the declared `rust-version = 1.97`.
- `-D warnings` specifically. An unused-variable warning slipped into two commits during
  this session and I only caught it by reading build output.
- A release workflow: tag → build both targets → `sha256sum` → attach to a GitHub
  release with the changelog section.
- `cargo-deny` or at minimum `cargo audit` for advisory and licence checks on the
  dependency tree.

**Exit criteria.** A green pipeline on a clean clone; a tag produces downloadable,
checksummed static binaries without manual steps.

**Effort:** 1 day. **Needs from you:** a GitHub remote (there is none configured).

---

## Phase 3 — Close the remaining evidence gaps

Ordered by how likely each is to embarrass the tool in front of a stranger.

### 3.1 Proxy matrix (highest value)

Confirmed so far: **microsocks** (`full`) and **OpenSSH `ssh -D`** (`open_only`, no
reply at all). Still unverified: **dante**, **3proxy**, and any commercial rotating
pool.

That last one matters because the `Collapsing` fixture models a proxy answering `0x01`
for everything, and *no real software has been observed doing this* — `ssh -D` turned out
to do something different. The README now says only "some proxies do this", which is
honest but weak. Either confirm it against something real or reconsider whether that
fixture models anything.

**Do:** run `transport test` against dante and 3proxy, capture raw bytes, and publish a
fidelity table in the transport guide. Add a `--known-open` fallback chain, because a
proxy that refuses to connect to itself as loop prevention will currently fail
calibration and look broken.

**Needs from you:** access to a commercial pool, if you have one. dante and 3proxy I can
build locally.

### 3.2 IPv6 has never executed

The code handles IPv6 literals, CIDRs, and `ATYP_IPV6` in SOCKS5. **Not one IPv6 probe
has ever run.** Only the `/112` prefix guard is tested. For a tool whose failure mode is
silently misreporting reachability, an entire untested address family is a real risk.

**Do:** integration tests scanning `::1` directly and through a SOCKS5 proxy, exercising
the `ATYP_IPV6` request path, plus IPv6 CIDR expansion end to end.

### 3.3 Scale has never been exercised

Largest runs to date: 60,000 probes on loopback (0.44s) and a 51,200-probe scan that was
deliberately interrupted. Never validated: sustained multi-hour operation, memory
stability over millions of probes, writer throughput at volume, resulting file sizes,
ETA accuracy, or the 1-host × 65,535-port case end to end.

**Do:** one ≥10⁶-probe run against a controlled target set, recording RSS over time,
probes/sec, output size, and whether `verify` still passes. Then decide whether gzip
output (currently deferred) is needed.

### 3.4 Proxy saturation and the default concurrency

`proxy` defaults to 512 concurrent. My own test proxy fell over at 64 against blackholed
destinations. This is the most likely first-contact failure, and it currently looks like
a scanr bug rather than proxy saturation.

**Do:** deliberately over-drive a real proxy; confirm the failure is legible now that
1.1 emits pressure warnings; then decide whether the default should drop to 128–256, or
whether `proxy-careful` should become the default for SOCKS5 transports.

**Exit criteria.** A published fidelity table covering four real proxies; IPv6 tested on
both transports; one million-probe run with stable memory and a passing `verify`; a
defended default concurrency.

**Effort:** 2–3 days, some of it wall-clock waiting.

---

## Phase 4 — Fuzz the untrusted parsers

`scanr` parses bytes from a proxy it does not control. A hostile or broken proxy is
directly in the threat model, and the SOCKS5 reply parser handles attacker-influenced
length fields (`ATYP_DOMAIN` carries a caller-supplied length). Current coverage is
hand-written malformed cases, which cover what I thought of.

**Do:** `cargo-fuzz` targets for the SOCKS5 reply parser, the TOML config path, and the
target/port spec parsers. Run each to saturation, fix findings, and commit a seed corpus
so CI can replay it cheaply.

**Exit criteria.** No crashes or hangs after a sustained run per target; corpus checked
in; a short CI job replaying it.

**Effort:** 1–2 days.

---

## Phase 5 — Documentation for someone who is not me

README covers quick start and the fidelity model well. Missing everything else the
design brief listed.

**Do:**
- **Configuration guide** — the annotated template is good, but a narrative guide for
  layering, precedence, and secrets is not the same thing.
- **Transport guide** — including the Phase 3.1 fidelity table and what each proxy type
  costs you.
- **Output schema reference** — consumer-facing, distinct from the internal spec, with a
  stability statement and worked `jq` examples.
- **Troubleshooting** — keyed to the actual diagnostics: `EADDRNOTAVAIL`, `EMFILE`,
  proxy saturation, unmeasured fidelity, DNS mode surprises.
- **Performance tuning** — the ephemeral-port ceiling, `SO_LINGER`, why concurrency is
  not monotonic, glibc vs musl.
- **Security considerations** — trust boundaries, what SOCKS5 auth does and does not
  protect, DNS leakage, credential handling, authorization.
- **Man page** via `clap_mangen`, and completion installation instructions per shell.

**Exit criteria.** A reader can go from install to a verified record, and diagnose the
three most common failures, without opening the source.

**Effort:** 1–2 days.

---

## Phase 6 — Polish that real use will prioritise

Deliberately last, because guessing here is wasteful.

- `output remainder --exact` emitting `host:port` pairs. The record already contains
  every probed pair, so exact resumption is derivable; target-granularity is a
  self-imposed limitation that re-probes completed ports.
- `--exit-nonzero-on-empty` for pipeline use.
- Progress ETA quality over long runs.
- `config show` is thin compared to the rest of the CLI.

---

## Explicitly deferred past first release

Windows and macOS · HTTP CONNECT · SSH-native transport · proxy chains · multiple
proxies per scan · adaptive concurrency · UDP and SYN scanning · library/API surface ·
plugins.

Each is recorded in the decision register with a revisit trigger. The tool's value is
that it is narrow; this list is the mechanism for keeping it so.

---

## Versioning recommendation

**Release as `0.1.0`, not `1.0.0`.**

The README already promises the JSONL schema is additive-stable at `schema_version 1`.
That is a promise worth keeping, and it should not be hardened into a semver-1.0
commitment until at least one external consumer has actually parsed a record and told us
what is missing. Ship `0.1.x`, invite schema feedback explicitly, and reserve `1.0.0`
for after the format has survived contact with someone else's tooling.

---

## Definition of done for the first release

- [ ] Licence files present and matching the declared SPDX expression
- [ ] `cargo install` and `cargo publish --dry-run` both verified
- [ ] Every warning code in the spec is reachable and tested
- [ ] Every documented JSONL field is emitted, enforced by a conformance test
- [ ] `--version` and `scan_started` carry the commit the binary was built from
- [ ] CI green on gnu + musl with `-D warnings`, plus an MSRV job
- [ ] Tagging produces checksummed static binaries automatically
- [ ] Fidelity table published for at least four real proxies
- [ ] IPv6 exercised on both direct and SOCKS5 paths
- [ ] One ≥10⁶-probe run with stable memory and a passing `verify`
- [ ] Fuzz targets clean, corpus committed
- [ ] Documentation set complete; man page installed
- [ ] Default concurrency defended by a measurement, not inherited from a guess

---

## What I cannot do without you

| Item | Needs |
|---|---|
| CI and release automation | A GitHub remote; none is configured |
| Commercial pool fidelity | Access to a real rotating proxy service |
| Million-probe validation | A target range you are authorized to scan at that scale |
| Crate name | Confirmation, or an alternative if `scanr` is taken |

Everything else — Phase 0, 1, 4, 5, the dante/3proxy matrix, IPv6, and the local half of
Phase 3 — I can do from here.
