# Milestone Plan

Ten milestones, reordered from the sixteen in the original brief. The tool is runnable
end-to-end from M3 onward; everything after that adds capability without a rewrite.

---

## M0 — Feasibility probe (throwaway code)

**Scope.** The thread-pool load test in `02-runtime-evaluation.md`, on glibc and static
musl. Plus the empirical `ssh -D` SOCKS5 reply-code test against local `sshd`.

**Acceptance.** All five pass criteria met, or a documented decision to adopt mimalloc
on musl / fall back to Tokio. `ssh -D` fidelity recorded in the decision register.

**Risk.** This is the one milestone that can invalidate D1. Doing it first is the point.

**Done when.** Numbers are in `docs/design/02-runtime-evaluation.md` and D1 is either
confirmed or revised. Probe code is deleted, not merged.

---

## M1 — Config: types, discovery, merge, validation, provenance

**Scope.** Serde types for the full schema. Two-file discovery with upward search.
Per-key merge. The field-metadata table that drives validation, the override allowlist,
and `config init` annotations from one source. Caret-span error rendering.
`scanr config init|show|validate|path`.

**Tests.** Deserialization of every field · unknown-key rejection with suggestions ·
precedence across all seven layers · per-key vs whole-array merge · duration parsing ·
credential redaction in every output path · inline-password rejection ·
`password_file` permission check · undefined-reference detection.

**Done when.** `config validate` catches every case in the validation list, and
`config init` output round-trips through `config validate` clean.

---

## M2 — Targets, ports, plan

**Scope.** Target parsing (literal, CIDR v4/v6, range, hostname, file, stdin), port
parsing, exclusion, de-duplication, the IPv6 `/112` guard. The Feistel permutation.
`ScanPlan` as an immutable resolved object. `scanr plan`.

**Tests.** CIDR expansion boundaries (`/31`, `/32`, `/0` refused) · range parsing ·
exclusion after expansion · dedup across overlapping includes · IPv6 guard ·
**permutation is a bijection over N for N ∈ {1, 2, 255, 65536, 255510} and is stable
across runs for a fixed seed** · plan projection arithmetic · provenance rendering.

**Done when.** `scanr plan internal-web` produces the output in `06-cli-spec.md`,
including both warnings, with no network activity.

---

## M3 — Direct transport, scheduler, human output

**Scope.** `Transport` trait, `direct` implementation with `SO_LINGER {on,0}`, the
thread pool, cancellation flag, token-bucket rate limiter, streaming stdout with TTY
detection. First runnable end-to-end scan.

**Fixtures.** In-process TCP servers: accepting, refusing, delayed-accept, silent
blackhole, reset-after-accept.

**Tests.** Each fixture classifies correctly · concurrency never exceeds the cap ·
rate limiter holds within 5% over 10s · no probe lost or duplicated across a full
matrix · TTY vs pipe output formatting.

**Benchmark.** 1 host × 65,535 ports and 256 × 100 against local fixtures.

**Done when.** `scanr run --targets 127.0.0.1 --ports 1-65535` is correct and the
counts reconcile exactly.

---

## M4 — JSONL writer

**Scope.** Writer thread, bounded channel, sequencing, all seven event types, flush
policy, `.partial` → `.jsonl` rename, writer-failure handling.

**Tests.** Sequence monotonic under concurrent workers · exactly one terminal event ·
nothing after it · counts reconcile with observed rows · credentials absent from the
file (grep the whole file for the secret) · `ENOSPC` simulated via a small tmpfs
produces exit 3 and leaves `.partial` · killing the process mid-scan leaves `.partial`.

**Done when.** `scanr output verify` passes on a natural run and correctly fails on
each corruption case.

---

## M5 — Interruption

**Scope.** SIGINT handling, bounded drain, `scan_interrupted`, second-signal immediate
exit, exit code 130.

**Tests.** Ctrl-C mid-scan produces a valid finalized file with accurate
`not_started` · drain latency within `connect_timeout + 250ms` · second signal exits
promptly · `.partial` is renamed on graceful interrupt.

**Done when.** Interrupting a 250k-probe scan leaves a file that `verify` accepts and
that accounts for every planned probe.

---

## M6 — SOCKS5

**Scope.** RFC 1928 CONNECT + RFC 1929 auth, written directly. Per-phase timing.
Reply-code → state mapping. `Fidelity`. `scanr transport test`.

**Fixtures.** In-process SOCKS5 server with injectable behaviour: success, each reply
code, auth required/accepted/rejected, no-acceptable-methods, disconnect at each
handshake phase, truncated reply, oversized domain length, wrong version byte, slow
byte-at-a-time reply.

**Tests.** Every fixture behaviour · malformed input never panics · credentials never
logged · `transport test` correctly reports `full` for a well-behaved fixture and
`open_only` for one that collapses to `0x01` · transport DNS passes the hostname
unresolved and no local DNS query occurs.

**Done when.** A proxied scan through the fixture produces correct results and
`transport test` reports fidelity accurately for both fixture modes.

---

## M7 — DNS, retries, diagnostics

**Scope.** `auto`/`transport`/`local`/`disabled`, multi-A expansion on the direct path,
the transport-switch warning. Timeout retry with merged records. The `diag` module:
sysctl and rlimit inspection, `EADDRNOTAVAIL` and `EMFILE` classification with
remediation, pressure warnings.

**Tests.** Each DNS mode · `disabled` rejects hostnames at plan time · multi-A expands
on direct and not through proxy · retry merges into one record with correct
`attempt_states` · descriptor exhaustion under a lowered `RLIMIT_NOFILE` produces the
diagnostic, not a generic error.

---

## M8 — Output commands

**Scope.** `summarize`, `verify` (full check list), `remainder`.

**Tests.** `remainder` output of an interrupted scan, fed back through `run`, probes
exactly the missing set · `verify` detects each corruption class.

---

## M9 — Profiles, docs, packaging

**Scope.** The four built-in profiles. Full documentation set. Static musl release
build, shell completions, CI (fmt, clippy, test, both targets), benchmarks.

**Done when.** A user can go from `config init` to a verified result file using only
the docs, and the Definition of Done list in the original brief is satisfied
item by item.

---

## Sequencing rationale

Config and plan come before any networking because `plan` is the artifact that makes
everything else reviewable — it is testable with zero I/O and it forces the resolution
and provenance model to be correct before anything depends on it. Direct transport
precedes SOCKS5 so the scheduler is proven against a trivial transport first. JSONL
precedes interruption because interruption is defined in terms of what it writes.
