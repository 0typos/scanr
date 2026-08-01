# Decision Register

Status values: `proposed` · `accepted` · `rejected` · `deferred`

Decisions D1–D18 were settled during the 2026-07-29 discovery session.

---

### D1 — I/O model: blocking sockets on a bounded thread pool
**Status:** accepted · **Alternatives:** mio, Tokio, smol, io_uring

**Rationale.** Target concurrency is 500–5,000 (see D2). SOCKS5 is the primary path,
and a handshake is a 2–3 round-trip request/response exchange — straight-line code when
blocking, a resumable partial-read/write state machine under any readiness-based loop.
`std::net::TcpStream::connect_timeout` already *is* this tool's core primitive, and
`set_read_timeout`/`set_write_timeout` give per-phase timeouts and per-phase measurement
for free. I/O dependency footprint is effectively zero.

**Consequences.** Cancellation latency is bounded by the longest outstanding timeout,
not instant. Hard ceiling around 10k threads. musl's `mallocng` contends badly under
many threads (see D17). Thread stacks set explicitly to 64 KiB.

**Revisit trigger.** Feasibility probe (M0) fails its bar, or sustained concurrency
requirement exceeds ~10k. Fallback is Tokio — the port is largely mechanical
(`std::net` → `tokio::net`, add `.await`), which is why this is the cheapest choice to
be wrong about.

**M0 result (measured 2026-07-29): CONFIRMED with wide margin.**

| metric | bar | measured |
|---|---|---|
| RSS at 5,000 threads | < 500 MiB | **40.6 MiB** |
| RSS at 10,000 threads | — | 81 MiB |
| Sustained rate, local accepting listener | >= 5,000/s | **68,949/s** |
| Ctrl-C drain latency (2s connect timeout) | <= 2.25s | 838 ms |
| Spawn cost, 10,000 threads | — | 227 ms, paid once |

Two findings beyond the pass criteria. Throughput at 2,048 threads (62,805/s) was
*lower* than at 512 (68,949/s), so concurrency is exposed as a tunable and documented as
non-monotonic rather than something to maximize. And end-to-end on the finished binary,
60,000 probes against loopback completed in 0.44–0.49s (~128,000 probes/s), well beyond
what any proxied scan can consume.

### D2 — `mio` rejected
**Status:** rejected

Two discovery answers dominated it. **Linux-only** removes its purpose as a portable
readiness abstraction — on Linux it is a thin safe `epoll` wrapper, and it ships no
timer facility at all, so a timer wheel, signalfd integration, and partial-IO state
machines would be hand-written regardless. **SOCKS-primary** makes the state-machine
cost apply to the dominant code path rather than an exotic one. It costs the most of
the three options and its distinguishing benefit does not apply here.

### D3 — Platform: Linux x86_64 first; macOS builds and is tested, Windows deferred
**Status:** accepted · **amended:** macOS was deferred, then turned out to cost one call

Windows stays deferred: it removes IOCP, console control events and a third CI matrix
from v1 entirely.

macOS was deferred with it, on the assumption that supporting it meant kqueue and a
cross-platform rewrite. That was wrong — there is no event loop to port, because the I/O
model is blocking sockets on threads (D1). Compile-checking `aarch64-apple-darwin`
turned up exactly **one** error: `libc::getrandom` does not exist on Apple platforms,
which have `getentropy` instead. Both spellings behind a `cfg`, and both Apple targets
build.

A `macos-latest` CI job now runs clippy and the full suite, so this is a tested claim.
What macOS does *not* get is the host diagnostics: `ephemeral_range` and `tcp_tw_reuse`
are read from `/proc`, so they report as unknown and the `ephemeral_budget` warning
cannot fire. `RLIMIT_NOFILE` still works, so the `fd_budget` warning does — which matters
there, because macOS defaults that limit to 256, well below the default concurrency.

Linux remains the platform the performance numbers are measured on and the only one with
a static musl build.

### D4 — SOCKS5 only; SOCKS4 and SOCKS4a dropped from v1
**Status:** accepted

SOCKS4 defines four reply codes (`0x5A` granted, `0x5B` rejected-or-failed, `0x5C`/`0x5D`
identd) and cannot distinguish closed from filtered under any circumstance. Dropping
4/4a removes two protocol implementations, two fixture servers, and a permanent
fidelity mismatch in the result schema.

### D5 — SOCKS5 implemented directly, no crate
**Status:** accepted

CONNECT with optional username/password auth (RFC 1928 / RFC 1929) is a few hundred
lines. Writing it directly gives exact control over reply-code mapping — which is
load-bearing for D8 — plus precise per-phase timing and auditable credential handling.

### D6 — One proxy per scan
**Status:** accepted · multi-proxy and chains deferred

The scheduler enforces a single global concurrency limit. No per-transport-instance
binding, no mid-scan proxy failover. Multi-proxy remains addable without reworking the
transport seam.

### D7 — Result states: `open` / `closed` / `filtered` / `error`
**Status:** accepted · **Alternative rejected:** the 12-state taxonomy in the original brief

Four public states, plus a structured `reason` and a `source` field recording whether
the classification came from the local stack or a proxy reply byte. Most of the 12
states would be permanently unreachable through a proxy, producing a schema that lies
by omission.

### D8 — Transport fidelity is measured and declared, not assumed
**Status:** accepted

`scanr transport test` connects through the configured proxy to a known-open port, a
known-closed port, and a blackhole, then reports which reply codes came back — i.e.
whether this proxy can distinguish closed from filtered at all. The measured fidelity
is declared in config (see `../configuration.md`) and recorded in the scan config event.

**Measured against real software (2026-07-29), by capturing raw bytes:**

| proxy | open | refused | blackholed | verdict |
|---|---|---|---|---|
| microsocks 1.0 | `05 00 …` | `05 05 …` | no reply, timeout | `full` |
| OpenSSH `ssh -D` | `05 00 …` | **no reply, channel closed** | no reply, timeout | `open_only` |

This **corrected an assumption**. The earlier documentation claimed `ssh -D` collapses
failures into `0x01 general failure`. It does not — it sends no SOCKS5 reply at all and
closes the channel, while its own client log records
`channel N: open failed: connect failed: Connection refused`. OpenSSH knows the reason
and has no way to express it in its SOCKS5 layer. The conclusion (`open_only`) was
right; the stated mechanism was wrong, and the docs now describe what was observed.

Also confirmed empirically: the `BND.ADDR` in a successful `ssh -D` reply is
`0.0.0.0:0`, which is direct evidence for D15 — a proxied hostname target genuinely
cannot record which address was probed.

**End-to-end validation.** The same 16 ports scanned three ways: direct and microsocks
produced *identical* states on all 16; through `ssh -D` the 4 open ports agreed exactly
and the 12 non-open became `error` carrying "proxy closed the connection while reading
CONNECT reply". No `closed` was ever fabricated.

### D9 — Probe sockets close with `SO_LINGER {on, 0}`
**Status:** accepted

Sends RST instead of FIN, skipping `TIME_WAIT` on our side. With one proxy per scan
every probe is a connection to the *same* socket address, so only the source port
varies: the default ephemeral range (`32768–60999` = 28,232 ports) against a hardcoded
60s `TCP_TIMEWAIT_LEN` caps sustained throughput at **~470 probes/sec** to a remote
proxy. This box has `tcp_tw_reuse = 2` (loopback-only, the default since ~2019), which
covers local proxies but not remote ones.

We have already extracted the answer from `connect()` and have no data to flush, so RST
close costs nothing functionally. Costs: some proxies log RSTs as errors; marginally
more detectable.

**Note:** `TcpStream::set_linger` is still unstable (rust#88494, verified on 1.97.1), so
this requires `socket2`.

**M0 result: the highest-leverage decision in the design, by a wide margin.** Measured
at a **7.5x sustained-throughput multiplier** — 9,189 probes/s without it versus 68,949
with — and TIME_WAIT accumulation over a five-second run fell from **21,931 sockets to
1**. Against a 28,232-port ephemeral range, the no-linger path was on course to exhaust
local ports in roughly seven seconds against a remote proxy.

### D10 — Retry timeouts once, emit one merged record
**Status:** accepted

Through a proxy a timeout is ambiguous between slow-proxy and filtered-destination; one
retry disambiguates the common case. The record carries `attempts` and `attempt_states`
so forensic detail survives while row count still equals probe count.

### D11 — JSONL records every probe outcome
**Status:** accepted

Full fidelity. A 256×1000 scan is ~256k lines / tens of MB. Makes "what was never
probed" derivable, which is what enables D12.

### D12 — No `resume`; `scanr output remainder` instead
**Status:** accepted · **Alternative rejected:** resume as specified in the original brief

Resume is semantically murky under DNS churn and changed profiles. "The set of probes
that never ran" is just a target list, so emitting it and piping it back gives
resume-by-composition with zero schema commitment.

**Amended.** The original implementation emitted whole targets, so resuming re-probed
ports that had already completed — which meant the claim above was not quite true, and
the argument for dropping `resume` was weaker than it read. The record contains every
probed pair, so the exact remainder was always derivable; only a way to express it was
missing. `remainder` now emits `host:port` endpoints and `run --pairs` consumes them.

A pair scan is the one case where an expanded list *is* embedded in the record, because
an explicit endpoint list has no compact spec. Bounded at 50,000, beyond which
`pairs_truncated` is set and `remainder` refuses rather than answering wrongly.

`abandoned` probes are included in the remainder: they were issued but never reported, so
whether they reached the network is unknown, and re-probing is the safe default.

### D13 — Config: user-level + project-local, project wins
**Status:** accepted

`~/.config/scanr/config.toml` for transports and credentials; `./scanr.toml` for scan
definitions, version-controlled. Precedence in `../configuration.md`.

### D14 — Credentials: no inline passwords, ever
**Status:** accepted · stricter than the original brief, which specified a warning

Only `password_env` and `password_file` are accepted. An inline `password` key is a
hard validation error naming both alternatives. Project config is expected to be
committed; a warning is not sufficient protection.

### D15 — DNS mode `auto` — transport when supported, local otherwise
**Status:** accepted, with mitigation

Through SOCKS5 the proxy resolves, and the reply's `BND.ADDR` is the proxy's bound
address, *not* the destination IP — so proxied hostname targets can never record a
resolved address, and multi-A-record expansion is impossible. Direct scans can do both.
The same config therefore behaves differently across transports.

**Mitigation:** `plan` prints the effective mode; each `target_resolved` event records
which mode applied; switching transports on a config containing hostnames warns.

### D16 — Probe order: seeded keyed Feistel permutation
**Status:** accepted

Randomized order across the whole matrix, but an in-memory shuffle costs ~520 MB for a
/16 × 1000 matrix. A 4-round Feistel network over the next power of two ≥ N, with
cycle-walking to skip out-of-range outputs, gives O(1) memory, streaming random order,
and exact reproducibility from the recorded seed.

### D17 — Single crate, not a workspace
**Status:** accepted · **Alternative rejected:** the 7-crate layout in the original brief

No dependency isolation, platform separation, or independent-reuse boundary currently
justifies it. Modules provide the same organization without the coordination cost.
Revisit if a library API becomes a goal.

### D18 — Dependency posture: pragmatic
**Status:** accepted

Well-maintained crates where they earn their place; SOCKS5 and the permutation written
directly. Per-crate rationale in `architecture.md`.

---

## Deferred / open

| Item | Status | Note |
|---|---|---|
| `ssh -D` reply-code fidelity | open | Needs a real `ssh -D` forward; `transport test` now measures it directly |
| musl allocator under many threads | accepted as-is | See D19 |
| gzip output | deferred | Revisit if files exceed ~1 GB |
| Progress rendering on stderr | proposed | Interval-based, TTY-only |
| Profile inheritance | rejected for v1 | Flat, complete profiles only |
| `per_target_concurrency` | rejected | With a proxy the shared resource is the proxy |
| IPv6 prefix expansion | accepted w/ guard | Refuse prefixes shorter than /112 absent opt-in |

### D19 — musl ships without an allocator swap, despite exceeding the M0 bar
**Status:** accepted · **Alternative rejected:** mimalloc / snmalloc for musl builds

**Measured (2026-07-29).** 60,000 probes against loopback, concurrency 1024, three runs
each on the same source revision:

| build | wall | throughput | RSS |
|---|---|---|---|
| glibc | 0.44 / 0.45 / 0.49 s | ~128,000 probes/s | 12.4 MB |
| musl | 0.83 / 0.76 / 0.84 s | ~75,000 probes/s | 8.7 MB |

musl is **~1.7x slower**, which exceeds the "< 25% delta" pass criterion set in the M0
plan. The stated remediation was to adopt mimalloc for musl builds. We are not taking
it, deliberately:

* mimalloc and snmalloc are C/C++ and require a musl-targeting C toolchain, which would
  destroy the property that makes the musl build worth having — a fully static
  `static-pie` binary produced by `cargo build --target x86_64-unknown-linux-musl` with
  no system dependencies.
* The delta is unobservable in the workload this tool exists for. 75,000 probes/s is
  roughly 15x above what a proxied scan can reach; `ssh -D` sustains low hundreds and a
  self-hosted daemon low thousands. The gap only appears on a loopback microbenchmark
  where neither the network nor a proxy is the bottleneck.
* musl uses *less* memory (8.7 MB vs 12.4 MB at the same concurrency).

**Consequences.** Documented in the README so the tradeoff is visible rather than
implicit. glibc is the better choice when you control the host; musl when portability
matters.

**Revisit trigger.** A workload where scanr itself is the bottleneck — realistically
only large direct LAN scans. If that appears, revisit with a pure-Rust allocator so the
static build survives.

### D20 — Config errors redact credentials in the source line they point at
**Status:** accepted

Caught by an end-to-end test rather than by review: the caret renderer echoes the
offending source line, so an error about an inline `password = "hunter2"` printed the
secret to stderr while rejecting it. Redaction now happens inside `ConfigError::render`
rather than at each call site, so no future error can leak a credential by forgetting to
handle it.

### D21 — SIGXFSZ is ignored so a write failure is reported, not fatal
**Status:** accepted

Exceeding `RLIMIT_FSIZE` raises `SIGXFSZ`, which by default kills the process. For a
tool whose central guarantee is that the record always says what happened, dying from a
signal is the worst possible outcome: no terminal event, no diagnostic, no exit code.
Ignoring it makes the write fail with `EFBIG` instead, which the writer already handles
by reporting the failure and leaving a `.partial` file. Same reasoning as `SIGPIPE`.

This is also what made the writer-failure path testable without root: capping
`RLIMIT_FSIZE` in a forked child is the closest reachable analogue of a full disk.

### D22 — Column padding is computed from visible width, never from format width
**Status:** accepted

Two alignment defects survived 278 tests because every test rendered to a pipe, where
the aligned path never runs. Rendering on a real pty showed both immediately:

* ANSI escapes inflate `str::len`, so `{:>9}` applied to a coloured latency silently
  stopped right-aligning.
* A service label wider than its 10-column field (`elasticsearch` is 13,
  `kube-apiserver` is 14) shifted every following field on that row only.

Padding is now applied explicitly from the plain text width, with colour added after the
layout is decided. Tests strip escape sequences and assert that visible column offsets
match across rows with and without colour and with labels of every length.

**Lesson worth keeping:** a formatter that is only ever exercised through a pipe is an
untested formatter. The `is_terminal()` branch needs a pty to reach.

### D23 — Proxy fidelity measured against four real implementations
**Status:** accepted · supersedes the assumptions in D8

Built and measured against real software rather than fixtures, capturing raw bytes.

| proxy | refused destination | blackholed | fidelity |
|---|---|---|---|
| microsocks | `0x05` | no reply, timeout | **full** |
| dante (sockd 1.4.3) | `0x05` | `0x01` | **full** |
| 3proxy | `0x05` | no reply, timeout | **full** |
| OpenSSH `ssh -D` | **no reply**, channel closed | no reply, timeout | **open_only** |

**Three assumptions were wrong.**

1. The `Collapsing` fixture models a proxy answering `0x01` for everything. **No real
   proxy tested does this.** The genuinely awkward case is OpenSSH answering *nothing*.
   dante uses `0x01` only for an unreachable destination, which is defensible.
2. Using the proxy's own listening socket as the known-open calibration target fails on
   **half** the proxies tested: dante refuses it by ruleset (`0x02`) and 3proxy answers
   `0x09`, which is not even a defined RFC 1928 code. Both are in fact `full`, and a
   naive calibration reported `unknown` for both. Fixed by binding our own listener when
   the proxy is on loopback.
3. `ssh -D` was expected to be the weakest under load. It handled concurrency 512 with
   zero loss, as did microsocks.

### D24 — Default concurrency stays at 512; the proxy's cap is the real constraint
**Status:** accepted · **Alternative rejected:** lowering the `proxy` default

Measured loss against 64 blackholed targets × 4 ports, sockets held ~2s:

| proxy | c=16 | c=24 | c=32 | c=48 | c=64 | c=256 | c=512 |
|---|---|---|---|---|---|---|---|
| microsocks | 0% | — | 0% | — | 0% | 0% | 0% |
| `ssh -D` | 0% | — | 0% | — | 0% | 0% | 0% |
| 3proxy, default `maxconn 100` | 0% | 0% | 7% | 37% | 48% | 95% | 80% |
| 3proxy, `maxconn 2000` | 0% | — | 0% | — | 0% | 0% | 0% |

The binding constraint is the proxy's own configured cap, not scanr's concurrency. The
same 3proxy binary loses nothing at 512 once `maxconn` is raised. Lowering scanr's default
cannot rescue a proxy capped at 100 — that configuration fails from concurrency 32 — while
it would slow the three proxies that handle 512 cleanly.

So no default is defensible as "the safe number". Instead the cap is made **visible**
(the `proxy_saturation` warning now fires, D-register/Phase 1) and **measurable**
(`transport test --calibrate`).

**Revisit trigger.** Evidence that a common proxy deployment fails at 512 for reasons
*other* than an explicit connection cap.

### D25 — Proxy capacity is measured by churn, not by a burst
**Status:** accepted · **Alternative rejected:** counting a simultaneous connection burst

The first implementation opened 64 simultaneous connections and counted acceptances. It
reported **64/64 for every proxy**, including the 3proxy configuration measured above as
losing 48% at concurrency 64. Useless, and worse than useless: it was false reassurance
of exactly the kind this project keeps trying to avoid.

The failure is churn-driven. 3proxy accepts 64 connections held open without complaint,
but holds *closed* connections in its table long enough that a scanner continuously
opening new ones exceeds the cap. Reproducing that needs repeated rounds, not one burst.

`--calibrate` now sweeps concurrency with four rounds per worker against a hanging
destination. It is deliberately conservative — it clears 16 where a real scan tolerated
24 — and worded as "what this test observed", not "the maximum safe value". Opt-in,
because it generates real traffic.

### D26 — Scale validated at 10^6 probes; gzip deferred, then adopted
**Status:** accepted · gzip **no longer deferred — shipped as `--compress`, see D28**

Measured on loopback, which is the only place a million-probe scan can be run without
authorization concerns — all of `127.0.0.0/8` is locally routable, giving 16.7M addresses.

| scan | probes | wall | rate | peak RSS | record |
|---|---|---|---|---|---|
| 1 host × all 65,535 ports | 65,535 | 0.42 s | ~156,000/s | 8.3 MB | 24 MB |
| /16 × 16 ports | 1,048,576 | 69 s | ~15,200/s | 17.0 MB | 377 MB |

**Memory is stable.** Sampled every second across the 69-second run: 5.8 MB at start,
17.0 MB peak, 17.0 MB at the end. The growth is the materialized target list (65,536
entries), allocated once, not drift. `output verify` passes on the 1,048,576-probe record.

Two things learned that are not about scanr:

* A service bound to `0.0.0.0` answers on *every* address in `127.0.0.0/8`, so 56,427 of
  the "open" results were port 22 on one sshd. Correct, and worth documenting because it
  makes loopback a poor proxy for "many distinct hosts".
* Hammering a real local service that hard produces genuine timeouts — 9,109 filtered and
  20,835 retries came from sshd's accept backlog overflowing, not from scanr.

**On gzip.** The record compresses **16.8×** (377 MB to 23.6 MB in 1.5 s), because the
lines are near-identical. That is a strong ratio, and it makes built-in compression more
attractive than when it was deferred with no numbers. Still deferred: it complicates
streaming durability and post-hoc inspection, and `gzip` after the fact costs one command.

**Revisit trigger,** now concrete rather than vague: someone routinely scanning above
~10M probes, where records reach multiple gigabytes.

### D27 — The SOCKS5 handshake is fuzzed as a unit, not just its reply parser
**Status:** accepted

The reply parser was fuzzed from the start, but everything before it was not: the
greeting, method selection, and the RFC 1929 authentication exchange. Those carry more
state and are equally peer-controlled — the proxy picks the auth method, supplies the
status byte we act on, and may close or stall at any point.

Required making the handshake generic over its stream rather than tied to `TcpStream`,
which is a better shape regardless: it is now drivable from a test without a socket.

The harness varies whether credentials are configured, so the no-auth, username/password,
and username-without-password paths are all reachable from one corpus, and it refuses
writes past a bound so the "peer stopped reading" path is exercised too. It asserts more
than absence of panics: a failed handshake must never report `open`, and must always
carry a reason a human can read.

66 million executions, clean.

### D28 — Records are framed gzip by default, pure Rust

**Status:** accepted · **Alternatives rejected:** zstd; a single gzip stream
· **amended:** shipped opt-in, then made the default

D26 deferred compression with numbers. Reading a 374 MB record back turned out to cost
4.2 GB, and fixing that exposed how much of the file is pure redundancy, so it was taken.

* **Framed, not streamed.** One gzip member per 256 KiB or per critical-event flush.
  Concatenated members are valid gzip, so `zcat` and friends are unaffected, and a killed
  scan still decodes up to its last completed frame. A single stream would be unreadable
  past its start — paying for compression precisely when a `.partial` record matters most.
* **gzip, not zstd.** Measured on one genuine 12 MB record: gzip -6 20.1x, zstd -3 18.0x,
  zstd -9 22.4x, zstd -19 26.1x at 100x the time. About 11% at comparable speed. The
  mainstream `zstd` crate binds a vendored C library, and a musl C toolchain would destroy
  the static build (D19); pure-Rust zstd encoders exist but are young, and a compressor
  defect here means unreadable evidence. `flate2` on `rust_backend` keeps the tree free of
  C — verified: 0 `NEEDED` entries in the musl binary.
* **On by default (amended).** It shipped opt-in on the argument that a record is a text
  file people grep. That argument lost: `zcat`, `zless` and every `scanr output` command
  read a compressed record unchanged, so the default cost ~20x the disk for every user who
  never read the flag. `--no-compress` restores the plain form, and `plan` says which you
  are getting.

**Revisit trigger:** a widely-deployed pure-Rust zstd encoder, or span encoding landing
(which would beat any compressor on homogeneous scans by orders of magnitude).

### D29 — `ssh -D` gets its own profile family

**Status:** accepted · **Alternative rejected:** continuing to point `ssh -D` at
`proxy-careful`

Measured against OpenSSH 10.2p1 through a real `ssh -D` tunnel. `ssh -D` is not a normal
SOCKS5 proxy in three ways, and the proxy profiles get all three wrong:

* **Its listener is local.** `tcp_tw_reuse = 2` exempts loopback, so the ~470/s ephemeral
  ceiling behind `proxy`'s `rate = 400` does not apply. That cap was the entire cost:
  4,000 probes took **80 s** under `proxy-careful` (rate 50), **10 s** under `proxy`
  (rate 400), and **0.16 s** with the cap removed. Every probe was reported in all three.
* **The local legs are free.** SOCKS negotiation measured 0.4–0.5 ms, and a refused
  destination returns in 0.4 ms because the channel simply closes. Only silent hosts ever
  cost `connect_timeout`.
* **Concurrency saturates at ~128, then cliffs.** Flat at ~28,500 probes/s from 32 to 128;
  at 160 and above it drops to ~1,850. Three runs at each level. The cliff is a fixed ~1 s
  stall, not a slower rate — 2,000 / 4,000 / 8,000 probes at concurrency 160 all cost
  ~1.1 s — so it amortises on a large scan and dominates a small one. Nothing above 128
  buys throughput, so all three profiles stay below it and a test enforces that.

`ssh-fast` / `ssh` / `ssh-slow` raise concurrency as the link gets *slower*, which inverts
the usual instinct: in-flight work needed is roughly rate x RTT, so a longer round trip
needs more outstanding probes to stay busy, bounded by the cliff.

**Caveat:** measured on loopback, so it characterises the OpenSSH client rather than a
network. The cliff location may move with ssh version or server; the profiles sit well
below it for that reason.

### D30 — Bulk outcomes collapse into spans, by default

**Status:** accepted · **Alternatives rejected:** dropping derivable fields; excluding
every retried probe · **amended:** shipped opt-in, then made the default

Measured: the bulk rows of a large scan carry one distinct `(state, source, reason)`
tuple with timings inside 0.2% of the timeout. ~360 bytes per row to say "the timeout
fired". On the `/16 × 16` scan, `--spans` takes 391,618,401 B / 1,048,580 events to
**2,582 B / 5 events** — 151,000× — while `verify` and `remainder` return identical
answers and the scan runs marginally faster for writing less.

* **Not field-stripping.** Removing every derivable field was measured at 1.69×, and only
  1.37× on top of compression, for a schema break. Spans attack the row count instead.
* **Ranges over `probe_index`.** That index is the target-major position, so a consumer
  expands a span with arithmetic and the specs in `scan_config` — the permutation decides
  visit order, never the mapping, so the seed is not needed.
* **A retry that agreed is still bulk.** The first rule excluded every retried probe,
  which sounded careful and collapsed *nothing*: `retries = 1` is the default and applies
  to timeouts, so in a scan of silent hosts every probe is retried. A probe whose attempts
  *disagreed* is a flapping host and keeps its row.
* **On by default (amended).** It trades per-probe timestamps for size, and that is a
  real loss — but only for results that all said the same thing. `open`, `error`,
  pressured and disagreeing-retry probes always keep their rows, so what a reader reaches
  for is untouched while the default record goes from 391 MB to 2.6 KB. `--no-spans`
  restores a row per probe.

  The cost lands on consumers: `probe_result` no longer covers every probe, so a naive
  `jq 'select(.type=="probe_result")'` under-reports. Documented in
  `docs/output-schema.md` rather than left to be discovered.

**Bounded:** one bitset per outcome class, 128 KB per class per million probes, and above
64 classes it stops collapsing — a record that varied is not one spans can help.

**Consequence:** `probe_result` no longer covers every probe when spans are on. `verify`
reconciles rows plus span counts, validates each span's ranges, and `remainder` expands
them. `output.spans` in `scan_config` records whether it was used.

### D31 — Service labels are layered, and the record says which layer answered

`service_label` was a compiled-in table of 59 ports and nothing else. That made every
record reproducible and most records unhelpful: a port outside the 59 got `null`, and a
port inside it got the registry's opinion regardless of what was actually listening.

It now resolves through three layers, most specific first:

1. `defaults.services_file`, if the config names one
2. `/etc/services`, if it exists
3. the compiled-in table

First layer with an answer wins, so a two-line custom file still inherits everything
else. The custom file is the point of the change — an internal port map is the only
source that can say `internal-api` instead of `http-alt` — and `/etc/services` is there
because ~5,800 tcp entries beat 59 for free.

**What this costs.** Labels are no longer identical across machines: two hosts with
different `/etc/services` will label the same port differently, and the old table could
not do that. That is accepted rather than worked around, because the alternative is
worse labels everywhere to protect a property almost nothing depends on.

It is paid for with provenance. Every record's `config` event carries
`service_labels.layers` — each source, how many entries it contributed, how many lines
it could not parse — so a disagreement between two records is answerable from the
records. `plan` shows the same thing before a scan is spent.

**What this does not touch.** `state`, `source`, and `reason` are unchanged and remain
the fields anything automated should key on. `service_label` was already documented as a
guess from the port number rather than a fingerprint, and it still is: nothing connects
to the service or reads a banner. Better-sourced guessing is still guessing. Port 4444
is `krb524` to all three layers and is essentially never Kerberos.

**Failure handling** splits on who chose the path. A configured file that cannot be read
is fatal — naming a path that is not there is a mistake, and scanning with different
labels than were asked for is worse than stopping. A missing `/etc/services` is not an
error at all; "when it exists" is its whole contract, and containers routinely lack one.
Lines that do not parse are counted and reported as a plan warning, never fatal:
refusing a scan over a stray line in the system's own file would be absurd. UDP and SCTP
rows are skipped without being counted as malformed, since roughly half of a real
`/etc/services` is UDP and counting those would report the file as broken on every
machine.

The parser also accepts `nmap-services`, whose extra frequency column parses as an
alias. That was not a design goal, but it is the obvious file to reach for and it costs
nothing to allow.

**Amended: `use_etc_services`.** The reproducibility cost above is opt-out. Setting
`defaults.use_etc_services = false` drops the middle layer, leaving labels that depend
only on the config and the binary — identical on every machine, which is what a scan
compared across a Linux runner and a laptop wants. The configured file and the builtin
still apply, so it costs coverage rather than control.

Declining is recorded separately from the file simply being absent. Both leave the layer
out of `service_labels.layers`, but they are different situations — a container without
the file, versus a deliberate trade — so `service_labels.use_etc_services` states which,
and `plan` marks the row `[/etc/services off]`.

That distinction is also what makes the rendering testable. A first version of the test
asserted only that the marker appeared, and passed against a build that ignored the flag
entirely: the row read `/etc/services (5862) ... [/etc/services off]`, contradicting
itself, and nothing objected. The test now requires the marker *and* the layer's
absence, and fails without the fix.

**Amended: the accumulator is sparse, not a bitset.** Each outcome class originally held
one bit per planned probe, sized at the moment the class first appeared. That is
`planned / 8` bytes per class regardless of how many probes ever land in it: 8.2 MB each
for a 65M-probe scan, and ~200 MB each for a `/8 x 100`, which `--allow-large-range`
permits — against a 64-class ceiling, up to ~12 GB for a scan that had so far reported
sixty-four results. `Reported` in `run.rs` is the same shape and explicitly refuses to
allocate above `MAX_TRACKED_PROBES` for this reason; the span accumulator had no ceiling
at all, and spans are on by default.

Each class now keeps a plain list of the indices it absorbed. Draining on every progress
tick — added so a killed process keeps its spans — is what makes this the better shape
anyway: a class only ever holds one interval's worth of probes, so memory follows
throughput rather than scan size. It beats the bitset whenever an interval absorbs fewer
than `planned / 64` probes, which at any real scan rate it does by orders of magnitude.

Probes complete out of order, so the list is sorted at drain time and deduplicated. The
dedup preserves an invariant the bitset gave for free: a span's `count` is the number of
endpoints its ranges cover, which is what a consumer expanding it gets back. One record
per probe means a duplicate should never arise, but the old code would have counted one
twice while setting a single bit, leaving the span's count disagreeing with its own
ranges.

`Spans::total()` and `Spans::is_empty()` were removed with it. Neither had a caller
outside the module's own tests, and `total()`'s contract — "total probes represented,
which the terminal counts must still account for" — stopped being true the moment
draining became periodic: after any drain it returned zero. Accounting reads `counts`,
which is maintained independently, so nothing depended on it; a future reader might not
have been so lucky.

**Amended: what the `builtin` row of `service_labels` counts.** The file layers report
ports they were the first to claim; the builtin row reported its full 59 regardless of
what shadowed it, so the rows described overlapping sets and did not sum to the table
they came from. It now reports what it still answers for — typically 2, because a stock
Linux `/etc/services` names 57 of the 59.

Worth stating precisely, because I got it wrong first time by measuring the wrong thing:
this counts ports a file layer *claimed*, not ports it *relabelled*. `/etc/services`
agrees with the builtin that 22 is `ssh`, and 22 still belongs to the layer that got
there first. Measuring differing labels instead gives 27, which is a real number
answering a question nobody asked.

### D32 — Banners are read, never solicited; interrogation is handed to nmap

**Status:** accepted · **Alternatives:** active service probes, no banners at all

`service_label` was always a guess from the port number — D31 made it a better-sourced
guess and could not make it evidence. A banner is evidence. `--banner` reads what an open
service volunteers on connect and records it verbatim.

**Passive only, and that is the whole design.** Not one byte is written; `scan_config`
records `banner.sent_bytes: 0` so a record can be audited on the point. Connecting to a
port and listening is what a connect scan already does, so this needs no consent story
beyond the one the tool already has. Sending a protocol probe is a different act — it
addresses the service rather than observing it — and would need its own justification,
its own flag, and its own paragraph in `security.md`.

**The cost is coverage, and it is severe.** Only services that greet first say anything:
SSH, SMTP, FTP, POP3, IMAP, MySQL, Telnet. HTTP does not, and neither does anything
behind TLS, which on a modern network is most of what anyone wants identified. This is
stated in the CLI help, the schema, and the guide, because an absent banner meaning
"said nothing unprompted" and meaning "nothing there" would otherwise be indistinguishable
to a reader.

**On by default**, which reverses an earlier call in this entry and is worth explaining.
The original argument was that reading changes what the scan does to a target. It does
not, much: the service writes its greeting when it accepts the connection whether or not
anyone reads it, and making that connection is what a connect scan already does. What
reading costs is holding an *open* socket a little longer, bounded by the adaptive wait
above, and open ports are rare. Against that, a scan that saw a banner and discarded it
is a worse record — and this tool exists to produce records.

`--no-banner`, or `banner = false` under `[defaults]` or on a scan, turns it off, and
`scan_config.banner.enabled` states which happened. The knob that genuinely needs asking
for is an *active* probe, and that is still not on offer.

**The timeout is a ceiling, not a wait.** A flat 500 ms looked harmless and was not:
concurrency here is the worker-thread count with no queue, so a worker parked in `read`
issues nothing while it waits — and the ports that pay the full wait are exactly the ones
that yield nothing, since a silent open port is the common case. At a 1% open rate and a
1 ms probe that turned into a multiple of the whole scan's duration, and on `direct-fast`
the wait was 1.67x that profile's entire connect budget. The wait now scales off the
probe's own measured connect (a greeting arrives about one round trip after the
connection is established), floored so a sub-millisecond connect still leaves room, and
capped by the configured value so the knob still means the most it will ever wait.

**Limits.** 1024 bytes by default, hard-capped at 4096: a greeting is tens of bytes (SSH
~40, SMTP ~100) and the cap exists so one hostile service cannot inflate a record. 500 ms,
because a service that volunteers a greeting does it immediately — this is a read on an
established connection, not another connect. One `read`, not a loop: the protocols above
all write their greeting with a single `write`, so looping would buy truncation resistance
nobody needs at the price of a second timeout to wait out.

**Displaying a banner is a security boundary.** The bytes are chosen by the scanned host
and a terminal acts on what it is given — `ESC [ 2J` clears the screen, `ESC ] 0 ;` rewrites
the title, and on some emulators a query sequence produces a reply the shell then reads as
input. Banners reach the screen as printable ASCII only, everything else replaced with `.`.
The record keeps the original bytes; only the display is sanitised. This is tested against
a fixture that sends exactly those sequences.

**Interrogation is not ours to do.** `nmap -sV` rests on a signature database two decades
deep, and a worse copy of it would be worse than useless — it would be confidently wrong.
`output results --format nmap` emits runnable `nmap -sV` commands instead, grouped by the
exact set of ports open on each host so nothing is offered a port it never had, with
`-Pn -n` to stop nmap repeating the liveness and resolution work already done. Pointing
nmap at the fraction of endpoints that answered is dramatically faster than letting it
scan everything.

`--format list` serves the same purpose for `httpx`, `tlsx` and `nuclei`, which between
them cover the HTTP and TLS surface a passive read cannot reach.

**Revisit trigger.** A TLS `ClientHello` is the one probe worth reconsidering: it is the
most standard thing that can be sent and it identifies a service definitively through the
certificate, SNI and ALPN. It would still be an active probe and belongs behind its own
flag, after the consent story above is written down properly.
