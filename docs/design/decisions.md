# Decision register

Status: `accepted` · `rejected` · `proposed` · `superseded`. One entry per decision:
what was decided, the evidence, and the trigger that would reopen it. D1–D18 were
settled 2026-07-29. Measurements are on one Linux x86_64 machine unless stated; the
long-form reasoning is in git history (`e2ec1a2` and earlier).

### D1 — Blocking sockets on a bounded thread pool
accepted · alternatives: mio, Tokio, smol, io_uring · trigger: sustained concurrency above ~10k (fallback Tokio; the port is mechanical)

- SOCKS5 is a 2–3 round-trip exchange: straight-line code when blocking, a resumable state machine under any readiness loop. `connect_timeout` is the core primitive; per-phase timeouts and timing come free. Zero I/O dependencies.
- Costs: cancellation latency bounded by the longest outstanding timeout; ~10k thread ceiling; 64 KiB stacks.

| metric | bar | measured 2026-07-29 |
|---|---|---|
| RSS at 5,000 threads | < 500 MiB | 40.6 MiB |
| RSS at 10,000 threads | — | 81 MiB |
| sustained rate, local listener | ≥ 5,000/s | 68,949/s |
| Ctrl-C drain, 2 s timeout | ≤ 2.25 s | 838 ms |
| spawn 10,000 threads | — | 227 ms, once |

Throughput is non-monotonic in concurrency (62,805/s at 2,048 < 68,949/s at 512), so concurrency is a tunable, not a maximum. End to end: 60,000 loopback probes in 0.44–0.49 s (~128,000/s).

### D2 — mio
rejected

Linux-only removes its portability value; on Linux it is a thin `epoll` wrapper with no timers, so a timer wheel and partial-I/O state machines would be hand-written anyway, on the dominant (SOCKS) path.

### D3 — Platforms
accepted · amended

- Linux x86_64 is supported: performance is measured there and it has the static musl build.
- macOS builds and passes the suite in CI. One `cfg`: `getentropy` instead of `getrandom`. `/proc` diagnostics (`ephemeral_range`, `tcp_tw_reuse`) report unknown, so `ephemeral_budget` cannot fire; `fd_budget` does (macOS defaults `RLIMIT_NOFILE` to 256).
- Windows: not planned. 1.0 supports Linux x86_64 only (D36).

### D4 — SOCKS5 only
accepted, permanent

SOCKS4/4a have four reply codes and cannot separate closed from filtered.

### D5 — SOCKS5 written directly
accepted

RFC 1928 CONNECT plus RFC 1929 auth is a few hundred lines. Owning it gives exact reply-code mapping (D8), per-phase timing, and auditable credential handling.

### D6 — One proxy per scan
superseded by D33

### D7 — Result states
accepted · alternative rejected: the 12-state taxonomy

`open` / `closed` / `filtered` / `error`, plus `source` (`local_stack`, `proxy_reply`, `timeout`, `internal`) and a `reason`. Most of the twelve are unreachable through a proxy.

### D8 — Fidelity is measured and declared, not assumed
accepted

`transport test` connects through the proxy to a known-open, a known-closed and a blackholed destination and reports the reply codes. The result is declared in config and recorded in `scan_config`.

- OpenSSH `ssh -D` sends **no reply** for a refused destination and closes the channel; its own log says `connect failed: Connection refused`. Fidelity `open_only`. (An earlier claim that it collapses to `0x01` was wrong.)
- `BND.ADDR` in a successful `ssh -D` reply is `0.0.0.0:0`: a proxied hostname target cannot record the address probed (D15).
- Validation: 16 ports, direct and microsocks identical on all 16; through `ssh -D` the 4 open agreed and the 12 non-open became `error`. No `closed` fabricated.

### D9 — Probe sockets close with `SO_LINGER {on, 0}`
accepted

RST instead of FIN skips `TIME_WAIT`. Every probe targets the same proxy address, so only the source port varies: 28,232 ephemeral ports against a 60 s `TCP_TIMEWAIT_LEN` caps a remote proxy at ~470 probes/s without it. Measured: **7.5×** (9,189 → 68,949 probes/s); `TIME_WAIT` sockets after 5 s, 21,931 → 1. Costs: some proxies log RSTs. Needs `socket2` (`TcpStream::set_linger` unstable, rust#88494).

### D10 — Retry a timeout once, one merged row
accepted

Through a proxy a timeout is ambiguous between slow proxy and filtered destination. The row carries `attempts` and `attempt_states`.

### D11 — The record holds every probe outcome
accepted

Makes "what was never probed" derivable (D12). Volume is handled by D28 and D30.

### D12 — No `resume`; `output remainder` and `run --pairs`
accepted · amended

- Resume is murky under DNS churn and profile changes; the un-probed set is just a target list.
- `remainder` emits `host:port` endpoints (the first version emitted whole targets and re-probed completed ports). `abandoned` probes are included.
- A pair scan embeds its list in the record, bounded at 50,000; beyond that `pairs_truncated` is set and `remainder` refuses.
- `remainder` writes a `# resumed-from: <scan_id>` comment that `--pairs` reads into `scan_config.resumed_from`; `--resumed-from` sets it by hand.

### D13 — Config: user then project, project wins
accepted

`~/.config/scanr/config.toml` for transports and credentials; `./scanr.toml` for scans.

### D14 — No inline passwords
accepted · stricter than the brief's warning

Inline `password` is a hard error. Only `password_env` and a mode-0600 `password_file`, checked on the descriptor the bytes are read from.

### D15 — DNS mode `auto`
accepted, with mitigation

Transport resolves when it can, else local. The same config resolves differently across transports; `plan` prints the mode, `target_resolved` records it, switching transports with hostnames warns.

### D16 — Seeded Feistel permutation for probe order
accepted

4 rounds over the next power of two ≥ N with cycle-walking: O(1) memory (a shuffle of /16 × 1000 is ~520 MB), streaming, reproducible from the recorded seed.

### D17 — Single crate
accepted · trigger: a library API becomes a goal

### D18 — Pragmatic dependencies
accepted

Per-crate rationale in `architecture.md`. SOCKS5, the permutation, spec parsing, the token bucket and caret rendering are written directly.

### D19 — musl ships without an allocator swap
accepted · trigger: scanr itself is the bottleneck (large direct LAN scans) → a pure-Rust allocator

| build | wall (60k probes, c=1024) | rate | RSS |
|---|---|---|---|
| glibc | 0.44 / 0.45 / 0.49 s | ~128,000/s | 12.4 MB |
| musl | 0.83 / 0.76 / 0.84 s | ~75,000/s | 8.7 MB |

1.7× exceeds the M0 "< 25 %" bar. Kept anyway: mimalloc/snmalloc need a musl C toolchain, which ends the fully static build; 75,000/s is ~15× any proxied rate.

### D20 — Config errors redact the source line they echo
accepted

Rejecting `password = "hunter2"` printed the password. Redaction lives in `ConfigError::render`, not at call sites.

### D21 — `SIGXFSZ` is ignored
accepted

`RLIMIT_FSIZE` then surfaces as `EFBIG` on write, which the writer reports; the default kills the process with no terminal event. Same reasoning as `SIGPIPE`. Also what makes writer failure testable without root.

### D22 — Column padding from visible width
accepted

ANSI escapes inflate `len`, and labels wider than 10 columns (`elasticsearch`, `kube-apiserver`) shifted one row. Both invisible through a pipe; tests strip escapes and compare offsets. A formatter only exercised through a pipe is untested.

### D23 — Fidelity measured against four real proxies
accepted · supersedes the assumptions in D8

| proxy | refused | blackholed | fidelity |
|---|---|---|---|
| microsocks | `0x05` | no reply, timeout | full |
| dante (sockd 1.4.3) | `0x05` | `0x01` | full |
| 3proxy | `0x05` | no reply, timeout | full |
| OpenSSH `ssh -D` | no reply, channel closed | no reply, timeout | open_only |

Three assumptions failed: no real proxy answers `0x01` for everything (the `Collapsing` fixture models nothing observed); the proxy's own listener as the known-open target fails on dante (`0x02` by ruleset) and 3proxy (`0x09`, undefined), so scanr binds its own listener when the proxy is on loopback; `ssh -D` handles concurrency 512 with zero loss.

### D24 — Default concurrency stays 512
accepted · trigger: a common deployment failing at 512 for a reason other than an explicit cap

Loss against 64 blackholed targets × 4 ports, sockets held ~2 s:

| proxy | c=16 | 24 | 32 | 48 | 64 | 256 | 512 |
|---|---|---|---|---|---|---|---|
| microsocks | 0 % | — | 0 % | — | 0 % | 0 % | 0 % |
| `ssh -D` | 0 % | — | 0 % | — | 0 % | 0 % | 0 % |
| 3proxy, `maxconn 100` | 0 % | 0 % | 7 % | 37 % | 48 % | 95 % | 80 % |
| 3proxy, `maxconn 2000` | 0 % | — | 0 % | — | 0 % | 0 % | 0 % |

The proxy's cap is the constraint; no scanr default rescues a proxy capped at 100. The cap is made visible (`proxy_saturation`) and measurable (`--calibrate`).

### D25 — Capacity measured by churn, not a burst
accepted

A 64-connection burst reported 64/64 for the 3proxy configuration above. `--calibrate` sweeps concurrency with four rounds per worker against a hanging destination; conservative (clears 16 where 24 was tolerated); opt-in because it is real traffic.

### D26 — Scale validated at 10⁶ probes
accepted

| scan | probes | wall | rate | peak RSS | record |
|---|---|---|---|---|---|
| 1 host × 65,535 ports | 65,535 | 0.42 s | ~156,000/s | 8.3 MB | 24 MB |
| /16 × 16 ports | 1,048,576 | 69 s | ~15,200/s | 17.0 MB | 377 MB |

RSS 5.8 → 17.0 MB and flat (the materialised target list). Loopback caveats: a `0.0.0.0` service answers on all of 127/8; sshd's backlog produced 9,109 filtered and 20,835 retries. The record compressed 16.8×, which led to D28.

### D27 — The SOCKS5 handshake is fuzzed as a unit
accepted

Greeting, method selection and RFC 1929 auth are peer-driven. The handshake is generic over its stream so the fuzzer drives it without a socket, with and without credentials, and with bounded writes so "peer stopped reading" is reached. Asserts a failed handshake is never `open` and always has a reason. 66 M executions clean.

### D28 — Framed gzip by default, pure Rust
accepted · alternatives rejected: zstd, a single stream · trigger: a widely deployed pure-Rust zstd encoder

- One gzip member per 256 KiB or per critical flush; concatenated members are valid gzip, so `zcat` works and a killed scan decodes to its last frame.
- On one 12 MB record: gzip -6 20.1×, zstd -3 18.0×, zstd -9 22.4×, zstd -19 26.1× at 100× the time. The `zstd` crate binds C; `flate2` on `rust_backend` keeps the musl binary at 0 `NEEDED`.
- Default on: every `scanr output` command and `zcat` read it; `--no-compress` restores plain.

### D29 — `ssh -D` has its own profile family
accepted · caveat: measured on loopback against OpenSSH 10.2p1

- Its listener is local, so `tcp_tw_reuse = 2` exempts it from the ~470/s ephemeral ceiling: 4,000 probes took 80 s under `proxy-careful`, 10 s under `proxy`, 0.16 s uncapped.
- Negotiation 0.4–0.5 ms; a refused destination returns in 0.4 ms.
- Flat ~28,500/s from concurrency 32 to 128; at ≥ 160 a fixed ~1 s stall drops it to ~1,850/s. `ssh-fast` / `ssh` / `ssh-slow` stay below 128 (test-enforced) and raise concurrency as the link slows (in-flight ≈ rate × RTT).

### D30 — Bulk outcomes collapse into spans, by default, in counter space
accepted · schema 2

- `/16 × 16`: 391,618,401 B / 1,048,580 events → 2,582 B / 5 events with identical `verify` and `remainder` output. Field-stripping (1.69×, 1.37× over gzip) rejected.
- Ranges are counter indices, not matrix positions: randomised order makes matrix-space runs degenerate toward one per probe. Rate-limited 20,001-probe scan: 10,023 ranges in matrix space, 595 in counter space (53,765 → 4,893 B). Expansion needs the recorded seed.
- `open`, `error`, pressured and disagreeing-retry probes keep their rows; a retry that agreed is bulk (otherwise `retries = 1` collapses nothing).
- Accumulator is a sorted, deduplicated index list per class, drained every progress tick, so memory follows throughput. A bitset sized from `planned` was 8.2 MB per class at 65 M probes and ~200 MB at `/8 × 100`, against a 64-class ceiling. Above 64 classes in a window, that window is not collapsed.
- Cost: no per-probe timestamp for collapsed results; `probe_result` no longer covers every probe.

### D31 — Service labels are layered with provenance
accepted · amended

`defaults.services_file` → `/etc/services` → a 59-port builtin; first answer wins. `scan_config.service_labels.layers` records each source's entries and unparseable lines; the builtin row counts only ports no file claimed (typically 2). A configured file that cannot be read is fatal; a missing `/etc/services` is not; UDP/SCTP rows are skipped, not counted as malformed; `nmap-services` parses. `use_etc_services = false` gives machine-independent labels, recorded distinctly from the file being absent. Still a guess from the port number.

### D32 — Banners are read, never solicited; interrogation goes to nmap
accepted · on by default (amended) · trigger: TLS ClientHello → D35

- Zero bytes written; `scan_config.banner.sent_bytes: 0`. Only services that greet first (SSH, SMTP, FTP, POP3, IMAP, MySQL, Telnet) say anything; HTTP and TLS do not. An absent banner means "said nothing unprompted".
- The wait scales off the probe's measured connect, floored, capped by `banner_timeout` (500 ms): a flat wait parks a worker per silent open port and was 1.67× `direct-fast`'s connect budget. 1024 bytes default, 4096 cap, one `read`.
- Display is printable ASCII only (tested against `ESC [ 2J`, `ESC ] 0 ;`, query sequences); the record keeps the bytes.
- `output results --format nmap` emits `nmap -sV -Pn -n` per host's exact open ports; `--format list` feeds `httpx`, `tlsx`, `nuclei`.

### D33 — Chains are one path; pools are many
accepted · supersedes D6

- A chain is the general case: `ProxyTransport` holds hops and a single proxy is one hop. A failed intermediate CONNECT is `error` naming the hop, never a verdict on the destination.
- **Amended 2026-08-25: a chain's fidelity is its exit hop's, not its weakest hop's.** Only the last CONNECT names the destination; an intermediate CONNECT either succeeds or fails the whole chain, and the exit's reply travels back through the tunnels untouched. Measured: squid (`open_only` by construction) → 3proxy SOCKS5 tests `full` end to end; dante → tinyproxy tests `open_only`. `fidelity_source` is `exit_hop` (was `weakest_hop`).
- A pool assigns by FNV-1a of the endpoint (stable across toolchains), so a scan stays reproducible. Not failover: a dead member fails its share. `via` on every result names the member.
- `Fidelity` has no `Ord`; `Fidelity::weakest` says what it means.

### D34 — HTTP CONNECT transport, open_only by construction
accepted 2026-08-25 · alternatives rejected: per-proxy status mapping; Digest/NTLM auth · trigger: a second vendor exposing the connect errno, as squid's `X-Squid-Error` does

- `type = "http"`, same keys as `socks5`; Basic auth only (`Proxy-Authorization`, base64 in the clear). A hop kind inside the existing path walker, so a chain may mix protocols: either CONNECT yields a raw tunnel.
- HTTP standardises no status meaning "the destination refused". Measured, raw status lines:

| proxy | refused | blackholed | distinguishes |
|---|---|---|---|
| squid 7.6 | `503`, `X-Squid-Error: ERR_CONNECT_FAIL 111` | `503`, `ERR_CONNECT_FAIL 110` (2 s `connect_timeout`; no reply under the 60 s default) | private header only |
| tinyproxy 1.11.2 | `500 Unable to connect` | `500 Unable to connect` | no |
| 3proxy 0.9.7 | `502 Bad Gateway` | `502 Bad Gateway` | no |

- So `2xx` is open, `407` and `403` are named, everything else is `error` carrying the status line; the transport is `open_only` with `fidelity_source: inherent`, `fidelity = "full"` is refused in config, and `transport test` reports the statuses seen rather than judging them. Mapping squid's errno header would give one vendor `full` on a private signal; not taken.
- Response parser is bounded at 8 KiB, deadline-driven against trickling, refuses anything not starting `HTTP/` byte by byte, filters peer text to printable ASCII, and stops at the blank line so a banner behind a `200` is left for the banner reader. Fuzz target `http_connect_reply`.
- Also found: 3proxy's SOCKS5 answers `0x05` for its *own* connect timeout when that is shorter than scanr's, so its "refused" means "failed"; documented as a caveat in `transports.md`.

### D35 — TLS ClientHello probe: active, opt-in, 1.3 and 1.2
accepted 2026-08-25 · amended 2026-08-27 (leaf read, SNI on the direct path, whole flight, TLS 1.3) · alternatives rejected: a full handshake via rustls (C/asm provider, ends the static build; D19, D28); x509 verification in scanr (D32: a worse `tlsx`); leaving 1.3 at `protocol_version` (the growing share of servers, unread) · trigger: none open

- The one thing scanr sends to a service. Off by default (`--tls`, `tls = true`); the record carries `scan_config.tls.sent_bytes` and a per-result `tls` object, so a record can be audited on the point. Runs only on open ports that volunteered no banner — TLS servers never speak first — on the same connection, after the banner wait.
- 218 fixed bytes: ClientHello offering 1.3 then 1.2, fixed client random, `TLS_AES_128_GCM_SHA256` and twenty common 1.2 suites, ALPN `h2, http/1.1`, one x25519 key share from a published private key, SNI whenever the target was given as a name — the direct path now keeps the name beside the address it resolved (`Destination::Resolved`), after a real 443 answered `internal_error` to a nameless hello. `docs/security.md` lists them and a test holds it to the code.
- Reads ServerHello (version, cipher, ALPN), Certificate (leaf DER ≤ 8 KiB embedded, SHA-256 always, chain length) or Alert, then resets. Verified against `openssl s_server`: `-tls1_2` yields the certificate it was given and `h2`; `-tls1_3` answers `protocol_version` (70). Flight bounded at 64 KiB, deadline-driven, ALPN filtered to printable ASCII; fuzz target `tls_reply`, seeds captured from OpenSSL.
- Amended: the leaf is read, never verified. `x509` lifts subject, issuer, alternative names, validity and key type from the DER already in the record into `tls.cert`, so a result line says `cn=nas.example self-signed expired` and `output results` says it again for any record that carries the DER. A fixed-depth walker, bounded strings and counts, fuzz target `x509_leaf`. Verification stays rejected: trust is a policy question `tlsx` and the browser answer better.
- Amended: TLS 1.3 is read, not just detected. The hello offers 1.3; when the server takes it, the probe finishes the key exchange — X25519, HKDF, AES-128-GCM hand-rolled in `crypto`, one RFC or NIST vector each — and decrypts the flight to Finished: EncryptedExtensions (ALPN), Certificate, CertificateVerify (signature scheme). Nothing is sent after the hello. The private key is a published constant, so the hello stays reproducible and the session protects nothing, which is why hand-rolled crypto without constant-time discipline is acceptable here and would not be anywhere else. HelloRetryRequest is recorded, not pursued. Verified against `openssl s_server -tls1_3`.
- Amended: the whole first flight is read, to ServerHelloDone. That adds the chain (up to 8 certificates after the leaf, each hashed and read), the ECDHE group and signature scheme from ServerKeyExchange, the compression byte and the ServerHello's extension list (`secure_renegotiation`, `extended_master_secret`, `session_ticket`). Same bytes sent; a flight that ends after the leaf is not an error. `serial`, `sig_alg` and `version` join `cert`; `sha1-signed` / `md5-signed` join the result line.
- SHA-256 and base64 are hand-rolled; no new dependency, musl binary still 0 `NEEDED`.
- Known limit: on the direct path a locally resolved hostname reaches the probe as an address, so no SNI is sent; through a proxy with transport DNS the name survives and SNI is sent. `sni` in the record says which.

### D37 — Results cross the worker→collector channel in batches
accepted 2026-08-25 · alternatives rejected: a lock-free queue; sharding the collector

- Profiled at 278k probes/s (loopback `/24 × 1000`, c=64): the single `sync_channel` carrying one message per probe cost ~29% of CPU in `Mutex::lock_contended` and waker traffic, allocation ~20%, syscalls ~12%; the collector thread held 44% of all samples. One process 0.92 s, four in parallel 0.30 s for the same work — the process, not the kernel, was the ceiling.
- Workers batch up to 64 results or 20 ms, flushing immediately on `open` or pressure so what the operator watches for is not delayed; `Drop` flushes on every exit path so a completed probe can never read as `abandoned`. Per-probe allocations removed: target names formatted once per target (`Arc<str>`), reasons `Cow<'static, str>`, attempt states inline, TLS observation boxed.
- Result: 256k probes 0.92 → 0.37 s at c=64, 1.54 → 0.40 s at c=512; 2.56M probes 14.1 → 4.3 s at c=512. The concurrency curve is flat to 512 (D1's non-monotonic finding was this contention). Rows mode (`--no-spans`) 2.37 → 1.70 s; its remaining cost is `serde_json::Value` per row.
- Amends D1: concurrency is still a tunable, but above ~64 it no longer costs throughput on the direct path; the right value is rate × RTT.

### D38 — No event loop yet: not mio, not tokio, not io_uring-only
deferred 2026-08-25 · trigger: a real direct-LAN workload where scanr, not the network, is the bottleneck; or a high-latency proxy that tolerates tens of thousands in flight

- **Where the time goes after D37** (loopback `/24 × 10,000`, c=512): ~75% userspace (scanr 42%, libc 30%, vdso 6.5%), ~20–25% kernel; the collector thread holds 47% of samples, each of 512 workers ~0.15%; 24 µs of CPU per probe, of which ~5 µs is kernel. An event loop replaces the kernel-and-scheduling quarter and leaves the serial collector untouched, so alone it moves the ceiling little.
- **mio, not tokio**, if readiness-based: tokio is mio plus a scheduler and task machinery a scanner does not want. D1 named tokio as the fallback for port cost, not speed. epoll does not cut syscalls per probe (socket, connect, epoll_ctl, epoll_wait, getsockopt, close ≈ the blocking path's seven); its win is threads → cores.
- **io_uring is the only path that cuts syscalls** — socket/connect/close as SQEs, one `enter` per batch — and it is pure Rust (`io-uring` crate), so the static build survives. It would also remove D1's ~10k in-flight ceiling, the per-read timeout handling, and cancellation latency (`ASYNC_CANCEL`). Expected with a parallelised collector: 1.5–2M probes/s direct on loopback; through a proxy, nothing changes.
- **Why not io_uring-only:** Docker's default seccomp profile blocks `io_uring_*` (2023), Kubernetes `RuntimeDefault` follows it, hardened hosts set `kernel.io_uring_disabled=2`. A tool that fails to start in a default container on its promised platform is a breaking change, so io_uring-only is a 2.0 with the kernel/container requirement stated, never a 1.x. It also flips D2 and D3: every proxy handshake becomes a completion-driven state machine (~2,500 lines of transport code), macOS goes, and the `unsafe` inventory grows from five thin libc calls to an SQE-heavy engine.
- **rayon is the wrong tool**: a CPU-bound pool sized to cores would cap in-flight probes at the core count; the hand-rolled pool with `fetch_add` already has no contention; the collector's remaining serial work is a per-worker shard merge, not a parallel reduction.
- **Order if the trigger fires:** (1) shard the collector's counts and spans per worker, merged at drain — the 47%; (2) `socket2` direct fast path dropping the two blocking-mode `ioctl`s; (3) an `engine = "uring"` direct-only path, with the thread pool kept for proxies (D2 stands there) and as the fallback where io_uring is blocked. 600k probes/s direct already exceeds what a LAN, a firewall's state table or an IDS tolerates, so until a workload asks, this stays deferred.

### D36 — 1.0 gate and stability policy
accepted 2026-08-25

The external-consumer gate is withdrawn. 1.0 promises the record, the CLI and the config format (additive within a major; a `schema_version` bump is a major); excludes the library API, stderr text, performance figures and platforms other than Linux x86_64. Tagged after HTTP CONNECT and the TLS probe land, the surface is pinned by a compat corpus, and a release candidate soaks on real engagements. Detail in `ROADMAP.md`.

---

## Deferred, open, rejected

| item | status | note |
|---|---|---|
| HTTP CONNECT | accepted, shipped | D34 |
| squid `X-Squid-Error` errno → `full` for squid | deferred | D34 trigger: a second vendor exposing the errno |
| TLS ClientHello | accepted, shipped | D35 |
| SNI for locally resolved names on the direct path | deferred | needs the hostname carried past resolution; D35 |
| commercial rotating pool fidelity | open | no access; add during soak if reachable |
| sustained multi-hour run | open | measure during soak |
| event loop / io_uring engine | deferred | D38 |
| aarch64 builds | deferred | post-1.0, additive |
| Windows | not planned | D3 |
| SSH-native transport | deferred | `ssh -D` covers it |
| adaptive concurrency | rejected | limits and diagnostics over hidden tuning; unfalsifiable in a record |
| profile inheritance | rejected | flat, complete profiles |
| `per_target_concurrency` | rejected | with a proxy the shared resource is the proxy |
| IPv6 prefix expansion | accepted with guard | refuse shorter than /112 without `--allow-large-range` |
| library API | deferred | D17 trigger |
