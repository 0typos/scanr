# Architecture

Single crate (D17). Modules, not workspace members.

```
src/
  main.rs            entry point, exit-code mapping
  cli/               clap definitions, override allowlist
  config/            TOML types, discovery, merge, validation, provenance
  plan/              ScanPlan, expansion, permutation, projections
    permute.rs       seeded Feistel index permutation
  net/
    target.rs        target spec parsing (IP, CIDR, range, hostname, file, stdin)
    ports.rs         port spec parsing
    dns.rs           resolution modes
  transport/
    mod.rs           Transport trait, Fidelity
    direct.rs
    socks5.rs        RFC 1928 / 1929, written directly
  sched/             thread pool, rate limiter, cancellation
  probe.rs           ProbeOutcome, classification
  output/
    jsonl.rs         writer thread, sequencing, durability
    human.rs         streaming stdout, TTY detection
  diag/              error model, sysctl inspection, remediation text
tests/
  fixtures/          in-process TCP + SOCKS5 servers
```

## Data flow

```
config discovery → merge → validate → ScanPlan (immutable, with provenance)
                                          │
                            ┌─────────────┴─────────────┐
                            │                           │
                    permutation over N            writer thread
                            │                     (bounded channel)
                    worker pool (N = concurrency)       │
                            │                    ┌──────┴──────┐
                       Transport::probe       stdout        JSONL
```

## Transport

The payoff of blocking I/O — no async trait, no pinning, no lifetimes:

```rust
pub trait Transport: Send + Sync {
    fn probe(&self, dest: &Destination, t: &Timeouts, cancel: &Cancel) -> ProbeOutcome;
    fn supports_remote_dns(&self) -> bool;
    fn declared_fidelity(&self) -> Fidelity;
}
```

`Destination` is either a resolved `SocketAddr` or a `(hostname, port)` pair — the
latter only permitted when `supports_remote_dns()`.

`Fidelity` records which of `open`/`closed`/`filtered` this transport can actually
distinguish. `direct` is `Full`. SOCKS5 is `Unknown` until measured by
`scanr transport test` (D8), then `Full` or `OpenOnly`.

## Scheduler

Fixed pool of `min(concurrency, total_probes)` threads, 64 KiB stacks, spawned once.
Each worker loops: check cancellation → take next index via `fetch_add` → map through
the permutation → acquire a rate-limiter token → probe → send outcome.

- **Concurrency** is the pool size. No semaphore, no queue.
- **Rate limiting** is a token bucket behind a `Mutex`. At ≤5k threads and ms-scale
  probes, acquisition rate stays in the low thousands/sec — uncontended in practice.
- **Backpressure** is structural: workers block on the bounded writer channel.
- **Fairness** is provided by the permutation (D16), which interleaves hosts and ports
  by construction.

## Cancellation

`AtomicBool` checked before each probe begins. In-flight probes are bounded by their
own socket timeouts. First SIGINT: stop scheduling, drain bounded by
`min(connect_timeout, 2s)`, write `scan_interrupted`, exit 130. Second SIGINT: flush
what is buffered and exit immediately.

Signal handling uses a flag set from the handler and polled by the main thread — no
allocation, no locks, no async-signal-unsafe calls in the handler.

## Output writer

Dedicated thread, `mpsc::sync_channel(4096)`, `BufWriter`. Sequence numbers assigned by
the writer, guaranteeing monotonicity regardless of worker completion order.

Results are inherently unordered — randomized probe order plus N concurrent workers.
`seq` therefore means *write order*, not probe order; each record carries its own
timestamps and probe index.

Flush policy: immediate `flush()` on lifecycle events (`scan_started`, `scan_config`,
all terminal events) and every 250 ms otherwise. No `fsync` per record — the durability
guarantee is "survives process death", not "survives power loss". Writer failure
(including `ENOSPC`) aborts the scan with exit code 3, after one attempt to write
`scan_failed`.

File is `<name>.jsonl.partial` during execution, renamed to `<name>.jsonl` once a
terminal event is persisted. Interrupted-but-finalized scans **are** renamed — the
terminal event distinguishes them; `.partial` means "process died without finalizing".

## Error model

Two layers. `ProbeOutcome` is per-probe and never fatal. `ScanError` is fatal and maps
to an exit code. Both carry an operational cause, not an errno — `EADDRNOTAVAIL`
renders as ephemeral-port exhaustion with the sysctl remediation (D9),
`ECONNREFUSED` to the proxy renders as "proxy not listening", SOCKS reply `0x02` as
"denied by proxy policy".

`thiserror` for definitions. No `miette` — the value it adds is span-annotated config
errors, and `toml`'s `Error::span()` plus ~100 lines of caret rendering covers that
without the tree.

## Dependencies

| Crate | Need | Why not std |
|---|---|---|
| `clap` (derive) | Subcommand tree, help, completions | Hand-rolling a 6-group tree with completions is real work for no gain |
| `serde` + `toml` | Config deserialization with spans | Writing a TOML parser is a liability for a config-first tool |
| `serde_json` | JSONL emission | Correct escaping matters; hand-rolling is a bug source |
| `socket2` | `SO_LINGER` (D9), socket setup | `TcpStream::set_linger` unstable (rust#88494) |
| `thiserror` | Error definitions | Boilerplate only |
| `libc` | `sysctl` reads, `signal`, `rlimit` | No std equivalent |

**Written directly:** SOCKS5 (D5), the Feistel permutation (D16), CIDR/range parsing,
duration parsing, the token bucket, the caret-renderer for config errors.

**Rejected:** `miette` (tree cost exceeds value), `tokio` (D1), `mio` (D2), any SOCKS
crate (D5), `tracing`/`log` (stderr diagnostics are structured by the diag module),
`uuid`/`ulid` (scan ID is epoch-ms plus 32 random bits from `getrandom`, sortable and
collision-safe enough for one host), `chrono`/`time` (RFC 3339 formatting from epoch is
~40 lines and we need no parsing or timezone handling).

## Platform boundaries

Linux-only assumptions are confined to `diag/` (sysctl and rlimit inspection) and the
signal setup in `main.rs`. Everything else is portable `std` — which is what makes the
deferred Windows/macOS work tractable later without an abstraction layer now.
