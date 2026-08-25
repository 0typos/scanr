# Architecture

Single crate (D17), blocking sockets on a bounded thread pool (D1), no async runtime.

## Modules

```
src/
  main.rs           entry point, exit-code mapping
  lib.rs            module list; the library surface is explicitly unsupported
  cli.rs            clap tree, override allowlist, signal setup, dispatch
  cancel.rs         cooperative cancellation flag (handler → workers and writer)
  config/
    mod.rs          discovery, loading, per-key merge, validation
    raw.rs          deserialized TOML shapes; layered lookup with provenance
    builtin.rs      built-in profiles; the annotated `config init` template
    error.rs        caret-annotated errors; redacts credential lines
  plan/
    types.rs        ScanPlan (immutable, with provenance), Fidelity, Timing, Banner, TransportKind
    resolve.rs      config + CLI overrides → ScanPlan; plan warnings
    permute.rs      seeded Feistel permutation (D16)
  net/
    target.rs       target spec parsing and expansion: IP, CIDR, range, hostname, file, stdin, pairs
    ports.rs        port spec parsing
  transport/
    mod.rs          Transport trait, Destination, build(), read_banner, linger close (D9)
    direct.rs       TcpStream::connect_timeout
    socks5.rs       the proxy path walker: RFC 1928/1929 hops, chains as the general case (D33)
    http.rs         HTTP CONNECT hop: request, bounded response parser, Basic auth (D34)
    pool.rs         deterministic member assignment by FNV-1a (D33)
  fidelity.rs       `transport test`: fidelity measurement and --calibrate (D8, D25)
  sched.rs          worker pool, token-bucket rate limiter
  probe.rs          ProbeOutcome, State, Source, OS-error classification
  run.rs            execute(): workers, collection, record lifecycle, terminal events
  output/
    jsonl.rs        record writer: sequencing, flush policy, gzip frames, .partial rename
    span.rs         span accumulation (D30)
    human.rs        stdout/stderr rendering, colour, width-aware padding (D22)
  verify.rs         readers: output events / results / summarize / verify / remainder
  services.rs       layered service labels (D31)
  diag.rs           host facts (sysctl, rlimit), pressure classification, WARNING_CODES
  units.rs          duration parsing and rendering
  timefmt.rs        RFC 3339 from epoch
  testsupport/      in-process TCP, SOCKS5 and HTTP CONNECT fixtures; feature `testsupport`
tests/              integration, cli_spec, spec_conformance, man_pages, differential (nmap; CI only)
fuzz/               six libFuzzer targets and committed seeds, replayed in CI
```

## Data flow

```
config discovery → merge → validate → ScanPlan (immutable, provenance)
                                          │
                        permutation over N probes
                                          │
                        worker pool (N = concurrency) → Transport::probe
                                          │  bounded channel
                        main thread: collect → stdout + JSONL record
```

## Transport

```rust
pub trait Transport: Send + Sync {
    fn probe(&self, dest: &Destination, timing: &Timing) -> ProbeOutcome;
    fn supports_remote_dns(&self) -> bool;
    fn name(&self) -> &str;
    fn type_name(&self) -> &'static str;
    fn fidelity(&self) -> Fidelity;
}
```

`Destination` is a `SocketAddr` or a `(hostname, port)`; the latter only when
`supports_remote_dns()`. `Fidelity` is `Full` / `OpenOnly` / `Unknown`; `direct` is
`Full`, SOCKS5 is whatever `transport test` measured and the config declares, HTTP is
`OpenOnly` by construction, a chain is its exit hop's, a pool is its weakest member's
and reports per member via `via`.

## Scheduler

`min(concurrency, probes)` threads, 64 KiB stacks, spawned once. Each worker: check
cancel → `fetch_add` the next counter index → permute → take a rate token → probe → send.
No queue; concurrency is the thread count. Backpressure is the bounded channel. Fairness
is the permutation.

## Cancellation

`AtomicBool` checked before each probe; in-flight probes end on their own timeouts. First
SIGINT: stop scheduling, drain, write `scan_interrupted`, exit 130. Second: exit
immediately, record still finalised. The handler only touches atomics.

## Writer

The main thread is the writer. Sequence numbers are assigned on write, so `seq` is write
order, not probe order. Lifecycle events flush immediately; everything else every 250 ms.
gzip is framed: a member per 256 KiB or per critical flush. No `fsync`: the guarantee is
"survives process death", not power loss. Any writer failure on any event type sets the
terminal event to `scan_failed` and exits 3. `.jsonl.partial` is renamed on the terminal
event; a file still `.partial` means the process died.

## Errors

`ProbeOutcome` is per probe and never fatal. `ScanError` is fatal and maps to an exit
code. Both carry an operational cause: `EADDRNOTAVAIL` → ephemeral-port exhaustion with
the sysctl remediation, `ECONNREFUSED` to the proxy → "proxy not listening", reply `0x02`
→ "denied by proxy policy".

## Dependencies

| crate | need | why not std |
|---|---|---|
| `clap` + `clap_complete` | 15-command tree, help, completions | real work for no gain |
| `serde` + `toml` | config with byte spans | a TOML parser is a liability |
| `serde_json` | JSONL | escaping |
| `socket2` | `SO_LINGER` | `set_linger` unstable (rust#88494) |
| `flate2` (`rust_backend`) | gzip frames | pure Rust keeps musl static |
| `thiserror` | error definitions | boilerplate |
| `libc` | sysctl, rlimit, signal, getrandom | no std equivalent |

Written directly: SOCKS5, HTTP CONNECT (with base64), the permutation, CIDR/range/port/duration parsing, the token
bucket, caret rendering, RFC 3339. Rejected: `miette`, `tokio`, `mio`, any SOCKS crate,
`tracing`/`log`, `uuid`/`ulid`, `chrono`/`time`.

## Platform boundaries

Linux-only assumptions are confined to `diag.rs` (sysctl and rlimit) and the signal setup
in `cli.rs`. `unsafe` is denied crate-wide; the five allowed blocks are listed in
`../security.md` and checked by a test.
