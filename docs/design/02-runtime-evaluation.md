# Runtime Evaluation

Decision: **blocking sockets on a bounded thread pool** (D1). `mio` rejected (D2).
Tokio retained as the documented fallback.

## Inputs that decided it

| Input | Value | Effect |
|---|---|---|
| Peak concurrent connections | 500–5,000 realistic (10k ceiling) | Inside thread-pool range |
| SOCKS5 share of traffic | Primary path | Favours straight-line handshake code |
| Platforms | Linux x86_64, glibc + musl | Removes mio's portability value |
| Proxies per scan | One | No per-instance scheduling |
| Cancellation | Bounded drain acceptable | Removes Tokio's main structural advantage |

The concurrency figure is capped in practice by the proxy, not by scanr. `ssh -D`
multiplexes every probe as a channel over a single TCP connection and realistically
sustains low hundreds. Self-hosted daemons sit in the low thousands. Commercial pools
impose their own limits. The scanner is not the bottleneck in any of the three
configurations in scope.

## The three candidates

### Blocking sockets + bounded thread pool — SELECTED

**For.** `std::net::TcpStream::connect_timeout` is already precisely this tool's core
primitive — it performs the non-blocking `connect()` → `EINPROGRESS` → wait-for-writable
→ `getsockopt(SO_ERROR)` sequence internally. A SOCKS5 handshake is straight-line code.
`set_read_timeout`/`set_write_timeout` provide per-phase timeouts *and* per-phase
measurement with no timer infrastructure. Stack traces are real; a hung probe is
diagnosable with `gdb` or `/proc/<pid>/task/*/stack`. I/O dependencies: none beyond
`socket2` for `SO_LINGER`.

Structurally, **there is no work queue** — N threads means exactly N in flight. The
brief's requirements to "avoid unbounded work queues", "apply backpressure", and "avoid
silently dropping probes" are satisfied by construction rather than by mechanism.

**Against.** A thread blocked in `connect_timeout` cannot be interrupted, so Ctrl-C
latency is bounded by the longest outstanding timeout rather than being immediate.
Roughly 10k threads is a real ceiling. musl's `mallocng` contends badly under high
thread counts.

**Cost.** 5,000 threads × 64 KiB explicit stacks = ~320 MiB virtual, small resident.
Spawn cost ~30 µs each, paid once.

### Tokio — FALLBACK

**For.** Timers, cancellation, and structured concurrency are ready-made. Cancellation
is immediate rather than timeout-bounded. Scales past 10k trivially. Mature ecosystem.

**Against.** A general-purpose multi-threaded work-stealing runtime is a poor fit for a
workload that is ~100% blocking-on-network with almost no CPU. It brings a substantial
dependency tree for capabilities this tool barely uses. `JoinSet`/`Semaphore` make
accidental unbounded concurrency easy to write. Per-phase timing requires explicit
instrumentation that blocking timeouts give away free.

**Why it is the fallback and not the choice.** The only decisive advantages —
immediate cancellation and >10k concurrency — are things we have established we do not
need. If M0 disproves that, the port is largely mechanical.

### mio — REJECTED

Requires hand-writing: a timer wheel (mio ships no timers by design; `Poll::poll` takes
a deadline and nothing more), signalfd or self-pipe integration, and a resumable
partial-read/partial-write state machine for every phase of the SOCKS5 handshake —
greeting, method selection, optional auth, request, reply, all with variable-length
address fields. Estimated 500–900 lines of the most defect-prone code in the project,
in service of a concurrency level threads already reach.

Its distinguishing value is portable readiness across epoll/kqueue/IOCP. On Linux-only
it is a thin safe `epoll` wrapper, a role `polling` or `rustix` also fill. Highest
cost, benefit does not apply.

### Considered and dismissed

- **smol / async-std** — same structural argument as Tokio with a smaller ecosystem and
  no compensating advantage for this workload.
- **io_uring** — optimizes syscall batching for high-IOPS storage and streaming I/O.
  This workload is one `connect()` and a handful of small reads per probe, latency-bound
  on the network. No meaningful benefit, significant complexity, kernel-version coupling.
- **Raw epoll via `rustix`/`libc`** — only relevant if mio were chosen; inherits every
  mio objection plus FFI surface.

## M0 feasibility probe

Not an A/B bake-off — one option is selected and the other two are argued. This
measures whether the selected option clears its bar.

**Method.** Spawn N ∈ {500, 2000, 5000, 10000} threads performing `connect_timeout`
against local listeners in three modes: accepting, refusing (RST), and blackholed
(DROP via nftables). Built for `x86_64-unknown-linux-gnu` and
`x86_64-unknown-linux-musl`.

**Measure.** Peak RSS · sustained probes/sec · Ctrl-C drain latency · CPU during steady
state · allocator contention on musl (with and without mimalloc) · `EADDRNOTAVAIL`
onset with and without `SO_LINGER {on,0}`.

**Pass criteria.**

| Metric | Bar |
|---|---|
| RSS at 5,000 threads | < 500 MiB |
| Sustained rate, local accepting listener | ≥ 5,000 probes/sec |
| Ctrl-C drain latency | ≤ connect_timeout + 250 ms |
| musl vs glibc throughput delta | < 25% (else adopt mimalloc for musl) |
| `SO_LINGER {on,0}` eliminates `EADDRNOTAVAIL` | yes, at 10× the ephemeral budget |

Failing the RSS or throughput bar at 5,000 threads triggers reconsideration of Tokio.
Failing only the musl delta triggers an allocator swap, not a runtime change.
