//! scanr — proxy-aware TCP connect scanner with reproducible, durable scan records.
//!
//! See `docs/design/` for the decision register and specifications. The short version:
//!
//! * Blocking sockets on a bounded thread pool, no async runtime (D1). There is no work
//!   queue — N worker threads means exactly N probes in flight, so backpressure and
//!   bounded concurrency hold by construction.
//! * Probe sockets close with `SO_LINGER{on,0}` (D9). Measured at a 7.5x throughput
//!   multiplier, and it is what keeps a scan inside the local ephemeral port budget.
//! * Every run writes a JSONL record ending in exactly one terminal event, so a file
//!   always answers "what was scanned, how, and did it finish?".
