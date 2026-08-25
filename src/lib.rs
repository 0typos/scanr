//! scanr — proxy-aware TCP connect scanner with reproducible, durable scan records.
//!
//! See `docs/design/decisions.md` for why it is built this way. The short version:
//!
//! * Blocking sockets on a bounded thread pool, no async runtime (D1). There is no work
//!   queue — N worker threads means exactly N probes in flight, so backpressure and
//!   bounded concurrency hold by construction.
//! * Probe sockets close with `SO_LINGER{on,0}` (D9). Measured at a 7.5x throughput
//!   multiplier, and it is what keeps a scan inside the local ephemeral port budget.
//! * Every run writes a JSONL record ending in exactly one terminal event, so a file
//!   always answers "what was scanned, how, and did it finish?".

//! # A note on this library's surface
//!
//! `scanr` ships as a binary. These modules are public so that the integration tests,
//! the man-page generator, and the fuzz targets can reach them — not because they are a
//! supported API. Nothing here is covered by semantic versioning, and internals move
//! whenever the binary needs them to. Depend on the JSONL record (`docs/output-schema.md`)
//! or the CLI (`docs/cli.md`), both of which have drift tests holding them still.

pub mod cancel;
pub mod cli;
pub mod config;
pub mod diag;
pub mod fidelity;
pub mod net;
pub mod output;
pub mod plan;
pub mod probe;
pub mod run;
pub mod sched;
pub mod services;
pub mod timefmt;
pub mod tls;
pub mod transport;
pub mod units;
pub mod verify;

/// In-process TCP and SOCKS5 fixtures.
///
/// Behind a feature so that a release build carries no fixture servers. `cfg(test)`
/// alone would not do: the integration tests are a separate crate and can only see what
/// a normal dependent sees.
#[cfg(any(test, feature = "testsupport"))]
pub mod testsupport;
