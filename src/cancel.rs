//! Cancellation signalling shared between the signal handler, scheduler, and writer.
//!
//! A blocking `connect_timeout` cannot be interrupted, so cancellation is cooperative:
//! workers check between probes and in-flight probes are bounded by their own socket
//! timeouts. M0 measured the resulting drain at 838 ms against a 2 s timeout.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

const RUNNING: u8 = 0;
const GRACEFUL: u8 = 1;
const FORCED: u8 = 2;

#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicU8>);

impl Cancel {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(RUNNING)))
    }

    /// First interrupt: stop scheduling, let in-flight probes drain.
    pub fn request_graceful(&self) {
        // Never downgrade a forced stop back to graceful.
        let _ = self
            .0
            .compare_exchange(RUNNING, GRACEFUL, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Second interrupt: finalize and exit immediately.
    pub fn request_forced(&self) {
        self.0.store(FORCED, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed) != RUNNING
    }

    pub fn is_forced(&self) -> bool {
        self.0.load(Ordering::Relaxed) == FORCED
    }

    /// Raw state, for handing to an async-signal-safe handler.
    pub fn raw(&self) -> Arc<AtomicU8> {
        self.0.clone()
    }
}

/// Escalate the shared flag. Called from a signal handler, so it must do nothing but
/// touch an atomic — no allocation, no locks, no formatting.
pub fn escalate(flag: &AtomicU8) {
    let current = flag.load(Ordering::SeqCst);
    let next = if current == RUNNING { GRACEFUL } else { FORCED };
    flag.store(next, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_running() {
        let c = Cancel::new();
        assert!(!c.is_cancelled());
        assert!(!c.is_forced());
    }

    #[test]
    fn first_request_is_graceful_second_is_forced() {
        let c = Cancel::new();
        c.request_graceful();
        assert!(c.is_cancelled());
        assert!(!c.is_forced());
        c.request_forced();
        assert!(c.is_forced());
    }

    #[test]
    fn graceful_never_downgrades_a_forced_stop() {
        let c = Cancel::new();
        c.request_forced();
        c.request_graceful();
        assert!(c.is_forced(), "graceful must not clobber forced");
    }

    #[test]
    fn escalate_mirrors_repeated_signals() {
        let c = Cancel::new();
        let raw = c.raw();
        escalate(&raw);
        assert!(c.is_cancelled() && !c.is_forced());
        escalate(&raw);
        assert!(c.is_forced());
        // Further signals stay forced.
        escalate(&raw);
        assert!(c.is_forced());
    }

    #[test]
    fn clones_share_state() {
        let a = Cancel::new();
        let b = a.clone();
        a.request_graceful();
        assert!(b.is_cancelled());
    }
}
