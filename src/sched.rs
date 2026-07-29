//! Worker pool and rate limiting.
//!
//! There is no work queue. The pool has exactly `concurrency` threads and each pulls
//! the next probe index from an atomic counter, so in-flight work is bounded by
//! construction rather than by a mechanism that could be got wrong. That structural
//! property is why the brief's "avoid unbounded queues / apply backpressure / never
//! silently drop probes" requirements need no separate implementation.
//!
//! Backpressure on the output side is equally structural: workers send results into a
//! bounded channel and block when the writer falls behind.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::cancel::Cancel;

/// Worker thread stacks. Probe stacks are shallow, and 64 KiB keeps 10,000 threads
/// inside ~640 MiB of address space (M0 measured 81 MiB resident at that count).
pub const WORKER_STACK_BYTES: usize = 64 * 1024;

/// Token bucket. A `Mutex` is adequate here: at <=5k workers with millisecond-scale
/// probes, acquisition rate stays in the low thousands per second.
pub struct RateLimiter {
    bucket: Option<Mutex<Bucket>>,
    rate: u32,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// `rate` of 0 means unlimited.
    pub fn new(rate: u32) -> Self {
        Self {
            bucket: (rate > 0).then(|| {
                Mutex::new(Bucket {
                    // Start empty so the first second is not a free burst.
                    tokens: 0.0,
                    last: Instant::now(),
                })
            }),
            rate,
        }
    }

    pub fn is_limited(&self) -> bool {
        self.bucket.is_some()
    }

    /// Block until a token is available, or until cancelled.
    pub fn acquire(&self, cancel: &Cancel) {
        let Some(bucket) = &self.bucket else {
            return;
        };
        let rate = self.rate as f64;
        loop {
            if cancel.is_cancelled() {
                return;
            }
            let wait = {
                let mut b = bucket.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.last = now;
                // Cap the burst at one second's worth so a stalled scan cannot resume
                // by dumping a huge batch at the proxy.
                b.tokens = (b.tokens + elapsed * rate).min(rate.max(1.0));
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64(((1.0 - b.tokens) / rate).min(0.25))
            };
            std::thread::sleep(wait);
        }
    }
}

/// Hands out probe indices. `fetch_add` past the end simply reports exhaustion, so
/// workers need no coordination beyond this counter.
pub struct WorkCounter {
    next: AtomicU64,
    total: u64,
}

impl WorkCounter {
    pub fn new(total: u64) -> Self {
        Self {
            next: AtomicU64::new(0),
            total,
        }
    }

    /// Next index, or `None` when the matrix is exhausted.
    pub fn take(&self) -> Option<u64> {
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        (i < self.total).then_some(i)
    }

    /// How many indices have been handed out, saturated at the total.
    pub fn issued(&self) -> u64 {
        self.next.load(Ordering::Relaxed).min(self.total)
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

/// Worker count for a scan: never more threads than there is work to do.
pub fn worker_count(concurrency: u32, probes: u64) -> usize {
    (concurrency as u64).min(probes).max(1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn counter_hands_out_each_index_exactly_once() {
        let c = Arc::new(WorkCounter::new(1000));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (c, seen) = (c.clone(), seen.clone());
            handles.push(std::thread::spawn(move || {
                let mut local = Vec::new();
                while let Some(i) = c.take() {
                    local.push(i);
                }
                seen.lock().unwrap().extend(local);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut all = seen.lock().unwrap().clone();
        all.sort_unstable();
        assert_eq!(all.len(), 1000, "no probe may be dropped or duplicated");
        assert_eq!(all, (0..1000).collect::<Vec<_>>());
    }

    #[test]
    fn counter_reports_issued_without_overshooting() {
        let c = WorkCounter::new(3);
        assert_eq!(c.issued(), 0);
        for _ in 0..10 {
            c.take();
        }
        assert_eq!(c.issued(), 3, "issued must saturate at the total");
    }

    #[test]
    fn unlimited_rate_never_blocks() {
        let r = RateLimiter::new(0);
        assert!(!r.is_limited());
        let start = Instant::now();
        for _ in 0..10_000 {
            r.acquire(&Cancel::new());
        }
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn rate_limiter_holds_within_tolerance() {
        let rate = 200;
        let r = RateLimiter::new(rate);
        let cancel = Cancel::new();
        let start = Instant::now();
        let n = 100;
        for _ in 0..n {
            r.acquire(&cancel);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let observed = n as f64 / elapsed;
        assert!(
            observed <= rate as f64 * 1.35,
            "observed {observed:.0}/s exceeds the {rate}/s limit"
        );
    }

    #[test]
    fn rate_limiter_is_shared_across_threads() {
        let rate = 400;
        let r = Arc::new(RateLimiter::new(rate));
        let cancel = Cancel::new();
        let count = Arc::new(AtomicU64::new(0));
        let start = Instant::now();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let (r, cancel, count) = (r.clone(), cancel.clone(), count.clone());
            handles.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    r.acquire(&cancel);
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let observed = count.load(Ordering::Relaxed) as f64 / elapsed;
        assert!(
            observed <= rate as f64 * 1.5,
            "aggregate {observed:.0}/s exceeds the shared {rate}/s limit"
        );
    }

    #[test]
    fn rate_limiter_holds_at_realistic_thread_counts() {
        // The earlier tests use 8 threads, which says nothing about a single mutex
        // shared by the 512 workers a default proxy scan actually spawns.
        let rate = 500;
        let threads = 512;
        let per_thread = 2;
        let r = Arc::new(RateLimiter::new(rate));
        let cancel = Cancel::new();
        let count = Arc::new(AtomicU64::new(0));

        let start = Instant::now();
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let (r, cancel, count) = (r.clone(), cancel.clone(), count.clone());
            handles.push(
                std::thread::Builder::new()
                    .stack_size(WORKER_STACK_BYTES)
                    .spawn(move || {
                        for _ in 0..per_thread {
                            r.acquire(&cancel);
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                    .expect("spawn"),
            );
        }
        for h in handles {
            h.join().unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total = count.load(Ordering::Relaxed);
        assert_eq!(
            total,
            (threads * per_thread) as u64,
            "every acquire must return"
        );

        let observed = total as f64 / elapsed;
        assert!(
            observed <= rate as f64 * 1.25,
            "{threads} threads observed {observed:.0}/s against a {rate}/s limit"
        );
        // Contention must not dominate: 1024 tokens at 500/s is ~2s of real waiting,
        // so anything past 3x that is the mutex, not the limiter.
        assert!(
            elapsed < 6.0,
            "took {elapsed:.1}s, suggesting lock contention rather than rate limiting"
        );
    }

    #[test]
    fn acquire_returns_promptly_when_cancelled() {
        let r = Arc::new(RateLimiter::new(1));
        let cancel = Cancel::new();
        r.acquire(&cancel); // drain the first token

        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            c2.request_graceful();
        });
        let start = Instant::now();
        r.acquire(&cancel);
        assert!(
            start.elapsed() < Duration::from_millis(600),
            "cancellation must break the rate-limit wait, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn worker_count_never_exceeds_the_work() {
        assert_eq!(worker_count(512, 10), 10);
        assert_eq!(worker_count(512, 100_000), 512);
        assert_eq!(worker_count(512, 0), 1);
        assert_eq!(worker_count(1, 100), 1);
    }
}
