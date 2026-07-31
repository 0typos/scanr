//! Seeded index permutation for randomized probe order (D16).
//!
//! Randomizing probe order across the whole target×port matrix spreads load and avoids
//! the burst pattern that IDS most readily flags. Materializing and shuffling the index
//! space is not viable — a /16 × 1000 ports is 65M entries, ~520 MB.
//!
//! Instead we use a 4-round Feistel network over the smallest power of two ≥ N, with
//! cycle-walking to skip out-of-range outputs. This gives:
//!
//!   * O(1) memory, streaming
//!   * a genuine bijection over [0, N)
//!   * exact reproducibility from a recorded 64-bit seed
//!
//! A scan can therefore be randomized *and* replayable, which an in-memory shuffle
//! would only manage by storing the whole permutation.

/// A bijection over `[0, n)` parameterized by a 64-bit seed.
#[derive(Debug, Clone)]
pub struct Permutation {
    n: u64,
    half_bits: u32,
    half_mask: u64,
    keys: [u64; ROUNDS],
}

const ROUNDS: usize = 4;

/// splitmix64 finalizer — cheap, and good enough avalanche for a round function.
#[inline]
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl Permutation {
    pub fn new(n: u64, seed: u64) -> Self {
        // Smallest even bit-width whose 2^bits >= n, minimum 2 so each half is >= 1 bit.
        let mut bits = 2u32;
        while bits < 64 && (1u64 << bits) < n {
            bits += 2;
        }
        let half_bits = bits / 2;

        let mut keys = [0u64; ROUNDS];
        let mut s = seed;
        for k in keys.iter_mut() {
            s = mix(s);
            *k = s;
        }

        Self {
            n,
            half_bits,
            half_mask: (1u64 << half_bits) - 1,
            keys,
        }
    }

    /// One pass of the Feistel network over the full 2^(2*half_bits) domain.
    #[inline]
    fn feistel(&self, x: u64) -> u64 {
        let mut l = (x >> self.half_bits) & self.half_mask;
        let mut r = x & self.half_mask;
        for k in self.keys {
            let f = mix(r ^ k) & self.half_mask;
            let next = l ^ f;
            l = r;
            r = next;
        }
        (l << self.half_bits) | r
    }

    /// Map an index in `[0, n)` to its permuted position in `[0, n)`.
    ///
    /// Cycle-walking: the Feistel network permutes `[0, 2^bits)`, which may be up to
    /// 4× larger than `n` (bit-width steps by 2). Re-applying until the output lands in
    /// range yields a bijection over `[0, n)`. Expected iterations stay small.
    #[inline]
    pub fn apply(&self, index: u64) -> u64 {
        debug_assert!(index < self.n);
        if self.n <= 1 {
            return index;
        }
        let mut x = index;
        loop {
            x = self.feistel(x);
            if x < self.n {
                return x;
            }
        }
    }

    pub fn len(&self) -> u64 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

/// Fill `buf` from the OS entropy source, reporting whether it succeeded.
///
/// Two spellings because there is no one call: Linux has `getrandom(2)`, and Apple
/// platforms have `getentropy(2)` instead — the sole thing that stopped this crate
/// compiling for macOS.
#[cfg(target_os = "linux")]
fn os_entropy(buf: &mut [u8]) -> bool {
    // SAFETY: getrandom writes at most buf.len() bytes into a buffer we own.
    let rc = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    rc == buf.len() as isize
}

#[cfg(target_vendor = "apple")]
fn os_entropy(buf: &mut [u8]) -> bool {
    // SAFETY: getentropy writes exactly buf.len() bytes into a buffer we own, and is
    // documented to accept up to 256 at a time.
    let rc = unsafe { libc::getentropy(buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    rc == 0
}

/// Draw a seed from the OS. Used when the user has not pinned one with `--seed`.
pub fn random_seed() -> u64 {
    let mut buf = [0u8; 8];
    // The OS call cannot fail for an 8-byte buffer, but fall back to a clock-derived
    // seed rather than panicking in the unreachable case.
    if os_entropy(&mut buf) {
        u64::from_ne_bytes(buf)
    } else {
        mix(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5EED))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn assert_bijection(n: u64, seed: u64) {
        let p = Permutation::new(n, seed);
        let mut seen = HashSet::with_capacity(n as usize);
        for i in 0..n {
            let v = p.apply(i);
            assert!(v < n, "n={n} seed={seed}: apply({i}) = {v} out of range");
            assert!(
                seen.insert(v),
                "n={n} seed={seed}: apply({i}) = {v} collided"
            );
        }
        assert_eq!(seen.len(), n as usize);
    }

    #[test]
    fn bijection_over_representative_sizes() {
        for n in [1u64, 2, 3, 4, 5, 255, 256, 257, 1000, 65536, 255510] {
            assert_bijection(n, 0x9f2c_00a1_b4de_7731);
        }
    }

    #[test]
    fn bijection_across_seeds() {
        for seed in [0u64, 1, u64::MAX, 0xdead_beef_cafe_f00d] {
            assert_bijection(1009, seed);
        }
    }

    #[test]
    fn stable_for_a_fixed_seed() {
        // This is what makes a randomized scan replayable.
        let a = Permutation::new(100_000, 42);
        let b = Permutation::new(100_000, 42);
        for i in (0..100_000).step_by(997) {
            assert_eq!(a.apply(i), b.apply(i));
        }
    }

    #[test]
    fn different_seeds_give_different_orders() {
        let a = Permutation::new(100_000, 1);
        let b = Permutation::new(100_000, 2);
        let differing = (0..1000).filter(|&i| a.apply(i) != b.apply(i)).count();
        assert!(differing > 900, "seeds produced near-identical orders");
    }

    #[test]
    fn actually_scatters() {
        // A sequential-ish permutation would defeat the purpose. Check that the first
        // 1000 outputs are spread across the whole range rather than clustered.
        let n = 1_000_000u64;
        let p = Permutation::new(n, 7);
        let buckets = 10;
        let mut hits = vec![0usize; buckets];
        for i in 0..1000 {
            hits[(p.apply(i) * buckets as u64 / n) as usize] += 1;
        }
        for (b, &h) in hits.iter().enumerate() {
            assert!(h > 30, "bucket {b} got only {h} of 1000 — poor scattering");
        }
    }

    #[test]
    fn handles_huge_domains_without_allocating() {
        // /16 × 1000 ports. The point of the design: no memory proportional to n.
        let n = 65_536u64 * 1000;
        let p = Permutation::new(n, 3);
        for i in [0u64, 1, n / 2, n - 1] {
            assert!(p.apply(i) < n);
        }
    }
}
