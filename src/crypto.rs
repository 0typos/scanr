//! The arithmetic a TLS 1.3 first flight needs and nothing more: X25519, HMAC/HKDF over
//! SHA-256, AES-128-GCM. Hand-rolled, as the SHA-256 was (D35): a few hundred lines
//! against a dependency tree, and the static musl build stays free of C and assembly.
//!
//! None of it protects a secret. The probe's private key is a published constant, the
//! session carries nothing after the server's flight, and a wrong answer is a failed
//! probe rather than a hole. So there is no constant-time discipline here, on purpose;
//! what there is instead is a test vector from the RFC or NIST for every primitive.

use crate::tls::sha256;

// ---------------------------------------------------------------- X25519 (RFC 7748)

/// A field element mod 2^255 − 19 in five 51-bit limbs.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const MASK51: u64 = (1 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    fn carry(mut self) -> Fe {
        for i in 0..4 {
            let c = self.0[i] >> 51;
            self.0[i] &= MASK51;
            self.0[i + 1] += c;
        }
        let c = self.0[4] >> 51;
        self.0[4] &= MASK51;
        self.0[0] += c * 19;
        let c = self.0[0] >> 51;
        self.0[0] &= MASK51;
        self.0[1] += c;
        self
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut h = self.carry().carry().0;
        // Subtract p once if the value is in [p, 2^255): q is 1 exactly then.
        let mut q = (h[0] + 19) >> 51;
        for limb in &h[1..] {
            q = (limb + q) >> 51;
        }
        h[0] += 19 * q;
        for i in 0..4 {
            let c = h[i] >> 51;
            h[i] &= MASK51;
            h[i + 1] += c;
        }
        h[4] &= MASK51;
        let mut out = [0u8; 32];
        let words = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    fn add(self, o: Fe) -> Fe {
        let mut r = self;
        for i in 0..5 {
            r.0[i] += o.0[i];
        }
        r.carry()
    }

    fn sub(self, o: Fe) -> Fe {
        // self + 2p − o keeps every limb positive.
        let mut r = self;
        r.0[0] += 0xf_ffff_ffff_ffda;
        for i in 1..5 {
            r.0[i] += 0xf_ffff_ffff_fffe;
        }
        for i in 0..5 {
            r.0[i] -= o.0[i];
        }
        r.carry()
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0.map(u128::from);
        let b = o.0.map(u128::from);
        let b19 = b.map(|x| x * 19);
        let r = [
            a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1],
            a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2],
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3],
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4],
            a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
        ];
        Fe::reduce_wide(r)
    }

    fn reduce_wide(r: [u128; 5]) -> Fe {
        let mut h = [0u64; 5];
        let mut c: u128 = 0;
        for i in 0..5 {
            let v = r[i] + c;
            h[i] = (v as u64) & MASK51;
            c = v >> 51;
        }
        h[0] += (c as u64) * 19;
        Fe(h).carry()
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn mul_small(self, k: u64) -> Fe {
        let r = self.0.map(|x| u128::from(x) * u128::from(k));
        Fe::reduce_wide(r)
    }

    /// `self^(p−2)`: the inverse, by square-and-multiply over the fixed exponent.
    fn invert(self) -> Fe {
        // p − 2 = 2^255 − 21: every bit set from 254 down to 5, then 0b01011.
        let mut r = Fe::ONE;
        for bit in (0..255).rev() {
            r = r.square();
            let set = if bit >= 5 {
                true
            } else {
                (0b01011 >> bit) & 1 == 1
            };
            if set {
                r = r.mul(self);
            }
        }
        r
    }
}

fn cswap(swap: bool, a: &mut Fe, b: &mut Fe) {
    if swap {
        std::mem::swap(a, b);
    }
}

/// RFC 7748 §5: the Montgomery ladder. `scalar` is clamped here.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let mut u = *point;
    u[31] &= 127;
    let x1 = Fe::from_bytes(&u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = false;
    for t in (0..255).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1 == 1;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    x2.mul(z2.invert()).to_bytes()
}

/// The public key for a private scalar: `X25519(k, 9)`.
pub fn x25519_public(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

// ---------------------------------------------------------------- HMAC, HKDF (RFC 2104, 5869, 8446)

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut msg = t.clone();
        msg.extend_from_slice(info);
        msg.push(i);
        t = hmac_sha256(prk, &msg).to_vec();
        out.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// RFC 8446 §7.1 `HKDF-Expand-Label`.
pub fn hkdf_expand_label(secret: &[u8; 32], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

fn to32(v: Vec<u8>) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// The server handshake traffic key and IV for an ECDHE shared secret and the hash of
/// `ClientHello || ServerHello` (RFC 8446 §7.1, no PSK).
pub fn tls13_server_handshake_keys(
    shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> ([u8; 16], [u8; 12]) {
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived = to32(hkdf_expand_label(&early, "derived", &sha256(&[]), 32));
    let handshake = hkdf_extract(&derived, shared);
    let server = to32(hkdf_expand_label(
        &handshake,
        "s hs traffic",
        transcript_hash,
        32,
    ));
    let key = hkdf_expand_label(&server, "key", &[], 16);
    let iv = hkdf_expand_label(&server, "iv", &[], 12);
    (key.try_into().unwrap(), iv.try_into().unwrap())
}

// ---------------------------------------------------------------- AES-128 (FIPS 197)

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES-128 with its eleven round keys expanded once.
pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Aes128 {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [
                    SBOX[t[1] as usize] ^ rcon,
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon = xtime(rcon);
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ t[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for (r, rk) in round_keys.iter_mut().enumerate() {
            for c in 0..4 {
                rk[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Aes128 { round_keys }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let add = |s: &mut [u8; 16], rk: &[u8; 16]| {
            for i in 0..16 {
                s[i] ^= rk[i];
            }
        };
        add(block, &self.round_keys[0]);
        for round in 1..=10 {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // ShiftRows on the column-major state: row r rotates left by r.
            let s = *block;
            for c in 0..4 {
                for r in 0..4 {
                    block[c * 4 + r] = s[((c + r) % 4) * 4 + r];
                }
            }
            if round != 10 {
                for c in 0..4 {
                    let col = &mut block[c * 4..c * 4 + 4];
                    let (a0, a1, a2, a3) = (col[0], col[1], col[2], col[3]);
                    let all = a0 ^ a1 ^ a2 ^ a3;
                    col[0] ^= all ^ xtime(a0 ^ a1);
                    col[1] ^= all ^ xtime(a1 ^ a2);
                    col[2] ^= all ^ xtime(a2 ^ a3);
                    col[3] ^= all ^ xtime(a3 ^ a0);
                }
            }
            add(block, &self.round_keys[round]);
        }
    }
}

// ---------------------------------------------------------------- GCM (NIST SP 800-38D)

fn ghash_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    let mut absorb = |data: &[u8]| {
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            y = ghash_mul(y ^ u128::from_be_bytes(block), h);
        }
    };
    absorb(aad);
    absorb(ct);
    let lens = (((aad.len() as u128) * 8) << 64) | ((ct.len() as u128) * 8);
    ghash_mul(y ^ lens, h)
}

/// AES-128-GCM with a 96-bit nonce. `open` checks the tag; `seal` appends one.
pub struct Aes128Gcm {
    aes: Aes128,
    h: u128,
}

impl Aes128Gcm {
    pub fn new(key: &[u8; 16]) -> Aes128Gcm {
        let aes = Aes128::new(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        Aes128Gcm {
            aes,
            h: u128::from_be_bytes(h),
        }
    }

    fn ctr(&self, nonce: &[u8; 12], counter: u32) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(nonce);
        block[12..].copy_from_slice(&counter.to_be_bytes());
        self.aes.encrypt_block(&mut block);
        block
    }

    fn keystream_xor(&self, nonce: &[u8; 12], data: &mut [u8]) {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let ks = self.ctr(nonce, 2 + i as u32);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let s = ghash(self.h, aad, ct);
        let ek = u128::from_be_bytes(self.ctr(nonce, 1));
        (s ^ ek).to_be_bytes()
    }

    /// Decrypt `ciphertext || tag`; `None` when the tag does not match.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 16 {
            return None;
        }
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        if self.tag(nonce, aad, ct) != tag {
            return None;
        }
        let mut pt = ct.to_vec();
        self.keystream_xor(nonce, &mut pt);
        Some(pt)
    }

    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut ct = plaintext.to_vec();
        self.keystream_xor(nonce, &mut ct);
        let tag = self.tag(nonce, aad, &ct);
        ct.extend_from_slice(&tag);
        ct
    }
}

/// RFC 8446 §5.3: the per-record nonce is the IV xor the sequence number.
pub fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn x25519_matches_rfc_7748_vectors() {
        // §5.2, first vector.
        let k = arr32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            hex(&x25519(&k, &u)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
        // §5.2, second vector.
        let k = arr32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            hex(&x25519(&k, &u)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
        // §5.2, one iteration from the base point.
        let mut k = [0u8; 32];
        k[0] = 9;
        assert_eq!(
            hex(&x25519(&k, &k)),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
    }

    #[test]
    fn x25519_diffie_hellman_agrees_both_ways() {
        // §6.1.
        let alice = arr32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = arr32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_pub = x25519_public(&alice);
        let bob_pub = x25519_public(&bob);
        assert_eq!(
            hex(&alice_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&bob_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex(&x25519(&alice, &bob_pub)), shared);
        assert_eq!(hex(&x25519(&bob, &alice_pub)), shared);
    }

    #[test]
    fn hkdf_matches_rfc_5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        assert_eq!(
            hex(&hkdf_expand(&prk, &info, 42)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn the_tls13_schedule_matches_rfc_8448_up_to_the_handshake_secret() {
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        assert_eq!(
            hex(&early),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
        let derived = hkdf_expand_label(&early, "derived", &sha256(&[]), 32);
        assert_eq!(
            hex(&derived),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );
        let client = arr32("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
        let server_pub = arr32("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
        let shared = x25519(&client, &server_pub);
        assert_eq!(
            hex(&shared),
            "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
        );
        let handshake = hkdf_extract(&to32(derived), &shared);
        assert_eq!(
            hex(&handshake),
            "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
        );
    }

    #[test]
    fn aes128_matches_fips_197() {
        let key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let mut block: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        Aes128::new(&key).encrypt_block(&mut block);
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    #[test]
    fn gcm_matches_the_nist_test_cases() {
        // Test case 2: zero key, zero nonce, one zero block.
        let gcm = Aes128Gcm::new(&[0u8; 16]);
        let sealed = gcm.seal(&[0u8; 12], &[], &[0u8; 16]);
        assert_eq!(
            hex(&sealed),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
        );
        assert_eq!(gcm.open(&[0u8; 12], &[], &sealed), Some(vec![0u8; 16]));
        // Test case 4: with associated data and a partial final block.
        let key: [u8; 16] = unhex("feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let gcm = Aes128Gcm::new(&key);
        let sealed = gcm.seal(&nonce, &aad, &pt);
        assert_eq!(
            hex(&sealed),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"
        );
        assert_eq!(gcm.open(&nonce, &aad, &sealed), Some(pt));
        let mut bad = sealed.clone();
        bad[3] ^= 1;
        assert_eq!(
            gcm.open(&nonce, &aad, &bad),
            None,
            "a flipped byte fails the tag"
        );
        assert_eq!(
            gcm.open(&nonce, b"other", &sealed),
            None,
            "wrong AAD fails the tag"
        );
    }

    #[test]
    fn the_record_nonce_xors_the_sequence_into_the_iv_tail() {
        let iv = [0xffu8; 12];
        let n = tls13_nonce(&iv, 1);
        assert_eq!(&n[..4], &[0xff; 4]);
        assert_eq!(n[11], 0xfe);
    }
}
