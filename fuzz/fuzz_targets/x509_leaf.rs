//! The X.509 leaf reader takes the certificate a TLS server chose to send. Every length,
//! tag, string and time in it is the peer's.
//!
//! Property: for any byte sequence the reader terminates, never panics, keeps every
//! string it reports to printable ASCII, and gives the same answer twice.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanr::x509::{MAX_NAMES, parse, summary_json};

fuzz_target!(|data: &[u8]| {
    let first = parse(data);
    if let Ok(leaf) = &first {
        for s in [&leaf.subject, &leaf.issuer].into_iter().chain(&leaf.san) {
            assert!(s.bytes().all(|b| (b' '..=b'~').contains(&b)), "{s:?}");
        }
        assert!(leaf.san.len() <= MAX_NAMES);
        assert!(leaf.san.len() as u32 <= leaf.san_count);
        let json = leaf.to_json();
        assert_eq!(summary_json(&json), leaf.summary());
    }
    assert_eq!(parse(data), first);
});
