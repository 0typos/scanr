//! The HTTP CONNECT response parser reads bytes from a proxy scanr does not control. The
//! header block's length is the peer's choice, the status line is parsed into a number
//! that is acted on, and header values are echoed into a reason string that reaches the
//! screen and the record.
//!
//! Property: for any byte sequence, parsing either returns a response with a three-digit
//! status and printable-ASCII text, or an error. It must never panic, never read past
//! `MAX_RESPONSE_BYTES`, and never accept something that did not start with `HTTP/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanr::transport::http::{MAX_RESPONSE_BYTES, read_response};

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    match read_response(&mut cursor, None) {
        Ok(r) => {
            assert!(data.starts_with(b"HTTP/"), "accepted a non-HTTP response");
            assert!((100..1000).contains(&r.status), "status {} out of range", r.status);
            assert!(
                r.status_line.bytes().all(|b| (b' '..=b'~').contains(&b)),
                "status line not printable: {:?}",
                r.status_line
            );
            for (n, v) in &r.headers {
                assert!(v.bytes().all(|b| (b' '..=b'~').contains(&b)), "{n}: {v:?}");
            }
            // Nothing past the blank line may have been consumed: it belongs to the
            // destination.
            assert!(cursor.position() as usize <= MAX_RESPONSE_BYTES);
        }
        Err(_) => {}
    }
    // Parsing holds no hidden state: the same bytes give the same answer.
    let a = read_response(&mut std::io::Cursor::new(data), None).ok();
    let b = read_response(&mut std::io::Cursor::new(data), None).ok();
    assert_eq!(a, b);
});
