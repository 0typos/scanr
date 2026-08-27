//! The TLS server-flight parser reads bytes from a service scanr does not control: record
//! lengths, handshake lengths, certificate lengths and the ALPN string are all the
//! peer's choice, and the leaf certificate is copied into the record.
//!
//! Property: for any byte sequence the parser terminates, never panics, never keeps a
//! leaf over `MAX_LEAF_DER`, and any ALPN it reports is printable ASCII.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanr::tls::{MAX_LEAF_DER, TlsObservation, client_hello, read_server_flight};

fuzz_target!(|data: &[u8]| {
    let hello = client_hello(None);
    let mut obs = TlsObservation::default();
    read_server_flight(&mut std::io::Cursor::new(data), None, &mut obs, &hello);
    if let Some(der) = &obs.leaf_der {
        assert!(der.len() <= MAX_LEAF_DER);
        assert_eq!(obs.leaf_sha256, Some(scanr::tls::sha256(der)));
    }
    if let Some(a) = &obs.alpn {
        assert!(a.bytes().all(|b| (b' '..=b'~').contains(&b)), "{a:?}");
    }
    assert!(obs.read_bytes as usize <= data.len());
    // The JSON form must always be producible.
    let _ = obs.to_json();
    let _ = obs.display();

    // No hidden state: the same bytes give the same observation.
    let mut again = TlsObservation::default();
    read_server_flight(&mut std::io::Cursor::new(data), None, &mut again, &hello);
    assert_eq!(obs, again);
});
