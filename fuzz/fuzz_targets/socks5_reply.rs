//! The SOCKS5 reply parser reads bytes from a proxy scanr does not control, and a
//! hostile or simply broken proxy is squarely in the threat model. The bound-address
//! length in an `ATYP_DOMAIN` reply is supplied by the peer, which makes this the most
//! security-relevant parser in the crate.
//!
//! Property: for any byte sequence, parsing either returns a reply code or an error.
//! It must never panic, never hang, and never read past what it was given.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanr::transport::socks5::read_reply;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    match read_reply(&mut cursor) {
        Ok(code) => {
            // A success can only be reported for a well-formed reply, which must have
            // begun with the version byte.
            assert!(!data.is_empty());
            assert_eq!(data[0], 0x05, "accepted a reply with a non-SOCKS5 version");
            // Whatever came back must be a byte we can describe.
            let _ = scanr::transport::socks5::reply_name(code);
        }
        Err(_) => {}
    }

    // Reading twice from the same bytes must agree: the parser holds no hidden state.
    let mut again = std::io::Cursor::new(data);
    let a = read_reply(&mut std::io::Cursor::new(data)).ok();
    let b = read_reply(&mut again).ok();
    assert_eq!(a, b, "parsing is not deterministic for {data:?}");
});
