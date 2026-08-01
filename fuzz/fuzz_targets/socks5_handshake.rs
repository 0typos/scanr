//! The whole SOCKS5 exchange against an arbitrary peer, not just its final reply.
//!
//! `socks5_reply` covers the CONNECT reply parser. This covers everything before it: the
//! greeting, method selection, and the RFC 1929 authentication sub-negotiation. Those
//! have more state and are equally peer-controlled — a proxy chooses the auth method,
//! supplies the status byte we act on, and can close or stall at any point.
//!
//! Property: for any peer behaviour, the handshake either completes or returns a probe
//! outcome. It must never panic and never loop forever.

#![no_main]

use std::io::{Read, Write};
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use scanr::plan::types::Fidelity;
use scanr::probe::{Phases, State};
use scanr::transport::socks5::{Socks5Transport, read_reply};

/// A peer that replies with fuzzer-supplied bytes and discards whatever we send.
struct FuzzPeer<'a> {
    inbound: std::io::Cursor<&'a [u8]>,
    written: usize,
}

impl Read for FuzzPeer<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inbound.read(buf)
    }
}

impl Write for FuzzPeer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written += buf.len();
        // A real proxy can also stop reading. Refusing writes past a bound exercises the
        // error path without needing a second fuzzer input.
        if self.written > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer stopped reading",
            ));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    // First byte selects whether credentials are configured, so both the no-auth and
    // username/password paths are reachable from one corpus.
    let (mode, body) = data.split_first().unwrap_or((&0, &[]));
    let (user, pass) = match mode % 3 {
        0 => (None, None),
        1 => (Some("scanner".to_string()), Some("hunter2".to_string())),
        // A username with no password is accepted by config and must not panic here.
        _ => (Some("scanner".to_string()), None),
    };

    let client = Socks5Transport::new(
        "fuzz".into(),
        "127.0.0.1:1080".parse().expect("valid literal"),
        user,
        pass,
        Fidelity::Unknown,
    );

    let mut peer = FuzzPeer {
        inbound: std::io::Cursor::new(body),
        written: 0,
    };
    let mut phases = Phases::default();

    // Credentials belong to the hop now, not the transport: a chain presents a different
    // pair at each link. One hop is what a single proxy is.
    let hop = client.hops()[0].clone();
    match client.negotiate(&mut peer, &hop, &mut phases, Instant::now()) {
        Ok(()) => {
            // A completed handshake must have consumed a well-formed method selection.
            assert!(
                body.len() >= 2 && body[0] == 0x05,
                "accepted a greeting that was not SOCKS5: {body:?}"
            );
            // Whatever remains is the CONNECT reply; parsing it must also be safe.
            let _ = read_reply(&mut peer);
        }
        Err(outcome) => {
            // A failure must always be reportable: a state, and a reason a human can read.
            assert!(
                outcome.state != State::Open,
                "a failed handshake must not report open"
            );
            assert!(
                outcome.reason.is_some(),
                "a failed handshake must carry a reason"
            );
        }
    }
});
