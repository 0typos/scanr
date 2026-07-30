//! Configuration is less hostile than network input — a user supplies it — but it is
//! still arbitrary text reaching a parser, a validator, and a caret renderer that slices
//! the source by byte offset. Slicing by byte offset on arbitrary UTF-8 is exactly where
//! a panic hides.
//!
//! Property: any input either loads and validates, or produces errors that render
//! without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(config) = toml::from_str::<scanr::config::raw::RawConfig>(data) else {
        return;
    };

    let files = scanr::config::raw::Layered {
        files: vec![scanr::config::raw::LoadedFile {
            layer: scanr::config::raw::Layer::Project,
            path: std::path::PathBuf::from("fuzz.toml"),
            text: data.to_string(),
            config,
        }],
    };

    // Validation must not panic on any parseable config.
    let errors = scanr::config::validate(&files);

    // Rendering is the risky half: it locates a byte span in the source and slices
    // around it. Multi-byte characters near a span boundary are the hazard.
    //
    // The redaction property took two attempts to state correctly, both defeated by the
    // fuzzer rather than by review:
    //
    //  1. "a fixed string never appears in output" — defeated by moving that string into
    //     a transport *type*, where echoing it back is correct, not a leak.
    //  2. "no credential value appears anywhere in output" — defeated by making the
    //     password a substring of a legitimately-echoed value, since both were built
    //     from repeated 'b's.
    //
    // The property that actually holds, and is what the code implements: when the caret
    // renderer echoes a source line that assigns a credential, that line shows
    // `[redacted]` rather than the value.
    for e in &errors {
        for line in e.render(Some(data)).lines() {
            // Source echoes look like `N | <source text>`.
            let Some((_, src)) = line.split_once('|') else {
                continue;
            };
            if is_credential_assignment(src.trim()) {
                assert!(
                    src.contains("[redacted]"),
                    "the caret renderer echoed a credential assignment unredacted: {src:?}"
                );
            }
        }
    }

    // Name lookups walk the same structures and must tolerate anything.
    let _ = files.profile_names();
    let _ = files.transport_names();
    let _ = files.scan_names();
    let _ = files.target_set_names();
    let _ = files.port_set_names();
});

/// Does this source line assign a value to a credential key?
fn is_credential_assignment(line: &str) -> bool {
    let Some((lhs, rhs)) = line.split_once('=') else {
        return false;
    };
    if rhs.trim().is_empty() {
        return false;
    }
    let key = lhs.trim().trim_matches('"').to_ascii_lowercase();
    key == "password" || key.ends_with("_password") || key.ends_with("secret")
}
