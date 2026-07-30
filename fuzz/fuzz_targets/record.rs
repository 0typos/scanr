//! `scanr output verify` and `summarize` read files that may be truncated, corrupted, or
//! written by a different version — a crashed scan leaves a partial file by design, so
//! malformed input is the expected case rather than the exceptional one.
//!
//! Property: any bytes produce a report or a clean error, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The reader takes a path, so the input has to reach it as a file.
    let Ok(dir) = tempfile::tempdir() else { return };
    let path = dir.path().join("scan-1-abcd1234.jsonl");
    if std::fs::write(&path, data).is_err() {
        return;
    }

    // verify must always produce a report rather than failing on content.
    if let Ok(report) = scanr::verify::verify(&path) {
        // Rendering walks every problem string.
        let _ = report.render();
    }

    // summarize and remainder are allowed to reject the file, not to panic on it.
    let _ = scanr::verify::summarize(&path);
    let _ = scanr::verify::remainder(&path);
});
