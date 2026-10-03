//! C-08: the vault header and body parser must never panic on untrusted bytes.
//!
//! `vault::header::split` is documented as safe to run on wholly untrusted input — it runs before
//! any key material is touched, so it is the first thing a downloaded or corrupted `.kagivault`
//! reaches. `[profile.release] panic = "abort"` at the workspace root means a panic here is a
//! process abort, not a caught error, so "never panics" is a hard requirement rather than a
//! nicety. This target drives the whole prefix/length/CBOR path with arbitrary bytes, and then
//! re-runs the parts the parser accepted through a truncated copy of the same input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kagisecure_core::vault::header::split(data);

    // A truncation of an otherwise well-formed file is the realistic corruption: a save that was
    // interrupted, a partial download, a truncated backup.
    if data.len() > 4 {
        for cut in [data.len() / 2, data.len() - 1, data.len() - 4] {
            let _ = kagisecure_core::vault::header::split(&data[..cut]);
        }
    }

    // And the header CBOR on its own, which is what a caller that re-encodes a header sees.
    let _ = kagisecure_core::vault::header::Header::from_cbor(data);
});
