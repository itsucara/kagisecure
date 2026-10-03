//! Step 11 (ADR-0035): the bundle reader must never panic on untrusted bytes.
//!
//! A bundle is a single file holding many records — a shared vault handed over as one attachment
//! or carried on a USB stick — so `bundle::parse` sees the same untrusted-file exposure the
//! exchange directory's individual `.ksr` files do (`shared_record.rs`), plus its own framing:
//! a magic, a version, a bounded record count and a length prefix per record, each checked
//! against what remains before it is trusted. This target drives parsing and, for anything that
//! does parse, re-encoding it, neither of which may panic.

#![no_main]

use kagisecure_shared::bundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelopes) = bundle::parse(data) {
        let _ = bundle::encode(&envelopes);
    }
});
