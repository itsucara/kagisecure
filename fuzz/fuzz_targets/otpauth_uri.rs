//! C-15: the `otpauth://` parser and its Base32 decoder must error, never panic or hang.
//!
//! A TOTP URI arrives from a scanned QR code or a pasted string — attacker-influenced input on
//! the import path. `Totp::parse_uri` slices the input by byte offsets in several places, so a
//! multi-byte UTF-8 character landing on one of those boundaries is the shape of defect this
//! target is looking for.

#![no_main]

use kagisecure_core::totp::{Totp, base32_decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let _ = base32_decode(text);

    if let Ok(totp) = Totp::parse_uri(text) {
        // Anything the parser accepts must also be usable: a period of zero would divide by zero
        // and a digit count outside 6..=8 would overflow the decimal rendering.
        let _ = totp.code_at(0);
        let _ = totp.code_at(u64::MAX);
        let _ = totp.seconds_remaining(u64::MAX);
        let uri = totp.to_uri();
        if let Some(rendered) = uri.expose_str() {
            let _ = Totp::parse_uri(rendered);
        }
    }
});
