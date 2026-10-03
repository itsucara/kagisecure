//! Shared helpers for the adversarial test files.
//!
//! These tests exist to hunt for latent defects rather than to cover the happy path, so they all
//! need the same three things: a vault that is cheap enough to unlock thousands of times, a
//! named canary value that must never be recoverable from anything the product returns, and a
//! handful of "did the secret survive an encoding?" decoders so an exfiltration test can prove
//! recovery rather than merely assert the literal bytes are gone.
//!
//! Every helper here drives the real components — `kagisecure_core::vault::Vault`,
//! `kagisecure_core::inject` — with no stubbing.

#![allow(dead_code)]

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_core::{Error, RecoveryCode};
use std::path::{Path, PathBuf};

/// The master password every adversarial vault test uses.
pub const PASSWORD: &[u8] = b"correct horse battery staple";

/// The canary secret. Long, distinctive and with no substring that occurs naturally, so that
/// finding *any* eight-byte window of it in an output is unambiguous evidence of a leak.
pub const CANARY: &str = "sk_live_kagisecure_canary_LANE1_7f4b2ce9d1a05836";

/// Argon2id parameters cheap enough to unlock in a loop. The *file* decides the cost, so a
/// non-default value here is part of the assertion rather than a shortcut.
pub fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Adversarial".to_owned(),
        kdf_hint: Some("lane1-adversarial".to_owned()),
    }
}

/// Create a fresh vault under `dir` with [`PASSWORD`] and [`cheap_options`].
pub fn new_vault(dir: &Path) -> (Vault, RecoveryCode, PathBuf) {
    let path = dir.join("adversarial.kagivault");
    let (vault, code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    (vault, code, path)
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The shortest prefix of a secret that counts as a leak.
///
/// Anything shorter is noise: a single byte of an API key occurs in every English word, and the
/// redaction marker `[kagisecure:redacted:NAME]` itself shares short runs with the canary.
pub const MIN_SIGNIFICANT_PREFIX: usize = 8;

/// The longest prefix of `needle` of at least [`MIN_SIGNIFICANT_PREFIX`] bytes that appears
/// anywhere in `haystack`, or 0 if there is none.
///
/// A masking test wants this rather than a boolean: leaking the first half of an API key is a
/// finding, and `contains` would report it as clean.
pub fn longest_leaked_prefix(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.len() < MIN_SIGNIFICANT_PREFIX {
        return 0;
    }
    (MIN_SIGNIFICANT_PREFIX..=needle.len())
        .rev()
        .find(|len| contains(haystack, &needle[..*len]))
        .unwrap_or(0)
}

/// Decode standard Base64, ignoring whitespace and padding. Returns `None` on any other
/// character, so a test can say "this output does not even decode" rather than guessing.
pub fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut width = 0u32;
    let mut out = Vec::new();
    for byte in input {
        if byte.is_ascii_whitespace() || *byte == b'=' {
            continue;
        }
        let value = ALPHABET.iter().position(|c| c == byte)? as u32;
        bits = (bits << 6) | value;
        width += 6;
        if width >= 8 {
            width -= 8;
            out.push(((bits >> width) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Decode lower- or upper-case hex, ignoring whitespace.
pub fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// Render an [`Error`] the way a user-facing caller would, including its source chain.
pub fn rendered_error(error: &Error) -> String {
    let mut text = format!("{error} | {error:?}");
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(inner) = source {
        text.push_str(&format!(" | {inner}"));
        source = inner.source();
    }
    text
}

/// A `/bin/sh -c <script>` invocation, for the tests whose whole point is that the *approved
/// command itself* is hostile. The injector never builds a shell string of its own; the shell is
/// the program the caller chose (`inject/mod.rs` module docs, rule 1).
#[cfg(unix)]
pub fn shell(script: &str) -> (std::ffi::OsString, Vec<std::ffi::OsString>) {
    (
        std::ffi::OsString::from("/bin/sh"),
        vec![
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(script),
        ],
    )
}
