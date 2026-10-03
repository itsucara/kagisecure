//! Adversarial tests for the TOTP engine and its `otpauth://` parser
//! (`kagisecure_core::totp`).
//!
//! A TOTP seed is a long-lived credential — losing one is losing a second factor for as long as
//! the user does not notice — so two properties matter more than any parsing nicety: the seed
//! must never appear in a rendering, and no input may make the parser panic or hang. A panic is
//! not merely a crash here: `[profile.release] panic = "abort"` at the workspace root means an
//! import that trips one takes the whole process down, and a `Secret` that was mid-flight is
//! never zeroized.
//!
//! Scenarios: C-14 (seed never reaches a log, `Debug` or error string), C-15 (malformed URIs
//! error rather than panic or hang).

mod common;

use common::rendered_error;
use kagisecure_core::model::Secret;
use kagisecure_core::totp::{Algorithm, Totp, TotpParams, base32_decode, base32_encode};

/// A canary seed, distinctive enough that finding it anywhere is unambiguous. Valid Base32.
const CANARY_SEED_B32: &str = "MZXWCANARYLANESEEDKAGISECURETOTPCANARY77";
/// The same seed after decoding, which is what a `Debug` of the internals would show.
fn canary_seed_bytes() -> Vec<u8> {
    base32_decode(CANARY_SEED_B32).expect("the canary seed must be valid Base32")
}

// ---------------------------------------------------------------------------------------------
// C-14 — the seed never reaches a rendering
// ---------------------------------------------------------------------------------------------

/// Every error path the parser has, driven with the canary seed present in the URI. The message
/// must never quote the URI, because the URI *is* the credential.
#[test]
fn no_totp_error_path_ever_quotes_the_seed() {
    let hostile = [
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&digits=9"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&digits=0"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&digits=999"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&digits=-1"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&digits=six"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&period=0"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&period=-30"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&period=99999999999999999999"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&algorithm=md5"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}&algorithm="),
        format!("otpauth://hotp/a?secret={CANARY_SEED_B32}&counter=1"),
        format!("otpauth://totp?secret={CANARY_SEED_B32}"),
        format!("https://evil.example/?secret={CANARY_SEED_B32}"),
        format!("otpauth://totp/a?secret={CANARY_SEED_B32}0"),
        format!("otpauth://totp/{CANARY_SEED_B32}"),
    ];

    let mut errors = 0;
    for uri in &hostile {
        if let Err(error) = Totp::parse_uri(uri) {
            let rendered = rendered_error(&error);
            assert!(
                !rendered.contains(CANARY_SEED_B32),
                "the error quoted the seed: {rendered}"
            );
            assert!(
                !rendered.contains(&CANARY_SEED_B32.to_ascii_lowercase()),
                "the error quoted the seed in lower case: {rendered}"
            );
            errors += 1;
        }
    }
    assert!(errors >= 10, "expected most of these URIs to be refused");
}

/// The same for the raw Base32 decoder, which is the function a hand-typed seed goes through.
#[test]
fn a_base32_decode_failure_never_quotes_its_input() {
    for input in [
        format!("{CANARY_SEED_B32}!"),
        format!("{CANARY_SEED_B32}0"),
        format!("{CANARY_SEED_B32}\u{1}"),
        format!("1{CANARY_SEED_B32}"),
    ] {
        let error = base32_decode(&input).expect_err(&input);
        assert!(!rendered_error(&error).contains(CANARY_SEED_B32));
    }
}

/// `Totp`, its `Secret` seed and the code it produces all render as `Secret(<redacted>)` or say
/// nothing at all, including inside a containing struct and inside a formatted panic message.
#[test]
fn nothing_about_a_configured_totp_renders_the_seed_or_the_code() {
    let totp = Totp::from_base32(CANARY_SEED_B32, TotpParams::default()).unwrap();
    let seed = canary_seed_bytes();
    let seed_text = String::from_utf8_lossy(&seed).into_owned();

    let rendered = format!("{totp:?}");
    assert!(rendered.contains("Secret(<redacted>)"), "{rendered}");
    assert!(!rendered.contains(CANARY_SEED_B32), "{rendered}");
    assert!(!rendered.contains(&seed_text), "{rendered}");

    let code = totp.code_at(1_700_000_000).unwrap();
    assert_eq!(format!("{code:?}"), "Secret(<redacted>)");

    // The URI form *is* the credential, so it is a `Secret` and renders as one — the only way to
    // the characters is the explicitly named escape hatch.
    let uri = totp.to_uri();
    assert_eq!(format!("{uri:?}"), "Secret(<redacted>)");
    assert!(uri.expose_str().unwrap().contains(CANARY_SEED_B32));

    // A seed handed in as raw bytes is treated identically.
    let raw = Totp::new(Secret::new(seed.clone()), TotpParams::default()).unwrap();
    assert!(!format!("{raw:?}").contains(&seed_text));
}

/// Parameters are metadata and may be rendered freely — but rendering them must not drag the
/// seed along, including through the caption the UI builds and through a label that an importer
/// filled in from a hostile QR code.
#[test]
fn rendering_totp_parameters_never_drags_the_seed_along() {
    let uri = format!(
        "otpauth://totp/{}:{}?secret={CANARY_SEED_B32}&issuer={}",
        CANARY_SEED_B32, "ada%40example.com", "ACME"
    );
    let totp = Totp::parse_uri(&uri).unwrap();
    let params = totp.params();
    let rendered = format!("{params:?} {:?}", params.caption());
    // The label legitimately echoes whatever the QR code carried, so the assertion is about the
    // *generator*, not the label: the parameters struct must hold no seed material of its own.
    assert!(!rendered.contains("secret="));
    assert_eq!(params.issuer.as_deref(), Some("ACME"));
    assert!(!format!("{totp:?}").contains(CANARY_SEED_B32));
}

// ---------------------------------------------------------------------------------------------
// C-15 — malformed URIs must error, never panic or hang
// ---------------------------------------------------------------------------------------------

/// A table of the shapes a hostile or merely broken `otpauth://` URI can take. Every one must
/// return — with `Ok` or `Err`, either is acceptable — without panicking.
fn hostile_uris() -> Vec<String> {
    let mut cases: Vec<String> = vec![
        String::new(),
        "o".to_owned(),
        "otpauth://".to_owned(),
        "otpauth:/".to_owned(),
        "OTPAUTH://TOTP/".to_owned(),
        "otpauth://totp/".to_owned(),
        "otpauth://totp/?".to_owned(),
        "otpauth://totp/?&&&&".to_owned(),
        "otpauth://totp/a?secret".to_owned(),
        "otpauth://totp/a?secret=".to_owned(),
        "otpauth://totp/a?=value".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=4294967296".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=255".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=256".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=\u{0}".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-512".to_owned(),
        "otpauth://totp/a?secret=!!!!".to_owned(),
        "otpauth://totp/a?secret=========".to_owned(),
        "otpauth://totp/a?secret=A".to_owned(),
        "otpauth://totp/:::::?secret=JBSWY3DPEHPK3PXP".to_owned(),
        // Percent escapes: truncated, invalid, and — the interesting ones — escapes whose
        // two hex digits straddle a multi-byte UTF-8 character boundary.
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%4".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%zz".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%\u{e9}".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%\u{20ac}".to_owned(),
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=%\u{1f600}".to_owned(),
        "otpauth://totp/\u{20ac}%\u{20ac}?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "otpauth://totp/a?secret=%\u{20ac}JBSWY3DPEHPK3PXP".to_owned(),
        // A non-ASCII byte immediately after the 10-character scheme prefix, so the `get(..10)`
        // slice lands on a character boundary only by luck.
        "otpauth:/\u{20ac}/totp/a?secret=JBSWY3DPEHPK3PXP".to_owned(),
        "\u{20ac}\u{20ac}\u{20ac}\u{20ac}".to_owned(),
    ];
    // Very long inputs, to catch anything quadratic or unbounded.
    cases.push(format!(
        "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP",
        "a".repeat(200_000)
    ));
    cases.push(format!("otpauth://totp/a?secret={}", "A".repeat(200_000)));
    cases.push(format!(
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP{}",
        "&x=1".repeat(50_000)
    ));
    cases.push(format!(
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer={}",
        "%".repeat(200_000)
    ));
    cases
}

/// The parser must return for every one of these, and must not panic.
#[test]
fn no_malformed_otpauth_uri_makes_the_parser_panic() {
    for uri in hostile_uris() {
        let label: String = uri.chars().take(60).collect();
        let outcome = std::panic::catch_unwind(|| Totp::parse_uri(&uri));
        assert!(
            outcome.is_ok(),
            "parsing panicked on: {label:?} (length {})",
            uri.len()
        );
    }
}

/// The companion to the test above, kept as the record of the fixed defect: no hostile URI
/// panics any more. `percent_decode` now reads its two-hex-digit window out of the byte slice
/// instead of re-slicing the `str`, so an escape straddling a multi-byte character decodes as a
/// literal `%` rather than slicing off a character boundary.
#[test]
fn the_inventory_of_otpauth_inputs_that_panic_is_empty() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let panicking: Vec<String> = hostile_uris()
        .into_iter()
        .filter(|uri| std::panic::catch_unwind(|| Totp::parse_uri(uri)).is_err())
        .collect();
    std::panic::set_hook(previous);

    let labels: Vec<String> = panicking
        .iter()
        .map(|uri| {
            format!(
                "len={} head={:?}",
                uri.len(),
                uri.chars().take(60).collect::<String>()
            )
        })
        .collect();
    assert!(labels.is_empty(), "these inputs still panic: {labels:?}");
}

/// Whatever the parser accepts, it must be usable without panicking: a period of zero would be a
/// division by zero in `counter_at`, and a digit count outside 6..=8 would overflow the decimal
/// rendering in `truncate`. Both are rejected at construction, so this drives the accepted
/// boundary values through the code-generation path.
#[test]
fn every_accepted_parameter_set_generates_a_code_without_panicking() {
    for digits in [6u8, 7, 8] {
        for period in [1u32, 15, 30, 90, u32::MAX] {
            for algorithm in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
                let totp = Totp::from_base32(
                    CANARY_SEED_B32,
                    TotpParams {
                        algorithm,
                        digits,
                        period,
                        issuer: None,
                        account: None,
                    },
                )
                .unwrap();
                for at in [0u64, 1, 59, 1_700_000_000, u64::MAX] {
                    let code = totp.code_at(at).unwrap();
                    let text = code.expose_str().unwrap();
                    assert_eq!(text.len(), usize::from(digits));
                    assert!(text.bytes().all(|b| b.is_ascii_digit()));
                    let left = totp.seconds_remaining(at);
                    assert!((1..=period).contains(&left), "{period}/{at}: {left}");
                }
            }
        }
    }
}

/// A zero period and an out-of-range digit count are refused at every entry point, so no
/// constructed `Totp` can ever divide by zero or overflow `10u32.pow(digits)`.
#[test]
fn a_zero_period_or_an_impossible_digit_count_is_refused_at_every_entry_point() {
    for (digits, period) in [(0u8, 30u32), (5, 30), (9, 30), (255, 30), (6, 0)] {
        let params = TotpParams {
            digits,
            period,
            ..TotpParams::default()
        };
        assert!(params.validate().is_err(), "{digits}/{period} validate()");
        assert!(
            Totp::new(Secret::new(canary_seed_bytes()), params.clone()).is_err(),
            "{digits}/{period} Totp::new"
        );
        assert!(
            Totp::from_base32(CANARY_SEED_B32, params).is_err(),
            "{digits}/{period} Totp::from_base32"
        );
    }
}

/// Base32 decoding must terminate and must not panic on any byte sequence, including inputs
/// made entirely of skipped characters and inputs with a truncated final group.
#[test]
fn base32_decoding_terminates_on_every_byte_sequence() {
    let mut cases: Vec<String> = vec![
        String::new(),
        "=".repeat(1000),
        " \t\n-".repeat(1000),
        "A".to_owned(),
        "AB".to_owned(),
        "ABC".to_owned(),
        "\u{20ac}".to_owned(),
        "\u{1f600}".repeat(100),
    ];
    for byte in 0u8..=127 {
        cases.push(format!("JBSW{}", char::from(byte)));
    }
    cases.push("A".repeat(500_000));

    for case in cases {
        let outcome = std::panic::catch_unwind(|| base32_decode(&case));
        assert!(outcome.is_ok(), "base32_decode panicked on {case:?}");
    }

    // Encoding is total and round-trips, which is what the decoder's tolerance is for.
    for length in 1..64usize {
        let bytes: Vec<u8> = (0..length).map(|i| (i * 31 + 7) as u8).collect();
        assert_eq!(base32_decode(&base32_encode(&bytes)).unwrap(), bytes);
    }
}
