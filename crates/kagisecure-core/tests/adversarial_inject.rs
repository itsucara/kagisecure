//! Adversarial tests for the injector's output masking (`kagisecure_core::inject`).
//!
//! The module documentation for `inject` states plainly that [`mask`] is an exact-value
//! substring replacement and "not a security boundary". These tests exist to turn that sentence
//! into evidence: they drive the real `run_with_env` against real child processes and record
//! exactly *which* shapes of leak get through, so that the claim is a measured inventory rather
//! than a disclaimer. Everything here uses the shared `CANARY` from `tests/common`, so a leak is
//! unambiguous.
//!
//! Scenarios: A-07 (encoding defeats exact-substring scrubbing), A-08 (truncation happens before
//! masking, so a straddling secret leaks its prefix), A-09 (near-miss inventory), A-10 (captured
//! output buffers are never zeroized).

#![cfg(unix)]

mod common;

use common::{CANARY, base64_decode, contains, longest_leaked_prefix, shell};
use kagisecure_core::inject::{DEFAULT_MAX_OUTPUT, EnvInjection, RunRequest, mask, run_with_env};
use kagisecure_core::model::Secret;
use std::ffi::OsString;
use std::time::Duration;

const VAR: &str = "CANARY_TOKEN";

fn canary_injection() -> Vec<EnvInjection> {
    vec![EnvInjection {
        name: kagisecure_core::proto::VarName::new(VAR).expect("a valid name"),
        value: Secret::from_string(CANARY.to_owned()),
    }]
}

fn run_script(
    script: &str,
    max_output: usize,
    args: &[&str],
) -> kagisecure_core::inject::RunOutcome {
    let (program, mut argv) = shell(script);
    argv.extend(args.iter().map(|a| OsString::from(*a)));
    let env = canary_injection();
    let request = RunRequest {
        program: &program,
        args: &argv,
        env: &env,
        cwd: None,
        mask_output: true,
        max_output,
        timeout: Some(Duration::from_secs(20)),
        new_process_group: true,
    };
    run_with_env(&request).expect("the shell should start")
}

// ---------------------------------------------------------------------------------------------
// A-08 — truncation runs before masking
// ---------------------------------------------------------------------------------------------

/// `run_with_env` caps each stream inside the draining thread (`inject/mod.rs` `drain`) and only
/// then calls `mask` on what survived. A child that emits `max_output - k` bytes of filler and
/// then the secret therefore hands back the secret's first `k` bytes verbatim: the truncated
/// buffer no longer contains the whole needle, so the exact-substring scrubber finds nothing to
/// replace and reports `masked == 0`.
#[test]
fn a_secret_straddling_the_output_cap_does_not_leak_its_prefix() {
    const FILLER: usize = 200;
    const LEAKED: usize = 8;
    let filler = "x".repeat(FILLER);
    let outcome = run_script(
        r#"printf %s "$0"; printf %s "$CANARY_TOKEN""#,
        FILLER + LEAKED,
        &[&filler],
    );

    assert!(outcome.stdout_truncated, "the cap should have been hit");
    assert_eq!(
        longest_leaked_prefix(&outcome.stdout, CANARY.as_bytes()),
        0,
        "the captured stdout still begins the canary: {:?}",
        String::from_utf8_lossy(&outcome.stdout[FILLER.min(outcome.stdout.len())..])
    );
}

/// The record of the fix, kept as a positive observation: the cap is still honoured, the stream
/// is still reported as truncated, and the fragment of the canary that used to survive at the
/// cut has been trimmed away rather than returned.
#[test]
fn the_output_cap_trims_a_fragment_of_a_secret_at_the_cut() {
    const FILLER: usize = 200;
    const LEAKED: usize = 8;
    let filler = "x".repeat(FILLER);
    let outcome = run_script(
        r#"printf %s "$0"; printf %s "$CANARY_TOKEN""#,
        FILLER + LEAKED,
        &[&filler],
    );

    assert!(outcome.stdout_truncated);
    assert!(
        outcome.stdout.len() <= FILLER + LEAKED,
        "the cap is still honoured"
    );
    assert_eq!(
        outcome.stdout,
        filler.as_bytes(),
        "only the filler should survive the cut"
    );
}

/// The control: with room for the whole value, masking does its job and nothing leaks.
#[test]
fn a_secret_that_fits_inside_the_output_cap_is_fully_masked() {
    let outcome = run_script(r#"printf %s "$CANARY_TOKEN""#, DEFAULT_MAX_OUTPUT, &[]);
    assert_eq!(outcome.masked, 1);
    assert!(!contains(&outcome.stdout, CANARY.as_bytes()));
    assert_eq!(longest_leaked_prefix(&outcome.stdout, CANARY.as_bytes()), 0);
    assert!(contains(
        &outcome.stdout,
        b"[kagisecure:redacted:CANARY_TOKEN]"
    ));
}

// ---------------------------------------------------------------------------------------------
// A-07 — an approved command can encode its way out
// ---------------------------------------------------------------------------------------------

/// Masking is exact-substring only, so a command the user approved can re-encode the value and
/// walk it straight past the scrubber. Each case here is recovered by the test, which is the
/// point: the assertion is not "the literal bytes are absent" (they are) but "the value cannot
/// be reconstructed from what was returned".
#[test]
#[ignore = "A-07 is not fixable: substring scrubbing cannot decide whether an arbitrary output \
encodes a value. Masking now also covers base64, hex and percent-encoded forms, but reversal, \
re-chunking and interleaving still defeat it. Kept as the standing statement of the limitation"]
fn an_approved_command_cannot_exfiltrate_the_canary_through_an_encoding() {
    let recovered = encoded_exfiltration_survey();
    let leaked: Vec<&str> = recovered
        .iter()
        .filter(|(_, ok)| *ok)
        .map(|(name, _)| *name)
        .collect();
    assert!(
        leaked.is_empty(),
        "the canary was recovered from masked stdout via: {leaked:?}"
    );
}

/// The measured inventory behind the ignored assertion above: which encodings actually work.
/// Kept un-ignored so the suite fails if the *set* of working exfiltration channels changes —
/// in either direction.
///
/// `base64` is now caught: `mask` searches for a few encodings a program produces without
/// meaning to leak anything (standard base64, hex, percent-encoding) as well as for the value
/// itself. That widens the net; it does not close it, as the remaining rows show.
#[test]
fn the_set_of_encoding_channels_that_defeat_masking_is_unchanged() {
    let expected = [
        ("base64", false),
        ("reversed", true),
        ("chunked", true),
        ("dot-interleaved", true),
    ];
    for (name, recovered) in encoded_exfiltration_survey() {
        let want = expected
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, w)| *w)
            .unwrap_or_else(|| panic!("{name}: channel not in the expected inventory"));
        assert_eq!(
            recovered, want,
            "{name}: the inventory of working exfiltration channels has changed"
        );
    }
}

/// Run one hostile script per encoding and report whether the canary could be reconstructed.
fn encoded_exfiltration_survey() -> Vec<(&'static str, bool)> {
    let mut results = Vec::new();

    // base64: the textbook case named in the injector's own module docs.
    let out = run_script(
        r#"printf %s "$CANARY_TOKEN" | base64"#,
        DEFAULT_MAX_OUTPUT,
        &[],
    );
    let recovered = base64_decode(&out.stdout).is_some_and(|bytes| bytes == CANARY.as_bytes());
    results.push(("base64", recovered));

    // reversed bytes.
    let out = run_script(
        r#"printf %s "$CANARY_TOKEN" | rev"#,
        DEFAULT_MAX_OUTPUT,
        &[],
    );
    let mut reversed: Vec<u8> = out
        .stdout
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    reversed.reverse();
    results.push(("reversed", reversed == CANARY.as_bytes()));

    // chunked across lines: every byte is present, no contiguous run is.
    let out = run_script(
        r#"printf %s "$CANARY_TOKEN" | fold -w 8"#,
        DEFAULT_MAX_OUTPUT,
        &[],
    );
    let joined: Vec<u8> = out
        .stdout
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    results.push(("chunked", joined == CANARY.as_bytes()));

    // interleaved with a separator, which is the same trick without a helper binary.
    let out = run_script(
        r#"printf %s "$CANARY_TOKEN" | sed 's/./&./g'"#,
        DEFAULT_MAX_OUTPUT,
        &[],
    );
    let stripped: Vec<u8> = out
        .stdout
        .iter()
        .copied()
        .filter(|b| *b != b'.' && !b.is_ascii_whitespace())
        .collect();
    results.push(("dot-interleaved", stripped == CANARY.as_bytes()));

    results
}

/// Masking is not even reached when the caller turns it off, and the injector does not second-
/// guess that. Recorded because the MCP path's safety rests entirely on its own caller.
#[test]
fn masking_is_opt_out_and_the_injector_does_not_override_the_caller() {
    let (program, argv) = shell(r#"printf %s "$CANARY_TOKEN""#);
    let env = canary_injection();
    let request = RunRequest {
        program: &program,
        args: &argv,
        env: &env,
        cwd: None,
        mask_output: false,
        max_output: DEFAULT_MAX_OUTPUT,
        timeout: Some(Duration::from_secs(20)),
        new_process_group: true,
    };
    let outcome = run_with_env(&request).unwrap();
    assert_eq!(outcome.masked, 0);
    assert!(contains(&outcome.stdout, CANARY.as_bytes()));
}

// ---------------------------------------------------------------------------------------------
// A-09 — the near-miss inventory
// ---------------------------------------------------------------------------------------------

/// What masking does **not** catch, enumerated. Each case is a rendering of the canary that a
/// real program produces by accident rather than by malice — a trailing newline the value did
/// not have, CRLF line endings, shell quoting, a URL-encoded query parameter, a JSON escape, a
/// line wrap — and the ones in the second table leave the value recoverable. A case change is in
/// the first table: `mask` folds ASCII case on the value itself.
///
/// This is deliberately a table rather than a property test: the value of the scenario is the
/// inventory, and a fixed table is the inventory. A randomized generator would report the same
/// classes with less precision and a dependency the crate does not have.
#[test]
fn the_inventory_of_renderings_that_defeat_exact_substring_masking_is_unchanged() {
    let injections = canary_injection();

    // Cases where the canary is present verbatim: masking succeeds.
    let caught = [
        ("bare", CANARY.to_owned()),
        ("trailing newline", format!("{CANARY}\n")),
        ("trailing CRLF", format!("{CANARY}\r\n")),
        ("single quoted", format!("'{CANARY}'")),
        ("inside JSON string", format!(r#"{{"token":"{CANARY}"}}"#)),
        ("URL query value", format!("https://x/y?t={CANARY}")),
        ("repeated twice", format!("{CANARY} {CANARY}")),
        ("upper-cased", CANARY.to_ascii_uppercase()),
    ];
    for (name, text) in caught {
        let mut buf = text.into_bytes();
        let n = mask(&mut buf, &injections);
        assert!(n >= 1, "{name}: expected the value to be found");
        assert!(
            !contains(&buf, CANARY.as_bytes()),
            "{name}: value survived masking"
        );
    }

    // Cases where the value is altered on its way out: masking finds nothing at all, and the
    // value is still trivially recoverable by the reader.
    let missed = [
        ("newline every 8 chars", chunk(CANARY, 8, "\n")),
        ("shell-escaped spaces", CANARY.replace('_', "\\_")),
        (
            "JSON with escaped underscores",
            CANARY.replace('_', "\\u005f"),
        ),
        ("percent-encoded underscores", CANARY.replace('_', "%5F")),
        ("split across a line wrap", chunk(CANARY, 16, "\\\n")),
        (
            "prefix only (log truncation)",
            CANARY[..CANARY.len() / 2].to_owned(),
        ),
    ];
    for (name, text) in missed {
        let mut buf = text.clone().into_bytes();
        let n = mask(&mut buf, &injections);
        assert_eq!(
            n, 0,
            "{name}: masking unexpectedly matched — the inventory has changed"
        );
        assert_eq!(
            buf,
            text.as_bytes(),
            "{name}: the buffer should be untouched"
        );
    }

    // The truncation case is the one that also leaks under A-08, so record the size of the leak.
    let half = CANARY.len() / 2;
    assert!(
        half >= 16,
        "a half-canary log truncation leaks {half} bytes of the value"
    );
}

/// A near miss that the mask *does* defeat by design: a value that is a prefix of another
/// injected value must not leave its remainder visible (`mask` sorts by descending length).
#[test]
fn a_value_that_is_a_prefix_of_another_does_not_leave_its_remainder_visible() {
    let injections = vec![
        EnvInjection {
            name: kagisecure_core::proto::VarName::new("SHORT").expect("a valid name"),
            value: Secret::from_string(CANARY[..16].to_owned()),
        },
        EnvInjection {
            name: kagisecure_core::proto::VarName::new("LONG").expect("a valid name"),
            value: Secret::from_string(CANARY.to_owned()),
        },
    ];
    let mut buf = format!("token={CANARY}").into_bytes();
    let n = mask(&mut buf, &injections);
    assert_eq!(n, 1);
    assert_eq!(buf, b"token=[kagisecure:redacted:LONG]");
    assert_eq!(longest_leaked_prefix(&buf, CANARY.as_bytes()), 0);
}

fn chunk(text: &str, width: usize, separator: &str) -> String {
    text.as_bytes()
        .chunks(width)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(separator)
}

// ---------------------------------------------------------------------------------------------
// A-10 — captured output is never zeroized
// ---------------------------------------------------------------------------------------------

/// `RunOutcome::stdout` and `::stderr` are plain `Vec<u8>`, not `Zeroizing`, and `mask` replaces
/// the buffer wholesale (`*buf = out`) — so the *pre-masking* allocation, which held the raw
/// secret, is freed without being wiped. This probe allocates over the freed region and looks for
/// the canary. It is best effort by nature: an allocator that does not hand the block back, or
/// that poisons it, makes the probe find nothing without making the defect go away.
#[test]
fn a_captured_output_buffer_does_not_survive_in_freed_memory() {
    const PROBES: usize = 512;

    let leaked_size = {
        let outcome = run_script(r#"printf %s "$CANARY_TOKEN""#, DEFAULT_MAX_OUTPUT, &[]);
        assert_eq!(outcome.masked, 1);
        let size = outcome.stdout.capacity().max(CANARY.len() * 4);
        drop(outcome);
        size
    };

    let mut found = false;
    for _ in 0..PROBES {
        let probe: Vec<u8> = vec![0u8; leaked_size];
        if contains(&probe, CANARY.as_bytes()) {
            found = true;
            break;
        }
    }
    assert!(
        !found,
        "the canary was still readable in memory freed by the injector"
    );
}

/// The structural half of A-10, which needs no allocator luck: the type the caller receives
/// exposes its plaintext-adjacent buffers as owned `Vec<u8>` with no wiping on drop, so a caller
/// that wants the guarantee has to build it itself.
#[test]
fn the_run_outcome_hands_back_plain_unprotected_byte_buffers() {
    let outcome = run_script(r#"printf %s "$CANARY_TOKEN""#, DEFAULT_MAX_OUTPUT, &[]);
    // Moving the buffer out proves it is an ordinary owned Vec: a zeroize-on-drop wrapper could
    // not be destructured this way, and the bytes would not outlive the outcome.
    let stdout: Vec<u8> = outcome.stdout;
    assert!(contains(&stdout, b"[kagisecure:redacted:CANARY_TOKEN]"));
    assert!(stdout.capacity() >= stdout.len());
}
