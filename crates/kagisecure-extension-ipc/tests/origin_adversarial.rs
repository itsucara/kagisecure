//! Adversarial: the origin rule, which is the check that stands between a saved credential and
//! every page in the world that is not the one it belongs to.
//!
//! `origin.rs` has unit tests for the rule as written. This file attacks it from the outside,
//! with the inputs a phishing page actually uses: a registrable domain that *looks* like the
//! saved one (punycode, homographs, a trailing dot, mixed case), a public suffix that entered the
//! list after the pinned `psl` snapshot was cut, a port that appears on one side only, and a
//! saved string whose scheme is ambiguous enough that a careless parse could turn `https` into
//! `http`.
//!
//! The rule under test is the real [`origin_match`] over real [`Origin`] values; nothing is
//! mocked, because there is nothing below it to mock. The last test is a deterministic sweep over
//! generated origin strings asserting the three properties the rule must have whatever it is
//! handed: it never panics, it is reflexive, and it is symmetric.

use kagisecure_extension_ipc::origin::{
    AgentOriginRendering, Origin, covering_website, item_match, origin_match,
};

/// Parse, or panic with the input that failed — every fixture in this file is meant to parse.
fn o(input: &str) -> Origin {
    Origin::parse(input).unwrap_or_else(|e| panic!("{input:?} should parse: {e}"))
}

/// Whether the rule lets `saved` fill `page`. Both must parse.
fn matches(saved: &str, page: &str) -> bool {
    origin_match(&o(saved), &o(page))
}

/// Whether the rule lets `saved` fill `page`, where either side may fail to parse.
///
/// An unparseable side is not a match — that is the safe answer and the one `item_match` gives.
fn matches_lenient(saved: &str, page: &str) -> bool {
    match (Origin::parse(saved), Origin::parse(page)) {
        (Ok(saved), Ok(page)) => origin_match(&saved, &page),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// B-06: lookalike registrable domains, including ones the pinned list may not know.
// ---------------------------------------------------------------------------

/// Hosts that a human might read as `example.com` and that must never match it.
///
/// Each is a *different registrable domain*, which is the only thing the rule is allowed to care
/// about — there is no similarity metric here, and there must not be one.
const LOOKALIKES: &[&str] = &[
    // Punycode for a Cyrillic homograph of "example".
    "https://xn--e1awd7f.com",
    // Punycode that renders as "exämple.com".
    "https://xn--exmple-cua.com",
    // A different TLD.
    "https://example.co",
    "https://example.com.co",
    "https://example.org",
    // The saved domain as a label of somebody else's domain.
    "https://example.com.evil.test",
    "https://example-com.test",
    "https://wwwexample.com",
    // The saved domain with a character appended or removed.
    "https://examplе.com.test",
    "https://exampl.com",
    "https://examplee.com",
    // An IP literal that might be where the name points.
    "https://93.184.216.34",
    "https://[2606:2800:220:1:248:1893:25c8:1946]",
];

#[test]
fn nothing_that_merely_resembles_the_saved_registrable_domain_matches_it() {
    for lookalike in LOOKALIKES {
        assert!(
            !matches_lenient("https://example.com", lookalike),
            "{lookalike} must not be filled with an item saved for example.com"
        );
        assert!(
            !matches_lenient(lookalike, "https://example.com"),
            "an item saved for {lookalike} must not fill example.com"
        );
    }
}

#[test]
fn a_host_under_a_public_suffix_does_not_reach_a_sibling_under_the_same_suffix() {
    // The property the Public Suffix List exists to give: `alice.github.io` and
    // `mallory.github.io` are different *sites*, not two subdomains of one.
    for (a, b) in [
        ("https://alice.github.io", "https://mallory.github.io"),
        (
            "https://one.s3.amazonaws.com",
            "https://two.s3.amazonaws.com",
        ),
        ("https://a.blogspot.com", "https://b.blogspot.com"),
        ("https://x.co.uk", "https://y.co.uk"),
        ("https://a.pages.dev", "https://b.pages.dev"),
    ] {
        assert!(!matches_lenient(a, b), "{a} must not fill {b}");
        assert!(!matches_lenient(b, a), "{b} must not fill {a}");
        assert!(matches_lenient(a, a), "{a} must fill itself");
    }
}

#[test]
fn a_suffix_the_pinned_list_may_not_know_still_fails_in_the_strict_direction() {
    // A stale list turns two sites under a newly-delegated suffix into one registrable domain,
    // which is the *unsafe* direction and is what ADR-0022's update policy exists to bound. This
    // test does not assert which way the pinned snapshot answers — that changes with the pin —
    // it asserts the invariant that survives either answer: two hosts that differ in the label
    // directly under the candidate suffix must not match each other unless they are the same
    // registrable domain, and a host must always match itself.
    for suffix in [
        // Delegations and private entries that have arrived or changed over the list's life.
        "dev", "app", "page", "foo", "zip", "mov", "boo", "nexus", "meme", "phd",
    ] {
        let a = format!("https://alice.example.{suffix}");
        let b = format!("https://mallory.other.{suffix}");
        assert!(
            !matches_lenient(&a, &b),
            "{a} must not fill {b} under any snapshot of the list"
        );
        assert!(matches_lenient(&a, &a), "{a} must fill itself");
    }
}

/// The `psl` version this file was last reviewed against, and when that review happened.
///
/// ADR-0022 makes the Public Suffix List a security-relevant dependency whose only update
/// mechanism is bumping this crate. A pin nobody revisits is therefore a slowly-expiring control,
/// and the test below is the expiry alarm. **To silence it, bump `psl` and then update both
/// constants** — not just the date.
const PSL_REVIEWED_VERSION: &str = "2.1.232";

/// Unix seconds at the last review of the pin above: 2026-09-20.
const PSL_REVIEWED_AT: u64 = 1_789_862_400;

/// Twelve months, in seconds, being how long a Public Suffix List snapshot may go unreviewed.
const PSL_REVIEW_INTERVAL: u64 = 365 * 24 * 60 * 60;

#[test]
fn the_pinned_public_suffix_list_has_been_reviewed_within_the_last_twelve_months() {
    // The list is compiled into the binary by whichever `psl` version `Cargo.lock` names, so the
    // lock file is where the snapshot's age is actually recorded.
    let mut lock = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    lock.pop();
    lock.pop();
    let lock = lock.join("Cargo.lock");
    let text = std::fs::read_to_string(&lock)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", lock.display()));

    let locked = text
        .split("[[package]]")
        .find(|block| block.contains("name = \"psl\""))
        .and_then(|block| {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix("version = "))
        })
        .map(|version| version.trim().trim_matches('"').to_owned())
        .expect("Cargo.lock should pin the psl crate");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    let overdue = now.saturating_sub(PSL_REVIEWED_AT) > PSL_REVIEW_INTERVAL;

    assert!(
        !(overdue && locked == PSL_REVIEWED_VERSION),
        "the Public Suffix List pinned in Cargo.lock (psl {locked}) has not been reviewed since \
         the timestamp recorded in this test, and a stale list silently merges two sites under a \
         newly-delegated suffix into one registrable domain. Bump `psl`, then update \
         PSL_REVIEWED_VERSION and PSL_REVIEWED_AT. See ADR-0022."
    );
}

// ---------------------------------------------------------------------------
// B-07: port confusion.
// ---------------------------------------------------------------------------

#[test]
fn a_port_that_differs_in_any_way_is_a_different_origin() {
    // The default is filled in before the comparison, so the interesting cases are the ones where
    // a port is written on one side only, or written as the default, or written as zero.
    assert!(matches("https://example.com", "https://example.com:443"));
    assert!(matches("https://example.com:443", "https://example.com"));
    assert!(matches("http://example.com", "http://example.com:80"));

    for (saved, page) in [
        // A port on the saved side only, and the other way round.
        ("https://example.com:8443", "https://example.com"),
        ("https://example.com", "https://example.com:8443"),
        // Zero is a port, not an absence.
        ("https://example.com:0", "https://example.com"),
        ("https://example.com", "https://example.com:0"),
        // The *other* scheme's default port, written out.
        ("https://example.com:80", "https://example.com"),
        ("http://example.com:443", "http://example.com"),
        // Neighbouring ports.
        ("https://example.com:8443", "https://example.com:8444"),
    ] {
        assert!(
            !matches_lenient(saved, page),
            "{saved} must not fill {page}: the ports differ"
        );
    }
}

#[test]
fn a_port_outside_the_range_is_not_an_origin_at_all() {
    // A port that cannot be a `u16` is not a port. Either the string fails to parse — the answer
    // this rule wants — or it parses to something whose port is *not* the one the attacker wrote,
    // in which case it must not match a page on the default port either.
    for impossible in [
        "https://example.com:65536",
        "https://example.com:99999",
        "https://example.com:-1",
        "https://example.com:443443",
        "https://example.com:0x1bb",
    ] {
        assert!(
            Origin::parse(impossible).is_err(),
            "{impossible} is not an origin and must not parse as one"
        );
        assert!(
            !matches_lenient(impossible, "https://example.com"),
            "{impossible} must not fill example.com"
        );
    }
}

// ---------------------------------------------------------------------------
// B-08: scheme confusion through the no-scheme default.
// ---------------------------------------------------------------------------

#[test]
fn an_ambiguous_saved_string_never_produces_an_http_origin_that_fills_an_https_page() {
    // `Origin::parse` assumes https for a string with no scheme, precisely so that a Websites
    // field a user typed by hand cannot silently widen to a plaintext origin. These are the
    // strings where the assumption could go wrong.
    for saved in [
        "example.com",
        "example.com/login",
        "//example.com",
        "///example.com",
        "example.com:80",
        "example.com:443",
        "http:example.com",
        "HTTP://example.com",
        "HtTpS://example.com",
        " example.com ",
        "\texample.com",
        "https:/example.com",
        "https:example.com",
        "//example.com:80/",
    ] {
        let Ok(parsed) = Origin::parse(saved) else {
            // Refusing to parse is always a safe answer.
            continue;
        };
        if parsed.scheme() == "http" {
            assert!(
                saved.to_ascii_lowercase().contains("http:"),
                "{saved:?} produced an http origin although it never said http: {parsed}"
            );
            assert!(
                !origin_match(&parsed, &o("https://example.com")),
                "{saved:?} parsed as {parsed} and matched an https page"
            );
        }
    }
}

#[test]
fn the_two_schemes_never_cover_each_other_in_either_direction() {
    assert!(!matches("http://example.com", "https://example.com"));
    assert!(!matches("https://example.com", "http://example.com"));
    assert!(!matches("http://sub.example.com", "https://example.com"));
    assert!(!matches(
        "https://example.com:8443",
        "http://example.com:8443"
    ));
}

#[test]
fn a_scheme_autofill_does_not_serve_is_refused_rather_than_coerced() {
    for saved in [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<b>x</b>",
        "about:blank",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/popup.html",
        "ws://example.com",
        "wss://example.com",
        "mailto:alice@example.com",
    ] {
        assert!(
            Origin::parse(saved).is_err(),
            "{saved:?} is not an origin autofill serves, and must not parse as one"
        );
        assert!(!matches_lenient(saved, "https://example.com"));
    }
}

// ---------------------------------------------------------------------------
// B-09: trailing dots, case, and punycode that has been encoded twice.
// ---------------------------------------------------------------------------

#[test]
fn case_differences_in_the_host_are_normalized_away_and_nothing_else_is() {
    assert!(matches("https://EXAMPLE.COM", "https://example.com"));
    assert!(matches("https://Example.Com", "https://eXaMpLe.cOm"));
    assert!(matches("HTTPS://example.com", "https://example.com"));
    assert!(matches(
        "https://SUB.Example.COM",
        "https://other.example.com"
    ));
}

#[test]
fn a_trailing_dot_gets_one_consistent_verdict_in_both_directions() {
    // `example.com.` is the fully-qualified form of `example.com`. Whether this rule treats them
    // as the same site is a decision either way; what must not happen is an *asymmetry*, where a
    // page can be filled by a saved string that the same page would not match back.
    for (a, b) in [
        ("https://example.com.", "https://example.com"),
        ("https://sub.example.com.", "https://sub.example.com"),
        ("https://example.com..", "https://example.com"),
    ] {
        let forward = matches_lenient(a, b);
        let backward = matches_lenient(b, a);
        assert_eq!(
            forward, backward,
            "{a} and {b} must get the same verdict whichever side is the saved one"
        );
        assert!(
            matches_lenient(a, a) || Origin::parse(a).is_err(),
            "{a} must at least match itself"
        );
    }
}

#[test]
fn punycode_that_has_been_encoded_twice_is_a_different_host_than_the_name_it_encodes() {
    for (unicode, once, twice) in [
        (
            "https://παράδειγμα.δοκιμή",
            "https://xn--hxajbheg2az3al.xn--jxalpdlp",
            "https://xn--xn--hxajbheg2az3al-ktb.xn--jxalpdlp",
        ),
        (
            "https://münchen.de",
            "https://xn--mnchen-3ya.de",
            "https://xn--xn--mnchen-3ya-4hb.de",
        ),
    ] {
        // The unicode form and its single punycode encoding are the same host.
        if let (Ok(a), Ok(b)) = (Origin::parse(unicode), Origin::parse(once)) {
            assert!(
                origin_match(&a, &b),
                "{unicode} and its punycode {once} are the same host"
            );
            assert_eq!(a.host(), b.host(), "the host is stored in punycode");
        }
        // Encoding it a second time makes a different name, and must not match either.
        assert!(
            !matches_lenient(twice, once),
            "{twice} must not fill {once}"
        );
        assert!(
            !matches_lenient(twice, unicode),
            "{twice} must not fill {unicode}"
        );
    }
}

#[test]
fn a_host_that_is_only_a_label_or_a_literal_is_matched_exactly() {
    // With no registrable domain there is no eTLD+1 to compare, and the fallback is exact host
    // equality — the stricter test, not a looser one.
    for (a, b, same) in [
        ("http://localhost:3000", "http://localhost:3000", true),
        ("http://localhost:3000", "http://localhost:3001", false),
        ("http://localhost", "http://127.0.0.1", false),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080", true),
        ("http://127.0.0.1:8080", "http://127.0.0.2:8080", false),
        ("http://[::1]:8080", "http://[::1]:8080", true),
        ("http://[::1]:8080", "http://127.0.0.1:8080", false),
        // A single label is not a parent of anything.
        ("http://localhost", "http://sub.localhost", false),
        ("http://intranet", "http://intranet.corp", false),
    ] {
        assert_eq!(
            matches_lenient(a, b),
            same,
            "{a} against {b} should be {same}"
        );
    }
}

// ---------------------------------------------------------------------------
// A deterministic sweep: the rule never panics, and is reflexive and symmetric.
// ---------------------------------------------------------------------------

/// A small deterministic generator, so a failure is reproducible from the seed alone.
///
/// A property-test dependency would have to be added to this crate's manifest, which is a change
/// other work in flight would have to merge around; a twelve-line xorshift costs nothing and
/// makes every failure replayable by printing one number.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let index = usize::try_from(self.next() % items.len() as u64).unwrap_or(0);
        &items[index]
    }
}

/// Fragments chosen to hit the rule's branches: schemes it serves and does not, hosts with and
/// without a registrable domain, IDN, literals, ports, trailing dots and stray punctuation.
fn generated_origin(rng: &mut Rng) -> String {
    const SCHEMES: &[&str] = &[
        "https://", "http://", "", "//", "ftp://", "HTTPS://", "http:",
    ];
    const HOSTS: &[&str] = &[
        "example.com",
        "sub.example.com",
        "example.com.",
        "EXAMPLE.com",
        "alice.github.io",
        "github.io",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "xn--mnchen-3ya.de",
        "münchen.de",
        "a.b.c.d.e.f.example.com",
        "",
        ".",
        "..",
        "-.example.com",
        "example..com",
        "ex ample.com",
        "example.com%00",
        "user:pass@example.com",
    ];
    const PORTS: &[&str] = &["", ":443", ":80", ":0", ":8443", ":65535", ":65536", ":-1"];
    const TAILS: &[&str] = &["", "/", "/login", "/a?b=c#d", "?x", "#y", "/../../etc"];

    format!(
        "{}{}{}{}",
        rng.pick(SCHEMES),
        rng.pick(HOSTS),
        rng.pick(PORTS),
        rng.pick(TAILS)
    )
}

#[test]
fn the_rule_never_panics_and_is_reflexive_and_symmetric_over_generated_origins() {
    const SEED: u64 = 0x5EED_1A3E_C0FF_EE01;
    const ROUNDS: usize = 20_000;

    let mut rng = Rng(SEED);
    for round in 0..ROUNDS {
        let left = generated_origin(&mut rng);
        let right = generated_origin(&mut rng);

        let (Ok(a), Ok(b)) = (Origin::parse(&left), Origin::parse(&right)) else {
            continue;
        };

        assert!(
            origin_match(&a, &a),
            "round {round} (seed {SEED:#x}): {left:?} does not match itself"
        );
        assert!(origin_match(&b, &b), "round {round}: {right:?}");
        assert_eq!(
            origin_match(&a, &b),
            origin_match(&b, &a),
            "round {round} (seed {SEED:#x}): {left:?} against {right:?} is not symmetric, so \
             which side is the saved one changes the answer"
        );

        // Parsing is idempotent: an origin's own serialization parses back to the same origin, so
        // the string the sheet shows and the string the lease is keyed on cannot drift apart.
        let serialized = a.ascii_serialization();
        let reparsed = Origin::parse(&serialized)
            .unwrap_or_else(|e| panic!("round {round}: {serialized:?} did not re-parse: {e}"));
        assert_eq!(
            reparsed.ascii_serialization(),
            serialized,
            "round {round}: {left:?} serializes to something that does not round-trip"
        );
        assert!(
            origin_match(&a, &reparsed),
            "round {round}: an origin does not match its own re-parsed serialization"
        );
    }
}

#[test]
fn a_generated_origin_never_matches_across_a_scheme_or_a_port_boundary() {
    // The two clauses that are pure equality, swept rather than enumerated: whatever else the
    // registrable-domain clause decides, a difference in scheme or port is always a refusal.
    const SEED: u64 = 0x5EED_1A3E_C0FF_EE02;
    let mut rng = Rng(SEED);
    for round in 0..20_000 {
        let left = generated_origin(&mut rng);
        let right = generated_origin(&mut rng);
        let (Ok(a), Ok(b)) = (Origin::parse(&left), Origin::parse(&right)) else {
            continue;
        };
        if a.scheme() != b.scheme() || a.port() != b.port() {
            assert!(
                !origin_match(&a, &b),
                "round {round} (seed {SEED:#x}): {left:?} matched {right:?} across a scheme or \
                 port difference"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The agent-fill sheet's rendering and the covering website (ADR-0036 §5).
// ---------------------------------------------------------------------------

#[test]
fn every_punycode_lookalike_is_rendered_in_unicode_beside_its_ascii_form() {
    for lookalike in LOOKALIKES {
        let Ok(origin) = Origin::parse(lookalike) else {
            continue;
        };
        let rendering = AgentOriginRendering::of(&origin);
        assert_eq!(
            rendering.ascii(),
            origin.ascii_serialization(),
            "{lookalike}"
        );
        if origin
            .host()
            .split('.')
            .any(|label| label.starts_with("xn--"))
        {
            assert!(
                rendering.unicode_host.is_some(),
                "{lookalike} must be shown as the browser shows it, too"
            );
        }
    }
    // The list's all-Cyrillic label under a Latin top-level domain is flagged, not only rendered.
    let homograph = AgentOriginRendering::of(&o("https://xn--e1awd7f.com"));
    assert!(homograph.mixed_script, "{homograph:?}");
}

#[test]
fn the_rendering_never_panics_and_always_puts_back_together_over_generated_origins() {
    const SEED: u64 = 0x5EED_1A3E_C0FF_EE03;
    let mut rng = Rng(SEED);
    for round in 0..20_000 {
        let left = generated_origin(&mut rng);
        let right = generated_origin(&mut rng);
        let Ok(page) = Origin::parse(&right) else {
            continue;
        };
        let rendering = AgentOriginRendering::of(&page);
        assert_eq!(
            rendering.ascii(),
            page.ascii_serialization(),
            "round {round} (seed {SEED:#x}): the rendering of {right:?} dropped or added something"
        );
        assert_eq!(
            rendering.not_encrypted,
            page.scheme() == "http",
            "round {round}: {right:?}"
        );
        // The covering website is the same rule as `item_match`, asked a different question.
        let saved = vec![left.clone()];
        assert_eq!(
            covering_website(&saved, &page).is_some(),
            item_match(&saved, &right, None).is_ok(),
            "round {round} (seed {SEED:#x}): {left:?} covering {right:?}"
        );
    }
}
