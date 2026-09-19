//! Origin parsing and the one rule that decides whether an item may be filled into a page.
//!
//! # The rule
//!
//! An item's saved website matches a page when **all three** of these hold:
//!
//! 1. the schemes are equal, and both are `http` or `https`;
//! 2. the ports are equal, after the scheme's default port is filled in;
//! 3. the hosts have the same **registrable domain** — eTLD+1 under the Public Suffix List — or,
//!    where there is no registrable domain to speak of, are byte-for-byte equal.
//!
//! There is no fuzzy match, no "close enough", no substring, and no scheme upgrade: an item saved
//! as `http://example.com` does not fill on `https://example.com`, because the two are different
//! origins and the user's own record is the thing being trusted. The roadmap's M6 criterion is
//! "there is no fuzzy or 'close enough' domain match", and this module is where that is true or
//! not.
//!
//! # Where "no registrable domain" happens, and why it is the safe branch
//!
//! [`psl`] answers with the eTLD+1 or with nothing. Nothing happens in three interesting cases,
//! and each falls back to **exact host equality**, which is strictly stricter than the eTLD+1
//! rule rather than a hole in it:
//!
//! * **IP literals.** `127.0.0.1` and `[::1]` have no domain structure. Exact match only.
//! * **A single label.** `localhost`, or an intranet name. Exact match only.
//! * **A host that is itself a public suffix.** `github.io` is on the list, so `github.io` has no
//!   eTLD+1 — while `alice.github.io` has one, and it is `alice.github.io`, not `github.io`. That
//!   is the property that keeps `mallory.github.io` from filling `alice.github.io`'s password,
//!   and it is why the list matters at all.
//!
//! # Update policy for the list
//!
//! The list is compiled into the binary by the [`psl`] crate at build time. It therefore updates
//! when the pinned crate version is bumped, and only then — `Cargo.lock` records exactly which
//! snapshot a given build was made against. A stale list fails in the *strict* direction for new
//! suffixes (two sites under a newly-delegated suffix look like one registrable domain), so the
//! policy is: bump `psl` whenever the dependency audit runs, and treat it as a security-relevant
//! dependency rather than a convenience one. See ADR-0022.

use url::{Host, Url};

/// A page or website origin: scheme, host, port. Nothing else — no path, no query, no fragment.
///
/// Constructed only through [`Origin::parse`], so an `Origin` in hand is always normalized:
/// lowercase scheme and host, explicit port, punycode host.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: String,
    host: Host<String>,
    port: u16,
}

/// Why a string is not an origin this module will match on.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OriginError {
    /// The string is not a URL at all.
    #[error("{0:?} is not a URL")]
    NotAUrl(String),
    /// The URL has a scheme autofill does not serve.
    #[error("{0:?} is not an http(s) URL — autofill only serves http and https")]
    UnsupportedScheme(String),
    /// The URL has no host: `file:///x`, `about:blank`, `data:…`.
    #[error("{0:?} has no host")]
    NoHost(String),
}

impl Origin {
    /// Parse an origin out of a URL or a bare origin string.
    ///
    /// Accepts what a user actually types into a Websites field — `example.com`,
    /// `example.com/login`, `https://example.com:8443/a/b?c#d` — and keeps only the origin. A
    /// string with no scheme is assumed `https`, because that is what a website is in 2026 and
    /// because guessing `http` would silently widen the match to a plaintext origin.
    ///
    /// # Errors
    ///
    /// [`OriginError`] when the string is not a URL, has no host, or has a scheme other than
    /// `http`/`https`.
    pub fn parse(input: &str) -> Result<Self, OriginError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(OriginError::NotAUrl(input.to_owned()));
        }
        let parsed = match Url::parse(trimmed) {
            Ok(u) => u,
            // No scheme: `example.com/login`. Assume https rather than http.
            Err(url::ParseError::RelativeUrlWithoutBase) => {
                Url::parse(&format!("https://{trimmed}"))
                    .map_err(|_| OriginError::NotAUrl(input.to_owned()))?
            }
            Err(_) => return Err(OriginError::NotAUrl(input.to_owned())),
        };
        let scheme = parsed.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(OriginError::UnsupportedScheme(input.to_owned()));
        }
        let host = parsed
            .host()
            .ok_or_else(|| OriginError::NoHost(input.to_owned()))?
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| OriginError::NoHost(input.to_owned()))?;
        Ok(Self { scheme, host, port })
    }

    /// The scheme, lowercase.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The port, with the scheme's default filled in.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host, as an ASCII string: punycode for an IDN, bare digits for IPv4, bracketless
    /// canonical form for IPv6.
    #[must_use]
    pub fn host(&self) -> String {
        match &self.host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(a) => a.to_string(),
            Host::Ipv6(a) => a.to_string(),
        }
    }

    /// Whether the host is a literal address rather than a name.
    #[must_use]
    pub fn is_ip_literal(&self) -> bool {
        matches!(self.host, Host::Ipv4(_) | Host::Ipv6(_))
    }

    /// The registrable domain (eTLD+1) of the host, when it has one.
    ///
    /// `None` for an IP literal, a single-label host, and a host that is itself a public suffix.
    /// Every one of those falls back to exact-host matching in [`origin_match`].
    #[must_use]
    pub fn registrable_domain(&self) -> Option<String> {
        let Host::Domain(domain) = &self.host else {
            return None;
        };
        let parsed = psl::domain(domain.as_bytes())?;
        std::str::from_utf8(parsed.as_bytes())
            .ok()
            .map(str::to_ascii_lowercase)
    }

    /// The ASCII serialization: `https://example.com`, with the port shown only when it is not
    /// the scheme's default.
    ///
    /// This is the string the approval sheet shows and the audit log records, so it must be
    /// unambiguous rather than pretty: an IPv6 host is bracketed, an IDN stays in punycode.
    #[must_use]
    pub fn ascii_serialization(&self) -> String {
        let host = match &self.host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(a) => a.to_string(),
            Host::Ipv6(a) => format!("[{a}]"),
        };
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            format!("{}://{host}", self.scheme)
        } else {
            format!("{}://{host}:{}", self.scheme, self.port)
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.ascii_serialization())
    }
}

/// Why a match was refused. Every variant is a fixed string, safe to put in an audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MatchFailure {
    /// The item has no website at all, so nothing could match.
    NoSavedWebsite,
    /// The item's websites are all unparseable, or all non-http(s).
    NoUsableSavedWebsite,
    /// The page's origin did not parse.
    PageOriginUnparseable,
    /// Scheme, host or port did not line up with any saved website.
    OriginMismatch,
    /// The fill target is in a cross-origin iframe whose origin does not match the item.
    IframeOriginMismatch,
}

impl MatchFailure {
    /// The token for the audit log and the extension's error message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSavedWebsite => "no saved website",
            Self::NoUsableSavedWebsite => "no usable saved website",
            Self::PageOriginUnparseable => "the page origin did not parse",
            Self::OriginMismatch => "the origin does not match a saved website",
            Self::IframeOriginMismatch => {
                "the form is in a cross-origin frame the item does not cover"
            }
        }
    }
}

/// Whether one saved origin covers one page origin.
///
/// The three-clause rule from the module documentation, and the only place it is written down.
#[must_use]
pub fn origin_match(saved: &Origin, page: &Origin) -> bool {
    if saved.scheme != page.scheme {
        return false;
    }
    if saved.port != page.port {
        return false;
    }
    match (saved.registrable_domain(), page.registrable_domain()) {
        // Both have a registrable domain: same site wins. `github.com` covers `gist.github.com`.
        (Some(a), Some(b)) => a == b,
        // Either side has none — an IP literal, a single label, or a host that *is* a public
        // suffix. Fall back to the stricter test rather than to a looser one.
        _ => saved.host().eq_ignore_ascii_case(&page.host()),
    }
}

/// Whether an item, described by its saved website strings, may be filled into a page.
///
/// `frame_origin` is `None` for a top-frame fill. When it is `Some` and differs from
/// `top_origin`, the **frame's** origin is the one that must match: a trusted top-level page does
/// not lend its trust to a third party's iframe (ADR-0020). When it is `Some` and equal, this
/// behaves exactly as a top-frame fill.
///
/// # Errors
///
/// [`MatchFailure`] naming which clause refused, for the audit entry.
pub fn item_match(
    saved_websites: &[String],
    top_origin: &str,
    frame_origin: Option<&str>,
) -> Result<Origin, MatchFailure> {
    if saved_websites.is_empty() {
        return Err(MatchFailure::NoSavedWebsite);
    }
    let saved: Vec<Origin> = saved_websites
        .iter()
        .filter_map(|s| Origin::parse(s).ok())
        .collect();
    if saved.is_empty() {
        return Err(MatchFailure::NoUsableSavedWebsite);
    }

    let top = Origin::parse(top_origin).map_err(|_| MatchFailure::PageOriginUnparseable)?;
    let cross_origin_frame = match frame_origin {
        Some(f) => {
            let frame = Origin::parse(f).map_err(|_| MatchFailure::PageOriginUnparseable)?;
            if frame == top { None } else { Some(frame) }
        }
        None => None,
    };

    let target = cross_origin_frame.clone().unwrap_or(top);
    if saved.iter().any(|s| origin_match(s, &target)) {
        Ok(target)
    } else if cross_origin_frame.is_some() {
        Err(MatchFailure::IframeOriginMismatch)
    } else {
        Err(MatchFailure::OriginMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(s: &str) -> Origin {
        Origin::parse(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    fn matches(saved: &str, page: &str) -> bool {
        origin_match(&o(saved), &o(page))
    }

    #[test]
    fn an_origin_keeps_only_scheme_host_and_port() {
        let origin = o("https://Example.COM:8443/login?next=/a#frag");
        assert_eq!(origin.scheme(), "https");
        assert_eq!(origin.host(), "example.com");
        assert_eq!(origin.port(), 8443);
        assert_eq!(origin.ascii_serialization(), "https://example.com:8443");
    }

    #[test]
    fn a_default_port_is_filled_in_and_then_hidden() {
        assert_eq!(o("https://example.com").port(), 443);
        assert_eq!(o("http://example.com").port(), 80);
        assert_eq!(
            o("https://example.com:443").ascii_serialization(),
            "https://example.com"
        );
        assert_eq!(
            o("http://example.com:80").ascii_serialization(),
            "http://example.com"
        );
        assert_eq!(
            o("http://example.com:8080").ascii_serialization(),
            "http://example.com:8080"
        );
    }

    #[test]
    fn a_bare_hostname_is_assumed_https_not_http() {
        // Guessing http would silently widen an item to a plaintext origin.
        assert_eq!(o("example.com").scheme(), "https");
        assert_eq!(
            o("example.com/login").ascii_serialization(),
            "https://example.com"
        );
    }

    #[test]
    fn non_web_schemes_are_refused() {
        for input in [
            "file:///etc/passwd",
            "about:blank",
            "data:text/html,<h1>hi",
            "chrome-extension://nlijibjnmanccalmafnfbobkcfjiibmd/popup.html",
            "javascript:alert(1)",
            "ftp://example.com",
        ] {
            let err = Origin::parse(input).unwrap_err();
            assert!(
                matches!(
                    err,
                    OriginError::UnsupportedScheme(_)
                        | OriginError::NotAUrl(_)
                        | OriginError::NoHost(_)
                ),
                "{input}: {err:?}"
            );
        }
    }

    #[test]
    fn an_empty_website_is_not_an_origin() {
        assert!(Origin::parse("").is_err());
        assert!(Origin::parse("   ").is_err());
    }

    // ---------------------------------------------------------------------------------------
    // The table. Each row is a claim about the product's most security-critical rule.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn same_registrable_domain_matches_across_subdomains() {
        assert!(matches("https://example.com", "https://example.com"));
        assert!(matches("https://example.com", "https://www.example.com"));
        assert!(matches("https://www.example.com", "https://example.com"));
        assert!(matches("https://github.com", "https://gist.github.com"));
        assert!(matches(
            "https://a.b.c.example.com",
            "https://d.example.com"
        ));
    }

    #[test]
    fn a_different_registrable_domain_never_matches() {
        assert!(!matches("https://example.com", "https://example.org"));
        assert!(!matches(
            "https://example.com",
            "https://example.com.evil.test"
        ));
        assert!(!matches("https://example.com", "https://notexample.com"));
        // The classic suffix attack: `example.com` must not cover a host that merely ends in it.
        assert!(!matches("https://example.com", "https://xexample.com"));
    }

    #[test]
    fn co_uk_is_a_public_suffix_so_two_sites_under_it_do_not_match() {
        // Without the Public Suffix List, a naive "last two labels" rule would make every
        // `*.co.uk` site one site.
        assert!(!matches("https://bbc.co.uk", "https://sainsburys.co.uk"));
        assert!(matches("https://bbc.co.uk", "https://www.bbc.co.uk"));
        assert!(matches("https://www.bbc.co.uk", "https://news.bbc.co.uk"));
        assert_eq!(
            o("https://news.bbc.co.uk").registrable_domain().as_deref(),
            Some("bbc.co.uk")
        );
    }

    #[test]
    fn github_io_is_a_public_suffix_so_two_users_pages_do_not_match() {
        assert_eq!(
            o("https://alice.github.io").registrable_domain().as_deref(),
            Some("alice.github.io")
        );
        assert!(!matches(
            "https://alice.github.io",
            "https://mallory.github.io"
        ));
        assert!(matches(
            "https://alice.github.io",
            "https://alice.github.io"
        ));
        assert!(matches(
            "https://alice.github.io",
            "https://blog.alice.github.io"
        ));
    }

    #[test]
    fn a_bare_public_suffix_has_no_registrable_domain_and_matches_only_itself() {
        let suffix = o("https://github.io");
        assert_eq!(suffix.registrable_domain(), None);
        assert!(matches("https://github.io", "https://github.io"));
        assert!(!matches("https://github.io", "https://alice.github.io"));
        assert!(!matches("https://alice.github.io", "https://github.io"));
    }

    #[test]
    fn the_scheme_must_be_equal_with_no_upgrade_or_downgrade() {
        assert!(!matches("http://example.com", "https://example.com"));
        assert!(!matches("https://example.com", "http://example.com"));
        assert!(matches("http://example.com", "http://example.com"));
    }

    #[test]
    fn the_port_must_be_equal() {
        assert!(!matches("https://example.com", "https://example.com:8443"));
        assert!(!matches("http://localhost:3000", "http://localhost:3001"));
        assert!(matches("http://localhost:3000", "http://localhost:3000"));
        // The default port is filled in on both sides before the comparison.
        assert!(matches("https://example.com:443", "https://example.com"));
        assert!(matches("http://example.com:80", "http://example.com"));
        // A non-default port on one side alone is a mismatch even for the same site.
        assert!(!matches(
            "https://www.example.com:8443",
            "https://example.com"
        ));
    }

    #[test]
    fn localhost_matches_only_itself() {
        assert_eq!(o("http://localhost:3000").registrable_domain(), None);
        assert!(matches("http://localhost:3000", "http://localhost:3000"));
        assert!(!matches("http://localhost:3000", "http://127.0.0.1:3000"));
        assert!(!matches(
            "http://localhost:3000",
            "http://evil.localhost:3000"
        ));
    }

    #[test]
    fn ip_literals_match_exactly_and_never_by_suffix() {
        assert!(o("http://127.0.0.1:3000").is_ip_literal());
        assert!(matches("http://127.0.0.1:3000", "http://127.0.0.1:3000"));
        assert!(!matches("http://127.0.0.1:3000", "http://127.0.0.2:3000"));
        assert!(!matches("http://192.168.1.1", "http://192.168.1.2"));

        assert!(o("http://[::1]:3000").is_ip_literal());
        assert!(matches("http://[::1]:3000", "http://[::1]:3000"));
        assert!(!matches("http://[::1]:3000", "http://[::2]:3000"));
        assert_eq!(
            o("http://[::1]:3000").ascii_serialization(),
            "http://[::1]:3000"
        );
        // IPv6 forms that name the same address are the same origin.
        assert!(matches(
            "http://[0:0:0:0:0:0:0:1]:3000",
            "http://[::1]:3000"
        ));
    }

    #[test]
    fn an_idn_is_compared_in_punycode_so_two_spellings_of_one_host_agree() {
        // The literals below are non-ASCII on purpose: they are IANA's reserved IDN test labels
        // (`παράδειγμα.δοκιμή`, "example.test"), and an IDN test needs a real IDN as *input*. They
        // are test data, not prose. Every assertion is written against the punycode form so the
        // intent is readable without reading the label.
        let unicode = o("https://παράδειγμα.δοκιμή");
        assert_eq!(unicode.host(), "xn--hxajbheg2az3al.xn--jxalpdlp");
        assert_eq!(
            unicode.ascii_serialization(),
            "https://xn--hxajbheg2az3al.xn--jxalpdlp"
        );
        // The same host, spelled the two ways a user might type it, is one origin.
        assert!(matches(
            "https://παράδειγμα.δοκιμή",
            "https://xn--hxajbheg2az3al.xn--jxalpdlp"
        ));
        // And a different IDN is a different origin, so the normalization is not flattening
        // everything onto one host.
        assert!(!matches(
            "https://παράδειγμα.δοκιμή",
            "https://xn--jxalpdlp"
        ));
    }

    #[test]
    fn host_comparison_is_case_insensitive() {
        assert!(matches("https://EXAMPLE.com", "https://example.COM"));
    }

    // ---------------------------------------------------------------------------------------
    // item_match: the whole-item rule, including the iframe policy.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn an_item_with_no_website_never_matches() {
        assert_eq!(
            item_match(&[], "https://example.com", None),
            Err(MatchFailure::NoSavedWebsite)
        );
    }

    #[test]
    fn an_item_whose_websites_are_all_unusable_says_so_rather_than_mismatching() {
        assert_eq!(
            item_match(
                &["file:///x".to_owned(), "not a url at all".to_owned()],
                "https://example.com",
                None
            ),
            Err(MatchFailure::NoUsableSavedWebsite)
        );
    }

    #[test]
    fn one_usable_website_among_junk_is_enough() {
        let saved = vec![
            "about:blank".to_owned(),
            "https://example.com".to_owned(),
            "".to_owned(),
        ];
        assert_eq!(
            item_match(&saved, "https://www.example.com", None)
                .unwrap()
                .ascii_serialization(),
            "https://www.example.com"
        );
    }

    #[test]
    fn an_unparseable_page_origin_is_refused_rather_than_guessed() {
        assert_eq!(
            item_match(&["https://example.com".to_owned()], "about:blank", None),
            Err(MatchFailure::PageOriginUnparseable)
        );
    }

    #[test]
    fn a_same_origin_iframe_behaves_like_a_top_frame_fill() {
        let saved = vec!["https://example.com".to_owned()];
        assert!(
            item_match(&saved, "https://example.com", Some("https://example.com")).is_ok(),
            "an iframe of the page itself is not a third party"
        );
    }

    #[test]
    fn a_cross_origin_iframe_is_matched_against_the_frame_not_the_page() {
        let saved = vec!["https://bank.test".to_owned()];
        // The classic attack: a page the item does not cover embeds the bank's login in a frame.
        // The *frame* is what gets matched, so this is allowed — and this is the case the policy
        // exists to permit, because it is how real federated logins work.
        let allowed = item_match(&saved, "https://shop.test", Some("https://bank.test")).unwrap();
        assert_eq!(allowed.ascii_serialization(), "https://bank.test");

        // And the inverse, which is the case the policy exists to *refuse*: the bank's own page
        // embeds an attacker's frame, and the attacker asks for the bank's password.
        assert_eq!(
            item_match(&saved, "https://bank.test", Some("https://evil.test")),
            Err(MatchFailure::IframeOriginMismatch)
        );
    }

    #[test]
    fn a_top_frame_mismatch_and_an_iframe_mismatch_are_told_apart() {
        let saved = vec!["https://bank.test".to_owned()];
        assert_eq!(
            item_match(&saved, "https://evil.test", None),
            Err(MatchFailure::OriginMismatch)
        );
        assert_eq!(
            item_match(&saved, "https://evil.test", Some("https://also-evil.test")),
            Err(MatchFailure::IframeOriginMismatch)
        );
    }

    #[test]
    fn the_returned_origin_is_the_one_that_was_matched() {
        // The audit entry and the lease are keyed on this, so it must be the frame's origin for
        // a cross-origin fill, not the page's.
        let saved = vec!["https://bank.test".to_owned()];
        let matched =
            item_match(&saved, "https://shop.test", Some("https://login.bank.test")).unwrap();
        assert_eq!(matched.ascii_serialization(), "https://login.bank.test");
    }

    #[test]
    fn failures_render_as_fixed_strings_safe_for_an_audit_entry() {
        for failure in [
            MatchFailure::NoSavedWebsite,
            MatchFailure::NoUsableSavedWebsite,
            MatchFailure::PageOriginUnparseable,
            MatchFailure::OriginMismatch,
            MatchFailure::IframeOriginMismatch,
        ] {
            assert!(!failure.as_str().is_empty());
        }
    }
}
