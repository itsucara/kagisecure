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

/// Whether a saved website covers a host the system asked about, ignoring scheme and port.
///
/// The host-level half of [`origin_match`], for front ends that are handed a bare domain rather
/// than an origin — macOS password AutoFill's service identifiers (ADR-0045 §4). Both arguments
/// are parsed the way [`Origin::parse`] parses a Websites field, so a bare `example.com`, a URL
/// and `example.com:8443/login` all work. Same registrable domain (eTLD+1 by the public suffix
/// list) matches, so `www.` and ordinary subdomains are covered; where either side has none — an
/// IP literal, a single label, a host that is itself a public suffix — only the exact host does.
/// Two sites on shared hosting (`alice.github.io`, `bob.github.io`) therefore never match.
#[must_use]
pub fn host_match(saved: &str, requested: &str) -> bool {
    let (Ok(saved), Ok(requested)) = (Origin::parse(saved), Origin::parse(requested)) else {
        return false;
    };
    match (saved.registrable_domain(), requested.registrable_domain()) {
        (Some(a), Some(b)) => a == b,
        _ => saved.host().eq_ignore_ascii_case(&requested.host()),
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

/// Which of an item's saved websites covers `page`, under the one rule in [`origin_match`].
///
/// The saved website the approval sheet shows beside the page's origin (ADR-0036 §5), so the human
/// can see *which* of their records the rule relied on — and, when its host is not the page's,
/// that the page is a subdomain of it. `None` exactly when [`item_match`] refuses a top-frame fill
/// of `page`: this is the same rule, answering a different question, not a second rule.
///
/// When several saved websites cover the page, one on the page's exact host is preferred, so the
/// subdomain disclosure appears only when no saved website names the page's own host; otherwise
/// the first in the item's order. Unparseable and non-http(s) entries are skipped, as
/// [`item_match`] skips them.
#[must_use]
pub fn covering_website(saved_websites: &[String], page: &Origin) -> Option<Origin> {
    let covering: Vec<Origin> = saved_websites
        .iter()
        .filter_map(|s| Origin::parse(s).ok())
        .filter(|saved| origin_match(saved, page))
        .collect();
    covering
        .iter()
        .find(|saved| saved.host == page.host)
        .cloned()
        .or_else(|| covering.into_iter().next())
}

/// How the agent-fill approval sheet renders a page origin so that a look-alike is obvious
/// (ADR-0036 §5).
///
/// The origin rule is what stops a look-alike — `examp1e.com` never covers `example.com` — so
/// this is defence in depth for what the rule allows by design, and it hides nothing: the
/// pieces concatenate back to exactly [`Origin::ascii_serialization`] (see [`Self::ascii`]), the
/// string the rule compared and the audit log records.
///
/// * The host is split into the **registrable domain**, to be emphasized, and whatever precedes
///   it, to be dimmed — because the rule accepts any subdomain of a saved site, and
///   `user-content.example.com` is a subdomain an agent can be steered to. A host with no
///   registrable domain (an IP literal, a single label, a public suffix) is emphasized whole.
/// * When any label is punycode (`xn--`), the Unicode rendering the browser may show is given
///   beside the ASCII form, with a mixed-script flag.
/// * `http` is flagged as not encrypted.
/// * A non-default port is always given; a default one never is, exactly as in the ASCII
///   serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentOriginRendering {
    /// The scheme, `http` or `https`.
    pub scheme: String,
    /// The labels in front of the registrable domain, with their trailing dot — `login.` in
    /// `login.example.com` — to be dimmed. Empty when there are none.
    pub dimmed_prefix: String,
    /// The registrable domain, to be emphasized; the whole host when there is none. ASCII, with
    /// an IPv6 literal in brackets.
    pub emphasized: String,
    /// The port, when it is not the scheme's default.
    pub port: Option<u16>,
    /// The whole host with every `xn--` label decoded to Unicode, when at least one label is
    /// punycode: what the address bar may show. Shown *beside* the ASCII form, never instead.
    pub unicode_host: Option<String>,
    /// Whether the Unicode host mixes scripts, or has a punycode label that does not decode.
    ///
    /// Deliberately conservative: set when the host's letters, taken together across every label,
    /// come from more than one of Latin, Greek, Cyrillic, and "anything else" — so a Cyrillic
    /// letter in a Latin label is flagged, and so is an all-Cyrillic label under a Latin
    /// top-level domain, the whole-script homograph (`аррӏе.com`). Digits, hyphens and combining
    /// marks belong to no script. Scripts other than those three are one class here: the check is
    /// aimed at look-alikes of Latin names, not at telling, say, Han from Hiragana. A false alarm
    /// costs a warning line on the sheet; a missed homograph costs the thing the sheet is for.
    pub mixed_script: bool,
    /// Whether the scheme is `http`: the value would travel unencrypted. The rule refuses a
    /// scheme that differs from the saved one, so this appears only when the saved website is
    /// itself `http`.
    pub not_encrypted: bool,
}

impl AgentOriginRendering {
    /// Render `origin`.
    #[must_use]
    pub fn of(origin: &Origin) -> Self {
        let host = match &origin.host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(a) => a.to_string(),
            Host::Ipv6(a) => format!("[{a}]"),
        };
        let (dimmed_prefix, emphasized) = match origin.registrable_domain() {
            Some(registrable)
                if host.len() > registrable.len()
                    && host.ends_with(&registrable)
                    && host[..host.len() - registrable.len()].ends_with('.') =>
            {
                let split = host.len() - registrable.len();
                (host[..split].to_owned(), host[split..].to_owned())
            }
            // The host *is* its registrable domain, or has none, or is spelled in a way the
            // split cannot line up with (a trailing dot): emphasize all of it rather than dim
            // anything by guesswork.
            _ => (String::new(), host.clone()),
        };
        let (unicode_host, mixed_script) = match &origin.host {
            Host::Domain(d) if d.split('.').any(is_punycode_label) => {
                let (unicode, all_decoded) = decode_labels(d);
                let mixed = !all_decoded || mixes_scripts(&unicode);
                (Some(unicode), mixed)
            }
            _ => (None, false),
        };
        let default = if origin.scheme == "https" { 443 } else { 80 };
        Self {
            scheme: origin.scheme.clone(),
            dimmed_prefix,
            emphasized,
            port: (origin.port != default).then_some(origin.port),
            unicode_host,
            mixed_script,
            not_encrypted: origin.scheme == "http",
        }
    }

    /// The pieces put back together: `scheme://` + dimmed prefix + emphasized part + `:port`.
    /// Always equal to the origin's [`Origin::ascii_serialization`].
    #[must_use]
    pub fn ascii(&self) -> String {
        let mut out = format!(
            "{}://{}{}",
            self.scheme, self.dimmed_prefix, self.emphasized
        );
        if let Some(port) = self.port {
            out.push(':');
            out.push_str(&port.to_string());
        }
        out
    }
}

/// Whether a host label is punycode.
fn is_punycode_label(label: &str) -> bool {
    label.len() > 4
        && label
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("xn--"))
}

/// The host with each punycode label decoded, and whether every one of them decoded.
///
/// A label that does not decode is kept in its ASCII form rather than dropped, so the rendering
/// never shows less than the host has.
fn decode_labels(host: &str) -> (String, bool) {
    let mut all_decoded = true;
    let labels: Vec<String> = host
        .split('.')
        .map(|label| {
            if is_punycode_label(label) {
                idna::punycode::decode_to_string(&label[4..]).unwrap_or_else(|| {
                    all_decoded = false;
                    label.to_owned()
                })
            } else {
                label.to_owned()
            }
        })
        .collect();
    (labels.join("."), all_decoded)
}

/// The script classes [`AgentOriginRendering::mixed_script`] tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Other,
}

/// Which script `c` belongs to, or `None` for a character that belongs to none.
///
/// By code-point block, written out rather than taken from a Unicode database so the check has
/// no dependency of its own; the blocks are the ones the three named scripts' letters live in.
fn script_of(c: char) -> Option<Script> {
    if c.is_ascii_alphabetic() {
        return Some(Script::Latin);
    }
    if c.is_ascii() {
        // Digits, the hyphen, and anything else ASCII a host can hold.
        return None;
    }
    Some(match u32::from(c) {
        // Combining diacritical marks take the script of the letter they sit on.
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F => {
            return None;
        }
        // Latin-1 Supplement's letters (not its signs or ×/÷), Latin Extended-A/B, IPA
        // Extensions, Latin Extended Additional, -C, -D, -E, and the fullwidth Latin letters.
        0x00C0..=0x00D6
        | 0x00D8..=0x00F6
        | 0x00F8..=0x02AF
        | 0x1E00..=0x1EFF
        | 0x2C60..=0x2C7F
        | 0xA720..=0xA7FF
        | 0xAB30..=0xAB6F
        | 0xFF21..=0xFF3A
        | 0xFF41..=0xFF5A => Script::Latin,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => Script::Greek,
        0x0400..=0x052F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Script::Cyrillic,
        _ => Script::Other,
    })
}

/// Whether the letters of `host` come from more than one script class.
fn mixes_scripts(host: &str) -> bool {
    let mut seen: Option<Script> = None;
    for script in host.chars().filter_map(script_of) {
        match seen {
            None => seen = Some(script),
            Some(first) if first != script => return true,
            Some(_) => {}
        }
    }
    false
}

/// Whether a two-step agent fill that began at `first` may continue at `next` (ADR-0036 §7.3).
///
/// A transcription of `sameSite` in `extensions/shared/tabmemory.js`, the rule the extension
/// already uses to carry an identifier-first choice from page one to page two, so the app and
/// the browser half cannot disagree about which page two is the same sign-in. It is the same
/// origin, or a subdomain of it: same scheme, and the rest of `next` either equal to the rest of
/// `first` or ending in `.` followed by it. The port is part of "the rest", as there — so a
/// subdomain on another port is not a continuation.
///
/// Stricter than [`origin_match`], on purpose: two siblings under one registrable domain
/// (`accounts.example.com` then `login.example.com`) are not a continuation, although the item
/// may cover both. The caller checks coverage separately; this answers only "is this still the
/// sign-in that started at `first`".
///
/// Both arguments are expected to be origins as the browser serializes them, which is what
/// [`Origin::ascii_serialization`] produces. Anything without a `scheme://` and a non-empty rest
/// is never a continuation of anything, as in the JavaScript.
#[must_use]
pub fn continues_same_site(first: &str, next: &str) -> bool {
    fn parts(origin: &str) -> Option<(&str, &str)> {
        let marker = origin.find("://")?;
        if marker == 0 {
            return None;
        }
        let rest = &origin[marker + 3..];
        if rest.is_empty() {
            return None;
        }
        Some((&origin[..marker], rest))
    }
    let (Some((scheme_a, host_a)), Some((scheme_b, host_b))) = (parts(first), parts(next)) else {
        return false;
    };
    if scheme_a != scheme_b {
        return false;
    }
    if host_a == host_b {
        return true;
    }
    host_b.ends_with(&format!(".{host_a}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_match_uses_the_registrable_domain() {
        use super::host_match;
        assert!(host_match("example.com", "www.example.com"));
        assert!(host_match("www.example.com", "example.com"));
        assert!(host_match("example.com", "login.example.com"));
        assert!(host_match("login.example.com", "example.com"));
        assert!(host_match("https://example.com/login", "example.com"));
        assert!(!host_match("example.com", "badexample.com"));
        assert!(!host_match("example.com", "example.com.evil.net"));
        // Shared hosting: each site is its own registrable domain.
        assert!(!host_match("alice.github.io", "bob.github.io"));
        assert!(!host_match("github.io", "alice.github.io"));
        assert!(host_match("alice.github.io", "www.alice.github.io"));
        // Multi-label public suffixes.
        assert!(host_match("shop.example.co.uk", "example.co.uk"));
        assert!(!host_match("alice.co.uk", "bob.co.uk"));
        assert!(!host_match("co.uk", "alice.co.uk"));
        // No registrable domain: exact host only.
        assert!(host_match("127.0.0.1", "127.0.0.1"));
        assert!(!host_match("localhost", "a.localhost"));
        assert!(!host_match("", "example.com"));
    }

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

    // ---------------------------------------------------------------------------------------
    // covering_website: which saved website the rule relied on.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn the_covering_website_is_the_saved_one_the_rule_relied_on() {
        let saved = vec![
            "not a url at all".to_owned(),
            "https://other.test".to_owned(),
            "https://example.com".to_owned(),
        ];
        let covering = covering_website(&saved, &o("https://login.example.com")).unwrap();
        assert_eq!(covering.ascii_serialization(), "https://example.com");
        assert_ne!(
            covering.host(),
            "login.example.com",
            "the hosts differ, so the sheet says the page is a subdomain of it"
        );
        assert_eq!(covering_website(&saved, &o("https://evil.test")), None);
        assert_eq!(covering_website(&[], &o("https://example.com")), None);
    }

    #[test]
    fn a_saved_website_on_the_pages_own_host_is_preferred() {
        let saved = vec![
            "https://example.com".to_owned(),
            "https://login.example.com/signin".to_owned(),
        ];
        assert_eq!(
            covering_website(&saved, &o("https://login.example.com"))
                .unwrap()
                .ascii_serialization(),
            "https://login.example.com"
        );
        // And with no exact host, the first in the item's order.
        let saved = vec![
            "https://www.example.com".to_owned(),
            "https://example.com".to_owned(),
        ];
        assert_eq!(
            covering_website(&saved, &o("https://login.example.com"))
                .unwrap()
                .ascii_serialization(),
            "https://www.example.com"
        );
    }

    #[test]
    fn the_covering_website_agrees_with_item_match_on_every_page() {
        // One rule, two questions: whatever `item_match` allows for a top frame, there is a
        // covering website, and whatever it refuses, there is none.
        let saved = vec![
            "https://example.com".to_owned(),
            "http://localhost:3000".to_owned(),
            "https://alice.github.io".to_owned(),
        ];
        for page in [
            "https://example.com",
            "https://login.example.com",
            "http://example.com",
            "https://example.com:8443",
            "http://localhost:3000",
            "http://localhost:3001",
            "https://mallory.github.io",
            "https://blog.alice.github.io",
            "https://example.org",
        ] {
            assert_eq!(
                covering_website(&saved, &o(page)).is_some(),
                item_match(&saved, page, None).is_ok(),
                "{page}"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // AgentOriginRendering: making a look-alike obvious on the agent-fill sheet.
    // ---------------------------------------------------------------------------------------

    fn render(s: &str) -> AgentOriginRendering {
        AgentOriginRendering::of(&o(s))
    }

    #[test]
    fn the_registrable_domain_is_split_out_for_emphasis() {
        for (page, dimmed, emphasized) in [
            ("https://login.example.com", "login.", "example.com"),
            (
                "https://user-content.example.com",
                "user-content.",
                "example.com",
            ),
            ("https://a.b.example.com", "a.b.", "example.com"),
            ("https://example.com", "", "example.com"),
            ("https://news.bbc.co.uk", "news.", "bbc.co.uk"),
            // The Public Suffix List decides where the split goes, not "the last two labels".
            ("https://alice.github.io", "", "alice.github.io"),
            ("https://blog.alice.github.io", "blog.", "alice.github.io"),
            // No registrable domain: the whole host is emphasized, nothing is dimmed.
            ("https://github.io", "", "github.io"),
            ("http://localhost:3000", "", "localhost"),
            ("http://127.0.0.1:3000", "", "127.0.0.1"),
            ("http://[::1]:3000", "", "[::1]"),
        ] {
            let rendering = render(page);
            assert_eq!(rendering.dimmed_prefix, dimmed, "{page}");
            assert_eq!(rendering.emphasized, emphasized, "{page}");
            assert_eq!(
                rendering.ascii(),
                o(page).ascii_serialization(),
                "the pieces hide nothing: {page}"
            );
        }
    }

    #[test]
    fn an_xn_label_gets_a_unicode_rendering_and_a_mixed_script_flag() {
        // The literals below are non-ASCII on purpose: they are what the address bar would show,
        // which is the thing under test. Each input is given in punycode.

        // A Cyrillic "а" inside a Latin label: the classic mixed-script look-alike.
        let mixed = render("https://xn--pypal-4ve.com");
        assert_eq!(mixed.unicode_host.as_deref(), Some("pаypal.com"));
        assert!(mixed.mixed_script);
        assert_eq!(
            mixed.emphasized, "xn--pypal-4ve.com",
            "the ASCII form is what is emphasized"
        );

        // An all-Cyrillic label under a Latin top-level domain: the whole-script homograph.
        let whole = render("https://login.xn--80ak6aa92e.com");
        assert_eq!(whole.unicode_host.as_deref(), Some("login.аррӏе.com"));
        assert!(whole.mixed_script);
        assert_eq!(whole.dimmed_prefix, "login.");
        assert_eq!(whole.emphasized, "xn--80ak6aa92e.com");

        // A Latin letter with a diacritic is still Latin: rendered, not flagged.
        let accented = render("https://xn--exmple-cua.com");
        assert_eq!(accented.unicode_host.as_deref(), Some("exämple.com"));
        assert!(!accented.mixed_script);

        // One script throughout, whatever it is, is not mixed.
        let greek = render("https://xn--hxajbheg2az3al.xn--jxalpdlp");
        assert_eq!(greek.unicode_host.as_deref(), Some("παράδειγμα.δοκιμή"));
        assert!(!greek.mixed_script);

        // A host with no punycode label has no Unicode rendering and nothing to flag.
        let plain = render("https://login.example.com");
        assert_eq!(plain.unicode_host, None);
        assert!(!plain.mixed_script);
    }

    #[test]
    fn the_script_check_treats_digits_hyphens_and_marks_as_neutral() {
        assert!(!mixes_scripts("login-2.example.com"));
        assert!(
            !mixes_scripts("e\u{0301}xample.com"),
            "a combining accent is not a script"
        );
        assert!(mixes_scripts("pаypal.com"));
        assert!(mixes_scripts("παypal.com"));
        assert!(
            mixes_scripts("בדיקה.com"),
            "Latin with anything else is mixed"
        );
        assert!(
            !mixes_scripts("בדיקה.טעסט"),
            "the check is about Latin look-alikes"
        );
        assert!(mixes_scripts("аα"), "Greek with Cyrillic is mixed too");
    }

    #[test]
    fn a_punycode_label_that_does_not_decode_is_flagged_not_trusted() {
        // `url` refuses such a host before an `Origin` exists, so this is the helper's own
        // contract: the label is kept verbatim, and the caller is told.
        for bad in ["xn--99999999999999", "xn--a-!!"] {
            let host = format!("login.{bad}.com");
            let (unicode, all_decoded) = decode_labels(&host);
            assert!(!all_decoded, "{bad}");
            assert_eq!(unicode, host, "nothing dropped, nothing guessed");
        }
        let (unicode, all_decoded) = decode_labels("xn--pypal-4ve.com");
        assert!(all_decoded);
        assert_eq!(unicode, "pаypal.com");
    }

    #[test]
    fn http_is_flagged_as_not_encrypted() {
        assert!(render("http://example.com").not_encrypted);
        assert!(render("http://localhost:3000").not_encrypted);
        assert!(!render("https://example.com").not_encrypted);
    }

    #[test]
    fn a_non_default_port_is_always_rendered() {
        for (page, port) in [
            ("https://example.com:8443", Some(8443)),
            ("https://login.example.com:8443/signin", Some(8443)),
            ("http://example.com:8080", Some(8080)),
            // The other scheme's default is not this scheme's default.
            ("https://example.com:80", Some(80)),
            ("http://example.com:443", Some(443)),
            ("http://[::1]:3000", Some(3000)),
            ("https://example.com:443", None),
            ("http://example.com:80", None),
            ("https://example.com", None),
        ] {
            let rendering = render(page);
            assert_eq!(rendering.port, port, "{page}");
            let ascii = rendering.ascii();
            match port {
                Some(port) => assert!(ascii.ends_with(&format!(":{port}")), "{ascii}"),
                None => assert_eq!(ascii.matches(':').count(), 1, "{ascii}"),
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // continues_same_site: the extension's `sameSite`, transcribed.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn same_site_continuation_matches_tabmemory_same_site() {
        // Every row is a case `extensions/chrome/test/tabmemory.test.js` asserts of `sameSite`,
        // directly or through `recall`, with the answer it asserts.
        for (first, next, same) in [
            // The same origin, and a subdomain of it: the case the feature exists for.
            ("https://example.com", "https://example.com", true),
            ("https://example.com", "https://login.example.com", true),
            ("https://example.test", "https://login.example.test", true),
            // A sibling subdomain: the app's rule would allow it; this one does not.
            (
                "https://accounts.example.com",
                "https://login.example.com",
                false,
            ),
            (
                "https://login.example.test",
                "https://evil.example.test",
                false,
            ),
            // Two sites under a public suffix are strangers.
            (
                "https://alice.github.io",
                "https://mallory.github.io",
                false,
            ),
            // Not a subdomain, however it ends.
            ("https://example.com", "https://notexample.com", false),
            (
                "https://example.com",
                "https://example.com.evil.test",
                false,
            ),
            // Scheme and port are part of the comparison.
            ("https://example.com", "http://example.com", false),
            ("http://example.test", "https://example.test", false),
            ("http://example.com:8080", "http://example.com:8080", true),
            ("http://example.com:8080", "http://example.com:9090", false),
            ("https://example.test", "https://example.test:8443", false),
            ("https://example.test:8443", "https://example.test", false),
            (
                "https://example.test",
                "https://login.example.test:8443",
                false,
            ),
            // Malformed input is never the same site as anything.
            ("example.com", "https://example.com", false),
            ("https://example.com", "null", false),
            ("https://example.com", "", false),
            ("", "", false),
        ] {
            assert_eq!(continues_same_site(first, next), same, "{first} -> {next}");
        }
    }

    #[test]
    fn a_continuation_needs_a_scheme_marker_and_something_after_it() {
        // The edges of the JavaScript's string surgery: `indexOf("://") <= 0` and an empty rest.
        assert!(!continues_same_site("://example.com", "://example.com"));
        assert!(!continues_same_site("https://", "https://"));
        assert!(continues_same_site("https://a", "https://b.a"));
        // A subdomain of a subdomain is still a subdomain.
        assert!(continues_same_site(
            "https://example.com",
            "https://a.b.example.com"
        ));
        // And the direction matters: going *up* from a subdomain is not a continuation.
        assert!(!continues_same_site(
            "https://login.example.com",
            "https://example.com"
        ));
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
