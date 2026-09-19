//! The messages on the extension channel.
//!
//! # Read this as the list of what the browser may learn
//!
//! [`Request`] is what the extension may ask. [`Response`] is what the app may answer. There are
//! four questions and six answers, and only two answer fields in the whole file are typed
//! [`FillValue`]. That is the enumeration ADR-0018 asks a reviewer to check: everything else is
//! an origin, a title, a username, an item id, a count or an error code.
//!
//! # Why the browser gets titles and usernames but no URLs
//!
//! [`Response::Matches`] answers "which of my items apply to the page I am on". The extension
//! already knows the origin — it is the origin the extension asked about — so returning the
//! item's saved website teaches the browser nothing it does not have, while returning *other*
//! saved websites would leak the user's site list to a compromised extension one page at a time.
//! So [`MatchItem`] carries the item's id, its title and its username, and nothing else with a
//! URL in it.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The version of this protocol the app speaks.
///
/// A `Hello` naming a different major version is refused rather than negotiated: the extension
/// and the app ship together, and a version skew means one of them was replaced under the other.
pub const PROTOCOL_VERSION: u32 = 1;

/// A value that must not be logged.
///
/// This is the extension channel's equivalent of `kagisecure_core::Secret`, and it exists
/// separately because this crate deliberately does not enable `secret-material` — the native
/// host links it and must never be able to open a vault.
///
/// What the type buys, concretely:
///
/// * no `Display`, so it cannot be interpolated into a message by accident;
/// * a `Debug` that prints `FillValue(<redacted>)`, so `dbg!` and `{:?}` on a whole `Response`
///   are safe;
/// * `ZeroizeOnDrop`, so the app's copy does not outlive the frame it was written into.
///
/// What it does not buy: once the JSON is serialized the bytes are an ordinary buffer, and once
/// the extension has them they are in a browser process. That is the residual risk
/// `docs/threat-model-browser-extension.md` records, not something a newtype can fix.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct FillValue(String);

impl FillValue {
    /// Wrap a value that is about to cross to the browser.
    ///
    /// Every call site of this function is a place a secret leaves the app. There are two, both
    /// in `kagisecure_agent::extension`, and both immediately after an approved fill.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the value back. Named to be greppable, like `Secret::expose_str`.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether there is anything here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for FillValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FillValue(<redacted>)")
    }
}

impl PartialEq for FillValue {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for FillValue {}

/// Where the extension is asking from.
///
/// Both origins are the *browser's* claim about itself. The app cannot verify them — a
/// compromised extension can say anything — which is why they are recorded on the approval sheet
/// and in the audit log verbatim, and why the match rule is applied to them rather than to
/// anything the app inferred. See `docs/threat-model-browser-extension.md` §4.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageContext {
    /// The top-level document's origin, e.g. `https://example.com`.
    pub top_origin: String,
    /// The origin of the frame the form is in, when it is not the top frame.
    ///
    /// `None` means the top frame. When this is `Some` and differs from `top_origin`, the fill is
    /// refused unless the **frame** origin matches the item — a page cannot borrow its own
    /// trustworthiness for a third party's iframe (ADR-0020).
    #[serde(default)]
    pub frame_origin: Option<String>,
}

impl PageContext {
    /// A top-frame context.
    #[must_use]
    pub fn top(origin: impl Into<String>) -> Self {
        Self {
            top_origin: origin.into(),
            frame_origin: None,
        }
    }

    /// The origin the match rule is applied to: the frame's, when there is one.
    #[must_use]
    pub fn effective_origin(&self) -> &str {
        self.frame_origin.as_deref().unwrap_or(&self.top_origin)
    }

    /// Whether the fill target is in a cross-origin iframe.
    #[must_use]
    pub fn is_cross_origin_frame(&self) -> bool {
        matches!(&self.frame_origin, Some(f) if f != &self.top_origin)
    }
}

/// Which fields a fill would write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FillField {
    /// The item's username. Metadata; the extension already saw it in [`MatchItem`].
    Username,
    /// The item's password. **This is the crossing.**
    Password,
}

impl FillField {
    /// The word the approval sheet and the audit entry use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
        }
    }

    /// Both fields: what a [`Request::Fill`] means when it names none.
    ///
    /// This is the serde default, and it is the *compatible* answer rather than the safe-looking
    /// one on purpose. `fields` has been on the wire since the protocol's first version and every
    /// shipped extension sends it; the default exists for a message hand-written by a test or by
    /// a future extension that has not been updated, and for those "fill this login" is what a
    /// fill has always meant. Defaulting to `[Username]` instead would silently turn a real fill
    /// into a half one, which is a harder failure to see than a full one.
    #[must_use]
    pub fn both() -> Vec<Self> {
        vec![Self::Username, Self::Password]
    }

    /// Whether a fill naming these fields would carry a secret across to the browser.
    ///
    /// The one question the approval rule turns on: a fill that writes only a username is
    /// metadata the extension already received in [`Response::Matches`], and is therefore served
    /// without an approval sheet (ADR-0030). Anything that names [`FillField::Password`] is a
    /// crossing and keeps the sheet.
    #[must_use]
    pub fn crosses_a_secret(fields: &[Self]) -> bool {
        fields.contains(&Self::Password)
    }
}

/// What the extension asks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ask", rename_all = "snake_case")]
pub enum Request {
    /// First message on every connection. Refused if the extension id is not pinned.
    Hello {
        /// The extension's own id, as the browser reports it to the extension.
        extension_id: String,
        /// What the extension believes it is running in, e.g. `"chrome"`. Display-only: the app
        /// establishes the browser from the native host's process ancestry, not from this.
        browser: String,
        /// The extension's version string. Display-only.
        extension_version: String,
        /// The protocol version the extension speaks.
        protocol_version: u32,
    },
    /// Cheap poll for the popup: is the vault unlocked?
    Status,
    /// "Which of my items apply to this page?" Never prompts; never returns a value.
    Match {
        /// Where the extension is asking from.
        page: PageContext,
    },
    /// "Fill this item into this page." Prompts unless a live lease already covers it.
    Fill {
        /// Where the extension is asking from.
        page: PageContext,
        /// Which item, from a prior [`Response::Matches`].
        item_id: String,
        /// Which fields to write.
        ///
        /// `["username"]` is the identifier-first case — page one of a Google/Microsoft/Okta
        /// sign-in, where there is no password box yet. The app answers such a request with the
        /// username **and nothing else**: see [`Response::filled`], which is the only constructor
        /// for the message that can carry a password.
        ///
        /// Absent, this means both fields — see [`FillField::both`].
        #[serde(default = "FillField::both")]
        fields: Vec<FillField>,
    },
    /// "Give me the current one-time code for this item." A separate, explicit second action.
    Totp {
        /// Where the extension is asking from.
        page: PageContext,
        /// Which item.
        item_id: String,
    },
}

/// One item that applies to the page. Metadata only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchItem {
    /// The item's id, quoted back in a [`Request::Fill`].
    pub item_id: String,
    /// The item's title.
    pub title: String,
    /// The item's username, if it has one. Not secret material (`FieldValue::Public`).
    #[serde(default)]
    pub username: Option<String>,
    /// Whether a [`Request::Totp`] on this item would produce a code.
    pub has_totp: bool,
}

/// A stable machine-readable failure, for the extension to branch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// The vault is locked. The popup offers "Open Kagisecure".
    VaultLocked,
    /// The user said no.
    UserDenied,
    /// Nobody answered the sheet in time.
    ApprovalTimeout,
    /// The item's saved websites do not cover this origin, or the iframe policy refused it.
    OriginMismatch,
    /// No item in the vault applies to this origin.
    NoMatch,
    /// The extension id is not the pinned one.
    UnknownExtension,
    /// The connecting process is not a native host launched by a recognized browser.
    UntrustedHost,
    /// The message did not make sense: bad version, bad order, unparseable origin.
    Protocol,
    /// Something failed inside the app.
    Internal,
}

impl ErrorCode {
    /// The token as it appears on the wire and in a log line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultLocked => "VAULT_LOCKED",
            Self::UserDenied => "USER_DENIED",
            Self::ApprovalTimeout => "APPROVAL_TIMEOUT",
            Self::OriginMismatch => "ORIGIN_MISMATCH",
            Self::NoMatch => "NO_MATCH",
            Self::UnknownExtension => "UNKNOWN_EXTENSION",
            Self::UntrustedHost => "UNTRUSTED_HOST",
            Self::Protocol => "PROTOCOL",
            Self::Internal => "INTERNAL",
        }
    }
}

/// What the app answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    /// The answer to [`Request::Hello`].
    Welcome {
        /// The protocol version the app speaks.
        protocol_version: u32,
        /// The app's version string.
        app_version: String,
        /// Whether the vault is unlocked right now.
        unlocked: bool,
        /// One line per fact the app established about the native host and the browser behind it
        /// — an executable path and a code-signature verdict each. On an ad-hoc build at least
        /// one of these says *unverified*, and the popup shows it: see ADR-0015 for why that is
        /// the truthful answer rather than a flattering one.
        host_evidence: Vec<String>,
    },
    /// The answer to [`Request::Status`].
    Status {
        /// Whether the vault is unlocked right now.
        unlocked: bool,
    },
    /// The answer to [`Request::Match`]. Never prompts, so it is safe to send on focus.
    Matches {
        /// The origin the match was performed against, echoed back so the extension can drop a
        /// stale answer after a navigation.
        origin: String,
        /// The items that apply, in vault order.
        items: Vec<MatchItem>,
    },
    /// The answer to an approved [`Request::Fill`]. **The one message that carries a password.**
    Filled {
        /// The item that was filled, echoed for correlation.
        item_id: String,
        /// The username, when it was asked for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        /// The password, when it was asked for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<FillValue>,
    },
    /// The answer to an approved [`Request::Totp`].
    TotpCode {
        /// The item, echoed for correlation.
        item_id: String,
        /// The current code.
        code: FillValue,
        /// How many seconds it stays valid, so the popup can show a countdown.
        seconds_remaining: u32,
    },
    /// Anything that did not work.
    Error {
        /// The stable token.
        code: ErrorCode,
        /// One human-readable line. Written from a fixed vocabulary; never interpolated with a
        /// value.
        message: String,
    },
}

impl Response {
    /// An error response.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    /// Build a [`Response::Filled`] that carries **only** the fields that were asked for.
    ///
    /// The enforcement point for the `fields` selector. A caller that looks up an item hands over
    /// whatever the item has; this drops anything the request did not name, so a username-only
    /// fill cannot carry a password even if the code above it forgets — which is the property
    /// [`Self::carries_only`] asserts and the canary test in this module checks by serializing the
    /// result and looking for the bytes.
    #[must_use]
    pub fn filled(
        item_id: impl Into<String>,
        requested: &[FillField],
        username: Option<String>,
        password: Option<FillValue>,
    ) -> Self {
        Self::Filled {
            item_id: item_id.into(),
            username: username.filter(|_| requested.contains(&FillField::Username)),
            password: password.filter(|_| requested.contains(&FillField::Password)),
        }
    }

    /// Whether this response carries no field beyond `requested`.
    ///
    /// True for every response that is not a [`Response::Filled`]: no other message has a field a
    /// fill request could have asked for.
    #[must_use]
    pub fn carries_only(&self, requested: &[FillField]) -> bool {
        match self {
            Self::Filled {
                username, password, ..
            } => {
                (username.is_none() || requested.contains(&FillField::Username))
                    && (password.is_none() || requested.contains(&FillField::Password))
            }
            _ => true,
        }
    }
}

/// A request with the correlation id the native host round-trips.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// A magic field naming the channel. Present so a frame from the MCP socket, which has no
    /// such field, fails to parse here rather than being interpreted (ADR-0019).
    #[serde(rename = "ksx")]
    pub channel: u32,
    /// The extension's correlation id, echoed on the reply.
    pub id: String,
    /// The message.
    pub body: T,
}

impl<T> Envelope<T> {
    /// Wrap `body` with `id`.
    pub fn new(id: impl Into<String>, body: T) -> Self {
        Self {
            channel: PROTOCOL_VERSION,
            id: id.into(),
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_value_redacts_itself_in_debug() {
        let value = FillValue::new("hunter2");
        assert_eq!(format!("{value:?}"), "FillValue(<redacted>)");
        assert_eq!(value.expose(), "hunter2");
    }

    #[test]
    fn a_whole_response_is_safe_to_debug_print() {
        let response = Response::Filled {
            item_id: "abc".to_owned(),
            username: Some("alice".to_owned()),
            password: Some(FillValue::new("CANARY-MARKER-0123456789abcdef")),
        };
        let rendered = format!("{response:?}");
        assert!(
            !rendered.contains("CANARY-MARKER"),
            "Debug on a Response must not print the password: {rendered}"
        );
        assert!(rendered.contains("alice"), "but the username is metadata");
    }

    #[test]
    fn a_fill_value_serializes_as_a_bare_string() {
        let json = serde_json::to_string(&FillValue::new("pw")).unwrap();
        assert_eq!(json, "\"pw\"");
        let back: FillValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "pw");
    }

    #[test]
    fn every_request_round_trips() {
        let requests = vec![
            Request::Hello {
                extension_id: "nlijibjnmanccalmafnfbobkcfjiibmd".to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.1.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            Request::Status,
            Request::Match {
                page: PageContext::top("https://example.com"),
            },
            Request::Fill {
                page: PageContext::top("https://example.com"),
                item_id: "i".to_owned(),
                fields: vec![FillField::Username, FillField::Password],
            },
            Request::Totp {
                page: PageContext::top("https://example.com"),
                item_id: "i".to_owned(),
            },
        ];
        for request in requests {
            let json = serde_json::to_string(&request).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(back, request);
        }
    }

    #[test]
    fn a_fill_that_names_no_fields_means_both_of_them() {
        // The compatibility default. A message written before `fields` existed, or by a test that
        // does not care, is a full login fill rather than a half one.
        let json = r#"{"ask":"fill","page":{"top_origin":"https://example.com"},"item_id":"i"}"#;
        let back: Request = serde_json::from_str(json).unwrap();
        match back {
            Request::Fill { fields, .. } => {
                assert_eq!(fields, vec![FillField::Username, FillField::Password]);
            }
            other => panic!("expected a fill, got {other:?}"),
        }
    }

    #[test]
    fn a_username_only_fill_cannot_carry_the_password() {
        // The canary: hand `filled` a password it was not asked for, and check the bytes are not
        // on the wire. This is the structural half of ADR-0030 — the app's own decision not to
        // read a password for a username-only request is the other half, and is asserted in
        // `kagisecure_agent::extension`.
        const MARKER: &str = "MARKER-8c1d40f6a9b24e73bd05a1c8e6f92d47";
        let requested = [FillField::Username];
        let response = Response::filled(
            "i",
            &requested,
            Some("alice".to_owned()),
            Some(FillValue::new(MARKER)),
        );
        match &response {
            Response::Filled {
                username, password, ..
            } => {
                assert_eq!(username.as_deref(), Some("alice"));
                assert!(password.is_none(), "the password was not asked for");
            }
            other => panic!("expected a fill, got {other:?}"),
        }
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains(MARKER), "{json}");
        assert!(!json.contains("password"), "not even the key: {json}");
        assert!(response.carries_only(&requested));
    }

    #[test]
    fn a_password_only_fill_carries_no_username() {
        let requested = [FillField::Password];
        let response = Response::filled(
            "i",
            &requested,
            Some("alice".to_owned()),
            Some(FillValue::new("pw")),
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("alice"), "{json}");
        assert!(response.carries_only(&requested));
    }

    #[test]
    fn carries_only_catches_a_response_that_overshot() {
        let overshot = Response::Filled {
            item_id: "i".to_owned(),
            username: Some("alice".to_owned()),
            password: Some(FillValue::new("pw")),
        };
        assert!(!overshot.carries_only(&[FillField::Username]));
        assert!(!overshot.carries_only(&[FillField::Password]));
        assert!(overshot.carries_only(&FillField::both()));
        assert!(
            Response::Status { unlocked: true }.carries_only(&[]),
            "a message with no fill fields carries nothing a fill could have asked for"
        );
    }

    #[test]
    fn only_a_fill_that_names_the_password_crosses_a_secret() {
        assert!(!FillField::crosses_a_secret(&[FillField::Username]));
        assert!(!FillField::crosses_a_secret(&[]));
        assert!(FillField::crosses_a_secret(&[FillField::Password]));
        assert!(FillField::crosses_a_secret(&FillField::both()));
    }

    #[test]
    fn an_mcp_frame_body_does_not_parse_as_an_extension_envelope() {
        // The two channels share a socket directory and a length-prefixed-JSON shape. They must
        // not share a *message*: a frame written for one has to fail on the other.
        let mcp = br#"{"op":"ListVaults"}"#;
        assert!(serde_json::from_slice::<Envelope<Request>>(mcp).is_err());
    }

    #[test]
    fn an_extension_envelope_does_not_parse_as_anything_without_its_magic() {
        let envelope = Envelope::new("1", Request::Status);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"ksx\":1"), "{json}");
        let stripped = json.replace("\"ksx\":1,", "");
        assert!(
            serde_json::from_str::<Envelope<Request>>(&stripped).is_err(),
            "the channel marker is required, not decorative"
        );
    }

    #[test]
    fn the_effective_origin_is_the_frames_when_there_is_one() {
        let top = PageContext::top("https://example.com");
        assert_eq!(top.effective_origin(), "https://example.com");
        assert!(!top.is_cross_origin_frame());

        let framed = PageContext {
            top_origin: "https://example.com".to_owned(),
            frame_origin: Some("https://login.other.test".to_owned()),
        };
        assert_eq!(framed.effective_origin(), "https://login.other.test");
        assert!(framed.is_cross_origin_frame());

        let same = PageContext {
            top_origin: "https://example.com".to_owned(),
            frame_origin: Some("https://example.com".to_owned()),
        };
        assert!(!same.is_cross_origin_frame());
    }

    #[test]
    fn error_codes_have_stable_tokens_on_the_wire() {
        let json =
            serde_json::to_string(&Response::error(ErrorCode::OriginMismatch, "no")).unwrap();
        assert!(json.contains("ORIGIN_MISMATCH"), "{json}");
        assert_eq!(ErrorCode::VaultLocked.as_str(), "VAULT_LOCKED");
    }

    #[test]
    fn only_two_response_fields_are_fill_values() {
        // A structural restatement of ADR-0018's table, asserted by construction: build every
        // response shape, serialize it, and check the marker only survives in the two that are
        // allowed to carry one.
        const MARKER: &str = "MARKER-3f9a2c7e5b1d4086a2c7e5b1d4086a2c";
        let carriers = [
            Response::Filled {
                item_id: "i".to_owned(),
                username: Some("u".to_owned()),
                password: Some(FillValue::new(MARKER)),
            },
            Response::TotpCode {
                item_id: "i".to_owned(),
                code: FillValue::new(MARKER),
                seconds_remaining: 12,
            },
        ];
        for response in &carriers {
            assert!(serde_json::to_string(response).unwrap().contains(MARKER));
        }

        let non_carriers = [
            Response::Welcome {
                protocol_version: PROTOCOL_VERSION,
                app_version: "0.1.0".to_owned(),
                unlocked: true,
                host_evidence: vec!["x".to_owned()],
            },
            Response::Status { unlocked: true },
            Response::Matches {
                origin: "https://example.com".to_owned(),
                items: vec![MatchItem {
                    item_id: "i".to_owned(),
                    title: "t".to_owned(),
                    username: Some("u".to_owned()),
                    has_totp: true,
                }],
            },
            Response::error(ErrorCode::NoMatch, "nothing here"),
            Response::Filled {
                item_id: "i".to_owned(),
                username: Some("u".to_owned()),
                password: None,
            },
        ];
        for response in &non_carriers {
            let json = serde_json::to_string(response).unwrap();
            assert!(!json.contains(MARKER), "{json}");
        }
    }
}
