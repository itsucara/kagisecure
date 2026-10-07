//! The messages on the extension channel.
//!
//! # Read this as the list of what the browser may learn
//!
//! [`Request`] is what the extension may ask. [`Response`] is what the app may answer. [`Push`] is
//! what the app may say without being asked. There are eight questions, seven answers and two
//! pushes, and only three answer fields in the whole file are typed [`FillValue`]. That is the
//! enumeration ADR-0018 asks a reviewer to check: everything else is an origin, a title, a
//! username, an item id, a tab id, a yes-or-no about a form, a count or an error code.
//!
//! # The app speaks first, but says nothing
//!
//! An agent's fill request (ADR-0036) arrives on the MCP socket and has to find its way to a tab,
//! so this channel is no longer only browser-initiated: the app may send a [`Push`]. A push is a
//! doorbell. It carries two opaque ids and nothing else — no value, no origin, no item id, no
//! title — and everything that carries information is still a [`Request`] the extension sends and
//! the browser stamps. The one message that carries a password is still a reply to a request the
//! extension made, built by the same [`Response::filled`].
//!
//! A push travels in a [`PushEnvelope`], which has neither the `id` nor the `body` of an
//! [`Envelope`], so a push frame fails to parse as a reply or a request and a reply fails to parse
//! as a push. [`HostBound`] is the one type that reads either, for the native host's side of the
//! socket, where both arrive interleaved.
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
///
/// Adding an [`ErrorCode`] is deliberately **not** a version change. The only parsers of the typed
/// enum — `kagisecure-nmhost` and the Safari app extension's transport — ship inside the same app
/// bundle as the listener that sends it, so they can never be older than it; the content script
/// branches on the code as a string and shows the app's own message for any code it does not
/// know. A bump, by contrast, would make every extension a version behind refuse *every* request
/// at `Hello` — turning a new, rare failure into a total one. `AUDIT_UNAVAILABLE` was added this
/// way (ADR-0040 §5), and `VAULT_CONFLICT` the same way: see [`ErrorCode::VaultConflict`].
///
/// Agent-requested fills (ADR-0036) were added the same way, for the same reason. The new
/// requests are sent only by an extension that knows them; [`Response::Noted`] answers only
/// those; and a [`Push`] goes only to a session whose `Hello` declared
/// [`Capability::AgentFill`] — which an extension built before this change never does, since an
/// absent `capabilities` list is an empty one. Nothing an older extension sends or receives
/// changes shape, so a bump would buy nothing but a refusal.
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
    /// in `kagisecure_agent::extension::crossing`, and both in functions that cannot be called
    /// without an `Approved` — which only a granted approval can produce (ADR-0037).
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
    /// Whether the **browser itself** reported that this request came from frame id 0.
    ///
    /// This is the one fact on this struct no message can arrange: the extension sets it from
    /// `sender.frameId == 0`, never from anything a page or a content script said. When a
    /// sub-frame claims a top origin equal to its own frame origin — the shape an embedded frame
    /// uses to pass itself off as a top-frame load — the extension sends `top_origin: "null"`,
    /// the platform serialization of an opaque origin, and leaves this `false`.
    ///
    /// Defaults to `false`, which is the safe direction: a message that does not say so is
    /// treated as a frame whose embedder could not be established, and disclosed as one (D-7).
    #[serde(default)]
    pub top_origin_established: bool,
}

impl PageContext {
    /// A top-frame context.
    #[must_use]
    pub fn top(origin: impl Into<String>) -> Self {
        Self {
            top_origin: origin.into(),
            frame_origin: None,
            top_origin_established: true,
        }
    }

    /// The origin the match rule is applied to: the frame's, when there is one.
    #[must_use]
    pub fn effective_origin(&self) -> &str {
        self.frame_origin.as_deref().unwrap_or(&self.top_origin)
    }

    /// Whether the fill target is in a frame rather than in a top-level document.
    ///
    /// Keyed on [`Self::top_origin_established`] rather than on `frame_origin != top_origin`: a
    /// sub-frame that claims its own origin as the top one would win that comparison and be
    /// disclosed as a plain top-frame load (D-7). Anything the browser did not itself confirm as
    /// frame 0 is a frame, whether or not its claimed embedder happens to match.
    #[must_use]
    pub fn is_cross_origin_frame(&self) -> bool {
        !self.top_origin_established
            || matches!(&self.frame_origin, Some(f) if f != &self.top_origin)
    }

    /// Whether the embedder of the frame this request came from is **unknown**.
    ///
    /// True whenever the browser did not report frame 0. The app must show "an unknown site"
    /// here, never the literal `"null"` [`Self::top_origin`] may carry.
    #[must_use]
    pub fn top_origin_unknown(&self) -> bool {
        !self.top_origin_established
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

/// Something an extension can do beyond the requests every version understands, declared in its
/// [`Request::Hello`].
///
/// Declared, not negotiated: the app never answers with a list of its own, it only decides what to
/// *send* a session by what that session said it can take. Today that is one thing, a [`Push`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The session accepts [`Push`]es and answers them with [`Request::TargetReport`] and
    /// [`Request::AgentFill`] (ADR-0036). Only a session that declared this is ever sent a push.
    AgentFill,
}

impl Capability {
    /// The token as it appears on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentFill => "agent_fill",
        }
    }

    /// The capability `token` names, or `None` for one this app does not know.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "agent_fill" => Some(Self::AgentFill),
            _ => None,
        }
    }
}

/// Read a `capabilities` list, keeping the tokens this app knows and dropping the rest.
///
/// A token the app does not know is *ignored*, not refused: an extension newer than the app may
/// declare something the app cannot use, and the right answer to that is to not use it, not to
/// refuse the extension's `Hello`. An entry that is not a string at all is still a malformed
/// message.
fn known_capabilities<'de, D>(deserializer: D) -> Result<Vec<Capability>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let tokens = Vec::<String>::deserialize(deserializer)?;
    let mut known: Vec<Capability> = tokens
        .iter()
        .filter_map(|t| Capability::from_token(t))
        .collect();
    known.dedup();
    Ok(known)
}

/// A field an agent-requested fill can write (ADR-0036 §7).
///
/// A separate type from [`FillField`], rather than a third member of it, because the human path's
/// `fields` selector has no one-time-code member and must not grow one by accident: a human's
/// one-time code is a [`Request::Totp`], a different request with its own sheet. On this path the
/// code is a field like the others, but never in the same grant as a password (§7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentFillField {
    /// The item's username.
    Username,
    /// The item's password.
    Password,
    /// The item's current one-time code.
    OneTimeCode,
    /// The item's password, typed into every new-password box of a recognised sign-up form
    /// (ADR-0048 §7). Served only for sealed agent test logins.
    NewPassword,
}

impl AgentFillField {
    /// The word the approval sheet and the audit entry use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::OneTimeCode => "one_time_code",
            Self::NewPassword => "new_password",
        }
    }

    /// The human path's name for this field, where it has one. `None` for the one-time code,
    /// which the human path asks for with [`Request::Totp`] instead, and for the new password,
    /// which the human path never fills.
    #[must_use]
    pub fn as_fill_field(self) -> Option<FillField> {
        match self {
            Self::Username => Some(FillField::Username),
            Self::Password => Some(FillField::Password),
            Self::OneTimeCode | Self::NewPassword => None,
        }
    }
}

/// What the browser, and only the browser, can say about the tab a report or a fill came from.
///
/// Every field but [`Self::visible`] is copied by the service worker from the `sender` the browser
/// attached to the content script's message — `sender.tab.id`, `sender.documentId`,
/// `sender.tab.active` — never from anything the content script or the page said. `visible` is
/// the content script's own reading of `document.visibilityState`, taken in its isolated world so
/// page script cannot shadow it.
///
/// These are what an agent fill's grant is bound to (ADR-0036 §4): a delivery is refused unless
/// its tab id and document id are the ones the approved report carried. A redirect, a reload or
/// a switch to another tab changes one of them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabFacts {
    /// The browser's id for the tab.
    pub tab_id: u64,
    /// The browser's id for the document in the tab's top frame, which a navigation replaces.
    ///
    /// `None` where the browser does not provide one; the binding then degrades to tab id, frame
    /// 0 and the exact origin, and that degradation is the app's to record (ADR-0036 §4, §12).
    #[serde(default)]
    pub document_id: Option<String>,
    /// Whether the tab is the active tab of its window, as the browser reported it.
    ///
    /// Defaults to `false`, the safe direction: a report that does not say so is not eligible.
    #[serde(default)]
    pub tab_active: bool,
    /// Whether the document was visible when the content script answered.
    ///
    /// Defaults to `false`, for the same reason.
    #[serde(default)]
    pub visible: bool,
}

/// Which sign-in fields the content script's detectors found in the page.
///
/// Presence only: a yes or a no per kind of field, never an element, a name or anything typed
/// into it. The detectors are the ones the human path already runs (`extensions/shared/forms.js`):
/// the login form, anchored on a password field; the identifier-first form, which refuses any page
/// with a usable password field; and the one-time-code field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundFields {
    /// A username field: a login form's, or the lone box of an identifier-first page.
    #[serde(default)]
    pub username: bool,
    /// A password field of a login form.
    #[serde(default)]
    pub password: bool,
    /// A one-time-code field.
    #[serde(default)]
    pub one_time_code: bool,
    /// A recognised sign-up form: one `autocomplete="new-password"` field or exactly two password
    /// fields, no current-password field, and nothing the login detector accepts (ADR-0048 §7).
    #[serde(default)]
    pub sign_up: bool,
    /// A username field of that sign-up form.
    #[serde(default)]
    pub sign_up_username: bool,
}

impl FoundFields {
    /// Whether this is page one of an identifier-first sign-in: a username field and no password
    /// field (ADR-0036 §7.3).
    ///
    /// The two form detectors are mutually exclusive — the identifier-first one refuses any page
    /// with a usable password field — so a username without a password is exactly that
    /// detector's page, and needs no flag of its own.
    #[must_use]
    pub fn is_identifier_only(&self) -> bool {
        self.username && !self.password
    }

    /// Whether the page has a field for every one of `fields`.
    ///
    /// `true` for an empty list, which is not a fill anyone asks for: refusing that is the
    /// caller's job, not this predicate's.
    #[must_use]
    ///
    /// A list that names [`AgentFillField::NewPassword`] is a sign-up fill: its username is the
    /// sign-up form's, never a login form's.
    pub fn covers(&self, fields: &[AgentFillField]) -> bool {
        let sign_up = fields.contains(&AgentFillField::NewPassword);
        fields.iter().all(|field| match field {
            AgentFillField::Username if sign_up => self.sign_up_username,
            AgentFillField::Username => self.username,
            AgentFillField::NewPassword => self.sign_up,
            AgentFillField::Password => self.password,
            AgentFillField::OneTimeCode => self.one_time_code,
        })
    }
}

/// Why the content script wrote nothing, or took back what it wrote, after an agent fill was
/// delivered (ADR-0036 §4, §8.3).
///
/// Reported in [`Request::AgentFillOutcome`] and audited as a follow-up of the fill's entry. Each
/// variant is a fixed token, safe to put in an audit entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentFillFailure {
    /// Re-running the detectors at delivery found no field for one of the granted fields: the
    /// form changed between the report and the delivery.
    FormChanged,
    /// A field was there but no longer writable — disabled, read-only, detached, or no longer a
    /// `type=password` input where a password was to go.
    NotWritable,
    /// The document was hidden, or the tab was no longer the active one, when the delivery
    /// arrived.
    NotVisible,
    /// The value was written but did not stick: the page's own script replaced it.
    WriteRejected,
    /// The tripwire (§8.3): within ten seconds of the fill, the filled password input stopped
    /// being `type=password` — the site's own "show password" control, clicked — so the content
    /// script cleared it. The fill *did* happen; this outcome follows the one that said so.
    Unmasked,
}

impl AgentFillFailure {
    /// The token as it appears on the wire and in an audit entry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FormChanged => "FORM_CHANGED",
            Self::NotWritable => "NOT_WRITABLE",
            Self::NotVisible => "NOT_VISIBLE",
            Self::WriteRejected => "WRITE_REJECTED",
            Self::Unmasked => "UNMASKED",
        }
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
        /// What the extension can do beyond the requests every version understands.
        ///
        /// Absent means none, which is what every extension built before the list existed sends.
        /// A token the app does not know is dropped while reading, not refused (see
        /// [`Capability`]); what remains is only ever the app's own vocabulary.
        #[serde(default, deserialize_with = "known_capabilities")]
        capabilities: Vec<Capability>,
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
    /// The answer to a [`Push::Locate`]: "this is the tab in front, and this is what is in it."
    ///
    /// Sent as a fresh request rather than as a reply to the push, so that the origin, the tab and
    /// the document are stamped by the browser exactly as every fill's are (ADR-0036 §3.2). Carries
    /// no item and no value; the app answers [`Response::Noted`] whatever it concludes, so the
    /// extension learns nothing from the answer about which items or sites the agent asked for.
    TargetReport {
        /// The probe this answers, from the [`Push::Locate`].
        probe_id: String,
        /// Where the report came from. Only a report the browser established as frame 0 is ever
        /// eligible.
        page: PageContext,
        /// What the browser said about the tab.
        tab: TabFacts,
        /// What the detectors found in the page.
        found: FoundFields,
    },
    /// "An approved fill is waiting for this tab; give it to me." Sent after a [`Push::Deliver`],
    /// once the content script has re-run its detectors and found the form still writable.
    ///
    /// Answered with the value in the one message that already carries one — [`Response::Filled`],
    /// built by [`Response::filled`] from the granted fields — or [`Response::TotpCode`] for a
    /// one-time-code grant, or an error. No new value-carrying type: the app re-checks the tab,
    /// the document, the origin and the grant from scratch and then answers exactly as a human
    /// fill is answered.
    AgentFill {
        /// The grant being redeemed, from the [`Push::Deliver`].
        grant_id: String,
        /// Where the request came from, stamped by the browser again.
        page: PageContext,
        /// What the browser said about the tab, again.
        tab: TabFacts,
        /// What the detectors found when they were re-run for the delivery.
        found: FoundFields,
    },
    /// "This is what became of the fill." Sent after the content script wrote — or did not write
    /// — what an [`Request::AgentFill`] returned, and once more if the tripwire fires.
    ///
    /// Carries field **names** and a reason, never a value. The app answers [`Response::Noted`].
    AgentFillOutcome {
        /// The grant the fill was made under.
        grant_id: String,
        /// Which fields were written and stuck.
        #[serde(default)]
        written: Vec<AgentFillField>,
        /// Why something was not written, or was taken back. `None` when every granted field was
        /// written.
        #[serde(default)]
        failure: Option<AgentFillFailure>,
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
///
/// # Why there is no `VAULT_BUSY`
///
/// `kagisecure-ipc`'s protocol has one, for a plain (non-audited) write that finds another process
/// holding the vault file's lock past the wait. This protocol has no write that is not audited —
/// every value a fill or a one-time code returns crosses only through `kagisecure_agent`'s
/// `audited_release`, and a lock held past that call's own wait is indistinguishable, on this
/// channel, from any other reason the `Allowed` entry could not be written: both leave nothing
/// released and both are answered [`Self::AuditUnavailable`] (ADR-0040 §5,
/// `docs/browser-extension.md` §4). Giving "busy" a code of its own here would be a variant with
/// nowhere to be constructed from — the property `kagisecure-ipc`'s own `ErrorCode` singles out as
/// the one worth failing a test over — since the pre-flight check that reads the file before a
/// request (`kagisecure_agent::vault::VaultHandle::sync`, the other place a stale vault surfaces)
/// never takes the file lock and so never sees a busy vault at all: see [`Self::VaultConflict`].
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
    /// The audit entry recording this fill could not be written, so nothing was filled
    /// ([ADR-0040](../../../docs/decisions/0040-audit-before-release.md)). A value crosses to the
    /// browser only once the log already says it did; when the log cannot be written — the disk
    /// is full, another kagisecure process holds the vault past the wait — the fill is refused
    /// instead. Retrying later can succeed; the app shows why the log cannot be written.
    AuditUnavailable,
    /// The vault file on disk is no longer one this unlocked session will build on: it was
    /// restored from an older copy, replaced by a different file, or removed while the vault was
    /// unlocked. Read here before a request, rather than at a write — `kagisecure-ipc`'s sibling
    /// code of the same name is the write-time version of the same fact. Nothing is served from a
    /// stale file and nothing on disk changes; only the user, resolving it in the app, can end the
    /// refusal, because retrying alone cannot. Before this variant existed the refusal was
    /// `INTERNAL` with a sentence saying the same thing; this is that sentence given its own code.
    VaultConflict,
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
            Self::AuditUnavailable => "AUDIT_UNAVAILABLE",
            Self::VaultConflict => "VAULT_CONFLICT",
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
        /// The value for a sign-up form's new-password boxes (ADR-0048 §7). Only an agent fill of
        /// a sealed test login carries it, built by [`Response::filled_sign_up`]; the human path
        /// never does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_password: Option<FillValue>,
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
    /// The answer to [`Request::TargetReport`] and [`Request::AgentFillOutcome`]: received.
    ///
    /// Deliberately says nothing more. A report the app found ineligible is answered the same as
    /// one it chose, so the extension — and a page that can observe it — cannot learn from the
    /// answer what the agent asked for.
    Noted,
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
            new_password: None,
        }
    }

    /// Build a [`Response::Filled`] for a sign-up fill (ADR-0048 §7): the new password, and the
    /// username only when it was asked for. Never a `password` member, so a content script that
    /// looks for one on a sign-up delivery finds nothing to put in a login box.
    #[must_use]
    pub fn filled_sign_up(
        item_id: impl Into<String>,
        with_username: bool,
        username: Option<String>,
        new_password: FillValue,
    ) -> Self {
        Self::Filled {
            item_id: item_id.into(),
            username: username.filter(|_| with_username),
            password: None,
            new_password: Some(new_password),
        }
    }

    /// Whether this response carries no field beyond `requested`.
    ///
    /// True for every response that is not a [`Response::Filled`]: no other message has a field a
    /// fill request could have asked for. A `new_password` member is never something the human
    /// path asked for, so its presence answers `false`.
    #[must_use]
    pub fn carries_only(&self, requested: &[FillField]) -> bool {
        match self {
            Self::Filled {
                username,
                password,
                new_password,
                ..
            } => {
                new_password.is_none()
                    && (username.is_none() || requested.contains(&FillField::Username))
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

/// A message the app sends without being asked (ADR-0036 §3.1).
///
/// A doorbell: each member carries opaque ids and **nothing else** — no value, no item id, no
/// title. The one exception is `Locate`'s `origin` (ADR-0036 amendment of 2026-10-03), the origin
/// the agent claimed, so the extension can find a matching tab in the background. What the extension does about one is to send a [`Request`], which the browser
/// stamps; nothing a push says is ever trusted as a fact about a page. Sent only to a session
/// whose `Hello` declared [`Capability::AgentFill`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "push", rename_all = "snake_case")]
pub enum Push {
    /// "Report the tab for `origin`." Answered, if at all, by a [`Request::TargetReport`] quoting
    /// `probe_id`. The extension reports the one tab (any visibility) on `origin`, preferring the
    /// active one when several match, and falls back to the tab in front.
    Locate {
        /// An id the app made up for this probe.
        probe_id: String,
        /// The origin the agent claimed, ASCII-serialized. A hint for choosing the tab only: the
        /// report the extension sends back is stamped by the browser and checked by the app.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
    },
    /// "An approved fill is waiting for the tab you reported for `probe_id`; ask for it."
    /// Answered by a [`Request::AgentFill`] quoting `grant_id`, from that tab and document only.
    Deliver {
        /// The probe whose report was approved, so the service worker can find the tab and
        /// document it stored for it.
        probe_id: String,
        /// The grant to redeem. Opaque, single-use, and never shown to the agent.
        grant_id: String,
    },
}

/// A [`Push`] on the wire.
///
/// `{"ksx":1,"push":{…}}`: the channel marker and the push, and neither of the fields an
/// [`Envelope`] requires. A push has no correlation id because nothing asked for it, and leaving
/// the field out rather than inventing one is what keeps a push from being routed as the reply to
/// some request — a push frame does not parse as an `Envelope<Response>` or an `Envelope<Request>`,
/// and an envelope does not parse as this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushEnvelope {
    /// The same channel marker [`Envelope`] carries.
    #[serde(rename = "ksx")]
    pub channel: u32,
    /// The push.
    pub push: Push,
}

impl PushEnvelope {
    /// Wrap `push`.
    #[must_use]
    pub fn new(push: Push) -> Self {
        Self {
            channel: PROTOCOL_VERSION,
            push,
        }
    }
}

/// Anything the app sends toward the native host: a reply to a request, or a push.
///
/// The type the native host's side of the socket reads, since the two arrive interleaved on one
/// stream once the app can speak first. Serialized as exactly an [`Envelope`] or exactly a
/// [`PushEnvelope`], and read by the field that tells them apart: a frame with an `id` and a
/// `body` is a reply, a frame with a `push` is a push, and a frame with both or neither is
/// malformed rather than guessed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostBound {
    /// A reply, with the id of the request it answers.
    Reply(Envelope<Response>),
    /// A push.
    Push(Push),
}

impl Serialize for HostBound {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct PushRef<'a> {
            #[serde(rename = "ksx")]
            channel: u32,
            push: &'a Push,
        }
        match self {
            Self::Reply(envelope) => envelope.serialize(serializer),
            Self::Push(push) => PushRef {
                channel: PROTOCOL_VERSION,
                push,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for HostBound {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // One pass through the fields of both envelopes, rather than `#[serde(untagged)]`, which
        // would buffer a whole reply — a `Filled` included — into an intermediate copy just to
        // try it against each shape in turn, and would answer a malformed frame with "did not
        // match any variant" instead of saying which field was wrong.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "ksx")]
            channel: u32,
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            body: Option<Response>,
            #[serde(default)]
            push: Option<Push>,
        }
        use serde::de::Error as _;
        let wire = Wire::deserialize(deserializer)?;
        match (wire.id, wire.body, wire.push) {
            (Some(id), Some(body), None) => Ok(Self::Reply(Envelope {
                channel: wire.channel,
                id,
                body,
            })),
            (None, None, Some(push)) => Ok(Self::Push(push)),
            (_, _, Some(_)) => Err(D::Error::custom(
                "a frame is a reply or a push, not both: a push has no `id` or `body`",
            )),
            (None, _, None) => Err(D::Error::missing_field("id")),
            (Some(_), None, None) => Err(D::Error::missing_field("body")),
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
            new_password: None,
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
                capabilities: vec![],
            },
            Request::Hello {
                extension_id: "nlijibjnmanccalmafnfbobkcfjiibmd".to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.2.0".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: vec![Capability::AgentFill],
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
            Request::TargetReport {
                probe_id: "p".to_owned(),
                page: PageContext::top("https://login.example.com"),
                tab: tab(),
                found: FoundFields {
                    username: true,
                    password: true,
                    one_time_code: false,
                    ..FoundFields::default()
                },
            },
            // An identifier-only page and a one-time-code page are both representable: later
            // phases build on them (ADR-0036 §7.3, §7.4).
            Request::TargetReport {
                probe_id: "p".to_owned(),
                page: PageContext::top("https://accounts.example.com"),
                tab: TabFacts {
                    document_id: None,
                    ..tab()
                },
                found: FoundFields {
                    username: true,
                    ..FoundFields::default()
                },
            },
            Request::AgentFill {
                grant_id: "g".to_owned(),
                page: PageContext::top("https://login.example.com"),
                tab: tab(),
                found: FoundFields {
                    one_time_code: true,
                    ..FoundFields::default()
                },
            },
            Request::AgentFillOutcome {
                grant_id: "g".to_owned(),
                written: vec![AgentFillField::Username, AgentFillField::Password],
                failure: None,
            },
            Request::AgentFillOutcome {
                grant_id: "g".to_owned(),
                written: vec![AgentFillField::Password],
                failure: Some(AgentFillFailure::Unmasked),
            },
            Request::AgentFillOutcome {
                grant_id: "g".to_owned(),
                written: vec![],
                failure: Some(AgentFillFailure::FormChanged),
            },
        ];
        for request in requests {
            let json = serde_json::to_string(&request).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(back, request);
        }
    }

    /// Browser-stamped facts for a tab in front, for the tests below.
    fn tab() -> TabFacts {
        TabFacts {
            tab_id: 42,
            document_id: Some("0F8A1C2B3D4E5F60718293A4B5C6D7E8".to_owned()),
            tab_active: true,
            visible: true,
        }
    }

    #[test]
    fn every_response_round_trips() {
        let responses = vec![
            Response::Welcome {
                protocol_version: PROTOCOL_VERSION,
                app_version: "0.1.0".to_owned(),
                unlocked: true,
                host_evidence: vec!["x".to_owned()],
            },
            Response::Status { unlocked: false },
            Response::Matches {
                origin: "https://example.com".to_owned(),
                items: vec![],
            },
            Response::filled("i", &FillField::both(), Some("u".to_owned()), None),
            Response::error(ErrorCode::NoMatch, "nothing here"),
            Response::Noted,
        ];
        for response in responses {
            let json = serde_json::to_string(&response).unwrap();
            let back: Response = serde_json::from_str(&json).unwrap();
            assert_eq!(back, response);
        }
        assert_eq!(
            serde_json::to_string(&Response::Noted).unwrap(),
            r#"{"reply":"noted"}"#
        );
    }

    #[test]
    fn a_hello_without_capabilities_declares_none() {
        // Every extension built before the list existed sends exactly this, and must keep being
        // served — and never be sent a push.
        let json = r#"{"ask":"hello","extension_id":"x","browser":"chrome","extension_version":"0.1.0","protocol_version":1}"#;
        match serde_json::from_str::<Request>(json).unwrap() {
            Request::Hello { capabilities, .. } => assert!(capabilities.is_empty()),
            other => panic!("expected a hello, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_capability_is_ignored_rather_than_refused() {
        let json = r#"{"ask":"hello","extension_id":"x","browser":"chrome","extension_version":"9.0.0","protocol_version":1,"capabilities":["teleport","agent_fill","agent_fill"]}"#;
        match serde_json::from_str::<Request>(json).unwrap() {
            Request::Hello { capabilities, .. } => {
                assert_eq!(capabilities, vec![Capability::AgentFill]);
            }
            other => panic!("expected a hello, got {other:?}"),
        }
        let only_unknown = r#"{"ask":"hello","extension_id":"x","browser":"chrome","extension_version":"9.0.0","protocol_version":1,"capabilities":["teleport"]}"#;
        match serde_json::from_str::<Request>(only_unknown).unwrap() {
            Request::Hello { capabilities, .. } => assert!(capabilities.is_empty()),
            other => panic!("expected a hello, got {other:?}"),
        }
        // A list that is not a list of strings is still a malformed message.
        let malformed = r#"{"ask":"hello","extension_id":"x","browser":"chrome","extension_version":"9.0.0","protocol_version":1,"capabilities":[7]}"#;
        assert!(serde_json::from_str::<Request>(malformed).is_err());
        assert_eq!(Capability::AgentFill.as_str(), "agent_fill");
        assert_eq!(
            serde_json::to_string(&Capability::AgentFill).unwrap(),
            "\"agent_fill\""
        );
    }

    #[test]
    fn missing_tab_facts_default_to_the_ineligible_answer() {
        // A report that does not say its tab is active and visible is not eligible, and a report
        // that says nothing about its fields has none.
        let json = r#"{"ask":"target_report","probe_id":"p","page":{"top_origin":"https://example.com","top_origin_established":true},"tab":{"tab_id":3},"found":{}}"#;
        match serde_json::from_str::<Request>(json).unwrap() {
            Request::TargetReport { tab, found, .. } => {
                assert!(!tab.tab_active);
                assert!(!tab.visible);
                assert_eq!(tab.document_id, None);
                assert_eq!(found, FoundFields::default());
            }
            other => panic!("expected a target report, got {other:?}"),
        }
        // But the tab id is not optional: there is nothing to bind a grant to without it.
        let no_tab = r#"{"ask":"target_report","probe_id":"p","page":{"top_origin":"https://example.com"},"tab":{},"found":{}}"#;
        assert!(serde_json::from_str::<Request>(no_tab).is_err());
    }

    #[test]
    fn found_fields_say_which_fills_the_page_can_take() {
        let login = FoundFields {
            username: true,
            password: true,
            ..FoundFields::default()
        };
        assert!(!login.covers(&[AgentFillField::NewPassword]));
        assert!(!login.covers(&[AgentFillField::Username, AgentFillField::NewPassword]));
        assert!(login.covers(&[AgentFillField::Username, AgentFillField::Password]));
        assert!(login.covers(&[AgentFillField::Password]));
        assert!(!login.covers(&[AgentFillField::OneTimeCode]));
        assert!(!login.is_identifier_only());

        let identifier = FoundFields {
            username: true,
            ..FoundFields::default()
        };
        assert!(identifier.is_identifier_only());
        assert!(!identifier.covers(&[AgentFillField::Username, AgentFillField::Password]));
        assert!(identifier.covers(&[AgentFillField::Username]));

        let code = FoundFields {
            one_time_code: true,
            ..FoundFields::default()
        };
        assert!(code.covers(&[AgentFillField::OneTimeCode]));
        assert!(!code.is_identifier_only());
        assert!(!FoundFields::default().is_identifier_only());

        let sign_up = FoundFields {
            sign_up: true,
            sign_up_username: true,
            ..FoundFields::default()
        };
        assert!(sign_up.covers(&[AgentFillField::Username, AgentFillField::NewPassword]));
        assert!(sign_up.covers(&[AgentFillField::NewPassword]));
        assert!(!sign_up.covers(&[AgentFillField::Password]));
        assert!(
            !sign_up.covers(&[AgentFillField::Username]),
            "a login username is not there"
        );
        assert!(!sign_up.is_identifier_only());
        let bare = FoundFields {
            sign_up: true,
            ..FoundFields::default()
        };
        assert!(!bare.covers(&[AgentFillField::Username, AgentFillField::NewPassword]));
    }

    #[test]
    fn a_sign_up_fill_carries_the_new_password_and_never_a_password() {
        // The serde canary for `filled_sign_up` (ADR-0048 Phase 1b).
        const MARKER: &str = "MARKER-5a0e2d9b7c4f4e1a8b3d6c9f0e2a4b7d";
        let response =
            Response::filled_sign_up("i", true, Some("alice".to_owned()), FillValue::new(MARKER));
        let json = serde_json::to_string(&response).unwrap();
        assert!(
            json.contains(&format!("\"new_password\":\"{MARKER}\"")),
            "{json}"
        );
        assert!(!json.contains("\"password\""), "no password member: {json}");
        assert!(json.contains("alice"), "{json}");
        let without =
            Response::filled_sign_up("i", false, Some("alice".to_owned()), FillValue::new(MARKER));
        assert!(!serde_json::to_string(&without).unwrap().contains("alice"));
        // And a human-path Filled never names the member at all.
        let human = Response::filled(
            "i",
            &FillField::both(),
            Some("a".to_owned()),
            Some(FillValue::new("pw")),
        );
        assert!(
            !serde_json::to_string(&human)
                .unwrap()
                .contains("new_password")
        );
    }

    #[test]
    fn agent_fill_fields_and_failures_have_stable_tokens() {
        for field in [
            AgentFillField::Username,
            AgentFillField::Password,
            AgentFillField::OneTimeCode,
        ] {
            let json = serde_json::to_string(&field).unwrap();
            assert_eq!(json, format!("\"{}\"", field.as_str()));
            assert_eq!(
                serde_json::from_str::<AgentFillField>(&json).unwrap(),
                field
            );
        }
        assert_eq!(
            AgentFillField::Password.as_fill_field(),
            Some(FillField::Password)
        );
        assert_eq!(AgentFillField::OneTimeCode.as_fill_field(), None);
        assert_eq!(AgentFillField::NewPassword.as_fill_field(), None);

        for failure in [
            AgentFillFailure::FormChanged,
            AgentFillFailure::NotWritable,
            AgentFillFailure::NotVisible,
            AgentFillFailure::WriteRejected,
            AgentFillFailure::Unmasked,
        ] {
            let json = serde_json::to_string(&failure).unwrap();
            assert_eq!(json, format!("\"{}\"", failure.as_str()));
            assert_eq!(
                serde_json::from_str::<AgentFillFailure>(&json).unwrap(),
                failure
            );
        }
    }

    /// Every push there is, one of each member. The `match` has no wildcard, so a new member does
    /// not compile until it is listed here — and so until the tests below have looked at it.
    fn every_push(probe_id: &str, grant_id: &str) -> Vec<Push> {
        let pushes = vec![
            Push::Locate {
                probe_id: probe_id.to_owned(),
                origin: None,
            },
            Push::Deliver {
                probe_id: probe_id.to_owned(),
                grant_id: grant_id.to_owned(),
            },
        ];
        for push in &pushes {
            match push {
                Push::Locate { .. } | Push::Deliver { .. } => {}
            }
        }
        pushes
    }

    #[test]
    fn no_push_carries_a_fill_value() {
        // The push counterpart of `only_three_response_fields_are_fill_values`. A push has no field
        // a value could occupy: serialize every one and check that its only keys are the tag and
        // the two ids, and that every string in it is one of the ids it was built with.
        const PROBE: &str = "probe-5d1c";
        const GRANT: &str = "grant-9e7b";
        for push in every_push(PROBE, GRANT) {
            let json = serde_json::to_value(HostBound::Push(push.clone())).unwrap();
            let outer = json.as_object().expect("an object");
            assert_eq!(
                outer.keys().map(String::as_str).collect::<Vec<_>>(),
                vec!["ksx", "push"],
                "{json}"
            );
            let inner = outer["push"].as_object().expect("an object");
            for (key, value) in inner {
                assert!(
                    ["push", "probe_id", "grant_id"].contains(&key.as_str()),
                    "a push grew a field: {key} in {json}"
                );
                let text = value.as_str().expect("every push field is a string");
                if key != "push" {
                    assert!(text == PROBE || text == GRANT, "{json}");
                }
            }
            let back: HostBound = serde_json::from_value(json).unwrap();
            assert_eq!(back, HostBound::Push(push));
        }
    }

    #[test]
    fn a_push_frame_does_not_parse_as_a_reply_or_a_request() {
        for push in every_push("p", "g") {
            let json = serde_json::to_string(&PushEnvelope::new(push.clone())).unwrap();
            assert!(json.starts_with(r#"{"ksx":1,"push":{"push":"#), "{json}");
            assert!(
                serde_json::from_str::<Envelope<Response>>(&json).is_err(),
                "a push must not be routable as a reply: {json}"
            );
            assert!(
                serde_json::from_str::<Envelope<Request>>(&json).is_err(),
                "a push must not be readable as a request: {json}"
            );
            // The two spellings of a push on the wire are one spelling.
            assert_eq!(
                json,
                serde_json::to_string(&HostBound::Push(push.clone())).unwrap()
            );
            assert_eq!(
                serde_json::from_str::<HostBound>(&json).unwrap(),
                HostBound::Push(push)
            );
        }

        // And the other way round: neither a reply nor a request reads as a push.
        let reply = serde_json::to_string(&Envelope::new("r1", Response::Noted)).unwrap();
        assert!(serde_json::from_str::<PushEnvelope>(&reply).is_err());
        let request = serde_json::to_string(&Envelope::new("r1", Request::Status)).unwrap();
        assert!(serde_json::from_str::<PushEnvelope>(&request).is_err());
        assert!(serde_json::from_str::<HostBound>(&request).is_err());

        // A reply reads as a reply, id and all.
        let filled = Envelope::new(
            "r2",
            Response::filled("i", &[FillField::Username], Some("u".to_owned()), None),
        );
        let json = serde_json::to_string(&filled).unwrap();
        assert_eq!(
            serde_json::to_string(&HostBound::Reply(filled.clone())).unwrap(),
            json
        );
        assert_eq!(
            serde_json::from_str::<HostBound>(&json).unwrap(),
            HostBound::Reply(filled)
        );
    }

    #[test]
    fn a_frame_that_is_both_a_reply_and_a_push_is_refused_rather_than_guessed() {
        let both = r#"{"ksx":1,"id":"r1","body":{"reply":"noted"},"push":{"push":"locate","probe_id":"p"}}"#;
        assert!(serde_json::from_str::<HostBound>(both).is_err());
        let push_with_id = r#"{"ksx":1,"id":"r1","push":{"push":"locate","probe_id":"p"}}"#;
        assert!(serde_json::from_str::<HostBound>(push_with_id).is_err());
        assert!(serde_json::from_str::<PushEnvelope>(push_with_id).is_err());
        let neither = r#"{"ksx":1}"#;
        assert!(serde_json::from_str::<HostBound>(neither).is_err());
        let id_only = r#"{"ksx":1,"id":"r1"}"#;
        assert!(serde_json::from_str::<HostBound>(id_only).is_err());
        let no_marker = r#"{"push":{"push":"locate","probe_id":"p"}}"#;
        assert!(serde_json::from_str::<HostBound>(no_marker).is_err());
        assert!(serde_json::from_str::<PushEnvelope>(no_marker).is_err());
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
            new_password: None,
        };
        assert!(!overshot.carries_only(&[FillField::Username]));
        assert!(!overshot.carries_only(&[FillField::Password]));
        assert!(overshot.carries_only(&FillField::both()));
        let sign_up =
            Response::filled_sign_up("i", true, Some("alice".to_owned()), FillValue::new("pw"));
        assert!(
            !sign_up.carries_only(&FillField::both()),
            "the human path never asks for a new password"
        );
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
            top_origin_established: true,
        };
        assert_eq!(framed.effective_origin(), "https://login.other.test");
        assert!(framed.is_cross_origin_frame());

        // A sub-frame claiming the top origin as its own used to read as a top-frame load, which
        // is the disclosure D-7 is about. The browser did not report frame 0, so it is a frame
        // with an unknown embedder.
        let same = PageContext {
            top_origin: "https://example.com".to_owned(),
            frame_origin: Some("https://example.com".to_owned()),
            top_origin_established: false,
        };
        assert!(same.is_cross_origin_frame());
        assert!(same.top_origin_unknown());

        // And a frame the browser *did* confirm is frame 0 is not disclosed as a frame.
        let top_with_frame = PageContext {
            top_origin: "https://example.com".to_owned(),
            frame_origin: Some("https://example.com".to_owned()),
            top_origin_established: true,
        };
        assert!(!top_with_frame.is_cross_origin_frame());
        assert!(!top_with_frame.top_origin_unknown());
    }

    #[test]
    fn error_codes_have_stable_tokens_on_the_wire() {
        let json =
            serde_json::to_string(&Response::error(ErrorCode::OriginMismatch, "no")).unwrap();
        assert!(json.contains("ORIGIN_MISMATCH"), "{json}");
        assert_eq!(ErrorCode::VaultLocked.as_str(), "VAULT_LOCKED");
    }

    #[test]
    fn every_error_code_serializes_as_its_own_token() {
        // `as_str` and serde's rename are two spellings of one fact; a new code that got one of
        // them wrong would reach the content script as a string it never branches on.
        for code in [
            ErrorCode::VaultLocked,
            ErrorCode::UserDenied,
            ErrorCode::ApprovalTimeout,
            ErrorCode::OriginMismatch,
            ErrorCode::NoMatch,
            ErrorCode::UnknownExtension,
            ErrorCode::UntrustedHost,
            ErrorCode::Protocol,
            ErrorCode::Internal,
            ErrorCode::AuditUnavailable,
            ErrorCode::VaultConflict,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(serde_json::from_str::<ErrorCode>(&json).unwrap(), code);
        }
        assert_eq!(ErrorCode::AuditUnavailable.as_str(), "AUDIT_UNAVAILABLE");
        assert_eq!(ErrorCode::VaultConflict.as_str(), "VAULT_CONFLICT");
    }

    #[test]
    fn only_three_response_fields_are_fill_values() {
        // A structural restatement of ADR-0018's table, asserted by construction: build every
        // response shape, serialize it, and check the marker only survives in the two that are
        // allowed to carry one.
        const MARKER: &str = "MARKER-3f9a2c7e5b1d4086a2c7e5b1d4086a2c";
        let carriers = [
            Response::Filled {
                item_id: "i".to_owned(),
                username: Some("u".to_owned()),
                password: Some(FillValue::new(MARKER)),
                new_password: None,
            },
            Response::filled_sign_up("i", false, None, FillValue::new(MARKER)),
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
                new_password: None,
            },
            Response::Noted,
        ];
        for response in &non_carriers {
            let json = serde_json::to_string(response).unwrap();
            assert!(!json.contains(MARKER), "{json}");
        }
    }
}
