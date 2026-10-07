//! The agent surface: six synchronous calls that let Swift host an IPC listener.
//!
//! # The shape, and why it is this shape
//!
//! Rust must never call up into Swift ([ADR-0001](../../../docs/decisions/0001-rust-core-native-ui.md),
//! architecture.md §4.1), and an approval is precisely the call that would want to. So the flow is
//! inverted: `kagisecure-agent` queues the question, and the app *pulls*.
//!
//! ```text
//!   Task.detached {                        // a background thread, because these calls block
//!       while running {
//!           if let req = agentNextRequest(timeoutMs: 500) {   // blocks up to 500 ms
//!               await MainActor.run { show the sheet }
//!               agentResolve(requestId: req.id, decision: …, verification: …)
//!           }
//!       }
//!   }
//! ```
//!
//! Every function here is `#[uniffi::export]`, synchronous, app → Rust, and returns a value.
//! There is no exported async, no foreign trait, and no callback interface.
//!
//! # One agent per process
//!
//! The agent is a process global rather than an object the app holds, because there is exactly one
//! socket and the app must not be able to bind it twice. `agent_start` on a socket another
//! kagisecure already holds — the CLI daemon, typically — fails with a message the UI can show
//! verbatim (architecture.md §4.2).
//!
//! # What crosses this boundary
//!
//! Metadata only. [`ApprovalRequestView`] is [`kagisecure_agent::ApprovalRequest`] with its
//! integers widened for UniFFI; neither has a field a secret value could occupy, which is
//! [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md)'s answer to "is this a fifth
//! crossing?" — it is not.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kagisecure_agent::approval::{
    AgentFillFacts, ApprovalKind, ApprovalRequest, ClientVerification, Decision,
};
use kagisecure_agent::browser_setup;
use kagisecure_agent::{Agent, AgentConfig, Endpoint, ExtensionAgent, ExtensionConfig};
use kagisecure_core::proto::LeaseId;
use kagisecure_extension_ipc::origin::AgentOriginRendering;
use kagisecure_ipc::protocol::AgentFillField;

use crate::session::VaultSession;
use crate::{FfiError, FfiResult};

/// The one agent this process may run.
static AGENT: Mutex<Option<Agent>> = Mutex::new(None);

/// The one browser-extension listener this process may run.
static EXTENSION: Mutex<Option<ExtensionAgent>> = Mutex::new(None);

/// The one approval queue, shared by both listeners.
///
/// Process-global rather than owned by either listener, because the app polls it with
/// [`agent_next_request`] and there must be exactly one thing to poll. A second queue would mean
/// a fill approval that never reached a sheet — the failure would be silence, which is the worst
/// possible failure for an approval mechanism, so the queue is hoisted above both owners rather
/// than handed from one to the other.
static QUEUE: std::sync::LazyLock<Arc<kagisecure_agent::ApprovalQueue>> =
    std::sync::LazyLock::new(|| Arc::new(kagisecure_agent::ApprovalQueue::new()));

/// The one agent-fill broker (ADR-0036), shared by both listeners.
///
/// Process-global for the reason [`QUEUE`] is, and one more: the app stops and restarts both
/// listeners on every lock and unlock, and the broker is where the feature switch lives — and
/// the blocks, sticky denials and budgets that must survive a lock (ADR-0036 §9). So neither listener owns it; each is handed
/// the same `Arc` when it starts.
static AGENT_FILL: std::sync::LazyLock<Arc<kagisecure_agent::AgentFillBroker>> =
    std::sync::LazyLock::new(|| Arc::new(kagisecure_agent::AgentFillBroker::new()));

/// The one test-login broker (ADR-0048), handed to every MCP agent the app starts.
///
/// Process-global for the reason [`AGENT_FILL`] is: the app restarts the listener on every lock
/// and unlock, and an agent's create limit must survive both (§11), as must the notices the app
/// has not drained yet.
static TEST_LOGINS: std::sync::LazyLock<Arc<kagisecure_agent::TestLoginBroker>> =
    std::sync::LazyLock::new(|| Arc::new(kagisecure_agent::TestLoginBroker::new()));

fn agent() -> std::sync::MutexGuard<'static, Option<Agent>> {
    AGENT.lock().unwrap_or_else(|e| e.into_inner())
}

fn extension() -> std::sync::MutexGuard<'static, Option<ExtensionAgent>> {
    EXTENSION.lock().unwrap_or_else(|e| e.into_inner())
}

/// What kind of request the approval sheet is about (ui-spec.md §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalAction {
    /// `create_environment`.
    CreateEnvironment,
    /// `add_variables`.
    AddVariables,
    /// `write_env_file`.
    WriteEnvFile,
    /// `run_with_env`.
    RunWithEnv,
    /// A browser extension wants to fill a credential into a page (M6).
    FillCredential,
    /// An agent asks for a login to be typed into a browser tab (ADR-0036). Always the full
    /// sheet — never presence-only, never "for this session" — and it mints nothing. The facts
    /// the sheet shows are in [`ApprovalRequestView::agent_fill`].
    AgentFill,
    /// An agent asks for a test login at a site outside the allowed origins (ADR-0048 §3).
    /// kagisecure generates the password; nothing is released. Always the full sheet with Touch
    /// ID — never presence-only, never "for this session" — and it mints nothing. The facts the
    /// sheet shows are in [`ApprovalRequestView::test_login`].
    CreateTestLogin,
}

impl From<ApprovalKind> for ApprovalAction {
    fn from(kind: ApprovalKind) -> Self {
        match kind {
            ApprovalKind::CreateEnvironment => Self::CreateEnvironment,
            ApprovalKind::AddVariables => Self::AddVariables,
            ApprovalKind::WriteEnvFile => Self::WriteEnvFile,
            ApprovalKind::RunWithEnv => Self::RunWithEnv,
            ApprovalKind::FillCredential => Self::FillCredential,
            ApprovalKind::AgentFill => Self::AgentFill,
            ApprovalKind::CreateTestLogin => Self::CreateTestLogin,
        }
    }
}

/// One question waiting for a human.
///
/// Read the field list as the definition of what the sheet may state. There is no value here, no
/// length, and no way to add one without editing ADR-0008.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalRequestView {
    /// Quote this back to [`agent_resolve`].
    pub id: String,
    /// What is being asked for.
    pub action: ApprovalAction,
    /// Whether granting mints a lease, so the sheet knows to show the TTL control.
    pub mints_lease: bool,
    /// The caller's **self-reported** name. Render it as a quotation, never as a label.
    pub client_name: String,
    /// The peer's process id.
    pub client_pid: Option<u32>,
    /// Whether that pid came from the kernel rather than from the caller's own word.
    pub client_pid_from_kernel: bool,
    /// The peer's kernel audit token (macOS `LOCAL_PEERTOKEN`, 64 hex digits). The macOS app runs
    /// its code-signature check on this when present, because a pid can be reused.
    #[uniffi(default = None)]
    pub client_audit_token: Option<String>,
    /// The executable behind that pid — what the app checks the code signature of.
    pub client_executable: Option<String>,
    /// The directory the sidecar was started in. Self-reported.
    pub client_cwd: Option<String>,
    /// The environment involved.
    pub environment_id: Option<String>,
    /// Its display name.
    pub environment_name: Option<String>,
    /// The canonical target directory, symlinks resolved.
    pub directory: Option<String>,
    /// The exact file that would be written.
    pub target_path: Option<String>,
    /// Variable **names**.
    pub variables: Vec<String>,
    /// The resolved argv, for `run_with_env`.
    pub command: Vec<String>,
    /// A `run_with_env` whose values go to the command's standard input, once, and not into its
    /// environment (ADR-0047). The sheet says so, and offers only **Allow once** and **Deny**:
    /// Rust grants any allow of it as a single use.
    ///
    /// `#[uniffi(default = false)]` so the Swift call sites that build a request by hand keep
    /// compiling.
    #[uniffi(default = false)]
    pub stdin_delivery: bool,
    /// `Some(false)` is the red "not gitignored" callout; `None` means not in a work tree.
    pub gitignored: Option<bool>,
    /// Whether the caller asked for an existing file to be replaced (`overwrite: true`).
    pub overwrite_requested: bool,
    /// Whether a file is already at [`Self::target_path`]. `None` when this is not a file write.
    pub target_exists: Option<bool>,
    /// When a file is already there, whether kagisecure wrote it in this unlock session.
    /// `Some(false)` is the destructive case: the bytes are the user's own and nothing can bring
    /// them back (threat-model M-16).
    pub target_written_by_us: Option<bool>,
    /// The TTL the agent asked for. The user may shorten it, never lengthen it.
    pub requested_ttl_seconds: u64,
    /// The use count the lease would carry.
    pub requested_uses: u32,
    /// The ceiling the TTL control must respect.
    pub max_ttl_seconds: u64,
    /// Unix seconds the request arrived.
    pub created_at: u64,
    /// Unix seconds the request self-denies with `APPROVAL_TIMEOUT`, for the countdown bar.
    pub expires_at: u64,

    // --- M6: the browser-extension fill. Empty for every other action. ---------------------
    /// The origin the fill would happen at, in ASCII serialization. This is the origin that was
    /// *matched*, so for a cross-origin iframe it is the frame's, not the page's.
    pub origin: Option<String>,
    /// The top-level page's origin when this is not a plain top-frame load — the signal the sheet
    /// turns into "this form is inside a frame on another site".
    ///
    /// May be the literal `"null"`, the serialization of an opaque origin. Never render it
    /// verbatim: when [`Self::top_origin_unknown`] is true the sheet says "an unknown site".
    pub top_origin: Option<String>,
    /// Whether the embedder of the frame could not be established — the browser did not report
    /// that this request came from frame 0 (D-7).
    pub top_origin_unknown: bool,
    /// The item that would be filled.
    pub item_id: Option<String>,
    /// Its title, so the sheet does not show a bare uuid.
    pub item_title: Option<String>,
    /// Which fields would be written: `username`, `password`, `one-time password`. **Names.**
    pub fill_fields: Vec<String>,
    /// The browser the app established from the native host's process ancestry.
    pub browser: Option<String>,
    /// That browser's pid — what `PeerCodeSignature` runs its check on for a fill.
    pub browser_pid: Option<u32>,
    /// That browser's executable path.
    pub browser_executable: Option<String>,
    /// Whether the process on the socket is an app extension we ship — true only for Safari.
    ///
    /// The app uses it to pick which code-signature requirement to check the peer against: our
    /// own team plus the app extension's bundle identifier, rather than a browser vendor's
    /// hardcoded team (ADR-0024 §5).
    pub browser_is_app_extension: bool,
    /// The extension's self-reported id. Only ever the pinned one; anything else never got here.
    pub extension_id: Option<String>,
    /// Ask only for a fresh LocalAuthentication check, **not** the sheet.
    ///
    /// Set for a fill whose exact origin, item and fields the human already reviewed at a full
    /// sheet in this unlock session and allowed for the session. The app runs the check with a
    /// reason naming the item and the site and answers **Allow once** on success; a cancelled or
    /// unavailable check is a denial. The check is the one thing that tells a person from an
    /// automation agent clicking in the page
    /// ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
    ///
    /// The one exception is the macOS app's presence grace window (ADR-0037's amendment of
    /// 2026-09-27): if a check for a fill of this item on this exact origin passed less than ten
    /// minutes ago in this unlock session, the app answers **Allow once** without asking again.
    /// Rust cannot see either way; the rule and its clock live in the app.
    ///
    /// Always `false` for [`ApprovalAction::AgentFill`]; the app treats an agent fill as a full
    /// sheet even if it ever arrived `true`.
    pub presence_only: bool,

    // --- ADR-0036: an agent-requested browser fill. `None` for every other action. ---------
    /// What the agent-fill sheet shows beyond the fields above. `Some` exactly when
    /// [`Self::action`] is [`ApprovalAction::AgentFill`].
    ///
    /// `#[uniffi(default = None)]` so the Swift call sites that build a request by hand — the
    /// unit tests do, many times — keep compiling and read `nil`.
    #[uniffi(default = None)]
    pub agent_fill: Option<AgentFillFactsView>,

    // --- ADR-0048: agent test logins. --------------------------------------------------------
    /// What the test-login sheet shows beyond the fields above. `Some` exactly when
    /// [`Self::action`] is [`ApprovalAction::CreateTestLogin`].
    ///
    /// `#[uniffi(default = None)]` so hand-built views in the Swift tests keep compiling.
    #[uniffi(default = None)]
    pub test_login: Option<TestLoginFactsView>,
    /// A `run_with_env` or `write_env_file` whose every selected variable is bound to a sealed
    /// test login (ADR-0048 §9). The app may answer it inside its presence grace window with no
    /// sheet and no prompt, as it answers agent fills; outside the window, the ordinary sheet and
    /// Touch ID. It never becomes a standing permission: the grace window is the app's.
    ///
    /// `#[uniffi(default = false)]` so hand-built views in the Swift tests keep compiling.
    #[uniffi(default = false)]
    pub rides_grace: bool,

    // --- ADR-0035 §14: values from a shared vault. Empty for the personal vault. ------------
    /// Where the values come from when that is a shared vault — `Shared vault “Ops” — 4
    /// members` — to be shown as a fact on the sheet. `None` for the personal vault.
    #[uniffi(default = None)]
    pub shared_source: Option<String>,
    /// One line per value about to be released that changed since this Mac last approved
    /// releasing it, or was never released from this Mac, naming who changed it and when.
    /// Names, labels and times only. Empty for the personal vault and when nothing changed.
    #[uniffi(default = [])]
    pub changed_since_approval: Vec<String>,
}

/// One website on a test-login sheet (ADR-0048 §3): the registrable domain large above the full
/// URL, and ADR-0046 §5's flags.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TestLoginWebsiteView {
    /// The website's origin, split for rendering.
    pub origin: AgentOriginView,
    /// The title of a login of the person's own saved for the same registrable domain — the
    /// near-host warning — when there is one.
    pub near_item_title: Option<String>,
    /// Whether the website is not `https`.
    pub not_https: bool,
}

/// [`kagisecure_agent::TestLoginFacts`]: who asks for which test login, where. Metadata only;
/// the password is generated after the approval and has nowhere to go here.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TestLoginFactsView {
    /// The agent as the audit log names it.
    pub agent: String,
    /// The agent's self-reported name. Render it as a quotation.
    pub agent_name: String,
    /// The title kagisecure would give the item.
    pub title: String,
    /// The username the agent chose.
    pub username: String,
    /// The websites, each split for rendering.
    pub websites: Vec<TestLoginWebsiteView>,
    /// The purpose the agent gave: agent-written data, never instructions.
    pub purpose: String,
    /// Every tag the item would carry.
    pub tags: Vec<String>,
    /// How the password would be generated, e.g. `32 characters, with symbols`.
    pub generator: String,
    /// Why, as the agent put it.
    pub reason: Option<String>,
}

impl From<kagisecure_agent::TestLoginFacts> for TestLoginFactsView {
    fn from(f: kagisecure_agent::TestLoginFacts) -> Self {
        Self {
            agent: f.agent,
            agent_name: f.agent_name,
            title: f.title,
            username: f.username,
            websites: f
                .websites
                .into_iter()
                .map(|w| TestLoginWebsiteView {
                    origin: w.origin.into(),
                    near_item_title: w.near_item_title,
                    not_https: w.not_https,
                })
                .collect(),
            purpose: f.purpose,
            tags: f.tags,
            generator: f.generator,
            reason: f.reason,
        }
    }
}

/// A test-login notice for the app (ADR-0048 §10): a system notification and the menu-bar entry
/// "N test logins created by agents". Asks nothing of the person.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TestLoginNoticeView {
    /// An agent created a test login.
    Created {
        /// The agent, as the audit log names it.
        agent: String,
        /// The title kagisecure composed.
        title: String,
        /// The username.
        username: String,
        /// The websites it is saved for.
        websites: Vec<String>,
    },
}

impl From<kagisecure_agent::TestLoginNotice> for TestLoginNoticeView {
    fn from(notice: kagisecure_agent::TestLoginNotice) -> Self {
        match notice {
            kagisecure_agent::TestLoginNotice::Created {
                agent,
                title,
                username,
                websites,
            } => Self::Created {
                agent,
                title,
                username,
                websites,
            },
        }
    }
}

/// A field an agent asked to have filled. A **name**; there is no variant that holds a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AgentFillFieldView {
    /// The login's username.
    Username,
    /// The login's password.
    Password,
    /// A one-time code from the item's one-time-password field.
    OneTimeCode,
    /// A sign-up form's new-password boxes, for a sealed agent test login (ADR-0048 §7).
    NewPassword,
}

impl From<AgentFillField> for AgentFillFieldView {
    fn from(field: AgentFillField) -> Self {
        match field {
            AgentFillField::Username => Self::Username,
            AgentFillField::Password => Self::Password,
            AgentFillField::OneTimeCode => Self::OneTimeCode,
            AgentFillField::NewPassword => Self::NewPassword,
        }
    }
}

/// A page origin split for the agent-fill sheet, so a look-alike is obvious (ADR-0036 §5):
/// [`kagisecure_extension_ipc::origin::AgentOriginRendering`], plus the pieces put back together.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AgentOriginView {
    /// `scheme://` + `dimmed_prefix` + `emphasized` + `:port` — exactly the ASCII serialization
    /// the origin rule compared and the audit log records.
    pub ascii: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The labels before the registrable domain, with their trailing dot, to be dimmed. May be
    /// empty.
    pub dimmed_prefix: String,
    /// The registrable domain (or the whole host when there is none), to be emphasized. ASCII.
    pub emphasized: String,
    /// The port, when it is not the scheme's default. Always shown when present.
    pub port: Option<u16>,
    /// The host with its `xn--` labels decoded, when there are any: shown *beside* the ASCII
    /// form, labelled "shown by the browser as", never instead of it.
    pub unicode_host: Option<String>,
    /// Whether the decoded host mixes scripts, or has a punycode label that does not decode.
    pub mixed_script: bool,
    /// Whether the scheme is `http`: shown in red as "not encrypted".
    pub not_encrypted: bool,
}

impl From<AgentOriginRendering> for AgentOriginView {
    fn from(r: AgentOriginRendering) -> Self {
        Self {
            ascii: r.ascii(),
            scheme: r.scheme,
            dimmed_prefix: r.dimmed_prefix,
            emphasized: r.emphasized,
            port: r.port,
            unicode_host: r.unicode_host,
            mixed_script: r.mixed_script,
            not_encrypted: r.not_encrypted,
        }
    }
}

/// [`kagisecure_agent::AgentFillFacts`]: the agent, the item, the page and the browser, as the
/// agent-fill sheet states them. Metadata only — names, paths, pids, flags and an origin.
///
/// Two identity stories: the **agent** (`agent_name` is self-reported and must be quoted; the
/// pids and executables are the kernel's) and the **browser** (the same facts the fill sheet
/// already shows for a fill the human started).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AgentFillFactsView {
    /// The agent's self-reported name. Render it as a quotation; it is unverified.
    pub agent_name: String,
    /// The sidecar's pid, from the kernel.
    pub sidecar_pid: u32,
    /// The sidecar's executable.
    pub sidecar_executable: Option<String>,
    /// The sidecar's kernel audit token (hex), for the signature check.
    #[uniffi(default = None)]
    pub sidecar_audit_token: Option<String>,
    /// The sidecar's parent pid, from the kernel — what the "started by" signature check runs on.
    pub parent_pid: Option<u32>,
    /// The sidecar's parent executable, from the kernel: what "this agent" means for blocking.
    pub parent_executable: Option<String>,
    /// The item that would be filled.
    pub item_id: String,
    /// Its title.
    pub item_title: String,
    /// Which fields would be written. Names. `[oneTimeCode]` alone is a one-time-code request,
    /// which always has a sheet of its own (ADR-0036 §7.4).
    pub fields: Vec<AgentFillFieldView>,
    /// Page one of an identifier-first sign-in (ADR-0036 §7.3): the username is written now and
    /// the password on the next page, in the same tab, without another sheet. The sheet says
    /// *"username now, password on the next page"*.
    #[uniffi(default = false)]
    pub two_step: bool,
    /// The page's origin, split for rendering.
    pub page_origin: AgentOriginView,
    /// The saved website that covered the page, in ASCII serialization.
    pub saved_website: String,
    /// Whether the page's host differs from the saved website's: "this page is a subdomain of it".
    pub page_host_differs: bool,
    /// The browser the app established from the native host's ancestry.
    pub browser: Option<String>,
    /// That browser's pid.
    pub browser_pid: Option<u32>,
    /// That browser's executable path.
    pub browser_executable: Option<String>,
    /// Whether the extension-side peer is an app extension we ship (Safari; never in practice).
    pub browser_is_app_extension: bool,
    /// The native messaging host's pid — "our helper".
    pub host_pid: Option<u32>,
    /// The native messaging host's kernel audit token (hex), for the signature check.
    #[uniffi(default = None)]
    pub host_audit_token: Option<String>,
    /// The native messaging host's executable.
    pub host_executable: Option<String>,
    /// The extension's self-reported id.
    pub extension_id: Option<String>,
}

impl From<AgentFillFacts> for AgentFillFactsView {
    fn from(f: AgentFillFacts) -> Self {
        Self {
            agent_name: f.agent_name,
            sidecar_pid: f.sidecar_pid,
            sidecar_executable: f.sidecar_executable,
            sidecar_audit_token: f.sidecar_audit_token,
            parent_pid: f.parent_pid,
            parent_executable: f.parent_executable,
            item_id: f.item_id,
            item_title: f.item_title,
            fields: f.fields.into_iter().map(Into::into).collect(),
            two_step: f.two_step,
            page_origin: f.page_origin.into(),
            saved_website: f.saved_website,
            page_host_differs: f.page_host_differs,
            browser: f.browser,
            browser_pid: f.browser_pid,
            browser_executable: f.browser_executable,
            browser_is_app_extension: f.browser_is_app_extension,
            host_pid: f.host_pid,
            host_audit_token: f.host_audit_token,
            host_executable: f.host_executable,
            extension_id: f.extension_id,
        }
    }
}

impl From<ApprovalRequest> for ApprovalRequestView {
    fn from(r: ApprovalRequest) -> Self {
        Self {
            id: r.id,
            action: r.kind.into(),
            mints_lease: r.kind.mints_lease(),
            client_name: r.client_name,
            client_pid: r.client_pid,
            client_pid_from_kernel: r.client_pid_from_kernel,
            client_audit_token: r.client_audit_token,
            client_executable: r.client_executable,
            client_cwd: r.client_cwd,
            environment_id: r.environment_id,
            environment_name: r.environment_name,
            directory: r.directory,
            target_path: r.target_path,
            variables: r.variables,
            command: r.command,
            stdin_delivery: r.stdin_delivery,
            gitignored: r.gitignored,
            overwrite_requested: r.overwrite_requested,
            target_exists: r.target_exists,
            target_written_by_us: r.target_written_by_us,
            requested_ttl_seconds: r.requested_ttl_seconds,
            requested_uses: r.requested_uses,
            max_ttl_seconds: r.max_ttl_seconds,
            created_at: r.created_at,
            expires_at: r.expires_at,
            origin: r.origin,
            top_origin: r.top_origin,
            top_origin_unknown: r.top_origin_unknown,
            item_id: r.item_id,
            item_title: r.item_title,
            fill_fields: r.fill_fields,
            browser: r.browser,
            browser_pid: r.browser_pid,
            browser_executable: r.browser_executable,
            browser_is_app_extension: r.browser_is_app_extension,
            extension_id: r.extension_id,
            presence_only: r.presence_only,
            agent_fill: r.agent_fill.map(Into::into),
            test_login: r.agent_test_login.map(Into::into),
            rides_grace: r.rides_grace,
            shared_source: r.shared_source,
            changed_since_approval: r.changed_since_approval,
        }
    }
}

/// The buttons on the sheet (ui-spec.md §10.3). There is no "always allow".
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalDecision {
    /// Mint a single-use lease; the next identical request re-prompts.
    AllowOnce,
    /// Mint a lease for the TTL and uses the user agreed to, bounded by what was requested.
    AllowSession {
        /// Seconds.
        ttl_seconds: u64,
        /// Uses.
        uses: u32,
    },
    /// Refuse. Returns `USER_DENIED`.
    Deny,
    /// Refuse, and refuse every agent fill from the same agent for the next thirty minutes
    /// without a sheet (ADR-0036 §9.3). Returns `USER_DENIED`. Offered only on the agent-fill
    /// sheet; for any other request it is exactly [`Self::Deny`]. A denial, so — like
    /// [`Self::Deny`] — it needs no biometric.
    ///
    /// UniFFI only: the C ABI's `KgsApprovalDecisionTag` has no counterpart, because Windows never
    /// offers agent fills.
    DenyAndBlock,
}

impl From<ApprovalDecision> for Decision {
    fn from(d: ApprovalDecision) -> Self {
        match d {
            ApprovalDecision::AllowOnce => Self::AllowOnce,
            ApprovalDecision::AllowSession { ttl_seconds, uses } => {
                Self::AllowSession { ttl_seconds, uses }
            }
            ApprovalDecision::Deny => Self::Deny,
            ApprovalDecision::DenyAndBlock => Self::DenyAndBlock,
        }
    }
}

/// Why an agent is blocked from asking for fills (ADR-0036 §9.3, §9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AgentFillBlockReasonView {
    /// The human pressed **Deny and block this agent**; lifts by itself after thirty minutes.
    DeniedAndBlocked,
    /// The agent's second origin mismatch in one unlock session; lifts only when unblocked.
    OriginMismatch,
}

impl From<kagisecure_agent::AgentFillBlockReason> for AgentFillBlockReasonView {
    fn from(reason: kagisecure_agent::AgentFillBlockReason) -> Self {
        match reason {
            kagisecure_agent::AgentFillBlockReason::DeniedAndBlocked => Self::DeniedAndBlocked,
            kagisecure_agent::AgentFillBlockReason::OriginMismatch => Self::OriginMismatch,
        }
    }
}

/// One blocked agent, for the blocks list in Agent access (ADR-0036 §9.3). Metadata only.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AgentFillBlockView {
    /// What the block is keyed on — the agent's kernel-resolved parent executable — and what
    /// [`agent_fill_unblock`] takes. Every client under the same program shares it.
    pub key: String,
    /// The self-reported name of the agent whose request set the block. Render it as a
    /// quotation; it is unverified.
    pub agent_name: String,
    /// Why.
    pub reason: AgentFillBlockReasonView,
    /// Unix seconds it lifts at, for a live countdown; `None` for a block that lasts until the
    /// human unblocks it.
    pub until: Option<u64>,
}

impl From<kagisecure_agent::AgentFillBlock> for AgentFillBlockView {
    fn from(block: kagisecure_agent::AgentFillBlock) -> Self {
        Self {
            key: block.key,
            agent_name: block.agent_name,
            reason: block.reason.into(),
            // Rounded up, so a countdown never reaches zero while the block still holds.
            until: block.remaining.map(|left| {
                let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
                kagisecure_core::unix_now().saturating_add(secs)
            }),
        }
    }
}

/// Something about agent fills the human should hear although no sheet was raised
/// (ADR-0036 §9.1, §9.4). Metadata only: names, a key, an origin, counts.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AgentFillNoticeView {
    /// An agent asked to fill an item into a tab whose origin the item is not saved for. Nothing
    /// was filled.
    OriginMismatch {
        /// The agent as the audit log names it: self-reported name quoted, kernel facts bare.
        agent: String,
        /// The item's title.
        item_title: String,
        /// The origin the browser reported, rendered so a look-alike is obvious.
        origin: AgentOriginView,
    },
    /// An agent asked for more sheets than its budget and is refused for the next
    /// `window_minutes`. One notice per cool-down, however many requests it refuses.
    RateLimited {
        /// The agent as the audit log names it.
        agent: String,
        /// The key its budget is kept under (its parent executable).
        key: String,
        /// How many times it asked inside the window, the refused request included.
        requests: u32,
        /// The window, and the cool-down, in minutes.
        window_minutes: u32,
    },
    /// An agent was blocked without the human pressing anything — its second origin mismatch in
    /// this unlock session — until the human unblocks it.
    Blocked {
        /// The agent as the audit log names it.
        agent: String,
        /// The key it is blocked under; [`agent_fill_unblock`] takes it.
        key: String,
        /// Why.
        reason: AgentFillBlockReasonView,
    },
    /// The tripwire (ADR-0036 §8.3) fired after an agent fill: the password input stopped being
    /// a password input within seconds — the site's "show password" control — and the extension
    /// cleared it. The fill did happen; what the agent could read, it may have read.
    Unmasked {
        /// The agent as the audit log names it.
        agent: String,
        /// The item's title.
        item_title: String,
        /// The origin the password was written at, rendered as the sheet rendered it.
        origin: AgentOriginView,
    },
}

impl From<kagisecure_agent::AgentFillNotice> for AgentFillNoticeView {
    fn from(notice: kagisecure_agent::AgentFillNotice) -> Self {
        use kagisecure_agent::AgentFillNotice as N;
        match notice {
            N::OriginMismatch {
                agent,
                item_title,
                origin,
            } => Self::OriginMismatch {
                agent,
                item_title,
                origin: origin.into(),
            },
            N::RateLimited {
                agent,
                key,
                requests,
                window_minutes,
            } => Self::RateLimited {
                agent,
                key,
                requests,
                window_minutes,
            },
            N::Blocked { agent, key, reason } => Self::Blocked {
                agent,
                key,
                reason: reason.into(),
            },
            N::Unmasked {
                agent,
                item_title,
                origin,
            } => Self::Unmasked {
                agent,
                item_title,
                origin: origin.into(),
            },
        }
    }
}

/// What the app's code-signature check concluded about the caller.
///
/// The check itself is Swift's, because it needs Security.framework and the app's own signing
/// requirement; the verdict is recorded here so the lease and the audit entry say what was
/// actually established rather than what was displayed.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct ClientVerificationView {
    /// Whether the peer's signature satisfied the app's requirement.
    pub verified: bool,
    /// One line of evidence: a signing identifier and team, or why the check failed.
    pub evidence: String,
}

impl From<ClientVerificationView> for ClientVerification {
    fn from(v: ClientVerificationView) -> Self {
        Self {
            verified: v.verified,
            evidence: v.evidence,
        }
    }
}

/// One live lease, for the Leases table (ui-spec.md §10.4).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct LeaseView {
    /// Identifier, for Revoke.
    pub id: String,
    /// The environment it is scoped to.
    pub environment_id: String,
    /// The canonical directory it is scoped to. Exact match, never a prefix.
    pub directory: String,
    /// The variable names it covers.
    pub variables: Vec<String>,
    /// `"env-file"` or `"run-command"`.
    pub kind: String,
    /// The caller it was minted for, as this process rendered it.
    pub client_identity: String,
    /// Unix seconds it dies at, for the live countdown.
    pub expires_at: u64,
    /// Uses left.
    pub uses_remaining: u32,
}

/// One audit entry, for the audit viewer.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AuditRowView {
    /// Position in the chain.
    pub seq: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// Who asked: `"cli"`, `"app"`, or `"mcp"`.
    pub actor: String,
    /// The tool or subcommand.
    pub tool: String,
    /// `"allowed"`, `"denied"` or `"failed"`.
    pub outcome: String,
    /// Environment involved.
    pub environment_id: Option<String>,
    /// Item involved.
    pub item_id: Option<String>,
    /// Variable **names**.
    pub variables: Vec<String>,
    /// Target path involved.
    pub target_path: Option<String>,
    /// A short machine-readable reason, e.g. an error code from mcp-server.md §7.
    pub detail: Option<String>,
}

/// Whether the audit log is fully written to disk, for the Audit viewer and Settings.
///
/// Separate from [`AuditRowView`]'s chain-verification concern: the chain check
/// (`VaultSession::audit_intact`) asks "is what's on disk internally consistent?", while this
/// asks "does disk even have everything that has been appended in memory?" — the failure mode a
/// save that keeps erroring (a hostile `chflags uchg` on the vault directory, a full disk)
/// produces, and the whole reason a denial is appended before it is ever allowed to be lost.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AuditDurabilityView {
    /// How many appended audit entries have not yet survived a successful save. Zero means the
    /// log on disk is fully caught up.
    pub unsaved_entries: u32,
    /// The most recent save failure, if any — a short, value-free message safe to show as-is.
    /// `None` means either no save has failed, or a later save has since succeeded.
    pub last_error: Option<String>,
}

/// The listener's state, for the menu bar and the Agent access pane.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AgentStatusView {
    /// Whether the socket is bound and being accepted on.
    pub running: bool,
    /// Where it is listening. Empty when it is not.
    pub endpoint: String,
    /// Approvals waiting for a human.
    pub pending_approvals: u32,
    /// Live leases.
    pub active_leases: u32,
    /// Whether the vault behind it is still unlocked.
    pub vault_unlocked: bool,
}

/// One MCP client's setup snippet (mcp-server.md §9).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct McpSnippetView {
    /// Display name, e.g. `"Claude Code"`.
    pub title: String,
    /// `"shell"`, `"json"` or `"toml"`, for the label above the code block.
    pub language: String,
    /// The text the copy button copies.
    pub body: String,
    /// Where it goes. `None` for Claude Code, which keeps its own registry.
    pub config_path: Option<String>,
}

/// Where the sidecar is and what to paste into each client.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct McpSetupView {
    /// The absolute path to `kagisecure-mcp`, or `None` if it could not be found.
    pub sidecar_path: Option<String>,
    /// One entry per client, in the order the screen lists them.
    pub snippets: Vec<McpSnippetView>,
}

// -------------------------------------------------------------------------------------------
// Exported functions
// -------------------------------------------------------------------------------------------

/// Read an endpoint the host named, or say why this platform cannot listen on it.
///
/// One place for the three overrides the app can pass, so that a string crossing the FFI means
/// exactly what the same string means on `kagisecure daemon --socket`: a path on Unix, a named
/// pipe name on Windows. The refusal is an [`FfiError::Invalid`] because that is what the app
/// shows to a human, and the sentence it carries names both the value and what to pass instead.
fn parse_endpoint(value: Option<&str>) -> FfiResult<Option<Endpoint>> {
    let Some(value) = value else {
        return Ok(None);
    };
    Endpoint::parse(std::ffi::OsStr::new(value))
        .map(Some)
        .map_err(|e| FfiError::invalid(e.to_string()))
}

/// Bind the IPC socket and start serving agents from `session`'s vault.
///
/// `socket_path` overrides the per-user default (architecture.md §4.2); pass `None` in the app.
/// Returns the endpoint it bound, for the "Set up your agent" screen.
///
/// # What the string means
///
/// The same thing `--socket` and `KAGISECURE_SOCKET` mean, because it goes through the same
/// `Endpoint::parse`: a **socket path** on Unix, and a **named pipe name** on Windows, which has
/// no filesystem sockets at all. A path supplied on Windows is refused with a message saying
/// what to pass instead, rather than accepted and then failing at `bind` with an opaque
/// `Unsupported: "not a named pipe path"`. It is not silently turned into a pipe name: two
/// directories holding the same file name would collapse onto one pipe.
///
/// The parameter keeps its name so that the generated bindings — and the Swift the app is built
/// against — keep theirs.
///
/// # Errors
///
/// [`FfiError::Invalid`] with a message written for a human when another kagisecure already holds
/// the socket, when `socket_path` is not usable on this platform, or when this process has
/// already started an agent.
#[uniffi::export]
pub fn agent_start(session: Arc<VaultSession>, socket_path: Option<String>) -> FfiResult<String> {
    let mut slot = agent();
    if let Some(existing) = slot.as_ref() {
        return Err(FfiError::invalid(format!(
            "This app is already serving agents on {}.",
            existing.endpoint()
        )));
    }
    let config = AgentConfig {
        endpoint: parse_endpoint(socket_path.as_deref())?,
        queue: Some(Arc::clone(&QUEUE)),
        agent_fill: Some(Arc::clone(&AGENT_FILL)),
        test_logins: Some(Arc::clone(&TEST_LOGINS)),
    };
    let started =
        Agent::start(session.handle(), &config).map_err(|e| FfiError::invalid(e.to_string()))?;
    let endpoint = started.endpoint();
    *slot = Some(started);
    Ok(endpoint)
}

/// Hand the running agent a machine vault to serve beside the personal one, or take it away with
/// `None` (ADR-0042 §2). `false` when no agent is running.
pub(crate) fn attach_machine_vault(machine: Option<Arc<kagisecure_agent::VaultHandle>>) -> bool {
    match agent().as_ref() {
        Some(a) => {
            a.attach_machine_vault(machine);
            true
        }
        None => false,
    }
}

/// Stop serving, deny every approval still waiting, and drop every lease.
///
/// Idempotent, and the first thing the app does when it locks: the vault key going away is what
/// makes leases invalid, and this is what makes that immediate rather than eventual.
#[uniffi::export]
pub fn agent_stop() {
    let mut slot = agent();
    if let Some(mut existing) = slot.take() {
        existing.stop();
    }
}

/// Whether the listener is running, and what it is holding.
#[uniffi::export]
#[must_use]
pub fn agent_status() -> AgentStatusView {
    match agent().as_ref() {
        None => AgentStatusView {
            running: false,
            endpoint: String::new(),
            pending_approvals: 0,
            active_leases: 0,
            vault_unlocked: false,
        },
        Some(a) => {
            let s = a.status();
            AgentStatusView {
                running: s.running,
                endpoint: s.endpoint,
                pending_approvals: s.pending_approvals,
                active_leases: s.active_leases,
                vault_unlocked: s.vault_unlocked,
            }
        }
    }
}

/// Wait up to `timeout_ms` for something to ask the user, and take it off the queue.
///
/// **This call blocks.** Call it from a background task, never from the main actor. The global is
/// released before the wait begins, so [`agent_resolve`] and every other call here stay
/// responsive while this one is parked.
#[uniffi::export]
#[must_use]
pub fn agent_next_request(timeout_ms: u32) -> Option<ApprovalRequestView> {
    // The shared queue, not the agent's — a fill approval arrives here even when the MCP listener
    // is not running at all.
    QUEUE
        .next(Duration::from_millis(u64::from(timeout_ms)))
        .map(Into::into)
}

/// Everything still outstanding, delivered or not — for a "pending requests" list.
#[uniffi::export]
#[must_use]
pub fn agent_pending_requests() -> Vec<ApprovalRequestView> {
    QUEUE.snapshot().into_iter().map(Into::into).collect()
}

/// Answer one request.
///
/// Returns `false` when the id is unknown, which normally means the 60-second window closed while
/// the user was thinking. That is not an error: the tool call has already been told
/// `APPROVAL_TIMEOUT`, and the sheet should just dismiss itself.
#[uniffi::export]
pub fn agent_resolve(
    request_id: String,
    decision: ApprovalDecision,
    verification: ClientVerificationView,
) -> bool {
    QUEUE.resolve(&request_id, &decision.into(), verification.into())
}

/// Which signer a peer's Authenticode signature must name (ADR-0032).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PeerRequirementKind {
    /// One of our own helpers — the MCP sidecar, or the native messaging host: signed with the same
    /// key as this build of Kagisecure. Never met by an unsigned build.
    OwnHelper,
    /// A browser: signed by the publisher the executable's file name maps to (`chrome.exe` →
    /// Google LLC, `msedge.exe` → Microsoft Corporation, `brave.exe` → Brave Software, Inc.).
    Browser,
}

/// Check the process behind `pid` with Authenticode, for the Windows approval sheet.
///
/// The Windows counterpart of the macOS app's Swift `PeerCodeSignature` (ADR-0015): the app calls
/// this with a request's `client_pid` and `client_executable` (`OwnHelper`) or its `browser_pid`
/// and `browser_executable` (`Browser`), shows the verdict, and hands it back unchanged to
/// [`agent_resolve`] so the lease and the audit entry record it.
///
/// `executable` must be the path from the request: a process that is no longer running that file
/// is not verified. The check is **structurally weaker than the macOS one** — it verifies a file,
/// not the running process — and ADR-0032 says exactly how; the verdict is a warning on the sheet,
/// never a gate.
///
/// It hashes the whole executable, so it takes as long as reading the file does: call it from the
/// same background task that polls [`agent_next_request`], not from the UI thread. It never touches
/// the network (no revocation check).
///
/// On every other platform this returns `verified: false` with "not available on this platform";
/// the macOS app keeps its own Swift check.
#[uniffi::export]
#[must_use]
pub fn verify_peer_code_signature(
    pid: u32,
    executable: String,
    requirement: PeerRequirementKind,
) -> ClientVerificationView {
    use kagisecure_ipc::authenticode::{Requirement, verify_browser, verify_peer};

    let executable = std::path::Path::new(&executable);
    let verdict = match requirement {
        PeerRequirementKind::OwnHelper => {
            verify_peer(pid, executable, &Requirement::SameSignerAsThisProcess)
        }
        PeerRequirementKind::Browser => verify_browser(pid, executable),
    };
    ClientVerificationView {
        verified: verdict.verified,
        evidence: verdict.evidence,
    }
}

/// Whether a saved website covers a host macOS password AutoFill asked about (ADR-0045 §4).
///
/// The same public-suffix rule the browser extension fills by
/// (`kagisecure_extension_ipc::origin::host_match`): same registrable domain, or the exact host
/// when there is none. Shared-hosting sites (`alice.github.io`, `bob.github.io`) do not match.
#[uniffi::export]
#[must_use]
pub fn autofill_host_matches(saved: String, requested: String) -> bool {
    kagisecure_extension_ipc::origin::host_match(&saved, &requested)
}

/// Live leases, for the Leases table.
#[uniffi::export]
#[must_use]
pub fn agent_leases() -> Vec<LeaseView> {
    let Some(leases) = agent().as_ref().map(Agent::leases) else {
        return Vec::new();
    };
    leases
        .into_iter()
        .map(|l| LeaseView {
            id: l.id.to_string(),
            environment_id: l.environment_id.to_string(),
            directory: l.directory,
            variables: l.variables,
            kind: l.kind.as_str().to_owned(),
            client_identity: l.client_identity,
            expires_at: l.expires_at,
            uses_remaining: l.uses_remaining,
        })
        .collect()
}

/// Revoke one lease and shred anything written under it.
///
/// # Errors
///
/// [`FfiError::Invalid`] if `lease_id` is not a lease identifier at all.
#[uniffi::export]
pub fn agent_revoke_lease(lease_id: String) -> FfiResult<bool> {
    let id: LeaseId = lease_id
        .parse()
        .map_err(|_| FfiError::invalid(format!("{lease_id:?} is not a lease id")))?;
    Ok(agent().as_ref().is_some_and(|a| a.revoke_lease(id)))
}

/// Revoke every lease at once ("Revoke all", ui-spec.md §10.4).
#[uniffi::export]
pub fn agent_revoke_all_leases() {
    if let Some(a) = agent().as_ref() {
        a.revoke_all_leases();
    }
}

/// Whether something asked the vault to lock over IPC (`kagisecure lock`): `true` once per request.
///
/// Only the report is consumed; the agent keeps refusing every request from the moment the lock
/// was acknowledged until the app takes the vault (see `Agent::take_lock_request`).
///
/// The app polls this alongside `agent_next_request` and performs the lock itself, because the app
/// owns the `VaultSession` and therefore the vault's lifetime.
#[uniffi::export]
pub fn agent_take_lock_request() -> bool {
    agent().as_ref().is_some_and(Agent::take_lock_request)
}

/// Where the sidecar is, and the snippet for each MCP client.
///
/// `bundle_helpers_dir` is the app's own `Contents/Helpers`, where architecture.md §8 puts the
/// bundled sidecar. A released app always answers from there; the search falls through to
/// `KAGISECURE_MCP` for a developer running a `target/` build, to an installed `Kagisecure.app`,
/// and to `PATH` for a Homebrew install.
#[uniffi::export]
#[must_use]
pub fn mcp_setup(bundle_helpers_dir: Option<String>) -> McpSetupView {
    let hint = bundle_helpers_dir.map(std::path::PathBuf::from);
    let found = kagisecure_agent::setup::sidecar_path(hint.as_deref());
    // With no binary to point at, the snippets still render — with the path the install *would*
    // have, so the screen can explain what is missing instead of going blank.
    let shown = found
        .clone()
        .unwrap_or_else(kagisecure_agent::setup::placeholder_sidecar_path);
    McpSetupView {
        sidecar_path: found.map(|p| p.display().to_string()),
        snippets: kagisecure_agent::setup::all_snippets(&shown)
            .into_iter()
            .map(|s| McpSnippetView {
                title: s.title,
                language: s.language,
                body: s.body,
                config_path: s.config_path,
            })
            .collect(),
    }
}

// -------------------------------------------------------------------------------------------
// The browser-extension surface (M6)
// -------------------------------------------------------------------------------------------

/// The extension listener's state, for the Browser extension pane.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ExtensionStatusView {
    /// Whether the extension socket is bound and being accepted on.
    pub running: bool,
    /// Where it is listening. Empty when it is not.
    pub endpoint: String,
    /// Whether the Safari front end — the App Group socket — is bound and being accepted on.
    pub safari_running: bool,
    /// Where the Safari socket is, or a sentence saying why there is not one.
    pub safari_endpoint: String,
    /// How many native hosts are connected right now — in practice, how many browsers.
    pub connected_hosts: u32,
    /// How many fill leases are alive right now.
    pub fill_leases: u32,
    /// Whether the vault behind it is still unlocked.
    pub vault_unlocked: bool,
}

/// One live fill lease, for the Leases table.
///
/// A different shape from [`LeaseView`] on purpose: a fill lease has an origin and an item where
/// an env lease has a directory and a variable set, and rendering both through one record would
/// mean four optional fields and a UI that has to guess which half is real.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FillLeaseView {
    /// The origin it covers, in ASCII serialization.
    pub origin: String,
    /// The item it covers.
    pub item_id: String,
    /// That item's title.
    pub item_title: String,
    /// **What** the lease covers: `username`, `password`, `one-time password`. A lease covers
    /// only the fields the sheet named, so the table must show them (D-3).
    pub fields: Vec<String>,
    /// The browser it was minted for, as this process rendered it.
    pub client_identity: String,
    /// Unix seconds it dies at, for the live countdown.
    pub expires_at: u64,
}

/// One browser's native-messaging manifest, for the Browser extension setup screen.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BrowserManifestView {
    /// The browser's display name.
    pub browser: String,
    /// The absolute path of the file the button would write.
    pub path: String,
    /// Exactly what would be written there, so the user can read it first.
    pub body: String,
    /// Whether that browser appears to be installed on this Mac.
    pub browser_installed: bool,
    /// Whether that exact file is already in place.
    pub installed: bool,
    /// Windows only: the registry subkey (relative to `HKEY_CURRENT_USER`) the install button
    /// will also set, mirroring [`kagisecure_agent::browser_setup::BrowserManifest::registry_key`]
    /// — see that field's own doc comment for the shape and for how a Windows browser finds this
    /// manifest at all, since it never scans a directory for one the way macOS does. `None` on
    /// macOS, which has nothing to register, and `None` here too until a build actually runs this
    /// screen on Windows.
    ///
    /// `#[uniffi(default = None)]` on purpose: this field was added after `BrowserManifestView`
    /// first shipped, and without a default an existing Swift call site that builds one of these
    /// by hand (`apps/macos/KagisecureTests/FillApprovalTests.swift` does, twice, as of this
    /// writing) would stop compiling over a field that means nothing on macOS. With the default,
    /// it keeps compiling and reads `nil`. Not independently verified against a Swift build from
    /// this session — there is no Xcode on the machine this was written on — so re-check this the
    /// first time a Windows-porting session runs `cargo xtask bindgen` and builds the Swift side.
    #[uniffi(default = None)]
    pub registry_key: Option<String>,
}

/// The Safari half of the setup screen — facts, and no button that writes a file (M6b).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SafariSetupView {
    /// The app extension's bundle identifier, which is what Safari lists and what the app pins.
    pub bundle_id: String,
    /// The App Group the app and the extension share, or `None` on a build with no team.
    pub app_group: Option<String>,
    /// The socket the extension connects to, or `None` when there is no App Group to put it in.
    pub socket_path: Option<String>,
    /// The `.appex` inside this bundle, when this build actually ships one.
    pub appex_path: Option<String>,
}

/// Everything the Browser extension screen needs (`docs/browser-extension.md` §5, §8).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ExtensionSetupView {
    /// The absolute path to `kagisecure-nmhost`, or `None` if it could not be found.
    pub nmhost_path: Option<String>,
    /// The pinned extension id, which the user needs in order to recognize what they loaded.
    pub extension_id: String,
    /// The native messaging host name the manifests are filed under.
    pub host_name: String,
    /// One entry per browser, installed browsers first.
    pub manifests: Vec<BrowserManifestView>,
    /// Safari, which needs no manifest and is enabled from Safari's own Settings.
    pub safari: SafariSetupView,
}

/// Bind the extension socket and start serving browsers from `session`'s vault.
///
/// Approvals arrive on the **same** queue [`agent_next_request`] already polls, so the app needs
/// no second loop and a fill cannot raise a sheet nobody is watching.
///
/// # Errors
///
/// [`FfiError::Invalid`], with a message written for a human, when another kagisecure holds the
/// socket, when either override is not usable on this platform, or when this process has already
/// started a listener.
///
/// Both strings mean what [`agent_start`]'s `socket_path` means: a path on Unix, a named pipe
/// name on Windows.
#[uniffi::export]
pub fn extension_start(
    session: Arc<VaultSession>,
    socket_path: Option<String>,
    safari_socket_path: Option<String>,
    team_id: Option<String>,
) -> FfiResult<String> {
    let mut slot = extension();
    if let Some(existing) = slot.as_ref() {
        return Err(FfiError::invalid(format!(
            "This app is already serving browser extensions on {}.",
            existing.endpoint()
        )));
    }
    let config = ExtensionConfig {
        endpoint: parse_endpoint(socket_path.as_deref())?,
        safari_endpoint: parse_endpoint(safari_socket_path.as_deref())?,
        team_id,
        agent_fill: Some(Arc::clone(&AGENT_FILL)),
        ..ExtensionConfig::new(Arc::clone(&QUEUE))
    };
    let started = ExtensionAgent::start(session.handle(), config)
        .map_err(|e| FfiError::invalid(e.to_string()))?;
    let endpoint = started.endpoint();
    *slot = Some(started);
    Ok(endpoint)
}

/// Stop serving browsers and drop every fill lease. Idempotent.
#[uniffi::export]
pub fn extension_stop() {
    let mut slot = extension();
    if let Some(mut existing) = slot.take() {
        existing.stop();
    }
}

/// Whether the extension listener is running, and what it is holding.
#[uniffi::export]
#[must_use]
pub fn extension_status() -> ExtensionStatusView {
    match extension().as_ref() {
        None => ExtensionStatusView {
            running: false,
            endpoint: String::new(),
            safari_running: false,
            safari_endpoint: String::new(),
            connected_hosts: 0,
            fill_leases: 0,
            vault_unlocked: false,
        },
        Some(e) => {
            let s = e.status();
            ExtensionStatusView {
                running: s.running,
                endpoint: s.endpoint,
                safari_running: s.safari_running,
                safari_endpoint: s.safari_endpoint,
                connected_hosts: s.connected_hosts,
                fill_leases: s.fill_leases,
                vault_unlocked: s.vault_unlocked,
            }
        }
    }
}

/// Live fill leases, for the Leases table.
#[uniffi::export]
#[must_use]
pub fn extension_fill_leases() -> Vec<FillLeaseView> {
    extension()
        .as_ref()
        .map(ExtensionAgent::fill_leases)
        .unwrap_or_default()
        .into_iter()
        .map(|l| FillLeaseView {
            origin: l.origin,
            item_id: l.item_id,
            item_title: l.item_title,
            fields: l.fields,
            client_identity: l.client_identity,
            expires_at: l.expires_at,
        })
        .collect()
}

/// Revoke one fill lease. `false` if there was no such live lease.
#[uniffi::export]
pub fn extension_revoke_fill_lease(origin: String, item_id: String) -> bool {
    extension()
        .as_ref()
        .is_some_and(|e| e.revoke_fill_lease(&origin, &item_id))
}

/// Revoke every fill lease, so the next fill at every origin asks again.
#[uniffi::export]
pub fn extension_revoke_all_fill_leases() {
    if let Some(e) = extension().as_ref() {
        e.revoke_all_fill_leases();
    }
}

/// Turn agent-requested browser fills on or off (ADR-0036 §2, implementation decision 12).
///
/// The app stores the switch in its own defaults and pushes it here at launch and whenever it
/// changes; Rust keeps it in memory only, and it starts **off**, so a process that never calls
/// this never serves an agent fill. Off, every `request_fill` answers `FILL_UNAVAILABLE` before
/// its item is looked up. The switch is a convenience, not a security boundary — the per-fill
/// sheet and its biometric are — and turning it on is the app's to gate behind a presence check.
///
/// UniFFI only: the C ABI never offers agent fills (implementation decision 8), and on a Windows
/// build this call changes nothing — the broker answers "off" there whatever it is told.
#[uniffi::export]
pub fn agent_fill_set_enabled(enabled: bool) {
    AGENT_FILL.set_enabled(enabled);
}

/// Every agent-fill notice queued since the last call, oldest first (ADR-0036 §9.1, §9.4,
/// implementation decision 11). The app drains it on its 1-second tick and shows each one in
/// Agent access, on the menu-bar badge and — if the user authorized it — as a system notification.
///
/// UniFFI only, like every `agent_fill_*` call.
#[uniffi::export]
#[must_use]
pub fn agent_fill_take_notices() -> Vec<AgentFillNoticeView> {
    AGENT_FILL
        .take_notices()
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Every test-login notice queued since the last call, oldest first (ADR-0048 §10). The app
/// drains it on its tick: a system notification per create, and the menu-bar entry "N test logins
/// created by agents".
#[uniffi::export]
#[must_use]
pub fn test_logins_take_notices() -> Vec<TestLoginNoticeView> {
    TEST_LOGINS
        .take_notices()
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Every agent blocked from asking for fills right now, for the blocks list in Agent access
/// (ADR-0036 §9.3). Blocks live in the process, not the vault: they survive a lock.
///
/// UniFFI only, like every `agent_fill_*` call.
#[uniffi::export]
#[must_use]
pub fn agent_fill_blocks() -> Vec<AgentFillBlockView> {
    AGENT_FILL.blocks().into_iter().map(Into::into).collect()
}

/// Lift the block on `key` (an [`AgentFillBlockView::key`]): the Unblock button. Returns whether
/// there was one. A denial the human gave in the last ten minutes still stands for the identical
/// request.
///
/// UniFFI only, like every `agent_fill_*` call.
#[uniffi::export]
pub fn agent_fill_unblock(key: String) -> bool {
    AGENT_FILL.unblock(&key)
}

/// Where the native host is, what the pinned extension id is, and what each browser needs written.
///
/// `bundle_helpers_dir` is the app's own `Contents/Helpers`, where a shipped `kagisecure-nmhost`
/// lives; the search falls through to `KAGISECURE_NMHOST`, an installed `Kagisecure.app` and
/// `PATH` — the same order [`mcp_setup`] uses for the sidecar, because it is the same search.
#[uniffi::export]
#[must_use]
pub fn extension_setup(
    bundle_helpers_dir: Option<String>,
    bundle_plugins_dir: Option<String>,
    team_id: Option<String>,
) -> ExtensionSetupView {
    let hint = bundle_helpers_dir.map(std::path::PathBuf::from);
    let plugins = bundle_plugins_dir.map(std::path::PathBuf::from);
    let safari = browser_setup::safari_setup(team_id.as_deref(), plugins.as_deref());
    let found = browser_setup::nmhost_path(hint.as_deref());
    // With no binary to point at the screen still renders — with the path an install *would*
    // have — so it can explain what is missing instead of going blank.
    let shown = found
        .clone()
        .unwrap_or_else(browser_setup::placeholder_nmhost_path);
    ExtensionSetupView {
        nmhost_path: found.map(|p| p.display().to_string()),
        extension_id: kagisecure_extension_ipc::PINNED_EXTENSION_IDS[0].to_owned(),
        host_name: kagisecure_extension_ipc::NATIVE_HOST_NAME.to_owned(),
        manifests: browser_setup::all_manifests(&shown)
            .into_iter()
            .map(|m| BrowserManifestView {
                browser: m.browser,
                path: m.path.display().to_string(),
                body: m.body,
                browser_installed: m.browser_installed,
                installed: m.installed,
                registry_key: m.registry_key,
            })
            .collect(),
        safari: SafariSetupView {
            bundle_id: safari.bundle_id,
            app_group: safari.app_group,
            socket_path: safari.socket_path.map(|p| p.display().to_string()),
            appex_path: safari.appex_path.map(|p| p.display().to_string()),
        },
    }
}

/// Write one browser's manifest.
///
/// Takes the record the screen is showing rather than a browser name, so what is written is
/// exactly what the user was looking at when they pressed the button.
///
/// # Errors
///
/// [`FfiError::Io`] naming the file that could not be written.
#[uniffi::export]
pub fn extension_install_manifest(manifest: BrowserManifestView) -> FfiResult<()> {
    browser_setup::install(&browser_setup::BrowserManifest {
        browser: manifest.browser,
        path: std::path::PathBuf::from(manifest.path),
        body: manifest.body,
        browser_installed: manifest.browser_installed,
        installed: manifest.installed,
        registry_key: manifest.registry_key,
    })
    .map_err(|message| FfiError::Io { message })
}

/// Remove one browser's manifest, turning the integration off for that browser.
///
/// # Errors
///
/// [`FfiError::Io`] naming the file that could not be removed. A file that was not there is
/// success.
#[uniffi::export]
pub fn extension_uninstall_manifest(manifest: BrowserManifestView) -> FfiResult<()> {
    browser_setup::uninstall(&browser_setup::BrowserManifest {
        browser: manifest.browser,
        path: std::path::PathBuf::from(manifest.path),
        body: manifest.body,
        browser_installed: manifest.browser_installed,
        installed: manifest.installed,
        registry_key: manifest.registry_key,
    })
    .map_err(|message| FfiError::Io { message })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn with_no_agent_running_every_call_answers_emptily_rather_than_panicking() {
        // The app can ask for leases before it has started the listener — at launch, or after a
        // lock — and every one of these has to be safe then.
        // `agent_next_request` and `agent_pending_requests` are deliberately *not* asserted here.
        // Since M6 they read the process-global approval queue rather than the agent's own, and
        // this test binary runs in parallel with
        // `a_fill_approval_reaches_the_same_queue_the_app_already_polls`, which puts something on
        // it. That test owns the queue's behaviour; this one owns "no agent, no panic".
        assert!(!agent_status().running);
        assert!(agent_leases().is_empty());
        assert!(!agent_take_lock_request());
        // Deliberately not `"req-1"`: the queue mints ids as `req-<n>` from 1, and this test
        // binary runs in parallel with one that puts a real request on the shared queue. An id
        // that could collide would make this test resolve somebody else's approval.
        assert!(!agent_resolve(
            "req-there-is-no-such-request".to_owned(),
            ApprovalDecision::Deny,
            ClientVerificationView::default()
        ));
        agent_revoke_all_leases();
        agent_stop();
    }

    #[test]
    fn with_no_extension_listener_running_every_call_answers_emptily() {
        assert!(!extension_status().running);
        assert!(extension_fill_leases().is_empty());
        assert!(!extension_revoke_fill_lease(
            "https://example.com".to_owned(),
            "item".to_owned()
        ));
        extension_revoke_all_fill_leases();
        extension_stop();
    }

    #[test]
    fn the_browser_setup_screen_always_has_something_to_show() {
        let setup = extension_setup(
            Some("/nowhere/at/all".to_owned()),
            Some("/nowhere/at/all/PlugIns".to_owned()),
            Some("TEAMID1234".to_owned()),
        );
        assert_eq!(setup.extension_id.len(), 32);
        assert_eq!(setup.host_name, "com.kagisecure.nmhost");
        assert!(
            !setup.manifests.is_empty(),
            "a screen with no browsers on it would be a dead end"
        );
        for manifest in &setup.manifests {
            // On Windows each browser gets its own file (`com.kagisecure.nmhost.<browser>.json`)
            // rather than sharing one — see `browser_setup`'s module doc comment on why one
            // shared file per registry pointer is the wrong shape there.
            if cfg!(windows) {
                assert!(
                    manifest.path.contains("com.kagisecure.nmhost")
                        && manifest.path.ends_with(".json"),
                    "{}",
                    manifest.path
                );
            } else {
                assert!(manifest.path.ends_with("com.kagisecure.nmhost.json"));
            }
            assert!(
                manifest.body.contains(&setup.extension_id),
                "every manifest must pin the same id the app checks"
            );
        }
        assert_eq!(
            setup.safari.bundle_id,
            "com.kagisecure.app.safari-extension"
        );
        assert_eq!(
            setup.safari.app_group.as_deref(),
            Some("TEAMID1234.com.kagisecure")
        );
        assert!(
            setup.safari.appex_path.is_none(),
            "that directory does not exist, so no extension is claimed"
        );
        assert!(
            !setup.manifests.iter().any(|m| m.browser.contains("Safari")),
            "Safari needs no manifest and must not be offered one"
        );
    }

    #[test]
    fn a_build_with_no_team_still_renders_the_safari_section() {
        // The ad-hoc case. The screen has to be able to say "this build cannot serve Safari, and
        // here is why" rather than going blank or claiming a socket nothing will connect to.
        let setup = extension_setup(None, None, None);
        assert_eq!(
            setup.safari.bundle_id,
            "com.kagisecure.app.safari-extension"
        );
        assert_eq!(setup.safari.app_group, None);
        if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_none() {
            assert_eq!(setup.safari.socket_path, None);
        }
    }

    #[test]
    fn installing_and_removing_a_manifest_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = BrowserManifestView {
            browser: "Test".to_owned(),
            path: dir
                .path()
                .join("Sub")
                .join("com.kagisecure.nmhost.json")
                .display()
                .to_string(),
            body: "{}\n".to_owned(),
            browser_installed: true,
            installed: false,
            registry_key: None,
        };
        extension_install_manifest(manifest.clone()).expect("install");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read"),
            "{}\n"
        );
        extension_uninstall_manifest(manifest.clone()).expect("uninstall");
        assert!(!std::path::Path::new(&manifest.path).exists());
        extension_uninstall_manifest(manifest).expect("uninstalling twice is not an error");
    }

    #[test]
    fn a_fill_approval_reaches_the_same_queue_the_app_already_polls() {
        // The property that makes M6 one sheet rather than two: a request pushed onto the shared
        // queue by the extension listener comes back out of `agent_next_request`, which the app's
        // existing loop is already calling — with no MCP agent running at all.
        let asker = Arc::clone(&QUEUE);
        let thread = std::thread::spawn(move || {
            asker.ask(ApprovalRequest {
                kind: ApprovalKind::FillCredential,
                origin: Some("https://example.com".to_owned()),
                item_title: Some("Example".to_owned()),
                fill_fields: vec!["username".to_owned(), "password".to_owned()],
                browser: Some("Google Chrome".to_owned()),
                ..ApprovalRequest::default()
            })
        });
        let delivered = agent_next_request(5_000).expect("the fill must reach the sheet");
        assert_eq!(delivered.action, ApprovalAction::FillCredential);
        assert_eq!(delivered.origin.as_deref(), Some("https://example.com"));
        assert_eq!(delivered.fill_fields.len(), 2);
        assert!(
            !delivered.mints_lease,
            "a fill lease is not an env lease; the sheet must not offer the env lease control"
        );
        assert!(agent_resolve(
            delivered.id.clone(),
            ApprovalDecision::Deny,
            ClientVerificationView::default()
        ));
        let outcome = thread.join().expect("asker");
        assert!(!outcome.granted);
    }

    #[test]
    fn a_malformed_lease_id_is_an_error_not_a_silent_false() {
        assert!(agent_revoke_lease("not-a-uuid".to_owned()).is_err());
    }

    #[test]
    fn the_setup_screen_always_has_something_to_show() {
        let setup = mcp_setup(Some("/nowhere/at/all".to_owned()));
        assert_eq!(setup.snippets.len(), 4);
        assert!(setup.snippets.iter().any(|s| s.title == "Claude Code"));
        assert!(
            setup.snippets.iter().all(|s| !s.body.is_empty()),
            "a snippet with no body would be a blank copy button"
        );
    }

    #[test]
    fn a_decision_maps_onto_the_library_enum_unchanged() {
        assert_eq!(
            Decision::from(ApprovalDecision::AllowOnce),
            Decision::AllowOnce
        );
        assert_eq!(
            Decision::from(ApprovalDecision::AllowSession {
                ttl_seconds: 300,
                uses: 2
            }),
            Decision::AllowSession {
                ttl_seconds: 300,
                uses: 2
            }
        );
        assert_eq!(Decision::from(ApprovalDecision::Deny), Decision::Deny);
        assert_eq!(
            Decision::from(ApprovalDecision::DenyAndBlock),
            Decision::DenyAndBlock
        );
    }

    #[test]
    fn an_agent_fill_block_crosses_with_its_deadline_in_unix_seconds() {
        let timed = AgentFillBlockView::from(kagisecure_agent::AgentFillBlock {
            key: "/usr/local/bin/node".to_owned(),
            agent_name: "example-agent".to_owned(),
            reason: kagisecure_agent::AgentFillBlockReason::DeniedAndBlocked,
            remaining: Some(Duration::from_millis(1_799_500)),
        });
        let now = kagisecure_core::unix_now();
        let until = timed.until.expect("a timed block");
        assert!(
            (now + 1800..=now + 1801).contains(&until),
            "{until} vs {now}"
        );
        assert_eq!(timed.reason, AgentFillBlockReasonView::DeniedAndBlocked);

        let open = AgentFillBlockView::from(kagisecure_agent::AgentFillBlock {
            key: "/usr/local/bin/node".to_owned(),
            agent_name: "example-agent".to_owned(),
            reason: kagisecure_agent::AgentFillBlockReason::OriginMismatch,
            remaining: None,
        });
        assert_eq!(open.until, None, "until somebody unblocks it");
    }

    #[test]
    fn unblocking_an_unknown_agent_is_a_quiet_no() {
        assert!(!agent_fill_unblock("/no/such/agent".to_owned()));
        assert!(
            agent_fill_blocks()
                .iter()
                .all(|b| b.key != "/no/such/agent")
        );
    }

    #[test]
    fn an_approval_request_view_carries_no_field_a_value_could_sit_in() {
        let view = ApprovalRequestView::from(ApprovalRequest {
            id: "req-1".to_owned(),
            variables: vec!["TOKEN".to_owned()],
            ..ApprovalRequest::default()
        });
        assert_eq!(view.variables, vec!["TOKEN".to_owned()]);
        assert!(view.mints_lease);
        assert_eq!(view.action, ApprovalAction::WriteEnvFile);
        assert!(!view.presence_only, "an env request is always a full sheet");
    }

    #[test]
    fn a_presence_only_fill_reaches_the_app_marked_as_one() {
        // The app decides "sheet or presence prompt" from this one flag, so it must survive the
        // crossing exactly — in both directions, since a lost `false` would hide a sheet.
        for presence_only in [true, false] {
            let view = ApprovalRequestView::from(ApprovalRequest {
                kind: ApprovalKind::FillCredential,
                origin: Some("https://example.com".to_owned()),
                item_title: Some("Example".to_owned()),
                fill_fields: vec!["password".to_owned()],
                presence_only,
                ..ApprovalRequest::default()
            });
            assert_eq!(view.presence_only, presence_only);
            assert_eq!(view.action, ApprovalAction::FillCredential);
        }
    }

    /// The facts of an agent fill at `origin`, covered by `https://example.com`.
    pub(crate) fn agent_fill_facts(origin: &str) -> AgentFillFacts {
        let origin = kagisecure_extension_ipc::origin::Origin::parse(origin).expect("an origin");
        AgentFillFacts {
            agent_name: "example-agent".to_owned(),
            sidecar_pid: 51_234,
            sidecar_executable: Some("/usr/local/bin/kagisecure-mcp".to_owned()),
            sidecar_audit_token: Some("00".repeat(32)),
            parent_pid: Some(51_200),
            parent_executable: Some("/path/to/client".to_owned()),
            item_id: "item-1".to_owned(),
            item_title: "Example (work)".to_owned(),
            fields: vec![AgentFillField::Username, AgentFillField::Password],
            two_step: true,
            page_origin: AgentOriginRendering::of(&origin),
            saved_website: "https://example.com".to_owned(),
            page_host_differs: true,
            browser: Some("Google Chrome".to_owned()),
            browser_pid: Some(400),
            browser_executable: Some("/Applications/Google Chrome.app".to_owned()),
            browser_is_app_extension: false,
            host_pid: Some(401),
            host_audit_token: Some("11".repeat(32)),
            host_executable: Some("/Applications/Kagisecure.app/kagisecure-nmhost".to_owned()),
            extension_id: Some("abcdefghijklmnopabcdefghijklmnop".to_owned()),
        }
    }

    #[test]
    fn a_test_login_request_crosses_with_its_facts_and_rides_grace_crosses_alone() {
        let origin =
            kagisecure_extension_ipc::origin::Origin::parse("https://staging.example-partner.com")
                .unwrap();
        let facts = kagisecure_agent::TestLoginFacts {
            agent: "mcp \"Claude Code\" pid 1".to_owned(),
            agent_name: "Claude Code".to_owned(),
            title: "test: shop / buyer #1".to_owned(),
            username: "buyer1@example.com".to_owned(),
            websites: vec![kagisecure_agent::TestLoginWebsite {
                origin: AgentOriginRendering::of(&origin),
                near_item_title: Some("Partner portal".to_owned()),
                not_https: false,
            }],
            purpose: "buyer".to_owned(),
            tags: vec!["agent-test".to_owned()],
            generator: "32 characters, with symbols".to_owned(),
            reason: None,
        };
        let view = ApprovalRequestView::from(ApprovalRequest {
            kind: ApprovalKind::CreateTestLogin,
            agent_test_login: Some(facts),
            ..ApprovalRequest::default()
        });
        assert_eq!(view.action, ApprovalAction::CreateTestLogin);
        assert!(!view.mints_lease);
        let crossed = view.test_login.expect("facts");
        assert_eq!(crossed.websites[0].origin.emphasized, "example-partner.com");
        assert_eq!(
            crossed.websites[0].near_item_title.as_deref(),
            Some("Partner portal")
        );
        assert!(!view.rides_grace);

        let run = ApprovalRequestView::from(ApprovalRequest {
            kind: ApprovalKind::RunWithEnv,
            rides_grace: true,
            ..ApprovalRequest::default()
        });
        assert!(run.rides_grace);
        assert!(run.test_login.is_none());
    }

    #[test]
    fn an_agent_fill_request_crosses_with_every_fact_intact() {
        let facts = agent_fill_facts("https://login.xn--exmple-cua.com:8443");
        let view = ApprovalRequestView::from(ApprovalRequest::for_agent_fill(facts.clone()));
        assert_eq!(view.action, ApprovalAction::AgentFill);
        assert!(!view.mints_lease, "an agent fill mints nothing");
        assert!(
            !view.presence_only,
            "an agent fill is always the full sheet"
        );
        assert_eq!(view.client_name, "example-agent");
        assert_eq!(view.client_pid, Some(51_234));
        assert!(view.client_pid_from_kernel);
        assert_eq!(view.item_id.as_deref(), Some("item-1"));

        let crossed = view.agent_fill.expect("the facts must reach the sheet");
        // Every member, compared with the source it came from.
        let AgentFillFactsView {
            agent_name,
            sidecar_pid,
            sidecar_executable,
            sidecar_audit_token,
            parent_pid,
            parent_executable,
            item_id,
            item_title,
            fields,
            two_step,
            page_origin,
            saved_website,
            page_host_differs,
            browser,
            browser_pid,
            browser_executable,
            browser_is_app_extension,
            host_pid,
            host_audit_token,
            host_executable,
            extension_id,
        } = crossed;
        assert_eq!(agent_name, facts.agent_name);
        assert_eq!(sidecar_pid, facts.sidecar_pid);
        assert_eq!(sidecar_executable, facts.sidecar_executable);
        assert_eq!(sidecar_audit_token, facts.sidecar_audit_token);
        assert_eq!(view.client_audit_token, facts.sidecar_audit_token);
        assert_eq!(parent_pid, facts.parent_pid);
        assert_eq!(parent_executable, facts.parent_executable);
        assert_eq!(item_id, facts.item_id);
        assert_eq!(item_title, facts.item_title);
        assert_eq!(
            fields,
            [AgentFillFieldView::Username, AgentFillFieldView::Password]
        );
        assert_eq!(two_step, facts.two_step);
        assert!(two_step);
        assert_eq!(saved_website, facts.saved_website);
        assert_eq!(page_host_differs, facts.page_host_differs);
        assert_eq!(browser, facts.browser);
        assert_eq!(browser_pid, facts.browser_pid);
        assert_eq!(browser_executable, facts.browser_executable);
        assert_eq!(browser_is_app_extension, facts.browser_is_app_extension);
        assert_eq!(host_pid, facts.host_pid);
        assert_eq!(host_audit_token, facts.host_audit_token);
        assert_eq!(host_executable, facts.host_executable);
        assert_eq!(extension_id, facts.extension_id);

        let AgentOriginView {
            ascii,
            scheme,
            dimmed_prefix,
            emphasized,
            port,
            unicode_host,
            mixed_script,
            not_encrypted,
        } = page_origin;
        let rendering = &facts.page_origin;
        assert_eq!(ascii, "https://login.xn--exmple-cua.com:8443");
        assert_eq!(ascii, rendering.ascii());
        assert_eq!(view.origin.as_deref(), Some(ascii.as_str()));
        assert_eq!(scheme, "https");
        assert_eq!(dimmed_prefix, "login.");
        assert_eq!(emphasized, "xn--exmple-cua.com");
        assert_eq!(port, Some(8443));
        assert_eq!(unicode_host, rendering.unicode_host);
        assert!(
            unicode_host.is_some(),
            "a punycode label gets a Unicode rendering"
        );
        assert_eq!(mixed_script, rendering.mixed_script);
        assert!(!not_encrypted);
    }

    #[test]
    fn an_unmasked_notice_crosses_with_the_agent_the_item_and_the_origin() {
        let origin = kagisecure_extension_ipc::origin::Origin::parse("https://login.example.com")
            .expect("an origin");
        let view = AgentFillNoticeView::from(kagisecure_agent::AgentFillNotice::Unmasked {
            agent: "mcp \"example-agent\"".to_owned(),
            item_title: "Example (work)".to_owned(),
            origin: AgentOriginRendering::of(&origin),
        });
        let AgentFillNoticeView::Unmasked {
            agent,
            item_title,
            origin,
        } = view
        else {
            panic!("an unmasked notice crosses as itself");
        };
        assert_eq!(agent, "mcp \"example-agent\"");
        assert_eq!(item_title, "Example (work)");
        assert_eq!(origin.ascii, "https://login.example.com");
        assert_eq!(origin.emphasized, "example.com");
    }

    #[test]
    fn every_agent_fill_field_crosses_as_itself() {
        for (field, view) in [
            (AgentFillField::Username, AgentFillFieldView::Username),
            (AgentFillField::Password, AgentFillFieldView::Password),
            (AgentFillField::OneTimeCode, AgentFillFieldView::OneTimeCode),
            (AgentFillField::NewPassword, AgentFillFieldView::NewPassword),
        ] {
            assert_eq!(AgentFillFieldView::from(field), view);
        }
    }

    #[test]
    fn a_request_that_is_not_an_agent_fill_carries_no_agent_fill_facts() {
        let view = ApprovalRequestView::from(ApprovalRequest {
            kind: ApprovalKind::FillCredential,
            origin: Some("https://example.com".to_owned()),
            ..ApprovalRequest::default()
        });
        assert_eq!(view.agent_fill, None);
    }

    /// The FFI adds nothing to `kagisecure_ipc::authenticode` but the enum; its own tests cover
    /// real signatures. This pins the two things the adapter decides: which requirement each kind
    /// maps to, and that neither can come back verified from an unsigned test build.
    #[test]
    fn the_peer_signature_check_never_verifies_an_unsigned_build() {
        let pid = std::process::id();
        let exe = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let own = verify_peer_code_signature(pid, exe.clone(), PeerRequirementKind::OwnHelper);
        assert!(!own.verified, "{own:?}");
        let browser = verify_peer_code_signature(pid, exe, PeerRequirementKind::Browser);
        assert!(!browser.verified, "{browser:?}");

        if cfg!(windows) {
            assert!(
                own.evidence
                    .starts_with("Authenticode: this build of Kagisecure is unsigned"),
                "{own:?}"
            );
            assert!(
                browser
                    .evidence
                    .ends_with("is not a browser with a known publisher"),
                "{browser:?}"
            );
        } else {
            for v in [own, browser] {
                assert_eq!(v.evidence, "Authenticode: not available on this platform");
            }
        }
    }
}
