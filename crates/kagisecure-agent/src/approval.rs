//! The approval queue: how an IPC thread asks a human a question without Rust calling into Swift.
//!
//! # The contract
//!
//! * The IPC thread calls [`ApprovalQueue::ask`] and blocks for at most
//!   [`APPROVAL_TIMEOUT_SECONDS`]. It gets back an [`Outcome`].
//! * The UI thread calls [`ApprovalQueue::next`] with a short timeout, in a loop, from a
//!   background task. It gets an [`ApprovalRequest`] or nothing.
//! * The UI thread calls [`ApprovalQueue::resolve`] with the user's [`Decision`].
//! * [`ApprovalQueue::deny_all`] answers everything outstanding at once. That is what a vault lock
//!   does.
//!
//! Nothing here calls into the foreign language, so there are no foreign callbacks, no async
//! exports and no `Sendable` conformance to negotiate (architecture.md §4.1, ADR-0001).
//!
//! # No values, restated
//!
//! [`ApprovalRequest`] is built from the IPC request and the peer's kernel-supplied identity. It
//! carries names, paths, pids and counts. There is no field a value could go in, and
//! `secret_markers_never_reach_the_approval_queue` in [`crate::service`] asserts that the values
//! an injection reads never appear in one.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use kagisecure_extension_ipc::origin::AgentOriginRendering;
use kagisecure_ipc::protocol::{AgentFillField, ErrorCode};
use kagisecure_ipc::server::PeerIdentity;

/// How long an unanswered approval waits before it counts as `APPROVAL_TIMEOUT`
/// (mcp-server.md §7).
pub const APPROVAL_TIMEOUT_SECONDS: u64 = 60;

/// What the caller wants to do. Drives the sentence at the top of the approval sheet
/// (ui-spec.md §10.2) and the icon next to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalKind {
    /// `create_environment` — a lightweight structural change.
    CreateEnvironment,
    /// `add_variables` — declaring names, possibly leaving some awaiting user input.
    AddVariables,
    /// `write_env_file` — an injection into a file.
    WriteEnvFile,
    /// `run_with_env` — an injection into a child process.
    RunWithEnv,
    /// A browser extension wants to fill a credential into a matched page (M6).
    ///
    /// The odd one out: every other kind is an *agent* asking for an injection into a file or a
    /// process, and this one is a *browser* asking for a value to be typed into a form. It shares
    /// the queue because the queue is the app's one "ask the human" mechanism and duplicating it
    /// would mean two sheets, two timeouts and two chances to get the biometric gate wrong. It
    /// does **not** share the lease store: an env-file lease is scoped to a directory and a set
    /// of variable names, and a fill lease is scoped to an origin and an item, which are not the
    /// same shape and must not be able to satisfy each other (ADR-0020).
    FillCredential,
    /// An **agent** asks for a login to be typed into a browser tab (`request_fill`,
    /// [ADR-0036](../../../docs/decisions/0036-agent-requested-browser-fill.md)).
    ///
    /// The second browser kind, and deliberately not a flavour of [`Self::FillCredential`]: the
    /// person who caused this one is not at the keyboard, so nothing the human path remembers may
    /// excuse it and nothing it grants may be remembered. It mints **nothing** — no fill lease,
    /// no env lease, ever — and `outcome_for` answers it as a single full review whatever the UI
    /// sends: never presence-only, never "for this session". A grant of it and a grant of a
    /// `FillCredential` never satisfy each other (`crossing::Approved::from_grant` takes the kind
    /// it expects). What the sheet shows beyond the common fields is
    /// [`ApprovalRequest::agent_fill`].
    AgentFill,
    /// An agent asks for a test login at a website outside the allowed origins
    /// (`create_test_login`, [ADR-0048](../../../docs/decisions/0048-agent-test-logins.md) §3).
    ///
    /// kagisecure generates the password; nothing is released by granting it. It mints nothing,
    /// and `outcome_for` answers it as a single full review whatever the UI sends — never
    /// presence-only, never "for this session" — so the next create at that site asks again.
    /// What the sheet shows beyond the common fields is [`ApprovalRequest::agent_test_login`].
    CreateTestLogin,
    /// An agent asks to run a command and store its standard output in a concealed field
    /// (`store_command_output`, [ADR-0049](../../../docs/decisions/0049-store-command-output.md)).
    ///
    /// It mints nothing, and `outcome_for` answers it as a single full review whatever the UI
    /// sends — never presence-only, never "for this session", no grace window — so every stored
    /// value costs its own fingerprint. What the sheet shows beyond the common fields (the argv in
    /// [`ApprovalRequest::command`], the directory, and for a stdin environment its name and
    /// variables) is [`ApprovalRequest::store_output`].
    StoreCommandOutput,
    /// An agent asks for a login to be typed as keystrokes into the focused field of a native app
    /// (`request_type`, [ADR-0050](../../../docs/decisions/0050-auto-type-into-native-apps.md)).
    ///
    /// Clamped like [`Self::AgentFill`]: one review, once, no lease, never presence-only. Like an
    /// agent fill it rides the app-wide presence grace window ([`ApprovalRequest::rides_grace`]):
    /// inside it the app answers with no sheet. What the sheet shows beyond the common fields —
    /// the target app — is [`ApprovalRequest::auto_type`].
    AutoType,
}

impl ApprovalKind {
    /// Whether this kind is one full review, once, with no lease and never presence-only,
    /// whatever a UI answers: the agent kinds whose grant nothing may remember.
    #[must_use]
    pub fn single_review(self) -> bool {
        matches!(
            self,
            Self::AgentFill | Self::CreateTestLogin | Self::StoreCommandOutput | Self::AutoType
        )
    }

    /// Whether granting this mints a lease. Never for [`Self::AgentFill`].
    #[must_use]
    pub fn mints_lease(self) -> bool {
        matches!(self, Self::WriteEnvFile | Self::RunWithEnv)
    }

    /// Whether granting this mints a **fill** lease, which is a different store with different
    /// scoping rules — see the variant documentation. Never for [`Self::AgentFill`]: an agent's
    /// approval must not make the human's next click silent (ADR-0036 §6).
    #[must_use]
    pub fn mints_fill_lease(self) -> bool {
        matches!(self, Self::FillCredential)
    }

    /// The tool name, as the audit log spells it.
    #[must_use]
    pub fn tool(self) -> &'static str {
        match self {
            Self::CreateEnvironment => "create_environment",
            Self::AddVariables => "add_variables",
            Self::WriteEnvFile => "write_env_file",
            Self::RunWithEnv => "run_with_env",
            Self::FillCredential => "fill_credential",
            Self::AgentFill => "request_fill",
            Self::CreateTestLogin => "create_test_login",
            Self::StoreCommandOutput => "store_command_output",
            Self::AutoType => "request_type",
        }
    }
}

/// Everything the approval sheet needs, and nothing else.
///
/// Every field is metadata. Read this struct as the definition of what a human is shown before
/// they put a fingerprint on something: if a fact is not here, the sheet cannot state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Opaque identifier, quoted back to [`ApprovalQueue::resolve`].
    pub id: String,
    /// What is being asked for.
    pub kind: ApprovalKind,
    /// The caller's **self-reported** name, from MCP `clientInfo`. Display-only, and the UI must
    /// render it as a quotation rather than as a label (architecture.md §5).
    pub client_name: String,
    /// The peer's process id.
    pub client_pid: Option<u32>,
    /// Whether that pid came from the kernel rather than from the peer's own word.
    pub client_pid_from_kernel: bool,
    /// The peer's kernel audit token (macOS `LOCAL_PEERTOKEN`), when there is one. The app runs
    /// its code-signature check on this rather than on the pid, which can be reused.
    pub client_audit_token: Option<String>,
    /// The executable behind that pid, resolved from the pid.
    pub client_executable: Option<String>,
    /// The directory the sidecar was started in — usually the project root. Self-reported.
    pub client_cwd: Option<String>,
    /// The environment this is about, if any.
    pub environment_id: Option<String>,
    /// Its display name, so the sheet does not show a bare uuid.
    pub environment_name: Option<String>,
    /// The canonical target directory (symlinks resolved), if any.
    pub directory: Option<String>,
    /// The exact file that would be written, if any.
    pub target_path: Option<String>,
    /// Variable **names**. Never values, never lengths.
    pub variables: Vec<String>,
    /// The resolved argv for `run_with_env`, empty otherwise.
    pub command: Vec<String>,
    /// A `run_with_env` whose values go to the command's **standard input**, once, rather than
    /// into its environment (ADR-0047). The sheet must say so; it offers no "for this session",
    /// and `outcome_for` makes any allow a single use whatever a UI sends.
    pub stdin_delivery: bool,
    /// Whether the caller passed `overwrite: true`, i.e. asked for an existing file to be
    /// replaced. `false` for every kind that does not write a file.
    pub overwrite_requested: bool,
    /// Whether a file already exists at [`Self::target_path`] right now. `None` when the request
    /// is not about a file.
    ///
    /// Checked when the request is built, so it is what was true a moment before the sheet went
    /// up — not a promise about what is true when the write happens.
    pub target_exists: Option<bool>,
    /// When a file is already there, whether **kagisecure** wrote it in this unlock session.
    ///
    /// `Some(false)` is the destructive case the sheet has to state plainly: the bytes about to
    /// be replaced are the user's own, and nothing here can bring them back (threat-model M-16).
    /// `None` when there is no file, or the request is not about one.
    pub target_written_by_us: Option<bool>,
    /// `Some(false)` means "inside a git work tree and not ignored" — the red callout in
    /// ui-spec.md §10.2. `None` means not inside a work tree at all.
    pub gitignored: Option<bool>,
    /// The TTL the agent asked for. The user may shorten it, never lengthen it.
    pub requested_ttl_seconds: u64,
    /// The use count the lease would carry.
    pub requested_uses: u32,
    /// The ceiling the user's control must respect (mcp-server.md §5).
    pub max_ttl_seconds: u64,
    /// Unix seconds when the request arrived.
    pub created_at: u64,
    /// Unix seconds at which the request self-denies with `APPROVAL_TIMEOUT`.
    pub expires_at: u64,

    // --- M6: the browser-extension fill request. Empty for every other kind. ----------------
    /// The origin the fill would happen at — the frame's origin for a cross-origin iframe, the
    /// page's otherwise. This is the origin that was *matched*, so it is what the lease is keyed
    /// on and what the audit entry records.
    pub origin: Option<String>,
    /// The top-level page's origin, when the fill is not a plain top-frame load. `Some` here is
    /// the visible signal that the form is in a third party's frame.
    ///
    /// `Some("null")` is the platform serialization of an **opaque** origin: the browser could
    /// not establish an embedder. It must never be rendered literally — see
    /// [`Self::top_origin_unknown`].
    pub top_origin: Option<String>,
    /// Whether the form is in a frame whose **embedder could not be established**.
    ///
    /// True whenever the browser did not itself report that this was frame 0. The sheet must
    /// then disclose "this form is inside a frame on an unknown site" rather than showing a
    /// top-frame load or the literal string `null` (D-7).
    pub top_origin_unknown: bool,
    /// The item that would be filled.
    pub item_id: Option<String>,
    /// Its title, so the sheet does not show a bare uuid.
    pub item_title: Option<String>,
    /// Which fields would be written: `username`, `password`. Names, never values.
    pub fill_fields: Vec<String>,
    /// The browser the app established from the native host's process ancestry, e.g.
    /// `"Google Chrome"`. `None` means no recognized browser, which is refused before it reaches
    /// a sheet — so a request that *is* on a sheet always has one.
    pub browser: Option<String>,
    /// That browser's pid, so the app can run its code-signature check on it.
    pub browser_pid: Option<u32>,
    /// That browser's executable path.
    pub browser_executable: Option<String>,
    /// Whether the process on the socket is an **app extension** we ship rather than a native
    /// messaging host launched by a browser.
    ///
    /// `true` only for Safari. The app uses it to pick which code-signature requirement to check
    /// the peer against: our own team and the app extension's bundle identifier, rather than a
    /// browser vendor's hardcoded team (ADR-0024 §5).
    pub browser_is_app_extension: bool,
    /// The extension's **self-reported** id. Display-only, and only ever the pinned one, because
    /// anything else was refused at `Hello`.
    pub extension_id: Option<String>,
    /// Ask for a fresh proof that a human is present, **not** for the sheet.
    ///
    /// Set only for a fill whose exact origin, item and field set the human already reviewed at a
    /// full sheet in this unlock session and chose **Allow for this session** for — the fill lease
    /// is that review's memory ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
    /// The app answers it with the LocalAuthentication check alone, and a cancelled or unavailable
    /// check is a denial.
    ///
    /// What it never excuses is the check itself. The reason it exists: a browser- or OS-automation
    /// agent can produce input the browser marks `isTrusted`, so "the user clicked in the page"
    /// proves nothing about a human. Touch ID, the login password or an Apple Watch does. A grant of
    /// such a request also never mints or extends a lease — `outcome_for` forces
    /// [`Grant::session`] off, whatever button a UI claims was pressed.
    pub presence_only: bool,

    // --- ADR-0036: an agent-requested browser fill. `None` for every other kind. -------------
    /// What the agent-fill sheet shows that no other sheet does. `Some` exactly when
    /// [`Self::kind`] is [`ApprovalKind::AgentFill`] — build such a request with
    /// [`Self::for_agent_fill`], which also copies the scope into the common fields above so the
    /// [`Grant`] carries it.
    pub agent_fill: Option<AgentFillFacts>,

    // --- ADR-0048: agent test logins. ---------------------------------------------------------
    /// What the test-login sheet shows that no other sheet does. `Some` exactly when
    /// [`Self::kind`] is [`ApprovalKind::CreateTestLogin`].
    pub agent_test_login: Option<TestLoginFacts>,

    // --- ADR-0049: storing a command's output. ------------------------------------------------
    /// What the store-output sheet shows that no other sheet does. `Some` exactly when
    /// [`Self::kind`] is [`ApprovalKind::StoreCommandOutput`].
    pub store_output: Option<StoreOutputFacts>,

    // --- ADR-0050: auto-type into a native app. -----------------------------------------------
    /// What the auto-type sheet shows that no other sheet does. `Some` exactly when
    /// [`Self::kind`] is [`ApprovalKind::AutoType`].
    pub auto_type: Option<AutoTypeFacts>,
    /// A `run_with_env` or `write_env_file` whose **every** selected variable is bound to a sealed
    /// test login (ADR-0048 §9): the app may answer it inside its presence grace window with no
    /// sheet and no prompt, the way it answers agent fills. Outside the window it is the ordinary
    /// sheet and Touch ID. Rust grants it exactly as any other request of its kind: the window
    /// and its clock live in the app. `false` for every other request.
    pub rides_grace: bool,

    // --- ADR-0035 §14: values from a shared vault. Empty for the personal vault. -----------
    /// Where the values come from, when that is a shared vault: `Shared vault “Ops” — 4
    /// members`. `None` for the personal vault.
    pub shared_source: Option<String>,
    /// One line per value about to be released that changed since this device last approved
    /// releasing it — or was never released from this device — naming who changed it and when:
    /// ``DATABASE_URL changed by Alice, 2 days ago``. Names, labels and times only. Empty for
    /// the personal vault, and when nothing changed.
    pub changed_since_approval: Vec<String>,
}

/// The facts an agent-fill sheet states (ADR-0036 §5), beyond the common fields.
///
/// Metadata only, like the rest of [`ApprovalRequest`]: names, paths, pids, flags and an origin.
/// No member has a type a secret value could be put in — `String`s that are names, never a
/// `Secret` or a `FillValue` — and `agent_fill_facts_have_no_member_a_value_fits_in` pins the list.
///
/// Two identity stories are told on this sheet, and the field names keep them apart: the
/// **agent** (who asked, over the MCP socket) and the **browser** (where the value would be
/// typed, over the extension socket).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentFillFacts {
    /// The agent's **self-reported** name, from MCP `clientInfo`. Render it as a quotation; it is
    /// unverified.
    pub agent_name: String,
    /// The sidecar's pid, from the kernel: the process a grant is bound to (ADR-0036,
    /// implementation decision 3).
    pub sidecar_pid: u32,
    /// The sidecar's executable, resolved from that pid.
    pub sidecar_executable: Option<String>,
    /// The sidecar's kernel audit token (macOS), what the app runs its signature check on.
    pub sidecar_audit_token: Option<String>,
    /// The sidecar's parent pid, resolved from the kernel — never the one the sidecar reports.
    /// What the app checks the code signature of, for "started by".
    pub parent_pid: Option<u32>,
    /// The sidecar's parent executable, resolved from the kernel: what "this agent" means for
    /// blocking (ADR-0036 §9.3). `None` when the kernel could not say; the sheet then says so.
    pub parent_executable: Option<String>,
    /// The item that would be filled.
    pub item_id: String,
    /// Its title, so the sheet does not show a bare uuid.
    pub item_title: String,
    /// Which fields would be written. Names, never values.
    pub fields: Vec<AgentFillField>,
    /// Whether this is page one of an identifier-first sign-in (ADR-0036 §7.3): the username is
    /// written now, and the password on the next page, in the same tab, without another sheet —
    /// the sheet says *"username now, password on the next page"*. Always `false` for a
    /// one-time code, which is its own request (§7.4).
    pub two_step: bool,
    /// The page's origin as the browser established it, split for rendering so a look-alike is
    /// obvious (registrable domain emphasized, the rest dimmed, punycode decoded beside it).
    pub page_origin: AgentOriginRendering,
    /// The saved website that covered the page, in ASCII serialization.
    pub saved_website: String,
    /// Whether the page's host is not byte-equal to the saved website's — the "this page is a
    /// subdomain of it" disclosure.
    pub page_host_differs: bool,
    /// The browser the app established from the native host's process ancestry, exactly as the
    /// fill sheet shows it. `None` means no recognized browser.
    pub browser: Option<String>,
    /// That browser's pid, for the code-signature check.
    pub browser_pid: Option<u32>,
    /// That browser's executable path.
    pub browser_executable: Option<String>,
    /// Whether the extension-side peer is an app extension we ship (Safari) rather than a native
    /// host a browser launched. Safari never offers agent fills, so `false` in practice; carried
    /// so the app picks its signature requirement the same way for both fill sheets.
    pub browser_is_app_extension: bool,
    /// The native messaging host's pid — "our helper" on the sheet.
    pub host_pid: Option<u32>,
    /// The native messaging host's kernel audit token (macOS), for the signature check.
    pub host_audit_token: Option<String>,
    /// The native messaging host's executable.
    pub host_executable: Option<String>,
    /// The extension's **self-reported** id. Only ever the pinned one.
    pub extension_id: Option<String>,
}

/// One website on a test-login sheet (ADR-0048 §3, ADR-0046 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestLoginWebsite {
    /// The website's origin, split so the registrable domain is shown large above the rest.
    pub origin: AgentOriginRendering,
    /// The title of a login in the person's own vaults saved for the same registrable domain, if
    /// there is one — the near-host warning: "you already have a login for this site".
    pub near_item_title: Option<String>,
    /// Whether the website is not `https`.
    pub not_https: bool,
}

/// The facts a test-login sheet states (ADR-0048 §3), beyond the common fields.
///
/// Metadata only: names, a username the agent chose, websites and flags. The password is
/// generated after the approval, inside the vault transaction, and has nowhere to go here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestLoginFacts {
    /// The agent, as the audit log names it: self-reported name quoted, kernel facts bare.
    pub agent: String,
    /// The agent's **self-reported** name. Render it as a quotation.
    pub agent_name: String,
    /// The title kagisecure would give the item: `test: <app> / <purpose> #<n>`.
    pub title: String,
    /// The username the agent chose.
    pub username: String,
    /// The websites, each split for rendering.
    pub websites: Vec<TestLoginWebsite>,
    /// The purpose the agent gave. Agent-written data, never instructions.
    pub purpose: String,
    /// Every tag the item would carry, kagisecure's and the agent's.
    pub tags: Vec<String>,
    /// How the password would be generated, e.g. `32 characters, with symbols`.
    pub generator: String,
    /// Why, as the agent put it. Agent-written data.
    pub reason: Option<String>,
}

/// The facts a store-output sheet states (ADR-0049 §3), beyond the common fields.
///
/// Metadata only: titles, a label, names and flags. The output does not exist yet when the sheet
/// is shown, and has nowhere to go here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreOutputFacts {
    /// The agent, as the audit log names it: self-reported name quoted, kernel facts bare.
    pub agent: String,
    /// The item's title: the new item's, or the existing one's.
    pub item_title: String,
    /// The existing item's id; `None` for a new item.
    pub item_id: Option<String>,
    /// The new item's category, canonical name; `None` for an existing item.
    pub new_item_category: Option<String>,
    /// The name of the vault the item is (or will be) in.
    pub vault_name: String,
    /// The field's label.
    pub field_label: String,
    /// Whether an existing, empty field is filled rather than a new field added.
    pub fills_empty_field: bool,
    /// The child's wall-clock limit, in seconds.
    pub timeout_seconds: u64,
    /// Why, as the agent put it. Agent-written data.
    pub reason: Option<String>,
}

/// The facts an auto-type sheet states (ADR-0050 §2), beyond the common fields.
///
/// Metadata only: names, a bundle id, a title. Nothing here has a type a value fits in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoTypeFacts {
    /// The agent, as the audit log names it: self-reported name quoted, kernel facts bare.
    pub agent: String,
    /// The item's title.
    pub item_title: String,
    /// The name of the vault the item is in.
    pub vault_name: String,
    /// The fields to type, in the order they are typed: `username`, `password`, `one_time_code`.
    pub fields: Vec<String>,
    /// The target app's bundle id, as the agent named it. The app resolves its name and icon.
    pub bundle_id: String,
    /// The signing team the agent requires, if it named one.
    pub team_id: Option<String>,
    /// The window-title substring the agent requires, if it named one. Agent-written data.
    pub window_title: Option<String>,
    /// Why, as the agent put it. Agent-written data.
    pub reason: Option<String>,
}

impl ApprovalRequest {
    /// The request for an agent's auto-type described by `facts`, of item `item_id`, from the peer
    /// behind `identity`. No lease; never presence-only; rides the presence grace window like an
    /// agent fill (ADR-0050 §2). The grant's scope is the item, the fields and — in `origin` — the
    /// target bundle id.
    #[must_use]
    pub fn for_auto_type(facts: AutoTypeFacts, item_id: String, identity: &PeerIdentity) -> Self {
        Self {
            kind: ApprovalKind::AutoType,
            origin: Some(facts.bundle_id.clone()),
            item_id: Some(item_id),
            item_title: Some(facts.item_title.clone()),
            fill_fields: facts.fields.clone(),
            requested_ttl_seconds: 0,
            requested_uses: 1,
            max_ttl_seconds: 0,
            presence_only: false,
            rides_grace: true,
            auto_type: Some(facts),
            ..Self::default()
        }
        .with_identity(identity)
    }

    /// The request for an agent's store-output run described by `facts`, running `argv` in
    /// `directory`, from the peer behind `identity`. No lease, so no lease life; never
    /// presence-only. A stdin environment is added by the caller on the common fields.
    #[must_use]
    pub fn for_store_output(
        facts: StoreOutputFacts,
        argv: Vec<String>,
        directory: String,
        identity: &PeerIdentity,
    ) -> Self {
        Self {
            kind: ApprovalKind::StoreCommandOutput,
            item_id: facts.item_id.clone(),
            item_title: Some(facts.item_title.clone()),
            command: argv,
            directory: Some(directory),
            requested_ttl_seconds: 0,
            requested_uses: 1,
            max_ttl_seconds: 0,
            presence_only: false,
            rides_grace: false,
            store_output: Some(facts),
            ..Self::default()
        }
        .with_identity(identity)
    }

    /// The request for an agent's test login described by `facts`, from the peer behind
    /// `identity`. No lease, so no lease life; never presence-only.
    #[must_use]
    pub fn for_test_login(facts: TestLoginFacts, identity: &PeerIdentity) -> Self {
        Self {
            kind: ApprovalKind::CreateTestLogin,
            item_title: Some(facts.title.clone()),
            requested_ttl_seconds: 0,
            requested_uses: 1,
            max_ttl_seconds: 0,
            presence_only: false,
            agent_test_login: Some(facts),
            ..Self::default()
        }
        .with_identity(identity)
    }

    /// The request for an agent fill described by `facts`.
    ///
    /// The scope — origin, item, field names, browser — is copied into the common fields from the
    /// facts, so what the [`Grant`] carries and what the sheet shows cannot disagree. The caller
    /// is the sidecar, so `client_*` is the sidecar: its pid from the kernel, its self-reported
    /// name. Never presence-only.
    #[must_use]
    pub fn for_agent_fill(facts: AgentFillFacts) -> Self {
        Self {
            kind: ApprovalKind::AgentFill,
            client_name: facts.agent_name.clone(),
            client_pid: Some(facts.sidecar_pid),
            client_pid_from_kernel: true,
            client_audit_token: facts.sidecar_audit_token.clone(),
            client_executable: facts.sidecar_executable.clone(),
            origin: Some(facts.page_origin.ascii()),
            item_id: Some(facts.item_id.clone()),
            item_title: Some(facts.item_title.clone()),
            fill_fields: facts.fields.iter().map(|f| f.as_str().to_owned()).collect(),
            browser: facts.browser.clone(),
            browser_pid: facts.browser_pid,
            browser_executable: facts.browser_executable.clone(),
            browser_is_app_extension: facts.browser_is_app_extension,
            extension_id: facts.extension_id.clone(),
            // No lease, so no lease life to show or to clamp.
            requested_ttl_seconds: 0,
            requested_uses: 1,
            max_ttl_seconds: 0,
            presence_only: false,
            agent_fill: Some(facts),
            ..Self::default()
        }
    }

    /// Fill in the caller-identity fields from what the kernel and the handshake said.
    pub fn with_identity(mut self, identity: &PeerIdentity) -> Self {
        self.client_name = identity
            .reported
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |c| c.name.clone());
        self.client_pid = identity.pid;
        self.client_pid_from_kernel = identity.pid_from_kernel;
        self.client_audit_token = identity.audit_token.clone();
        self.client_executable = identity.executable.clone();
        self.client_cwd = identity.reported.as_ref().and_then(|c| c.cwd.clone());
        self
    }
}

impl Default for ApprovalRequest {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: ApprovalKind::WriteEnvFile,
            client_name: "unknown".to_owned(),
            client_pid: None,
            client_pid_from_kernel: false,
            client_audit_token: None,
            client_executable: None,
            client_cwd: None,
            environment_id: None,
            environment_name: None,
            directory: None,
            target_path: None,
            variables: Vec::new(),
            command: Vec::new(),
            stdin_delivery: false,
            gitignored: None,
            overwrite_requested: false,
            target_exists: None,
            target_written_by_us: None,
            requested_ttl_seconds: kagisecure_core::lease::DEFAULT_TTL_SECONDS,
            requested_uses: kagisecure_core::lease::DEFAULT_USES,
            max_ttl_seconds: kagisecure_core::lease::MAX_TTL_SECONDS,
            created_at: 0,
            expires_at: 0,
            origin: None,
            top_origin: None,
            top_origin_unknown: false,
            item_id: None,
            item_title: None,
            fill_fields: Vec::new(),
            browser: None,
            browser_pid: None,
            browser_executable: None,
            browser_is_app_extension: false,
            extension_id: None,
            presence_only: false,
            agent_fill: None,
            agent_test_login: None,
            store_output: None,
            auto_type: None,
            rides_grace: false,
            shared_source: None,
            changed_since_approval: Vec::new(),
        }
    }
}

/// What the app learned about the caller by checking its code signature.
///
/// Rust cannot do this check: it needs `SecCodeCopyGuestWithAttributes`, which lives in
/// Security.framework and would drag platform integration into the shared core (the layering rule
/// in architecture.md §2.5, and the same argument ADR-0008 makes for the Secure Enclave). So the
/// app performs it, shows the verdict on the sheet, and hands it back here to be written into the
/// lease and the audit entry. The value travels app → Rust, like every other FFI call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientVerification {
    /// Whether the peer's signature checked out against the app's requirement.
    pub verified: bool,
    /// One line of human-readable evidence — a signing identifier, a team id, or why not.
    pub evidence: String,
}

impl ClientVerification {
    /// The honest answer when nobody looked.
    #[must_use]
    pub fn unchecked() -> Self {
        Self {
            verified: false,
            evidence: "code signature not checked".to_owned(),
        }
    }
}

/// What the human said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Mint a single-use lease (ui-spec.md §10.3). The next identical request re-prompts.
    AllowOnce,
    /// Mint a lease for `ttl_seconds` and `uses`, both bounded by what the request asked for.
    AllowSession {
        /// Seconds, clamped to the request's ceiling.
        ttl_seconds: u64,
        /// Uses, clamped to the request's ceiling.
        uses: u32,
    },
    /// Refuse. Returns `USER_DENIED` with no partial write.
    Deny,
    /// Refuse, and refuse every agent fill from the same agent for the next thirty minutes
    /// without asking (ADR-0036 §9.3). Returns `USER_DENIED`, and [`Outcome::block_agent`] tells
    /// the agent-fill broker to set the block.
    ///
    /// Only an [`ApprovalKind::AgentFill`] sheet offers it. For any other request it is exactly
    /// [`Self::Deny`]: there is no block for a caller of the other tools to be put under.
    DenyAndBlock,
}

/// The answer an IPC thread gets back.
///
/// Only this module can make one: `Self::grant` is private, so a struct literal outside it does
/// not compile. That is what makes a [`Grant`] mean something — the only `Outcome` that carries one
/// is the one [`ApprovalQueue::ask`] returned for a request somebody [resolved](ApprovalQueue::resolve)
/// with an allow.
#[derive(Debug)]
pub struct Outcome {
    /// Whether to proceed.
    pub granted: bool,
    /// Which error code a refusal maps to.
    pub code: ErrorCode,
    /// The lease TTL the human agreed to.
    pub ttl_seconds: u64,
    /// The lease use count the human agreed to.
    pub uses: u32,
    /// What the app said about the caller's signature.
    pub verification: ClientVerification,
    /// Whether the human pressed **Allow for this session** rather than **Allow once**.
    ///
    /// The env channel does not need this — "once" is expressed there as `uses = 1` — but the
    /// fill channel has no use counter, so "once" and "for this session" differ only in whether a
    /// lease is minted at all. Rather than have the extension service infer that from a use count
    /// that means nothing to it, the queue says which button was pressed.
    ///
    /// Always `false` for a [presence-only](ApprovalRequest::presence_only) request.
    pub session: bool,
    /// Whether the human pressed **Deny and block this agent** ([`Decision::DenyAndBlock`]) on an
    /// agent-fill sheet. Always `false` for every other kind of request, and for any grant.
    pub block_agent: bool,
    /// The proof, when there is one. `Some` exactly when [`Self::granted`] is true.
    ///
    /// Private on purpose — see the type's documentation. The public fields above are a readout for
    /// the MCP channel and for tests; a caller that releases a value takes the [`Grant`] with
    /// [`Self::into_grant`] instead, because a readout can be edited and a `Grant` cannot.
    grant: Option<Grant>,
}

impl Outcome {
    fn refused(code: ErrorCode, verification: ClientVerification) -> Self {
        Self {
            granted: false,
            code,
            ttl_seconds: 0,
            uses: 0,
            verification,
            session: false,
            block_agent: false,
            grant: None,
        }
    }

    /// The grant, or why there is none.
    ///
    /// # Errors
    ///
    /// [`Self::code`] when the request was refused, timed out or swept by a lock, so the caller
    /// can say which.
    pub fn into_grant(self) -> Result<Grant, ErrorCode> {
        self.grant.ok_or(self.code)
    }
}

/// Proof that a human granted one specific [`ApprovalRequest`].
///
/// # Why this is a type rather than a `bool`
///
/// The invariant the browser channel rests on is *every response that carries a secret comes from
/// a granted `ask`, and every grant in the app went through the biometric gate*
/// ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)). A
/// `granted: bool`, or an early return that skips `ask` because some other state said "fine",
/// satisfies the compiler just as well as the real thing; the lease short-circuit that ADR-0037
/// removed was exactly that. A `Grant` cannot be made up:
///
/// * its fields are private and it has no public constructor, so only this module can build one;
/// * this module builds one in exactly one place, `outcome_for`, for a [`Decision::AllowOnce`] or
///   [`Decision::AllowSession`] handed to [`ApprovalQueue::resolve`] — which the app calls only
///   after `LAContext.evaluatePolicy` succeeded (`AgentService.allow`);
/// * it is not `Clone`, so one grant is one crossing, not a token to keep;
/// * it carries the scope the human was shown, copied from the request, so the code that builds a
///   value can check that it is building the value that was approved rather than trusting that the
///   two agree.
#[derive(Debug, PartialEq, Eq)]
pub struct Grant {
    kind: ApprovalKind,
    origin: Option<String>,
    item_id: Option<String>,
    fill_fields: Vec<String>,
    presence_only: bool,
    session: bool,
    ttl_seconds: u64,
    verification: ClientVerification,
}

impl Grant {
    /// What kind of request was granted.
    #[must_use]
    pub fn kind(&self) -> ApprovalKind {
        self.kind
    }

    /// The origin the human was shown, for a fill.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// The item the human was shown, for a fill.
    #[must_use]
    pub fn item_id(&self) -> Option<&str> {
        self.item_id.as_deref()
    }

    /// The field names the human was shown, for a fill: `username`, `password`,
    /// `one-time password`.
    #[must_use]
    pub fn fill_fields(&self) -> &[String] {
        &self.fill_fields
    }

    /// Whether this was a [presence-only](ApprovalRequest::presence_only) confirmation rather than a
    /// review at a full sheet.
    #[must_use]
    pub fn presence_only(&self) -> bool {
        self.presence_only
    }

    /// Whether the human pressed **Allow for this session**. Never true for a presence-only grant.
    #[must_use]
    pub fn session(&self) -> bool {
        self.session
    }

    /// The lease life the human agreed to, already clamped to the request's ceiling.
    #[must_use]
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// What the app said about the caller's signature when it granted this.
    #[must_use]
    pub fn verification(&self) -> &ClientVerification {
        &self.verification
    }
}

/// One question waiting for an answer.
struct Pending {
    request: ApprovalRequest,
    answer: Option<Outcome>,
    /// Set once [`ApprovalQueue::next`] has handed this out, so a slow UI does not get it twice.
    delivered: bool,
}

/// The queue itself.
#[derive(Default)]
pub struct ApprovalQueue {
    state: Mutex<QueueState>,
    /// Signalled when a request arrives (for `next`) or is answered (for `ask`).
    signal: Condvar,
}

#[derive(Default)]
struct QueueState {
    pending: VecDeque<Pending>,
    next_id: u64,
    /// Set by [`ApprovalQueue::deny_all`] so a request that arrives during a lock is refused
    /// rather than parked forever.
    closed: bool,
}

impl std::fmt::Debug for ApprovalQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalQueue")
            .field("waiting", &self.waiting())
            .finish()
    }
}

impl ApprovalQueue {
    /// An empty, open queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many questions are waiting for a human. Drives the menu-bar badge.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.state().pending.len()
    }

    /// Ask, and block until somebody answers or 60 seconds pass.
    ///
    /// `request.id` is assigned here, not by the caller, so an id cannot be forged or reused.
    #[must_use]
    pub fn ask(&self, mut request: ApprovalRequest) -> Outcome {
        let deadline = std::time::Instant::now() + Duration::from_secs(APPROVAL_TIMEOUT_SECONDS);
        let id = {
            let mut state = self.state();
            if state.closed {
                return Outcome::refused(ErrorCode::VaultLocked, ClientVerification::unchecked());
            }
            state.next_id = state.next_id.wrapping_add(1);
            let id = format!("req-{}", state.next_id);
            request.id.clone_from(&id);
            // An agent fill is always the full sheet (ADR-0036 §5): cleared here, before the UI
            // can see it, as well as in `outcome_for`, so a caller that set it by mistake cannot
            // turn the sheet into a bare presence prompt.
            if request.kind.single_review() {
                request.presence_only = false;
                // No grace window for these: every one is its own review (ADR-0049 §3).
                if request.kind == ApprovalKind::StoreCommandOutput {
                    request.rides_grace = false;
                }
            }
            request.created_at = kagisecure_core::unix_now();
            request.expires_at = request.created_at + APPROVAL_TIMEOUT_SECONDS;
            state.pending.push_back(Pending {
                request,
                answer: None,
                delivered: false,
            });
            id
        };
        self.signal.notify_all();

        let mut state = self.state();
        loop {
            let position = state.pending.iter().position(|p| p.request.id == id);
            match position {
                None => {
                    // Removed without an answer: `deny_all` swept it, which is a lock.
                    return Outcome::refused(
                        ErrorCode::VaultLocked,
                        ClientVerification::unchecked(),
                    );
                }
                Some(index) if state.pending[index].answer.is_some() => {
                    let pending = state.pending.remove(index).expect("index just checked");
                    return pending.answer.expect("checked");
                }
                Some(_) => {}
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                if let Some(index) = state.pending.iter().position(|p| p.request.id == id) {
                    state.pending.remove(index);
                }
                return Outcome::refused(
                    ErrorCode::ApprovalTimeout,
                    ClientVerification::unchecked(),
                );
            }
            let (next, _) = self
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            state = next;
        }
    }

    /// Take the next undelivered request, waiting up to `timeout` for one to arrive.
    ///
    /// This is the call the app makes in a loop from a background task. It blocks, on purpose:
    /// a blocking sync call is what UniFFI does well, and a busy poll would be the alternative.
    #[must_use]
    pub fn next(&self, timeout: Duration) -> Option<ApprovalRequest> {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.state();
        loop {
            if let Some(pending) = state.pending.iter_mut().find(|p| !p.delivered) {
                pending.delivered = true;
                return Some(pending.request.clone());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, _) = self
                .signal
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            state = next;
        }
    }

    /// Everything currently waiting, delivered or not — for a "pending requests" list.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ApprovalRequest> {
        self.state()
            .pending
            .iter()
            .map(|p| p.request.clone())
            .collect()
    }

    /// Answer one request.
    ///
    /// Returns `false` if the id is unknown or already answered — which is the normal outcome of
    /// resolving a request that timed out while the user was thinking, and is not an error.
    pub fn resolve(&self, id: &str, decision: &Decision, verification: ClientVerification) -> bool {
        let answered = {
            let mut state = self.state();
            match state
                .pending
                .iter_mut()
                .find(|p| p.request.id == id && p.answer.is_none())
            {
                None => false,
                Some(pending) => {
                    pending.answer = Some(outcome_for(&pending.request, decision, verification));
                    true
                }
            }
        };
        if answered {
            self.signal.notify_all();
        }
        answered
    }

    /// Refuse everything outstanding and refuse everything that arrives afterwards.
    ///
    /// Called when the vault locks. `code` is `VAULT_LOCKED`, not `USER_DENIED`: the user did not
    /// decline, the vault went away, and the model should be told to ask for an unlock rather
    /// than to give up (mcp-server.md §7).
    pub fn deny_all(&self) {
        {
            let mut state = self.state();
            state.closed = true;
            state.pending.clear();
        }
        self.signal.notify_all();
    }

    /// Accept questions again, after an unlock.
    pub fn reopen(&self) {
        self.state().closed = false;
    }
}

/// Turn a decision into the bounded grant it authorizes.
///
/// The clamping is the enforcement of "the user may shorten the TTL but not lengthen it beyond
/// the tool's max" (ui-spec.md §10.2). It happens here, once, rather than in each UI.
///
/// This is also the **only** place a [`Grant`] is constructed. A presence-only request is granted
/// as "once" whichever allow the UI sent: a presence confirmation proves a human is there, it does
/// not re-review the scope, so it must not be able to mint or extend the memory of a review
/// (ADR-0037).
///
/// An [`ApprovalKind::AgentFill`] is clamped harder still (ADR-0036 §5, §6): it is never
/// presence-only, "for this session" is "once", and it carries no lease life — there is no lease
/// to mint, whichever button a UI claims was pressed.
///
/// A `run_with_env` with [`ApprovalRequest::stdin_delivery`] is likewise always "once": one
/// approval, one run (ADR-0047).
fn outcome_for(
    request: &ApprovalRequest,
    decision: &Decision,
    verification: ClientVerification,
) -> Outcome {
    // An agent's test login is clamped exactly as an agent fill is (ADR-0048 §3): one review,
    // once, no lease, never presence-only.
    // So is a store-output run (ADR-0049 §3).
    let agent_fill = request.kind.single_review();
    let (ttl_seconds, uses, session) = match decision {
        Decision::Deny => return Outcome::refused(ErrorCode::UserDenied, verification),
        Decision::DenyAndBlock => {
            return Outcome {
                block_agent: matches!(
                    request.kind,
                    ApprovalKind::AgentFill | ApprovalKind::AutoType
                ),
                ..Outcome::refused(ErrorCode::UserDenied, verification)
            };
        }
        Decision::AllowOnce | Decision::AllowSession { .. } if agent_fill => (0, 1, false),
        // One run, one approval (ADR-0047): the lease exists only to carry this run's id.
        Decision::AllowOnce | Decision::AllowSession { .. } if request.stdin_delivery => (
            request.requested_ttl_seconds.min(request.max_ttl_seconds),
            1,
            false,
        ),
        Decision::AllowOnce => (
            request.requested_ttl_seconds.min(request.max_ttl_seconds),
            1,
            false,
        ),
        Decision::AllowSession { ttl_seconds, uses } => (
            (*ttl_seconds)
                .min(request.max_ttl_seconds)
                .min(request.requested_ttl_seconds.max(1)),
            (*uses).min(request.requested_uses).max(1),
            true,
        ),
    };
    let presence_only = request.presence_only && !agent_fill;
    let session = session && !request.presence_only;
    Outcome {
        granted: true,
        code: ErrorCode::Internal,
        ttl_seconds,
        uses,
        verification: verification.clone(),
        session,
        block_agent: false,
        grant: Some(Grant {
            kind: request.kind,
            origin: request.origin.clone(),
            item_id: request.item_id.clone(),
            fill_fields: request.fill_fields.clone(),
            presence_only,
            session,
            ttl_seconds,
            verification,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            kind: ApprovalKind::WriteEnvFile,
            variables: vec!["TOKEN".to_owned()],
            requested_ttl_seconds: 900,
            requested_uses: 10,
            ..ApprovalRequest::default()
        }
    }

    fn verified() -> ClientVerification {
        ClientVerification {
            verified: true,
            evidence: "test".to_owned(),
        }
    }

    #[test]
    fn a_request_reaches_the_ui_and_its_answer_reaches_the_asker() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));

        let delivered = queue
            .next(Duration::from_secs(5))
            .expect("the request should reach the UI");
        assert_eq!(delivered.variables, vec!["TOKEN".to_owned()]);
        assert!(queue.resolve(
            &delivered.id,
            &Decision::AllowSession {
                ttl_seconds: 300,
                uses: 3
            },
            verified()
        ));

        let outcome = thread.join().expect("asker thread");
        assert!(outcome.granted);
        assert_eq!(outcome.ttl_seconds, 300);
        assert_eq!(outcome.uses, 3);
        assert!(outcome.verification.verified);
    }

    #[test]
    fn allow_once_is_a_single_use_lease_whatever_the_agent_asked_for() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        queue.resolve(&delivered.id, &Decision::AllowOnce, verified());
        let outcome = thread.join().expect("asker");
        assert!(outcome.granted);
        assert_eq!(outcome.uses, 1, "allow once means once");
        assert_eq!(outcome.ttl_seconds, 900);
    }

    #[test]
    fn a_user_may_shorten_a_lease_but_never_lengthen_it() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        queue.resolve(
            &delivered.id,
            &Decision::AllowSession {
                ttl_seconds: 86_400 * 7,
                uses: 9_999,
            },
            verified(),
        );
        let outcome = thread.join().expect("asker");
        assert_eq!(
            outcome.ttl_seconds, 900,
            "a UI cannot grant more than the agent asked for"
        );
        assert_eq!(outcome.uses, 10);
    }

    #[test]
    fn denial_is_user_denied() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        queue.resolve(
            &delivered.id,
            &Decision::Deny,
            ClientVerification::unchecked(),
        );
        let outcome = thread.join().expect("asker");
        assert!(!outcome.granted);
        assert_eq!(outcome.code, ErrorCode::UserDenied);
    }

    #[test]
    fn locking_the_vault_denies_everything_waiting() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));
        // Wait for it to be queued before sweeping, so the test asserts the sweep and not a race.
        let _ = queue.next(Duration::from_secs(5)).expect("delivered");
        queue.deny_all();
        let outcome = thread.join().expect("asker");
        assert!(!outcome.granted);
        assert_eq!(outcome.code, ErrorCode::VaultLocked);
        assert_eq!(queue.waiting(), 0);
    }

    #[test]
    fn a_request_made_while_locked_is_refused_at_once() {
        let queue = ApprovalQueue::new();
        queue.deny_all();
        let outcome = queue.ask(request());
        assert_eq!(outcome.code, ErrorCode::VaultLocked);
        queue.reopen();
        assert_eq!(queue.waiting(), 0);
    }

    #[test]
    fn next_hands_each_request_out_once() {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request()));
        let first = queue.next(Duration::from_secs(5));
        assert!(first.is_some());
        let second = queue.next(Duration::from_millis(50));
        assert!(second.is_none(), "a delivered request is not re-delivered");
        assert_eq!(queue.snapshot().len(), 1, "but it is still outstanding");
        queue.deny_all();
        let _ = thread.join();
    }

    #[test]
    fn resolving_an_unknown_id_is_false_rather_than_a_panic() {
        let queue = ApprovalQueue::new();
        assert!(!queue.resolve("req-nope", &Decision::AllowOnce, verified()));
    }

    fn fill_request(presence_only: bool) -> ApprovalRequest {
        ApprovalRequest {
            kind: ApprovalKind::FillCredential,
            origin: Some("https://example.com".to_owned()),
            item_id: Some("item-1".to_owned()),
            fill_fields: vec!["password".to_owned()],
            requested_ttl_seconds: 300,
            requested_uses: 1,
            max_ttl_seconds: 900,
            presence_only,
            ..ApprovalRequest::default()
        }
    }

    fn answer(request: ApprovalRequest, decision: &Decision) -> Outcome {
        let queue = Arc::new(ApprovalQueue::new());
        let asker = Arc::clone(&queue);
        let thread = std::thread::spawn(move || asker.ask(request));
        let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
        assert!(queue.resolve(&delivered.id, decision, verified()));
        thread.join().expect("asker")
    }

    #[test]
    fn deny_and_block_is_a_denial_that_marks_only_an_agent_fill() {
        let blocked = answer(
            ApprovalRequest::for_agent_fill(agent_fill_facts()),
            &Decision::DenyAndBlock,
        );
        assert!(!blocked.granted);
        assert!(blocked.block_agent, "the broker is told to set the block");
        assert_eq!(blocked.into_grant().unwrap_err(), ErrorCode::UserDenied);

        // Any other sheet has no agent block to set: it is a plain denial.
        let other = answer(fill_request(false), &Decision::DenyAndBlock);
        assert!(!other.granted);
        assert!(!other.block_agent);
        assert_eq!(other.into_grant().unwrap_err(), ErrorCode::UserDenied);

        let denied = answer(
            ApprovalRequest::for_agent_fill(agent_fill_facts()),
            &Decision::Deny,
        );
        assert!(!denied.block_agent, "a plain denial blocks nothing");
    }

    #[test]
    fn a_grant_carries_the_scope_the_human_was_shown() {
        let grant = answer(fill_request(false), &Decision::AllowOnce)
            .into_grant()
            .expect("allow once is a grant");
        assert_eq!(grant.kind(), ApprovalKind::FillCredential);
        assert_eq!(grant.origin(), Some("https://example.com"));
        assert_eq!(grant.item_id(), Some("item-1"));
        assert_eq!(grant.fill_fields(), ["password".to_owned()]);
        assert!(!grant.presence_only());
        assert!(!grant.session(), "allow once is not a session");
        assert!(grant.verification().verified);
    }

    #[test]
    fn a_refusal_carries_no_grant() {
        let outcome = answer(fill_request(false), &Decision::Deny);
        assert!(!outcome.granted);
        let refused = outcome.into_grant().expect_err("a denial is not a grant");
        assert_eq!(refused, ErrorCode::UserDenied);

        let queue = ApprovalQueue::new();
        queue.deny_all();
        assert!(
            queue.ask(fill_request(true)).into_grant().is_err(),
            "a lock is not a grant"
        );
    }

    #[test]
    fn a_presence_confirmation_is_never_a_session_whatever_the_ui_pressed() {
        // A UI that answers a presence-only prompt with "Allow for this session" — by mistake, or
        // because it was told to — must not be able to extend the memory of a review with it.
        let outcome = answer(
            fill_request(true),
            &Decision::AllowSession {
                ttl_seconds: 900,
                uses: 5,
            },
        );
        assert!(outcome.granted);
        assert!(!outcome.session, "the readout says once");
        let grant = outcome.into_grant().expect("granted");
        assert!(grant.presence_only());
        assert!(!grant.session(), "and so does the grant");

        // The same answer to a full review is a session, so the clamp is about presence_only and
        // nothing else.
        let reviewed = answer(
            fill_request(false),
            &Decision::AllowSession {
                ttl_seconds: 900,
                uses: 5,
            },
        )
        .into_grant()
        .expect("granted");
        assert!(reviewed.session());
        assert_eq!(reviewed.ttl_seconds(), 300, "clamped to what was requested");
    }

    /// An agent-fill request for `login.example.com`, covered by `https://example.com`.
    fn agent_fill_facts() -> AgentFillFacts {
        let origin = kagisecure_extension_ipc::origin::Origin::parse("https://login.example.com")
            .expect("a valid origin");
        AgentFillFacts {
            agent_name: "example-agent".to_owned(),
            sidecar_pid: 51_234,
            sidecar_executable: Some("/usr/local/bin/kagisecure-mcp".to_owned()),
            sidecar_audit_token: None,
            parent_pid: Some(51_200),
            parent_executable: Some("/path/to/client".to_owned()),
            item_id: "item-1".to_owned(),
            item_title: "Example (work)".to_owned(),
            fields: vec![AgentFillField::Username, AgentFillField::Password],
            two_step: false,
            page_origin: AgentOriginRendering::of(&origin),
            saved_website: "https://example.com".to_owned(),
            page_host_differs: true,
            browser: Some("Google Chrome".to_owned()),
            browser_pid: Some(400),
            browser_executable: Some("/Applications/Google Chrome.app".to_owned()),
            browser_is_app_extension: false,
            host_pid: Some(401),
            host_audit_token: None,
            host_executable: Some("/Applications/Kagisecure.app/kagisecure-nmhost".to_owned()),
            extension_id: Some("abcdefghijklmnopabcdefghijklmnop".to_owned()),
        }
    }

    #[test]
    fn an_agent_fill_request_carries_its_scope_in_the_common_fields_too() {
        let request = ApprovalRequest::for_agent_fill(agent_fill_facts());
        assert_eq!(request.kind, ApprovalKind::AgentFill);
        assert_eq!(request.origin.as_deref(), Some("https://login.example.com"));
        assert_eq!(request.item_id.as_deref(), Some("item-1"));
        assert_eq!(request.fill_fields, ["username", "password"]);
        assert_eq!(request.client_name, "example-agent");
        assert_eq!(request.client_pid, Some(51_234));
        assert!(!request.presence_only);
        assert_eq!(request.agent_fill, Some(agent_fill_facts()));
        assert!(!request.kind.mints_lease());
        assert!(!request.kind.mints_fill_lease());
        assert_eq!(request.kind.tool(), "request_fill");
    }

    #[test]
    fn an_agent_fill_grant_is_never_a_session_or_presence_only() {
        // A caller that marks the request presence-only, and a UI that answers it "for this
        // session": neither may turn an agent fill into anything but one full review, once.
        for decision in [
            Decision::AllowOnce,
            Decision::AllowSession {
                ttl_seconds: 900,
                uses: 5,
            },
        ] {
            let request = ApprovalRequest {
                presence_only: true,
                ..ApprovalRequest::for_agent_fill(agent_fill_facts())
            };
            let queue = Arc::new(ApprovalQueue::new());
            let asker = Arc::clone(&queue);
            let thread = std::thread::spawn(move || asker.ask(request));
            let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
            assert!(
                !delivered.presence_only,
                "the UI must be handed a full sheet, not a presence prompt"
            );
            assert!(queue.resolve(&delivered.id, &decision, verified()));
            let outcome = thread.join().expect("asker");

            assert!(outcome.granted);
            assert!(!outcome.session, "{decision:?} is once for an agent fill");
            assert_eq!(outcome.ttl_seconds, 0, "there is no lease life to agree to");
            let grant = outcome.into_grant().expect("granted");
            assert_eq!(grant.kind(), ApprovalKind::AgentFill);
            assert!(!grant.presence_only(), "{decision:?}");
            assert!(!grant.session(), "{decision:?}");
            assert_eq!(grant.ttl_seconds(), 0);
            assert!(!grant.kind().mints_lease() && !grant.kind().mints_fill_lease());
            assert_eq!(grant.origin(), Some("https://login.example.com"));
            assert_eq!(grant.item_id(), Some("item-1"));
        }
    }

    /// `AgentFillFacts` is what a human reads before approving an agent fill, and it reaches the
    /// app across the FFI. Like the rest of [`ApprovalRequest`] it must have no member a value
    /// could be put in. The destructuring below names every member with no `..`, so a new one is
    /// a compile error here, and whoever adds it has to extend the type check with it.
    #[test]
    fn agent_fill_facts_have_no_member_a_value_fits_in() {
        fn type_of<T>(_: &T) -> &'static str {
            std::any::type_name::<T>()
        }
        let AgentFillFacts {
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
        } = agent_fill_facts();
        let AgentOriginRendering {
            scheme,
            dimmed_prefix,
            emphasized,
            port,
            unicode_host,
            mixed_script,
            not_encrypted,
        } = page_origin;
        let types = [
            type_of(&agent_name),
            type_of(&sidecar_pid),
            type_of(&sidecar_executable),
            type_of(&sidecar_audit_token),
            type_of(&parent_pid),
            type_of(&parent_executable),
            type_of(&item_id),
            type_of(&item_title),
            type_of(&fields),
            type_of(&two_step),
            type_of(&saved_website),
            type_of(&page_host_differs),
            type_of(&browser),
            type_of(&browser_pid),
            type_of(&browser_executable),
            type_of(&browser_is_app_extension),
            type_of(&host_pid),
            type_of(&host_audit_token),
            type_of(&host_executable),
            type_of(&extension_id),
            type_of(&scheme),
            type_of(&dimmed_prefix),
            type_of(&emphasized),
            type_of(&port),
            type_of(&unicode_host),
            type_of(&mixed_script),
            type_of(&not_encrypted),
        ];
        for ty in types {
            for forbidden in ["Secret", "FillValue", "Zeroizing", "Vec<u8>", "Item"] {
                assert!(
                    !ty.contains(forbidden),
                    "an agent-fill fact has type {ty}, which could hold a value"
                );
            }
        }
        // The one list is of field *names*: an enum with no payload.
        assert_eq!(
            type_of(&fields),
            "alloc::vec::Vec<kagisecure_ipc::protocol::AgentFillField>"
        );
    }

    #[test]
    fn next_returns_nothing_when_nothing_is_waiting() {
        let queue = ApprovalQueue::new();
        assert!(queue.next(Duration::from_millis(20)).is_none());
    }

    #[test]
    fn a_test_login_grant_is_once_mints_nothing_and_is_never_presence_only() {
        for decision in [
            Decision::AllowOnce,
            Decision::AllowSession {
                ttl_seconds: 900,
                uses: 5,
            },
            Decision::DenyAndBlock,
        ] {
            let request = ApprovalRequest {
                kind: ApprovalKind::CreateTestLogin,
                presence_only: true,
                requested_ttl_seconds: 0,
                max_ttl_seconds: 0,
                ..ApprovalRequest::default()
            };
            let queue = Arc::new(ApprovalQueue::new());
            let asker = Arc::clone(&queue);
            let thread = std::thread::spawn(move || asker.ask(request));
            let delivered = queue.next(Duration::from_secs(5)).expect("delivered");
            assert!(!delivered.presence_only);
            assert!(queue.resolve(&delivered.id, &decision, verified()));
            let outcome = thread.join().expect("asker");
            if decision == Decision::DenyAndBlock {
                assert!(!outcome.granted);
                assert!(!outcome.block_agent, "there is no block for this kind");
                continue;
            }
            assert!(!outcome.session);
            assert_eq!(outcome.uses, 1);
            assert_eq!(outcome.ttl_seconds, 0);
            let grant = outcome.into_grant().expect("granted");
            assert!(!grant.presence_only() && !grant.session());
            assert!(!grant.kind().mints_lease() && !grant.kind().mints_fill_lease());
        }
        assert_eq!(ApprovalKind::CreateTestLogin.tool(), "create_test_login");
    }
}
