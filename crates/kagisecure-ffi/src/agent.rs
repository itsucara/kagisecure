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

use kagisecure_agent::approval::{ApprovalKind, ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::browser_setup;
use kagisecure_agent::{Agent, AgentConfig, ExtensionAgent, ExtensionConfig};
use kagisecure_core::proto::LeaseId;

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
}

impl From<ApprovalKind> for ApprovalAction {
    fn from(kind: ApprovalKind) -> Self {
        match kind {
            ApprovalKind::CreateEnvironment => Self::CreateEnvironment,
            ApprovalKind::AddVariables => Self::AddVariables,
            ApprovalKind::WriteEnvFile => Self::WriteEnvFile,
            ApprovalKind::RunWithEnv => Self::RunWithEnv,
            ApprovalKind::FillCredential => Self::FillCredential,
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
    /// `Some(false)` is the red "not gitignored" callout; `None` means not in a work tree.
    pub gitignored: Option<bool>,
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
    /// The top-level page's origin when it differs from [`Self::origin`] — the signal the sheet
    /// turns into "this form is inside a frame on another site".
    pub top_origin: Option<String>,
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
            client_executable: r.client_executable,
            client_cwd: r.client_cwd,
            environment_id: r.environment_id,
            environment_name: r.environment_name,
            directory: r.directory,
            target_path: r.target_path,
            variables: r.variables,
            command: r.command,
            gitignored: r.gitignored,
            requested_ttl_seconds: r.requested_ttl_seconds,
            requested_uses: r.requested_uses,
            max_ttl_seconds: r.max_ttl_seconds,
            created_at: r.created_at,
            expires_at: r.expires_at,
            origin: r.origin,
            top_origin: r.top_origin,
            item_id: r.item_id,
            item_title: r.item_title,
            fill_fields: r.fill_fields,
            browser: r.browser,
            browser_pid: r.browser_pid,
            browser_executable: r.browser_executable,
            browser_is_app_extension: r.browser_is_app_extension,
            extension_id: r.extension_id,
        }
    }
}

/// The three buttons on the sheet (ui-spec.md §10.3). There is no "always allow".
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
}

impl From<ApprovalDecision> for Decision {
    fn from(d: ApprovalDecision) -> Self {
        match d {
            ApprovalDecision::AllowOnce => Self::AllowOnce,
            ApprovalDecision::AllowSession { ttl_seconds, uses } => {
                Self::AllowSession { ttl_seconds, uses }
            }
            ApprovalDecision::Deny => Self::Deny,
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

/// Bind the IPC socket and start serving agents from `session`'s vault.
///
/// `socket_path` overrides the per-user default (architecture.md §4.2); pass `None` in the app.
/// Returns the endpoint it bound, for the "Set up your agent" screen.
///
/// # Errors
///
/// [`FfiError::Invalid`] with a message written for a human when another kagisecure already holds
/// the socket, or when this process has already started an agent.
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
        socket_path: socket_path.map(std::path::PathBuf::from),
        queue: Some(Arc::clone(&QUEUE)),
    };
    let started =
        Agent::start(session.handle(), &config).map_err(|e| FfiError::invalid(e.to_string()))?;
    let endpoint = started.endpoint();
    *slot = Some(started);
    Ok(endpoint)
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

/// Whether something asked the vault to lock over IPC (`kagisecure lock`), clearing the flag.
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
/// socket or this process has already started a listener.
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
        socket_path: socket_path.map(std::path::PathBuf::from),
        safari_socket_path: safari_socket_path.map(std::path::PathBuf::from),
        team_id,
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
    })
    .map_err(|message| FfiError::Io { message })
}

#[cfg(test)]
mod tests {
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
            assert!(manifest.path.ends_with("com.kagisecure.nmhost.json"));
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
    }
}
