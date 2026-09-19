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

use kagisecure_ipc::protocol::ErrorCode;
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
}

impl ApprovalKind {
    /// Whether granting this mints a lease.
    #[must_use]
    pub fn mints_lease(self) -> bool {
        matches!(self, Self::WriteEnvFile | Self::RunWithEnv)
    }

    /// Whether granting this mints a **fill** lease, which is a different store with different
    /// scoping rules — see the variant documentation.
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
    /// The top-level page's origin, when it differs from [`Self::origin`]. `Some` here is the
    /// visible signal that the form is in a third party's frame.
    pub top_origin: Option<String>,
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
}

impl ApprovalRequest {
    /// Fill in the caller-identity fields from what the kernel and the handshake said.
    pub fn with_identity(mut self, identity: &PeerIdentity) -> Self {
        self.client_name = identity
            .reported
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |c| c.name.clone());
        self.client_pid = identity.pid;
        self.client_pid_from_kernel = identity.pid_from_kernel;
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
            client_executable: None,
            client_cwd: None,
            environment_id: None,
            environment_name: None,
            directory: None,
            target_path: None,
            variables: Vec::new(),
            command: Vec::new(),
            gitignored: None,
            requested_ttl_seconds: kagisecure_core::lease::DEFAULT_TTL_SECONDS,
            requested_uses: kagisecure_core::lease::DEFAULT_USES,
            max_ttl_seconds: kagisecure_core::lease::MAX_TTL_SECONDS,
            created_at: 0,
            expires_at: 0,
            origin: None,
            top_origin: None,
            item_id: None,
            item_title: None,
            fill_fields: Vec::new(),
            browser: None,
            browser_pid: None,
            browser_executable: None,
            browser_is_app_extension: false,
            extension_id: None,
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
}

/// The answer an IPC thread gets back.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub session: bool,
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
        }
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
fn outcome_for(
    request: &ApprovalRequest,
    decision: &Decision,
    verification: ClientVerification,
) -> Outcome {
    match decision {
        Decision::Deny => Outcome::refused(ErrorCode::UserDenied, verification),
        Decision::AllowOnce => Outcome {
            granted: true,
            code: ErrorCode::Internal,
            ttl_seconds: request.requested_ttl_seconds.min(request.max_ttl_seconds),
            uses: 1,
            verification,
            session: false,
        },
        Decision::AllowSession { ttl_seconds, uses } => Outcome {
            granted: true,
            code: ErrorCode::Internal,
            ttl_seconds: (*ttl_seconds)
                .min(request.max_ttl_seconds)
                .min(request.requested_ttl_seconds.max(1)),
            uses: (*uses).min(request.requested_uses).max(1),
            verification,
            session: true,
        },
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

    #[test]
    fn next_returns_nothing_when_nothing_is_waiting() {
        let queue = ApprovalQueue::new();
        assert!(queue.next(Duration::from_millis(20)).is_none());
    }
}
