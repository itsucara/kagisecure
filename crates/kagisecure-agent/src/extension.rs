//! The browser-extension listener: the second socket, and the one place a value crosses to a
//! browser.
//!
//! # How this differs from [`crate::service`], and why
//!
//! `service` answers an MCP sidecar over a protocol that structurally cannot carry a value. This
//! module answers a native messaging host over a protocol that carries exactly one, on purpose,
//! because a password manager that cannot fill a password field is not a password manager. Every
//! other difference follows from that:
//!
//! | | MCP channel | Extension channel |
//! | --- | --- | --- |
//! | Can carry a value | no, structurally | yes, in two fields |
//! | Caller identity | the sidecar's own signature | the native host's, **and its parent browser's** |
//! | Scope of a grant | a directory and a variable set | an origin and one item |
//! | Lease store | [`kagisecure_core::lease::LeaseStore`] | [`crate::fill_lease::FillLeaseStore`] |
//! | Approval queue | shared — one sheet, one timeout, one biometric gate |
//!
//! # Two front ends, one service
//!
//! There are two sockets, not two protocols. The Chromium family reaches the app through
//! `kagisecure-nmhost` on the socket beside the agent socket; Safari reaches it through the app
//! extension inside our own bundle, on a socket in the App Group container the sandboxed extension
//! can see ([ADR-0024](../../../docs/decisions/0024-safari-app-group-socket.md)). Both speak the
//! same [`kagisecure_extension_ipc::protocol`], share this service, this lease store and this
//! approval queue, and differ only in gate 2 below.
//!
//! # The order of checks, which is the security argument
//!
//! 1. **Same user.** A connection from another local uid is closed before a byte is read.
//! 2. **The right peer for this socket.** On the native-messaging socket, the host's process
//!    ancestry must contain a recognized browser within three hops — a native host is a pipe, and
//!    a pipe with no browser above it is a program pretending to be one. On the Safari socket the
//!    peer *is* the extension, so the test is that its executable is the `.appex` inside our own
//!    bundle. Either failure is `UNTRUSTED_HOST` before anything is served, and is audited.
//! 3. **Pinned extension id.** `Hello` from anything but the committed id — the Chromium key-pinned
//!    id, or the Safari app extension's bundle identifier — is refused. This is not an
//!    authentication — a compromised extension keeps its id — it is what stops a *different*
//!    extension the user installed from talking to the vault at all.
//! 4. **Origin match.** The item's saved websites must cover the page, by
//!    [`kagisecure_extension_ipc::origin`]'s rule. A mismatch is `ORIGIN_MISMATCH` and an audit
//!    entry, never a prompt: there is nothing useful for a human to weigh about a fill the rule
//!    already refused.
//! 5. **The human.** First fill for an (origin, item) pair in this unlock session raises the
//!    approval sheet and needs a fingerprint. A live fill lease skips the fingerprint and nothing
//!    else — the user's click in the page is still required, by the content script, always.
//!
//!    The one fill that does not reach this gate is a request for the **username alone**, which
//!    is what the first page of an identifier-first sign-in asks for. Nothing crosses that the
//!    browser was not already handed by `Match`, which never prompts either, so a sheet there
//!    would be a fingerprint for a value the extension already has. It is still audited, as
//!    `FILL_USERNAME_ONLY`, and it still has to pass gates 1–4
//!    ([ADR-0030](../../../docs/decisions/0030-identifier-first-login.md)).
//!
//! # `agent_visible` is deliberately not consulted
//!
//! `Item::agent_visible` is default-deny for *agents*: it is the answer to "may a language model
//! learn that this item exists". The browser extension is the user's own browser, filling the
//! user's own login, at the user's own click, behind a biometric. Gating autofill on the agent
//! flag would mean a user has to grant an LLM visibility over an item in order to log in to a
//! website with it, which is exactly backwards. Recorded in ADR-0018 and in
//! `docs/threat-model-browser-extension.md` §5.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Field, Item};
use kagisecure_core::proto::{FieldKind, Outcome as AuditOutcome};
use kagisecure_core::unix_now;
use kagisecure_extension_ipc::endpoint::{extension_endpoint, safari_endpoint};
use kagisecure_extension_ipc::listener::{HostConnection, Listener};
use kagisecure_extension_ipc::origin::{MatchFailure, item_match};
use kagisecure_extension_ipc::peer::{HostIdentity, HostKind};
use kagisecure_extension_ipc::protocol::{
    ErrorCode, FillField, FillValue, MatchItem, PROTOCOL_VERSION, PageContext, Request, Response,
};
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
// The approval queue is shared with the MCP channel, so an `Outcome` comes back carrying *that*
// channel's error code. The two vocabularies overlap but are not the same type, and the mapping
// between them is written out once, in `authorize`.
use kagisecure_ipc::protocol::ErrorCode as QueueCode;
use kagisecure_ipc::server::own_uid;

use crate::approval::{ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
use crate::fill_lease::{
    DEFAULT_FILL_TTL_SECONDS, FillLease, FillLeaseStore, MAX_FILL_TTL_SECONDS,
};
use crate::vault::VaultHandle;

/// How long the accept loop sleeps between polls. Same reasoning as [`crate::agent`].
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// Audit `detail` tokens. A fixed vocabulary, like every other `detail` this project writes.
pub mod audit_detail {
    /// A fill was approved by the user, at a sheet, with a biometric.
    pub const FILL_APPROVED: &str = "FILL_APPROVED";
    /// A fill was refused, timed out, or the vault locked under it.
    pub const FILL_DENIED: &str = "FILL_DENIED";
    /// A fill was refused by the origin rule before any human was asked.
    pub const FILL_ORIGIN_MISMATCH: &str = "FILL_ORIGIN_MISMATCH";
    /// A fill went ahead under a live lease, with no new biometric.
    pub const FILL_LEASED: &str = "FILL_LEASED";
    /// Only the username was asked for and written, so no sheet was raised
    /// ([ADR-0030](../../../docs/decisions/0030-identifier-first-login.md)).
    pub const FILL_USERNAME_ONLY: &str = "FILL_USERNAME_ONLY";
    /// A native host was refused before it could ask anything.
    pub const HOST_REFUSED: &str = "HOST_REFUSED";
}

/// Why the extension listener could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionError {
    /// Something else already holds the extension socket.
    #[error(
        "another kagisecure is already serving browser extensions on {endpoint}. Quit the other \
         copy of the app and try again."
    )]
    AlreadyBound {
        /// Where the conflict is.
        endpoint: String,
    },
    /// The endpoint could not be worked out or prepared.
    #[error("{0}")]
    Endpoint(#[from] EndpointError),
    /// This process is already serving extensions.
    #[error("the browser-extension listener is already running on {endpoint}")]
    AlreadyRunning {
        /// Where it is running.
        endpoint: String,
    },
}

/// Knobs the host sets at start.
pub struct ExtensionConfig {
    /// Listen here instead of the per-user default.
    pub socket_path: Option<std::path::PathBuf>,
    /// Serve the Safari app extension here instead of at the App Group default.
    ///
    /// `None` with a `team_id` means "the App Group container for that team"; `None` with no
    /// team means "do not serve Safari at all", which is what an ad-hoc build gets, because an
    /// ad-hoc build cannot carry the App Group entitlement the extension needs (ADR-0024 §6).
    pub safari_socket_path: Option<std::path::PathBuf>,
    /// The team identifier this app is signed with, used to derive the App Group container.
    ///
    /// Supplied by the app from `SecCodeCopySigningInformation` on itself rather than hardcoded,
    /// so a fork that signs with its own identity gets its own group with no source edit.
    pub team_id: Option<String>,
    /// The approval queue to ask through.
    ///
    /// Required, and deliberately not defaulted: sharing the app's one queue is the whole reason
    /// a fill approval looks and behaves like every other approval, and a listener that quietly
    /// made its own would produce a second sheet nobody is polling for.
    pub queue: Arc<ApprovalQueue>,
    /// Answer every approval with "allow for this session" without asking a human.
    ///
    /// **Refused in release builds.** The same rule, and the same reason, as
    /// `kagisecure daemon --auto-approve` (ADR-0007 §2): the cross-process test needs something
    /// to press the button, and a shipped binary must not contain a way to skip the human. Note
    /// that even here the request still goes through [`ApprovalQueue::ask`] and is answered
    /// through [`ApprovalQueue::resolve`], so the test exercises the production path with a robot
    /// in the chair rather than a bypass around it.
    pub auto_approve: bool,
    /// Serve a connecting process even when no recognized browser launched it.
    ///
    /// **Refused in release builds**, for the same reason as [`Self::auto_approve`]. It exists
    /// because the ancestry gate is the one check a test cannot satisfy honestly: a test binary's
    /// parent is `cargo`, and the alternative to this flag is either to not test the code behind
    /// the gate at all, or to launch a browser from a unit test. The gate itself is tested with
    /// the flag *off*, which is the direction that matters.
    pub allow_unlaunched_host: bool,
}

impl ExtensionConfig {
    /// A configuration that asks `queue` and nothing else.
    #[must_use]
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            socket_path: None,
            safari_socket_path: None,
            team_id: None,
            queue,
            auto_approve: false,
            allow_unlaunched_host: false,
        }
    }
}

impl std::fmt::Debug for ExtensionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionConfig")
            .field("socket_path", &self.socket_path)
            .field("safari_socket_path", &self.safari_socket_path)
            .field("team_id", &self.team_id)
            .field("auto_approve", &self.auto_approve)
            .field("allow_unlaunched_host", &self.allow_unlaunched_host)
            .finish_non_exhaustive()
    }
}

/// What the UI shows about the extension listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionStatus {
    /// Whether the socket is bound and being accepted on.
    pub running: bool,
    /// Where it is listening.
    pub endpoint: String,
    /// Whether the Safari front end is bound and being accepted on.
    pub safari_running: bool,
    /// Where Safari's socket is, or why there is not one.
    pub safari_endpoint: String,
    /// How many browsers are connected right now.
    pub connected_hosts: u32,
    /// How many fill leases are alive right now.
    pub fill_leases: u32,
    /// Whether the vault behind it is still unlocked.
    pub vault_unlocked: bool,
}

struct ExtShared {
    handle: Arc<VaultHandle>,
    leases: Arc<Mutex<FillLeaseStore>>,
    queue: Arc<ApprovalQueue>,
    connected: Arc<Mutex<u32>>,
    auto_approve: bool,
    allow_unlaunched_host: bool,
    stopping: Arc<AtomicBool>,
}

impl ExtShared {
    /// What a vault lock does to this channel: every fill lease dies with the key.
    fn on_vault_locked(&self) {
        self.leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_all();
    }
}

/// A running (or stopped) extension listener over a shared vault.
pub struct ExtensionAgent {
    shared: Arc<ExtShared>,
    endpoint: Endpoint,
    accept: Option<std::thread::JoinHandle<()>>,
    safari: Option<SafariFrontEnd>,
    /// Why Safari is not being served, when it is not. Shown verbatim on the setup screen.
    safari_unavailable: Option<String>,
}

/// The Safari half: a second socket, in the App Group container, with its own accept thread.
struct SafariFrontEnd {
    endpoint: Endpoint,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for ExtensionAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionAgent")
            .field("endpoint", &self.endpoint.to_string())
            .field("running", &self.accept.is_some())
            .field(
                "safari_endpoint",
                &self.safari.as_ref().map(|s| s.endpoint.to_string()),
            )
            .finish()
    }
}

impl ExtensionAgent {
    /// Bind the extension socket and start accepting native hosts.
    ///
    /// # Errors
    ///
    /// [`ExtensionError::AlreadyBound`] when another kagisecure holds the socket, or
    /// [`ExtensionError::Endpoint`] if the directory cannot be prepared. In a release build,
    /// `auto_approve` is an [`ExtensionError::Endpoint`]-free hard refusal — see the panic note.
    ///
    /// # Panics
    ///
    /// If `auto_approve` is set in a release build. This is a programming error that would ship a
    /// vault with no human in the approval loop, so it fails loudly at start rather than silently
    /// at the first fill.
    pub fn start(
        handle: Arc<VaultHandle>,
        config: ExtensionConfig,
    ) -> Result<Self, ExtensionError> {
        assert!(
            !(config.auto_approve && !cfg!(debug_assertions)),
            "auto-approve is a test affordance and must never be compiled into a release build"
        );
        assert!(
            !(config.allow_unlaunched_host && !cfg!(debug_assertions)),
            "allow-unlaunched-host is a test affordance and must never be compiled into a release \
             build"
        );

        let endpoint = match &config.socket_path {
            Some(path) => Endpoint::Path(path.clone()),
            None => extension_endpoint()?,
        };
        let listener = match Listener::bind(&endpoint) {
            Ok(l) => l,
            Err(EndpointError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse =>
            {
                return Err(ExtensionError::AlreadyBound {
                    endpoint: endpoint.to_string(),
                });
            }
            Err(e) => return Err(ExtensionError::from(e)),
        };
        listener.set_accept_nonblocking(true).map_err(|source| {
            ExtensionError::Endpoint(EndpointError::Io {
                path: std::path::PathBuf::from(endpoint.to_string()),
                source,
            })
        })?;

        let shared = Arc::new(ExtShared {
            handle: Arc::clone(&handle),
            leases: Arc::new(Mutex::new(FillLeaseStore::new())),
            queue: config.queue,
            connected: Arc::new(Mutex::new(0)),
            auto_approve: config.auto_approve,
            allow_unlaunched_host: config.allow_unlaunched_host,
            stopping: Arc::new(AtomicBool::new(false)),
        });

        // The MCP agent registers a lock hook too, and `set_lock_hook` replaces rather than
        // appends — so the two must not both register one. `VaultHandle::add_lock_hook` is the
        // additive form, added in M6 for exactly this reason.
        let weak: Weak<ExtShared> = Arc::downgrade(&shared);
        handle.add_lock_hook(Box::new(move || {
            if let Some(shared) = weak.upgrade() {
                shared.on_vault_locked();
            }
        }));

        let accept_shared = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name("kagisecure-extension-accept".to_owned())
            .spawn(move || accept_loop(&listener, &accept_shared))
            .map_err(|source| {
                ExtensionError::Endpoint(EndpointError::Io {
                    path: std::path::PathBuf::from(endpoint.to_string()),
                    source,
                })
            })?;

        // Safari is best-effort and never fatal: an ad-hoc build has no App Group, and a Mac with
        // no Safari extension enabled simply never connects. A failure here leaves the Chromium
        // front end serving and puts a sentence on the setup screen, rather than taking autofill
        // down for every browser because one of them could not be set up.
        let (safari, safari_unavailable) = start_safari(
            &config.safari_socket_path,
            config.team_id.as_deref(),
            &shared,
        );

        Ok(Self {
            shared,
            endpoint,
            accept: Some(accept),
            safari,
            safari_unavailable,
        })
    }

    /// Where this listener is bound.
    #[must_use]
    pub fn endpoint(&self) -> String {
        self.endpoint.to_string()
    }

    /// Where the Safari front end is bound, if it is.
    #[must_use]
    pub fn safari_endpoint(&self) -> Option<String> {
        self.safari.as_ref().map(|s| s.endpoint.to_string())
    }

    /// Why Safari is not being served, if it is not.
    #[must_use]
    pub fn safari_unavailable(&self) -> Option<&str> {
        self.safari_unavailable.as_deref()
    }

    /// A snapshot for the Browser extension pane and the menu bar.
    #[must_use]
    pub fn status(&self) -> ExtensionStatus {
        let now = unix_now();
        let stopping = self.shared.stopping.load(Ordering::SeqCst);
        ExtensionStatus {
            running: self.accept.is_some() && !stopping,
            endpoint: self.endpoint.to_string(),
            safari_running: self
                .safari
                .as_ref()
                .is_some_and(|s| s.accept.is_some() && !stopping),
            safari_endpoint: self.safari.as_ref().map_or_else(
                || {
                    self.safari_unavailable
                        .clone()
                        .unwrap_or_else(|| "not serving Safari".to_owned())
                },
                |s| s.endpoint.to_string(),
            ),
            connected_hosts: *self
                .shared
                .connected
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            fill_leases: u32::try_from(
                self.shared
                    .leases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .live_count(now),
            )
            .unwrap_or(u32::MAX),
            vault_unlocked: self.shared.handle.is_unlocked(),
        }
    }

    /// Every live fill lease, for the Leases table.
    #[must_use]
    pub fn fill_leases(&self) -> Vec<FillLease> {
        self.shared
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .summaries(unix_now())
    }

    /// Revoke one fill lease. `false` if there was none.
    pub fn revoke_fill_lease(&self, origin: &str, item_id: &str) -> bool {
        self.shared
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke(origin, item_id)
    }

    /// Revoke every fill lease.
    pub fn revoke_all_fill_leases(&self) {
        self.shared.on_vault_locked();
    }

    /// Stop accepting and drop every fill lease. Safe to call twice.
    pub fn stop(&mut self) {
        if self.shared.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.shared.on_vault_locked();
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
        if let Some(path) = self.endpoint.path() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(safari) = self.safari.as_mut() {
            if let Some(thread) = safari.accept.take() {
                let _ = thread.join();
            }
            if let Some(path) = safari.endpoint.path() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Bind and serve the Safari front end, or say why not.
///
/// Returns `(front end, reason it is absent)` — exactly one of the two is `Some`.
fn start_safari(
    explicit: &Option<std::path::PathBuf>,
    team_id: Option<&str>,
    shared: &Arc<ExtShared>,
) -> (Option<SafariFrontEnd>, Option<String>) {
    let endpoint = match explicit {
        Some(path) => Endpoint::Path(path.clone()),
        None => match safari_endpoint(team_id) {
            Some(endpoint) => endpoint,
            None => {
                return (
                    None,
                    Some(
                        "This build is not signed with a team identity, so it has no App Group \
                         for the Safari extension to reach it through. Build with \
                         `make macos SIGN=developer-id`."
                            .to_owned(),
                    ),
                );
            }
        },
    };

    let listener = match Listener::bind_kind(&endpoint, HostKind::SafariAppExtension) {
        Ok(listener) => listener,
        Err(e) => {
            return (
                None,
                Some(format!("The Safari socket could not be opened: {e}")),
            );
        }
    };
    if listener.set_accept_nonblocking(true).is_err() {
        return (
            None,
            Some("The Safari socket could not be made non-blocking.".to_owned()),
        );
    }

    let accept_shared = Arc::clone(shared);
    match std::thread::Builder::new()
        .name("kagisecure-safari-accept".to_owned())
        .spawn(move || accept_loop(&listener, &accept_shared))
    {
        Ok(accept) => (
            Some(SafariFrontEnd {
                endpoint,
                accept: Some(accept),
            }),
            None,
        ),
        Err(e) => (
            None,
            Some(format!("The Safari accept thread could not start: {e}")),
        ),
    }
}

impl Drop for ExtensionAgent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: &Listener, shared: &Arc<ExtShared>) {
    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut connection = match listener.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(_) => {
                if shared.stopping.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let shared = Arc::clone(shared);
        if std::thread::Builder::new()
            .name("kagisecure-extension-conn".to_owned())
            .spawn(move || {
                {
                    let mut count = shared.connected.lock().unwrap_or_else(|e| e.into_inner());
                    *count = count.saturating_add(1);
                }
                serve_host(&shared, &mut connection);
                {
                    let mut count = shared.connected.lock().unwrap_or_else(|e| e.into_inner());
                    *count = count.saturating_sub(1);
                }
            })
            .is_err()
        {
            continue;
        }
    }
}

/// Serve one native host until it goes away.
///
/// A refusal is *not* a silent close. The gates below fire before any request has been read, so
/// there is no correlation id to answer on yet — and answering on a made-up one would come back
/// to the native host as a correlation error, which it would report as a protocol bug rather than
/// as "you are not allowed here". So a refused host is served exactly one thing: the refusal,
/// against whatever id it asks with, for as long as it keeps asking.
fn serve_host(shared: &Arc<ExtShared>, connection: &mut HostConnection) {
    let identity = connection.identity().clone();

    // Gate 1: same user. A hard refusal, not a warning, exactly as on the MCP socket.
    let refusal = if identity
        .euid
        .zip(own_uid())
        .is_some_and(|(peer, mine)| peer != mine)
    {
        Some(Response::error(
            ErrorCode::UntrustedHost,
            "This socket only serves the user who owns it.",
        ))
    } else if identity.launched_by_browser() || shared.allow_unlaunched_host {
        // Gate 2 passed: a recognized browser is above this host, or — on the Safari socket — the
        // peer is our own app extension. See the module documentation for what that does and does
        // not establish.
        None
    } else {
        record_host_refusal(shared, &identity);
        Some(Response::error(
            ErrorCode::UntrustedHost,
            match connection.kind() {
                HostKind::SafariAppExtension => {
                    "That is not this app's Safari extension. Nothing was served."
                }
                HostKind::NativeMessaging => {
                    "kagisecure-nmhost was not launched by a recognized browser. Nothing was served."
                }
            },
        ))
    };

    let mut service = ExtensionService::new(Arc::clone(shared), connection.kind(), identity);

    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let envelope = match connection.read_request() {
            Ok(e) => e,
            Err(_) => return,
        };
        // Checked again after the read: this thread was parked in `read_request` while the host
        // stopped, and a request that arrives after a stop must not be served by a listener that
        // has already given up its socket. Closing here is what makes the native host reconnect
        // to whatever is listening now.
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let response = match &refusal {
            Some(refused) => refused.clone(),
            None => service.handle(&envelope.body),
        };
        if connection.write_response(&envelope.id, &response).is_err() {
            return;
        }
    }
}

fn record_host_refusal(shared: &Arc<ExtShared>, identity: &HostIdentity) {
    shared.handle.with_mut(|vault| {
        vault.append_audit(AuditDraft {
            actor: actor_for(identity, None),
            client_pid: identity.pid,
            tool: "extension_connect".to_owned(),
            outcome: AuditOutcome::Denied,
            detail: Some(audit_detail::HOST_REFUSED.to_owned()),
            ..AuditDraft::default()
        });
        let _ = vault.save();
    });
}

/// How the audit log names an extension caller.
///
/// The browser is the established fact and goes bare; the extension id is self-reported and is
/// quoted, the same discipline `kagisecure_ipc::PeerIdentity::describe` applies to a sidecar's
/// self-reported name.
fn actor_for(identity: &HostIdentity, extension_id: Option<&str>) -> String {
    let browser = identity
        .browser
        .map_or("unknown browser", |b| b.display_name());
    match extension_id {
        Some(id) => format!("extension {id:?} via {browser}"),
        None => format!("extension via {browser}"),
    }
}

/// One connected native host's session state.
struct ExtensionService {
    shared: Arc<ExtShared>,
    /// Which socket this connection arrived on, which is what decides the extension-id pin.
    kind: HostKind,
    identity: HostIdentity,
    /// Set by a successful `Hello`. Every other request is refused until it is.
    extension_id: Option<String>,
}

impl ExtensionService {
    fn new(shared: Arc<ExtShared>, kind: HostKind, identity: HostIdentity) -> Self {
        Self {
            shared,
            kind,
            identity,
            extension_id: None,
        }
    }

    fn handle(&mut self, request: &Request) -> Response {
        match request {
            Request::Hello {
                extension_id,
                protocol_version,
                ..
            } => self.hello(extension_id, *protocol_version),
            _ if self.extension_id.is_none() => Response::error(
                ErrorCode::Protocol,
                "Say hello before asking for anything else.",
            ),
            _ if !self.shared.handle.is_unlocked() => {
                // A locked vault takes its fill leases with it, whether or not the hook ran.
                self.shared.on_vault_locked();
                Response::error(
                    ErrorCode::VaultLocked,
                    "The kagisecure vault is locked. Open Kagisecure and unlock it.",
                )
            }
            Request::Status => Response::Status { unlocked: true },
            Request::Match { page } => self.matches(page),
            Request::Fill {
                page,
                item_id,
                fields,
            } => self.fill(page, item_id, fields),
            Request::Totp { page, item_id } => self.totp(page, item_id),
        }
    }

    fn hello(&mut self, extension_id: &str, protocol_version: u32) -> Response {
        if protocol_version != PROTOCOL_VERSION {
            return Response::error(
                ErrorCode::Protocol,
                format!(
                    "This app speaks extension protocol {PROTOCOL_VERSION}; the extension speaks \
                     {protocol_version}. Update whichever is older."
                ),
            );
        }
        // Which pin applies is decided by the socket the connection arrived on, not by the
        // identifier's shape. A Chromium extension that sends the Safari bundle id is refused,
        // and so is the reverse.
        let pinned = match self.kind {
            HostKind::SafariAppExtension => {
                kagisecure_extension_ipc::is_pinned_safari_extension(extension_id)
            }
            HostKind::NativeMessaging => {
                kagisecure_extension_ipc::is_pinned_extension(extension_id)
            }
        };
        if !pinned {
            self.record(AuditDraft {
                actor: actor_for(&self.identity, Some(extension_id)),
                client_pid: self.identity.pid,
                tool: "extension_hello".to_owned(),
                outcome: AuditOutcome::Denied,
                detail: Some(audit_detail::HOST_REFUSED.to_owned()),
                ..AuditDraft::default()
            });
            return Response::error(
                ErrorCode::UnknownExtension,
                "That extension id is not the one this app serves.",
            );
        }
        self.extension_id = Some(extension_id.to_owned());
        Response::Welcome {
            protocol_version: PROTOCOL_VERSION,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            unlocked: self.shared.handle.is_unlocked(),
            host_evidence: self.identity.evidence(),
        }
    }

    /// "Which of my items apply to this page?" No prompt, no value, no audit entry.
    ///
    /// Deliberately silent in the audit log: the content script asks this every time a login form
    /// gains focus, and an audit log with one entry per focus event is an audit log nobody reads.
    /// Nothing is disclosed that the extension could not already infer — it named the origin — and
    /// the two things that *do* disclose something, [`Self::fill`] and [`Self::totp`], are both
    /// recorded.
    fn matches(&self, page: &PageContext) -> Response {
        let frame = page.frame_origin.as_deref();
        let found = self.shared.handle.with(|vault| {
            let mut matched_origin = None;
            let items: Vec<MatchItem> = vault
                .items()
                .iter()
                .filter(|item| !item.is_trashed() && !item.archived)
                .filter_map(|item| {
                    let origin = item_match(&saved_websites(item), &page.top_origin, frame).ok()?;
                    matched_origin = Some(origin.ascii_serialization());
                    Some(MatchItem {
                        item_id: item.id.to_string(),
                        title: item.title.clone(),
                        username: username_of(item),
                        has_totp: item.totp_field().is_some(),
                    })
                })
                .collect();
            (items, matched_origin)
        });

        let Some((items, matched_origin)) = found else {
            return Response::error(ErrorCode::VaultLocked, "The vault locked.");
        };
        // With nothing matched there is no matched origin to echo, so echo the one that was
        // asked about — the extension uses it only to drop a stale answer after a navigation.
        let origin = matched_origin.unwrap_or_else(|| page.effective_origin().to_owned());
        Response::Matches { origin, items }
    }

    fn fill(&self, page: &PageContext, item_id: &str, fields: &[FillField]) -> Response {
        let mut wanted: Vec<FillField> = fields.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.is_empty() {
            return Response::error(ErrorCode::Protocol, "A fill must name at least one field.");
        }
        let field_names: Vec<String> = wanted.iter().map(|f| f.as_str().to_owned()).collect();

        let matched = match self.check_origin("fill_credential", page, item_id) {
            None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
            Some(Err(response)) => return response,
            Some(Ok(matched)) => matched,
        };

        // Before the human, not after. Asking somebody to put a fingerprint on a fill that cannot
        // happen — the item has no password, the field was renamed away — teaches them that the
        // sheet is noise. The check is after the origin rule, so a page that does not match still
        // learns nothing about what the item contains.
        let crosses_a_secret = FillField::crosses_a_secret(&wanted);
        let has_fields = self
            .shared
            .handle
            .with(|vault| {
                vault.find_item(item_id).ok().is_some_and(|item| {
                    let password_ok = !crosses_a_secret || password_of(item).is_some();
                    // Only when the username is the *whole* request: a login fill whose item has
                    // no username has always filled the password and left the box alone, and
                    // turning that into a refusal would be a regression dressed as a check.
                    let username_ok = crosses_a_secret || username_of(item).is_some();
                    password_ok && username_ok
                })
            })
            .unwrap_or(false);
        if !has_fields {
            return Response::error(
                ErrorCode::NoMatch,
                "That item does not have the fields the fill asked for.",
            );
        }

        // Identifier-first page one: a request for the username and nothing else. No secret
        // crosses, so no sheet and no biometric — the browser was handed this username, without a
        // prompt, by the `match` that drew the icon. What does not change: gates 1–4 above
        // (same user, the right peer, the pinned id, the origin rule), the user's own click in
        // the page, and the audit entry. ADR-0030 is the argument; `FILL_USERNAME_ONLY` is how a
        // reader tells this apart from a fill somebody approved.
        if !crosses_a_secret {
            let built = self.shared.handle.with(|vault| {
                let item = vault.find_item(item_id).ok()?;
                Some(Response::filled(
                    item.id.to_string(),
                    &wanted,
                    username_of(item),
                    None,
                ))
            });
            return match built.flatten() {
                Some(response) => {
                    debug_assert!(response.carries_only(&wanted));
                    self.record_username_only(&matched, item_id, &field_names);
                    response
                }
                None => Response::error(ErrorCode::VaultLocked, "The vault locked."),
            };
        }

        let approved =
            match self.require_approval("fill_credential", &matched, page, item_id, &field_names) {
                None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
                Some(Err(response)) => return response,
                Some(Ok(approved)) => approved,
            };

        // The crossing. Everything above this line is metadata; this is the one place a value
        // leaves the app for a browser (ADR-0018).
        let built = self.shared.handle.with(|vault| {
            let item = vault.find_item(item_id).ok()?;
            let username = wanted
                .contains(&FillField::Username)
                .then(|| username_of(item))
                .flatten();
            let password = if wanted.contains(&FillField::Password) {
                Some(FillValue::new(password_of(item)?))
            } else {
                None
            };
            Some(Response::filled(
                item.id.to_string(),
                &wanted,
                username,
                password,
            ))
        });

        match built.flatten() {
            Some(response) => {
                debug_assert!(response.carries_only(&wanted));
                self.record_fill(&approved, "fill_credential", item_id, &field_names);
                response
            }
            None => Response::error(ErrorCode::VaultLocked, "The vault locked."),
        }
    }

    fn totp(&self, page: &PageContext, item_id: &str) -> Response {
        let field_names = vec!["one-time password".to_owned()];

        let matched = match self.check_origin("totp_code", page, item_id) {
            None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
            Some(Err(response)) => return response,
            Some(Ok(matched)) => matched,
        };

        // Same reasoning as the fill: refuse an impossible request before asking a human.
        let has_totp = self
            .shared
            .handle
            .with(|vault| {
                vault
                    .find_item(item_id)
                    .ok()
                    .and_then(Item::totp_field)
                    .is_some_and(|f| f.totp_generator().is_ok())
            })
            .unwrap_or(false);
        if !has_totp {
            return Response::error(
                ErrorCode::NoMatch,
                "That item has no working one-time password.",
            );
        }

        let approved =
            match self.require_approval("totp_code", &matched, page, item_id, &field_names) {
                None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
                Some(Err(response)) => return response,
                Some(Ok(approved)) => approved,
            };

        let built = self.shared.handle.with(|vault| {
            let item = vault.find_item(item_id).ok()?;
            let generator = item.totp_field()?.totp_generator().ok()?;
            let now = unix_now();
            let code = generator.code_at(now).ok()?;
            Some(Response::TotpCode {
                item_id: item.id.to_string(),
                code: FillValue::new(code.expose_str()?.to_owned()),
                seconds_remaining: generator.seconds_remaining(now),
            })
        });

        match built.flatten() {
            Some(response) => {
                self.record_fill(&approved, "totp_code", item_id, &field_names);
                response
            }
            None => Response::error(ErrorCode::VaultLocked, "The vault locked."),
        }
    }

    /// The item, and whether the origin rule lets it be filled here.
    ///
    /// `None` means the vault locked mid-flight. `Err(response)` is a refusal to return verbatim,
    /// already recorded in the audit log.
    fn check_origin(
        &self,
        tool: &str,
        page: &PageContext,
        item_id: &str,
    ) -> Option<Result<Matched, Response>> {
        // Hold the vault for as short a time as possible, and never across the approval wait.
        let looked_up = self.shared.handle.with(|vault| {
            vault.find_item(item_id).ok().map(|item| {
                (
                    item.title.clone(),
                    item_match(
                        &saved_websites(item),
                        &page.top_origin,
                        page.frame_origin.as_deref(),
                    )
                    .map(|o| o.ascii_serialization()),
                )
            })
        })?;

        let Some((title, verdict)) = looked_up else {
            return Some(Err(Response::error(
                ErrorCode::NoMatch,
                "No such item in this vault.",
            )));
        };

        match verdict {
            Ok(origin) => Some(Ok(Matched { origin, title })),
            Err(failure) => {
                self.record_mismatch(tool, page, item_id, failure);
                Some(Err(Response::error(
                    ErrorCode::OriginMismatch,
                    format!("Refused: {}.", failure.as_str()),
                )))
            }
        }
    }

    /// The lease check, and failing that the human.
    ///
    /// A live lease excuses the biometric and nothing else; **Allow once** deliberately mints no
    /// lease, so the next fill at this origin asks again.
    fn require_approval(
        &self,
        tool: &str,
        matched: &Matched,
        page: &PageContext,
        item_id: &str,
        field_names: &[String],
    ) -> Option<Result<Approved, Response>> {
        let origin = matched.origin.clone();

        let covered = {
            let mut leases = self.shared.leases.lock().unwrap_or_else(|e| e.into_inner());
            leases.covers(&origin, item_id, unix_now())
        };
        if covered {
            return Some(Ok(Approved {
                origin,
                leased: true,
            }));
        }

        let request = ApprovalRequest {
            kind: ApprovalKind::FillCredential,
            client_name: self
                .identity
                .browser
                .map_or("a browser", |b| b.display_name())
                .to_owned(),
            client_pid: self.identity.pid,
            client_pid_from_kernel: self.identity.pid.is_some(),
            client_executable: self.identity.executable.clone(),
            origin: Some(origin.clone()),
            top_origin: (page.top_origin != origin).then(|| page.top_origin.clone()),
            item_id: Some(item_id.to_owned()),
            item_title: Some(matched.title.clone()),
            fill_fields: field_names.to_vec(),
            browser: self.identity.browser.map(|b| b.display_name().to_owned()),
            browser_pid: self.identity.browser_pid,
            browser_executable: self.identity.browser_executable.clone(),
            browser_is_app_extension: self.identity.app_extension,
            extension_id: self.extension_id.clone(),
            requested_ttl_seconds: DEFAULT_FILL_TTL_SECONDS,
            requested_uses: 1,
            max_ttl_seconds: MAX_FILL_TTL_SECONDS,
            ..ApprovalRequest::default()
        };

        if self.shared.auto_approve {
            self.auto_approve(&request);
        }
        let outcome = self.shared.queue.ask(request);

        if !outcome.granted {
            self.record(AuditDraft {
                actor: actor_for(&self.identity, self.extension_id.as_deref()),
                client_pid: self.identity.pid,
                tool: tool.to_owned(),
                item_id: item_id.parse().ok(),
                variables: field_names.to_vec(),
                target_path: Some(origin),
                outcome: AuditOutcome::Denied,
                detail: Some(audit_detail::FILL_DENIED.to_owned()),
                ..AuditDraft::default()
            });
            return Some(Err(Response::error(
                match outcome.code {
                    QueueCode::ApprovalTimeout => ErrorCode::ApprovalTimeout,
                    QueueCode::VaultLocked => ErrorCode::VaultLocked,
                    _ => ErrorCode::UserDenied,
                },
                match outcome.code {
                    QueueCode::ApprovalTimeout => "Nobody answered the approval within 60 seconds.",
                    QueueCode::VaultLocked => "The vault locked before the approval was answered.",
                    _ => "You declined this fill.",
                },
            )));
        }

        if outcome.session {
            self.shared
                .leases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .grant(
                    &origin,
                    item_id,
                    &matched.title,
                    &actor_for(&self.identity, self.extension_id.as_deref()),
                    outcome.ttl_seconds,
                    unix_now(),
                );
        }

        Some(Ok(Approved {
            origin,
            leased: false,
        }))
    }

    /// Answer our own question, from a second thread, for the cross-process test.
    ///
    /// Deliberately goes through `resolve` rather than short-circuiting `ask`, so the test drives
    /// the same code the sheet does. Gated on `auto_approve`, which cannot be set in a release
    /// build (see [`ExtensionConfig::auto_approve`]).
    fn auto_approve(&self, request: &ApprovalRequest) {
        let queue = Arc::clone(&self.shared.queue);
        let ttl = request.requested_ttl_seconds;
        std::thread::spawn(move || {
            if let Some(delivered) = queue.next(Duration::from_secs(5)) {
                queue.resolve(
                    &delivered.id,
                    &Decision::AllowSession {
                        ttl_seconds: ttl,
                        uses: 1,
                    },
                    ClientVerification {
                        verified: false,
                        evidence: "auto-approved by a debug build".to_owned(),
                    },
                );
            }
        });
    }

    fn record_fill(&self, approved: &Approved, tool: &str, item_id: &str, field_names: &[String]) {
        self.record(AuditDraft {
            actor: actor_for(&self.identity, self.extension_id.as_deref()),
            client_pid: self.identity.pid,
            tool: tool.to_owned(),
            item_id: item_id.parse().ok(),
            variables: field_names.to_vec(),
            target_path: Some(approved.origin.clone()),
            outcome: AuditOutcome::Allowed,
            detail: Some(
                if approved.leased {
                    audit_detail::FILL_LEASED
                } else {
                    audit_detail::FILL_APPROVED
                }
                .to_owned(),
            ),
            ..AuditDraft::default()
        });
    }

    /// Record a fill that wrote only a username.
    ///
    /// Same tool name as every other fill, so the audit view's `fill_credential` filter shows it
    /// and nobody has to know a second name to find it; a different `detail`, because "the app
    /// answered this without asking anyone" is exactly the thing a reader of the log needs to be
    /// able to see. No lease is minted and none is consumed: a username-only fill neither needs
    /// authorization nor grants any.
    fn record_username_only(&self, matched: &Matched, item_id: &str, field_names: &[String]) {
        self.record(AuditDraft {
            actor: actor_for(&self.identity, self.extension_id.as_deref()),
            client_pid: self.identity.pid,
            tool: "fill_credential".to_owned(),
            item_id: item_id.parse().ok(),
            variables: field_names.to_vec(),
            target_path: Some(matched.origin.clone()),
            outcome: AuditOutcome::Allowed,
            detail: Some(audit_detail::FILL_USERNAME_ONLY.to_owned()),
            ..AuditDraft::default()
        });
    }

    fn record_mismatch(
        &self,
        tool: &str,
        page: &PageContext,
        item_id: &str,
        failure: MatchFailure,
    ) {
        self.record(AuditDraft {
            actor: actor_for(&self.identity, self.extension_id.as_deref()),
            client_pid: self.identity.pid,
            tool: tool.to_owned(),
            item_id: item_id.parse().ok(),
            target_path: Some(page.effective_origin().to_owned()),
            outcome: AuditOutcome::Denied,
            detail: Some(format!(
                "{} ({})",
                audit_detail::FILL_ORIGIN_MISMATCH,
                failure.as_str()
            )),
            ..AuditDraft::default()
        });
    }

    /// Append an audit entry and persist it.
    ///
    /// A fill changes nothing in the vault except its own audit entry, so — like the read-only
    /// MCP tools — it has to save, or an entire browsing session's fills would be lost the moment
    /// the vault locked.
    fn record(&self, draft: AuditDraft) {
        self.shared.handle.with_mut(|vault| {
            vault.append_audit(draft);
            if let Err(e) = vault.save() {
                eprintln!("kagisecure: could not persist the audit entry: {e}");
            }
        });
    }
}

/// An item whose saved websites cover the page that asked.
struct Matched {
    /// The origin that matched — the frame's, for a cross-origin fill.
    origin: String,
    /// The item's title, for the sheet and the leases table.
    title: String,
}

/// What an authorized fill knows about itself, for the audit entry.
struct Approved {
    /// The origin that was matched — the frame's, for a cross-origin fill.
    origin: String,
    /// Whether a live lease covered this, so the entry can say `FILL_LEASED` rather than
    /// `FILL_APPROVED` and a reader can tell "the user just authorized this" from "the user
    /// authorized this a few minutes ago".
    leased: bool,
}

/// Every website an item claims, from both places one can be written.
///
/// `Item::urls` is the canonical list (ADR-0029) and the one the edit sheet's Websites field
/// writes. A `FieldKind::Url` public field also still counts — not because the `Login` template
/// puts one there any more, but because a user can freely add a custom URL field, and because an
/// item saved by a pre-ADR-0029 build is only migrated the next time its vault is *opened* (core
/// folds a legacy `website` field into `urls` on load), not retroactively before that. Both are
/// the user's own statement about where this credential belongs, so both count, and nothing else
/// does. In particular the *title* is not consulted, however domain-like it looks.
#[must_use]
pub fn saved_websites(item: &Item) -> Vec<String> {
    let mut out = item.urls.clone();
    out.extend(
        item.fields
            .iter()
            .filter(|f| f.kind == FieldKind::Url)
            .filter_map(|f| f.value.as_public())
            .filter(|v| !v.is_empty())
            .map(str::to_owned),
    );
    out
}

/// The item's username, if it has a public one.
fn username_of(item: &Item) -> Option<String> {
    item.fields
        .iter()
        .find(|f| f.label.eq_ignore_ascii_case("username"))
        .or_else(|| {
            item.fields
                .iter()
                .find(|f| f.label.eq_ignore_ascii_case("email"))
        })
        .and_then(|f| f.value.as_public())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// The item's password, as a plain `String` at the moment it crosses.
///
/// Prefers a field literally called `password`; falls back to the first concealed field that is
/// not a TOTP seed, so an item that renamed its password field still fills. A TOTP seed is
/// excluded explicitly: filling an `otpauth://` URI into a password box would be both useless and
/// a disclosure of the shared seed.
fn password_of(item: &Item) -> Option<String> {
    let named = item
        .fields
        .iter()
        .find(|f| f.label.eq_ignore_ascii_case("password") && f.kind != FieldKind::Totp);
    let candidate: Option<&Field> = named.or_else(|| {
        item.fields
            .iter()
            .find(|f| f.kind != FieldKind::Totp && f.value.is_secret() && f.value.has_value())
    });
    candidate
        .and_then(|f| f.value.as_secret())
        .and_then(|s| s.expose_str())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_core::model::{Category, Secret, VaultId};

    fn login(vault_id: VaultId, title: &str, urls: &[&str]) -> Item {
        let mut item = Item::new(vault_id, Category::Login, title);
        item.urls = urls.iter().map(|s| (*s).to_owned()).collect();
        item.fields.push(Field::public("username", "alice"));
        item.fields
            .push(Field::concealed("password", Secret::new(b"pw".to_vec())));
        item
    }

    #[test]
    fn saved_websites_reads_both_places_a_website_can_live() {
        let mut item = login(VaultId::new(), "Example", &["https://example.com"]);
        let mut website = Field::public("website", "https://login.example.com");
        website.kind = FieldKind::Url;
        item.fields.push(website);

        let websites = saved_websites(&item);
        assert_eq!(websites.len(), 2);
        assert!(websites.contains(&"https://example.com".to_owned()));
        assert!(websites.contains(&"https://login.example.com".to_owned()));
    }

    #[test]
    fn the_title_is_never_treated_as_a_website() {
        let item = login(VaultId::new(), "example.com", &[]);
        assert!(
            saved_websites(&item).is_empty(),
            "a domain-shaped title must not authorize a fill"
        );
    }

    #[test]
    fn an_empty_url_field_is_not_a_website() {
        let mut item = login(VaultId::new(), "Example", &[]);
        let mut website = Field::public("website", "");
        website.kind = FieldKind::Url;
        item.fields.push(website);
        assert!(saved_websites(&item).is_empty());
    }

    #[test]
    fn the_username_comes_from_the_username_field_or_the_email_field() {
        let item = login(VaultId::new(), "Example", &[]);
        assert_eq!(username_of(&item), Some("alice".to_owned()));

        let mut only_email = Item::new(VaultId::new(), Category::Login, "E");
        only_email.fields.push(Field::public("email", "a@b.test"));
        assert_eq!(username_of(&only_email), Some("a@b.test".to_owned()));

        let bare = Item::new(VaultId::new(), Category::Login, "B");
        assert_eq!(username_of(&bare), None);
    }

    #[test]
    fn the_password_comes_from_the_password_field() {
        let item = login(VaultId::new(), "Example", &[]);
        assert_eq!(password_of(&item), Some("pw".to_owned()));
    }

    #[test]
    fn a_renamed_password_field_still_fills_but_a_totp_seed_never_does() {
        let mut item = Item::new(VaultId::new(), Category::Login, "R");
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        item.fields.push(Field::concealed(
            "passphrase",
            Secret::new(b"correct horse".to_vec()),
        ));
        assert_eq!(
            password_of(&item),
            Some("correct horse".to_owned()),
            "the TOTP field must be skipped even though it comes first and is concealed"
        );
    }

    #[test]
    fn an_item_with_only_a_totp_seed_has_no_password_to_fill() {
        let mut item = Item::new(VaultId::new(), Category::Login, "T");
        item.fields.push(Field::totp(
            "one-time password",
            Secret::new(b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".to_vec()),
        ));
        assert_eq!(password_of(&item), None);
    }

    #[test]
    fn an_empty_password_is_not_a_password() {
        let mut item = Item::new(VaultId::new(), Category::Login, "E");
        item.fields
            .push(Field::concealed("password", Secret::new(Vec::new())));
        assert_eq!(password_of(&item), None);
    }

    #[test]
    fn the_actor_string_quotes_the_self_reported_id_and_leaves_the_browser_bare() {
        let identity = HostIdentity {
            browser: Some(kagisecure_extension_ipc::peer::KnownBrowser::Chrome),
            ..HostIdentity::default()
        };
        let actor = actor_for(&identity, Some("Google Chrome"));
        assert!(actor.contains("\"Google Chrome\""), "{actor}");
        assert!(actor.contains("via Google Chrome"), "{actor}");
        assert_eq!(actor_for(&identity, None), "extension via Google Chrome");
    }

    #[test]
    fn every_audit_detail_token_is_screaming_snake_case() {
        for token in [
            audit_detail::FILL_APPROVED,
            audit_detail::FILL_DENIED,
            audit_detail::FILL_ORIGIN_MISMATCH,
            audit_detail::FILL_LEASED,
            audit_detail::FILL_USERNAME_ONLY,
            audit_detail::HOST_REFUSED,
        ] {
            assert!(
                token.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{token}"
            );
        }
    }
}
