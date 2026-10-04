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
//! 5. **The human, every time.** Every fill that crosses a secret — a password or a one-time
//!    code — goes through [`ApprovalQueue::ask`] and needs a LocalAuthentication check: Touch ID,
//!    the login password, or an Apple Watch. There is no path around the question
//!    ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
//!    Since ADR-0037's amendment of 2026-09-27 the macOS app answers it without a new check when
//!    a check for a fill on the same exact origin passed less than ten minutes ago in this unlock
//!    session (same item too, for a presence-only request); that rule lives in the app, and this
//!    module asks exactly as before.
//!
//!    What a live fill lease changes is **what** is asked, not **whether**. The first fill of an
//!    (origin, item, fields) triple raises the full approval sheet; if the human chose **Allow for
//!    this session**, the lease remembers that review, and a later fill of the same triple from
//!    the top frame of that same origin is asked as [`ApprovalRequest::presence_only`] — no sheet,
//!    just the check. A fill from a sub-frame, or from a page whose top frame the browser did not
//!    establish, always gets the full sheet, because the sheet is where that difference is shown.
//!
//!    Why the click in the page is not enough on its own: the content script's `isTrusted` test
//!    proves the event did not come from page script, and nothing more. Input synthesized over
//!    the DevTools protocol, and input injected at the OS level through Quartz events or
//!    Accessibility, are both trusted — so a browser- or OS-automation agent can click the icon
//!    with no human present. Only the LocalAuthentication check tells a person from a program.
//!
//!    All of this is structural rather than conventional: the code that reads a secret lives in
//!    `crossing`, every function there takes an `Approved`, and an `Approved` can be built only
//!    from the [`Grant`] a resolved `ask` returns.
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
//! user's own login, at the user's own request, behind a biometric. Gating autofill on the agent
//! flag would mean a user has to grant an LLM visibility over an item in order to log in to a
//! website with it, which is exactly backwards. Recorded in ADR-0018 and in
//! `docs/threat-model-browser-extension.md` §5.
//!
//! # Other processes write the vault too
//!
//! As on the MCP channel ([`crate::service`]), every request that reads the vault first brings it
//! up to date with the file, so an item another process deleted or edited is answered as it is
//! now; a file that no longer continues this session refuses the request rather than answer from
//! a copy that is no longer the vault.
//!
//! # Audit before release
//!
//! A reply that carries a value — a password, a one-time code, and a username-only fill's username
//! too — is a *release*, and is released only once the `Allowed` entry recording it is on disk
//! ([ADR-0040](../../../docs/decisions/0040-audit-before-release.md), [`crate::release`]). The
//! value is read inside the transaction that commits that entry, on the file as it is then, and
//! leaves in the reply only if the commit succeeded; if it cannot be written, the answer is
//! `AUDIT_UNAVAILABLE` and nothing crosses. Before a sheet or a presence prompt is raised, audit
//! entries still waiting from an earlier failed write are flushed, and a flush that fails refuses
//! the fill without asking anyone.
//!
//! Every other entry this channel writes — refusals, denials, mismatches — is recorded
//! best-effort through [`VaultHandle::record_best_effort`]: it never changes the reply, and a
//! failed write leaves it queued rather than lost.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Item, ItemId};
use kagisecure_core::proto::{FieldKind, Outcome as AuditOutcome};
use kagisecure_core::unix_now;
use kagisecure_extension_ipc::endpoint::{extension_endpoint, safari_endpoint};
use kagisecure_extension_ipc::frame::FrameError;
use kagisecure_extension_ipc::listener::{HostConnection, Listener, PushSender};
use kagisecure_extension_ipc::origin::{MatchFailure, item_match};
use kagisecure_extension_ipc::peer::{HostIdentity, HostKind};
use kagisecure_extension_ipc::protocol::{
    Capability, ErrorCode, FillField, MatchItem, PROTOCOL_VERSION, PageContext, Request, Response,
};
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
use kagisecure_ipc::sever::LiveConnections;
// The approval queue is shared with the MCP channel, so an `Outcome` comes back carrying *that*
// channel's error code. The two vocabularies overlap but are not the same type, and the mapping
// between them is written out once, in `authorize`.
use kagisecure_ipc::protocol::ErrorCode as QueueCode;
use kagisecure_ipc::server::peer_is_same_user;

use crate::approval::{
    ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Decision, Grant,
};
use crate::catalog::{Catalog, Found};
use crate::fill_lease::{
    DEFAULT_FILL_TTL_SECONDS, FillLease, FillLeaseStore, MAX_FILL_TTL_SECONDS,
};
use crate::release::{self, Acted, NotReleased, Released, audited_release};
use crate::shared::SheetFacts;
use crate::vault::{LockHookGuard, REQUEST_LOCK_TIMEOUT, VaultHandle, sync_could_not_read};

pub mod agent_fill;
mod crossing;

use agent_fill::{AgentFillBroker, SessionTicket};
use crossing::{Approved, TOTP_FIELD};

/// How long the accept loop sleeps between polls. Same reasoning as [`crate::agent`].
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// How long [`ExtensionAgent::stop`] waits for the connections it severed to be let go of.
///
/// A connection parked in a read — the state nearly every connection is in — ends as soon as it
/// is severed, so in practice the wait is a thread switch. The bound is for one that is not in a
/// read: a fill waiting at the approval sheet cannot be hurried from here, since the queue is
/// shared with the MCP channel and this listener stopping is no reason to answer that channel's
/// requests. Such a connection is already severed, so it can never be served another request; it
/// is only its thread and its handle that outlive the stop, until the sheet is answered or times
/// out.
const STOP_DRAIN: Duration = Duration::from_secs(2);

/// Audit `detail` tokens. A fixed vocabulary, like every other `detail` this project writes.
pub mod audit_detail {
    /// A fill was approved by the user, at a sheet, with a biometric.
    pub const FILL_APPROVED: &str = "FILL_APPROVED";
    /// A fill whose scope the user reviewed at a sheet earlier in this unlock session was
    /// confirmed with a **fresh** biometric, without the sheet
    /// ([ADR-0037](../../../docs/decisions/0037-every-fill-needs-a-fresh-presence-proof.md)).
    pub const FILL_CONFIRMED: &str = "FILL_CONFIRMED";
    /// A fill was refused, timed out, or the vault locked under it.
    pub const FILL_DENIED: &str = "FILL_DENIED";
    /// A fill was refused by the origin rule before any human was asked.
    pub const FILL_ORIGIN_MISMATCH: &str = "FILL_ORIGIN_MISMATCH";
    /// **No longer written.** Builds before ADR-0037 wrote it for a fill that went ahead under a
    /// live lease with no biometric at all; that path no longer exists. Kept so that an audit
    /// log from such a build can still be read by name.
    pub const FILL_LEASED: &str = "FILL_LEASED";
    /// Only the username was asked for and written, so no sheet was raised
    /// ([ADR-0030](../../../docs/decisions/0030-identifier-first-login.md)).
    pub const FILL_USERNAME_ONLY: &str = "FILL_USERNAME_ONLY";
    /// A native host was refused before it could ask anything.
    pub const HOST_REFUSED: &str = "HOST_REFUSED";
    /// The reply frame carrying a released value could not be written to the native host. The
    /// code of the `Failed` follow-up to that fill's `Allowed` entry, as
    /// `"REPLY_FAILED (entry <seq>)"` ([ADR-0040](../../../docs/decisions/0040-audit-before-release.md) §2).
    pub const REPLY_FAILED: &str = "REPLY_FAILED";
    /// A request's frame was read in full but its body did not deserialize, so it was answered
    /// with `PROTOCOL` instead of a fill or a match.
    pub const PROTOCOL_ERROR: &str = "PROTOCOL_ERROR";
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
    ///
    /// An [`Endpoint`] rather than a path, for the reason
    /// [`crate::AgentConfig::endpoint`](crate::agent::AgentConfig::endpoint) gives: a socket
    /// location is a file on Unix and a named pipe on Windows, and a host naming one has to say
    /// which it means.
    pub endpoint: Option<Endpoint>,
    /// Serve the Safari app extension here instead of at the App Group default.
    ///
    /// `None` with a `team_id` means "the App Group container for that team"; `None` with no
    /// team means "do not serve Safari at all", which is what an ad-hoc build gets, because an
    /// ad-hoc build cannot carry the App Group entitlement the extension needs (ADR-0024 §6).
    pub safari_endpoint: Option<Endpoint>,
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
    /// The agent-fill broker a session that declares `agent_fill` is registered with
    /// (ADR-0036).
    ///
    /// The app passes the same process-wide `Arc` it gives the MCP [`crate::Agent`]: that shared
    /// broker is the only way an agent's `request_fill` reaches a browser tab. `None` registers
    /// nobody, so no session is ever pushed to, and the agent-fill requests are refused.
    pub agent_fill: Option<Arc<AgentFillBroker>>,
}

impl ExtensionConfig {
    /// A configuration that asks `queue` and nothing else.
    #[must_use]
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            endpoint: None,
            safari_endpoint: None,
            team_id: None,
            queue,
            auto_approve: false,
            allow_unlaunched_host: false,
            agent_fill: None,
        }
    }
}

impl std::fmt::Debug for ExtensionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionConfig")
            .field("endpoint", &self.endpoint.as_ref().map(ToString::to_string))
            .field(
                "safari_endpoint",
                &self.safari_endpoint.as_ref().map(ToString::to_string),
            )
            .field("team_id", &self.team_id)
            .field("auto_approve", &self.auto_approve)
            .field("allow_unlaunched_host", &self.allow_unlaunched_host)
            .field("agent_fill", &self.agent_fill.is_some())
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
    /// Every host connection being served right now, on either front end, each with the means
    /// to end it from another thread. Entered before its thread is spawned and removed only after
    /// the thread has dropped it, so "empty" means no accepted handle is still open — a
    /// correctness condition on Windows, where one stale connection keeps the pipe name alive
    /// (see [`kagisecure_ipc::sever`]).
    hosts: LiveConnections,
    auto_approve: bool,
    allow_unlaunched_host: bool,
    stopping: Arc<AtomicBool>,
    /// See [`ExtensionConfig::agent_fill`].
    agent_fill: Option<Arc<AgentFillBroker>>,
    /// Replaces gate 2 when set ([`ExtensionAgent::start_gated`]).
    host_gate: Option<HostGate>,
}

/// Who may connect, in place of "a recognized browser launched this host": the unattended
/// extension endpoint's gate, which admits only a native host descended from a live run's own
/// browser (ADR-0042 §12.4).
pub type HostGate = Arc<dyn Fn(&HostIdentity) -> bool + Send + Sync>;

impl ExtShared {
    /// What a vault lock does to this channel: every fill lease dies with the key, and so does
    /// an agent-fill grant waiting to be redeemed.
    fn on_vault_locked(&self) {
        self.leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_all();
        if let Some(broker) = &self.agent_fill {
            broker.revoke_all();
        }
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
    /// This listener's own lock hook, registered additively (`VaultHandle::add_lock_hook`, the
    /// only kind of registration there is) so no other registration can displace it and the MCP
    /// agent stopping cannot deregister it — see [`crate::vault::LockHookGuard`]. Held for as long as `Self` is, exactly as it lived
    /// in the handle's own list before hooks became individually removable: nothing here retires
    /// it early, so it keeps firing until this value is dropped.
    ///
    /// Never read — its only job is to exist for as long as `Self` does and run its `Drop` glue
    /// when that ends, so `dead_code` cannot see the use.
    #[allow(dead_code)]
    lock_hook: LockHookGuard,
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
        Self::start_with(handle, config, None)
    }

    /// As [`Self::start`], with `gate` deciding which native hosts are served instead of "a
    /// recognized browser launched it" (ADR-0042 §12.4). Everything else — the same-user check,
    /// the protocol, the broker — is unchanged.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    pub fn start_gated(
        handle: Arc<VaultHandle>,
        config: ExtensionConfig,
        gate: HostGate,
    ) -> Result<Self, ExtensionError> {
        Self::start_with(handle, config, Some(gate))
    }

    fn start_with(
        handle: Arc<VaultHandle>,
        config: ExtensionConfig,
        host_gate: Option<HostGate>,
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

        let endpoint = match &config.endpoint {
            Some(endpoint) => endpoint.clone(),
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
            hosts: LiveConnections::new(),
            auto_approve: config.auto_approve,
            allow_unlaunched_host: config.allow_unlaunched_host,
            stopping: Arc::new(AtomicBool::new(false)),
            agent_fill: config.agent_fill,
            host_gate,
        });

        // The MCP agent registers a lock hook too. Registration is additive, so neither can
        // displace the other; the guard is kept on `Self` below, and the MCP agent stopping drops
        // only its own guards, never this one.
        let weak: Weak<ExtShared> = Arc::downgrade(&shared);
        let lock_hook = handle.add_lock_hook(Box::new(move || {
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
            config.safari_endpoint.as_ref(),
            config.team_id.as_deref(),
            &shared,
        );

        Ok(Self {
            shared,
            endpoint,
            accept: Some(accept),
            safari,
            safari_unavailable,
            lock_hook,
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
            connected_hosts: u32::try_from(self.shared.hosts.len()).unwrap_or(u32::MAX),
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

    /// Grant a fill lease directly, bypassing the wire protocol.
    ///
    /// Test support, in the naming convention `kagisecure_core::Error::all_variants_for_test`
    /// already uses for the same purpose: it lets an integration test put a real lease in this
    /// listener's own store without spawning `kagisecure-nmhost` and driving a whole
    /// match/approve/fill handshake just to get one row into [`ExtensionAgent::fill_leases`] —
    /// which is all a test of what a *lock* does to that store needs.
    pub fn grant_fill_lease_for_test(&self, origin: &str, item_id: &str, item_title: &str) {
        self.shared
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .grant(
                origin,
                item_id,
                item_title,
                &["password".to_owned()],
                "test",
                DEFAULT_FILL_TTL_SECONDS,
                unix_now(),
            );
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

    /// Stop accepting, end every connected host's session, and drop every fill lease. Safe to
    /// call twice.
    ///
    /// Ending the sessions is what lets the same endpoint be bound again by the next
    /// [`ExtensionAgent::start`] — which is what the app does on every unlock after a lock. On
    /// Windows a pipe name lives as long as any accepted instance of it is open, so a stop that
    /// left a host's thread parked in its read would leave the name taken, and the restart would
    /// be refused (see [`kagisecure_extension_ipc::sever`]). On Unix the stale session would only
    /// have lingered until the host next spoke; ending it here makes both platforms behave the
    /// same way — the host sees its connection close, and its one-retry reconnect finds whatever
    /// is listening now.
    ///
    /// Blocks for at most `STOP_DRAIN` waiting for the severed sessions' threads to let go.
    pub fn stop(&mut self) {
        if self.shared.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.shared.on_vault_locked();
        // Both accept threads first, so that no connection can be accepted — and so escape the
        // severing below — after it has run.
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.safari.as_mut().and_then(|s| s.accept.take()) {
            let _ = thread.join();
        }
        let _ = self.shared.hosts.sever_all(STOP_DRAIN);
        if let Some(path) = self.endpoint.path() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(path) = self.safari.as_ref().and_then(|s| s.endpoint.path()) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Bind and serve the Safari front end, or say why not.
///
/// Returns `(front end, reason it is absent)` — exactly one of the two is `Some`.
fn start_safari(
    explicit: Option<&Endpoint>,
    team_id: Option<&str>,
    shared: &Arc<ExtShared>,
) -> (Option<SafariFrontEnd>, Option<String>) {
    let endpoint = match explicit {
        Some(endpoint) => endpoint.clone(),
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
        // A connection a stop could not end is one that would keep this endpoint taken after the
        // stop, so one whose handle cannot even be duplicated is not served. Duplicating a handle
        // this process already holds fails only when the process is out of handles.
        let Ok(severer) = connection.severer() else {
            continue;
        };
        let ticket = shared.hosts.arrived(severer);
        let serving = Arc::clone(shared);
        if std::thread::Builder::new()
            .name("kagisecure-extension-conn".to_owned())
            .spawn(move || {
                serve_host(&serving, &mut connection);
                // Every handle to the connection is closed *before* it leaves the registry, which
                // is the order `LiveConnections::sever_all` relies on.
                drop(connection);
                serving.hosts.gone(ticket);
            })
            .is_err()
        {
            // The closure, and the connection in it, were dropped with the failed spawn.
            shared.hosts.gone(ticket);
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

    // Gate 1: same user. A hard refusal, not a warning, exactly as on the MCP socket — and
    // fail-closed in the same way: a host whose uid the kernel would not report is refused
    // rather than waved through (D-9). On Windows the comparison is the token SID behind the
    // host's pid, which `HostIdentity` only ever takes from the kernel.
    let refusal = if !peer_is_same_user(identity.euid, identity.pid) {
        Some(Response::error(
            ErrorCode::UntrustedHost,
            "This socket only serves the user who owns it.",
        ))
    } else if shared
        .host_gate
        .as_ref()
        .map_or(identity.launched_by_browser(), |gate| gate(&identity))
        || shared.allow_unlaunched_host
    {
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
                HostKind::NativeMessaging if shared.host_gate.is_some() => {
                    "This endpoint serves only the browser kagisecure started for this run. \
                     Nothing was served."
                }
                HostKind::NativeMessaging => {
                    "kagisecure-nmhost was not launched by a recognized browser. Nothing was served."
                }
            },
        ))
    };

    let mut service = ExtensionService::new(
        Arc::clone(shared),
        connection.kind(),
        identity.clone(),
        connection.push_sender(),
    );

    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let (id, body) = match connection.read_request() {
            Ok(envelope) => (envelope.id, Ok(envelope.body)),
            // The frame was read in full — length prefix and all of its bytes — so the wire is
            // still in sync; only the body failed to deserialize. That is answerable rather than
            // fatal, but only when an id could be recovered from it to answer against.
            Err(FrameError::InvalidBody { id: Some(id), .. }) => (id, Err(())),
            // No id was recoverable from an unparseable body, or a genuine wire failure (EOF, a
            // broken length prefix, an oversized frame, any I/O error) left the stream in a state
            // that is not known to be in sync: closing is the only safe move for either.
            Err(_) => return,
        };
        // Checked again after the read: this thread was parked in `read_request` while the host
        // stopped, and a request that arrives after a stop must not be served by a listener that
        // has already given up its socket. Closing here is what makes the native host reconnect
        // to whatever is listening now.
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let response = match (&refusal, body) {
            (Some(refused), _) => refused.clone(),
            (None, Ok(body)) => service.handle(&body),
            // A refusal always wins, so this branch only fires for a host that already passed the
            // gates above — the message shape was the only thing wrong. Audited without the body:
            // the whole point is that this app never learns, let alone records, what it could not
            // parse.
            (None, Err(())) => {
                record_protocol_refusal(shared, &identity);
                Response::error(
                    ErrorCode::Protocol,
                    "That message could not be parsed. Check the request shape and retry.",
                )
            }
        };
        let written = connection.write_response(&id, &response);
        // A value released for this request was committed to the audit log before `handle`
        // returned; if the frame carrying it did not make it out, the log says so too.
        if let Some(released) = service.released.take()
            && written.is_err()
        {
            service.reply_failed(released);
        }
        if written.is_err() {
            return;
        }
    }
}

fn record_host_refusal(shared: &Arc<ExtShared>, identity: &HostIdentity) {
    record_best_effort(
        shared,
        AuditDraft {
            actor: actor_for(identity, None),
            client_pid: identity.pid,
            tool: "extension_connect".to_owned(),
            outcome: AuditOutcome::Denied,
            detail: Some(audit_detail::HOST_REFUSED.to_owned()),
            ..AuditDraft::default()
        },
    );
}

/// Audit a request the app could not parse. Never carries the request itself: the fixed `detail`
/// token is the only thing this writes about it.
fn record_protocol_refusal(shared: &Arc<ExtShared>, identity: &HostIdentity) {
    record_best_effort(
        shared,
        AuditDraft {
            actor: actor_for(identity, None),
            client_pid: identity.pid,
            tool: "extension_request".to_owned(),
            outcome: AuditOutcome::Denied,
            detail: Some(audit_detail::PROTOCOL_ERROR.to_owned()),
            ..AuditDraft::default()
        },
    );
}

/// Record an audit entry durably and best-effort: the one way this channel writes the vault.
///
/// Every entry here describes something that has already been decided — a refused host, an
/// unparseable request, a denial, a fill — so a failed write must never change the reply. Nor
/// may it lose the entry: a refusal is exactly the kind of entry a burst of prompt-injection
/// exfiltration attempts leaves behind (docs/mcp-server.md §6), and a fill is the one record of a
/// value that crossed. The entry is therefore queued before it is written, stays queued if the
/// write fails, and is written by the next write that succeeds; the failure itself stays visible
/// on the vault (`last_save_error`, `unsaved_audit_entries`) for the app to show the human. See
/// [`VaultHandle::record_best_effort`].
fn record_best_effort(shared: &ExtShared, draft: AuditDraft) {
    // `false` means locked: nothing to write to, and nothing lost the lock did not take.
    let _ = shared
        .handle
        .record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
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
    /// The fill the request being answered released, for [`Self::reply_failed`]. Taken by the
    /// connection loop after every reply.
    released: Option<ReleasedReply>,
    /// How to push to this connection, for the agent-fill broker.
    push: PushSender,
    /// This session's registration with the agent-fill broker, when its `Hello` declared
    /// `agent_fill` and it may be served one. Dropped — and so deregistered, taking any grant
    /// bound to it along — when the connection ends.
    agent_fill: Option<SessionTicket>,
}

impl ExtensionService {
    fn new(
        shared: Arc<ExtShared>,
        kind: HostKind,
        identity: HostIdentity,
        push: PushSender,
    ) -> Self {
        Self {
            shared,
            kind,
            identity,
            extension_id: None,
            released: None,
            push,
            agent_fill: None,
        }
    }

    fn handle(&mut self, request: &Request) -> Response {
        match request {
            Request::Hello {
                extension_id,
                protocol_version,
                capabilities,
                ..
            } => self.hello(extension_id, *protocol_version, capabilities),
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
            // Reads nothing from the vault, so there is nothing to bring up to date.
            Request::Status => Response::Status { unlocked: true },
            // Agent-requested fills (ADR-0036) are answered only on a session that declared them
            // and is registered with the broker: any other session was never pushed to, so it is
            // answering a probe that was never made.
            Request::TargetReport { .. }
            | Request::AgentFill { .. }
            | Request::AgentFillOutcome { .. }
                if self.agent_fill.is_none() =>
            {
                Response::error(
                    ErrorCode::Protocol,
                    "This session does not serve agent-requested fills.",
                )
            }
            // A report is answered `Noted` whatever the broker makes of it, so the extension —
            // and a page that can watch it — learns nothing about what the agent asked for.
            Request::TargetReport {
                probe_id,
                page,
                tab,
                found,
            } => {
                if let Some(ticket) = &self.agent_fill {
                    ticket
                        .broker()
                        .report(ticket.id(), probe_id, page, tab, *found);
                }
                Response::Noted
            }
            Request::AgentFillOutcome {
                grant_id,
                written,
                failure,
            } => {
                if let Some(ticket) = &self.agent_fill {
                    ticket.broker().outcome(
                        ticket.id(),
                        &self.shared.handle,
                        grant_id,
                        written,
                        *failure,
                    );
                }
                Response::Noted
            }
            Request::AgentFill {
                grant_id,
                page,
                tab,
                found,
            } => self.agent_fill(grant_id, page, tab, *found),
            // Everything below reads the vault: bring it up to date with the file first.
            _ if let Err(refusal) = self.sync() => refusal,
            Request::Match { page } => self.matches(page),
            Request::Fill {
                page,
                item_id,
                fields,
            } => self.fill(page, item_id, fields),
            Request::Totp { page, item_id } => self.totp(page, item_id),
        }
    }

    /// Bring the vault up to date with its file before a request reads it.
    ///
    /// Same rule as the MCP channel's `Service::sync`: a file that was read and does not
    /// continue this session (an older copy, a different vault, nothing at the path) refuses the
    /// request, and keeps refusing until the user resolves it in the app; a file that could not
    /// be read at all is answered from memory. Nothing here writes the file.
    ///
    /// The refusal is `VAULT_CONFLICT` — this protocol's equivalent of the MCP channel's code of
    /// the same name (`kagisecure-ipc`'s `ErrorCode::VaultConflict`, `docs/mcp-server.md` §7).
    /// Added without a protocol version bump, the same way `AUDIT_UNAVAILABLE` was (ADR-0040 §5):
    /// see the doc comment on `kagisecure_extension_ipc::protocol::PROTOCOL_VERSION`. Before this
    /// code existed the refusal was `INTERNAL` with this same sentence; an extension built before
    /// this change still shows that sentence, verbatim, for the new code, because the content
    /// script falls back to the app's own message for a code it does not branch on.
    ///
    /// `VaultBusy` never reaches here: [`VaultHandle::sync`] only reads the file (see
    /// `refresh_if_changed`) and never takes its write lock, so the errors it can return are
    /// exactly the ones `VAULT_CONFLICT` names — never "another process is writing it right now".
    /// A busy *write* — the lock held past the wait while a fill's audit entry is committed — is a
    /// different moment, already `AUDIT_UNAVAILABLE` (`docs/browser-extension.md` §4); see
    /// `kagisecure_extension_ipc::protocol::ErrorCode`'s own doc comment for why that call is
    /// deliberate rather than an oversight.
    fn sync(&self) -> Result<(), Response> {
        // Shared vaults another process wrote to are picked up the same way, each from its own
        // file (`crate::shared`).
        self.shared.handle.refresh_shared();
        match self.shared.handle.sync() {
            None => Err(Response::error(ErrorCode::VaultLocked, "The vault locked.")),
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) if sync_could_not_read(&e) => {
                eprintln!("kagisecure: could not re-read the vault file; serving from memory: {e}");
                Ok(())
            }
            Some(Err(e)) => {
                eprintln!("kagisecure: refusing browser requests until the vault is resolved: {e}");
                Err(Response::error(
                    ErrorCode::VaultConflict,
                    "The vault file changed on disk in a way Kagisecure will not merge. Open \
                     Kagisecure to resolve it.",
                ))
            }
        }
    }

    fn hello(
        &mut self,
        extension_id: &str,
        protocol_version: u32,
        capabilities: &[Capability],
    ) -> Response {
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
        // A second `Hello` on one connection replaces the first registration rather than adding
        // a second session for the same browser.
        self.agent_fill = None;
        // Only the native-messaging front end can be pushed to: Safari's transport opens one
        // connection per message (ADR-0036 §12), so a Safari session is never registered,
        // whatever it declares. Windows never offers agent fills at all.
        if capabilities.contains(&Capability::AgentFill)
            && self.kind == HostKind::NativeMessaging
            && !cfg!(windows)
            && let Some(broker) = &self.shared.agent_fill
        {
            self.agent_fill = Some(broker.register(
                self.push.clone(),
                self.identity.clone(),
                extension_id.to_owned(),
            ));
        }
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
        let found = self.with_catalog(|catalog| {
            let mut matched_origin = None;
            let items: Vec<MatchItem> = catalog
                .all_items()
                .iter()
                .map(|found| found.value)
                .filter(|item| is_servable(item))
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

    /// A credential fill: the username, the password, or both.
    ///
    /// # The order, which is ADR-0037 and ADR-0040 together
    ///
    /// 1. Metadata checks, on the vault as it was brought up to date at the start of the request:
    ///    the item is one a browser may be served ([`servable`]), its saved websites cover the page,
    ///    it has the fields asked for. None of these asks anybody anything.
    /// 2. For a fill that crosses a secret, the human ([`Self::require_approval`]) — preceded by a
    ///    pre-flight flush of any audit entries still waiting, so nobody is asked to touch the
    ///    sensor for a fill whose record could not be written anyway.
    /// 3. The release ([`Self::release`]): one transaction, on the file as it is on disk *now*,
    ///    that re-checks step 1, reads the value — through `crossing`, with the approval — and
    ///    appends the `Allowed` entry. The value is carried out of the transaction only if that
    ///    commit succeeded; the reply that carries it is written after `handle` returns. So the
    ///    entry is on disk before the first byte of the value is on the wire, and the value that
    ///    leaves is the one read from the state the entry was committed against.
    fn fill(&mut self, page: &PageContext, item_id: &str, fields: &[FillField]) -> Response {
        const TOOL: &str = "fill_credential";
        let mut wanted: Vec<FillField> = fields.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.is_empty() {
            return Response::error(ErrorCode::Protocol, "A fill must name at least one field.");
        }
        let field_names: Vec<String> = wanted.iter().map(|f| f.as_str().to_owned()).collect();

        let matched = match self.check_origin(TOOL, page, item_id) {
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
            .with_catalog(|catalog| {
                servable(catalog, item_id)
                    .is_some_and(|found| has_fill_fields(found.value, crosses_a_secret))
            })
            .unwrap_or(false);
        if !has_fields {
            return Response::error(ErrorCode::NoMatch, MISSING_FIELDS);
        }

        // Identifier-first page one: a request for the username and nothing else. No secret
        // crosses, so no sheet and no biometric — the browser was handed this username, without a
        // prompt, by the `match` that drew the icon. What does not change: gates 1–4 above
        // (same user, the right peer, the pinned id, the origin rule), the request in the page,
        // and the audit entry. ADR-0030 is the argument; `FILL_USERNAME_ONLY` is how a reader
        // tells this apart from a fill somebody approved. ADR-0037 leaves it exactly as it was:
        // an automation agent that triggers this learns a username `match` already told it.
        //
        // It is still a release (ADR-0040 §4): a value leaves in the reply, so its entry is
        // committed first, and a fill whose entry cannot be written is refused. There is no
        // pre-flight: nobody is asked, so there is no attention to spare, and the commit itself
        // writes anything still waiting or fails.
        if !crosses_a_secret {
            let entry = self.fill_entry(
                TOOL,
                &matched.origin,
                item_id,
                &field_names,
                Some(audit_detail::FILL_USERNAME_ONLY),
            );
            let origin = matched.origin;
            return self.release(TOOL, entry, None, page, item_id, |catalog| {
                let item = in_scope(catalog, item_id, page, &origin)?;
                if !has_fill_fields(item, false) {
                    return Err(Refusal::MissingFields(MISSING_FIELDS));
                }
                let response =
                    Response::filled(item.id.to_string(), &wanted, username_of(item), None);
                debug_assert!(response.carries_only(&wanted));
                Ok(response)
            });
        }

        let (approved, review) =
            match self.require_approval(TOOL, &matched, page, item_id, &field_names) {
                None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
                Some(Err(response)) => return response,
                Some(Ok(approved)) => approved,
            };
        let entry = self.fill_entry(
            TOOL,
            approved.origin(),
            item_id,
            &field_names,
            Some(approval_detail(&approved)),
        );
        let origin = approved.origin().to_owned();

        // The crossing. Everything above this line is metadata; this is the one place a password
        // leaves the app for a browser (ADR-0018), it cannot be reached without `approved`
        // (ADR-0037), and it runs inside the transaction that commits the entry (ADR-0040).
        self.release(TOOL, entry, review, page, item_id, move |catalog| {
            let item = in_scope(catalog, item_id, page, &origin)?;
            if !has_fill_fields(item, true) {
                return Err(Refusal::MissingFields(MISSING_FIELDS));
            }
            let response = crossing::filled(approved, item, &wanted, username_of(item))
                .ok_or(Refusal::NotCovered)?;
            debug_assert!(response.carries_only(&wanted));
            Ok(response)
        })
    }

    /// An agent fill being redeemed (ADR-0036 §4): everything is re-checked and released by the
    /// broker, through `crossing`, inside the audited release transaction. What comes back here is
    /// only the reply, and — for a release — what [`Self::reply_failed`] needs.
    fn agent_fill(
        &mut self,
        grant_id: &str,
        page: &PageContext,
        tab: &kagisecure_extension_ipc::protocol::TabFacts,
        found: kagisecure_extension_ipc::protocol::FoundFields,
    ) -> Response {
        let Some(ticket) = &self.agent_fill else {
            return Response::error(ErrorCode::Protocol, "No fill is waiting for this page.");
        };
        // Like every request that reads the vault, brought up to date with the file first; a
        // refusal here spends the grant, since the extension sends no outcome after an error.
        if let Err(refusal) = self.sync() {
            ticket.broker().abandon(grant_id);
            return refusal;
        }
        let redemption =
            ticket
                .broker()
                .redeem(ticket.id(), &self.shared.handle, grant_id, page, tab, found);
        if let Some((entry, entry_seq, grant_id)) = redemption.released {
            self.released = Some(ReleasedReply {
                entry,
                entry_seq,
                agent_grant: Some(grant_id),
            });
        }
        redemption.response
    }

    /// A one-time code. The same order as [`Self::fill`]; there is no username-only shortcut,
    /// because the code is itself the secret.
    fn totp(&mut self, page: &PageContext, item_id: &str) -> Response {
        const TOOL: &str = "totp_code";
        let field_names = vec![TOTP_FIELD.to_owned()];

        let matched = match self.check_origin(TOOL, page, item_id) {
            None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
            Some(Err(response)) => return response,
            Some(Ok(matched)) => matched,
        };

        // Same reasoning as the fill: refuse an impossible request before asking a human.
        let has_totp = self
            .with_catalog(|catalog| {
                servable(catalog, item_id)
                    .is_some_and(|found| crossing::has_working_totp(found.value))
            })
            .unwrap_or(false);
        if !has_totp {
            return Response::error(ErrorCode::NoMatch, NO_WORKING_TOTP);
        }

        let (approved, review) =
            match self.require_approval(TOOL, &matched, page, item_id, &field_names) {
                None => return Response::error(ErrorCode::VaultLocked, "The vault locked."),
                Some(Err(response)) => return response,
                Some(Ok(approved)) => approved,
            };
        let entry = self.fill_entry(
            TOOL,
            approved.origin(),
            item_id,
            &field_names,
            Some(approval_detail(&approved)),
        );
        let origin = approved.origin().to_owned();

        self.release(TOOL, entry, review, page, item_id, move |catalog| {
            let item = in_scope(catalog, item_id, page, &origin)?;
            if !crossing::has_working_totp(item) {
                return Err(Refusal::MissingFields(NO_WORKING_TOTP));
            }
            crossing::totp_code(approved, item, unix_now()).ok_or(Refusal::NotCovered)
        })
    }

    /// Release a reply that carries a value, only once the audit entry describing it is on disk
    /// ([`audited_release`], [ADR-0040](../../../docs/decisions/0040-audit-before-release.md)).
    ///
    /// `build` runs inside the transaction, on the file as it is on disk now, and returns the
    /// reply; nothing it read leaves unless the `Allowed` entry `entry` commits in the same
    /// transaction. It must re-check everything that decides the fill — the item may have been
    /// deleted, trashed, archived or moved to other websites while a sheet was up — because the
    /// request-start sync is as old as the human was slow.
    ///
    /// `review` is the lease an **Allow for this session** asked for. It is minted only here, after
    /// the commit, so a fill whose entry could not be written never leaves a lease behind: there is
    /// nothing to revoke because nothing was granted (ADR-0040 §3).
    ///
    /// On success the entry and its sequence number are kept for the connection loop, which
    /// records a follow-up if the reply frame cannot then be written ([`Self::reply_failed`]).
    fn release(
        &mut self,
        tool: &str,
        entry: AuditDraft,
        review: Option<Review>,
        page: &PageContext,
        item_id: &str,
        build: impl FnOnce(&Catalog<'_>) -> Result<Response, Refusal>,
    ) -> Response {
        let handle = &self.shared.handle;
        let released = audited_release(
            handle,
            REQUEST_LOCK_TIMEOUT,
            entry.clone(),
            // A shared item is read as its vault's snapshot is now: the personal vault's handle
            // is held, a shared vault's state is second (`crate::shared`).
            |tx| build(&Catalog::new(tx, handle.shared_snapshots())),
            // A fill's act is building the reply; the entry's seq is already carried on
            // `Released` and recorded below, so the act itself does not need it.
            |reply, _entry_seq| Acted::done(reply),
        );
        match released {
            Ok(Released { value, entry_seq }) => {
                if let Some(review) = review {
                    self.remember_review(review);
                }
                self.released = Some(ReleasedReply {
                    entry,
                    entry_seq,
                    agent_grant: None,
                });
                value
            }
            Err(NotReleased::Locked) => {
                Response::error(ErrorCode::VaultLocked, "The vault locked.")
            }
            // Its `Failed` entry is already queued (`audited_release`).
            Err(NotReleased::AuditUnavailable(_)) => audit_unavailable(),
            Err(NotReleased::Refused(refusal)) => {
                self.refused(tool, &entry, page, item_id, refusal)
            }
        }
    }

    /// Answer, and record, a release its transaction refused.
    ///
    /// Every case happened after the request-start checks passed, so something changed on disk
    /// in between — usually while a sheet was up. The reply is the one the same state would have
    /// produced at the start: an item that is gone, trashed or archived is answered exactly like
    /// one that never existed. The entry is the caller's record that an approved fill did not go
    /// ahead, best-effort like every refusal.
    fn refused(
        &self,
        tool: &str,
        entry: &AuditDraft,
        page: &PageContext,
        item_id: &str,
        refusal: Refusal,
    ) -> Response {
        let failed = |code: ErrorCode| AuditDraft {
            outcome: AuditOutcome::Failed,
            detail: Some(code.as_str().to_owned()),
            ..entry.clone()
        };
        match refusal {
            Refusal::Gone => {
                self.record(failed(ErrorCode::NoMatch));
                no_such_item()
            }
            Refusal::MissingFields(message) => {
                self.record(failed(ErrorCode::NoMatch));
                Response::error(ErrorCode::NoMatch, message)
            }
            Refusal::OriginMoved(failure) => {
                self.record_mismatch(tool, page, item_id, failure);
                Response::error(
                    ErrorCode::OriginMismatch,
                    format!("Refused: {}.", failure.as_str()),
                )
            }
            Refusal::NotCovered => {
                self.record(failed(ErrorCode::Internal));
                Response::error(
                    ErrorCode::Internal,
                    "The approval did not match the fill. Nothing was sent.",
                )
            }
        }
    }

    /// The reply frame carrying the last released value could not be written: record that, as
    /// the follow-up to its `Allowed` entry ([`release::follow_up`]).
    ///
    /// Called by the connection loop, which owns the connection. Best-effort: the value's fate is
    /// already sealed — it did not reach the browser, or not all of it — and a failed write here
    /// must not turn into anything else.
    fn reply_failed(&self, released: ReleasedReply) {
        self.record(release::follow_up(
            &released.entry,
            audit_detail::REPLY_FAILED,
            released.entry_seq,
        ));
        if let (Some(grant_id), Some(ticket)) = (&released.agent_grant, &self.agent_fill) {
            ticket.broker().reply_failed(grant_id);
        }
    }

    /// The item, and whether the origin rule lets it be filled here.
    ///
    /// `None` means the vault locked mid-flight. `Err(response)` is a refusal to return verbatim,
    /// already recorded in the audit log when there is anything to record.
    ///
    /// An item in the trash or the archive is answered exactly as one that does not exist — the
    /// same code and sentence, before the origin rule, with no audit entry — which is how `match`
    /// already treats it. Answering it any other way would tell a caller holding an old item id
    /// that the item is still there.
    fn check_origin(
        &self,
        tool: &str,
        page: &PageContext,
        item_id: &str,
    ) -> Option<Result<Matched, Response>> {
        // Hold the vault for as short a time as possible, and never across the approval wait.
        let looked_up = self.with_catalog(|catalog| {
            servable(catalog, item_id).map(|found| {
                let item = found.value;
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
            return Some(Err(no_such_item()));
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

    /// Ask the human, always, and turn their answer into an [`Approved`] or a refusal.
    ///
    /// There is no early return between here and [`ApprovalQueue::ask`]: every call reaches the
    /// queue, and the app answers nothing on the queue with an allow without a fresh
    /// LocalAuthentication check. What the fill lease decides is only **which** question is asked
    /// (ADR-0037):
    ///
    /// * no live lease for this exact (origin, item, fields) → the full sheet;
    /// * a live lease, and the request comes from the top frame of that same origin, as the
    ///   browser itself established → [`ApprovalRequest::presence_only`]: no sheet, just the
    ///   check, because the scope on the sheet is the one the human already reviewed;
    /// * a live lease, but the request comes from a sub-frame, or from a page whose top frame the
    ///   browser did not establish → the full sheet again, because "this form is inside a frame on
    ///   another site" is exactly what the sheet exists to say and a presence prompt cannot.
    ///
    /// A lease is minted only by a full review answered **Allow for this session**; a presence
    /// confirmation never mints or extends one. **Allow once** mints nothing, so the next fill
    /// raises the sheet again. What comes back beside the approval is that review, still to be
    /// remembered: [`Self::release`] mints the lease only once the fill's audit entry is on disk.
    ///
    /// Before anybody is asked, the audit log is checked (ADR-0040 §3, pre-flight): entries still
    /// waiting from an earlier failed write are written now, and if that fails the fill is refused
    /// with `AUDIT_UNAVAILABLE` without a sheet or a presence prompt — this fill's own entry would
    /// fail the same way, and a touch of the sensor for a fill that will then be refused is
    /// attention wasted and a lesson that the prompt is noise.
    fn require_approval(
        &self,
        tool: &str,
        matched: &Matched,
        page: &PageContext,
        item_id: &str,
        field_names: &[String],
    ) -> Option<Result<(Approved, Option<Review>), Response>> {
        let origin = matched.origin.clone();

        let reviewed_earlier = {
            let mut leases = self.shared.leases.lock().unwrap_or_else(|e| e.into_inner());
            leases.covers(&origin, item_id, field_names, unix_now())
        };
        // Keyed off "the browser said this was frame 0" and an exact origin comparison, never off
        // the lease alone: a lease minted at a top-level login must not let a frame of the same
        // origin, embedded in somebody else's page, skip the sheet that would have said so (D-7).
        // An item from a shared vault: the sheet says so, and a value changed since this device
        // last approved it always gets the full sheet, whatever review would otherwise stand in
        // for it (ADR-0035 §14).
        let shared = self.sheet_facts(tool, item_id, field_names);
        let presence_only = reviewed_earlier
            && page.top_origin_established
            && page.top_origin == origin
            && !shared.as_ref().is_some_and(SheetFacts::changed);

        let mut request = ApprovalRequest {
            kind: ApprovalKind::FillCredential,
            client_name: self
                .identity
                .browser
                .map_or("a browser", |b| b.display_name())
                .to_owned(),
            client_pid: self.identity.pid,
            client_pid_from_kernel: self.identity.pid.is_some(),
            client_audit_token: self.identity.audit_token.clone(),
            client_executable: self.identity.executable.clone(),
            origin: Some(origin.clone()),
            // The disclosure keys off "the browser did not tell us this was frame 0", not off a
            // string comparison a sub-frame can arrange to win by claiming its own origin as the
            // top one (D-7). `top_origin` may be the literal `"null"` — the platform
            // serialization of an opaque origin — which `top_origin_unknown` tells the sheet to
            // render as "an unknown site" rather than verbatim.
            top_origin: (!page.top_origin_established || page.top_origin != origin)
                .then(|| page.top_origin.clone()),
            top_origin_unknown: !page.top_origin_established,
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
            presence_only,
            ..ApprovalRequest::default()
        };
        if let Some(shared) = &shared {
            shared.state_on(&mut request);
        }

        if let Err(refusal) = self.audit_preflight(tool, &origin, item_id, field_names) {
            return Some(Err(refusal));
        }
        if self.shared.auto_approve {
            self.auto_approve(&request);
        }
        let grant = match self.shared.queue.ask(request).into_grant() {
            Ok(grant) => grant,
            Err(code) => {
                self.record(AuditDraft {
                    actor: actor_for(&self.identity, self.extension_id.as_deref()),
                    client_pid: self.identity.pid,
                    tool: tool.to_owned(),
                    vault_id: shared.as_ref().map(|s| s.vault_id),
                    item_id: ItemId::parse_canonical(item_id),
                    variables: field_names.to_vec(),
                    target_path: Some(origin),
                    outcome: AuditOutcome::Denied,
                    detail: Some(audit_detail::FILL_DENIED.to_owned()),
                    ..AuditDraft::default()
                });
                return Some(Err(Response::error(
                    match code {
                        QueueCode::ApprovalTimeout => ErrorCode::ApprovalTimeout,
                        QueueCode::VaultLocked => ErrorCode::VaultLocked,
                        _ => ErrorCode::UserDenied,
                    },
                    match code {
                        QueueCode::ApprovalTimeout => {
                            "Nobody answered the approval within 60 seconds."
                        }
                        QueueCode::VaultLocked => {
                            "The vault locked before the approval was answered."
                        }
                        _ if presence_only => {
                            "Nobody confirmed this fill with Touch ID or the login password."
                        }
                        _ => "You declined this fill.",
                    },
                )));
            }
        };

        if let Some(shared) = &shared {
            shared.record_approved(&self.shared.handle);
        }
        let review = Review::of(&grant, &origin, item_id, &matched.title, field_names);
        match Approved::from_grant(
            grant,
            ApprovalKind::FillCredential,
            &origin,
            item_id,
            field_names,
        ) {
            Some(approved) => Some(Ok((approved, review))),
            // Unreachable while `ask` answers the request it was given; refused rather than
            // trusted if that ever stops being true. See `crossing::Approved::from_grant`.
            None => Some(Err(Response::error(
                ErrorCode::Internal,
                "The approval did not match the fill. Nothing was sent.",
            ))),
        }
    }

    /// The pre-flight described at [`Self::require_approval`]: `Err` carries the refusal.
    ///
    /// The refusal is recorded like a release that could not be recorded — a `Failed` entry with
    /// detail `AUDIT_UNAVAILABLE`, queued rather than written, since a write just failed.
    fn audit_preflight(
        &self,
        tool: &str,
        origin: &str,
        item_id: &str,
        field_names: &[String],
    ) -> Result<(), Response> {
        match self.shared.handle.flush(REQUEST_LOCK_TIMEOUT) {
            None => Err(Response::error(ErrorCode::VaultLocked, "The vault locked.")),
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                eprintln!(
                    "kagisecure: not asking the user to approve {tool}: earlier audit entries \
                     still cannot be written: {e}"
                );
                let entry = self.fill_entry(tool, origin, item_id, field_names, None);
                let _ = self
                    .shared
                    .handle
                    .queue_audit(release::unavailable_entry(&entry));
                Err(audit_unavailable())
            }
        }
    }

    /// Mint the fill lease that remembers a full review answered **Allow for this session**.
    ///
    /// Takes a [`Review`], which only a [`Grant`] makes, so that nothing but a grant can mint one:
    /// a lease is the memory of a review somebody made, and this is the only call to the store's
    /// `grant` in the crate. Called only after the fill that review approved was committed to the
    /// audit log ([`Self::release`]).
    fn remember_review(&self, review: Review) {
        // The sheet was up for as long as the human took, and the vault may have locked under
        // it. `on_vault_locked` empties this store, so a lease minted after that hook ran would
        // outlive the key it stands for and sit in the Leases table until the next request
        // happened to clear it (B-24). The check is made **while holding the store's lock**, so a
        // lock that lands in the middle either clears the store before this grant (and the check
        // sees a locked vault) or blocks on the mutex and clears it after.
        let mut leases = self.shared.leases.lock().unwrap_or_else(|e| e.into_inner());
        if self.shared.handle.is_unlocked() {
            leases.grant(
                &review.origin,
                &review.item_id,
                &review.title,
                &review.field_names,
                &actor_for(&self.identity, self.extension_id.as_deref()),
                review.ttl_seconds,
                unix_now(),
            );
        } else {
            leases.revoke_all();
        }
    }

    /// Answer our own question, from a second thread, for the cross-process test.
    ///
    /// Deliberately goes through `resolve` rather than short-circuiting `ask`, so the test drives
    /// the same code the sheet does. Gated on `auto_approve`, which cannot be set in a release
    /// build (see [`ExtensionConfig::auto_approve`]). A presence-only request is answered
    /// **Allow once**, as the app answers it; the queue would clamp a session answer anyway.
    fn auto_approve(&self, request: &ApprovalRequest) {
        let queue = Arc::clone(&self.shared.queue);
        let ttl = request.requested_ttl_seconds;
        std::thread::spawn(move || {
            if let Some(delivered) = queue.next(Duration::from_secs(5)) {
                let decision = if delivered.presence_only {
                    Decision::AllowOnce
                } else {
                    Decision::AllowSession {
                        ttl_seconds: ttl,
                        uses: 1,
                    }
                };
                queue.resolve(
                    &delivered.id,
                    &decision,
                    ClientVerification {
                        verified: false,
                        evidence: "auto-approved by a debug build".to_owned(),
                    },
                );
            }
        });
    }

    /// The audit entry a fill is released under ([`Self::release`]): who asked, for which item
    /// and field **names** at which origin. Written `Allowed` when the fill commits, and the base
    /// of the `Failed` entry when it does not.
    ///
    /// `detail` says how it was authorized: `FILL_APPROVED` for a full review,
    /// `FILL_CONFIRMED` for a presence proof under an earlier review, `FILL_USERNAME_ONLY` for a
    /// username-only fill — which has the same tool name as every other fill, so the audit view's
    /// `fill_credential` filter shows it, and a different detail, because "the app answered this
    /// without asking anyone" is exactly what a reader of the log needs to be able to see.
    /// `None` only for an entry that is about to be turned into a refusal, whose detail replaces
    /// it.
    fn fill_entry(
        &self,
        tool: &str,
        origin: &str,
        item_id: &str,
        field_names: &[String],
        detail: Option<&str>,
    ) -> AuditDraft {
        AuditDraft {
            actor: actor_for(&self.identity, self.extension_id.as_deref()),
            client_pid: self.identity.pid,
            tool: tool.to_owned(),
            vault_id: self.shared_vault_of(item_id),
            item_id: ItemId::parse_canonical(item_id),
            variables: field_names.to_vec(),
            target_path: Some(origin.to_owned()),
            outcome: AuditOutcome::Allowed,
            detail: detail.map(str::to_owned),
            ..AuditDraft::default()
        }
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
            item_id: ItemId::parse_canonical(item_id),
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

    /// Record an audit entry, durably and best-effort ([`record_best_effort`]).
    ///
    /// A fill changes nothing in the vault except its own audit entry, so — like the read-only
    /// MCP tools — it has to be written straight away, or an entire browsing session's fills
    /// would be lost the moment the vault locked.
    fn record(&self, draft: AuditDraft) {
        record_best_effort(&self.shared, draft);
    }

    /// Run `f` against the personal vault and the shared vaults attached to it, as one
    /// ([`Catalog`]); `None` when the vault is locked. Never call it while the vault is held.
    fn with_catalog<T>(&self, f: impl FnOnce(&Catalog<'_>) -> T) -> Option<T> {
        let shared = self.shared.handle.shared_snapshots();
        self.shared
            .handle
            .with(|vault| f(&Catalog::new(vault, shared)))
    }

    /// The shared vault item `item_id` is in, for its audit entries (ADR-0035 decision 24):
    /// `None` for the personal vault, or when it cannot be found.
    fn shared_vault_of(&self, item_id: &str) -> Option<kagisecure_core::proto::VaultId> {
        let id = ItemId::parse_canonical(item_id)?;
        self.with_catalog(|catalog| catalog.item(&id).and_then(|f| f.place.audit_vault()))
            .flatten()
    }

    /// What the sheet for filling `item_id` states when the item is in a shared vault: its
    /// password for a credential fill that crosses one, its one-time code for `totp_code`.
    fn sheet_facts(&self, tool: &str, item_id: &str, field_names: &[String]) -> Option<SheetFacts> {
        let code = tool == "totp_code";
        let password = field_names
            .iter()
            .any(|name| name == FillField::Password.as_str());
        self.with_catalog(|catalog| {
            let found = servable(catalog, item_id)?;
            let snapshot = found.place.shared()?;
            Some(SheetFacts::for_fill(snapshot, found.value, password, code))
        })
        .flatten()
    }
}

/// An item whose saved websites cover the page that asked.
struct Matched {
    /// The origin that matched — the frame's, for a cross-origin fill.
    origin: String,
    /// The item's title, for the sheet and the leases table.
    title: String,
}

/// A full review answered **Allow for this session**, waiting to be remembered as a fill lease
/// once the fill it approved is on disk ([`ExtensionService::release`]).
struct Review {
    origin: String,
    item_id: String,
    title: String,
    field_names: Vec<String>,
    ttl_seconds: u64,
}

impl Review {
    /// The review `grant` asks to be remembered, if it asks for one: a full review, answered for
    /// the session. A presence confirmation is never one (ADR-0037), whatever the UI pressed.
    fn of(
        grant: &Grant,
        origin: &str,
        item_id: &str,
        title: &str,
        field_names: &[String],
    ) -> Option<Self> {
        (grant.session() && !grant.presence_only()).then(|| Self {
            origin: origin.to_owned(),
            item_id: item_id.to_owned(),
            title: title.to_owned(),
            field_names: field_names.to_vec(),
            ttl_seconds: grant.ttl_seconds(),
        })
    }
}

/// A fill that was committed to the audit log, until its reply frame has been written.
struct ReleasedReply {
    /// The entry it was released under.
    entry: AuditDraft,
    /// The `seq` of its `Allowed` entry.
    entry_seq: u64,
    /// For an agent fill, the grant it was released under, so the broker stops waiting for an
    /// outcome the extension will never send.
    agent_grant: Option<String>,
}

/// Why a release's transaction did not release — decided on the file as it was on disk then.
enum Refusal {
    /// The item is gone, in the trash or archived.
    Gone,
    /// The item's saved websites no longer cover the origin that was approved.
    OriginMoved(MatchFailure),
    /// The item no longer has what was asked for; the sentence says what.
    MissingFields(&'static str),
    /// The approval does not cover what was about to be built. Unreachable while `ask` answers
    /// the request it was given; see `crossing::Approved::from_grant`.
    NotCovered,
}

/// The sentence for a fill whose item lacks the fields it asked for.
const MISSING_FIELDS: &str = "That item does not have the fields the fill asked for.";

/// The sentence for a one-time-code request whose item has no working one.
const NO_WORKING_TOTP: &str = "That item has no working one-time password.";

/// The one answer for an item a browser may not be served: absent, trashed or archived alike.
fn no_such_item() -> Response {
    Response::error(ErrorCode::NoMatch, "No such item in this vault.")
}

/// The answer for a fill refused because its audit entry could not be written.
fn audit_unavailable() -> Response {
    Response::error(
        ErrorCode::AuditUnavailable,
        "Kagisecure could not write its audit log, so nothing was filled. Open Kagisecure to see \
         why.",
    )
}

/// Whether a browser may be served `item` at all: not in the trash and not archived — the same
/// rule `match` applies, so an item the icon would never offer cannot be filled by id either.
fn is_servable(item: &Item) -> bool {
    !item.is_trashed() && !item.archived
}

/// The item `reference` names, if a browser may be served it ([`is_servable`]): in the personal
/// vault or an attached shared vault, by the catalog's collision rules ([`Catalog::item`]) — a
/// shared login item is filled exactly as a personal one (ADR-0035 §14).
///
/// `None` for an item that is absent, trashed or archived alike, so that every caller answers
/// the three the same way ([`no_such_item`]) — a fill cannot become an oracle for "this item
/// still exists, in the trash".
///
/// `reference` must be an item id, exactly as `match` handed it out
/// ([`ItemId::parse_canonical`]). Never a title or an id prefix, which is what
/// [`kagisecure_core::Vault::find_item`] would also accept for a person at a terminal: through that door a request
/// could tell "no item has this title" from "two do — one of them perhaps in the trash" (not
/// found versus ambiguous), a title someone else controls could collide with the one being
/// filled and block it, and every audit entry would name whatever string was sent instead of an
/// item. Anything that is not an exact id is simply no item at all.
fn servable<'c>(catalog: &'c Catalog<'_>, reference: &str) -> Option<Found<'c, Item>> {
    catalog
        .item(&ItemId::parse_canonical(reference)?)
        .filter(|found| is_servable(found.value))
}

/// Whether `item` has what a fill asks for: a password when a secret crosses, a username when
/// the username is the whole request.
///
/// Only when the username is the *whole* request: a login fill whose item has no username has
/// always filled the password and left the box alone, and turning that into a refusal would be a
/// regression dressed as a check.
fn has_fill_fields(item: &Item, crosses_a_secret: bool) -> bool {
    if crosses_a_secret {
        crossing::has_password(item)
    } else {
        username_of(item).is_some()
    }
}

/// Inside a release's transaction: the item, if it may still be filled at `origin` from `page`.
///
/// The same checks the request started with, repeated on the file as it is now — the request's
/// own sync may be a minute old if a sheet was shown.
fn in_scope<'c>(
    catalog: &'c Catalog<'_>,
    item_id: &str,
    page: &PageContext,
    origin: &str,
) -> Result<&'c Item, Refusal> {
    let item = servable(catalog, item_id).ok_or(Refusal::Gone)?.value;
    let matched = item_match(
        &saved_websites(item),
        &page.top_origin,
        page.frame_origin.as_deref(),
    )
    .map_err(Refusal::OriginMoved)?;
    if matched.ascii_serialization() == origin {
        Ok(item)
    } else {
        Err(Refusal::OriginMoved(MatchFailure::OriginMismatch))
    }
}

/// How an approval is named in the audit log.
fn approval_detail(approved: &Approved) -> &'static str {
    if approved.reviewed_earlier() {
        audit_detail::FILL_CONFIRMED
    } else {
        audit_detail::FILL_APPROVED
    }
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

/// The item's username, if it has a public one (`Item::username` — the one definition the app's
/// "Copy Username" uses too).
fn username_of(item: &Item) -> Option<String> {
    item.username().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_core::model::{Category, Field, Secret, VaultId};

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
            audit_detail::FILL_CONFIRMED,
            audit_detail::FILL_DENIED,
            audit_detail::FILL_ORIGIN_MISMATCH,
            audit_detail::FILL_LEASED,
            audit_detail::FILL_USERNAME_ONLY,
            audit_detail::HOST_REFUSED,
            audit_detail::PROTOCOL_ERROR,
            audit_detail::REPLY_FAILED,
        ] {
            assert!(
                token.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{token}"
            );
        }
    }
}
