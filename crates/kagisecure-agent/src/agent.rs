//! The listener and the handle the host drives it with.
//!
//! One [`Agent`] owns: the bound socket, one accept thread, one thread per connection, the lease
//! store, and the approval queue. The host — the macOS app through `kagisecure-ffi`, or
//! `kagisecure daemon` — never sees a thread. It sees six synchronous calls:
//!
//! ```text
//!   start(handle, endpoint)   next_request(timeout)   resolve(id, decision, verification)
//!   leases()                  revoke_lease(id)        stop()
//! ```
//!
//! That is the whole surface, and it is deliberately the shape UniFFI is good at: sync, app →
//! Rust, value-returning (architecture.md §4.1).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kagisecure_core::Vault;
use kagisecure_core::lease::LeaseStore;
use kagisecure_core::proto::{LeaseId, LeaseSummary};
use kagisecure_core::unix_now;
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
use kagisecure_ipc::protocol::{ErrorCode, Response};
use kagisecure_ipc::server::{Connection, Server, peer_is_same_user};
use kagisecure_ipc::sever::LiveConnections;

use crate::approval::{ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
use crate::children::ChildRegistry;
use crate::extension::agent_fill::AgentFillBroker;
use crate::service::Service;
use crate::vault::{LockHookGuard, VaultHandle};

/// How long the accept loop sleeps between polls. Long enough not to spin, short enough that a
/// connecting sidecar does not notice.
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// How long [`Agent::stop`] waits for the connections it severed to be let go of.
///
/// A connection parked in a read — where an idle sidecar's connection spends its life — ends as
/// soon as it is severed, so in practice the wait is a thread switch. So does one waiting at the
/// approval sheet: the stop denies everything queued before it severs, and the request returns
/// at once. So, normally, does a `run_with_env` waiting for its command: the stop ends every
/// such child first (within [`crate::children::CHILD_KILL_GRACE`]), so the call returns and
/// reaches its read. The bound is for a request that is still *working* anyway — a child the
/// kill could not reap, say. Such a connection is severed, so its reply goes nowhere and it can
/// never be served another request; only its thread and its handle outlive the stop. On Windows
/// the handle keeps the pipe name for that long, and a restart in that window is refused as
/// [`AgentError::AlreadyBound`] rather than served.
const STOP_DRAIN: Duration = Duration::from_secs(2);

/// Why an agent could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// Something else is already listening on this endpoint — the other half of the pair, most
    /// likely: the CLI daemon if the app is starting, or the app if the daemon is.
    #[error(
        "another kagisecure is already listening on {endpoint}. Only one process can serve \
         agents at a time: quit the kagisecure app, or stop `kagisecure daemon`, and try again."
    )]
    AlreadyBound {
        /// Where the conflict is.
        endpoint: String,
    },
    /// The endpoint could not be worked out or prepared.
    #[error("{0}")]
    Endpoint(#[from] EndpointError),
    /// This agent is already running.
    #[error("the agent is already running on {endpoint}")]
    AlreadyRunning {
        /// Where it is running.
        endpoint: String,
    },
}

/// Knobs the host sets at start.
#[derive(Clone, Default)]
pub struct AgentConfig {
    /// Listen here instead of the per-user default (architecture.md §4.2).
    ///
    /// An [`Endpoint`] rather than a path, because the two platforms do not agree on what a
    /// socket location *is*: on Unix it is a file in a directory the caller controls, and on
    /// Windows there are no filesystem sockets at all, so it is a named pipe in a machine-global
    /// namespace. A host that wants a specific location has to say which of the two it means —
    /// [`Endpoint::parse`] turns a string a user supplied into one, and
    /// [`Endpoint::for_instance`] makes a fresh one for a harness or a second vault.
    pub endpoint: Option<Endpoint>,
    /// Ask through this queue instead of a fresh one.
    ///
    /// The app passes the same `Arc` it gives [`crate::ExtensionAgent`], so an MCP approval and a
    /// browser-fill approval arrive in one queue, on one sheet, behind one biometric gate
    /// (M6/ADR-0020). `None` keeps the M4 behaviour — a queue of this agent's own — which is what
    /// `kagisecure daemon` wants, since it serves no browsers.
    pub queue: Option<Arc<ApprovalQueue>>,
    /// The agent-fill broker `request_fill` is served through (ADR-0036).
    ///
    /// The app passes the same process-wide `Arc` it gives [`crate::ExtensionAgent`], which is
    /// what lets an agent's request reach a browser tab. `None` — `kagisecure daemon`, which
    /// serves no browser — answers every `request_fill` with `FILL_UNAVAILABLE`.
    pub agent_fill: Option<Arc<AgentFillBroker>>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("endpoint", &self.endpoint.as_ref().map(ToString::to_string))
            .field("shared_queue", &self.queue.is_some())
            .field("agent_fill", &self.agent_fill.is_some())
            .finish()
    }
}

/// What the UI shows about the listener itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStatus {
    /// Whether the socket is bound and being accepted on.
    pub running: bool,
    /// Where it is listening.
    pub endpoint: String,
    /// How many approvals are waiting for a human right now.
    pub pending_approvals: u32,
    /// How many leases are alive right now.
    pub active_leases: u32,
    /// Whether the vault behind it is still unlocked.
    pub vault_unlocked: bool,
}

/// State every connection thread, and the lock hook, shares.
struct Shared {
    handle: Arc<VaultHandle>,
    leases: Arc<Mutex<LeaseStore>>,
    queue: Arc<ApprovalQueue>,
    /// Raised by the `lock` tool and **never lowered** for the life of this agent: from the
    /// instant a lock is acknowledged, nothing is served, whether or not the host has got round to
    /// taking the vault yet. There is nothing to lower it for — the host takes the vault, a vault
    /// never comes back into the same handle, and a new unlock starts a new agent.
    lock_requested: Arc<AtomicBool>,
    /// Whether the host has been told about `lock_requested` ([`Agent::take_lock_request`]), so
    /// it is told once rather than on every poll. Separate from the flag itself on purpose: the
    /// report is consumed, the lock is not.
    lock_reported: AtomicBool,
    stopping: Arc<AtomicBool>,
    /// Every `run_with_env` child currently running under an injected environment, so a lock can
    /// end them (mcp-server.md's "lock ends what an approval started").
    children: Arc<ChildRegistry>,
    /// Every connection being served right now, each with the means to end it from
    /// [`Agent::stop`]. See [`kagisecure_ipc::sever`] for why a stop that skipped them would not
    /// release the endpoint on Windows.
    connections: LiveConnections,
    /// The agent-fill broker, if this host serves `request_fill`. Process-wide, not this agent's:
    /// a lock empties its grants, a stop leaves it for the next agent.
    agent_fill: Option<Arc<AgentFillBroker>>,
    /// The machine vault the host attached ([`Agent::attach_machine_vault`]), served beside the
    /// personal vault while it is unlocked, and locked with it (ADR-0042 §2).
    machine: crate::service::MachineSlot,
}

impl Shared {
    /// What a vault lock does to an agent, in one place: no more questions, no more leases, and
    /// nothing left on disk that a lease authorized.
    ///
    /// Returns one `Failed` audit draft (tool `tool`) per written file that was left alone because
    /// its path no longer names the file kagisecure wrote ([`crate::service::shred_written`]), for
    /// the caller to record wherever it still can.
    fn on_vault_locked(&self, tool: &str) -> Vec<kagisecure_core::audit::AuditDraft> {
        // The ordinary socket reads the machine vault only while the personal vault is unlocked:
        // its key came from the personal body, so it goes with it.
        if let Some(machine) = self
            .machine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            drop(machine.take());
        }
        self.queue.deny_all();
        if let Some(broker) = &self.agent_fill {
            broker.revoke_all();
        }
        let entries = self
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_all();
        crate::service::shred_written(entries, tool).1
    }

    /// [`Self::on_vault_locked`] for a caller with the vault still unlocked (a stop, the Leases
    /// table's "Revoke all"): what it could not shred is recorded best-effort.
    fn revoke_everything_and_record(&self, tool: &str) {
        for draft in self.on_vault_locked(tool) {
            let _ = self
                .handle
                .record_best_effort(crate::vault::REQUEST_LOCK_TIMEOUT, draft);
        }
    }

    /// The other half of "lock ends what an approval started": end every `run_with_env` child
    /// still running under an injected environment, and record why.
    ///
    /// A [`crate::vault::VaultLockHook`], not a [`crate::vault::LockHook`], because it is the one
    /// piece of lock cleanup that must *write* something durable — a `Failed`/`KILLED_ON_LOCK`
    /// entry per child — and by the time an ordinary `LockHook` runs, the vault this would write
    /// to is already gone from the handle. `VaultHandle::take` runs this one with the vault still
    /// in hand, so `vault.queue_audit` here rides out on `take`'s own closing
    /// [`kagisecure_core::Vault::flush_audit`], best-effort like every other queued entry.
    fn kill_children_for_lock(&self, vault: &mut Vault) {
        for draft in self
            .children
            .kill_all_for_lock(crate::children::CHILD_KILL_GRACE)
        {
            vault.queue_audit(draft);
        }
    }

    /// `Agent::stop()`'s own version of the same cleanup: end every `run_with_env` child still
    /// running under an injected environment, and record a best-effort `Failed`/`KILLED_ON_STOP`
    /// entry per child.
    ///
    /// Unlike [`Self::kill_children_for_lock`], stopping does not take the vault away — the app
    /// may quit or the agent may be toggled off with the vault still unlocked — so there is no
    /// vault-lock hook handing this a `&mut Vault` to queue onto. It uses the ordinary
    /// [`crate::vault::VaultHandle::record_best_effort`] instead, ridden out on this handle like
    /// any other queued entry; a locked vault (nothing to record onto) makes this a no-op, which
    /// is the right answer since a locked vault already took every lease and child with it.
    fn kill_children_for_stop(&self) {
        for draft in self
            .children
            .kill_all_for_stop(crate::children::CHILD_KILL_GRACE)
        {
            let _ = self
                .handle
                .record_best_effort(crate::vault::REQUEST_LOCK_TIMEOUT, draft);
        }
    }
}

/// A running (or stopped) IPC listener over a shared vault.
pub struct Agent {
    shared: Arc<Shared>,
    endpoint: Endpoint,
    accept: Option<std::thread::JoinHandle<()>>,
    /// This agent's own lock hook, held only so `stop` can retire it by dropping this — which
    /// deregisters exactly this entry and nothing another subsystem (the browser-extension
    /// listener, concretely) has registered on the same [`VaultHandle`]. See
    /// [`crate::vault::LockHookGuard`]'s own doc comment for why that isolation holds.
    vault_lock_hook: Option<LockHookGuard>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("endpoint", &self.endpoint.to_string())
            .field("running", &self.accept.is_some())
            .finish()
    }
}

impl Agent {
    /// Bind the socket and start accepting.
    ///
    /// # Errors
    ///
    /// [`AgentError::AlreadyBound`] when another kagisecure process holds the socket — which is
    /// exactly the app-versus-daemon collision architecture.md §4.2 has to make legible — or
    /// [`AgentError::Endpoint`] if the directory cannot be prepared.
    pub fn start(handle: Arc<VaultHandle>, config: &AgentConfig) -> Result<Self, AgentError> {
        let endpoint = match &config.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => Endpoint::discover()?,
        };
        let server = match Server::bind(&endpoint) {
            Ok(s) => s,
            Err(EndpointError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse =>
            {
                return Err(AgentError::AlreadyBound {
                    endpoint: endpoint.to_string(),
                });
            }
            Err(e) => return Err(AgentError::from(e)),
        };

        // Poll rather than park, so `stop()` is deterministic even when the socket file has
        // already been swept out from under us (a `TempDir` in a test, a deleted run directory).
        server.set_accept_nonblocking(true).map_err(|source| {
            AgentError::Endpoint(EndpointError::Io {
                path: std::path::PathBuf::from(endpoint.to_string()),
                source,
            })
        })?;

        let shared = Arc::new(Shared {
            handle: Arc::clone(&handle),
            leases: Arc::new(Mutex::new(LeaseStore::new())),
            queue: config
                .queue
                .clone()
                .unwrap_or_else(|| Arc::new(ApprovalQueue::new())),
            lock_requested: Arc::new(AtomicBool::new(false)),
            lock_reported: AtomicBool::new(false),
            stopping: Arc::new(AtomicBool::new(false)),
            children: Arc::new(ChildRegistry::new()),
            connections: LiveConnections::new(),
            agent_fill: config.agent_fill.clone(),
            machine: Arc::new(Mutex::new(None)),
        });
        shared.queue.reopen();

        // The hook is what makes "lock means locked" true even for a request already in flight.
        // `Weak` so the handle does not keep a stopped agent alive. The guard it returns is kept
        // on `Self` so `stop` can retire exactly this hook later, without touching whatever else
        // is registered on `handle` (the browser-extension listener's own hook, concretely).
        //
        // A vault lock hook — run after the vault has left the handle, but with it still in hand
        // (see `VaultLockHook`'s own doc comment) — because two parts of this cleanup must record
        // what they did: a written file left alone because its path no longer names what
        // kagisecure wrote, and a running `run_with_env` child ended by the lock.
        let weak: Weak<Shared> = Arc::downgrade(&shared);
        let vault_lock_hook = handle.add_vault_lock_hook(Box::new(move |vault| {
            if let Some(shared) = weak.upgrade() {
                for draft in shared.on_vault_locked("lock") {
                    vault.queue_audit(draft);
                }
                shared.kill_children_for_lock(vault);
            }
        }));

        let accept_shared = Arc::clone(&shared);
        let accept = std::thread::Builder::new()
            .name("kagisecure-agent-accept".to_owned())
            .spawn(move || accept_loop(&server, &accept_shared))
            .map_err(|source| {
                AgentError::Endpoint(EndpointError::Io {
                    path: std::path::PathBuf::from(endpoint.to_string()),
                    source,
                })
            })?;

        Ok(Self {
            shared,
            endpoint,
            accept: Some(accept),
            vault_lock_hook: Some(vault_lock_hook),
        })
    }

    /// Serve the machine vault `machine` beside the personal vault, or stop serving it with
    /// `None` (ADR-0042 §2). The host opens it with the key from the unlocked personal vault; a
    /// lock of the personal vault drops it. Interactive use only: every release from it asks the
    /// person exactly as the personal vault does.
    pub fn attach_machine_vault(&self, machine: Option<Arc<VaultHandle>>) {
        let previous = std::mem::replace(
            &mut *self
                .shared
                .machine
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            machine,
        );
        if let Some(previous) = previous {
            let still_attached = self
                .shared
                .machine
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|now| Arc::ptr_eq(now, &previous));
            if !still_attached {
                drop(previous.take());
            }
        }
    }

    /// Where this agent is listening.
    #[must_use]
    pub fn endpoint(&self) -> String {
        self.endpoint.to_string()
    }

    /// A snapshot for the menu bar and the Agent access pane.
    #[must_use]
    pub fn status(&self) -> AgentStatus {
        let active = u32::try_from(
            self.shared
                .leases
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .summaries(unix_now())
                .len(),
        )
        .unwrap_or(u32::MAX);
        AgentStatus {
            running: self.accept.is_some() && !self.shared.stopping.load(Ordering::SeqCst),
            endpoint: self.endpoint.to_string(),
            pending_approvals: u32::try_from(self.shared.queue.waiting()).unwrap_or(u32::MAX),
            active_leases: active,
            vault_unlocked: self.shared.handle.is_unlocked(),
        }
    }

    /// The approval queue, so a host can wait on it without holding a lock on the agent itself.
    #[must_use]
    pub fn queue(&self) -> Arc<ApprovalQueue> {
        Arc::clone(&self.shared.queue)
    }

    /// Block for up to `timeout` waiting for something to ask the user.
    #[must_use]
    pub fn next_request(&self, timeout: Duration) -> Option<ApprovalRequest> {
        self.shared.queue.next(timeout)
    }

    /// Everything still waiting for an answer, delivered or not.
    #[must_use]
    pub fn pending_requests(&self) -> Vec<ApprovalRequest> {
        self.shared.queue.snapshot()
    }

    /// Answer one request. `false` means the id is unknown — normally because it timed out.
    pub fn resolve(&self, id: &str, decision: &Decision, verification: ClientVerification) -> bool {
        self.shared.queue.resolve(id, decision, verification)
    }

    /// Live leases, newest state, for the Leases table (ui-spec.md §10.4).
    #[must_use]
    pub fn leases(&self) -> Vec<LeaseSummary> {
        self.shared
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .summaries(unix_now())
    }

    /// Revoke one lease and shred anything written under it. `false` if there was no such lease.
    pub fn revoke_lease(&self, id: LeaseId) -> bool {
        let paths = self
            .shared
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke(id);
        match paths {
            None => false,
            Some(entries) => {
                let (_, skipped) = crate::service::shred_written(entries, "revoke_lease");
                for draft in skipped {
                    let _ = self
                        .shared
                        .handle
                        .record_best_effort(crate::vault::REQUEST_LOCK_TIMEOUT, draft);
                }
                true
            }
        }
    }

    /// Revoke everything.
    pub fn revoke_all_leases(&self) {
        self.shared
            .revoke_everything_and_record("revoke_all_leases");
        self.shared.queue.reopen();
    }

    /// Whether a caller asked the vault to lock (`kagisecure lock`) since the host last asked:
    /// `true` once per lock request.
    ///
    /// The host polls this and performs the lock itself, because the host owns the vault's
    /// lifetime — see `Service::lock`. Only the *report* is consumed. The lock itself stays in
    /// force: this agent serves nothing from the moment the lock was acknowledged, including in
    /// the gap between this call and the host taking the vault — which is exactly the gap an
    /// earlier version, clearing the flag here, reopened.
    pub fn take_lock_request(&self) -> bool {
        self.shared.lock_requested.load(Ordering::SeqCst)
            && !self.shared.lock_reported.swap(true, Ordering::SeqCst)
    }

    /// Stop accepting, deny everything outstanding, drop every lease, end every `run_with_env`
    /// child still running under an injected environment, and end every connected sidecar's
    /// session.
    ///
    /// The child cleanup is "lock ends what an approval started" applied to a plain stop — an app
    /// quit, or the agent toggled off — rather than to a vault lock: an approval that already
    /// released a value into a running child must not survive the thing that authorized it going
    /// away, whether that thing is the vault or the agent itself.
    ///
    /// Dropping `vault_lock_hook` retires only this agent's own lock hook — the guard deregisters
    /// just the entry it was returned for (see [`crate::vault::LockHookGuard`]) — so a stopped
    /// agent is not woken by a later lock without also silencing the browser-extension
    /// listener's hook on the same [`VaultHandle`], which this used to do by calling a
    /// since-removed `clear_lock_hook` that emptied every hook on the handle, whoever registered
    /// it.
    ///
    /// Safe to call twice.
    ///
    /// Ending the sessions is what lets the same endpoint be bound again by the next
    /// [`Agent::start`] — which is what the app does on every unlock after a lock. On Windows a
    /// pipe name lives as long as any accepted instance of it is open, so a stop that left a
    /// sidecar's thread parked in its read would leave the name taken and the restart refused
    /// (see [`kagisecure_ipc::sever`]; `tests/agent_restart.rs` is the scenario). On Unix the
    /// stale session would have lingered until the sidecar next spoke — and then been *served*,
    /// by a stopped agent, over a socket it had given up. Ending it here makes both platforms
    /// behave the same way: the sidecar sees its connection close, and its next tool call
    /// connects to whatever is listening now.
    ///
    /// Blocks for at most `STOP_DRAIN` waiting for the severed sessions' threads to let go.
    pub fn stop(&mut self) {
        if self.shared.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.vault_lock_hook = None;
        // Before severing: this denies every queued approval, so a connection waiting at the
        // sheet returns from its request and reaches its read, where the severing ends it.
        self.shared.revoke_everything_and_record("agent_stop");
        // Likewise before severing: a connection whose `run_with_env` is waiting on its child
        // returns once the child is ended, instead of holding its handle — and, on Windows, the
        // pipe name — for the rest of that call's timeout.
        self.shared.kill_children_for_stop();
        // The accept thread next, so that no connection can be accepted — and so escape the
        // severing below — after it has run.
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
        let _ = self.shared.connections.sever_all(STOP_DRAIN);
        if let Some(path) = self.endpoint.path() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(server: &Server, shared: &Arc<Shared>) {
    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let mut connection = match server.accept() {
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
        let ticket = shared.connections.arrived(severer);
        let serving = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("kagisecure-agent-conn".to_owned())
            .spawn(move || {
                serve_connection(&serving, &mut connection);
                // Every handle to the connection is closed *before* it leaves the registry, which
                // is the order `LiveConnections::sever_all` relies on.
                drop(connection);
                serving.connections.gone(ticket);
            });
        if spawned.is_err() {
            // Out of threads: the honest answer is to drop the connection rather than to serve it
            // on the accept thread and stall every other caller. The closure, and the connection
            // in it, were dropped with the failed spawn, so its handles are closed; its entry
            // goes too, or its severer's duplicate handle would keep the endpoint taken.
            shared.connections.gone(ticket);
        }
    }
}

fn serve_connection(shared: &Arc<Shared>, connection: &mut Connection) {
    // The same-user check is the one piece of caller verification the kernel can settle on every
    // platform, and it is a hard gate rather than a warning (threat-model M-13/M-15). It is also
    // fail-closed: `peer_is_same_user` refuses a peer whose uid the kernel would not report,
    // rather than skipping the comparison, so the gate cannot be removed by making one of its
    // two inputs unavailable (D-9). On Windows, where a pipe has no uid, it compares the token
    // SID behind the kernel's pid for the peer instead — never a pid the peer reported itself.
    let identity = connection.identity();
    if !peer_is_same_user(identity.euid, identity.kernel_pid()) {
        let _ = connection.write_response(&Response::error(
            ErrorCode::Internal,
            "This socket only serves the user who owns it.",
        ));
        return;
    }

    let service = Service::new(
        Arc::clone(&shared.handle),
        Arc::clone(&shared.leases),
        Arc::clone(&shared.queue),
        Arc::clone(&shared.lock_requested),
        Arc::clone(&shared.stopping),
        Arc::clone(&shared.children),
        shared.agent_fill.clone(),
    )
    .with_machine(Arc::clone(&shared.machine));

    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let request = match connection.read_request() {
            Ok(r) => r,
            Err(_) => return,
        };
        // Checked again after the read, as the extension listener does: this thread may have been
        // parked in `read_request` while the host stopped, and a request arriving after a stop
        // must not be served by an agent whose leases, children, lock hook and socket are already
        // gone. `stop` severs the connection as well, but a request already in flight can win
        // that race; this is what catches it. Closing is what makes the caller reconnect to
        // whatever is listening now.
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let response = service.handle(&request, connection);
        if connection.write_response(&response).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use kagisecure_core::Vault;
    use kagisecure_core::lease::{LeaseRequest, LeaseStore};
    use kagisecure_core::proto::{EnvId, LeaseKind};

    use super::*;

    fn scratch_vault(dir: &std::path::Path) -> Vault {
        let mut options = kagisecure_core::vault::CreateOptions::new().expect("options");
        options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
            kagisecure_core::crypto::kdf::MIN_M_KIB,
            kagisecure_core::crypto::kdf::MIN_T,
            1,
        )
        .expect("kdf");
        let (vault, _code) =
            Vault::create(dir.join("v.kagivault"), b"pw", &options).expect("create");
        vault
    }

    fn lease_request() -> LeaseRequest {
        LeaseRequest {
            environment_id: EnvId::new(),
            directory: std::path::PathBuf::from("/tmp"),
            filename: Some(".env".to_owned()),
            variables: BTreeSet::from(["TOKEN".to_owned()]),
            kind: LeaseKind::EnvFile,
            command: None,
            replaces_unowned_file: false,
        }
    }

    #[test]
    fn starting_twice_on_one_socket_is_a_legible_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let config = AgentConfig {
            endpoint: Some(Endpoint::for_instance(dir.path(), "a.sock")),
            queue: None,
            agent_fill: None,
        };
        let first = Agent::start(Arc::clone(&handle), &config).expect("first agent");

        let second_handle = VaultHandle::new(scratch_vault(&dir.path().join("second")));
        std::fs::create_dir_all(dir.path().join("second")).ok();
        let error = Agent::start(second_handle, &config);
        match error {
            Err(AgentError::AlreadyBound { endpoint }) => {
                assert!(endpoint.contains("a.sock"), "{endpoint}");
            }
            other => panic!("expected AlreadyBound, got {other:?}"),
        }
        drop(first);
    }

    #[test]
    fn locking_the_vault_kills_every_lease_and_denies_what_is_waiting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let agent = Agent::start(
            Arc::clone(&handle),
            &AgentConfig {
                queue: None,
                agent_fill: None,
                endpoint: Some(Endpoint::for_instance(dir.path(), "b.sock")),
            },
        )
        .expect("agent");

        agent
            .shared
            .leases
            .lock()
            .unwrap()
            .grant(&lease_request(), "test", 900, 10, unix_now());
        assert_eq!(agent.leases().len(), 1);

        // Something is mid-approval when the user locks.
        let queue = Arc::clone(&agent.shared.queue);
        let asker = std::thread::spawn(move || queue.ask(ApprovalRequest::default()));
        // Let it queue.
        let _ = agent.next_request(Duration::from_secs(5));

        drop(handle.take());

        let outcome = asker.join().expect("asker");
        assert!(!outcome.granted, "a locked vault grants nothing");
        assert_eq!(outcome.code, ErrorCode::VaultLocked);
        assert!(
            agent.leases().is_empty(),
            "locking must drop every lease (mcp-server.md §5)"
        );
        assert!(!agent.status().vault_unlocked);
    }

    #[test]
    fn revoking_a_lease_removes_it_from_the_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let agent = Agent::start(
            handle,
            &AgentConfig {
                queue: None,
                agent_fill: None,
                endpoint: Some(Endpoint::for_instance(dir.path(), "c.sock")),
            },
        )
        .expect("agent");
        let id = agent.shared.leases.lock().unwrap().grant(
            &lease_request(),
            "test",
            900,
            10,
            unix_now(),
        );
        assert_eq!(agent.leases().len(), 1);
        assert!(agent.revoke_lease(id));
        assert!(agent.leases().is_empty());
        assert!(!agent.revoke_lease(id), "revoking twice is not a lie");
    }

    #[test]
    fn an_expired_lease_leaves_the_table_on_its_own() {
        let mut store = LeaseStore::new();
        let now = unix_now();
        store.grant(&lease_request(), "test", 60, 10, now);
        assert_eq!(store.summaries(now).len(), 1);
        assert!(
            store.summaries(now + 61).is_empty(),
            "expiry is enforced by the store, not by a UI timer"
        );
    }

    #[test]
    fn stopping_is_idempotent_and_removes_the_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let endpoint = Endpoint::for_instance(dir.path(), "d.sock");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let mut agent = Agent::start(
            handle,
            &AgentConfig {
                endpoint: Some(endpoint.clone()),
                queue: None,
                agent_fill: None,
            },
        )
        .expect("agent");
        // Only a filesystem socket leaves something behind to remove: a named pipe goes away
        // with the handle that created it, so on Windows there is no file to look for. The
        // idempotence of `stop()` is asserted either way.
        let socket = endpoint.path().map(std::path::Path::to_path_buf);
        if let Some(socket) = &socket {
            assert!(socket.exists());
        }
        agent.stop();
        agent.stop();
        if let Some(socket) = &socket {
            assert!(!socket.exists());
        }
        assert!(!agent.status().running);
    }

    /// Real-child kill test, Unix-only, exactly as `crate::children`'s own tests are: exercising
    /// [`ChildKillHandle::kill`] end to end needs a real process, and `sleep` is the fixture
    /// `kagisecure-childproc` and `crate::children` both already use.
    #[test]
    #[cfg(unix)]
    fn stopping_the_agent_kills_a_tracked_child_and_records_killed_on_stop() {
        use kagisecure_core::audit::AuditDraft;
        use kagisecure_core::proto::Outcome;

        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let mut agent = Agent::start(
            Arc::clone(&handle),
            &AgentConfig {
                queue: None,
                agent_fill: None,
                endpoint: Some(Endpoint::for_instance(dir.path(), "f.sock")),
            },
        )
        .expect("agent");

        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        let mut child =
            kagisecure_core::inject::Spawned::spawn(&mut command, true).expect("spawn sleep");
        let kill = child.kill_handle();
        let _id = agent.shared.children.register(
            kill,
            AuditDraft {
                tool: "run_with_env".to_owned(),
                ..AuditDraft::default()
            },
            3,
        );
        assert_eq!(agent.shared.children.len(), 1);

        // Stopping the agent — not locking the vault — must still end the child, the same way a
        // lock would (mcp-server.md's "lock ends what an approval started" applies to a plain
        // stop too).
        agent.stop();

        assert!(agent.shared.children.is_empty());
        let started = std::time::Instant::now();
        loop {
            if child.try_reap().expect("try_reap").is_some() {
                break;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "should have died by now"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        // The vault was never locked, so it is still there to check: the audit log carries a
        // best-effort `Failed`/`KILLED_ON_STOP` entry naming the `Allowed` entry it followed.
        let entries = handle
            .with(|v| v.audit_entries().to_vec())
            .expect("still unlocked");
        assert!(
            entries.iter().any(|e| {
                e.tool == "run_with_env"
                    && e.outcome == Outcome::Failed
                    && e.detail.as_deref() == Some("KILLED_ON_STOP (entry 3)")
            }),
            "{entries:?}"
        );
    }

    /// The other interleaving of the lock race: the release was prepared, the vault locks — its
    /// hooks drain this agent's child registry, which is still empty — and only then does the
    /// child spawn and register. It must be killed anyway, not left running with the injected
    /// value where no later lock will look for it.
    ///
    /// Driven through the real `run_with_env_tracked` and the real vault-lock hook: the `on_spawn`
    /// callback completes the lock (`VaultHandle::take`) and then registers, exactly the order a
    /// lock landing between `prepare_release` and the spawn produces.
    #[test]
    #[cfg(unix)]
    fn a_child_spawned_just_after_a_lock_is_killed_not_left_running() {
        use kagisecure_core::audit::AuditDraft;
        use kagisecure_core::inject::{RunRequest, run_with_env_tracked};

        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let agent = Agent::start(
            Arc::clone(&handle),
            &AgentConfig {
                queue: None,
                agent_fill: None,
                endpoint: Some(Endpoint::for_instance(dir.path(), "g.sock")),
            },
        )
        .expect("agent");

        let program = std::ffi::OsString::from("sleep");
        let args = [std::ffi::OsString::from("20")];
        let mut request = RunRequest::new(&program, &args, &[]);
        request.timeout = Some(Duration::from_secs(30));
        request.new_process_group = true;

        let started = std::time::Instant::now();
        let outcome = run_with_env_tracked(&request, |kill| {
            drop(handle.take());
            let _ = agent.shared.children.register(
                kill,
                AuditDraft {
                    tool: "run_with_env".to_owned(),
                    ..AuditDraft::default()
                },
                1,
            );
        })
        .expect("spawned");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the child outlived the lock: {:?}",
            started.elapsed()
        );
        assert_eq!(outcome.exit_code, None, "it was killed, not left to finish");
        assert!(agent.shared.children.is_empty());
    }

    #[test]
    fn the_lock_request_flag_is_consumed_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let agent = Agent::start(
            handle,
            &AgentConfig {
                queue: None,
                agent_fill: None,
                endpoint: Some(Endpoint::for_instance(dir.path(), "e.sock")),
            },
        )
        .expect("agent");
        assert!(!agent.take_lock_request());
        agent.shared.lock_requested.store(true, Ordering::SeqCst);
        assert!(agent.take_lock_request());
        assert!(!agent.take_lock_request());
    }
}
