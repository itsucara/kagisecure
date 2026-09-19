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

use kagisecure_core::inject::envfile;
use kagisecure_core::lease::LeaseStore;
use kagisecure_core::proto::{LeaseId, LeaseSummary};
use kagisecure_core::unix_now;
use kagisecure_ipc::endpoint::{Endpoint, EndpointError};
use kagisecure_ipc::protocol::{ErrorCode, Response};
use kagisecure_ipc::server::{Connection, Server, own_uid};

use crate::approval::{ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
use crate::service::Service;
use crate::vault::VaultHandle;

/// How long the accept loop sleeps between polls. Long enough not to spin, short enough that a
/// connecting sidecar does not notice.
const ACCEPT_POLL: Duration = Duration::from_millis(25);

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
    pub socket_path: Option<std::path::PathBuf>,
    /// Ask through this queue instead of a fresh one.
    ///
    /// The app passes the same `Arc` it gives [`crate::ExtensionAgent`], so an MCP approval and a
    /// browser-fill approval arrive in one queue, on one sheet, behind one biometric gate
    /// (M6/ADR-0020). `None` keeps the M4 behaviour — a queue of this agent's own — which is what
    /// `kagisecure daemon` wants, since it serves no browsers.
    pub queue: Option<Arc<ApprovalQueue>>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("socket_path", &self.socket_path)
            .field("shared_queue", &self.queue.is_some())
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
    lock_requested: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

impl Shared {
    /// What a vault lock does to an agent, in one place: no more questions, no more leases, and
    /// nothing left on disk that a lease authorized.
    fn on_vault_locked(&self) {
        self.queue.deny_all();
        let paths = self
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke_all();
        for path in paths {
            let _ = envfile::shred(&path);
        }
    }
}

/// A running (or stopped) IPC listener over a shared vault.
pub struct Agent {
    shared: Arc<Shared>,
    endpoint: Endpoint,
    accept: Option<std::thread::JoinHandle<()>>,
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
        let endpoint = match &config.socket_path {
            Some(path) => Endpoint::Path(path.clone()),
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
            stopping: Arc::new(AtomicBool::new(false)),
        });
        shared.queue.reopen();

        // The hook is what makes "lock means locked" true even for a request already in flight.
        // `Weak` so the handle does not keep a stopped agent alive.
        let weak: Weak<Shared> = Arc::downgrade(&shared);
        handle.set_lock_hook(Box::new(move || {
            if let Some(shared) = weak.upgrade() {
                shared.on_vault_locked();
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
        })
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
            Some(paths) => {
                for path in paths {
                    let _ = envfile::shred(&path);
                }
                true
            }
        }
    }

    /// Revoke everything.
    pub fn revoke_all_leases(&self) {
        self.shared.on_vault_locked();
        self.shared.queue.reopen();
    }

    /// Whether a caller asked the vault to lock (`kagisecure lock`), clearing the flag.
    ///
    /// The host polls this and performs the lock itself, because the host owns the vault's
    /// lifetime — see `Service::lock`.
    pub fn take_lock_request(&self) -> bool {
        self.shared.lock_requested.swap(false, Ordering::SeqCst)
    }

    /// Stop accepting, deny everything outstanding, and drop every lease.
    ///
    /// Safe to call twice.
    pub fn stop(&mut self) {
        if self.shared.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        self.shared.handle.clear_lock_hook();
        self.shared.on_vault_locked();
        if let Some(thread) = self.accept.take() {
            let _ = thread.join();
        }
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
        let shared = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("kagisecure-agent-conn".to_owned())
            .spawn(move || serve_connection(&shared, &mut connection));
        if spawned.is_err() {
            // Out of threads: the honest answer is to drop the connection rather than to serve it
            // on the accept thread and stall every other caller.
            continue;
        }
    }
}

fn serve_connection(shared: &Arc<Shared>, connection: &mut Connection) {
    // The same-user check is the one piece of caller verification the kernel can settle on every
    // platform, and it is a hard gate rather than a warning (threat-model M-13/M-15).
    if let (Some(peer), Some(mine)) = (connection.identity().euid, own_uid())
        && peer != mine
    {
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
    );

    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let request = match connection.read_request() {
            Ok(r) => r,
            Err(_) => return,
        };
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
        options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(8, 1, 1).expect("kdf");
        let (vault, _code) =
            Vault::create(dir.join("v.kagivault"), b"pw", &options).expect("create");
        vault
    }

    fn lease_request() -> LeaseRequest {
        LeaseRequest {
            environment_id: EnvId::new(),
            directory: std::path::PathBuf::from("/tmp"),
            variables: BTreeSet::from(["TOKEN".to_owned()]),
            kind: LeaseKind::EnvFile,
            command: None,
        }
    }

    #[test]
    fn starting_twice_on_one_socket_is_a_legible_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("a.sock");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let config = AgentConfig {
            socket_path: Some(socket.clone()),
            queue: None,
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
                socket_path: Some(dir.path().join("b.sock")),
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
                socket_path: Some(dir.path().join("c.sock")),
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
        let socket = dir.path().join("d.sock");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let mut agent = Agent::start(
            handle,
            &AgentConfig {
                socket_path: Some(socket.clone()),
                queue: None,
            },
        )
        .expect("agent");
        assert!(socket.exists());
        agent.stop();
        agent.stop();
        assert!(!socket.exists());
        assert!(!agent.status().running);
    }

    #[test]
    fn the_lock_request_flag_is_consumed_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let handle = VaultHandle::new(scratch_vault(dir.path()));
        let agent = Agent::start(
            handle,
            &AgentConfig {
                queue: None,
                socket_path: Some(dir.path().join("e.sock")),
            },
        )
        .expect("agent");
        assert!(!agent.take_lock_request());
        agent.shared.lock_requested.store(true, Ordering::SeqCst);
        assert!(agent.take_lock_request());
        assert!(!agent.take_lock_request());
    }
}
