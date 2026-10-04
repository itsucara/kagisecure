//! The request handler: one function per IPC message, exactly as `kagisecure daemon` had them.
//!
//! This module is the M2 daemon's `Daemon` impl, moved out of the CLI unchanged in behaviour and
//! changed in two structural ways:
//!
//! 1. **The vault is borrowed, not owned.** Every access goes through [`VaultHandle`], so the app
//!    can lock underneath a request in flight and the next thing this code touches is a `None`.
//! 2. **Approval is a queue round trip, not a terminal read.** `Service::ask` hands an
//!    [`ApprovalRequest`] to the [`ApprovalQueue`] and blocks; whether the answer comes from a
//!    Touch ID sheet or from `y`/`N` on a terminal is not this module's business.
//!
//! The rules that matter did not move: the exact-directory lease match, the "broader request
//! re-prompts" property, the audit entry on every call including denials, and the fact that no
//! value crosses the IPC boundary.
//!
//! # Other processes write the vault too
//!
//! The CLI writes the same file this process serves from (see [`crate::vault`]). So every
//! request first brings the vault up to date with the file (`Service::sync`) — which is what
//! makes a `kagisecure env agent-access --deny` in a terminal hide the environment from the very
//! next request — and every change is a transaction on the file as it is at that moment, with the
//! checks that decide it made again inside the transaction, after the approval sheet.
//!
//! Audit entries come in three kinds:
//!
//! * One that belongs to a change (`create_environment`, `add_variables`) is written in the same
//!   transaction as the change, so they commit or fail together.
//! * One that authorizes a release (`write_env_file`, `run_with_env`) is written **before** the
//!   release, and the release happens only if that write succeeded ([`crate::release`]): fail
//!   closed, `AUDIT_UNAVAILABLE`. A release that then fails or ends abnormally is completed by a
//!   best-effort `Failed` entry naming the first.
//! * Every other entry — a read-only tool, a denial, a refusal, a failure, a revoke, a lock — is
//!   recorded best-effort ([`VaultHandle::record_best_effort`]): it never changes the reply, and a
//!   write that fails leaves it queued rather than lost.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{EnvInjection, RunRequest, envfile, run_with_env_tracked};
use kagisecure_core::lease::{self, LeaseRequest, LeaseStore, WrittenEntry};
use kagisecure_core::model::{Environment, VarSource};
use kagisecure_core::proto::{
    Category, EnvId, EnvironmentSummary, FieldId, ItemId, ItemSummary, LeaseId, LeaseKind, Outcome,
    VarName, VaultId,
};
use kagisecure_core::{Vault, unix_now};
use kagisecure_extension_ipc::origin::Origin;
use kagisecure_ipc::protocol::{
    AddVariablesStatus, AgentFillField, ClientInfo, ErrorCode, MAX_DESCRIPTION_CHARS,
    MAX_ENVIRONMENT_NAME_CHARS, MAX_HINT_CHARS, MAX_RUN_ARGS, MAX_VARIABLES_PER_CALL, OutputMode,
    PROTOCOL_VERSION, Request, Response, VariableRequest, agent_fill_fields_ok, clamp_run_timeout,
    display_text_ok, rfc3339,
};
use kagisecure_ipc::server::{Connection, PeerIdentity};

use crate::approval::{
    ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Outcome as Approval,
};
use crate::catalog::Catalog;
use crate::extension::agent_fill::{self, AgentFillBroker, AgentFillCall, Sidecar};
use crate::release::{self, Acted, NotReleased, Released, audited_release};
use crate::shared::SheetFacts;
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle, WriteFailure, sync_could_not_read};

/// The name this process answers the handshake with.
pub const SERVER_NAME: &str = "kagisecure-agent";

/// The single answer to "there is no such item" **and** to "there is an item you may not see".
///
/// These two must be one reply, byte for byte, or the tool is an enumeration oracle: a caller
/// walks ids, watches which ones answer differently, and learns exactly which ids name something
/// real in a vault it is not allowed to read. `agent_visible` exists to stop precisely that
/// (threat-model M-8), so the distinction never reaches the wire — there is no
/// `NOT_AGENT_VISIBLE` for it to reach the wire *as*.
const NO_SUCH_ITEM: &str = "No item with that id. Call list_items again.";

/// The same single answer for an environment. See [`NO_SUCH_ITEM`].
const NO_SUCH_ENVIRONMENT: &str = "No environment with that id. Call list_environments again.";

/// The same single answer for a logical vault. See [`NO_SUCH_ITEM`].
const NO_SUCH_VAULT: &str = "No vault with that id. Call list_vaults again.";

/// The answer to `create_environment` or `add_variables` aimed at a shared vault (ADR-0035 §14,
/// decision 27): agents read shared vaults and never write to them. Given only for a shared vault
/// or environment the agent can already see — anything else is `NOT_FOUND`, as ever.
const SHARED_IS_READ_ONLY: &str = "That vault is shared with other people, and agents cannot \
                                   change a shared vault. Nothing was asked or changed. Use a \
                                   vault that is not shared, or ask the user to make the change \
                                   in kagisecure.";

/// The answer when a variable's binding leads nowhere the agent may go: the item or field is gone,
/// or hidden, trashed or unshared since the binding was made. One fixed sentence for all of them,
/// naming nothing, for the reason in [`NO_SUCH_ITEM`].
const UNRESOLVABLE_BINDING: &str = "A variable in this environment is bound to an item or field \
                                    that does not exist or is not shared with agents. Nothing was \
                                    released. Ask the user to fix the binding in kagisecure.";

/// The answer to a variable name that is not an identifier (mcp-server.md §2.6).
const INVALID_VARIABLE_NAME: &str = "A variable name must match ^[A-Za-z_][A-Za-z0-9_]*$ and be at \
                                     most 128 characters: letters, digits and underscores, not \
                                     starting with a digit. Nothing was changed. Fix the name and \
                                     retry.";

/// The answer to `add_variables` naming a variable the environment already has (mcp-server.md
/// §2.6). There is no tool that removes or replaces one: that is the user's, in kagisecure.
const VARIABLE_EXISTS: &str = "The environment already has a variable with one of those names. \
                               add_variables only adds; it does not replace, and there is no tool \
                               to remove one. Nothing was changed. Leave out the existing names, \
                               or ask the user to change that variable in kagisecure.";

/// The answer when another process holds the vault file's write lock for too long.
const VAULT_BUSY: &str = "Another kagisecure process is writing to the vault, so nothing was \
                          changed. Wait a few seconds, then retry once.";

/// The answer when the vault file no longer continues what this session last saw on disk.
const VAULT_CONFLICT: &str = "The vault file on disk no longer matches the unlocked vault: it was \
                              restored from an older copy, replaced, or removed. Nothing was \
                              changed. Tell the user to open kagisecure and resolve it; do not \
                              retry until they have.";

/// The answer when a release was refused because its audit entry could not be written first.
const AUDIT_UNAVAILABLE: &str = "kagisecure could not record this request in the vault's audit \
                                 log, so nothing was released: no file was written and no command \
                                 was run. Tell the user the vault cannot be written right now \
                                 (kagisecure shows why); do not retry in a loop.";

/// The answer to `request_fill` when agent fills cannot be served at all (ADR-0036 §11.2).
///
/// Fixed, and given before the item is looked up, so it is the same for every item id — real,
/// hidden or made up — and cannot be used to learn anything about one.
const FILL_UNAVAILABLE: &str = "kagisecure cannot fill a browser tab for an agent right now: agent \
                                fills are turned off, or no browser with the kagisecure extension \
                                is connected. Nothing was filled. Tell the user; do not retry.";

/// The answer to a `request_fill` origin that is not an http(s) origin.
const INVALID_FILL_ORIGIN: &str = "origin must be the http or https origin of the page you have \
                                   open, such as https://example.com. Nothing was asked or filled. \
                                   Fix the argument and retry.";

/// The answer to a `request_fill` field list the schema does not accept.
const INVALID_FILL_FIELDS: &str = "fields must name username, password or both, each at most once, \
                                   or one_time_code on its own. Nothing was asked or filled. Fix \
                                   the argument and retry.";

/// The longest `origin` `request_fill` accepts. An origin is a scheme, a host and a port; this is
/// generous for that, and keeps a string of any length out of the parser.
const MAX_FILL_ORIGIN_CHARS: usize = 2048;

/// What `run_with_env`'s act produced.
enum Ran {
    /// The command ran — to completion, to its deadline, or until a lock ended it.
    Finished(kagisecure_core::inject::RunOutcome),
    /// Nothing was started: the vault locked after the release was prepared and before the spawn.
    NotStarted,
}

/// Whether the agent may still serve: [`Service::is_serving`]'s answer, in a form a release's
/// `act` can carry.
#[derive(Clone)]
struct Gate {
    handle: Arc<VaultHandle>,
    lock_requested: Arc<std::sync::atomic::AtomicBool>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl Gate {
    fn is_serving(&self) -> bool {
        self.handle.is_unlocked() && self.flags_allow()
    }

    /// The two flags alone — neither a lock acknowledged nor the owning agent stopped — without
    /// touching the vault handle's mutex, for a caller already holding the lease-store lock (the
    /// two are never held together in this file).
    fn flags_allow(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        !self.lock_requested.load(SeqCst) && !self.stopping.load(SeqCst)
    }
}

/// A lease use set aside for one release by [`Service::reserve`].
#[derive(Clone, Copy, Debug)]
struct Reservation {
    lease_id: LeaseId,
    /// Whether this call minted the lease, as opposed to finding one an earlier call was
    /// granted. Only a lease minted here is this call's to revoke when the release fails.
    minted: bool,
    /// When the lease expires, for the reply.
    expires_at: u64,
}

/// What a release request selects: the environment's name as the listing shows it, the variable
/// names, and — for a shared environment — what the sheet says about it and what approving it
/// records ([`Service::selected_names`]).
struct Selected {
    env_name: String,
    names: Vec<String>,
    shared: Option<SheetFacts>,
}

/// Why a release's prepare step refused ([`Service::prepare_release`]).
#[derive(Debug)]
enum Refusal {
    /// The vault was locked while the request was in flight.
    Locked,
    /// The environment is gone or hidden, or a variable cannot be resolved.
    Vault(kagisecure_core::Error),
}

/// The state one connection handler needs. Cheap to clone: everything is an `Arc`.
#[derive(Clone)]
pub struct Service {
    handle: Arc<VaultHandle>,
    leases: Arc<Mutex<LeaseStore>>,
    queue: Arc<ApprovalQueue>,
    lock_requested: Arc<std::sync::atomic::AtomicBool>,
    /// The owning agent's own stop flag. Its leases, its children and its lock hook all belong
    /// to that one agent instance; once it has stopped (and emptied them for the last time),
    /// nothing may be served, granted or registered on its behalf.
    stopping: Arc<std::sync::atomic::AtomicBool>,
    /// Every `run_with_env` child currently running under an injected environment — see
    /// `crate::children`.
    children: Arc<crate::children::ChildRegistry>,
    /// The agent-fill broker, when this host serves `request_fill` at all (ADR-0036). `None` —
    /// `kagisecure daemon`, which serves no browser — answers every call `FILL_UNAVAILABLE`.
    agent_fill: Option<Arc<AgentFillBroker>>,
    /// The machine vault, when the host attached one (ADR-0042 §2): read through this socket with
    /// the ordinary sheet and presence proof, like the personal vault, and only while the personal
    /// vault is unlocked — which is when this service serves at all.
    machine: Option<MachineSlot>,
}

/// Where the ordinary agent keeps the machine vault the host attached ([`Service::with_machine`]).
pub type MachineSlot = Arc<Mutex<Option<Arc<VaultHandle>>>>;

impl Service {
    /// Build a service over a shared vault, lease store and approval queue, for the agent whose
    /// lock and stop flags are `lock_requested` and `stopping`, answering `request_fill` through
    /// `agent_fill` when there is one.
    #[must_use]
    pub fn new(
        handle: Arc<VaultHandle>,
        leases: Arc<Mutex<LeaseStore>>,
        queue: Arc<ApprovalQueue>,
        lock_requested: Arc<std::sync::atomic::AtomicBool>,
        stopping: Arc<std::sync::atomic::AtomicBool>,
        children: Arc<crate::children::ChildRegistry>,
        agent_fill: Option<Arc<AgentFillBroker>>,
    ) -> Self {
        Self {
            handle,
            leases,
            queue,
            lock_requested,
            stopping,
            children,
            agent_fill,
            machine: None,
        }
    }

    /// Serve the machine vault in `slot` too, beside the personal vault (ADR-0042 §2): its
    /// environments are listed with the personal vault's, and `write_env_file` and `run_with_env`
    /// for one of them are served against it — the same sheet, the same leases, recorded in the
    /// machine vault's log. `create_environment`, `add_variables`, `request_fill` and the item
    /// tools never reach it (implementation decision 14).
    #[must_use]
    pub fn with_machine(mut self, slot: MachineSlot) -> Self {
        self.machine = Some(slot);
        self
    }

    /// This service, pointed at the attached machine vault, if one is attached and open.
    fn machine_service(&self) -> Option<Self> {
        let handle = self
            .machine
            .as_ref()?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        if !handle.is_unlocked() {
            return None;
        }
        Some(Self {
            handle,
            machine: None,
            ..self.clone()
        })
    }

    fn has_environment(&self, id: EnvId) -> bool {
        self.handle
            .with(|v| v.environments().iter().any(|e| e.id == id))
            .unwrap_or(false)
    }

    /// Route a request to the machine vault where it belongs there, and add the machine vault's
    /// share to a listing. `None` when the personal vault answers alone.
    fn machine_part(&self, request: &Request, connection: &mut Connection) -> Option<Response> {
        let machine = self.machine_service()?;
        match request {
            Request::WriteEnvFile { environment_id, .. }
            | Request::RunWithEnv { environment_id, .. }
                if !self.has_environment(*environment_id)
                    && machine.has_environment(*environment_id) =>
            {
                Some(machine.handle(request, connection))
            }
            Request::ListVaults | Request::ListEnvironments { .. } => {
                let personal = self.dispatch(request, connection);
                let theirs = machine.handle(request, connection);
                Some(match (personal, theirs) {
                    (Response::Vaults { mut vaults }, Response::Vaults { vaults: more }) => {
                        vaults.extend(more);
                        Response::Vaults { vaults }
                    }
                    (
                        Response::Environments { mut environments },
                        Response::Environments { environments: more },
                    ) => {
                        environments.extend(more);
                        Response::Environments { environments }
                    }
                    (personal, _) => personal,
                })
            }
            _ => None,
        }
    }

    fn leases(&self) -> std::sync::MutexGuard<'_, LeaseStore> {
        self.leases.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Undo a lease `write_env_file`/`run_with_env` minted for this call, if this call then
    /// failed after the grant: the release was refused, its audit entry could not be written, or
    /// the write or spawn itself failed.
    ///
    /// `minted` distinguishes "this call just approved a fresh lease" from "this call found and
    /// reused a lease an earlier, already-successful call was granted" — only the former is this
    /// call's to revoke. Without this, every `Err` path after `LeaseStore::grant` (vault locked,
    /// the environment hidden or the file in conflict by the time of the release, a resolution
    /// error, the A-05 re-resolve refusal, the write/spawn itself failing) leaves a
    /// live, multi-use lease behind that silently authorizes a later request with no sheet, even
    /// though the human never saw the operation it was approved for actually happen.
    ///
    /// The lease store and the vault handle are never held together in this file: leases are
    /// reserved before a release's transaction and revoked or recorded after it, and the
    /// transaction's prepare step reads only the vault.
    fn revoke_if_minted(&self, lease_id: LeaseId, minted: bool) {
        revoke_minted(&self.leases, lease_id, minted);
    }

    /// Handle one request.
    pub fn handle(&self, request: &Request, connection: &mut Connection) -> Response {
        if let Request::Hello { protocol, client } = request {
            return Self::hello(*protocol, client, connection);
        }
        // `request_fill`'s first gate comes before the lock check (ADR-0036 §11.1), so its answer
        // cannot depend on the vault's state or on the item it names. It runs its own gates, in
        // their documented order, from here.
        if let Request::RequestFill {
            item_id,
            origin,
            fields,
        } = request
        {
            return self.request_fill(*item_id, origin, fields, connection);
        }
        if !self.is_serving() {
            // A locked vault kills leases and running children even if the lock hooks somehow did
            // not run: this is the belt to that brace, and it is cheap — an empty registry or
            // lease store makes both calls a no-op.
            self.kill_leases();
            self.kill_running_children();
            return Self::locked();
        }
        // Before anything reads the vault: another process may have changed the file since the
        // last request — hidden an environment, removed an item — and the answer must reflect
        // that now, not whenever this process next happens to write.
        if let Err(refusal) = self.sync()
            && Self::needs_current_file(request)
        {
            return refusal;
        }
        if let Some(response) = self.machine_part(request, connection) {
            return response;
        }
        self.dispatch(request, connection)
    }

    /// The request, against this service's own vault.
    fn dispatch(&self, request: &Request, connection: &mut Connection) -> Response {
        match request {
            Request::Hello { protocol, client } => Self::hello(*protocol, client, connection),
            Request::ListVaults => self.list_vaults(connection),
            Request::ListItems {
                vault_id,
                query,
                category,
                limit,
                cursor,
            } => self.list_items(
                *vault_id,
                query.as_deref(),
                category.as_deref(),
                *limit,
                cursor.as_deref(),
                connection,
            ),
            Request::ListEnvironments { vault_id } => self.list_environments(*vault_id, connection),
            Request::DescribeItem { item_id } => {
                self.describe_item(&item_id.to_string(), connection)
            }
            Request::CreateEnvironment {
                vault_id,
                name,
                description,
            } => self.create_environment(*vault_id, name, description.as_deref(), connection),
            Request::AddVariables {
                environment_id,
                variables,
            } => self.add_variables(*environment_id, variables, connection),
            Request::WriteEnvFile {
                environment_id,
                directory,
                filename,
                variables,
                overwrite,
                ttl_seconds,
            } => self.write_env_file(
                *environment_id,
                directory,
                filename,
                variables.as_deref(),
                *overwrite,
                *ttl_seconds,
                connection,
            ),
            Request::RunWithEnv {
                environment_id,
                command,
                args,
                cwd,
                variables,
                timeout_seconds,
                output,
            } => self.run_with_env(
                *environment_id,
                command,
                args,
                cwd,
                variables.as_deref(),
                *timeout_seconds,
                *output,
                connection,
            ),
            Request::RevokeEnvFile { lease_id, path } => {
                self.revoke(*lease_id, path.as_deref(), connection)
            }
            Request::RequestFill {
                item_id,
                origin,
                fields,
            } => self.request_fill(*item_id, origin, fields, connection),
            Request::Audit { limit, verify } => self.audit(*limit, *verify),
            Request::ListLeases => Response::Leases {
                leases: self.leases().summaries(unix_now()),
            },
            Request::Lock => self.lock(connection),
        }
    }

    /// Whether `request` must be refused when [`Self::sync`] could not confirm the file.
    ///
    /// Everything that reads the vault to decide what an agent may see, change or receive does.
    /// The exceptions are the requests that must work in any state: `revoke_env_file` is cleanup
    /// and cleanup must not fail (see [`Self::revoke`]), `lock` is how the user gets out, the
    /// lease list is this process's own bookkeeping, and `audit` shows this session's log as it
    /// holds it.
    fn needs_current_file(request: &Request) -> bool {
        !matches!(
            request,
            Request::Hello { .. }
                | Request::RevokeEnvFile { .. }
                | Request::Audit { .. }
                | Request::ListLeases
                | Request::Lock
        )
    }

    fn hello(protocol: u32, client: &ClientInfo, connection: &mut Connection) -> Response {
        if protocol != PROTOCOL_VERSION {
            return Response::error(
                ErrorCode::Internal,
                format!(
                    "This build speaks protocol {PROTOCOL_VERSION}; the caller speaks {protocol}."
                ),
            );
        }
        connection.adopt_reported(client.clone());
        let identity = connection.identity().clone();
        Response::Hello {
            server: SERVER_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: PROTOCOL_VERSION,
            client_identity: identity.describe(),
            client_verified: identity.verified(),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Vault access helpers
    // -----------------------------------------------------------------------------------------

    /// Run `f` against the vault, or produce a `VAULT_LOCKED` reply.
    fn read<T>(&self, f: impl FnOnce(&Vault) -> T) -> Result<T, Response> {
        self.handle.with(f).ok_or_else(Self::locked)
    }

    /// Run `f` against the personal vault and the shared vaults attached to it, as one
    /// ([`Catalog`]), or produce a `VAULT_LOCKED` reply.
    fn read_catalog<T>(&self, f: impl FnOnce(&Catalog<'_>) -> T) -> Result<T, Response> {
        let shared = self.handle.shared_snapshots();
        self.read(|vault| f(&Catalog::new(vault, shared)))
    }

    /// Whether this connection may still be served.
    ///
    /// Two conditions, and the second is the interesting one. `is_unlocked` asks whether the host
    /// still holds the vault key. `lock_requested` asks whether somebody has already been *told*
    /// the vault is locked — because [`Self::lock`] answers `Locked` and sets that flag, while the
    /// host drops the key on its own schedule when it next polls [`Agent::take_lock_request`].
    ///
    /// Without the second condition there is a window between those two moments — up to one poll
    /// interval, 250 ms in `kagisecure daemon` — in which `kagisecure lock` has printed "the vault
    /// key and every lease are gone" and the socket is still answering `list_items`, and, with an
    /// approval channel that says yes, still writing `.env` files. "Locking must mean locking" is
    /// the stated rationale for half the lease rules in `docs/mcp-server.md` §5; it has to be true
    /// from the instant the lock is acknowledged, not from the instant the host notices.
    ///
    /// [`Agent::take_lock_request`]: crate::Agent::take_lock_request
    fn is_serving(&self) -> bool {
        self.gate().is_serving()
    }

    /// [`Self::is_serving`], detached from `self` so a release's `act` — which runs without a
    /// `Service` — can make the same check immediately before it spawns.
    fn gate(&self) -> Gate {
        Gate {
            handle: Arc::clone(&self.handle),
            lock_requested: Arc::clone(&self.lock_requested),
            stopping: Arc::clone(&self.stopping),
        }
    }

    fn locked() -> Response {
        Response::error(
            ErrorCode::VaultLocked,
            "The kagisecure vault is locked. Ask the user to unlock it.",
        )
    }

    /// Bring the vault up to date with its file.
    ///
    /// `Err` carries the reply for a request that needs the current file
    /// ([`Self::needs_current_file`]): `VAULT_LOCKED` if the vault locked, `VAULT_CONFLICT` if the
    /// file was read and does not continue this session (an older copy, a different vault,
    /// nothing at the path). That state is sticky by construction — memory is left as it was, so
    /// the next request finds the same file and refuses again — until the file is put back or the
    /// user resolves it in the app. Nothing here ever writes the file.
    ///
    /// A file that could not be *read* is not a conflict: see [`sync_could_not_read`].
    fn sync(&self) -> Result<(), Response> {
        // Shared vaults another process wrote to — the CLI — are picked up the same way, each
        // from its own file; one that cannot be re-read is served as this process last read it.
        self.handle.refresh_shared();
        match self.handle.sync() {
            None => Err(Self::locked()),
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) if sync_could_not_read(&e) => {
                eprintln!("kagisecure: could not re-read the vault file; serving from memory: {e}");
                Ok(())
            }
            Some(Err(e)) => {
                eprintln!("kagisecure: refusing agent requests until the vault is resolved: {e}");
                Err(Self::conflict())
            }
        }
    }

    fn conflict() -> Response {
        Response::error(ErrorCode::VaultConflict, VAULT_CONFLICT)
    }

    /// The reply for a change whose transaction failed, and the code its audit entry records.
    fn write_failed(error: &kagisecure_core::Error) -> (ErrorCode, Response) {
        match WriteFailure::of(error) {
            WriteFailure::Busy => (
                ErrorCode::VaultBusy,
                Response::error(ErrorCode::VaultBusy, VAULT_BUSY),
            ),
            WriteFailure::Conflict => (ErrorCode::VaultConflict, Self::conflict()),
            WriteFailure::Other => (
                ErrorCode::Internal,
                Response::error(ErrorCode::Internal, error.to_string()),
            ),
        }
    }

    /// The set of logical vaults an agent is allowed to know about at all.
    fn visible_vaults(vault: &Vault) -> BTreeSet<VaultId> {
        vault
            .vault_summaries()
            .into_iter()
            .filter(|v| v.agent_visible)
            .map(|v| v.id)
            .collect()
    }

    /// Whether an agent may *bind* to `field` of `item`: the item in the personal vault and
    /// visible by the rule `list_items` and `describe_item` use, and the field's own agent flag,
    /// which is whether `describe_item` discloses the field at all. An agent cannot bind what it
    /// could not have been shown, nor bind a personal environment into a shared vault
    /// ([`Catalog::personal_field_bindable`]).
    fn field_shared(vault: &Vault, item: ItemId, field: FieldId) -> bool {
        Catalog::new(vault, Vec::new()).personal_field_bindable(item, field)
    }

    // -----------------------------------------------------------------------------------------
    // Read-only tools
    // -----------------------------------------------------------------------------------------

    fn list_vaults(&self, connection: &Connection) -> Response {
        let vaults = match self.read_catalog(|catalog| catalog.agent_vaults()) {
            Ok(v) => v,
            Err(response) => return response,
        };
        self.record_best_effort(AuditDraft {
            tool: "list_vaults".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Vaults { vaults }
    }

    fn list_items(
        &self,
        vault_id: Option<VaultId>,
        query: Option<&str>,
        category: Option<&str>,
        limit: usize,
        cursor: Option<&str>,
        connection: &Connection,
    ) -> Response {
        let wanted: Option<Category> = category.map(|c| c.parse().unwrap_or(Category::Login));
        let all = match self.read_catalog(|catalog| {
            catalog
                .agent_items()
                .into_iter()
                .filter(|i| vault_id.is_none_or(|v| i.vault_id == v))
                .filter(|i| wanted.as_ref().is_none_or(|c| &i.category == c))
                .filter(|i| {
                    query.is_none_or(|q| {
                        let needle = q.to_lowercase();
                        i.title.to_lowercase().contains(&needle)
                            || i.tags.iter().any(|t| t.to_lowercase().contains(&needle))
                    })
                })
                .collect::<Vec<ItemSummary>>()
        }) {
            Ok(v) => v,
            Err(response) => return response,
        };

        let start: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
        let end = start.saturating_add(limit).min(all.len());
        let page: Vec<ItemSummary> = all
            .into_iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .collect();
        let next_cursor = (page.len() == limit && limit > 0).then(|| end.to_string());

        self.record_best_effort(AuditDraft {
            tool: "list_items".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Items {
            items: page,
            next_cursor,
        }
    }

    fn list_environments(&self, vault_id: Option<VaultId>, connection: &Connection) -> Response {
        let environments = match self.read_catalog(|catalog| {
            catalog
                .agent_environments()
                .into_iter()
                .filter(|e| vault_id.is_none_or(|v| e.vault_id == v))
                .collect::<Vec<EnvironmentSummary>>()
        }) {
            Ok(v) => v,
            Err(response) => return response,
        };
        self.record_best_effort(AuditDraft {
            tool: "list_environments".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Environments { environments }
    }

    fn describe_item(&self, reference: &str, connection: &Connection) -> Response {
        // By exact id only, like every other agent-facing lookup: a title or an id prefix names
        // nothing here, and is answered exactly like an id that names no item.
        let found = self.read_catalog(|catalog| {
            catalog
                .agent_item(reference)
                .map(|found| (catalog.item_summary(found), found.place.audit_vault()))
        });
        let found = match found {
            Ok(v) => v,
            Err(response) => return response,
        };
        // One answer for absent and hidden on purpose: see `NO_SUCH_ITEM`.
        let Some((summary, shared_vault)) = found else {
            return no_such_item();
        };
        self.record_best_effort(AuditDraft {
            tool: "describe_item".to_owned(),
            vault_id: shared_vault,
            item_id: Some(summary.id),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Item {
            item: Box::new(summary),
        }
    }

    /// `request_fill` (mcp-server.md §2.10, ADR-0036): gates 1–4 here, in §11.1's order, and
    /// gates 5–9 in the broker ([`agent_fill`]).
    ///
    /// 1. **Enabled, and not blocked or limited.** The switch, a kernel-established sidecar (and
    ///    its parent, which every limit is keyed on) to bind a grant to, then
    ///    [`AgentFillBroker::admit`]: a block, a sticky denial, the agent's budget of sheets and
    ///    the one flow slot — all before anything else, so none of them can depend on the vault or
    ///    the item. Then the arguments, which depend on nothing either.
    /// 2. **Vault unlocked**, and up to date with its file.
    /// 3. **The item**, by [`agent_visible_item`] — the one predicate `describe_item` uses — so an
    ///    absent item and a hidden one take the same path to the same bytes, before any browser
    ///    is asked.
    /// 4. **The fields**, and an archived item (implementation decision 13).
    fn request_fill(
        &self,
        item_id: ItemId,
        origin: &str,
        fields: &[AgentFillField],
        connection: &Connection,
    ) -> Response {
        // Gate 1: enabled (and never on Windows), with a sidecar the kernel vouches for.
        let Some(broker) = self.agent_fill.as_ref().filter(|b| b.is_enabled()) else {
            return fill_unavailable();
        };
        let Some(sidecar) = Sidecar::of(connection.identity()) else {
            return fill_unavailable();
        };
        // Gate 1: not blocked or limited (ADR-0036 §9). The claim is only compared here, with
        // the spelling a denial was recorded under; an origin that does not parse matches
        // nothing, and is refused just below.
        let claimed_key = Origin::parse(origin).ok().map(|o| o.ascii_serialization());
        let item_key = item_id.to_string();
        let slot = match broker.admit(&sidecar, &item_key, claimed_key.as_deref(), fields) {
            Ok(slot) => slot,
            Err(refusal) => {
                // The field names only once they are known to be a valid set: nothing unchecked
                // goes into the log.
                let named = if agent_fill_fields_ok(fields) {
                    fields
                } else {
                    &[]
                };
                let (entry, reply) = agent_fill::refused_at_gate_one(
                    refusal,
                    &sidecar,
                    &item_key,
                    claimed_key.as_deref(),
                    named,
                );
                self.record_best_effort(entry);
                return reply;
            }
        };

        // Every way out from here on leaves an entry (ADR-0036 §10), best-effort — a write that
        // fails never changes the answer. Until gate 3 has looked the item up, none names it.
        let refused = |reply: Response| {
            if let Some(entry) = agent_fill::refused_before_the_item(&sidecar, fields, &reply) {
                self.record_best_effort(entry);
            }
            reply
        };

        // The arguments, which the process that owns the vault checks for itself: any local
        // process can speak this protocol without the sidecar.
        if !agent_fill_fields_ok(fields) {
            return refused(Response::error(
                ErrorCode::InvalidArgument,
                INVALID_FILL_FIELDS,
            ));
        }
        let claimed = match Origin::parse(origin) {
            Ok(claimed) if display_text_ok(origin, MAX_FILL_ORIGIN_CHARS, false) => claimed,
            _ => {
                return refused(Response::error(
                    ErrorCode::InvalidArgument,
                    INVALID_FILL_ORIGIN,
                ));
            }
        };

        // Gate 2: the vault.
        if !self.is_serving() {
            return refused(Self::locked());
        }
        if let Err(refusal) = self.sync() {
            return refused(refusal);
        }

        let mut call = AgentFillCall {
            handle: &self.handle,
            queue: &self.queue,
            sidecar,
            item_id: item_id.to_string(),
            claimed_origin: claimed.ascii_serialization(),
            fields: fields.to_vec(),
            vault_id: None,
            standing: Mutex::new(None),
        };
        // Gates 3 and 4, on one read of the vault.
        let looked_up = self.read_catalog(|catalog| {
            catalog.agent_item(&call.item_id).map(|found| {
                (
                    agent_fill::nothing_to_fill(found.value, fields),
                    found.place.audit_vault(),
                )
            })
        });
        match looked_up {
            // Locked since gate 2: no item was looked up, and the entry names none.
            Err(response) => {
                self.record_best_effort(AuditDraft {
                    item_id: None,
                    ..call.entry(Outcome::Denied, ErrorCode::VaultLocked.as_str())
                });
                response
            }
            // Gate 3: absent, hidden, in a hidden vault or trashed — one path, one answer. The
            // entry names no item: it would say which ids are real.
            Ok(None) => {
                self.record_best_effort(AuditDraft {
                    item_id: None,
                    ..call.entry(Outcome::Denied, ErrorCode::NotFound.as_str())
                });
                no_such_item()
            }
            // Gate 4: a field the item has no value for, or an archived item.
            Ok(Some((Some(message), vault_id))) => {
                call.vault_id = vault_id;
                self.record_best_effort(
                    call.entry(Outcome::Denied, ErrorCode::NothingToFill.as_str()),
                );
                Response::error(ErrorCode::NothingToFill, message)
            }
            // Gates 5–9, naming the shared vault the item is in, if it is in one.
            Ok(Some((None, vault_id))) => {
                call.vault_id = vault_id;
                slot.serve(&call)
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Approving tools
    // -----------------------------------------------------------------------------------------

    fn create_environment(
        &self,
        vault_id: Option<VaultId>,
        name: &str,
        description: Option<&str>,
        connection: &Connection,
    ) -> Response {
        // The name goes on the sheet and into the vault; the documented limits hold here, not
        // only in the sidecar (mcp-server.md §2.5).
        if name.trim().is_empty()
            || !display_text_ok(name, MAX_ENVIRONMENT_NAME_CHARS, false)
            || !description.is_none_or(|d| display_text_ok(d, MAX_DESCRIPTION_CHARS, true))
        {
            return Response::error(
                ErrorCode::InvalidArgument,
                "An environment name must be one line of 1 to 128 characters, and a description \
                 at most 512 characters, with no control characters. Nothing was asked or \
                 changed. Fix the argument and retry.",
            );
        }
        // A shared vault the agent can see is named as such: agents never write to one
        // (ADR-0035 §14, decision 27). One it cannot see is `NOT_FOUND` just below, as ever.
        if let Some(wanted) = vault_id {
            match self.read_catalog(|catalog| {
                catalog
                    .agent_vaults()
                    .iter()
                    .any(|v| v.shared && v.id == wanted)
            }) {
                Ok(true) => {
                    return Response::error(ErrorCode::InvalidArgument, SHARED_IS_READ_ONLY);
                }
                Ok(false) => {}
                Err(response) => return response,
            }
        }
        // Checked before the sheet so the human is never asked about a creation that cannot
        // happen, and checked again inside the transaction, where it counts: the sheet may be up
        // for a minute, and the user may hide the vault meanwhile, here or from a terminal.
        match self.read(|vault| Self::target_vault(vault, vault_id)) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Self::target_refused(&e),
            Err(response) => return response,
        }

        let approved = self.ask(
            ApprovalRequest {
                kind: ApprovalKind::CreateEnvironment,
                environment_name: Some(name.to_owned()),
                ..ApprovalRequest::default()
            }
            .with_identity(connection.identity()),
        );
        if !approved.granted {
            return self.denied(
                "create_environment",
                &approved,
                None,
                Vec::new(),
                connection,
            );
        }

        let committed = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            let target = Self::target_vault(tx, vault_id)?;
            let mut env = Environment::new(target, name);
            env.description = description.map(str::to_owned);
            // Created through an approved agent request, so it is visible to the agent that
            // asked. A CLI-created environment stays invisible until the user says otherwise
            // (ADR-0007).
            env.agent_visible = true;
            let summary = env.summary();
            tx.add_environment(env);
            // In the same transaction as the change it describes: both are written, or neither.
            tx.append_audit(AuditDraft {
                tool: "create_environment".to_owned(),
                vault_id: Some(target),
                environment_id: Some(summary.id),
                outcome: Outcome::Allowed,
                ..Self::draft(connection)
            });
            Ok(summary)
        });
        match committed {
            None => Self::locked(),
            Some(Ok(summary)) => Response::Environment {
                environment: Box::new(summary),
            },
            Some(Err(e @ kagisecure_core::Error::ItemNotFound(_))) => Self::target_refused(&e),
            Some(Err(e)) => {
                self.write_refused("create_environment", None, Vec::new(), &e, connection)
            }
        }
    }

    /// The logical vault a new environment goes into: the one named, or the first; either way
    /// one the user has made visible to agents.
    ///
    /// # Errors
    ///
    /// [`kagisecure_core::Error::ItemNotFound`] — the error `Vault::find_vault` uses for a vault —
    /// for a vault that does not exist **or** is hidden, which are one answer for the reason in
    /// [`NO_SUCH_ITEM`]. Creating in a hidden vault would hand back an id the agent cannot then
    /// see.
    fn target_vault(vault: &Vault, wanted: Option<VaultId>) -> kagisecure_core::Result<VaultId> {
        let target = match wanted {
            Some(id) => id,
            None => vault.default_vault_id()?,
        };
        if Self::visible_vaults(vault).contains(&target) {
            Ok(target)
        } else {
            Err(kagisecure_core::Error::ItemNotFound(target.to_string()))
        }
    }

    /// The reply for a [`Self::target_vault`] refusal.
    fn target_refused(error: &kagisecure_core::Error) -> Response {
        match error {
            kagisecure_core::Error::ItemNotFound(_) => {
                Response::error(ErrorCode::NotFound, NO_SUCH_VAULT)
            }
            other => Response::error(ErrorCode::Internal, other.to_string()),
        }
    }

    /// Answer a change whose transaction failed after the human approved it, and record that it
    /// did not happen. The entry the change itself would have written was discarded with it.
    fn write_refused(
        &self,
        tool: &str,
        environment_id: Option<EnvId>,
        variables: Vec<String>,
        error: &kagisecure_core::Error,
        connection: &Connection,
    ) -> Response {
        let (code, response) = Self::write_failed(error);
        let draft = AuditDraft {
            tool: tool.to_owned(),
            environment_id,
            variables,
            outcome: Outcome::Failed,
            detail: Some(code.as_str().to_owned()),
            ..Self::draft(connection)
        };
        if code == ErrorCode::VaultBusy {
            // The holder that just outlasted this request's wait would outlast a second one:
            // queue the entry for the next write instead of making the caller wait twice.
            let _ = self.handle.queue_audit(draft);
        } else {
            self.record_best_effort(draft);
        }
        response
    }

    fn add_variables(
        &self,
        environment_id: EnvId,
        variables: &[VariableRequest],
        connection: &Connection,
    ) -> Response {
        // Every name is checked here, before anything else: before a human is asked about it and
        // long before it is stored. The pattern is mcp-server.md §2.6's, and it is enforced by the
        // process that renders names into `.env` lines and environment blocks — not left to the
        // sidecar, which a hostile caller would simply not run.
        let names = match Self::valid_names(variables) {
            Ok(names) => names,
            Err(response) => return response,
        };
        let reference = environment_id.to_string();
        // A shared environment the agent can see: agents never write to a shared vault
        // (ADR-0035 §14, decision 27). A hidden one is `NOT_FOUND` just below, as ever.
        match self.read_catalog(|catalog| {
            catalog
                .agent_environment(&environment_id)
                .is_some_and(|found| found.place.shared().is_some())
        }) {
            Ok(true) => return Response::error(ErrorCode::InvalidArgument, SHARED_IS_READ_ONLY),
            Ok(false) => {}
            Err(response) => return response,
        }
        let addressable = self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            vault.find_environment(&reference).ok().map(|env| {
                (
                    env.name.clone(),
                    env.agent_visible && visible.contains(&env.vault_id),
                    Self::declares_any(env, &names),
                )
            })
        });
        let addressable = match addressable {
            Ok(v) => v,
            Err(response) => return response,
        };
        // Hidden and absent are one answer here too: see `NO_SUCH_ITEM`.
        let Some((env_name, true, declared)) = addressable else {
            return Response::error(ErrorCode::NotFound, NO_SUCH_ENVIRONMENT);
        };
        // Answered before the sheet — a human is not asked about a change that cannot happen —
        // and again inside the transaction, where it counts.
        if declared {
            return Response::error(ErrorCode::InvalidArgument, VARIABLE_EXISTS);
        }

        let var_names = names;
        let names: Vec<String> = var_names.iter().map(ToString::to_string).collect();
        let approved = self.ask(
            ApprovalRequest {
                kind: ApprovalKind::AddVariables,
                environment_id: Some(reference.clone()),
                environment_name: Some(env_name),
                variables: names.clone(),
                ..ApprovalRequest::default()
            }
            .with_identity(connection.identity()),
        );
        if !approved.granted {
            return self.denied(
                "add_variables",
                &approved,
                Some(environment_id),
                names,
                connection,
            );
        }

        let replaced = std::cell::Cell::new(false);
        let committed = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            // Everything that decides this change is read again here, inside the transaction:
            // the sheet may have been up for a minute, and the user may have hidden the
            // environment or an item meanwhile — in the app, or from a terminal, which is the
            // case the file re-read at the start of the transaction exists for.
            let visible = Self::visible_vaults(tx);
            let addressable = tx
                .find_environment(&reference)
                .is_ok_and(|env| env.agent_visible && visible.contains(&env.vault_id));
            if !addressable {
                return Err(kagisecure_core::Error::EnvNotFound(reference.clone()));
            }
            // `set_var` replaces by name. Adding is all this tool does: a name that is there now —
            // the user's own binding, perhaps added while the sheet was up — is refused, and the
            // transaction rolls back untouched.
            if tx
                .find_environment(&reference)
                .is_ok_and(|env| Self::declares_any(env, &var_names))
            {
                replaced.set(true);
                return Err(kagisecure_core::Error::TransactionAborted);
            }
            let mut resolved = Vec::with_capacity(variables.len());
            for (request, name) in variables.iter().zip(&var_names) {
                let source = match &request.bind_to {
                    Some(field) => {
                        // A binding target must be something the agent could have been shown:
                        // exactly `describe_item`'s rules — the item visible to agents, in a
                        // vault visible to agents, not in the trash (archived is fine: listed
                        // and described like any other item) — plus the field's own flag, which
                        // `describe_item` reports and which is the user's answer for that value.
                        // Anything else would let a binding, and the next release, reach a value
                        // the user never shared.
                        let shared = Self::field_shared(tx, field.item_id, field.field_id);
                        // A field the user has not shared is answered exactly as a field that
                        // does not exist, for the reason in `NO_SUCH_ITEM`.
                        if !shared {
                            return Err(kagisecure_core::Error::ItemNotFound(
                                field.item_id.to_string(),
                            ));
                        }
                        VarSource::ItemField {
                            item: field.item_id,
                            field: field.field_id,
                        }
                    }
                    None => VarSource::Pending {
                        hint: request.hint.clone(),
                    },
                };
                resolved.push((name.clone(), source));
            }
            // All or nothing: every binding is checked before the first variable is set, and a
            // refusal rolls the transaction back.
            let env = tx.find_environment_mut(&reference)?;
            for (name, source) in resolved {
                env.set_var(name, source);
            }
            tx.append_audit(AuditDraft {
                tool: "add_variables".to_owned(),
                environment_id: Some(environment_id),
                variables: names.clone(),
                outcome: Outcome::Allowed,
                ..Self::draft(connection)
            });
            Ok(())
        });
        match committed {
            None => return Self::locked(),
            Some(Ok(())) => {}
            Some(Err(kagisecure_core::Error::TransactionAborted)) if replaced.get() => {
                return Response::error(ErrorCode::InvalidArgument, VARIABLE_EXISTS);
            }
            Some(Err(kagisecure_core::Error::EnvNotFound(_))) => {
                return Response::error(ErrorCode::NotFound, NO_SUCH_ENVIRONMENT);
            }
            Some(Err(kagisecure_core::Error::ItemNotFound(_))) => {
                return Response::error(ErrorCode::NotFound, NO_SUCH_ITEM);
            }
            Some(Err(e)) => {
                return self.write_refused(
                    "add_variables",
                    Some(environment_id),
                    names,
                    &e,
                    connection,
                );
            }
        }

        let (bound, pending): (Vec<&VariableRequest>, Vec<&VariableRequest>) =
            variables.iter().partition(|v| v.bind_to.is_some());
        let bound: Vec<String> = bound.into_iter().map(|v| v.name.clone()).collect();
        let pending: Vec<String> = pending.into_iter().map(|v| v.name.clone()).collect();

        let status = if pending.is_empty() {
            AddVariablesStatus::Complete
        } else {
            AddVariablesStatus::PendingUserInput
        };
        Response::AddedVariables {
            environment_id,
            bound,
            pending,
            deep_link: format!("kagisecure://environments/{environment_id}/pending"),
            status,
        }
    }

    /// Whether `env` already declares any of `names`.
    fn declares_any(env: &Environment, names: &[VarName]) -> bool {
        names.iter().any(|name| env.var(name.as_str()).is_some())
    }

    /// Every requested variable name as a [`VarName`], or the `INVALID_ARGUMENT` reply for the
    /// first that is not one — or that repeats an earlier name in the same request, which would
    /// otherwise silently replace it inside the transaction.
    ///
    /// The message is fixed and does not echo the name back: it is the caller's own input, but it
    /// is also a string of any length and content, and a reply is read by a model.
    ///
    /// Also the rest of the request's documented limits (mcp-server.md §2.6): at most
    /// [`MAX_VARIABLES_PER_CALL`] variables, each hint one line of at most [`MAX_HINT_CHARS`]
    /// characters — a hint is shown to the human on the sheet and in the app's editor.
    fn valid_names(variables: &[VariableRequest]) -> Result<Vec<VarName>, Response> {
        if variables.len() > MAX_VARIABLES_PER_CALL {
            return Err(Response::error(
                ErrorCode::InvalidArgument,
                "At most 50 variables per call. Nothing was asked or changed. Split the request.",
            ));
        }
        if variables
            .iter()
            .filter_map(|v| v.hint.as_deref())
            .any(|hint| !display_text_ok(hint, MAX_HINT_CHARS, false))
        {
            return Err(Response::error(
                ErrorCode::InvalidArgument,
                "A hint must be one line of at most 200 characters, with no control characters. \
                 Nothing was asked or changed. Shorten it and retry.",
            ));
        }
        let mut names: Vec<VarName> = Vec::with_capacity(variables.len());
        for request in variables {
            let Ok(name) = VarName::new(request.name.clone()) else {
                return Err(Response::error(
                    ErrorCode::InvalidArgument,
                    INVALID_VARIABLE_NAME,
                ));
            };
            if names.contains(&name) {
                return Err(Response::error(
                    ErrorCode::InvalidArgument,
                    "The same variable name appears twice in this request. Send each name once.",
                ));
            }
            names.push(name);
        }
        Ok(names)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_env_file(
        &self,
        environment_id: EnvId,
        directory: &str,
        filename: &str,
        variables: Option<&[String]>,
        overwrite: bool,
        ttl_seconds: u64,
        connection: &Connection,
    ) -> Response {
        const TOOL: &str = "write_env_file";
        let reference = environment_id.to_string();
        let selected = match self.selected_names(environment_id, variables) {
            Ok(Some(v)) => v,
            Ok(None) => return Response::error(ErrorCode::NotFound, NO_SUCH_ENVIRONMENT),
            Err(response) => return response,
        };
        let Selected {
            env_name,
            names,
            shared,
        } = selected;

        // The filename is validated **here**, before anything else happens with it: before a
        // human is shown a sheet, and before a lease is minted (A-03/A-04). `envfile::write`
        // validates it too, but that is the last line of the function, long after both. Two
        // things go wrong when the check runs late:
        //
        // * `canonical.join("../../../tmp/x")` renders as `/approved/dir/../../../tmp/x` and
        //   `canonical.join("/etc/kagisecure.env")` *discards the base entirely*, so the sheet
        //   can name a path that is not inside the directory printed beside it, and is not
        //   where any byte would land;
        // * a request that cannot possibly succeed still grants a ten-use lease on the
        //   directory, which then covers every legitimate filename in it with no second sheet.
        //
        // A name that passes is a plain file name, so `canonical.join(filename)` below is inside
        // `canonical`, contains no `..`, and is exactly what `envfile::write` will produce.
        if let Err(e) = envfile::validate_filename(filename) {
            let code = error_code_for(&e);
            return self.failed(TOOL, code, Some(environment_id), names, &e, connection);
        }

        let canonical = match canonical_dir(directory) {
            Ok(p) => p,
            Err(message) => return Response::error(ErrorCode::InvalidPath, message),
        };
        let target = canonical.join(filename);

        // What the human has to be told about the file that is already there, read before the
        // sheet goes up (D-1). `written_by_us` is only meaningful when something is there.
        let target_exists = target.exists();
        // A file that is there and may not be replaced makes the request impossible — the same
        // refusal `envfile::write` would give — so it is answered now: before a human is asked
        // to approve it, before a lease use is spent on it, and before an `Allowed` entry would
        // record a release that could not happen. `envfile::write` still makes the final check.
        if target_exists && !overwrite {
            let e = kagisecure_core::Error::EnvFileExists(target);
            let code = error_code_for(&e);
            return self.failed(TOOL, code, Some(environment_id), names, &e, connection);
        }
        // "Ours" means the file there now is the very file kagisecure wrote at this path — not
        // merely that the path is in the ledger: a file the user renamed over it since is theirs.
        let written_by_us = target_exists && self.written_file_is_still_there(&target);

        let request = LeaseRequest {
            environment_id,
            directory: canonical.clone(),
            // The approval is for this one file. A lease that did not carry the name would let an
            // approval for `.env.example` write `.env` with no second sheet (D-2).
            filename: Some(filename.to_owned()),
            variables: names.iter().cloned().collect(),
            kind: LeaseKind::EnvFile,
            command: None,
            // `overwrite` is part of what is being asked, not a detail of the write: replacing a
            // file kagisecure did not write is never covered by a lease, so the human sees this
            // sheet — with the file named as not kagisecure's — every time.
            replaces_unowned_file: target_exists && !written_by_us,
        };
        let mut entry = AuditDraft {
            tool: TOOL.to_owned(),
            vault_id: shared.as_ref().map(|s| s.vault_id),
            environment_id: Some(environment_id),
            variables: names.clone(),
            target_path: Some(human_path(&target)),
            ..Self::draft(connection)
        };
        let reservation = match self.reserve(&request, &entry, shared.as_ref(), connection, || {
            ApprovalRequest {
                kind: ApprovalKind::WriteEnvFile,
                environment_id: Some(reference.clone()),
                environment_name: Some(env_name),
                directory: Some(human_path(&canonical)),
                target_path: Some(human_path(&target)),
                variables: names.clone(),
                gitignored: envfile::gitignore_status(&target),
                overwrite_requested: overwrite,
                target_exists: Some(target_exists),
                target_written_by_us: target_exists.then_some(written_by_us),
                requested_ttl_seconds: ttl_seconds,
                requested_uses: lease::DEFAULT_USES,
                shared_source: shared.as_ref().map(|s| s.source.clone()),
                changed_since_approval: shared
                    .as_ref()
                    .map(|s| s.changes.clone())
                    .unwrap_or_default(),
                ..ApprovalRequest::default()
            }
        }) {
            Ok(r) => r,
            Err(response) => return response,
        };
        entry.lease_id = Some(reservation.lease_id);

        // A-05 (TOCTOU): the approved directory must still be itself. Checked here, before an
        // `Allowed` entry is committed for a release that would be refused — the swap this
        // catches happens while the sheet is up — and again inside the act, immediately before
        // the write; see `still_canonical`.
        if !still_canonical(&canonical) {
            self.revoke_if_minted(reservation.lease_id, reservation.minted);
            let e = kagisecure_core::Error::InvalidPath(canonical);
            let code = error_code_for(&e);
            return self.failed(TOOL, code, Some(environment_id), names, &e, connection);
        }

        let act = {
            let leases = Arc::clone(&self.leases);
            let filename = filename.to_owned();
            let Reservation {
                lease_id, minted, ..
            } = reservation;
            move |injections: Vec<EnvInjection>, _entry_seq: u64| {
                let written = if still_canonical(&canonical) {
                    envfile::write(&canonical, &filename, &injections, overwrite)
                } else {
                    Err(kagisecure_core::Error::InvalidPath(canonical))
                };
                drop(injections);
                match written {
                    Ok(written) => Acted::done(Ok(written)),
                    Err(e) => {
                        // Before the follow-up entry is written, which can wait on another
                        // writer: a lease this call minted must not outlive its failure even
                        // for that long.
                        revoke_minted(&leases, lease_id, minted);
                        let code = match &e {
                            kagisecure_core::Error::EnvFileExists(_) => {
                                ErrorCode::FileExists.as_str()
                            }
                            kagisecure_core::Error::InvalidPath(_)
                            | kagisecure_core::Error::InvalidEnvFileName(_) => {
                                ErrorCode::InvalidPath.as_str()
                            }
                            _ => "WRITE_FAILED",
                        };
                        Acted::abnormal(code, Err(e))
                    }
                }
            }
        };
        let released = audited_release(
            &self.handle,
            REQUEST_LOCK_TIMEOUT,
            entry,
            |tx| self.prepare_release(tx, environment_id, &names),
            act,
        );
        let written = match released {
            Err(refused) => {
                return self.not_released(
                    TOOL,
                    refused,
                    &reservation,
                    environment_id,
                    names,
                    connection,
                );
            }
            // Recorded already: the `Failed` entry naming the `Allowed` one.
            Ok(Released { value: Err(e), .. }) => {
                return Response::error(error_code_for(&e), agent_message(&e));
            }
            Ok(Released {
                value: Ok(written), ..
            }) => written,
        };

        self.leases()
            .record_written(reservation.lease_id, written.path.clone(), written.identity);
        // The vault may have been locked between the commit and the write: the lock hook shreds
        // what the leases wrote, and this file was not in the ledger yet when it ran. Locking
        // must mean locking.
        if !self.is_serving() {
            let _ = envfile::shred(&written.path, written.identity);
            return Self::locked();
        }

        Response::WroteEnvFile {
            path: human_path(&written.path),
            variables_written: written.variables,
            bytes: written.bytes,
            lease_id: reservation.lease_id,
            expires_at: rfc3339(reservation.expires_at),
            gitignored: written.gitignored,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_env(
        &self,
        environment_id: EnvId,
        command: &str,
        args: &[String],
        cwd: &str,
        variables: Option<&[String]>,
        timeout_seconds: u64,
        output: OutputMode,
        connection: &Connection,
    ) -> Response {
        const TOOL: &str = "run_with_env";
        // Every argument is shown on the sheet; the documented bound holds here, not only in the
        // sidecar (mcp-server.md §2.8).
        if args.len() > MAX_RUN_ARGS {
            return Response::error(
                ErrorCode::InvalidArgument,
                "At most 64 arguments. Nothing was asked or run. Simplify the command.",
            );
        }
        // Clamped here, not only in the sidecar: any local process can speak this protocol
        // without the sidecar, and an unbounded timeout would both keep a child alive
        // indefinitely and overflow the deadline arithmetic in `inject::run_with_env`.
        let timeout_seconds = clamp_run_timeout(timeout_seconds);
        let reference = environment_id.to_string();
        let selected = match self.selected_names(environment_id, variables) {
            Ok(Some(v)) => v,
            Ok(None) => return Response::error(ErrorCode::NotFound, NO_SUCH_ENVIRONMENT),
            Err(response) => return response,
        };
        let Selected {
            env_name,
            names,
            shared,
        } = selected;

        let canonical = match canonical_dir(cwd) {
            Ok(p) => p,
            Err(message) => return Response::error(ErrorCode::InvalidPath, message),
        };

        let mut argv = vec![command.to_owned()];
        argv.extend(args.iter().cloned());

        let request = LeaseRequest {
            environment_id,
            directory: canonical.clone(),
            filename: None,
            variables: names.iter().cloned().collect(),
            kind: LeaseKind::RunCommand,
            command: Some(argv.clone()),
            replaces_unowned_file: false,
        };
        let mut entry = AuditDraft {
            tool: TOOL.to_owned(),
            vault_id: shared.as_ref().map(|s| s.vault_id),
            environment_id: Some(environment_id),
            variables: names.clone(),
            target_path: Some(human_path(&canonical)),
            ..Self::draft(connection)
        };
        let reservation = match self.reserve(&request, &entry, shared.as_ref(), connection, || {
            ApprovalRequest {
                kind: ApprovalKind::RunWithEnv,
                environment_id: Some(reference.clone()),
                environment_name: Some(env_name),
                directory: Some(human_path(&canonical)),
                variables: names.clone(),
                command: argv,
                requested_ttl_seconds: lease::DEFAULT_TTL_SECONDS,
                requested_uses: lease::DEFAULT_USES,
                shared_source: shared.as_ref().map(|s| s.source.clone()),
                changed_since_approval: shared
                    .as_ref()
                    .map(|s| s.changes.clone())
                    .unwrap_or_default(),
                ..ApprovalRequest::default()
            }
        }) {
            Ok(r) => r,
            Err(response) => return response,
        };
        entry.lease_id = Some(reservation.lease_id);

        // A-05 (TOCTOU): as in `write_env_file` — once here, before anything is committed, and
        // once inside the act, immediately before the spawn.
        if !still_canonical(&canonical) {
            self.revoke_if_minted(reservation.lease_id, reservation.minted);
            let e = kagisecure_core::Error::InvalidPath(canonical);
            let code = error_code_for(&e);
            return self.failed(TOOL, code, Some(environment_id), names, &e, connection);
        }

        // A template for the `Failed`/`KILLED_ON_LOCK` entry `crate::children::ChildRegistry`
        // writes if the vault locks while this child is still running — the same tool, lease,
        // environment, variables and target as the `Allowed` entry below, which is exactly what
        // `entry` (before `audited_release` moves it) already is.
        let entry_template = entry.clone();

        let act = {
            let leases = Arc::clone(&self.leases);
            let children = Arc::clone(&self.children);
            let gate = self.gate();
            let program = std::ffi::OsString::from(command);
            let os_args: Vec<std::ffi::OsString> =
                args.iter().map(std::ffi::OsString::from).collect();
            let Reservation {
                lease_id, minted, ..
            } = reservation;
            move |injections: Vec<EnvInjection>, entry_seq: u64| {
                // The last moment before a spawn: a lock acknowledged since `prepare_release`
                // checked the flag means nothing starts at all. (A lock landing after this check
                // is `ChildRegistry::register`'s to catch — it kills the child at once.)
                let killed_on_lock = std::cell::Cell::new(false);
                let ran = if !gate.is_serving() {
                    Ok(Ran::NotStarted)
                } else if still_canonical(&canonical) {
                    // `_tracked`, not the plain `run_with_env`: `on_spawn` registers the child
                    // with `children` the instant it exists, so a lock racing this call has
                    // something to kill from the moment there is anything to kill at all — and
                    // `child_id` deregisters it again on every exit path below, so a child that
                    // finished before any lock ever leaves no trace behind to leak.
                    let child_id = std::cell::Cell::new(None);
                    let outcome = run_with_env_tracked(
                        &RunRequest {
                            program: &program,
                            args: &os_args,
                            env: &injections,
                            cwd: Some(&canonical),
                            mask_output: true,
                            max_output: kagisecure_core::inject::DEFAULT_MAX_OUTPUT,
                            timeout: Some(Duration::from_secs(timeout_seconds)),
                            // A group of its own: a lock or the deadline ends the command and
                            // everything it spawned, and never this process's own group.
                            new_process_group: true,
                        },
                        |kill| match children.register(kill, entry_template.clone(), entry_seq) {
                            Ok(id) => child_id.set(Some(id)),
                            // The lock landed between the check above and this spawn, and has
                            // already drained the registry: `register` killed the child at once.
                            Err(crate::children::RegistryClosed) => killed_on_lock.set(true),
                        },
                    );
                    if let Some(id) = child_id.into_inner() {
                        children.deregister(id);
                    }
                    outcome.map(Ran::Finished)
                } else {
                    Err(kagisecure_core::Error::InvalidPath(canonical))
                };
                drop(injections);
                match ran {
                    Ok(Ran::NotStarted) => {
                        Acted::abnormal("LOCKED_BEFORE_START", Ok(Ran::NotStarted))
                    }
                    Ok(ran) if killed_on_lock.get() => Acted::abnormal("KILLED_ON_LOCK", Ok(ran)),
                    // The command did run; it was killed at its limit. The reply is still its
                    // result, and the lease stands: this is not a failure to release.
                    Ok(Ran::Finished(outcome)) if outcome.timed_out => {
                        Acted::abnormal("TIMED_OUT", Ok(Ran::Finished(outcome)))
                    }
                    Ok(ran) => Acted::done(Ok(ran)),
                    Err(e) => {
                        revoke_minted(&leases, lease_id, minted);
                        let code = match &e {
                            kagisecure_core::Error::InvalidPath(_) => {
                                ErrorCode::InvalidPath.as_str()
                            }
                            kagisecure_core::Error::Spawn { .. }
                            | kagisecure_core::Error::NonUtf8EnvValue(_) => "SPAWN_FAILED",
                            _ => "RUN_FAILED",
                        };
                        Acted::abnormal(code, Err(e))
                    }
                }
            }
        };
        // No lock of any kind is held while the child runs: `act` is called after the
        // transaction has committed and released both the handle and the file lock.
        let released = audited_release(
            &self.handle,
            REQUEST_LOCK_TIMEOUT,
            entry,
            |tx| self.prepare_release(tx, environment_id, &names),
            act,
        );
        let outcome = match released {
            Err(refused) => {
                return self.not_released(
                    TOOL,
                    refused,
                    &reservation,
                    environment_id,
                    names,
                    connection,
                );
            }
            // Recorded already: the `Failed` entry naming the `Allowed` one.
            Ok(Released { value: Err(e), .. }) => {
                return Response::error(error_code_for(&e), agent_message(&e));
            }
            // Nothing was started: the vault locked between the release's prepare and its spawn.
            Ok(Released {
                value: Ok(Ran::NotStarted),
                ..
            }) => return Self::locked(),
            Ok(Released {
                value: Ok(Ran::Finished(outcome)),
                ..
            }) => outcome,
        };

        // The vault may have locked while the child ran: `kill_children_for_lock` already ended
        // it and recorded `KILLED_ON_LOCK` directly on the vault it still had in hand (this
        // process's own `record_best_effort` cannot — the vault is gone from the handle by now).
        // "Locking must mean locking" (`Self::is_serving`'s own doc comment) applies here exactly
        // as it does to `write_env_file`'s post-write check: the caller must not be told about a
        // child's output as though the vault were still open when it answers.
        if !self.is_serving() {
            return Self::locked();
        }

        let include = output == OutputMode::Scrubbed;
        Response::Ran {
            exit_code: outcome.exit_code,
            stdout: include.then(|| String::from_utf8_lossy(&outcome.stdout).into_owned()),
            stderr: include.then(|| String::from_utf8_lossy(&outcome.stderr).into_owned()),
            truncated: outcome.stdout_truncated || outcome.stderr_truncated,
            scrubbed: outcome.masked,
            lease_id: reservation.lease_id,
            expires_at: rfc3339(reservation.expires_at),
        }
    }

    fn revoke(
        &self,
        lease_id: Option<LeaseId>,
        path: Option<&str>,
        connection: &Connection,
    ) -> Response {
        // Dropping a lease is always allowed: there is no approval, and no way for a request to
        // fail in a way that leaves the lease alive.
        //
        // **Shredding a file is a different act.** `shred` zeroes a file's bytes and unlinks it,
        // so a caller-supplied path that this vault never wrote would make `revoke_env_file` an
        // unauthenticated destroy-any-file primitive: `revoke_env_file(path: "~/.ssh/id_rsa")`.
        // Only a path in `LeaseStore`'s written ledger — which outlives the lease that wrote it,
        // so a revoke after the expiry still works — is ever handed to `shred`.
        //
        // An unknown path is a silent no-op with an audit entry rather than an error, because
        // revoking is cleanup and cleanup must not fail (see `tests/revoke.rs`'s header): an
        // agent tidying up after a restart cannot tell a path it wrote from one it did not, and
        // an error there would push it to "request a fresh injection". The audit entry is what
        // makes the refusal visible to the human afterwards.
        let mut targets: Vec<WrittenEntry> = Vec::new();
        let mut refused: Option<String> = None;
        {
            let mut leases = self.leases();
            if let Some(id) = lease_id
                && let Some(entries) = leases.revoke(id)
            {
                targets.extend(entries);
            }
            if let Some(p) = path {
                let candidate = PathBuf::from(p);
                let ours = leases.written(&candidate);
                targets.extend(leases.revoke_by_path(&candidate));
                match ours {
                    Some(entry) => {
                        if !targets.iter().any(|t| t.path == entry.path) {
                            targets.push(entry);
                        }
                    }
                    None => refused = Some(human_path(&candidate)),
                }
            }
        }

        // Only the file each ledger entry names is touched — see `envfile::shred`. A path that
        // now names something else is left alone and recorded, one entry per path.
        let (shredded, skipped) = shred_written(targets, "revoke_env_file");
        let shredded: Vec<String> = shredded.iter().map(|p| human_path(p)).collect();
        for draft in skipped {
            self.record_best_effort(AuditDraft {
                lease_id,
                client_pid: connection.identity().pid,
                ..draft
            });
        }

        self.record_best_effort(AuditDraft {
            tool: "revoke_env_file".to_owned(),
            lease_id,
            target_path: shredded.first().cloned().or_else(|| refused.clone()),
            outcome: Outcome::Allowed,
            detail: refused
                .is_some()
                .then(|| "PATH_NOT_WRITTEN_BY_KAGISECURE".to_owned()),
            ..Self::draft(connection)
        });
        Response::Revoked { shredded }
    }

    fn audit(&self, limit: usize, verify: bool) -> Response {
        match self.read(|vault| {
            let chain_intact = verify.then(|| vault.verify_audit().is_ok());
            let all = vault.audit_entries();
            let start = all.len().saturating_sub(limit);
            (all[start..].to_vec(), chain_intact)
        }) {
            Ok((entries, chain_intact)) => Response::Audit {
                entries,
                chain_intact,
            },
            Err(response) => response,
        }
    }

    /// `kagisecure lock`, over IPC.
    ///
    /// The agent does **not** take the vault out of the handle itself: the process that unlocked
    /// it owns its lifetime (the app holds a `VaultSession`, the daemon holds a `Vault`), and a
    /// library reaching in to destroy its host's state would leave the host holding a session
    /// object that can no longer answer anything. Instead this raises a flag the host polls and
    /// acts on, which for both hosts is a handful of lines and keeps the ownership honest.
    fn lock(&self, connection: &Connection) -> Response {
        // Set *first*, before any of the cleanup below: "locking must mean locking" from the
        // instant this call is acknowledged, not from whenever the cleanup happens to finish.
        // `kill_running_children` in particular can end a child quickly (a plain `SIGTERM`) while
        // its own `record_best_effort` write is still in flight — a connection thread blocked in
        // that child's wait loop must see `is_serving() == false` the moment it wakes up, not race
        // this call's own audit write to find out.
        self.lock_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Queued before anything else, so it exists whatever happens next; written only after
        // the lock has taken effect, because a write can wait on another process and a lock
        // must not. If the host takes the vault before the write below gets the chance,
        // `VaultHandle::take` makes the last attempt.
        let _ = self.handle.queue_audit(AuditDraft {
            tool: "lock".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });

        // Everything `Shared::on_vault_locked` does, done now rather than when the host next
        // polls: the leases die, the files they wrote are shredded, and the approval queue closes
        // so that a request already blocked in `ask` — or one that arrives in the next
        // millisecond — cannot be answered "allow" after the user has pressed Lock. Ending a
        // running `run_with_env` child the same way, now rather than waiting for the host's own
        // poll of `take_lock_request`, is the same idea: the vault is still in the handle at this
        // point, so the ordinary best-effort audit path already reaches it — no need for the
        // vault-lock-hook `VaultHandle::take` uses for the case this early call misses (an agent
        // that never calls `lock` and is only ever locked by the host itself, e.g. the app's own
        // lock button).
        self.kill_leases();
        self.kill_running_children();
        self.queue.deny_all();
        if let Some(broker) = &self.agent_fill {
            broker.revoke_all();
        }
        self.handle.flush_best_effort(REQUEST_LOCK_TIMEOUT);
        Response::Locked
    }

    /// Drop every lease and shred every file written under one — each only if the path still
    /// names the file that was written, with a best-effort record of any that did not.
    pub(crate) fn kill_leases(&self) {
        let entries = self.leases().revoke_all();
        let (_, skipped) = shred_written(entries, "lock");
        for draft in skipped {
            self.record_best_effort(draft);
        }
    }

    /// Whether the file at `target` is the one this session's ledger says kagisecure wrote there
    /// last — compared by identity on the file itself, never by path alone.
    fn written_file_is_still_there(&self, target: &Path) -> bool {
        let recorded = self.leases().written(target);
        recorded.is_some_and(|entry| envfile::current_identity(target) == Some(entry.identity))
    }

    /// End every `run_with_env` child still running under an injected environment, and record why
    /// — the early-cleanup counterpart to [`Self::kill_leases`]. Unlike
    /// `crate::agent::Shared::kill_children_for_lock` (the vault-lock hook `VaultHandle::take`
    /// runs once the vault is actually gone), this runs while the vault is still in the handle, so
    /// each `Failed`/`KILLED_ON_LOCK` draft goes through the ordinary
    /// [`VaultHandle::record_best_effort`] rather than needing anywhere else to go.
    pub(crate) fn kill_running_children(&self) {
        for draft in self
            .children
            .kill_all_for_lock(crate::children::CHILD_KILL_GRACE)
        {
            self.handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------------------------------

    /// Set aside one use of a lease for a release: a live lease that already covers `request`,
    /// or — when there is none — a new one, minted after `sheet` has been put to the human and
    /// approved.
    ///
    /// The use is taken **here**, in the same lease-store critical section that found or minted
    /// the lease, so two concurrent calls can never both spend a lease's last use (A-06, D-8).
    /// It is spent whether or not the release then happens: failing towards less authority. A
    /// lease this call minted is revoked outright on any failure ([`Self::revoke_if_minted`]).
    ///
    /// Before a sheet is shown, the audit log is checked (pre-flight): entries still waiting from
    /// an earlier failed write are written now, and if that fails the request is refused with
    /// `AUDIT_UNAVAILABLE` without asking — the release's own entry would fail the same way, and
    /// the human should not approve something that will then be refused.
    ///
    /// `entry` is the release's audit entry (its lease is not known yet), used for the denial or
    /// the refusal this can answer with.
    fn reserve(
        &self,
        request: &LeaseRequest,
        entry: &AuditDraft,
        shared: Option<&SheetFacts>,
        connection: &Connection,
        sheet: impl FnOnce() -> ApprovalRequest,
    ) -> Result<Reservation, Response> {
        // A shared value that changed since this device last approved it is never released
        // under a lease that approval minted: the sheet says who changed it, every time
        // (ADR-0035 §14).
        let changed = shared.is_some_and(SheetFacts::changed);
        if !changed {
            let now = unix_now();
            let mut leases = self.leases();
            // Under the lease-store lock that `Agent::stop` and the `lock` tool also take to empty
            // it, after raising their flag: a use is taken from, or a lease added to, a store that
            // is still this agent's live one — never one that has already been emptied for the last
            // time.
            if !self.gate().flags_allow() {
                return Err(Self::locked());
            }
            if let Some((lease_id, expires_at)) =
                leases.find(request, now).map(|l| (l.id, l.expires_at))
            {
                leases.consume(lease_id, now);
                return Ok(Reservation {
                    lease_id,
                    minted: false,
                    expires_at,
                });
            }
        }

        self.audit_preflight(entry)?;
        let approved = self.ask(sheet().with_identity(connection.identity()));
        if !approved.granted {
            return Err(self.denied(
                &entry.tool,
                &approved,
                entry.environment_id,
                entry.variables.clone(),
                connection,
            ));
        }
        // What the human just saw is what they approved: the next sheet names only what changes
        // after this. Best-effort — failing to record it only means asking again.
        if let Some(shared) = shared {
            shared.record_approved(&self.handle);
        }
        // The lease's life starts when the human approved it, not when the sheet went up.
        let now = unix_now();
        let mut leases = self.leases();
        // See above: the sheet may have been up while the agent stopped or a lock was acknowledged.
        if !self.gate().flags_allow() {
            return Err(Self::locked());
        }
        let lease_id = leases.grant(
            request,
            describe_with_verification(connection.identity(), &approved.verification),
            approved.ttl_seconds,
            approved.uses,
            now,
        );
        let expires_at = leases
            .summaries(now)
            .into_iter()
            .find(|l| l.id == lease_id)
            .map_or(now, |l| l.expires_at);
        leases.consume(lease_id, now);
        Ok(Reservation {
            lease_id,
            minted: true,
            expires_at,
        })
    }

    /// The pre-flight described at [`Self::reserve`]: `Err` carries the refusal.
    fn audit_preflight(&self, entry: &AuditDraft) -> Result<(), Response> {
        match self.handle.flush(REQUEST_LOCK_TIMEOUT) {
            None => Err(Self::locked()),
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                eprintln!(
                    "kagisecure: not asking the user to approve {}: earlier audit entries still \
                     cannot be written: {e}",
                    entry.tool
                );
                let _ = self.handle.queue_audit(release::unavailable_entry(entry));
                Err(Self::audit_unavailable())
            }
        }
    }

    /// The `prepare` half of a release ([`audited_release`]): inside the transaction, so against
    /// the file as it is on disk now, confirm the environment is still one the agent may use and
    /// resolve the selected variables.
    ///
    /// The request-start sync is a minute old by now if a sheet was shown, and the user may have
    /// hidden the environment meanwhile — in the app, or with `kagisecure env agent-access --deny`
    /// in a terminal. A live lease does not outlast that: it was granted for an environment the
    /// agent could see.
    ///
    /// Takes no lock of its own and must not: it runs under this handle's mutex and the file lock.
    /// That is why "locked" is read from the flag and not from [`Self::is_serving`] — the vault is
    /// necessarily still here while the transaction holds it.
    fn prepare_release(
        &self,
        vault: &Vault,
        environment_id: EnvId,
        names: &[String],
    ) -> Result<Vec<EnvInjection>, Refusal> {
        if self
            .lock_requested
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Refusal::Locked);
        }
        // Gone and hidden are one error, so the reply cannot tell them apart (`NO_SUCH_ITEM`);
        // every binding about to be followed is checked against the rule `list_items` and
        // `describe_item` use before a single value is resolved. A shared environment is read
        // from its vault's snapshot as it is now — the personal vault's handle is held, and a
        // shared vault's state is taken second, the one lock order (`crate::shared`).
        Catalog::new(vault, self.handle.shared_snapshots())
            .release_environment(&environment_id, names)
            .map_err(Refusal::Vault)
    }

    /// Answer a release that did not happen, and undo what this call set up for it.
    fn not_released(
        &self,
        tool: &str,
        refused: NotReleased<Refusal>,
        reservation: &Reservation,
        environment_id: EnvId,
        variables: Vec<String>,
        connection: &Connection,
    ) -> Response {
        self.revoke_if_minted(reservation.lease_id, reservation.minted);
        match refused {
            NotReleased::Locked | NotReleased::Refused(Refusal::Locked) => Self::locked(),
            NotReleased::Refused(Refusal::Vault(e)) => self.failed(
                tool,
                error_code_for(&e),
                Some(environment_id),
                variables,
                &e,
                connection,
            ),
            // Its `Failed` entry is already queued (`audited_release`).
            NotReleased::AuditUnavailable(_) => Self::audit_unavailable(),
        }
    }

    fn audit_unavailable() -> Response {
        Response::error(ErrorCode::AuditUnavailable, AUDIT_UNAVAILABLE)
    }

    /// What a release request selects: the environment's name as the listing shows it and the
    /// variable names, and for a shared environment the source and "changed since approval"
    /// facts for the sheet (ADR-0035 §14) with what approving them records.
    ///
    /// `Ok(None)` means "no such environment, or not agent-visible"; `Err` means locked.
    fn selected_names(
        &self,
        environment_id: EnvId,
        wanted: Option<&[String]>,
    ) -> Result<Option<Selected>, Response> {
        self.read_catalog(|catalog| {
            let found = catalog.agent_environment(&environment_id)?;
            let env = found.value;
            let names = match wanted {
                Some(names) => names.to_vec(),
                None => env.vars.iter().map(|v| v.name.clone()).collect(),
            };
            let shared = found
                .place
                .shared()
                .map(|snapshot| SheetFacts::for_environment(snapshot, &environment_id, &names));
            Some(Selected {
                env_name: catalog.environment_name(found),
                names,
                shared,
            })
        })
    }

    /// The audit entry every tool call starts from.
    ///
    /// `client_pid` comes from the **kernel** — `PeerIdentity::pid` is read with
    /// `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`, not from anything the caller said about itself —
    /// which is what makes it worth recording at all. `docs/mcp-server.md` §6 lists it as part of
    /// every entry, and the browser path in `extension.rs` has always written it; this path did
    /// not, because `draft` had no `self` and so no connection to read it from. An audit log whose
    /// stated purpose is "a burst of denials is the only evidence a user will have that a prompt
    /// injection attempted an exfiltration" has to be able to say *which process*.
    fn draft(connection: &Connection) -> AuditDraft {
        AuditDraft {
            actor: "mcp".to_owned(),
            client_pid: connection.identity().pid,
            ..AuditDraft::default()
        }
    }

    /// Record an audit entry that is not part of a change, durably and best-effort.
    ///
    /// For every entry that is neither written inside a change's own transaction nor a release's
    /// authorization ([`crate::release`]): the read-only tools (a read-only tool changes nothing
    /// but its own audit entry, so without a write of its own the entry would wait for some later
    /// change), `denied`/`failed` (the entries that matter most: a burst of denials is the only
    /// evidence a prompt-injection exfiltration attempt ever leaves), `lock` and
    /// `revoke_env_file`.
    ///
    /// A failed write never changes what the caller gets back — turning a disk problem into a
    /// different tool response would tell the caller nothing useful, and for `denied` it must not
    /// turn a denial into something else. What it must not do either is lose the entry, or fail
    /// silently: the entry stays queued on the vault and is written by the next write that
    /// succeeds, and `Vault::last_save_error` / `Vault::unsaved_audit_entries` stay set until
    /// then, so the app can surface it to the human even after this process has moved on (see
    /// `AuditView`/`SettingsView` on the Swift side). See [`VaultHandle::record_best_effort`].
    fn record_best_effort(&self, draft: AuditDraft) {
        // `false` means locked: nothing to write to, and nothing lost that the lock did not
        // already take.
        let _ = self.handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
    }

    fn denied(
        &self,
        tool: &str,
        approval: &Approval,
        environment_id: Option<EnvId>,
        variables: Vec<String>,
        connection: &Connection,
    ) -> Response {
        self.record_best_effort(AuditDraft {
            tool: tool.to_owned(),
            environment_id,
            variables,
            outcome: Outcome::Denied,
            detail: Some(approval.code.as_str().to_owned()),
            ..Self::draft(connection)
        });
        denied_reply(approval.code)
    }

    fn failed(
        &self,
        tool: &str,
        code: ErrorCode,
        environment_id: Option<EnvId>,
        variables: Vec<String>,
        error: &kagisecure_core::Error,
        connection: &Connection,
    ) -> Response {
        let message = agent_message(error);
        self.record_best_effort(AuditDraft {
            tool: tool.to_owned(),
            environment_id,
            variables,
            outcome: Outcome::Failed,
            detail: Some(code.as_str().to_owned()),
            ..Self::draft(connection)
        });
        Response::error(code, message)
    }

    /// Put the question to whoever is answering questions, and block.
    fn ask(&self, request: ApprovalRequest) -> Approval {
        self.queue.ask(request)
    }
}

/// The item `reference` names, if an agent may know it exists: agent-visible itself, not in the
/// trash, and in a logical vault visible to agents or in an attached shared vault
/// ([`Catalog::agent_item`], with its collision rules). Archived items are included, exactly as
/// `list_items` lists them.
///
/// The one predicate every agent-facing lookup of a single item shares — `describe_item`,
/// `request_fill`'s gate 3 and its release — so an absent item and a hidden one are one `None`,
/// taken down one path, and cannot drift apart into an item one tool hides and another reaches.
/// By exact id only: a title or an id prefix names nothing.
pub(crate) fn agent_visible_item<'c>(
    catalog: &'c Catalog<'_>,
    reference: &str,
) -> Option<&'c kagisecure_core::model::Item> {
    catalog.agent_item(reference).map(|found| found.value)
}

/// The one reply for an item an agent may not know about, absent and hidden alike.
pub(crate) fn no_such_item() -> Response {
    Response::error(ErrorCode::NotFound, NO_SUCH_ITEM)
}

/// `request_fill` cannot be served at all (gates 1 and 5).
pub(crate) fn fill_unavailable() -> Response {
    Response::error(ErrorCode::FillUnavailable, FILL_UNAVAILABLE)
}

/// The vault locked.
pub(crate) fn locked_reply() -> Response {
    Service::locked()
}

/// Nothing was released because its audit entry could not be written.
pub(crate) fn audit_unavailable() -> Response {
    Service::audit_unavailable()
}

/// The reply for an approval that was not granted, by the queue's code.
pub(crate) fn denied_reply(code: ErrorCode) -> Response {
    Response::error(
        code,
        match code {
            ErrorCode::ApprovalTimeout => {
                "Nobody answered the approval prompt within 60 seconds. Tell the user, then you \
                 may retry once."
            }
            ErrorCode::VaultLocked => {
                "The kagisecure vault locked before the request was answered. Ask the user to \
                 unlock it."
            }
            _ => "The user declined. Stop; do not request the same thing again.",
        },
    )
}

/// How the lease and the audit log name a caller, once the app has checked its signature.
///
/// The self-reported name stays in quotes so a caller that calls itself `"Claude Code (verified)"`
/// cannot borrow the word (the same rule `PeerIdentity::describe` follows), and the verdict this
/// process reached is stated bare.
#[must_use]
pub fn describe_with_verification(
    identity: &PeerIdentity,
    verification: &ClientVerification,
) -> String {
    let base = identity.describe();
    if verification.evidence.is_empty() {
        return base;
    }
    let verdict = if verification.verified {
        "signature verified"
    } else {
        "signature UNVERIFIED"
    };
    format!("{base} [{verdict}: {}]", verification.evidence)
}

/// How a path is shown to a human — the approval sheet, the audit log, and the path a tool call
/// hands back to the agent to relay. Everywhere this module would otherwise reach for
/// `path.display()` on something a person (or a model speaking for one) reads, it goes through
/// here instead of calling `.display()` directly.
///
/// Plain `.display()` is fine on every platform this crate ships on except one:
/// [`canonical_dir`]'s `canonicalize()` call always returns the verbatim form on Windows —
/// `\\?\C:\Users\...` — which is correct for the file APIs it feeds and is not a spelling any
/// human ever typed or would recognize as their own project directory.
///
/// **Not used for the A-05 TOCTOU comparisons below.** Those compare one `canonicalize()` output
/// against another, directly, so both sides are always the same verbatim form; running either
/// side through this function first would let a change of *prefix style* look identical to no
/// change at all, which is exactly the class of bug that check exists to catch.
///
/// `pub` for the same reason [`canonical_dir`] is: the adversarial test suite talks to a real
/// agent over a real socket rather than through a mock, so it needs the same transform to build
/// the strings it expects the sheet and the audit log to show.
#[must_use]
pub fn human_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        if let Some(simplified) = windows_paths::simplify_verbatim_disk_path(path) {
            return simplified;
        }
    }
    path.display().to_string()
}

#[cfg(windows)]
mod windows_paths {
    use std::path::Path;

    /// Strip a `\\?\C:\...` verbatim-disk prefix down to the ordinary `C:\...` spelling, when
    /// doing so is safe.
    ///
    /// This is the same idea as the `dunce` crate's `simplified()` — stripping `\\?\` is not
    /// always safe, so this is deliberately narrower than a blind `strip_prefix`, rather than a
    /// new dependency for four lines of logic:
    ///
    /// * **Only a plain disk path.** `\\?\UNC\server\share\...` (a verbatim UNC path) and any
    ///   other verbatim form (`\\?\Volume{...}`, …) are returned unchanged — none of those have
    ///   an ordinary spelling that means the same thing.
    /// * **Only when it round-trips.** Windows' *ordinary* path parsing silently trims a trailing
    ///   `.` or ` ` from every component; verbatim parsing does not. A file whose real name ends
    ///   that way — creatable only by going through a verbatim path in the first place — would
    ///   print a different, wrong name with the prefix gone. If any component would be changed by
    ///   ordinary parsing, this refuses rather than guess, and the caller keeps showing `\\?\`.
    ///
    /// This is for display only, never for a path this process goes on to open — see
    /// [`super::human_path`].
    #[must_use]
    pub(super) fn simplify_verbatim_disk_path(path: &Path) -> Option<String> {
        let rest = path.to_str()?.strip_prefix(r"\\?\")?;
        let mut chars = rest.chars();
        let drive = chars.next().filter(char::is_ascii_alphabetic)?;
        if chars.next() != Some(':') || chars.next() != Some('\\') {
            return None;
        }
        let tail = &rest[3..];
        let round_trips = tail
            .split('\\')
            .all(|component| !component.ends_with('.') && !component.ends_with(' '));
        round_trips.then(|| format!("{drive}:\\{tail}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_verbatim_disk_path_is_simplified() {
            assert_eq!(
                simplify_verbatim_disk_path(Path::new(r"\\?\C:\Users\jack\project")),
                Some(r"C:\Users\jack\project".to_owned())
            );
        }

        #[test]
        fn a_bare_root_is_simplified() {
            assert_eq!(
                simplify_verbatim_disk_path(Path::new(r"\\?\C:\")),
                Some(r"C:\".to_owned())
            );
        }

        #[test]
        fn a_verbatim_unc_path_is_left_alone() {
            assert_eq!(
                simplify_verbatim_disk_path(Path::new(r"\\?\UNC\server\share\file")),
                None
            );
        }

        #[test]
        fn a_non_verbatim_path_is_left_alone() {
            assert_eq!(
                simplify_verbatim_disk_path(Path::new(r"C:\Users\jack\project")),
                None
            );
        }

        #[test]
        fn a_component_that_would_be_trimmed_by_ordinary_parsing_is_left_alone() {
            // A trailing dot or space is significant only through a verbatim path; ordinary
            // parsing would silently drop it and name a different file.
            assert_eq!(
                simplify_verbatim_disk_path(Path::new(r"\\?\C:\Users\jack\weird. ")),
                None
            );
        }
    }
}

/// The audit `detail` for a ledger entry whose path no longer names the file that was written, so
/// the shredder left it alone.
pub(crate) const NOT_SHREDDED_FILE_REPLACED: &str = "NOT_SHREDDED_FILE_REPLACED";

/// Shred every ledger entry through [`envfile::shred`], which touches only the very file that was
/// written. Returns the paths actually removed, and one `Failed` audit draft (tool `tool`, detail
/// [`NOT_SHREDDED_FILE_REPLACED`], the path as target) for each entry whose path now names
/// something else — a symlink planted after the write, a file renamed over it — for the caller to
/// record wherever it can: the vault may be mid-lock.
pub(crate) fn shred_written(
    entries: Vec<WrittenEntry>,
    tool: &str,
) -> (Vec<PathBuf>, Vec<AuditDraft>) {
    let mut removed = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        match envfile::shred(&entry.path, entry.identity) {
            Ok(envfile::Shredded::Removed) => removed.push(entry.path),
            Ok(envfile::Shredded::Missing) => {}
            Ok(envfile::Shredded::NotTheWrittenFile) => {
                eprintln!(
                    "kagisecure: not shredding {}: it is no longer the file kagisecure wrote",
                    entry.path.display()
                );
                skipped.push(AuditDraft {
                    actor: "mcp".to_owned(),
                    tool: tool.to_owned(),
                    target_path: Some(human_path(&entry.path)),
                    outcome: Outcome::Failed,
                    detail: Some(NOT_SHREDDED_FILE_REPLACED.to_owned()),
                    ..AuditDraft::default()
                });
            }
            Err(e) => eprintln!("kagisecure: could not shred {}: {e}", entry.path.display()),
        }
    }
    (removed, skipped)
}

/// [`Service::revoke_if_minted`], for a release's act, which runs without a `Service`.
fn revoke_minted(leases: &Mutex<LeaseStore>, lease_id: LeaseId, minted: bool) {
    if minted {
        leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revoke(lease_id);
    }
}

/// A-05 (TOCTOU): whether an approved directory still resolves to itself.
///
/// `canonical` came out of `canonicalize`, so it is its own canonical form; if it no longer
/// resolves to itself, the directory has been replaced — with a symlink, in the interesting case
/// — between the sheet being answered and now, and a write or spawn into it would land somewhere
/// the human never approved. Refusing is the only safe answer: the approval was for a place, not
/// for a name.
///
/// This narrows the window rather than closing it. Closing it means holding a directory handle
/// open across the approval and writing relative to it with `openat`, which `std` does not expose
/// and which `kagisecure-core` would have to take an FFI dependency to reach. On a single-user
/// machine the attacker here is the user's own uid, so the remaining race is hardening, not a
/// privilege boundary — whereas this check turns the *reliable* version of the attack, a swap
/// during the seconds a sheet is up, into a refusal.
fn still_canonical(canonical: &Path) -> bool {
    canonical.canonicalize().ok().as_deref() == Some(canonical)
}

/// Canonicalize a directory, rejecting anything that is not an existing absolute directory.
///
/// The canonical form is what the approval sheet shows and what the lease records, so
/// `/Users/x/code/../../../tmp` becomes `/tmp` *before* the human is asked, not after.
///
/// # Errors
///
/// A message for the model, saying what to fix.
pub fn canonical_dir(directory: &str) -> Result<PathBuf, String> {
    let raw = Path::new(directory);
    if !raw.is_absolute() {
        return Err(format!(
            "{directory:?} is not an absolute path. Use an absolute path."
        ));
    }
    let canonical = raw
        .canonicalize()
        .map_err(|_| format!("{directory:?} does not exist. Fix the path."))?;
    if !canonical.is_dir() {
        return Err(format!("{directory:?} is not a directory. Fix the path."));
    }
    Ok(canonical)
}

/// The message an agent gets for `error`.
///
/// Anything that comes from *resolving* an environment gets a fixed sentence, never core's own
/// `Display`: core's text is written for the vault's owner at a terminal, and names what it
/// could not find — an item by its title, an environment by its name — which for an item the
/// agent may not see is exactly the metadata `agent_visible` exists to withhold (threat-model
/// M-8). The rest — a path, a file name, a program the agent itself supplied, an I/O failure
/// writing it — is the agent's own input coming back, and keeps its text. The audit entry for a
/// refusal records a code and ids, never this text.
fn agent_message(error: &kagisecure_core::Error) -> std::borrow::Cow<'static, str> {
    use kagisecure_core::Error as E;
    match error {
        E::EnvNotFound(_) | E::AmbiguousEnv(_) => NO_SUCH_ENVIRONMENT.into(),
        E::ItemNotFound(_) | E::AmbiguousItem(_) | E::FieldNotFound { .. } | E::NotASecret(_) => {
            UNRESOLVABLE_BINDING.into()
        }
        E::VarNotFound(..) => "No variable with that name in this environment. Nothing was \
                               released. Call list_environments again."
            .into(),
        E::VarNotPopulated(_) => "A selected variable has no value yet: the user has not entered \
                                  it in kagisecure. Nothing was released. Tell the user; call \
                                  list_environments to see when it is populated."
            .into(),
        E::InvalidVarName(_) => "This environment holds a variable name kagisecure will not write \
                                 (it does not match ^[A-Za-z_][A-Za-z0-9_]*$). Nothing was \
                                 released. Ask the user to rename it in kagisecure."
            .into(),
        other => other.to_string().into(),
    }
}

/// Map a core error onto the stable code table in mcp-server.md §7.
#[must_use]
pub fn error_code_for(error: &kagisecure_core::Error) -> ErrorCode {
    use kagisecure_core::Error as E;
    match error {
        E::EnvFileExists(_) => ErrorCode::FileExists,
        E::InvalidPath(_) | E::InvalidEnvFileName(_) => ErrorCode::InvalidPath,
        E::InvalidVarName(_) => ErrorCode::InvalidArgument,
        E::EnvNotFound(_) | E::ItemNotFound(_) | E::FieldNotFound { .. } | E::VarNotFound(..) => {
            ErrorCode::NotFound
        }
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_is_refused() {
        assert!(canonical_dir("relative/path").is_err());
    }

    #[test]
    fn a_missing_path_is_refused() {
        assert!(canonical_dir("/definitely/not/here/at/all").is_err());
    }

    #[test]
    fn dot_dot_is_resolved_before_the_prompt_would_see_it() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let sneaky = format!("{}/a/b/../..", dir.path().display());
        let resolved = canonical_dir(&sneaky).unwrap();
        assert_eq!(resolved, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn a_file_is_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(canonical_dir(file.to_str().unwrap()).is_err());
    }

    #[test]
    fn core_errors_map_onto_the_documented_codes() {
        use kagisecure_core::Error as E;
        assert_eq!(
            error_code_for(&E::EnvFileExists(PathBuf::from("/x/.env"))),
            ErrorCode::FileExists
        );
        assert_eq!(
            error_code_for(&E::EnvNotFound("x".to_owned())),
            ErrorCode::NotFound
        );
        assert_eq!(
            error_code_for(&E::InvalidPath(PathBuf::from("/x"))),
            ErrorCode::InvalidPath
        );
        assert_eq!(error_code_for(&E::Rng), ErrorCode::Internal);
    }

    #[test]
    fn a_resolution_error_reaches_an_agent_as_a_fixed_sentence_naming_nothing() {
        use kagisecure_core::Error as E;
        for error in [
            E::FieldNotFound {
                item: "Payroll root".to_owned(),
                field: "password".to_owned(),
            },
            E::ItemNotFound("Payroll root".to_owned()),
            E::AmbiguousItem("Payroll root".to_owned()),
            E::EnvNotFound("Payroll root".to_owned()),
            E::VarNotFound("X".to_owned(), "Payroll root".to_owned()),
            E::NotASecret("Payroll root".to_owned()),
        ] {
            let message = agent_message(&error);
            assert!(!message.contains("Payroll"), "{error:?} -> {message}");
        }
    }

    #[test]
    fn fill_unavailable_is_one_fixed_sentence() {
        let Response::Error { code, message } = fill_unavailable() else {
            panic!("fill_unavailable must refuse");
        };
        assert_eq!(code, ErrorCode::FillUnavailable);
        assert_eq!(message, FILL_UNAVAILABLE);
    }

    #[test]
    fn the_refusal_entry_is_spelled_like_the_code_the_caller_gets() {
        assert_eq!(
            release::AUDIT_UNAVAILABLE,
            ErrorCode::AuditUnavailable.as_str()
        );
    }

    #[test]
    fn a_verified_signature_is_stated_bare_and_the_claimed_name_stays_quoted() {
        let identity = PeerIdentity {
            pid: Some(42),
            euid: Some(501),
            pid_from_kernel: true,
            executable: Some(
                "/Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp".to_owned(),
            ),
            reported: Some(ClientInfo {
                name: "Claude Code (verified)".to_owned(),
                version: "1".to_owned(),
                pid: 42,
                parent_pid: None,
                argv0: "kagisecure-mcp".to_owned(),
                cwd: None,
            }),
            audit_token: None,
        };
        let described = describe_with_verification(
            &identity,
            &ClientVerification {
                verified: true,
                evidence: "com.kagisecure.mcp (TEAMID)".to_owned(),
            },
        );
        assert!(described.contains("signature verified"), "{described}");
        assert!(
            described.contains("\"Claude Code (verified)\""),
            "{described}"
        );
        assert!(described.contains("TEAMID"), "{described}");
    }

    #[test]
    fn an_unchecked_signature_says_so() {
        let identity = PeerIdentity::default();
        let described = describe_with_verification(&identity, &ClientVerification::unchecked());
        assert!(described.contains("signature UNVERIFIED"), "{described}");
    }
}
