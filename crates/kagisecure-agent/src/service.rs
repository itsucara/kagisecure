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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{RunRequest, envfile, run_with_env};
use kagisecure_core::lease::{self, LeaseRequest, LeaseStore};
use kagisecure_core::model::{EnvVar, Environment, VarSource};
use kagisecure_core::proto::{
    Category, EnvId, EnvironmentSummary, ItemSummary, LeaseId, LeaseKind, Outcome, VaultId,
};
use kagisecure_core::{Vault, unix_now};
use kagisecure_ipc::protocol::{
    AddVariablesStatus, ClientInfo, ErrorCode, OutputMode, PROTOCOL_VERSION, Request, Response,
    VariableRequest, rfc3339,
};
use kagisecure_ipc::server::{Connection, PeerIdentity};

use crate::approval::{
    ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Outcome as Approval,
};
use crate::vault::VaultHandle;

/// The name this process answers the handshake with.
pub const SERVER_NAME: &str = "kagisecure-agent";

/// The state one connection handler needs. Cheap to clone: everything is an `Arc`.
#[derive(Clone)]
pub struct Service {
    handle: Arc<VaultHandle>,
    leases: Arc<Mutex<LeaseStore>>,
    queue: Arc<ApprovalQueue>,
    lock_requested: Arc<std::sync::atomic::AtomicBool>,
}

impl Service {
    /// Build a service over a shared vault, lease store and approval queue.
    #[must_use]
    pub fn new(
        handle: Arc<VaultHandle>,
        leases: Arc<Mutex<LeaseStore>>,
        queue: Arc<ApprovalQueue>,
        lock_requested: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            handle,
            leases,
            queue,
            lock_requested,
        }
    }

    fn leases(&self) -> std::sync::MutexGuard<'_, LeaseStore> {
        self.leases.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Handle one request.
    ///
    /// # Panics
    ///
    /// Never: the `expect` below is guarded by the `is_unlocked` arm immediately above it.
    pub fn handle(&self, request: &Request, connection: &mut Connection) -> Response {
        match request {
            Request::Hello { protocol, client } => Self::hello(*protocol, client, connection),
            _ if !self.is_serving() => {
                // A locked vault kills leases even if the lock hook somehow did not run: this is
                // the belt to that brace, and it is cheap.
                self.kill_leases();
                Response::error(
                    ErrorCode::VaultLocked,
                    "The kagisecure vault is locked. Ask the user to unlock it.",
                )
            }
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
            Request::Audit { limit, verify } => self.audit(*limit, *verify),
            Request::ListLeases => Response::Leases {
                leases: self.leases().summaries(unix_now()),
            },
            Request::Lock => self.lock(connection),
        }
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
        self.handle.is_unlocked()
            && !self
                .lock_requested
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn locked() -> Response {
        Response::error(
            ErrorCode::VaultLocked,
            "The kagisecure vault is locked. Ask the user to unlock it.",
        )
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

    // -----------------------------------------------------------------------------------------
    // Read-only tools
    // -----------------------------------------------------------------------------------------

    fn list_vaults(&self, connection: &Connection) -> Response {
        let vaults = match self.read(|v| {
            v.vault_summaries()
                .into_iter()
                .filter(|s| s.agent_visible)
                .collect::<Vec<_>>()
        }) {
            Ok(v) => v,
            Err(response) => return response,
        };
        self.record_and_save(AuditDraft {
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
        let all = match self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            vault
                .item_summaries()
                .into_iter()
                .filter(|i| i.agent_visible && !i.trashed && visible.contains(&i.vault_id))
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

        self.record_and_save(AuditDraft {
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
        let environments = match self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            vault
                .environment_summaries()
                .into_iter()
                .filter(|e| e.agent_visible && visible.contains(&e.vault_id))
                .filter(|e| vault_id.is_none_or(|v| e.vault_id == v))
                .collect::<Vec<EnvironmentSummary>>()
        }) {
            Ok(v) => v,
            Err(response) => return response,
        };
        self.record_and_save(AuditDraft {
            tool: "list_environments".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Environments { environments }
    }

    fn describe_item(&self, reference: &str, connection: &Connection) -> Response {
        let found = self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            vault.find_item(reference).ok().map(|item| {
                let summary = item.summary();
                let allowed = summary.agent_visible
                    && !summary.trashed
                    && visible.contains(&summary.vault_id);
                (summary, allowed)
            })
        });
        let found = match found {
            Ok(v) => v,
            Err(response) => return response,
        };
        let Some((summary, allowed)) = found else {
            return Response::error(
                ErrorCode::NotFound,
                "No item with that id. Call list_items again.",
            );
        };
        if !allowed {
            return Response::error(
                ErrorCode::NotAgentVisible,
                "That item exists but the user has not made it visible to agents. Ask them to \
                 turn on agent access for it; do not retry.",
            );
        }
        self.record_and_save(AuditDraft {
            tool: "describe_item".to_owned(),
            item_id: Some(summary.id),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        Response::Item {
            item: Box::new(summary),
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
        let target = match vault_id {
            Some(v) => v,
            None => match self.read(|vault| vault.default_vault_id()) {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Response::error(ErrorCode::Internal, e.to_string()),
                Err(response) => return response,
            },
        };

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

        let mut env = Environment::new(target, name);
        env.description = description.map(str::to_owned);
        // Created through an approved agent request, so it is visible to the agent that asked.
        // A CLI-created environment stays invisible until the user says otherwise (ADR-0007).
        env.agent_visible = true;
        let summary = env.summary();
        if self
            .handle
            .with_mut(|vault| vault.add_environment(env))
            .is_none()
        {
            return Self::locked();
        }

        self.record(AuditDraft {
            tool: "create_environment".to_owned(),
            vault_id: Some(target),
            environment_id: Some(summary.id),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        if let Err(message) = self.save() {
            return Response::error(ErrorCode::Internal, message);
        }
        Response::Environment {
            environment: Box::new(summary),
        }
    }

    fn add_variables(
        &self,
        environment_id: EnvId,
        variables: &[VariableRequest],
        connection: &Connection,
    ) -> Response {
        let reference = environment_id.to_string();
        let addressable = self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            vault.find_environment(&reference).ok().map(|env| {
                (
                    env.name.clone(),
                    env.agent_visible && visible.contains(&env.vault_id),
                )
            })
        });
        let addressable = match addressable {
            Ok(v) => v,
            Err(response) => return response,
        };
        let env_name = match addressable {
            Some((name, true)) => name,
            Some((_, false)) => {
                return Response::error(
                    ErrorCode::NotAgentVisible,
                    "That environment is not visible to agents.",
                );
            }
            None => {
                return Response::error(
                    ErrorCode::NotFound,
                    "No environment with that id. Call list_environments again.",
                );
            }
        };

        let names: Vec<String> = variables.iter().map(|v| v.name.clone()).collect();
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

        let mut bound = Vec::new();
        let mut pending = Vec::new();
        for request in variables {
            let source = match &request.bind_to {
                Some(field) => {
                    let item_ref = field.item_id.to_string();
                    let ok = self.read(|vault| {
                        vault.find_item(&item_ref).is_ok_and(|item| {
                            item.agent_visible && item.fields.iter().any(|f| f.id == field.field_id)
                        })
                    });
                    match ok {
                        Ok(true) => VarSource::ItemField {
                            item: field.item_id,
                            field: field.field_id,
                        },
                        Ok(false) => {
                            return Response::error(
                                ErrorCode::NotFound,
                                "That item or field does not exist, or is not visible to agents.",
                            );
                        }
                        Err(response) => return response,
                    }
                }
                None => VarSource::Pending {
                    hint: request.hint.clone(),
                },
            };
            let is_binding = matches!(source, VarSource::ItemField { .. });
            let set = self.handle.with_mut(|vault| {
                vault
                    .find_environment_mut(&reference)
                    .map(|env| {
                        env.set_var(EnvVar {
                            name: request.name.clone(),
                            source,
                        });
                    })
                    .map_err(|e| e.to_string())
            });
            match set {
                Some(Ok(())) => {}
                Some(Err(message)) => return Response::error(ErrorCode::Internal, message),
                None => return Self::locked(),
            }
            if is_binding {
                bound.push(request.name.clone());
            } else {
                pending.push(request.name.clone());
            }
        }

        self.record(AuditDraft {
            tool: "add_variables".to_owned(),
            environment_id: Some(environment_id),
            variables: names,
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        if let Err(message) = self.save() {
            return Response::error(ErrorCode::Internal, message);
        }

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
        let reference = environment_id.to_string();
        let selected = match self.selected_names(&reference, variables) {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Response::error(
                    ErrorCode::NotFound,
                    "No environment with that id, or it is not visible to agents. Call \
                     list_environments again.",
                );
            }
            Err(response) => return response,
        };
        let (env_name, names) = selected;

        let canonical = match canonical_dir(directory) {
            Ok(p) => p,
            Err(message) => return Response::error(ErrorCode::InvalidPath, message),
        };
        let target = canonical.join(filename);

        let request = LeaseRequest {
            environment_id,
            directory: canonical.clone(),
            variables: names.iter().cloned().collect(),
            kind: LeaseKind::EnvFile,
            command: None,
        };

        let now = unix_now();
        let existing = self.leases().find(&request, now).map(|l| l.id);
        let lease_id = match existing {
            Some(id) => id,
            None => {
                let approved = self.ask(
                    ApprovalRequest {
                        kind: ApprovalKind::WriteEnvFile,
                        environment_id: Some(reference.clone()),
                        environment_name: Some(env_name),
                        directory: Some(canonical.display().to_string()),
                        target_path: Some(target.display().to_string()),
                        variables: names.clone(),
                        gitignored: envfile::gitignore_status(&target),
                        requested_ttl_seconds: ttl_seconds,
                        requested_uses: lease::DEFAULT_USES,
                        ..ApprovalRequest::default()
                    }
                    .with_identity(connection.identity()),
                );
                if !approved.granted {
                    return self.denied(
                        "write_env_file",
                        &approved,
                        Some(environment_id),
                        names,
                        connection,
                    );
                }
                self.leases().grant(
                    &request,
                    describe_with_verification(connection.identity(), &approved.verification),
                    approved.ttl_seconds,
                    approved.uses,
                    now,
                )
            }
        };

        // The vault lock is held only for the resolution and the write, never across the prompt.
        let guard = self.handle.guard();
        let Some(vault) = guard.as_ref() else {
            return Self::locked();
        };
        let injections = match vault.resolve_environment(&reference, Some(&names)) {
            Ok(i) => i,
            Err(e) => {
                let code = error_code_for(&e);
                drop(guard);
                return self.failed(
                    "write_env_file",
                    code,
                    Some(environment_id),
                    names,
                    &e,
                    connection,
                );
            }
        };
        let written = match envfile::write(&canonical, filename, &injections, overwrite) {
            Ok(w) => w,
            Err(e) => {
                let code = error_code_for(&e);
                drop(injections);
                drop(guard);
                return self.failed(
                    "write_env_file",
                    code,
                    Some(environment_id),
                    names,
                    &e,
                    connection,
                );
            }
        };
        drop(injections);
        drop(guard);

        let expires_at = {
            let mut leases = self.leases();
            leases.consume(lease_id, now);
            leases.record_written(lease_id, written.path.clone());
            leases
                .summaries(now)
                .into_iter()
                .find(|l| l.id == lease_id)
                .map_or(now + ttl_seconds, |l| l.expires_at)
        };

        self.record(AuditDraft {
            tool: "write_env_file".to_owned(),
            environment_id: Some(environment_id),
            variables: written.variables.clone(),
            target_path: Some(written.path.display().to_string()),
            lease_id: Some(lease_id),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        if let Err(message) = self.save() {
            return Response::error(ErrorCode::Internal, message);
        }

        Response::WroteEnvFile {
            path: written.path.display().to_string(),
            variables_written: written.variables,
            bytes: written.bytes,
            lease_id,
            expires_at: rfc3339(expires_at),
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
        let reference = environment_id.to_string();
        let selected = match self.selected_names(&reference, variables) {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Response::error(
                    ErrorCode::NotFound,
                    "No environment with that id, or it is not visible to agents. Call \
                     list_environments again.",
                );
            }
            Err(response) => return response,
        };
        let (env_name, names) = selected;

        let canonical = match canonical_dir(cwd) {
            Ok(p) => p,
            Err(message) => return Response::error(ErrorCode::InvalidPath, message),
        };

        let mut argv = vec![command.to_owned()];
        argv.extend(args.iter().cloned());

        let request = LeaseRequest {
            environment_id,
            directory: canonical.clone(),
            variables: names.iter().cloned().collect(),
            kind: LeaseKind::RunCommand,
            command: Some(argv.clone()),
        };

        let now = unix_now();
        let existing = self.leases().find(&request, now).map(|l| l.id);
        let lease_id = match existing {
            Some(id) => id,
            None => {
                let approved = self.ask(
                    ApprovalRequest {
                        kind: ApprovalKind::RunWithEnv,
                        environment_id: Some(reference.clone()),
                        environment_name: Some(env_name),
                        directory: Some(canonical.display().to_string()),
                        variables: names.clone(),
                        command: argv.clone(),
                        requested_ttl_seconds: lease::DEFAULT_TTL_SECONDS,
                        requested_uses: lease::DEFAULT_USES,
                        ..ApprovalRequest::default()
                    }
                    .with_identity(connection.identity()),
                );
                if !approved.granted {
                    return self.denied(
                        "run_with_env",
                        &approved,
                        Some(environment_id),
                        names,
                        connection,
                    );
                }
                self.leases().grant(
                    &request,
                    describe_with_verification(connection.identity(), &approved.verification),
                    approved.ttl_seconds,
                    approved.uses,
                    now,
                )
            }
        };

        let guard = self.handle.guard();
        let Some(vault) = guard.as_ref() else {
            return Self::locked();
        };
        let injections = match vault.resolve_environment(&reference, Some(&names)) {
            Ok(i) => i,
            Err(e) => {
                let code = error_code_for(&e);
                drop(guard);
                return self.failed(
                    "run_with_env",
                    code,
                    Some(environment_id),
                    names,
                    &e,
                    connection,
                );
            }
        };

        let os_args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        let run = RunRequest {
            program: std::ffi::OsStr::new(command),
            args: &os_args,
            env: &injections,
            cwd: Some(&canonical),
            mask_output: true,
            max_output: kagisecure_core::inject::DEFAULT_MAX_OUTPUT,
            timeout: Some(Duration::from_secs(timeout_seconds)),
        };
        let outcome = match run_with_env(&run) {
            Ok(o) => o,
            Err(e) => {
                let code = error_code_for(&e);
                drop(injections);
                drop(guard);
                return self.failed(
                    "run_with_env",
                    code,
                    Some(environment_id),
                    names,
                    &e,
                    connection,
                );
            }
        };
        drop(injections);
        drop(guard);

        let expires_at = {
            let mut leases = self.leases();
            leases.consume(lease_id, now);
            leases
                .summaries(now)
                .into_iter()
                .find(|l| l.id == lease_id)
                .map_or(now + lease::DEFAULT_TTL_SECONDS, |l| l.expires_at)
        };

        self.record(AuditDraft {
            tool: "run_with_env".to_owned(),
            environment_id: Some(environment_id),
            variables: names,
            target_path: Some(canonical.display().to_string()),
            lease_id: Some(lease_id),
            outcome: Outcome::Allowed,
            detail: outcome.timed_out.then(|| "TIMED_OUT".to_owned()),
            ..Self::draft(connection)
        });
        if let Err(message) = self.save() {
            return Response::error(ErrorCode::Internal, message);
        }

        let include = output == OutputMode::Scrubbed;
        Response::Ran {
            exit_code: outcome.exit_code,
            stdout: include.then(|| String::from_utf8_lossy(&outcome.stdout).into_owned()),
            stderr: include.then(|| String::from_utf8_lossy(&outcome.stderr).into_owned()),
            truncated: outcome.stdout_truncated || outcome.stderr_truncated,
            scrubbed: outcome.masked,
            lease_id,
            expires_at: rfc3339(expires_at),
        }
    }

    fn revoke(
        &self,
        lease_id: Option<LeaseId>,
        path: Option<&str>,
        connection: &Connection,
    ) -> Response {
        // Revoking access is always allowed: there is no approval, and no way for a request to
        // fail in a way that leaves the lease alive.
        let mut targets: Vec<PathBuf> = Vec::new();
        {
            let mut leases = self.leases();
            if let Some(id) = lease_id
                && let Some(paths) = leases.revoke(id)
            {
                targets.extend(paths);
            }
            if let Some(p) = path {
                let candidate = PathBuf::from(p);
                targets.extend(leases.revoke_by_path(&candidate));
                if !targets.contains(&candidate) {
                    targets.push(candidate);
                }
            }
        }

        let mut shredded = Vec::new();
        for target in targets {
            if envfile::shred(&target).unwrap_or(false) {
                shredded.push(target.display().to_string());
            }
        }

        self.record(AuditDraft {
            tool: "revoke_env_file".to_owned(),
            lease_id,
            target_path: shredded.first().cloned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        let _ = self.save();
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
        self.record(AuditDraft {
            tool: "lock".to_owned(),
            outcome: Outcome::Allowed,
            ..Self::draft(connection)
        });
        let _ = self.save();

        // Everything `Shared::on_vault_locked` does, done now rather than when the host next
        // polls: the leases die, the files they wrote are shredded, and the approval queue closes
        // so that a request already blocked in `ask` — or one that arrives in the next
        // millisecond — cannot be answered "allow" after the user has pressed Lock.
        self.kill_leases();
        self.queue.deny_all();
        self.lock_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Response::Locked
    }

    /// Drop every lease and shred every file written under one.
    pub(crate) fn kill_leases(&self) {
        let paths = self.leases().revoke_all();
        for path in paths {
            let _ = envfile::shred(&path);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------------------------------

    /// The variable names a request selects, with the environment's display name.
    ///
    /// `Ok(None)` means "no such environment, or not agent-visible"; `Err` means locked.
    #[allow(clippy::type_complexity)]
    fn selected_names(
        &self,
        reference: &str,
        wanted: Option<&[String]>,
    ) -> Result<Option<(String, Vec<String>)>, Response> {
        self.read(|vault| {
            let visible = Self::visible_vaults(vault);
            let env = vault.find_environment(reference).ok()?;
            if !env.agent_visible || !visible.contains(&env.vault_id) {
                return None;
            }
            let names = match wanted {
                Some(names) => names.to_vec(),
                None => env.vars.iter().map(|v| v.name.clone()).collect(),
            };
            Some((env.name.clone(), names))
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

    fn record(&self, draft: AuditDraft) {
        self.handle.with_mut(|vault| vault.append_audit(draft));
    }

    /// Record an audit entry for a read-only call and persist it straight away.
    ///
    /// The mutating paths save because they changed something; a read-only tool changes nothing
    /// but its own audit entry, so without this the entry would sit in memory until some later
    /// mutating call happened to save — and would be lost entirely if none ever came. An agent
    /// that only ever *reads* would leave no trace, which defeats the point of auditing reads.
    ///
    /// A failed save does not fail the read: the caller asked for metadata it is entitled to and
    /// already has, and turning a disk problem into a tool error would tell it nothing useful.
    fn record_and_save(&self, draft: AuditDraft) {
        self.record(draft);
        if let Err(message) = self.save() {
            eprintln!("kagisecure: could not persist the audit entry: {message}");
        }
    }

    fn save(&self) -> Result<(), String> {
        match self
            .handle
            .with(|vault| vault.save().map_err(|e| e.to_string()))
        {
            Some(result) => result,
            // Locked between the append and the save: nothing to write, and nothing was lost that
            // the lock did not already discard.
            None => Ok(()),
        }
    }

    fn denied(
        &self,
        tool: &str,
        approval: &Approval,
        environment_id: Option<EnvId>,
        variables: Vec<String>,
        connection: &Connection,
    ) -> Response {
        self.record(AuditDraft {
            tool: tool.to_owned(),
            environment_id,
            variables,
            outcome: Outcome::Denied,
            detail: Some(approval.code.as_str().to_owned()),
            ..Self::draft(connection)
        });
        let _ = self.save();
        Response::error(
            approval.code,
            match approval.code {
                ErrorCode::ApprovalTimeout => {
                    "Nobody answered the approval prompt within 60 seconds. Tell the user, then \
                     you may retry once."
                }
                ErrorCode::VaultLocked => {
                    "The kagisecure vault locked before the request was answered. Ask the user to \
                     unlock it."
                }
                _ => "The user declined. Stop; do not request the same thing again.",
            },
        )
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
        let message = error.to_string();
        self.record(AuditDraft {
            tool: tool.to_owned(),
            environment_id,
            variables,
            outcome: Outcome::Failed,
            detail: Some(code.as_str().to_owned()),
            ..Self::draft(connection)
        });
        let _ = self.save();
        Response::error(code, message)
    }

    /// Put the question to whoever is answering questions, and block.
    fn ask(&self, request: ApprovalRequest) -> Approval {
        self.queue.ask(request)
    }
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

/// Map a core error onto the stable code table in mcp-server.md §7.
#[must_use]
pub fn error_code_for(error: &kagisecure_core::Error) -> ErrorCode {
    use kagisecure_core::Error as E;
    match error {
        E::EnvFileExists(_) => ErrorCode::FileExists,
        E::InvalidPath(_) | E::InvalidEnvFileName(_) => ErrorCode::InvalidPath,
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
