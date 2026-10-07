//! The unattended socket's requests (ADR-0042 §6): the release path for command grants, and what
//! every other message gets there.
//!
//! The order of checks for `run_with_env`, each answered before the next is made:
//!
//! 1. **Armed**, or `UNATTENDED_PAUSED` before anything else is looked at.
//! 2. **In a run** ([`super::runs::RunRegistry::bind`]), or `NOT_GRANTED` (`OUTSIDE_RUN`).
//! 3. **Arguments** within the schema, or `INVALID_ARGUMENT`.
//! 4. **A grant of this run's job covers the request** — environment, variables (a subset),
//!    executable path, the whole argument list, the canonical working directory — and is not
//!    suspended, expired, used up or over its per-run limit. A request no grant covers is a
//!    **strike**: every grant of the job is suspended and the run is ended. The others simply
//!    refuse. One code and one message for every reason; the reason is in the audit entry.
//! 5. **Pins hold now**: the executable, every pinned input, the working directory; and nothing it
//!    releases changed since the grant was approved (implementation decision 3). Otherwise the
//!    grant is suspended.
//! 6. **Audit pre-flight**, or `AUDIT_UNAVAILABLE`.
//! 7. **Release** through [`crate::release::audited_release`] on the machine vault: the grant's use
//!    counted and the `Allowed` entry committed in one transaction, then the command spawned in a
//!    process group registered to the run, so the run's end ends it.
//! 8. **Reply**: the exit code only. Output is never returned unattended, whatever was asked.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{
    Delivery as InjectDelivery, EnvInjection, RunOutcome, RunRequest, run_with_env_tracked,
};
use kagisecure_core::model::VarSource;
use kagisecure_core::proto::{EnvId, LeaseId, Outcome};
use kagisecure_core::unix_now;
use kagisecure_core::vault::machine::{CommandGrant, GrantId, MachineSection};
use kagisecure_ipc::protocol::{
    ClientInfo, Delivery, ErrorCode, MAX_RUN_ARGS, PROTOCOL_VERSION, Request, Response, rfc3339,
};
use kagisecure_ipc::server::{Connection, peer_is_same_user};

use super::runs::Run;
use super::{Core, TOOL_GRANT, engine_entry, pins};
use crate::release::{Acted, NotReleased, Released, audited_release};
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle};

/// `NOT_GRANTED`'s one message (ADR-0042 §6).
pub const NOT_GRANTED: &str = "Stop. Do not retry or try variations; the owner has been told.";

/// `UNATTENDED_PAUSED`'s one message (ADR-0042 §6).
pub const UNATTENDED_PAUSED: &str = "Tell the user unattended jobs are paused; do not retry.";

const AUDIT_UNAVAILABLE: &str = "kagisecure could not record this request in the machine vault's \
                                 audit log, so nothing was released. Do not retry in a loop.";

/// Serve one connection on the unattended socket.
pub(crate) fn serve_connection(core: &Arc<Core>, connection: &mut Connection) {
    let identity = connection.identity();
    if !peer_is_same_user(identity.euid, identity.kernel_pid()) {
        let _ = connection.write_response(&Response::error(
            ErrorCode::Internal,
            "This socket only serves the user who owns it.",
        ));
        return;
    }
    loop {
        if core.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let Ok(request) = connection.read_request() else {
            return;
        };
        if core.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let response = handle(core, &request, connection);
        if connection.write_response(&response).is_err() {
            return;
        }
    }
}

pub(super) fn not_granted() -> Response {
    Response::error(ErrorCode::NotGranted, NOT_GRANTED)
}

fn paused() -> Response {
    Response::error(ErrorCode::UnattendedPaused, UNATTENDED_PAUSED)
}

fn hello(protocol: u32, client: &ClientInfo, connection: &mut Connection) -> Response {
    if protocol != PROTOCOL_VERSION {
        return Response::error(
            ErrorCode::Internal,
            format!("This build speaks protocol {PROTOCOL_VERSION}; the caller speaks {protocol}."),
        );
    }
    connection.adopt_reported(client.clone());
    let identity = connection.identity().clone();
    Response::Hello {
        server: crate::service::SERVER_NAME.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol: PROTOCOL_VERSION,
        client_identity: identity.describe(),
        client_verified: identity.verified(),
    }
}

/// The audit actor of a request from a run (ADR-0042 §8): `mcp unattended "<job>" run <id> pid <n>
/// <executable>`. The `mcp` prefix keeps it under the Audit view's agent filter.
pub(super) fn actor(run: Option<&Run>, pid: Option<u32>) -> String {
    let exe = pid
        .and_then(kagisecure_ipc::server::executable_for_pid)
        .unwrap_or_else(|| "unknown".to_owned());
    let pid = pid.map_or_else(|| "?".to_owned(), |p| p.to_string());
    match run {
        Some(run) => format!(
            "mcp unattended {:?} run {} pid {pid} {exe}",
            run.job_name, run.id
        ),
        None => format!("mcp unattended (no run) pid {pid} {exe}"),
    }
}

/// Handle one request on the unattended socket.
pub(crate) fn handle(core: &Arc<Core>, request: &Request, connection: &mut Connection) -> Response {
    match request {
        Request::Hello { protocol, client } => return hello(*protocol, client, connection),
        Request::Lock => {
            // Any same-user process may pause the jobs: refusing is always allowed. A denial of
            // service, never a disclosure (ADR-0042 §3).
            core.disarm("LOCK_REQUEST");
            return Response::Locked;
        }
        _ => {}
    }
    let Some(handle) = core.armed() else {
        return paused();
    };
    if let Some(Err(e)) = handle.sync()
        && !crate::vault::sync_could_not_read(&e)
    {
        core.disarm("VAULT_CONFLICT");
        return paused();
    }
    let pid = connection.identity().kernel_pid();
    let Some(run) = core.runs.bind(pid) else {
        record_refusal(
            core,
            None,
            pid,
            connection,
            request.tool_name(),
            None,
            Vec::new(),
            "OUTSIDE_RUN",
        );
        return not_granted();
    };
    let ctx = Ctx {
        core,
        handle: &handle,
        run: &run,
        pid,
        connection,
    };
    match request {
        Request::RunWithEnv {
            environment_id,
            variables,
            delivery: Delivery::Stdin,
            ..
        } => {
            // A standing grant covers an exact command run with its environment; stdin delivery
            // is one approval per run by design (ADR-0047), so no grant can cover it, and asking
            // is a strike like any other request outside the job's grants.
            ctx.strike(
                "run_with_env",
                Some(*environment_id),
                variables.clone().unwrap_or_default(),
                "NO_GRANT",
            );
            not_granted()
        }
        Request::RunWithEnv {
            environment_id,
            command,
            args,
            cwd,
            variables,
            timeout_seconds: _,
            output: _,
            delivery: Delivery::Environment,
        } => ctx.run_with_env(*environment_id, command, args, cwd, variables.as_deref()),
        Request::WriteEnvFile {
            environment_id,
            variables,
            ..
        } => {
            // A file outlives the run and is readable by every same-user process: never
            // unattended, and asking is a strike (ADR-0042 §1, §7).
            ctx.strike(
                "write_env_file",
                Some(*environment_id),
                variables.clone().unwrap_or_default(),
                "NO_GRANT",
            );
            not_granted()
        }
        Request::RequestFill {
            item_id,
            origin,
            fields,
        } => ctx.request_fill(item_id, origin, fields),
        Request::ListEnvironments { vault_id } => ctx.list_environments(*vault_id),
        Request::ListVaults => ctx.list_vaults(),
        Request::ListItems { .. } => Response::Items {
            items: Vec::new(),
            next_cursor: None,
        },
        Request::DescribeItem { .. } => crate::service::no_such_item(),
        Request::RevokeEnvFile { .. } => Response::Revoked {
            shredded: Vec::new(),
        },
        Request::ListLeases => Response::Leases { leases: Vec::new() },
        // Agent test logins are personal and interactive only (ADR-0048 §12): nothing to list.
        Request::ListTestLogins { .. } => Response::TestLogins {
            items: Vec::new(),
            next_cursor: None,
        },
        Request::CreateEnvironment { .. }
        | Request::AddVariables { .. }
        | Request::CreateTestLogin { .. }
        | Request::TrashTestLogins { .. }
        | Request::Audit { .. } => {
            // Changes to the vault, and its log, are the person's: refused, not a strike — none
            // of these releases anything.
            record_refusal(
                core,
                Some(&run),
                pid,
                connection,
                request.tool_name(),
                None,
                Vec::new(),
                "NO_GRANT",
            );
            not_granted()
        }
        Request::Hello { .. } | Request::Lock => {
            unreachable!("answered above")
        }
    }
}

/// Record a refusal in the machine log.
#[allow(clippy::too_many_arguments)]
fn record_refusal(
    core: &Core,
    run: Option<&Run>,
    pid: Option<u32>,
    connection: &Connection,
    tool: &str,
    environment_id: Option<EnvId>,
    variables: Vec<String>,
    reason: &str,
) {
    core.record(refusal_entry(
        run,
        pid,
        connection,
        tool,
        environment_id,
        variables,
        reason,
    ));
}

pub(super) fn refusal_entry(
    run: Option<&Run>,
    pid: Option<u32>,
    connection: &Connection,
    tool: &str,
    environment_id: Option<EnvId>,
    variables: Vec<String>,
    reason: &str,
) -> AuditDraft {
    AuditDraft {
        actor: actor(run, pid),
        client_pid: connection.identity().pid,
        tool: tool.to_owned(),
        environment_id,
        variables,
        outcome: Outcome::Denied,
        detail: Some(format!("NOT_GRANTED ({reason})")),
        ..AuditDraft::default()
    }
}

/// What step 4 and 5 decided.
enum Decision {
    /// No grant of the job covers the request: a strike.
    Strike,
    /// A grant covers it but refuses now, without a strike.
    Refuse(&'static str),
    /// A grant covers it, but a pin or a value changed: suspend that grant.
    Suspend(GrantId, &'static str),
    /// Release under this grant, these variables.
    Release(Box<CommandGrant>, Vec<String>),
}

/// The canonical form of a directory, as a string; the input itself when it cannot be resolved,
/// which then matches no grant's canonical directory.
pub(super) fn canonical(dir: &str) -> String {
    std::fs::canonicalize(dir).map_or_else(|_| dir.to_owned(), |p| p.to_string_lossy().into_owned())
}

pub(super) struct Ctx<'a> {
    pub(super) core: &'a Arc<Core>,
    pub(super) handle: &'a Arc<VaultHandle>,
    pub(super) run: &'a Arc<Run>,
    pub(super) pid: Option<u32>,
    pub(super) connection: &'a Connection,
}

impl Ctx<'_> {
    pub(super) fn refuse(
        &self,
        tool: &str,
        env: Option<EnvId>,
        variables: Vec<String>,
        reason: &str,
    ) -> Response {
        record_refusal(
            self.core,
            Some(self.run),
            self.pid,
            self.connection,
            tool,
            env,
            variables,
            reason,
        );
        not_granted()
    }

    /// One strike (ADR-0042 §7): every grant of the run's job suspended, the refusal and the
    /// suspension recorded, the run ended, and the owner told.
    pub(super) fn strike(
        &self,
        tool: &str,
        env: Option<EnvId>,
        variables: Vec<String>,
        reason: &str,
    ) {
        let refusal = refusal_entry(
            Some(self.run),
            self.pid,
            self.connection,
            tool,
            env,
            variables,
            reason,
        );
        let suspended = engine_entry(
            TOOL_GRANT,
            Outcome::Denied,
            format!(
                "GRANT_SUSPENDED ({reason}) job {:?} run {}",
                self.run.job_name, self.run.id
            ),
        );
        let job = self.run.job;
        let written = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            tx.machine_mut()?.suspend_job(job, unix_now(), reason);
            tx.append_audit(refusal.clone());
            tx.append_audit(suspended.clone());
            Ok(())
        });
        if !matches!(written, Some(Ok(()))) {
            // The suspension could not be written: the run is ended anyway, and the entries wait
            // for the next write. A grant that could not be suspended on disk still answers
            // nothing this run, which is over.
            self.core.record(refusal);
            self.core.record(suspended);
        }
        self.run.end("STRIKE");
        self.core
            .notice("SUSPENDED", Some(&self.run.job_name), reason);
    }

    /// Suspend one grant whose pin or value changed.
    fn suspend(
        &self,
        grant: GrantId,
        tool: &str,
        env: EnvId,
        variables: Vec<String>,
        reason: &str,
    ) {
        let refusal = refusal_entry(
            Some(self.run),
            self.pid,
            self.connection,
            tool,
            Some(env),
            variables,
            reason,
        );
        let suspended = engine_entry(
            TOOL_GRANT,
            Outcome::Denied,
            format!("GRANT_SUSPENDED ({reason}) grant {grant}"),
        );
        let written = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            tx.machine_mut()?.suspend_grant(grant, unix_now(), reason);
            tx.append_audit(refusal.clone());
            tx.append_audit(suspended.clone());
            Ok(())
        });
        if !matches!(written, Some(Ok(()))) {
            self.core.record(refusal);
            self.core.record(suspended);
        }
        self.core
            .notice("SUSPENDED", Some(&self.run.job_name), reason);
    }

    /// Steps 4 and 5 against the machine vault as it is now.
    fn decide(
        &self,
        env: EnvId,
        command: &str,
        args: &[String],
        cwd: &str,
        variables: Option<&[String]>,
    ) -> Decision {
        let cwd = canonical(cwd);
        let now = unix_now();
        self.handle
            .with(|vault| {
                let Some(machine) = vault.machine() else {
                    return Decision::Strike;
                };
                let covering = |g: &&CommandGrant| {
                    g.job == self.run.job
                        && g.env == env
                        && g.executable.path == command
                        && g.args == args
                        && g.working_dir == cwd
                        && variables.is_none_or(|wanted| {
                            !wanted.is_empty() && wanted.iter().all(|w| g.variables.contains(w))
                        })
                };
                let candidates: Vec<&CommandGrant> =
                    machine.command_grants.iter().filter(covering).collect();
                if candidates.is_empty() {
                    return Decision::Strike;
                }
                let Some(grant) = candidates.iter().find(|g| g.suspended.is_none()) else {
                    return Decision::Refuse("SUSPENDED");
                };
                if now >= grant.limits.expires_at {
                    return Decision::Refuse("EXPIRED");
                }
                if grant.uses >= grant.limits.total_uses {
                    return Decision::Refuse("USED_UP");
                }
                let names = variables.map_or_else(|| grant.variables.clone(), <[String]>::to_vec);
                if !pins::executable_holds(&grant.executable)
                    || !grant.pinned_inputs.iter().all(|f| f.holds())
                    || canonical(&grant.working_dir) != grant.working_dir
                {
                    return Decision::Suspend(grant.id, "PIN_CHANGED");
                }
                if value_changed(vault, machine, grant, &names) {
                    return Decision::Suspend(grant.id, "VALUE_CHANGED");
                }
                Decision::Release(Box::new((*grant).clone()), names)
            })
            .unwrap_or(Decision::Refuse("LOCKED"))
    }

    fn run_with_env(
        &self,
        env: EnvId,
        command: &str,
        args: &[String],
        cwd: &str,
        variables: Option<&[String]>,
    ) -> Response {
        const TOOL: &str = "run_with_env";
        if args.len() > MAX_RUN_ARGS {
            return Response::error(
                ErrorCode::InvalidArgument,
                "At most 64 arguments. Nothing was run.",
            );
        }
        let requested: Vec<String> = variables.map(<[String]>::to_vec).unwrap_or_default();
        let (grant, names) = match self.decide(env, command, args, cwd, variables) {
            Decision::Strike => {
                self.strike(TOOL, Some(env), requested, "NO_GRANT");
                return not_granted();
            }
            Decision::Refuse(reason) => return self.refuse(TOOL, Some(env), requested, reason),
            Decision::Suspend(grant, reason) => {
                self.suspend(grant, TOOL, env, requested, reason);
                return not_granted();
            }
            Decision::Release(grant, names) => (grant, names),
        };
        if !self.run.reserve(grant.id, grant.limits.per_run) {
            return self.refuse(TOOL, Some(env), names, "PER_RUN_LIMIT");
        }

        let target = canonical(cwd);
        let entry = AuditDraft {
            actor: actor(Some(self.run), self.pid),
            client_pid: self.connection.identity().pid,
            tool: TOOL.to_owned(),
            environment_id: Some(env),
            variables: names.clone(),
            target_path: Some(target.clone()),
            detail: Some(format!("UNATTENDED_GRANT {} RUN {}", grant.id, self.run.id)),
            ..AuditDraft::default()
        };

        // Step 6: nothing is released while earlier entries cannot be written.
        if !matches!(self.handle.flush(REQUEST_LOCK_TIMEOUT), Some(Ok(()))) {
            self.run.unreserve(grant.id);
            let _ = self
                .handle
                .queue_audit(crate::release::unavailable_entry(&entry));
            return Response::error(ErrorCode::AuditUnavailable, AUDIT_UNAVAILABLE);
        }

        let grant_id = grant.id;
        let reference = env.to_string();
        let prepare_names = names.clone();
        let template = entry.clone();
        let timeout = Duration::from_secs(u64::from(grant.timeout_secs)).min(self.run.remaining());
        let act = {
            let run = Arc::clone(self.run);
            let program = std::ffi::OsString::from(command);
            let os_args: Vec<std::ffi::OsString> =
                args.iter().map(std::ffi::OsString::from).collect();
            let dir = std::path::PathBuf::from(&target);
            move |injections: Vec<EnvInjection>, entry_seq: u64| {
                let child = std::cell::Cell::new(None);
                let ended = std::cell::Cell::new(false);
                let outcome = run_with_env_tracked(
                    &RunRequest {
                        program: &program,
                        args: &os_args,
                        env: &injections,
                        delivery: InjectDelivery::Environment,
                        cwd: Some(&dir),
                        mask_output: true,
                        max_output: kagisecure_core::inject::DEFAULT_MAX_OUTPUT,
                        timeout: Some(timeout),
                        new_process_group: true,
                    },
                    |kill| match run.children.register(kill, template, entry_seq) {
                        Ok(id) => child.set(Some(id)),
                        // The run ended between the release and the spawn: `register` killed it.
                        Err(crate::children::RegistryClosed) => ended.set(true),
                    },
                );
                if let Some(id) = child.get() {
                    run.children.deregister(id);
                }
                drop(injections);
                match outcome {
                    Ok(o) if ended.get() => Acted::abnormal("KILLED_ON_RUN_END", Ok(o)),
                    Ok(o) if o.timed_out => Acted::abnormal("TIMED_OUT", Ok(o)),
                    Ok(o) => Acted::done(Ok::<RunOutcome, kagisecure_core::Error>(o)),
                    Err(e) => Acted::abnormal("SPAWN_FAILED", Err(e)),
                }
            }
        };
        let released = audited_release(
            self.handle,
            REQUEST_LOCK_TIMEOUT,
            entry,
            move |tx| {
                let now = unix_now();
                {
                    let machine = tx.machine_mut().map_err(|_| "GONE")?;
                    let grant = machine
                        .command_grants
                        .iter_mut()
                        .find(|g| g.id == grant_id)
                        .ok_or("GONE")?;
                    if grant.suspended.is_some() {
                        return Err("SUSPENDED");
                    }
                    if now >= grant.limits.expires_at {
                        return Err("EXPIRED");
                    }
                    if grant.uses >= grant.limits.total_uses {
                        return Err("USED_UP");
                    }
                    grant.uses += 1;
                }
                tx.resolve_environment(&reference, Some(&prepare_names))
                    .map_err(|_| "UNRESOLVABLE")
            },
            act,
        );
        let outcome = match released {
            Ok(Released {
                value: Ok(outcome), ..
            }) => outcome,
            Ok(Released { value: Err(_), .. }) => {
                // Recorded already: the `Failed` entry naming the `Allowed` one.
                return Response::error(
                    ErrorCode::Internal,
                    "The granted command could not be started. Do not retry.",
                );
            }
            Err(NotReleased::Locked) => {
                self.run.unreserve(grant_id);
                return paused();
            }
            Err(NotReleased::Refused(reason)) => {
                self.run.unreserve(grant_id);
                return self.refuse(TOOL, Some(env), names, reason);
            }
            Err(NotReleased::AuditUnavailable(_)) => {
                self.run.unreserve(grant_id);
                return Response::error(ErrorCode::AuditUnavailable, AUDIT_UNAVAILABLE);
            }
        };
        Response::Ran {
            exit_code: outcome.exit_code,
            stdout: None,
            stderr: None,
            truncated: false,
            scrubbed: 0,
            // A standing grant stands where a lease would: its id, and its hard expiry
            // (implementation decision 13).
            lease_id: LeaseId(grant_id.0),
            expires_at: rfc3339(grant.limits.expires_at),
        }
    }

    /// The environments this run's job has grants over, each with only the granted variable
    /// names (ADR-0042 §1: the metadata tools answer only what the run's grants cover).
    fn granted_environments(&self) -> Vec<kagisecure_core::proto::EnvironmentSummary> {
        self.handle
            .with(|vault| {
                let Some(machine) = vault.machine() else {
                    return Vec::new();
                };
                let mut out = Vec::new();
                for env in vault.environments() {
                    let granted: BTreeSet<&str> = machine
                        .command_grants
                        .iter()
                        .filter(|g| g.job == self.run.job && g.env == env.id)
                        .flat_map(|g| g.variables.iter().map(String::as_str))
                        .collect();
                    if granted.is_empty() {
                        continue;
                    }
                    let mut summary = env.summary();
                    summary
                        .variables
                        .retain(|v| granted.contains(v.name.as_str()));
                    for v in &mut summary.variables {
                        v.item_id = None;
                        v.field_id = None;
                    }
                    out.push(summary);
                }
                out
            })
            .unwrap_or_default()
    }

    fn list_environments(&self, vault_id: Option<kagisecure_core::proto::VaultId>) -> Response {
        let mut environments = self.granted_environments();
        environments.retain(|e| vault_id.is_none_or(|v| e.vault_id == v));
        Response::Environments { environments }
    }

    fn list_vaults(&self) -> Response {
        let wanted: BTreeSet<_> = self
            .granted_environments()
            .into_iter()
            .map(|e| e.vault_id)
            .collect();
        let vaults = self
            .handle
            .with(|vault| {
                vault
                    .vault_summaries()
                    .into_iter()
                    .filter(|v| wanted.contains(&v.id))
                    .collect()
            })
            .unwrap_or_default();
        Response::Vaults { vaults }
    }
}

/// Whether anything `grant` releases as `names` changed after the grant was last approved: the
/// environment, or an item a released variable is bound to (implementation decision 3).
pub(super) fn value_changed(
    vault: &kagisecure_core::Vault,
    _machine: &MachineSection,
    grant: &CommandGrant,
    names: &[String],
) -> bool {
    let Some(env) = vault.environments().iter().find(|e| e.id == grant.env) else {
        return true;
    };
    if env.updated_at > grant.approved_at {
        return true;
    }
    names
        .iter()
        .any(|name| match env.var(name).map(|v| &v.source) {
            Some(VarSource::ItemField { item, .. }) => vault
                .item_by_id(item)
                .is_none_or(|i| i.updated_at > grant.approved_at),
            Some(_) => false,
            None => true,
        })
}
