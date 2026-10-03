//! A job's own program started with its environment (ADR-0042 implementation decision 51).
//!
//! When one of a job's command grants names exactly the job's own program — the same executable,
//! the whole argument list and the working directory — the engine does not wait for the program to
//! ask: it resolves the grant's variables and starts the program with them already in its
//! environment. A plain script gets them with no socket call at all.
//!
//! It is a release like any other, through [`crate::release::audited_release`]: the grant is
//! checked again inside the transaction, its use is counted there, and the `Allowed` entry
//! (`run_with_env`, detail `UNATTENDED_GRANT <g> RUN <r> (JOB_START)`) is committed before the
//! program starts. A grant that is suspended, expired or used up starts the program without the
//! variables and records why; a changed pin or value suspends the grant first, as §7 has it.

use std::process::Command;

use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{EnvInjection, Spawned, set_env};
use kagisecure_core::proto::Outcome;
use kagisecure_core::unix_now;
use kagisecure_core::vault::machine::{CommandGrant, GrantId, Job};

use super::service::{canonical, value_changed};
use super::{Core, TOOL_GRANT, engine_entry, pins};
use crate::release::{Acted, NotReleased, Released, audited_release};
use crate::vault::{REQUEST_LOCK_TIMEOUT, VaultHandle};

/// What the job's own-program grant, if it has one, allows at its start.
pub(super) enum AtStart {
    /// No grant names the job's own program.
    None,
    /// Start it with these variables of this grant.
    Release(Box<CommandGrant>, Vec<String>),
    /// A grant names it but refuses now, for this reason: start it without them.
    Refuse(&'static str),
    /// A grant names it, but a pin or a value changed: suspend the grant, then start without.
    Suspend(GrantId, &'static str),
}

/// Whether `grant` names exactly `job`'s own program.
fn is_own_program(grant: &CommandGrant, job: &Job) -> bool {
    grant.job == job.id
        && grant.executable.path == job.root.path
        && grant.args == job.args
        && grant.working_dir == job.working_dir
}

/// Decide, on the machine vault as it is now, what `job`'s start may release.
pub(super) fn decide(vault: &Vault, job: &Job) -> AtStart {
    let Some(machine) = vault.machine() else {
        return AtStart::None;
    };
    let candidates: Vec<&CommandGrant> = machine
        .command_grants
        .iter()
        .filter(|g| is_own_program(g, job))
        .collect();
    if candidates.is_empty() {
        return AtStart::None;
    }
    let Some(grant) = candidates.iter().find(|g| g.suspended.is_none()) else {
        return AtStart::Refuse("SUSPENDED");
    };
    if unix_now() >= grant.limits.expires_at {
        return AtStart::Refuse("EXPIRED");
    }
    if grant.uses >= grant.limits.total_uses {
        return AtStart::Refuse("USED_UP");
    }
    if !pins::executable_holds(&grant.executable)
        || !grant.pinned_inputs.iter().all(|f| f.holds())
        || canonical(&grant.working_dir) != grant.working_dir
    {
        return AtStart::Suspend(grant.id, "PIN_CHANGED");
    }
    if value_changed(vault, machine, grant, &grant.variables) {
        return AtStart::Suspend(grant.id, "VALUE_CHANGED");
    }
    AtStart::Release(Box::new((*grant).clone()), grant.variables.clone())
}

/// The actor of a release at a job's start: the run's, under the Unattended and agent filters.
fn actor(job: &Job, run: u64) -> String {
    format!(
        "mcp unattended {:?} run {run} job start {}",
        job.name, job.root.path
    )
}

/// How a start with its grant went.
pub(super) enum Started {
    /// The program runs, with the variables.
    WithGrant(Spawned, GrantId),
    /// The grant refused inside the transaction (it changed since [`decide`]): start without.
    Refused(&'static str),
    /// Nothing started, for this audit reason.
    Failed(&'static str),
}

/// Release `grant`'s `names` and start the program `make_command` builds with them, run `run`.
pub(super) fn start_with_grant(
    handle: &VaultHandle,
    job: &Job,
    run: u64,
    grant: &CommandGrant,
    names: Vec<String>,
    make_command: impl FnOnce() -> Command + 'static,
) -> Started {
    let entry = AuditDraft {
        actor: actor(job, run),
        tool: "run_with_env".to_owned(),
        environment_id: Some(grant.env),
        variables: names.clone(),
        target_path: Some(job.working_dir.clone()),
        detail: Some(format!(
            "UNATTENDED_GRANT {} RUN {run} (JOB_START)",
            grant.id
        )),
        ..AuditDraft::default()
    };
    // Nothing is released while earlier entries cannot be written.
    if !matches!(handle.flush(REQUEST_LOCK_TIMEOUT), Some(Ok(()))) {
        let _ = handle.queue_audit(crate::release::unavailable_entry(&entry));
        return Started::Failed("AUDIT_UNAVAILABLE");
    }
    let grant_id = grant.id;
    let reference = grant.env.to_string();
    let released = audited_release(
        handle,
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
            tx.resolve_environment(&reference, Some(&names))
                .map_err(|_| "UNRESOLVABLE")
        },
        move |injections: Vec<EnvInjection>, _entry_seq| {
            let mut command = make_command();
            let spawned = set_env(&mut command, &injections)
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|()| Spawned::spawn(&mut command, true));
            // The values leave this process's memory with the buffers; the command's own copy of
            // its environment goes with it.
            drop(command);
            drop(injections);
            match spawned {
                Ok(spawned) => Acted::done(Ok(spawned)),
                Err(e) => Acted::abnormal("SPAWN_FAILED", Err(e)),
            }
        },
    );
    match released {
        Ok(Released {
            value: Ok(spawned), ..
        }) => Started::WithGrant(spawned, grant_id),
        Ok(Released { value: Err(_), .. }) => Started::Failed("SPAWN_FAILED"),
        Err(NotReleased::Refused(reason)) => Started::Refused(reason),
        Err(NotReleased::Locked) => Started::Failed("LOCKED"),
        Err(NotReleased::AuditUnavailable(_)) => Started::Failed("AUDIT_UNAVAILABLE"),
    }
}

/// Record that the job's own-program grant released nothing at its start, and why.
pub(super) fn record_refusal(core: &Core, job: &Job, run: u64, reason: &str) {
    core.record(AuditDraft {
        actor: actor(job, run),
        tool: "run_with_env".to_owned(),
        target_path: Some(job.working_dir.clone()),
        outcome: Outcome::Denied,
        detail: Some(format!("NOT_GRANTED ({reason})")),
        ..AuditDraft::default()
    });
}

/// Suspend the job's own-program grant whose pin or value changed (§7), and tell the owner.
pub(super) fn suspend(core: &Core, handle: &VaultHandle, job: &Job, grant: GrantId, reason: &str) {
    let suspended = engine_entry(
        TOOL_GRANT,
        Outcome::Denied,
        format!("GRANT_SUSPENDED ({reason}) grant {grant}"),
    );
    let written = handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
        tx.machine_mut()?.suspend_grant(grant, unix_now(), reason);
        tx.append_audit(suspended.clone());
        Ok(())
    });
    if !matches!(written, Some(Ok(()))) {
        core.record(suspended);
    }
    core.notice("SUSPENDED", Some(&job.name), reason);
}
