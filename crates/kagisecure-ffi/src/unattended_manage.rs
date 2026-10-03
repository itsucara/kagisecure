//! Managing unattended jobs from the app (ADR-0042 Phase 3): what the machine vault holds, the
//! person's decisions — copying an environment in, creating a job with its grant, revoking,
//! re-enabling — the machine log, and "While you were away".
//!
//! Every call takes the unlocked **personal** session: the machine vault's key is in its body, and
//! the person's decisions are recorded in its log. The machine vault is opened for the call and
//! closed after it. No value crosses here: an environment is copied inside Rust, and what comes
//! back is names, paths, schedules, counts and audit rows.
//!
//! The calls that widen access — copying an environment, creating a job, re-enabling a grant —
//! take the presence proof the app has just made, and record it; the app makes it with the same
//! `PresenceCoordinator` every other decision uses. Revoking asks for nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use kagisecure_agent::unattended::pins::pin_executable;
use kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT;
use kagisecure_core::audit::{AuditDraft, AuditEntry};
use kagisecure_core::model::{Environment, Secret, VarSource};
use kagisecure_core::proto::{EnvId, Outcome, VarName};
use kagisecure_core::unix_now;
use kagisecure_core::vault::Vault;
use kagisecure_core::vault::machine::{
    CommandGrant, DEFAULT_GRANT_LIFETIME_SECS, DEFAULT_PER_RUN, DEFAULT_RUN_DEADLINE_SECS,
    DEFAULT_TOTAL_USES, GrantId, GrantLimits, Job, JobId, MAX_GRANT_LIFETIME_SECS, PresencePath,
    ScheduleTime, Weekday, machine_vault_path,
};

use crate::agent::AuditRowView;
use crate::session::VaultSession;
use crate::unattended::UnattendedPresence;
use crate::{FfiError, FfiResult};

/// The actor the app's own decisions are recorded under, in both logs.
const APP: &str = "app";

/// The `tool` of the person's decisions about unattended jobs.
const TOOL_DECISION: &str = "unattended_decision";

/// The `tool` of the summary acknowledgement, in the personal log (ADR-0042 §8).
const TOOL_SUMMARY: &str = "unattended_summary";

/// The key under which a copied environment names the personal environment it came from.
const COPIED_FROM: &str = "copied_from";

/// The most "While you were away" lists.
const SUMMARY_LIMIT: usize = 200;

// ---------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------

/// One calendar time: every day, or one weekday (0 = Monday ... 6 = Sunday), at `hour:minute`,
/// in the Mac's local time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedTimeView {
    /// `None` for every day.
    pub weekday: Option<u8>,
    /// 0 to 23.
    pub hour: u8,
    /// 0 to 59.
    pub minute: u8,
}

/// An environment in the machine vault.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MachineEnvironmentView {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Variable names.
    pub variable_names: Vec<String>,
    /// The personal environment it was copied from, if it was.
    pub copied_from: Option<String>,
    /// Unix seconds of the last change.
    pub updated_at: u64,
}

/// A command grant, for Agent access.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedGrantView {
    /// Identifier.
    pub id: String,
    /// The environment it releases from.
    pub environment_id: String,
    /// Its name, or empty when it is gone.
    pub environment_name: String,
    /// The variable names it releases.
    pub variables: Vec<String>,
    /// The command it lets run.
    pub command: String,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// Its working directory.
    pub working_dir: String,
    /// Uses so far.
    pub uses: u32,
    /// Uses allowed in total.
    pub total_uses: u32,
    /// Releases allowed per run.
    pub per_run: u32,
    /// Unix seconds when it expires.
    pub expires_at: u64,
    /// Why it is suspended, if it is.
    pub suspended_reason: Option<String>,
}

/// A job, with its grants.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedJobView {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// The program it starts.
    pub program: String,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// Its working directory.
    pub working_dir: String,
    /// When it runs.
    pub schedule: Vec<UnattendedTimeView>,
    /// How long a run may last, in minutes.
    pub run_deadline_minutes: u32,
    /// Its command grants.
    pub grants: Vec<UnattendedGrantView>,
}

/// What the machine vault holds, for Agent access.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedOverviewView {
    /// Whether this personal vault has a machine vault at all.
    pub has_machine_vault: bool,
    /// Its environments.
    pub environments: Vec<MachineEnvironmentView>,
    /// Its jobs.
    pub jobs: Vec<UnattendedJobView>,
}

/// A new job and the command grant it runs under, from the one "New job" sheet.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedJobDraft {
    /// Display name.
    pub name: String,
    /// The program the job starts, by absolute path.
    pub program: String,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// Its working directory, absolute.
    pub working_dir: String,
    /// When it runs; at least one time.
    pub schedule: Vec<UnattendedTimeView>,
    /// The machine-vault environment the grant releases from.
    pub environment_id: String,
    /// The variables it releases; all of the environment's when empty.
    pub variables: Vec<String>,
    /// The command the job may run with them; the program itself when `None`.
    pub command: Option<String>,
    /// That command's arguments; the program's own when `None`.
    pub command_arguments: Option<Vec<String>>,
    /// Days until the grant expires; 30 when 0, at most 90.
    pub expires_in_days: u32,
    /// The run browser, by absolute path, for a job that signs in (ADR-0042 §12.3); the default
    /// run browser when `None` and there are logins.
    #[uniffi(default = None)]
    pub run_browser: Option<String>,
    /// Login grants (ADR-0042 §12.2). With logins, `environment_id` may be empty: a job that only
    /// signs in.
    #[uniffi(default = [])]
    pub logins: Vec<crate::unattended_logins::UnattendedLoginDraft>,
}

/// "While you were away" (ADR-0042 §9): what the machine log recorded since the person last
/// acknowledged it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedSummaryView {
    /// The entries, newest first, at most 200.
    pub rows: Vec<AuditRowView>,
    /// How many entries there are in all since the acknowledgement.
    pub total: u32,
    /// Runs started.
    pub runs: u32,
    /// Values released.
    pub releases: u32,
    /// Requests refused.
    pub refusals: u32,
    /// Grants suspended.
    pub suspensions: u32,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn locked() -> FfiError {
    FfiError::invalid("The vault is locked.")
}

fn presence_path(presence: UnattendedPresence) -> PresencePath {
    match presence {
        UnattendedPresence::Confirmed => PresencePath::Confirmed,
        UnattendedPresence::ConfirmedMasterPassword => PresencePath::ConfirmedMasterPassword,
    }
}

fn presence_detail(presence: UnattendedPresence) -> &'static str {
    match presence {
        UnattendedPresence::Confirmed => "PRESENCE_CONFIRMED",
        UnattendedPresence::ConfirmedMasterPassword => "PRESENCE_CONFIRMED_MASTER_PASSWORD",
    }
}

fn decision(detail: String) -> AuditDraft {
    AuditDraft {
        actor: APP.to_owned(),
        tool: TOOL_DECISION.to_owned(),
        outcome: Outcome::Allowed,
        detail: Some(detail),
        ..AuditDraft::default()
    }
}

/// Record a decision in the personal log, best-effort.
fn record_personal(session: &VaultSession, draft: AuditDraft) {
    let _ = session
        .handle()
        .record_best_effort(REQUEST_LOCK_TIMEOUT, draft);
}

/// The machine vault, opened with the key in the unlocked personal body. `Ok(None)` when there is
/// none.
pub(crate) fn open_machine(session: &VaultSession) -> FfiResult<Option<Vault>> {
    let opened = session
        .handle()
        .with(|v| {
            v.machine_vault_key()
                .map(|key| Vault::open_machine(machine_vault_path(v.path()), key))
        })
        .ok_or_else(locked)?;
    match opened {
        None => Ok(None),
        Some(result) => Ok(Some(result?)),
    }
}

/// The machine vault, created first if there is none.
pub(crate) fn ensure_machine(session: &Arc<VaultSession>) -> FfiResult<Vault> {
    crate::unattended::unattended_create_machine_vault(Arc::clone(session))?;
    open_machine(session)?.ok_or_else(|| FfiError::invalid("This vault has no machine vault."))
}

fn weekday_number(weekday: Weekday) -> u8 {
    match weekday {
        Weekday::Monday => 0,
        Weekday::Tuesday => 1,
        Weekday::Wednesday => 2,
        Weekday::Thursday => 3,
        Weekday::Friday => 4,
        Weekday::Saturday => 5,
        Weekday::Sunday => 6,
    }
}

fn weekday(n: u8) -> FfiResult<Weekday> {
    Ok(match n {
        0 => Weekday::Monday,
        1 => Weekday::Tuesday,
        2 => Weekday::Wednesday,
        3 => Weekday::Thursday,
        4 => Weekday::Friday,
        5 => Weekday::Saturday,
        6 => Weekday::Sunday,
        _ => return Err(FfiError::invalid("A weekday is 0 (Monday) to 6 (Sunday).")),
    })
}

fn time_view(time: &ScheduleTime) -> UnattendedTimeView {
    match *time {
        ScheduleTime::Daily { hour, minute } => UnattendedTimeView {
            weekday: None,
            hour,
            minute,
        },
        ScheduleTime::Weekly {
            weekday,
            hour,
            minute,
        } => UnattendedTimeView {
            weekday: Some(weekday_number(weekday)),
            hour,
            minute,
        },
    }
}

fn schedule_time(view: &UnattendedTimeView) -> FfiResult<ScheduleTime> {
    Ok(match view.weekday {
        None => ScheduleTime::Daily {
            hour: view.hour,
            minute: view.minute,
        },
        Some(n) => ScheduleTime::Weekly {
            weekday: weekday(n)?,
            hour: view.hour,
            minute: view.minute,
        },
    })
}

fn audit_row(e: &AuditEntry) -> AuditRowView {
    AuditRowView {
        seq: e.seq,
        timestamp: e.timestamp,
        actor: e.actor.clone(),
        tool: e.tool.clone(),
        outcome: match e.outcome {
            Outcome::Allowed => "allowed".to_owned(),
            Outcome::Denied => "denied".to_owned(),
            Outcome::Failed => "failed".to_owned(),
        },
        environment_id: e.environment_id.map(|i| i.to_string()),
        item_id: e.item_id.map(|i| i.to_string()),
        variables: e.variables.clone(),
        target_path: e.target_path.clone(),
        detail: e.detail.clone(),
    }
}

fn copied_from(env: &Environment) -> Option<String> {
    env.unknown
        .get(COPIED_FROM)
        .and_then(ciborium::Value::as_text)
        .map(str::to_owned)
}

/// A directory as the grant compares it: canonical.
fn canonical_dir(dir: &str) -> FfiResult<String> {
    std::fs::canonicalize(dir)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| FfiError::invalid(format!("The folder {dir} does not exist.")))
}

fn parse<T: std::str::FromStr>(text: &str, what: &str) -> FfiResult<T> {
    text.parse()
        .map_err(|_| FfiError::invalid(format!("Not a {what} id.")))
}

/// How far the person has read the machine log: the entry count recorded by the last
/// `SUMMARY_ACKNOWLEDGED` in the personal log, 0 if none.
fn acknowledged_count(entries: &[AuditRowView]) -> usize {
    entries
        .iter()
        .rev()
        .filter(|e| e.tool == TOOL_SUMMARY)
        .find_map(|e| {
            e.detail
                .as_deref()?
                .strip_prefix("SUMMARY_ACKNOWLEDGED (entries ")?
                .split(' ')
                .next()?
                .trim_end_matches(')')
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

/// Count and list the machine log's entries (oldest first) after `from` — what happened while the
/// person was away, so not the person's own decisions (actor `app`).
fn summarize(entries: &[AuditRowView], from: usize) -> UnattendedSummaryView {
    let since: Vec<&AuditRowView> = entries
        .iter()
        .skip(from)
        .filter(|e| e.actor != APP)
        .collect();
    let starts =
        |e: &AuditRowView, prefix: &str| e.detail.as_deref().is_some_and(|d| d.starts_with(prefix));
    let count = |f: &dyn Fn(&AuditRowView) -> bool| {
        u32::try_from(since.iter().filter(|e| f(e)).count()).unwrap_or(u32::MAX)
    };
    UnattendedSummaryView {
        rows: since
            .iter()
            .rev()
            .take(SUMMARY_LIMIT)
            .map(|e| (*e).clone())
            .collect(),
        total: u32::try_from(since.len()).unwrap_or(u32::MAX),
        runs: count(&|e| starts(e, "JOB_STARTED")),
        releases: count(&|e| {
            e.outcome == "allowed"
                && (starts(e, "UNATTENDED_GRANT") || starts(e, "UNATTENDED_FILL_APPROVED"))
        }),
        refusals: count(&|e| starts(e, "NOT_GRANTED")),
        suspensions: count(&|e| starts(e, "GRANT_SUSPENDED")),
    }
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// What the machine vault holds: its environments and its jobs with their grants.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_overview(session: Arc<VaultSession>) -> FfiResult<UnattendedOverviewView> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(UnattendedOverviewView {
            has_machine_vault: false,
            environments: Vec::new(),
            jobs: Vec::new(),
        });
    };
    let environments: Vec<MachineEnvironmentView> = machine
        .environments()
        .iter()
        .map(|e| MachineEnvironmentView {
            id: e.id.to_string(),
            name: e.name.clone(),
            variable_names: e.vars.iter().map(|v| v.name.clone()).collect(),
            copied_from: copied_from(e),
            updated_at: e.updated_at,
        })
        .collect();
    let env_name = |id: EnvId| {
        machine
            .environments()
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.clone())
            .unwrap_or_default()
    };
    let grant_view = |g: &CommandGrant| UnattendedGrantView {
        id: g.id.to_string(),
        environment_id: g.env.to_string(),
        environment_name: env_name(g.env),
        variables: g.variables.clone(),
        command: g.executable.path.clone(),
        arguments: g.args.clone(),
        working_dir: g.working_dir.clone(),
        uses: g.uses,
        total_uses: g.limits.total_uses,
        per_run: g.limits.per_run,
        expires_at: g.limits.expires_at,
        suspended_reason: g.suspended.as_ref().map(|s| s.reason.clone()),
    };
    let jobs = machine
        .machine()
        .map(|section| {
            section
                .jobs
                .iter()
                .map(|job| UnattendedJobView {
                    id: job.id.to_string(),
                    name: job.name.clone(),
                    program: job.root.path.clone(),
                    arguments: job.args.clone(),
                    working_dir: job.working_dir.clone(),
                    schedule: job.schedule.iter().map(time_view).collect(),
                    run_deadline_minutes: job.run_deadline_secs / 60,
                    grants: section
                        .command_grants
                        .iter()
                        .filter(|g| g.job == job.id)
                        .map(grant_view)
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(UnattendedOverviewView {
        has_machine_vault: true,
        environments,
        jobs,
    })
}

/// A page of the machine vault's log, newest first — the Audit view's second log.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_audit_page(
    session: Arc<VaultSession>,
    limit: u32,
    offset: u32,
) -> FfiResult<Vec<AuditRowView>> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(Vec::new());
    };
    Ok(machine
        .audit_entries()
        .iter()
        .rev()
        .skip(offset as usize)
        .take(limit as usize)
        .map(audit_row)
        .collect())
}

/// "While you were away": what the machine log recorded since the person last acknowledged it.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_summary(session: Arc<VaultSession>) -> FfiResult<UnattendedSummaryView> {
    let from = session
        .handle()
        .with(|v| {
            let rows: Vec<AuditRowView> = v
                .audit_entries()
                .iter()
                .filter(|e| e.tool == TOOL_SUMMARY)
                .map(audit_row)
                .collect();
            acknowledged_count(&rows)
        })
        .ok_or_else(locked)?;
    let Some(machine) = open_machine(&session)? else {
        return Ok(summarize(&[], 0));
    };
    let rows: Vec<AuditRowView> = machine.audit_entries().iter().map(audit_row).collect();
    Ok(summarize(&rows, from))
}

/// The person has read the summary: record, in the personal log, how far the machine log went and
/// its head as they saw it (ADR-0042 §8), so a later rollback of the machine vault below that point
/// shows as a gap.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_acknowledge_summary(session: Arc<VaultSession>) -> FfiResult<()> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(());
    };
    let count = machine.audit_entries().len();
    let head: String = machine
        .audit_head()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    record_personal(
        &session,
        AuditDraft {
            actor: APP.to_owned(),
            tool: TOOL_SUMMARY.to_owned(),
            outcome: Outcome::Allowed,
            detail: Some(format!(
                "SUMMARY_ACKNOWLEDGED (entries {count} head {head})"
            )),
            ..AuditDraft::default()
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The person's decisions
// ---------------------------------------------------------------------------------------------

/// The key under which a copy records what its values came from: a personal environment's
/// last-changed stamp, or a shared environment's records by variable (ADR-0042 §13).
const COPIED_SOURCES: &str = "copied_sources";

/// What `copied_from` starts with for a copy from shared vault `vault`.
fn shared_prefix(vault: &kagisecure_core::proto::VaultId) -> String {
    let hex: String = vault
        .0
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("shared:{hex}:")
}

/// How a copy of shared environment `env` in shared vault `vault` is named in `copied_from`.
fn shared_source_key(vault: &kagisecure_core::proto::VaultId, env: &EnvId) -> String {
    format!("{}{env}", shared_prefix(vault))
}

/// When a personal environment's values last changed: the environment's own stamp, or a later
/// one of an item a variable is bound to.
fn personal_stamp(vault: &Vault, env: &Environment) -> u64 {
    env.vars
        .iter()
        .filter_map(|var| match &var.source {
            VarSource::ItemField { item, .. } => vault.item_by_id(item).map(|i| i.updated_at),
            _ => None,
        })
        .fold(env.updated_at, u64::max)
}

/// The machine environment copied from `source_key`, if there is one.
fn existing_copy(machine: &Vault, source_key: &str) -> Option<EnvId> {
    machine
        .environments()
        .iter()
        .find(|e| copied_from(e).as_deref() == Some(source_key))
        .map(|e| e.id)
}

/// One copy about to be written into the machine vault.
struct CopyPlan {
    /// The machine environment's id: the earlier copy's, or a new one.
    id: EnvId,
    /// What `copied_from` says.
    source_key: String,
    name: String,
    visible: bool,
    values: Vec<kagisecure_core::inject::EnvInjection>,
    /// What the values came from, for noticing a newer source.
    sources: ciborium::Value,
    detail: String,
}

/// Write `plan` into `machine`: a new copy or an earlier one brought up to date, re-approving the
/// grants over it, since the person has just confirmed the values (owner's answer 10).
fn write_copy(machine: &mut Vault, plan: &CopyPlan, now: u64) -> FfiResult<()> {
    let names: Vec<String> = plan
        .values
        .iter()
        .map(|v| v.name.as_str().to_owned())
        .collect();
    machine.transact(|tx| {
        let vault_id = tx.default_vault_id()?;
        tx.set_vault_agent_visible(vault_id, true);
        if !tx.environments().iter().any(|e| e.id == plan.id) {
            let mut env = Environment::new(vault_id, plan.name.clone());
            env.id = plan.id;
            tx.add_environment(env);
        }
        let env = tx.find_environment_mut(&plan.id.to_string())?;
        env.name.clone_from(&plan.name);
        env.agent_visible = plan.visible;
        env.unknown.insert(
            COPIED_FROM.to_owned(),
            ciborium::Value::Text(plan.source_key.clone()),
        );
        env.unknown
            .insert(COPIED_SOURCES.to_owned(), plan.sources.clone());
        env.vars.clear();
        for injection in &plan.values {
            env.set_var(
                VarName::new(injection.name.as_str().to_owned())?,
                VarSource::Literal(Secret::new(injection.value.expose().to_vec())),
            );
        }
        let stamp = env.updated_at.max(now);
        if let Ok(section) = tx.machine_mut() {
            for grant in section
                .command_grants
                .iter_mut()
                .filter(|g| g.env == plan.id)
            {
                grant.approved_at = stamp;
            }
        }
        tx.append_audit(AuditDraft {
            environment_id: Some(plan.id),
            variables: names.clone(),
            ..decision(plan.detail.clone())
        });
        Ok(())
    })?;
    Ok(())
}

/// Copy a personal environment's variables, as they are now, into the machine vault — or bring an
/// earlier copy up to date — after the app's presence proof. The values are resolved and written
/// inside Rust; none crosses. Updating a copy re-approves the grants over it (owner's answer 10),
/// since the person has just confirmed the change. Returns the machine environment's id.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked, the environment is not found or a variable has
/// no value, or a write fails.
#[uniffi::export]
pub fn unattended_copy_environment(
    session: Arc<VaultSession>,
    personal_environment_id: String,
    presence: UnattendedPresence,
) -> FfiResult<String> {
    let source: EnvId = parse(&personal_environment_id, "environment")?;
    let (name, visible, values, stamp) = session
        .handle()
        .with(|v| -> FfiResult<_> {
            let env = v
                .environments()
                .iter()
                .find(|e| e.id == source)
                .ok_or_else(|| FfiError::invalid("No such environment."))?;
            let values = v.resolve_environment(&source.to_string(), None)?;
            Ok((
                env.name.clone(),
                env.agent_visible,
                values,
                personal_stamp(v, env),
            ))
        })
        .ok_or_else(locked)??;
    let mut machine = ensure_machine(&session)?;
    let detail = format!(
        "ENVIRONMENT_COPIED ({} variables, {})",
        values.len(),
        presence_detail(presence)
    );
    let names: Vec<String> = values.iter().map(|v| v.name.as_str().to_owned()).collect();
    let plan = CopyPlan {
        id: existing_copy(&machine, &personal_environment_id).unwrap_or_default(),
        source_key: personal_environment_id,
        name,
        visible,
        values,
        sources: ciborium::Value::Integer(stamp.into()),
        detail: detail.clone(),
    };
    write_copy(&mut machine, &plan, unix_now())?;
    record_personal(
        &session,
        AuditDraft {
            environment_id: Some(source),
            variables: names,
            ..decision(detail)
        },
    );
    Ok(plan.id.to_string())
}

/// Copy a shared vault's environment into the machine vault — or bring an earlier copy up to date
/// — after the app's presence proof (ADR-0042 §13). Refused when an admin of the vault forbids
/// copies, and for a variable bound to a login's field: a shared login is never copied for
/// unattended use. Before anything is written, a record goes to the shared vault saying this
/// device holds the copy, described as `holder` ("Alice's MacBook"), so every member sees it.
/// Returns the machine environment's id.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked, copies are forbidden, the environment is not in
/// the shared vault or binds a login's field, a value is missing, or a write fails.
#[uniffi::export]
pub fn unattended_copy_shared_environment(
    session: Arc<VaultSession>,
    shared: Arc<crate::shared::SharedVaultSession>,
    environment_id: String,
    holder: String,
    presence: UnattendedPresence,
) -> FfiResult<String> {
    let source: EnvId = parse(&environment_id, "environment")?;
    if !shared.unattended_state()?.copies_allowed {
        return Err(FfiError::invalid(
            "An admin of this shared vault does not allow unattended copies of its values.",
        ));
    }
    let snapshot = shared.unattended_snapshot()?;
    let env = snapshot
        .environment(&source)
        .ok_or_else(|| FfiError::invalid("No such environment in this shared vault."))?;
    let login_bound = env.vars.iter().any(|var| match &var.source {
        VarSource::ItemField { item, .. } => snapshot
            .item(item)
            .is_some_and(|i| i.category == kagisecure_core::proto::Category::Login),
        _ => false,
    });
    if login_bound {
        return Err(FfiError::invalid(
            "A variable of this environment is a login's field. A shared login is never copied \
             for unattended use: give the job an account of its own.",
        ));
    }
    let names: Vec<String> = env.vars.iter().map(|v| v.name.clone()).collect();
    let values = snapshot.resolve_environment(&source, None)?;
    let sources = ciborium::Value::Map(
        snapshot
            .env_sources(&source, &names)
            .into_iter()
            .map(|(name, records)| {
                (
                    ciborium::Value::Text(name),
                    ciborium::Value::Array(
                        records
                            .iter()
                            .map(|r| ciborium::Value::Text(r.to_string()))
                            .collect(),
                    ),
                )
            })
            .collect(),
    );
    let source_key = shared_source_key(&shared.raw_vault_id(), &source);
    let mut machine = ensure_machine(&session)?;
    let id = existing_copy(&machine, &source_key).unwrap_or_default();
    let now = unix_now();
    // Tell the members first: a copy nobody was told about is the one thing this must not make.
    let note = kagisecure_shared::unattended::CopyNote {
        copy: id,
        source,
        name: env.name.clone(),
        variables: names.clone(),
        holder: holder.trim().chars().take(128).collect(),
        held: true,
    };
    shared.with_replica(|replica, device| {
        kagisecure_shared::unattended::record_copy(replica, device, &note, now)
            .map_err(crate::shared::shared_failure)
    })?;
    let detail = format!(
        "SHARED_ENVIRONMENT_COPIED ({} variables, {})",
        values.len(),
        presence_detail(presence)
    );
    let plan = CopyPlan {
        id,
        source_key,
        name: format!("{} ({})", env.name, snapshot.name()),
        visible: env.agent_visible,
        values,
        sources,
        detail: detail.clone(),
    };
    write_copy(&mut machine, &plan, now)?;
    record_personal(
        &session,
        AuditDraft {
            environment_id: Some(source),
            vault_id: Some(shared.raw_vault_id()),
            variables: names,
            ..decision(detail)
        },
    );
    Ok(id.to_string())
}

/// Remove a copy of a shared environment from the machine vault, telling the shared vault's
/// members this device no longer holds it. Asks for nothing.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or a write fails.
#[uniffi::export]
pub fn unattended_remove_shared_copy(
    session: Arc<VaultSession>,
    shared: Arc<crate::shared::SharedVaultSession>,
    environment_id: String,
    holder: String,
) -> FfiResult<bool> {
    let id: EnvId = parse(&environment_id, "environment")?;
    let Some(machine) = open_machine(&session)? else {
        return Ok(false);
    };
    let Some(env) = machine.environments().iter().find(|e| e.id == id) else {
        return Ok(false);
    };
    let prefix = shared_prefix(&shared.raw_vault_id());
    if let Some(source) = copied_from(env)
        .as_deref()
        .and_then(|key| key.strip_prefix(prefix.as_str()))
        .and_then(|rest| rest.parse::<EnvId>().ok())
    {
        let note = kagisecure_shared::unattended::CopyNote {
            copy: id,
            source,
            name: env.name.clone(),
            variables: env.vars.iter().map(|v| v.name.clone()).collect(),
            holder: holder.trim().chars().take(128).collect(),
            held: false,
        };
        shared.with_replica(|replica, device| {
            kagisecure_shared::unattended::record_copy(replica, device, &note, unix_now())
                .map_err(crate::shared::shared_failure)
        })?;
    }
    drop(machine);
    unattended_remove_environment(session, environment_id)
}

/// The machine environments whose source changed since they were copied — the personal
/// environment (or an item it binds) edited, or a newer version of a shared environment's value —
/// or whose source is gone. Their values are as copied: **Update** copies them again (owner's
/// decision: copies stay copies). A copy of a shared vault not among `shared` is not judged.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_stale_copies(
    session: Arc<VaultSession>,
    shared: Vec<Arc<crate::shared::SharedVaultSession>>,
) -> FfiResult<Vec<String>> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(Vec::new());
    };
    let mut stale = Vec::new();
    for env in machine.environments() {
        let Some(key) = copied_from(env) else {
            continue;
        };
        let recorded = env.unknown.get(COPIED_SOURCES);
        let changed = if let Some(rest) = key.strip_prefix("shared:") {
            let Some((vault, source)) = rest.split_once(':') else {
                continue;
            };
            let Some(vault_session) = shared
                .iter()
                .find(|s| shared_prefix(&s.raw_vault_id()) == format!("shared:{vault}:"))
            else {
                continue;
            };
            let Ok(source) = source.parse::<EnvId>() else {
                continue;
            };
            let Ok(snapshot) = vault_session.unattended_snapshot() else {
                continue;
            };
            let names: Vec<String> = env.vars.iter().map(|v| v.name.clone()).collect();
            if snapshot.environment(&source).is_none() {
                true
            } else {
                let now: Vec<(ciborium::Value, ciborium::Value)> = snapshot
                    .env_sources(&source, &names)
                    .into_iter()
                    .map(|(name, records)| {
                        (
                            ciborium::Value::Text(name),
                            ciborium::Value::Array(
                                records
                                    .iter()
                                    .map(|r| ciborium::Value::Text(r.to_string()))
                                    .collect(),
                            ),
                        )
                    })
                    .collect();
                recorded != Some(&ciborium::Value::Map(now))
            }
        } else {
            let Ok(source) = key.parse::<EnvId>() else {
                continue;
            };
            session
                .handle()
                .with(|v| {
                    v.environments()
                        .iter()
                        .find(|e| e.id == source)
                        .is_none_or(|e| {
                            recorded != Some(&ciborium::Value::Integer(personal_stamp(v, e).into()))
                        })
                })
                .ok_or_else(locked)?
        };
        if changed {
            stale.push(env.id.to_string());
        }
    }
    Ok(stale)
}

/// A device holding an unattended copy of a shared vault's environment (ADR-0042 §13), for the
/// members view and the rotation list.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedUnattendedCopyView {
    /// How the holder describes itself.
    pub holder: String,
    /// Whether the holder is still in the vault. A removed device keeps its copy: rotate the
    /// values at their service.
    pub holder_active: bool,
    /// The environment's name when copied.
    pub environment_name: String,
    /// The variable names copied.
    pub variables: Vec<String>,
    /// When the holder copied it, unix seconds.
    pub copied_at: u64,
}

/// Which devices hold unattended copies of this shared vault's values.
///
/// # Errors
///
/// [`FfiError`] when the shared vault is locked or damaged.
#[uniffi::export]
pub fn shared_unattended_copies(
    shared: Arc<crate::shared::SharedVaultSession>,
) -> FfiResult<Vec<SharedUnattendedCopyView>> {
    Ok(shared
        .unattended_state()?
        .copies
        .into_iter()
        .map(|c| SharedUnattendedCopyView {
            holder: c.holder,
            holder_active: c.holder_active,
            environment_name: c.name,
            variables: c.variables,
            copied_at: c.at,
        })
        .collect())
}

/// A shared vault's environment, as "Add an Environment…" offers it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedEnvironmentChoice {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Variable names.
    pub variable_names: Vec<String>,
    /// Whether a variable is a login's field: such an environment is never copied.
    pub login_bound: bool,
}

/// The environments of a shared vault that could be copied for unattended jobs, by name.
///
/// # Errors
///
/// [`FfiError`] when the shared vault is locked or damaged.
#[uniffi::export]
pub fn shared_environments_for_copy(
    shared: Arc<crate::shared::SharedVaultSession>,
) -> FfiResult<Vec<SharedEnvironmentChoice>> {
    let snapshot = shared.unattended_snapshot()?;
    let mut choices: Vec<SharedEnvironmentChoice> = snapshot
        .environments()
        .iter()
        .map(|env| SharedEnvironmentChoice {
            id: env.id.to_string(),
            name: env.name.clone(),
            variable_names: env.vars.iter().map(|v| v.name.clone()).collect(),
            login_bound: env.vars.iter().any(|var| match &var.source {
                VarSource::ItemField { item, .. } => snapshot
                    .item(item)
                    .is_some_and(|i| i.category == kagisecure_core::proto::Category::Login),
                _ => false,
            }),
        })
        .collect();
    choices.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(choices)
}

/// Whether members may copy this shared vault's values for unattended jobs. `true` unless an
/// admin said no.
///
/// # Errors
///
/// [`FfiError`] when the shared vault is locked or damaged.
#[uniffi::export]
pub fn shared_unattended_copies_allowed(
    shared: Arc<crate::shared::SharedVaultSession>,
) -> FfiResult<bool> {
    Ok(shared.unattended_state()?.copies_allowed)
}

/// Allow or forbid unattended copies of this shared vault's values, as an admin. Copies already
/// made stay where they are; the members view flags them.
///
/// # Errors
///
/// [`FfiError::Invalid`] when this device is not an admin, and when the write fails.
#[uniffi::export]
pub fn shared_set_unattended_copies_allowed(
    shared: Arc<crate::shared::SharedVaultSession>,
    allowed: bool,
) -> FfiResult<()> {
    if !shared.is_admin() {
        return Err(FfiError::invalid(
            "Only an admin of this shared vault can change this.",
        ));
    }
    shared.with_replica(|replica, device| {
        kagisecure_shared::unattended::set_copies_allowed(replica, device, allowed, unix_now())
            .map(|_| ())
            .map_err(crate::shared::shared_failure)
    })
}

/// Create a job and the command grant it runs under, in one step, after the app's presence proof.
/// Executables are pinned as they are now: by code-signing identity when they have a team, by
/// hash otherwise. Returns the job's id.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked, a path is not absolute or does not exist, the
/// environment is not in the machine vault, or the draft breaks a rule of the machine vault.
#[uniffi::export]
pub fn unattended_create_job(
    session: Arc<VaultSession>,
    draft: UnattendedJobDraft,
    presence: UnattendedPresence,
) -> FfiResult<String> {
    if !draft.program.starts_with('/') {
        return Err(FfiError::invalid("Choose the program by its full path."));
    }
    let command_path = draft
        .command
        .clone()
        .unwrap_or_else(|| draft.program.clone());
    if !command_path.starts_with('/') {
        return Err(FfiError::invalid("Choose the command by its full path."));
    }
    let env_id: Option<EnvId> = if draft.environment_id.is_empty() {
        None
    } else {
        Some(parse(&draft.environment_id, "environment")?)
    };
    if env_id.is_none() && draft.logins.is_empty() {
        return Err(FfiError::invalid(
            "Choose an environment for the job's command, or a login it signs in with.",
        ));
    }
    let working_dir = canonical_dir(&draft.working_dir)?;
    let schedule = draft
        .schedule
        .iter()
        .map(schedule_time)
        .collect::<FfiResult<Vec<_>>>()?;
    let pin = |path: &str| {
        pin_executable(path)
            .map_err(|_| FfiError::invalid(format!("Cannot read {path} to pin it.")))
    };
    let root = pin(&draft.program)?;
    let executable = pin(&command_path)?;
    let run_browser = if draft.logins.is_empty() {
        None
    } else {
        let path = draft
            .run_browser
            .clone()
            .or_else(crate::unattended_logins::unattended_default_run_browser)
            .ok_or_else(|| {
                FfiError::invalid(
                    "A job that signs in needs its own browser: install Microsoft Edge, or \
                     choose a Chromium-family browser that loads the kagisecure extension.",
                )
            })?;
        if !path.starts_with('/') {
            return Err(FfiError::invalid("Choose the browser by its full path."));
        }
        Some(pin(&path)?)
    };
    let lifetime = match u64::from(draft.expires_in_days) * 24 * 60 * 60 {
        0 => DEFAULT_GRANT_LIFETIME_SECS,
        n => n.min(MAX_GRANT_LIFETIME_SECS),
    };
    let mut machine = open_machine(&session)?
        .ok_or_else(|| FfiError::invalid("This vault has no machine vault."))?;
    let now = unix_now();
    let job = Job {
        id: JobId::new(),
        name: draft.name.trim().to_owned(),
        root,
        args: draft.arguments.clone(),
        working_dir: working_dir.clone(),
        schedule,
        run_deadline_secs: DEFAULT_RUN_DEADLINE_SECS,
        catch_up_secs: 0,
        run_browser,
        created_at: now,
        presence: presence_path(presence),
        unknown: BTreeMap::new(),
    };
    let job_id = job.id;
    let limits = GrantLimits {
        per_run: DEFAULT_PER_RUN,
        total_uses: DEFAULT_TOTAL_USES,
        expires_at: now + lifetime,
    };
    let logins = crate::unattended_logins::login_grants(
        &machine,
        job_id,
        &draft.logins,
        limits,
        now,
        presence_path(presence),
    )?;
    let detail = format!(
        "JOB_CREATED (job {:?}, {})",
        job.name,
        presence_detail(presence)
    );
    machine.transact(|tx| {
        let section = tx.machine_mut()?;
        section.jobs.push(job.clone());
        section.login_grants.extend(logins.iter().cloned());
        for login in &logins {
            tx.append_audit(AuditDraft {
                item_id: Some(login.item),
                variables: vec![login.origin.clone()],
                ..decision(format!(
                    "LOGIN_GRANT_CREATED (job {:?}, {}{})",
                    job.name,
                    presence_detail(presence),
                    if login.one_time_codes {
                        ", ONE_TIME_CODES"
                    } else {
                        ""
                    }
                ))
            });
        }
        let Some(env_id) = env_id else {
            tx.append_audit(AuditDraft {
                target_path: Some(working_dir.clone()),
                ..decision(detail.clone())
            });
            return Ok(());
        };
        let env = tx
            .environments()
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(kagisecure_core::Error::EnvNotFound(env_id.to_string()))?;
        let variables: Vec<String> = if draft.variables.is_empty() {
            env.vars.iter().map(|v| v.name.clone()).collect()
        } else {
            draft.variables.clone()
        };
        let stamp = env.updated_at.max(now);
        let grant = CommandGrant {
            id: GrantId::new(),
            job: job_id,
            env: env_id,
            variables: variables.clone(),
            executable,
            args: draft
                .command_arguments
                .clone()
                .unwrap_or_else(|| draft.arguments.clone()),
            working_dir: working_dir.clone(),
            pinned_inputs: Vec::new(),
            timeout_secs: DEFAULT_RUN_DEADLINE_SECS,
            limits,
            uses: 0,
            created_at: now,
            approved_at: stamp,
            presence: presence_path(presence),
            suspended: None,
            unknown: BTreeMap::new(),
        };
        tx.machine_mut()?.command_grants.push(grant);
        tx.append_audit(AuditDraft {
            environment_id: Some(env_id),
            variables,
            target_path: Some(working_dir.clone()),
            ..decision(detail.clone())
        });
        Ok(())
    })?;
    record_personal(&session, decision(detail));
    Ok(job_id.to_string())
}

/// Revoke a job: remove it and every grant of it. Asks for nothing — narrowing is always allowed.
/// A run of it in progress is not ended here; its next request finds no grant.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the write fails.
#[uniffi::export]
pub fn unattended_revoke_job(session: Arc<VaultSession>, job_id: String) -> FfiResult<bool> {
    let id: JobId = parse(&job_id, "job")?;
    let Some(mut machine) = open_machine(&session)? else {
        return Ok(false);
    };
    let removed = machine.transact(|tx| {
        let removed = tx.machine_mut()?.remove_job(id);
        if let Some(job) = &removed {
            tx.append_audit(decision(format!("JOB_REVOKED (job {:?})", job.name)));
        }
        Ok(removed.map(|j| j.name))
    })?;
    if let Some(name) = &removed {
        record_personal(&session, decision(format!("JOB_REVOKED (job {name:?})")));
    }
    Ok(removed.is_some())
}

/// Re-enable a suspended grant after the app's presence proof: the suspension is cleared and what
/// it releases counts as approved now (ADR-0042 implementation decision 23).
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the write fails.
#[uniffi::export]
pub fn unattended_reenable_grant(
    session: Arc<VaultSession>,
    grant_id: String,
    presence: UnattendedPresence,
) -> FfiResult<bool> {
    let id: GrantId = parse(&grant_id, "grant")?;
    let Some(mut machine) = open_machine(&session)? else {
        return Ok(false);
    };
    let now = unix_now();
    let detail = format!(
        "GRANT_REENABLED (grant {id}, {})",
        presence_detail(presence)
    );
    let done = machine.transact(|tx| {
        let section = tx.machine_mut()?;
        if let Some(grant) = section
            .command_grants
            .iter_mut()
            .find(|g| g.id == id && g.suspended.is_some())
        {
            grant.suspended = None;
            grant.approved_at = now;
            grant.presence = presence_path(presence);
        } else if let Some(grant) = section
            .login_grants
            .iter_mut()
            .find(|g| g.id == id && g.suspended.is_some())
        {
            grant.suspended = None;
            grant.approved_at = now;
            grant.presence = presence_path(presence);
        } else {
            return Ok(false);
        }
        tx.append_audit(decision(detail.clone()));
        Ok(true)
    })?;
    if done {
        record_personal(&session, decision(detail));
    }
    Ok(done)
}

/// Remove an environment from the machine vault, with every job whose grant uses it. Asks for
/// nothing.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the write fails.
#[uniffi::export]
pub fn unattended_remove_environment(
    session: Arc<VaultSession>,
    environment_id: String,
) -> FfiResult<bool> {
    let id: EnvId = parse(&environment_id, "environment")?;
    let Some(mut machine) = open_machine(&session)? else {
        return Ok(false);
    };
    let removed = machine.transact(|tx| {
        if !tx.environments().iter().any(|e| e.id == id) {
            return Ok(false);
        }
        let section = tx.machine_mut()?;
        let jobs: Vec<JobId> = section
            .command_grants
            .iter()
            .filter(|g| g.env == id)
            .map(|g| g.job)
            .collect();
        for job in jobs {
            section.remove_job(job);
        }
        tx.remove_environment(&id.to_string())?;
        tx.append_audit(decision(format!("ENVIRONMENT_REMOVED ({id})")));
        Ok(true)
    })?;
    if removed {
        record_personal(&session, decision(format!("ENVIRONMENT_REMOVED ({id})")));
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tool: &str, detail: &str, outcome: &str) -> AuditRowView {
        AuditRowView {
            seq: 0,
            timestamp: 0,
            actor: "unattended".to_owned(),
            tool: tool.to_owned(),
            outcome: outcome.to_owned(),
            environment_id: None,
            item_id: None,
            variables: Vec::new(),
            target_path: None,
            detail: Some(detail.to_owned()),
        }
    }

    #[test]
    fn the_acknowledgement_is_read_back_from_the_personal_log() {
        let entries = vec![
            entry(
                TOOL_SUMMARY,
                "SUMMARY_ACKNOWLEDGED (entries 3 head 00)",
                "allowed",
            ),
            entry("run_with_env", "x", "allowed"),
            entry(
                TOOL_SUMMARY,
                "SUMMARY_ACKNOWLEDGED (entries 7 head ab)",
                "allowed",
            ),
        ];
        assert_eq!(acknowledged_count(&entries), 7);
        assert_eq!(acknowledged_count(&[]), 0);
    }

    #[test]
    fn the_summary_counts_what_happened_since() {
        let entries = vec![
            entry("unattended_job", "JOB_STARTED (run 1)", "allowed"),
            entry("run_with_env", "UNATTENDED_GRANT g RUN 1", "allowed"),
            entry("run_with_env", "NOT_GRANTED (NO_GRANT)", "denied"),
            entry("unattended_grant", "GRANT_SUSPENDED (NO_GRANT)", "denied"),
            entry("unattended_job", "JOB_STARTED (run 2)", "allowed"),
        ];
        let all = summarize(&entries, 0);
        assert_eq!(
            (
                all.total,
                all.runs,
                all.releases,
                all.refusals,
                all.suspensions
            ),
            (5, 2, 1, 1, 1)
        );
        assert_eq!(all.rows[0].detail.as_deref(), Some("JOB_STARTED (run 2)"));
        let mut with_decision = entries.clone();
        with_decision.push(AuditRowView {
            actor: APP.to_owned(),
            ..entry(TOOL_DECISION, "JOB_CREATED (job \"x\")", "allowed")
        });
        assert_eq!(
            summarize(&with_decision, 0).total,
            5,
            "the person's own decisions are not news"
        );
        let later = summarize(&entries, 4);
        assert_eq!((later.total, later.runs), (1, 1));
        assert_eq!(summarize(&entries, 9).total, 0);
    }

    #[test]
    fn times_round_trip() {
        for view in [
            UnattendedTimeView {
                weekday: None,
                hour: 2,
                minute: 30,
            },
            UnattendedTimeView {
                weekday: Some(6),
                hour: 23,
                minute: 59,
            },
        ] {
            assert_eq!(time_view(&schedule_time(&view).unwrap()), view);
        }
        assert!(
            schedule_time(&UnattendedTimeView {
                weekday: Some(7),
                hour: 0,
                minute: 0
            })
            .is_err()
        );
    }
}

#[cfg(test)]
mod shared_copy_tests {
    use super::*;
    use kagisecure_core::model::{Field, Item};
    use kagisecure_core::proto::Category;

    const VALUE: &str = "shared-copy-canary-9c2d";

    struct Setup {
        _dir: tempfile::TempDir,
        personal: Arc<VaultSession>,
        shared: Arc<crate::shared::SharedVaultSession>,
        env: EnvId,
        login_env: EnvId,
        token: (
            kagisecure_core::proto::ItemId,
            kagisecure_core::proto::FieldId,
        ),
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let personal = VaultSession::create(
            dir.path()
                .join("p.kagivault")
                .to_string_lossy()
                .into_owned(),
            "pw".to_owned(),
            "Personal".to_owned(),
            Some(64),
            Some(1),
        )
        .unwrap();
        let shared = personal
            .create_shared_vault("Ops".to_owned(), None)
            .unwrap();
        let vault_id = shared.raw_vault_id();
        let mut token = Item::new(vault_id, Category::ApiCredential, "Deploy token");
        token.fields.push(Field::concealed(
            "token",
            Secret::from_string(VALUE.to_owned()),
        ));
        let mut login = Item::new(vault_id, Category::Login, "Service login");
        login.fields.push(Field::concealed(
            "password",
            Secret::from_string("pw".to_owned()),
        ));
        let mut env = Environment::new(vault_id, "deploy");
        env.set_var(
            VarName::new("TOKEN".to_owned()).unwrap(),
            VarSource::ItemField {
                item: token.id,
                field: token.fields[0].id,
            },
        );
        let mut login_env = Environment::new(vault_id, "sign in");
        login_env.set_var(
            VarName::new("PASSWORD".to_owned()).unwrap(),
            VarSource::ItemField {
                item: login.id,
                field: login.fields[0].id,
            },
        );
        let (env_id, login_env_id) = (env.id, login_env.id);
        let token_ids = (token.id, token.fields[0].id);
        shared
            .with_replica(|replica, device| {
                let now = unix_now();
                let fail = crate::shared::shared_failure;
                kagisecure_shared::write::put_item(replica, device, token, now).map_err(fail)?;
                kagisecure_shared::write::put_item(replica, device, login, now).map_err(fail)?;
                kagisecure_shared::write::put_env(replica, device, env, now).map_err(fail)?;
                kagisecure_shared::write::put_env(replica, device, login_env, now).map_err(fail)?;
                Ok(())
            })
            .unwrap();
        Setup {
            _dir: dir,
            personal,
            shared,
            env: env_id,
            login_env: login_env_id,
            token: token_ids,
        }
    }

    #[test]
    fn a_shared_copy_is_announced_noticed_when_stale_updated_and_removed() {
        let s = setup();
        let copy = unattended_copy_shared_environment(
            s.personal.clone(),
            s.shared.clone(),
            s.env.to_string(),
            "Test Mac".to_owned(),
            UnattendedPresence::Confirmed,
        )
        .unwrap();

        // Every member reads that this device holds a copy.
        let copies = shared_unattended_copies(s.shared.clone()).unwrap();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].holder, "Test Mac");
        assert_eq!(copies[0].variables, ["TOKEN"]);
        assert!(copies[0].holder_active);

        let overview = unattended_overview(s.personal.clone()).unwrap();
        assert_eq!(overview.environments.len(), 1);
        assert_eq!(overview.environments[0].id, copy);
        assert_eq!(overview.environments[0].name, "deploy (Ops)");
        assert!(
            overview.environments[0]
                .copied_from
                .as_deref()
                .is_some_and(|k| k.starts_with("shared:"))
        );
        let shared_list = vec![s.shared.clone()];
        assert!(
            unattended_stale_copies(s.personal.clone(), shared_list.clone())
                .unwrap()
                .is_empty()
        );

        // Another version of the bound value: the copy is stale, and keeps its value until Update.
        let mut changed = Item::new(
            s.shared.raw_vault_id(),
            Category::ApiCredential,
            "Deploy token",
        );
        changed.id = s.token.0;
        let mut field = Field::concealed("token", Secret::from_string("rotated".to_owned()));
        field.id = s.token.1;
        changed.fields.push(field);
        s.shared
            .with_replica(|replica, device| {
                kagisecure_shared::write::put_item(replica, device, changed, unix_now())
                    .map_err(crate::shared::shared_failure)
            })
            .unwrap();
        assert_eq!(
            unattended_stale_copies(s.personal.clone(), shared_list.clone()).unwrap(),
            std::slice::from_ref(&copy)
        );
        let again = unattended_copy_shared_environment(
            s.personal.clone(),
            s.shared.clone(),
            s.env.to_string(),
            "Test Mac".to_owned(),
            UnattendedPresence::Confirmed,
        )
        .unwrap();
        assert_eq!(again, copy, "Update brings the same copy up to date");
        assert!(
            unattended_stale_copies(s.personal.clone(), shared_list)
                .unwrap()
                .is_empty()
        );

        // A shared login is never copied.
        assert!(
            unattended_copy_shared_environment(
                s.personal.clone(),
                s.shared.clone(),
                s.login_env.to_string(),
                "Test Mac".to_owned(),
                UnattendedPresence::Confirmed,
            )
            .is_err()
        );

        // Removing the copy tells the members.
        assert!(
            unattended_remove_shared_copy(
                s.personal.clone(),
                s.shared.clone(),
                copy,
                "Test Mac".to_owned()
            )
            .unwrap()
        );
        assert!(
            shared_unattended_copies(s.shared.clone())
                .unwrap()
                .is_empty()
        );
        assert!(
            unattended_overview(s.personal.clone())
                .unwrap()
                .environments
                .is_empty()
        );
    }

    #[test]
    fn an_admin_can_forbid_copies() {
        let s = setup();
        assert!(shared_unattended_copies_allowed(s.shared.clone()).unwrap());
        shared_set_unattended_copies_allowed(s.shared.clone(), false).unwrap();
        assert!(!shared_unattended_copies_allowed(s.shared.clone()).unwrap());
        assert!(
            unattended_copy_shared_environment(
                s.personal.clone(),
                s.shared.clone(),
                s.env.to_string(),
                "Test Mac".to_owned(),
                UnattendedPresence::Confirmed,
            )
            .is_err()
        );
        assert!(
            unattended_overview(s.personal.clone())
                .unwrap()
                .environments
                .is_empty(),
            "nothing was copied"
        );
    }

    #[test]
    fn a_personal_copy_is_stale_after_its_source_changes() {
        let s = setup();
        let env = s
            .personal
            .create_environment("local".to_owned(), None)
            .unwrap();
        s.personal
            .set_variable_value(env.id.clone(), "A".to_owned(), "one".to_owned())
            .unwrap();
        let copy = unattended_copy_environment(
            s.personal.clone(),
            env.id.clone(),
            UnattendedPresence::Confirmed,
        )
        .unwrap();
        assert!(
            unattended_stale_copies(s.personal.clone(), Vec::new())
                .unwrap()
                .is_empty()
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        s.personal
            .set_variable_value(env.id, "A".to_owned(), "two".to_owned())
            .unwrap();
        assert_eq!(
            unattended_stale_copies(s.personal.clone(), Vec::new()).unwrap(),
            [copy]
        );
    }
}
