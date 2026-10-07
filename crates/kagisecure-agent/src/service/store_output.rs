//! `store_command_output` (ADR-0049): run a command the agent names, after the person approves it
//! with a sheet and Touch ID, and store its standard output in a concealed field — never returning
//! that output to the agent.
//!
//! The shape: validate → resolve the target (only somewhere empty, §2) → for a stdin environment,
//! its names and values present → the audit pre-flight → the sheet → `audited_release` records the
//! run before the child starts and releases the stdin values, if any → the child, through
//! `run_with_env`'s machinery (process group, deadline, kill on lock) → the output's rules (§6) →
//! one transaction that re-checks the target, writes the field and appends the `STORED` entry.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::{
    Delivery as InjectDelivery, EnvInjection, RunOutcome, RunRequest, mask, run_with_env_tracked,
};
use kagisecure_core::model::{Field, FieldKind, Item, Secret};
use kagisecure_core::proto::{Category, ItemId, Outcome, VaultId};
use kagisecure_core::vault::Tx;
use kagisecure_ipc::protocol::{
    ErrorCode, MAX_RUN_ARGS, MAX_STORE_REASON_CHARS, MAX_STORED_FIELD_LABEL_CHARS,
    MAX_STORED_ITEM_TITLE_CHARS, MAX_STORED_OUTPUT_BYTES, NotStoredReason, Response,
    STORE_OUTPUT_CATEGORIES, StdinEnvironment, StoreStatus, StoreTarget, clamp_run_timeout,
    display_text_ok,
};
use kagisecure_ipc::server::Connection;

use super::{
    NO_SUCH_ENVIRONMENT, NO_SUCH_ITEM, NO_SUCH_VAULT, Refusal, SHARED_IS_READ_ONLY, Selected,
    Service, canonical_dir, denied_reply, human_path, still_canonical,
};
use crate::approval::{ApprovalRequest, StoreOutputFacts};
use crate::catalog::{Catalog, Place};
use crate::extension::agent_fill;
use crate::release::{Acted, NotReleased, Released, audited_release};
use crate::vault::REQUEST_LOCK_TIMEOUT;

const TOOL: &str = "store_command_output";

/// The `Allowed` entry's detail prefix, before the argv (ADR-0049 §4).
const DETAIL_RUN: &str = "STORE_OUTPUT";
/// The detail of the entry committed with the write.
const DETAIL_STORED: &str = "STORED";
/// The detail prefix of the entry for output that was not stored, before the reason token.
const DETAIL_NOT_STORED: &str = "NOT_STORED";

const INVALID_STORE: &str = "store_command_output needs exactly one of item_id and new_item; a \
     field_label of 1-64 characters on one line; a new item title of 1-128 characters on one line \
     and a category of api-credential, password, server or database; a reason of at most 200 \
     characters on one line; and at most 64 arguments. Nothing was asked or run. Fix the argument \
     and retry.";

const FIELD_TAKEN: &str = "That item already has a field with this label that holds a value, or \
     that is not concealed. store_command_output never replaces a value. Nothing was asked or run. \
     Choose another field_label, or create a new item with new_item.";

const PRIMARY_REFUSED: &str = "That field would be the password kagisecure fills on the item's \
     websites, and store_command_output never writes it. Nothing was asked or run. Choose another \
     field_label, or create a new item with new_item.";

const ARCHIVED: &str = "That item is archived. Nothing was asked or run. Ask the user to restore \
     it, or create a new item with new_item.";

const NOT_ON_THIS_PLATFORM: &str = "store_command_output is not offered on this platform yet. \
     Nothing was asked or run.";

const CHANGED_IN_FLIGHT: &str = "The item changed while this request was waiting for approval, \
     and the field can no longer be written without replacing a value. Nothing was stored. Call \
     describe_item and retry.";

/// What the sidecar sends, borrowed.
pub(crate) struct StoreArgs<'a> {
    pub command: &'a str,
    pub args: &'a [String],
    pub cwd: &'a str,
    pub timeout_seconds: u64,
    pub target: &'a StoreTarget,
    pub field_label: &'a str,
    pub stdin_environment: Option<&'a StdinEnvironment>,
    pub reason: Option<&'a str>,
}

/// Where the output goes, resolved and checked (ADR-0049 §2).
#[derive(Clone, Debug)]
enum Plan {
    /// A new item in `vault_id`.
    NewItem {
        vault_id: VaultId,
        vault_name: String,
        title: String,
        category: Category,
    },
    /// An existing personal item: a new field, or the empty concealed field `label` names.
    Existing {
        item_id: ItemId,
        vault_id: VaultId,
        vault_name: String,
        title: String,
        fills_empty: bool,
    },
}

impl Plan {
    fn item_id(&self) -> Option<ItemId> {
        match self {
            Self::NewItem { .. } => None,
            Self::Existing { item_id, .. } => Some(*item_id),
        }
    }

    fn vault_id(&self) -> VaultId {
        match self {
            Self::NewItem { vault_id, .. } | Self::Existing { vault_id, .. } => *vault_id,
        }
    }
}

/// What the child produced, as the release's act hands it back.
enum Child {
    /// It ran — to its end, its deadline, or until a lock ended it.
    Ran {
        outcome: RunOutcome,
        /// The captured standard output, in a zeroizing buffer, unmasked.
        stdout: Secret,
        killed_on_lock: bool,
    },
    /// The vault locked between the release and the spawn.
    NotStarted,
    /// It could not be started.
    Failed(kagisecure_core::Error),
}

impl Service {
    /// `store_command_output` (ADR-0049). See the module documentation.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn store_command_output(
        &self,
        args: &StoreArgs<'_>,
        connection: &Connection,
    ) -> Response {
        // The Windows app has no sheet for this kind (ADR-0049 §7).
        if cfg!(windows) {
            return Response::error(ErrorCode::InvalidArgument, NOT_ON_THIS_PLATFORM);
        }
        if !valid(args) {
            return Response::error(ErrorCode::InvalidArgument, INVALID_STORE);
        }
        let timeout_seconds = clamp_run_timeout(args.timeout_seconds);
        let actor = agent_fill::actor_for(connection.identity());
        let entry = |outcome: Outcome, detail: String, item_id: Option<ItemId>| AuditDraft {
            actor: actor.clone(),
            client_pid: connection.identity().pid,
            tool: TOOL.to_owned(),
            item_id,
            outcome,
            detail: Some(detail),
            ..AuditDraft::default()
        };

        // The target, before anyone is asked: a request that cannot be written is refused here.
        let plan = match self.read_catalog(|catalog| resolve(catalog, args)) {
            Err(response) | Ok(Err(response)) => return response,
            Ok(Ok(plan)) => plan,
        };

        // The stdin environment's names, all with a value (ADR-0047's rule, ADR-0049 §5).
        let stdin = match args.stdin_environment {
            None => None,
            Some(env) => {
                let selected = match self
                    .selected_names(env.environment_id, env.variables.as_deref())
                {
                    Ok(Some(selected)) => selected,
                    Ok(None) => return Response::error(ErrorCode::NotFound, NO_SUCH_ENVIRONMENT),
                    Err(response) => return response,
                };
                match self.unpopulated(env.environment_id, &selected.names) {
                    Ok(missing) if missing.is_empty() => {}
                    Ok(missing) => {
                        return Response::error(
                            ErrorCode::NotPopulated,
                            format!(
                                "These variables have no value yet: {}. Nothing was asked or run. \
                                 Ask the user to enter them in kagisecure, then call again.",
                                missing.join(", ")
                            ),
                        );
                    }
                    Err(response) => return response,
                }
                Some((env.environment_id, selected))
            }
        };

        let canonical = match canonical_dir(args.cwd) {
            Ok(p) => p,
            Err(message) => return Response::error(ErrorCode::InvalidPath, message),
        };
        let mut argv = vec![args.command.to_owned()];
        argv.extend(args.args.iter().cloned());

        let names: Vec<String> = stdin
            .as_ref()
            .map(|(_, s)| s.names.clone())
            .unwrap_or_default();
        let environment_id = stdin.as_ref().map(|(id, _)| *id);
        let run_entry = AuditDraft {
            vault_id: Some(plan.vault_id()),
            environment_id,
            variables: names.clone(),
            target_path: Some(human_path(&canonical)),
            ..entry(
                Outcome::Allowed,
                format!("{DETAIL_RUN} {argv:?}"),
                plan.item_id(),
            )
        };

        // Never ask a question whose answer could not be recorded (ADR-0040).
        if let Err(response) = self.audit_preflight(&run_entry) {
            return response;
        }
        let (item_title, item_id, new_item_category, vault_name, fills_empty_field) = match &plan {
            Plan::NewItem {
                vault_name,
                title,
                category,
                ..
            } => (
                title.clone(),
                None,
                Some(category.as_str().to_owned()),
                vault_name.clone(),
                false,
            ),
            Plan::Existing {
                item_id,
                vault_name,
                title,
                fills_empty,
                ..
            } => (
                title.clone(),
                Some(item_id.to_string()),
                None,
                vault_name.clone(),
                *fills_empty,
            ),
        };
        let mut sheet = ApprovalRequest::for_store_output(
            StoreOutputFacts {
                agent: actor.clone(),
                item_title,
                item_id,
                new_item_category,
                vault_name,
                field_label: args.field_label.to_owned(),
                fills_empty_field,
                timeout_seconds,
                reason: args.reason.map(str::to_owned),
            },
            argv.clone(),
            human_path(&canonical),
            connection.identity(),
        );
        if let Some((
            id,
            Selected {
                env_name, shared, ..
            },
        )) = &stdin
        {
            sheet.environment_id = Some(id.to_string());
            sheet.environment_name = Some(env_name.clone());
            sheet.variables.clone_from(&names);
            sheet.stdin_delivery = true;
            sheet.shared_source = shared.as_ref().map(|s| s.source.clone());
            sheet.changed_since_approval = shared
                .as_ref()
                .map(|s| s.changes.clone())
                .unwrap_or_default();
        }
        let approved = self.ask(sheet);
        if !approved.granted {
            self.record_best_effort(AuditDraft {
                environment_id,
                variables: names,
                ..entry(
                    Outcome::Denied,
                    approved.code.as_str().to_owned(),
                    plan.item_id(),
                )
            });
            return denied_reply(approved.code);
        }
        if let Some((
            _,
            Selected {
                shared: Some(shared),
                ..
            },
        )) = &stdin
        {
            shared.record_approved(&self.handle);
        }

        // The run: recorded before the child starts, with the stdin values released by the same
        // transaction that records it.
        let entry_template = run_entry.clone();
        let act = {
            let children = Arc::clone(&self.children);
            let gate = self.gate();
            let program = OsString::from(args.command);
            let os_args: Vec<OsString> = args.args.iter().map(OsString::from).collect();
            let canonical: PathBuf = canonical.clone();
            let delivery = if stdin.is_some() {
                InjectDelivery::Stdin
            } else {
                InjectDelivery::Environment
            };
            move |injections: Vec<EnvInjection>, entry_seq: u64| {
                if !gate.is_serving() {
                    return Acted::abnormal("LOCKED_BEFORE_START", Child::NotStarted);
                }
                if !still_canonical(&canonical) {
                    return Acted::abnormal(
                        "INVALID_PATH",
                        Child::Failed(kagisecure_core::Error::InvalidPath(canonical)),
                    );
                }
                let killed_on_lock = std::cell::Cell::new(false);
                let child_id = std::cell::Cell::new(None);
                let ran = run_with_env_tracked(
                    &RunRequest {
                        program: &program,
                        args: &os_args,
                        env: &injections,
                        delivery,
                        cwd: Some(&canonical),
                        // Standard output is the value: never masked. Standard error is scrubbed
                        // below, once the output is known too.
                        mask_output: false,
                        // One byte over the cap (plus a CRLF) is enough to tell "too large".
                        max_output: MAX_STORED_OUTPUT_BYTES + 3,
                        timeout: Some(Duration::from_secs(timeout_seconds)),
                        new_process_group: true,
                    },
                    |kill| match children.register(kill, entry_template.clone(), entry_seq) {
                        Ok(id) => child_id.set(Some(id)),
                        Err(crate::children::RegistryClosed) => killed_on_lock.set(true),
                    },
                );
                if let Some(id) = child_id.into_inner() {
                    children.deregister(id);
                }
                match ran {
                    Ok(mut outcome) => {
                        let stdout = Secret::new(std::mem::take(&mut outcome.stdout));
                        // Best effort, as in `run_with_env`: the injected values, and the output
                        // itself, are taken out of what goes back to the agent.
                        let _ = mask(&mut outcome.stderr, &injections);
                        redact(&mut outcome.stderr, stdout.expose());
                        let killed = killed_on_lock.get();
                        let abnormal = if killed {
                            Some("KILLED_ON_LOCK")
                        } else if outcome.timed_out {
                            Some("TIMED_OUT")
                        } else {
                            None
                        };
                        let child = Child::Ran {
                            outcome,
                            stdout,
                            killed_on_lock: killed,
                        };
                        match abnormal {
                            Some(code) => Acted::abnormal(code, child),
                            None => Acted::done(child),
                        }
                    }
                    Err(e) => {
                        let code = match &e {
                            kagisecure_core::Error::Spawn { .. }
                            | kagisecure_core::Error::NonUtf8EnvValue(_)
                            | kagisecure_core::Error::UnsendableOnStdin(_) => "SPAWN_FAILED",
                            _ => "RUN_FAILED",
                        };
                        Acted::abnormal(code, Child::Failed(e))
                    }
                }
            }
        };
        let released = audited_release(
            &self.handle,
            REQUEST_LOCK_TIMEOUT,
            run_entry,
            |tx| match environment_id {
                Some(id) => self.prepare_release(tx, id, &names),
                None if self
                    .lock_requested
                    .load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    Err(Refusal::Locked)
                }
                None => Ok(Vec::new()),
            },
            act,
        );
        let (outcome, stdout, killed_on_lock) = match released {
            Err(NotReleased::Locked | NotReleased::Refused(Refusal::Locked)) => {
                return Self::locked();
            }
            Err(NotReleased::Refused(Refusal::Vault(e))) => {
                return self.failed(
                    TOOL,
                    super::error_code_for(&e),
                    environment_id,
                    names,
                    &e,
                    connection,
                );
            }
            Err(NotReleased::AuditUnavailable(_)) => return Self::audit_unavailable(),
            Ok(Released {
                value: Child::NotStarted,
                ..
            }) => return Self::locked(),
            // Recorded already: the `Failed` entry naming the `Allowed` one.
            Ok(Released {
                value: Child::Failed(e),
                ..
            }) => return Response::error(super::error_code_for(&e), super::agent_message(&e)),
            Ok(Released {
                value:
                    Child::Ran {
                        outcome,
                        stdout,
                        killed_on_lock,
                    },
                ..
            }) => (outcome, stdout, killed_on_lock),
        };
        // A lock while the child ran ended it; the caller is told so, not about its output.
        if !self.is_serving() {
            return Self::locked();
        }

        let not_stored = |reason: NotStoredReason, outcome: &RunOutcome| {
            self.record_best_effort(entry(
                Outcome::Failed,
                format!("{DETAIL_NOT_STORED} {}", reason.as_str()),
                plan.item_id(),
            ));
            Response::StoredCommandOutput {
                status: StoreStatus::NotStored,
                reason: Some(reason),
                item_id: None,
                field_label: args.field_label.to_owned(),
                item_created: false,
                exit_code: outcome.exit_code,
                stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
                stderr_truncated: outcome.stderr_truncated,
            }
        };
        let value = match checked_output(&outcome, &stdout, killed_on_lock) {
            Err(reason) => return not_stored(reason, &outcome),
            Ok(value) => value,
        };
        drop(stdout);

        // The write, with its entry, re-checking the target on the file as it is now: the sheet
        // may have been up for a minute.
        let refused = std::cell::Cell::new(None::<Response>);
        let field_label = args.field_label;
        let committed = self.handle.transact(REQUEST_LOCK_TIMEOUT, |tx| {
            let written = match &plan {
                Plan::NewItem {
                    vault_id,
                    title,
                    category,
                    ..
                } => {
                    if !Self::visible_vaults(tx).contains(vault_id) {
                        refused.set(Some(Response::error(ErrorCode::NotFound, NO_SUCH_VAULT)));
                        return Err(kagisecure_core::Error::TransactionAborted);
                    }
                    let mut item = Item::new(*vault_id, category.clone(), title.clone());
                    let field = Field::concealed(field_label, value);
                    item.primary_secret = Some(field.id);
                    item.fields.push(field);
                    // Made by an approved agent request: visible to agents, whatever the vault's
                    // default, so the agent can bind the field next (ADR-0049 §2).
                    item.set_agent_visible_all(true);
                    let id = item.id;
                    tx.add_item(item);
                    (id, true)
                }
                Plan::Existing { item_id, .. } => {
                    match write_existing(tx, *item_id, field_label, value) {
                        Ok(()) => (*item_id, false),
                        Err(reply) => {
                            refused.set(Some(reply));
                            return Err(kagisecure_core::Error::TransactionAborted);
                        }
                    }
                }
            };
            // In the same transaction as the write: both are written, or neither (ADR-0039).
            tx.append_audit(AuditDraft {
                vault_id: Some(plan.vault_id()),
                ..entry(Outcome::Allowed, DETAIL_STORED.to_owned(), Some(written.0))
            });
            Ok(written)
        });
        match committed {
            None => Self::locked(),
            Some(Ok((item_id, item_created))) => Response::StoredCommandOutput {
                status: StoreStatus::Stored,
                reason: None,
                item_id: Some(item_id),
                field_label: args.field_label.to_owned(),
                item_created,
                exit_code: outcome.exit_code,
                stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
                stderr_truncated: outcome.stderr_truncated,
            },
            Some(Err(e)) => {
                if let Some(reply) = refused.take() {
                    self.record_best_effort(entry(
                        Outcome::Failed,
                        format!("{DETAIL_NOT_STORED} target_changed"),
                        plan.item_id(),
                    ));
                    return reply;
                }
                let (code, response) = Self::write_failed(&e);
                self.record_best_effort(entry(
                    Outcome::Failed,
                    format!("{DETAIL_NOT_STORED} {}", code.as_str()),
                    plan.item_id(),
                ));
                response
            }
        }
    }
}

/// The argument rules every caller is held to, not only the sidecar's (ADR-0049 §1).
fn valid(args: &StoreArgs<'_>) -> bool {
    let one_line =
        |text: &str, max: usize| !text.trim().is_empty() && display_text_ok(text, max, false);
    let target_ok = match args.target {
        StoreTarget::Item { .. } => true,
        StoreTarget::NewItem {
            title, category, ..
        } => {
            one_line(title, MAX_STORED_ITEM_TITLE_CHARS)
                && category
                    .as_deref()
                    .is_none_or(|c| STORE_OUTPUT_CATEGORIES.contains(&c))
        }
    };
    target_ok
        && args.args.len() <= MAX_RUN_ARGS
        && one_line(args.field_label, MAX_STORED_FIELD_LABEL_CHARS)
        && args
            .reason
            .is_none_or(|r| display_text_ok(r, MAX_STORE_REASON_CHARS, false))
}

/// The vault's display name, for the sheet.
fn vault_name(vault: &Vault, id: VaultId) -> String {
    vault
        .vault_summaries()
        .into_iter()
        .find(|v| v.id == id)
        .map_or_else(|| id.to_string(), |v| v.name)
}

/// Resolve and check the target against the catalog as it is now (ADR-0049 §2).
fn resolve(catalog: &Catalog<'_>, args: &StoreArgs<'_>) -> Result<Plan, Response> {
    match args.target {
        StoreTarget::NewItem {
            title,
            category,
            vault_id,
        } => {
            if let Some(wanted) = vault_id
                && catalog
                    .agent_vaults()
                    .iter()
                    .any(|v| v.shared && v.id == *wanted)
            {
                return Err(Response::error(
                    ErrorCode::InvalidArgument,
                    SHARED_IS_READ_ONLY,
                ));
            }
            let personal = catalog.personal();
            let target = Service::target_vault(personal, *vault_id)
                .map_err(|e| Service::target_refused(&e))?;
            let category: Category = category
                .as_deref()
                .unwrap_or("api-credential")
                .parse()
                .unwrap_or(Category::ApiCredential);
            Ok(Plan::NewItem {
                vault_id: target,
                vault_name: vault_name(personal, target),
                title: title.clone(),
                category,
            })
        }
        StoreTarget::Item { item_id } => {
            let Some(found) = catalog.agent_item(&item_id.to_string()) else {
                return Err(Response::error(ErrorCode::NotFound, NO_SUCH_ITEM));
            };
            if matches!(found.place, Place::Shared(_)) {
                return Err(Response::error(
                    ErrorCode::InvalidArgument,
                    SHARED_IS_READ_ONLY,
                ));
            }
            let item = found.value;
            if item.archived {
                return Err(Response::error(ErrorCode::InvalidArgument, ARCHIVED));
            }
            let fills_empty = target_field(item, args.field_label)?;
            Ok(Plan::Existing {
                item_id: item.id,
                vault_id: item.vault_id,
                vault_name: vault_name(catalog.personal(), item.vault_id),
                title: item.title.clone(),
                fills_empty,
            })
        }
    }
}

/// Whether writing `label` into `item` fills an existing empty field (`true`) or adds one
/// (`false`); `Err` when it would replace a value or write the autofill password (ADR-0049 §2).
fn target_field(item: &Item, label: &str) -> Result<bool, Response> {
    let existing = item
        .fields
        .iter()
        .find(|f| f.label.eq_ignore_ascii_case(label));
    let fills_empty = match existing {
        None => false,
        Some(field)
            if field.kind == FieldKind::Concealed
                && field.value.is_secret()
                && !field.value.has_value() =>
        {
            true
        }
        Some(_) => return Err(Response::error(ErrorCode::InvalidArgument, FIELD_TAKEN)),
    };
    if !item.urls.is_empty() {
        let written_is_primary = match existing {
            // The field filled is the primary secret, by designation or as the first candidate.
            Some(field) => item
                .primary_secret_field()
                .is_some_and(|p| p.id == field.id),
            // A new concealed field becomes the primary secret of an item that has none.
            None => item.primary_secret_field().is_none(),
        };
        if written_is_primary {
            return Err(Response::error(ErrorCode::InvalidArgument, PRIMARY_REFUSED));
        }
    }
    Ok(fills_empty)
}

/// Write `value` into `item_id` inside the transaction, re-checking everything [`target_field`]
/// decided. `Err` is the reply.
fn write_existing(
    tx: &mut Tx<'_>,
    item_id: ItemId,
    label: &str,
    value: Secret,
) -> Result<(), Response> {
    let changed = || Response::error(ErrorCode::InvalidArgument, CHANGED_IN_FLIGHT);
    // Still one an agent may write: visible, personal, not archived. (The catalog's visibility
    // rule, on the file as it is now.)
    let visible = {
        let catalog = Catalog::new(tx, Vec::new());
        catalog
            .agent_item(&item_id.to_string())
            .is_some_and(|found| matches!(found.place, Place::Personal) && !found.value.archived)
    };
    if !visible {
        return Err(Response::error(ErrorCode::NotFound, NO_SUCH_ITEM));
    }
    let item = tx.item_by_id_mut(&item_id).ok_or_else(changed)?;
    let fills_empty = target_field(item, label).map_err(|_| changed())?;
    // Pinned before the change, so the new field cannot be chosen as the primary secret later.
    item.pin_primary_secret();
    if fills_empty {
        let field = item
            .fields
            .iter_mut()
            .find(|f| f.label.eq_ignore_ascii_case(label))
            .ok_or_else(changed)?;
        field.value = kagisecure_core::model::FieldValue::Secret(value);
        field.agent_visible = true;
    } else {
        let mut field = Field::concealed(label, value);
        field.agent_visible = true;
        item.fields.push(field);
    }
    item.updated_at = kagisecure_core::unix_now();
    Ok(())
}

/// The output's rules (ADR-0049 §6): `Ok` is the value to store.
fn checked_output(
    outcome: &RunOutcome,
    stdout: &Secret,
    killed_on_lock: bool,
) -> Result<Secret, NotStoredReason> {
    if killed_on_lock {
        return Err(NotStoredReason::KilledOnLock);
    }
    if outcome.timed_out {
        return Err(NotStoredReason::TimedOut);
    }
    if outcome.exit_code != Some(0) {
        return Err(NotStoredReason::ExitStatus);
    }
    if outcome.stdout_truncated {
        return Err(NotStoredReason::TooLarge);
    }
    let mut bytes = stdout.expose();
    if let Some(rest) = bytes.strip_suffix(b"\n") {
        bytes = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    if bytes.is_empty() {
        return Err(NotStoredReason::Empty);
    }
    if bytes.len() > MAX_STORED_OUTPUT_BYTES {
        return Err(NotStoredReason::TooLarge);
    }
    if bytes.contains(&0) {
        return Err(NotStoredReason::NulByte);
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(NotStoredReason::NotUtf8);
    }
    if bytes.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(NotStoredReason::MultiLine);
    }
    Ok(Secret::new(bytes.to_vec()))
}

/// Replace every occurrence of the captured output, and of its trimmed form, in `buf`.
fn redact(buf: &mut Vec<u8>, output: &[u8]) {
    let trimmed = output
        .strip_suffix(b"\n")
        .map_or(output, |rest| rest.strip_suffix(b"\r").unwrap_or(rest));
    if trimmed.is_empty() {
        return;
    }
    let marker = b"[kagisecure:redacted:output]";
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i..].starts_with(trimmed) {
            out.extend_from_slice(marker);
            i += trimmed.len();
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    *buf = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(code: Option<i32>) -> RunOutcome {
        RunOutcome {
            exit_code: code,
            ..RunOutcome::default()
        }
    }

    fn check(out: &[u8]) -> Result<Vec<u8>, NotStoredReason> {
        checked_output(&outcome(Some(0)), &Secret::new(out.to_vec()), false)
            .map(|s| s.expose().to_vec())
    }

    #[test]
    fn one_trailing_newline_is_removed_and_nothing_else() {
        assert_eq!(check(b"tok\n").unwrap(), b"tok");
        assert_eq!(check(b"tok\r\n").unwrap(), b"tok");
        assert_eq!(check(b"tok").unwrap(), b"tok");
        assert_eq!(check(b" tok ").unwrap(), b" tok ");
    }

    #[test]
    fn the_output_rules_refuse_with_fixed_reasons() {
        assert_eq!(check(b""), Err(NotStoredReason::Empty));
        assert_eq!(check(b"\n"), Err(NotStoredReason::Empty));
        assert_eq!(check(b"a\nb\n"), Err(NotStoredReason::MultiLine));
        assert_eq!(check(b"a\n\n"), Err(NotStoredReason::MultiLine));
        assert_eq!(check(b"a\0b"), Err(NotStoredReason::NulByte));
        assert_eq!(check(&[0xff, 0xfe]), Err(NotStoredReason::NotUtf8));
        assert_eq!(
            check(&vec![b'a'; MAX_STORED_OUTPUT_BYTES + 1]),
            Err(NotStoredReason::TooLarge)
        );
        assert!(check(&vec![b'a'; MAX_STORED_OUTPUT_BYTES]).is_ok());
        let out = Secret::new(b"tok".to_vec());
        assert_eq!(
            checked_output(&outcome(Some(1)), &out, false).map(|_| ()),
            Err(NotStoredReason::ExitStatus)
        );
        assert_eq!(
            checked_output(&outcome(None), &out, true).map(|_| ()),
            Err(NotStoredReason::KilledOnLock)
        );
    }

    #[test]
    fn the_output_is_redacted_from_stderr() {
        let mut err = b"got tok-123 ok".to_vec();
        redact(&mut err, b"tok-123\n");
        assert_eq!(err, b"got [kagisecure:redacted:output] ok");
    }
}
