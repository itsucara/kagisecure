//! `request_type` (ADR-0050): type a saved login's username and password, or a one-time code, as
//! keystrokes into the field focused in the app the agent names — after the person approves it,
//! or inside the presence grace window.
//!
//! The shape: the platform and the broker (ready, not blocked, one at a time, under the rate) →
//! the arguments → the item and its fields → the audit pre-flight → the sheet (the app answers it
//! with no sheet inside the grace window) → `audited_release` records the `Allowed` entry and, in
//! the same transaction, the crossing builds the values → the job goes to the app, which checks
//! the frontmost app and the focused field right before it types → a `Failed` follow-up for
//! anything but `TYPED`.

use std::sync::Arc;
use std::time::Instant;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_ipc::protocol::{
    ErrorCode, MAX_TYPE_REASON_CHARS, Response, TypeField, TypeTarget, display_text_ok,
    type_fields_ok, type_order, type_target_ok,
};
use kagisecure_ipc::server::Connection;

use super::{Service, denied_reply};
use crate::approval::{ApprovalRequest, AutoTypeFacts};
use crate::auto_type::{AdmitRefusal, AutoTypeBroker, AutoTypeJob, TypeOutcome};
use crate::catalog::Catalog;
use crate::extension::agent_fill::{self, Sidecar};
use crate::extension::auto_type_values;
use crate::release::{Acted, NotReleased, Released, audited_release};
use crate::vault::REQUEST_LOCK_TIMEOUT;

const TOOL: &str = "request_type";

/// The `Allowed` entry's detail prefix, before the target bundle id.
const DETAIL_TYPE: &str = "AUTO_TYPE";

const INVALID_TYPE: &str = "request_type needs fields of username, password or both, or \
     one_time_code on its own, none twice; a target bundle_id of letters, digits, '.', '-' and \
     '_' (at most 255); a team_id of ten upper-case letters and digits; a window_title of at most \
     256 characters on one line; and a reason of at most 200 characters on one line. Nothing was \
     asked or typed. Fix the argument and retry.";

const NOT_ON_THIS_PLATFORM: &str = "request_type is not offered on this platform. Nothing was \
     asked or typed.";

const NO_TYPIST: &str = "kagisecure cannot type into apps right now: the kagisecure app is not \
     running, the user has not granted it the Accessibility permission, or has turned agent \
     auto-type off in Settings. Nothing was asked or typed. Ask the user to check kagisecure's \
     Settings.";

const SECURE_INPUT: &str = "Another app is holding secure keyboard input (a password prompt or \
     a terminal's Secure Keyboard Entry), so keystrokes would not arrive. Nothing was typed. Ask \
     the user to close that prompt or turn Secure Keyboard Entry off, then retry.";

const NOT_TYPED_IN_TIME: &str = "The kagisecure app did not type in time. Nothing is known to \
     have been typed. Retry once; if it happens again, tell the user.";

/// The one message for every mismatch found before typing (ADR-0050 §3).
const NO_MATCHING_TARGET: &str = "The app in front is not the target you named, or no text \
     field in it has keyboard focus (a password needs a secure text field). Nothing was typed. \
     Bring the app to the front, click into the field, and retry.";

/// The message for focus that moved while typing.
const STOPPED_PARTWAY: &str = "Keyboard focus moved while kagisecure was typing, so it stopped. \
     Part of the value may have been typed into the field: clear it before you retry. Keep the \
     app in front and the field focused, then retry.";

const NOTHING_TO_TYPE: &str = "That item has no value for a field you asked to type, or is \
     archived. Nothing was typed. Check describe_item.";

const BLOCKED: &str = "The user chose to block auto-type requests from this agent for now. \
     Nothing was asked or typed. Do not retry; tell the user what you were trying to do.";

const BUSY: &str = "Another auto-type is in progress; they are served one at a time. Nothing was \
     asked or typed. Retry in a few seconds.";

const RATE_LIMITED: &str = "This agent has asked for 30 auto-types in ten minutes. Nothing was \
     asked or typed. Wait a few minutes, and tell the user if you need more.";

/// Why the crossing produced nothing inside the transaction.
enum Refused {
    /// The item is gone, hidden, archived or emptied since the sheet.
    Recheck,
    /// A grant that did not cover the request: never expected.
    Internal,
}

/// What the sidecar sends, borrowed.
pub(crate) struct TypeArgs<'a> {
    pub item_id: ItemId,
    pub fields: &'a [TypeField],
    pub target: &'a TypeTarget,
    pub reason: Option<&'a str>,
}

fn valid(args: &TypeArgs<'_>) -> bool {
    type_fields_ok(args.fields)
        && type_target_ok(args.target)
        && args
            .reason
            .is_none_or(|r| display_text_ok(r, MAX_TYPE_REASON_CHARS, false))
}

/// Whether `item` has a value for every one of `fields`. Reads no value out.
fn has_values(item: &kagisecure_core::model::Item, fields: &[TypeField]) -> bool {
    !item.archived
        && fields.iter().all(|field| match field {
            TypeField::Username => item.username().is_some_and(|u| !u.is_empty()),
            TypeField::Password => item
                .primary_secret_field()
                .and_then(|f| f.value.as_secret())
                .is_some_and(|s| !s.is_empty()),
            TypeField::OneTimeCode => item
                .totp_field()
                .is_some_and(kagisecure_core::model::Field::has_working_totp),
        })
}

impl Service {
    /// Serve `request_type` through `broker` (ADR-0050). The app passes one process-wide broker.
    #[must_use]
    pub fn with_auto_type(mut self, broker: Arc<AutoTypeBroker>) -> Self {
        self.auto_type = Some(broker);
        self
    }

    /// `request_type` (ADR-0050). See the module documentation.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn request_type(&self, args: &TypeArgs<'_>, connection: &Connection) -> Response {
        if cfg!(windows) {
            return Response::error(ErrorCode::TypeUnavailable, NOT_ON_THIS_PLATFORM);
        }
        let Some(broker) = self.auto_type.as_ref().filter(|b| b.is_ready()) else {
            return Response::error(ErrorCode::TypeUnavailable, NO_TYPIST);
        };
        // Limits are keyed on the kernel's word for who asked, so a caller it cannot vouch for is
        // not served.
        let Some(sidecar) = Sidecar::of(connection.identity()) else {
            return Response::error(ErrorCode::TypeUnavailable, NO_TYPIST);
        };
        let actor = agent_fill::actor_for(connection.identity());
        let ordered = type_order(args.fields);
        let names: Vec<String> = ordered.iter().map(|f| f.as_str().to_owned()).collect();
        let entry = |outcome: Outcome, detail: String, item_id: Option<ItemId>| AuditDraft {
            actor: actor.clone(),
            client_pid: connection.identity().pid,
            tool: TOOL.to_owned(),
            item_id,
            variables: if valid(args) {
                names.clone()
            } else {
                Vec::new()
            },
            outcome,
            detail: Some(detail),
            ..AuditDraft::default()
        };

        let slot = match broker.admit(sidecar.key(), Instant::now()) {
            Ok(slot) => slot,
            Err(refusal) => {
                let (code, message) = match refusal {
                    AdmitRefusal::Blocked => (ErrorCode::UserDenied, BLOCKED),
                    AdmitRefusal::Busy => (ErrorCode::RateLimited, BUSY),
                    AdmitRefusal::RateLimited => (ErrorCode::RateLimited, RATE_LIMITED),
                };
                self.record_best_effort(entry(Outcome::Denied, code.as_str().to_owned(), None));
                return Response::error(code, message);
            }
        };

        if !valid(args) {
            return Response::error(ErrorCode::InvalidArgument, INVALID_TYPE);
        }
        let target = args.target.clone();
        let item_key = args.item_id.to_string();

        // The item, and a value for every field, before anyone is asked.
        let looked_up = self.read_catalog(|catalog| {
            let found = catalog.agent_item(&item_key)?;
            let item = found.value;
            let vault_name = catalog
                .agent_vaults()
                .into_iter()
                .find(|v| v.id == item.vault_id || Some(v.id) == found.place.audit_vault())
                .map_or_else(String::new, |v| v.name);
            Some((
                catalog.item_title(found),
                vault_name,
                has_values(item, &ordered),
            ))
        });
        let (item_title, vault_name) = match looked_up {
            Err(response) => return response,
            Ok(None) => return super::no_such_item(),
            Ok(Some((_, _, false))) => {
                return Response::error(ErrorCode::NothingToFill, NOTHING_TO_TYPE);
            }
            Ok(Some((title, vault, true))) => (title, vault),
        };

        let allowed = entry(
            Outcome::Allowed,
            format!("{DETAIL_TYPE} {}", target.bundle_id),
            Some(args.item_id),
        );
        // Never ask a question whose answer could not be recorded (ADR-0040).
        if let Err(response) = self.audit_preflight(&allowed) {
            return response;
        }
        let sheet = ApprovalRequest::for_auto_type(
            AutoTypeFacts {
                agent: actor.clone(),
                item_title: item_title.clone(),
                vault_name,
                fields: names.clone(),
                bundle_id: target.bundle_id.clone(),
                team_id: target.team_id.clone(),
                window_title: target.window_title.clone(),
                reason: args.reason.map(str::to_owned),
            },
            item_key.clone(),
            connection.identity(),
        );
        let approved = self.ask(sheet);
        if approved.block_agent {
            broker.block(sidecar.key(), Instant::now());
        }
        let grant = match approved.into_grant() {
            Ok(grant) => grant,
            Err(code) => {
                self.record_best_effort(entry(
                    Outcome::Denied,
                    code.as_str().to_owned(),
                    Some(args.item_id),
                ));
                return denied_reply(code);
            }
        };

        // The crossing, inside the transaction that commits the `Allowed` entry; then the job.
        let job_id = broker.fresh_id();
        let act = {
            let broker = Arc::clone(broker);
            let target = target.clone();
            let item_title = item_title.clone();
            let gate = self.gate();
            move |values, _entry_seq| {
                if !gate.is_serving() {
                    return Acted::abnormal(TypeOutcome::Locked.as_str(), TypeOutcome::Locked);
                }
                let outcome = broker.deliver(AutoTypeJob {
                    id: job_id,
                    item_title,
                    target,
                    values,
                });
                match outcome {
                    TypeOutcome::Typed => Acted::done(outcome),
                    other => Acted::abnormal(other.as_str(), other),
                }
            }
        };
        let handle = &self.handle;
        let checked = ordered.clone();
        let bundle_id = target.bundle_id.clone();
        let released = audited_release(
            handle,
            REQUEST_LOCK_TIMEOUT,
            allowed,
            move |tx| {
                let catalog = Catalog::new(tx, handle.shared_snapshots());
                let item = super::agent_visible_item(&catalog, &item_key)
                    .filter(|item| has_values(item, &checked))
                    .ok_or(Refused::Recheck)?;
                auto_type_values(
                    grant,
                    &bundle_id,
                    item,
                    &checked,
                    kagisecure_core::unix_now(),
                )
                .ok_or(Refused::Internal)
            },
            act,
        );
        drop(slot);
        let outcome = match released {
            Err(NotReleased::Locked) => return Self::locked(),
            Err(NotReleased::AuditUnavailable(_)) => return Self::audit_unavailable(),
            Err(NotReleased::Refused(Refused::Recheck)) => {
                self.record_best_effort(entry(
                    Outcome::Failed,
                    "CHANGED_DURING_APPROVAL".to_owned(),
                    Some(args.item_id),
                ));
                return Response::error(ErrorCode::NothingToFill, NOTHING_TO_TYPE);
            }
            Err(NotReleased::Refused(Refused::Internal)) => {
                self.record_best_effort(entry(
                    Outcome::Failed,
                    "INTERNAL".to_owned(),
                    Some(args.item_id),
                ));
                return Response::error(
                    ErrorCode::Internal,
                    "kagisecure could not prepare the values. Nothing was typed.",
                );
            }
            Ok(Released { value, .. }) => value,
        };
        // The `Failed` follow-up for anything but `TYPED` is already recorded.
        match outcome {
            TypeOutcome::Typed => Response::Typed {
                fields_typed: ordered,
                bundle_id: target.bundle_id,
            },
            TypeOutcome::TargetMismatch | TypeOutcome::FocusChanged { typed_any: false } => {
                Response::error(ErrorCode::NoMatchingTarget, NO_MATCHING_TARGET)
            }
            TypeOutcome::FocusChanged { typed_any: true } => {
                Response::error(ErrorCode::NoMatchingTarget, STOPPED_PARTWAY)
            }
            TypeOutcome::SecureInput => Response::error(ErrorCode::TypeUnavailable, SECURE_INPUT),
            TypeOutcome::AccessibilityDenied => {
                Response::error(ErrorCode::TypeUnavailable, NO_TYPIST)
            }
            TypeOutcome::TimedOut => Response::error(ErrorCode::TypeUnavailable, NOT_TYPED_IN_TIME),
            TypeOutcome::Locked => Self::locked(),
        }
    }
}
