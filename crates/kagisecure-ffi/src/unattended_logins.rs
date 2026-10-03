//! Unattended sign-ins from the app (ADR-0042 §12, Phase 5): copying a personal login into the
//! machine vault, the login grants a job holds, and the run browser it declares.
//!
//! As everywhere in `unattended_manage`, every call takes the unlocked personal session, and the
//! calls that widen access take the app's presence proof and record it in both logs. No value
//! crosses: a login is copied inside Rust, and what comes back is titles, usernames, origins and
//! counts.

use std::sync::Arc;

use kagisecure_agent::RunBrowserSetup;
use kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, FieldKind, Item};
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_core::unix_now;
use kagisecure_core::vault::Vault;
use kagisecure_core::vault::machine::{
    GrantId, GrantLimits, JobId, LoginField, LoginGrant, PresencePath, canonical_https_origin,
};
use kagisecure_extension_ipc::origin::Origin;

use crate::session::VaultSession;
use crate::unattended::UnattendedPresence;
use crate::unattended_manage::{ensure_machine, open_machine};
use crate::{FfiError, FfiResult};

/// The key under which a copied login names the personal item it came from.
const COPIED_FROM: &str = "copied_from";

/// Run browsers the app offers without asking, in order: builds measured to load the extension
/// headless and read a profile's manifest (ADR-0042 implementation decision 40). Google Chrome
/// ignores `--load-extension`, and Brave does not read the manifest, so neither is here.
const RUN_BROWSERS: [&str; 2] = [
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
];

/// A Login item of the machine vault.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MachineLoginView {
    /// Identifier.
    pub id: String,
    /// Title.
    pub title: String,
    /// The username, if it has a public one.
    pub username: Option<String>,
    /// The exact https origins a login grant may name.
    pub origins: Vec<String>,
    /// Whether it holds a one-time-password seed.
    pub has_one_time_code: bool,
    /// The personal item it was copied from, if it was.
    pub copied_from: Option<String>,
    /// Unix seconds of the last change.
    pub updated_at: u64,
}

/// A login grant, for Agent access.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedLoginGrantView {
    /// Identifier.
    pub id: String,
    /// The job whose runs may use it.
    pub job_id: String,
    /// The machine login it fills.
    pub item_id: String,
    /// That login's title, or empty when it is gone.
    pub item_title: String,
    /// The one exact https origin.
    pub origin: String,
    /// Where the sign-in may lead.
    pub follow_on_origins: Vec<String>,
    /// The fields it may fill: `username`, `password`, `one_time_code`.
    pub fields: Vec<String>,
    /// The one-time-code switch.
    pub one_time_codes: bool,
    /// Sign-ins so far.
    pub uses: u32,
    /// Sign-ins allowed in total.
    pub total_uses: u32,
    /// Sign-ins allowed per run.
    pub per_run: u32,
    /// Unix seconds when it expires.
    pub expires_at: u64,
    /// Why it is suspended, if it is.
    pub suspended_reason: Option<String>,
}

/// A login grant in the "New job" sheet.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedLoginDraft {
    /// A Login item of the machine vault ([`unattended_copy_login`] returns one).
    pub item_id: String,
    /// One of its websites, as an exact https origin.
    pub origin: String,
    /// Where the sign-in may lead.
    #[uniffi(default = [])]
    pub follow_on_origins: Vec<String>,
    /// The one-time-code switch, off by default (ADR-0042 §12.5).
    #[uniffi(default = false)]
    pub one_time_codes: bool,
}

fn login_field_name(field: LoginField) -> &'static str {
    match field {
        LoginField::Username => "username",
        LoginField::Password => "password",
        LoginField::OneTimeCode => "one_time_code",
    }
}

/// The exact https origins `item`'s websites name, in order, each once.
fn https_origins(item: &Item) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for site in kagisecure_agent::extension::saved_websites(item) {
        let Ok(origin) = Origin::parse(&site) else {
            continue;
        };
        if let Ok(canonical) = canonical_https_origin(&origin.ascii_serialization())
            && !out.contains(&canonical)
        {
            out.push(canonical);
        }
    }
    out
}

fn copied_from(item: &Item) -> Option<String> {
    item.extra
        .get(COPIED_FROM)
        .and_then(ciborium::Value::as_text)
        .map(str::to_owned)
}

fn has_code(item: &Item) -> bool {
    item.fields.iter().any(|f| f.kind == FieldKind::Totp)
}

fn decision(detail: String) -> AuditDraft {
    AuditDraft {
        actor: "app".to_owned(),
        tool: "unattended_decision".to_owned(),
        outcome: Outcome::Allowed,
        detail: Some(detail),
        ..AuditDraft::default()
    }
}

fn presence_detail(presence: UnattendedPresence) -> &'static str {
    match presence {
        UnattendedPresence::Confirmed => "PRESENCE_CONFIRMED",
        UnattendedPresence::ConfirmedMasterPassword => "PRESENCE_CONFIRMED_MASTER_PASSWORD",
    }
}

/// The machine vault's Login items.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_machine_logins(session: Arc<VaultSession>) -> FfiResult<Vec<MachineLoginView>> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(Vec::new());
    };
    Ok(machine
        .items()
        .iter()
        .filter(|i| i.category == Category::Login && i.trashed_at.is_none())
        .map(|i| MachineLoginView {
            id: i.id.to_string(),
            title: i.title.clone(),
            username: i.username().map(str::to_owned),
            origins: https_origins(i),
            has_one_time_code: has_code(i),
            copied_from: copied_from(i),
            updated_at: i.updated_at,
        })
        .collect())
}

/// Every login grant of the machine vault, for Agent access.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or the machine vault cannot be opened.
#[uniffi::export]
pub fn unattended_login_grants(
    session: Arc<VaultSession>,
) -> FfiResult<Vec<UnattendedLoginGrantView>> {
    let Some(machine) = open_machine(&session)? else {
        return Ok(Vec::new());
    };
    let title = |id: &ItemId| {
        machine
            .item_by_id(id)
            .map(|i| i.title.clone())
            .unwrap_or_default()
    };
    Ok(machine
        .machine()
        .map(|section| {
            section
                .login_grants
                .iter()
                .map(|g| UnattendedLoginGrantView {
                    id: g.id.to_string(),
                    job_id: g.job.to_string(),
                    item_id: g.item.to_string(),
                    item_title: title(&g.item),
                    origin: g.origin.clone(),
                    follow_on_origins: g.follow_on_origins.clone(),
                    fields: g
                        .fields
                        .iter()
                        .map(|f| login_field_name(*f).to_owned())
                        .collect(),
                    one_time_codes: g.one_time_codes,
                    uses: g.uses,
                    total_uses: g.limits.total_uses,
                    per_run: g.limits.per_run,
                    expires_at: g.limits.expires_at,
                    suspended_reason: g.suspended.as_ref().map(|s| s.reason.clone()),
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Copy a personal Login item, as it is now, into the machine vault — or bring an earlier copy up
/// to date — after the app's presence proof (ADR-0042 §12.1: a login the owner moved in
/// knowingly). Its password history is not copied, and its websites become the exact https
/// origins they name. Updating a copy re-approves the login grants
/// over it, since the person has just confirmed the change. Returns the machine item's id.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked, the item is not a personal Login or has no
/// https website, or a write fails.
#[uniffi::export]
pub fn unattended_copy_login(
    session: Arc<VaultSession>,
    personal_item_id: String,
    presence: UnattendedPresence,
) -> FfiResult<String> {
    let source: ItemId = personal_item_id
        .parse()
        .map_err(|_| FfiError::invalid("Not an item id."))?;
    let original = session
        .handle()
        .with(|v| {
            v.item_by_id(&source)
                .filter(|i| i.category == Category::Login && i.trashed_at.is_none())
                .map(deep_copy)
        })
        .ok_or_else(|| FfiError::invalid("The vault is locked."))?
        .ok_or_else(|| FfiError::invalid("Choose one of your logins."))??;
    let origins = https_origins(&original);
    if origins.is_empty() {
        return Err(FfiError::invalid(
            "This login has no https website. Add the site's address to it first.",
        ));
    }
    let mut machine = ensure_machine(&session)?;
    let existing = machine
        .items()
        .iter()
        .find(|i| copied_from(i).as_deref() == Some(personal_item_id.as_str()))
        .map(|i| i.id);
    let now = unix_now();
    let detail = format!(
        "LOGIN_COPIED (item {:?}, {})",
        original.title,
        presence_detail(presence)
    );
    let id = copy_into(
        &mut machine,
        original,
        &origins,
        existing,
        &personal_item_id,
        now,
        &detail,
    )?;
    let _ = session.handle().record_best_effort(
        REQUEST_LOCK_TIMEOUT,
        AuditDraft {
            item_id: Some(source),
            ..decision(detail)
        },
    );
    Ok(id.to_string())
}

/// A copy of `item`, secrets and all, through the vault's own encoding: `Item` is deliberately not
/// `Clone`. The buffer is zeroed when it is dropped.
fn deep_copy(item: &Item) -> FfiResult<Item> {
    let mut buffer = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(item, &mut *buffer)
        .map_err(|_| FfiError::invalid("The login could not be copied."))?;
    ciborium::from_reader(buffer.as_slice())
        .map_err(|_| FfiError::invalid("The login could not be copied."))
}

fn copy_into(
    machine: &mut Vault,
    original: Item,
    origins: &[String],
    existing: Option<ItemId>,
    source_key: &str,
    now: u64,
    detail: &str,
) -> FfiResult<ItemId> {
    let vault_id = machine.default_vault_id()?;
    let mut copy = original;
    copy.id = existing.unwrap_or_default();
    copy.vault_id = vault_id;
    copy.agent_visible = true;
    copy.history.clear();
    // A machine vault's websites are exact https origins (ADR-0042 §2): the copy keeps those its
    // websites name, and nothing else.
    copy.urls = origins.to_vec();
    copy.extra.insert(
        COPIED_FROM.to_owned(),
        ciborium::Value::Text(source_key.to_owned()),
    );
    copy.updated_at = now;
    let id = copy.id;
    let mut pending = Some(copy);
    machine.transact(|tx| {
        tx.set_vault_agent_visible(vault_id, true);
        if let Some(copy) = pending.take() {
            match tx.item_by_id_mut(&id) {
                Some(slot) => *slot = copy,
                None => tx.add_item(copy),
            }
        }
        if let Ok(section) = tx.machine_mut() {
            for grant in section.login_grants.iter_mut().filter(|g| g.item == id) {
                grant.approved_at = now;
            }
        }
        tx.append_audit(AuditDraft {
            item_id: Some(id),
            ..decision(detail.to_owned())
        });
        Ok(())
    })?;
    Ok(id)
}

/// The run browser the app offers first: Microsoft Edge, else Chromium, if installed.
#[uniffi::export]
#[must_use]
pub fn unattended_default_run_browser() -> Option<String> {
    RUN_BROWSERS
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
        .map(|p| (*p).to_owned())
}

/// Whether this app can start a run browser: the native host and the extension are where the
/// engine looks for them.
#[uniffi::export]
#[must_use]
pub fn unattended_run_browser_ready() -> bool {
    RunBrowserSetup::discover().is_some()
}

/// The login grants `drafts` describe, for job `job` in `machine`, approved `now`.
pub(crate) fn login_grants(
    machine: &Vault,
    job: JobId,
    drafts: &[UnattendedLoginDraft],
    limits: GrantLimits,
    now: u64,
    presence: PresencePath,
) -> FfiResult<Vec<LoginGrant>> {
    drafts
        .iter()
        .map(|d| {
            let item: ItemId = d
                .item_id
                .parse()
                .map_err(|_| FfiError::invalid("Not an item id."))?;
            let saved = machine
                .item_by_id(&item)
                .filter(|i| i.category == Category::Login)
                .ok_or_else(|| FfiError::invalid("That login is not in the machine vault."))?;
            let origin = canonical_https_origin(&d.origin)
                .map_err(|_| FfiError::invalid("Choose one of the login's https websites."))?;
            if !saved.urls.contains(&origin) {
                return Err(FfiError::invalid(
                    "Choose one of the login's https websites.",
                ));
            }
            let follow_on_origins = d
                .follow_on_origins
                .iter()
                .map(|o| {
                    canonical_https_origin(o).map_err(|_| {
                        FfiError::invalid(format!("{o} is not an exact https origin."))
                    })
                })
                .collect::<FfiResult<Vec<_>>>()?;
            let mut fields = vec![LoginField::Username, LoginField::Password];
            if d.one_time_codes {
                if !has_code(saved) {
                    return Err(FfiError::invalid(
                        "That login has no one-time password to generate codes from.",
                    ));
                }
                fields.push(LoginField::OneTimeCode);
            }
            Ok(LoginGrant {
                id: GrantId::new(),
                job,
                item,
                fields,
                origin,
                follow_on_origins,
                one_time_codes: d.one_time_codes,
                limits,
                uses: 0,
                created_at: now,
                approved_at: now.max(saved.updated_at),
                presence,
                suspended: None,
                unknown: std::collections::BTreeMap::new(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagisecure_core::model::{Field, Secret};
    use kagisecure_core::proto::VaultId;

    #[test]
    fn a_login_offers_its_https_websites_as_exact_origins() {
        let mut item = Item::new(VaultId::new(), Category::Login, "Service");
        item.urls = vec![
            "https://Example.com/login".to_owned(),
            "example.com".to_owned(),
            "http://plain.example".to_owned(),
            "https://app.example.com:8443/x".to_owned(),
        ];
        assert_eq!(
            https_origins(&item),
            ["https://example.com", "https://app.example.com:8443"]
        );
        item.fields.push(Field::concealed(
            "password",
            Secret::from_string("x".to_owned()),
        ));
        assert!(!has_code(&item));
    }
}
