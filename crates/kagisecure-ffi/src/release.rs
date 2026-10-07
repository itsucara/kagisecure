//! Releasing a value to the app: one field, one one-time code, or one item's notes, each behind a
//! fresh presence proof ([ADR-0038](../../../docs/decisions/0038-app-release-needs-presence.md)).
//!
//! # The shape of a release
//!
//! `release_field`, `release_totp` and `release_notes` all run the same three steps:
//!
//! 1. **Read the facts, synchronously** (`VaultSession::begin_release`): borrow the vault, check
//!    the item and field exist and can be released at all, build the prompt from what the field is
//!    (its kind and the item's primary-secret designation, which a relabel cannot change), its
//!    label and the item's title, and register the release as the one awaiting a prompt. The
//!    borrow ends here.
//! 2. **Ask the gate** — the one `.await`. Nothing is borrowed across it, and nothing *can* be:
//!    the vault borrow wraps a `std::sync::MutexGuard`, which is not `Send`, and uniffi requires
//!    an exported future to be `Send`, so holding it here does not compile (ADR-0038 §3).
//! 3. **Settle, synchronously** (`VaultSession::settle_release`): borrow the vault again, and
//!    only if this release is still registered — a lock that ran during the prompt has already
//!    taken it out and recorded it `VAULT_LOCKED` — and the item and field still exist, record the
//!    outcome and hand back a release object.
//!
//! One call, one prompt, one field (user decision 1): a release object is bound to the item and
//! field it was granted for, by id, and there is no way to point it at another.
//!
//! # A release is a capability, not a copy
//!
//! [`FieldRelease`], [`TotpRelease`] and [`NotesRelease`] hold no value. Each use re-reads the
//! vault through the shared handle, so a release stops working the moment the vault locks, and
//! also after its five-minute cap (user decisions 2 and 5; use does not extend it) and after
//! `close()`. A release for a copy is spent by its one use; a release for showing a value stays
//! readable until it ends, and copying that shown value is the one thing that needs no new touch
//! (user decision 1) — recorded as `SHOWN_EARLIER`, so the log says honestly that no touch
//! happened for that entry.
//!
//! # Audit (ADR-0040 step 10)
//!
//! Every outcome is recorded best-effort through the vault's pending queue, actor `app`, with the
//! item id and the field's label: `PRESENCE_CONFIRMED` on a grant (or
//! `PRESENCE_CONFIRMED_MASTER_PASSWORD` when the master-password fallback answered it),
//! `PRESENCE_CANCELLED`, `PRESENCE_UNAVAILABLE`, `PRESENCE_BUSY` or `VAULT_LOCKED` on a refusal
//! (the first three throttled to one entry per reason per minute, the rest of the minute counted
//! into one `<detail>_REPEATED:<n>` entry — `Presence::throttle_refusal`),
//! `GONE_DURING_PROMPT` (outcome `failed`) when what was confirmed had been deleted by the time
//! the prompt answered, and `SHOWN_EARLIER` on a copy of a shown value. A failed write never withholds a value from the person who asked for
//! it (ADR-0040 user decision 1); the entry stays queued and the app's durability warning shows.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use kagisecure_agent::VaultHandle;
use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{FieldId, FieldValue, Item, ItemId};
use kagisecure_core::proto::Outcome;

use crate::generate::TotpCodeView;
use crate::presence::{
    self, DETAIL_GONE_DURING_PROMPT, DETAIL_PRESENCE_BUSY, DETAIL_PRESENCE_CANCELLED,
    DETAIL_PRESENCE_CONFIRMED, DETAIL_PRESENCE_CONFIRMED_MASTER_PASSWORD,
    DETAIL_PRESENCE_UNAVAILABLE, DETAIL_SHOWN_EARLIER, Presence, PresenceGate, PresenceOutcome,
    RELEASE_TTL, RegisterRefusal, ReleasePurpose, Settled, Subject,
};
use crate::session::VaultSession;
use crate::{FfiError, FfiResult};

/// What kind of value a release carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Field,
    Totp,
    Notes,
}

/// The audit `tool` for releasing `kind` for `purpose`, or `Invalid` for a pairing that means
/// nothing (editing a one-time code; Quick Access copying a note).
fn tool_for(kind: Kind, purpose: ReleasePurpose) -> FfiResult<&'static str> {
    use ReleasePurpose as P;
    Ok(match (kind, purpose) {
        (Kind::Field, P::Reveal) => "reveal_field",
        (Kind::Field | Kind::Notes, P::Copy) => "copy_field",
        (Kind::Field | Kind::Notes, P::EditReveal) => "edit_reveal",
        (Kind::Field | Kind::Totp, P::QuickAccessCopy) => "quick_access_copy",
        (Kind::Totp, P::Reveal) => "totp_show",
        (Kind::Totp, P::Copy) => "totp_copy",
        (Kind::Notes, P::Reveal) => "notes_show",
        (Kind::Totp, P::EditReveal) => {
            return Err(FfiError::invalid(
                "a one-time code is not edited; release the field itself to edit its setup",
            ));
        }
        (Kind::Field | Kind::Totp, P::AutoType) => "auto_type",
        (Kind::Notes, P::QuickAccessCopy) => {
            return Err(FfiError::invalid("Quick Access does not copy notes"));
        }
        (Kind::Notes, P::AutoType) => {
            return Err(FfiError::invalid("notes are not auto-typed"));
        }
    })
}

/// The audit `tool` for copying a value `kind` already shown (`SHOWN_EARLIER`).
fn shown_copy_tool(kind: Kind) -> &'static str {
    match kind {
        Kind::Field | Kind::Notes => "copy_field",
        Kind::Totp => "totp_copy",
    }
}

/// The label a notes release records, standing in for a field label.
const NOTES_LABEL: &str = "notes";

/// Exactly what a release is for: resolved to ids when it began, so nothing about it — not a
/// label edited during the prompt, not a second field with the same name — can point it anywhere
/// else afterwards.
#[derive(Clone, Debug)]
struct Target {
    kind: Kind,
    purpose: ReleasePurpose,
    item_id: ItemId,
    field_id: Option<FieldId>,
    /// The field's label when the release began — metadata, for the audit entry.
    label: String,
    tool: &'static str,
}

impl Target {
    fn draft(&self, tool: &str, outcome: Outcome, detail: &str) -> AuditDraft {
        AuditDraft {
            actor: "app".to_owned(),
            tool: tool.to_owned(),
            item_id: Some(self.item_id),
            variables: vec![self.label.clone()],
            outcome,
            detail: Some(detail.to_owned()),
            ..AuditDraft::default()
        }
    }

    /// The entry this release writes on `outcome`.
    fn entry(&self, outcome: Outcome, detail: &str) -> AuditDraft {
        self.draft(self.tool, outcome, detail)
    }

    /// The field as it is in `item` now — by id, never by label — or `NotPresent`.
    fn field<'i>(&self, item: &'i Item) -> FfiResult<&'i kagisecure_core::model::Field> {
        let id = self
            .field_id
            .expect("a field or one-time-code release always names its field");
        item.fields
            .iter()
            .find(|f| f.id == id)
            .ok_or_else(|| FfiError::missing("field", id.to_string()))
    }
}

/// Where a release reads its item from: the personal vault, or one shared vault
/// (`crate::shared`). Either way the audit entries go to the personal vault's log, and the
/// personal vault's lock ends the release.
#[derive(Clone)]
pub(crate) enum Source {
    /// The personal vault, through its handle.
    Personal,
    /// A shared vault's items, as this device reads them.
    Shared(Arc<crate::shared::SharedCore>),
}

impl Source {
    /// Apply `f` to item `id` as it is now — by id, never by title — or answer `NotPresent`, or
    /// `VaultLocked` once the personal vault has locked.
    fn read<T>(
        &self,
        handle: &VaultHandle,
        id: &ItemId,
        f: impl FnOnce(&Item) -> FfiResult<T>,
    ) -> FfiResult<T> {
        let missing = || FfiError::missing("item", id.to_string());
        match self {
            Self::Personal => handle
                .with(|vault| vault.item_by_id(id).ok_or_else(missing).and_then(f))
                .unwrap_or(Err(FfiError::VaultLocked)),
            Self::Shared(core) => {
                if !handle.is_unlocked() {
                    return Err(FfiError::VaultLocked);
                }
                core.read_item(id, f)
            }
        }
    }

    /// As [`Source::read`], with the personal vault already borrowed by the caller (the lock
    /// order is the personal vault's handle first, a shared vault's state second).
    fn read_in<T>(
        &self,
        vault: &Vault,
        id: &ItemId,
        f: impl FnOnce(&Item) -> FfiResult<T>,
    ) -> FfiResult<T> {
        match self {
            Self::Personal => vault
                .item_by_id(id)
                .ok_or_else(|| FfiError::missing("item", id.to_string()))
                .and_then(f),
            Self::Shared(core) => core.read_item(id, f),
        }
    }
}

/// Everything a release needs from the session that asks for it: the personal vault's handle —
/// for the audit log, the lock and the one lock order — its presence state, and where the item
/// is read from.
pub(crate) struct Releaser {
    pub(crate) handle: Arc<VaultHandle>,
    pub(crate) presence: Arc<Presence>,
    pub(crate) source: Source,
}

/// A release between asking the gate and hearing back. Carried across the `.await`, so it holds
/// only shared handles and plain data — no vault borrow.
///
/// If the future carrying it is dropped before it settles — the caller's task was cancelled —
/// `Drop` takes it out of the registry and queues a `PRESENCE_CANCELLED` denial, so the log does
/// not show a prompt that never ended and a later lock does not record it as `VAULT_LOCKED`.
struct Pending {
    token: u64,
    target: Target,
    reason: String,
    gate: Arc<dyn PresenceGate>,
    handle: Arc<VaultHandle>,
    presence: Arc<Presence>,
    settled: bool,
}

impl Pending {
    async fn ask(&self) -> PresenceOutcome {
        self.gate.confirm(self.reason.clone()).await
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Handle first, registry second: the one lock order (`Presence::register`).
        let mut guard = self.handle.guard();
        self.presence.abandon(self.token, guard.as_mut());
    }
}

/// What a granted release holds: where to read, what it may do, and until when.
struct Grant {
    target: Target,
    handle: Arc<VaultHandle>,
    source: Source,
    presence: Arc<Presence>,
    expires_at: Instant,
    state: Mutex<GrantState>,
}

#[derive(Default)]
struct GrantState {
    closed: bool,
    /// A one-use release (a copy) has been used.
    spent: bool,
}

/// Whether a use spends a one-use release.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    /// Reading the value the release was granted for.
    Read,
    /// Copying a value an earlier touch already put on screen.
    CopyShown,
}

impl Grant {
    /// Refuse if this release has ended — closed, past its cap, or a copy already used — and mark
    /// a one-use release spent. Spent before the read, so a read that then fails (the vault
    /// locked, the field went) still spends it: failing closed.
    fn begin_use(&self, how: Use) -> FfiResult<()> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(FfiError::ended("this release was closed"));
        }
        if self.presence.now() >= self.expires_at {
            return Err(FfiError::ended(
                "this release has passed its five-minute limit",
            ));
        }
        match how {
            Use::Read if self.target.purpose.is_one_use() => {
                if state.spent {
                    return Err(FfiError::ended("this copy has already been used"));
                }
                state.spent = true;
            }
            Use::Read => {}
            Use::CopyShown if !self.target.purpose.shows_value() => {
                return Err(FfiError::invalid(
                    "only a value released to be shown can be copied without a new check",
                ));
            }
            Use::CopyShown => {}
        }
        Ok(())
    }

    /// Re-read the item from the vault as it is now and apply `f`.
    fn read<T>(&self, f: impl FnOnce(&Item) -> FfiResult<T>) -> FfiResult<T> {
        self.source.read(&self.handle, &self.target.item_id, f)
    }

    /// Record a copy of the shown value — no new touch — best-effort.
    fn record_shown_copy(&self) {
        let draft = self.target.draft(
            shown_copy_tool(self.target.kind),
            Outcome::Allowed,
            DETAIL_SHOWN_EARLIER,
        );
        self.handle
            .record_best_effort(crate::session::APP_LOCK_TIMEOUT, draft);
    }

    fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
    }

    fn is_live(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        !state.closed
            && !(self.target.purpose.is_one_use() && state.spent)
            && self.presence.now() < self.expires_at
            && self.handle.is_unlocked()
    }

    fn seconds_remaining(&self) -> u32 {
        let left = self
            .expires_at
            .saturating_duration_since(self.presence.now());
        u32::try_from(left.as_secs()).unwrap_or(u32::MAX)
    }
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Metadata only; a grant holds no value to print in the first place.
        f.debug_struct("Grant")
            .field("kind", &self.target.kind)
            .field("purpose", &self.target.purpose)
            .field("item_id", &self.target.item_id)
            .field("field_id", &self.target.field_id)
            .finish_non_exhaustive()
    }
}

/// The field of `item` with exactly the id `reference` — never a label match — or `NotPresent`.
fn field_by_id<'i>(
    item: &'i Item,
    reference: &str,
) -> FfiResult<&'i kagisecure_core::model::Field> {
    FieldId::parse_canonical(reference)
        .and_then(|id| item.fields.iter().find(|f| f.id == id))
        .ok_or_else(|| FfiError::missing("field", reference))
}

/// The text of a released field.
fn field_text(field: &kagisecure_core::model::Field) -> FfiResult<String> {
    match &field.value {
        FieldValue::Public(s) => Ok(s.clone()),
        FieldValue::Secret(secret) => secret
            .expose_str()
            .map(str::to_owned)
            .ok_or_else(|| FfiError::invalid("this value is not text and cannot be shown")),
    }
}

// MARK: - The release objects

/// One concealed field's value, released by one presence check ([`VaultSession::release_field`]).
///
/// Holds no value: [`FieldRelease::value`] reads the field from the vault each time, and fails
/// once the vault is locked, after five minutes, after [`FieldRelease::close`] — and, for a
/// [`ReleasePurpose::Copy`] or [`ReleasePurpose::QuickAccessCopy`] release, after its one use.
#[derive(Debug, uniffi::Object)]
pub struct FieldRelease {
    grant: Grant,
}

#[uniffi::export]
impl FieldRelease {
    /// The field's value, as it is in the vault now.
    ///
    /// # Errors
    ///
    /// [`FfiError::ReleaseEnded`], [`FfiError::VaultLocked`], [`FfiError::NotPresent`] if the item
    /// or field has gone, [`FfiError::Invalid`] if the value is not text.
    pub fn value(&self) -> FfiResult<String> {
        self.grant.begin_use(Use::Read)?;
        self.grant
            .read(|item| field_text(self.grant.target.field(item)?))
    }

    /// The value again, for the clipboard — the copy of a shown value that needs no new touch
    /// (user decision 1). Recorded as `copy_field` with `SHOWN_EARLIER`.
    ///
    /// # Errors
    ///
    /// As [`FieldRelease::value`], and [`FfiError::Invalid`] for a release that was never shown
    /// (a copy's own release: a second copy is a second touch).
    pub fn copy_shown_value(&self) -> FfiResult<String> {
        self.grant.begin_use(Use::CopyShown)?;
        let value = self
            .grant
            .read(|item| field_text(self.grant.target.field(item)?))?;
        self.grant.record_shown_copy();
        Ok(value)
    }

    /// End this release now — on deselect, on hide. Idempotent.
    pub fn close(&self) {
        self.grant.close();
    }

    /// Whether a use would still be allowed (the vault may still refuse it if the field has gone).
    pub fn is_live(&self) -> bool {
        self.grant.is_live()
    }

    /// Seconds left before the five-minute cap ends this release.
    pub fn seconds_remaining(&self) -> u32 {
        self.grant.seconds_remaining()
    }

    /// What this release was granted for.
    pub fn purpose(&self) -> ReleasePurpose {
        self.grant.target.purpose
    }

    /// The item it is bound to.
    pub fn item_id(&self) -> String {
        self.grant.target.item_id.to_string()
    }

    /// The field it is bound to.
    pub fn field_id(&self) -> String {
        self.grant
            .target
            .field_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    }
}

/// One item's one-time code, released by one presence check ([`VaultSession::release_totp`]).
///
/// [`TotpRelease::code_at`] derives the code for the caller's own clock, so the digits and the
/// countdown ring stay drawn from one instant, exactly as `TotpCodeView` always has been. Ends as
/// [`FieldRelease`] does.
#[derive(Debug, uniffi::Object)]
pub struct TotpRelease {
    grant: Grant,
}

impl TotpRelease {
    fn code(&self, at: u64) -> FfiResult<TotpCodeView> {
        self.grant.read(|item| {
            let field = self.grant.target.field(item)?;
            TotpCodeView::build(&field.totp_generator()?, at)
        })
    }
}

#[uniffi::export]
impl TotpRelease {
    /// The code at Unix time `at`, from the field as it is in the vault now.
    ///
    /// # Errors
    ///
    /// [`FfiError::ReleaseEnded`], [`FfiError::VaultLocked`], [`FfiError::NotPresent`], and
    /// [`FfiError::Invalid`] if the field no longer holds a one-time-password setup.
    pub fn code_at(&self, at: u64) -> FfiResult<TotpCodeView> {
        self.grant.begin_use(Use::Read)?;
        self.code(at)
    }

    /// The code at `at`, for the clipboard, from a release granted to show it — no new touch
    /// (user decision 1). Recorded as `totp_copy` with `SHOWN_EARLIER`.
    ///
    /// # Errors
    ///
    /// As [`TotpRelease::code_at`], and [`FfiError::Invalid`] for a release that was never shown.
    pub fn copy_shown_code_at(&self, at: u64) -> FfiResult<TotpCodeView> {
        self.grant.begin_use(Use::CopyShown)?;
        let code = self.code(at)?;
        self.grant.record_shown_copy();
        Ok(code)
    }

    /// End this release now. Idempotent.
    pub fn close(&self) {
        self.grant.close();
    }

    /// Whether a use would still be allowed.
    pub fn is_live(&self) -> bool {
        self.grant.is_live()
    }

    /// Seconds left before the five-minute cap ends this release.
    pub fn seconds_remaining(&self) -> u32 {
        self.grant.seconds_remaining()
    }

    /// What this release was granted for.
    pub fn purpose(&self) -> ReleasePurpose {
        self.grant.target.purpose
    }

    /// The item it is bound to.
    pub fn item_id(&self) -> String {
        self.grant.target.item_id.to_string()
    }

    /// The one-time-password field it is bound to.
    pub fn field_id(&self) -> String {
        self.grant
            .target
            .field_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    }
}

/// One item's notes, released by one presence check ([`VaultSession::release_notes`]). Ends as
/// [`FieldRelease`] does.
#[derive(Debug, uniffi::Object)]
pub struct NotesRelease {
    grant: Grant,
}

impl NotesRelease {
    fn read_text(&self) -> FfiResult<String> {
        self.grant.read(|item| {
            item.notes
                .as_ref()
                .map(|n| n.expose().to_owned())
                .ok_or_else(|| FfiError::missing("notes", item.id.to_string()))
        })
    }
}

#[uniffi::export]
impl NotesRelease {
    /// The notes, as they are in the vault now.
    ///
    /// # Errors
    ///
    /// [`FfiError::ReleaseEnded`], [`FfiError::VaultLocked`], [`FfiError::NotPresent`] if the item
    /// or its notes have gone.
    pub fn text(&self) -> FfiResult<String> {
        self.grant.begin_use(Use::Read)?;
        self.read_text()
    }

    /// The notes again, for the clipboard, from a release granted to show them — no new touch.
    /// Recorded as `copy_field` (label `notes`) with `SHOWN_EARLIER`.
    ///
    /// # Errors
    ///
    /// As [`NotesRelease::text`], and [`FfiError::Invalid`] for a release that was never shown.
    pub fn copy_shown_text(&self) -> FfiResult<String> {
        self.grant.begin_use(Use::CopyShown)?;
        let text = self.read_text()?;
        self.grant.record_shown_copy();
        Ok(text)
    }

    /// End this release now. Idempotent.
    pub fn close(&self) {
        self.grant.close();
    }

    /// Whether a use would still be allowed.
    pub fn is_live(&self) -> bool {
        self.grant.is_live()
    }

    /// Seconds left before the five-minute cap ends this release.
    pub fn seconds_remaining(&self) -> u32 {
        self.grant.seconds_remaining()
    }

    /// What this release was granted for.
    pub fn purpose(&self) -> ReleasePurpose {
        self.grant.target.purpose
    }

    /// The item it is bound to.
    pub fn item_id(&self) -> String {
        self.grant.target.item_id.to_string()
    }
}

// MARK: - The release calls

#[uniffi::export]
impl VaultSession {
    /// Release one concealed field's value, behind a fresh presence check (ADR-0038).
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 2, outbound, with
    /// the fail-closed check ADR-0038 puts in front of it. One field per call and one prompt per
    /// field: showing the password and then the one-time code is two touches (user decision 1).
    ///
    /// The prompt names the field's label, the item's title and the action, sanitised. With no
    /// gate installed, nothing is asked and nothing is released.
    ///
    /// # Errors
    ///
    /// Before any prompt: [`FfiError::VaultLocked`], [`FfiError::NotPresent`] for an unknown item
    /// or field, [`FfiError::Invalid`] for a field that is not concealed (its value is already in
    /// [`crate::FieldView::value`]) or whose value is not text, [`FfiError::NoPresenceGate`],
    /// [`FfiError::PresenceBusy`] if another release is awaiting its prompt. After it:
    /// [`FfiError::PresenceCancelled`], [`FfiError::PresenceUnavailable`],
    /// [`FfiError::PresenceBusy`], [`FfiError::VaultLocked`] if the vault locked meanwhile, and
    /// [`FfiError::NotPresent`] if the item or field went.
    pub async fn release_field(
        &self,
        item_id: String,
        field_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<FieldRelease>> {
        self.releaser().field(item_id, field_id, purpose).await
    }

    /// Release an item's one-time code, behind a fresh presence check — the named TOTP field, or
    /// with `field_id` `None` the item's first one (what the list row and Quick Access ⌥⏎ need).
    ///
    /// ADR-0008 crossing 5, outbound, behind ADR-0038's check. `purpose` is
    /// [`ReleasePurpose::Reveal`] for the detail pane's live code (`totp_show`), or a copy
    /// (`totp_copy`, `quick_access_copy`); [`ReleasePurpose::EditReveal`] is refused — editing a
    /// one-time password's setup is [`VaultSession::release_field`] on the field itself.
    ///
    /// # Errors
    ///
    /// As [`VaultSession::release_field`], with [`FfiError::NotPresent`] for an item with no
    /// one-time password and [`FfiError::Invalid`] for a field whose setup does not parse.
    pub async fn release_totp(
        &self,
        item_id: String,
        field_id: Option<String>,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<TotpRelease>> {
        self.releaser().totp(item_id, field_id, purpose).await
    }

    /// Release an item's notes, behind a fresh presence check (user decision 3: every note is
    /// secret). [`ReleasePurpose::QuickAccessCopy`] is refused.
    ///
    /// # Errors
    ///
    /// As [`VaultSession::release_field`], with [`FfiError::NotPresent`] for an item with no
    /// notes.
    pub async fn release_notes(
        &self,
        item_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<NotesRelease>> {
        self.releaser().notes(item_id, purpose).await
    }
}

impl VaultSession {
    /// This session's releases: the personal vault's items.
    fn releaser(&self) -> Releaser {
        Releaser {
            handle: self.handle(),
            presence: self.presence(),
            source: Source::Personal,
        }
    }
}

impl Releaser {
    /// [`VaultSession::release_field`], for whichever vault this releaser reads.
    pub(crate) async fn field(
        &self,
        item_id: String,
        field_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<FieldRelease>> {
        let pending = self.begin(Kind::Field, &item_id, Some(&field_id), purpose)?;
        let outcome = pending.ask().await;
        let grant = self.settle(pending, outcome)?;
        Ok(Arc::new(FieldRelease { grant }))
    }

    /// [`VaultSession::release_totp`], for whichever vault this releaser reads.
    pub(crate) async fn totp(
        &self,
        item_id: String,
        field_id: Option<String>,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<TotpRelease>> {
        let pending = self.begin(Kind::Totp, &item_id, field_id.as_deref(), purpose)?;
        let outcome = pending.ask().await;
        let grant = self.settle(pending, outcome)?;
        Ok(Arc::new(TotpRelease { grant }))
    }

    /// [`VaultSession::release_notes`], for whichever vault this releaser reads.
    pub(crate) async fn notes(
        &self,
        item_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<NotesRelease>> {
        let pending = self.begin(Kind::Notes, &item_id, None, purpose)?;
        let outcome = pending.ask().await;
        let grant = self.settle(pending, outcome)?;
        Ok(Arc::new(NotesRelease { grant }))
    }

    /// Write whatever is queued, best-effort, once the caller has let the vault go.
    fn flush_best_effort(&self) {
        self.handle
            .flush_best_effort(crate::session::APP_LOCK_TIMEOUT);
    }

    /// Record a refusal decided while `vault` is borrowed, through the refusal throttle
    /// (`Presence::throttle_refusal`): queue what it says to write, let the borrow go, and write
    /// best-effort only if there was anything — a counted refusal writes nothing at all.
    fn record_refusal(
        &self,
        mut vault: crate::session::VaultRef<'_>,
        detail: &'static str,
        draft: AuditDraft,
    ) {
        let entries = self.presence.throttle_refusal(detail, draft);
        let write = !entries.is_empty();
        for entry in entries {
            vault.queue_audit(entry);
        }
        drop(vault);
        if write {
            self.flush_best_effort();
        }
    }

    /// Step 1: read the facts and register, or refuse — all before any prompt, and with every
    /// borrow ended by the time this returns.
    fn begin(
        &self,
        kind: Kind,
        item_ref: &str,
        field_ref: Option<&str>,
        purpose: ReleasePurpose,
    ) -> FfiResult<Pending> {
        let tool = tool_for(kind, purpose)?;
        // The personal vault is borrowed first, whichever vault the item is in: its audit log
        // takes the entries, and its handle then a shared vault's state is the one lock order.
        let vault =
            crate::session::VaultRef::new(self.handle.guard()).ok_or(FfiError::VaultLocked)?;
        // Exact ids only (`field_by_id`, `ItemId::parse_canonical`): a title, an id prefix or a
        // field label would make this lookup an oracle — "not found" and "ambiguous" answer
        // differently, and a trashed duplicate is enough to tell them apart — and let a relabel
        // or a colliding title point a release somewhere the caller did not name. Anything that
        // is not an id is answered exactly like an id that names nothing.
        let id =
            ItemId::parse_canonical(item_ref).ok_or_else(|| FfiError::missing("item", item_ref))?;
        let (target, reason) = self.source.read_in(&vault, &id, |item| {
            describe(kind, item, item_ref, field_ref, purpose, tool)
        })?;

        let presence = Arc::clone(&self.presence);
        let Some(gate) = presence.gate() else {
            self.record_refusal(
                vault,
                DETAIL_PRESENCE_UNAVAILABLE,
                target.entry(Outcome::Denied, DETAIL_PRESENCE_UNAVAILABLE),
            );
            return Err(FfiError::NoPresenceGate);
        };
        // Handle mutex held (`vault`), registry second: the one lock order.
        let token =
            match presence.register(target.entry(Outcome::Denied, DETAIL_PRESENCE_CANCELLED)) {
                Ok(token) => token,
                Err(RegisterRefusal::Busy) => {
                    self.record_refusal(
                        vault,
                        DETAIL_PRESENCE_BUSY,
                        target.entry(Outcome::Denied, DETAIL_PRESENCE_BUSY),
                    );
                    return Err(FfiError::PresenceBusy);
                }
                Err(RegisterRefusal::Locked) => return Err(FfiError::VaultLocked),
            };
        drop(vault);
        Ok(Pending {
            token,
            target,
            reason,
            gate,
            handle: Arc::clone(&self.handle),
            presence,
            settled: false,
        })
    }

    /// Step 3: the prompt has answered. Record it, and grant only a confirmed release whose vault
    /// is still unlocked and whose item and field still exist.
    fn settle(&self, mut pending: Pending, outcome: PresenceOutcome) -> FfiResult<Grant> {
        pending.settled = true;
        let presence = Arc::clone(&pending.presence);
        let target = pending.target.clone();

        let handle = Arc::clone(&self.handle);
        let mut guard = handle.guard();
        let Settled::Current { master_password } = presence.settle(pending.token) else {
            // A lock took this release out of the registry while the prompt was up, and has
            // already recorded it `VAULT_LOCKED`. Whatever the prompt said, nothing is released.
            return Err(FfiError::VaultLocked);
        };
        let Some(vault) = guard.as_mut() else {
            return Err(FfiError::VaultLocked);
        };
        let refusal = match outcome {
            PresenceOutcome::Confirmed => None,
            PresenceOutcome::Cancelled => {
                Some((DETAIL_PRESENCE_CANCELLED, FfiError::PresenceCancelled))
            }
            PresenceOutcome::Unavailable => {
                Some((DETAIL_PRESENCE_UNAVAILABLE, FfiError::PresenceUnavailable))
            }
            PresenceOutcome::Busy => Some((DETAIL_PRESENCE_BUSY, FfiError::PresenceBusy)),
        };
        if let Some((detail, error)) = refusal {
            // Throttled (`Presence::throttle_refusal`): the first refusal of a reason in a minute
            // is written, the rest only counted — a refusal must not be a way to rewrite the vault
            // file at will.
            let entries = presence.throttle_refusal(detail, target.entry(Outcome::Denied, detail));
            let write = !entries.is_empty();
            for entry in entries {
                vault.queue_audit(entry);
            }
            drop(guard);
            if write {
                self.flush_best_effort();
            }
            return Err(error);
        }

        // Confirmed. Check against the vault as it is now, not as it was when the prompt went up:
        // the item, the field or the notes may have been deleted, from this window or another
        // process. A person said yes to something that is no longer there — recorded as a
        // failure, so the log does not end at a prompt nobody can see the answer to.
        let still_there = self
            .source
            .read_in(vault, &target.item_id, |item| match target.kind {
                Kind::Field | Kind::Totp => target.field(item).map(|_| ()),
                Kind::Notes if item.has_notes() => Ok(()),
                Kind::Notes => Err(FfiError::missing("notes", item.id.to_string())),
            });
        if let Err(gone) = still_there {
            vault.queue_audit(target.entry(Outcome::Failed, DETAIL_GONE_DURING_PROMPT));
            drop(guard);
            self.flush_best_effort();
            return Err(gone);
        }
        let detail = if master_password {
            DETAIL_PRESENCE_CONFIRMED_MASTER_PASSWORD
        } else {
            DETAIL_PRESENCE_CONFIRMED
        };
        // Refusals counted but not yet written go first, so the log shows a burst of them before
        // the grant it ended in.
        for summary in presence.drain_refusal_counts() {
            vault.queue_audit(summary);
        }
        vault.queue_audit(target.entry(Outcome::Allowed, detail));
        drop(guard);
        self.flush_best_effort();

        Ok(Grant {
            expires_at: presence.now() + RELEASE_TTL,
            target,
            handle,
            source: self.source.clone(),
            presence,
            state: Mutex::new(GrantState::default()),
        })
    }
}

/// What a release of `kind` of `item` is for, and the sentence its prompt shows — or why it
/// cannot be asked for at all.
fn describe(
    kind: Kind,
    item: &Item,
    item_ref: &str,
    field_ref: Option<&str>,
    purpose: ReleasePurpose,
    tool: &'static str,
) -> FfiResult<(Target, String)> {
    let mut noun = "concealed field";
    let (field_id, label) = match kind {
        Kind::Field => {
            let reference = field_ref.expect("release_field always names a field");
            let field = field_by_id(item, reference)?;
            noun = presence::field_noun(item, field);
            let FieldValue::Secret(secret) = &field.value else {
                return Err(FfiError::invalid(
                    "that field is not concealed; its value is already on the item",
                ));
            };
            if secret.expose_str().is_none() {
                return Err(FfiError::invalid(
                    "this value is not text and cannot be shown",
                ));
            }
            (Some(field.id), field.label.clone())
        }
        Kind::Totp => {
            let field = match field_ref {
                Some(reference) => field_by_id(item, reference)?,
                None => item
                    .totp_field()
                    .ok_or_else(|| FfiError::missing("one-time password", item_ref))?,
            };
            // Refuse a field that cannot produce a code before anyone is asked to touch.
            field.totp_generator()?;
            (Some(field.id), field.label.clone())
        }
        Kind::Notes => {
            if !item.has_notes() {
                return Err(FfiError::missing("notes", item_ref));
            }
            (None, NOTES_LABEL.to_owned())
        }
    };
    let subject = match kind {
        Kind::Field => Subject::Field {
            noun,
            title: &item.title,
            label: &label,
        },
        Kind::Totp => Subject::Totp { title: &item.title },
        Kind::Notes => Subject::Notes { title: &item.title },
    };
    let reason = presence::reason(&subject, purpose);
    Ok((
        Target {
            kind,
            purpose,
            item_id: item.id,
            field_id,
            label,
            tool,
        },
        reason,
    ))
}
