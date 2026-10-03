//! `VaultSession` — every method — and the free functions about vault files.
//!
//! Every function taking a `session` requires it to be a live handle from one of the
//! `kgs_session_*` constructors that has not been passed to [`kgs_session_free`]; every slice,
//! `out` and `error` follows the module rules. The `# Safety` sections below say only what is
//! particular to each function.

use std::sync::Arc;

use super::{
    KgsAuditRowArray, KgsBuffer, KgsCategoryInfo, KgsCategoryInfoArray, KgsEnvironmentView,
    KgsEnvironmentViewArray, KgsFieldView, KgsItemDraft, KgsItemFilter, KgsItemSort, KgsItemView,
    KgsItemViewArray, KgsKeepAppVersionOutcomeTag, KgsMasterPasswordCheckTag, KgsOptBuffer,
    KgsOptSlice, KgsOptU32, KgsSession, KgsSidebarCounts, KgsSlice, KgsStatus, KgsUnlockKind,
    KgsVaultConflictKind, KgsVaultView, KgsVaultViewArray, Release, call, free, read,
    session as live, slot,
};
use crate::agent::AuditDurabilityView;
use crate::{
    DivergedFileView, FfiResult, KeepAppVersionOutcome, MasterPasswordCheck,
    VaultConflictDetailsView, VaultSession,
};

fn into_handle(session: Arc<VaultSession>) -> *mut KgsSession {
    Box::into_raw(Box::new(KgsSession { session }))
}

// -------------------------------------------------------------------------------------------
// Vault files
// -------------------------------------------------------------------------------------------

/// [`crate::vault_exists`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_vault_exists(
    path: KgsSlice,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(crate::vault_exists(path.string()?)));
            Ok(())
        })
    }
}

/// [`crate::default_vault_path`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_default_vault_path(
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(crate::default_vault_path()));
            Ok(())
        })
    }
}

/// [`crate::platform_slot_id`], read from the header without unlocking.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_platform_slot_id(
    path: KgsSlice,
    out: *mut KgsOptBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsOptBuffer::from_string(crate::platform_slot_id(
                path.string()?,
            )?));
            Ok(())
        })
    }
}

/// [`crate::platform_wrapped_key`]: the keystore's opaque ciphertext, raw bytes, for Windows Hello
/// (or Touch ID) to unwrap.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_platform_wrapped_key(
    path: KgsSlice,
    out: *mut KgsOptBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsOptBuffer::from_vec(crate::platform_wrapped_key(
                path.string()?,
            )?));
            Ok(())
        })
    }
}

/// [`crate::PlatformSlotInfo`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsPlatformSlotInfo {
    /// The header's vault-file id, raw bytes.
    pub vault_id: KgsBuffer,
    /// The platform slot's id, when there is one.
    pub slot_id: KgsOptBuffer,
    /// The platform slot's opaque wrapped key, raw bytes, when there is one.
    pub wrapped_key: KgsOptBuffer,
}

impl Release for KgsPlatformSlotInfo {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.vault_id.release();
            self.slot_id.release();
            self.wrapped_key.release();
        }
    }
}

/// [`crate::platform_slot_info`]: the vault-file id and the platform slot, from one read of the
/// header. Free with [`kgs_platform_slot_info_free`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_platform_slot_info(
    path: KgsSlice,
    out: *mut KgsPlatformSlotInfo,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let info = crate::platform_slot_info(path.string()?)?;
            out.write(KgsPlatformSlotInfo {
                vault_id: KgsBuffer::from_vec(info.vault_id),
                slot_id: KgsOptBuffer::from_string(info.slot_id),
                wrapped_key: KgsOptBuffer::from_vec(info.wrapped_key),
            });
            Ok(())
        })
    }
}

/// Free a [`KgsPlatformSlotInfo`].
///
/// # Safety
///
/// `info` is null, or a record [`kgs_platform_slot_info`] wrote and nothing has freed since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_platform_slot_info_free(info: *mut KgsPlatformSlotInfo) {
    // SAFETY: forwarded to the caller.
    unsafe { free(info) }
}

/// [`crate::category_catalog`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_category_catalog(
    out: *mut KgsCategoryInfoArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsCategoryInfoArray::collect(
                crate::category_catalog(),
                KgsCategoryInfo::new,
            ));
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// Constructors and lifetime
// -------------------------------------------------------------------------------------------

/// [`VaultSession::create`]. An absent `kdf_m_kib` / `kdf_t` is UniFFI's `None`: the desktop
/// profile. ADR-0008 crossing 1.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_create(
    path: KgsSlice,
    master_password: KgsSlice,
    vault_name: KgsSlice,
    kdf_m_kib: KgsOptU32,
    kdf_t: KgsOptU32,
    out: *mut *mut KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = VaultSession::create(
                path.string()?,
                master_password.string()?,
                vault_name.string()?,
                kdf_m_kib.option(),
                kdf_t.option(),
            )?;
            out.write(into_handle(session));
            Ok(())
        })
    }
}

/// [`VaultSession::unlock_with_password`]. ADR-0008 crossing 1.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_unlock_with_password(
    path: KgsSlice,
    master_password: KgsSlice,
    out: *mut *mut KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session =
                VaultSession::unlock_with_password(path.string()?, master_password.string()?)?;
            out.write(into_handle(session));
            Ok(())
        })
    }
}

/// [`VaultSession::unlock_with_recovery_code`]. ADR-0008 crossing 1.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_unlock_with_recovery_code(
    path: KgsSlice,
    code: KgsSlice,
    out: *mut *mut KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = VaultSession::unlock_with_recovery_code(path.string()?, code.string()?)?;
            out.write(into_handle(session));
            Ok(())
        })
    }
}

/// [`VaultSession::unlock_with_vault_key`]. ADR-0008 crossing 4: `vault_key` is raw bytes and is
/// never interpreted as text. The one owned copy made here (`to_vec`) is moved into
/// `unlock_with_vault_key`, which holds it in a `Zeroizing` and wipes it before returning; the
/// caller's own buffer is the caller's to clear.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_unlock_with_vault_key(
    path: KgsSlice,
    vault_key: KgsSlice,
    out: *mut *mut KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session =
                VaultSession::unlock_with_vault_key(path.string()?, vault_key.bytes()?.to_vec())?;
            out.write(into_handle(session));
            Ok(())
        })
    }
}

/// Release the caller's reference. When it is the last one, the session drops, which locks it if
/// [`kgs_session_lock`] has not already — but lock explicitly first: that is the moment the
/// release in flight is refused and the key is wiped, whoever else still holds a reference.
///
/// # Safety
///
/// `session` must be null or a pointer from a `kgs_session_*` constructor that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_free(session: *mut KgsSession) {
    if !session.is_null() {
        // SAFETY: a pointer `into_handle` produced, freed exactly once — the caller's promise.
        drop(unsafe { Box::from_raw(session) });
    }
}

// -------------------------------------------------------------------------------------------
// Session state
// -------------------------------------------------------------------------------------------

/// [`VaultSession::lock`]: lock now — wipe the key, end every release, and answer a release
/// whose presence prompt is still up `VAULT_LOCKED`, whatever the prompt then says (ADR-0038 §4).
/// Idempotent. Every later call on the session answers [`KgsStatus::VaultLocked`] (or its locked
/// default); the handle itself stays valid until [`kgs_session_free`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_lock(
    session: *const KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.lock();
            Ok(())
        })
    }
}

/// [`VaultSession::is_unlocked`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_is_unlocked(
    session: *const KgsSession,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live(session)?.is_unlocked()));
            Ok(())
        })
    }
}

/// [`VaultSession::sync`]: re-read the vault file if another writer changed it. `out` is 1 if
/// anything was picked up.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_sync(
    session: *const KgsSession,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live(session)?.sync()));
            Ok(())
        })
    }
}

/// [`DivergedFileView`], coming out — and, borrowed back, going in inside a
/// [`KgsVaultConflictDetails`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KgsDivergedFile {
    /// Audit entries the file has that this session does not.
    pub audit_entries_only_in_file: u64,
    /// Items only in the file.
    pub items_only_in_file: u64,
    /// Items in both that differ.
    pub items_differing: u64,
    /// Environments only in the file.
    pub environments_only_in_file: u64,
    /// Environments in both that differ.
    pub environments_differing: u64,
    /// Logical vaults only in the file, or differing.
    pub vaults_only_in_file_or_differing: u64,
    /// 0 or 1.
    pub master_password_differs: u8,
    /// 0 or 1.
    pub recovery_code_differs: u8,
    /// 0 or 1: the platform slot (Touch ID or Windows Hello) differs.
    pub touch_id_differs: u8,
}

impl KgsDivergedFile {
    fn new(d: DivergedFileView) -> Self {
        Self {
            audit_entries_only_in_file: d.audit_entries_only_in_file,
            items_only_in_file: d.items_only_in_file,
            items_differing: d.items_differing,
            environments_only_in_file: d.environments_only_in_file,
            environments_differing: d.environments_differing,
            vaults_only_in_file_or_differing: d.vaults_only_in_file_or_differing,
            master_password_differs: u8::from(d.master_password_differs),
            recovery_code_differs: u8::from(d.recovery_code_differs),
            touch_id_differs: u8::from(d.touch_id_differs),
        }
    }

    fn to_ffi(self) -> DivergedFileView {
        DivergedFileView {
            audit_entries_only_in_file: self.audit_entries_only_in_file,
            items_only_in_file: self.items_only_in_file,
            items_differing: self.items_differing,
            environments_only_in_file: self.environments_only_in_file,
            environments_differing: self.environments_differing,
            vaults_only_in_file_or_differing: self.vaults_only_in_file_or_differing,
            master_password_differs: self.master_password_differs != 0,
            recovery_code_differs: self.recovery_code_differs != 0,
            touch_id_differs: self.touch_id_differs != 0,
        }
    }
}

/// [`VaultConflictDetailsView`]. Free with [`kgs_vault_conflict_details_free`]; hand it back,
/// unmodified, to [`kgs_session_keep_app_version_over_conflict`] as what the person confirmed.
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsVaultConflictDetails {
    /// A [`KgsVaultConflictKind`].
    pub kind: u32,
    /// A short fingerprint of the file on disk, when there is one to read.
    pub file_fingerprint: KgsOptBuffer,
    /// Audit entries this session holds.
    pub session_audit_entries: u64,
    /// 0 or 1: whether `diverged` is meaningful.
    pub has_diverged: u8,
    /// For a diverged file, what it has that this session would overwrite; all-zero otherwise.
    pub diverged: KgsDivergedFile,
}

impl KgsVaultConflictDetails {
    fn new(d: VaultConflictDetailsView) -> Self {
        Self {
            kind: KgsVaultConflictKind::tag(d.kind),
            file_fingerprint: KgsOptBuffer::from_string(d.file_fingerprint),
            session_audit_entries: d.session_audit_entries,
            has_diverged: u8::from(d.diverged.is_some()),
            diverged: d.diverged.map(KgsDivergedFile::new).unwrap_or_default(),
        }
    }

    /// # Safety
    ///
    /// `file_fingerprint` must be all-zero or as this library wrote it.
    unsafe fn to_ffi(&self) -> FfiResult<VaultConflictDetailsView> {
        let file_fingerprint = if self.file_fingerprint.present == 0 {
            None
        } else {
            let value = &self.file_fingerprint.value;
            // SAFETY: a buffer this library wrote and the caller has not modified — its promise.
            let slice = KgsSlice {
                ptr: value.ptr,
                len: value.len,
            };
            Some(unsafe { slice.string() }?)
        };
        Ok(VaultConflictDetailsView {
            kind: KgsVaultConflictKind::parse(self.kind)?,
            file_fingerprint,
            session_audit_entries: self.session_audit_entries,
            diverged: (self.has_diverged != 0).then(|| self.diverged.to_ffi()),
        })
    }
}

impl Release for KgsVaultConflictDetails {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.file_fingerprint.release() };
        *self = Self::default();
    }
}

/// An optional [`KgsVaultConflictDetails`]. Free `value` with [`kgs_vault_conflict_details_free`]
/// either way.
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsOptVaultConflictDetails {
    /// 1 if there is a conflict, 0 for `None`.
    pub present: u8,
    /// The details; all-zero when absent.
    pub value: KgsVaultConflictDetails,
}

/// [`KeepAppVersionOutcome`]: `tag` is a [`KgsKeepAppVersionOutcomeTag`], and `details` is
/// meaningful only for `FileChangedAgain`. Free with [`kgs_keep_app_version_outcome_free`].
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsKeepAppVersionOutcome {
    /// A [`KgsKeepAppVersionOutcomeTag`].
    pub tag: u32,
    /// For `FileChangedAgain`, the file as it is now; all-zero otherwise.
    pub details: KgsVaultConflictDetails,
}

impl Release for KgsKeepAppVersionOutcome {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.details.release() };
        self.tag = 0;
    }
}

/// [`VaultSession::conflict`]: the kind of conflict this session has hit, as a
/// [`KgsVaultConflictKind`] tag, or absent.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_conflict(
    session: *const KgsSession,
    out: *mut KgsOptU32,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let kind = live(session)?.conflict().map(KgsVaultConflictKind::tag);
            out.write(KgsOptU32::from_option(kind));
            Ok(())
        })
    }
}

/// [`VaultSession::conflict_details`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_conflict_details(
    session: *const KgsSession,
    out: *mut KgsOptVaultConflictDetails,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let details = live(session)?.conflict_details()?;
            out.write(match details {
                Some(details) => KgsOptVaultConflictDetails {
                    present: 1,
                    value: KgsVaultConflictDetails::new(details),
                },
                None => KgsOptVaultConflictDetails::default(),
            });
            Ok(())
        })
    }
}

/// [`VaultSession::keep_app_version_over_conflict`]. `confirmed` is the
/// [`KgsVaultConflictDetails`] the person was shown, exactly as it came out.
///
/// # Safety
///
/// Module rules; `session` live; `confirmed` readable, and as this library wrote it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_keep_app_version_over_conflict(
    session: *const KgsSession,
    confirmed: *const KgsVaultConflictDetails,
    out: *mut KgsKeepAppVersionOutcome,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let confirmed = read(confirmed, "confirmed conflict")?.to_ffi()?;
            let outcome = live(session)?.keep_app_version_over_conflict(confirmed)?;
            use KgsKeepAppVersionOutcomeTag as T;
            out.write(match outcome {
                KeepAppVersionOutcome::Overwritten => KgsKeepAppVersionOutcome {
                    tag: T::Overwritten as u32,
                    details: KgsVaultConflictDetails::default(),
                },
                KeepAppVersionOutcome::NoLongerInConflict => KgsKeepAppVersionOutcome {
                    tag: T::NoLongerInConflict as u32,
                    details: KgsVaultConflictDetails::default(),
                },
                KeepAppVersionOutcome::FileChangedAgain { details } => KgsKeepAppVersionOutcome {
                    tag: T::FileChangedAgain as u32,
                    details: KgsVaultConflictDetails::new(details),
                },
            });
            Ok(())
        })
    }
}

/// [`VaultSession::note_reopened_after_conflict`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_note_reopened_after_conflict(
    session: *const KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.note_reopened_after_conflict();
            Ok(())
        })
    }
}

/// Free a [`KgsVaultConflictDetails`] — including the `value` of a
/// [`KgsOptVaultConflictDetails`], present or not.
///
/// # Safety
///
/// As [`kgs_platform_slot_info_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_vault_conflict_details_free(details: *mut KgsVaultConflictDetails) {
    // SAFETY: forwarded to the caller.
    unsafe { free(details) }
}

/// Free a [`KgsKeepAppVersionOutcome`].
///
/// # Safety
///
/// As [`kgs_platform_slot_info_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_keep_app_version_outcome_free(outcome: *mut KgsKeepAppVersionOutcome) {
    // SAFETY: forwarded to the caller.
    unsafe { free(outcome) }
}

/// [`VaultSession::take_recovery_code`]: present once, after `kgs_session_create`, and absent
/// from then on.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_take_recovery_code(
    session: *const KgsSession,
    out: *mut KgsOptBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsOptBuffer::from_string(
                live(session)?.take_recovery_code(),
            ));
            Ok(())
        })
    }
}

/// [`VaultSession::path`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_path(
    session: *const KgsSession,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(live(session)?.path()));
            Ok(())
        })
    }
}

/// [`VaultSession::unlocked_by`], as a [`KgsUnlockKind`] tag.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_unlocked_by(
    session: *const KgsSession,
    out: *mut u32,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsUnlockKind::tag(live(session)?.unlocked_by()));
            Ok(())
        })
    }
}

/// [`VaultSession::vaults`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_vaults(
    session: *const KgsSession,
    out: *mut KgsVaultViewArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsVaultViewArray::collect(
                live(session)?.vaults(),
                KgsVaultView::new,
            ));
            Ok(())
        })
    }
}

/// [`VaultSession::set_vault_agent_visible`]. `out` is 0 or 1: the core's "the logical vault was
/// found" — always 1 on success, because an unknown id is an error first.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_vault_agent_visible(
    session: *const KgsSession,
    vault_id: KgsSlice,
    visible: u8,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let changed =
                live(session)?.set_vault_agent_visible(vault_id.string()?, visible != 0)?;
            out.write(u8::from(changed));
            Ok(())
        })
    }
}

/// [`VaultSession::default_vault_id`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_default_vault_id(
    session: *const KgsSession,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(live(session)?.default_vault_id()?));
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// Items
// -------------------------------------------------------------------------------------------

/// [`VaultSession::list_items`]: one sidebar section, optionally searched, sorted by a
/// [`KgsItemSort`] tag.
///
/// # Safety
///
/// Module rules; `session` live; `filter` valid for a read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_list_items(
    session: *const KgsSession,
    filter: *const KgsItemFilter,
    query: KgsOptSlice,
    sort: u32,
    out: *mut KgsItemViewArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let filter = read(filter, "filter")?.to_ffi()?;
            let items =
                live(session)?.list_items(filter, query.string()?, KgsItemSort::parse(sort)?);
            out.write(KgsItemViewArray::collect(items, KgsItemView::new));
            Ok(())
        })
    }
}

/// [`VaultSession::item`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_item(
    session: *const KgsSession,
    item_id: KgsSlice,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsItemView::new(live(session)?.item(item_id.string()?)?));
            Ok(())
        })
    }
}

/// [`VaultSession::sidebar_counts`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_sidebar_counts(
    session: *const KgsSession,
    out: *mut KgsSidebarCounts,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsSidebarCounts::new(live(session)?.sidebar_counts()));
            Ok(())
        })
    }
}

/// [`VaultSession::create_item`]. An absent `vault_id` is the default logical vault.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_create_item(
    session: *const KgsSession,
    vault_id: KgsOptSlice,
    category: KgsSlice,
    title: KgsSlice,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.create_item(
                vault_id.string()?,
                category.string()?,
                title.string()?,
            )?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::save_item`]. ADR-0008 crossing 2, inbound: every field value in `draft`.
///
/// # Safety
///
/// Module rules; `session` live; `draft` valid for a read, with every slice and list inside it
/// satisfying its type's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_save_item(
    session: *const KgsSession,
    draft: *const KgsItemDraft,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let draft = read(draft, "item draft")?.to_ffi()?;
            out.write(KgsItemView::new(live(session)?.save_item(draft)?));
            Ok(())
        })
    }
}

/// [`VaultSession::set_favorite`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_favorite(
    session: *const KgsSession,
    item_id: KgsSlice,
    favorite: u8,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.set_favorite(item_id.string()?, favorite != 0)?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::set_archived`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_archived(
    session: *const KgsSession,
    item_id: KgsSlice,
    archived: u8,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.set_archived(item_id.string()?, archived != 0)?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::set_trashed`]. A soft delete.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_trashed(
    session: *const KgsSession,
    item_id: KgsSlice,
    trashed: u8,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.set_trashed(item_id.string()?, trashed != 0)?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::set_agent_visible`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_agent_visible(
    session: *const KgsSession,
    item_id: KgsSlice,
    visible: u8,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.set_agent_visible(item_id.string()?, visible != 0)?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::set_field_agent_visible`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_field_agent_visible(
    session: *const KgsSession,
    item_id: KgsSlice,
    field_id: KgsSlice,
    visible: u8,
    out: *mut KgsItemView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let view = live(session)?.set_field_agent_visible(
                item_id.string()?,
                field_id.string()?,
                visible != 0,
            )?;
            out.write(KgsItemView::new(view));
            Ok(())
        })
    }
}

/// [`VaultSession::delete_item`]. Permanent, and only for an item still in the Trash and still
/// at `revision` — the [`KgsItemView::revision`] of the row the person chose — so an item
/// restored or changed elsewhere meanwhile is refused as [`KgsStatus::ItemChangedElsewhere`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_delete_item(
    session: *const KgsSession,
    item_id: KgsSlice,
    revision: KgsSlice,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.delete_item(item_id.string()?, revision.string()?)
        })
    }
}

/// [`VaultSession::field`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_field(
    session: *const KgsSession,
    item_id: KgsSlice,
    field_id: KgsSlice,
    out: *mut KgsFieldView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let field = live(session)?.field(item_id.string()?, field_id.string()?)?;
            out.write(KgsFieldView::new(field));
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// Environments
// -------------------------------------------------------------------------------------------

/// [`VaultSession::environments`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_environments(
    session: *const KgsSession,
    out: *mut KgsEnvironmentViewArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsEnvironmentViewArray::collect(
                live(session)?.environments(),
                KgsEnvironmentView::new,
            ));
            Ok(())
        })
    }
}

/// [`VaultSession::environment`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_environment(
    session: *const KgsSession,
    environment_id: KgsSlice,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?.environment(environment_id.string()?)?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::create_environment`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_create_environment(
    session: *const KgsSession,
    name: KgsSlice,
    description: KgsOptSlice,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?.create_environment(name.string()?, description.string()?)?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::set_environment_agent_visible`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_environment_agent_visible(
    session: *const KgsSession,
    environment_id: KgsSlice,
    visible: u8,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?
                .set_environment_agent_visible(environment_id.string()?, visible != 0)?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::set_variable_value`]. ADR-0008 crossing 2, inbound: `value` is the secret.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_variable_value(
    session: *const KgsSession,
    environment_id: KgsSlice,
    name: KgsSlice,
    value: KgsSlice,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?.set_variable_value(
                environment_id.string()?,
                name.string()?,
                value.string()?,
            )?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::bind_variable`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_bind_variable(
    session: *const KgsSession,
    environment_id: KgsSlice,
    name: KgsSlice,
    item_id: KgsSlice,
    field_id: KgsSlice,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?.bind_variable(
                environment_id.string()?,
                name.string()?,
                item_id.string()?,
                field_id.string()?,
            )?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::remove_variable`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_remove_variable(
    session: *const KgsSession,
    environment_id: KgsSlice,
    name: KgsSlice,
    out: *mut KgsEnvironmentView,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let env = live(session)?.remove_variable(environment_id.string()?, name.string()?)?;
            out.write(KgsEnvironmentView::new(env));
            Ok(())
        })
    }
}

/// [`VaultSession::delete_environment`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_delete_environment(
    session: *const KgsSession,
    environment_id: KgsSlice,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.delete_environment(environment_id.string()?)
        })
    }
}

// -------------------------------------------------------------------------------------------
// Audit
// -------------------------------------------------------------------------------------------

/// [`VaultSession::audit_page`], newest first.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_audit_page(
    session: *const KgsSession,
    limit: u32,
    offset: u32,
    out: *mut KgsAuditRowArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsAuditRowArray::collect(
                live(session)?.audit_page(limit, offset),
                super::KgsAuditRow::new,
            ));
            Ok(())
        })
    }
}

/// [`VaultSession::audit_count`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_audit_count(
    session: *const KgsSession,
    out: *mut u32,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(live(session)?.audit_count());
            Ok(())
        })
    }
}

/// [`VaultSession::audit_intact`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_audit_intact(
    session: *const KgsSession,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live(session)?.audit_intact()));
            Ok(())
        })
    }
}

/// [`AuditDurabilityView`], going out. Free with [`kgs_audit_durability_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsAuditDurability {
    /// How many appended audit entries have not yet survived a successful save.
    pub unsaved_entries: u32,
    /// The most recent save failure, value-free; absent when none is outstanding.
    pub last_error: KgsOptBuffer,
}

impl Release for KgsAuditDurability {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.last_error.release() };
    }
}

/// [`VaultSession::audit_durability`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_audit_durability(
    session: *const KgsSession,
    out: *mut KgsAuditDurability,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let AuditDurabilityView {
                unsaved_entries,
                last_error,
            } = live(session)?.audit_durability();
            out.write(KgsAuditDurability {
                unsaved_entries,
                last_error: KgsOptBuffer::from_string(last_error),
            });
            Ok(())
        })
    }
}

/// Free a [`KgsAuditDurability`].
///
/// # Safety
///
/// `durability` must be null or point to a record this library wrote, or one already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_audit_durability_free(durability: *mut KgsAuditDurability) {
    // SAFETY: forwarded to the caller.
    unsafe { free(durability) }
}

// -------------------------------------------------------------------------------------------
// Credentials and the platform slot
// -------------------------------------------------------------------------------------------

/// [`VaultSession::change_master_password`]. ADR-0008 crossing 1.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_change_master_password(
    session: *const KgsSession,
    new_password: KgsSlice,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.change_master_password(new_password.string()?)
        })
    }
}

/// [`MasterPasswordCheck`]: `tag` is a [`KgsMasterPasswordCheckTag`]; `retry_after_ms` is zero
/// for `Verified`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KgsMasterPasswordCheck {
    /// A [`KgsMasterPasswordCheckTag`].
    pub tag: u32,
    /// For `Wrong` and `Throttled`: milliseconds until an attempt will be checked.
    pub retry_after_ms: u64,
}

impl KgsMasterPasswordCheck {
    fn new(check: MasterPasswordCheck) -> Self {
        use KgsMasterPasswordCheckTag as T;
        match check {
            MasterPasswordCheck::Verified => Self {
                tag: T::Verified as u32,
                retry_after_ms: 0,
            },
            MasterPasswordCheck::Wrong { retry_after_ms } => Self {
                tag: T::Wrong as u32,
                retry_after_ms,
            },
            MasterPasswordCheck::Throttled { retry_after_ms } => Self {
                tag: T::Throttled as u32,
                retry_after_ms,
            },
        }
    }
}

/// [`VaultSession::verify_master_password`]: whether `master_password` opens this unlocked vault,
/// checked in memory, never against the file — rate limited and audited per session (ADR-0038
/// user decision 7). The one master-password check the app has: the presence gate's fallback
/// and the approval sheet's alike. ADR-0008 crossing 1.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_verify_master_password(
    session: *const KgsSession,
    master_password: KgsSlice,
    out: *mut KgsMasterPasswordCheck,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let check = live(session)?.verify_master_password(master_password.string()?)?;
            out.write(KgsMasterPasswordCheck::new(check));
            Ok(())
        })
    }
}

/// [`VaultSession::vault_file_id_bytes`]: the header's vault-file id, raw bytes, from memory.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_vault_file_id_bytes(
    session: *const KgsSession,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_vec(live(session)?.vault_file_id_bytes()));
            Ok(())
        })
    }
}

/// [`VaultSession::vault_file_id`]: the same id, hex. Still answers after a lock.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_vault_file_id(
    session: *const KgsSession,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(live(session)?.vault_file_id()));
            Ok(())
        })
    }
}

/// [`VaultSession::has_platform_slot`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_has_platform_slot(
    session: *const KgsSession,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live(session)?.has_platform_slot()));
            Ok(())
        })
    }
}

/// [`VaultSession::platform_slot_id`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_platform_slot_id(
    session: *const KgsSession,
    out: *mut KgsOptBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsOptBuffer::from_string(live(session)?.platform_slot_id()));
            Ok(())
        })
    }
}

/// [`VaultSession::export_vault_key_for_platform_wrapping`]. ADR-0008 crossing 3, outbound: 32
/// raw bytes, which the caller clears and returns to `kgs_buffer_free` as soon as the platform
/// keystore has wrapped them.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_export_vault_key(
    session: *const KgsSession,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let key = live(session)?.export_vault_key_for_platform_wrapping();
            out.write(KgsBuffer::from_vec(key));
            Ok(())
        })
    }
}

/// [`VaultSession::install_platform_slot`]. `wrapped_key` is the keystore's opaque ciphertext,
/// raw bytes.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_install_platform_slot(
    session: *const KgsSession,
    slot_id: KgsSlice,
    label: KgsSlice,
    wrapped_key: KgsSlice,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            live(session)?.install_platform_slot(
                slot_id.string()?,
                label.string()?,
                wrapped_key.bytes()?.to_vec(),
            )
        })
    }
}

/// [`VaultSession::remove_platform_slot`]. `out` is 0 or 1: whether there was one.
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_remove_platform_slot(
    session: *const KgsSession,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live(session)?.remove_platform_slot()?));
            Ok(())
        })
    }
}

/// [`VaultSession::save`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_save(
    session: *const KgsSession,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe { call(error, || live(session)?.save()) }
}
