//! The presence gate and the three presence-gated releases (ADR-0038), across the C ABI.
//!
//! # Why a callback, and why it cannot be used to skip the gate
//!
//! On the UniFFI side the gate is an async foreign trait, [`PresenceGate`], that Swift implements
//! with `LocalAuthentication`. An async foreign trait does not cross a hand-written C ABI, so here
//! the gate is one C function pointer, [`kgs_session_set_presence_gate`]'s `confirm`, which the
//! Windows app implements with Windows Hello (`UserConsentVerifier`). Everything else is the same
//! Rust the Swift app runs: this crate still builds and sanitises the prompt's sentence, still
//! allows one release in flight at a time, still re-reads the vault after the answer, still
//! refuses a release whose prompt was up when the vault locked, and still audits every grant and
//! refusal. C# answers exactly one question — did a person just confirm *this sentence* — and
//! never sees a value until Rust has decided to hand one out.
//!
//! It is the ADR-0003 rule "no foreign callbacks" bent in the narrowest way that keeps the
//! guarantee: the callback runs **synchronously, on the thread that called the release**, inside
//! that call. Rust never starts a thread that calls into C#, never keeps a callback pending after
//! the call that raised it returns, and never calls it for anything but a release.
//!
//! It fails closed at every step:
//!
//! * **No gate, no release.** Until [`kgs_session_set_presence_gate`] succeeds, every
//!   `kgs_session_release_*` answers [`KgsStatus::NoPresenceGate`] without asking anyone. A null
//!   `confirm` is refused, so it installs nothing.
//! * **Once per session.** A second install is refused and the first gate stays, so nothing that
//!   runs later can swap in a gate that always says yes.
//! * **Only `Confirmed` releases.** The callback returns a [`KgsPresenceOutcome`] tag; any value
//!   that is not one of those tags is read as `Cancelled`.
//!
//! Stated plainly, as ADR-0037 and ADR-0038 state it for Swift: Rust cannot see whether C# really
//! asked Windows Hello before returning `Confirmed`. That half rests on the app's one gate
//! implementation, exactly as it rests on `LocalAuthenticationGate` on macOS.
//!
//! # Threading
//!
//! A `kgs_session_release_*` call blocks its thread for as long as the prompt is up — it is a
//! person deciding — so call it from a background thread, never the UI thread. The callback is
//! invoked on that same thread; if it needs the UI thread to show the prompt, it must hand the
//! prompt to the UI thread and wait for the answer, not call back into anything that waits on the
//! blocked thread. No vault lock is held while it runs (ADR-0038 §3), so the callback may call
//! [`crate::capi::kgs_session_verify_master_password`] — the master-password fallback, ADR-0038
//! user decision 7 — on the same session, which is what marks the waiting release as granted by
//! the master password rather than by Windows Hello.
//!
//! # Handles
//!
//! A release is an opaque [`KgsFieldRelease`], [`KgsTotpRelease`] or [`KgsNotesRelease`]: one
//! strong reference to the Rust object, freed with its own `*_free`. It holds no value; every read
//! goes back to the vault and is refused once the release has ended (closed, five minutes,
//! locked, or a copy's one use).

use std::ffi::c_void;
use std::sync::Arc;

use super::{
    KgsBuffer, KgsPresenceOutcome, KgsReleasePurpose, KgsSlice, KgsStatus, KgsTotpCode, call,
    session as live, slot,
};
use crate::{
    FfiError, FfiResult, FieldRelease, NotesRelease, PresenceGate, PresenceOutcome, TotpRelease,
};

/// The Windows app's presence check: the C function behind a [`PresenceGate`].
///
/// # Contract for the implementation
///
/// The same one `PresenceGate` states for Swift: a fresh Windows Hello check every call, no reuse
/// of an earlier verification, `Confirmed` only for a verification that completed, `Busy` rather
/// than waiting when another prompt is already up, and never an exception or a panic across this
/// boundary — catch everything and answer `Cancelled` or `Unavailable`.
struct CallbackGate {
    confirm: unsafe extern "C" fn(context: *mut c_void, reason: KgsSlice) -> u32,
    context: *mut c_void,
}

// SAFETY: [`kgs_session_set_presence_gate`]'s caller promises that `confirm` may be called from
// any thread, concurrently, with `context`, for as long as the session lives. The pointer is never
// dereferenced by Rust, only handed back to that function.
unsafe impl Send for CallbackGate {}
// SAFETY: as above.
unsafe impl Sync for CallbackGate {}

#[async_trait::async_trait]
impl PresenceGate for CallbackGate {
    async fn confirm(&self, reason: String) -> PresenceOutcome {
        let bytes = reason.as_bytes();
        let slice = KgsSlice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        };
        // SAFETY: `confirm` and `context` are what the installer handed over, under the contract
        // on `kgs_session_set_presence_gate`; `slice` borrows `reason`, alive for the whole call.
        let tag = unsafe { (self.confirm)(self.context, slice) };
        // Anything but a known tag is a bug on the other side, and a bug must never release.
        KgsPresenceOutcome::parse(tag).unwrap_or(PresenceOutcome::Cancelled)
    }
}

/// [`crate::VaultSession::set_presence_gate`]: install the app's presence check on this session.
///
/// `confirm(context, reason)` is called once per release, synchronously, on the thread that called
/// the `kgs_session_release_*` function, with `reason` the whole sentence to show (UTF-8, not
/// NUL-terminated, valid only during the call). It returns a [`KgsPresenceOutcome`] tag; anything
/// else counts as `Cancelled`.
///
/// Refused — and nothing installed — when `confirm` is null or a gate is already installed.
///
/// # Safety
///
/// Module rules; `session` live. `confirm` must be null or a function that may be called from any
/// thread, concurrently, with `context`, until the last reference to this session is freed, and
/// that never unwinds or throws across this boundary. `context` is passed back untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_set_presence_gate(
    session: *const super::KgsSession,
    confirm: Option<unsafe extern "C" fn(context: *mut c_void, reason: KgsSlice) -> u32>,
    context: *mut c_void,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let session = live(session)?;
            let confirm = confirm
                .ok_or_else(|| FfiError::invalid("the presence check's function was null"))?;
            session.set_presence_gate(Arc::new(CallbackGate { confirm, context }))
        })
    }
}

// -------------------------------------------------------------------------------------------
// Field
// -------------------------------------------------------------------------------------------

/// A [`FieldRelease`], as the C# side holds it. Free with [`kgs_field_release_free`].
pub struct KgsFieldRelease {
    release: Arc<FieldRelease>,
}

/// # Safety
///
/// `release` must be null or a live pointer from [`kgs_session_release_field`].
unsafe fn field_release<'a>(release: *const KgsFieldRelease) -> FfiResult<&'a FieldRelease> {
    // SAFETY: the caller promises a live pointer or null, and `as_ref` handles null.
    unsafe { release.as_ref() }
        .map(|r| &*r.release)
        .ok_or_else(|| FfiError::invalid("the release handle was null"))
}

/// [`crate::VaultSession::release_field`]: ask the presence gate, then hand out a handle that can
/// read one concealed field. Blocks while the prompt is up. `purpose` is a [`KgsReleasePurpose`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_release_field(
    session: *const super::KgsSession,
    item_id: KgsSlice,
    field_id: KgsSlice,
    purpose: u32,
    out: *mut *mut KgsFieldRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = live(session)?;
            let purpose = KgsReleasePurpose::parse(purpose)?;
            let (item_id, field_id) = (item_id.string()?, field_id.string()?);
            let release = super::block_on(session.release_field(item_id, field_id, purpose))?;
            out.write(Box::into_raw(Box::new(KgsFieldRelease { release })));
            Ok(())
        })
    }
}

/// [`FieldRelease::value`]. ADR-0008 crossing 2, outbound.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_release_value(
    release: *const KgsFieldRelease,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(field_release(release)?.value()?));
            Ok(())
        })
    }
}

/// [`FieldRelease::copy_shown_value`]: the shown value again, for the clipboard, with no new touch.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_release_copy_shown_value(
    release: *const KgsFieldRelease,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(
                field_release(release)?.copy_shown_value()?,
            ));
            Ok(())
        })
    }
}

/// [`FieldRelease::close`]. Idempotent.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_release_close(
    release: *const KgsFieldRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            field_release(release)?.close();
            Ok(())
        })
    }
}

/// [`FieldRelease::is_live`] and [`FieldRelease::seconds_remaining`] together.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_release_state(
    release: *const KgsFieldRelease,
    out: *mut KgsReleaseState,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let release = field_release(release)?;
            out.write(KgsReleaseState {
                is_live: u8::from(release.is_live()),
                seconds_remaining: release.seconds_remaining(),
                purpose: KgsReleasePurpose::tag(release.purpose()),
            });
            Ok(())
        })
    }
}

/// Drop the caller's reference to a field release. Freeing does not end it early; call
/// [`kgs_field_release_close`] for that.
///
/// # Safety
///
/// `release` must be null or a pointer from [`kgs_session_release_field`] not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_field_release_free(release: *mut KgsFieldRelease) {
    if !release.is_null() {
        // SAFETY: a pointer `kgs_session_release_field` produced, freed once — the caller's
        // promise.
        drop(unsafe { Box::from_raw(release) });
    }
}

// -------------------------------------------------------------------------------------------
// One-time code
// -------------------------------------------------------------------------------------------

/// A [`TotpRelease`], as the C# side holds it. Free with [`kgs_totp_release_free`].
pub struct KgsTotpRelease {
    release: Arc<TotpRelease>,
}

/// # Safety
///
/// `release` must be null or a live pointer from [`kgs_session_release_totp`].
unsafe fn totp_release<'a>(release: *const KgsTotpRelease) -> FfiResult<&'a TotpRelease> {
    // SAFETY: the caller promises a live pointer or null, and `as_ref` handles null.
    unsafe { release.as_ref() }
        .map(|r| &*r.release)
        .ok_or_else(|| FfiError::invalid("the release handle was null"))
}

/// [`crate::VaultSession::release_totp`]: ask the presence gate, then hand out a handle that
/// derives one item's one-time code — the named field's, or with `field_id` absent the item's
/// first. Blocks while the prompt is up. `purpose` is a [`KgsReleasePurpose`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_release_totp(
    session: *const super::KgsSession,
    item_id: KgsSlice,
    field_id: super::KgsOptSlice,
    purpose: u32,
    out: *mut *mut KgsTotpRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = live(session)?;
            let purpose = KgsReleasePurpose::parse(purpose)?;
            let (item_id, field_id) = (item_id.string()?, field_id.string()?);
            let release = super::block_on(session.release_totp(item_id, field_id, purpose))?;
            out.write(Box::into_raw(Box::new(KgsTotpRelease { release })));
            Ok(())
        })
    }
}

/// [`TotpRelease::code_at`]: the code at Unix time `at`. ADR-0008 crossing 5, outbound.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_release_code_at(
    release: *const KgsTotpRelease,
    at: u64,
    out: *mut KgsTotpCode,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsTotpCode::new(totp_release(release)?.code_at(at)?));
            Ok(())
        })
    }
}

/// [`TotpRelease::copy_shown_code_at`]: the shown code again, for the clipboard, no new touch.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_release_copy_shown_code_at(
    release: *const KgsTotpRelease,
    at: u64,
    out: *mut KgsTotpCode,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsTotpCode::new(
                totp_release(release)?.copy_shown_code_at(at)?,
            ));
            Ok(())
        })
    }
}

/// [`TotpRelease::close`]. Idempotent.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_release_close(
    release: *const KgsTotpRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            totp_release(release)?.close();
            Ok(())
        })
    }
}

/// [`TotpRelease::is_live`], [`TotpRelease::seconds_remaining`] and its purpose.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_release_state(
    release: *const KgsTotpRelease,
    out: *mut KgsReleaseState,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let release = totp_release(release)?;
            out.write(KgsReleaseState {
                is_live: u8::from(release.is_live()),
                seconds_remaining: release.seconds_remaining(),
                purpose: KgsReleasePurpose::tag(release.purpose()),
            });
            Ok(())
        })
    }
}

/// Drop the caller's reference to a one-time-code release.
///
/// # Safety
///
/// `release` must be null or a pointer from [`kgs_session_release_totp`] not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_totp_release_free(release: *mut KgsTotpRelease) {
    if !release.is_null() {
        // SAFETY: a pointer `kgs_session_release_totp` produced, freed once — the caller's
        // promise.
        drop(unsafe { Box::from_raw(release) });
    }
}

// -------------------------------------------------------------------------------------------
// Notes
// -------------------------------------------------------------------------------------------

/// A [`NotesRelease`], as the C# side holds it. Free with [`kgs_notes_release_free`].
pub struct KgsNotesRelease {
    release: Arc<NotesRelease>,
}

/// # Safety
///
/// `release` must be null or a live pointer from [`kgs_session_release_notes`].
unsafe fn notes_release<'a>(release: *const KgsNotesRelease) -> FfiResult<&'a NotesRelease> {
    // SAFETY: the caller promises a live pointer or null, and `as_ref` handles null.
    unsafe { release.as_ref() }
        .map(|r| &*r.release)
        .ok_or_else(|| FfiError::invalid("the release handle was null"))
}

/// [`crate::VaultSession::release_notes`]: ask the presence gate, then hand out a handle that can
/// read one item's notes. Blocks while the prompt is up. `purpose` is a [`KgsReleasePurpose`].
///
/// # Safety
///
/// Module rules; `session` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_release_notes(
    session: *const super::KgsSession,
    item_id: KgsSlice,
    purpose: u32,
    out: *mut *mut KgsNotesRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let session = live(session)?;
            let purpose = KgsReleasePurpose::parse(purpose)?;
            let item_id = item_id.string()?;
            let release = super::block_on(session.release_notes(item_id, purpose))?;
            out.write(Box::into_raw(Box::new(KgsNotesRelease { release })));
            Ok(())
        })
    }
}

/// [`NotesRelease::text`].
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_notes_release_text(
    release: *const KgsNotesRelease,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(notes_release(release)?.text()?));
            Ok(())
        })
    }
}

/// [`NotesRelease::copy_shown_text`]: the shown notes again, for the clipboard, no new touch.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_notes_release_copy_shown_text(
    release: *const KgsNotesRelease,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(
                notes_release(release)?.copy_shown_text()?,
            ));
            Ok(())
        })
    }
}

/// [`NotesRelease::close`]. Idempotent.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_notes_release_close(
    release: *const KgsNotesRelease,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            notes_release(release)?.close();
            Ok(())
        })
    }
}

/// [`NotesRelease::is_live`], [`NotesRelease::seconds_remaining`] and its purpose.
///
/// # Safety
///
/// Module rules; `release` live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_notes_release_state(
    release: *const KgsNotesRelease,
    out: *mut KgsReleaseState,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let release = notes_release(release)?;
            out.write(KgsReleaseState {
                is_live: u8::from(release.is_live()),
                seconds_remaining: release.seconds_remaining(),
                purpose: KgsReleasePurpose::tag(release.purpose()),
            });
            Ok(())
        })
    }
}

/// Drop the caller's reference to a notes release.
///
/// # Safety
///
/// `release` must be null or a pointer from [`kgs_session_release_notes`] not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_notes_release_free(release: *mut KgsNotesRelease) {
    if !release.is_null() {
        // SAFETY: a pointer `kgs_session_release_notes` produced, freed once — the caller's
        // promise.
        drop(unsafe { Box::from_raw(release) });
    }
}

// -------------------------------------------------------------------------------------------
// Shared
// -------------------------------------------------------------------------------------------

/// A release's lifecycle, read in one call: `is_live`, `seconds_remaining` and `purpose` of a
/// [`FieldRelease`], [`TotpRelease`] or [`NotesRelease`]. Plain data; nothing to free. (The item
/// and field a release is bound to are what the caller asked for, so they are not repeated here.)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KgsReleaseState {
    /// 0 or 1: whether a use would still be allowed.
    pub is_live: u8,
    /// Seconds left before the five-minute cap ends the release.
    pub seconds_remaining: u32,
    /// A [`KgsReleasePurpose`].
    pub purpose: u32,
}
