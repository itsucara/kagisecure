//! `capi` — the explicit `extern "C"` surface the Windows app calls through P/Invoke.
//!
//! [ADR-0003](../../../../docs/decisions/0003-uniffi-vs-csbindgen.md)'s evaluation found that no
//! release of `uniffi-bindgen-cs` reads UniFFI 0.32 metadata, so C# takes the ADR's fallback: a
//! hand-marshalled C ABI over the same Rust functions the UniFFI surface exports. This module
//! covers that whole surface — every `#[uniffi::export]` function and method, and every record and
//! enum they carry — except the handful of macOS-only inputs listed under
//! [What is not here](#what-is-not-here).
//!
//! | File | What it wraps |
//! | --- | --- |
//! | `mod.rs` | the rules below, the shared ABI types, status and error plumbing |
//! | `enums.rs` | every fieldless enum's `u32` tag, as a `#[repr(u32)]` `Kgs*` enum |
//! | `items.rs` | items, fields, categories, the sidebar, logical vaults, environments, audit rows |
//! | `session.rs` | `VaultSession` and the vault-file free functions |
//! | `presence.rs` | the presence gate (a C callback) and the three release handles (ADR-0038) |
//! | `generate.rs` | the password generator and TOTP |
//! | `agent.rs` | the agent, its approval queue, leases, MCP setup, the browser-extension listener |
//! | `import.rs` | import formats, the plan handle, reports and outcomes, shredding |
//!
//! The C# declarations are **generated** from these files by `cargo xtask bindgen-cs` (csbindgen)
//! into `apps/windows/Kagisecure.Interop/Native/NativeMethods.g.cs`, which is checked in. So a
//! signature or layout here is the single source of truth, and `xtask`'s
//! `generated_csharp_is_up_to_date` test fails when the checked-in file has drifted from it.
//!
//! # Rules every function here follows
//!
//! * **No logic.** Each body converts its arguments, calls the function the UniFFI surface already
//!   exports, and converts the result. If a rule about items or vaults appears here, it is a
//!   layering bug.
//! * **Every function returns a [`KgsStatus`]** — the fallible ones and the infallible ones alike,
//!   so a panic in either is a status rather than an abort — except [`kgs_abi_version`] and the
//!   `*_free` functions. A function writes its result to its one out-parameter only on
//!   [`KgsStatus::Ok`], and on failure writes the error's message to `error` if `error` is
//!   non-null. The status is the variant of [`FfiError`]; the message is its `Display`, exactly
//!   what the Swift side sees through UniFFI's flat error.
//! * **Out-parameters are claimed before any work is done**, so a null one cannot create a vault
//!   file, start a listener, or mint a handle nobody would free.
//! * **A panic does not unwind into C#.** It is caught and reported as [`KgsStatus::Panic`]. (In a
//!   `panic = "abort"` release build it aborts instead, which is also not undefined behaviour.)
//!
//! ## Going in: borrowed, for the duration of one call
//!
//! * **Strings and bytes are the same thing:** a [`KgsSlice`] of UTF-8 or raw bytes. Nothing is
//!   ever NUL-terminated, so a byte array is never read as a C string and a `0x00` inside key
//!   material is data, not an end marker (ADR-0003 C3). A string that is not UTF-8 is
//!   [`KgsStatus::Invalid`], never lossily decoded.
//! * **An optional string** is a [`KgsOptSlice`]: `present` is 0 or 1 and `value` is read only
//!   when it is 1, so `None` and `""` stay different.
//! * **A list** is a borrowed `{ptr, len}` of its element type — [`KgsSliceList`] for strings,
//!   [`KgsFieldDraftList`] for fields. `ptr` may be null only when `len` is zero.
//! * **A record that only goes in** is `Kgs<Name>` with borrowed slices inside
//!   ([`KgsItemDraft`], [`KgsGeneratorRecipe`]). **A record that goes both ways** has an owned
//!   `Kgs<Name>` for out and a borrowed `Kgs<Name>Ref` for in ([`KgsTotpParamsRef`],
//!   [`KgsBrowserManifestRef`]).
//!
//! ## Coming out: owned by the caller until it hands them back
//!
//! * **Everything Rust hands out, Rust frees.** A string or byte string is a [`KgsBuffer`]; a
//!   record is `Kgs<Name>`, `#[repr(C)]`, its fields in the same order as the UniFFI record's.
//!   Every buffer is zeroized before it is freed, so a vault key, a revealed field or a generated
//!   password does not survive in the Rust heap after the caller is done with it.
//! * **A list** is `Kgs<Elem>Array { ptr, len, cap }` — one concrete `#[repr(C)]` struct per
//!   element type, holding a `Vec`'s raw parts. The caller reads `len` elements from `ptr` and
//!   never touches `cap`. `ptr` is non-null even for an empty list, and must not be read then.
//! * **One free per out type.** A record or list the caller received is returned to exactly one
//!   `kgs_<name>_free`, which frees every buffer and every nested list inside it, recursively,
//!   and resets the record to all-zero. Freeing a zeroed or already-freed record is a no-op, so a
//!   caller can free in a `finally` without tracking whether the call succeeded.
//! * **An optional value** is `KgsOpt<Name> { present, value }` ([`KgsOptBuffer`],
//!   [`KgsOptU32`], [`KgsOptVaultConflictDetails`], …). When `present` is 0 the `value` is all-zero, which is
//!   why the caller may free it unconditionally.
//! * **Booleans are `u8`**, 0 or 1, because C# `bool` is not blittable.
//! * **Fieldless enums are `u32`.** The named values are the `#[repr(u32)]` `Kgs*` enums in
//!   `enums.rs`, which exist to be generated into C#; struct fields and arguments stay `u32`
//!   because a C# value that is out of range must be an error here, not undefined behaviour. A tag
//!   this build does not know is [`KgsStatus::Invalid`].
//! * **Enums with data** are `{ tag: u32, <every variant's payload, flattened> }`: a payload field
//!   is read only for the variants that carry it and ignored for the rest ([`KgsItemFilter`],
//!   [`KgsApprovalDecision`]). None of the UniFFI surface's data-carrying enums comes *out*.
//!
//! ## Objects
//!
//! `Arc`-style objects are an opaque pointer to one strong reference: [`KgsSession`] for a
//! `VaultSession`, [`KgsImportPlan`] for an `ImportPlanHandle`. Each has a `kgs_*_free` that drops
//! that reference. Passing a handle *into* a function that takes an `Arc` (starting the agent,
//! committing an import) clones the reference; the caller still owns and frees its own.
//!
//! # Threading
//!
//! Every function here is synchronous and may be called from any thread; the objects behind the
//! handles are `Send + Sync` and serialise on their own locks. The three `release_*` calls are
//! async in the UniFFI surface; here each runs its future to completion on the calling thread
//! (`block_on`), so it blocks for as long as the presence prompt it raises is up — call them
//! off the UI thread, like every other slow call here. None of them should be called from
//! the UI thread, because several are slow on purpose: creating, unlocking and changing the
//! master password run Argon2id (about a second at the desktop profile), and every mutating
//! session method re-encrypts and saves the whole file before it returns.
//!
//! One function **blocks by design**: [`kgs_agent_next_request`] parks the calling thread for up
//! to `timeout_ms` waiting for something to ask the user (ADR-0014). The host calls it in a loop
//! from one dedicated background thread, with a short timeout — the Swift app uses 500 ms — and
//! checks its own cancellation flag between calls. There is no way to interrupt a call that is
//! parked, and none is needed: cancellation latency is bounded by the timeout, which is exactly
//! the Swift app's story. The agent's global lock is released before the wait begins, so
//! [`kgs_agent_resolve`] and every other call stay responsive while a poll is parked.
//!
//! # What is not here
//!
//! Only inputs and outputs that are meaningful on macOS alone, all Safari / App Group:
//!
//! * `extension_start`'s `safari_socket_path` and `team_id`: [`kgs_extension_start`] passes
//!   `None` for both. They name the App Group socket the Safari app extension connects to
//!   (ADR-0024), which has no Windows counterpart.
//! * `extension_setup`'s `bundle_plugins_dir` and `team_id`, and the `SafariSetupView` it returns:
//!   [`KgsExtensionSetup`] has no `safari` member.
//! * `ExtensionStatusView`'s `safari_running` and `safari_endpoint`: [`KgsExtensionStatus`] leaves
//!   them out.
//!
//! And everything about agent-requested browser fills
//! ([ADR-0036](../../../../docs/decisions/0036-agent-requested-browser-fill.md)), which Windows
//! never offers — excluded, not degraded: `request_fill` answers `FILL_UNAVAILABLE` there before
//! any item is looked up, whichever browser is connected.
//!
//! * `ApprovalRequestView`'s `agent_fill` (`AgentFillFactsView`, `AgentFillFieldView`,
//!   `AgentOriginView`): [`KgsApprovalRequest`] leaves it out. Only the action tag,
//!   [`KgsApprovalAction::AgentFill`], crosses, because the tag conversion is exhaustive; a host
//!   that ever receives it denies it.
//! * The agent-fill calls the UniFFI surface gains for the macOS app — `agent_fill_*` (the
//!   feature switch, the blocks list, unblocking, the notice queue): none of them is exported
//!   here, nor their `AgentFillBlockView`, `AgentFillBlockReasonView` and `AgentFillNoticeView`.
//! * `ApprovalDecision::DenyAndBlock`, the agent-fill sheet's *Deny and block this agent*:
//!   [`KgsApprovalDecisionTag`] has no tag for it, since no Windows sheet can offer it.
//!
//! And everything about unattended jobs
//! ([ADR-0042](../../../../docs/decisions/0042-unattended-agent-access.md) §14): Windows never
//! offers them, because a same-user process can read the app's memory there. None of the
//! `unattended_*` calls, nor `agent_attach_machine_vault`, nor their views, is exported here.
//!
//! And, of the three release objects ([`crate::FieldRelease`], [`crate::TotpRelease`],
//! [`crate::NotesRelease`]), the `item_id` and `field_id` getters: the caller named both when it
//! asked for the release. Their `is_live`, `seconds_remaining` and `purpose` come back together as
//! one [`KgsReleaseState`].
//!
//! Everything else crosses, including the platform-slot calls: on Windows the "platform keystore"
//! is Windows Hello, and it wraps and unwraps the vault key through the same five functions
//! Touch ID does.
//!
//! [`FfiError`]: crate::FfiError

// The one module in this crate that may use `unsafe`: a C ABI cannot be written without it. The
// crate root forbids it outright when `capi` is off and denies it everywhere else when it is on.
#![allow(unsafe_code)]

use std::mem::{ManuallyDrop, MaybeUninit};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;

use zeroize::Zeroize;

use crate::{FfiError, FfiResult, ImportPlanHandle, VaultSession};

/// `impl Release` and the two constructors for one `Kgs<Elem>Array`.
///
/// The struct itself is written out by hand next to its element type, because csbindgen reads
/// source and never sees what a macro expands to; only the impls come from here.
macro_rules! array {
    ($array:ident, $elem:ty) => {
        impl $array {
            /// Leak `items` into the raw parts the caller reads.
            #[allow(dead_code, reason = "every array gets both constructors")]
            pub(crate) fn from_vec(items: Vec<$elem>) -> Self {
                let (ptr, len, cap) = $crate::capi::leak(items);
                Self { ptr, len, cap }
            }

            /// Convert each element of `items` with `convert` and leak the result.
            #[allow(dead_code, reason = "every array gets both constructors")]
            pub(crate) fn collect<S>(
                items: impl IntoIterator<Item = S>,
                convert: impl FnMut(S) -> $elem,
            ) -> Self {
                Self::from_vec(items.into_iter().map(convert).collect())
            }
        }

        impl Default for $array {
            /// All-zero: what an absent optional record's list is, and what a freed one becomes.
            fn default() -> Self {
                Self {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                    cap: 0,
                }
            }
        }

        impl $crate::capi::Release for $array {
            unsafe fn release(&mut self) {
                // SAFETY: forwarded to the caller: `ptr`/`len`/`cap` are what `from_vec` leaked,
                // or zero.
                unsafe { $crate::capi::release_vec(&mut self.ptr, &mut self.len, &mut self.cap) }
            }
        }
    };
}

mod agent;
mod enums;
mod generate;
mod import;
mod items;
mod presence;
mod session;
#[cfg(test)]
mod tests;

pub use agent::*;
pub use enums::*;
pub use generate::*;
pub use import::*;
pub use items::*;
pub use presence::*;
pub use session::*;

/// The version of this ABI. The C# side checks it once at load and refuses to run against a DLL
/// that disagrees — the job UniFFI's contract-version check does for the Swift side. Bump it on
/// any change to a signature or a `#[repr(C)]` layout under `capi/`.
///
/// Generated into C# as `NativeMethods.KGS_ABI_VERSION`, so the two cannot be bumped apart.
pub const KGS_ABI_VERSION: u32 = 5;

/// The outcome of a call. `Ok` is zero; every other value names an [`FfiError`] variant, plus a
/// panic, which only a C boundary has to report as a value.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KgsStatus {
    /// Success. The out-parameter was written.
    Ok = 0,
    /// [`FfiError::NotFound`].
    NotFound = 1,
    /// [`FfiError::AlreadyExists`].
    AlreadyExists = 2,
    /// [`FfiError::WrongCredential`].
    WrongCredential = 3,
    /// [`FfiError::NoSuchSlot`].
    NoSuchSlot = 4,
    /// [`FfiError::NotPresent`].
    NotPresent = 5,
    /// [`FfiError::Invalid`] — including a string argument that is not UTF-8, an enum tag this
    /// build does not know, and a null pointer where one is required.
    Invalid = 6,
    /// [`FfiError::Io`].
    Io = 7,
    /// [`FfiError::Busy`]: another writer held the vault past the wait. Nothing was written.
    Busy = 8,
    /// [`FfiError::Diverged`]: the vault file is no longer the one this session builds on.
    Diverged = 9,
    /// [`FfiError::ItemChangedElsewhere`]: the item changed since the edit or the row was read.
    ItemChangedElsewhere = 10,
    /// [`FfiError::VaultLocked`].
    VaultLocked = 11,
    /// [`FfiError::NoPresenceGate`]: no gate is installed, so nothing was released.
    NoPresenceGate = 12,
    /// [`FfiError::PresenceCancelled`].
    PresenceCancelled = 13,
    /// [`FfiError::PresenceUnavailable`]: the caller may offer the master-password fallback.
    PresenceUnavailable = 14,
    /// [`FfiError::PresenceBusy`].
    PresenceBusy = 15,
    /// [`FfiError::ReleaseEnded`]: a release handle is no longer live; ask again.
    ReleaseEnded = 16,
    /// The Rust side panicked. Always a bug in this crate.
    Panic = 101,
}

impl KgsStatus {
    fn of(error: &FfiError) -> Self {
        match error {
            FfiError::NotFound { .. } => Self::NotFound,
            FfiError::AlreadyExists { .. } => Self::AlreadyExists,
            FfiError::WrongCredential => Self::WrongCredential,
            FfiError::NoSuchSlot { .. } => Self::NoSuchSlot,
            FfiError::NotPresent { .. } => Self::NotPresent,
            FfiError::Invalid { .. } => Self::Invalid,
            FfiError::Io { .. } => Self::Io,
            FfiError::Busy { .. } => Self::Busy,
            FfiError::Diverged { .. } => Self::Diverged,
            FfiError::ItemChangedElsewhere { .. } => Self::ItemChangedElsewhere,
            FfiError::VaultLocked => Self::VaultLocked,
            FfiError::NoPresenceGate => Self::NoPresenceGate,
            FfiError::PresenceCancelled => Self::PresenceCancelled,
            FfiError::PresenceUnavailable => Self::PresenceUnavailable,
            FfiError::PresenceBusy => Self::PresenceBusy,
            FfiError::ReleaseEnded { .. } => Self::ReleaseEnded,
        }
    }
}

// -------------------------------------------------------------------------------------------
// Ownership
// -------------------------------------------------------------------------------------------

/// An out-type that owns Rust allocations the caller must hand back.
pub(crate) trait Release {
    /// Free every allocation inside `self`, recursively, and leave `self` all-zero.
    ///
    /// # Safety
    ///
    /// Every pointer inside `self` must be null, or one this library wrote and the caller has not
    /// modified since.
    unsafe fn release(&mut self);
}

/// A `Vec`'s raw parts, leaked for the caller to read and later hand back to [`release_vec`].
pub(crate) fn leak<T>(items: Vec<T>) -> (*mut T, usize, usize) {
    let mut items = ManuallyDrop::new(items);
    (items.as_mut_ptr(), items.len(), items.capacity())
}

/// Rebuild the `Vec` [`leak`] leaked, release each element, free it, and zero the parts.
///
/// # Safety
///
/// `ptr` must be null, or `ptr`/`len`/`cap` must be exactly what [`leak`] returned for a `Vec<T>`
/// that has not been released since.
pub(crate) unsafe fn release_vec<T: Release>(ptr: &mut *mut T, len: &mut usize, cap: &mut usize) {
    if !ptr.is_null() {
        // SAFETY: the raw parts of a `Vec<T>` `leak` produced, untouched since — the caller's
        // promise — so rebuilding it takes back exactly that allocation, once.
        let mut items = unsafe { Vec::from_raw_parts(*ptr, *len, *cap) };
        for item in &mut items {
            // SAFETY: each element was written by this library, per the same promise.
            unsafe { item.release() };
        }
    }
    *ptr = ptr::null_mut();
    *len = 0;
    *cap = 0;
}

/// Release one out-record through a pointer the caller passed back.
///
/// # Safety
///
/// `record` must be null or point to a `T` that is all-zero or was written by this library and not
/// modified since.
unsafe fn free<T: Release>(record: *mut T) {
    // SAFETY: the caller promises a valid pointer or null; `as_mut` handles null.
    if let Some(record) = unsafe { record.as_mut() } {
        // SAFETY: forwarded to the caller.
        unsafe { record.release() };
    }
}

// -------------------------------------------------------------------------------------------
// Strings and bytes
// -------------------------------------------------------------------------------------------

/// Bytes Rust allocated and the caller now owns, until it hands them back to [`kgs_buffer_free`]
/// (or to the free function of the record the buffer sits in).
///
/// The three fields are a `Vec<u8>`'s raw parts. The caller reads `len` bytes from `ptr` and must
/// not touch `cap`; it exists so the free can rebuild the exact allocation.
#[repr(C)]
#[derive(Debug)]
pub struct KgsBuffer {
    /// Start of the bytes. Null only for a zeroed, never-written or already-freed buffer.
    pub ptr: *mut u8,
    /// How many bytes are valid.
    pub len: usize,
    /// The allocation's capacity. Opaque to the caller.
    pub cap: usize,
}

impl KgsBuffer {
    const EMPTY: Self = Self {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };

    fn from_vec(bytes: Vec<u8>) -> Self {
        let (ptr, len, cap) = leak(bytes);
        Self { ptr, len, cap }
    }

    fn from_string(text: String) -> Self {
        Self::from_vec(text.into_bytes())
    }
}

impl Default for KgsBuffer {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Release for KgsBuffer {
    unsafe fn release(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr`/`len`/`cap` are the raw parts of a `Vec<u8>` `KgsBuffer::from_vec`
            // leaked, untouched since — the caller's promise.
            let mut bytes = unsafe { Vec::from_raw_parts(self.ptr, self.len, self.cap) };
            bytes.zeroize();
        }
        *self = Self::EMPTY;
    }
}

/// An optional [`KgsBuffer`]. `value` is all-zero when `present` is 0.
#[repr(C)]
#[derive(Debug, Default)]
pub struct KgsOptBuffer {
    /// 1 if there is a value, 0 for `None`.
    pub present: u8,
    /// The value; all-zero when absent.
    pub value: KgsBuffer,
}

impl KgsOptBuffer {
    fn from_string(text: Option<String>) -> Self {
        Self::from_vec(text.map(String::into_bytes))
    }

    fn from_vec(bytes: Option<Vec<u8>>) -> Self {
        match bytes {
            Some(bytes) => Self {
                present: 1,
                value: KgsBuffer::from_vec(bytes),
            },
            None => Self {
                present: 0,
                value: KgsBuffer::EMPTY,
            },
        }
    }
}

impl Release for KgsOptBuffer {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.value.release() };
        self.present = 0;
    }
}

/// A list of strings going out.
#[repr(C)]
#[derive(Debug)]
pub struct KgsBufferArray {
    /// First element.
    pub ptr: *mut KgsBuffer,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsBufferArray, KgsBuffer);

impl KgsBufferArray {
    fn strings(items: Vec<String>) -> Self {
        Self::collect(items, KgsBuffer::from_string)
    }
}

/// Bytes the caller owns and lends to Rust for the duration of one call.
///
/// Used for strings (UTF-8, not NUL-terminated) and for raw bytes alike. `ptr` may be null only
/// when `len` is zero.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsSlice {
    /// Start of the bytes.
    pub ptr: *const u8,
    /// How many.
    pub len: usize,
}

impl KgsSlice {
    /// # Safety
    ///
    /// `ptr` must be valid for `len` reads for as long as the returned slice is used.
    unsafe fn bytes<'a>(self) -> FfiResult<&'a [u8]> {
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.ptr.is_null() {
            return Err(FfiError::invalid("a non-empty argument had a null pointer"));
        }
        // SAFETY: non-null, and the caller promises `len` readable bytes for the call's duration.
        Ok(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
    }

    /// # Safety
    ///
    /// As [`KgsSlice::bytes`].
    unsafe fn string(self) -> FfiResult<String> {
        // SAFETY: forwarded to the caller.
        let bytes = unsafe { self.bytes() }?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| FfiError::invalid("a string argument was not valid UTF-8"))
    }
}

/// An optional string going in. `value` is read only when `present` is 1.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsOptSlice {
    /// 1 if there is a value, 0 for `None`.
    pub present: u8,
    /// The value, when present.
    pub value: KgsSlice,
}

impl KgsOptSlice {
    /// # Safety
    ///
    /// When `present` is non-zero, `value` must satisfy [`KgsSlice::bytes`]'s contract.
    unsafe fn string(self) -> FfiResult<Option<String>> {
        if self.present == 0 {
            return Ok(None);
        }
        // SAFETY: forwarded to the caller.
        unsafe { self.value.string() }.map(Some)
    }
}

/// A list of strings going in.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsSliceList {
    /// First element. May be null only when `len` is zero.
    pub ptr: *const KgsSlice,
    /// How many.
    pub len: usize,
}

impl KgsSliceList {
    /// # Safety
    ///
    /// `ptr` must be valid for `len` reads of a [`KgsSlice`], each of which must satisfy
    /// [`KgsSlice::bytes`]'s contract, for the call's duration.
    unsafe fn strings(self) -> FfiResult<Vec<String>> {
        // SAFETY: forwarded to the caller.
        let slices = unsafe { borrow_list(self.ptr, self.len) }?;
        slices
            .iter()
            // SAFETY: forwarded to the caller.
            .map(|s| unsafe { s.string() })
            .collect()
    }
}

/// A borrowed `{ptr, len}` list as a Rust slice.
///
/// # Safety
///
/// `ptr` must be valid for `len` reads of `T` for as long as the result is used.
unsafe fn borrow_list<'a, T>(ptr: *const T, len: usize) -> FfiResult<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FfiError::invalid("a non-empty list had a null pointer"));
    }
    // SAFETY: non-null, and the caller promises `len` readable elements.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// An optional `u32` — an optional enum tag, or an optional count. Plain data, used both ways.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KgsOptU32 {
    /// 1 if there is a value, 0 for `None`.
    pub present: u8,
    /// The value; zero when absent.
    pub value: u32,
}

impl KgsOptU32 {
    fn from_option(value: Option<u32>) -> Self {
        Self {
            present: u8::from(value.is_some()),
            value: value.unwrap_or(0),
        }
    }

    fn option(self) -> Option<u32> {
        (self.present != 0).then_some(self.value)
    }
}

/// An optional boolean going out. `value` is 0 when `present` is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KgsOptBool {
    /// 1 if there is a value, 0 for `None`.
    pub present: u8,
    /// 0 or 1.
    pub value: u8,
}

impl KgsOptBool {
    fn from_option(value: Option<bool>) -> Self {
        Self {
            present: u8::from(value.is_some()),
            value: u8::from(value.unwrap_or(false)),
        }
    }
}

// -------------------------------------------------------------------------------------------
// Objects
// -------------------------------------------------------------------------------------------

/// An unlocked vault, as the C# side holds it: an opaque pointer to one strong reference.
///
/// Freeing it with [`kgs_session_free`] drops that reference; when it is the last one, the
/// [`VaultSession`] drops, which is the lock — the vault key is zeroized and the agent's leases
/// die. That is the same lifecycle Swift gets from UniFFI's `Arc`.
pub struct KgsSession {
    session: Arc<VaultSession>,
}

/// A parsed import, as the C# side holds it: one strong reference to an [`ImportPlanHandle`].
/// Freed by [`kgs_import_plan_free`]; the parsed values it holds die with the last reference.
pub struct KgsImportPlan {
    plan: Arc<ImportPlanHandle>,
}

/// Borrow the session behind a handle.
///
/// # Safety
///
/// `session` must be null or a live pointer from one of the `kgs_session_*` constructors.
unsafe fn session<'a>(session: *const KgsSession) -> FfiResult<&'a Arc<VaultSession>> {
    // SAFETY: the caller promises a live pointer or null, and `as_ref` handles null.
    unsafe { session.as_ref() }
        .map(|s| &s.session)
        .ok_or_else(|| FfiError::invalid("the session handle was null"))
}

/// Borrow the plan behind a handle.
///
/// # Safety
///
/// `plan` must be null or a live pointer from [`kgs_session_import_preview`].
unsafe fn plan<'a>(plan: *const KgsImportPlan) -> FfiResult<&'a Arc<ImportPlanHandle>> {
    // SAFETY: the caller promises a live pointer or null, and `as_ref` handles null.
    unsafe { plan.as_ref() }
        .map(|p| &p.plan)
        .ok_or_else(|| FfiError::invalid("the import plan handle was null"))
}

// -------------------------------------------------------------------------------------------
// Calls
// -------------------------------------------------------------------------------------------

/// Run `future` to completion on the calling thread, parking it while the future is pending.
///
/// For the async release calls, whose only await is the presence gate. On this ABI that gate is
/// [`presence::CallbackGate`], which answers synchronously, so in practice the future is ready on
/// its first poll; the parking loop is what keeps this correct for any future anyway. No runtime,
/// no timer, no dependency: the waker unparks the one thread that is waiting.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Wake, Waker};

    struct Unpark(std::thread::Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// Run `body`, catching a panic, and turn its error into a status plus a message in `error`.
///
/// # Safety
///
/// `error` must be null or valid for one write of a [`KgsBuffer`].
unsafe fn call(error: *mut KgsBuffer, body: impl FnOnce() -> FfiResult<()>) -> KgsStatus {
    let (status, message) = match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => return KgsStatus::Ok,
        Ok(Err(e)) => (KgsStatus::of(&e), e.to_string()),
        Err(_) => (KgsStatus::Panic, "kagisecure panicked".to_owned()),
    };
    if !error.is_null() {
        // SAFETY: non-null, and the caller promises it is valid for a write.
        unsafe { error.write(KgsBuffer::from_string(message)) };
    }
    status
}

/// The slot an out-parameter points at, or an error if it is null.
///
/// Every function claims its slot *before* doing any work, so a null out-parameter cannot create
/// a vault file, or mint a handle or a buffer that nobody would ever free.
///
/// # Safety
///
/// `out` must be null or valid for one write of a `T` for the rest of the call.
unsafe fn slot<'a, T>(out: *mut T) -> FfiResult<&'a mut MaybeUninit<T>> {
    // SAFETY: the caller promises a writable pointer or null. `MaybeUninit<T>` has `T`'s layout
    // and never reads what is there, so an uninitialised slot is fine.
    unsafe { out.cast::<MaybeUninit<T>>().as_mut() }
        .ok_or_else(|| FfiError::invalid("an out-parameter was null"))
}

/// Read a borrowed record argument, or an error if the pointer is null.
///
/// # Safety
///
/// `record` must be null or valid for a read of a `T` for the rest of the call.
unsafe fn read<'a, T>(record: *const T, what: &str) -> FfiResult<&'a T> {
    // SAFETY: the caller promises a readable pointer or null, and `as_ref` handles null.
    unsafe { record.as_ref() }.ok_or_else(|| FfiError::invalid(format!("the {what} was null")))
}

// -------------------------------------------------------------------------------------------
// Always-present entry points
// -------------------------------------------------------------------------------------------

/// [`KGS_ABI_VERSION`].
#[unsafe(no_mangle)]
pub extern "C" fn kgs_abi_version() -> u32 {
    KGS_ABI_VERSION
}

/// Zeroize and free a buffer this library handed out, and reset it to empty.
///
/// Idempotent: freeing an already-freed (or never-written) buffer does nothing.
///
/// # Safety
///
/// `buffer` must be null or point to a [`KgsBuffer`] that is empty or was written by this library
/// and not modified since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_buffer_free(buffer: *mut KgsBuffer) {
    // SAFETY: forwarded to the caller.
    unsafe { free(buffer) }
}
