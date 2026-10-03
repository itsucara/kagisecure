//! Owner-only access control on Windows: what `0600` and `0700` are on Unix (threat-model M-13).
//!
//! On Unix the vault, the injected `.env` and the import report are created mode `0600`, and
//! the directories this program creates for them `0700`. None of that has a Windows meaning —
//! `OpenOptionsExt::mode` does not exist there — so before this module, every one of those files
//! simply inherited whatever ACL its containing directory happened to carry. This module is the
//! replacement: one security descriptor, built from the SID of the account this process runs as,
//! attached to the object **when the object is created**, so there is never a moment in which
//! the file exists under an inherited ACL.
//!
//! # The descriptor, stated exactly
//!
//! ```text
//! O:<user SID>D:P(A;;FA;;;<user SID>)          files and named pipes
//! O:<user SID>D:P(A;OICI;FA;;;<user SID>)      directories
//! ```
//!
//! * `O:` — the owner is the user, not whatever the token's default owner is. For an elevated
//!   administrator that default is `BUILTIN\Administrators`, and an owner has implicit
//!   `READ_CONTROL | WRITE_DAC` whatever the DACL says, so leaving it defaulted would hand the
//!   right to rewrite this ACL to a group rather than to the user.
//! * `D:P` — a DACL, **protected**: inheritable entries on the parent do not flow in, now or when
//!   something later re-applies inheritance down the tree. Without `P` the single entry below is
//!   merely *added to* whatever the parent grants, which is the state this module exists to end.
//! * `(A;;FA;;;<user SID>)` — the only entry: allow `FILE_ALL_ACCESS` to the user. A named pipe
//!   is a file object, so the same right set covers connecting (`GENERIC_READ | GENERIC_WRITE`)
//!   and creating further instances (`FILE_CREATE_PIPE_INSTANCE`) — and nobody else gets either.
//! * `OICI` on directories only — files and subdirectories created inside later inherit the same
//!   single entry. This matters more than the directory's own entry does, because Windows grants
//!   *Bypass traverse checking* to Everyone by default: a directory's DACL does **not** stop
//!   another user opening a file inside it by its full path, the way a `0700` directory does on
//!   Unix. Each file's own DACL is the boundary; the directory's inheritable entry makes that true
//!   of files this program did not create itself.
//!
//! # Why the user's SID alone, and not SYSTEM or Administrators as well
//!
//! The default `%LOCALAPPDATA%` ACL grants SYSTEM and `BUILTIN\Administrators` as well as the
//! user, and an earlier sketch of this descriptor (formerly on `Endpoint::prepare_dir`) copied
//! that shape. It is deliberately not kept. An `Administrators` entry would let *every* elevated
//! process of *every* administrator account on the machine open the vault as a matter of course
//! — a second admin user reading this user's `.env` with no privileged act at all — which is
//! exactly the other-local-user exposure M-13 is about. What it would buy in exchange is nothing:
//! SYSTEM and administrators can already reach any file on the machine through privileges that
//! bypass the DACL (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`,
//! `SeDebugPrivilege`), which is also how backup software reaches it; that route is deliberate,
//! privileged and auditable, where an ACE is none of those. The Unix analogue is the same: `0600`
//! grants root nothing, and root reads the file anyway through `CAP_DAC_OVERRIDE`. The cost, stated
//! plainly: a service that reads user files *without* using backup semantics — the Windows Search
//! indexer, for one — cannot read these files. For a vault and a secrets file that is the point.
//!
//! The user's elevated processes carry the same user SID and are granted like any other.
//!
//! # Why this is in `kagisecure-core`, and why it contains `unsafe`
//!
//! The vault writer and the `.env` writer are in this crate and the dependency arrow points
//! *into* it — `kagisecure-ipc` depends on core, never the reverse — so a helper those two
//! functions call can only live here or in a new crate. It is here, as the one module in
//! `kagisecure-core` that may use `unsafe`, compiled only on Windows. `std` has no security
//! descriptor API at all, and building one means `windows-sys` calls: there is no safe wrapper to
//! reach for. Everything else in the crate is exactly as `unsafe`-free as before, and on every
//! other platform the crate is still `#![forbid(unsafe_code)]` — see the crate attribute in
//! `lib.rs`, which is `deny` on Windows only so that this module's `allow` can take effect.
//!
//! The `unsafe` here is held to three shapes, each with its own `// SAFETY:` comment: a Win32
//! call whose pointer arguments are locals that outlive it; a returned handle or allocation
//! taken into an owner that frees it exactly once ([`OwnedHandle`], `LocalAlloc`); and copying a
//! SID or ACL the OS just returned into a `Vec<u8>` whose length the OS itself reported. Every
//! structure read back — SIDs and ACLs — is parsed from those owned bytes by safe code with
//! bounds checks, rather than by pointer arithmetic over OS memory.
//!
//! # What this does not do
//!
//! * It does not touch the ACL of a directory that **already exists**. `write_atomically`
//!   `chmod`s an existing directory to `0700` on Unix, best effort; the Windows equivalent would
//!   be `SetSecurityInfo` with a protected, inheritable entry, which *propagates* down the tree
//!   and rewrites the ACL of every file beneath it — on a vault kept in `Documents`, all of
//!   `Documents`. The file's own DACL is the boundary here (see `OICI` above), so the existing
//!   directory is left alone.
//! * It says nothing about a handle someone **already holds**. Access is checked when a handle
//!   is opened; rewriting the DACL of an existing file (only [`create_or_truncate_file`] does
//!   that) does not revoke a handle another process opened earlier. The same is true of `fchmod`.
//! * It is not tested against a second local account. The tests read the descriptor back and
//!   check it is exactly the one described above; "another user is refused" follows from that
//!   descriptor by Windows' access check, and has not been exercised by logging in as one.
//! * Paths are passed to `CreateFileW`/`CreateDirectoryW` as given, without the `\\?\` prefix
//!   `std` adds for paths longer than `MAX_PATH`. A path that long fails to be created here,
//!   loudly, rather than being created without protection.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `FILE_ALL_ACCESS`, the mask the single entry grants. Kept as a number so tests can compare
/// against what the OS reports back without importing `windows-sys` themselves.
pub const FILE_ALL_ACCESS: u32 = windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`: the flags on a directory's entry.
pub const INHERIT_TO_CHILDREN: u8 = 0x01 | 0x02;

/// `INHERITED_ACE`: marks an entry that came from a parent — when the descriptor was assigned
/// with auto-inheritance. A file created by plain `CreateFileW` holds its inherited entries
/// *without* this flag; see [`object_security`].
pub const INHERITED: u8 = 0x10;

/// A security identifier, held as its binary form.
///
/// Two SIDs are the same principal exactly when their binary forms are equal — revision,
/// authority and every sub-authority — which is what `EqualSid` compares, so equality here is
/// byte equality and needs no FFI.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Parse the SID at the start of `bytes`, ignoring anything after it.
    ///
    /// The layout is fixed (`winnt.h`): revision (always 1), sub-authority count (at most 15),
    /// a six-byte big-endian identifier authority, then that many little-endian `u32`s.
    fn parse_prefix(bytes: &[u8]) -> io::Result<Self> {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed SID");
        let (&revision, &count) = (
            bytes.first().ok_or_else(malformed)?,
            bytes.get(1).ok_or_else(malformed)?,
        );
        if revision != 1 || count > 15 {
            return Err(malformed());
        }
        let len = 8 + 4 * usize::from(count);
        let sid = bytes.get(..len).ok_or_else(malformed)?;
        Ok(Self(sid.to_vec()))
    }

    /// The binary form, as `winnt.h` lays it out.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Sid {
    /// The string form, `S-1-5-21-…`, as `ConvertSidToStringSidW` would render it: the
    /// identifier authority in decimal when it fits in 32 bits and in hex otherwise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        let authority = b[2..8]
            .iter()
            .fold(0_u64, |acc, &byte| (acc << 8) | u64::from(byte));
        write!(f, "S-{}-", b[0])?;
        if authority >> 32 == 0 {
            write!(f, "{authority}")?;
        } else {
            write!(f, "0x{authority:012X}")?;
        }
        for chunk in b[8..].as_chunks::<4>().0 {
            write!(f, "-{}", u32::from_le_bytes(*chunk))?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sid({self})")
    }
}

/// Which descriptor to build: see the module documentation for the exact SDDL of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// A regular file. One entry, not inheritable (a file has no children).
    File,
    /// A directory. One entry, inherited by everything created inside it.
    Directory,
    /// A named pipe. The same descriptor as [`ObjectKind::File`].
    Pipe,
}

/// The owner-only descriptor for `kind`, as an SDDL string, for the account this process runs as.
///
/// This is the form `interprocess`'s `SecurityDescriptor::deserialize` takes, which is how
/// `kagisecure-ipc` attaches it to a named pipe without any `unsafe` of its own.
///
/// # Errors
///
/// Any failure reading this process's token.
pub fn owner_only_sddl(kind: ObjectKind) -> io::Result<String> {
    Ok(sddl_for(&current_user_sid()?, kind))
}

fn sddl_for(user: &Sid, kind: ObjectKind) -> String {
    let inherit = match kind {
        ObjectKind::Directory => "OICI",
        ObjectKind::File | ObjectKind::Pipe => "",
    };
    format!("O:{user}D:P(A;{inherit};FA;;;{user})")
}

/// The user SID of the account this process runs as, from its own token.
///
/// # Errors
///
/// Any failure opening or reading the token. This does not happen to a running process in
/// practice, and the callers treat it as fatal rather than guessing.
pub fn current_user_sid() -> io::Result<Sid> {
    // SAFETY: `GetCurrentProcess` takes nothing and returns a pseudo-handle (`-1`) that is valid
    // for as long as this process exists and must not be closed. Borrowing it — never wrapping
    // it in an `OwnedHandle` — is exactly that contract.
    let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
    process_user_sid(process)
}

/// The user SID of the process behind `process`.
///
/// `process` needs `PROCESS_QUERY_LIMITED_INFORMATION`, which is what `OpenProcessToken` with
/// `TOKEN_QUERY` requires of it. `kagisecure-ipc` uses this to compare a named-pipe peer's
/// account with this one.
///
/// # Errors
///
/// Any failure opening or reading the token — including the usual one, `ERROR_ACCESS_DENIED`
/// for a process belonging to another account. Callers deciding "same user?" must read an error
/// as "no".
pub fn process_user_sid(process: BorrowedHandle<'_>) -> io::Result<Sid> {
    let mut raw_token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a live handle for the duration of the borrow; `raw_token` is a local
    // the call writes one handle into on success and leaves alone on failure.
    let ok = unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &raw mut raw_token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `raw_token` is a fresh token handle that nothing else owns.
    // `OwnedHandle` closes it exactly once, on every return path below.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    // First call: ask for the size. It "fails" with `ERROR_INSUFFICIENT_BUFFER` by design, so
    // only the length it reports is used.
    let mut len = 0_u32;
    // SAFETY: a null buffer with a zero length is the documented way to ask for the size; the
    // call writes only `len`.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut len,
        );
    }
    let byte_len = usize::try_from(len).map_err(io::Error::other)?;
    if byte_len < size_of::<TOKEN_USER>() {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements rather than `u8` so the buffer is aligned for `TOKEN_USER`, which starts
    // with a pointer.
    let mut buf = vec![0_u64; byte_len.div_ceil(size_of::<u64>())];
    // SAFETY: `buf` is a live allocation of at least `len` bytes, and `len` is passed as its
    // size, so the call cannot write past it.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            len,
            &raw mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a `TOKEN_USER` (the buffer is 8-byte aligned,
    // which satisfies its alignment, and at least `size_of::<TOKEN_USER>()` long, checked above).
    // Its `User.Sid` points into the same buffer, which stays alive until after the copy.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` came from the OS, points into `buf`, and `buf` outlives this call.
    unsafe { copy_sid(sid) }
}

/// Copy the SID at `sid` into owned bytes.
///
/// # Safety
///
/// `sid` must be null or point to memory that stays valid for the duration of the call.
unsafe fn copy_sid(sid: PSID) -> io::Result<Sid> {
    // SAFETY: `IsValidSid` only reads through `sid`, which the caller promises is valid; it is
    // the documented check to run before trusting `GetLengthSid`.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid SID"));
    }
    // SAFETY: `sid` is valid (checked just above), so its length is its own header's answer.
    let len = usize::try_from(unsafe { GetLengthSid(sid) }).map_err(io::Error::other)?;
    // SAFETY: a valid SID occupies exactly `GetLengthSid` bytes starting at `sid`, and the
    // caller keeps that memory alive for the duration of this call.
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) };
    Sid::parse_prefix(bytes)
}

/// A self-relative security descriptor allocated by `LocalAlloc`, freed on drop.
struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API documented to allocate it with `LocalAlloc` and
        // to transfer ownership to the caller, and `Drop` runs exactly once.
        unsafe { LocalFree(self.0) };
    }
}

impl LocalDescriptor {
    /// Build the owner-only descriptor for `kind`.
    fn owner_only(kind: ObjectKind) -> io::Result<Self> {
        let sddl = wide_nul(OsStr::new(&owner_only_sddl(kind)?))?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the call; `sd` is a
        // local the call writes a `LocalAlloc`ed pointer into on success. The size out-param is
        // optional and not wanted.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    /// `SECURITY_ATTRIBUTES` pointing at this descriptor. Borrowing `self` keeps it alive for as
    /// long as the attributes are in use.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    /// The DACL inside this descriptor, for `SetSecurityInfo`.
    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `self.0` is a valid descriptor owned by `self`; the three out-params are
        // locals. The returned pointer points into `self.0`, which the caller keeps alive by
        // borrowing `self` for as long as it uses the pointer.
        let ok = unsafe {
            GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut dacl, &raw mut defaulted)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            // A missing or null DACL would grant everyone everything. Our own SDDL always has
            // one, so this is unreachable — and refused rather than applied if it ever is not.
            return Err(io::Error::other("owner-only descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

/// `s` as a NUL-terminated UTF-16 string, refusing an interior NUL that would truncate it.
fn wide_nul(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = s.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Create `path` as a new, empty file readable and writable by this user only, open for writing.
///
/// The Windows counterpart of `OpenOptions::new().write(true).create_new(true).mode(0o600)`:
/// `CREATE_NEW` fails if anything already exists at `path`, and the descriptor is part of the
/// `CreateFileW` call itself, so the file never exists under any other ACL — not even empty.
/// `FILE_FLAG_OPEN_REPARSE_POINT` keeps `CREATE_NEW` from following a symlink planted at `path`,
/// as `std` does for `create_new`. Share mode is `std`'s default.
///
/// # Errors
///
/// [`io::ErrorKind::AlreadyExists`] if `path` exists, or any other failure creating it.
pub fn create_new_file(path: &Path) -> io::Result<File> {
    let descriptor = LocalDescriptor::owner_only(ObjectKind::File)?;
    let attributes = descriptor.attributes();
    let wide = wide_nul(path.as_os_str())?;
    // SAFETY: `wide` is NUL-terminated and `attributes` (with the descriptor it points at, kept
    // alive by `descriptor`) outlives the call; the template handle is optional and null.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` succeeded, so `raw` is a fresh file handle nothing else owns; `File`
    // takes ownership and closes it once.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

/// Open `path` for reading and writing, creating it — owner-only, empty — if nothing is there.
///
/// The counterpart of `OpenOptions::new().read(true).write(true).create(true).mode(0o600)`, for
/// the vault's sibling lock file (`vault::lock`), which is created once and then only ever
/// opened and locked, never written. `OPEN_ALWAYS` applies the descriptor only when it creates
/// the file, exactly as `mode` does on Unix; an existing file keeps its ACL — every build that
/// creates this file creates it through here. `share_mode` is passed through: the lock file is
/// opened without `FILE_SHARE_DELETE`, so it cannot be renamed or deleted while held.
///
/// # Errors
///
/// Any failure opening or creating the file, with the OS error code intact (the lock's caller
/// sorts sharing violations from everything else by it).
pub fn open_or_create_file(path: &Path, share_mode: u32) -> io::Result<File> {
    let descriptor = LocalDescriptor::owner_only(ObjectKind::File)?;
    let attributes = descriptor.attributes();
    let wide = wide_nul(path.as_os_str())?;
    // SAFETY: `wide` is NUL-terminated and `attributes` (with the descriptor it points at, kept
    // alive by `descriptor`) outlives the call; the template handle is optional and null.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share_mode,
            &raw const attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` succeeded, so `raw` is a fresh file handle nothing else owns; `File`
    // takes ownership and closes it once.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

/// Create or reuse `path`, owner-only, open for writing and empty.
///
/// The counterpart of `OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)`
/// followed by a `chmod` — but ordered so nothing sensitive is written before the ACL is right:
///
/// * `path` does not exist: exactly [`create_new_file`].
/// * `path` exists: it is opened *without* truncating, its DACL is replaced with the owner-only
///   one (protected), and only then is it emptied. If the DACL cannot be replaced — the file
///   belongs to someone else, say — this fails with the old contents untouched, rather than
///   writing into a file whose ACL is not ours.
///
/// As with `fchmod`, replacing the DACL of an existing file does not revoke a handle another
/// process already had open on it.
///
/// # Errors
///
/// Any failure creating, opening, re-securing or truncating the file.
pub fn create_or_truncate_file(path: &Path) -> io::Result<File> {
    match create_new_file(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        other => return other,
    }
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .access_mode(GENERIC_WRITE | WRITE_DAC)
        .open(path)?;
    restrict_to_owner(file.as_handle())?;
    file.set_len(0)?;
    Ok(file)
}

/// Replace the DACL on an open file with the protected owner-only one.
///
/// The handle needs `WRITE_DAC`. The owner is left as it is: changing it would need
/// `WRITE_OWNER`, and the DACL — not the owner — is what decides who may open the file.
fn restrict_to_owner(handle: BorrowedHandle<'_>) -> io::Result<()> {
    let descriptor = LocalDescriptor::owner_only(ObjectKind::File)?;
    let dacl = descriptor.dacl()?;
    // SAFETY: `handle` is live for the borrow; `dacl` points into `descriptor`, which is alive
    // until the end of this function. Owner, group and SACL are not being set, so null.
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    Ok(())
}

/// `std::fs::create_dir_all`, except that every directory this call creates is owner-only, with
/// an entry its children inherit.
///
/// Directories that already exist are left exactly as they are (see the module documentation
/// for why that is deliberate). Every *missing* component is created with the descriptor at
/// creation time, parents first — so a vault directory created under a fresh
/// `%LOCALAPPDATA%\kagisecure` gets it on both levels.
///
/// # Errors
///
/// Any failure creating a missing component.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    let descriptor = LocalDescriptor::owner_only(ObjectKind::Directory)?;
    create_dir_all_with(path, &descriptor)
}

fn create_dir_all_with(path: &Path, descriptor: &LocalDescriptor) -> io::Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all_with(parent, descriptor)?;
    }
    let attributes = descriptor.attributes();
    let wide = wide_nul(path.as_os_str())?;
    // SAFETY: `wide` is NUL-terminated and `attributes` (with the descriptor behind it) outlives
    // the call.
    let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        // Somebody else created it between the `is_dir` check and here: fine, as it is for
        // `std::fs::create_dir_all`, provided it really is a directory.
        let raced = error.raw_os_error() == i32::try_from(ERROR_ALREADY_EXISTS).ok();
        if !(raced && path.is_dir()) {
            return Err(error);
        }
    }
    Ok(())
}

/// One entry of a DACL, as read back from the OS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    /// `ACE_HEADER::AceType`: 0 is allow, 1 is deny; anything else is an object or callback
    /// entry this module never writes.
    pub ace_type: u8,
    /// `ACE_HEADER::AceFlags` — inheritance, and [`INHERITED`] for an entry from a parent.
    pub flags: u8,
    /// The access mask, for allow and deny entries.
    pub mask: Option<u32>,
    /// The trustee, for allow and deny entries.
    pub sid: Option<Sid>,
}

impl Ace {
    /// Whether this is an access-allowed entry.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        self.ace_type == 0
    }
}

/// An object's owner and DACL, as the OS reports them for an open handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSecurity {
    /// The owner SID.
    pub owner: Sid,
    /// Whether the DACL is protected from inheritance (`SE_DACL_PROTECTED`).
    pub dacl_protected: bool,
    /// The DACL's entries, in order — or `None` for a *null* DACL, which grants everyone
    /// everything and is never what this module writes.
    pub dacl: Option<Vec<Ace>>,
}

/// Read the owner and DACL of the object behind `handle`.
///
/// The handle needs `READ_CONTROL`. A connected named-pipe client handle has it (it is part of
/// `GENERIC_READ`), which is how a client checks who owns the pipe it reached, and how the tests
/// check what this module wrote.
///
/// Queried as `SE_KERNEL_OBJECT` — the descriptor exactly as the object holds it — rather than
/// `SE_FILE_OBJECT`. The file-object path does extra work for inheritance, and on a named pipe
/// created with the *default* descriptor (an unprotected DACL) it fails outright with
/// `ERROR_INVALID_PARAMETER` when asked for the DACL (observed on Windows 11 26200). A client
/// checking a pipe it did not create must be able to read exactly that kind of pipe.
///
/// # Errors
///
/// Any failure from `GetSecurityInfo`, or an owner or ACL that does not parse.
pub fn object_security(handle: BorrowedHandle<'_>) -> io::Result<ObjectSecurity> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is live for the borrow; every out-param is a local. On success `sd` is a
    // `LocalAlloc`ed descriptor this function now owns, and `owner`/`dacl` point into it.
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut sd,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    let sd = LocalDescriptor(sd);

    let (mut control, mut revision) = (0_u16, 0_u32);
    // SAFETY: `sd.0` is the valid descriptor just returned; both out-params are locals.
    if unsafe { GetSecurityDescriptorControl(sd.0, &raw mut control, &raw mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `owner` points into `sd`, which is alive until the end of this function.
    let owner = unsafe { copy_sid(owner) }?;
    let dacl = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` points to a valid ACL inside `sd`; `AclSize` is, per `winnt.h`, the size
        // of the whole ACL including its header and every entry, so the slice covers exactly the
        // ACL and nothing past it. `sd` outlives the copy.
        let bytes = unsafe {
            let size = usize::from((*dacl).AclSize);
            std::slice::from_raw_parts(dacl.cast::<u8>(), size).to_vec()
        };
        Some(parse_acl(&bytes)?)
    };
    Ok(ObjectSecurity {
        owner,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        dacl,
    })
}

/// [`object_security`] for a file or directory named by path.
///
/// Opens `path` for `READ_CONTROL` only — with `FILE_FLAG_BACKUP_SEMANTICS`, which is what lets
/// `CreateFileW` open a directory at all, and grants nothing extra to a caller without the backup
/// privilege — and reads its owner and DACL. What the tests, here and in the crates that write
/// files through this module, use to check what actually landed on disk.
///
/// # Errors
///
/// Any failure opening `path` or reading its descriptor.
pub fn path_security(path: &Path) -> io::Result<ObjectSecurity> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    object_security(file.as_handle())
}

/// Whether `security` is exactly the owner-only descriptor this module writes for `kind`, for
/// `user`: `user` owns it, the DACL is protected, and it holds one allow entry, `FILE_ALL_ACCESS`
/// for `user`, not inherited, with the inheritance flags `kind` calls for.
///
/// `check_owner` is `false` only for a file re-secured by [`create_or_truncate_file`], which
/// replaces the DACL but leaves the owner as it was.
#[must_use]
pub fn is_owner_only(
    security: &ObjectSecurity,
    user: &Sid,
    kind: ObjectKind,
    check_owner: bool,
) -> bool {
    let flags = match kind {
        ObjectKind::Directory => INHERIT_TO_CHILDREN,
        ObjectKind::File | ObjectKind::Pipe => 0,
    };
    let entry_is_ours = |ace: &Ace| {
        ace.is_allow()
            && ace.sid.as_ref() == Some(user)
            && ace.mask == Some(FILE_ALL_ACCESS)
            && ace.flags == flags
    };
    (!check_owner || security.owner == *user)
        && security.dacl_protected
        && matches!(security.dacl.as_deref(), Some([only]) if entry_is_ours(only))
}

/// Parse an ACL from its binary form, bounds-checking every entry against the ACL's own size.
fn parse_acl(bytes: &[u8]) -> io::Result<Vec<Ace>> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed ACL");
    let u16_at = |b: &[u8], at: usize| -> io::Result<u16> {
        let s = b.get(at..at + 2).ok_or_else(malformed)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    };
    // ACL header: revision, pad, AclSize (u16), AceCount (u16), pad (u16).
    let count = u16_at(bytes, 4)?;
    let mut aces = Vec::with_capacity(usize::from(count));
    let mut offset = 8_usize;
    for _ in 0..count {
        // ACE_HEADER: type, flags, AceSize (u16) — the size covers the header.
        let ace_type = *bytes.get(offset).ok_or_else(malformed)?;
        let flags = *bytes.get(offset + 1).ok_or_else(malformed)?;
        let size = usize::from(u16_at(bytes, offset + 2)?);
        let ace = bytes.get(offset..offset + size).ok_or_else(malformed)?;
        if size < 4 {
            return Err(malformed());
        }
        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE: header, then a u32 mask, then the SID.
        let (mask, sid) = if ace_type <= 1 {
            let m = ace.get(4..8).ok_or_else(malformed)?;
            let mask = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
            (
                Some(mask),
                Some(Sid::parse_prefix(ace.get(8..).ok_or_else(malformed)?)?),
            )
        } else {
            (None, None)
        };
        aces.push(Ace {
            ace_type,
            flags,
            mask,
            sid,
        });
        offset += size;
    }
    Ok(aces)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The assertion every test below makes: owned by us, protected, one allow entry for us —
    /// spelled out field by field for a readable failure, then through [`is_owner_only`], so
    /// that the predicate other crates' tests rely on is itself checked against the long form.
    fn assert_owner_only(security: &ObjectSecurity, kind: ObjectKind) {
        let me = current_user_sid().unwrap();
        assert_eq!(security.owner, me, "owner");
        assert!(
            security.dacl_protected,
            "DACL must be protected: {security:?}"
        );
        let dacl = security.dacl.as_ref().expect("a DACL, not a null one");
        assert_eq!(dacl.len(), 1, "exactly one entry: {dacl:?}");
        let ace = &dacl[0];
        assert!(ace.is_allow(), "{ace:?}");
        assert_eq!(ace.sid.as_ref(), Some(&me));
        assert_eq!(ace.mask, Some(FILE_ALL_ACCESS));
        let flags = if kind == ObjectKind::Directory {
            INHERIT_TO_CHILDREN
        } else {
            0
        };
        assert_eq!(ace.flags, flags, "{ace:?}");
        assert!(is_owner_only(security, &me, kind, true));
    }

    fn security_of(path: &Path) -> ObjectSecurity {
        path_security(path).unwrap()
    }

    #[test]
    fn the_current_user_has_a_user_sid() {
        let sid = current_user_sid().unwrap();
        let text = sid.to_string();
        assert!(text.starts_with("S-1-5-"), "{text}");
        assert_eq!(Sid::parse_prefix(sid.as_bytes()).unwrap(), sid);
    }

    #[test]
    fn a_new_file_is_owner_only_from_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        drop(create_new_file(&path).unwrap());
        assert_owner_only(&security_of(&path), ObjectKind::File);
    }

    #[test]
    fn create_new_refuses_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("taken");
        std::fs::write(&path, b"x").unwrap();
        let err = create_new_file(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn an_existing_file_is_re_secured_before_it_is_emptied() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.md");
        std::fs::write(&path, b"old contents").unwrap();
        // Inherited from the temp directory, not ours yet.
        assert!(!security_of(&path).dacl_protected);
        let mut file = create_or_truncate_file(&path).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let security = security_of(&path);
        // The owner is left alone on this path (see `restrict_to_owner`); the DACL is ours.
        let me = current_user_sid().unwrap();
        assert!(security.dacl_protected);
        let dacl = security.dacl.unwrap();
        assert_eq!(dacl.len(), 1, "{dacl:?}");
        assert_eq!(dacl[0].sid.as_ref(), Some(&me));
        assert!(dacl[0].is_allow());
    }

    #[test]
    fn created_directories_pass_the_entry_down() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        create_dir_all(&nested).unwrap();
        assert_owner_only(&security_of(&dir.path().join("a")), ObjectKind::Directory);
        assert_owner_only(&security_of(&nested), ObjectKind::Directory);

        // A file created inside by plain `std` inherits the single entry, not the temp dir's.
        // (Not asserted: the `INHERITED` flag. `CreateFileW` does not ask for auto-inheritance,
        // so the descriptor the object actually holds — which is what `object_security` reads —
        // carries the inherited entry without that flag; `icacls` shows `(I)` because the
        // file-object view reconstructs it from the parent. The entry is what grants access.)
        let child = nested.join("plain");
        std::fs::write(&child, b"x").unwrap();
        let security = security_of(&child);
        assert!(!security.dacl_protected);
        let dacl = security.dacl.unwrap();
        assert_eq!(dacl.len(), 1, "{dacl:?}");
        assert_eq!(dacl[0].sid, Some(current_user_sid().unwrap()));
        assert_eq!(dacl[0].mask, Some(FILE_ALL_ACCESS));

        // And an existing directory is left alone.
        create_dir_all(&nested).unwrap();
        assert!(!security_of(dir.path()).dacl_protected);
    }

    #[test]
    fn the_string_form_matches_the_documented_layout() {
        // S-1-5-18, LocalSystem: revision 1, one sub-authority, authority 5, sub-authority 18.
        let system = Sid(vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        assert_eq!(system.to_string(), "S-1-5-18");
        assert_eq!(
            sddl_for(&system, ObjectKind::Directory),
            "O:S-1-5-18D:P(A;OICI;FA;;;S-1-5-18)"
        );
        assert_eq!(
            sddl_for(&system, ObjectKind::Pipe),
            "O:S-1-5-18D:P(A;;FA;;;S-1-5-18)"
        );
    }
}
