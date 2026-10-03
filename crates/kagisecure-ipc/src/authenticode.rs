//! Authenticode verification of a peer process: the Windows counterpart of the macOS app's
//! `PeerCodeSignature` ([ADR-0015](../../../docs/decisions/0015-peer-code-signature-verification.md)),
//! and **structurally weaker than it** ([ADR-0032](../../../docs/decisions/0032-authenticode-peer-verification.md)).
//!
//! # What is being compared with what
//!
//! macOS checks the *running process*: `SecCodeCopyGuestWithAttributes` resolves a pid to a live
//! `SecCode`, and `SecCodeCheckValidity` checks the pages that process is executing. Windows has no
//! counterpart for an ordinary process. `WinVerifyTrust` verifies a **file**, so this module has to
//! go pid → image path → file → signature, and every arrow is a place where the thing checked can
//! stop being the thing that is running. [`verify_peer`] narrows those windows as far as the
//! documented API allows:
//!
//! 1. **The process handle is opened first and held throughout.** An open handle keeps the process
//!    object, and therefore its pid, from being reused until it is closed, so every later question
//!    is asked of one process rather than of "whoever has that number now".
//! 2. **The image path is read from that handle** (`QueryFullProcessImageNameW`,
//!    `PROCESS_NAME_WIN32`) and must equal `expected_executable` — the path the approval sheet
//!    shows. A mismatch means the pid now names a different program, and nothing is verified.
//! 3. **The file is opened with a share mode that denies writing and deleting** (and so renaming)
//!    for as long as the check runs, and without following a reparse point at the final
//!    component. The signature is then verified **through that handle**
//!    (`WINTRUST_FILE_INFO::hFile`), so the bytes hashed are the bytes of the file that was opened.
//! 4. **The image path is read again after the open, and again at the end,** and must not have
//!    changed; and the process must still be running (`WaitForSingleObject(handle, 0)`). The
//!    `PROCESS_NAME_WIN32` name follows a rename of the image file itself — measured on Windows 11
//!    26200 — so a running image renamed away and replaced by a signed file between steps 2 and 3
//!    shows up as a changed path here and is refused.
//!
//! What this still cannot see, stated plainly: the name `QueryFullProcessImageNameW` reports does
//! **not** follow a rename of a *parent directory* (same measurement). A same-user attacker who
//! can rename the directory their unsigned program runs from can put a genuinely signed file at
//! the old path, and this check will verify that file. That, and the fact that a same-user process
//! can inject into a genuinely signed one anyway, is why the verdict is a warning on the sheet and
//! never a gate (ADR-0015's rule, kept), and why ADR-0032 calls the result weaker than macOS rather
//! than equivalent to it.
//!
//! # Policy
//!
//! * **Embedded signatures only.** Catalog-signed files (most of `System32`) are reported as
//!   having no embedded signature. Neither of the two requirements can ever be met by a catalog
//!   signature — our helpers and every supported browser carry embedded signatures — so the
//!   `CryptCATAdmin*` path would add unsafe code for no caller.
//! * **No revocation checking, and no network.** `WTD_REVOKE_NONE` with
//!   `WTD_CACHE_ONLY_URL_RETRIEVAL`: the check runs while an approval sheet is waiting for a
//!   human, must work offline, and should not tell a CRL or OCSP server which binaries asked for
//!   secrets. The evidence line says "revocation not checked" so nobody reads more into it.
//! * **An unsigned build of kagisecure verifies nothing as "ours".** Two unsigned binaries do not
//!   share a signer; they share the absence of one. [`Requirement::SameSignerAsThisProcess`] on a
//!   `cargo build` is therefore always unverified, with evidence that says why.
//!
//! # Unsafe code
//!
//! Like [`crate::kernel_peer`], this module is one of the crate's reviewed exceptions to
//! `#![deny(unsafe_code)]`, and only its Windows implementation uses it. Everything that decides a
//! verdict ([`Requirement`], the browser table, and the comparison in `judge`) is safe code that
//! compiles, and is tested, on every platform.

#![allow(unsafe_code)]

use std::path::Path;

/// The prefix every evidence line carries, so the audit log says which mechanism reached it.
const PREFIX: &str = "Authenticode: ";

/// A third party's code-signing identity: who must have signed a browser for it to be that browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publisher {
    /// What the approval sheet calls the program, e.g. `"Google Chrome"`.
    pub name: &'static str,
    /// The leaf signing certificate's subject common names that are accepted, compared exactly.
    ///
    /// Exact rather than "contains": `"Google LLC"` must not be satisfied by a certificate issued
    /// to `"Not Google LLC"`. A publicly trusted code-signing CA validates the organization named
    /// here before issuing, which is the whole of what makes the name mean something.
    pub subjects: &'static [&'static str],
}

/// The browsers this module knows the Authenticode publisher of, keyed by executable file name.
///
/// The Windows counterpart of `PeerCodeSignature.knownBrowsers` on macOS, which pairs a bundle
/// identifier with a team identifier. Authenticode has no signed identifier, so the file name —
/// the same key `kagisecure_extension_ipc::peer::known_browser_for` recognizes a browser by —
/// selects the publisher, and the signature must then name that publisher. The consequence, which
/// ADR-0032 records: any program **that publisher** signed, renamed to the browser's file name,
/// satisfies the entry.
///
/// * Google Chrome's and Microsoft Edge's subjects were read from the installed browsers on the
///   Windows 11 machine this was written on (`Get-AuthenticodeSignature`).
/// * Brave's was not — Brave was not installed there. A wrong value fails closed: Brave would be
///   reported unverified, never a stranger verified.
/// * Arc and Chromium are absent on purpose. Arc's Windows publisher was not confirmed (the same
///   reason `browser_setup` leaves Arc's registry key out), and Chromium builds are not signed by
///   anyone in particular. Both are reported as having no known publisher.
pub const KNOWN_BROWSERS: &[(&str, Publisher)] = &[
    (
        "chrome.exe",
        Publisher {
            name: "Google Chrome",
            subjects: &["Google LLC"],
        },
    ),
    (
        "msedge.exe",
        Publisher {
            name: "Microsoft Edge",
            subjects: &["Microsoft Corporation"],
        },
    ),
    (
        "brave.exe",
        Publisher {
            name: "Brave Browser",
            subjects: &["Brave Software, Inc."],
        },
    ),
];

/// What a peer's signature must satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// One of kagisecure's own helpers (the MCP sidecar, the native messaging host): the peer's
    /// leaf signing certificate must carry the same public key as the certificate that signed the
    /// module this code is running in. The Windows form of ADR-0015's "same team as this app".
    ///
    /// Comparing keys rather than names means a stranger who obtains a certificate with the same
    /// subject is still a stranger, and comparing against this build rather than a constant means
    /// there is nothing to update at release time and a fork that signs both halves works.
    SameSignerAsThisProcess,
    /// Somebody else's program, signed by a specific publisher.
    Publisher(Publisher),
}

impl Requirement {
    /// The requirement for a browser, chosen by `executable`'s file name from [`KNOWN_BROWSERS`].
    ///
    /// Case-insensitive, as `known_browser_for` is on Windows: `CHROME.EXE` and `chrome.exe` name
    /// the same file there. `None` for a browser with no known publisher.
    #[must_use]
    pub fn for_browser_executable(executable: &Path) -> Option<Self> {
        let name = executable.file_name()?.to_str()?;
        KNOWN_BROWSERS
            .iter()
            .find(|(file, _)| name.eq_ignore_ascii_case(file))
            .map(|(_, publisher)| Self::Publisher(*publisher))
    }
}

/// The verdict: whether the requirement was met, and one line saying what was found.
///
/// The same shape as the macOS `PeerSignature` and as `ClientVerification`, so it can travel into
/// the lease and the audit entry unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    /// Whether the peer satisfied the requirement.
    pub verified: bool,
    /// One human-readable line for the approval sheet and the audit log.
    pub evidence: String,
}

impl Verification {
    #[cfg_attr(not(windows), allow(dead_code))]
    fn verified(evidence: impl std::fmt::Display) -> Self {
        Self {
            verified: true,
            evidence: format!("{PREFIX}{evidence}"),
        }
    }

    fn unverified(evidence: impl std::fmt::Display) -> Self {
        Self {
            verified: false,
            evidence: format!("{PREFIX}{evidence}"),
        }
    }
}

/// Check the process `pid` against `requirement`.
///
/// `expected_executable` is the path the caller already knows the peer by — the approval request's
/// `client_executable` / `browser_executable`, which the agent resolved from the kernel's pid when
/// the request arrived. It must equal the image path of the process `pid` names *now*, or nothing
/// is verified: that is what catches a pid that has since been handed to another program.
///
/// Never fails and never blocks on the network; every failure is `verified: false` with the reason
/// in the evidence. Off Windows it always answers "not available on this platform" — the macOS app
/// runs its own Security.framework check in Swift (ADR-0015).
#[must_use]
pub fn verify_peer(
    pid: u32,
    expected_executable: &Path,
    requirement: &Requirement,
) -> Verification {
    #[cfg(windows)]
    {
        let peer = imp::inspect_process(pid, expected_executable);
        match requirement {
            Requirement::SameSignerAsThisProcess => judge(requirement, &peer, imp::own_signature()),
            // A publisher requirement never consults this build's own signature.
            Requirement::Publisher(_) => judge(requirement, &peer, &Inspection::NotSigned),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, expected_executable, requirement);
        unsupported()
    }
}

/// [`verify_peer`] for a browser, with the publisher chosen from [`KNOWN_BROWSERS`] by the file
/// name of `executable`.
#[must_use]
pub fn verify_browser(pid: u32, executable: &Path) -> Verification {
    if cfg!(not(windows)) {
        return unsupported();
    }
    match Requirement::for_browser_executable(executable) {
        Some(requirement) => verify_peer(pid, executable, &requirement),
        None => Verification::unverified(format_args!(
            "{} is not a browser with a known publisher",
            executable
                .file_name()
                .map_or_else(|| executable.display(), |n| Path::new(n).display())
        )),
    }
}

/// The honest answer off Windows.
fn unsupported() -> Verification {
    Verification::unverified("not available on this platform")
}

/// A signing certificate, reduced to the two things a verdict needs.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signer {
    /// The leaf certificate's subject common name, for the evidence line and the publisher match.
    subject: String,
    /// The leaf certificate's `SubjectPublicKeyInfo`, for "same signer".
    key: PublicKey,
}

/// A certificate's `SubjectPublicKeyInfo`, copied out of the certificate so it outlives it.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicKey {
    algorithm: String,
    parameters: Vec<u8>,
    bits: Vec<u8>,
    unused_bits: u32,
}

/// What looking at one file (or one process's file) established.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Inspection {
    /// A valid embedded signature chaining to a trusted root, and its signer.
    Signed(Signer),
    /// No embedded signature at all. Catalog signatures are not consulted.
    NotSigned,
    /// Anything else, with the reason: the process is gone, the path moved, the signature is
    /// broken, the chain is untrusted.
    Refused(String),
}

#[cfg_attr(not(windows), allow(dead_code))]
const NOT_SIGNED: &str =
    "not signed (no embedded Authenticode signature; catalog signatures are not consulted)";

#[cfg_attr(not(windows), allow(dead_code))]
const CHAIN_NOTE: &str = "chain valid; revocation not checked";

/// Turn what was found about the peer (and, for our own helpers, about ourselves) into a verdict.
///
/// Pure and platform-independent, so every wording and every "never verified" rule here is tested
/// on every platform, not just the one the FFI runs on.
#[cfg_attr(not(windows), allow(dead_code))]
fn judge(requirement: &Requirement, peer: &Inspection, ours: &Inspection) -> Verification {
    // A problem establishing *which* file is running outranks anything about signatures: it means
    // the verdict would not be about the process that asked.
    if let Inspection::Refused(why) = peer {
        return Verification::unverified(why);
    }
    match requirement {
        Requirement::SameSignerAsThisProcess => {
            let ours = match ours {
                Inspection::Signed(ours) => ours,
                Inspection::NotSigned => {
                    let caller = match peer {
                        Inspection::Signed(p) => format!("the caller is signed by '{}'", p.subject),
                        _ => "the caller is not signed either".to_owned(),
                    };
                    return Verification::unverified(format_args!(
                        "this build of Kagisecure is unsigned, so no caller can be verified as its \
                         signer ({caller})"
                    ));
                }
                Inspection::Refused(why) => {
                    return Verification::unverified(format_args!(
                        "this build of Kagisecure's own signature could not be established ({why})"
                    ));
                }
            };
            let Inspection::Signed(peer) = peer else {
                return Verification::unverified(NOT_SIGNED);
            };
            if peer.key == ours.key {
                Verification::verified(format_args!(
                    "signed by '{}', the same signer as this build of Kagisecure ({CHAIN_NOTE})",
                    peer.subject
                ))
            } else if peer.subject == ours.subject {
                Verification::unverified(format_args!(
                    "signed by '{}' but with a different key — same name, not the same signer as \
                     this build of Kagisecure",
                    peer.subject
                ))
            } else {
                Verification::unverified(format_args!(
                    "signed by '{}', which differs from this build of Kagisecure's signer ('{}')",
                    peer.subject, ours.subject
                ))
            }
        }
        Requirement::Publisher(publisher) => {
            let Inspection::Signed(peer) = peer else {
                return Verification::unverified(NOT_SIGNED);
            };
            if publisher.subjects.contains(&peer.subject.as_str()) {
                Verification::verified(format_args!("signed by '{}' ({CHAIN_NOTE})", peer.subject))
            } else {
                Verification::unverified(format_args!(
                    "signed by '{}', not by {}'s publisher ('{}')",
                    peer.subject,
                    publisher.name,
                    publisher.subjects.join("' or '")
                ))
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::CStr;
    use std::fs::{File, OpenOptions};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{
        CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
        CERT_E_UNTRUSTEDTESTROOT, CRYPT_E_SECURITY_SETTINGS, CloseHandle, ERROR_SHARING_VIOLATION,
        HANDLE, HMODULE, INVALID_HANDLE_VALUE, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST,
        TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
        TRUST_E_SUBJECT_NOT_TRUSTED, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CertGetNameStringW, szOID_COMMON_NAME,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WTHelperGetProvCertFromChain,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleFileNameW, GetModuleHandleExW,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        QueryFullProcessImageNameW, WaitForSingleObject,
    };

    use super::{Inspection, PublicKey, Signer};

    /// Long enough for any Win32 path, including long-path-aware ones; see
    /// `kernel_peer::executable_path` for why `MAX_PATH` is the wrong size.
    const PATH_BUF: usize = 32768;

    /// An open process handle, closed on drop.
    ///
    /// Holding it is the pid-reuse guard: while any handle to a process object is open, the object
    /// — and its pid — survives, even after the process exits.
    struct Process {
        handle: HANDLE,
        pid: u32,
    }

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: `self.handle` came from `OpenProcess` and was checked to be non-null before
            // this value was constructed; `Drop` runs once, so it is closed exactly once.
            unsafe { CloseHandle(self.handle) };
        }
    }

    impl Process {
        fn open(pid: u32) -> Option<Self> {
            // `PROCESS_QUERY_LIMITED_INFORMATION` for the image path and `SYNCHRONIZE` for the
            // liveness wait: the least this needs, and — unlike `PROCESS_QUERY_INFORMATION` — both
            // still granted on the same user's elevated processes, which a browser or a sidecar
            // started from an elevated terminal may be.
            // SAFETY: a plain call with three by-value arguments; the result is checked for null
            // (the failure value) before it is wrapped, and the wrapper closes it.
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            if handle.is_null() {
                None
            } else {
                Some(Self { handle, pid })
            }
        }

        /// Whether the process is still running.
        ///
        /// A zero-timeout wait on the process object rather than `GetExitCodeProcess ==
        /// STILL_ACTIVE`: a process that exited with code 259 is indistinguishable from a live one
        /// by exit code, and not by this.
        fn is_running(&self) -> bool {
            // SAFETY: `self.handle` is a live process handle opened with `SYNCHRONIZE`, which is
            // the right a wait requires. A zero timeout makes this a poll; it cannot block.
            unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
        }

        /// The Win32 path of the process's image, read from this handle.
        fn image_path(&self) -> Option<PathBuf> {
            let mut buf = vec![0_u16; PATH_BUF];
            let mut len = u32::try_from(buf.len()).ok()?;
            // SAFETY: `self.handle` is live and carries `PROCESS_QUERY_LIMITED_INFORMATION`, the
            // right this call requires. `buf` is a live allocation of `buf.len()` code units and
            // `len` says so up front; on success it is overwritten with the count written, which
            // is all that is read back. Nothing is read from `buf` on failure.
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    self.handle,
                    PROCESS_NAME_WIN32,
                    buf.as_mut_ptr(),
                    std::ptr::addr_of_mut!(len),
                )
            };
            let len = usize::try_from(len).ok()?;
            if ok == 0 || len == 0 || len > buf.len() {
                return None;
            }
            buf.truncate(len);
            Some(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
        }
    }

    /// Establish which file `pid` is running, pin it, and verify its signature.
    ///
    /// The order of operations is the TOCTOU mitigation; the module documentation walks through
    /// it, and ADR-0032 says what it does not cover.
    pub(super) fn inspect_process(pid: u32, expected: &Path) -> Inspection {
        let Some(process) = Process::open(pid) else {
            return Inspection::Refused(format!(
                "process {pid} could not be opened — it has exited, or belongs to another account"
            ));
        };
        if !process.is_running() {
            return Inspection::Refused(format!("process {pid} has exited"));
        }
        let Some(image) = process.image_path() else {
            return Inspection::Refused(format!(
                "the executable of process {pid} could not be resolved"
            ));
        };
        if image != expected {
            return Inspection::Refused(format!(
                "process {pid} is running {}, not {} — the process that asked may have exited and \
                 its pid been reused",
                image.display(),
                expected.display()
            ));
        }

        let file = match open_pinned(&image) {
            Ok(file) => file,
            Err(why) => return Inspection::Refused(why),
        };
        // The file is now pinned: it cannot be written, renamed or deleted until `file` is dropped.
        // If the image was renamed away between reading its path and opening that path, the name
        // the process reports has changed, and the file just opened is not the one running.
        if process.image_path().as_deref() != Some(image.as_path()) {
            return moved(&process);
        }

        let inspection = verify_file(&image, &file);

        if !process.is_running() {
            return Inspection::Refused(format!("process {pid} exited during the check"));
        }
        if process.image_path().as_deref() != Some(image.as_path()) {
            return moved(&process);
        }
        drop(file);
        inspection
    }

    fn moved(process: &Process) -> Inspection {
        Inspection::Refused(format!(
            "the executable of process {} was moved during the check",
            process.pid
        ))
    }

    /// Verify a file by path, pinned for the duration exactly as a peer's image is.
    ///
    /// For the tests, which need a real signer to stand in for "ours", and for [`own_signature`].
    pub(crate) fn inspect_file(path: &Path) -> Inspection {
        match open_pinned(path) {
            Ok(file) => verify_file(path, &file),
            Err(why) => Inspection::Refused(why),
        }
    }

    /// Open `path` so that nobody can change what it names while the handle is open.
    ///
    /// `FILE_SHARE_READ` alone: other readers — including the loader, and whatever else is running
    /// this image — are unaffected, but no one can open it for writing or for deletion (which is
    /// also what a rename needs), and the open itself fails if someone already has. The final
    /// component is opened as itself (`FILE_FLAG_OPEN_REPARSE_POINT`) and refused if it is a
    /// reparse point: the image path Windows reports for a running process is already resolved,
    /// so a link at that exact path now means the path no longer names the image.
    fn open_pinned(path: &Path) -> Result<File, String> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == i32::try_from(ERROR_SHARING_VIOLATION).ok() {
                    format!(
                        "{} is open for writing or deletion by another process, so it cannot be \
                         pinned for the check",
                        path.display()
                    )
                } else {
                    format!("{} could not be opened for the check ({e})", path.display())
                }
            })?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("{} could not be inspected ({e})", path.display()))?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a reparse point, not the executable itself",
                path.display()
            ));
        }
        if !metadata.is_file() {
            return Err(format!("{} is not a file", path.display()));
        }
        Ok(file)
    }

    /// `WinVerifyTrust` state that must be closed exactly once, whatever the verdict was.
    ///
    /// `WTD_STATEACTION_VERIFY` leaves provider state allocated even when verification fails, and
    /// the signer certificate this module reads lives inside it — so the close happens on drop,
    /// after the certificate has been copied out, on every path.
    struct TrustState<'a> {
        data: &'a mut WINTRUST_DATA,
    }

    impl Drop for TrustState<'_> {
        fn drop(&mut self) {
            self.data.dwStateAction = WTD_STATEACTION_CLOSE;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            // SAFETY: `self.data` is the same `WINTRUST_DATA` a `WTD_STATEACTION_VERIFY` call was
            // made with, still pointing at its `WINTRUST_FILE_INFO` and the path buffer, both of
            // which outlive this guard (they are declared before it in `verify_file`). With
            // `WTD_STATEACTION_CLOSE` the call frees `hWVTStateData` and touches nothing else.
            unsafe {
                WinVerifyTrust(
                    INVALID_HANDLE_VALUE,
                    std::ptr::addr_of_mut!(action),
                    std::ptr::from_mut(&mut *self.data).cast(),
                )
            };
        }
    }

    /// Verify the embedded Authenticode signature of the file open as `file` (at `path`).
    fn verify_file(path: &Path, file: &File) -> Inspection {
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide_path.as_ptr(),
            // The handle is what gets hashed; the path is only a label for the provider.
            hFile: file.as_raw_handle(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            // No revocation checking and no network retrieval: see the module documentation.
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: std::ptr::addr_of_mut!(file_info),
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_REVOCATION_CHECK_NONE
                | WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_DISABLE_MD2_MD4,
            dwUIContext: WTD_UICONTEXT_EXECUTE,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` is a fully initialized `WINTRUST_DATA` whose `cbStruct` is its own size,
        // whose union member is `pFile` (matching `WTD_CHOICE_FILE`), pointing at `file_info`,
        // which points at `wide_path` (NUL-terminated) and at `file`'s handle, open for reading.
        // All of them outlive the call and the `TrustState` guard that closes the state after it.
        // `INVALID_HANDLE_VALUE` as the window means "no interactive user": no UI is shown.
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                std::ptr::addr_of_mut!(action),
                std::ptr::addr_of_mut!(data).cast(),
            )
        };
        let state = TrustState { data: &mut data };
        if status != 0 {
            return describe_failure(status);
        }
        // SAFETY: verification succeeded with `WTD_STATEACTION_VERIFY`, so `hWVTStateData` is the
        // provider state handle these helpers are documented to take; it stays valid until
        // `state` is dropped, after `signer_from_state` has copied out everything it needs.
        match unsafe { signer_from_state(state.data.hWVTStateData) } {
            Some(signer) => Inspection::Signed(signer),
            None => Inspection::Refused(
                "the signature verified but its signer certificate could not be read".to_owned(),
            ),
        }
    }

    /// Read the primary signer's leaf certificate out of verified `WinVerifyTrust` state.
    ///
    /// # Safety
    ///
    /// `state` must be the `hWVTStateData` of a successful `WTD_STATEACTION_VERIFY` call that has
    /// not yet been closed, and must stay unclosed until this returns.
    unsafe fn signer_from_state(state: HANDLE) -> Option<Signer> {
        // SAFETY: per this function's contract, `state` is live provider state.
        let provider = unsafe { WTHelperProvDataFromStateData(state) };
        if provider.is_null() {
            return None;
        }
        // Signer 0, not a countersigner: the primary signature's signer.
        // SAFETY: `provider` is non-null provider data from the call above, valid while `state`.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null() {
            return None;
        }
        // Certificate 0 of the signer's chain is the signer's own (leaf) certificate.
        // SAFETY: `signer` is non-null signer data owned by `provider`, valid while `state`.
        let cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if cert.is_null() {
            return None;
        }
        // SAFETY: `cert` is a non-null `CRYPT_PROVIDER_CERT` owned by the provider state.
        let context = unsafe { (*cert).pCert };
        if context.is_null() {
            return None;
        }
        // SAFETY: `context` is a non-null certificate context owned by the provider state, which
        // outlives this call per this function's contract.
        unsafe { signer_from_certificate(context) }
    }

    /// Copy the subject common name and the public key out of `context`.
    ///
    /// # Safety
    ///
    /// `context` must point at a valid `CERT_CONTEXT` for the duration of the call.
    unsafe fn signer_from_certificate(context: *const CERT_CONTEXT) -> Option<Signer> {
        let oid = szOID_COMMON_NAME.cast::<core::ffi::c_void>();
        // SAFETY: `context` is valid per the contract; `oid` is a static NUL-terminated OID string,
        // which is what `CERT_NAME_ATTR_TYPE` takes as its type parameter. A null buffer with a
        // zero length asks for the required length (in UTF-16 units, including the NUL).
        let needed = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_ATTR_TYPE,
                0,
                oid,
                std::ptr::null_mut(),
                0,
            )
        };
        let mut name = vec![0_u16; usize::try_from(needed).ok()?.max(1)];
        // SAFETY: as above, with `name` a live buffer of exactly the length passed alongside it.
        let written = unsafe {
            CertGetNameStringW(
                context,
                CERT_NAME_ATTR_TYPE,
                0,
                oid,
                name.as_mut_ptr(),
                u32::try_from(name.len()).ok()?,
            )
        };
        // The count includes the terminating NUL; 1 means "no such attribute".
        let chars = usize::try_from(written)
            .ok()?
            .saturating_sub(1)
            .min(name.len());
        let subject = String::from_utf16_lossy(&name[..chars]);

        // SAFETY: `context` is valid per the contract.
        let info = unsafe { (*context).pCertInfo };
        if info.is_null() {
            return None;
        }
        // SAFETY: `info` is the non-null `CERT_INFO` of a valid certificate context, and lives as
        // long as the context does.
        let spki = unsafe { &(*info).SubjectPublicKeyInfo };
        let algorithm = if spki.Algorithm.pszObjId.is_null() {
            String::new()
        } else {
            // SAFETY: a non-null `pszObjId` is a NUL-terminated ASCII OID owned by the certificate.
            unsafe { CStr::from_ptr(spki.Algorithm.pszObjId.cast()) }
                .to_string_lossy()
                .into_owned()
        };
        // SAFETY: the parameters blob's `pbData` points at `cbData` bytes owned by the
        // certificate; `bytes` checks for null/empty before building a slice.
        let parameters = unsafe {
            bytes(
                spki.Algorithm.Parameters.pbData,
                spki.Algorithm.Parameters.cbData,
            )
        };
        // SAFETY: likewise for the key's bit string.
        let bits = unsafe { bytes(spki.PublicKey.pbData, spki.PublicKey.cbData) };
        if bits.is_empty() {
            return None;
        }
        Some(Signer {
            subject,
            key: PublicKey {
                algorithm,
                parameters,
                bits,
                unused_bits: spki.PublicKey.cUnusedBits,
            },
        })
    }

    /// Copy `len` bytes at `ptr`, or nothing when there are none.
    ///
    /// # Safety
    ///
    /// When `ptr` is non-null and `len` is non-zero, `ptr` must be valid for reads of `len` bytes.
    unsafe fn bytes(ptr: *const u8, len: u32) -> Vec<u8> {
        let Ok(len) = usize::try_from(len) else {
            return Vec::new();
        };
        if ptr.is_null() || len == 0 {
            return Vec::new();
        }
        // SAFETY: non-null and non-empty, so valid for `len` bytes per this function's contract.
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }

    /// What a failed `WinVerifyTrust` means, in words for the sheet.
    fn describe_failure(status: i32) -> Inspection {
        let why = match status {
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                return Inspection::NotSigned;
            }
            TRUST_E_BAD_DIGEST => "signature does not match the file — modified after signing",
            CERT_E_UNTRUSTEDROOT | CERT_E_UNTRUSTEDTESTROOT => {
                "signed, but the certificate chain ends in a root this machine does not trust"
            }
            CERT_E_CHAINING => "signed, but the certificate chain could not be built",
            CERT_E_EXPIRED => "signed with a certificate that has expired, and not timestamped",
            CERT_E_REVOKED => "signed with a certificate that has been revoked",
            TRUST_E_EXPLICIT_DISTRUST => {
                "signed with a certificate this machine explicitly distrusts"
            }
            CRYPT_E_SECURITY_SETTINGS => "signature rejected by this machine's security policy",
            TRUST_E_SUBJECT_NOT_TRUSTED => "signature present but not trusted",
            _ => {
                return Inspection::Refused(format!(
                    "signature invalid (WinVerifyTrust 0x{:08X})",
                    status.cast_unsigned()
                ));
            }
        };
        Inspection::Refused(why.to_owned())
    }

    /// The signature on the module this code is running in — `kagisecure_ffi.dll` in the Windows
    /// app, the executable itself for a statically linked binary — computed once per process.
    ///
    /// The module rather than the process image, because the module is what this project builds
    /// and signs: under the WinUI app the process image is the C# host, and a verdict about
    /// "ours" should rest on the code that is actually making it.
    pub(super) fn own_signature() -> &'static Inspection {
        static OWN: OnceLock<Inspection> = OnceLock::new();
        OWN.get_or_init(|| match own_module_path() {
            Some(path) => inspect_file(&path),
            None => Inspection::Refused("this module's own file could not be located".to_owned()),
        })
    }

    fn own_module_path() -> Option<PathBuf> {
        let mut module: HMODULE = std::ptr::null_mut();
        // Any address inside this module identifies it; this function's own is the obvious one.
        let anchor = own_module_path as *const () as *const u16;
        // SAFETY: with `FROM_ADDRESS`, the name parameter is an address inside a loaded module,
        // which a function of this module is. `UNCHANGED_REFCOUNT` means the returned handle is
        // not owned and must not be freed, and it is not. `module` is live stack storage.
        let ok = unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                anchor,
                std::ptr::addr_of_mut!(module),
            )
        };
        if ok == 0 || module.is_null() {
            return None;
        }
        let mut buf = vec![0_u16; PATH_BUF];
        // SAFETY: `module` is a handle to a module that stays loaded (it contains this code), and
        // `buf` is a live buffer of the length passed alongside it. The return value is the
        // number of units written, excluding the NUL, or the buffer length on truncation.
        let len =
            unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), u32::try_from(buf.len()).ok()?) };
        let len = usize::try_from(len).ok()?;
        if len == 0 || len >= buf.len() {
            return None;
        }
        buf.truncate(len);
        Some(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(subject: &str, key: u8) -> Inspection {
        Inspection::Signed(Signer {
            subject: subject.to_owned(),
            key: PublicKey {
                algorithm: "1.2.840.113549.1.1.1".to_owned(),
                parameters: vec![5, 0],
                bits: vec![key; 32],
                unused_bits: 0,
            },
        })
    }

    const GOOGLE: Publisher = KNOWN_BROWSERS[0].1;

    #[test]
    fn the_browser_table_is_chosen_by_file_name_case_insensitively() {
        // Built from components rather than written as `C:\...`: a backslash is a separator on
        // Windows only, and the lookup is by file name, which this test runs everywhere.
        let chrome: std::path::PathBuf = [
            "Program Files",
            "Google",
            "Chrome",
            "Application",
            "CHROME.EXE",
        ]
        .iter()
        .collect();
        assert_eq!(
            Requirement::for_browser_executable(&chrome),
            Some(Requirement::Publisher(GOOGLE))
        );
        let edge = Requirement::for_browser_executable(Path::new("msedge.exe"));
        assert!(
            matches!(edge, Some(Requirement::Publisher(p)) if p.subjects == ["Microsoft Corporation"])
        );
        // No publisher is known for these, so no requirement exists that they could meet.
        for unknown in [
            "chromium.exe",
            "Arc.exe",
            "chrome.exe.evil",
            "evil-chrome.exe",
            "",
        ] {
            assert_eq!(
                Requirement::for_browser_executable(Path::new(unknown)),
                None,
                "{unknown}"
            );
        }
    }

    #[test]
    fn a_publisher_is_matched_exactly_not_by_substring() {
        let req = Requirement::Publisher(GOOGLE);
        let ok = judge(&req, &signer("Google LLC", 1), &Inspection::NotSigned);
        assert!(ok.verified, "{ok:?}");
        assert_eq!(
            ok.evidence,
            "Authenticode: signed by 'Google LLC' (chain valid; revocation not checked)"
        );
        for impostor in ["Not Google LLC", "Google LLC Evil", "google llc", "Google"] {
            let v = judge(&req, &signer(impostor, 1), &Inspection::NotSigned);
            assert!(!v.verified, "{impostor}");
            assert!(
                v.evidence
                    .contains("not by Google Chrome's publisher ('Google LLC')"),
                "{v:?}"
            );
        }
    }

    #[test]
    fn two_unsigned_binaries_never_share_a_signer() {
        let v = judge(
            &Requirement::SameSignerAsThisProcess,
            &Inspection::NotSigned,
            &Inspection::NotSigned,
        );
        assert!(!v.verified);
        assert!(
            v.evidence.contains("this build of Kagisecure is unsigned"),
            "{v:?}"
        );
        assert!(v.evidence.contains("not signed either"), "{v:?}");
    }

    #[test]
    fn same_signer_compares_keys_not_names() {
        let req = Requirement::SameSignerAsThisProcess;
        let same = judge(&req, &signer("Kagisecure", 7), &signer("Kagisecure", 7));
        assert!(same.verified, "{same:?}");

        let other_key = judge(&req, &signer("Kagisecure", 8), &signer("Kagisecure", 7));
        assert!(!other_key.verified);
        assert!(
            other_key.evidence.contains("different key"),
            "{other_key:?}"
        );

        let stranger = judge(&req, &signer("Mallory", 8), &signer("Kagisecure", 7));
        assert!(!stranger.verified);
        assert!(
            stranger.evidence.contains("differs from this build"),
            "{stranger:?}"
        );

        let unsigned_peer = judge(&req, &Inspection::NotSigned, &signer("Kagisecure", 7));
        assert!(!unsigned_peer.verified);
        assert!(
            unsigned_peer.evidence.contains("not signed"),
            "{unsigned_peer:?}"
        );

        let broken_self = judge(
            &req,
            &signer("Kagisecure", 7),
            &Inspection::Refused("bad digest".to_owned()),
        );
        assert!(!broken_self.verified);
        assert!(
            broken_self
                .evidence
                .contains("own signature could not be established")
        );
    }

    #[test]
    fn a_problem_finding_the_process_outranks_everything_else() {
        let gone = Inspection::Refused("process 1 has exited".to_owned());
        for req in [
            Requirement::SameSignerAsThisProcess,
            Requirement::Publisher(GOOGLE),
        ] {
            let v = judge(&req, &gone, &signer("Kagisecure", 7));
            assert!(!v.verified);
            assert_eq!(v.evidence, "Authenticode: process 1 has exited");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_nothing_is_verified_and_it_says_why() {
        let pid = std::process::id();
        for v in [
            verify_peer(
                pid,
                Path::new("/bin/sh"),
                &Requirement::SameSignerAsThisProcess,
            ),
            verify_browser(pid, Path::new("chrome.exe")),
        ] {
            assert!(!v.verified);
            assert_eq!(v.evidence, "Authenticode: not available on this platform");
        }
    }

    /// Against real processes and real signatures. Every peer is started **suspended**: the process
    /// exists, its image is mapped and its path is resolvable, but not one instruction of it runs,
    /// so starting Microsoft Edge here has no side effect at all.
    #[cfg(windows)]
    mod windows {
        use std::os::windows::process::CommandExt;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};

        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        use super::super::imp::inspect_file;
        use super::super::*;
        use crate::kernel_peer;

        /// Kills and reaps the child on drop, so a failed assertion leaves nothing suspended.
        struct Suspended(Child);

        impl Drop for Suspended {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        impl Suspended {
            fn start(exe: &Path) -> Self {
                let child = Command::new(exe)
                    .creation_flags(CREATE_SUSPENDED)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap_or_else(|e| panic!("start {} suspended: {e}", exe.display()));
                Self(child)
            }

            fn pid(&self) -> u32 {
                self.0.id()
            }

            /// The path the agent would have put on the approval request for this pid.
            fn executable(&self) -> PathBuf {
                PathBuf::from(kernel_peer::executable_path(self.pid()).expect("image path"))
            }
        }

        /// Microsoft Edge, which ships with Windows 11 and carries an embedded signature by
        /// "Microsoft Corporation" (read on the machine this was written on).
        fn edge() -> Option<PathBuf> {
            ["ProgramFiles(x86)", "ProgramFiles"]
                .iter()
                .filter_map(std::env::var_os)
                .map(|root| PathBuf::from(root).join(r"Microsoft\Edge\Application\msedge.exe"))
                .find(|p| p.is_file())
        }

        fn system32(exe: &str) -> PathBuf {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
            PathBuf::from(root).join("System32").join(exe)
        }

        const MICROSOFT_WINDOWS: Publisher = Publisher {
            name: "Windows",
            subjects: &["Microsoft Windows", "Microsoft Corporation"],
        };

        macro_rules! edge_or_skip {
            () => {
                match edge() {
                    Some(path) => path,
                    None => {
                        eprintln!("skipping: Microsoft Edge is not installed on this machine");
                        return;
                    }
                }
            };
        }

        #[test]
        fn a_running_edge_is_verified_as_microsoft_edge_by_its_pid() {
            let edge = edge_or_skip!();
            let peer = Suspended::start(&edge);
            let v = verify_browser(peer.pid(), &peer.executable());
            assert!(v.verified, "{v:?}");
            assert_eq!(
                v.evidence,
                "Authenticode: signed by 'Microsoft Corporation' (chain valid; revocation not \
                 checked)"
            );
        }

        #[test]
        fn edge_does_not_satisfy_google_chromes_publisher() {
            let edge = edge_or_skip!();
            let peer = Suspended::start(&edge);
            let chrome = Requirement::for_browser_executable(Path::new("chrome.exe")).unwrap();
            let v = verify_peer(peer.pid(), &peer.executable(), &chrome);
            assert!(!v.verified, "{v:?}");
            assert_eq!(
                v.evidence,
                "Authenticode: signed by 'Microsoft Corporation', not by Google Chrome's \
                 publisher ('Google LLC')"
            );
        }

        /// `cmd.exe` is signed by Microsoft — through a catalog, not an embedded signature, like
        /// nearly all of `System32` on this machine. That is reported as what it is rather than
        /// verified: catalog signatures are out of scope (ADR-0032).
        #[test]
        fn a_catalog_signed_system_binary_has_no_embedded_signature() {
            let peer = Suspended::start(&system32("cmd.exe"));
            let v = verify_peer(
                peer.pid(),
                &peer.executable(),
                &Requirement::Publisher(MICROSOFT_WINDOWS),
            );
            assert!(!v.verified, "{v:?}");
            assert_eq!(v.evidence, format!("Authenticode: {NOT_SIGNED}"));
        }

        #[test]
        fn an_unsigned_binary_is_not_signed() {
            // This test binary, from `target/`, which nobody signs.
            let exe = std::env::current_exe().unwrap();
            let peer = Suspended::start(&exe);
            let v = verify_peer(
                peer.pid(),
                &peer.executable(),
                &Requirement::Publisher(MICROSOFT_WINDOWS),
            );
            assert!(!v.verified, "{v:?}");
            assert!(v.evidence.contains("not signed"), "{v:?}");
        }

        #[test]
        fn an_unsigned_build_verifies_nobody_as_its_own_signer() {
            let edge = edge_or_skip!();
            assert_eq!(
                imp::own_signature(),
                &Inspection::NotSigned,
                "this test assumes an unsigned test binary"
            );
            let peer = Suspended::start(&edge);
            let v = verify_peer(
                peer.pid(),
                &peer.executable(),
                &Requirement::SameSignerAsThisProcess,
            );
            assert!(!v.verified, "{v:?}");
            assert_eq!(
                v.evidence,
                "Authenticode: this build of Kagisecure is unsigned, so no caller can be verified \
                 as its signer (the caller is signed by 'Microsoft Corporation')"
            );
        }

        /// The verified branch of `SameSignerAsThisProcess`, which an unsigned test binary cannot
        /// reach on its own: Edge's own file stands in for "this build", so the comparison runs on
        /// two real certificates read through the real `WinVerifyTrust` path.
        #[test]
        fn the_same_certificate_is_the_same_signer_and_an_unsigned_peer_is_not() {
            let edge = edge_or_skip!();
            let ours = inspect_file(&edge);
            assert!(matches!(ours, Inspection::Signed(_)), "{ours:?}");
            let req = Requirement::SameSignerAsThisProcess;

            let peer = Suspended::start(&edge);
            let peer_seen = imp::inspect_process(peer.pid(), &peer.executable());
            let v = judge(&req, &peer_seen, &ours);
            assert!(v.verified, "{v:?}");
            assert!(
                v.evidence.contains("the same signer as this build"),
                "{v:?}"
            );

            let unsigned = Suspended::start(&std::env::current_exe().unwrap());
            let unsigned_seen = imp::inspect_process(unsigned.pid(), &unsigned.executable());
            let v = judge(&req, &unsigned_seen, &ours);
            assert!(!v.verified, "{v:?}");
        }

        /// Google Chrome, when it is installed (it was on the machine this was written on), for
        /// the table's other confirmed entry and for "a different real signer is not ours".
        #[test]
        fn chrome_is_verified_as_google_chrome_and_is_not_edges_signer() {
            let edge = edge_or_skip!();
            let Some(chrome) = ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
                .iter()
                .filter_map(std::env::var_os)
                .map(|root| PathBuf::from(root).join(r"Google\Chrome\Application\chrome.exe"))
                .find(|p| p.is_file())
            else {
                eprintln!("skipping: Google Chrome is not installed on this machine");
                return;
            };
            let peer = Suspended::start(&chrome);
            let v = verify_browser(peer.pid(), &peer.executable());
            assert!(v.verified, "{v:?}");
            assert!(v.evidence.contains("signed by 'Google LLC'"), "{v:?}");

            let peer_seen = imp::inspect_process(peer.pid(), &peer.executable());
            let v = judge(
                &Requirement::SameSignerAsThisProcess,
                &peer_seen,
                &inspect_file(&edge),
            );
            assert!(!v.verified, "{v:?}");
            assert_eq!(
                v.evidence,
                "Authenticode: signed by 'Google LLC', which differs from this build of \
                 Kagisecure's signer ('Microsoft Corporation')"
            );
        }

        #[test]
        fn a_process_that_is_not_the_expected_executable_is_not_verified() {
            let edge = edge_or_skip!();
            let peer = Suspended::start(&edge);
            let expected = system32("notepad.exe");
            let v = verify_peer(
                peer.pid(),
                &expected,
                &Requirement::Publisher(KNOWN_BROWSERS[1].1),
            );
            assert!(!v.verified, "{v:?}");
            assert!(v.evidence.contains("msedge.exe, not "), "{v:?}");
            assert!(v.evidence.contains("pid been reused"), "{v:?}");
        }

        #[test]
        fn an_exited_process_is_not_verified() {
            let mut child = Command::new(system32("cmd.exe"))
                .args(["/c", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            let expected = system32("cmd.exe");
            child.wait().unwrap();
            // `child` still holds its process handle, so the pid still names this (exited)
            // process rather than a newcomer: the "has exited" branch, deterministically.
            let v = verify_peer(pid, &expected, &Requirement::Publisher(MICROSOFT_WINDOWS));
            assert!(!v.verified, "{v:?}");
            assert_eq!(
                v.evidence,
                format!("Authenticode: process {pid} has exited")
            );

            // With the last handle gone the pid is free: whatever it names now, if anything, is
            // not verified as the process that exited.
            drop(child);
            let v = verify_peer(pid, &expected, &Requirement::Publisher(MICROSOFT_WINDOWS));
            assert!(!v.verified, "{v:?}");
        }

        /// The image path Windows reports follows a rename of the running executable, so an image
        /// renamed away after the request was made no longer matches the path on the request.
        #[test]
        fn a_running_image_renamed_after_the_request_no_longer_matches() {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("peer.exe");
            std::fs::copy(std::env::current_exe().unwrap(), &original).unwrap();
            let peer = Suspended::start(&original);
            let on_the_request = peer.executable();
            std::fs::rename(&original, dir.path().join("renamed.exe")).unwrap();

            let v = verify_peer(
                peer.pid(),
                &on_the_request,
                &Requirement::SameSignerAsThisProcess,
            );
            assert!(!v.verified, "{v:?}");
            assert!(v.evidence.contains("renamed.exe, not "), "{v:?}");
        }

        #[test]
        fn a_pid_that_names_nothing_is_not_verified() {
            // Pids are multiples of four on Windows; this one is never handed out.
            let v = verify_peer(
                u32::MAX - 2,
                Path::new(r"C:\nothing.exe"),
                &Requirement::SameSignerAsThisProcess,
            );
            assert!(!v.verified, "{v:?}");
            assert!(v.evidence.contains("could not be opened"), "{v:?}");
        }
    }
}
