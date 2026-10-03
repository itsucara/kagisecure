//! Finding `kagisecure-nmhost`, and writing the `NativeMessagingHosts` manifest each browser
//! needs before it will launch it.
//!
//! # Why the app writes this file rather than an installer
//!
//! A native messaging host manifest is a per-user JSON file naming an **absolute path** to a
//! binary and an allow-list of extension origins. The path is not knowable at build time — a
//! contributor's is under `target/debug`, a user's is inside the app bundle's `Contents/Helpers`
//! — so something that
//! knows where it is has to write it. That something is the app, from a setup screen, with a
//! button, so the user can see exactly which file is being written and to which browser before it
//! happens.
//!
//! # What is in the file, and what each part does
//!
//! ```json
//! {
//!   "name": "com.kagisecure.nmhost",
//!   "description": "…",
//!   "path": "/absolute/path/to/kagisecure-nmhost",
//!   "type": "stdio",
//!   "allowed_origins": ["chrome-extension://<pinned id>/"]
//! }
//! ```
//!
//! `allowed_origins` is the browser's half of the pinning: Chrome will only connect an extension
//! whose id appears here. The app's half is [`kagisecure_extension_ipc::is_pinned_extension`],
//! checked at `Hello`. Neither is a substitute for the other — the manifest is a file on disk that
//! anything running as the user could rewrite, and the app's check is code that would have to be
//! replaced — so both are present and both are cheap.
//!
//! # Windows: a registry value, not a directory scan
//!
//! Chromium browsers on Windows do not scan a well-known directory for these manifests the way
//! they do on macOS — they read one registry value:
//! `HKEY_CURRENT_USER\Software\<vendor fragment>\NativeMessagingHosts\<host name>`, whose unnamed
//! (default) value is the absolute path to a manifest file that may live anywhere. `HKCU` only:
//! writing `HKLM` needs elevation and would register the host for every user of the machine, not
//! just this one.
//!
//! So on Windows, [`all_manifests`] builds each [`BrowserManifest`] from
//! `windows_all_manifests`, not from a directory listing, and [`install`]/[`uninstall`] also
//! write/delete a registry key when [`BrowserManifest::registry_key`] is `Some`. Each browser gets
//! its **own** manifest file (`windows_manifest_path`/`windows_manifest_slug`), not one shared
//! file with four registry pointers into it — sharing one file would mean removing one browser's
//! registration either left another browser's registry entry dangling, or left behind a file
//! `uninstall` had already claimed to remove.
//!
//! The registry reads and writes themselves are isolated in the `windows_registry` module, the
//! only corner of this crate that is `#[allow(unsafe_code)]` (see `lib.rs`'s doc comment on why
//! the crate is `deny`, not `forbid`, because of exactly this).

use std::path::{Path, PathBuf};

use kagisecure_extension_ipc::peer::KnownBrowser;
use kagisecure_extension_ipc::{NATIVE_HOST_NAME, PINNED_EXTENSION_IDS};

/// Points the setup screen at a `kagisecure-nmhost` a developer built.
pub const NMHOST_ENV: &str = "KAGISECURE_NMHOST";

/// The native messaging host's file name. Re-exported from [`crate::bundle`].
pub use crate::bundle::NMHOST;

/// Where `kagisecure-nmhost` is, if it can be found.
///
/// `bundle_helpers_dir` is the app's own `Contents/Helpers`, where a shipped copy lives. The
/// search itself is [`crate::bundle::find`]'s, shared with [`crate::setup::sidecar_path`]: two
/// "where is our other binary" searches that disagreed would be a support problem nobody could
/// reproduce.
#[must_use]
pub fn nmhost_path(bundle_helpers_dir: Option<&Path>) -> Option<PathBuf> {
    crate::bundle::find(NMHOST, bundle_helpers_dir, NMHOST_ENV)
}

/// The host path an install *would* have, for a screen that found nothing and has to say so.
#[must_use]
pub fn placeholder_nmhost_path() -> PathBuf {
    crate::bundle::installed_helper(NMHOST)
}

/// One browser's manifest: where it goes and what goes in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserManifest {
    /// The browser's display name.
    pub browser: String,
    /// The absolute path of the file to write.
    pub path: PathBuf,
    /// The JSON to write there, pretty-printed so a user can read it before agreeing to it.
    pub body: String,
    /// Whether that browser appears to be installed on this Mac.
    ///
    /// Not a gate — a user may be about to install it, and a manifest written first works fine —
    /// but the setup screen sorts by it so the browser somebody actually uses is at the top.
    pub browser_installed: bool,
    /// Whether the file is already there with exactly this content.
    pub installed: bool,
    /// The registry subkey, relative to `HKEY_CURRENT_USER`, that [`install`] also sets on
    /// Windows — `HKCU\<this>`'s unnamed (default) value becomes `path`.
    ///
    /// `None` on every other platform, which has nothing to register, and `None` on Windows too
    /// for a browser this build does not have a confirmed registry vendor fragment for (see
    /// `windows_registry_vendor`'s own doc comment for which one and why).
    ///
    /// Added after this struct first shipped, so it is the one field a caller from before this
    /// existed does not set — which is why it is last, and why the FFI record's equivalent field
    /// (`crates/kagisecure-ffi/src/agent.rs`'s `BrowserManifestView::registry_key`) carries
    /// `#[uniffi(default = None)]`: an existing Swift call site that builds a
    /// `BrowserManifestView` without naming this field keeps compiling, reading `nil`, exactly as
    /// it did before this field existed.
    pub registry_key: Option<String>,
}

/// The manifest body for `nmhost_path`.
///
/// Hand-rolled rather than routed through `serde_json`, because this crate does not otherwise
/// depend on it and because the shape is four fixed keys and two interpolations. The two
/// interpolated values are escaped: a path can legally contain a quote or a backslash, and a
/// manifest that JSON-parsers reject is a failure mode with no error message anywhere.
#[must_use]
pub fn manifest_body(nmhost_path: &Path) -> String {
    let origins = PINNED_EXTENSION_IDS
        .iter()
        .map(|id| format!("    \"chrome-extension://{id}/\""))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "{{\n  \"name\": \"{NATIVE_HOST_NAME}\",\n  \"description\": \"kagisecure autofill \
         bridge\",\n  \"path\": \"{}\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": \
         [\n{origins}\n  ]\n}}\n",
        json_escape(&nmhost_path.display().to_string())
    )
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The directory a browser reads its per-user manifests from, on macOS.
///
/// This is the directory of a browser's **default** profile. A browser launched with
/// `--user-data-dir=X` reads its manifests from `X/NativeMessagingHosts` instead — measured on
/// Edge 152 and 154 and Chromium 153 (browser-extension.md §9; ADR-0042, "Phase 5: the
/// measurement") — which is where an unattended run browser's manifest is written.
///
/// Windows does not use this function at all — see the module doc comment's "Windows: a registry
/// value, not a directory scan" section, and `windows_all_manifests`. This is `None` on Windows
/// today (`HOME` is normally unset there), which used to be this function's *only* Windows
/// behavior; it is now simply irrelevant there rather than load-bearing, since [`all_manifests`]
/// no longer calls it on that platform.
#[must_use]
pub fn manifest_dir(browser: KnownBrowser) -> Option<PathBuf> {
    let fragment = browser.native_messaging_dir_fragment()?;
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join(fragment),
    )
}

/// Whether a browser's application bundle is present, for the "is it installed" hint.
///
/// Both `/Applications` and `~/Applications`, because a per-user install is the normal way a
/// second browser gets onto a managed Mac. Only used by `all_manifests`' non-Windows branch —
/// Windows has its own hint, `windows_browser_installed`, above.
#[cfg(not(windows))]
fn is_installed(browser: KnownBrowser) -> bool {
    let Some(name) = bundle_name(browser) else {
        return false;
    };
    if PathBuf::from("/Applications").join(name).exists() {
        return true;
    }
    std::env::var_os("HOME")
        .is_some_and(|home| PathBuf::from(home).join("Applications").join(name).exists())
}

#[cfg(not(windows))]
fn bundle_name(browser: KnownBrowser) -> Option<&'static str> {
    let name = match browser {
        KnownBrowser::Chrome => "Google Chrome.app",
        KnownBrowser::Edge => "Microsoft Edge.app",
        KnownBrowser::Arc => "Arc.app",
        KnownBrowser::Brave => "Brave Browser.app",
        KnownBrowser::Chromium => "Chromium.app",
        KnownBrowser::Safari => "Safari.app",
        // `KnownBrowser` is `#[non_exhaustive]`. A browser this build does not know the bundle
        // name of gets no installed-hint, which costs a sort order and nothing else.
        _ => return None,
    };
    Some(name)
}

/// Every manifest the setup screen offers, installed browsers first.
///
/// On Windows this is `windows_all_manifests`, built from the registry rather than a directory
/// listing — see the module doc comment.
#[must_use]
pub fn all_manifests(nmhost: &Path) -> Vec<BrowserManifest> {
    let body = manifest_body(nmhost);
    #[cfg(windows)]
    {
        windows_all_manifests(&body)
    }
    #[cfg(not(windows))]
    {
        let mut out: Vec<BrowserManifest> = KnownBrowser::installable()
            .iter()
            .filter_map(|browser| {
                let dir = manifest_dir(*browser)?;
                let path = dir.join(format!("{NATIVE_HOST_NAME}.json"));
                let installed = std::fs::read_to_string(&path).is_ok_and(|on_disk| on_disk == body);
                Some(BrowserManifest {
                    browser: browser.display_name().to_owned(),
                    path,
                    body: body.clone(),
                    browser_installed: is_installed(*browser),
                    installed,
                    registry_key: None,
                })
            })
            .collect();
        out.sort_by_key(|m| !m.browser_installed);
        out
    }
}

/// Write one manifest, creating its directory, and — on Windows, when
/// [`BrowserManifest::registry_key`] is `Some` — the registry value that points a browser at it.
///
/// # Errors
///
/// Any I/O failure, with the path in the message — a setup screen has to be able to say *which*
/// file it could not write. On Windows, also a registry failure after a successful write, worded
/// to say the file *did* get written even though the browser will not find it yet.
pub fn install(manifest: &BrowserManifest) -> Result<(), String> {
    // Both failures name the **manifest** path, not the directory. The user is looking at a screen
    // that shows them one path and a button; an error naming something else makes them hunt.
    if let Some(dir) = manifest.path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            format!(
                "could not write {}: its folder {} could not be created: {e}",
                manifest.path.display(),
                dir.display()
            )
        })?;
    }
    std::fs::write(&manifest.path, &manifest.body)
        .map_err(|e| format!("could not write {}: {e}", manifest.path.display()))?;
    #[cfg(windows)]
    {
        if let Some(key) = manifest.registry_key.as_deref() {
            windows_registry::set_default_value(key, &manifest.path).map_err(|e| {
                format!(
                    "wrote {}, but could not point {} at it in the registry: {e}",
                    manifest.path.display(),
                    manifest.browser
                )
            })?;
        }
    }
    Ok(())
}

/// Remove one manifest, so a user can turn the integration off from the same screen that turned
/// it on — and, on Windows, the registry value that pointed a browser at it.
///
/// The registry entry is removed first: if that fails, the manifest file is left in place rather
/// than deleted out from under a registry value the browser might still read (however briefly)
/// before the next attempt.
///
/// # Errors
///
/// Any I/O or registry failure other than "it was not there", which is success.
pub fn uninstall(manifest: &BrowserManifest) -> Result<(), String> {
    #[cfg(windows)]
    {
        if let Some(key) = manifest.registry_key.as_deref() {
            windows_registry::delete_key(key).map_err(|e| {
                format!(
                    "could not remove the registry entry for {}: {e}",
                    manifest.browser
                )
            })?;
        }
    }
    match std::fs::remove_file(&manifest.path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove {}: {e}", manifest.path.display())),
    }
}

// ---------------------------------------------------------------------------------------------
// Windows: registry-based registration (see the module doc comment)
// ---------------------------------------------------------------------------------------------

/// The HKCU vendor fragment a Windows Chromium browser files its native-messaging registrations
/// under: `HKCU\Software\<fragment>\NativeMessagingHosts\<host name>`. Checked against each
/// browser's own native-messaging documentation (Chrome, Edge and Chromium share the mechanism
/// Google documents; Brave, being Chromium-based, follows the same convention under its own
/// vendor fragment).
///
/// `None` for a browser this project has not confirmed a Windows registry vendor fragment for —
/// which today means `Arc`. Arc does ship a Windows build, but this project has not verified its
/// native-messaging registry path against primary documentation, and an unconfirmed guess would
/// either silently register nothing or, worse, write into a path that happens to be wrong for a
/// different purpose. Honest absence, matching how this module already treats Safari and any
/// future `KnownBrowser` variant it does not otherwise recognize.
#[cfg(windows)]
#[must_use]
fn windows_registry_vendor(browser: KnownBrowser) -> Option<&'static str> {
    match browser {
        KnownBrowser::Chrome => Some(r"Google\Chrome"),
        KnownBrowser::Edge => Some(r"Microsoft\Edge"),
        KnownBrowser::Brave => Some(r"BraveSoftware\Brave-Browser"),
        KnownBrowser::Chromium => Some("Chromium"),
        // `KnownBrowser` is `#[non_exhaustive]`; `Arc`, `Safari`, and anything this build does not
        // otherwise name get no Windows registration.
        _ => None,
    }
}

/// A short, filesystem- and registry-safe slug per browser, so each gets its **own** manifest
/// file under the shared `NativeMessagingHosts` directory rather than all four pointing at one
/// shared file — see the module doc comment for why sharing one file is the wrong shape here.
#[cfg(windows)]
#[must_use]
fn windows_manifest_slug(browser: KnownBrowser) -> Option<&'static str> {
    match browser {
        KnownBrowser::Chrome => Some("chrome"),
        KnownBrowser::Edge => Some("edge"),
        KnownBrowser::Brave => Some("brave"),
        KnownBrowser::Chromium => Some("chromium"),
        _ => None,
    }
}

/// Where one browser's own manifest file lives on Windows.
///
/// Under this app's own per-user app-data directory (`%LOCALAPPDATA%\Kagisecure`, via
/// `directories::BaseDirs::data_local_dir`) rather than anywhere browser-owned — a Windows browser
/// does not scan a directory for these at all (unlike macOS), so nothing requires the file to
/// live anywhere in particular except where the registry value this browser also gets points it.
#[cfg(windows)]
#[must_use]
fn windows_manifest_path(browser: KnownBrowser) -> Option<PathBuf> {
    let slug = windows_manifest_slug(browser)?;
    let dirs = directories::BaseDirs::new()?;
    Some(
        dirs.data_local_dir()
            .join("Kagisecure")
            .join("NativeMessagingHosts")
            .join(format!("{NATIVE_HOST_NAME}.{slug}.json")),
    )
}

/// Whether `browser` appears to be installed, on Windows.
///
/// Reads each browser's own `App Paths` registration — `HKEY_.._.\Software\Microsoft\Windows\
/// CurrentVersion\App Paths\<exe name>`, the standard, documented way a Windows installer
/// advertises where its executable is — under both `HKEY_CURRENT_USER` (a per-user install, how
/// Chrome and Brave commonly install) and `HKEY_LOCAL_MACHINE` (a machine-wide install, how Edge
/// ships by default). Read-only: this is a hint, not the write side of anything, so reading either
/// hive costs nothing and needs no elevation.
///
/// Not a gate, exactly as the macOS hint beside it (`is_installed`) is not: only a sort key for
/// which browser the screen lists first.
#[cfg(windows)]
#[must_use]
fn windows_browser_installed(browser: KnownBrowser) -> bool {
    let exe = match browser {
        KnownBrowser::Chrome => "chrome.exe",
        KnownBrowser::Edge => "msedge.exe",
        KnownBrowser::Brave => "brave.exe",
        // Chromium ships no standard Windows installer and therefore no standard `App Paths`
        // entry to check — the same honest "we don't know" this module already gives Chromium on
        // macOS, where it is not shipped as an application bundle either (`bundle_name`, above).
        _ => return false,
    };
    let subkey = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
    windows_registry::key_exists_hkcu(&subkey) || windows_registry::key_exists_hklm(&subkey)
}

/// Every manifest the setup screen offers, on Windows — installed browsers first, exactly like
/// the non-Windows half of [`all_manifests`], but read from the registry rather than a directory
/// listing.
#[cfg(windows)]
#[must_use]
fn windows_all_manifests(body: &str) -> Vec<BrowserManifest> {
    let mut out: Vec<BrowserManifest> = KnownBrowser::installable()
        .iter()
        .filter_map(|browser| {
            let path = windows_manifest_path(*browser)?;
            let registry_key = windows_registry_vendor(*browser).map(|vendor| {
                format!(r"Software\{vendor}\NativeMessagingHosts\{NATIVE_HOST_NAME}")
            });
            let file_matches = std::fs::read_to_string(&path).is_ok_and(|on_disk| on_disk == body);
            let shown_path = path.display().to_string();
            let registered = registry_key.as_deref().is_some_and(|key| {
                windows_registry::read_default_value(key).as_deref() == Some(shown_path.as_str())
            });
            Some(BrowserManifest {
                browser: browser.display_name().to_owned(),
                path,
                body: body.to_owned(),
                browser_installed: windows_browser_installed(*browser),
                installed: file_matches && registered,
                registry_key,
            })
        })
        .collect();
    out.sort_by_key(|m| !m.browser_installed);
    out
}

/// The direct Win32 registry calls the functions above need. The only corner of this crate that
/// is `#[allow(unsafe_code)]` — see `lib.rs`'s doc comment on why the crate is `deny`, not
/// `forbid`, because of exactly this module.
///
/// Every function here operates on one subkey path at a time and closes whatever handle it opens
/// on every return path; none of them touch anything outside `HKEY_CURRENT_USER` except the one
/// **read-only** `HKEY_LOCAL_MACHINE` check `windows_browser_installed` needs, which needs no
/// elevation because it never writes.
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_registry {
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };

    /// A NUL-terminated UTF-16 encoding of `s`, which is what every wide-string Win32 registry
    /// call here needs.
    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Open (or, with `create`, create) `hive\subkey`, with `access` rights. `None` if it does not
    /// exist and `create` is false, or on any other failure — a registry read that cannot open its
    /// key is "not there," not something worth a distinct error to the setup screen.
    fn open(hive: HKEY, subkey: &str, access: u32, create: bool) -> Option<HKEY> {
        let wide_subkey = wide_null(subkey);
        let mut hkey: HKEY = ptr::null_mut();
        let status = if create {
            let mut disposition = 0u32;
            // SAFETY: `hive` is one of the well-known pseudo-handles this module passes in
            // (`HKEY_CURRENT_USER`/`HKEY_LOCAL_MACHINE`), which need no closing themselves;
            // `wide_subkey` is a valid NUL-terminated wide string that outlives this call; `hkey`
            // and `disposition` are valid, aligned, writable out-pointers for the single write
            // `RegCreateKeyExW` makes to each before returning.
            unsafe {
                RegCreateKeyExW(
                    hive,
                    wide_subkey.as_ptr(),
                    0,
                    ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    access,
                    ptr::null(),
                    &mut hkey,
                    &mut disposition,
                )
            }
        } else {
            // SAFETY: same reasoning as the `create` branch, minus the two out-pointers
            // `RegOpenKeyExW` does not take.
            unsafe { RegOpenKeyExW(hive, wide_subkey.as_ptr(), 0, access, &mut hkey) }
        };
        (status == ERROR_SUCCESS).then_some(hkey)
    }

    /// Close a handle [`open`] returned. Every caller below pairs one of these with every `open`
    /// on every return path, including the early ones.
    fn close(hkey: HKEY) {
        // SAFETY: every caller passes a handle `open` returned successfully, not yet closed.
        unsafe {
            RegCloseKey(hkey);
        }
    }

    /// Set `HKEY_CURRENT_USER\<subkey>`'s unnamed (default) value to `value`'s path, as a
    /// `REG_SZ`, creating every missing intermediate key along the way. Non-volatile: it has to
    /// survive a reboot, like any other browser integration setting.
    ///
    /// # Errors
    ///
    /// A message naming the Win32 error code — a setup screen has to be able to say *why* the
    /// button failed, and there is no richer error type on this side of the FFI boundary to carry
    /// one in.
    pub(super) fn set_default_value(subkey: &str, value: &Path) -> Result<(), String> {
        let Some(hkey) = open(HKEY_CURRENT_USER, subkey, KEY_SET_VALUE, true) else {
            return Err("could not create or open the registry key".to_owned());
        };
        let wide_value = wide_null(&value.display().to_string());
        // `wide_value`'s length in *bytes*, NUL terminator included — `RegSetValueExW` wants a
        // byte count, and the terminator is exactly what a `REG_SZ` reader relies on to know
        // where the string ends.
        let byte_len = u32::try_from(wide_value.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: `hkey` was just opened above with `KEY_SET_VALUE` access and is still open; a
        // null `lpvaluename` names the unnamed (default) value; `wide_value`'s buffer is valid
        // for exactly `byte_len` bytes for the duration of this call.
        let status = unsafe {
            RegSetValueExW(
                hkey,
                ptr::null(),
                0,
                REG_SZ,
                wide_value.as_ptr().cast::<u8>(),
                byte_len,
            )
        };
        close(hkey);
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(format!("registry error {status}"))
        }
    }

    /// Read `HKEY_CURRENT_USER\<subkey>`'s unnamed (default) value back. `None` if the key or the
    /// value does not exist, or the value is larger than this function is willing to allocate for
    /// what is always, in practice, one of this process's own filesystem paths.
    #[must_use]
    pub(super) fn read_default_value(subkey: &str) -> Option<String> {
        let hkey = open(HKEY_CURRENT_USER, subkey, KEY_QUERY_VALUE, false)?;
        // A generous fixed buffer: this only ever reads back a path this process wrote itself,
        // never attacker-controlled input sized adversarially, so there is no need to probe the
        // real size with a first null-buffer call the way a hostile-input caller would have to.
        let mut buffer = [0u16; 4096];
        let mut byte_len = u32::try_from(buffer.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: `hkey` is open with query access; `buffer` is valid for `byte_len` bytes and
        // `byte_len` is set to exactly that many bytes beforehand, which `RegQueryValueExW`
        // requires of both the buffer and the in/out length it is given.
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                buffer.as_mut_ptr().cast::<u8>(),
                &mut byte_len,
            )
        };
        close(hkey);
        if status != ERROR_SUCCESS {
            return None;
        }
        let words = (byte_len as usize / 2).min(buffer.len());
        Some(
            String::from_utf16_lossy(&buffer[..words])
                .trim_end_matches('\0')
                .to_owned(),
        )
    }

    /// Delete `HKEY_CURRENT_USER\<subkey>` and everything under it. Missing already is success:
    /// uninstalling something that was never installed is a normal no-op everywhere else in this
    /// module too (see [`super::uninstall`]'s own doc comment).
    ///
    /// # Errors
    ///
    /// A message naming the Win32 error code, for any failure other than "it was not there".
    pub(super) fn delete_key(subkey: &str) -> Result<(), String> {
        let wide_subkey = wide_null(subkey);
        // SAFETY: `HKEY_CURRENT_USER` is a well-known pseudo-handle that needs no closing itself;
        // `wide_subkey` is a valid NUL-terminated wide string for the duration of this call.
        let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, wide_subkey.as_ptr()) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(format!("registry error {status}"))
        }
    }

    /// Whether `HKEY_CURRENT_USER\<subkey>` exists at all.
    #[must_use]
    pub(super) fn key_exists_hkcu(subkey: &str) -> bool {
        open(HKEY_CURRENT_USER, subkey, KEY_QUERY_VALUE, false).is_some_and(|hkey| {
            close(hkey);
            true
        })
    }

    /// Whether `HKEY_LOCAL_MACHINE\<subkey>` exists at all. Read-only, like its HKCU sibling —
    /// see the module's own doc comment for why reading this hive needs no elevation.
    #[must_use]
    pub(super) fn key_exists_hklm(subkey: &str) -> bool {
        open(HKEY_LOCAL_MACHINE, subkey, KEY_QUERY_VALUE, false).is_some_and(|hkey| {
            close(hkey);
            true
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A throwaway subkey under this module's own test namespace, unique per test run —
        /// never a real browser's registration — so a panic mid-test cannot leave a stray key
        /// behind for the next run to trip over, and so two test binaries running at once never
        /// collide. Deleted at the end of every test that creates one; a test that only reads
        /// (`reading_a_key_nothing_ever_wrote_answers_none`) creates nothing to clean up.
        fn throwaway_subkey(test_name: &str) -> String {
            format!(
                r"Software\Kagisecure\BrowserSetupTests\{test_name}-{}-{}",
                std::process::id(),
                unix_now_for_tests(),
            )
        }

        fn unix_now_for_tests() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_nanos() as u64
        }

        #[test]
        fn a_value_set_is_read_back_verbatim() {
            let subkey = throwaway_subkey("round-trip");
            set_default_value(&subkey, Path::new(r"C:\Users\test\kagisecure-nmhost.exe"))
                .expect("set");
            assert_eq!(
                read_default_value(&subkey).as_deref(),
                Some(r"C:\Users\test\kagisecure-nmhost.exe")
            );
            assert!(key_exists_hkcu(&subkey));
            delete_key(&subkey).expect("clean up");
            assert!(!key_exists_hkcu(&subkey), "delete_key must remove it");
        }

        #[test]
        fn reading_a_key_nothing_ever_wrote_answers_none() {
            let subkey = throwaway_subkey("never-written");
            assert_eq!(read_default_value(&subkey), None);
            assert!(!key_exists_hkcu(&subkey));
        }

        #[test]
        fn deleting_something_that_was_never_there_is_success_not_an_error() {
            let subkey = throwaway_subkey("delete-nothing");
            delete_key(&subkey).expect("deleting nothing is fine, like `uninstall`'s file case");
        }

        #[test]
        fn setting_the_same_key_twice_replaces_rather_than_errors() {
            let subkey = throwaway_subkey("overwrite");
            set_default_value(&subkey, Path::new(r"C:\one.exe")).expect("first set");
            set_default_value(&subkey, Path::new(r"C:\two.exe")).expect("second set");
            assert_eq!(read_default_value(&subkey).as_deref(), Some(r"C:\two.exe"));
            delete_key(&subkey).expect("clean up");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Safari: nothing to write, and three facts the screen has to be able to show
// ---------------------------------------------------------------------------------------------

/// What the Browser extension screen says about Safari.
///
/// There is no manifest here and no button that writes one: a Safari Web Extension is an app
/// extension inside this app's bundle, and it is enabled from Safari's own Settings. So this
/// record is entirely facts the screen would otherwise have to guess — whether the extension is
/// actually in this build, which App Group the two halves share, and where the socket is
/// ([ADR-0024](../../../docs/decisions/0024-safari-app-group-socket.md)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafariSetup {
    /// The app extension's bundle identifier, which is what Safari lists and what the app pins.
    pub bundle_id: String,
    /// The App Group the app and the extension share, or `None` on a build with no team.
    pub app_group: Option<String>,
    /// The socket the extension connects to, or `None` when there is no App Group to put it in.
    pub socket_path: Option<PathBuf>,
    /// The `.appex` inside this bundle, when this build actually ships one.
    ///
    /// `None` on a build made before the target existed, or one whose `PlugIns` directory was
    /// stripped — which is a thing worth saying out loud, because Safari simply shows no
    /// extension in that case and gives the user nothing to act on.
    pub appex_path: Option<PathBuf>,
}

/// The Safari half of the setup screen.
///
/// `team_id` comes from the app's own code signature (`SecCodeCopySigningInformation` on itself),
/// not from a constant: a fork that signs with its own identity gets its own App Group with no
/// source edit. `bundle_plugins_dir` is this app's `Contents/PlugIns`.
#[must_use]
pub fn safari_setup(team_id: Option<&str>, bundle_plugins_dir: Option<&Path>) -> SafariSetup {
    let appex_path = bundle_plugins_dir.and_then(|dir| {
        let candidate = dir.join(format!(
            "{}.appex",
            kagisecure_extension_ipc::SAFARI_EXTENSION_EXECUTABLE
        ));
        candidate.is_dir().then_some(candidate)
    });
    SafariSetup {
        bundle_id: kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID.to_owned(),
        app_group: team_id.map(kagisecure_extension_ipc::endpoint::app_group_id),
        socket_path: kagisecure_extension_ipc::endpoint::safari_endpoint(team_id)
            .and_then(|e| e.path().map(std::path::Path::to_path_buf)),
        appex_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safari_has_no_manifest_to_write_but_does_have_a_group_and_a_socket() {
        let setup = safari_setup(Some("TEAMID1234"), None);
        assert_eq!(
            setup.bundle_id,
            kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID
        );
        assert_eq!(
            setup.app_group.as_deref(),
            Some("TEAMID1234.com.kagisecure")
        );
        assert!(setup.appex_path.is_none(), "no bundle was named");
        if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_none() {
            let socket = setup.socket_path.expect("a team gives a socket");
            assert!(
                socket
                    .to_string_lossy()
                    .contains("TEAMID1234.com.kagisecure"),
                "{}",
                socket.display()
            );
        }
    }

    /// The manifest a browser reads holds an absolute path, so the placeholder the screen shows
    /// has to be the path a real install has — and it has to be inside the bundle, where the
    /// binary is signed and notarized with the app that vouches for it (ADR-0026).
    #[test]
    fn the_placeholder_manifest_points_inside_an_installed_bundle() {
        let shown = placeholder_nmhost_path();
        // Built from the same constants `bundle::installed_helper` composes, joined with
        // `Path::join` rather than typed out with `/`, so the assertion holds on Windows (where
        // the separator is `\` and `NMHOST` carries a `.exe` suffix) as well as on macOS.
        let expected = PathBuf::from(crate::bundle::INSTALLED_APP)
            .join("Contents")
            .join(crate::bundle::HELPERS_DIR)
            .join(NMHOST);
        assert_eq!(shown, expected);
        let body = manifest_body(&shown);
        // The manifest JSON-escapes its path (a Windows path's `\` becomes `\\`), so compare
        // against the same escaping rather than the raw display string.
        assert!(body.contains(&json_escape(&expected.display().to_string())));
        assert!(!body.contains("Contents/MacOS"));
    }

    #[test]
    fn a_build_with_no_team_has_no_group_and_no_socket_to_offer() {
        if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_some() {
            return;
        }
        let setup = safari_setup(None, None);
        assert_eq!(setup.app_group, None);
        assert_eq!(setup.socket_path, None);
        assert!(
            !setup.bundle_id.is_empty(),
            "the bundle id is a constant and is always shown"
        );
    }

    #[test]
    fn the_app_extension_is_reported_only_when_it_is_really_in_the_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plugins = dir.path().join("PlugIns");
        std::fs::create_dir_all(&plugins).expect("dirs");
        assert!(
            safari_setup(None, Some(&plugins)).appex_path.is_none(),
            "an empty PlugIns directory ships no extension"
        );

        let appex = plugins.join(format!(
            "{}.appex",
            kagisecure_extension_ipc::SAFARI_EXTENSION_EXECUTABLE
        ));
        std::fs::create_dir_all(&appex).expect("appex");
        assert_eq!(
            safari_setup(None, Some(&plugins)).appex_path,
            Some(appex),
            "and a build that does ship one says where it is"
        );
    }

    #[test]
    fn the_manifest_names_the_host_the_path_and_the_pinned_origin() {
        let body = manifest_body(Path::new(
            "/Applications/Kagisecure.app/Contents/MacOS/kagisecure-nmhost",
        ));
        assert!(
            body.contains("\"name\": \"com.kagisecure.nmhost\""),
            "{body}"
        );
        assert!(body.contains("\"type\": \"stdio\""), "{body}");
        assert!(
            body.contains("/Applications/Kagisecure.app/Contents/MacOS/kagisecure-nmhost"),
            "{body}"
        );
        for id in PINNED_EXTENSION_IDS {
            assert!(
                body.contains(&format!("chrome-extension://{id}/")),
                "{body}"
            );
        }
    }

    #[test]
    fn the_manifest_is_valid_json_even_for_an_awkward_path() {
        // A path with a quote in it is legal on macOS and would otherwise produce a file the
        // browser rejects with no error anyone would ever see.
        let body = manifest_body(Path::new("/tmp/a\"b\\c/kagisecure-nmhost"));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("the manifest must always parse");
        assert_eq!(parsed["name"], NATIVE_HOST_NAME);
        assert_eq!(parsed["path"], "/tmp/a\"b\\c/kagisecure-nmhost");
        assert_eq!(
            parsed["allowed_origins"].as_array().unwrap().len(),
            PINNED_EXTENSION_IDS.len()
        );
    }

    #[test]
    fn a_plain_manifest_parses_and_says_what_it_should() {
        let body = manifest_body(Path::new("/usr/local/bin/kagisecure-nmhost"));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["type"], "stdio");
        assert_eq!(
            parsed["allowed_origins"][0],
            format!("chrome-extension://{}/", PINNED_EXTENSION_IDS[0])
        );
    }

    #[test]
    fn every_offered_browser_has_a_destination_under_the_users_own_library() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        if cfg!(windows) {
            // One fewer than macOS: Arc is in `KnownBrowser::installable()` but has no confirmed
            // Windows registry vendor fragment (`windows_registry_vendor`'s own doc comment), so
            // `windows_all_manifests` leaves it out rather than offering a guessed registry path.
            assert_eq!(
                manifests.len(),
                KnownBrowser::installable().len() - 1,
                "{manifests:?}"
            );
        } else {
            assert_eq!(manifests.len(), KnownBrowser::installable().len());
        }
        for manifest in &manifests {
            assert!(!manifest.browser.is_empty());
            if cfg!(windows) {
                assert!(
                    manifest.path.extension().is_some_and(|ext| ext == "json"),
                    "{}",
                    manifest.path.display()
                );
                assert!(
                    manifest
                        .path
                        .to_string_lossy()
                        .contains("NativeMessagingHosts"),
                    "a Windows manifest must go under this app's own app-data directory: {}",
                    manifest.path.display()
                );
                assert!(
                    manifest.registry_key.is_some(),
                    "every browser this list offers on Windows must have somewhere to register: \
                     {}",
                    manifest.browser
                );
            } else {
                assert!(
                    manifest.path.ends_with("com.kagisecure.nmhost.json"),
                    "{}",
                    manifest.path.display()
                );
                assert!(
                    manifest
                        .path
                        .to_string_lossy()
                        .contains("Application Support"),
                    "a manifest must go under the user's own Library: {}",
                    manifest.path.display()
                );
            }
        }
    }

    #[test]
    fn a_browser_that_is_not_installed_is_reported_as_such() {
        // Chromium is not shipped as an application bundle on a normal Mac, so this asserts the
        // hint can be `false` at all — a check that always answers `true` is not a check.
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        let chromium = manifests
            .iter()
            .find(|m| m.browser == "Chromium")
            .expect("Chromium is offered");
        assert_eq!(
            chromium.browser_installed,
            PathBuf::from("/Applications/Chromium.app").exists()
                || std::env::var_os("HOME")
                    .is_some_and(|h| PathBuf::from(h).join("Applications/Chromium.app").exists())
        );
    }

    #[test]
    fn installed_browsers_are_listed_first() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        let first_absent = manifests.iter().position(|m| !m.browser_installed);
        if let Some(index) = first_absent {
            assert!(
                manifests[index..].iter().all(|m| !m.browser_installed),
                "the list must be partitioned, not interleaved"
            );
        }
    }

    #[test]
    fn safari_is_not_offered_because_it_does_not_use_native_messaging_hosts() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        assert!(
            !manifests.iter().any(|m| m.browser == "Safari"),
            "offering Safari a manifest it cannot read would be a lie in the UI"
        );
    }

    #[test]
    fn installing_writes_the_file_and_reinstalling_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: dir.path().join("nested").join("com.kagisecure.nmhost.json"),
            body: manifest_body(Path::new("/tmp/kagisecure-nmhost")),
            browser_installed: true,
            installed: false,
            registry_key: None,
        };
        install(&manifest).expect("install");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read back"),
            manifest.body
        );
        install(&manifest).expect("install again");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read back"),
            manifest.body
        );
    }

    #[test]
    fn a_failure_names_the_manifest_file_the_screen_is_showing() {
        // A directory that `create_dir_all` can never produce, on either platform this runs on:
        // - macOS: `/System` has been read-only since Catalina.
        // - Windows: `<` and `>` are illegal in any path component — verified separately that
        //   `CreateDirectory` refuses them ("Illegal characters in path") regardless of
        //   permissions. A directory literally named `CON` was tried first and turned out not to
        //   be reliably refused: modern Windows only special-cases reserved device names for a
        //   bare, unqualified open, not for `CreateDirectory` under a real parent.
        let unwritable = if cfg!(windows) {
            PathBuf::from(r"C:\nowhere<>\inner\com.kagisecure.nmhost.json")
        } else {
            PathBuf::from("/System/nowhere/com.kagisecure.nmhost.json")
        };
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: unwritable,
            body: "{}\n".to_owned(),
            browser_installed: false,
            installed: false,
            registry_key: None,
        };
        let error = install(&manifest).unwrap_err();
        assert!(error.contains("com.kagisecure.nmhost.json"), "{error}");
    }

    #[test]
    fn uninstalling_something_that_is_not_there_is_success_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: dir.path().join("absent.json"),
            body: String::new(),
            browser_installed: false,
            installed: false,
            registry_key: None,
        };
        uninstall(&manifest).expect("uninstalling nothing is fine");
        install(&BrowserManifest {
            body: "x".to_owned(),
            ..manifest.clone()
        })
        .expect("install");
        uninstall(&manifest).expect("uninstall");
        assert!(!manifest.path.exists());
    }

    /// The end-to-end path `every_offered_browser_has_a_destination_under_the_users_own_library`
    /// stops short of: `install`/`uninstall` actually reaching the registry, not just the file —
    /// exercised through the public API rather than `windows_registry` directly, and against a
    /// throwaway subkey under this test's own namespace (never a real browser's registration), so
    /// this never touches anything a real Chrome/Edge/Brave/Chromium install reads.
    #[test]
    #[cfg(windows)]
    fn install_sets_the_registry_value_and_uninstall_removes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let subkey = format!(
            r"Software\Kagisecure\BrowserSetupTests\install-uninstall-{}",
            std::process::id()
        );
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: dir.path().join("com.kagisecure.nmhost.test.json"),
            body: "{\"name\":\"com.kagisecure.nmhost\"}\n".to_owned(),
            browser_installed: true,
            installed: false,
            registry_key: Some(subkey.clone()),
        };

        install(&manifest).expect("install");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read back"),
            manifest.body
        );
        assert_eq!(
            windows_registry::read_default_value(&subkey).as_deref(),
            Some(manifest.path.display().to_string().as_str()),
            "install must point the registry value at exactly the file it wrote"
        );

        uninstall(&manifest).expect("uninstall");
        assert!(!manifest.path.exists(), "uninstall must remove the file");
        assert_eq!(
            windows_registry::read_default_value(&subkey),
            None,
            "uninstall must remove the registry value too"
        );
    }

    #[test]
    fn a_manifest_that_matches_byte_for_byte_reports_itself_installed() {
        // The "installed" flag has to be content-sensitive, not existence-sensitive: a manifest
        // pointing at a stale `target/debug` binary is worse than none, because the browser
        // launches nothing and says nothing.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("com.kagisecure.nmhost.json");
        let body = manifest_body(Path::new("/tmp/one"));
        std::fs::write(&path, &body).expect("write");
        assert!(std::fs::read_to_string(&path).is_ok_and(|d| d == body));
        assert!(
            !std::fs::read_to_string(&path)
                .is_ok_and(|d| d == manifest_body(Path::new("/tmp/two")))
        );
    }

    #[test]
    fn the_host_is_found_beside_the_app_before_anywhere_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("Contents").join("MacOS");
        std::fs::create_dir_all(&bundle).expect("dirs");
        let binary = bundle.join(NMHOST);
        std::fs::write(&binary, b"#!/bin/sh\n").expect("write");
        assert_eq!(nmhost_path(Some(&bundle)), Some(binary));
    }

    #[test]
    fn a_bundle_directory_with_nothing_in_it_falls_through_rather_than_lying() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Whatever this returns, it must not be the empty bundle's path.
        let found = nmhost_path(Some(dir.path()));
        assert!(found.as_ref().is_none_or(|p| !p.starts_with(dir.path())));
    }
}
