//! `kagisecure generate` and `kagisecure totp`.
//!
//! Both print secret material to the terminal, which is the CLI's documented exception (see the
//! crate docs and ADR-0005): a generated password the user asked for is of no use anywhere else,
//! and a one-time code has to be readable to be typed. Neither ever reaches a process argument,
//! where `ps` would see it.
//!
//! `generate` never touches a vault, so it has nothing to audit. `totp` does: every code it shows
//! or copies is a release from the vault, on the user's own hands rather than an agent's, so it is
//! audited the same way `item show --reveal` is — best-effort, and never blocking the code from
//! reaching the terminal or the clipboard (design doc "transactions-and-audit" part B, user
//! decision 1).

#[cfg(target_os = "macos")]
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::generator::{CharacterOptions, Recipe, Separator, WordOptions};
use kagisecure_core::{Error, Vault};

use crate::cli::{ClipboardClearArgs, GenerateArgs, TotpArgs};
use crate::commands::{cli_draft, record_audit_best_effort};
use crate::prompt::SecretInput;

/// Print one or more generated passwords.
///
/// # Errors
///
/// If the recipe cannot be satisfied, or the operating system generator fails.
pub fn generate(args: &GenerateArgs) -> Result<()> {
    let separator: Separator = args.separator.parse()?;
    let recipe = match args.words {
        Some(words) => Recipe::Words(WordOptions {
            words,
            separator,
            capitalize: args.capitalize,
            include_digit: args.include_digit,
        }),
        None => Recipe::Characters(CharacterOptions {
            length: args.length,
            lowercase: !args.no_lowercase,
            uppercase: !args.no_uppercase,
            digits: !args.no_digits,
            symbols: !args.no_symbols,
            avoid_ambiguous: args.avoid_ambiguous,
        }),
    };

    if args.count == 0 {
        bail!("--count must be at least 1");
    }

    for _ in 0..args.count {
        let password = recipe.generate()?;
        let text = password
            .expose_str()
            .ok_or_else(|| anyhow::anyhow!("the generator produced non-text output"))?;
        println!("{text}");
    }

    if args.strength {
        // Standard error, so `kagisecure generate | pbcopy` still copies only the password.
        let strength = recipe.strength();
        eprintln!(
            "{:.0} bits — {}",
            strength.bits,
            strength.level.label().to_lowercase()
        );
    }
    Ok(())
}

/// Print (or copy) an item's current one-time password.
///
/// Audited best-effort, like `item show --reveal`: actor `cli`, tool `totp_show` or `totp_copy`,
/// the item id and the field's label, detail `MASTER_PASSWORD` (the CLI's presence proof is the
/// master password it already asked for to open the vault). The code still reaches the terminal
/// or the clipboard even if the audit save fails — only a warning goes to stderr.
///
/// # Errors
///
/// If the vault cannot be opened, the item or field does not resolve, the field is not a
/// one-time password, or `--copy` is used where there is no clipboard to copy to.
pub fn totp(path: &Path, args: &TotpArgs, input: &mut SecretInput) -> Result<()> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let mut vault = Vault::open_with_password(path, password.as_bytes())?;

    let (item_ref, field_ref) = match args.item.split_once('/') {
        Some((item, field)) => (item, Some(field)),
        None => (args.item.as_str(), None),
    };
    let item = vault.find_item(item_ref)?;

    let field = match field_ref {
        Some(reference) => item.field(reference).ok_or_else(|| Error::FieldNotFound {
            item: item_ref.to_owned(),
            field: reference.to_owned(),
        })?,
        None => item.totp_field().ok_or_else(|| Error::FieldNotFound {
            item: item_ref.to_owned(),
            field: "one-time password".to_owned(),
        })?,
    };

    let generator = field.totp_generator()?;
    let now = kagisecure_core::unix_now();
    let code = generator.code_at(now)?;
    let text = code
        .expose_str()
        .ok_or_else(|| anyhow::anyhow!("the code is not text"))?;
    let remaining = generator.seconds_remaining(now);

    let item_id = item.id;
    let field_label = field.label.clone();

    let tool = if args.copy { "totp_copy" } else { "totp_show" };

    if args.copy {
        copy_to_clipboard(text)?;
        // The code itself stays off stdout when it went to the clipboard: the point of --copy is
        // that it does not land in a scrollback buffer.
        eprintln!("Copied {} digits, valid for {remaining}s.", text.len());
    } else {
        println!("{text}");
        eprintln!("valid for {remaining}s");
    }

    // Printed or copied first, on purpose: a failed audit save must not cost the user the code
    // they asked for.
    record_audit_best_effort(
        &mut vault,
        AuditDraft {
            item_id: Some(item_id),
            variables: vec![field_label],
            detail: Some("MASTER_PASSWORD".to_owned()),
            ..cli_draft(tool)
        },
    );
    Ok(())
}

/// How long a copied code sits on the clipboard before [`schedule_clear`]'s helper removes it,
/// unless something else was copied first — the same default `PasteboardService.defaultClearSeconds`
/// uses in the app.
#[cfg(target_os = "macos")]
const CLIPBOARD_CLEAR_SECONDS: u64 = 60;

/// The JXA (`osascript -l JavaScript`) script [`write_pasteboard_concealed`] runs. Reads the value
/// from its own standard input — never argv, never an environment variable — and prints the
/// resulting `NSPasteboard.generalPasteboard.changeCount` so the caller can later ask
/// [`schedule_clear`]'s helper to clear only if nothing has copied since.
#[cfg(target_os = "macos")]
const COPY_SCRIPT: &str = r"
ObjC.import('AppKit');
ObjC.import('Foundation');
var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var str = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
pb.setStringForType(str, 'public.utf8-plain-text');
pb.setStringForType(str, 'org.nspasteboard.ConcealedType');
pb.setStringForType(str, 'org.nspasteboard.TransientType');
pb.changeCount;
";

/// Hand a value to the system clipboard, marked concealed and transient, and schedule its removal.
///
/// One function, dispatching to one implementation per platform this CLI ships a clipboard path
/// for; everywhere else, `--copy` bails rather than pretending. On Windows it is
/// `copy_via_windows_clipboard`, which marks the value excluded from history and Cloud
/// Clipboard but does not schedule a clear; the rest of this comment is about macOS.
///
/// # Why `osascript`/JXA and not `pbcopy`
///
/// `pbcopy` can only write `public.utf8-plain-text` / `NSStringPboardType`: it has no flag for a
/// custom pasteboard type, so it cannot mark the item the way
/// `apps/macos/Kagisecure/Services/PasteboardService.swift` does. `osascript -l JavaScript`
/// (JavaScript for Automation) ships with every Mac and drives `NSPasteboard` directly through its
/// ObjC bridge — no new crate dependency (`kagisecure-cli` links nothing macOS-specific today, and
/// the workspace has no `objc2`/`cocoa` dependency to reuse), no `unsafe` in this crate
/// (`#![forbid(unsafe_code)]` in `main.rs`), and the value still reaches it only over its standard
/// input ([`COPY_SCRIPT`]), never as an argv entry `ps` could see and never through an environment
/// variable another same-user process could read back with `ps -E` — the same channel `pbcopy` was
/// using.
///
/// It sets `public.utf8-plain-text` (so anything that pastes still works),
/// `org.nspasteboard.ConcealedType` (the marker `PasteboardService.copy(_:label:)` sets, which
/// clipboard managers that honour it skip recording into history) and
/// `org.nspasteboard.TransientType` (a stronger hint some managers use to mean "do not persist
/// even transiently" — the app does not set this one today, so the CLI is ahead of it here).
///
/// # What this cannot do that the app can
///
/// * **Universal Clipboard.** Nothing in the public pasteboard API opts an item out of Handoff;
///   the two markers above reduce the chance a *clipboard manager* keeps a copy, but Continuity
///   can still hand the item to a nearby Mac or iPhone regardless. `PasteboardService.swift` has
///   the same exposure — it does not disable this either — so this is a pre-existing gap shared
///   with the app, not something the CLI introduces or could close on its own; if it is ever
///   closed it should be closed once, in `PasteboardService`, with `kagisecure` following.
/// * **A clear that survives the shell prompt returning reliably.** `PasteboardService` clears
///   after `clearSeconds` because it is a long-lived app process with a timer. `kagisecure totp
///   --copy` exits as soon as it has printed the confirmation line, so nothing here can wait 60
///   seconds itself; [`schedule_clear`] spawns a detached second invocation of this same binary to
///   do that from outside the exiting process instead. That helper is not durable against a log
///   out, a reboot, or the user killing it: unlike the app's in-process timer, there is no record
///   that it is owed and no retry if it dies, which is the one respect in which this is weaker
///   than the app rather than merely different. It is still the fundamentally correct option
///   available to a one-shot CLI process — better than not clearing at all, and better than a fake
///   clear that only claims to have scheduled one.
///
/// # Errors
///
/// If this is not macOS, `osascript` could not be run, or it did not report a numeric change
/// count.
fn copy_to_clipboard(value: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let change_count = write_pasteboard_concealed(value)?;
        schedule_clear(change_count);
        Ok(())
    }
    #[cfg(windows)]
    {
        copy_via_windows_clipboard(value)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = value;
        bail!("--copy needs macOS or Windows; pipe the code to your own clipboard tool instead")
    }
}

/// Run [`COPY_SCRIPT`] and return the pasteboard's change count right after the copy.
#[cfg(target_os = "macos")]
fn write_pasteboard_concealed(value: &str) -> Result<i64> {
    let mut child = Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript", "-e", COPY_SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run /usr/bin/osascript: {e}"))?;
    // Taken, written, and dropped here — closing the pipe's write end — rather than borrowed with
    // `.as_mut()`: `osascript`'s `readDataToEndOfFile` blocks until it sees the standard input
    // pipe close, and it stays open for as long as `child.stdin` holds it, which `child.wait()` or
    // `wait_with_output()` alone does not close.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("osascript has no standard input"))?;
    stdin.write_all(value.as_bytes())?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "osascript exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("osascript did not report a pasteboard change count"))
}

/// Spawn a detached, hidden `kagisecure __clipboard-clear` to clear the pasteboard in
/// [`CLIPBOARD_CLEAR_SECONDS`], but only if it still holds what was just copied (`changeCount ==
/// change_count`) — see [`clipboard_clear_helper`]. Best-effort: if the helper cannot even be
/// spawned, this warns on stderr rather than failing the copy that already succeeded.
#[cfg(target_os = "macos")]
fn schedule_clear(change_count: i64) {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!(
                "kagisecure: warning: could not find my own executable path ({e}), so the \
                 clipboard will not be cleared automatically; clear it yourself."
            );
            return;
        }
    };
    let mut cmd = Command::new(exe);
    cmd.args([
        "__clipboard-clear",
        "--if-unchanged",
        &change_count.to_string(),
        "--after-seconds",
        &CLIPBOARD_CLEAR_SECONDS.to_string(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // A new process group so a `Ctrl-C` sent to this terminal's foreground group — which this
    // process is about to leave anyway by exiting — does not also reach the helper before it has
    // had a chance to detach from the controlling terminal on its own.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    if cmd.spawn().is_err() {
        eprintln!(
            "kagisecure: warning: could not schedule an automatic clipboard clear; clear it \
             yourself."
        );
    }
}

/// `kagisecure __clipboard-clear` (hidden). Waits, then clears the clipboard if [`schedule_clear`]
/// spawned this instance for a value nothing has overwritten in the meantime.
///
/// # Errors
///
/// If `osascript` could not be run.
pub fn clipboard_clear_helper(args: &ClipboardClearArgs) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("__clipboard-clear is only scheduled on macOS");
    }
    std::thread::sleep(std::time::Duration::from_secs(args.after_seconds));
    let script = format!(
        "ObjC.import('AppKit'); var pb = $.NSPasteboard.generalPasteboard; \
         if (pb.changeCount == {}) {{ pb.clearContents; }}",
        args.if_unchanged
    );
    let status = Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript", "-e", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| anyhow::anyhow!("could not run /usr/bin/osascript: {e}"))?;
    if !status.success() {
        bail!("osascript exited with {status}");
    }
    Ok(())
}

/// Windows: `OpenClipboard` / `EmptyClipboard` / `SetClipboardData(CF_UNICODETEXT)`, called
/// directly through `windows-sys` rather than by spawning `clip.exe`. `clip.exe` reads the console
/// code page rather than UTF-8, so a generated passphrase with any non-ASCII character in it would
/// be mangled silently — which is the one failure mode a password generator must not have — and a
/// spawn would also put the value through another process for no benefit. This was the
/// `TODO(windows)` on this function; see below for what replaced it.
///
/// **Pasteboard hygiene, and where this does and does not match ADR-0017.** The macOS *app*'s
/// `PasteboardService` (ADR-0017 decision 3) does two things to a secret it copies: marks it
/// `org.nspasteboard.ConcealedType` so a clipboard manager's history skips it, and clears the
/// clipboard on a timer (default 60s). This function does the Windows equivalent of the first —
/// see "history and Cloud Clipboard exclusion" below — but **not** the second. When this was
/// written the macOS CLI did not clear either, and matching it was judged more important than
/// giving one platform's CLI a mitigation the other lacked. The macOS path has since gained a
/// detached helper that clears after 60 seconds if nothing else was copied (`schedule_clear`);
/// the Windows equivalent — the same helper, keyed on `GetClipboardSequenceNumber` — is not
/// built yet, so on Windows a caller that wants the code off the clipboard sooner has to paste it
/// and clear the clipboard themselves.
///
/// **History and Cloud Clipboard exclusion.** Three clipboard formats, registered with no payload
/// or a payload of `DWORD` `0`, are Microsoft's documented way for an application to say "do not
/// remember this, and do not sync it to another device": `ExcludeClipboardContentFromMonitorProcessing`
/// (no payload — this format's mere presence is the signal, which is why `put_clipboard_data`
/// below is not used for it), `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard`
/// (each `DWORD` `0`). Registering them after the real text is what marks *that* clipboard
/// contents excluded, which is why they come after `SetClipboardData(CF_UNICODETEXT, ...)` below,
/// not before it.
#[cfg(windows)]
#[allow(unsafe_code)]
fn copy_via_windows_clipboard(value: &str) -> Result<()> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{GetLastError, GlobalFree};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use windows_sys::w;
    use zeroize::Zeroizing;

    /// Allocate a moveable global memory block, copy `bytes` into it, and hand it to
    /// `SetClipboardData`. On success the system owns the memory from that point on — moveable
    /// global memory handed to a successful `SetClipboardData` must never be freed or locked
    /// again by the caller; only the failure paths below free what they allocated.
    ///
    /// # Safety
    ///
    /// The calling thread must already hold the clipboard open (every caller in this module goes
    /// through the `OpenClipboard` check below first).
    unsafe fn put_clipboard_data(format: u32, bytes: &[u8]) -> Result<()> {
        // SAFETY: `GMEM_MOVEABLE` is what `SetClipboardData`'s documentation requires the handle
        // to be; `bytes.len()` is a small, non-adversarial size (a generated password or a TOTP
        // code), never zero (checked by every caller below).
        let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) };
        if handle.is_null() {
            bail!("could not allocate clipboard memory (error {})", unsafe {
                GetLastError()
            });
        }
        // SAFETY: `handle` was just allocated above by this thread and is not yet locked.
        let dest = unsafe { GlobalLock(handle) };
        if dest.is_null() {
            let error = unsafe { GetLastError() };
            // SAFETY: `handle` is still exclusively ours; nothing has taken ownership of it.
            unsafe {
                GlobalFree(handle);
            }
            bail!("could not lock clipboard memory (error {error})");
        }
        // SAFETY: `dest` is valid for `bytes.len()` bytes — `GlobalLock` succeeded on a block
        // allocated with exactly that size — and `bytes` is a valid, non-overlapping source of
        // the same length.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), dest.cast::<u8>(), bytes.len());
        }
        // SAFETY: `handle` was locked exactly once, immediately above. `GlobalUnlock`'s return
        // value only distinguishes "still locked by another `GlobalLock` call" from "fully
        // unlocked, or an error" — indistinguishable without `GetLastError` — and a single
        // lock/unlock pair reaching zero is the expected, successful outcome here, not a failure,
        // so the return value is intentionally not checked.
        unsafe {
            GlobalUnlock(handle);
        }
        // SAFETY: `handle` is a valid moveable global memory object, unlocked, holding exactly
        // `bytes`, which is what `SetClipboardData` requires of its argument.
        let accepted = unsafe { SetClipboardData(format, handle) };
        if accepted.is_null() {
            let error = unsafe { GetLastError() };
            // Ownership never transferred, so this is still ours to free.
            // SAFETY: `handle` was never handed to a `SetClipboardData` call that succeeded.
            unsafe {
                GlobalFree(handle);
            }
            bail!("could not set clipboard data (error {error})");
        }
        Ok(())
    }

    // A NUL-terminated UTF-16 buffer, which is what `CF_UNICODETEXT` is documented to hold.
    // `Zeroizing` wipes this copy of the secret on every return path below, including the early
    // ones — the only copy that is meant to survive this function is the one now owned by the
    // clipboard itself, which is the point of `--copy`.
    let wide: Zeroizing<Vec<u16>> =
        Zeroizing::new(value.encode_utf16().chain(std::iter::once(0)).collect());
    let wide_bytes: &[u8] =
        // SAFETY: reinterpreting a `[u16]` as the `[u8]` `SetClipboardData` wants is valid for
        // any slice of `Copy` integers — every bit pattern of `u16` is a valid pair of `u8`s, the
        // resulting length (`len * 2`) fits the same allocation, and the alignment requirement
        // only gets weaker (`u8` aligns to 1).
        unsafe { std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2) };

    // The clipboard is one system-wide lock, and clipboard managers and remote-desktop clients take
    // it for a few milliseconds every time it changes. Failing `--copy` because one of them was
    // mid-read is wrong, so a busy clipboard is retried briefly before giving up.
    const OPEN_ATTEMPTS: u32 = 10;
    let mut attempt = 1;
    // SAFETY: a null `HWND` associates the open clipboard with the *current thread* rather than a
    // window — the documented way for a console application with no window of its own to take
    // it. `OpenClipboard`'s only precondition is that this thread not already hold the clipboard,
    // which is true; this function does not call it reentrantly, and a failed call holds nothing.
    while unsafe { OpenClipboard(ptr::null_mut()) } == 0 {
        if attempt == OPEN_ATTEMPTS {
            bail!("could not open the clipboard (error {})", unsafe {
                GetLastError()
            });
        }
        attempt += 1;
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // Ties `CloseClipboard` to every return path below, success or failure — an open clipboard
    // that is never closed locks every other application out of it until this process exits.
    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            // SAFETY: paired one-to-one with the successful `OpenClipboard` above; `ClipboardGuard`
            // is constructed only once, right after that call succeeds.
            unsafe {
                CloseClipboard();
            }
        }
    }
    let _guard = ClipboardGuard;

    // SAFETY: the clipboard is open on this thread, per the check just above.
    if unsafe { EmptyClipboard() } == 0 {
        bail!("could not clear the clipboard (error {})", unsafe {
            GetLastError()
        });
    }

    // SAFETY: the clipboard is open on this thread; `put_clipboard_data`'s own precondition.
    unsafe { put_clipboard_data(CF_UNICODETEXT as u32, wide_bytes) }?;

    // History and Cloud Clipboard exclusion — best-effort. A failure here does not undo the copy
    // above: the code is on the clipboard either way, and the user asked for `--copy` to work, not
    // for it to fail over a hygiene format an older Windows build may not recognize.
    // SAFETY: the clipboard is still open on this thread; `RegisterClipboardFormatW` has no other
    // precondition, and its return of `0` (meaning "registration failed") is checked before use.
    let exclude_from_monitoring =
        unsafe { RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing")) };
    if exclude_from_monitoring != 0 {
        // SAFETY: the clipboard is open; a `NULL` data handle is documented as valid for
        // `SetClipboardData` and means "no data, only mark the format present."
        unsafe {
            SetClipboardData(exclude_from_monitoring, ptr::null_mut());
        }
    }
    // `w!` needs a string literal at each call site (it is a `const`-evaluated macro, not a
    // function), so the two `DWORD`-zero formats are two blocks rather than a loop over an array
    // of names — the payload the two share is factored into `put_clipboard_data` instead.
    let history = unsafe { RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory")) };
    if history != 0 {
        let zero: u32 = 0;
        // SAFETY: the clipboard is still open, per the outer function's guard above.
        let _ = unsafe { put_clipboard_data(history, &zero.to_ne_bytes()) };
    }
    let cloud_clipboard = unsafe { RegisterClipboardFormatW(w!("CanUploadToCloudClipboard")) };
    if cloud_clipboard != 0 {
        let zero: u32 = 0;
        // SAFETY: the clipboard is still open, per the outer function's guard above.
        let _ = unsafe { put_clipboard_data(cloud_clipboard, &zero.to_ne_bytes()) };
    }

    Ok(())
}

/// Exercised against the real, single, system-wide Windows clipboard — there is no mock for it,
/// and `--copy`'s only job is to reach that one real thing correctly.
#[cfg(all(test, windows))]
#[allow(unsafe_code)]
mod windows_clipboard_tests {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
        RegisterClipboardFormatW,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use windows_sys::w;

    use super::copy_via_windows_clipboard;

    /// Held by each test for its whole body. The tests share the one system clipboard, and they
    /// run on parallel threads of one process — where an `OpenClipboard(NULL)` is not exclusive
    /// between threads, so one test's `CloseClipboard` would close the clipboard under the other
    /// mid-copy (seen as `EmptyClipboard` failing with `ERROR_CLIPBOARD_NOT_OPEN`, 1418).
    static CLIPBOARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        CLIPBOARD.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Read back whatever `CF_UNICODETEXT` currently holds, as a Rust `String`. Not `pub`: a test
    /// helper for this module alone, deliberately separate from `copy_via_windows_clipboard`'s own
    /// unsafe code so a bug in one is not masked by the same bug in the other.
    fn read_clipboard_unicode_text() -> String {
        // SAFETY: a null `HWND` is the same documented "this thread, not a window" association
        // `copy_via_windows_clipboard` uses.
        assert_ne!(
            unsafe { OpenClipboard(std::ptr::null_mut()) },
            0,
            "open for read-back"
        );
        let text = {
            // SAFETY: the clipboard is open, per the check just above.
            let handle = unsafe { GetClipboardData(CF_UNICODETEXT as u32) };
            assert!(!handle.is_null(), "nothing was copied");
            // SAFETY: `handle` came from `GetClipboardData` on an open clipboard and is valid to
            // lock for the duration of this block; it is not modified through this read-only
            // lock, and the caller (`copy_via_windows_clipboard`) still owns the handle itself —
            // per `GetClipboardData`'s contract, a reader must never free or write through it.
            let ptr = unsafe { GlobalLock(handle) };
            assert!(!ptr.is_null(), "lock the clipboard data for reading");
            // SAFETY: `CF_UNICODETEXT` is documented as a NUL-terminated UTF-16 string, so
            // scanning for the terminator before slicing is safe and does not read past the
            // block `GlobalLock` just validated.
            let text = unsafe {
                let start = ptr.cast::<u16>();
                let mut len = 0usize;
                while *start.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(start, len))
            };
            // SAFETY: paired with the successful `GlobalLock` immediately above.
            unsafe {
                GlobalUnlock(handle);
            }
            text
        };
        // SAFETY: paired with the successful `OpenClipboard` above.
        unsafe {
            CloseClipboard();
        }
        text
    }

    #[test]
    fn the_value_round_trips_through_the_real_clipboard() {
        let _clipboard = exclusive();
        let value = "correct-horse-battery-staple-42";
        copy_via_windows_clipboard(value).expect("copy to the real clipboard");
        assert_eq!(read_clipboard_unicode_text(), value);
    }

    /// The history/Cloud Clipboard exclusion formats this function registers are themselves
    /// readable back with `IsClipboardFormatAvailable`, so this is checking the same real
    /// clipboard state Windows' own clipboard history feature would consult — not re-deriving the
    /// constants and asserting they equal themselves.
    #[test]
    fn the_entry_is_marked_excluded_from_history_and_monitor_processing() {
        let _clipboard = exclusive();
        copy_via_windows_clipboard("hygiene-check-value").expect("copy");
        for name in [
            "ExcludeClipboardContentFromMonitorProcessing",
            "CanIncludeInClipboardHistory",
            "CanUploadToCloudClipboard",
        ] {
            // SAFETY: `RegisterClipboardFormatW` has no precondition beyond a valid, NUL-terminated
            // wide string, which `w!` produces at compile time; the same format name registered
            // twice returns the same id.
            let format = unsafe {
                match name {
                    "ExcludeClipboardContentFromMonitorProcessing" => {
                        RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"))
                    }
                    "CanIncludeInClipboardHistory" => {
                        RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory"))
                    }
                    _ => RegisterClipboardFormatW(w!("CanUploadToCloudClipboard")),
                }
            };
            // SAFETY: `IsClipboardFormatAvailable` has no precondition; it does not require the
            // clipboard to be open.
            assert_ne!(
                unsafe { IsClipboardFormatAvailable(format) },
                0,
                "{name} was not registered on the clipboard entry"
            );
        }
    }
}
