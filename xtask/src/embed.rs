//! `cargo xtask embed` — put the three helper binaries into a built app and sign inside-out.
//!
//! This is the packaging step [ADR-0026](../../docs/decisions/0026-helper-binaries-inside-the-app-bundle.md)
//! describes, and it runs *after* `xcodebuild`, not inside it. Two things ruled out an Xcode
//! build phase: a Copy Files phase names files that must exist when the project is generated, and
//! a Run Script phase runs under `ENABLE_USER_SCRIPT_SANDBOXING`, which denies it both the read of
//! a binary outside the project and the `codesign` that has to follow.
//!
//! The order below is the one notarization requires and it is not the obvious one:
//!
//! 1. Copy each helper into `Contents/Helpers` — *not* `Contents/MacOS`, where the CLI's name
//!    would collide with the app's own executable on a case-insensitive filesystem — and sign
//!    **it** under the Hardened Runtime, with its own minimal entitlements and a secure timestamp.
//! 2. Copy the unpacked Chromium extension (`extensions/shared`) into
//!    `Contents/Resources/ChromiumExtension`, which an unattended job's run browser loads
//!    (ADR-0042 §12.3). Plain files, sealed by the app's own signature in step 4.
//! 3. Leave the Safari `.appex` alone. Xcode already signed it, correctly, and re-signing a valid
//!    nested bundle only risks breaking it.
//! 4. Re-sign the **app** last, with the entitlements it was built with. Adding files to a signed
//!    bundle invalidates its seal — `Contents/_CodeSignature/CodeResources` is a manifest of
//!    hashes — so the outer signature has to be the last one applied. Sign the outer first and
//!    every inner signature you add afterwards makes it invalid again.
//!
//! Between 3 and 4, Sparkle's framework (ADR-0044) is re-signed inside-out with the same
//! identity. Xcode's copy-and-sign of an embedded framework signs the framework only, not the
//! helpers nested in it (`Autoupdate`, `Updater.app`, two XPC services), which keep the signature
//! Sparkle's own build gave them — and notarization rejects a bundle with any piece not signed by
//! the team. The order and the flags are the ones Sparkle's documentation gives for signing by
//! hand.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::chrome_package::extension_files;
use crate::helpers::{HELPERS, HELPERS_DIR};
use crate::util::{capture_all, repo_root, run};

/// Where the run browser's copy of the extension goes, under `Contents/Resources`. Must match
/// `kagisecure_agent::unattended::browser::RunBrowserSetup::discover`.
const RUN_BROWSER_EXTENSION_DIR: &str = "ChromiumExtension";

/// Copy the staged helpers into `app` and sign the bundle inside-out.
///
/// `identity` is what `codesign --sign` is given: a `Developer ID Application` certificate for a
/// release, or `-` for the ad-hoc signature a clean checkout uses (as CI did too, before it was
/// removed on 2026-09-19). An ad-hoc signature
/// cannot carry a secure timestamp, so one is only requested when there is a real identity.
pub fn embed(app: &Path, staging: &Path, entitlements: &Path, identity: &str) -> Result<()> {
    if !app.is_dir() {
        bail!("no app bundle at {}", app.display());
    }
    if !staging.is_dir() {
        bail!(
            "no staged helper binaries at {}. Run `cargo xtask helpers` first.",
            staging.display()
        );
    }

    let app_entitlements = extract_entitlements(app)?;
    // `Contents/Helpers`. Putting `kagisecure` next to `Contents/MacOS/Kagisecure` overwrites the
    // app — same path, case-insensitively — with no error from anything. See ADR-0026.
    let destination = app.join("Contents").join(HELPERS_DIR);
    std::fs::create_dir_all(&destination)
        .with_context(|| format!("creating {}", destination.display()))?;
    let ad_hoc = identity == "-";

    for helper in HELPERS {
        let source = staging.join(helper);
        if !source.is_file() {
            bail!("{helper} is missing from {}", staging.display());
        }
        let target = destination.join(helper);
        // Remove and recreate rather than overwrite: writing over a Mach-O in place is how a
        // bundle ends up with a stale code signature attached to fresh bytes.
        if target.exists() {
            std::fs::remove_file(&target)?;
        }
        std::fs::copy(&source, &target)
            .with_context(|| format!("copying {helper} into the bundle"))?;
        sign(&target, identity, entitlements, ad_hoc)
            .with_context(|| format!("signing {helper}"))?;
        println!("embed: {helper} -> {}", target.display());
    }

    let extension = app
        .join("Contents")
        .join("Resources")
        .join(RUN_BROWSER_EXTENSION_DIR);
    copy_extension(&repo_root()?.join("extensions").join("shared"), &extension)?;
    println!("embed: extension -> {}", extension.display());

    sign_sparkle(app, identity, ad_hoc)?;

    sign(app, identity, &app_entitlements, ad_hoc).context("re-signing the app bundle")?;
    println!("embed: re-signed {}", app.display());
    Ok(())
}

/// Replace `target` with a copy of the extension in `source`.
///
/// The same file set `cargo xtask chrome-package` ships — subdirectories included (`icons/`, which
/// both manifests name; a flat copy would leave the run browser refusing to load the extension),
/// dotfiles and tests left out — but with the committed manifest unchanged: the run browser loads
/// this copy unpacked, and it is the manifest's `key` that gives it the id the app pins (ADR-0021).
fn copy_extension(source: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        std::fs::remove_dir_all(target)
            .with_context(|| format!("removing {}", target.display()))?;
    }
    std::fs::create_dir_all(target).with_context(|| format!("creating {}", target.display()))?;
    for relative in extension_files(source)? {
        let from = source.join(&relative);
        let to = target.join(&relative);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::copy(&from, &to).with_context(|| format!("copying {}", from.display()))?;
    }
    Ok(())
}

/// Re-sign Sparkle's nested code, innermost first, then the framework itself. A no-op for a bundle
/// that does not embed it.
fn sign_sparkle(app: &Path, identity: &str, ad_hoc: bool) -> Result<()> {
    let framework = app.join("Contents/Frameworks/Sparkle.framework");
    if !framework.is_dir() {
        return Ok(());
    }
    let version = framework.join("Versions/B");
    // The Downloader service keeps its own entitlements (it is sandboxed so it can reach the
    // network); nothing else in the framework has any.
    let parts: [(PathBuf, bool); 5] = [
        (version.join("XPCServices/Installer.xpc"), false),
        (version.join("XPCServices/Downloader.xpc"), true),
        (version.join("Autoupdate"), false),
        (version.join("Updater.app"), false),
        (framework.clone(), false),
    ];
    for (target, keep_entitlements) in parts {
        if !target.exists() {
            continue;
        }
        let mut command = Command::new("codesign");
        command
            .arg("--force")
            .args(["--sign", identity])
            .args(["--options", "runtime"]);
        if keep_entitlements {
            command.arg("--preserve-metadata=entitlements");
        }
        command.arg(if ad_hoc {
            "--timestamp=none"
        } else {
            "--timestamp"
        });
        run(command.arg(&target)).with_context(|| format!("signing {}", target.display()))?;
    }
    println!("embed: re-signed {}", framework.display());
    Ok(())
}

/// One `codesign` invocation, with the flags notarization requires.
fn sign(target: &Path, identity: &str, entitlements: &Path, ad_hoc: bool) -> Result<()> {
    let mut command = Command::new("codesign");
    command
        .arg("--force")
        .args(["--sign", identity])
        // The Hardened Runtime. Notarization requires it, and it blocks the code-injection
        // vectors that matter most to a process holding a vault key (ADR-0010).
        .args(["--options", "runtime"])
        .arg("--entitlements")
        .arg(entitlements);
    if ad_hoc {
        command.arg("--timestamp=none");
    } else {
        // Apple's timestamp server, not the local clock. Without it the notary service answers
        // "The signature does not include a secure timestamp".
        command.arg("--timestamp");
    }
    run(command.arg(target))
}

/// The entitlements the app was built with, written to a file `codesign` can be handed back.
///
/// Read off the built bundle rather than off `project.yml`: XcodeGen generates the entitlements
/// plist, and `$(AppIdentifierPrefix)` inside it is only expanded at build time, so the file in
/// the tree is a template and the bundle has the real thing.
fn extract_entitlements(app: &Path) -> Result<PathBuf> {
    let (ok, xml) = capture_all(
        Command::new("codesign")
            .args(["-d", "--entitlements", "-", "--xml"])
            .arg(app),
    )?;
    if !ok || !xml.contains("<plist") {
        bail!(
            "could not read the entitlements off {}; is it signed?\n{xml}",
            app.display()
        );
    }
    // `codesign -d` writes its own `Executable=<absolute path>` line to stderr, which
    // `capture_all` folds in — after the plist, not before it. Keep exactly `<?xml` through
    // `</plist>`: anything else in this file is signed into the app as part of its entitlements,
    // and that line would ship the build machine's path inside every release.
    let start = xml
        .find("<?xml")
        .context("codesign printed no plist for the app's entitlements")?;
    let end = xml[start..]
        .find("</plist>")
        .map(|i| start + i + "</plist>".len())
        .context("codesign printed an unterminated plist for the app's entitlements")?;
    let path = app
        .parent()
        .context("the app bundle has no parent directory")?
        .join("Kagisecure.built.entitlements");
    std::fs::write(&path, &xml[start..end])
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
