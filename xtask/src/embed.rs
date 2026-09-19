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
//! 2. Leave the Safari `.appex` alone. Xcode already signed it, correctly, and re-signing a valid
//!    nested bundle only risks breaking it.
//! 3. Re-sign the **app** last, with the entitlements it was built with. Adding files to a signed
//!    bundle invalidates its seal — `Contents/_CodeSignature/CodeResources` is a manifest of
//!    hashes — so the outer signature has to be the last one applied. Sign the outer first and
//!    every inner signature you add afterwards makes it invalid again.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::helpers::{HELPERS, HELPERS_DIR};
use crate::util::{capture_all, run};

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

    sign(app, identity, &app_entitlements, ad_hoc).context("re-signing the app bundle")?;
    println!("embed: re-signed {}", app.display());
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
    // `codesign -d` writes its own progress line to stderr, which `capture_all` folds in. Keep
    // from the first `<?xml` so the file is a plist and nothing else.
    let start = xml
        .find("<?xml")
        .context("codesign printed no plist for the app's entitlements")?;
    let path = app
        .parent()
        .context("the app bundle has no parent directory")?
        .join("Kagisecure.built.entitlements");
    std::fs::write(&path, &xml[start..]).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
