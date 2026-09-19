//! `cargo xtask dist` — build, sign, notarize, staple, package, verify.
//!
//! The whole release, in one command, so that nobody has to reconstruct the order from a
//! document. The order is not the obvious one and it matters; `docs/releasing.md` explains why at
//! length, and [ADR-0028](../../docs/decisions/0028-the-release-pipeline.md) records the
//! decisions. In brief:
//!
//! 1. Build **Release** — a Debug build carries `com.apple.security.get-task-allow`, which Apple
//!    rejects at notarization every time.
//! 2. Sign inside-out: helpers, then the Safari `.appex`, then the app. Xcode does this for us,
//!    with the helper binaries signed by the build phase that embeds them; this task verifies it
//!    rather than redoing it.
//! 3. Notarize the **`.app`** and staple it, *before* building the DMG. The bundle a user
//!    actually runs is the copy they dragged out of the mounted image, and that copy carries no
//!    ticket of its own unless the app was stapled before it was wrapped.
//! 4. Build the DMG around the stapled app, notarize that too, staple it.
//! 5. Verify all three ways — `codesign`, `spctl`, `stapler validate` — on both artifacts.
//!
//! Everything lands in `dist/`, which is gitignored.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::bindgen::bindgen;
use crate::embed::embed;
use crate::helpers::{Arches, HELPERS, HELPERS_DIR, Profile, helpers};
use crate::util::{capture, capture_all, run, says};
use crate::version;

/// The app's display name. Capitalised, and the DMG takes it exactly: two namespaces, one for the
/// proper noun (`Kagisecure.app`, `Kagisecure.dmg`) and one for everything lowercase (the
/// `kagisecure` CLI, the crates, `com.kagisecure.app`).
const APP_NAME: &str = "Kagisecure";

/// The identity, named generically so that no organisation's certificate is written down here and
/// a fork signs with its own by doing nothing (ADR-0025).
const IDENTITY: &str = "Developer ID Application";

/// The environment variable naming the `notarytool` credential profile.
///
/// A *name*, never a credential: the Apple ID and the app-specific password behind it live in the
/// keychain, put there once by the person releasing, with
/// `xcrun notarytool store-credentials`.
const PROFILE_ENV: &str = "NOTARY_KEYCHAIN_PROFILE";

/// How much of the pipeline to run.
pub struct Options {
    /// Build for both architectures. Off makes a much faster, host-only artifact for trying the
    /// pipeline out; a real release is always universal (ADR-0027).
    pub universal: bool,
    /// Stop after signing and verifying, before talking to Apple. What to use when there is no
    /// credential profile on the machine (what CI's build-only job used, before CI was removed
    /// on 2026-09-19).
    pub skip_notarize: bool,
}

/// Run the pipeline.
pub fn dist(root: &Path, options: &Options) -> Result<()> {
    let version = version::check(root)?;
    let arches = if options.universal {
        Arches::Universal
    } else {
        Arches::Host
    };

    let dist_dir = root.join("dist");
    if dist_dir.exists() {
        std::fs::remove_dir_all(&dist_dir).context("clearing dist/")?;
    }
    std::fs::create_dir_all(&dist_dir)?;

    let team = team_id()?;
    println!(
        "dist: {APP_NAME} {version}, team {team}, {}",
        arch_label(arches)
    );

    ensure_icon(root)?;
    bindgen(root, arches)?;
    let staging = helpers(root, Profile::Release, arches)?;
    let app = build_app(root, &dist_dir, &staging, &team, arches)?;

    assert_no_debug_entitlement(&app)?;
    assert_no_build_paths(&app)?;
    verify_signature(&app)?;

    let profile = std::env::var(PROFILE_ENV).ok().filter(|p| !p.is_empty());
    let notarized = match (options.skip_notarize, profile) {
        (true, _) => {
            println!("dist: --skip-notarize, so nothing was submitted to Apple");
            false
        }
        (false, None) => bail!(
            "no notarization credential. Set {PROFILE_ENV} to the name of a notarytool keychain \
             profile, which the person releasing creates once with:\n\n    xcrun notarytool \
             store-credentials \"<team>-notary\" --apple-id <the Apple ID> --team-id {team}\n\n\
             Then re-run. To build and sign without submitting, pass --skip-notarize."
        ),
        (false, Some(profile)) => {
            notarize(&dist_dir, &app, &profile).context("notarizing the app")?;
            staple(&app)?;
            true
        }
    };

    let dmg = build_dmg(&dist_dir, &app)?;
    if notarized {
        let profile = std::env::var(PROFILE_ENV).expect("checked above");
        notarize(&dist_dir, &dmg, &profile).context("notarizing the disk image")?;
        staple(&dmg)?;
    }

    report(&app, &dmg, notarized)?;
    Ok(())
}

fn arch_label(arches: Arches) -> &'static str {
    match arches {
        Arches::Universal => "universal (arm64 + x86_64)",
        Arches::Host => "host architecture only",
    }
}

/// The team identifier, read out of the Developer ID certificate in the keychain.
///
/// Nothing about a specific team is committed; `KAGISECURE_TEAM_ID` overrides it on a machine
/// with more than one certificate.
fn team_id() -> Result<String> {
    if let Ok(explicit) = std::env::var("KAGISECURE_TEAM_ID")
        && !explicit.is_empty()
    {
        return Ok(explicit);
    }
    let identities =
        capture(Command::new("security").args(["find-identity", "-v", "-p", "codesigning"]))
            .context("listing code-signing identities")?;

    for line in identities.lines() {
        let Some(rest) = line.split_once(&format!("{IDENTITY}: ")).map(|(_, r)| r) else {
            continue;
        };
        // `… (TEAMID)" (…)` — the team is the last parenthesised group before the closing quote.
        let Some(before_quote) = rest.split('"').next() else {
            continue;
        };
        if let Some(open) = before_quote.rfind('(')
            && let Some(close) = before_quote.rfind(')')
            && open < close
        {
            return Ok(before_quote[open + 1..close].to_owned());
        }
    }
    bail!(
        "no \"{IDENTITY}\" certificate in the keychain. Check with:\n    security find-identity \
         -v -p codesigning\nor set KAGISECURE_TEAM_ID and make sure the certificate is there."
    )
}

/// Generate the app icon from the committed artwork if nobody has yet.
fn ensure_icon(root: &Path) -> Result<()> {
    let icon = root.join("apps/macos/Kagisecure/Resources/Kagisecure.icns");
    if icon.is_file() {
        return Ok(());
    }
    run(Command::new("bash").arg(root.join("apps/macos/Scripts/make-icon.sh")))
        .context("generating the app icon")
}

/// `xcodegen generate`, then `xcodebuild … -configuration Release`, then copy the app to `dist/`.
fn build_app(
    root: &Path,
    dist_dir: &Path,
    staging: &Path,
    team: &str,
    arches: Arches,
) -> Result<PathBuf> {
    let macos_dir = root.join("apps/macos");
    run(Command::new("xcodegen")
        .current_dir(&macos_dir)
        .arg("generate"))
    .context("generating the Xcode project")?;

    // A build directory of our own, so that a release never picks up an object file from a Debug
    // build sitting in the shared DerivedData.
    let derived = dist_dir.join("DerivedData");
    let archs = match arches {
        Arches::Universal => "arm64 x86_64",
        Arches::Host => {
            if cfg!(target_arch = "x86_64") {
                "x86_64"
            } else {
                "arm64"
            }
        }
    };

    run(Command::new("xcodebuild")
        .current_dir(&macos_dir)
        .args(["-project", "Kagisecure.xcodeproj"])
        .args(["-scheme", "Kagisecure"])
        .args(["-destination", "platform=macOS"])
        .args(["-configuration", "Release"])
        .arg("-derivedDataPath")
        .arg(&derived)
        .arg(format!("ARCHS={archs}"))
        .arg("ONLY_ACTIVE_ARCH=NO")
        .arg("CODE_SIGN_STYLE=Manual")
        .arg(format!("CODE_SIGN_IDENTITY={IDENTITY}"))
        .arg(format!("DEVELOPMENT_TEAM={team}"))
        // Hardened Runtime is already on for every target in project.yml; the timestamp is not,
        // because an ad-hoc signature cannot carry one and a plain local build signs ad-hoc (as
        // CI did too, before it was removed on 2026-09-19). Both are required for
        // notarization, so a release asks for the timestamp explicitly.
        .arg("OTHER_CODE_SIGN_FLAGS=--timestamp")
        // Xcode adds `com.apple.security.get-task-allow` to the entitlements it signs with unless
        // told not to — it is the "let a debugger attach" entitlement, and it is injected on top
        // of the entitlements file, so turning off the Debug configuration is not enough. Apple
        // rejects it at notarization every time. Measured on this project: a Release build with
        // this setting left at its default came out carrying it.
        .arg("CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO")
        // Strip the debug map out of the shipped executables. Without this, a plain `build`
        // leaves the linker's STABS entries in the symbol table, and those name every object
        // file and Swift module by the absolute path it was built at — the release machine's
        // home directory and checkout layout, in a binary anyone can download.
        .arg("DEPLOYMENT_POSTPROCESSING=YES")
        .arg("STRIP_INSTALLED_PRODUCT=YES")
        .arg("STRIP_STYLE=non-global")
        .arg("STRIP_SWIFT_SYMBOLS=YES")
        .arg("build"))
    .context("building the app")?;

    let built = derived
        .join("Build/Products/Release")
        .join(format!("{APP_NAME}.app"));
    if !built.is_dir() {
        bail!("xcodebuild produced no app at {}", built.display());
    }

    let app = dist_dir.join(format!("{APP_NAME}.app"));
    // `ditto` rather than `cp -r`: it is the copy that preserves extended attributes and the
    // signature's own metadata, and a `cp -r`d bundle can fail `codesign --verify` for no reason
    // the diff would show.
    run(Command::new("ditto").arg(&built).arg(&app)).context("copying the app into dist/")?;

    // The helpers go in here rather than during the build, and the app is re-signed around them.
    // See `crate::embed` for why, and for the order.
    embed(
        &app,
        staging,
        &root.join("apps/macos/Signing/Helper.entitlements"),
        IDENTITY,
    )?;

    for helper in HELPERS {
        let path = app.join("Contents").join(HELPERS_DIR).join(helper);
        if !path.is_file() {
            bail!("{helper} is not in the bundle at {}", path.display());
        }
    }
    println!("dist: app -> {}", app.display());
    Ok(app)
}

/// Refuse to submit anything carrying the entitlement Apple always rejects.
///
/// `com.apple.security.get-task-allow` lets a debugger attach. Xcode adds it to every Debug
/// build, and the notary service rejects it with *"The executable requests the
/// com.apple.security.get-task-allow entitlement"* — which costs a submission and twenty minutes
/// to discover. Checking locally costs a second.
fn assert_no_debug_entitlement(app: &Path) -> Result<()> {
    let mut offenders = Vec::new();
    for binary in mach_o_files(app)? {
        let (_, text) = capture_all(
            Command::new("codesign")
                .args(["-d", "--entitlements", "-", "--xml"])
                .arg(&binary),
        )?;
        if says(&text, "get-task-allow") {
            offenders.push(binary);
        }
    }
    if !offenders.is_empty() {
        bail!(
            "these binaries carry com.apple.security.get-task-allow, which Apple rejects at \
             notarization — this is a Debug build:\n{}",
            offenders
                .iter()
                .map(|p| format!("  {}", p.display()))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    println!("dist: no get-task-allow anywhere in the bundle");
    Ok(())
}

/// Refuse to ship a binary that names the machine it was built on.
///
/// `strings` does not look everywhere by default (it skips the symbol table), so this reads the
/// raw bytes. Any `/Users/` or the builder's own home directory is a leak of a username and a
/// directory layout; `--remap-path-prefix` (Rust) and stripping (Swift) exist so there are none.
fn assert_no_build_paths(app: &Path) -> Result<()> {
    let mut needles: Vec<Vec<u8>> = vec![b"/Users/".to_vec()];
    if let Some(home) = std::env::var_os("HOME") {
        needles.push(home.to_string_lossy().as_bytes().to_vec());
    }
    let mut offenders = Vec::new();
    for binary in mach_o_files(app)? {
        let bytes =
            std::fs::read(&binary).with_context(|| format!("reading {}", binary.display()))?;
        let hits: usize = needles
            .iter()
            .map(|n| {
                bytes
                    .windows(n.len())
                    .filter(|w| *w == n.as_slice())
                    .count()
            })
            .sum();
        if hits > 0 {
            offenders.push(format!("  {} ({hits} occurrences)", binary.display()));
        }
    }
    if !offenders.is_empty() {
        bail!(
            "these binaries embed absolute build paths from this machine:\n{}",
            offenders.join("\n")
        );
    }
    println!("dist: no build-machine paths in any Mach-O");
    Ok(())
}

/// Every Mach-O in the bundle: the app, the helpers, the app extension's executable.
fn mach_o_files(app: &Path) -> Result<Vec<PathBuf>> {
    let mut found = vec![app.join("Contents/MacOS").join(APP_NAME)];
    for helper in HELPERS {
        found.push(app.join("Contents").join(HELPERS_DIR).join(helper));
    }
    let plugins = app.join("Contents/PlugIns");
    if plugins.is_dir() {
        for entry in std::fs::read_dir(&plugins)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "appex") {
                let name = path
                    .file_stem()
                    .context("an .appex with no name")?
                    .to_string_lossy()
                    .into_owned();
                found.push(path.join("Contents/MacOS").join(name));
            }
        }
    }
    found.retain(|p| p.is_file());
    Ok(found)
}

/// `codesign --verify --deep --strict`, plus the Authority line, on every Mach-O.
fn verify_signature(app: &Path) -> Result<()> {
    let (ok, text) = capture_all(
        Command::new("codesign")
            .args(["--verify", "--deep", "--strict", "--verbose=2"])
            .arg(app),
    )?;
    if !ok {
        bail!("codesign --verify --deep --strict failed:\n{text}");
    }

    for binary in mach_o_files(app)? {
        // Captured first and searched afterwards, never piped into `grep -q`: see `util::capture`.
        let (_, description) = capture_all(
            Command::new("codesign")
                .args(["-dv", "--verbose=4"])
                .arg(&binary),
        )?;
        if !says(&description, &format!("Authority={IDENTITY}")) {
            bail!(
                "{} is not signed with a {IDENTITY} certificate:\n{description}",
                binary.display()
            );
        }
        if !says(&description, "flags=0x10000(runtime)") && !says(&description, "runtime") {
            bail!(
                "{} is not signed under the Hardened Runtime:\n{description}",
                binary.display()
            );
        }
        if !says(&description, "Timestamp=") {
            bail!(
                "{} has no secure timestamp; sign with --timestamp:\n{description}",
                binary.display()
            );
        }
    }
    println!("dist: every Mach-O is Developer ID signed, hardened and timestamped");
    Ok(())
}

/// Submit to the notary service and wait for the verdict.
///
/// `notarytool` cannot take a directory, so an `.app` is zipped first; a `.dmg` goes as it is.
fn notarize(dist_dir: &Path, target: &Path, profile: &str) -> Result<()> {
    let submission = if target.is_dir() {
        let zip = dist_dir.join(format!("{APP_NAME}.zip"));
        if zip.exists() {
            std::fs::remove_file(&zip)?;
        }
        // `ditto -c -k --keepParent` is the archive format Apple's own documentation asks for;
        // `zip -r` does not preserve the symlinks inside a bundle correctly.
        run(Command::new("ditto")
            .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
            .arg(target)
            .arg(&zip))
        .context("zipping the app for submission")?;
        zip
    } else {
        target.to_path_buf()
    };

    println!(
        "dist: submitting {} to the notary service; this takes minutes, sometimes half an hour",
        submission.file_name().unwrap_or_default().to_string_lossy()
    );
    let (ok, text) = capture_all(
        Command::new("xcrun")
            .args(["notarytool", "submit"])
            .arg(&submission)
            .args(["--keychain-profile", profile])
            .arg("--wait"),
    )?;
    println!("{text}");
    if !ok || !says(&text, "status: Accepted") {
        bail!(
            "notarization did not come back Accepted. Read the log before changing anything — \
             guessing wastes a submission:\n    xcrun notarytool log <submission-id> \
             --keychain-profile {profile}"
        );
    }
    Ok(())
}

/// Attach the ticket, so the artifact verifies with no network.
fn staple(target: &Path) -> Result<()> {
    run(Command::new("xcrun")
        .arg("stapler")
        .arg("staple")
        .arg(target))
    .with_context(|| format!("stapling {}", target.display()))?;
    println!("dist: stapled {}", target.display());
    Ok(())
}

/// Build the disk image around the app — which is already stapled by the time this runs.
///
/// A stable filename with no version in it, so that
/// `releases/latest/download/Kagisecure.dmg` is a permanent "always latest" link for a download
/// button and for Homebrew's `livecheck`. The version is in the git tag, the release page, the
/// About window and `Info.plist`; a fifth copy in the filename buys nothing and creates a
/// stale-file hazard in `dist/`.
fn build_dmg(dist_dir: &Path, app: &Path) -> Result<PathBuf> {
    let staging = dist_dir.join("dmg");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;

    run(Command::new("ditto")
        .arg(app)
        .arg(staging.join(format!("{APP_NAME}.app"))))
    .context("staging the app for the disk image")?;

    // The drag-to-install target. A relative symlink would point inside the image; an absolute
    // one resolves to the real /Applications on the machine that mounted it.
    link_applications(&staging)?;

    let dmg = dist_dir.join(format!("{APP_NAME}.dmg"));
    if dmg.exists() {
        std::fs::remove_file(&dmg)?;
    }
    run(Command::new("hdiutil")
        .args(["create", "-volname", APP_NAME])
        .arg("-srcfolder")
        .arg(&staging)
        .args(["-ov", "-format", "UDZO"])
        .arg(&dmg))
    .context("creating the disk image")?;

    // `hdiutil` leaves the image unsigned. Notarization accepts an unsigned DMG — the ticket
    // covers the app inside — but `spctl -t open --context context:primary-signature` then finds
    // no usable signature on the container itself and rejects it. Sign the DMG the same way the
    // app was signed, before it is submitted.
    run(Command::new("codesign")
        .args(["--force", "--sign", IDENTITY, "--timestamp"])
        .arg(&dmg))
    .context("signing the disk image")?;

    println!("dist: dmg -> {}", dmg.display());
    Ok(dmg)
}

/// The verification the skill insists on, all three of it, on both artifacts — then the checksum.
fn report(app: &Path, dmg: &Path, notarized: bool) -> Result<()> {
    println!("\n--- verification ---");

    let (_, app_assessment) = capture_all(
        Command::new("spctl")
            .args(["-a", "-vv", "-t", "install"])
            .arg(app),
    )?;
    println!("spctl (app):\n{app_assessment}");

    let (_, dmg_assessment) = capture_all(
        Command::new("spctl")
            .args([
                "-a",
                "-vv",
                "-t",
                "open",
                "--context",
                "context:primary-signature",
            ])
            .arg(dmg),
    )?;
    println!("spctl (dmg):\n{dmg_assessment}");

    for target in [app, dmg] {
        let (_, text) = capture_all(
            Command::new("xcrun")
                .args(["stapler", "validate"])
                .arg(target),
        )?;
        println!("stapler validate {}:\n{text}", target.display());
    }

    let checksum = capture(Command::new("shasum").args(["-a", "256"]).arg(dmg))?;
    println!("\nSHA-256: {checksum}");

    if !notarized {
        println!(
            "\nNOTE: nothing was submitted to Apple, so neither artifact carries a ticket and \
             Gatekeeper will refuse them on another Mac. Set {PROFILE_ENV} and re-run without \
             --skip-notarize."
        );
    } else if !says(&app_assessment, "source=Notarized Developer ID") {
        bail!("the app was notarized but spctl does not see a ticket:\n{app_assessment}");
    }
    Ok(())
}

#[cfg(unix)]
fn link_applications(staging: &std::path::Path) -> Result<()> {
    std::os::unix::fs::symlink("/Applications", staging.join("Applications"))
        .context("creating the /Applications symlink")
}

#[cfg(not(unix))]
fn link_applications(_staging: &std::path::Path) -> Result<()> {
    bail!("a disk image can only be built on macOS")
}
