//! Sparkle's half of `cargo xtask dist` (ADR-0044): the updater's settings for the build, and the
//! feed the release adds itself to.
//!
//! The same shape as itsustar's `scripts/release-mac`. The release build gets the production feed
//! URL and the EdDSA public key on the xcodebuild command line, the stapled app is zipped and
//! signed with the private key, Sparkle's `generate_appcast` adds it to the feed and signs the
//! feed, and the result lands in `dist/mac-updates/`, laid out exactly as
//! `https://kagisecure.com/mac/` serves it. Uploading it is the release's last manual step
//! (docs/releasing.md §8): the archive first, the feed last, so the feed never names an archive
//! that is not there yet.
//!
//! The key pair lives in the release machine's login keychain under [`KEY_ACCOUNT`], created once
//! with Sparkle's `generate_keys --account com.kagisecure.app`. Only the public half ever leaves
//! it, and only into the built app's Info.plist.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::util::{capture, capture_all, run};

/// Where every release build looks for updates.
pub const FEED_URL: &str = "https://kagisecure.com/mac/appcast.xml";

/// The keychain account Sparkle's tools keep the EdDSA key under.
pub const KEY_ACCOUNT: &str = "com.kagisecure.app";

/// How many releases the feed keeps listing.
const ITEMS_KEPT: u32 = 5;

/// The updater settings a release build is made with.
pub struct Settings {
    pub feed_url: String,
    pub public_key: String,
}

impl Settings {
    /// The `xcodebuild` build-setting overrides that put these into the app's Info.plist.
    pub fn build_settings(&self) -> [String; 2] {
        [
            format!("KAGISECURE_UPDATE_FEED_URL={}", self.feed_url),
            format!("KAGISECURE_SPARKLE_PUBLIC_KEY={}", self.public_key),
        ]
    }
}

/// Resolve the Sparkle package into `derived` (so its command-line tools exist) and read the
/// public key from the keychain.
pub fn settings(macos_dir: &Path, derived: &Path) -> Result<Settings> {
    run(Command::new("xcodebuild")
        .current_dir(macos_dir)
        .args(["-project", "Kagisecure.xcodeproj"])
        .args(["-scheme", "Kagisecure"])
        .arg("-derivedDataPath")
        .arg(derived)
        .arg("-resolvePackageDependencies"))
    .context("resolving Swift packages")?;
    let public_key = capture(
        Command::new(tool(derived, "generate_keys")?)
            .args(["--account", KEY_ACCOUNT])
            .arg("-p"),
    )
    .with_context(|| {
        format!(
            "no Sparkle key for account {KEY_ACCOUNT} in the keychain. Create it once with \
             Sparkle's `generate_keys --account {KEY_ACCOUNT}` and back up the private key \
             (`generate_keys --account {KEY_ACCOUNT} -x <file>`): losing it means no installed \
             copy can ever update again."
        )
    })?
    .trim()
    .to_string();
    if public_key.is_empty() {
        bail!("Sparkle's generate_keys printed no public key for account {KEY_ACCOUNT}");
    }
    Ok(Settings {
        feed_url: FEED_URL.to_string(),
        public_key,
    })
}

/// Check the built app carries exactly these settings.
pub fn verify_info(app: &Path, settings: &Settings) -> Result<()> {
    let info = app.join("Contents/Info.plist");
    for (key, expected) in [
        ("SUFeedURL", settings.feed_url.as_str()),
        ("SUPublicEDKey", settings.public_key.as_str()),
        ("SURequireSignedFeed", "true"),
    ] {
        let actual = plist_value(&info, key)?;
        if actual != expected {
            bail!("{key} in the app's Info.plist is '{actual}', expected '{expected}'");
        }
    }
    if !app.join("Contents/Frameworks/Sparkle.framework").is_dir() {
        bail!("Sparkle.framework is not embedded in {}", app.display());
    }
    Ok(())
}

/// Zip the stapled app, add it to the feed (the live one, fetched first, so earlier releases stay
/// listed), sign the feed, and verify it. Returns the feed directory.
pub fn feed(dist_dir: &Path, derived: &Path, app: &Path, version: &str) -> Result<PathBuf> {
    let feed = dist_dir.join("mac-updates");
    let releases = feed.join("releases");
    std::fs::create_dir_all(&releases)?;
    let appcast = feed.join("appcast.xml");

    // The live feed, if there is one yet: 404 is the first release.
    let status = capture(
        Command::new("curl")
            .args(["--silent", "--show-error", "--output"])
            .arg(&appcast)
            .args(["--write-out", "%{http_code}", FEED_URL]),
    )?;
    match status.as_str() {
        "200" => {}
        "404" => {
            let _ = std::fs::remove_file(&appcast);
        }
        other => bail!("reading {FEED_URL} answered {other}"),
    }
    if appcast.is_file()
        && std::fs::read_to_string(&appcast)?.contains(&format!(
            "<sparkle:shortVersionString>{version}</sparkle:shortVersionString>"
        ))
    {
        bail!("the live feed already lists {version}; bump the version first");
    }

    let archive = releases.join(format!("Kagisecure-{version}.zip"));
    run(Command::new("ditto")
        .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
        .arg(app)
        .arg(&archive))
    .context("zipping the app for Sparkle")?;

    let prefix = format!("{}/releases/", FEED_URL.trim_end_matches("/appcast.xml"));
    run(Command::new(tool(derived, "generate_appcast")?)
        .args(["--account", KEY_ACCOUNT])
        .args(["--download-url-prefix", &prefix])
        .args(["--maximum-deltas", "0"])
        .args(["--maximum-versions", &ITEMS_KEPT.to_string()])
        .arg("-o")
        .arg(&appcast)
        .arg(&releases))
    .context("generate_appcast")?;
    let _ = std::fs::remove_dir_all(releases.join("old_updates"));

    let written = std::fs::read_to_string(&appcast)?;
    if !written.contains(&format!("Kagisecure-{version}.zip")) {
        bail!("the feed does not list Kagisecure-{version}.zip");
    }
    run(Command::new(tool(derived, "sign_update")?)
        .args(["--account", KEY_ACCOUNT, "--verify"])
        .arg(&appcast))
    .context("the signed feed does not verify")?;
    println!("dist: Sparkle feed -> {}", feed.display());
    Ok(feed)
}

/// One of Sparkle's command-line tools, from the resolved package.
fn tool(derived: &Path, name: &str) -> Result<PathBuf> {
    let artifacts = derived.join("SourcePackages/artifacts");
    find(&artifacts, name)?.with_context(|| {
        format!(
            "Sparkle's {name} was not found under {}; package resolution should have put it there",
            artifacts.display()
        )
    })
}

fn find(dir: &Path, name: &str) -> Result<Option<PathBuf>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(None);
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = find(&path, name)? {
                return Ok(Some(found));
            }
        } else if path.file_name().is_some_and(|n| n == name)
            && path.parent().is_some_and(|p| p.ends_with("bin"))
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn plist_value(plist: &Path, key: &str) -> Result<String> {
    let (ok, out) = capture_all(
        Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :{key}")])
            .arg(plist),
    )?;
    Ok(if ok {
        out.trim().to_string()
    } else {
        "(absent)".to_string()
    })
}
