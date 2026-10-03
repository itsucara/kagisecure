//! Repository automation. `cargo xtask <task>`.
//!
//! Architecture §7 picks `cargo xtask` over a Makefile or a pile of shell scripts, so anything
//! that has to happen the same way on every machine belongs here: the Swift bindings, the
//! helper binaries the app bundle carries, the version check, and the whole signed-and-notarized
//! release — `dist` for macOS, `dist-windows` for the WinUI app (ADR-0034) — and the browser
//! extension's Chrome Web Store package, `chrome-package`.

mod bindgen;
mod bindgen_cs;
mod chrome_package;
mod dist;
mod dist_windows;
mod embed;
mod helpers;
mod license_rtf;
mod sparkle;
mod util;
mod version;
mod winget;

use anyhow::{Context, Result, bail};

use crate::helpers::{Arches, Profile};
use crate::util::repo_root;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let root = repo_root()?;

    match args.first().map(String::as_str) {
        Some("bindgen") if flags == ["--swift-only"] => bindgen::swift_sources_only(&root),
        Some("bindgen") => bindgen::bindgen(&root, arches(&flags)?),
        Some("bindgen-cs") => {
            // Only `--release` means anything here: a Windows DLL has no universal build.
            if let Some(flag) = flags.iter().find(|f| **f != "--release") {
                bail!("unknown flag {flag:?}");
            }
            let profile = if flags.contains(&"--release") {
                Profile::Release
            } else {
                Profile::Debug
            };
            bindgen_cs::bindgen_cs(&root, profile).map(|_| ())
        }
        Some("helpers") => {
            let profile = if flags.contains(&"--release") {
                Profile::Release
            } else {
                Profile::Debug
            };
            helpers::helpers(&root, profile, arches(&flags)?).map(|_| ())
        }
        Some("version") => version::check(&root).map(|_| ()),
        Some("embed") => {
            let profile = if flags.contains(&"--release") {
                Profile::Release
            } else {
                Profile::Debug
            };
            let app = flags
                .iter()
                .find(|f| !f.starts_with("--"))
                .context("cargo xtask embed needs the path to a built .app")?;
            embed::embed(
                std::path::Path::new(app),
                &helpers::staging_dir(&root, profile),
                &root.join("apps/macos/Signing/Helper.entitlements"),
                &std::env::var("KAGISECURE_SIGN_IDENTITY").unwrap_or_else(|_| "-".to_owned()),
            )
        }
        Some("dist") => dist::dist(
            &root,
            &dist::Options {
                // Universal is the default here and only here: `dist` is the release, and a
                // release that runs on half the Macs in the world is not one (ADR-0027).
                universal: !flags.contains(&"--host-only"),
                skip_notarize: flags.contains(&"--skip-notarize"),
            },
        ),
        Some("chrome-package") => {
            if let Some(flag) = flags.first() {
                bail!("unknown flag {flag:?}");
            }
            chrome_package::chrome_package(&root).map(|_| ())
        }
        Some("dist-windows") => {
            if let Some(flag) = flags.first() {
                bail!("unknown flag {flag:?}");
            }
            dist_windows::dist_windows(&root)
        }
        Some("winget-manifest") => {
            let (version, url) = winget::parse_args(&flags)?;
            winget::winget_manifest(&root, &version, &url)
        }
        Some("help" | "--help" | "-h") | None => {
            usage();
            Ok(())
        }
        Some(other) => {
            usage();
            bail!("unknown task {other:?}");
        }
    }
}

/// `--universal` on the tasks whose default is the host architecture.
fn arches(flags: &[&str]) -> Result<Arches> {
    for flag in flags {
        if !matches!(
            *flag,
            "--universal" | "--release" | "--host-only" | "--skip-notarize"
        ) {
            bail!("unknown flag {flag:?}");
        }
    }
    Ok(if flags.contains(&"--universal") {
        Arches::Universal
    } else {
        Arches::Host
    })
}

fn usage() {
    eprintln!(
        "cargo xtask <task>\n\
         \n\
         tasks:\n\
         \x20 bindgen [--universal]\n\
         \x20           build kagisecure-ffi, regenerate the Swift bindings into\n\
         \x20           apps/macos/KagisecureFFI/Sources, and assemble the xcframework\n\
         \x20 bindgen --swift-only\n\
         \x20           regenerate only the checked-in Swift sources, from a host build; runs\n\
         \x20           on any OS, so an FFI change made off a Mac does not leave them stale\n\
         \x20 bindgen-cs [--release]\n\
         \x20           Windows only: build kagisecure_ffi.dll with the `capi` C ABI, stage it\n\
         \x20           in target/windows/<Configuration>, where apps/windows picks it up, and\n\
         \x20           regenerate the C# declarations (ADR-0003 fallback, csbindgen)\n\
         \x20 helpers [--release] [--universal]\n\
         \x20           build kagisecure-mcp, kagisecure-nmhost and the kagisecure CLI into\n\
         \x20           target/helpers/<Configuration>, where the app's embed build phase\n\
         \x20           picks them up\n\
         \x20 embed [--release] <path/to/Kagisecure.app>\n\
         \x20           copy the staged helpers into a built app and sign it inside-out.\n\
         \x20           Signs ad-hoc unless KAGISECURE_SIGN_IDENTITY names a certificate\n\
         \x20 version   check that Cargo.toml, apps/macos/project.yml, the two extension\n\
         \x20           manifests and CHANGELOG.md agree\n\
         \x20 chrome-package\n\
         \x20           zip extensions/shared for the Chrome Web Store into\n\
         \x20           dist/kagisecure-chrome-<version>.zip: `key` removed, version from\n\
         \x20           Cargo.toml, no dotfiles or tests, deterministic, every file the manifest\n\
         \x20           names checked. See docs/chrome-web-store.md\n\
         \x20 dist [--host-only] [--skip-notarize]\n\
         \x20           the release: Release build, Developer ID signing, notarization,\n\
         \x20           stapling, DMG, and the verification that proves it worked. Universal\n\
         \x20           unless --host-only. Reads the notarytool credential profile's *name*\n\
         \x20           from NOTARY_KEYCHAIN_PROFILE; see docs/releasing.md\n\
         \x20 dist-windows\n\
         \x20           Windows only: build the helpers and kagisecure_ffi.dll, publish the\n\
         \x20           WinUI app self-contained, Authenticode-sign every PE this project\n\
         \x20           builds, package a per-user MSI with wix, verify and print its SHA-256.\n\
         \x20           Signs with the certificate named by KAGISECURE_SIGN_CERT_SHA1 or\n\
         \x20           KAGISECURE_SIGN_CERT_SUBJECT; with neither set, builds an unsigned MSI\n\
         \x20           and says so loudly. See docs/releasing.md and ADR-0034\n\
         \x20 winget-manifest --version <x.y.z> --url <installer url>\n\
         \x20           Windows only: generate the three winget package manifest YAML files\n\
         \x20           (version, installer, defaultLocale) for the MSI `dist-windows` already\n\
         \x20           built at dist/windows/Kagisecure.msi, into\n\
         \x20           target/dist-windows/winget/<version>/. Reads the MSI's own SHA-256 and\n\
         \x20           ProductCode; does not upload or submit anything. See docs/releasing.md\n\
         \x20           §10.8 for how a maintainer submits the result to winget-pkgs\n"
    );
}
