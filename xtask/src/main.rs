//! Repository automation. `cargo xtask <task>`.
//!
//! Architecture §7 picks `cargo xtask` over a Makefile or a pile of shell scripts, so anything
//! that has to happen the same way on every machine belongs here: the Swift bindings, the
//! helper binaries the app bundle carries, the version check, and the whole signed-and-notarized
//! release.

mod bindgen;
mod dist;
mod embed;
mod helpers;
mod util;
mod version;

use anyhow::{Context, Result, bail};

use crate::helpers::{Arches, Profile};
use crate::util::repo_root;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let root = repo_root()?;

    match args.first().map(String::as_str) {
        Some("bindgen") => bindgen::bindgen(&root, arches(&flags)?),
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
         \x20 helpers [--release] [--universal]\n\
         \x20           build kagisecure-mcp, kagisecure-nmhost and the kagisecure CLI into\n\
         \x20           target/helpers/<Configuration>, where the app's embed build phase\n\
         \x20           picks them up\n\
         \x20 embed [--release] <path/to/Kagisecure.app>\n\
         \x20           copy the staged helpers into a built app and sign it inside-out.\n\
         \x20           Signs ad-hoc unless KAGISECURE_SIGN_IDENTITY names a certificate\n\
         \x20 version   check that Cargo.toml, apps/macos/project.yml and CHANGELOG.md agree\n\
         \x20 dist [--host-only] [--skip-notarize]\n\
         \x20           the release: Release build, Developer ID signing, notarization,\n\
         \x20           stapling, DMG, and the verification that proves it worked. Universal\n\
         \x20           unless --host-only. Reads the notarytool credential profile's *name*\n\
         \x20           from NOTARY_KEYCHAIN_PROFILE; see docs/releasing.md\n"
    );
}
