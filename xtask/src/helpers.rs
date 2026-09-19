//! `cargo xtask helpers` — build the three binaries that ship inside the app bundle.
//!
//! `kagisecure-mcp`, `kagisecure-nmhost` and the `kagisecure` CLI are staged into
//! `target/helpers/<Configuration>/`, which is where `apps/macos/Scripts/embed-helpers.sh` looks
//! for them. Staging exists so that the Xcode build phase never has to know whether a build is
//! universal: `lipo` happens here, and the phase copies whatever it finds.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::util::{cargo, release_rustflags, run};

/// The binaries a released app carries. Must match `kagisecure_agent::bundle`'s three name
/// constants — the app looks for exactly these names in exactly the directory below.
pub const HELPERS: [&str; 3] = ["kagisecure-mcp", "kagisecure-nmhost", "kagisecure"];

/// Where inside `Contents` they go. Must match `kagisecure_agent::bundle::HELPERS_DIR`.
pub const HELPERS_DIR: &str = "Helpers";

/// The crate each of them comes out of.
const PACKAGES: [&str; 3] = ["kagisecure-mcp", "kagisecure-nmhost", "kagisecure-cli"];

/// Apple silicon.
pub const AARCH64: &str = "aarch64-apple-darwin";
/// Intel.
pub const X86_64: &str = "x86_64-apple-darwin";

/// How a build is arranged: one architecture, or both `lipo`d together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arches {
    /// Whatever this machine is. What a contributor gets (and what CI built, before it was
    /// removed on 2026-09-19).
    Host,
    /// `aarch64` and `x86_64` in one Mach-O. What a release ships (ADR-0027).
    Universal,
}

impl Arches {
    /// The rustc target triples to build.
    pub fn targets(self) -> Vec<&'static str> {
        match self {
            Self::Host => vec![host_target()],
            Self::Universal => vec![AARCH64, X86_64],
        }
    }
}

/// This machine's target triple, as far as the two Apple ones go.
pub fn host_target() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        X86_64
    } else {
        AARCH64
    }
}

/// `Debug` or `Release`, spelled the way Xcode spells it — the staging directory is named after
/// `$CONFIGURATION`, so the two must agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// `cargo build`.
    Debug,
    /// `cargo build --release`. The only one a release ships.
    Release,
}

impl Profile {
    /// The Xcode configuration name, which is also the staging directory's name.
    pub fn configuration(self) -> &'static str {
        match self {
            Self::Debug => "Debug",
            Self::Release => "Release",
        }
    }

    /// The `target/<triple>/<here>` directory cargo writes to.
    pub fn cargo_dir(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

/// Where `helpers` stages its output and where the Xcode build phase reads it.
pub fn staging_dir(root: &Path, profile: Profile) -> PathBuf {
    root.join("target")
        .join("helpers")
        .join(profile.configuration())
}

/// Build the three helpers and stage them.
pub fn helpers(root: &Path, profile: Profile, arches: Arches) -> Result<PathBuf> {
    let targets = arches.targets();
    for target in &targets {
        let mut command = Command::new(cargo());
        command.current_dir(root).arg("build");
        if profile == Profile::Release {
            command
                .arg("--release")
                .env("RUSTFLAGS", release_rustflags(root));
        }
        for package in PACKAGES {
            command.args(["-p", package]);
        }
        command.args(["--target", target]);
        run(&mut command).with_context(|| format!("building the helpers for {target}"))?;
    }

    let staging = staging_dir(root, profile);
    std::fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;

    for helper in HELPERS {
        let slices: Vec<PathBuf> = targets
            .iter()
            .map(|target| {
                root.join("target")
                    .join(target)
                    .join(profile.cargo_dir())
                    .join(helper)
            })
            .collect();
        for slice in &slices {
            if !slice.is_file() {
                bail!("cargo did not produce {}", slice.display());
            }
        }
        let destination = staging.join(helper);
        if slices.len() == 1 {
            std::fs::copy(&slices[0], &destination)
                .with_context(|| format!("staging {}", destination.display()))?;
        } else {
            let mut command = Command::new("lipo");
            command.arg("-create");
            for slice in &slices {
                command.arg(slice);
            }
            command.arg("-output").arg(&destination);
            run(&mut command).with_context(|| format!("lipo-ing {helper}"))?;
        }
        println!("helpers: {} -> {}", helper, destination.display());
    }
    Ok(staging)
}
