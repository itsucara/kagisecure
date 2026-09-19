//! `cargo xtask version` — one version number, checked in the two places it is written.
//!
//! The workspace version in `Cargo.toml` is the source of truth. XcodeGen cannot read a
//! `Cargo.toml`, so `apps/macos/project.yml` repeats it as `MARKETING_VERSION`, and a repeated
//! constant is a constant that drifts. This task is what stops it: `cargo xtask dist` runs it
//! before it builds anything.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// The workspace version from `Cargo.toml`.
///
/// Parsed by hand rather than with a TOML crate: the value is on one line in a file this
/// repository controls, and adding a dependency to `xtask` so that it can read four characters
/// out of its own manifest would be a poor trade.
pub fn workspace_version(root: &Path) -> Result<String> {
    let manifest = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let mut in_package = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_package && let Some(rest) = trimmed.strip_prefix("version") {
            let value = rest
                .trim_start()
                .strip_prefix('=')
                .context("[workspace.package] version has no `=`")?;
            return Ok(value.trim().trim_matches('"').to_owned());
        }
    }
    bail!(
        "no version in [workspace.package] of {}",
        manifest.display()
    )
}

/// The `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` XcodeGen will bake into the bundles.
fn project_versions(root: &Path) -> Result<(String, String)> {
    let spec = root.join("apps/macos/project.yml");
    let text =
        std::fs::read_to_string(&spec).with_context(|| format!("reading {}", spec.display()))?;
    let value_of = |key: &str| -> Option<String> {
        text.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(&format!("{key}:")))
            .map(|rest| rest.trim().trim_matches('"').to_owned())
    };
    let marketing = value_of("MARKETING_VERSION")
        .with_context(|| format!("no MARKETING_VERSION in {}", spec.display()))?;
    let current = value_of("CURRENT_PROJECT_VERSION")
        .with_context(|| format!("no CURRENT_PROJECT_VERSION in {}", spec.display()))?;
    Ok((marketing, current))
}

/// Check every place the version is written, and print it.
pub fn check(root: &Path) -> Result<String> {
    let workspace = workspace_version(root)?;
    let (marketing, current) = project_versions(root)?;

    if marketing != workspace {
        bail!(
            "version drift: Cargo.toml [workspace.package] says {workspace}, but \
             apps/macos/project.yml MARKETING_VERSION says {marketing}. Update project.yml."
        );
    }
    if current != workspace {
        bail!(
            "version drift: Cargo.toml [workspace.package] says {workspace}, but \
             apps/macos/project.yml CURRENT_PROJECT_VERSION says {current}. Update project.yml."
        );
    }

    let changelog = root.join("CHANGELOG.md");
    let text = std::fs::read_to_string(&changelog)
        .with_context(|| format!("reading {}", changelog.display()))?;
    if !text.contains(&format!("## {workspace}")) {
        bail!(
            "CHANGELOG.md has no `## {workspace}` section. A release with no changelog entry is \
             a release nobody can read."
        );
    }

    println!("version: {workspace} — Cargo.toml, project.yml and CHANGELOG.md agree");
    Ok(workspace)
}
