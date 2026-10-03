//! `cargo xtask version` — one version number, checked everywhere it is written.
//!
//! The workspace version in `Cargo.toml` is the source of truth. XcodeGen cannot read a
//! `Cargo.toml`, so `apps/macos/project.yml` repeats it as `MARKETING_VERSION`, and a repeated
//! constant is a constant that drifts. The browser extension has no build step, so its two
//! manifests (`extensions/shared/manifest.json` for Chromium, `extensions/safari/manifest.json`
//! for Safari) repeat it too. This task is what stops them drifting: `cargo xtask dist` and
//! `cargo xtask chrome-package` run it before they build anything, and the manifests are also
//! checked by a unit test, so `cargo test` catches a bump that missed one.

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

/// The extension manifests that repeat the workspace version, relative to the repository root.
pub const EXTENSION_MANIFESTS: &[&str] = &[
    "extensions/shared/manifest.json",
    "extensions/safari/manifest.json",
];

/// The `"version"` of a browser extension manifest.
///
/// A line scan for the same reason [`workspace_version`] is one: a JSON parser would be fine
/// here, but the field is one line in a file this repository controls, and this keeps the check
/// readable next to its neighbours. Only a top-level `"version"` is meant; the manifests have no
/// nested one, and `manifest_version` is a different key.
pub fn manifest_version(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        let rest = line.strip_prefix("\"version\"")?;
        let value = rest.trim_start().strip_prefix(':')?.trim();
        let value = value.trim_end_matches(',').trim();
        Some(value.trim_matches('"').to_owned())
    })
}

/// Check that both extension manifests carry `workspace` as their version.
pub fn check_extension_manifests(root: &Path, workspace: &str) -> Result<()> {
    for relative in EXTENSION_MANIFESTS {
        let path = root.join(relative);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let found =
            manifest_version(&text).with_context(|| format!("no \"version\" in {relative}"))?;
        if found != workspace {
            bail!(
                "version drift: Cargo.toml [workspace.package] says {workspace}, but {relative} \
                 says {found}. Update the manifest's \"version\"."
            );
        }
    }
    Ok(())
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

    check_extension_manifests(root, &workspace)?;

    let changelog = root.join("CHANGELOG.md");
    let text = std::fs::read_to_string(&changelog)
        .with_context(|| format!("reading {}", changelog.display()))?;
    if !text.contains(&format!("## {workspace}")) {
        bail!(
            "CHANGELOG.md has no `## {workspace}` section. A release with no changelog entry is \
             a release nobody can read."
        );
    }

    println!(
        "version: {workspace} — Cargo.toml, project.yml, the extension manifests and CHANGELOG.md \
         agree"
    );
    Ok(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_version_is_read_and_manifest_version_is_not() {
        let text =
            "{\n  \"manifest_version\": 3,\n  \"name\": \"K\",\n  \"version\": \"0.1.1\",\n}";
        assert_eq!(manifest_version(text).as_deref(), Some("0.1.1"));
        assert_eq!(manifest_version("{ \"manifest_version\": 3 }"), None);
    }

    /// The guard against drift that runs with every `cargo test`, not only when someone remembers
    /// `cargo xtask version`.
    #[test]
    fn the_extension_manifests_carry_the_workspace_version() {
        let root = crate::util::repo_root().unwrap();
        let workspace = workspace_version(&root).unwrap();
        check_extension_manifests(&root, &workspace).unwrap();
    }
}
