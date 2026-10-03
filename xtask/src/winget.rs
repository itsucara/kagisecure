//! `cargo xtask winget-manifest --version X --url URL` — generate the three winget package
//! manifest YAML files for a built `dist-windows` release.
//!
//! A separate task from `dist-windows` itself, deliberately: `dist-windows` produces
//! `dist/windows/Kagisecure.msi` on *this* machine, but a winget manifest's `InstallerUrl` has to
//! name wherever that exact MSI ends up publicly downloadable (a GitHub release asset today, per
//! `docs/releasing.md`), which is only known once the release is uploaded — a step this pipeline
//! does not do and should not guess at. Run `dist-windows` first, upload `Kagisecure.msi` to the
//! release, then run this with that URL.
//!
//! This does not submit anything to `microsoft/winget-pkgs` — see `docs/releasing.md` §10.8 for
//! how a maintainer does that by hand with the generated files.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::util::{capture, sha256_file};

/// `winget-pkgs`' own package identifier convention: `<Publisher>.<PackageName>`, no spaces.
/// "Itsucara" matches the publisher name macOS's Developer ID and the Homebrew tap already use
/// (`README.md`); nothing here invents a second name for the same organisation.
pub const PACKAGE_IDENTIFIER: &str = "Itsucara.Kagisecure";

/// The winget manifest schema version these three files declare. `docs/releasing.md` §10.8 says
/// to bump this (and re-run `winget validate`) if a submission is rejected for a schema that has
/// since moved on — 1.6.0 is simply the version whose schema this was written against and checked
/// with `winget validate` on this machine, not a hard requirement of winget itself.
const SCHEMA_VERSION: &str = "1.6.0";

/// Run the task: read the MSI `dist-windows` already built, and write
/// `target/dist-windows/winget/<version>/*.yaml`.
pub fn winget_manifest(root: &Path, version: &str, url: &str) -> Result<()> {
    if !cfg!(windows) {
        bail!(
            "cargo xtask winget-manifest reads the built MSI's ProductCode via the Windows \
             Installer COM API (through PowerShell); run it on Windows, after `dist-windows`"
        );
    }
    if version.trim().is_empty() {
        bail!("--version needs a value, e.g. --version 0.1.0");
    }
    if url.trim().is_empty() {
        bail!("--url needs a value, e.g. --url https://github.com/.../Kagisecure.msi");
    }

    let msi = root.join("dist/windows/Kagisecure.msi");
    if !msi.is_file() {
        bail!(
            "no MSI at {} — run `cargo xtask dist-windows` first, then re-run this with the \
             URL the resulting Kagisecure.msi was uploaded to",
            msi.display()
        );
    }

    let sha256 = sha256_file(&msi)?;
    let product_code = read_product_code(&msi)?;
    println!(
        "winget-manifest: {} -> ProductCode {product_code}",
        msi.display()
    );
    println!("winget-manifest: SHA-256 {sha256}");

    let out_dir = root.join("target/dist-windows/winget").join(version);
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    write_file(
        &out_dir.join(format!("{PACKAGE_IDENTIFIER}.yaml")),
        &version_manifest(version),
    )?;
    write_file(
        &out_dir.join(format!("{PACKAGE_IDENTIFIER}.installer.yaml")),
        &installer_manifest(version, url, &sha256, &product_code),
    )?;
    write_file(
        &out_dir.join(format!("{PACKAGE_IDENTIFIER}.locale.en-US.yaml")),
        &locale_manifest(version),
    )?;

    println!("winget-manifest: manifests -> {}", out_dir.display());
    println!(
        "winget-manifest: not submitted anywhere. See docs/releasing.md §10.8 for how a \
         maintainer submits these to microsoft/winget-pkgs."
    );
    Ok(())
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    println!("winget-manifest: wrote {}", path.display());
    Ok(())
}

fn version_manifest(version: &str) -> String {
    format!(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.{SCHEMA_VERSION}.schema.json\n\
         PackageIdentifier: {PACKAGE_IDENTIFIER}\n\
         PackageVersion: {version}\n\
         DefaultLocale: en-US\n\
         ManifestType: version\n\
         ManifestVersion: {SCHEMA_VERSION}\n"
    )
}

fn installer_manifest(version: &str, url: &str, sha256: &str, product_code: &str) -> String {
    format!(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.{SCHEMA_VERSION}.schema.json\n\
         PackageIdentifier: {PACKAGE_IDENTIFIER}\n\
         PackageVersion: {version}\n\
         InstallerType: msi\n\
         # ADR-0034: a per-user MSI (Scope=\"perUser\" in Product.wxs), no admin/UAC prompt — the\n\
         # winget installer scope has to say the same thing or winget would offer a machine-wide\n\
         # install this MSI cannot do.\n\
         Scope: user\n\
         InstallModes:\n\
         \x20 - interactive\n\
         \x20 - silent\n\
         \x20 - silentWithProgress\n\
         UpgradeBehavior: install\n\
         Installers:\n\
         \x20 - Architecture: x64\n\
         \x20   InstallerUrl: {url}\n\
         \x20   InstallerSha256: {sha256}\n\
         \x20   ProductCode: '{product_code}'\n\
         ManifestType: installer\n\
         ManifestVersion: {SCHEMA_VERSION}\n"
    )
}

fn locale_manifest(version: &str) -> String {
    format!(
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.{SCHEMA_VERSION}.schema.json\n\
         PackageIdentifier: {PACKAGE_IDENTIFIER}\n\
         PackageVersion: {version}\n\
         PackageLocale: en-US\n\
         Publisher: Itsucara\n\
         PublisherUrl: https://itsucara.com\n\
         PackageName: Kagisecure\n\
         PackageUrl: https://github.com/itsucara/kagisecure\n\
         License: MIT OR Apache-2.0\n\
         LicenseUrl: https://github.com/itsucara/kagisecure/blob/main/LICENSE-MIT\n\
         ShortDescription: A local-first password manager\n\
         ManifestType: defaultLocale\n\
         ManifestVersion: {SCHEMA_VERSION}\n"
    )
}

/// Read the `ProductCode` Windows actually assigned the built MSI, straight from its own
/// Property table — `Product.wxs` does not pin one (`<Package>` has no `Id`, so WiX generates a
/// fresh GUID every build), so the only place to learn the real value is the artifact itself.
/// Uses the same `WindowsInstaller.Installer` COM automation `docs/releasing.md` §10.4 shows for
/// inspecting the MSI's tables by hand — no new dependency for one property read.
fn read_product_code(msi: &Path) -> Result<String> {
    let msi_str = msi
        .to_str()
        .context("the MSI's path is not valid UTF-8")?
        .replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $installer = New-Object -ComObject WindowsInstaller.Installer; \
         $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @('{msi_str}', 0)); \
         $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @(\"SELECT Value FROM Property WHERE Property = 'ProductCode'\")); \
         $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null); \
         $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null); \
         $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)"
    );
    let output = capture(Command::new("powershell").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script,
    ]))
    .context("reading ProductCode from the MSI via WindowsInstaller.Installer")?;
    let code = output.trim();
    if !(code.starts_with('{') && code.ends_with('}') && code.len() == 38) {
        bail!(
            "unexpected ProductCode read from {}: {code:?}",
            msi.display()
        );
    }
    Ok(code.to_uppercase())
}

/// Parse `--version <v> --url <u>` (in either order) out of the flags following `winget-manifest`
/// on the command line.
pub fn parse_args(flags: &[&str]) -> Result<(String, String)> {
    let mut version = None;
    let mut url = None;
    let mut iter = flags.iter();
    while let Some(flag) = iter.next() {
        match *flag {
            "--version" => {
                version = Some(iter.next().context("--version needs a value")?.to_string());
            }
            "--url" => {
                url = Some(iter.next().context("--url needs a value")?.to_string());
            }
            other => bail!("unknown flag {other:?}"),
        }
    }
    let version = version.context("winget-manifest needs --version <x.y.z>")?;
    let url = url.context("winget-manifest needs --url <installer url>")?;
    Ok((version, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_and_url_in_either_order() {
        let (v, u) = parse_args(&[
            "--version",
            "0.1.0",
            "--url",
            "https://example/Kagisecure.msi",
        ])
        .unwrap();
        assert_eq!(v, "0.1.0");
        assert_eq!(u, "https://example/Kagisecure.msi");

        let (v, u) = parse_args(&[
            "--url",
            "https://example/Kagisecure.msi",
            "--version",
            "0.1.0",
        ])
        .unwrap();
        assert_eq!(v, "0.1.0");
        assert_eq!(u, "https://example/Kagisecure.msi");
    }

    #[test]
    fn rejects_missing_flags() {
        assert!(parse_args(&["--version", "0.1.0"]).is_err());
        assert!(parse_args(&["--url", "https://example"]).is_err());
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(parse_args(&["--version", "0.1.0", "--url", "u", "--bogus"]).is_err());
    }

    #[test]
    fn manifest_bodies_carry_the_given_values() {
        let installer = installer_manifest(
            "0.1.0",
            "https://example/Kagisecure.msi",
            "ABCDEF",
            "{11111111-1111-1111-1111-111111111111}",
        );
        assert!(installer.contains("PackageVersion: 0.1.0"));
        assert!(installer.contains("InstallerUrl: https://example/Kagisecure.msi"));
        assert!(installer.contains("InstallerSha256: ABCDEF"));
        assert!(installer.contains("ProductCode: '{11111111-1111-1111-1111-111111111111}'"));
        assert!(installer.contains("Scope: user"));
        assert!(installer.contains("InstallerType: msi"));

        let version = version_manifest("0.1.0");
        assert!(version.contains(&format!("PackageIdentifier: {PACKAGE_IDENTIFIER}")));

        let locale = locale_manifest("0.1.0");
        assert!(locale.contains("Publisher: Itsucara"));
    }
}
