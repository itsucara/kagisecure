//! `cargo xtask dist-windows` — build, sign, package, verify the Windows release.
//!
//! The Windows analogue of `dist` (`xtask/src/dist.rs`), and [ADR-0034](../../docs/decisions/0034-windows-distribution-a-per-user-signed-msi.md)
//! is the decision this implements: a per-user WiX v5 MSI, everything flat in one install
//! directory, every PE Authenticode-signed individually before packaging. In order:
//!
//! 1. **`cargo xtask version`** — the same one-number check `dist` runs.
//! 2. **Build the three helpers** (`kagisecure-mcp`, `kagisecure-nmhost`, `kagisecure`) in release,
//!    for this machine's Windows target.
//! 3. **`cargo xtask bindgen-cs --release`** — `kagisecure_ffi.dll` with the `capi` C ABI.
//! 4. **`dotnet publish` the WinUI app**, self-contained, into the same flat layout directory the
//!    helpers land in. Flat is the point: `kagisecure_agent::bundle::find`'s "beside the running
//!    executable" step already finds a helper next to whatever binary is asking, so this layout
//!    needs no change to `crates/` at all — see the ADR for why macOS's `Contents/Helpers` has no
//!    Windows equivalent to build.
//! 5. **Sign every PE this project builds** — `kagisecure_ffi.dll` and all four `.exe`s — with
//!    `signtool`, if a certificate is configured; otherwise an **unsigned** build, announced
//!    loudly, never silently. `KAGISECURE_SIGN_CERT_SHA1` or `KAGISECURE_SIGN_CERT_SUBJECT` picks
//!    the certificate generically, matching ADR-0025's macOS pattern — nothing about a specific
//!    organisation's certificate is written down here.
//! 6. **`wix build`** the MSI around the signed (or unsigned) layout directory, then sign the MSI
//!    itself.
//! 7. **Verify** every signature with `signtool verify /pa`, when anything was signed, and print
//!    the MSI's SHA-256.
//!
//! Everything lands in `dist/windows/`, under the same gitignored `dist/` the macOS pipeline uses.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::bindgen_cs::{bindgen_cs, windows_target};
use crate::helpers::{PACKAGES, Profile};
use crate::util::{capture_all, cargo, release_rustflags, run};
use crate::version;

/// The app's display name — matches `APP_NAME` in `dist.rs` and the MSI's `Name`/`ProductName`.
const APP_NAME: &str = "Kagisecure";

/// The helper binaries a release carries, in their Windows (`.exe`-suffixed) form. Must match
/// `kagisecure_agent::bundle`'s `SIDECAR`/`NMHOST`/`CLI` constants.
const HELPER_EXES: [&str; 3] = [
    "kagisecure-mcp.exe",
    "kagisecure-nmhost.exe",
    "kagisecure.exe",
];

/// The native library `kagisecure_ffi`'s `capi` feature builds — what the app's P/Invoke layer
/// loads, and what `verify_peer_code_signature` (ADR-0032) reads its own signature from.
const FFI_DLL: &str = "kagisecure_ffi.dll";

/// The WinUI app's own executable, once published.
const APP_EXE: &str = "Kagisecure.App.exe";

/// Every PE this project builds and therefore signs itself. Deliberately not the whole publish
/// output: the .NET runtime and Windows App SDK files in there are Microsoft's own binaries,
/// already signed by Microsoft, and re-signing them is not this pipeline's business.
fn our_pes() -> [&'static str; 5] {
    [
        FFI_DLL,
        "kagisecure-mcp.exe",
        "kagisecure-nmhost.exe",
        "kagisecure.exe",
        APP_EXE,
    ]
}

/// The environment variable naming a certificate by SHA-1 thumbprint. Checked before
/// [`SIGN_SUBJECT_ENV`]; a thumbprint names exactly one certificate, a subject can match more than
/// one if the store holds an expired or renewed one alongside the current one.
const SIGN_THUMBPRINT_ENV: &str = "KAGISECURE_SIGN_CERT_SHA1";

/// The environment variable naming a certificate by subject substring — `signtool sign /n`.
const SIGN_SUBJECT_ENV: &str = "KAGISECURE_SIGN_CERT_SUBJECT";

/// Overrides the RFC 3161 timestamp authority `signtool` calls. A timestamp is required — an
/// Authenticode signature with no secure timestamp expires with the certificate, exactly like the
/// macOS `--timestamp` flag `dist.rs` always passes — but which authority to call is not a
/// decision this repository makes for a fork signing with its own certificate, which may be
/// countersigned by a CA whose own timestamp service is preferred.
const TIMESTAMP_ENV: &str = "KAGISECURE_TIMESTAMP_URL";
const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

/// Run the pipeline.
pub fn dist_windows(root: &Path) -> Result<()> {
    if !cfg!(windows) {
        bail!("cargo xtask dist-windows builds and signs Windows binaries; run it on Windows");
    }

    let ver = version::check(root)?;
    println!("dist-windows: {APP_NAME} {ver}");

    let dist_dir = root.join("dist").join("windows");
    if dist_dir.exists() {
        std::fs::remove_dir_all(&dist_dir).context("clearing dist/windows/")?;
    }
    std::fs::create_dir_all(&dist_dir)?;
    let layout = dist_dir.join("layout");
    std::fs::create_dir_all(&layout)?;

    build_helpers(root)?;
    let dll = bindgen_cs(root, Profile::Release).context("building kagisecure_ffi.dll")?;

    publish_app(root, &layout, &ver)?;
    stage_helpers(root, &layout)?;
    std::fs::copy(&dll, layout.join(FFI_DLL))
        .with_context(|| format!("staging {FFI_DLL} into the layout"))?;

    for pe in our_pes() {
        let path = layout.join(pe);
        if !path.is_file() {
            bail!(
                "{pe} did not land in the layout directory at {}",
                path.display()
            );
        }
    }
    println!("dist-windows: layout -> {}", layout.display());

    let signing = Signing::from_env()?;
    match &signing {
        Signing::Configured { .. } => {
            for pe in our_pes() {
                signing.sign(&layout.join(pe))?;
            }
            println!("dist-windows: every PE this project builds is signed");
        }
        Signing::Unsigned => {
            println!(
                "\n\
                 ================================================================\n\
                 dist-windows: UNSIGNED BUILD. Neither {SIGN_THUMBPRINT_ENV} nor\n\
                 {SIGN_SUBJECT_ENV} names a certificate, so kagisecure_ffi.dll and\n\
                 every helper .exe are unsigned. ADR-0032's verify_peer will report\n\
                 this build's own helpers as unverified (\"this build of Kagisecure\n\
                 is unsigned\"), exactly as an ad-hoc macOS build does. Fine for\n\
                 local testing; not for distribution.\n\
                 ================================================================\n"
            );
        }
    }

    let msi = build_msi(root, &dist_dir, &layout, &ver)?;
    if let Signing::Configured { .. } = &signing {
        signing.sign(&msi)?;
    }

    report(&signing, &msi)?;
    Ok(())
}

/// Build the three helpers, release, for this machine's Windows target.
fn build_helpers(root: &Path) -> Result<()> {
    let target = windows_target();
    let mut command = Command::new(cargo());
    command
        .current_dir(root)
        .arg("build")
        .arg("--release")
        .env("RUSTFLAGS", release_rustflags(root));
    for package in PACKAGES {
        command.args(["-p", package]);
    }
    command.args(["--target", target]);
    run(&mut command).context("building kagisecure-mcp, kagisecure-nmhost and the kagisecure CLI")
}

/// Copy the three built helpers into the layout directory.
fn stage_helpers(root: &Path, layout: &Path) -> Result<()> {
    let target = windows_target();
    for exe in HELPER_EXES {
        let source = root.join("target").join(target).join("release").join(exe);
        if !source.is_file() {
            bail!("cargo did not produce {}", source.display());
        }
        std::fs::copy(&source, layout.join(exe))
            .with_context(|| format!("staging {exe} into the layout"))?;
    }
    Ok(())
}

/// `dotnet publish` the WinUI app, self-contained, straight into the layout directory.
///
/// Self-contained (`WindowsAppSDKSelfContained=true`, `--self-contained true`) rather than the
/// framework-dependent build the checked-in `Kagisecure.App.csproj` defaults to for the
/// `dotnet run` inner loop: a release that needs "install the Windows App Runtime first" as an
/// extra step is a worse first impression than the larger download (ADR-0034). These are
/// command-line MSBuild properties, not a change to the checked-in project file, so the inner
/// loop other sessions are editing `apps/windows/Kagisecure.App/**` against is untouched.
fn publish_app(root: &Path, layout: &Path, ver: &str) -> Result<()> {
    let csproj = root.join("apps/windows/Kagisecure.App/Kagisecure.App.csproj");
    if !csproj.is_file() {
        bail!("no project at {}", csproj.display());
    }
    let file_version = format!("{ver}.0");
    let mut command = Command::new("dotnet");
    command
        // From apps/windows, not the repository root: the SDK is chosen by the global.json found
        // walking up from the working directory, and the one that pins .NET 8 lives there. From
        // the root, the newest SDK installed would build the release instead of the one every
        // test ran against.
        .current_dir(root.join("apps/windows"))
        .arg("publish")
        .arg(&csproj)
        .args(["-c", "Release"])
        .args(["-r", "win-x64"])
        .args(["--self-contained", "true"])
        .arg("-p:Platform=x64")
        .arg("-p:WindowsAppSDKSelfContained=true")
        .arg("-p:PublishSingleFile=false")
        .arg("-p:WindowsPackageType=None")
        .arg(format!("-p:Version={ver}"))
        .arg(format!("-p:AssemblyVersion={file_version}"))
        .arg(format!("-p:FileVersion={file_version}"))
        .args(["-o"])
        .arg(layout);
    run(&mut command).context("dotnet publish apps/windows/Kagisecure.App")?;

    // `dotnet publish` for this unpackaged (`WindowsPackageType=None`) WinUI app copies every
    // *framework* `.pri` file (`Microsoft.UI.pri`, `Microsoft.WindowsAppRuntime.pri`, …) into the
    // publish output, but drops the app's *own* compiled resource index —
    // `Kagisecure.App.pri` — which `dotnet build` produces into `bin/...` without trouble. Its
    // absence is not cosmetic: measured on this machine, a layout published without it installs
    // and launches into a hard crash before a single window paints — Application Error (Event ID
    // 1000) names `Microsoft.UI.Xaml.dll`, exception code `0xc000027b`, the instant
    // `Kagisecure.App.exe` starts. Copying it in by hand after publish, found by name rather than
    // by a hardcoded `bin/x64/Release/<tfm>/<rid>/` path so a `TargetFramework` bump does not
    // silently break this again, fixes it — confirmed by installing and launching both without
    // and with this file present. This is `dotnet publish`'s file list not including a file
    // `dotnet build` already produced; nothing in `apps/windows/**` needed to change for it.
    let pri_name = format!(
        "{}.pri",
        csproj
            .file_stem()
            .and_then(|s| s.to_str())
            .context("the app's .csproj has no file stem")?
    );
    let build_dir = csproj
        .parent()
        .context("the app's .csproj has no parent directory")?
        .join("bin");
    let pri_source = find_file_named(&build_dir, &pri_name).with_context(|| {
        format!(
            "{pri_name} was not found anywhere under {} after `dotnet publish` — this is the \
             app's own compiled XAML resource index; without it next to the exe, the published \
             app fast-fails at startup (see the comment above this)",
            build_dir.display()
        )
    })?;
    std::fs::copy(&pri_source, layout.join(&pri_name))
        .with_context(|| format!("copying {pri_name} into the layout"))?;
    println!(
        "dist-windows: {pri_name} -> {}",
        layout.join(&pri_name).display()
    );

    if !layout.join(APP_EXE).is_file() {
        bail!(
            "dotnet publish did not produce {} in {}",
            APP_EXE,
            layout.display()
        );
    }
    println!("dist-windows: app -> {}", layout.join(APP_EXE).display());
    Ok(())
}

/// Find a file named `name` anywhere under `dir`, depth-first. `dir` is a `bin/` tree whose exact
/// shape (`<platform>/<config>/<tfm>/<rid>/…`) depends on properties this task does not want to
/// duplicate and keep in sync with the `.csproj`.
fn find_file_named(dir: &Path, name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path.file_name().is_some_and(|f| f == name) {
            return Some(path);
        }
    }
    subdirs
        .into_iter()
        .find_map(|subdir| find_file_named(&subdir, name))
}

/// Where a certificate was found, or the honest statement that none was.
enum Signing {
    Configured {
        signtool: PathBuf,
        selector: Vec<String>,
        timestamp_url: String,
    },
    Unsigned,
}

impl Signing {
    /// Read the environment; locate `signtool` only if a certificate was actually named — an
    /// unsigned build needs it not at all, and should not fail because it is missing.
    fn from_env() -> Result<Self> {
        let selector = if let Ok(thumb) = std::env::var(SIGN_THUMBPRINT_ENV)
            && !thumb.is_empty()
        {
            Some(vec!["/sha1".to_owned(), thumb])
        } else if let Ok(subject) = std::env::var(SIGN_SUBJECT_ENV)
            && !subject.is_empty()
        {
            Some(vec!["/n".to_owned(), subject])
        } else {
            None
        };
        let Some(selector) = selector else {
            return Ok(Self::Unsigned);
        };
        let timestamp_url =
            std::env::var(TIMESTAMP_ENV).unwrap_or_else(|_| DEFAULT_TIMESTAMP_URL.to_owned());
        let signtool = find_signtool()?;
        Ok(Self::Configured {
            signtool,
            selector,
            timestamp_url,
        })
    }

    /// `signtool sign /fd sha256 /tr <url> /td sha256 <selector> <file>`.
    fn sign(&self, file: &Path) -> Result<()> {
        let Self::Configured {
            signtool,
            selector,
            timestamp_url,
        } = self
        else {
            return Ok(());
        };
        let mut command = Command::new(signtool);
        command
            .arg("sign")
            .args(["/fd", "sha256"])
            .args(["/tr", timestamp_url])
            .args(["/td", "sha256"])
            .args(selector)
            .arg(file);
        run(&mut command).with_context(|| format!("signing {}", file.display()))?;
        println!("dist-windows: signed {}", file.display());
        Ok(())
    }

    /// `signtool verify /pa`.
    fn verify(&self, file: &Path) -> Result<()> {
        let Self::Configured { signtool, .. } = self else {
            return Ok(());
        };
        let (ok, text) = capture_all(Command::new(signtool).args(["verify", "/pa"]).arg(file))?;
        if !ok {
            bail!("signtool verify /pa failed for {}:\n{text}", file.display());
        }
        println!("dist-windows: verified {}", file.display());
        Ok(())
    }
}

/// Find `signtool.exe`. Never downloaded or installed here — it ships with the Windows SDK, which
/// this task expects to already be on the machine when a certificate is configured, and says
/// exactly what to do when it is not.
fn find_signtool() -> Result<PathBuf> {
    // 1. PATH, in case a shell already has the SDK's tools directory on it.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("signtool.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    // 2. The Windows SDK's own layout: `…\Windows Kits\10\bin\<version>\<arch>\signtool.exe`,
    // highest SDK version first, this host's architecture first (falling back to x86, which every
    // SDK install carries and which runs fine under WOW64 on either 64-bit architecture).
    let arches: &[&str] = if cfg!(target_arch = "aarch64") {
        &["arm64", "x64", "x86"]
    } else {
        &["x64", "x86"]
    };
    for program_files in ["ProgramFiles(x86)", "ProgramFiles"] {
        let Some(base) = std::env::var_os(program_files) else {
            continue;
        };
        let bin = PathBuf::from(base)
            .join("Windows Kits")
            .join("10")
            .join("bin");
        if !bin.is_dir() {
            continue;
        }
        let mut versions: Vec<PathBuf> = std::fs::read_dir(&bin)
            .with_context(|| format!("reading {}", bin.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        // Lexicographic descending sorts `10.0.26100.0` above `10.0.19041.0`; every SDK version
        // string here has the same number of dot-separated numeric components, so this agrees
        // with numeric ordering.
        versions.sort();
        versions.reverse();
        for version_dir in versions {
            for arch in arches {
                let candidate = version_dir.join(arch).join("signtool.exe");
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    bail!(
        "signtool.exe was not found on PATH or under any \"Windows Kits\\10\\bin\" SDK \
         directory. {SIGN_THUMBPRINT_ENV} or {SIGN_SUBJECT_ENV} names a certificate, so signing \
         was requested but the tool to do it is missing. Install the \"Windows SDK Signing \
         Tools for Desktop Apps\" component — via the Visual Studio Installer's Individual \
         Components tab, or the standalone Windows SDK installer at \
         https://developer.microsoft.com/windows/downloads/windows-sdk/ — then re-run. This is \
         not installed automatically."
    )
}

/// The WiX UI and Util extensions `Product.wxs`'s installer wizard needs — the welcome/license/
/// install-folder/progress/finish dialog set (`WixUI_InstallDir`) comes from the first, and the
/// "Launch Kagisecure" finish-page checkbox's `WixShellExec` custom action comes from the second.
/// Pinned to the same `5.0.1` release as the `wix` tool itself
/// (`packaging/windows/.config/dotnet-tools.json`): an unpinned `wix extension add` resolves the
/// newest version on nuget.org, and the newest at the time this was written (7.0.0) targets WiX
/// v6 and fails to load under this v5 tool (`WIX6101: Could not find expected package root folder
/// wixext5`) — pinning is not paranoia here, it is the difference between working and not.
const WIX_EXTENSIONS: [&str; 2] = ["WixToolset.UI.wixext/5.0.1", "WixToolset.Util.wixext/5.0.1"];

/// Locate (restoring if needed) and run the `wix` dotnet local tool, then build the MSI.
///
/// `wix` is a `dotnet tool`, restored from the manifest checked in at
/// `packaging/windows/.config/dotnet-tools.json` — a NuGet package restore, not new system-wide
/// software, which is the one kind of tool-fetching this pipeline does on its own. `signtool`,
/// above, is the opposite case: it is real system software, and this pipeline only ever names the
/// command that installs it.
///
/// The WiX UI/Util extensions (`WIX_EXTENSIONS`) are restored the same reproducible way: `wix
/// extension add`, run from `packaging_dir` **without** `-g`, caches them under
/// `packaging/windows/.wix/extensions/` — a project-local, gitignored NuGet cache next to
/// `.config/dotnet-tools.json`, not a machine-wide install (`-g` would cache them once per user
/// account instead, which is what this deliberately avoids).
fn build_msi(root: &Path, dist_dir: &Path, layout: &Path, ver: &str) -> Result<PathBuf> {
    let packaging_dir = root.join("packaging/windows");
    let wxs = packaging_dir.join("Product.wxs");
    if !wxs.is_file() {
        bail!("no {}", wxs.display());
    }

    let restore_status = Command::new("dotnet")
        .current_dir(&packaging_dir)
        .args(["tool", "restore"])
        .status()
        .context("could not start `dotnet tool restore`")?;
    if !restore_status.success() {
        bail!(
            "`dotnet tool restore` failed in {}. If this is a missing-`dotnet` problem rather \
             than a restore problem, install the .NET SDK first: \
             https://dotnet.microsoft.com/download",
            packaging_dir.display()
        );
    }

    for ext in WIX_EXTENSIONS {
        let mut command = Command::new("dotnet");
        command.current_dir(&packaging_dir).args([
            "tool",
            "run",
            "wix",
            "--",
            "extension",
            "add",
            ext,
        ]);
        run(&mut command).with_context(|| format!("wix extension add {ext}"))?;
    }

    // The license dialog's text: concatenates LICENSE-MIT and LICENSE-APACHE, regenerated on
    // every run so it can never go stale relative to the two files that are the actual license
    // (see license_rtf.rs's doc comment for why this is not checked in).
    crate::license_rtf::write(root, &packaging_dir.join("License.rtf"))?;

    let msi = dist_dir.join(format!("{APP_NAME}.msi"));
    if msi.exists() {
        std::fs::remove_file(&msi)?;
    }
    let mut command = Command::new("dotnet");
    command
        .current_dir(&packaging_dir)
        .args(["tool", "run", "wix", "--"])
        .arg("build")
        .arg("Product.wxs")
        .args(["-arch", "x64"]);
    for ext in WIX_EXTENSIONS {
        command.arg("-ext").arg(ext);
    }
    command
        .arg("-d")
        .arg(format!("Version={ver}"))
        .arg("-d")
        .arg(format!("LayoutDir={}", layout.display()))
        .args(["-o"])
        .arg(&msi);
    run(&mut command).context("wix build")?;

    if !msi.is_file() {
        bail!("wix build did not produce {}", msi.display());
    }
    println!("dist-windows: msi -> {}", msi.display());
    Ok(msi)
}

/// Verify (if signed) and print the checksum.
fn report(signing: &Signing, msi: &Path) -> Result<()> {
    println!("\n--- verification ---");
    if let Signing::Configured { .. } = signing {
        signing.verify(msi)?;
    } else {
        println!("dist-windows: nothing signed, nothing to verify");
    }

    let checksum = crate::util::sha256_file(msi)?;
    println!("\nSHA-256: {checksum}");

    if matches!(signing, Signing::Unsigned) {
        println!(
            "\nNOTE: this MSI is unsigned. Windows SmartScreen and Authenticode peer \
             verification (ADR-0032) will treat it, and everything inside it, as an untrusted, \
             unverified build. Set {SIGN_THUMBPRINT_ENV} or {SIGN_SUBJECT_ENV} and re-run to \
             ship a signed release."
        );
    }
    Ok(())
}
