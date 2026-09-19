//! `cargo xtask bindgen` — the static library, the Swift bindings and the xcframework.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::helpers::Arches;
use crate::util::{cargo, release_rustflags, run, utf8};

/// Build the static library, generate the Swift bindings, and package the xcframework.
///
/// The generated `.swift` is checked in (architecture.md §6, as amended by
/// [ADR-0009](../../docs/decisions/0009-checked-in-swift-bindings.md)); the `.a`, the headers and
/// the `.xcframework` are not, because they are large binaries that a checkout can rebuild in
/// seconds. Running this twice must produce no diff — asserted locally (this ran in CI until CI
/// was removed on 2026-09-19).
///
/// `arches` decides whether the library is one slice or two. The *bindings* are identical either
/// way — UniFFI reads the metadata out of one slice and the metadata is architecture-independent
/// — so a universal build stays idempotent against the checked-in Swift, which is what let CI
/// keep checking a cheap host-only build (ADR-0027), and lets a local check do the same now.
pub fn bindgen(root: &Path, arches: Arches) -> Result<()> {
    let package = root.join("apps/macos/KagisecureFFI");
    let sources = package.join("Sources/KagisecureFFI");
    let artifacts = package.join("Artifacts");
    let headers = artifacts.join("Headers");
    let framework = artifacts.join("KagisecureFFI.xcframework");

    // 1. The static library the app links. `--release` because a debug build of the crypto is
    //    slow enough to be noticeable in the UI, and because a release build should not ship one.
    let targets = arches.targets();
    for target in &targets {
        run(Command::new(cargo())
            .current_dir(root)
            .env("RUSTFLAGS", release_rustflags(root))
            .args(["build", "--release", "-p", "kagisecure-ffi", "--target"])
            .arg(target))
        .with_context(|| format!("building kagisecure-ffi for {target}"))?;
    }
    let library = fat_library(root, &targets)?;

    // 2. The bindings: the Swift wrapper into the package's `Sources`, the C header and the
    //    modulemap into a staging directory that step 3 folds into the xcframework.
    std::fs::create_dir_all(&sources)?;
    if headers.exists() {
        std::fs::remove_dir_all(&headers)?;
    }
    std::fs::create_dir_all(&headers)?;

    // Read the metadata out of a single slice: UniFFI parses the library's symbols, and a fat
    // archive is a container it has no reason to understand. Which slice does not matter — the
    // interface is the same in both.
    let metadata_source = utf8(&single_slice(root, targets[0]))?;
    uniffi::generate_swift_bindings(uniffi::SwiftBindingsOptions {
        generate_swift_sources: true,
        generate_headers: false,
        generate_modulemap: false,
        source: metadata_source.clone(),
        out_dir: utf8(&sources)?,
        xcframework: true,
        module_name: None,
        modulemap_filename: None,
        metadata_no_deps: false,
        link_frameworks: Vec::new(),
        config: None,
    })
    .map_err(|e| anyhow::anyhow!("{e:?}"))
    .context("generating Swift sources")?;

    uniffi::generate_swift_bindings(uniffi::SwiftBindingsOptions {
        generate_swift_sources: false,
        generate_headers: true,
        generate_modulemap: true,
        source: metadata_source,
        out_dir: utf8(&headers)?,
        // Not `true`, despite this ending up inside an xcframework. `--xcframework` emits
        // `framework module …`, which describes a real `.framework` bundle; what
        // `-create-xcframework -library … -headers …` produces is a *library* xcframework, whose
        // headers directory needs a plain `module …`. With `framework module`, Swift never finds
        // the module, `#if canImport(kagisecure_ffiFFI)` quietly evaluates false, and the wrapper
        // fails to compile with a few hundred "cannot find type 'RustBuffer'" errors. Verified on
        // Xcode 26.2 / Swift 6.2.3; recorded in ADR-0009.
        xcframework: false,
        // The generated Swift does `import kagisecure_ffiFFI`, so the modulemap must declare a
        // module of exactly that name. The default would be `kagisecure_ffi` (the library's
        // basename), which compiles to a wrapper whose `canImport` check silently fails and whose
        // FFI symbols are then undefined.
        module_name: Some("kagisecure_ffiFFI".to_owned()),
        modulemap_filename: Some("module.modulemap".to_owned()),
        metadata_no_deps: false,
        link_frameworks: Vec::new(),
        config: None,
    })
    .map_err(|e| anyhow::anyhow!("{e:?}"))
    .context("generating headers and modulemap")?;

    // 3. The xcframework SwiftPM's `binaryTarget` points at. Rebuilt from scratch every time:
    //    `-create-xcframework` refuses to write over an existing bundle. One `-library` pair even
    //    for a universal build — an xcframework's slices are *platforms*, and both architectures
    //    are the same platform, so a fat archive is one entry rather than two.
    if framework.exists() {
        std::fs::remove_dir_all(&framework)?;
    }
    run(Command::new("xcodebuild")
        .arg("-create-xcframework")
        .arg("-library")
        .arg(&library)
        .arg("-headers")
        .arg(&headers)
        .arg("-output")
        .arg(&framework))
    .context("assembling the xcframework")?;

    println!("bindgen: swift sources -> {}", sources.display());
    println!("bindgen: xcframework   -> {}", framework.display());
    Ok(())
}

/// One target's `libkagisecure_ffi.a`.
fn single_slice(root: &Path, target: &str) -> PathBuf {
    root.join("target")
        .join(target)
        .join("release/libkagisecure_ffi.a")
}

/// The library to put in the xcframework: the one slice, or a `lipo`d archive of all of them.
fn fat_library(root: &Path, targets: &[&str]) -> Result<PathBuf> {
    let slices: Vec<PathBuf> = targets
        .iter()
        .map(|target| single_slice(root, target))
        .collect();
    for slice in &slices {
        if !slice.is_file() {
            bail!("expected a static library at {}", slice.display());
        }
    }
    if let [only] = slices.as_slice() {
        return Ok(only.clone());
    }

    let output_dir = root.join("target/universal-apple-darwin/release");
    std::fs::create_dir_all(&output_dir)?;
    let output = output_dir.join("libkagisecure_ffi.a");
    let mut command = Command::new("lipo");
    command.arg("-create");
    for slice in &slices {
        command.arg(slice);
    }
    command.arg("-output").arg(&output);
    run(&mut command).context("lipo-ing libkagisecure_ffi.a")?;
    println!("bindgen: universal library -> {}", output.display());
    Ok(output)
}
