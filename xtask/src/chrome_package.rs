//! `cargo xtask chrome-package` — the zip a Chrome Web Store upload takes.
//!
//! `extensions/shared` *is* the extension: Chromium loads it unpacked, the Safari target copies
//! it, `cargo xtask embed` puts it in the app bundle. The store wants the same files in a zip, with
//! two differences in the manifest, and this task makes exactly those:
//!
//! 1. **`key` is removed.** The committed public key pins the unpacked id (ADR-0021), and the store
//!    refuses a *new* item whose manifest carries one — it assigns the item an id of its own at the
//!    first upload. See ADR-0021's amendment of 2026-10-03 and `docs/chrome-web-store.md` for what
//!    happens to the allow-list afterwards.
//! 2. **`version` is the workspace version**, read from `Cargo.toml`. The committed manifest is
//!    meant to say the same thing already (`cargo xtask version` checks it); writing it here as
//!    well means a package can never carry a stale one.
//!
//! The zip holds only what the extension needs — no dotfiles, no tests — and is deterministic:
//! entries in sorted order, every timestamp 1980-01-01, every mode 0644. The same tree gives the
//! same bytes, so a package can be rebuilt and compared. Before writing anything, every file the
//! manifest names (and every script the service worker and the popup load) is checked to be in
//! the package; a store upload with a missing icon is an upload the store rejects, and a missing
//! script is one it accepts.
//!
//! Output: `dist/kagisecure-chrome-<version>.zip`. Uploading it is a human step in the developer
//! dashboard; nothing here talks to the store.

use std::collections::BTreeSet;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::version;

/// The extension's source directory, relative to the repository root.
pub const EXTENSION_DIR: &str = "extensions/shared";

/// The Chrome Web Store's limit on the manifest `description`, which is also the listing's summary.
const MAX_DESCRIPTION_CHARS: usize = 132;

/// The longest `name` Chrome accepts.
const MAX_NAME_CHARS: usize = 75;

/// File types the extension is made of. Anything else in [`EXTENSION_DIR`] is refused rather than
/// silently shipped or silently dropped: either way, someone should decide.
const SHIPPED_EXTENSIONS: &[&str] = &["js", "html", "css", "json", "png"];

/// Build the store package and return its path.
pub fn chrome_package(root: &Path) -> Result<PathBuf> {
    let version = version::workspace_version(root)?;
    // The committed manifests must agree with the workspace before anything is packaged: the
    // package would carry the right number regardless, but an unpacked load of the same tree would
    // not, and the two should never tell different stories.
    version::check_extension_manifests(root, &version)?;

    let source = root.join(EXTENSION_DIR);
    let manifest_path = source.join("manifest.json");
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = store_manifest(&manifest_text, &version)?;

    let files = extension_files(&source)?;
    check_references(&manifest, &source, &files)?;

    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(files.len());
    for relative in &files {
        let bytes = if relative == "manifest.json" {
            let mut text = serde_json::to_string_pretty(&manifest)?;
            text.push('\n');
            text.into_bytes()
        } else {
            let path = source.join(relative);
            std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?
        };
        entries.push((relative.clone(), bytes));
    }

    let dist = root.join("dist");
    std::fs::create_dir_all(&dist).with_context(|| format!("creating {}", dist.display()))?;
    let target = dist.join(format!("kagisecure-chrome-{version}.zip"));
    // Written beside the target and renamed into place, so an interrupted run never leaves a
    // truncated zip under the name a person is about to upload.
    let partial = dist.join(format!(".kagisecure-chrome-{version}.zip.partial"));
    {
        let file = std::fs::File::create(&partial)
            .with_context(|| format!("creating {}", partial.display()))?;
        write_zip(file, &entries)?;
    }
    std::fs::rename(&partial, &target)
        .with_context(|| format!("moving the package to {}", target.display()))?;

    println!(
        "chrome-package: {} ({} files)",
        target.display(),
        entries.len()
    );
    for (name, bytes) in &entries {
        println!("  {:>8}  {name}", bytes.len());
    }
    println!(
        "chrome-package: `key` removed, version {version}. Upload it in the developer dashboard; \
         docs/chrome-web-store.md has the steps."
    );
    Ok(target)
}

/// The manifest the store gets: the committed one without `key`, with `version` set.
///
/// Also checks the few things the store rejects at upload that can be checked here, so the
/// failure is a sentence in a terminal rather than a red banner in a dashboard.
pub fn store_manifest(committed: &str, version: &str) -> Result<Value> {
    let mut manifest: Value =
        serde_json::from_str(committed).context("manifest.json is not valid JSON")?;
    let object = manifest
        .as_object_mut()
        .context("manifest.json is not a JSON object")?;

    object.remove("key");
    if !is_chrome_version(version) {
        bail!(
            "{version:?} is not a version Chrome accepts: one to four dot-separated integers, \
             each 0-65535, no leading zeros"
        );
    }
    object.insert("version".to_owned(), Value::String(version.to_owned()));

    if object.get("manifest_version").and_then(Value::as_u64) != Some(3) {
        bail!("manifest.json must be manifest_version 3");
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .context("manifest.json has no name")?;
    if name.chars().count() > MAX_NAME_CHARS {
        bail!("the manifest name is longer than {MAX_NAME_CHARS} characters");
    }
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .context("manifest.json has no description; the store shows it as the summary")?;
    let length = description.chars().count();
    if length > MAX_DESCRIPTION_CHARS {
        bail!(
            "the manifest description is {length} characters; the store allows \
             {MAX_DESCRIPTION_CHARS}"
        );
    }
    Ok(manifest)
}

/// Whether `version` is a Chrome extension version: 1–4 dot-separated integers, each 0–65535,
/// with no leading zeros.
fn is_chrome_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    (1..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u32>().is_ok_and(|n| n <= 65_535)
        })
}

/// Every file the extension ships, relative to `source`, with `/` separators, sorted.
///
/// Walks subdirectories (`icons/`). Skips anything whose name starts with a dot — `.DS_Store`, an
/// editor's swap file, a stray `.git` — and anything named like a test. Refuses a file of any type
/// not in [`SHIPPED_EXTENSIONS`], so a new kind of file is a decision rather than an accident.
/// Shared with `cargo xtask embed`, so the app bundle's copy and the store's are the same set.
pub fn extension_files(source: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    walk(source, source, &mut found)?;
    found.sort();
    if !found.iter().any(|f| f == "manifest.json") {
        bail!("no manifest.json in {}", source.display());
    }
    Ok(found)
}

fn walk(base: &Path, dir: &Path, found: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
        if name.starts_with('.') {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            // Chromium silently refuses a symlinked content script (docs/browser-extension.md §9),
            // so a symlink here is a bug in the tree, not something to follow.
            bail!(
                "{} is a symlink; the extension must be plain files",
                path.display()
            );
        }
        if kind.is_dir() {
            walk(base, &path, found)?;
            continue;
        }
        if name.contains(".test.") || name.contains(".spec.") {
            continue;
        }
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !SHIPPED_EXTENSIONS.contains(&extension) {
            bail!(
                "{} is not a file type the extension ships ({}). Move it out of {EXTENSION_DIR}, \
                 or add its type to SHIPPED_EXTENSIONS in xtask/src/chrome_package.rs.",
                path.display(),
                SHIPPED_EXTENSIONS.join(", ")
            );
        }
        let relative = path
            .strip_prefix(base)
            .context("walked outside the extension directory")?;
        let parts: Vec<&str> = relative
            .components()
            .map(|c| c.as_os_str().to_str().unwrap_or_default())
            .collect();
        found.push(parts.join("/"));
    }
    Ok(())
}

/// Check that every file `manifest` refers to is among `files`, following the two places this
/// extension loads further scripts: `importScripts(…)` in the service worker, and `<script src>`
/// (and `<link href>`) in an HTML page.
pub fn check_references(manifest: &Value, source: &Path, files: &[String]) -> Result<()> {
    let shipped: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    let mut missing = Vec::new();
    for reference in manifest_references(manifest) {
        let normalized = reference.trim_start_matches('/');
        if !shipped.contains(normalized) {
            missing.push(format!("{reference} (named in manifest.json)"));
            continue;
        }
        let loaded = if normalized.ends_with(".html") {
            html_references(&read_text(source, normalized)?)
        } else if manifest
            .pointer("/background/service_worker")
            .and_then(Value::as_str)
            == Some(reference.as_str())
        {
            imported_scripts(&read_text(source, normalized)?)
        } else {
            Vec::new()
        };
        for inner in loaded {
            if !shipped.contains(inner.trim_start_matches('/')) {
                missing.push(format!("{inner} (loaded by {normalized})"));
            }
        }
    }
    if !missing.is_empty() {
        bail!(
            "the package would be missing files the extension loads:\n  {}",
            missing.join("\n  ")
        );
    }
    Ok(())
}

fn read_text(source: &Path, relative: &str) -> Result<String> {
    let path = source.join(relative);
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

/// Every path the manifest names: the service worker, content scripts and styles, the popup,
/// the options page, and every icon.
fn manifest_references(manifest: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |value: Option<&Value>| {
        if let Some(path) = value.and_then(Value::as_str) {
            out.push(path.to_owned());
        }
    };
    push(manifest.pointer("/background/service_worker"));
    push(manifest.pointer("/action/default_popup"));
    push(manifest.pointer("/options_page"));
    push(manifest.pointer("/options_ui/page"));
    if let Some(scripts) = manifest.get("content_scripts").and_then(Value::as_array) {
        for script in scripts {
            for key in ["js", "css"] {
                for path in script
                    .get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    push(Some(path));
                }
            }
        }
    }
    for icons in [
        manifest.get("icons"),
        manifest.pointer("/action/default_icon"),
    ]
    .into_iter()
    .flatten()
    {
        match icons {
            Value::String(_) => push(Some(icons)),
            Value::Object(map) => {
                for path in map.values() {
                    push(Some(path));
                }
            }
            _ => {}
        }
    }
    out
}

/// The string literals inside every `importScripts(…)` call. A plain scan, not a JavaScript
/// parser: the call is written once, at the top of `background.js`, with literal arguments.
fn imported_scripts(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("importScripts(") {
        let after = &rest[start + "importScripts(".len()..];
        let Some(end) = after.find(')') else { break };
        out.extend(quoted_strings(&after[..end]));
        rest = &after[end..];
    }
    out
}

/// The relative `src` and `href` attribute values in an HTML page.
fn html_references(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for attribute in ["src=\"", "href=\""] {
        let mut rest = source;
        while let Some(start) = rest.find(attribute) {
            let after = &rest[start + attribute.len()..];
            let Some(end) = after.find('"') else { break };
            let value = &after[..end];
            if !value.is_empty() && !value.contains(':') && !value.starts_with('#') {
                out.push(value.to_owned());
            }
            rest = &after[end..];
        }
    }
    out
}

fn quoted_strings(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find(['"', '\'']) {
        // Both quote characters are ASCII, so the byte is the character.
        let quote = char::from(rest.as_bytes()[start]);
        let body = &rest[start + 1..];
        let Some(end) = body.find(quote) else { break };
        out.push(body[..end].to_owned());
        rest = &body[end + 1..];
    }
    out
}

/// Write `entries` as a zip: in the order given (the caller sorts), deflated, with a fixed
/// timestamp and mode so the bytes depend on nothing but the contents.
pub fn write_zip<W: Write + Seek>(writer: W, entries: &[(String, Vec<u8>)]) -> Result<W> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::DEFAULT)
        .unix_permissions(0o644);
    let mut zip = ZipWriter::new(writer);
    for (name, bytes) in entries {
        zip.start_file(name.as_str(), options)
            .with_context(|| format!("adding {name} to the zip"))?;
        zip.write_all(bytes)?;
    }
    zip.finish().context("finishing the zip")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    const COMMITTED: &str = r#"{
      "manifest_version": 3,
      "name": "Kagisecure",
      "version": "0.1.0",
      "description": "Fill saved logins.",
      "key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
      "permissions": ["nativeMessaging", "activeTab"],
      "background": { "service_worker": "background.js" },
      "content_scripts": [{ "matches": ["https://*/*"], "js": ["origin.js", "content.js"] }],
      "icons": { "16": "icons/icon-16.png", "128": "icons/icon-128.png" },
      "action": { "default_popup": "popup.html", "default_icon": { "16": "icons/icon-16.png" } }
    }"#;

    #[test]
    fn the_store_manifest_has_no_key_and_the_workspace_version() {
        let manifest = store_manifest(COMMITTED, "0.1.1").unwrap();
        assert!(manifest.get("key").is_none(), "{manifest}");
        assert_eq!(manifest["version"], "0.1.1");
    }

    #[test]
    fn the_store_manifest_changes_nothing_else() {
        let committed: Value = serde_json::from_str(COMMITTED).unwrap();
        let mut expected = committed.as_object().unwrap().clone();
        expected.remove("key");
        expected.insert("version".to_owned(), Value::String("2.0".to_owned()));
        let manifest = store_manifest(COMMITTED, "2.0").unwrap();
        assert_eq!(manifest, Value::Object(expected));
    }

    #[test]
    fn a_manifest_with_no_key_is_fine_too() {
        let without: Value = {
            let mut v: Value = serde_json::from_str(COMMITTED).unwrap();
            v.as_object_mut().unwrap().remove("key");
            v
        };
        let manifest = store_manifest(&without.to_string(), "0.1.1").unwrap();
        assert!(manifest.get("key").is_none());
    }

    #[test]
    fn versions_chrome_rejects_are_refused() {
        for bad in ["", "1.", "1.2.3.4.5", "01.2", "1.70000", "1.2-beta", "v1"] {
            assert!(
                store_manifest(COMMITTED, bad).is_err(),
                "{bad:?} was accepted"
            );
        }
        for good in ["0", "0.1.1", "1.2.3.4", "65535.0"] {
            assert!(
                store_manifest(COMMITTED, good).is_ok(),
                "{good:?} was refused"
            );
        }
    }

    #[test]
    fn a_description_over_the_store_limit_is_refused() {
        let long = COMMITTED.replace("Fill saved logins.", &"x".repeat(MAX_DESCRIPTION_CHARS + 1));
        assert!(store_manifest(&long, "0.1.1").is_err());
        let exact = COMMITTED.replace("Fill saved logins.", &"x".repeat(MAX_DESCRIPTION_CHARS));
        assert!(store_manifest(&exact, "0.1.1").is_ok());
    }

    #[test]
    fn not_manifest_v3_is_refused() {
        let v2 = COMMITTED.replace("\"manifest_version\": 3", "\"manifest_version\": 2");
        assert!(store_manifest(&v2, "0.1.1").is_err());
    }

    #[test]
    fn every_reference_is_collected() {
        let manifest: Value = serde_json::from_str(COMMITTED).unwrap();
        let mut found = manifest_references(&manifest);
        found.sort();
        assert_eq!(
            found,
            [
                "background.js",
                "content.js",
                "icons/icon-128.png",
                "icons/icon-16.png",
                "icons/icon-16.png",
                "origin.js",
                "popup.html",
            ]
        );
    }

    #[test]
    fn imported_scripts_and_html_references_are_found() {
        assert_eq!(
            imported_scripts(
                "\"use strict\";\nimportScripts(\"origin.js\", 'tabmemory.js', \"native.js\");\n"
            ),
            ["origin.js", "tabmemory.js", "native.js"]
        );
        assert_eq!(
            html_references(
                "<link href=\"popup.css\" rel=stylesheet><a href=\"https://kagisecure.com\">x</a>\
                 <script src=\"popup.js\"></script>"
            ),
            ["popup.js", "popup.css"]
        );
    }

    /// A scratch copy of an extension tree. Removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str, files: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "xtask-chrome-package-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            for (path, body) in files {
                let path = dir.join(path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, body).unwrap();
            }
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tree() -> Vec<(&'static str, &'static str)> {
        vec![
            ("manifest.json", COMMITTED),
            ("background.js", "importScripts(\"origin.js\");"),
            ("origin.js", ""),
            ("content.js", ""),
            ("popup.html", "<script src=\"popup.js\"></script>"),
            ("popup.js", ""),
            ("icons/icon-16.png", "png"),
            ("icons/icon-128.png", "png"),
        ]
    }

    #[test]
    fn the_file_set_skips_dotfiles_and_tests_and_walks_icons() {
        let mut files = tree();
        files.push((".DS_Store", "junk"));
        files.push(("icons/.DS_Store", "junk"));
        files.push(("forms.test.js", "test"));
        let scratch = Scratch::new("set", &files);
        assert_eq!(
            extension_files(&scratch.0).unwrap(),
            [
                "background.js",
                "content.js",
                "icons/icon-128.png",
                "icons/icon-16.png",
                "manifest.json",
                "origin.js",
                "popup.html",
                "popup.js",
            ]
        );
    }

    #[test]
    fn an_unexpected_file_type_is_refused() {
        let mut files = tree();
        files.push(("notes.md", "# hi"));
        let scratch = Scratch::new("unexpected", &files);
        assert!(extension_files(&scratch.0).is_err());
    }

    #[test]
    fn a_complete_tree_passes_the_reference_check() {
        let scratch = Scratch::new("complete", &tree());
        let files = extension_files(&scratch.0).unwrap();
        let manifest = store_manifest(COMMITTED, "0.1.1").unwrap();
        check_references(&manifest, &scratch.0, &files).unwrap();
    }

    #[test]
    fn a_missing_icon_or_script_fails_the_reference_check() {
        for absent in ["icons/icon-128.png", "origin.js", "popup.js", "content.js"] {
            let files: Vec<_> = tree().into_iter().filter(|(p, _)| *p != absent).collect();
            let scratch = Scratch::new(&format!("missing-{}", absent.replace('/', "-")), &files);
            let found = extension_files(&scratch.0).unwrap();
            let manifest = store_manifest(COMMITTED, "0.1.1").unwrap();
            let error = check_references(&manifest, &scratch.0, &found)
                .expect_err(absent)
                .to_string();
            assert!(error.contains(absent), "{error}");
        }
    }

    #[test]
    fn the_zip_is_deterministic_and_holds_what_it_was_given() {
        let entries = vec![
            ("a.js".to_owned(), b"one".to_vec()),
            ("icons/b.png".to_owned(), vec![0, 1, 2, 3]),
        ];
        let first = write_zip(Cursor::new(Vec::new()), &entries)
            .unwrap()
            .into_inner();
        let second = write_zip(Cursor::new(Vec::new()), &entries)
            .unwrap()
            .into_inner();
        assert_eq!(first, second, "the same entries must give the same bytes");

        let mut archive = zip::ZipArchive::new(Cursor::new(first)).unwrap();
        assert_eq!(archive.len(), 2);
        for (index, (name, bytes)) in entries.iter().enumerate() {
            let mut file = archive.by_index(index).unwrap();
            assert_eq!(file.name(), name);
            assert_eq!(file.last_modified(), Some(DateTime::DEFAULT));
            let mut read = Vec::new();
            file.read_to_end(&mut read).unwrap();
            assert_eq!(&read, bytes);
        }
    }

    /// The real tree: what `cargo xtask chrome-package` would ship today passes its own checks.
    #[test]
    fn the_committed_extension_packages() {
        let root = crate::util::repo_root().unwrap();
        let source = root.join(EXTENSION_DIR);
        let committed = std::fs::read_to_string(source.join("manifest.json")).unwrap();
        let version = version::workspace_version(&root).unwrap();
        let manifest = store_manifest(&committed, &version).unwrap();
        let files = extension_files(&source).unwrap();
        check_references(&manifest, &source, &files).unwrap();
        for icon in [
            "icons/icon-16.png",
            "icons/icon-32.png",
            "icons/icon-48.png",
            "icons/icon-128.png",
        ] {
            assert!(files.iter().any(|f| f == icon), "{icon} is not shipped");
        }
    }
}
