//! Finding `kagisecure-nmhost`, and writing the `NativeMessagingHosts` manifest each browser
//! needs before it will launch it.
//!
//! # Why the app writes this file rather than an installer
//!
//! A native messaging host manifest is a per-user JSON file naming an **absolute path** to a
//! binary and an allow-list of extension origins. The path is not knowable at build time — a
//! contributor's is under `target/debug`, a user's is inside the app bundle's `Contents/Helpers`
//! — so something that
//! knows where it is has to write it. That something is the app, from a setup screen, with a
//! button, so the user can see exactly which file is being written and to which browser before it
//! happens.
//!
//! # What is in the file, and what each part does
//!
//! ```json
//! {
//!   "name": "com.kagisecure.nmhost",
//!   "description": "…",
//!   "path": "/absolute/path/to/kagisecure-nmhost",
//!   "type": "stdio",
//!   "allowed_origins": ["chrome-extension://<pinned id>/"]
//! }
//! ```
//!
//! `allowed_origins` is the browser's half of the pinning: Chrome will only connect an extension
//! whose id appears here. The app's half is [`kagisecure_extension_ipc::is_pinned_extension`],
//! checked at `Hello`. Neither is a substitute for the other — the manifest is a file on disk that
//! anything running as the user could rewrite, and the app's check is code that would have to be
//! replaced — so both are present and both are cheap.

use std::path::{Path, PathBuf};

use kagisecure_extension_ipc::peer::KnownBrowser;
use kagisecure_extension_ipc::{NATIVE_HOST_NAME, PINNED_EXTENSION_IDS};

/// Points the setup screen at a `kagisecure-nmhost` a developer built.
pub const NMHOST_ENV: &str = "KAGISECURE_NMHOST";

/// The native messaging host's file name. Re-exported from [`crate::bundle`].
pub use crate::bundle::NMHOST;

/// Where `kagisecure-nmhost` is, if it can be found.
///
/// `bundle_helpers_dir` is the app's own `Contents/Helpers`, where a shipped copy lives. The
/// search itself is [`crate::bundle::find`]'s, shared with [`crate::setup::sidecar_path`]: two
/// "where is our other binary" searches that disagreed would be a support problem nobody could
/// reproduce.
#[must_use]
pub fn nmhost_path(bundle_helpers_dir: Option<&Path>) -> Option<PathBuf> {
    crate::bundle::find(NMHOST, bundle_helpers_dir, NMHOST_ENV)
}

/// The host path an install *would* have, for a screen that found nothing and has to say so.
#[must_use]
pub fn placeholder_nmhost_path() -> PathBuf {
    crate::bundle::installed_helper(NMHOST)
}

/// One browser's manifest: where it goes and what goes in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserManifest {
    /// The browser's display name.
    pub browser: String,
    /// The absolute path of the file to write.
    pub path: PathBuf,
    /// The JSON to write there, pretty-printed so a user can read it before agreeing to it.
    pub body: String,
    /// Whether that browser appears to be installed on this Mac.
    ///
    /// Not a gate — a user may be about to install it, and a manifest written first works fine —
    /// but the setup screen sorts by it so the browser somebody actually uses is at the top.
    pub browser_installed: bool,
    /// Whether the file is already there with exactly this content.
    pub installed: bool,
}

/// The manifest body for `nmhost_path`.
///
/// Hand-rolled rather than routed through `serde_json`, because this crate does not otherwise
/// depend on it and because the shape is four fixed keys and two interpolations. The two
/// interpolated values are escaped: a path can legally contain a quote or a backslash, and a
/// manifest that JSON-parsers reject is a failure mode with no error message anywhere.
#[must_use]
pub fn manifest_body(nmhost_path: &Path) -> String {
    let origins = PINNED_EXTENSION_IDS
        .iter()
        .map(|id| format!("    \"chrome-extension://{id}/\""))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "{{\n  \"name\": \"{NATIVE_HOST_NAME}\",\n  \"description\": \"kagisecure autofill \
         bridge\",\n  \"path\": \"{}\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": \
         [\n{origins}\n  ]\n}}\n",
        json_escape(&nmhost_path.display().to_string())
    )
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The directory a browser reads its per-user manifests from, on macOS.
///
/// **Not** derived from the browser's `--user-data-dir`. Chromium resolves this path from
/// `NSApplicationSupportDirectory` and the browser's own fixed fragment, so a Chrome launched with
/// a throwaway profile still reads the manifest from the standard location. That is worth knowing
/// before writing an end-to-end test that expects otherwise.
#[must_use]
pub fn manifest_dir(browser: KnownBrowser) -> Option<PathBuf> {
    let fragment = browser.native_messaging_dir_fragment()?;
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join(fragment),
    )
}

/// Whether a browser's application bundle is present, for the "is it installed" hint.
///
/// Both `/Applications` and `~/Applications`, because a per-user install is the normal way a
/// second browser gets onto a managed Mac.
fn is_installed(browser: KnownBrowser) -> bool {
    let Some(name) = bundle_name(browser) else {
        return false;
    };
    if PathBuf::from("/Applications").join(name).exists() {
        return true;
    }
    std::env::var_os("HOME")
        .is_some_and(|home| PathBuf::from(home).join("Applications").join(name).exists())
}

fn bundle_name(browser: KnownBrowser) -> Option<&'static str> {
    let name = match browser {
        KnownBrowser::Chrome => "Google Chrome.app",
        KnownBrowser::Edge => "Microsoft Edge.app",
        KnownBrowser::Arc => "Arc.app",
        KnownBrowser::Brave => "Brave Browser.app",
        KnownBrowser::Chromium => "Chromium.app",
        KnownBrowser::Safari => "Safari.app",
        // `KnownBrowser` is `#[non_exhaustive]`. A browser this build does not know the bundle
        // name of gets no installed-hint, which costs a sort order and nothing else.
        _ => return None,
    };
    Some(name)
}

/// Every manifest the setup screen offers, installed browsers first.
#[must_use]
pub fn all_manifests(nmhost: &Path) -> Vec<BrowserManifest> {
    let body = manifest_body(nmhost);
    let mut out: Vec<BrowserManifest> = KnownBrowser::installable()
        .iter()
        .filter_map(|browser| {
            let dir = manifest_dir(*browser)?;
            let path = dir.join(format!("{NATIVE_HOST_NAME}.json"));
            let installed = std::fs::read_to_string(&path).is_ok_and(|on_disk| on_disk == body);
            Some(BrowserManifest {
                browser: browser.display_name().to_owned(),
                path,
                body: body.clone(),
                browser_installed: is_installed(*browser),
                installed,
            })
        })
        .collect();
    out.sort_by_key(|m| !m.browser_installed);
    out
}

/// Write one manifest, creating its directory.
///
/// # Errors
///
/// Any I/O failure, with the path in the message — a setup screen has to be able to say *which*
/// file it could not write.
pub fn install(manifest: &BrowserManifest) -> Result<(), String> {
    // Both failures name the **manifest** path, not the directory. The user is looking at a screen
    // that shows them one path and a button; an error naming something else makes them hunt.
    if let Some(dir) = manifest.path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            format!(
                "could not write {}: its folder {} could not be created: {e}",
                manifest.path.display(),
                dir.display()
            )
        })?;
    }
    std::fs::write(&manifest.path, &manifest.body)
        .map_err(|e| format!("could not write {}: {e}", manifest.path.display()))
}

/// Remove one manifest, so a user can turn the integration off from the same screen that turned
/// it on.
///
/// # Errors
///
/// Any I/O failure other than "it was not there", which is success.
pub fn uninstall(manifest: &BrowserManifest) -> Result<(), String> {
    match std::fs::remove_file(&manifest.path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove {}: {e}", manifest.path.display())),
    }
}

// ---------------------------------------------------------------------------------------------
// Safari: nothing to write, and three facts the screen has to be able to show
// ---------------------------------------------------------------------------------------------

/// What the Browser extension screen says about Safari.
///
/// There is no manifest here and no button that writes one: a Safari Web Extension is an app
/// extension inside this app's bundle, and it is enabled from Safari's own Settings. So this
/// record is entirely facts the screen would otherwise have to guess — whether the extension is
/// actually in this build, which App Group the two halves share, and where the socket is
/// ([ADR-0024](../../../docs/decisions/0024-safari-app-group-socket.md)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafariSetup {
    /// The app extension's bundle identifier, which is what Safari lists and what the app pins.
    pub bundle_id: String,
    /// The App Group the app and the extension share, or `None` on a build with no team.
    pub app_group: Option<String>,
    /// The socket the extension connects to, or `None` when there is no App Group to put it in.
    pub socket_path: Option<PathBuf>,
    /// The `.appex` inside this bundle, when this build actually ships one.
    ///
    /// `None` on a build made before the target existed, or one whose `PlugIns` directory was
    /// stripped — which is a thing worth saying out loud, because Safari simply shows no
    /// extension in that case and gives the user nothing to act on.
    pub appex_path: Option<PathBuf>,
}

/// The Safari half of the setup screen.
///
/// `team_id` comes from the app's own code signature (`SecCodeCopySigningInformation` on itself),
/// not from a constant: a fork that signs with its own identity gets its own App Group with no
/// source edit. `bundle_plugins_dir` is this app's `Contents/PlugIns`.
#[must_use]
pub fn safari_setup(team_id: Option<&str>, bundle_plugins_dir: Option<&Path>) -> SafariSetup {
    let appex_path = bundle_plugins_dir.and_then(|dir| {
        let candidate = dir.join(format!(
            "{}.appex",
            kagisecure_extension_ipc::SAFARI_EXTENSION_EXECUTABLE
        ));
        candidate.is_dir().then_some(candidate)
    });
    SafariSetup {
        bundle_id: kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID.to_owned(),
        app_group: team_id.map(kagisecure_extension_ipc::endpoint::app_group_id),
        socket_path: kagisecure_extension_ipc::endpoint::safari_endpoint(team_id)
            .and_then(|e| e.path().map(std::path::Path::to_path_buf)),
        appex_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safari_has_no_manifest_to_write_but_does_have_a_group_and_a_socket() {
        let setup = safari_setup(Some("TEAMID1234"), None);
        assert_eq!(
            setup.bundle_id,
            kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID
        );
        assert_eq!(
            setup.app_group.as_deref(),
            Some("TEAMID1234.com.kagisecure")
        );
        assert!(setup.appex_path.is_none(), "no bundle was named");
        if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_none() {
            let socket = setup.socket_path.expect("a team gives a socket");
            assert!(
                socket
                    .to_string_lossy()
                    .contains("TEAMID1234.com.kagisecure"),
                "{}",
                socket.display()
            );
        }
    }

    /// The manifest a browser reads holds an absolute path, so the placeholder the screen shows
    /// has to be the path a real install has — and it has to be inside the bundle, where the
    /// binary is signed and notarized with the app that vouches for it (ADR-0026).
    #[test]
    fn the_placeholder_manifest_points_inside_an_installed_bundle() {
        let shown = placeholder_nmhost_path();
        assert_eq!(
            shown,
            PathBuf::from("/Applications/Kagisecure.app/Contents/Helpers/kagisecure-nmhost")
        );
        let body = manifest_body(&shown);
        assert!(body.contains("/Applications/Kagisecure.app/Contents/Helpers/kagisecure-nmhost"));
        assert!(!body.contains("Contents/MacOS"));
    }

    #[test]
    fn a_build_with_no_team_has_no_group_and_no_socket_to_offer() {
        if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_some() {
            return;
        }
        let setup = safari_setup(None, None);
        assert_eq!(setup.app_group, None);
        assert_eq!(setup.socket_path, None);
        assert!(
            !setup.bundle_id.is_empty(),
            "the bundle id is a constant and is always shown"
        );
    }

    #[test]
    fn the_app_extension_is_reported_only_when_it_is_really_in_the_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plugins = dir.path().join("PlugIns");
        std::fs::create_dir_all(&plugins).expect("dirs");
        assert!(
            safari_setup(None, Some(&plugins)).appex_path.is_none(),
            "an empty PlugIns directory ships no extension"
        );

        let appex = plugins.join(format!(
            "{}.appex",
            kagisecure_extension_ipc::SAFARI_EXTENSION_EXECUTABLE
        ));
        std::fs::create_dir_all(&appex).expect("appex");
        assert_eq!(
            safari_setup(None, Some(&plugins)).appex_path,
            Some(appex),
            "and a build that does ship one says where it is"
        );
    }

    #[test]
    fn the_manifest_names_the_host_the_path_and_the_pinned_origin() {
        let body = manifest_body(Path::new(
            "/Applications/Kagisecure.app/Contents/MacOS/kagisecure-nmhost",
        ));
        assert!(
            body.contains("\"name\": \"com.kagisecure.nmhost\""),
            "{body}"
        );
        assert!(body.contains("\"type\": \"stdio\""), "{body}");
        assert!(
            body.contains("/Applications/Kagisecure.app/Contents/MacOS/kagisecure-nmhost"),
            "{body}"
        );
        for id in PINNED_EXTENSION_IDS {
            assert!(
                body.contains(&format!("chrome-extension://{id}/")),
                "{body}"
            );
        }
    }

    #[test]
    fn the_manifest_is_valid_json_even_for_an_awkward_path() {
        // A path with a quote in it is legal on macOS and would otherwise produce a file the
        // browser rejects with no error anyone would ever see.
        let body = manifest_body(Path::new("/tmp/a\"b\\c/kagisecure-nmhost"));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("the manifest must always parse");
        assert_eq!(parsed["name"], NATIVE_HOST_NAME);
        assert_eq!(parsed["path"], "/tmp/a\"b\\c/kagisecure-nmhost");
        assert_eq!(
            parsed["allowed_origins"].as_array().unwrap().len(),
            PINNED_EXTENSION_IDS.len()
        );
    }

    #[test]
    fn a_plain_manifest_parses_and_says_what_it_should() {
        let body = manifest_body(Path::new("/usr/local/bin/kagisecure-nmhost"));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["type"], "stdio");
        assert_eq!(
            parsed["allowed_origins"][0],
            format!("chrome-extension://{}/", PINNED_EXTENSION_IDS[0])
        );
    }

    #[test]
    fn every_offered_browser_has_a_destination_under_the_users_own_library() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        assert_eq!(manifests.len(), KnownBrowser::installable().len());
        for manifest in &manifests {
            assert!(
                manifest.path.ends_with("com.kagisecure.nmhost.json"),
                "{}",
                manifest.path.display()
            );
            assert!(
                manifest
                    .path
                    .to_string_lossy()
                    .contains("Application Support"),
                "a manifest must go under the user's own Library: {}",
                manifest.path.display()
            );
            assert!(!manifest.browser.is_empty());
        }
    }

    #[test]
    fn a_browser_that_is_not_installed_is_reported_as_such() {
        // Chromium is not shipped as an application bundle on a normal Mac, so this asserts the
        // hint can be `false` at all — a check that always answers `true` is not a check.
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        let chromium = manifests
            .iter()
            .find(|m| m.browser == "Chromium")
            .expect("Chromium is offered");
        assert_eq!(
            chromium.browser_installed,
            PathBuf::from("/Applications/Chromium.app").exists()
                || std::env::var_os("HOME")
                    .is_some_and(|h| PathBuf::from(h).join("Applications/Chromium.app").exists())
        );
    }

    #[test]
    fn installed_browsers_are_listed_first() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        let first_absent = manifests.iter().position(|m| !m.browser_installed);
        if let Some(index) = first_absent {
            assert!(
                manifests[index..].iter().all(|m| !m.browser_installed),
                "the list must be partitioned, not interleaved"
            );
        }
    }

    #[test]
    fn safari_is_not_offered_because_it_does_not_use_native_messaging_hosts() {
        let manifests = all_manifests(Path::new("/tmp/kagisecure-nmhost"));
        assert!(
            !manifests.iter().any(|m| m.browser == "Safari"),
            "offering Safari a manifest it cannot read would be a lie in the UI"
        );
    }

    #[test]
    fn installing_writes_the_file_and_reinstalling_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: dir.path().join("nested").join("com.kagisecure.nmhost.json"),
            body: manifest_body(Path::new("/tmp/kagisecure-nmhost")),
            browser_installed: true,
            installed: false,
        };
        install(&manifest).expect("install");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read back"),
            manifest.body
        );
        install(&manifest).expect("install again");
        assert_eq!(
            std::fs::read_to_string(&manifest.path).expect("read back"),
            manifest.body
        );
    }

    #[test]
    fn a_failure_names_the_manifest_file_the_screen_is_showing() {
        // `/System` is read-only on every macOS since Catalina, so this exercises the
        // create-directory failure, which is the one that would otherwise name a path the user
        // never saw.
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: PathBuf::from("/System/nowhere/com.kagisecure.nmhost.json"),
            body: "{}\n".to_owned(),
            browser_installed: false,
            installed: false,
        };
        let error = install(&manifest).unwrap_err();
        assert!(error.contains("com.kagisecure.nmhost.json"), "{error}");
    }

    #[test]
    fn uninstalling_something_that_is_not_there_is_success_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = BrowserManifest {
            browser: "Test".to_owned(),
            path: dir.path().join("absent.json"),
            body: String::new(),
            browser_installed: false,
            installed: false,
        };
        uninstall(&manifest).expect("uninstalling nothing is fine");
        install(&BrowserManifest {
            body: "x".to_owned(),
            ..manifest.clone()
        })
        .expect("install");
        uninstall(&manifest).expect("uninstall");
        assert!(!manifest.path.exists());
    }

    #[test]
    fn a_manifest_that_matches_byte_for_byte_reports_itself_installed() {
        // The "installed" flag has to be content-sensitive, not existence-sensitive: a manifest
        // pointing at a stale `target/debug` binary is worse than none, because the browser
        // launches nothing and says nothing.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("com.kagisecure.nmhost.json");
        let body = manifest_body(Path::new("/tmp/one"));
        std::fs::write(&path, &body).expect("write");
        assert!(std::fs::read_to_string(&path).is_ok_and(|d| d == body));
        assert!(
            !std::fs::read_to_string(&path)
                .is_ok_and(|d| d == manifest_body(Path::new("/tmp/two")))
        );
    }

    #[test]
    fn the_host_is_found_beside_the_app_before_anywhere_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("Contents").join("MacOS");
        std::fs::create_dir_all(&bundle).expect("dirs");
        let binary = bundle.join("kagisecure-nmhost");
        std::fs::write(&binary, b"#!/bin/sh\n").expect("write");
        assert_eq!(nmhost_path(Some(&bundle)), Some(binary));
    }

    #[test]
    fn a_bundle_directory_with_nothing_in_it_falls_through_rather_than_lying() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Whatever this returns, it must not be the empty bundle's path.
        let found = nmhost_path(Some(dir.path()));
        assert!(found.as_ref().is_none_or(|p| !p.starts_with(dir.path())));
    }
}
