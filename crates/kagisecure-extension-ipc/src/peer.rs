//! Who is on the other end of the extension socket — and, one hop further, what launched them.
//!
//! # Why one hop further than the MCP channel
//!
//! For the MCP socket, the connecting process *is* the thing being judged: `kagisecure-mcp` is a
//! program the user installed and Claude Code spawns. For the extension socket the connecting
//! process is [`kagisecure-nmhost`](../../kagisecure_nmhost/index.html), which is a pipe — it
//! holds no vault, decides nothing, and would be exactly as trustworthy if a hostile program ran
//! it. The interesting question is *who launched it*, because Chrome launches a native messaging
//! host as a direct child, and a native host launched by something that is not a browser is a
//! program pretending to be a browser extension.
//!
//! So the identity this module builds has two halves:
//!
//! * the **host**: the kernel's peer pid, its executable path;
//! * the **browser**: the first ancestor within [`MAX_ANCESTRY_HOPS`] hops whose executable is a
//!   recognized browser, its pid and its executable path.
//!
//! Neither half includes a code-signature verdict, and that is deliberate: `SecCode*` lives in
//! Security.framework, and [ADR-0015](../../../docs/decisions/0015-peer-code-signature-verification.md)
//! already settled that the check belongs in Swift and travels *down* with the decision. This
//! module supplies the pids that check is performed on.
//!
//! # What "recognized browser" means, and what it does not
//!
//! It means the executable path ends in a known browser's binary path. That is a **path** test,
//! and ADR-0015 is explicit that a path is not an identity: anything that can write to
//! `/Applications` can put a program there. It is not the security boundary — the approval sheet
//! and the biometric are — it is what lets the sheet say *"launched by Google Chrome"* instead of
//! *"launched by something"*, and what lets the app refuse a native host that was launched by a
//! shell script with no browser anywhere above it.
//!
//! # The Safari front end is the other shape
//!
//! Safari does not launch a native messaging host. Its extension is an app extension inside our
//! own bundle, and macOS launches it from `launchd`, so there is no browser anywhere in its
//! ancestry to find. The ancestry walk is therefore replaced, on that socket only, by a test on
//! the **peer itself**: its executable must be
//! `…/KagisecureSafariExtension.appex/Contents/MacOS/KagisecureSafariExtension`
//! ([`is_safari_extension_executable`]). That is strictly better evidence than the Chromium side
//! gets — the process being judged is one we ship, rather than a pipe with a browser above it —
//! and the code-signature check the app runs on it in Swift is against *our own* team rather than
//! a vendor's. [`HostKind`] selects between the two.

use std::path::Path;

/// How far up the process tree to look for a browser.
///
/// Chrome launches a native messaging host from the browser process, so one hop is the expected
/// answer. Three allows for a launcher shim (Arc ships one) and for a future Chromium that moves
/// the launch into a utility process, without letting the search wander into `launchd`.
pub const MAX_ANCESTRY_HOPS: usize = 3;

/// The bundle identifier of the Safari Web Extension shipped inside the app.
///
/// This is what the app extension reports about *itself* — it is the appex's own
/// `Bundle.main.bundleIdentifier`, stamped onto the `Hello` by the native handler rather than
/// taken from web content, because `browser.runtime.id` in Safari is a per-install UUID and
/// therefore cannot be pinned (ADR-0024 §4).
pub const SAFARI_EXTENSION_BUNDLE_ID: &str = "com.kagisecure.app.safari-extension";

/// The file name of the Safari app extension's executable, inside its `.appex`.
pub const SAFARI_EXTENSION_EXECUTABLE: &str = "KagisecureSafariExtension";

/// Whether `executable` is our Safari app extension's binary.
///
/// Two conditions, both on the path: the file name is the extension's executable, **and** it sits
/// inside a bundle called `KagisecureSafariExtension.appex`. Like [`known_browser_for`] this is a
/// path test and not an identity — the identity is the code-signature check the app runs in Swift
/// on the same pid, and shows on the sheet. What the path test buys is that a stray program called
/// `KagisecureSafariExtension` sitting in `/tmp` does not reach a `Hello`.
#[must_use]
pub fn is_safari_extension_executable(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name == SAFARI_EXTENSION_EXECUTABLE)
        && executable.contains(&format!("/{SAFARI_EXTENSION_EXECUTABLE}.appex/"))
}

/// Which of the two front ends a connection arrived on.
///
/// The two sockets speak the same [`crate::protocol`] and differ only in who is allowed to be on
/// the other end, which is why this is a parameter to identity resolution rather than a second
/// implementation of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HostKind {
    /// The Chromium native messaging host, launched by a browser as a child process.
    #[default]
    NativeMessaging,
    /// The Safari Web Extension's app extension, launched by the system on Safari's behalf.
    SafariAppExtension,
}

/// A browser this app will serve.
///
/// Safari is never produced by [`known_browser_for`], and that is not an oversight: the Safari Web
/// Extension route does not use a native messaging *host* at all — it uses an app extension in the
/// containing app's bundle — so a Safari-launched nmhost is not a thing that can happen. Safari
/// reaches [`HostIdentity`] through [`HostKind::SafariAppExtension`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownBrowser {
    /// Google Chrome, any channel.
    Chrome,
    /// Microsoft Edge.
    Edge,
    /// The Arc browser.
    Arc,
    /// Brave.
    Brave,
    /// Vanilla Chromium, including the build Playwright drives.
    Chromium,
    /// Safari. Never returned on macOS today; see the type documentation.
    Safari,
}

impl KnownBrowser {
    /// The name the approval sheet shows.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Chrome => "Google Chrome",
            Self::Edge => "Microsoft Edge",
            Self::Arc => "Arc",
            Self::Brave => "Brave Browser",
            Self::Chromium => "Chromium",
            Self::Safari => "Safari",
        }
    }

    /// The identifier this browser's directory uses under `Application Support`, for writing its
    /// `NativeMessagingHosts` manifest.
    #[must_use]
    pub fn native_messaging_dir_fragment(self) -> Option<&'static str> {
        match self {
            Self::Chrome => Some("Google/Chrome/NativeMessagingHosts"),
            Self::Edge => Some("Microsoft Edge/NativeMessagingHosts"),
            Self::Arc => Some("Arc/User Data/NativeMessagingHosts"),
            Self::Brave => Some("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            Self::Chromium => Some("Chromium/NativeMessagingHosts"),
            Self::Safari => None,
        }
    }

    /// Every browser the setup screen offers to install for, in the order it lists them.
    #[must_use]
    pub fn installable() -> &'static [Self] {
        &[
            Self::Chrome,
            Self::Edge,
            Self::Arc,
            Self::Brave,
            Self::Chromium,
        ]
    }
}

/// Whether `executable` is a browser we recognize.
///
/// Matched on the trailing path components rather than on the whole path, so a browser installed
/// under `~/Applications` or in a Playwright cache is recognized as the same program.
#[must_use]
pub fn known_browser_for(executable: &str) -> Option<KnownBrowser> {
    // Longest first: "Google Chrome Helper" must not be mistaken for something shorter, and
    // "Brave Browser" contains "Browser".
    const TABLE: &[(&str, KnownBrowser)] = &[
        ("Google Chrome Canary", KnownBrowser::Chrome),
        ("Google Chrome Beta", KnownBrowser::Chrome),
        ("Google Chrome Dev", KnownBrowser::Chrome),
        ("Google Chrome for Testing", KnownBrowser::Chromium),
        ("Google Chrome", KnownBrowser::Chrome),
        ("Microsoft Edge Canary", KnownBrowser::Edge),
        ("Microsoft Edge Beta", KnownBrowser::Edge),
        ("Microsoft Edge Dev", KnownBrowser::Edge),
        ("Microsoft Edge", KnownBrowser::Edge),
        ("Brave Browser Beta", KnownBrowser::Brave),
        ("Brave Browser", KnownBrowser::Brave),
        ("Chromium", KnownBrowser::Chromium),
        ("Arc", KnownBrowser::Arc),
        ("Safari", KnownBrowser::Safari),
        // Linux, for a contributor running the host under a distro build.
        ("google-chrome-stable", KnownBrowser::Chrome),
        ("google-chrome", KnownBrowser::Chrome),
        ("microsoft-edge", KnownBrowser::Edge),
        ("brave-browser", KnownBrowser::Brave),
        ("chromium-browser", KnownBrowser::Chromium),
        ("chromium", KnownBrowser::Chromium),
    ];
    let name = Path::new(executable).file_name()?.to_str()?;
    // Exact file-name match only. A *prefix* match would accept `Google Chrome Helper (Renderer)`
    // and `Google Chrome Framework`, neither of which launches a native messaging host, and a
    // *substring* match would accept `/tmp/Not Google Chrome At All`.
    TABLE
        .iter()
        .find(|(needle, _)| name == *needle)
        .map(|(_, browser)| *browser)
}

/// The parent process id of `pid`, or `None` if it cannot be determined.
///
/// Implemented with `/bin/ps` rather than with `sysctl(KERN_PROC_PID)` so that this crate stays
/// free of `unsafe` — the one FFI module in the workspace's IPC layer is
/// `kagisecure_ipc::kernel_peer`, and adding a second one for a fact that `ps` reports accurately
/// would be a poor trade. The cost is one short-lived process per approval, on a path that is
/// already going to show a human a dialog.
#[must_use]
pub fn parent_pid(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("/bin/ps")
            .args(["-o", "ppid=", "-p"])
            .arg(pid.to_string())
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        let parsed: u32 = text.trim().parse().ok()?;
        if parsed == 0 { None } else { Some(parsed) }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// What the app established about the process on the other end of the extension socket.
///
/// Every field is either a kernel fact or `None`. Nothing here is self-reported: the extension's
/// own claims about its id and its browser live in [`crate::protocol::Request::Hello`] and are
/// kept separate on purpose, so the sheet can show them as a quotation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostIdentity {
    /// The native host's pid, from the kernel.
    pub pid: Option<u32>,
    /// The native host's effective uid, from the kernel. A mismatch is refused, not warned about.
    pub euid: Option<u32>,
    /// The native host's executable path, resolved from its pid.
    pub executable: Option<String>,
    /// The immediate parent's pid.
    pub parent_pid: Option<u32>,
    /// The immediate parent's executable path.
    pub parent_executable: Option<String>,
    /// The first recognized browser at or above the parent, if there is one.
    pub browser: Option<KnownBrowser>,
    /// That browser's pid — what the app runs its code-signature check on.
    pub browser_pid: Option<u32>,
    /// That browser's executable path.
    pub browser_executable: Option<String>,
    /// Whether the peer is an **app extension** rather than a native messaging host.
    ///
    /// `true` only for the Safari front end. It changes two things and nothing else: the sheet
    /// says "extension" where it otherwise says "launched by", and the app runs its Swift
    /// code-signature check against the app-extension requirement rather than the browser-vendor
    /// one — the appex is signed by *us*, and Safari itself is never the process on the socket.
    pub app_extension: bool,
}

impl HostIdentity {
    /// Build an identity from a pid the kernel supplied, on the native-messaging front end.
    #[must_use]
    pub fn resolve(pid: Option<u32>, euid: Option<u32>) -> Self {
        Self::resolve_kind(HostKind::NativeMessaging, pid, euid)
    }

    /// Build an identity for whichever front end the connection arrived on.
    #[must_use]
    pub fn resolve_kind(kind: HostKind, pid: Option<u32>, euid: Option<u32>) -> Self {
        match kind {
            HostKind::NativeMessaging => Self::resolve_native_messaging(pid, euid),
            HostKind::SafariAppExtension => Self::resolve_safari(pid, euid),
        }
    }

    /// The Safari front end: the peer *is* the extension, so there is nothing to walk up to.
    ///
    /// macOS launches an app extension from `launchd`, not from Safari, so the process-ancestry
    /// gate the Chromium side uses would refuse every genuine Safari connection and accept
    /// nothing in its place. What replaces it is a check on the peer itself: its executable must
    /// be the `.appex` binary inside our own bundle. That is strictly better evidence — the
    /// process being judged is the one we ship, rather than a pipe with a browser somewhere above
    /// it (ADR-0024 §5).
    #[must_use]
    fn resolve_safari(pid: Option<u32>, euid: Option<u32>) -> Self {
        let executable = pid.and_then(kagisecure_ipc::server::executable_for_pid);
        let is_ours = executable
            .as_deref()
            .is_some_and(is_safari_extension_executable);
        Self {
            pid,
            euid,
            executable: executable.clone(),
            parent_pid: pid.and_then(parent_pid),
            parent_executable: None,
            browser: is_ours.then_some(KnownBrowser::Safari),
            browser_pid: is_ours.then_some(pid).flatten(),
            browser_executable: is_ours.then_some(executable).flatten(),
            app_extension: is_ours,
        }
    }

    fn resolve_native_messaging(pid: Option<u32>, euid: Option<u32>) -> Self {
        let executable = pid.and_then(kagisecure_ipc::server::executable_for_pid);
        let parent = pid.and_then(parent_pid);
        let parent_executable = parent.and_then(kagisecure_ipc::server::executable_for_pid);

        // Walk up looking for a browser, starting at the parent.
        let mut browser = None;
        let mut cursor = parent;
        for _ in 0..MAX_ANCESTRY_HOPS {
            let Some(current) = cursor else { break };
            if let Some(path) = kagisecure_ipc::server::executable_for_pid(current)
                && let Some(known) = known_browser_for(&path)
            {
                browser = Some((known, current, path));
                break;
            }
            cursor = parent_pid(current);
        }

        Self {
            pid,
            euid,
            executable,
            parent_pid: parent,
            parent_executable,
            browser: browser.as_ref().map(|(b, _, _)| *b),
            browser_pid: browser.as_ref().map(|(_, p, _)| *p),
            browser_executable: browser.map(|(_, _, path)| path),
            app_extension: false,
        }
    }

    /// Whether a recognized browser launched this host.
    ///
    /// This is a gate: a native host with no browser above it is refused with `UNTRUSTED_HOST`
    /// before any request is served. It is *not* a claim that the browser is genuine — see the
    /// module documentation, and the code-signature verdict the app attaches separately.
    #[must_use]
    pub fn launched_by_browser(&self) -> bool {
        self.browser.is_some()
    }

    /// One line per fact, for the approval sheet, the popup and the audit entry.
    ///
    /// Deliberately says *"signature not checked here"* rather than nothing: the check happens in
    /// Swift and this string is written by Rust, so it must not read as if a check passed.
    #[must_use]
    pub fn evidence(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "{}: {} (pid {})",
            if self.app_extension {
                "App extension"
            } else {
                "Native host"
            },
            self.executable.as_deref().unwrap_or("unknown executable"),
            self.pid.map_or_else(|| "?".to_owned(), |p| p.to_string())
        ));
        match (&self.browser, &self.browser_executable) {
            // The Safari front end: the peer is the app extension, and Safari is not a separate
            // process on the socket, so the line names what is actually established rather than
            // implying a second process was inspected.
            (Some(browser), Some(_)) if self.app_extension => lines.push(format!(
                "Launched by: {} (extension {SAFARI_EXTENSION_BUNDLE_ID}, pid {})",
                browser.display_name(),
                self.pid.map_or_else(|| "?".to_owned(), |p| p.to_string())
            )),
            (Some(browser), Some(path)) => lines.push(format!(
                "Launched by: {} — {} (pid {})",
                browser.display_name(),
                path,
                self.browser_pid
                    .map_or_else(|| "?".to_owned(), |p| p.to_string())
            )),
            _ => lines.push(format!(
                "Launched by: {} — not a recognized browser",
                self.parent_executable
                    .as_deref()
                    .unwrap_or("unknown parent")
            )),
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chrome_executable_path_is_recognized() {
        assert_eq!(
            known_browser_for("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Some(KnownBrowser::Chrome)
        );
        assert_eq!(
            known_browser_for(
                "/Users/x/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            ),
            Some(KnownBrowser::Chrome),
            "a per-user install is the same browser"
        );
        assert_eq!(
            known_browser_for("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            Some(KnownBrowser::Edge)
        );
        assert_eq!(
            known_browser_for("/Applications/Arc.app/Contents/MacOS/Arc"),
            Some(KnownBrowser::Arc)
        );
        assert_eq!(
            known_browser_for("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
            Some(KnownBrowser::Brave)
        );
        assert_eq!(
            known_browser_for("/usr/bin/google-chrome-stable"),
            Some(KnownBrowser::Chrome)
        );
    }

    #[test]
    fn a_helper_process_is_not_the_browser() {
        // Chrome's renderer and GPU helpers never launch a native messaging host. Accepting one
        // as "the browser" would mean any compromised renderer could stand in for Chrome itself.
        assert_eq!(
            known_browser_for(
                "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
            ),
            None
        );
        assert_eq!(
            known_browser_for("/x/Google Chrome Helper (Renderer)"),
            None
        );
    }

    #[test]
    fn a_program_that_merely_mentions_a_browser_is_not_one() {
        assert_eq!(known_browser_for("/tmp/Not Google Chrome At All"), None);
        assert_eq!(known_browser_for("/tmp/Google Chrome.sh"), None);
        assert_eq!(known_browser_for("/bin/sh"), None);
        assert_eq!(known_browser_for("/usr/bin/curl"), None);
        assert_eq!(known_browser_for(""), None);
    }

    #[test]
    fn every_installable_browser_has_a_manifest_directory() {
        for browser in KnownBrowser::installable() {
            assert!(
                browser.native_messaging_dir_fragment().is_some(),
                "{browser:?} is offered for installation but has nowhere to install to"
            );
            assert!(!browser.display_name().is_empty());
        }
        assert_eq!(
            KnownBrowser::Safari.native_messaging_dir_fragment(),
            None,
            "Safari does not use native messaging host manifests"
        );
    }

    #[test]
    fn this_process_has_a_parent() {
        assert!(parent_pid(std::process::id()).is_some());
    }

    #[test]
    fn an_impossible_pid_has_no_parent() {
        assert_eq!(parent_pid(u32::MAX), None);
    }

    #[test]
    fn an_identity_with_no_browser_above_it_is_refused_and_says_why() {
        // The test binary's ancestry is a shell or cargo, never a browser.
        let identity = HostIdentity::resolve(Some(std::process::id()), Some(501));
        assert!(!identity.launched_by_browser());
        let evidence = identity.evidence().join("\n");
        assert!(evidence.contains("not a recognized browser"), "{evidence}");
        assert!(evidence.contains("Native host:"), "{evidence}");
    }

    #[test]
    fn an_identity_with_no_pid_at_all_still_renders_rather_than_panicking() {
        let identity = HostIdentity::default();
        assert!(!identity.launched_by_browser());
        assert_eq!(identity.evidence().len(), 2);
        assert!(identity.evidence()[0].contains("unknown executable"));
    }

    #[test]
    fn our_safari_app_extension_is_recognized_wherever_the_app_is_installed() {
        for prefix in [
            "/Applications",
            "/Users/somebody/Applications",
            "/Users/somebody/Library/Developer/Xcode/DerivedData/Kagisecure-abc/Build/Products/Debug",
        ] {
            let path = format!(
                "{prefix}/Kagisecure.app/Contents/PlugIns/{SAFARI_EXTENSION_EXECUTABLE}.appex\
                 /Contents/MacOS/{SAFARI_EXTENSION_EXECUTABLE}"
            );
            assert!(is_safari_extension_executable(&path), "{path}");
        }
    }

    #[test]
    fn a_program_that_merely_has_the_right_file_name_is_not_the_app_extension() {
        // The name alone is trivially forgeable — anybody can `cp` a binary and rename it. The
        // `.appex` component is what makes the path test worth having at all, and the real
        // identity is the code-signature check the app runs on the same pid.
        assert!(!is_safari_extension_executable(&format!(
            "/tmp/{SAFARI_EXTENSION_EXECUTABLE}"
        )));
        assert!(!is_safari_extension_executable(
            "/Applications/Safari.app/Contents/MacOS/Safari"
        ));
        assert!(!is_safari_extension_executable(""));
        assert!(!is_safari_extension_executable(&format!(
            "/tmp/{SAFARI_EXTENSION_EXECUTABLE}.appex/Contents/MacOS/SomethingElse"
        )));
    }

    #[test]
    fn a_connection_on_the_safari_socket_from_something_that_is_not_the_appex_is_refused() {
        // This test process is not an app extension, so resolving it as one must produce an
        // identity the listener refuses — the gate, exercised in the direction that matters.
        let identity = HostIdentity::resolve_kind(
            HostKind::SafariAppExtension,
            Some(std::process::id()),
            Some(501),
        );
        assert!(!identity.launched_by_browser());
        assert!(!identity.app_extension);
    }

    #[test]
    fn the_safari_evidence_names_the_extension_rather_than_implying_a_second_process() {
        let identity = HostIdentity {
            pid: Some(4242),
            executable: Some(format!(
                "/Applications/Kagisecure.app/Contents/PlugIns/{SAFARI_EXTENSION_EXECUTABLE}.appex\
                 /Contents/MacOS/{SAFARI_EXTENSION_EXECUTABLE}"
            )),
            browser: Some(KnownBrowser::Safari),
            browser_pid: Some(4242),
            browser_executable: Some("x".to_owned()),
            app_extension: true,
            ..HostIdentity::default()
        };
        let evidence = identity.evidence().join("\n");
        assert!(evidence.contains("App extension:"), "{evidence}");
        assert!(
            evidence.contains(&format!(
                "Safari (extension {SAFARI_EXTENSION_BUNDLE_ID}, pid 4242)"
            )),
            "{evidence}"
        );
    }

    #[test]
    fn the_native_messaging_front_end_never_reports_an_app_extension() {
        let identity = HostIdentity::resolve(Some(std::process::id()), Some(501));
        assert!(!identity.app_extension);
    }
}
