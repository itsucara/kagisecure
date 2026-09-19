import AppKit
import Foundation
import Observation

import KagisecureFFI

/// The app's half of the browser-extension channel (M6).
///
/// # Why this is not part of `AgentService`
///
/// It nearly is. The two listeners share the approval queue on purpose — one sheet, one timeout,
/// one biometric gate — so `AgentService`'s poll loop already delivers a fill request without
/// knowing what a browser is. What this class owns is the half that is genuinely different: a
/// second socket with its own lifecycle, a second lease store with different scoping, and the
/// setup screen that writes a browser's native-messaging manifest.
///
/// Put another way: `AgentService` owns *asking the human*. This owns *the browser channel*. The
/// fill request crosses from here to there through Rust, not through Swift.
///
/// # What it does not own
///
/// Filling. There is no code in this app that writes into a web page; the value crosses to the
/// extension over the socket and the content script writes it. This class never sees one.
@MainActor
@Observable
final class ExtensionService {
    /// The listener's state, refreshed on `AgentService`'s tick.
    private(set) var status: ExtensionStatusView = ExtensionStatusView(
        running: false, endpoint: "", safariRunning: false, safariEndpoint: "",
        connectedHosts: 0, fillLeases: 0, vaultUnlocked: false)

    /// Live fill leases, refreshed on the tick.
    private(set) var fillLeases: [FillLeaseView] = []

    /// Why the listener could not start, if it could not. Shown verbatim in the setup screen.
    private(set) var startupError: String?

    /// Where the native host is and what each browser needs written. Read once, refreshed after
    /// an install so the "installed" ticks are current.
    private(set) var setup: ExtensionSetupView?

    /// The last install/uninstall failure, for the screen to show next to the button that failed.
    var lastError: String?

    // MARK: - Lifecycle

    /// Bind the extension socket and start serving browsers. Safe to call when already running.
    func start(session: VaultSession) {
        guard !status.running else { return }
        startupError = nil
        do {
            _ = try extensionStart(
                session: session,
                socketPath: Self.socketOverride(),
                safariSocketPath: Self.safariSocketOverride(),
                // The team identifier comes from this app's own code signature, so the App Group
                // the Safari extension reaches us through follows whoever signed the build
                // (ADR-0024 §6). An ad-hoc build has none, and the Rust side then serves Chromium
                // only and says why.
                teamId: PeerCodeSignature.ownTeamIdentifier())
        } catch {
            startupError = Self.message(for: error)
        }
        status = extensionStatus()
        refreshSetup()
    }

    /// Stop serving and drop every fill lease.
    ///
    /// Called from `AppModel.lock` before the vault session is released, so there is no interval
    /// in which a locked vault is still answering a browser.
    func stop() {
        extensionStop()
        fillLeases.removeAll()
        status = extensionStatus()
    }

    /// Refresh the observable state. Driven by `AgentService`'s one-second tick rather than a
    /// second timer, so the two panes cannot disagree about what time it is.
    func tick() {
        status = extensionStatus()
        fillLeases = extensionFillLeases()
    }

    // MARK: - Leases

    func revoke(_ lease: FillLeaseView) {
        _ = extensionRevokeFillLease(origin: lease.origin, itemId: lease.itemId)
        tick()
    }

    func revokeAll() {
        extensionRevokeAllFillLeases()
        tick()
    }

    // MARK: - Setup

    func refreshSetup() {
        setup = extensionSetup(
            bundleHelpersDir: Self.bundleHelpersDirectory(),
            bundlePluginsDir: Self.bundlePlugInsDirectory(),
            teamId: PeerCodeSignature.ownTeamIdentifier())
    }

    /// Write one browser's native messaging manifest.
    ///
    /// Deliberately takes the record the screen is showing, so what lands on disk is exactly the
    /// JSON the user was looking at when they pressed the button.
    func install(_ manifest: BrowserManifestView) {
        lastError = nil
        do {
            try extensionInstallManifest(manifest: manifest)
        } catch {
            lastError = Self.message(for: error)
        }
        refreshSetup()
    }

    func uninstall(_ manifest: BrowserManifestView) {
        lastError = nil
        do {
            try extensionUninstallManifest(manifest: manifest)
        } catch {
            lastError = Self.message(for: error)
        }
        refreshSetup()
    }

    // MARK: - Helpers

    /// `KAGISECURE_EXTENSION_SOCKET` moves the listener, which is how a second vault — or the
    /// end-to-end suite — runs without touching the user's own.
    private static func socketOverride() -> String? {
        ProcessInfo.processInfo.environment["KAGISECURE_EXTENSION_SOCKET"]
    }

    /// `KAGISECURE_SAFARI_SOCKET` moves the Safari front end off the App Group container.
    ///
    /// Only useful for a test double: the real Safari extension is sandboxed and can reach the
    /// group container and nothing else, so an override that pointed elsewhere would be a socket
    /// the extension could not open.
    private static func safariSocketOverride() -> String? {
        ProcessInfo.processInfo.environment["KAGISECURE_SAFARI_SOCKET"]
    }

    /// This app's own `Contents/Helpers`, where a shipped `kagisecure-nmhost` lives.
    ///
    /// Not `Contents/MacOS`: the CLI that ships beside the host is called `kagisecure`, the app's
    /// own executable is `Kagisecure`, and on a case-insensitive filesystem — the macOS default —
    /// those are one file. See ADR-0026.
    static func bundleHelpersDirectory() -> String? {
        Bundle.main.executableURL?
            .deletingLastPathComponent()  // Contents/MacOS
            .deletingLastPathComponent()  // Contents
            .appendingPathComponent("Helpers", isDirectory: true)
            .path
    }

    /// This app's own `Contents/PlugIns`, where the Safari app extension lives.
    ///
    /// Derived from the executable rather than from `Bundle.main.builtInPlugInsURL`, which answers
    /// for the *bundle* and is `nil` for a bundle that ships none — the case this screen most
    /// needs to be able to describe.
    static func bundlePlugInsDirectory() -> String? {
        Bundle.main.executableURL?
            .deletingLastPathComponent()  // Contents/MacOS
            .deletingLastPathComponent()  // Contents
            .appendingPathComponent("PlugIns", isDirectory: true)
            .path
    }

    static func message(for error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .WrongCredential:
                return "That did not unlock the vault."
            case .NotFound(let m), .AlreadyExists(let m), .NoSuchSlot(let m), .NotPresent(let m),
                .Invalid(let m), .Io(let m):
                return m
            }
        }
        return error.localizedDescription
    }
}
