import AppKit
import Foundation
import Observation
import SafariServices

import KagisecureFFI

/// One browser on this Mac, as the "Connect your browsers" prompt sees it (ui-spec.md §6.5).
struct BrowserCandidate: Identifiable, Equatable, Hashable {
    enum Kind: Equatable, Hashable {
        /// A Chromium-family browser: a native-messaging manifest plus the extension.
        case chromium
        /// Safari: the web extension inside this app, switched on in Safari's Settings.
        case safari
    }

    /// Stable key for persistence, e.g. `googlechrome`, `safari`.
    let id: String
    /// What the person reads, e.g. "Google Chrome".
    let name: String
    let kind: Kind
    /// The browser's application bundle is on this Mac.
    let installed: Bool
    /// Kagisecure can fill in it: for Chromium, the manifest is written and the extension is in a
    /// profile; for Safari, the extension is switched on.
    let connected: Bool
    /// Where the browser is, for its icon and for opening a page in it.
    var appURL: URL?
}

/// The pure decision: which browsers to offer, and when (unit-tested in BrowserConnectPromptTests).
enum BrowserConnectPrompt {
    /// `UserDefaults` key: ids the person checked "Don't ask about this browser again" for.
    static let silencedKey = "browserPrompt.silenced"
    /// `UserDefaults` key: `[id: secondsSince1970]` until which "Later" holds a browser back.
    static let snoozedUntilKey = "browserPrompt.snoozedUntil"
    /// How long "Later" holds a browser back.
    static let snoozeInterval: TimeInterval = 7 * 24 * 60 * 60

    /// The Chrome Web Store listing of the extension.
    static let webStoreItemID = "aacppfmljihmjacphgpkbmanhbhphjgl"
    static let webStoreURL = URL(string: "https://chromewebstore.google.com/detail/\(webStoreItemID)")!

    /// Installed, not connected, not silenced, not snoozed.
    static func browsersToOffer(
        _ candidates: [BrowserCandidate], silenced: Set<String>, snoozedUntil: [String: Date], now: Date
    ) -> [BrowserCandidate] {
        candidates.filter { browser in
            guard browser.installed, !browser.connected, !silenced.contains(browser.id) else { return false }
            if let until = snoozedUntil[browser.id], until > now { return false }
            return true
        }
    }

    /// Whether to raise the sheet: unlocked, not yet shown this launch, and something to offer.
    static func shouldPresent(unlocked: Bool, alreadyShownThisLaunch: Bool, offer: [BrowserCandidate]) -> Bool {
        unlocked && !alreadyShownThisLaunch && !offer.isEmpty
    }

    /// The snooze table after "Later": every offered browser that is still unconnected and was
    /// not silenced is held back for `snoozeInterval`. Expired entries are dropped.
    static func snoozing(
        _ offered: [BrowserCandidate], silenced: Set<String>, existing: [String: Date], now: Date
    ) -> [String: Date] {
        var out = existing.filter { $0.value > now }
        for browser in offered where !browser.connected && !silenced.contains(browser.id) {
            out[browser.id] = now.addingTimeInterval(snoozeInterval)
        }
        return out
    }

    // MARK: Persistence

    static func silenced(in defaults: UserDefaults) -> Set<String> {
        Set(defaults.stringArray(forKey: silencedKey) ?? [])
    }

    static func setSilenced(_ ids: Set<String>, in defaults: UserDefaults) {
        defaults.set(ids.sorted(), forKey: silencedKey)
    }

    static func snoozedUntil(in defaults: UserDefaults) -> [String: Date] {
        let raw = defaults.dictionary(forKey: snoozedUntilKey) as? [String: Double] ?? [:]
        return raw.mapValues { Date(timeIntervalSince1970: $0) }
    }

    static func setSnoozedUntil(_ table: [String: Date], in defaults: UserDefaults) {
        defaults.set(table.mapValues(\.timeIntervalSince1970), forKey: snoozedUntilKey)
    }

    /// `"Google Chrome"` → `googlechrome`.
    static func id(for name: String) -> String {
        name.lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
    }
}

/// Finds the browsers, asks whether each is connected, and runs the prompt (ui-spec.md §6.5).
@MainActor
@Observable
final class BrowserConnectModel {
    /// Every browser this build knows how to connect, installed or not. Refreshed by `refresh()`.
    private(set) var browsers: [BrowserCandidate] = []
    /// What the open sheet lists. Fixed for the life of the sheet so rows do not vanish as they
    /// connect; their `connected` flag is kept current instead.
    private(set) var offered: [BrowserCandidate] = []
    /// Raise the sheet as soon as nothing else is on screen (RootView queues it).
    var pending = false
    /// Ids checked "Don't ask about this browser again" in the open sheet.
    var dontAsk: Set<String> = []
    /// Silenced ids, mirrored from defaults so Settings updates live.
    private(set) var silenced: Set<String> = []

    private var shownThisLaunch = false
    private var pollTask: Task<Void, Never>?
    private let defaults: UserDefaults
    private weak var ext: ExtensionService?

    init(defaults: UserDefaults = AppDefaults.shared) {
        self.defaults = defaults
        silenced = BrowserConnectPrompt.silenced(in: defaults)
    }

    func bind(_ ext: ExtensionService) {
        self.ext = ext
    }

    /// Called once the vault is unlocked and the extension listener has started.
    func vaultUnlocked(ext: ExtensionService) {
        self.ext = ext
        // The UI-test suite drives its own sheets; a prompt it does not expect would stall it.
        guard !ProcessInfo.processInfo.arguments.contains(where: { $0.hasPrefix("-KSUITest") }) else { return }
        Task {
            await refresh()
            let offer = BrowserConnectPrompt.browsersToOffer(
                browsers, silenced: silenced, snoozedUntil: BrowserConnectPrompt.snoozedUntil(in: defaults),
                now: Date())
            guard BrowserConnectPrompt.shouldPresent(
                unlocked: true, alreadyShownThisLaunch: shownThisLaunch, offer: offer)
            else { return }
            shownThisLaunch = true
            offered = offer
            dontAsk = []
            pending = true
        }
    }

    func vaultLocked() {
        pending = false
        stopPolling()
    }

    /// Show a fixed list without detection — for the screenshot test.
    func present(_ list: [BrowserCandidate]) {
        offered = list
        pending = true
    }

    // MARK: Sheet lifecycle

    func sheetAppeared() {
        stopPolling()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard let self, !Task.isCancelled else { return }
                await self.refresh()
            }
        }
    }

    /// "Later" or "Done": silence the checked browsers and snooze the rest.
    func dismiss() {
        stopPolling()
        pending = false
        var silencedNow = silenced
        silencedNow.formUnion(dontAsk)
        BrowserConnectPrompt.setSilenced(silencedNow, in: defaults)
        silenced = silencedNow
        let table = BrowserConnectPrompt.snoozing(
            offered, silenced: silencedNow, existing: BrowserConnectPrompt.snoozedUntil(in: defaults), now: Date())
        BrowserConnectPrompt.setSnoozedUntil(table, in: defaults)
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    // MARK: Settings

    /// Allow prompting for a silenced browser again (and clear its snooze).
    func allowPrompt(for id: String, _ allow: Bool) {
        if allow { silenced.remove(id) } else { silenced.insert(id) }
        BrowserConnectPrompt.setSilenced(silenced, in: defaults)
        var table = BrowserConnectPrompt.snoozedUntil(in: defaults)
        table[id] = nil
        BrowserConnectPrompt.setSnoozedUntil(table, in: defaults)
    }

    func resetAll() {
        silenced = []
        BrowserConnectPrompt.setSilenced([], in: defaults)
        BrowserConnectPrompt.setSnoozedUntil([:], in: defaults)
    }

    // MARK: Connect

    func connect(_ browser: BrowserCandidate) {
        switch browser.kind {
        case .safari:
            if let id = ext?.setup?.safari.bundleId {
                SFSafariApplication.showPreferencesForExtension(withIdentifier: id) { _ in }
            }
        case .chromium:
            // Write the native-messaging manifest first, so the extension finds this app the
            // moment it is added.
            if let ext, let manifest = ext.setup?.manifests.first(where: {
                BrowserConnectPrompt.id(for: $0.browser) == browser.id
            }), !manifest.installed {
                ext.install(manifest)
            }
            if let app = browser.appURL {
                NSWorkspace.shared.open(
                    [BrowserConnectPrompt.webStoreURL], withApplicationAt: app,
                    configuration: NSWorkspace.OpenConfiguration())
            } else {
                NSWorkspace.shared.open(BrowserConnectPrompt.webStoreURL)
            }
        }
        Task { await refresh() }
    }

    // MARK: Detection

    /// Re-read which browsers exist and which are connected.
    func refresh() async {
        guard let ext else { return }
        ext.refreshSetup()
        guard let setup = ext.setup else { return }
        let extensionIDs = [setup.extensionId, BrowserConnectPrompt.webStoreItemID]
        var list: [BrowserCandidate] = setup.manifests.map { manifest in
            let id = BrowserConnectPrompt.id(for: manifest.browser)
            let profileRoot = URL(fileURLWithPath: manifest.path)
                .deletingLastPathComponent()  // NativeMessagingHosts
                .deletingLastPathComponent()
            let app = Self.appURL(for: manifest.browser)
            return BrowserCandidate(
                id: id, name: manifest.browser, kind: .chromium,
                installed: manifest.browserInstalled || app != nil,
                connected: manifest.installed
                    && Self.anyProfileHasExtension(root: profileRoot, ids: extensionIDs),
                appURL: app)
        }
        // Safari is only offered when this build can actually serve it.
        if setup.safari.appexPath != nil, setup.safari.appGroup != nil {
            let enabled = await Self.safariExtensionEnabled(setup.safari.bundleId)
            list.append(BrowserCandidate(
                id: "safari", name: "Safari", kind: .safari, installed: true, connected: enabled,
                appURL: NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari")))
        }
        browsers = list
        offered = offered.map { old in list.first { $0.id == old.id } ?? old }
    }

    private static let bundleIDs: [String: String] = [
        "Google Chrome": "com.google.Chrome",
        "Microsoft Edge": "com.microsoft.edgemac",
        "Arc": "company.thebrowser.Browser",
        "Brave Browser": "com.brave.Browser",
        "Chromium": "org.chromium.Chromium",
    ]

    static func appURL(for name: String) -> URL? {
        guard let id = bundleIDs[name] else { return nil }
        return NSWorkspace.shared.urlForApplication(withBundleIdentifier: id)
    }

    /// Whether any profile under a Chromium user-data directory lists the extension. Both a store
    /// install and an unpacked load are recorded in the profile's `Preferences` or
    /// `Secure Preferences`, keyed by the extension id.
    nonisolated static func anyProfileHasExtension(root: URL, ids: [String]) -> Bool {
        let fm = FileManager.default
        guard let profiles = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else {
            return false
        }
        let needles = ids.map { Data($0.utf8) }
        for profile in profiles {
            for file in ["Secure Preferences", "Preferences"] {
                guard let data = try? Data(contentsOf: profile.appendingPathComponent(file)) else { continue }
                if needles.contains(where: { data.range(of: $0) != nil }) { return true }
            }
        }
        return false
    }

    private static func safariExtensionEnabled(_ id: String) async -> Bool {
        await withCheckedContinuation { continuation in
            SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: id) { state, _ in
                continuation.resume(returning: state?.isEnabled ?? false)
            }
        }
    }
}
