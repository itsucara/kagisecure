import AppKit
import SwiftUI
import XCTest

@testable import Kagisecure

/// The "Connect your browsers" decision logic (ui-spec.md §6.5).
@MainActor
final class BrowserConnectPromptTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func browser(
        _ id: String, installed: Bool = true, connected: Bool = false, kind: BrowserCandidate.Kind = .chromium
    ) -> BrowserCandidate {
        BrowserCandidate(id: id, name: id, kind: kind, installed: installed, connected: connected, appURL: nil)
    }

    private func offer(
        _ list: [BrowserCandidate], silenced: Set<String> = [], snoozed: [String: Date] = [:]
    ) -> [String] {
        BrowserConnectPrompt.browsersToOffer(list, silenced: silenced, snoozedUntil: snoozed, now: now).map(\.id)
    }

    func testOffersOnlyInstalledUnconnectedBrowsers() {
        let list = [
            browser("chrome"), browser("edge", installed: false), browser("brave", connected: true),
            browser("safari", kind: .safari),
        ]
        XCTAssertEqual(offer(list), ["chrome", "safari"])
    }

    func testSilencedBrowserIsNeverOffered() {
        XCTAssertEqual(offer([browser("chrome"), browser("arc")], silenced: ["chrome"]), ["arc"])
    }

    func testSnoozeHoldsBackUntilItExpires() {
        let list = [browser("chrome")]
        XCTAssertEqual(offer(list, snoozed: ["chrome": now.addingTimeInterval(60)]), [])
        XCTAssertEqual(offer(list, snoozed: ["chrome": now]), ["chrome"])
        XCTAssertEqual(offer(list, snoozed: ["chrome": now.addingTimeInterval(-60)]), ["chrome"])
    }

    func testPresentsAtMostOncePerLaunchAndOnlyWhenUnlocked() {
        let some = [browser("chrome")]
        XCTAssertTrue(BrowserConnectPrompt.shouldPresent(unlocked: true, alreadyShownThisLaunch: false, offer: some))
        XCTAssertFalse(BrowserConnectPrompt.shouldPresent(unlocked: true, alreadyShownThisLaunch: true, offer: some))
        XCTAssertFalse(BrowserConnectPrompt.shouldPresent(unlocked: false, alreadyShownThisLaunch: false, offer: some))
        XCTAssertFalse(BrowserConnectPrompt.shouldPresent(unlocked: true, alreadyShownThisLaunch: false, offer: []))
    }

    func testLaterSnoozesUnconnectedUnsilencedBrowsersForAWeek() {
        let offered = [browser("chrome"), browser("edge", connected: true), browser("arc")]
        let stale = ["old": now.addingTimeInterval(-1), "keep": now.addingTimeInterval(100)]
        let table = BrowserConnectPrompt.snoozing(offered, silenced: ["arc"], existing: stale, now: now)
        XCTAssertEqual(table["chrome"], now.addingTimeInterval(7 * 24 * 60 * 60))
        XCTAssertNil(table["edge"])
        XCTAssertNil(table["arc"])
        XCTAssertNil(table["old"])
        XCTAssertNotNil(table["keep"])
    }

    func testPersistenceRoundTrips() {
        let suite = "BrowserConnectPromptTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        BrowserConnectPrompt.setSilenced(["chrome", "safari"], in: defaults)
        XCTAssertEqual(BrowserConnectPrompt.silenced(in: defaults), ["chrome", "safari"])
        BrowserConnectPrompt.setSnoozedUntil(["arc": now], in: defaults)
        XCTAssertEqual(BrowserConnectPrompt.snoozedUntil(in: defaults)["arc"], now)

        let model = BrowserConnectModel(defaults: defaults)
        XCTAssertEqual(model.silenced, ["chrome", "safari"])
        model.allowPrompt(for: "chrome", true)
        XCTAssertEqual(BrowserConnectPrompt.silenced(in: defaults), ["safari"])
        model.resetAll()
        XCTAssertEqual(BrowserConnectPrompt.silenced(in: defaults), [])
        XCTAssertEqual(BrowserConnectPrompt.snoozedUntil(in: defaults), [:])
    }

    func testDismissSilencesCheckedAndSnoozesTheRest() {
        let suite = "BrowserConnectPromptTests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let model = BrowserConnectModel(defaults: defaults)
        model.present([browser("chrome"), browser("brave")])
        model.dontAsk = ["brave"]
        model.dismiss()
        XCTAssertFalse(model.pending)
        XCTAssertEqual(BrowserConnectPrompt.silenced(in: defaults), ["brave"])
        XCTAssertNotNil(BrowserConnectPrompt.snoozedUntil(in: defaults)["chrome"])
        XCTAssertNil(BrowserConnectPrompt.snoozedUntil(in: defaults)["brave"])
    }

    func testIdIsStableSlug() {
        XCTAssertEqual(BrowserConnectPrompt.id(for: "Google Chrome"), "googlechrome")
        XCTAssertEqual(BrowserConnectPrompt.id(for: "Brave Browser"), "bravebrowser")
    }

    func testProfileScanFindsTheExtensionId() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        let profile = root.appendingPathComponent("Profile 1")
        try FileManager.default.createDirectory(at: profile, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertFalse(BrowserConnectModel.anyProfileHasExtension(root: root, ids: ["abc"]))
        try Data(#"{"extensions":{"settings":{"abc":{}}}}"#.utf8)
            .write(to: profile.appendingPathComponent("Secure Preferences"))
        XCTAssertTrue(BrowserConnectModel.anyProfileHasExtension(root: root, ids: ["zzz", "abc"]))
    }

    /// Renders the sheet to PNG (en/ja, light/dark) for design review. Opt-in via
    /// `TEST_RUNNER_KS_BROWSER_PROMPT_SHOTS=<dir>`.
    func testRenderBrowserConnectSheet() throws {
        guard let dir = ProcessInfo.processInfo.environment["KS_BROWSER_PROMPT_SHOTS"], !dir.isEmpty else {
            throw XCTSkip("set KS_BROWSER_PROMPT_SHOTS to render the sheet")
        }
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        func app(_ bundle: String) -> URL? { NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundle) }
        let list = [
            BrowserCandidate(id: "googlechrome", name: "Google Chrome", kind: .chromium, installed: true, connected: false, appURL: app("com.google.Chrome")),
            BrowserCandidate(id: "microsoftedge", name: "Microsoft Edge", kind: .chromium, installed: true, connected: true, appURL: app("com.microsoft.edgemac")),
            BrowserCandidate(id: "bravebrowser", name: "Brave Browser", kind: .chromium, installed: true, connected: false, appURL: app("com.brave.Browser")),
            BrowserCandidate(id: "safari", name: "Safari", kind: .safari, installed: true, connected: false, appURL: app("com.apple.Safari")),
        ]
        let suite = "BrowserConnectPromptShots-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        for (lang, dark) in [("en", false), ("en", true), ("ja", false), ("ja", true)] {
            let model = BrowserConnectModel(defaults: defaults)
            model.present(list)
            model.dontAsk = ["bravebrowser"]
            let root = BrowserConnectSheet(showSetup: {})
                .environment(model)
                .environment(\.locale, Locale(identifier: lang))
            let host = NSHostingView(rootView: root)
            host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            host.frame = NSRect(origin: .zero, size: host.fittingSize)
            let window = NSWindow(
                contentRect: host.frame, styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.backgroundColor = dark ? NSColor(white: 0.16, alpha: 1) : NSColor(white: 0.97, alpha: 1)
            window.titlebarAppearsTransparent = true
            window.titleVisibility = .hidden
            window.contentView = host
            window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
            window.orderFrontRegardless()
            for _ in 0..<6 {
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.15))
            }
            host.frame.size = host.fittingSize
            window.setContentSize(host.fittingSize)
            window.displayIfNeeded()
            let view = window.contentView?.superview ?? host
            let rep = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: rep)
            let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
            try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent(
                "browser-prompt-\(lang)-\(dark ? "dark" : "light").png"))
            window.orderOut(nil)
        }
    }
}
