import AppKit
import ApplicationServices
import SwiftUI
import XCTest

import KagisecureFFI

@testable import Kagisecure

/// The Settings window's status badges, and the pane catalogue (ui-spec.md §17).
@MainActor
final class SettingsTests: XCTestCase {
    private func ext(running: Bool = true, safari: Bool = false, hosts: UInt32 = 0) -> ExtensionStatusView {
        ExtensionStatusView(
            running: running, endpoint: "", safariRunning: safari, safariEndpoint: "",
            connectedHosts: hosts, fillLeases: 0, vaultUnlocked: running)
    }

    private func agent(running: Bool = true, pending: UInt32 = 0) -> AgentStatusView {
        AgentStatusView(running: running, endpoint: "", pendingApprovals: pending, activeLeases: 0, vaultUnlocked: running)
    }

    func testBrowserExtensionStatus() {
        XCTAssertEqual(SettingsStatus.browserExtension(ext(running: false)), .locked)
        XCTAssertEqual(SettingsStatus.browserExtension(ext()), .ready)
        XCTAssertEqual(SettingsStatus.browserExtension(ext(running: false, safari: true)), .ready)
        XCTAssertEqual(SettingsStatus.browserExtension(ext(hosts: 2)), .connected(2))
    }

    func testAgentListenerStatus() {
        XCTAssertEqual(SettingsStatus.agentListener(agent(running: false, pending: 3)), .stopped)
        XCTAssertEqual(SettingsStatus.agentListener(agent()), .listening)
        XCTAssertEqual(SettingsStatus.agentListener(agent(pending: 2)), .waiting(2))
    }

    func testEveryPaneIsInExactlyOneSidebarGroup() {
        let grouped = SettingsPane.groups.flatMap { $0 }
        XCTAssertEqual(grouped.count, Set(grouped).count)
        XCTAssertEqual(Set(grouped), Set(SettingsPane.allCases))
    }

    func testAutoFillDeepLinkTargetsPasswordsSettings() {
        XCTAssertEqual(
            SystemSettingsLink.autoFill.absoluteString,
            "x-apple.systempreferences:com.apple.Passwords-Settings.extension")
    }

    /// Renders every pane to PNG, in English and Japanese, light and dark, for design review.
    /// Opt-in: runs only when `KS_SETTINGS_SHOTS` names an output directory (pass it to
    /// `xcodebuild` as `TEST_RUNNER_KS_SETTINGS_SHOTS=…`).
    func testRenderSettingsPanes() throws {
        guard let dir = ProcessInfo.processInfo.environment["KS_SETTINGS_SHOTS"], !dir.isEmpty else {
            throw XCTSkip("set KS_SETTINGS_SHOTS to render the Settings panes")
        }
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let vault = NSTemporaryDirectory() + "settings-shots-\(UUID().uuidString)/vault.kagi"
        let model = AppModel(vaultPath: vault)
        let updater = AppUpdater()
        for (lang, locale) in [("en", "en"), ("ja", "ja")] {
            for dark in [false, true] {
                for pane in SettingsPane.allCases {
                    let root = SettingsView(fixedPane: pane)
                        .environment(model)
                        .environment(updater)
                        .environment(\.locale, Locale(identifier: locale))
                    let size = NSSize(width: 800, height: 640)
                    let host = NSHostingView(rootView: root)
                    host.frame = NSRect(origin: .zero, size: size)
                    let window = NSWindow(
                        contentRect: host.frame, styleMask: [.titled, .closable, .fullSizeContentView],
                        backing: .buffered, defer: false)
                    window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                    window.contentView = host
                    window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
                    window.orderFrontRegardless()
                    for _ in 0..<6 {
                        host.layoutSubtreeIfNeeded()
                        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
                    }
                    let name = "\(SettingsPane.allCases.firstIndex(of: pane)!)-\(pane.rawValue)-\(lang)-\(dark ? "dark" : "light").png"
                    let out = URL(fileURLWithPath: dir).appendingPathComponent(name)
                    // Drawn off screen: `cacheDisplay` needs a window, not a visible one.
                    let frameView = window.contentView?.superview ?? host
                    window.displayIfNeeded()
                    let rep = try XCTUnwrap(frameView.bitmapImageRepForCachingDisplay(in: frameView.bounds))
                    frameView.cacheDisplay(in: frameView.bounds, to: rep)
                    let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
                    try png.write(to: out)
                    window.orderOut(nil)
                }
            }
        }
    }

    /// Reads every pane's accessibility tree the way VoiceOver and other AX clients do. A label
    /// that resolves through an element pointing back at it recursed until the stack overflowed
    /// (0.1.4, Settings › General, 2026-10-04).
    func testEveryPaneHasAFiniteAccessibilityTree() {
        let vault = NSTemporaryDirectory() + "settings-ax-\(UUID().uuidString)/vault.kagi"
        let model = AppModel(vaultPath: vault)
        let updater = AppUpdater()
        // The second pass differs from the launch language, so General also shows its relaunch
        // notice.
        let original = AppLanguage.stored()
        defer { AppLanguage.store(original) }
        for (pass, locale) in ["en", "ja"].enumerated() {
            if pass == 1 { AppLanguage.store(original == "ja" ? "en" : "ja") }
            for pane in SettingsPane.allCases {
                let root = SettingsView(fixedPane: pane)
                    .environment(model)
                    .environment(updater)
                    .environment(\.locale, Locale(identifier: locale))
                let host = NSHostingView(rootView: root)
                host.frame = NSRect(x: 0, y: 0, width: 800, height: 640)
                let window = NSWindow(
                    contentRect: host.frame, styleMask: [.titled, .closable],
                    backing: .buffered, defer: false)
                window.contentView = host
                window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
                window.orderFrontRegardless()
                for _ in 0..<4 {
                    host.layoutSubtreeIfNeeded()
                    RunLoop.main.run(until: Date().addingTimeInterval(0.1))
                }
                var visited = 0
                Self.walk(window, depth: 0, visited: &visited)
                Self.walkThroughAXServer()
                XCTAssertGreaterThan(visited, 1, "\(pane) exposed no accessibility elements")
                window.orderOut(nil)
            }
        }
    }

    private static let attributes: [NSAccessibility.Attribute] = [
        .role, .roleDescription, .title, .description, .value, .help, .identifier,
        .titleUIElement, .valueDescription, .placeholderValue,
    ]

    private static func walk(_ element: Any, depth: Int, visited: inout Int) {
        guard depth < 60, let object = element as? NSObject else { return }
        visited += 1
        if let ax = object as? NSAccessibilityProtocol {
            _ = ax.accessibilityLabel()
            _ = ax.accessibilityValue()
            _ = ax.accessibilityTitle()
        }
        for attribute in attributes {
            _ = object.accessibilityAttributeValue(attribute)
        }
        let children = object.accessibilityAttributeValue(.children) as? [Any] ?? []
        for child in children { walk(child, depth: depth + 1, visited: &visited) }
    }

    /// The real client path: AX requests over the accessibility server, answered by our main
    /// run loop (`CopyMultipleAttributeValues`, as in the crash). Needs the test runner to be a
    /// trusted accessibility client; silently does nothing otherwise.
    private static func walkThroughAXServer() {
        guard AXIsProcessTrusted() else { return }
        let done = Atomic()
        let pid = getpid()
        Thread.detachNewThread {
            let app = AXUIElementCreateApplication(pid)
            AXUIElementSetMessagingTimeout(app, 5)
            var count = 0
            func visit(_ element: AXUIElement, _ depth: Int) {
                guard depth < 60, count < 5000 else { return }
                count += 1
                var names: CFArray?
                guard AXUIElementCopyAttributeNames(element, &names) == .success,
                    let list = names as? [String]
                else { return }
                var values: CFArray?
                _ = AXUIElementCopyMultipleAttributeValues(element, list as CFArray, [], &values)
                var children: CFTypeRef?
                if AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &children)
                    == .success, let kids = children as? [AXUIElement]
                {
                    for kid in kids { visit(kid, depth + 1) }
                }
            }
            visit(app, 0)
            done.set()
        }
        let deadline = Date().addingTimeInterval(60)
        while !done.value, Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        }
    }

    private final class Atomic: @unchecked Sendable {
        private let lock = NSLock()
        private var flag = false
        var value: Bool { lock.withLock { flag } }
        func set() { lock.withLock { flag = true } }
    }
}
