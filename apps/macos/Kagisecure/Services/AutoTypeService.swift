import AppKit
import ApplicationServices
import Carbon.HIToolbox
import Foundation

import KagisecureFFI

/// Auto-type into native apps (ADR-0050): verify the frontmost app and the focused field, then
/// type values as synthetic keystrokes — never through the clipboard.
///
/// Two callers share one typist:
///
/// * **Agents** (`request_type`): Rust hands an approved job over `autoTypeNextJob`; this service
///   types it and answers `autoTypeFinish`. The approval and the grace window were Rust's and
///   `AgentService`'s business; this file only verifies and types.
/// * **The person** (Quick Access's "Type into previous app", the Item menu's "Type Login"): the
///   values come from in-app releases that rode the same presence grace window, and the target is
///   whatever app was frontmost before kagisecure.
///
/// # What is checked, and when
///
/// Right before the first keystroke: the frontmost app's bundle id (and signing team, when one
/// was named), the focused window's title (when named), that a text field holds keyboard focus,
/// that a password goes only into a secure text field, and that no other app holds secure event
/// input. Before every value after the first, and after each chunk of characters, the focus is
/// checked again; a change stops typing at once.
@MainActor
final class AutoTypeService {
    /// Where a check reads the system's state. `SystemFocusInspector` in production.
    let inspector: FocusInspector
    /// Where keystrokes go. `CGEventPoster` in production.
    let poster: KeystrokePoster
    /// How long to wait for the target to come back in front after kagisecure's own sheet.
    var activationWait: Duration = .milliseconds(1500)
    /// Characters sent between focus checks.
    static let chunkSize = 8

    private var pollTask: Task<Void, Never>?

    /// The one typist the app uses.
    static let shared = AutoTypeService()

    /// The `AppDefaults` key for the agent auto-type switch. On by default.
    static let agentsEnabledKey = "agentAutoTypeEnabled"

    init(inspector: FocusInspector = SystemFocusInspector(), poster: KeystrokePoster = CGEventPoster()) {
        self.inspector = inspector
        self.poster = poster
    }

    // MARK: - Permission

    /// Whether kagisecure holds the Accessibility permission.
    var isTrusted: Bool { inspector.isTrusted }

    /// Ask macOS to show the Accessibility prompt, which opens System Settings.
    func requestPermission() {
        let key = "AXTrustedCheckOptionPrompt"  // kAXTrustedCheckOptionPrompt, not concurrency-safe to reference
        _ = AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
    }

    /// Tell Rust whether agents may be served.
    func syncReadiness(defaults: UserDefaults = AppDefaults.shared) {
        let enabled = defaults.object(forKey: Self.agentsEnabledKey) as? Bool ?? true
        autoTypeSetReady(ready: enabled && isTrusted)
    }

    // MARK: - Agent jobs

    func start() {
        syncReadiness()
        guard pollTask == nil else { return }
        pollTask = Task.detached(priority: .userInitiated) { [weak self] in
            while !Task.isCancelled {
                guard let job = autoTypeNextJob(timeoutMs: 250) else { continue }
                guard let self else { return }
                let outcome = await self.perform(job)
                _ = autoTypeFinish(id: job.id, outcome: outcome)
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
        autoTypeSetReady(ready: false)
    }

    /// Verify and type one agent job.
    func perform(_ job: AutoTypeJobView) async -> AutoTypeOutcomeView {
        let target = Target(bundleId: job.bundleId, teamId: job.teamId, windowTitle: job.windowTitle)
        await waitForFrontmost(target.bundleId)
        return type(job.values.map { ($0.field, $0.value) }, into: target)
    }

    private func waitForFrontmost(_ bundleId: String) async {
        let deadline = ContinuousClock.now + activationWait
        while inspector.frontmost()?.bundleId != bundleId, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    // MARK: - Person-initiated

    /// Type `values` into whatever app comes to the front once kagisecure steps aside — the
    /// person's own auto-type (ADR-0050 §7). Never into kagisecure itself.
    func typeIntoFrontmost(_ values: [(AutoTypeFieldView, String)]) async -> AutoTypeOutcomeView {
        let own = Bundle.main.bundleIdentifier
        if NSApp.isActive { NSApp.hide(nil) }
        let deadline = ContinuousClock.now + activationWait
        var front = inspector.frontmost()
        while front?.bundleId == nil || front?.bundleId == own, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
            front = inspector.frontmost()
        }
        guard let bundleId = front?.bundleId, bundleId != own else { return .targetMismatch }
        // The app in front now is the target; nothing more to require of it.
        return type(values, into: Target(bundleId: bundleId, teamId: nil, windowTitle: nil))
    }

    /// Say why a person's auto-type typed nothing, in a system alert-free way: a beep and a log.
    static func notifyFailure(_ outcome: AutoTypeOutcomeView) {
        NSSound.beep()
        NSLog("kagisecure auto-type did not complete: %@", String(describing: outcome))
    }

    // MARK: - Typing

    /// What must be in front.
    struct Target: Equatable {
        var bundleId: String
        var teamId: String?
        var windowTitle: String?
    }

    /// Verify `target`, then type `values` in order with Tab between them.
    func type(_ values: [(AutoTypeFieldView, String)], into target: Target) -> AutoTypeOutcomeView {
        guard inspector.isTrusted else { return .accessibilityDenied }
        if inspector.secureInputActive() { return .secureInput }
        guard let front = inspector.frontmost(), matches(front, target) else { return .targetMismatch }
        guard let first = values.first, let focus = inspector.focusedElement(),
            accepts(focus, first.0)
        else { return .targetMismatch }

        var typedAny = false
        var current = focus
        for (index, (field, value)) in values.enumerated() {
            if index > 0 {
                poster.postKey(UInt16(kVK_Tab))
                typedAny = true
                // The next field is wherever Tab put focus: same app, and the right kind.
                guard let next = inspector.focusedElement(), stillTarget(target),
                    accepts(next, field)
                else { return .focusChanged(typedAny: typedAny) }
                current = next
            }
            var chunk = ""
            for character in value {
                chunk.append(character)
                if chunk.count >= Self.chunkSize {
                    poster.postText(chunk)
                    typedAny = true
                    chunk = ""
                    guard stillFocused(current, target) else { return .focusChanged(typedAny: true) }
                }
            }
            if !chunk.isEmpty {
                poster.postText(chunk)
                typedAny = true
                guard stillFocused(current, target) else { return .focusChanged(typedAny: true) }
            }
        }
        return .typed
    }

    private func matches(_ app: FrontmostApp, _ target: Target) -> Bool {
        guard app.bundleId == target.bundleId else { return false }
        if let team = target.teamId, app.teamId != team { return false }
        if let title = target.windowTitle {
            guard let window = app.windowTitle, window.localizedCaseInsensitiveContains(title) else {
                return false
            }
        }
        return true
    }

    private func accepts(_ element: FocusedElement, _ field: AutoTypeFieldView) -> Bool {
        switch field {
        case .password: element.isSecure
        case .username, .oneTimeCode: element.isTextInput
        }
    }

    private func stillTarget(_ target: Target) -> Bool {
        !inspector.secureInputActive() && inspector.frontmost().map { matches($0, target) } == true
    }

    private func stillFocused(_ element: FocusedElement, _ target: Target) -> Bool {
        stillTarget(target) && inspector.focusedElement()?.identity == element.identity
    }
}

// MARK: - Seams

/// The frontmost app, as the check needs it.
struct FrontmostApp: Equatable {
    var bundleId: String?
    var teamId: String?
    var windowTitle: String?
}

/// The element with keyboard focus.
struct FocusedElement: Equatable {
    /// Stable for one element: changes when focus moves.
    var identity: Int
    /// A text field, text area, combo box or search field.
    var isTextInput: Bool
    /// An `AXSecureTextField`.
    var isSecure: Bool
}

/// Reads the system's focus state. Faked in tests.
@MainActor
protocol FocusInspector {
    var isTrusted: Bool { get }
    func frontmost() -> FrontmostApp?
    func focusedElement() -> FocusedElement?
    func secureInputActive() -> Bool
}

/// Posts keystrokes. Faked in tests.
@MainActor
protocol KeystrokePoster {
    /// Type `text` as unicode keyboard events.
    func postText(_ text: String)
    /// Press and release one virtual key.
    func postKey(_ keyCode: UInt16)
}

/// The real inspector: NSWorkspace, the Accessibility API and the code-signing API.
struct SystemFocusInspector: FocusInspector {
    var isTrusted: Bool { AXIsProcessTrusted() }

    func frontmost() -> FrontmostApp? {
        guard let app = NSWorkspace.shared.frontmostApplication else { return nil }
        let element = AXUIElementCreateApplication(app.processIdentifier)
        var window: CFTypeRef?
        var title: String?
        if AXUIElementCopyAttributeValue(element, kAXFocusedWindowAttribute as CFString, &window) == .success,
            let window
        {
            var value: CFTypeRef?
            // swiftlint:disable:next force_cast
            if AXUIElementCopyAttributeValue(window as! AXUIElement, kAXTitleAttribute as CFString, &value) == .success {
                title = value as? String
            }
        }
        return FrontmostApp(
            bundleId: app.bundleIdentifier, teamId: Self.teamId(pid: app.processIdentifier), windowTitle: title)
    }

    func focusedElement() -> FocusedElement? {
        let system = AXUIElementCreateSystemWide()
        var focused: CFTypeRef?
        guard AXUIElementCopyAttributeValue(system, kAXFocusedUIElementAttribute as CFString, &focused) == .success,
            let focused
        else { return nil }
        // swiftlint:disable:next force_cast
        let element = focused as! AXUIElement
        var role: CFTypeRef?
        var subrole: CFTypeRef?
        AXUIElementCopyAttributeValue(element, kAXRoleAttribute as CFString, &role)
        AXUIElementCopyAttributeValue(element, kAXSubroleAttribute as CFString, &subrole)
        let roleName = role as? String ?? ""
        let secure = (subrole as? String) == (kAXSecureTextFieldSubrole as String)
        let text = secure
            || [kAXTextFieldRole, kAXTextAreaRole, kAXComboBoxRole].map { $0 as String }.contains(roleName)
        return FocusedElement(identity: Int(CFHash(element)), isTextInput: text, isSecure: secure)
    }

    func secureInputActive() -> Bool { IsSecureEventInputEnabled() }

    /// The Apple team that signed the process, from its dynamic code signature.
    static func teamId(pid: pid_t) -> String? {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
            == errSecSuccess
        else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }
}

/// The real poster: `CGEvent` keyboard events carrying unicode strings.
struct CGEventPoster: KeystrokePoster {
    func postText(_ text: String) {
        let units = Array(text.utf16)
        guard let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true),
            let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false)
        else { return }
        units.withUnsafeBufferPointer { buffer in
            down.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
            up.keyboardSetUnicodeString(stringLength: buffer.count, unicodeString: buffer.baseAddress)
        }
        down.post(tap: .cghidEventTap)
        up.post(tap: .cghidEventTap)
    }

    func postKey(_ keyCode: UInt16) {
        CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: true)?.post(tap: .cghidEventTap)
        CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: false)?.post(tap: .cghidEventTap)
    }
}
