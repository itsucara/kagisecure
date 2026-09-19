import AppKit
import Carbon.HIToolbox
import Foundation

/// A system-wide keyboard shortcut, registered with Carbon's `RegisterEventHotKey`.
///
/// # Why Carbon, in 2026
///
/// There are two ways to notice a key combination while another app is frontmost, and only one of
/// them is free:
///
/// | Approach | Permission | What it sees |
/// | --- | --- | --- |
/// | `NSEvent.addGlobalMonitorForEvents(matching: .keyDown)` | **Input Monitoring** (TCC) | every keystroke on the machine |
/// | `RegisterEventHotKey` | none | one combination, and only when it is pressed |
///
/// The first is a password manager asking to watch the user type, which is the single most
/// alarming permission this app could request and the one it can least afford to normalise. The
/// second is the API the OS provides for exactly this, hands over nothing but "your shortcut
/// fired", and needs no prompt at all. That it lives in a framework called Carbon is an
/// aesthetic problem, not an engineering one — `RegisterEventHotKey` is not deprecated and is
/// what Spotlight-style panels in shipping apps still use. See ADR-0017.
///
/// If registration fails — almost always because another app already owns the combination — the
/// failure is reported rather than swallowed, so the UI can say "⇧⌘Space is taken" instead of
/// leaving the user pressing a dead shortcut.
@MainActor
final class GlobalHotKey {
    /// Why a registration did not take.
    enum Failure: Error, CustomStringConvertible {
        /// Another application already holds this combination.
        case alreadyRegistered
        /// Carbon refused for some other reason; the status code is included for a bug report.
        case osStatus(OSStatus)

        var description: String {
            switch self {
            case .alreadyRegistered:
                "another app already uses this shortcut"
            case .osStatus(let status):
                "the system refused to register it (error \(status))"
            }
        }
    }

    /// ⇧⌘Space, 1Password 8's Quick Access binding (ui-spec.md §7).
    static let quickAccess = (keyCode: UInt32(kVK_Space), modifiers: UInt32(cmdKey | shiftKey))

    /// Every live registration, keyed by the id the Carbon callback reports.
    ///
    /// A static table rather than a captured closure because the callback is `@convention(c)`
    /// and cannot capture anything at all.
    fileprivate static var handlers: [UInt32: () -> Void] = [:]
    private static var nextID: UInt32 = 1
    private static var eventHandler: EventHandlerRef?

    private var reference: EventHotKeyRef?
    private let id: UInt32

    /// Register `keyCode` + `modifiers` system-wide.
    ///
    /// - Throws: ``Failure`` when the combination is unavailable.
    init(keyCode: UInt32, modifiers: UInt32, action: @escaping () -> Void) throws {
        Self.installEventHandlerIfNeeded()
        id = Self.nextID
        Self.nextID += 1

        // A four-character signature is the Carbon convention; this one is "KGSC".
        let hotKeyID = EventHotKeyID(signature: 0x4B47_5343, id: id)
        var reference: EventHotKeyRef?
        let status = RegisterEventHotKey(
            keyCode, modifiers, hotKeyID, GetApplicationEventTarget(), 0, &reference)
        guard status == noErr, let reference else {
            throw status == OSStatus(eventHotKeyExistsErr)
                ? Failure.alreadyRegistered : Failure.osStatus(status)
        }
        self.reference = reference
        Self.handlers[id] = action
    }

    // There is deliberately no `deinit`. A `deinit` is nonisolated, and both pieces of state it
    // would want — the `EventHotKeyRef` (an `OpaquePointer`) and the handler table (main-actor,
    // holding non-`Sendable` closures) — are things Swift 6 will not let one touch. Teardown is
    // `unregister()` instead, called explicitly. Nothing leaks past the process: Carbon releases
    // every registration a process holds when it exits, and this app registers one shortcut once
    // and keeps it for its whole life.

    /// Give the shortcut back and forget its action.
    ///
    /// Not needed for the app's own single, process-lifetime registration; it exists so a test
    /// can register and release a combination without leaving it claimed.
    func unregister() {
        if let reference {
            UnregisterEventHotKey(reference)
            self.reference = nil
        }
        Self.handlers.removeValue(forKey: id)
    }

    private static func installEventHandlerIfNeeded() {
        guard eventHandler == nil else { return }
        var spec = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        var handler: EventHandlerRef?
        InstallEventHandler(
            GetApplicationEventTarget(), kagisecureHotKeyCallback, 1, &spec, nil, &handler)
        eventHandler = handler
    }

    /// Run the action registered for `id`. Called from the C callback, on the main actor.
    fileprivate static func fire(_ id: UInt32) {
        handlers[id]?()
    }
}

/// The C callback Carbon invokes. It cannot capture, cannot be a method and cannot touch
/// main-actor state directly, so it does the one thing it is allowed to do: read the hot-key id
/// out of the event and hop to the main actor.
private func kagisecureHotKeyCallback(
    _ next: EventHandlerCallRef?,
    _ event: EventRef?,
    _ userData: UnsafeMutableRawPointer?
) -> OSStatus {
    var hotKeyID = EventHotKeyID()
    let status = GetEventParameter(
        event,
        EventParamName(kEventParamDirectObject),
        EventParamType(typeEventHotKeyID),
        nil,
        MemoryLayout<EventHotKeyID>.size,
        nil,
        &hotKeyID)
    guard status == noErr else { return status }
    let id = hotKeyID.id
    DispatchQueue.main.async {
        MainActor.assumeIsolated { GlobalHotKey.fire(id) }
    }
    return noErr
}
