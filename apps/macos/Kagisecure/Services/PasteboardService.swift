import AppKit
import Foundation

/// The one place anything reaches the clipboard, and the one place it is taken back off again.
///
/// # Why a service rather than two lines at each call site
///
/// A password on the general pasteboard is readable by every process on the machine for as long
/// as it sits there, and it survives into clipboard-manager history unless the writer opts out.
/// Both mitigations — the concealed-type marker and the timed clear — have to be applied at
/// *every* copy or they are worth nothing, so there is exactly one function that copies.
///
/// # The clear is conditional, on purpose
///
/// Clearing the pasteboard unconditionally after 60 seconds would throw away whatever the user
/// copied in the meantime. `NSPasteboard.changeCount` increments on every write by any process,
/// so the timer compares the count it recorded against the count it finds: if they differ, the
/// clipboard has moved on and is none of our business. This is the same rule 1Password and
/// KeePassXC use, and it is the difference between a security feature and a bug report.
@MainActor
enum PasteboardService {
    /// `UserDefaults` key for the clear delay in seconds. 0 disables the clear.
    static let clearSecondsKey = "pasteboardClearSeconds"
    /// The default delay, in seconds (ui-spec.md §11's "copy" actions; configurable in Settings).
    static let defaultClearSeconds = 60
    /// The choices Settings offers.
    static let clearSecondsChoices = [15, 30, 60, 120, 300, 0]

    /// The configured delay, or the default when the user has never chosen one.
    static var clearSeconds: Int {
        AppDefaults.shared.object(forKey: clearSecondsKey) as? Int ?? defaultClearSeconds
    }

    /// The most recent copy's description, for the transient confirmation the UI shows.
    private(set) static var lastCopied: String?

    /// A monotonically increasing token, so a view can react to "something was copied" without
    /// the label itself having to change.
    private(set) static var copyCount = 0

    /// Put a value on the clipboard, marked concealed, and schedule its removal.
    ///
    /// `label` is metadata — a field name — and is the only part of this that is ever displayed
    /// or logged. The value is not returned, not stored and not printed.
    static func copy(_ value: String, label: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        // `org.nspasteboard.ConcealedType` is the convention clipboard managers honour to keep a
        // password out of their searchable history. It costs nothing and is the difference
        // between a value living for 60 seconds and living in a database.
        pasteboard.setString(value, forType: .init("org.nspasteboard.ConcealedType"))
        pasteboard.setString(value, forType: .string)

        lastCopied = label
        copyCount += 1

        let seconds = clearSeconds
        guard seconds > 0 else { return }
        let stamp = pasteboard.changeCount
        // App Nap throttles timers in an application the user is not looking at — which is
        // exactly the situation here, because the point of copying a password is to go and paste
        // it somewhere else. Observed: a 60-second clear that had not fired after 90 seconds
        // while the app sat in the background. `beginActivity` opts this one countdown out.
        // `…AllowingIdleSystemSleep`, not `.userInitiated`: a clipboard timer is not a reason to
        // keep someone's Mac awake, and if the machine does sleep the vault locks anyway.
        let activity = ProcessInfo.processInfo.beginActivity(
            options: .userInitiatedAllowingIdleSystemSleep,
            reason: "clearing a copied secret from the clipboard")
        Task { @MainActor in
            defer { ProcessInfo.processInfo.endActivity(activity) }
            try? await Task.sleep(for: .seconds(Double(seconds)))
            clearIfUnchanged(since: stamp)
        }
    }

    /// Clear the pasteboard, but only if nothing has written to it since `stamp`.
    ///
    /// Exposed rather than private so the test target can drive it without waiting a minute.
    @discardableResult
    static func clearIfUnchanged(since stamp: Int) -> Bool {
        let pasteboard = NSPasteboard.general
        guard pasteboard.changeCount == stamp else { return false }
        pasteboard.clearContents()
        return true
    }

    /// A human sentence for the Settings pane and the copy confirmation.
    static func clearDescription(seconds: Int) -> String {
        switch seconds {
        case 0: "Never cleared"
        case 60: "Cleared after 1 minute"
        case let s where s % 60 == 0: "Cleared after \(s / 60) minutes"
        default: "Cleared after \(seconds) seconds"
        }
    }
}
