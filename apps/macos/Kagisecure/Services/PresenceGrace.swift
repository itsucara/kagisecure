import Foundation

import KagisecureFFI

/// The presence grace window (ADR-0037, amendments of 2026-09-27 and 2026-10-03).
///
/// # The rule
///
/// After **any** presence check succeeds — Touch ID, the login password or an Apple Watch, for a
/// fill, an agent fill, or an in-app reveal, copy, Quick Access or one-time code (ADR-0038) — one
/// global window opens. While it is open:
///
/// * an in-app release is granted without a prompt (`AppPresenceGate`);
/// * a browser fill or an agent fill is granted without a prompt, and an agent fill or a
///   presence-only fill without a sheet either (`AgentService`), unless the stricter
///   `agentFillRequiresSheetKey` setting is on.
///
/// The window is **sliding**: every use extends it. Its length is the user's setting
/// (`Duration`, stored under `durationKey`), "Until locked" by default.
///
/// # What closes it
///
/// Everything here is in memory. `AgentService.stop()` clears it, and that runs on every lock —
/// including the automatic ones on sleep, display sleep and screen lock — and a restart of the app
/// starts with none. A wall clock that moves backwards closes the window rather than stretching
/// it.
///
/// # What it costs
///
/// Inside the window, anything that can drive the app or the browser gets values without a person
/// touching anything (threat-model-browser-extension.md R-15). The owner chose that trade on
/// 2026-10-03: convenience first, with stricter values (a shorter window, a sheet for every agent
/// fill) kept as settings a future organization policy can enforce.
struct PresenceGrace {
    /// How long the window stays open after its last use.
    enum Duration: String, CaseIterable, Identifiable, Sendable {
        case tenMinutes
        case thirtyMinutes
        case oneHour
        case untilLocked

        var id: String { rawValue }

        /// The length in seconds, or `nil` for "until the vault locks".
        var seconds: TimeInterval? {
            switch self {
            case .tenMinutes: 10 * 60
            case .thirtyMinutes: 30 * 60
            case .oneHour: 60 * 60
            case .untilLocked: nil
            }
        }

        var label: String {
            switch self {
            case .tenMinutes: String(localized: "10 minutes")
            case .thirtyMinutes: String(localized: "30 minutes")
            case .oneHour: String(localized: "1 hour")
            case .untilLocked: String(localized: "Until locked")
            }
        }
    }

    /// The `AppDefaults` key the window length is stored under.
    static let durationKey = "presenceGraceDuration"

    /// The `AppDefaults` key for the stricter behavior: show the agent-fill sheet even while the
    /// window is open. Off by default.
    static let agentFillRequiresSheetKey = "agentFillRequiresSheet"

    static let defaultDuration: Duration = .untilLocked

    /// The stored window length, or the default.
    static func storedDuration(_ defaults: UserDefaults = AppDefaults.shared) -> Duration {
        defaults.string(forKey: durationKey).flatMap(Duration.init(rawValue:)) ?? defaultDuration
    }

    /// What a sheet says above its buttons while its Allow would ride the window.
    static let sheetCaption = String(
        localized: "You confirmed with Touch ID or your login password recently, so allowing this will not ask again until the vault locks or the grace period ends.")

    /// When the window was last opened or used.
    private(set) var lastUse: Date?

    /// Whether nothing is remembered.
    var isEmpty: Bool { lastUse == nil }

    /// Whether the grace can apply to `request` at all: a browser fill or an agent fill.
    static func applies(to request: ApprovalRequestView) -> Bool {
        switch request.action {
        case .fillCredential, .agentFill: true
        case .writeEnvFile, .runWithEnv, .createEnvironment, .addVariables: false
        }
    }

    /// Open the window, or extend it, at `now`.
    mutating func touch(at now: Date) {
        lastUse = now
    }

    /// Whether the window is open at `now` for a window of `duration`.
    func isOpen(at now: Date, duration: Duration) -> Bool {
        guard let lastUse else { return false }
        let elapsed = now.timeIntervalSince(lastUse)
        guard elapsed >= 0 else { return false }
        guard let seconds = duration.seconds else { return true }
        return elapsed < seconds
    }

    /// Forget everything — on a lock.
    mutating func clear() {
        lastUse = nil
    }
}
