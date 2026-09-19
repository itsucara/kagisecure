import AppKit
import Foundation

/// Locks the vault on idle, sleep and screen lock (ui-spec.md §6.2, ADR-0004 "common rules").
///
/// Three unconditional triggers and one configurable one. The unconditional ones are notifications
/// the system posts; the idle timer is ours, driven by a repeating check against
/// `CGEventSource.secondsSinceLastEventType`, which measures *system-wide* input idleness rather
/// than "our window lost focus" — locking because the user switched to their editor for eleven
/// minutes while actively typing would be wrong, and a plain `Timer` reset on our own events would
/// do exactly that.
@MainActor
final class AutoLockCoordinator {
    /// Idle timeout in minutes; 0 disables the idle trigger. Sleep and screen lock are never
    /// disabled — those are not preferences.
    static let idleMinutesKey = "autoLockIdleMinutes"
    static let defaultIdleMinutes = 10

    private let onLock: (LockReason) -> Void
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []

    init(onLock: @escaping (LockReason) -> Void) {
        self.onLock = onLock
    }

    // No `deinit` cleanup: `stop()` is what removes the observers, and a `nonisolated deinit`
    // cannot touch main-actor state. The coordinator lives as long as `AppModel` does, and
    // `lock(reason:)` calls `stop()` on every path that ends a session, so there is nothing left
    // to tear down by the time this is deallocated.

    static var idleMinutes: Int {
        let stored = AppDefaults.shared.object(forKey: idleMinutesKey) as? Int
        return stored ?? defaultIdleMinutes
    }

    func start() {
        stop()
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(
            workspace.addObserver(
                forName: NSWorkspace.willSleepNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.onLock(.sleep) }
            })
        observers.append(
            workspace.addObserver(
                forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.onLock(.screenLock) }
            })
        // The screen *lock* is a distributed notification, not a workspace one, and it is the
        // trigger that matters most: a locked screen with an unlocked vault behind it is the
        // situation ADR-0004 rule 4 exists to prevent.
        observers.append(
            DistributedNotificationCenter.default().addObserver(
                forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.onLock(.screenLock) }
            })

        let minutes = Self.idleMinutes
        guard minutes > 0 else { return }
        let deadline = Double(minutes) * 60
        // Checking four times a minute bounds the overshoot at fifteen seconds, which is well
        // inside the resolution anyone configuring this in whole minutes cares about.
        let timer = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                if Self.systemIdleSeconds() >= deadline {
                    self.onLock(.idle)
                }
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        for observer in observers {
            DistributedNotificationCenter.default().removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        observers.removeAll()
    }

    /// Seconds since the last keyboard or pointer event anywhere on the system.
    static func systemIdleSeconds() -> Double {
        let keyboard = CGEventSource.secondsSinceLastEventType(
            .hidSystemState, eventType: .keyDown)
        let mouse = CGEventSource.secondsSinceLastEventType(
            .hidSystemState, eventType: .mouseMoved)
        return min(keyboard, mouse)
    }
}
