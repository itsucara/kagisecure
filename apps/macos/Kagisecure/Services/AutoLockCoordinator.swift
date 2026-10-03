import AppKit
import Foundation

/// Locks the vault on idle, sleep and screen lock (ui-spec.md §6.2, ADR-0004 "common rules").
///
/// Three unconditional triggers and one configurable one. The unconditional ones are notifications
/// the system posts; the idle timer is ours, and it is driven by the *minimum* of three
/// measurements (docs/investigations/2026-09-27-remote-idle-relock.md):
///
/// - `systemIdleSeconds()`, from `CGEventSource.secondsSinceLastEventType` — system-wide input
///   idleness. Locking because the user switched to their editor for eleven minutes while actively
///   typing there would be wrong, and a timer that only reset on our own window's events would do
///   exactly that, so system-wide idleness always stays part of the answer.
/// - Time since this session's own successful unlock. `systemIdleSeconds()` measures time since the
///   machine last saw *any* physical key or click, which can already be hours in the past the
///   moment someone unlocks — over accessibility- or remote-control-driven input, which does not
///   feed the HID event stream at all. Without a floor at the unlock itself, the very next
///   15-second check could end a session that had just begun.
/// - Time since the last *in-app* activity: an `NSEvent` local monitor for key, mouse and scroll
///   events in the app's own windows (installed by `start()`), plus every explicit vault operation
///   reported through `noteInAppActivity()` — a reveal, a copy, a save, and so on. This is what
///   keeps a session alive across accessibility/remote-control input for as long as it continues,
///   since that input never moves the system-wide HID counters.
///
/// The idle trigger only fires once every one of the three says the person has been away for the
/// configured timeout.
@MainActor
final class AutoLockCoordinator {
    /// Idle timeout in minutes; 0 disables the idle trigger. Sleep and screen lock are never
    /// disabled — those are not preferences.
    static let idleMinutesKey = "autoLockIdleMinutes"
    static let defaultIdleMinutes = 10

    private let onLock: (LockReason) -> Void
    /// The clock. Injected by tests; real callers get the wall clock.
    private let now: () -> Date
    /// `systemIdleSeconds()`, or a fake for tests that would otherwise depend on the real keyboard
    /// and mouse.
    private let idleSecondsProvider: () -> Double
    /// The distributed notification that means the screen locked. Always the real
    /// `com.apple.screenIsLocked` in the app; a test passes a name of its own so it never has to
    /// post the real one, which `distnoted` would deliver machine-wide — to every other
    /// `AutoLockCoordinator` on the Mac, including a real, running app (see
    /// `AutoLockAdversarialTests`).
    private let screenLockNotificationName: String
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var activityMonitor: Any?

    /// When this session's successful unlock happened, per `now()`. `nil` before `start()` and
    /// after `stop()`.
    private var unlockedAt: Date?
    /// The most recent in-app activity — an event in one of our own windows, or an explicit
    /// `noteInAppActivity()` call. `start()` sets this equal to `unlockedAt`, so a session with no
    /// activity yet is exactly as fresh as its unlock: neither more idle nor less.
    private var lastActivityAt: Date?

    init(
        onLock: @escaping (LockReason) -> Void,
        now: @escaping () -> Date = Date.init,
        idleSecondsProvider: @escaping () -> Double = AutoLockCoordinator.systemIdleSeconds,
        screenLockNotificationName: String = "com.apple.screenIsLocked"
    ) {
        self.onLock = onLock
        self.now = now
        self.idleSecondsProvider = idleSecondsProvider
        self.screenLockNotificationName = screenLockNotificationName
    }

    // No `deinit` cleanup: `stop()` is what removes the observers and the activity monitor, and a
    // `nonisolated deinit` cannot touch main-actor state. The coordinator lives as long as
    // `AppModel` does, and `lock(reason:)` calls `stop()` on every path that ends a session, so
    // there is nothing left to tear down by the time this is deallocated.

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
                forName: .init(screenLockNotificationName), object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.onLock(.screenLock) }
            })

        // A fresh baseline for this session: no time before this instant counts against it, and no
        // in-app activity has happened yet either — see the type's doc comment.
        let started = now()
        unlockedAt = started
        lastActivityAt = started

        // System-wide HID idleness cannot see remote-control or accessibility-driven input, so
        // real interaction with our own windows is tracked independently and always wins over a
        // stale HID reading. A *local* monitor only ever sees events in this app's own windows —
        // typing in another app must not read as "still here" (see the type's doc comment).
        activityMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [
                .keyDown, .keyUp, .leftMouseDown, .rightMouseDown, .otherMouseDown,
                .leftMouseDragged, .rightMouseDragged, .otherMouseDragged, .mouseMoved,
                .scrollWheel,
            ]
        ) { [weak self] event in
            self?.noteInAppActivity()
            return event
        }

        let minutes = Self.idleMinutes
        guard minutes > 0 else { return }
        let deadline = Double(minutes) * 60
        // Checking four times a minute bounds the overshoot at fifteen seconds, which is well
        // inside the resolution anyone configuring this in whole minutes cares about.
        let timer = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.checkIdle(deadline: deadline)
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        if let activityMonitor {
            NSEvent.removeMonitor(activityMonitor)
        }
        activityMonitor = nil
        unlockedAt = nil
        lastActivityAt = nil
        for observer in observers {
            DistributedNotificationCenter.default().removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        observers.removeAll()
    }

    /// Record in-app activity — the same as a keystroke or a click in one of our own windows.
    ///
    /// Called by the local event monitor `start()` installs, and by call sites elsewhere
    /// (`VaultStore`, `ItemReleases`) for vault operations that can be driven without necessarily
    /// producing a fresh local `NSEvent` first — a reveal, a copy, a save. A no-op before `start()`
    /// or after `stop()`, so a stray call against a locked/never-started coordinator cannot
    /// resurrect a session that no longer exists.
    func noteInAppActivity() {
        guard unlockedAt != nil else { return }
        lastActivityAt = now()
    }

    /// The idle check the 15-second timer runs: lock only once the HID idle time, the time since
    /// unlock, and the time since the last in-app activity all reach `deadline`.
    private func checkIdle(deadline: Double) {
        if effectiveIdleSeconds() >= deadline {
            onLock(.idle)
        }
    }

    /// `min(systemIdle, timeSinceUnlock, timeSinceLastInAppActivity)`. `.infinity` for a
    /// measurement that has no baseline yet (the coordinator was never started), which never wins
    /// the minimum against a real reading.
    private func effectiveIdleSeconds() -> Double {
        let current = now()
        let sinceUnlock = unlockedAt.map { current.timeIntervalSince($0) } ?? .infinity
        let sinceActivity = lastActivityAt.map { current.timeIntervalSince($0) } ?? .infinity
        return min(idleSecondsProvider(), sinceUnlock, sinceActivity)
    }

    /// Runs the same check the real 15-second `Timer` runs. Exposed (rather than left behind the
    /// timer alone) so tests can drive it deterministically against an injected clock instead of
    /// waiting on a real `Timer` on the run loop.
    func triggerIdleCheckForTesting() {
        let minutes = Self.idleMinutes
        guard minutes > 0 else { return }
        checkIdle(deadline: Double(minutes) * 60)
    }

    /// Seconds since the last keyboard or pointer event anywhere on the system.
    ///
    /// `nonisolated`: it touches no actor state, only `CGEventSource`, and needs to be usable as a
    /// plain `() -> Double` value — the `idleSecondsProvider` default — without dragging
    /// `@MainActor` isolation into that closure's type.
    nonisolated static func systemIdleSeconds() -> Double {
        let keyboard = CGEventSource.secondsSinceLastEventType(
            .hidSystemState, eventType: .keyDown)
        let mouse = CGEventSource.secondsSinceLastEventType(
            .hidSystemState, eventType: .mouseMoved)
        return min(keyboard, mouse)
    }
}
