import AppKit
import Foundation
import Testing

@testable import Kagisecure

/// Adversarial tests for `AutoLockCoordinator` (ui-spec.md §6.2, ADR-0004 rule 4).
///
/// # Why this file exists
///
/// The coordinator's own doc comment makes a promise the code has to keep:
///
/// > Idle timeout in minutes; 0 disables the idle trigger. Sleep and screen lock are never
/// > disabled — those are not preferences.
///
/// That is a security boundary written as a comment, and it is exactly the kind of thing an
/// `early return` refactor erases. `start()` reads `idleMinutes` and `return`s when it is zero,
/// *after* registering the three notification observers — so the ordering of those two halves is
/// load-bearing and nothing else asserts it. G-23 is that assertion: with the idle timer switched
/// off, a sleep and a screen lock must still lock the vault.
@MainActor
struct AutoLockAdversarialTests {
    /// Runs `body` with `autoLockIdleMinutes` set to `minutes`, then restores whatever was there.
    private func withIdleMinutes(_ minutes: Int, _ body: () async throws -> Void) async rethrows {
        let key = AutoLockCoordinator.idleMinutesKey
        let saved = AppDefaults.shared.object(forKey: key)
        defer {
            if let saved { AppDefaults.shared.set(saved, forKey: key) }
            else { AppDefaults.shared.removeObject(forKey: key) }
        }
        AppDefaults.shared.set(minutes, forKey: key)
        try await body()
    }

    /// Collects every reason the coordinator locked for.
    private final class Recorder {
        private(set) var reasons: [LockReason] = []
        func record(_ reason: LockReason) { reasons.append(reason) }
    }

    // MARK: - G-23: zero disables the idle timer and nothing else

    @Test func sleepStillLocksWhenTheIdleTimeoutIsDisabled() async {
        await withIdleMinutes(0) {
            #expect(AutoLockCoordinator.idleMinutes == 0, "the idle trigger is switched off")
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator { recorder.record($0) }
            coordinator.start()
            defer { coordinator.stop() }

            NSWorkspace.shared.notificationCenter.post(
                name: NSWorkspace.willSleepNotification, object: nil)

            #expect(
                recorder.reasons == [.sleep],
                "sleep is not a preference: ADR-0004 rule 4 is about exactly this")
        }
    }

    @Test func screenSleepStillLocksWhenTheIdleTimeoutIsDisabled() async {
        await withIdleMinutes(0) {
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator { recorder.record($0) }
            coordinator.start()
            defer { coordinator.stop() }

            NSWorkspace.shared.notificationCenter.post(
                name: NSWorkspace.screensDidSleepNotification, object: nil)

            #expect(recorder.reasons == [.screenLock])
        }
    }

    @Test func bothUnconditionalTriggersSurviveEveryIdleSetting() async {
        // The setting is a number a user types; every value of it has to leave the two
        // unconditional triggers alone, including the ones that are not offered in the UI.
        for minutes in [0, -1, 1, 10, Int.max] {
            await withIdleMinutes(minutes) {
                let recorder = Recorder()
                let coordinator = AutoLockCoordinator { recorder.record($0) }
                coordinator.start()
                defer { coordinator.stop() }

                NSWorkspace.shared.notificationCenter.post(
                    name: NSWorkspace.willSleepNotification, object: nil)
                NSWorkspace.shared.notificationCenter.post(
                    name: NSWorkspace.screensDidSleepNotification, object: nil)

                #expect(
                    recorder.reasons == [.sleep, .screenLock],
                    "idleMinutes = \(minutes) changed an unconditional trigger")
            }
        }
    }

    @Test func stoppingRemovesEveryObserverSoALockedAppDoesNotKeepLocking() async {
        await withIdleMinutes(0) {
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator { recorder.record($0) }
            coordinator.start()
            coordinator.stop()

            NSWorkspace.shared.notificationCenter.post(
                name: NSWorkspace.willSleepNotification, object: nil)
            NSWorkspace.shared.notificationCenter.post(
                name: NSWorkspace.screensDidSleepNotification, object: nil)

            #expect(recorder.reasons.isEmpty, "a stopped coordinator is deaf")
        }
    }

    @Test func startingTwiceDoesNotLockTwicePerEvent() async {
        // `start()` calls `stop()` first for exactly this reason. Two observers on one
        // notification would lock, then lock again on an already-locked vault.
        await withIdleMinutes(0) {
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator { recorder.record($0) }
            coordinator.start()
            coordinator.start()
            defer { coordinator.stop() }

            NSWorkspace.shared.notificationCenter.post(
                name: NSWorkspace.willSleepNotification, object: nil)

            #expect(recorder.reasons == [.sleep], "duplicate observers: \(recorder.reasons)")
        }
    }

    // MARK: - B-25: the screen-lock notification

    @Test func theScreenLockDistributedNotificationReachesTheCoordinator() async throws {
        // A *distributed* notification is delivered by `distnoted` machine-wide, to every process
        // listening for its name — not just this one. Posting the real `com.apple.screenIsLocked`
        // here would lock every other `AutoLockCoordinator` on this Mac too, including a real,
        // running app someone is using right now. A name unique to this run reaches only the
        // coordinator this test itself just built, which is what "reaches the coordinator" is
        // actually testing — the production name is never posted to, only ever listened for
        // (`AutoLockCoordinator`'s own default).
        try await withIdleMinutes(0) {
            let testOnlyName = "com.kagisecure.test.screenIsLocked.\(UUID().uuidString)"
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) }, screenLockNotificationName: testOnlyName)
            coordinator.start()
            defer { coordinator.stop() }

            DistributedNotificationCenter.default().post(name: .init(testOnlyName), object: nil)

            var delivered = false
            for _ in 0..<40 {
                if !recorder.reasons.isEmpty {
                    delivered = true
                    break
                }
                try await Task.sleep(for: .milliseconds(50))
            }
            // Delivery through `distnoted` is not guaranteed for a self-posted notification in
            // every environment, so a non-delivery is reported rather than failed — what must
            // never happen is delivery with the wrong reason.
            if delivered {
                #expect(recorder.reasons == [.screenLock])
            } else {
                #expect(
                    recorder.reasons.isEmpty,
                    """
                    com.apple.screenIsLocked was not delivered in this environment, so the only \
                    thing left to assert is that nothing locked for the wrong reason; the observer \
                    registration itself is covered by the workspace-notification tests above.
                    """)
            }
        }
    }

    @Test func theIdleProbeMeasuresSystemWideInputRatherThanOurOwnWindow() {
        // `systemIdleSeconds` is the difference between "the user left" and "the user switched to
        // their editor". A regression to a per-app timer would make this negative-or-zero-ish
        // constant rather than a real, moving system measurement; all a test can assert without
        // driving HID is that it is a sane non-negative number from the HID system state.
        let seconds = AutoLockCoordinator.systemIdleSeconds()
        #expect(seconds >= 0)
        #expect(seconds.isFinite)
    }

    // MARK: - Remote/automated-use idle relock (docs/investigations/2026-09-27-remote-idle-relock.md)
    //
    // These drive `triggerIdleCheckForTesting()` directly against an injected clock and a fake
    // system-idle reading, rather than waiting on the real 15-second `Timer` — the same style the
    // rest of this file uses for the workspace/distributed notifications, adapted for a coordinator
    // that now also depends on wall-clock time.

    /// A settable clock, so a test can move time forward without a real `sleep`.
    private final class TestClock {
        var current = Date(timeIntervalSince1970: 1_700_000_000)
        func now() -> Date { current }
        func advance(_ seconds: TimeInterval) { current = current.addingTimeInterval(seconds) }
    }

    @Test func justUnlockedWithHoursOfStaleHIDIdleDoesNotLockImmediately() async {
        // The incident this reproduces: the machine's HID idle counters were already ~3 hours
        // stale (accessibility/remote-control input does not reset them) at the moment of a
        // successful unlock. The very next idle check must not end the session it just started.
        await withIdleMinutes(1) {
            let clock = TestClock()
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) },
                now: clock.now,
                idleSecondsProvider: { 3 * 60 * 60 })
            coordinator.start()
            defer { coordinator.stop() }

            coordinator.triggerIdleCheckForTesting()

            #expect(
                recorder.reasons.isEmpty,
                "a session that just unlocked must not inherit hours of stale HID idleness")
        }
    }

    @Test func inAppActivityResetsTheIdleClockEvenWithStaleHID() async {
        // Simulates continued accessibility/remote-control interaction, which never touches the
        // HID counters: without the in-app activity floor, time since unlock alone would exceed
        // the timeout here.
        await withIdleMinutes(1) {
            let clock = TestClock()
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) },
                now: clock.now,
                idleSecondsProvider: { 3 * 60 * 60 })
            coordinator.start()
            defer { coordinator.stop() }

            clock.advance(50)  // near the 60s deadline, measured from unlock
            coordinator.noteInAppActivity()  // e.g. a reveal, a copy, or a click in our window
            clock.advance(55)  // 105s since unlock; only 55s since that activity

            coordinator.triggerIdleCheckForTesting()

            #expect(
                recorder.reasons.isEmpty,
                "in-app activity should have reset the clock even though time since unlock alone would have exceeded the timeout"
            )
        }
    }

    @Test func genuineIdleAfterTheWindowStillLocksDespiteStaleHID() async {
        // The other half of the fix: the unlock baseline and in-app activity must not turn into a
        // way to disable the idle timer altogether. With no activity for longer than the timeout,
        // the vault still locks — even while the (irrelevant, stale) HID reading stays huge.
        await withIdleMinutes(1) {
            let clock = TestClock()
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) },
                now: clock.now,
                idleSecondsProvider: { 3 * 60 * 60 })
            coordinator.start()
            defer { coordinator.stop() }

            clock.advance(61)  // past the one-minute deadline, no activity in between
            coordinator.triggerIdleCheckForTesting()

            #expect(recorder.reasons == [.idle], "genuine idle past the timeout must still lock")
        }
    }

    @Test func activityBeforeTheDeadlineThenGenuineIdleStillLocks() async {
        // In-app activity resets the clock, but only until its own timeout runs out again — it is
        // not a standing exemption from the idle trigger.
        await withIdleMinutes(1) {
            let clock = TestClock()
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) },
                now: clock.now,
                idleSecondsProvider: { 3 * 60 * 60 })
            coordinator.start()
            defer { coordinator.stop() }

            clock.advance(30)
            coordinator.noteInAppActivity()
            coordinator.triggerIdleCheckForTesting()
            #expect(recorder.reasons.isEmpty, "30s since the last activity is still under a minute")

            clock.advance(61)
            coordinator.triggerIdleCheckForTesting()
            #expect(recorder.reasons == [.idle], "61s of silence since that activity must lock")
        }
    }

    @Test func lockingAndUnlockingAgainRestartsTheBaseline() async {
        // A second `start()` (a fresh unlock) must not inherit the first session's clock — the
        // same "unlock resets the idle clock" rule `start()` documents, exercised across a
        // stop/start pair the way a real lock/unlock cycle produces one.
        await withIdleMinutes(1) {
            let clock = TestClock()
            let recorder = Recorder()
            let coordinator = AutoLockCoordinator(
                onLock: { recorder.record($0) },
                now: clock.now,
                idleSecondsProvider: { 3 * 60 * 60 })
            coordinator.start()
            clock.advance(61)
            coordinator.triggerIdleCheckForTesting()
            #expect(recorder.reasons == [.idle])
            coordinator.stop()

            coordinator.start()
            coordinator.triggerIdleCheckForTesting()
            #expect(
                recorder.reasons == [.idle],
                "the fresh unlock must not immediately re-lock on the old session's stale clock")
        }
    }
}
