import Foundation
import Observation

/// Who a presence prompt is being raised for.
enum PresenceOwner: Equatable, Sendable {
    /// An approval the agent or the browser extension is waiting on — the sheet's Allow buttons
    /// and a presence-only fill (ADR-0037). Carries the request id.
    case approval(String)
    /// A value the app itself is about to show or copy (ADR-0038): a reveal, a copy, Quick Access,
    /// a one-time code, notes, a value shown to edit it.
    case release
    /// Enrolling Touch ID unlock (`AppModel.enrollTouchID`, ADR-0004, ADR-0011). This owner's
    /// prompt is not driven through `gate.authenticate` the way an approval's or a release's is —
    /// it is the Secure Enclave's own `SecKeyCreateRandomKey` prompt, which the coordinator's
    /// `LAContext`-based gate has no way to raise or own. Taking the slot for it anyway keeps the
    /// one-prompt invariant: a release or an approval that arrives while enrolment is in flight
    /// is refused, not shown beside a sheet the person is already looking at, and enrolment
    /// itself is refused if it arrives while something else holds the slot.
    case enrolment
    /// Turning on a switch that widens what an agent may ask for — today only "Let agents ask to
    /// fill logins in your browser" (`AgentFillService`, ADR-0036 §2, implementation decision 12).
    /// Turning one off never asks.
    case featureSwitch
}

/// The right to have the one presence prompt on screen. Handed out by
/// `PresenceCoordinator.begin(_:)`, spent by `PresenceCoordinator.authenticate(_:reason:)`.
struct PresenceTicket: Equatable, Sendable {
    /// A serial that is never reused, so a stale ticket cannot end somebody else's prompt.
    let token: UInt64
    let owner: PresenceOwner
}

/// One presence prompt on screen at a time, app-wide (ADR-0037 §3, extended by ADR-0038 §6).
///
/// # Why one, and why refused rather than queued
///
/// A Touch ID sheet does not say which of two requests a touch answers. Two prompts raised at
/// once — an automation agent's copy behind the person's own reveal, say — are one touch away
/// from the person answering the one they did not look at. So there is exactly one slot, and a
/// second request while it is taken is **refused**: a release answers `Busy` straight away, and
/// an approval sheet's Allow says another confirmation is in progress. Nothing is queued behind a
/// prompt, because a queue is exactly what would let a background attempt pile up behind a
/// legitimate one and ride the touch that follows it.
///
/// The one thing that *waits* is an approval the Rust queue already holds: a presence-only fill at
/// the head of `AgentService`'s queue is not raised while the slot is taken, and is raised when it
/// frees (`addIdleObserver`). That is not a second prompt queued behind the first — it is a
/// question that exists independently of any prompt, with its own 60-second expiry, that simply
/// is not asked until nothing else is being asked.
///
/// # A lock
///
/// `cancelInFlight()` asks the gate to invalidate the prompt that is up (a `LAContext` becomes
/// invalid and the system dismisses its sheet; the master-password fallback's panel closes). The
/// slot is **not** cleared by that call: it is cleared only when the prompt's own `authenticate`
/// returns, because until then the system may still be drawing the sheet, and a new prompt raised
/// beside it is the stacking this type exists to prevent (ADR-0037's `presencePrompt` rule, now
/// held for every prompt in the app rather than one kind).
///
/// # What it does not decide
///
/// Whether an outcome grants anything. That stays with each caller: `AgentService.allow` for an
/// approval, Rust's `settle_release` for a value. This type only makes sure there is never more
/// than one question on screen.
@MainActor
@Observable
final class PresenceCoordinator {
    /// What actually asks: `LocalAuthenticationGate` in the app, a double in tests and, under
    /// `#if DEBUG` and a launch argument only, `ScriptedBiometricGate` in the UI-test suite.
    var gate: BiometricGate

    /// The prompt that is up, if one is.
    private(set) var current: PresenceTicket?

    private var nextToken: UInt64 = 0
    private var idleObservers: [() -> Void] = []

    init(gate: BiometricGate = LocalAuthenticationGate()) {
        self.gate = gate
    }

    /// Whether a prompt is on screen.
    var isBusy: Bool { current != nil }

    // MARK: - The grace window (ADR-0037 amendment of 2026-10-03)

    /// The one app-wide grace window. Opened by any successful check, extended by every use,
    /// cleared on every lock (`clearGrace`, from `AgentService.stop()`).
    private(set) var grace = PresenceGrace()

    /// The clock the grace window is measured against. Replaceable for tests.
    var clock: () -> Date = { Date() }

    /// The window length. Read from `AppDefaults` on every check so a change in Settings applies
    /// at once. Replaceable for tests.
    var graceDuration: () -> PresenceGrace.Duration = { PresenceGrace.storedDuration() }

    /// Whether the grace window is open now.
    var graceIsOpen: Bool { grace.isOpen(at: clock(), duration: graceDuration()) }

    /// Open the window, or extend it (sliding).
    func touchGrace() {
        grace.touch(at: clock())
    }

    /// If the window is open, extend it and return `true`; otherwise `false`.
    func rideGrace() -> Bool {
        guard graceIsOpen else { return false }
        touchGrace()
        return true
    }

    /// Close the window — on every lock.
    func clearGrace() {
        grace.clear()
    }

    /// Take the slot for `owner`, or `nil` if a prompt is already up. Synchronous, so a caller
    /// that decides to ask and the slot it asks in cannot be separated by another caller's await.
    func begin(_ owner: PresenceOwner) -> PresenceTicket? {
        guard current == nil else { return nil }
        nextToken &+= 1
        let ticket = PresenceTicket(token: nextToken, owner: owner)
        current = ticket
        return ticket
    }

    /// Ask the gate, in the slot `ticket` holds, and give the slot up when the gate has answered.
    ///
    /// A ticket that is not the current one — never issued, or already spent — asks nothing and
    /// answers `.busy`: there is no way to reach the gate except through the slot.
    func authenticate(_ ticket: PresenceTicket, reason: String) async -> BiometricOutcome {
        let outcome = await ask(ticket, reason: reason)
        end(ticket)
        return outcome
    }

    /// Ask the gate in the slot `ticket` holds and **keep** the slot — for a holder with a second
    /// question to put before it is done (the master-password fallback, after the gate answered
    /// `.unavailable`). The holder must call `end(_:)`; `AppPresenceGate` does so in a `defer`.
    func ask(_ ticket: PresenceTicket, reason: String) async -> BiometricOutcome {
        guard current == ticket else { return .busy }
        return await gate.authenticate(reason: reason)
    }

    /// Give the slot up without asking — for a holder that decided not to ask after all, or that
    /// asked something other than the gate (the master-password fallback).
    func end(_ ticket: PresenceTicket) {
        guard current == ticket else { return }
        current = nil
        for observer in idleObservers { observer() }
    }

    /// Bumped by every `cancelInFlight()`. A holder captures it before asking and treats any
    /// answer that arrives after it changed as belonging to a vault that has since locked.
    private(set) var cancelGeneration: UInt64 = 0

    /// Tear down the prompt that is up — called when the vault locks. The slot stays taken until
    /// that prompt's own call returns (see the type's documentation).
    func cancelInFlight() {
        cancelGeneration &+= 1
        gate.cancelInFlight()
        for handler in cancelHandlers { handler() }
    }

    /// Called every time the slot frees. `AgentService` uses it to raise a presence-only fill that
    /// was waiting for the slot.
    func addIdleObserver(_ observer: @escaping () -> Void) {
        idleObservers.append(observer)
    }

    /// Called by `cancelInFlight()` alongside the gate, for a prompt that is not the gate's — the
    /// master-password fallback's panel.
    func addCancelHandler(_ handler: @escaping () -> Void) {
        cancelHandlers.append(handler)
    }

    private var cancelHandlers: [() -> Void] = []
}
