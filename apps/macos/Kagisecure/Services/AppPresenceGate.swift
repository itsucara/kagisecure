import Foundation

import KagisecureFFI

/// The app's `PresenceGate` (ADR-0038 §6): what Rust awaits before it releases any value to the
/// app — a reveal, a copy, Quick Access, a one-time code, notes, a value shown to edit it.
///
/// Installed once on every session, at unlock (`AppModel.adopt`), with
/// `VaultSession.setPresenceGate`; Rust refuses a second install, so nothing that runs later can
/// swap in a gate that always says yes. With none installed every release fails closed.
///
/// # What it asks
///
/// `LocalAuthentication`'s `.deviceOwnerAuthentication` — Touch ID, an Apple Watch or the Mac's
/// login password — through `PresenceCoordinator`, the app-wide one-prompt-at-a-time slot shared
/// with the approval flow (ADR-0037). The coordinator's gate is `LocalAuthenticationGate`, which
/// builds a **fresh `LAContext` for every call** and never sets a reuse duration, so one touch can
/// never pay for a later, unrelated release. `reason` is Rust's sentence, built from vault facts
/// and sanitised there; it is shown as it is.
///
/// # The grace window
///
/// While the app-wide grace window is open (`PresenceGrace`, ADR-0037 amendment of 2026-10-03)
/// nothing is asked and the release is confirmed; a successful check opens or extends the window.
///
/// # When `LocalAuthentication` cannot run (user decision 7)
///
/// The gate answering `.unavailable` — no passcode set, a policy that refuses, a session with no
/// window server — falls back to the vault's master password, typed into the app's own panel
/// (`MasterPasswordFallback`) and checked by Rust (`verifyMasterPassword`, rate limited there).
/// The slot stays taken for the whole of it: the fallback is a prompt like any other, and no
/// second one is raised beside it. Rust records a grant reached this way
/// `PRESENCE_CONFIRMED_MASTER_PASSWORD`, from its own knowledge of the check, not from anything
/// this type claims.
///
/// # A lock
///
/// `PresenceCoordinator.cancelInFlight()` invalidates the `LAContext` and closes the fallback
/// panel, so the prompt goes away with the vault; whatever it answers afterwards, Rust has already
/// recorded the release `VAULT_LOCKED` and hands nothing out. An answer that comes back after a
/// lock is also reported here as `.cancelled`, belt and braces.
final class AppPresenceGate: PresenceGate {
    private let confirmOnMain: @MainActor @Sendable (String) async -> PresenceOutcome

    /// - Parameters:
    ///   - coordinator: the app-wide prompt slot.
    ///   - fallback: the master-password panel, for when the gate cannot run.
    ///   - session: the session this gate is installed on — held weakly, because the session holds
    ///     this gate and a strong reference back would keep a locked vault's object alive.
    @MainActor
    init(
        coordinator: PresenceCoordinator, fallback: MasterPasswordFallback, session: VaultSession
    ) {
        let weakSession = WeakSession(session)
        confirmOnMain = { reason in
            await Self.confirm(
                reason: reason, coordinator: coordinator, fallback: fallback,
                session: weakSession.value)
        }
    }

    func confirm(reason: String) async -> PresenceOutcome {
        await confirmOnMain(reason)
    }

    @MainActor
    private static func confirm(
        reason: String, coordinator: PresenceCoordinator, fallback: MasterPasswordFallback,
        session: VaultSession?
    ) async -> PresenceOutcome {
        // Inside the grace window (ADR-0037 amendment of 2026-10-03): no prompt, and the use
        // extends the window.
        if coordinator.rideGrace() { return .confirmed }
        // One prompt at a time, app-wide: refused, not queued.
        guard let ticket = coordinator.begin(.release) else { return .busy }
        defer { coordinator.end(ticket) }
        let generation = coordinator.cancelGeneration
        let outcome: PresenceOutcome
        switch await coordinator.ask(ticket, reason: reason) {
        case .authenticated:
            outcome = .confirmed
        case .cancelled:
            outcome = .cancelled
        case .busy:
            outcome = .busy
        case .unavailable:
            guard let session, session.isUnlocked(),
                coordinator.cancelGeneration == generation
            else { return .unavailable }
            outcome =
                await fallback.ask(reason: reason, session: session)
                ? .confirmed : .cancelled
        }
        // A lock while the prompt was up: whatever it answered belongs to a vault that is gone.
        guard coordinator.cancelGeneration == generation else { return .cancelled }
        if outcome == .confirmed { coordinator.touchGrace() }
        return outcome
    }
}

/// A weak reference to a session that can cross into a `@Sendable` closure.
private final class WeakSession: @unchecked Sendable {
    // Written once, in `init`; `weak` so the gate never keeps a locked session alive.
    private(set) weak var value: VaultSession?

    init(_ value: VaultSession) {
        self.value = value
    }
}
