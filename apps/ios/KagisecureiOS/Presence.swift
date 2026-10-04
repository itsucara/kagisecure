import Foundation
import KagisecureFFI
import LocalAuthentication

/// A fresh presence check for every reveal and copy (ADR-0038): no reuse window — the Mac's
/// grace period applies to fills only, which iOS does not have yet.
protocol PresenceChecking: Sendable {
    func check(reason: String) async -> PresenceOutcome
}

struct LocalAuthenticationPresence: PresenceChecking {
    func check(reason: String) async -> PresenceOutcome {
        let context = LAContext()
        context.localizedCancelTitle = String(localized: "Cancel")
        var probe: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &probe) else {
            return .unavailable
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication, localizedReason: reason) ? .confirmed : .cancelled
        } catch {
            return .cancelled
        }
    }
}

struct ScriptedPresence: PresenceChecking {
    let outcome: PresenceOutcome
    func check(reason: String) async -> PresenceOutcome { outcome }
}

/// The gate installed on every session before anything can be released.
final class AppPresenceGate: PresenceGate {
    let checker: any PresenceChecking
    init(checker: any PresenceChecking) { self.checker = checker }
    func confirm(reason: String) async -> PresenceOutcome { await checker.check(reason: reason) }
}
