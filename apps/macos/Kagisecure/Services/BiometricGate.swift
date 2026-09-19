import Foundation
import LocalAuthentication

/// The result of asking for a fingerprint.
enum BiometricOutcome: Equatable {
    /// The user authenticated.
    case authenticated
    /// The user cancelled, or fell back and then cancelled. **Not** a denial: ui-spec.md §10.3
    /// says a fumbled fingerprint must return to the approval dialog rather than be mistaken for
    /// a policy decision.
    case cancelled
    /// The gate could not run at all, with a reason to show.
    case unavailable(String)
}

/// Whatever asks the human for a fingerprint before an approval is granted.
///
/// A protocol rather than a direct `LAContext` call for one reason: the approval view model is
/// the piece of this app with real logic in it — decision mapping, TTL clamping, what a cancelled
/// biometric means — and none of that is testable if the only way to reach it is a system sheet
/// nobody can drive from XCTest. `TestBiometricGate` in the test bundle is the double.
protocol BiometricGate: Sendable {
    /// Whether a biometric or password prompt can be raised at all.
    func isAvailable() -> Bool

    /// Ask, with `reason` as the sheet's explanation. Returns on the calling task's actor.
    func authenticate(reason: String) async -> BiometricOutcome
}

/// The real gate: `LAContext.evaluatePolicy`.
///
/// # Why this works where the Secure Enclave does not
///
/// [ADR-0011](../../../../docs/decisions/0011-secure-enclave-under-ad-hoc-signing.md) records that
/// filing a Secure Enclave key in the keychain needs `keychain-access-groups`, hence a
/// provisioning profile, hence an Apple Developer account — so Touch ID *unlock* degrades to the
/// password slot on an ad-hoc-signed build.
///
/// `evaluatePolicy` is a different API with a different requirement: it needs **no entitlement**.
/// It does not hand back key material, it answers a yes/no about the person at the keyboard, and
/// that is exactly what an approval gate is. So the approval sheet's Touch ID is real on every
/// build, including this one, even though the unlock screen's is not.
///
/// `.deviceOwnerAuthentication` rather than `.deviceOwnerAuthenticationWithBiometrics`: the former
/// falls back to the login password on a Mac with no Touch ID, or with a finger that will not
/// read, which is the difference between "approve with your password" and "you cannot approve".
struct LocalAuthenticationGate: BiometricGate {
    /// The policy to evaluate. Injected so the availability probe and the evaluation cannot
    /// disagree about which one is being asked for.
    var policy: LAPolicy = .deviceOwnerAuthentication

    func isAvailable() -> Bool {
        LAContext().canEvaluatePolicy(policy, error: nil)
    }

    func authenticate(reason: String) async -> BiometricOutcome {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var probe: NSError?
        guard context.canEvaluatePolicy(policy, error: &probe) else {
            return .unavailable(probe?.localizedDescription ?? "no authentication method available")
        }
        do {
            let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
            return ok ? .authenticated : .cancelled
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                return .cancelled
            default:
                return .unavailable(error.localizedDescription)
            }
        } catch {
            return .unavailable(error.localizedDescription)
        }
    }
}
