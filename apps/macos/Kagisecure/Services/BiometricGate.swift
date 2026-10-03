import Foundation
import LocalAuthentication

/// The result of asking for a fingerprint.
enum BiometricOutcome: Equatable {
    /// The user authenticated.
    case authenticated
    /// The user cancelled, fell back and then cancelled, or **tried and failed** (a finger or a
    /// password that did not match, a lockout after too many of those). **Not** a denial: ui-spec.md
    /// §10.3 says a fumbled fingerprint must return to the approval dialog rather than be mistaken
    /// for a policy decision. Never a reason to offer the master-password fallback either: the
    /// check *ran* and did not pass.
    case cancelled
    /// The gate could not run at all, with a reason to show — no passcode set, no biometry or
    /// watch available, no way to show a prompt. The only answer ADR-0038 (user decision 7) lets
    /// the app meet with the master-password fallback.
    case unavailable(String)
    /// Not asked: another presence prompt is already on screen, and a second one is refused
    /// rather than stacked beside it (`PresenceCoordinator`). Never a grant, and not a decision
    /// either — the approval sheet stays up.
    case busy
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

    /// Tear down every prompt this gate has up, so each pending `authenticate` returns without a
    /// grant as soon as the system lets it.
    ///
    /// Called when the vault locks. A prompt raised for a request the lock has already denied must
    /// not stay on screen into the next unlock, where it would sit on top of — and be mistaken
    /// for — a prompt about something else. A requirement rather than a defaulted extension, so
    /// every gate has to say what a lock does to its prompt, including a double that does nothing.
    func cancelInFlight()
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
///
/// # A fresh context every time, and no reuse window
///
/// Since ADR-0037 this is what stands between an automation agent clicking in a browser and a
/// password: every fill that crosses a secret asks here. So each call builds a **new** `LAContext`
/// and never sets `touchIDAuthenticationAllowableReuseDuration`, whose default is zero. A reused
/// context, or a non-zero reuse window, would let one touch for the human's own fill quietly pay
/// for the next few fills too — which is exactly the gap ADR-0037 closed at the lease, reopened one
/// layer down. `makeContext` exists so a test can observe both properties; the app never sets it.
///
/// # A lock invalidates the prompt that is up
///
/// Every context is registered in `inFlight` for exactly as long as its `evaluatePolicy` runs, and
/// `cancelInFlight` calls `invalidate()` on each, which makes the system dismiss the prompt and
/// complete the evaluation with `LAError.appCancel`. A context invalidated before it reached
/// `evaluatePolicy` fails there with `invalidContext`. Either way the answer is not a grant.
struct LocalAuthenticationGate: BiometricGate {
    /// The policy to evaluate. Injected so the availability probe and the evaluation cannot
    /// disagree about which one is being asked for.
    var policy: LAPolicy = .deviceOwnerAuthentication

    /// Where each call's context comes from. Called once per `authenticate`, never cached.
    var makeContext: @Sendable () -> LAContext = { LAContext() }

    /// The contexts whose evaluation has not returned yet. A reference, so every copy of this
    /// value — `AgentService.gate` is a copy — cancels the same prompts.
    let inFlight = InFlightContexts()

    func isAvailable() -> Bool {
        makeContext().canEvaluatePolicy(policy, error: nil)
    }

    /// Whether this Mac has Touch ID enrolled — for copy that has to say "your login password,
    /// every time" when it does not. Never consulted for a decision.
    static func hasBiometrics() -> Bool {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType != .none
    }

    func cancelInFlight() {
        inFlight.invalidateAll()
    }

    func authenticate(reason: String) async -> BiometricOutcome {
        let context = makeContext()
        // Registered before anything can be shown, removed only once the evaluation has returned:
        // the window in which a lock must be able to reach it is exactly the prompt's lifetime.
        let token = inFlight.register(context)
        defer { inFlight.remove(token) }
        context.localizedCancelTitle = "Cancel"
        var probe: NSError?
        guard context.canEvaluatePolicy(policy, error: &probe) else {
            let description = probe?.localizedDescription ?? "no authentication method available"
            // A lockout is the aftermath of failed attempts, not a check that cannot run.
            if let probe, probe.domain == LAError.errorDomain,
                LAError.Code(rawValue: probe.code) == .biometryLockout
            {
                return .cancelled
            }
            return .unavailable(description)
        }
        do {
            let ok = try await context.evaluatePolicy(policy, localizedReason: reason)
            return ok ? .authenticated : .cancelled
        } catch let error as LAError {
            return Self.outcome(for: error.code, description: error.localizedDescription)
        } catch {
            // Not an `LAError` at all: something unexpected happened to a check that did start.
            // Fail closed, and not towards the fallback.
            return .cancelled
        }
    }

    /// What a failed evaluation means, by `LAError` code — precisely, because `.unavailable` is the
    /// one answer that opens the master-password fallback (ADR-0038 user decision 7: only when
    /// `LocalAuthentication` *cannot run*).
    ///
    /// * **Cannot run → `.unavailable`:** no passcode on the Mac, no biometry or companion device
    ///   available, enrolled, paired or connected, or no way to show a prompt (`notInteractive`).
    /// * **Ran and did not pass → `.cancelled`:** the person cancelled or chose the fallback
    ///   button, the system or the app cancelled it (a lock), the context was invalidated, the
    ///   finger or password did not match (`authenticationFailed`), or too many of those locked
    ///   biometry out. Mapping any of these to `.unavailable`, as every code but the four
    ///   cancellations once was, turned "Touch ID said no" into "type the master password
    ///   instead" — a way round the sensor for anyone who knows (or is guessing) it.
    /// * **Anything else**, including a code this SDK does not know yet → `.cancelled`: failing
    ///   closed never grants, and never reaches for the fallback on a guess.
    static func outcome(for code: LAError.Code, description: String) -> BiometricOutcome {
        switch code {
        case .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled, .biometryNotPaired,
            .biometryDisconnected, .watchNotAvailable, .companionNotAvailable, .notInteractive:
            return .unavailable(description)
        case .userCancel, .appCancel, .systemCancel, .userFallback, .invalidContext,
            .authenticationFailed, .biometryLockout:
            return .cancelled
        default:
            return .cancelled
        }
    }
}

/// The `LAContext`s a `LocalAuthenticationGate` is currently evaluating, so a lock can reach them.
///
/// A class behind a lock rather than state on the gate, because the gate is a `Sendable` value
/// that is copied freely and `authenticate` runs off the main actor.
final class InFlightContexts: @unchecked Sendable {
    private let lock = NSLock()
    private var contexts: [UInt64: LAContext] = [:]
    private var next: UInt64 = 0

    /// Track `context` until `remove` is called with the returned token.
    func register(_ context: LAContext) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        next &+= 1
        contexts[next] = context
        return next
    }

    func remove(_ token: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        contexts.removeValue(forKey: token)
    }

    /// How many evaluations are still running — for tests.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return contexts.count
    }

    /// Invalidate every registered context. Each stays registered until its own evaluation
    /// returns, so a second lock in the meantime invalidates it again, which is harmless.
    func invalidateAll() {
        lock.lock()
        let live = Array(contexts.values)
        lock.unlock()
        for context in live { context.invalidate() }
    }
}
