import Foundation
import LocalAuthentication
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Adversarial tests for the biometric gate in front of `AgentService.allow(_:decision:)`.
///
/// # Why this file exists
///
/// `allow` is the single place in the app where a secret is released, and the only thing standing
/// in front of it is one line:
///
///     guard outcome == .authenticated else { return outcome }
///
/// Everything in this file exists to hold that line. A gate that cannot run, a gate that is
/// cancelled, and a gate that fails with any of `LAError`'s documented codes must all leave the
/// request unanswered, the queue untouched and no lease minted — and the reason string the gate is
/// asked with must never carry a value.
///
/// The double follows the `ScriptedBiometricGate` pattern from `UITestSupport.swift`: the same
/// `BiometricGate` protocol the shipped `LocalAuthenticationGate` conforms to, so what is under
/// test is the app's use of the protocol rather than a parallel invention.
@MainActor
struct BiometricGateAdversarialTests {
    /// A gate that answers a scripted outcome and, optionally, sleeps first so a test can act
    /// inside the window `allow` is awaiting in.
    final class ScriptedGate: BiometricGate, @unchecked Sendable {
        private let outcome: BiometricOutcome
        private let stall: Duration
        private let lock = NSLock()
        private var _reasons: [String] = []

        var reasons: [String] {
            lock.lock()
            defer { lock.unlock() }
            return _reasons
        }

        init(_ outcome: BiometricOutcome, stall: Duration = .zero) {
            self.outcome = outcome
            self.stall = stall
        }

        func isAvailable() -> Bool {
            if case .unavailable = outcome { return false }
            return true
        }

        func authenticate(reason: String) async -> BiometricOutcome {
            record(reason)
            if stall > .zero { try? await Task.sleep(for: stall) }
            return outcome
        }

        /// The scripted answer arrives on its own schedule; a lock does not shorten it.
        func cancelInFlight() {}

        private func record(_ reason: String) {
            lock.lock()
            defer { lock.unlock() }
            _reasons.append(reason)
        }
    }

    // MARK: - G-13: every non-authenticated outcome grants nothing

    /// The codes that mean `LocalAuthentication` *cannot run* — the only ones that may reach the
    /// master-password fallback (ADR-0038 user decision 7).
    static let cannotRun: [LAError.Code] = [
        .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled, .biometryNotPaired,
        .biometryDisconnected, .watchNotAvailable, .companionNotAvailable, .notInteractive,
        .touchIDNotAvailable, .touchIDNotEnrolled,
    ]

    /// The codes that mean the check ran and did not pass — including a finger or password that
    /// did not match, and the lockout that follows too many of those.
    static let ranAndFailed: [LAError.Code] = [
        .userCancel, .appCancel, .systemCancel, .userFallback, .invalidContext,
        .authenticationFailed, .biometryLockout, .touchIDLockout,
    ]

    /// One entry per documented `LAError.Code`, as `LocalAuthenticationGate.outcome(for:)` maps
    /// it, so this table is the full space of things `allow` can be handed.
    static let nonGrantingOutcomes: [(name: String, outcome: BiometricOutcome)] = {
        ranAndFailed.map { ("LAError.\($0.rawValue) (ran, did not pass)", .cancelled) }
            + cannotRun.map {
                ("LAError.\($0.rawValue)", .unavailable("KS_CANARY_GATE_FAILURE \($0.rawValue)"))
            }
    }()

    /// A check that ran and failed — above all `authenticationFailed` — is `.cancelled`, never
    /// `.unavailable`: only "cannot run" opens the master-password fallback, so "Touch ID said
    /// no" can never become "type the master password instead".
    @Test func aFailedCheckIsNeverUnavailable() {
        for code in Self.ranAndFailed {
            #expect(
                LocalAuthenticationGate.outcome(for: code, description: "x") == .cancelled,
                "LAError.\(code.rawValue) ran and did not pass")
        }
        for code in Self.cannotRun {
            #expect(
                LocalAuthenticationGate.outcome(for: code, description: "x") == .unavailable("x"),
                "LAError.\(code.rawValue) means the check cannot run")
        }
        // A code this table does not name fails closed, and not towards the fallback.
        let unknown = LAError.Code(rawValue: -9_999) ?? .authenticationFailed
        #expect(LocalAuthenticationGate.outcome(for: unknown, description: "x") == .cancelled)
    }

    @Test func noOutcomeOtherThanAuthenticatedIsTreatedAsAGrant() async {
        // Every non-granting outcome, against a service that is not running: `allow` must return
        // the gate's own answer and must not fall through to the resolve-and-advance path. If it
        // ever did, `agentResolve` would be called for a request nobody authenticated.
        for entry in Self.nonGrantingOutcomes {
            let service = AgentService()
            let gate = ScriptedGate(entry.outcome)
            service.gate = gate
            let request = ApprovalRenderingAdversarialTests.request(clientName: "KS_CANARY_CALLER")

            let outcome = await service.allow(request, decision: .allowOnce)

            #expect(outcome == entry.outcome, "\(entry.name) must be reported, not reinterpreted")
            #expect(outcome != .authenticated, "\(entry.name) is not a grant")
            #expect(gate.reasons.count == 1, "\(entry.name): exactly one prompt per attempt")
            #expect(agentLeases().isEmpty, "\(entry.name) minted a lease")
        }
    }

    @Test func theOutcomeTypeHasExactlyOneGrantingCase() {
        // A structural guard on `BiometricOutcome`. `allow`'s gate is an equality check against a
        // single case; adding a second "succeeded"-ish case without revisiting that check is the
        // shape the failure would take, and `Equatable` conformance means it would compile.
        #expect(BiometricOutcome.authenticated == .authenticated)
        #expect(BiometricOutcome.cancelled != .authenticated)
        #expect(BiometricOutcome.unavailable("") != .authenticated)
        #expect(
            BiometricOutcome.unavailable("no authentication method available") != .authenticated,
            "an unavailable gate is the case a fail-open bug would most plausibly hide in")
    }

    // MARK: - G-14: an unavailable gate has no bypass

    @Test func anUnavailableGateIsStillAGateRatherThanAnExemption() async {
        // The realistic fail-open: a Mac with no Touch ID and no password set, where
        // `canEvaluatePolicy` is false and the temptation is to let the approval through because
        // "there is nothing to ask". `LocalAuthenticationGate` returns `.unavailable` there, and
        // `allow` must treat that as a refusal.
        let service = AgentService()
        let gate = ScriptedGate(.unavailable("KS_CANARY_NO_AUTH_METHOD"))
        service.gate = gate
        #expect(!gate.isAvailable(), "the double models a Mac that cannot raise the prompt")

        let outcome = await service.allow(
            ApprovalRenderingAdversarialTests.request(clientName: "KS_CANARY_CALLER"),
            decision: .allowSession(ttlSeconds: 900, uses: 10))

        #expect(outcome == .unavailable("KS_CANARY_NO_AUTH_METHOD"))
        #expect(agentLeases().isEmpty, "an unavailable gate must mint nothing")
    }

    @Test func theRealGateOnlyReportsAuthenticatedForATrueEvaluation() {
        // `LocalAuthenticationGate` cannot be driven from a test — `LAContext` raises a system
        // sheet — so this asserts the one thing about it that is reachable: the policy it is
        // configured with is `.deviceOwnerAuthentication`, which is what makes a Mac with no Touch
        // ID fall back to the login password rather than to nothing at all.
        #expect(LocalAuthenticationGate().policy == .deviceOwnerAuthentication)
    }

    // MARK: - G-15: the reason string names the act, never a value

    /// A value that must never appear in a system prompt. Obviously test data.
    static let secretCanary = "KS_CANARY_SECRET_sk_live_do_not_ship"

    @Test func theBiometricReasonNamesTheItemAndOriginAndNeverAValue() {
        let fill = ApprovalRenderingAdversarialTests.fillRequest(
            itemTitle: "Acme staging", origin: "https://acme.example")
        let reason = AgentService.reason(for: fill)
        #expect(reason == "fill Acme staging into https://acme.example")
        #expect(!reason.contains(Self.secretCanary))
        #expect(!reason.lowercased().contains("password:"))
    }

    @Test func noActionsReasonStringCarriesAVariableValue() {
        // Every action, with a canary planted in every field a value could plausibly leak from.
        for action in [
            ApprovalAction.writeEnvFile, .runWithEnv, .createEnvironment, .addVariables,
            .fillCredential, .agentFill, .createTestLogin,
        ] {
            let request = Self.canaryLadenRequest(action: action)
            let reason = AgentService.reason(for: request)
            #expect(
                !reason.contains(Self.secretCanary),
                "\(action) put a secret in the Touch ID prompt: \(reason)")
            #expect(!reason.contains("\n"), "\(action): the system prompt is one sentence")
        }
    }

    @Test func theRunWithEnvReasonNamesOnlyTheProgramNotItsArguments() {
        // `--token=…` on a command line is the classic way a secret reaches a screenshot. The
        // reason string takes `command.first` only, and this pins that.
        var request = Self.canaryLadenRequest(action: .runWithEnv)
        request = ApprovalRequestView(
            id: request.id, action: .runWithEnv, mintsLease: true, clientName: request.clientName,
            clientPid: request.clientPid, clientPidFromKernel: true,
            clientExecutable: request.clientExecutable, clientCwd: request.clientCwd,
            environmentId: request.environmentId, environmentName: request.environmentName,
            directory: request.directory, targetPath: nil, variables: request.variables,
            command: ["deploy", "--token=\(Self.secretCanary)"], gitignored: false,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 900, requestedUses: 1, maxTtlSeconds: 86_400, createdAt: 0,
            expiresAt: 60, origin: nil, topOrigin: nil, topOriginUnknown: false, itemId: nil,
            itemTitle: nil, fillFields: [], browser: nil, browserPid: nil, browserExecutable: nil,
            browserIsAppExtension: false, extensionId: nil, presenceOnly: false)
        let reason = AgentService.reason(for: request)
        #expect(reason.contains("deploy"))
        #expect(!reason.contains(Self.secretCanary), "the arguments are not in the prompt")
    }

    // MARK: - ADR-0036: an agent fill is the sheet and the gate, every time

    @Test func noOutcomeOtherThanAuthenticatedAllowsAnAgentFill() async {
        // The sheet's "Fill on …" is the only way to an agent fill's grant, and it is `allow`.
        // Every non-granting outcome must come back as itself, send nothing — not even a denial,
        // since the sheet is still up to be answered — and leave the request where it was.
        for entry in Self.nonGrantingOutcomes {
            let gate = ScriptedGate(entry.outcome)
            let log = DecisionLog()
            let service = Self.service(gate: gate, log: log)
            let request = AgentFillApprovalTests.agentFillRequest(
                facts: AgentFillApprovalTests.facts(agentName: Self.secretCanary))
            service.enqueue(request)

            let outcome = await service.allow(request, decision: .allowOnce)

            #expect(outcome == entry.outcome, "\(entry.name) must be reported, not reinterpreted")
            #expect(gate.reasons.count == 1, "\(entry.name): exactly one prompt per attempt")
            #expect(log.decisions.isEmpty, "\(entry.name) sent Rust an answer")
            #expect(service.current?.id == request.id, "\(entry.name): still waiting for a human")
            #expect(
                !(gate.reasons.first ?? "").contains(Self.secretCanary),
                "the agent's self-reported name is not in the system prompt")
        }
    }

    @Test func anAgentFillFlaggedPresenceOnlyIsNeverAskedWithoutItsSheet() async {
        // Rust never sets `presenceOnly` on an agent fill; if it ever arrived set, the app must
        // not take the shortcut that skips the sheet — a bare Touch ID prompt for a request whose
        // site, item and agent nobody has seen.
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = AgentFillApprovalTests.agentFillRequest(presenceOnly: true)

        service.enqueue(request)
        try? await Task.sleep(for: .milliseconds(300))

        #expect(gate.reasons.isEmpty, "no prompt without the sheet in front of it")
        #expect(log.decisions.isEmpty, "and certainly no grant")
        #expect(service.sheetRequest?.id == request.id)

        // Only the sheet's own Allow reaches the gate — and then it is once.
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 1)
        #expect(log.decisions.map(\.decision) == [.allowOnce])
    }

    @Test func aTouchThatLandsAfterALockIsNotAnAgentFillGrant() async {
        let gate = HeldGate()
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)

        let answer = Task { await service.allow(request, decision: .allowOnce) }
        #expect(await Self.eventually { gate.parked == 1 })
        service.stop()
        gate.release(.authenticated)

        #expect(await answer.value == .cancelled, "reported as a cancellation")
        #expect(log.decisions.isEmpty, "and nothing reaches Rust")
    }

    // MARK: - ADR-0037: a presence-only fill is the gate and nothing else

    /// Every decision `AgentService` sent for a request, in order — observed through the
    /// `resolver` seam, because these requests are handed to the service directly and no Rust
    /// queue holds them.
    final class DecisionLog: @unchecked Sendable {
        private let lock = NSLock()
        private var _decisions: [(id: String, decision: ApprovalDecision)] = []

        var decisions: [(id: String, decision: ApprovalDecision)] {
            lock.lock()
            defer { lock.unlock() }
            return _decisions
        }

        func record(_ id: String, _ decision: ApprovalDecision) {
            lock.lock()
            defer { lock.unlock() }
            _decisions.append((id, decision))
        }
    }

    private static func service(
        gate: BiometricGate, log: DecisionLog
    ) -> AgentService {
        let service = AgentService()
        service.gate = gate
        service.resolver = { id, decision, _ in
            log.record(id, decision)
            return true
        }
        return service
    }

    /// Poll `condition` on the main actor for up to five seconds.
    private static func eventually(_ condition: () -> Bool) async -> Bool {
        for _ in 0..<100 {
            if condition() { return true }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return condition()
    }

    private static func presenceRequest(
        id: String = "ks-presence-1", itemId: String? = nil
    ) -> ApprovalRequestView {
        let base = ApprovalRenderingAdversarialTests.fillRequest(
            itemTitle: "Acme staging", origin: "https://acme.example", presenceOnly: true)
        return ApprovalRequestView(
            id: id, action: base.action, mintsLease: base.mintsLease, clientName: base.clientName,
            clientPid: base.clientPid, clientPidFromKernel: base.clientPidFromKernel,
            clientExecutable: base.clientExecutable, clientCwd: base.clientCwd,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: [], gitignored: nil, overwriteRequested: false,
            targetExists: nil, targetWrittenByUs: nil, requestedTtlSeconds: 300,
            requestedUses: 1, maxTtlSeconds: 900,
            // Far in the future, so the tick's expiry sweep never answers these first.
            createdAt: UInt64(Date.now.timeIntervalSince1970),
            expiresAt: UInt64(Date.now.timeIntervalSince1970) + 600,
            origin: base.origin, topOrigin: nil, topOriginUnknown: false,
            itemId: itemId ?? base.itemId,
            itemTitle: base.itemTitle, fillFields: base.fillFields, browser: base.browser,
            browserPid: base.browserPid, browserExecutable: base.browserExecutable,
            browserIsAppExtension: false, extensionId: base.extensionId, presenceOnly: true)
    }

    @Test func aPresenceOnlyFillAsksTheGateExactlyOnceAndGrantsOnlyOnce() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = Self.presenceRequest()

        service.enqueue(request)
        #expect(service.sheetRequest == nil, "a presence-only fill never raises the sheet")

        #expect(await Self.eventually { service.current == nil }, "the prompt resolved it")
        #expect(gate.reasons.count == 1, "one prompt, no retry, no second touch")
        #expect(gate.reasons.first == AgentService.presenceReason(for: request))
        let sent = log.decisions
        #expect(sent.count == 1)
        #expect(sent.first?.id == request.id)
        #expect(
            sent.first?.decision == .allowOnce,
            "a presence confirmation is once — it never asks Rust for a session")
    }

    @Test func aCancelledOrUnavailablePresencePromptIsADenialAndNothingElse() async {
        // With no sheet to return to, a fumbled or impossible check must not leave the request
        // parked for an automation agent to wait out, and must never be read as a grant.
        for entry in Self.nonGrantingOutcomes {
            let gate = ScriptedGate(entry.outcome)
            let log = DecisionLog()
            let service = Self.service(gate: gate, log: log)
            let request = Self.presenceRequest()

            service.enqueue(request)

            #expect(
                await Self.eventually { service.current == nil },
                "\(entry.name): the request is answered, not left up")
            #expect(gate.reasons.count == 1, "\(entry.name): exactly one prompt")
            let sent = log.decisions.map(\.decision)
            #expect(sent == [.deny], "\(entry.name): a denial, and only a denial — got \(sent)")
            #expect(agentLeases().isEmpty, "\(entry.name) minted a lease")
        }
    }

    @Test func onlyOnePresencePromptIsUpAtATime() async {
        // Two presence-only fills arrive together — a page, or an agent, clicking twice. Two
        // system prompts stacked on each other would invite a single touch to be read as an
        // answer to the one the person did not look at. The first touch opens the app-wide grace
        // window (ADR-0037 amendment of 2026-10-03), so the second rides it without a prompt.
        let gate = ConcurrencyGate(stall: .milliseconds(200))
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        service.enqueue(Self.presenceRequest(id: "ks-presence-a", itemId: "ks-canary-item-a"))
        service.enqueue(Self.presenceRequest(id: "ks-presence-b", itemId: "ks-canary-item-b"))

        #expect(await Self.eventually { service.current == nil })
        #expect(gate.calls == 1, "the second rode the grace window the first opened")
        #expect(gate.maxInFlight == 1, "never two prompts at once")
        #expect(log.decisions.map(\.id) == ["ks-presence-a", "ks-presence-b"], "in order")
    }

    @Test func thePresencePromptNamesTheItemAndTheSiteAndSaysWhenToRefuse() {
        let reason = AgentService.reason(for: Self.presenceRequest())
        #expect(reason.contains("Acme staging"))
        #expect(reason.contains("https://acme.example"))
        #expect(reason.contains("only if you just asked Kagisecure to fill this"))
        #expect(!reason.contains("\n"), "the system prompt is one sentence")
        let laden = AgentService.reason(
            for: Self.canaryLadenRequest(action: .fillCredential, presenceOnly: true))
        #expect(!laden.contains(Self.secretCanary))
    }

    @Test func theRealGateBuildsAFreshContextForEveryCheckAndNeverAReuseWindow() async {
        // `LAContext` cannot be driven from a test without raising a system sheet, so the contexts
        // here refuse at `canEvaluatePolicy` — before anything is shown — and the test observes
        // what it can: how many contexts were made, whether any was reused, and whether any was
        // given a Touch ID reuse window. A shared context or a non-zero window would let one touch
        // for the person's own fill pay for the fills after it (ADR-0037).
        let made = ContextLog()
        let gate = LocalAuthenticationGate(makeContext: {
            let context = RefusingContext()
            made.append(context)
            return context
        })

        let first = await gate.authenticate(reason: "fill A into https://a.example")
        let second = await gate.authenticate(reason: "fill A into https://a.example")

        #expect(first != .authenticated && second != .authenticated)
        let contexts = made.contexts
        #expect(contexts.count == 2, "one context per check")
        if contexts.count == 2 {
            #expect(contexts[0] !== contexts[1], "never the same context twice")
        }
        for context in contexts {
            #expect(context.touchIDAuthenticationAllowableReuseDuration == 0)
        }
    }

    // MARK: - A lock while a presence prompt is up

    @Test func aLockUnderAnOpenPresencePromptNeverLetsTheNextUnlockStackASecondOne() async {
        // The prompt for A is up. The vault locks — `stop()` — and unlocks at once, and B, another
        // presence-only fill, arrives while A's system prompt is still being torn down. B must
        // wait: two LocalAuthentication prompts on screen at once is exactly the situation in
        // which one touch answers the prompt the person did not read. And A's answer, whenever
        // it comes, belongs to a session that has ended: even a successful touch must not reach
        // Rust as a grant.
        let gate = HeldGate()
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        service.enqueue(Self.presenceRequest(id: "ks-presence-before-lock"))
        #expect(await Self.eventually { gate.parked == 1 }, "A's prompt is up")
        let promptA = service.presencePrompt
        #expect(promptA?.requestId == "ks-presence-before-lock")

        service.stop()
        #expect(gate.cancels == 1, "the lock tears down the prompt that is up")
        #expect(
            service.presencePrompt == promptA,
            "but the flag stays until A's prompt has actually returned")

        // The quick unlock, and B.
        service.enqueue(Self.presenceRequest(id: "ks-presence-after-unlock"))
        try? await Task.sleep(for: .milliseconds(200))
        #expect(gate.calls == 1, "B waits: no second prompt while A's is still on screen")
        #expect(service.sheetRequest == nil, "and B does not fall through to the sheet either")

        // A's prompt finally returns — as a touch, the worst case.
        gate.release(.authenticated)
        #expect(await Self.eventually { gate.calls == 2 }, "only now is B's prompt raised")
        #expect(service.presencePromptFor == "ks-presence-after-unlock")
        #expect(
            !log.decisions.contains { $0.id == "ks-presence-before-lock" },
            "A was answered by the lock; a touch after it sends nothing, not even a denial")

        gate.release(.authenticated)
        #expect(await Self.eventually { service.current == nil })
        #expect(gate.maxInFlight == 1, "never two prompts at once, across the lock")
        #expect(log.decisions.map(\.id) == ["ks-presence-after-unlock"])
        #expect(log.decisions.map(\.decision) == [.allowOnce])
    }

    @Test func aTouchThatLandsAfterALockIsNotAGrantOnTheSheetPathEither() async {
        // The same race through the sheet's Allow button rather than a presence prompt.
        let gate = HeldGate()
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = Self.canaryLadenRequest(action: .writeEnvFile)
        service.enqueue(request)

        let answer = Task { await service.allow(request, decision: .allowOnce) }
        #expect(await Self.eventually { gate.parked == 1 })
        service.stop()
        gate.release(.authenticated)

        #expect(await answer.value == .cancelled, "reported as a cancellation")
        #expect(log.decisions.isEmpty, "and nothing reaches Rust")
    }

    @Test func theRealGateInvalidatesTheContextThatIsUpWhenTheVaultLocks() async {
        // `PromptingContext` stands in for the system prompt: `evaluatePolicy` parks until the
        // context is invalidated, and then completes the way LocalAuthentication does, with
        // `appCancel`. What is asserted is the gate's side: that a lock reaches the context that
        // is actually up, and that the answer is not a grant.
        let made = ContextLog()
        let gate = LocalAuthenticationGate(makeContext: {
            let context = PromptingContext()
            made.append(context)
            return context
        })

        let answer = Task { await gate.authenticate(reason: "fill A into https://a.example") }
        #expect(await Self.eventually { gate.inFlight.count == 1 }, "the prompt is up")
        gate.cancelInFlight()

        let outcome = await answer.value
        #expect(outcome == .cancelled, "an invalidated prompt is a cancellation, never a grant")
        #expect(gate.inFlight.count == 0, "and it is no longer tracked once it has returned")
        let contexts = made.contexts.compactMap { $0 as? PromptingContext }
        #expect(contexts.count == 1)
        #expect(contexts.first?.invalidated == true, "the lock invalidated that very context")
    }

    /// A context whose evaluation stays "on screen" until it is invalidated.
    final class PromptingContext: LAContext, @unchecked Sendable {
        private let lock = NSLock()
        private var reply: ((Bool, Error?) -> Void)?
        private var _invalidated = false

        var invalidated: Bool {
            lock.lock()
            defer { lock.unlock() }
            return _invalidated
        }

        override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
            true
        }

        override func evaluatePolicy(
            _ policy: LAPolicy, localizedReason: String,
            reply: @escaping (Bool, Error?) -> Void
        ) {
            lock.lock()
            let already = _invalidated
            if !already { self.reply = reply }
            lock.unlock()
            if already { reply(false, LAError(.invalidContext)) }
        }

        override func invalidate() {
            lock.lock()
            _invalidated = true
            let pending = reply
            reply = nil
            lock.unlock()
            pending?(false, LAError(.appCancel))
        }
    }

    /// A gate whose prompts stay up until the test releases them, one at a time, in order.
    ///
    /// `cancelInFlight` is recorded and deliberately does **not** complete anything: it models a
    /// system prompt that takes a while to go away after it is invalidated, which is the window
    /// the one-prompt-at-a-time rule has to hold across.
    final class HeldGate: BiometricGate, @unchecked Sendable {
        private let lock = NSLock()
        private var waiting: [CheckedContinuation<BiometricOutcome, Never>] = []
        private var inFlight = 0
        private var _maxInFlight = 0
        private var _calls = 0
        private var _cancels = 0

        var parked: Int { read { waiting.count } }
        var calls: Int { read { _calls } }
        var cancels: Int { read { _cancels } }
        var maxInFlight: Int { read { _maxInFlight } }

        func isAvailable() -> Bool { true }

        func authenticate(reason: String) async -> BiometricOutcome {
            enter()
            let outcome = await withCheckedContinuation { park($0) }
            leave()
            return outcome
        }

        func cancelInFlight() {
            lock.lock()
            defer { lock.unlock() }
            _cancels += 1
        }

        /// Complete the oldest prompt still up with `outcome`.
        func release(_ outcome: BiometricOutcome) {
            lock.lock()
            let next = waiting.isEmpty ? nil : waiting.removeFirst()
            lock.unlock()
            next?.resume(returning: outcome)
        }

        private func park(_ continuation: CheckedContinuation<BiometricOutcome, Never>) {
            lock.lock()
            defer { lock.unlock() }
            waiting.append(continuation)
        }

        private func enter() {
            lock.lock()
            defer { lock.unlock() }
            _calls += 1
            inFlight += 1
            _maxInFlight = max(_maxInFlight, inFlight)
        }

        private func leave() {
            lock.lock()
            defer { lock.unlock() }
            inFlight -= 1
        }

        private func read<T>(_ body: () -> T) -> T {
            lock.lock()
            defer { lock.unlock() }
            return body()
        }
    }

    /// A context that refuses before raising anything.
    final class RefusingContext: LAContext {
        override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
            false
        }
    }

    final class ContextLog: @unchecked Sendable {
        private let lock = NSLock()
        private var _contexts: [LAContext] = []

        var contexts: [LAContext] {
            lock.lock()
            defer { lock.unlock() }
            return _contexts
        }

        func append(_ context: LAContext) {
            lock.lock()
            defer { lock.unlock() }
            _contexts.append(context)
        }
    }

    /// A gate that authenticates after a stall and records how many checks overlapped.
    final class ConcurrencyGate: BiometricGate, @unchecked Sendable {
        private let stall: Duration
        private let lock = NSLock()
        private var inFlight = 0
        private var _maxInFlight = 0
        private var _calls = 0

        init(stall: Duration) { self.stall = stall }

        var maxInFlight: Int {
            lock.lock()
            defer { lock.unlock() }
            return _maxInFlight
        }

        var calls: Int {
            lock.lock()
            defer { lock.unlock() }
            return _calls
        }

        func isAvailable() -> Bool { true }

        func authenticate(reason: String) async -> BiometricOutcome {
            enter()
            try? await Task.sleep(for: stall)
            leave()
            return .authenticated
        }

        func cancelInFlight() {}

        private func enter() {
            lock.lock()
            defer { lock.unlock() }
            _calls += 1
            inFlight += 1
            _maxInFlight = max(_maxInFlight, inFlight)
        }

        private func leave() {
            lock.lock()
            defer { lock.unlock() }
            inFlight -= 1
        }
    }

    // MARK: - Builder

    static func canaryLadenRequest(
        action: ApprovalAction, presenceOnly: Bool = false
    ) -> ApprovalRequestView {
        ApprovalRequestView(
            id: "ks-canary-req", action: action, mintsLease: true, clientName: "KS_CANARY_CALLER",
            clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: "/tmp/ks-canary",
            environmentId: "ks-canary-env", environmentName: "acme / staging",
            directory: "/tmp/ks-canary", targetPath: "/tmp/ks-canary/.env",
            // A variable *named* after the canary: the count is what the prompt may say, the name
            // is not.
            variables: [secretCanary], command: ["deploy", secretCanary], gitignored: false,
            overwriteRequested: false, targetExists: false, targetWrittenByUs: nil,
            requestedTtlSeconds: 900, requestedUses: 10, maxTtlSeconds: 86_400, createdAt: 0,
            expiresAt: 60, origin: "https://acme.example", topOrigin: nil,
            topOriginUnknown: false, itemId: "ks-canary-item", itemTitle: "Acme staging", fillFields: ["password"],
            browser: "Google Chrome", browserPid: 4244,
            browserExecutable: "/Applications/Google Chrome.app", browserIsAppExtension: false,
            extensionId: "ks-canary-extension", presenceOnly: presenceOnly)
    }
}
