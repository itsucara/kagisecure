import Foundation
import SwiftUI
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The agent-fill approval, on the Swift side (ADR-0036 §5, §9.2; ui-spec.md §10.7).
///
/// # What is under test
///
/// The rules the sheet enforces that are not pixels:
///
/// * the Allow button is enabled while the sheet is key (the 1.5-second hold was removed), and the hold restarts
///   when the window loses key and gets it back (`AllowDelay`);
/// * `Esc` denies and `Return` does nothing (`AgentFillSheetKeys`) — no default button;
/// * Allow goes through `AgentService.allow`, which asks the presence gate for every fill outside a
///   grace window for its origin (`PresenceGraceTests`) and sends Rust **Allow once** whatever it
///   was handed;
/// * an agent fill is the full sheet even if it arrived flagged presence-only (implementation
///   decision 5);
/// * a cancelled or impossible presence check neither grants nor denies: the sheet stays up;
/// * the strings the sheet leads with — the site first, the registrable domain on the button,
///   §8.2's sentence verbatim.
///
/// The requests are handed to the service directly, and what it sends is observed through the
/// `resolver` seam, the way `BiometricGateAdversarialTests` does it.
@MainActor
struct AgentFillApprovalTests {
    // MARK: - Fixtures

    static func origin(
        scheme: String = "https", dimmedPrefix: String = "login.", emphasized: String = "example.com",
        port: UInt16? = nil, unicodeHost: String? = nil, mixedScript: Bool = false
    ) -> AgentOriginView {
        let host = dimmedPrefix + emphasized
        return AgentOriginView(
            ascii: "\(scheme)://\(host)\(port.map { ":\($0)" } ?? "")",
            scheme: scheme, dimmedPrefix: dimmedPrefix, emphasized: emphasized, port: port,
            unicodeHost: unicodeHost, mixedScript: mixedScript, notEncrypted: scheme == "http")
    }

    static func facts(
        agentName: String = "example-agent", origin: AgentOriginView = origin(),
        itemTitle: String = "Example (work)", fields: [AgentFillFieldView] = [.username, .password],
        twoStep: Bool = false
    ) -> AgentFillFactsView {
        AgentFillFactsView(
            agentName: agentName, sidecarPid: 51_234,
            sidecarExecutable: "/Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp",
            parentPid: 51_200, parentExecutable: "/usr/local/bin/example-client",
            itemId: "item-agent-1", itemTitle: itemTitle, fields: fields, twoStep: twoStep,
            pageOrigin: origin, savedWebsite: "https://example.com", pageHostDiffers: true,
            browser: "Google Chrome", browserPid: 4241,
            browserExecutable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            browserIsAppExtension: false, hostPid: 4242, hostExecutable: "/tmp/kagisecure-nmhost",
            extensionId: "nlijibjnmanccalmafnfbobkcfjiibmd")
    }

    /// An agent fill as `ApprovalRequest::for_agent_fill` builds one: the common fields copied
    /// from the facts, no lease, never presence-only — unless a test says otherwise.
    static func agentFillRequest(
        id: String = "ks-agent-fill-1", facts: AgentFillFactsView? = facts(),
        presenceOnly: Bool = false
    ) -> ApprovalRequestView {
        let now = UInt64(Date.now.timeIntervalSince1970)
        return ApprovalRequestView(
            id: id, action: .agentFill, mintsLease: false,
            clientName: facts?.agentName ?? "unknown", clientPid: facts?.sidecarPid,
            clientPidFromKernel: true, clientExecutable: facts?.sidecarExecutable, clientCwd: nil,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: [], gitignored: nil, overwriteRequested: false,
            targetExists: nil, targetWrittenByUs: nil, requestedTtlSeconds: 0, requestedUses: 1,
            maxTtlSeconds: 0,
            // Far in the future, so the tick's expiry sweep never answers these first.
            createdAt: now, expiresAt: now + 600,
            origin: facts?.pageOrigin.ascii, topOrigin: nil, topOriginUnknown: false,
            itemId: facts?.itemId, itemTitle: facts?.itemTitle,
            fillFields: facts.map { AgentFillSheetView.fieldNames($0.fields).components(separatedBy: ", ") } ?? [],
            browser: facts?.browser, browserPid: facts?.browserPid,
            browserExecutable: facts?.browserExecutable, browserIsAppExtension: false,
            extensionId: facts?.extensionId, presenceOnly: presenceOnly, agentFill: facts)
    }

    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate
    typealias DecisionLog = BiometricGateAdversarialTests.DecisionLog

    static func service(gate: BiometricGate, log: DecisionLog) -> AgentService {
        let service = AgentService()
        service.gate = gate
        service.resolver = { id, decision, _ in
            log.record(id, decision)
            return true
        }
        return service
    }

    // MARK: - The Allow hold (zero since 2026-10-03)

    @Test func theAllowButtonIsEnabledAsSoonAsTheSheetIsKey() {
        let t0 = ContinuousClock.now
        var delay = AllowDelay()
        #expect(AllowDelay.hold == .zero)
        delay.becameKey(at: t0)
        #expect(delay.isOpen)
        delay.refresh(at: t0)
        #expect(AgentFillSheetView.allowEnabled(delay: delay, hasFacts: true))
    }

    @Test func losingKeyClosesAllow() {
        let t0 = ContinuousClock.now
        var delay = AllowDelay()
        delay.becameKey(at: t0)
        delay.resignedKey()
        #expect(!delay.isOpen)
        delay.refresh(at: t0.advanced(by: .seconds(6)))
        #expect(!delay.isOpen, "time alone does not reopen it")
        delay.becameKey(at: t0.advanced(by: .seconds(7)))
        #expect(delay.isOpen)
    }

    @Test func theHoldNeverOpensForASheetThatWasNeverKey() {
        var delay = AllowDelay()
        delay.refresh(at: ContinuousClock.now.advanced(by: .seconds(60)))
        #expect(!delay.isOpen)
        #expect(delay.deadline == nil)
    }

    @Test func allowIsNeverEnabledWithoutTheFactsTheSheetNames() {
        let t0 = ContinuousClock.now
        var delay = AllowDelay()
        delay.becameKey(at: t0)
        delay.refresh(at: t0.advanced(by: .seconds(10)))
        #expect(!AgentFillSheetView.allowEnabled(delay: delay, hasFacts: false))
    }

    // MARK: - The keyboard

    @Test func escapeDenies() {
        #expect(AgentFillSheetKeys.response(to: .escape) == .deny)
        #expect(AgentFillSheetKeys.denyShortcut == .cancelAction)
        #expect(AgentFillSheetKeys.denyShortcut.key == .escape)
        #expect(AgentFillSheetKeys.handledKeys.contains(.escape))

        // And the deny the key triggers is a denial, sent once, with no prompt.
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = Self.agentFillRequest()
        service.enqueue(request)
        service.deny(request)
        #expect(log.decisions.map(\.decision) == [.deny])
        #expect(gate.reasons.isEmpty, "saying no never asks for a fingerprint")
        #expect(service.current == nil)
    }

    @Test func returnDoesNothing() {
        #expect(AgentFillSheetKeys.response(to: .return) == .swallow)
        #expect(AgentFillSheetKeys.response(to: AgentFillSheetKeys.enter) == .swallow)
        #expect(AgentFillSheetKeys.handledKeys.contains(.return))
        #expect(AgentFillSheetKeys.allowShortcut == nil, "no keyboard path to Allow")
        #expect(AgentFillSheetKeys.denyShortcut != .defaultAction, "and Deny is not the default either")
        #expect(AgentFillSheetKeys.response(to: "a") == .ignore)
    }

    // MARK: - Allow goes through the gate, outside a grace window

    @Test func allowAlwaysAsksThePresenceGateAndSendsAllowOnce() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let first = Self.agentFillRequest(id: "ks-agent-fill-a")
        // The grace window is app-wide since 2026-10-03; it is cleared between the two below so
        // the second asks again. `PresenceGraceTests` covers riding it.
        let second = Self.agentFillRequest(
            id: "ks-agent-fill-b", facts: Self.facts(origin: Self.origin(emphasized: "example.org")))
        service.enqueue(first)

        #expect(await service.allow(first, decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 1, "one fresh check for the first fill")
        service.presence.clearGrace()
        service.enqueue(second)
        // Handed a session by mistake — or by a caller that should know better — it is still once.
        #expect(
            await service.allow(second, decision: .allowSession(ttlSeconds: 900, uses: 10))
                == .authenticated)
        #expect(gate.reasons.count == 2, "and another for the second, on another site")
        #expect(log.decisions.map(\.id) == ["ks-agent-fill-a", "ks-agent-fill-b"])
        #expect(log.decisions.map(\.decision) == [.allowOnce, .allowOnce])
        #expect(
            gate.reasons == [
                AgentService.agentFillReason(for: first), AgentService.agentFillReason(for: second),
            ])
        #expect(agentLeases().isEmpty, "an agent fill mints no lease")
    }

    @Test func aPresenceOnlyAgentFillStillShowsTheSheet() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = Self.agentFillRequest(presenceOnly: true)

        #expect(AgentService.needsSheet(request))
        #expect(service.enqueue(request), "queued for a human, not answered on arrival")
        #expect(service.sheetRequest?.id == request.id, "shown as the sheet")

        try? await Task.sleep(for: .milliseconds(300))
        #expect(gate.reasons.isEmpty, "no bare presence prompt was raised for it")
        #expect(log.decisions.isEmpty, "and nothing was sent")
        #expect(service.presencePrompt == nil)
        #expect(service.sheetRequest?.id == request.id, "the sheet is still what asks")
    }

    @Test func aCancelledPresenceCheckGrantsNothingAndDeniesNothing() async {
        for entry in BiometricGateAdversarialTests.nonGrantingOutcomes {
            let gate = ScriptedGate(entry.outcome)
            let log = DecisionLog()
            let service = Self.service(gate: gate, log: log)
            let request = Self.agentFillRequest()
            service.enqueue(request)

            let outcome = await service.allow(request, decision: .allowOnce)

            #expect(outcome == entry.outcome, "\(entry.name) is reported as itself")
            #expect(gate.reasons.count == 1, "\(entry.name): exactly one prompt")
            #expect(log.decisions.isEmpty, "\(entry.name): no grant, and no denial either")
            #expect(
                service.sheetRequest?.id == request.id,
                "\(entry.name): the sheet stays up — a fumbled fingerprint is not a decision")
            #expect(agentLeases().isEmpty)
        }
    }

    @Test func aBusyPresenceSlotAsksNothingAndSendsNothing() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)
        let request = Self.agentFillRequest()
        service.enqueue(request)
        // A reveal's prompt is up elsewhere in the app.
        let held = service.presence.begin(.release)
        #expect(held != nil)

        #expect(await service.allow(request, decision: .allowOnce) == .busy)
        #expect(gate.reasons.isEmpty)
        #expect(log.decisions.isEmpty)
        if let held { service.presence.end(held) }
    }

    // MARK: - What the sheet says

    @Test func theSentenceLeadsWithTheSiteAndLeavesTheAgentsNameOut() {
        let request = Self.agentFillRequest(
            facts: Self.facts(agentName: "KS_CANARY_AGENT is verified"))
        let sentence = AgentFillSheetView.sentence(for: request)
        #expect(sentence == "An agent asks to sign in to login.example.com with “Example (work)”")
        #expect(!sentence.contains("KS_CANARY_AGENT"), "the agent's chosen name is not the lead")
        #expect(ApprovalSheet.sentence(for: request) == sentence, "one sentence for the kind")
    }

    @Test func theAllowButtonNamesTheRegistrableDomain() {
        #expect(AgentFillSheetView.allowLabel(for: Self.agentFillRequest()) == "Fill on example.com…")
        let lookalike = Self.agentFillRequest(
            facts: Self.facts(
                origin: Self.origin(dimmedPrefix: "example.com.", emphasized: "attacker.test")))
        #expect(
            AgentFillSheetView.allowLabel(for: lookalike) == "Fill on attacker.test…",
            "the button names what it approves, not the label an attacker put in front")
        #expect(AgentFillSheetView.allowLabel(for: Self.agentFillRequest(facts: nil)) == "Fill…")
    }

    @Test func aNonDefaultPortIsAlwaysRendered() {
        let request = Self.agentFillRequest(facts: Self.facts(origin: Self.origin(port: 8443)))
        #expect(AgentFillSheetView.siteText(Self.origin(port: 8443)) == "https://login.example.com:8443")
        #expect(AgentFillSheetView.sentence(for: request).contains("login.example.com:8443"))
        #expect(AgentFillSheetView.siteText(Self.origin()) == "https://login.example.com")
    }

    @Test func theSheetCarriesADR0036Section8Point2Verbatim() {
        #expect(
            AgentFillSheetView.readableByTheAgent
                == "kagisecure never gives the agent a value. It types the value into a page the "
                + "agent is driving, on a site saved for that login, after you approve — and an "
                + "agent that can run script in that page can read it there.")
    }

    @Test func theFieldsAreNamesInTheOrderAsked() {
        #expect(AgentFillSheetView.fieldNames([.username, .password]) == "username, password")
        #expect(AgentFillSheetView.fieldNames([.oneTimeCode]) == "one-time code")
    }

    @Test func theTouchIDReasonNamesTheSiteAndTheItemAndNotTheAgent() {
        let request = Self.agentFillRequest(
            facts: Self.facts(agentName: "KS_CANARY_AGENT", itemTitle: "Example (work)"))
        let reason = AgentService.reason(for: request)
        #expect(reason.contains("https://login.example.com"))
        #expect(reason.contains("Example (work)"))
        #expect(!reason.contains("KS_CANARY_AGENT"))
        #expect(!reason.contains("\n"), "the system prompt is one sentence")
    }

    // MARK: - WP-F3: two-step sign-ins

    @Test func theTwoStepHeadlineAndFillRowSayTheUsernameIsNowAndThePasswordIsNext() {
        let request = Self.agentFillRequest(facts: Self.facts(twoStep: true))
        let sentence = AgentFillSheetView.sentence(for: request)
        // The lead sentence is unchanged — the site still comes first — and the two-step story is
        // carried by its own explanation and by the Fill row, not folded into it.
        #expect(sentence == "An agent asks to sign in to login.example.com with “Example (work)”")

        #expect(
            AgentFillSheetView.twoStepExplanation
                == "The username is filled now. The password follows on the next page of the "
                + "same site, without asking you again. This approval is good for up to 60 "
                + "seconds.")
        #expect(AgentFillSheetView.twoStepExplanation.contains("60 seconds"))
        #expect(AgentFillSheetView.twoStepExplanation.contains("without asking"))

        let summary = AgentFillSheetView.fillSummary(Self.facts(twoStep: true))
        #expect(summary.contains("username now"))
        #expect(summary.contains("password on the next page"))
        #expect(summary.contains("without asking again"))
        #expect(summary.contains("60 seconds"))
    }

    @Test func aSingleStepFillsSummaryIsJustTheFieldNames() {
        let facts = Self.facts(twoStep: false)
        #expect(AgentFillSheetView.fillSummary(facts) == "username, password")
    }

    // MARK: - WP-F3: one-time codes

    @Test func theOneTimeCodeHeadlineAndFillRowSayItIsACodeNotThePassword() {
        let request = Self.agentFillRequest(facts: Self.facts(fields: [.oneTimeCode]))
        let sentence = AgentFillSheetView.sentence(for: request)
        #expect(
            sentence
                == "An agent asks to fill the one-time code for “Example (work)” on "
                + "login.example.com")
        #expect(!sentence.contains("sign in"), "a code is not a sign-in")

        let summary = AgentFillSheetView.fillSummary(Self.facts(fields: [.oneTimeCode]))
        #expect(summary == "a one-time code — not the password")

        // The Allow button still names the domain, whatever is being filled.
        #expect(AgentFillSheetView.allowLabel(for: request) == "Fill on example.com…")
    }

    // MARK: - WP-F3: the Touch ID prompt distinguishes what it is for

    @Test func theTouchIDReasonDistinguishesSignInTwoStepAndOneTimeCode() {
        let signIn = Self.agentFillRequest(facts: Self.facts())
        let signInReason = AgentService.reason(for: signIn)
        #expect(signInReason.contains("https://login.example.com"))
        #expect(signInReason.contains("Example (work)"))

        let twoStep = Self.agentFillRequest(facts: Self.facts(twoStep: true))
        let twoStepReason = AgentService.reason(for: twoStep)
        #expect(twoStepReason.contains("https://login.example.com"))
        #expect(twoStepReason.contains("Example (work)"))
        #expect(twoStepReason.contains("next page"))
        #expect(twoStepReason != signInReason, "a two-step request gets its own sentence")

        let code = Self.agentFillRequest(facts: Self.facts(fields: [.oneTimeCode]))
        let codeReason = AgentService.reason(for: code)
        #expect(codeReason.contains("https://login.example.com"))
        #expect(codeReason.contains("Example (work)"))
        #expect(codeReason.contains("one-time code"))
        #expect(codeReason != signInReason)
        #expect(codeReason != twoStepReason)

        for reason in [signInReason, twoStepReason, codeReason] {
            #expect(!reason.contains("example-agent"), "never the agent's name")
            #expect(!reason.contains("\n"), "one sentence")
        }
    }
}
