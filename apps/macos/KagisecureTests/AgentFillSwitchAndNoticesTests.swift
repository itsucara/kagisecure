import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Phase 2 of agent-requested fills, on the Swift side (ADR-0036 §2, §9; implementation decisions
/// 11, 12, 31–33; ui-spec.md §10.4, §10.7).
///
/// # What is under test
///
/// * the feature switch is on by default and flips either way without a presence check; what is
///   pushed to Rust is what is stored;
/// * **Deny and block** sends `.denyAndBlock` for an agent fill — and a plain `.deny` for anything
///   else — without a presence check;
/// * notices drained on the tick land in the recent list newest first, count toward the badge,
///   bounce the Dock icon **once** per drain, and are posted as system notifications;
/// * Unblock calls the FFI with the block's key and re-reads the list.
///
/// Every FFI and system call goes through `AgentFillService`'s seams, so nothing here touches the
/// process-wide broker, the Dock or the notification center.
@MainActor
struct AgentFillSwitchAndNoticesTests {
    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate
    typealias DecisionLog = BiometricGateAdversarialTests.DecisionLog

    // MARK: - Doubles

    /// Records what the service asked of the system notification center.
    final class RecordingNotifier: AgentFillNotifier {
        private(set) var authorizationRequests = 0
        private(set) var posts: [(title: String, body: String)] = []

        func requestAuthorization() async { authorizationRequests += 1 }
        func post(title: String, body: String) async { posts.append((title, body)) }
    }

    /// Everything the service sent across its seams.
    final class Calls {
        var pushed: [Bool] = []
        var attention = 0
        var unblocked: [String] = []
        var pendingNotices: [AgentFillNoticeView] = []
        var blocks: [AgentFillBlockView] = []
    }

    /// A throwaway defaults suite, so no test reads or writes the real preference.
    static func scratchDefaults() -> UserDefaults {
        let name = "ks-agent-fill-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    static func service(
        gate: BiometricGate, defaults: UserDefaults = scratchDefaults(), calls: Calls,
        notifier: RecordingNotifier
    ) -> AgentFillService {
        let presence = PresenceCoordinator(gate: gate)
        let service = AgentFillService(presence: presence, defaults: defaults, notifier: notifier)
        service.pushEnabled = { calls.pushed.append($0) }
        service.takeNotices = {
            defer { calls.pendingNotices = [] }
            return calls.pendingNotices
        }
        service.fetchBlocks = { calls.blocks }
        service.unblocker = { key in
            calls.unblocked.append(key)
            let had = calls.blocks.contains { $0.key == key }
            calls.blocks.removeAll { $0.key == key }
            return had
        }
        service.requestAttention = { calls.attention += 1 }
        return service
    }

    static let actor = "mcp \"example-agent\" [UNVERIFIED] pid 51234 /Applications/Kagisecure.app/Contents/Helpers/kagisecure-mcp"

    static func lookalike() -> AgentOriginView {
        AgentFillApprovalTests.origin(dimmedPrefix: "", emphasized: "examp1e.com")
    }

    // MARK: - The switch

    @Test func theSwitchIsOnByDefault() {
        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), calls: calls, notifier: RecordingNotifier())
        #expect(service.enabled, "on by default (amendment of 2026-10-03)")
        service.applyStoredSwitch()
        #expect(calls.pushed == [true])
    }

    @Test func turningTheSwitchOnAsksNothing() async {
        let gate = ScriptedGate(.authenticated)
        let calls = Calls()
        let notifier = RecordingNotifier()
        let defaults = Self.scratchDefaults()
        defaults.set(false, forKey: AgentFillService.enabledKey)
        let service = Self.service(gate: gate, defaults: defaults, calls: calls, notifier: notifier)
        #expect(!service.enabled)

        await service.setEnabled(true)

        #expect(gate.reasons.isEmpty, "no presence check")
        #expect(service.enabled)
        #expect(calls.pushed == [true])
        #expect(defaults.bool(forKey: AgentFillService.enabledKey))
        #expect(notifier.authorizationRequests == 1)
    }

    @Test func turningTheSwitchOffAsksNothing() async {
        let gate = ScriptedGate(.authenticated)
        let calls = Calls()
        let defaults = Self.scratchDefaults()
        defaults.set(true, forKey: AgentFillService.enabledKey)
        let service = Self.service(
            gate: gate, defaults: defaults, calls: calls, notifier: RecordingNotifier())
        service.applyStoredSwitch()
        #expect(service.enabled)
        #expect(calls.pushed == [true], "the stored switch is pushed at launch and unlock")

        await service.setEnabled(false)

        #expect(gate.reasons.isEmpty, "narrowing never asks")
        #expect(!service.enabled)
        #expect(calls.pushed == [true, false])
        #expect(!defaults.bool(forKey: AgentFillService.enabledKey))
    }

    @Test func theStoredSwitchIsPushedEvenWhenOff() {
        let calls = Calls()
        let defaults = Self.scratchDefaults()
        defaults.set(false, forKey: AgentFillService.enabledKey)
        let service = Self.service(
            gate: ScriptedGate(.authenticated), defaults: defaults, calls: calls,
            notifier: RecordingNotifier())
        service.applyStoredSwitch()
        #expect(calls.pushed == [false], "Rust hears the user's choice, not an assumption")
    }

    // MARK: - Deny and block

    @Test func denyAndBlockSendsItsDecisionWithoutAPresenceCheck() {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = AgentFillApprovalTests.service(gate: gate, log: log)
        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)

        service.denyAndBlock(request)

        #expect(log.decisions.map(\.id) == [request.id])
        #expect(log.decisions.map(\.decision) == [.denyAndBlock])
        #expect(gate.reasons.isEmpty, "saying no never asks for a fingerprint")
        #expect(service.current == nil, "the sheet is answered")
    }

    @Test func denyAndBlockOnAnythingButAnAgentFillIsAPlainDenial() {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = AgentFillApprovalTests.service(gate: gate, log: log)
        var request = AgentFillApprovalTests.agentFillRequest(id: "ks-env-1", facts: nil)
        request.action = .writeEnvFile
        service.enqueue(request)

        service.denyAndBlock(request)

        #expect(log.decisions.map(\.decision) == [.deny])
        #expect(gate.reasons.isEmpty)
    }

    @Test func theDenyAndBlockButtonSaysWhatItDoes() {
        #expect(AgentFillSheetView.denyAndBlockLabel == "Deny and block this agent for 30 minutes")
        #expect(AgentFillSheetKeys.response(to: .escape) == .deny, "Esc is still a plain Deny")
    }

    // MARK: - Notices

    @Test func noticesDrainIntoTheListAndRaiseAttentionOncePerDrain() async {
        let calls = Calls()
        let notifier = RecordingNotifier()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), calls: calls, notifier: notifier)
        calls.pendingNotices = [
            .originMismatch(agent: Self.actor, itemTitle: "Example (work)", origin: Self.lookalike()),
            .blocked(agent: Self.actor, key: "/usr/local/bin/example-client", reason: .originMismatch),
        ]

        service.tick()

        #expect(service.recent.count == 2)
        if case .some(.blocked) = service.recent.first?.notice {} else {
            Issue.record("newest first: the block came after the mismatch")
        }
        #expect(service.unseen == 2)
        #expect(calls.attention == 1, "one bounce for the batch, not one per notice")
        #expect(await eventually { notifier.posts.count == 2 })

        // A quiet tick changes nothing and bounces nothing.
        service.tick()
        #expect(service.recent.count == 2)
        #expect(calls.attention == 1)

        service.markSeen()
        #expect(service.unseen == 0, "seeing Agent access clears the badge")
        #expect(service.recent.count == 2, "but keeps the list")
    }

    @Test func theRecentListIsShortAndLockEmptiesIt() {
        let calls = Calls()
        let service = Self.service(
            gate: ScriptedGate(.authenticated), calls: calls, notifier: RecordingNotifier())
        for n in 0..<(AgentFillService.recentLimit + 3) {
            calls.pendingNotices = [
                .rateLimited(agent: Self.actor, key: "/k\(n)", requests: 4, windowMinutes: 10)
            ]
            service.tick()
        }
        #expect(service.recent.count == AgentFillService.recentLimit)
        #expect(calls.attention == AgentFillService.recentLimit + 3)

        service.vaultLocked()
        #expect(service.recent.isEmpty, "the list names items; it goes with the key")
        #expect(service.unseen == 0)
    }

    @Test func noticeTextIsMetadataInTheADRsWords() {
        let mismatch = AgentFillNoticeView.originMismatch(
            agent: Self.actor, itemTitle: "Example (work)", origin: Self.lookalike())
        #expect(
            AgentFillText.body(for: mismatch)
                == "“example-agent” asked to fill “Example (work)” on examp1e.com, which is not a "
                + "site saved for it. Nothing was filled.")

        let limited = AgentFillNoticeView.rateLimited(
            agent: Self.actor, key: "/usr/local/bin/example-client", requests: 4, windowMinutes: 10)
        #expect(
            AgentFillText.body(for: limited)
                == "“example-agent” has asked to fill logins 4 times in 10 minutes; further "
                + "requests are refused for 10 minutes.")

        let blocked = AgentFillNoticeView.blocked(
            agent: Self.actor, key: "/usr/local/bin/example-client", reason: .originMismatch)
        #expect(AgentFillText.body(for: blocked).contains("until you unblock it"))

        // The actor's kernel facts are not the name; an actor with no reported name is "An agent".
        #expect(!AgentFillText.body(for: limited).contains("pid"))
        #expect(AgentFillText.agentName(fromActor: "mcp unknown [UNVERIFIED] pid 1 /x") == "An agent")
        #expect(
            AgentFillText.agentName(fromActor: "mcp \"a \\\"quoted\\\" name\" [UNVERIFIED] pid 1 /x")
                == "“a 'quoted' name”",
            "an escaped quote in the name cannot close the app's own quotation")
    }

    @Test func theUnmaskedNoticeSaysWhatHappenedAndNoMore() {
        let unmasked = AgentFillNoticeView.unmasked(
            agent: Self.actor, itemTitle: "Example (work)", origin: AgentFillApprovalTests.origin())
        #expect(
            AgentFillText.body(for: unmasked)
                == "“example-agent” filled a password from “Example (work)” on "
                + "login.example.com and the page made it visible within seconds; kagisecure "
                + "cleared the field. The agent may have read it.")
        #expect(AgentFillText.title(for: unmasked) == "Filled password was revealed")
        // Metadata only: the agent's reported name, the item's title and the origin — no value.
        #expect(!AgentFillText.body(for: unmasked).contains("pid"))
    }

    @Test func aPunycodeOriginIsShownBesideItsUnicodeRendering() {
        let origin = AgentFillApprovalTests.origin(
            dimmedPrefix: "", emphasized: "xn--exmple-cua.com", unicodeHost: "exämple.com",
            mixedScript: false)
        #expect(
            AgentFillText.site(origin)
                == "xn--exmple-cua.com (shown by the browser as exämple.com)")
    }

    // MARK: - Blocks

    @Test func unblockCallsTheFFIWithTheKeyAndRefreshesTheList() {
        let calls = Calls()
        calls.blocks = [
            AgentFillBlockView(
                key: "/usr/local/bin/example-client", agentName: "example-agent",
                reason: .deniedAndBlocked, until: 1_900_000_000),
            AgentFillBlockView(
                key: "/opt/other/agent", agentName: "other", reason: .originMismatch, until: nil),
        ]
        let service = Self.service(
            gate: ScriptedGate(.authenticated), calls: calls, notifier: RecordingNotifier())
        service.tick()
        #expect(service.blocks.count == 2)

        service.unblock(service.blocks[0])

        #expect(calls.unblocked == ["/usr/local/bin/example-client"])
        #expect(service.blocks.map(\.key) == ["/opt/other/agent"], "re-read, not patched")
    }

    @Test func aBlockSaysUntilWhen() {
        #expect(AgentFillText.until(nil) == "until you unblock it")
        #expect(AgentFillText.until(1_900_000_000).hasPrefix("until "))
        #expect(AgentFillText.reason(.deniedAndBlocked) == "You chose Deny and block")
        #expect(AgentFillText.quoted("KS\u{202E}agent") == "“KSagent”", "sanitized, then quoted")
    }
}
