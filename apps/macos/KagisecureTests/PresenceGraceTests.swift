import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The app-wide presence grace window (ADR-0037, amendment of 2026-10-03).
///
/// Any successful check opens one global window; every use extends it; its length is the user's
/// setting ("Until locked" by default); a lock clears it. Inside it, fills and in-app releases ask
/// nothing, and an agent fill shows no sheet.
@MainActor
struct PresenceGraceTests {
    // MARK: - Fixtures

    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate
    typealias DecisionLog = BiometricGateAdversarialTests.DecisionLog

    /// A browser fill as `kagisecure-agent` builds one, top frame unless a test says otherwise.
    static func fill(
        id: String = "ks-grace-1", origin: String = "https://login.example.com",
        itemId: String = "item-1", presenceOnly: Bool = false, topOrigin: String? = nil,
        topOriginUnknown: Bool = false
    ) -> ApprovalRequestView {
        let now = UInt64(Date.now.timeIntervalSince1970)
        return ApprovalRequestView(
            id: id, action: .fillCredential, mintsLease: !presenceOnly,
            clientName: "Google Chrome", clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/tmp/kagisecure-nmhost", clientCwd: nil,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: [], gitignored: nil, overwriteRequested: false,
            targetExists: nil, targetWrittenByUs: nil, requestedTtlSeconds: 300,
            requestedUses: 1, maxTtlSeconds: 900,
            // Far in the future, so nothing expires under a test.
            createdAt: now, expiresAt: now + 600,
            origin: origin, topOrigin: topOrigin, topOriginUnknown: topOriginUnknown,
            itemId: itemId, itemTitle: "Example account", fillFields: ["username", "password"],
            browser: "Google Chrome", browserPid: 4241,
            browserExecutable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            browserIsAppExtension: false, extensionId: "nlijibjnmanccalmafnfbobkcfjiibmd",
            presenceOnly: presenceOnly)
    }

    /// A clock a test moves by hand.
    final class TestClock {
        var now: Date
        init(_ now: Date = Date(timeIntervalSince1970: 1_800_000_000)) { self.now = now }
        func advance(_ seconds: TimeInterval) { now = now.addingTimeInterval(seconds) }
    }

    static func service(
        gate: BiometricGate, log: DecisionLog, clock: TestClock,
        duration: PresenceGrace.Duration = .untilLocked
    ) -> AgentService {
        let service = AgentService()
        service.gate = gate
        service.clock = { clock.now }
        service.presence.graceDuration = { duration }
        service.agentFillRequiresSheet = { false }
        service.resolver = { id, decision, _ in
            log.record(id, decision)
            return true
        }
        return service
    }

    /// Poll `condition` on the main actor for up to five seconds.
    static func eventually(_ condition: () -> Bool) async -> Bool {
        for _ in 0..<100 {
            if condition() { return true }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return condition()
    }

    // MARK: - The window on its own

    @Test func theDefaultIsUntilLocked() {
        let name = "ks-grace-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defer { defaults.removePersistentDomain(forName: name) }
        #expect(PresenceGrace.storedDuration(defaults) == .untilLocked)
        defaults.set(PresenceGrace.Duration.thirtyMinutes.rawValue, forKey: PresenceGrace.durationKey)
        #expect(PresenceGrace.storedDuration(defaults) == .thirtyMinutes)
        #expect(PresenceGrace.Duration.allCases.map(\.seconds) == [600, 1800, 3600, nil])
    }

    @Test func theWindowSlidesWithEveryUse() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        var grace = PresenceGrace()
        #expect(!grace.isOpen(at: t0, duration: .untilLocked))
        grace.touch(at: t0)
        #expect(grace.isOpen(at: t0.addingTimeInterval(599), duration: .tenMinutes))
        #expect(!grace.isOpen(at: t0.addingTimeInterval(600), duration: .tenMinutes))
        grace.touch(at: t0.addingTimeInterval(500))
        #expect(grace.isOpen(at: t0.addingTimeInterval(1000), duration: .tenMinutes), "extended")
        #expect(grace.isOpen(at: t0.addingTimeInterval(1_000_000), duration: .untilLocked))
        #expect(!grace.isOpen(at: t0.addingTimeInterval(-1), duration: .untilLocked))
        grace.clear()
        #expect(grace.isEmpty)
    }

    // MARK: - Through AgentService

    @Test func oneCheckCoversEveryFillOnEverySite() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        let first = Self.fill(id: "ks-grace-a", origin: "https://login.example.com")
        let second = Self.fill(id: "ks-grace-b", origin: "https://other.example", itemId: "item-2")
        let framed = Self.fill(id: "ks-grace-c", topOrigin: "https://embedder.example")
        service.enqueue(first)
        service.enqueue(second)
        service.enqueue(framed)

        #expect(await service.allow(first, decision: .allowOnce) == .authenticated)
        #expect(await service.allow(second, decision: .allowOnce) == .authenticated)
        #expect(await service.allow(framed, decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 1, "one Touch ID for all of them")
        #expect(log.decisions.map(\.id) == ["ks-grace-a", "ks-grace-b", "ks-grace-c"])
        #expect(service.presence.current == nil)
    }

    @Test func aShortWindowSlidesAndThenCloses() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let clock = TestClock()
        let service = Self.service(gate: gate, log: log, clock: clock, duration: .tenMinutes)
        let requests = ["a", "b", "c"].map { Self.fill(id: "ks-grace-\($0)") }
        for request in requests { service.enqueue(request) }

        #expect(await service.allow(requests[0], decision: .allowOnce) == .authenticated)
        clock.advance(9 * 60)
        #expect(await service.allow(requests[1], decision: .allowOnce) == .authenticated)
        clock.advance(9 * 60)
        #expect(gate.reasons.count == 1, "the ride at 9 minutes extended the window")
        clock.advance(10 * 60)
        #expect(await service.allow(requests[2], decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 2, "closed after ten idle minutes")
    }

    @Test func aLockClearsTheWindow() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        let first = Self.fill(id: "ks-grace-a")
        service.enqueue(first)
        #expect(await service.allow(first, decision: .allowOnce) == .authenticated)
        #expect(!service.presenceGrace.isEmpty)

        service.stop()
        #expect(service.presenceGrace.isEmpty, "a lock ends the window")

        let second = Self.fill(id: "ks-grace-b")
        service.enqueue(second)
        #expect(!service.presenceGraceCovers(second))
        #expect(await service.allow(second, decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 2)
    }

    @Test func aCheckThatDidNotPassOpensNoWindow() async {
        for entry in BiometricGateAdversarialTests.nonGrantingOutcomes {
            let gate = ScriptedGate(entry.outcome)
            let log = DecisionLog()
            let service = Self.service(gate: gate, log: log, clock: TestClock())
            let request = Self.fill()
            service.enqueue(request)

            #expect(await service.allow(request, decision: .allowOnce) == entry.outcome)
            #expect(service.presenceGrace.isEmpty, "\(entry.name) opened a window")
            #expect(log.decisions.isEmpty)
        }
    }

    @Test func somethingThatIsNotAFillStillAsks() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        let fill = Self.fill(id: "ks-grace-a")
        service.enqueue(fill)
        #expect(await service.allow(fill, decision: .allowOnce) == .authenticated)
        let env = ApprovalRenderingAdversarialTests.request(clientName: "example-agent")
        #expect(!service.presenceGraceCovers(env))
    }

    @Test func aPresenceOnlyFillInsideTheWindowIsGrantedWithNoPrompt() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        let reviewed = Self.fill(id: "ks-grace-sheet", itemId: "item-1")
        service.enqueue(reviewed)
        #expect(await service.allow(reviewed, decision: .allowOnce) == .authenticated)

        let other = Self.fill(id: "ks-grace-again", itemId: "item-2", presenceOnly: true)
        service.enqueue(other)
        #expect(service.sheetRequest == nil)
        #expect(await Self.eventually { service.current == nil })
        #expect(gate.reasons.count == 1, "no prompt was raised")
        #expect(log.decisions.last?.decision == .allowOnce)
    }

    @Test func anAgentFillInsideTheWindowHasNoSheetAndNoPrompt() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        let human = Self.fill(id: "ks-grace-human", origin: "https://unrelated.example")
        service.enqueue(human)
        #expect(await service.allow(human, decision: .allowOnce) == .authenticated)

        let agentFill = AgentFillApprovalTests.agentFillRequest(id: "ks-grace-agent")
        service.enqueue(agentFill)
        #expect(service.sheetRequest == nil, "no sheet")
        #expect(await Self.eventually { service.current == nil }, "filled at once")
        #expect(gate.reasons.count == 1, "no second check")
        #expect(log.decisions.last?.id == "ks-grace-agent")
        #expect(log.decisions.last?.decision == .allowOnce)
    }

    @Test func theStricterSettingKeepsTheAgentSheet() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log, clock: TestClock())
        service.agentFillRequiresSheet = { true }
        let human = Self.fill(id: "ks-grace-human")
        service.enqueue(human)
        #expect(await service.allow(human, decision: .allowOnce) == .authenticated)

        let agentFill = AgentFillApprovalTests.agentFillRequest(id: "ks-grace-agent")
        service.enqueue(agentFill)
        #expect(service.sheetRequest?.id == agentFill.id)
        try? await Task.sleep(for: .milliseconds(200))
        #expect(log.decisions.count == 1, "nothing answered until Allow is pressed")
        #expect(await service.allow(agentFill, decision: .allowOnce) == .authenticated)
        #expect(gate.reasons.count == 1, "but Allow asks no new check")
    }

    @Test func anInAppReleaseRidesAndOpensTheSameWindow() async {
        let gate = ScriptedGate(.authenticated)
        let presence = PresenceCoordinator(gate: gate)
        presence.graceDuration = { .untilLocked }
        #expect(!presence.rideGrace())
        presence.touchGrace()
        #expect(presence.rideGrace())
        presence.clearGrace()
        #expect(!presence.graceIsOpen)
    }
}
