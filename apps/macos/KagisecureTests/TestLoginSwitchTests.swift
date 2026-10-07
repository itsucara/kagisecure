import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// ADR-0048 §1, §3, §10 through `TestLoginService`'s seams: no vault, no Touch ID sheet.
@MainActor
struct TestLoginSwitchTests {
    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate

    final class Notifier: AgentFillNotifier {
        var authorizations = 0
        var posts: [(title: String, body: String)] = []
        func requestAuthorization() async { authorizations += 1 }
        func post(title: String, body: String) async { posts.append((title, body)) }
    }

    final class State {
        var enabled = false
        var domains: [String] = []
        var pushed: [Bool] = []
    }

    static func service(_ outcome: BiometricOutcome, state: State, notifier: Notifier) -> TestLoginService {
        let service = TestLoginService(presence: PresenceCoordinator(gate: ScriptedGate(outcome)), notifier: notifier)
        service.fetchSettings = {
            AgentTestLoginSettingsView(enabled: state.enabled, autoDomains: state.domains, vaultId: nil)
        }
        service.pushEnabled = { state.enabled = $0; state.pushed.append($0) }
        service.addDomain = { state.domains.append($0); return $0 }
        service.removeDomain = { d in state.domains.removeAll { $0 == d }; return true }
        return service
    }

    @Test func turningOnAsksForPresenceThenPushes() async {
        let state = State(), notifier = Notifier()
        let service = Self.service(.authenticated, state: state, notifier: notifier)
        await service.setEnabled(true)
        #expect(state.pushed == [true])
        #expect(service.settings.enabled)
        #expect(notifier.authorizations == 1)
    }

    @Test func aCancelledCheckLeavesItOff() async {
        let state = State(), notifier = Notifier()
        let service = Self.service(.cancelled, state: state, notifier: notifier)
        await service.setEnabled(true)
        #expect(state.pushed.isEmpty)
        #expect(!service.settings.enabled)
        #expect(service.problem != nil)
    }

    @Test func turningOffAsksNothing() async {
        let state = State(), notifier = Notifier()
        state.enabled = true
        let service = Self.service(.cancelled, state: state, notifier: notifier)
        service.refresh()
        await service.setEnabled(false)
        #expect(state.pushed == [false])
    }

    @Test func addingADomainNeedsPresenceAndRemovingDoesNot() async {
        let state = State(), notifier = Notifier()
        let denied = Self.service(.cancelled, state: state, notifier: notifier)
        #expect(await denied.add(domain: "example.com") == false)
        #expect(state.domains.isEmpty)
        let ok = Self.service(.authenticated, state: state, notifier: notifier)
        #expect(await ok.add(domain: "example.com"))
        #expect(ok.settings.autoDomains == ["example.com"])
        denied.remove(domain: "example.com")
        #expect(state.domains.isEmpty)
    }

    @Test func aNoticeCountsAndPostsTheSentence() async {
        let state = State(), notifier = Notifier()
        let service = Self.service(.authenticated, state: state, notifier: notifier)
        service.takeNotices = {
            [.created(agent: "mcp \"Claude Code\" pid 1", title: "test: shop / buyer #1",
                      username: "u", websites: ["http://localhost:47800"])]
        }
        service.tick()
        #expect(service.createdCount == 1)
        for _ in 0..<50 where notifier.posts.isEmpty { try? await Task.sleep(for: .milliseconds(20)) }
        #expect(notifier.posts.first?.body == "“Claude Code” created test login “test: shop / buyer #1” for localhost:47800")
        #expect(TestLoginService.menuTitle(count: 3) == "3 test logins created by agents")
        service.vaultLocked()
        #expect(service.createdCount == 0)
    }

    @Test func acknowledgingClearsTheMenuBarCount() {
        let service = Self.service(.authenticated, state: State(), notifier: Notifier())
        service.takeNotices = {
            [.created(agent: "a", title: "t", username: "u", websites: ["http://localhost:1"])]
        }
        service.tick()
        #expect(service.createdCount == 1)
        service.acknowledge()
        #expect(service.createdCount == 0)
    }

    @Test func theSealedPasswordFieldIsNotRemovable() {
        #expect(ItemEditView.isSealed("f1", regenerateOnlyFieldId: "f1"))
        #expect(!ItemEditView.isSealed("f2", regenerateOnlyFieldId: "f1"))
        #expect(!ItemEditView.isSealed(nil, regenerateOnlyFieldId: nil))
        #expect(!ItemEditView.isSealed("f1", regenerateOnlyFieldId: nil))
    }
}
