import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// ADR-0048: the create sheet's strings, and which requests ride the presence grace.
@MainActor
struct TestLoginApprovalTests {
    static func facts(
        host: String = "example-partner.com", prefix: String = "staging.", scheme: String = "https",
        near: String? = nil
    ) -> TestLoginFactsView {
        let origin = AgentOriginView(
            ascii: "\(scheme)://\(prefix)\(host)", scheme: scheme, dimmedPrefix: prefix,
            emphasized: host, port: nil, unicodeHost: nil, mixedScript: false,
            notEncrypted: scheme == "http")
        return TestLoginFactsView(
            agent: "mcp \"Claude Code\"", agentName: "Claude Code", title: "test: shop / buyer #1",
            username: "buyer1@example.test",
            websites: [TestLoginWebsiteView(origin: origin, nearItemTitle: near, notHttps: scheme == "http")],
            purpose: "buyer", tags: ["app:shop"], generator: "32 characters, with symbols",
            reason: "testing checkout")
    }

    static func request(
        action: ApprovalAction, testLogin: TestLoginFactsView? = nil, ridesGrace: Bool = false
    ) -> ApprovalRequestView {
        let now = UInt64(Date.now.timeIntervalSince1970)
        return ApprovalRequestView(
            id: "ks-test-login-1", action: action, mintsLease: action == .runWithEnv,
            clientName: "Claude Code", clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: nil,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: action == .runWithEnv ? ["npm", "test"] : [], gitignored: nil,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 0, requestedUses: 1, maxTtlSeconds: 0,
            createdAt: now, expiresAt: now + 600, origin: nil, topOrigin: nil,
            topOriginUnknown: false, itemId: nil, itemTitle: nil, fillFields: [], browser: nil,
            browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil, presenceOnly: false, testLogin: testLogin, ridesGrace: ridesGrace)
    }

    @Test func theSentenceLeadsWithTheRegistrableDomainAndQuotesTheAgent() {
        let r = Self.request(action: .createTestLogin, testLogin: Self.facts())
        let sentence = ApprovalSheet.sentence(for: r)
        #expect(sentence == "“Claude Code” wants to create a test login for example-partner.com")
    }

    @Test func theReasonNamesTheSiteAndNoValue() {
        let r = Self.request(action: .createTestLogin, testLogin: Self.facts())
        let reason = AgentService.reason(for: r)
        #expect(reason.contains("example-partner.com"))
        #expect(!reason.contains("\n"))
        #expect(!reason.contains("buyer1@example.test"))
    }

    @Test func theSummaryAndGeneratorLinesSayTheAgentNeverReceivesThePassword() {
        let r = Self.request(action: .createTestLogin, testLogin: Self.facts())
        #expect(ApprovalSheet.summary(for: r, ttlSeconds: 0).contains("never receives the password"))
        #expect(TestLoginFactsBlock.generatorSummary(Self.facts()).contains("32 characters, with symbols"))
        #expect(ApprovalSheet.symbol(for: r) == "person.badge.plus")
    }

    @Test func severalWebsitesAreCountedAndNearHostIsWorded() {
        var f = Self.facts()
        f.websites.append(f.websites[0])
        #expect(TestLoginFactsBlock.leadDomain(f) == "example-partner.com and 1 more")
        #expect(TestLoginFactsBlock.nearHostText("Partner").contains("“Partner”"))
    }

    @Test func aCreateNeverRidesTheGrace() {
        let r = Self.request(action: .createTestLogin, testLogin: Self.facts(), ridesGrace: true)
        #expect(!PresenceGrace.applies(to: r))
    }

    @Test func onlyARunBoundToTestLoginsRidesTheGrace() {
        #expect(PresenceGrace.applies(to: Self.request(action: .runWithEnv, ridesGrace: true)))
        #expect(PresenceGrace.applies(to: Self.request(action: .writeEnvFile, ridesGrace: true)))
        #expect(!PresenceGrace.applies(to: Self.request(action: .runWithEnv)))
        #expect(!PresenceGrace.applies(to: Self.request(action: .addVariables, ridesGrace: true)))
    }

    @Test func aRidesGraceRunSkipsItsSheetOnlyInsideTheWindow() {
        let service = AgentService()
        let run = Self.request(action: .runWithEnv, ridesGrace: true)
        #expect(!service.skipsSheet(run))
        service.presence.touchGrace()
        #expect(service.skipsSheet(run))
        #expect(!service.skipsSheet(Self.request(action: .runWithEnv)))
        let create = Self.request(action: .createTestLogin, testLogin: Self.facts())
        #expect(!service.skipsSheet(create))
    }
}
