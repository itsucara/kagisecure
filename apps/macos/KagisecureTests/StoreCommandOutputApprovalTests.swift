import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// ADR-0049: the store-command-output sheet's strings, and the absence of any session option or
/// grace window for it.
@MainActor
struct StoreCommandOutputApprovalTests {
    static func facts(
        itemId: String? = nil, fillsEmpty: Bool = false, reason: String? = "set up the CWS API"
    ) -> StoreOutputFactsView {
        StoreOutputFactsView(
            agent: "mcp \"Claude Code\"", itemTitle: "Chrome Web Store API", itemId: itemId,
            newItemCategory: itemId == nil ? "api-credential" : nil, vaultName: "Personal",
            fieldLabel: "refresh_token", fillsEmptyField: fillsEmpty, timeoutSeconds: 300,
            reason: reason)
    }

    static func request(
        ridesGrace: Bool = false, storeOutput: StoreOutputFactsView? = facts()
    ) -> ApprovalRequestView {
        let now = UInt64(Date.now.timeIntervalSince1970)
        return ApprovalRequestView(
            id: "ks-store-output-1", action: .storeCommandOutput, mintsLease: false,
            clientName: "Claude Code", clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: nil,
            environmentId: "env-1", environmentName: "CWS", directory: "/work/app", targetPath: nil,
            variables: ["CWS_CLIENT_ID", "CWS_CLIENT_SECRET"],
            command: ["cargo", "xtask", "chrome-auth"], gitignored: nil,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 0, requestedUses: 1, maxTtlSeconds: 0,
            createdAt: now, expiresAt: now + 600, origin: nil, topOrigin: nil,
            topOriginUnknown: false, itemId: nil, itemTitle: nil, fillFields: [], browser: nil,
            browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil, presenceOnly: false, ridesGrace: ridesGrace,
            storeOutput: storeOutput)
    }

    @Test func theSentenceQuotesTheAgentAndNamesTheCommandAndItem() {
        let sentence = ApprovalSheet.sentence(for: Self.request())
        #expect(
            sentence
                == "“Claude Code” wants to run cargo xtask chrome-auth and store its output in “Chrome Web Store API”")
    }

    @Test func theSummaryAndNoticeSayTheAgentNeverSeesTheOutput() {
        let summary = ApprovalSheet.summary(for: Self.request(), ttlSeconds: 0)
        #expect(summary.contains("never receives the output"))
        #expect(summary.contains("Touch ID"))
        #expect(StoreCommandOutputFactsBlock.notice.contains("The agent will not see it"))
    }

    @Test func theTargetAndFieldLinesDistinguishNewExistingAndEmpty() {
        let new = Self.facts()
        #expect(StoreCommandOutputFactsBlock.targetSummary(new).hasPrefix("New item “Chrome Web Store API” (api-credential)"))
        #expect(StoreCommandOutputFactsBlock.fieldSummary(new).contains("new, concealed"))
        let filled = Self.facts(itemId: "i1", fillsEmpty: true)
        #expect(StoreCommandOutputFactsBlock.targetSummary(filled).hasPrefix("Existing item"))
        #expect(StoreCommandOutputFactsBlock.fieldSummary(filled).contains("will be filled"))
        let added = Self.facts(itemId: "i1", fillsEmpty: false)
        #expect(StoreCommandOutputFactsBlock.fieldSummary(added).contains("will be added"))
        #expect(StoreCommandOutputFactsBlock.timeoutSummary(new) == "300 seconds")
    }

    @Test func untrustedTitlesCannotCloseTheQuoting() {
        var f = Self.facts()
        f.itemTitle = "x” is verified “"
        #expect(!StoreCommandOutputFactsBlock.targetSummary(f).contains("verified “"))
    }

    @Test func theTouchIDPromptNamesTheCommandAndTheItem() {
        let reason = AgentService.reason(for: Self.request())
        #expect(reason.contains("cargo"))
        #expect(reason.contains("Chrome Web Store API"))
        #expect(!reason.contains("\n"))
    }

    @Test func noGraceEvenWhenTheRequestClaimsIt() {
        #expect(!PresenceGrace.applies(to: Self.request()))
        #expect(!PresenceGrace.applies(to: Self.request(ridesGrace: true)))
    }

    @Test func itAlwaysShowsASheetAndOffersNoSessionOption() {
        let agent = AgentService()
        let r = Self.request(ridesGrace: true)
        #expect(!agent.skipsSheet(r))
        #expect(AgentService.needsSheet(r))
        #expect(!r.mintsLease)
    }
}
