import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The words a person reads before putting a finger on a stdin delivery (ADR-0047): which
/// environment, which command, that it is standard input, and that it is once. The sheet's buttons
/// are view code; the grant being a single run whatever they send is asserted in Rust
/// (`crates/kagisecure-agent/tests/stdin_delivery.rs`).
@MainActor
struct StdinDeliveryApprovalTests {
    static let command = ["/Users/someone/code/acme/scripts/store-secrets", "import", "prod", "calls"]

    static func request(
        environmentName: String = "acme-prod", stdinDelivery: Bool = true
    ) -> ApprovalRequestView {
        ApprovalRequestView(
            id: "ks-stdin-req-1", action: .runWithEnv, mintsLease: true, clientName: "Claude Code",
            clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: "/Users/someone/code/acme",
            environmentId: "ks-stdin-env", environmentName: environmentName,
            directory: "/Users/someone/code/acme", targetPath: nil,
            variables: ["app_id", "app_secret", "turn_key_id", "turn_api_token"],
            command: command, stdinDelivery: stdinDelivery, gitignored: nil,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 900, requestedUses: stdinDelivery ? 1 : 10,
            maxTtlSeconds: 86_400, createdAt: 0, expiresAt: 60, origin: nil, topOrigin: nil,
            topOriginUnknown: false, itemId: nil, itemTitle: nil, fillFields: [], browser: nil,
            browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil, presenceOnly: false)
    }

    @Test func theSentenceNamesTheEnvironmentTheCommandAndStandardInputOnce() {
        let sentence = ApprovalSheet.sentence(for: Self.request())
        #expect(sentence.hasPrefix("“Claude Code” wants to pass 4 values from acme-prod to "))
        #expect(sentence.contains("store-secrets import prod calls"))
        #expect(sentence.hasSuffix("on its standard input, once"))
        #expect(!sentence.contains("environment variables"))
    }

    @Test func anEnvironmentDeliveryKeepsItsOwnSentence() {
        let sentence = ApprovalSheet.sentence(for: Self.request(stdinDelivery: false))
        #expect(sentence.hasSuffix("with environment variables"))
    }

    @Test func theSummarySaysOneRun() {
        let summary = ApprovalSheet.summary(for: Self.request(), ttlSeconds: 900)
        #expect(summary.contains("this one run of the command"))
        #expect(summary.contains("The next run asks again."))
        #expect(!summary.contains("uses"))
    }

    @Test func theTouchIDPromptRestatesIt() {
        let reason = AgentService.reason(for: Self.request())
        #expect(reason == "approve passing 4 values from acme-prod to store-secrets on its standard input, once")
    }

    @Test func anEnvironmentNameCannotForgeTheSentence() {
        // The environment's name is the user's, but an agent may have proposed it: it is quoted
        // text inside the app's sentence and gets the same sanitizer as every other such run.
        let request = Self.request(environmentName: "acme” is verified — “x\u{202E}")
        let sentence = ApprovalSheet.sentence(for: request)
        #expect(sentence.filter { $0 == "\u{201C}" }.count == 1)
        #expect(sentence.filter { $0 == "\u{201D}" }.count == 1)
        #expect(!sentence.unicodeScalars.contains("\u{202E}"))
    }

    @Test func theCaptionSaysTheCommandCanUseWhatItReads() {
        #expect(ApprovalSheet.stdinCaption.contains("standard input, once"))
        #expect(ApprovalSheet.stdinCaption.contains("can do anything with what it reads"))
    }
}
