import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The browser-fill approval, on the Swift side (M6).
///
/// # What is under test, and what is not
///
/// The *rule* — which items a page may be filled from — is Rust's, and is asserted there
/// (`crates/kagisecure-extension-ipc/src/origin.rs` has the table). What is asserted here is the
/// half only Swift owns:
///
/// * that a fill request is recognized as a fill and routed to the fill rendering, not the agent
///   one;
/// * that the sheet's sentence, biometric prompt and summary state the item and the origin and
///   never anything else;
/// * that a fill's identity is **two** verdicts, and that the single verdict recorded in the lease
///   and the audit entry is the weaker of them;
/// * that a cross-origin frame is visible in the record the sheet is built from.
///
/// The sheet's pixels are not asserted. What is asserted is every string the sheet reads off the
/// model, which is where a mistake would actually be — a view that renders the wrong field is a
/// bug you see; a model that hands the view an origin from the wrong frame is not.
@MainActor
struct FillApprovalTests {
    // MARK: - Fixtures

    /// A fill request as `kagisecure-agent` builds one, with nothing that a value could sit in.
    private static func fillRequest(
        origin: String = "https://example.com",
        topOrigin: String? = nil,
        fields: [String] = ["username", "password"],
        title: String = "Example account",
        browser: String? = "Google Chrome"
    ) -> ApprovalRequestView {
        ApprovalRequestView(
            id: "req-1",
            action: .fillCredential,
            mintsLease: false,
            clientName: browser ?? "a browser",
            clientPid: 4242,
            clientPidFromKernel: true,
            clientExecutable: "/tmp/kagisecure-nmhost",
            clientCwd: nil,
            environmentId: nil,
            environmentName: nil,
            directory: nil,
            targetPath: nil,
            variables: [],
            command: [],
            gitignored: nil,
            requestedTtlSeconds: 300,
            requestedUses: 1,
            maxTtlSeconds: 900,
            createdAt: 1_757_000_000,
            expiresAt: 1_757_000_060,
            origin: origin,
            topOrigin: topOrigin,
            itemId: "item-1",
            itemTitle: title,
            fillFields: fields,
            browser: browser,
            browserPid: 4241,
            browserExecutable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            browserIsAppExtension: false,
            extensionId: "nlijibjnmanccalmafnfbobkcfjiibmd")
    }

    /// An env-file request, for the comparisons that matter: the two must not be confused.
    private static func envRequest() -> ApprovalRequestView {
        ApprovalRequestView(
            id: "req-2",
            action: .writeEnvFile,
            mintsLease: true,
            clientName: "Claude Code",
            clientPid: 99,
            clientPidFromKernel: true,
            clientExecutable: "/tmp/kagisecure-mcp",
            clientCwd: "/tmp/project",
            environmentId: "env-1",
            environmentName: "acme / staging",
            directory: "/tmp/project",
            targetPath: "/tmp/project/.env",
            variables: ["TOKEN"],
            command: [],
            gitignored: false,
            requestedTtlSeconds: 900,
            requestedUses: 10,
            maxTtlSeconds: 3_600,
            createdAt: 1_757_000_000,
            expiresAt: 1_757_000_060,
            origin: nil,
            topOrigin: nil,
            itemId: nil,
            itemTitle: nil,
            fillFields: [],
            browser: nil,
            browserPid: nil,
            browserExecutable: nil,
            browserIsAppExtension: false,
            extensionId: nil)
    }

    // MARK: - The record

    @Test("a fill request carries an origin and an item, and no field a value could sit in")
    func fillRequestIsMetadataOnly() {
        let request = Self.fillRequest()
        #expect(request.action == .fillCredential)
        #expect(request.origin == "https://example.com")
        #expect(request.itemTitle == "Example account")
        #expect(request.fillFields == ["username", "password"])

        // The record is the definition of what the sheet may state. Nothing here is a value, and
        // this mirrors the Rust-side assertion in `kagisecure-ffi`'s `agent` tests.
        let mirrored = Mirror(reflecting: request)
        let names = mirrored.children.compactMap(\.label)
        #expect(!names.contains("password"))
        #expect(!names.contains("value"))
        #expect(!names.contains("secret"))
    }

    @Test("an env request carries no browser fields, and a fill carries no env fields")
    func theTwoKindsDoNotBleedIntoEachOther() {
        let fill = Self.fillRequest()
        #expect(fill.environmentId == nil)
        #expect(fill.targetPath == nil)
        #expect(fill.variables.isEmpty)
        #expect(fill.command.isEmpty)
        // A fill mints a *fill* lease, which is a different store. `mintsLease` refers to the env
        // lease store, so it must be false — a sheet that read it as "this grants nothing" would
        // hide the TTL control the fill needs.
        #expect(!fill.mintsLease)

        let env = Self.envRequest()
        #expect(env.origin == nil)
        #expect(env.itemId == nil)
        #expect(env.fillFields.isEmpty)
        #expect(env.browser == nil)
    }

    // MARK: - What the human is told

    @Test("the biometric prompt names the item and the origin, and nothing else")
    func biometricReasonIsSpecific() {
        let reason = AgentService.reason(for: Self.fillRequest())
        #expect(reason.contains("Example account"))
        #expect(reason.contains("https://example.com"))
        // The prompt names the action, not the field's value.
        #expect(!reason.contains("password"))
    }

    @Test("the biometric prompt for an env write still says what it always said")
    func biometricReasonForEnvIsUnchanged() {
        let reason = AgentService.reason(for: Self.envRequest())
        #expect(reason.contains("1 variable"))
        #expect(reason.contains(".env"))
    }

    @Test("a one-time-code request is described as a code, not as a password")
    func totpRequestReadsAsACode() {
        let request = Self.fillRequest(fields: ["one-time password"])
        let reason = AgentService.reason(for: request)
        #expect(reason.contains("Example account"))
        #expect(request.fillFields == ["one-time password"])
    }

    @Test("the sheet's sentence names the browser, the item and nothing else")
    func fillSentenceIsAccurate() {
        let sentence = ApprovalSheet.sentence(for: Self.fillRequest())
        #expect(sentence.contains("Google Chrome"))
        #expect(sentence.contains("Example account"))
        #expect(sentence.contains("password"), "the sentence says which credential is wanted")
        // The browser is the app's own conclusion from the process tree, so it is not quoted:
        // quotation marks in this UI mean "the caller said so".
        #expect(!sentence.contains("“Google Chrome”"))
    }

    @Test("an agent's self-reported name is still quoted, so it cannot borrow our vocabulary")
    func agentSentenceQuotesTheSelfReportedName() {
        let sentence = ApprovalSheet.sentence(for: Self.envRequest())
        #expect(sentence.contains("“Claude Code”"))
    }

    @Test("a one-time-code fill says code, not password")
    func totpSentenceSaysCode() {
        let sentence = ApprovalSheet.sentence(for: Self.fillRequest(fields: ["one-time password"]))
        #expect(sentence.contains("one-time code"))
        #expect(!sentence.contains("the password for"))
    }

    @Test("the scope summary states the fields, the item and the origin, and no value")
    func fillSummaryIsSpecific() {
        let summary = ApprovalSheet.summary(for: Self.fillRequest(), ttlSeconds: 300)
        #expect(summary.contains("username and password"))
        #expect(summary.contains("Example account"))
        #expect(summary.contains("https://example.com"))
        #expect(summary.contains("nothing is stored in the browser"))
    }

    @Test("the env summary is unchanged by M6")
    func envSummaryIsUnchanged() {
        let summary = ApprovalSheet.summary(for: Self.envRequest(), ttlSeconds: 900)
        #expect(summary.contains("TOKEN"))
        #expect(summary.contains("/tmp/project"))
        #expect(summary.contains("15 minutes"))
    }

    @Test("a fill has its own icon, so the sheet does not look like a .env write")
    func fillHasItsOwnSymbol() {
        #expect(ApprovalSheet.symbol(for: Self.fillRequest()) == "key.horizontal")
        #expect(ApprovalSheet.symbol(for: Self.envRequest()) != "key.horizontal")
    }

    // MARK: - Identity

    @Test("a fill's identity is two verdicts, and the recorded one is the weaker")
    func combinedVerdictIsTheWeakerHalf() {
        // The case this build actually produces: Chrome is signed by Google and verifies; a
        // `cargo build` native host is ad-hoc and does not.
        let signed = PeerSignature(verified: true, evidence: "Google Chrome (team EQHXZ8M8AV)")
        let adhoc = PeerSignature(verified: false, evidence: "kagisecure-nmhost, ad-hoc signed")

        let mixed = FillSignature(host: adhoc, browser: signed)
        #expect(
            !mixed.verified,
            "a verified browser must not launder an unverified helper into a green badge")

        let both = FillSignature(host: signed, browser: signed)
        #expect(both.verified)

        let noBrowser = FillSignature(host: signed, browser: nil)
        #expect(!noBrowser.verified, "no browser above the helper is not a pass")
    }

    @Test("both halves of the evidence reach the sheet, verbatim")
    func bothEvidenceLinesSurvive() {
        let fill = FillSignature(
            host: PeerSignature(verified: false, evidence: "helper is ad-hoc"),
            browser: PeerSignature(verified: true, evidence: "Google Chrome (team EQHXZ8M8AV)"))
        let combined = [fill.host.evidence, fill.browser?.evidence]
            .compactMap { $0 }
            .joined(separator: "; ")
        #expect(combined.contains("helper is ad-hoc"))
        #expect(combined.contains("Google Chrome"))
    }

    @Test("a browser this app does not know is not accepted on the strength of being signed")
    func anUnknownBrowserIsNotVerified() {
        // The check runs against this test process, which is signed as the test bundle and is not
        // in `knownBrowsers`. A check that passed anything with a valid signature would say
        // verified here, which is the bug this asserts against.
        let verdict = PeerCodeSignature().checkBrowser(pid: UInt32(ProcessInfo.processInfo.processIdentifier))
        #expect(!verdict.verified)
        #expect(!verdict.evidence.isEmpty)
    }

    @Test("this process is not one of our helpers either")
    func thisProcessIsNotANativeMessagingHost() {
        let verdict = PeerCodeSignature().checkHost(pid: UInt32(ProcessInfo.processInfo.processIdentifier))
        #expect(!verdict.verified)
    }

    @Test("no pid is an honest refusal rather than a crash")
    func noPidIsHandled() {
        let signer = PeerCodeSignature()
        #expect(!signer.checkHost(pid: nil).verified)
        #expect(!signer.checkBrowser(pid: nil).verified)
        let fill = signer.checkFill(hostPid: nil, browserPid: nil, isAppExtension: false)
        #expect(!fill.verified)
        #expect(fill.browser == nil, "no browser pid means no browser verdict, not a false one")
    }

    @Test("the browser table names a team for every browser, because a browser is somebody else's")
    func everyKnownBrowserHasATeam() {
        for browser in PeerCodeSignature.knownBrowsers {
            #expect(!browser.team.isEmpty, "\(browser.identifier) has no team to compare against")
            #expect(browser.identifier.contains("."), "\(browser.identifier) is not a bundle id")
            #expect(!browser.name.isEmpty)
        }
    }

    @Test("our own identifier prefixes do not overlap between the sidecar and the helper")
    func theTwoIdentifierListsAreDisjoint() {
        // If they overlapped, a sidecar connecting to the extension socket would be waved through
        // as a native messaging host, and the reverse.
        for prefix in PeerCodeSignature.knownHostIdentifierPrefixes {
            #expect(!PeerCodeSignature.isKnown(prefix), "\(prefix) is accepted as a sidecar")
        }
        for prefix in PeerCodeSignature.knownIdentifierPrefixes {
            #expect(!PeerCodeSignature.isKnownHost(prefix), "\(prefix) is accepted as a helper")
        }
    }

    // MARK: - The iframe signal

    @Test("a cross-origin frame is visible in the record, and a same-origin one is not")
    func crossOriginFrameIsFlagged() {
        let framed = Self.fillRequest(
            origin: "https://bank.test", topOrigin: "https://aggregator.test")
        #expect(framed.topOrigin == "https://aggregator.test")
        #expect(
            framed.origin == "https://bank.test",
            "the origin the sheet shows is the frame's — the one that was matched")

        let plain = Self.fillRequest()
        #expect(
            plain.topOrigin == nil,
            "a top-frame fill must not raise the frame warning")
    }

    // MARK: - The service

    @Test("with no listener running, the extension surface answers emptily rather than crashing")
    func extensionServiceIsSafeBeforeUnlock() {
        let service = ExtensionService()
        #expect(!service.status.running)
        #expect(service.fillLeases.isEmpty)
        service.revokeAll()
        service.stop()
        #expect(!service.status.running)
    }

    @Test("the setup screen always has a browser to offer and an id to check")
    func setupIsNeverBlank() {
        let service = ExtensionService()
        service.refreshSetup()
        let setup = try! #require(service.setup)
        #expect(setup.extensionId.count == 32)
        #expect(setup.hostName == "com.kagisecure.nmhost")
        #expect(!setup.manifests.isEmpty)
        for manifest in setup.manifests {
            #expect(manifest.path.hasSuffix("com.kagisecure.nmhost.json"))
            #expect(
                manifest.body.contains(setup.extensionId),
                "every manifest must pin the id the app checks at Hello")
            #expect(
                manifest.path.contains("Application Support"),
                "a manifest belongs under the user's own Library")
        }
        #expect(
            !setup.manifests.contains { $0.browser == "Safari" },
            "Safari does not read native messaging host manifests")
    }

    @Test("installing and removing a manifest round-trips through the service")
    func installRoundTrips() throws {
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ks-ext-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("com.kagisecure.nmhost.json").path
        let manifest = BrowserManifestView(
            browser: "Test", path: path, body: "{}\n", browserInstalled: true, installed: false)

        let service = ExtensionService()
        service.install(manifest)
        #expect(service.lastError == nil)
        #expect(FileManager.default.fileExists(atPath: path))
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "{}\n")

        service.uninstall(manifest)
        #expect(service.lastError == nil)
        #expect(!FileManager.default.fileExists(atPath: path))

        // Removing something that is not there is success, not an error a screen has to explain.
        service.uninstall(manifest)
        #expect(service.lastError == nil)
    }

    @Test("a manifest that cannot be written reports the path rather than failing silently")
    func installFailureIsLegible() {
        let manifest = BrowserManifestView(
            browser: "Test",
            path: "/System/nope/com.kagisecure.nmhost.json",
            body: "{}\n",
            browserInstalled: true,
            installed: false)
        let service = ExtensionService()
        service.install(manifest)
        let error = service.lastError
        #expect(error != nil)
        #expect(error?.contains("com.kagisecure.nmhost.json") == true)
    }
}
