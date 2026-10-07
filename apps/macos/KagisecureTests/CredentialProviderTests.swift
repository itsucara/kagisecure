import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// System-wide AutoFill (ADR-0045): the app's answer to the credential provider extension.
///
/// One Touch ID opens the grace window and everything fills until lock; outside it, a request
/// that may not show UI is told to show UI, and one from the sheet goes through one presence
/// check. A locked vault brings the app forward.
@MainActor
struct CredentialProviderTests {
    // MARK: - Fixtures

    final class FakeVault: AutoFillVault {
        var items: [AutoFillLogin] = [
            AutoFillLogin(
                id: "a", title: "Example", username: "alice", domains: ["login.example.com"],
                hasOneTimeCode: true),
            AutoFillLogin(
                id: "b", title: "Another", username: "bob", domains: ["other.test"],
                hasOneTimeCode: false),
        ]
        var releases = 0
        var outcome: Error?
        /// Stands in for `AppPresenceGate`: the real release opens the grace window on success.
        var onRelease: () -> Void = {}

        func logins() -> [AutoFillLogin] { items }
        func username(itemId: String) -> String? { items.first { $0.id == itemId }?.username }
        func releasePassword(itemId: String) async throws -> String {
            releases += 1
            if let outcome { throw outcome }
            onRelease()
            return "pw-\(itemId)"
        }
        func releaseOneTimeCode(itemId: String) async throws -> String {
            releases += 1
            if let outcome { throw outcome }
            onRelease()
            return "123456"
        }
    }

    final class Clock {
        var now = Date(timeIntervalSince1970: 1_800_000_000)
    }

    static func handler(
        vault: FakeVault?, clock: Clock = Clock(),
        duration: PresenceGrace.Duration = .untilLocked
    ) -> CredentialProviderHandler {
        let presence = PresenceCoordinator(gate: BiometricGateAdversarialTests.ScriptedGate(.authenticated))
        presence.clock = { clock.now }
        presence.graceDuration = { duration }
        let handler = CredentialProviderHandler(presence: presence)
        handler.vault = vault
        handler.requiresConfirmation = { false }
        vault?.onRelease = { presence.touchGrace() }
        return handler
    }

    // MARK: - Grace

    @Test func withoutUIOutsideGraceAsksForTheSheetAndReleasesNothing() async {
        let vault = FakeVault()
        let handler = Self.handler(vault: vault)
        let response = await handler.handle(.credential(itemId: "a", interactive: false))
        #expect(response == .refused(.interactionRequired, message: "Confirm in the AutoFill sheet."))
        #expect(vault.releases == 0)
    }

    @Test func withoutUIInsideGraceFillsWithNoPrompt() async {
        let vault = FakeVault()
        let handler = Self.handler(vault: vault)
        handler.presence.touchGrace()
        let response = await handler.handle(.credential(itemId: "a", interactive: false))
        #expect(response == .credential(username: "alice", password: "pw-a"))
    }

    @Test func oneInteractiveCheckOpensGraceForLaterSilentFills() async {
        let vault = FakeVault()
        let handler = Self.handler(vault: vault)
        #expect(!handler.presence.graceIsOpen)
        _ = await handler.handle(.credential(itemId: "a", interactive: true))
        #expect(handler.presence.graceIsOpen)
        let silent = await handler.handle(.credential(itemId: "b", interactive: false))
        #expect(silent == .credential(username: "bob", password: "pw-b"))
    }

    @Test func expiredGraceAsksAgain() async {
        let clock = Clock()
        let vault = FakeVault()
        let handler = Self.handler(vault: vault, clock: clock, duration: .tenMinutes)
        handler.presence.touchGrace()
        clock.now = clock.now.addingTimeInterval(11 * 60)
        let response = await handler.handle(.oneTimeCode(itemId: "a", interactive: false))
        #expect(response == .refused(.interactionRequired, message: "Confirm in the AutoFill sheet."))
    }

    @Test func lockClearsGraceSoSilentFillStops() async {
        let vault = FakeVault()
        let handler = Self.handler(vault: vault)
        handler.presence.touchGrace()
        handler.presence.clearGrace()
        let response = await handler.handle(.credential(itemId: "a", interactive: false))
        #expect(response == .refused(.interactionRequired, message: "Confirm in the AutoFill sheet."))
    }

    @Test func confirmationSettingRefusesSilentFillEvenInGrace() async {
        let vault = FakeVault()
        let handler = Self.handler(vault: vault)
        handler.requiresConfirmation = { true }
        handler.presence.touchGrace()
        let silent = await handler.handle(.credential(itemId: "a", interactive: false))
        #expect(silent == .refused(.interactionRequired, message: "Confirm in the AutoFill sheet."))
        let sheet = await handler.handle(.credential(itemId: "a", interactive: true))
        #expect(sheet == .credential(username: "alice", password: "pw-a"))
    }

    // MARK: - Locked, refusals

    @Test func lockedInteractiveRaisesTheApp() async {
        let handler = Self.handler(vault: nil)
        var raised = 0
        handler.raiseApp = { raised += 1 }
        let response = await handler.handle(.credential(itemId: "a", interactive: true))
        #expect(response == .refused(.locked, message: "Kagisecure is locked."))
        #expect(raised == 1)
        _ = await handler.handle(.credential(itemId: "a", interactive: false))
        #expect(raised == 1, "a no-UI request must not bring the app forward")
    }

    @Test func cancelledPresenceIsReported() async {
        let vault = FakeVault()
        vault.outcome = FfiError.PresenceCancelled(message: "no")
        let handler = Self.handler(vault: vault)
        let response = await handler.handle(.credential(itemId: "a", interactive: true))
        #expect(response == .refused(.cancelled, message: "Not confirmed."))
        #expect(!handler.presence.graceIsOpen)
    }

    @Test func unknownItemIsNotFound() async {
        let handler = Self.handler(vault: FakeVault())
        handler.presence.touchGrace()
        let response = await handler.handle(.credential(itemId: "zzz", interactive: false))
        #expect(response == .refused(.notFound, message: "No such login."))
    }

    @Test func statusReportsGrace() async {
        let handler = Self.handler(vault: FakeVault())
        #expect(await handler.handle(.status) == .status(unlocked: true, graceOpen: false))
        handler.presence.touchGrace()
        #expect(await handler.handle(.status) == .status(unlocked: true, graceOpen: true))
        handler.vault = nil
        #expect(await handler.handle(.status) == .status(unlocked: false, graceOpen: false))
    }

    // MARK: - The list

    @Test func listPutsMatchingServicesFirstAndSearches() async {
        let handler = Self.handler(vault: FakeVault())
        let ranked = await handler.handle(.logins(query: nil, services: ["https://other.test/login"]))
        guard case .logins(let items) = ranked else { Issue.record("\(ranked)"); return }
        #expect(items.map(\.id) == ["b", "a"])
        let searched = await handler.handle(.logins(query: "ALI", services: []))
        guard case .logins(let found) = searched else { Issue.record("\(searched)"); return }
        #expect(found.map(\.id) == ["a"])
    }

    @Test func domainMatching() {
        #expect(AutoFillMatching.host(of: "https://Login.Example.com:443/x") == "login.example.com")
        #expect(AutoFillMatching.host(of: "example.com/path") == "example.com")
    }

    /// Host matching is the Rust public-suffix rule the browser extension fills by (ADR-0045 §4,
    /// 2026-10-04 amendment), not a suffix test: `www.` and subdomains of one site match, two
    /// sites on shared hosting or under a multi-label public suffix do not.
    @Test func hostMatchingUsesTheRegistrableDomain() {
        let m = autofillHostMatches(saved:requested:)
        #expect(m("www.example.com", "example.com"))
        #expect(m("example.com", "www.example.com"))
        #expect(m("example.com", "login.example.com"))
        #expect(m("login.example.com", "example.com"))
        #expect(!m("example.com", "badexample.com"))
        #expect(!m("example.com", "example.com.evil.net"))
        #expect(!m("alice.github.io", "bob.github.io"))
        #expect(!m("github.io", "alice.github.io"))
        #expect(m("alice.github.io", "www.alice.github.io"))
        #expect(m("shop.example.co.uk", "example.co.uk"))
        #expect(!m("alice.co.uk", "bob.co.uk"))
        #expect(!m("co.uk", "alice.co.uk"))
    }

    @Test func sharedHostingSitesDoNotRankEachOtherFirst() {
        let logins = [
            AutoFillLogin(id: "bob", title: "A Bob", username: nil, domains: ["bob.github.io"], hasOneTimeCode: false),
            AutoFillLogin(id: "alice", title: "B Alice", username: nil, domains: ["alice.github.io"], hasOneTimeCode: false),
        ]
        let ranked = AutoFillMatching.rank(
            logins, query: nil, services: ["https://alice.github.io/login"],
            matches: autofillHostMatches(saved:requested:))
        #expect(ranked.map(\.id) == ["alice", "bob"])
    }

    // MARK: - The socket override (finding: env var disabled the peer check in release)

    @Test func autofillSocketOverrideIsIgnoredInARelease() {
        let env = [AutoFillTestOverride.environmentKey: "/tmp/x.sock"]
        // Release build, XCTest not loaded: ignored even with XCTest's variable set by an attacker.
        #expect(AutoFillTestOverride.value(isDebugBuild: false, xcTestLoaded: false, environment: env) == nil)
        var withVar = env
        withVar["XCTestConfigurationFilePath"] = "/tmp/fake.xctestconfiguration"
        #expect(AutoFillTestOverride.value(isDebugBuild: false, xcTestLoaded: false, environment: withVar) == nil)
        // XCTest loaded but not configured: ignored.
        #expect(AutoFillTestOverride.value(isDebugBuild: false, xcTestLoaded: true, environment: env) == nil)
        // Really under XCTest, or a DEBUG build: honoured.
        #expect(AutoFillTestOverride.value(isDebugBuild: false, xcTestLoaded: true, environment: withVar) == "/tmp/x.sock")
        #expect(AutoFillTestOverride.value(isDebugBuild: true, xcTestLoaded: false, environment: env) == "/tmp/x.sock")
        // Nothing set: nothing to honour.
        #expect(AutoFillTestOverride.value(isDebugBuild: true, xcTestLoaded: true, environment: [:]) == nil)
    }

    // MARK: - Audit token (finding: peer checks ran on a reusable pid)

    @Test func auditTokenHexRoundTripsAndRejectsGarbage() {
        let hex = String(repeating: "0a", count: 32)
        #expect(PeerCodeSignature.auditToken(hex: hex) == Data(repeating: 0x0a, count: 32))
        #expect(PeerCodeSignature.auditToken(hex: nil) == nil)
        #expect(PeerCodeSignature.auditToken(hex: "0a") == nil)
        #expect(PeerCodeSignature.auditToken(hex: String(repeating: "zz", count: 32)) == nil)
    }

    @Test func socketAuditTokenNamesThisProcessAndDrivesTheCheck() throws {
        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let token = try #require(PeerCodeSignature.auditToken(socket: fds[0]))
        #expect(token.count == 32)
        // `audit_token_t.val[5]` is the pid.
        let pid = token.withUnsafeBytes { $0.load(fromByteOffset: 20, as: UInt32.self) }
        #expect(pid == UInt32(getpid()))
        // The token resolves to a SecCode (this test runner), which is not our AutoFill provider.
        let verdict = PeerCodeSignature().checkCredentialProvider(pid: pid, auditToken: token)
        #expect(!verdict.verified)
        #expect(!verdict.evidence.contains("would not inspect"), "\(verdict.evidence)")
        // A token for a process that no longer matches (pid version bumped) is refused, where a
        // pid lookup would have described whoever holds the pid now.
        var stale = token
        stale.withUnsafeMutableBytes { raw in
            let v = raw.load(fromByteOffset: 28, as: UInt32.self)
            raw.storeBytes(of: v &+ 1, toByteOffset: 28, as: UInt32.self)
        }
        let staleVerdict = PeerCodeSignature().checkCredentialProvider(pid: pid, auditToken: stale)
        #expect(!staleVerdict.verified)
        #expect(staleVerdict.evidence.contains("would not inspect"), "\(staleVerdict.evidence)")
    }

    @Test func identityKeysNeverCarryAValue() {
        let keys = CredentialIdentitySync.keys(for: FakeVault().items)
        #expect(keys.contains("pw|login.example.com|alice|a"))
        #expect(keys.contains("otp|login.example.com|a"))
        #expect(!keys.contains { $0.contains("pw-") })
    }

    // MARK: - The wire

    @Test func requestsAndResponsesRoundTrip() throws {
        let requests: [AutoFillRequest] = [
            .status, .logins(query: "x", services: ["a.test"]),
            .credential(itemId: "i", interactive: true), .oneTimeCode(itemId: "i", interactive: false),
        ]
        for request in requests {
            let data = try JSONEncoder().encode(request)
            #expect(try JSONDecoder().decode(AutoFillRequest.self, from: data) == request)
        }
        let responses: [AutoFillResponse] = [
            .status(unlocked: true, graceOpen: false), .logins(FakeVault().items),
            .credential(username: "u", password: "p"), .oneTimeCode(code: "1"),
            .refused(.interactionRequired, message: "m"),
        ]
        for response in responses {
            let data = try JSONEncoder().encode(response)
            #expect(try JSONDecoder().decode(AutoFillResponse.self, from: data) == response)
        }
    }

    @Test func socketServesOneRequestPerConnection() async throws {
        let path = "/tmp/ks-autofill-\(UInt32.random(in: 0...UInt32.max)).sock"
        let server = try AutoFillSocketServer(
            path: path, verifyPeer: { _ in true },
            handle: { request in
                request == .status ? .status(unlocked: true, graceOpen: true) : .logins([])
            })
        defer { server.stop() }
        let reply = try await Task.detached { try AutoFillWire.exchange(path: path, .status) }.value
        #expect(reply == .status(unlocked: true, graceOpen: true))
    }

    @Test func socketRefusesAnUnverifiedPeer() async throws {
        let path = "/tmp/ks-autofill-\(UInt32.random(in: 0...UInt32.max)).sock"
        let server = try AutoFillSocketServer(
            path: path, verifyPeer: { _ in false },
            handle: { _ in .credential(username: "u", password: "leak") })
        defer { server.stop() }
        let reply = try await Task.detached {
            try AutoFillWire.exchange(path: path, .credential(itemId: "a", interactive: false))
        }.value
        #expect(reply == .refused(.untrusted, message: "Not this app's AutoFill provider."))
    }

    @Test func testVaultItemsAreNeverOfferedToAutoFill() {
        func item(inTestVault: Bool) -> ItemView {
            ItemView(
                id: "i", vaultId: "v", category: "login", categoryDisplayName: "Login",
                categorySymbol: "key", title: "t",
                fields: [FieldView(id: "p", label: "password", kind: .concealed, concealed: true,
                                   hasValue: true, value: nil, section: nil, agentVisible: true)],
                tags: [], urls: ["http://localhost:47800"], hasNotes: false, favorite: false,
                archived: false, trashed: false, agentVisible: true, createdAt: 0, updatedAt: 0,
                subtitle: nil, username: "u", primarySecretFieldId: "p", revision: "r",
                inAgentTestVault: inTestVault)
        }
        #expect(SessionAutoFillVault.login(from: item(inTestVault: false)) != nil)
        #expect(SessionAutoFillVault.login(from: item(inTestVault: true)) == nil)
    }
}
