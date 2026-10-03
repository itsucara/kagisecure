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
        #expect(AutoFillMatching.matches(domain: "www.example.com", host: "example.com"))
        #expect(AutoFillMatching.matches(domain: "example.com", host: "login.example.com"))
        #expect(!AutoFillMatching.matches(domain: "example.com", host: "badexample.com"))
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
}
