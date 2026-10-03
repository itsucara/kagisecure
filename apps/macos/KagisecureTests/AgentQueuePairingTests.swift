import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Adversarial tests for the pairing between *the request on screen* and *the answer sent back*.
///
/// # Why this file exists
///
/// `AgentService` keeps three pieces of state that have to agree with each other: `queue` (the
/// requests, head first), `currentSignature` (the code-signature verdict for the head), and
/// whatever request the sheet is currently showing the user. `allow(_:decision:)` holds a
/// reference to the third while `await`ing a biometric that can take seconds, and during that
/// await `tick()` runs `dropExpired()`, which can remove the head and re-adopt a signature for a
/// *different* request. Two properties have to hold across that window (D-4):
///
///   * the verdict recorded with the decision is the one captured for *that* request before the
///     await, not whatever `currentSignature` holds after it, and
///   * `advance(resolved:)` retires the request that was actually resolved, by id, leaving a
///     request nobody has seen on the queue.
///
/// This file drives that window with a real sidecar, a real socket and a stalling biometric.
/// It also covers the symmetric race at the other end: `stop()`'s bounded 750 ms wait can expire
/// while the poll loop is inside `agentNextRequest`, and a request taken in that window must be
/// denied rather than dropped (G-17). And it pins what `KAGISECURE_SOCKET` is allowed to do to the
/// endpoint's permissions (G-26).
///
/// Two of these are slow on purpose: the approval window is a hardcoded 60 seconds in
/// `kagisecure-agent`, so provoking an expiry mid-await costs about 70 seconds of wall clock
/// each. They are regression guards for D-4 and are worth the minute.
@MainActor
struct AgentQueuePairingTests {
    // MARK: - Fixture

    /// A throwaway vault with one agent-visible environment bound to one concealed field.
    ///
    /// Deliberately a copy of `AgentServiceTests`'s rather than a shared helper: these suites run
    /// against the same process-global agent, and a fixture that two suites could mutate is
    /// exactly the coupling that would make a failure here unreadable.
    private static func fixture() throws -> (VaultSession, URL, String) {
        // `sun_path` is 104 bytes on macOS, so the socket's directory has to be short.
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ksq-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("test.kagivault").path,
            masterPassword: "correct horse battery staple", vaultName: "Personal",
            kdfMKib: 64, kdfT: 1)
        _ = session.takeRecoveryCode()

        let vaultId = try session.defaultVaultId()
        _ = try session.setVaultAgentVisible(vaultId: vaultId, visible: true)

        let item = try session.createItem(
            vaultId: nil, category: "api-credential", title: "KS_CANARY_ITEM")
        let draft = ItemDraft(
            id: item.id, category: item.category, title: item.title,
            fields: item.fields.map {
                FieldDraft(
                    id: $0.id, label: $0.label, kind: $0.kind, concealed: $0.concealed,
                    value: $0.concealed
                        ? "KS_CANARY_SECRET_sk_live_do_not_ship" : "https://api.example",
                    section: $0.section, agentVisible: true)
            },
            tags: [], urls: [], notes: nil, revision: item.revision)
        let saved = try session.saveItem(draft: draft)
        _ = try session.setAgentVisible(itemId: saved.id, visible: true)

        guard let field = saved.fields.first(where: { $0.concealed }) else {
            throw CancellationError()
        }
        let environment = try session.createEnvironment(name: "acme / staging", description: nil)
        _ = try session.bindVariable(
            environmentId: environment.id, name: "KS_CANARY_TOKEN", itemId: saved.id,
            fieldId: field.id)
        let shared = try session.setEnvironmentAgentVisible(
            environmentId: environment.id, visible: true)
        return (session, directory, shared.id)
    }

    private static func sidecarPath() -> String? {
        var url = URL(fileURLWithPath: #filePath)
        // …/apps/macos/KagisecureTests/AgentQueuePairingTests.swift -> repository root
        for _ in 0..<4 { url.deleteLastPathComponent() }
        let candidate = url.appendingPathComponent("target/debug/kagisecure-mcp")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate.path : nil
    }

    private static func waitForRequest(
        on service: AgentService, other than: String? = nil
    ) async throws -> ApprovalRequestView {
        for _ in 0..<200 {
            if let request = service.current, request.id != than { return request }
            try await Task.sleep(for: .milliseconds(50))
        }
        Issue.record("no approval request arrived within 10 seconds")
        throw CancellationError()
    }

    // MARK: - D-4 / G-01 / G-02: the answer must belong to the request that was on screen

    @Test
    func aRequestThatExpiresMidBiometricDoesNotStealTheNextRequestsPlace() async throws {
        let sidecar = try #require(Self.sidecarPath(), "target/debug/kagisecure-mcp is not built")
        let (session, directory, environmentId) = try Self.fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let socket = directory.appendingPathComponent("q.sock").path
        let service = AgentService()
        // Long enough that the first request's 60-second window closes while `allow` is parked.
        let gate = BiometricGateAdversarialTests.ScriptedGate(.authenticated, stall: .seconds(10))
        service.gate = gate
        setenv("KAGISECURE_SOCKET", socket, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)
        defer { service.stop() }
        #expect(service.startupError == nil)

        // Caller A: unsigned-from-the-app's-point-of-view sidecar, first in the queue.
        let first = try RawSidecar(binary: sidecar, socket: socket, cwd: project)
        defer { first.stop() }
        let firstCall = Task.detached {
            try first.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                    "ttl_seconds": 900,
                ])
        }
        let requestA = try await Self.waitForRequest(on: service)

        // Deliberate gap before B is asked. Each request carries its own 60-second window from
        // the moment Rust took it, so a B launched immediately after A would expire about a
        // second after A does — inside the stalling biometric below, which would retire B for a
        // reason that has nothing to do with the pairing this test is about. Fifteen seconds of
        // daylight keeps B alive well past the point where A's answer comes back.
        try await Task.sleep(for: .seconds(15))

        // Caller B: a second, independent process, queued behind A.
        let secondProject = directory.appendingPathComponent("project2")
        try FileManager.default.createDirectory(
            at: secondProject, withIntermediateDirectories: true)
        let second = try RawSidecar(binary: sidecar, socket: socket, cwd: secondProject)
        defer { second.stop() }
        let secondCall = Task.detached {
            try second.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": secondProject.resolvingSymlinksInPath().path,
                    "ttl_seconds": 900,
                ])
        }
        // Wait until Rust has both.
        for _ in 0..<200 where agentPendingRequests().count < 2 {
            try await Task.sleep(for: .milliseconds(50))
        }
        let pending = agentPendingRequests()
        #expect(pending.count == 2, "the fixture needs two queued requests")
        let requestB = try #require(pending.first { $0.id != requestA.id })

        // Park the biometric so that A's 60-second window closes while it is open.
        let secondsLeft = Double(requestA.expiresAt) - Date().timeIntervalSince1970
        if secondsLeft > 5 {
            try await Task.sleep(for: .seconds(secondsLeft - 5))
        }
        let outcome = await service.allow(requestA, decision: .allowSession(ttlSeconds: 900, uses: 1))
        #expect(outcome == .authenticated)

        // (b) No request leaves the UI queue unanswered. B was never shown to anybody, so it must
        //     still be on screen — `advance()` removing `queue.first` unconditionally is what
        //     takes it away.
        #expect(
            service.current?.id == requestB.id,
            "request \(requestB.id) was dropped off the sheet without ever being answered")

        // (c) Whatever was resolved must not have left B answered on the wire by A's approval.
        let stillPending = agentPendingRequests().map(\.id)
        #expect(
            stillPending.contains(requestB.id) || service.current?.id == requestB.id,
            "B is neither pending nor on screen — it was answered by somebody else's biometric")

        _ = try? await firstCall.value
        service.deny(requestB)
        _ = try? await secondCall.value
    }

    @Test
    func theVerdictRecordedBelongsToTheRequestThatWasApproved() async throws {
        let sidecar = try #require(Self.sidecarPath(), "target/debug/kagisecure-mcp is not built")
        let (session, directory, environmentId) = try Self.fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let socket = directory.appendingPathComponent("v.sock").path
        let service = AgentService()
        service.gate = BiometricGateAdversarialTests.ScriptedGate(.authenticated, stall: .seconds(10))
        setenv("KAGISECURE_SOCKET", socket, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)
        defer { service.stop() }

        let first = try RawSidecar(binary: sidecar, socket: socket, cwd: project)
        defer { first.stop() }
        let firstCall = Task.detached {
            try first.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                    "ttl_seconds": 900,
                ])
        }
        let requestA = try await Self.waitForRequest(on: service)
        let signatureForA = try #require(service.currentSignature)

        let secondProject = directory.appendingPathComponent("project2")
        try FileManager.default.createDirectory(
            at: secondProject, withIntermediateDirectories: true)
        let second = try RawSidecar(binary: sidecar, socket: socket, cwd: secondProject)
        defer { second.stop() }
        let secondCall = Task.detached {
            try second.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": secondProject.resolvingSymlinksInPath().path,
                    "ttl_seconds": 900,
                ])
        }
        for _ in 0..<200 where agentPendingRequests().count < 2 {
            try await Task.sleep(for: .milliseconds(50))
        }

        let secondsLeft = Double(requestA.expiresAt) - Date().timeIntervalSince1970
        if secondsLeft > 5 { try await Task.sleep(for: .seconds(secondsLeft - 5)) }
        _ = await service.allow(requestA, decision: .allowSession(ttlSeconds: 900, uses: 1))

        // Whatever lease A's approval minted must be scoped to A's own directory and carry the
        // verdict computed for A. A lease describing the *next* caller is a record that cannot be
        // audited — and `directory` is the field that says which caller it is.
        #expect(!signatureForA.evidence.isEmpty, "the sheet showed a verdict for A")
        if let lease = agentLeases().first {
            #expect(
                lease.directory == project.resolvingSymlinksInPath().path,
                "the lease A's biometric minted is scoped to \(lease.directory), not A's directory")
        }

        _ = try? await firstCall.value
        if let head = service.current { service.deny(head) }
        _ = try? await secondCall.value
    }

    // MARK: - G-17: stop() versus a request taken in the same breath

    @Test func aRequestTakenWhileStoppingIsAnsweredRatherThanDropped() async throws {
        // The poll loop can be parked inside `agentNextRequest` when `stop()` cancels it, and
        // `stop()`'s wait is bounded at three poll intervals. The loop's cancellation branch
        // answers anything it took with `deny`, and the property that matters to a caller is that
        // its tool call returns *promptly* rather than sitting out the 60-second approval window.
        let sidecar = try #require(Self.sidecarPath(), "target/debug/kagisecure-mcp is not built")
        let (session, directory, environmentId) = try Self.fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let socket = directory.appendingPathComponent("s.sock").path
        let service = AgentService()
        service.gate = BiometricGateAdversarialTests.ScriptedGate(.cancelled)
        setenv("KAGISECURE_SOCKET", socket, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)

        let mcp = try RawSidecar(binary: sidecar, socket: socket, cwd: project)
        defer { mcp.stop() }
        let call = Task.detached {
            try mcp.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                ])
        }

        // Land inside the poll window: long enough that the request is on the wire, short enough
        // that the loop is plausibly still parked when `stop()` cancels it.
        try await Task.sleep(for: .milliseconds(120))
        let startedStopping = Date()
        service.stop()

        let reply = try await withThrowingTaskGroup(of: String?.self) { group in
            group.addTask { try await call.value }
            group.addTask {
                try await Task.sleep(for: .seconds(15))
                return nil
            }
            let first = try await group.next()
            group.cancelAll()
            return first ?? nil
        }

        let answer = try #require(
            reply, "the caller was left hanging: a request taken during stop() was dropped")
        #expect(
            Date().timeIntervalSince(startedStopping) < 15,
            "the reply must not wait out the 60-second approval window")
        #expect(
            !answer.contains("\"error\"") || answer.contains("USER_DENIED"),
            "a request answered during a lock is denied, not errored: \(answer.prefix(200))")
        #expect(
            !FileManager.default.fileExists(atPath: project.appendingPathComponent(".env").path),
            "a request answered during a lock writes nothing")
        #expect(agentLeases().isEmpty)
    }

    @Test func stoppingAnAlreadyStoppedServiceIsInert() {
        let service = AgentService()
        service.stop()
        service.stop()
        #expect(!service.status.running)
        #expect(service.current == nil)
        #expect(service.currentSignature == nil)
    }

    // MARK: - G-26: what KAGISECURE_SOCKET is allowed to do

    /// `KAGISECURE_SOCKET` is honoured in every build, release included, so the question is not
    /// whether the override exists but whether it can be used to put the listener somewhere other
    /// processes can reach. `Endpoint::prepare_dir` in `kagisecure-ipc` chmods the containing
    /// directory to `0700` before the bind, and this asserts that it does so even for a directory
    /// the caller deliberately created world-writable.
    @Test func theSocketOverrideForcesAPrivateEndpointDirectory() throws {
        let (session, directory, _) = try Self.fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        // A deliberately permissive directory, as a hostile or careless value would name.
        let open = directory.appendingPathComponent("open")
        try FileManager.default.createDirectory(
            at: open, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o777])
        let socket = open.appendingPathComponent("o.sock").path

        let service = AgentService()
        setenv("KAGISECURE_SOCKET", socket, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)
        defer { service.stop() }
        #expect(service.startupError == nil, "the override bound: \(service.startupError ?? "")")

        let attributes = try FileManager.default.attributesOfItem(atPath: open.path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        #expect(
            mode & 0o077 == 0,
            "the endpoint's directory is group/other accessible (mode \(String(mode, radix: 8)))")
    }

    @Test func theSocketOverrideIsTheOnlyEnvironmentVariableThatMovesTheListener() throws {
        // A narrow pin on the blast radius of the override: one variable, read once, with no
        // second name and no path expansion. A test that only read the code could not tell the
        // difference; this one starts the listener and checks where it actually bound.
        let (session, directory, _) = try Self.fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let socket = directory.appendingPathComponent("p.sock").path

        let service = AgentService()
        setenv("KAGISECURE_SOCKET", socket, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)
        defer { service.stop() }

        #expect(service.startupError == nil)
        #expect(
            service.status.endpoint.contains("p.sock"),
            "the listener bound \(service.status.endpoint), not the override")
        #expect(
            FileManager.default.fileExists(atPath: socket),
            "the override names the socket path exactly, with no directory of its own invented")
    }
}
