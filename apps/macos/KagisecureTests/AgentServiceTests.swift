import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// A `BiometricGate` a test can drive.
///
/// The reason `BiometricGate` is a protocol at all: `LAContext.evaluatePolicy` raises a system
/// sheet nobody can answer from a test run, and the decisions around it — what a cancellation
/// means, what gets recorded, when the lease is minted — are the part with actual logic in them.
final class TestBiometricGate: BiometricGate, @unchecked Sendable {
    private let outcome: BiometricOutcome
    private let lock = NSLock()
    private var _reasons: [String] = []

    /// Every reason string the app asked with, in order. Asserted so a future refactor cannot
    /// quietly start putting something interesting in the system prompt.
    var reasons: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _reasons
    }

    init(_ outcome: BiometricOutcome) {
        self.outcome = outcome
    }

    func isAvailable() -> Bool { true }

    func authenticate(reason: String) async -> BiometricOutcome {
        record(reason)
        return outcome
    }

    private func record(_ reason: String) {
        lock.lock()
        defer { lock.unlock() }
        _reasons.append(reason)
    }
}

/// The approval flow, end to end, through the real FFI and the real `kagisecure-mcp` binary.
///
/// Nothing about the agent is mocked: a real socket, a real sidecar process, a real IPC round
/// trip, a real lease. The one double is the biometric, because a fingerprint is the one thing a
/// test cannot supply.
@MainActor
struct AgentServiceTests {
    // MARK: - Fixture

    /// A throwaway vault with one agent-visible environment bound to one concealed field.
    private static func fixture() throws -> (VaultSession, URL, String) {
        // Short, on purpose: `sun_path` is 104 bytes on macOS and the default temporary
        // directory plus a UUID plus "/project/a.sock" does not fit. A socket path that is too
        // long fails at bind, which reads as a mysterious i/o error rather than a naming problem.
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ks-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("test.kagivault").path,
            masterPassword: "correct horse battery staple", vaultName: "Personal",
            kdfMKib: 8, kdfT: 1)
        _ = session.takeRecoveryCode()

        // Agent access is default-deny at three levels; the fixture opens all three, exactly as
        // `kagisecure env agent-access --allow` does (threat-model M-9).
        let vaultId = try session.defaultVaultId()
        _ = try session.setVaultAgentVisible(vaultId: vaultId, visible: true)

        let item = try session.createItem(
            vaultId: nil, category: "api-credential", title: "Acme staging")
        let draft = ItemDraft(
            id: item.id, category: item.category, title: item.title,
            fields: item.fields.map {
                FieldDraft(
                    id: $0.id, label: $0.label, kind: $0.kind, concealed: $0.concealed,
                    value: $0.concealed ? "sk_live_kagisecure_test" : "https://api.example",
                    section: $0.section, agentVisible: true)
            },
            tags: [], urls: [], notes: nil)
        let saved = try session.saveItem(draft: draft)
        _ = try session.setAgentVisible(itemId: saved.id, visible: true)

        guard let field = saved.fields.first(where: { $0.concealed }) else {
            throw CancellationError()
        }
        let environment = try session.createEnvironment(name: "acme / staging", description: nil)
        _ = try session.bindVariable(
            environmentId: environment.id, name: "TOKEN", itemId: saved.id, fieldId: field.id)
        let shared = try session.setEnvironmentAgentVisible(
            environmentId: environment.id, visible: true)
        return (session, directory, shared.id)
    }

    /// The repository's `target/debug/kagisecure-mcp`, found relative to this source file.
    private static func sidecarPath() -> String? {
        var url = URL(fileURLWithPath: #filePath)
        // …/apps/macos/KagisecureTests/AgentServiceTests.swift -> repository root
        for _ in 0..<4 { url.deleteLastPathComponent() }
        let candidate = url.appendingPathComponent("target/debug/kagisecure-mcp")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate.path : nil
    }

    // MARK: - Unit-ish: what the sheet is told

    @Test func theReasonStringNamesTheActionAndNeverAValue() {
        let request = Self.sampleRequest()
        let reason = AgentService.reason(for: request)
        #expect(reason.contains("writing"))
        #expect(reason.contains("1 variable"))
        #expect(!reason.contains("TOKEN"), "the system prompt names the count, not the variables")
    }

    @Test func durationsReadTheWayTheSpecWritesThem() {
        #expect(ApprovalSheet.duration(900) == "15 minutes")
        #expect(ApprovalSheet.duration(60) == "1 minute")
        #expect(ApprovalSheet.duration(30) == "30 s")
        #expect(ApprovalSheet.duration(7200) == "2.0 hours")
    }

    @Test func aSidecarSigningIdentifierIsRecognizedIncludingCargosAdHocForm() {
        // `codesign`'s ad-hoc identifier for a `cargo build` binary is the file name plus a
        // content hash; an exact match would call our own sidecar a stranger.
        #expect(PeerCodeSignature.isKnown("kagisecure-mcp"))
        #expect(PeerCodeSignature.isKnown("kagisecure_mcp-43e7de0718ccfd8e"))
        #expect(PeerCodeSignature.isKnown("com.kagisecure.mcp"))
        #expect(!PeerCodeSignature.isKnown("com.evil.mcp"))
        #expect(!PeerCodeSignature.isKnown("kagisecure"))
    }

    @Test func aProcessThatDoesNotExistIsUnverifiedRatherThanTrusted() {
        let verdict = PeerCodeSignature().check(pid: nil)
        #expect(!verdict.verified)
        #expect(verdict == .noPeer)
        // A pid nothing can own: the check must fail closed.
        #expect(!PeerCodeSignature().check(pid: UInt32.max).verified)
    }

    @Test func anUnstartedServiceIsInertRatherThanCrashy() {
        let service = AgentService()
        #expect(!service.status.running)
        #expect(service.current == nil)
        #expect(service.leases.isEmpty)
        service.stop()
    }

    // MARK: - Integration: a real sidecar, a real approval

    @Test func approvingARealSidecarRequestWritesTheFileAndMintsALease() async throws {
        guard let sidecar = Self.sidecarPath() else {
            // Nothing to talk to. Skipping is honest; failing would be a statement about the
            // developer's build directory rather than about the app.
            return
        }
        let (session, directory, environmentId) = try Self.fixture()
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let service = AgentService()
        let gate = TestBiometricGate(.authenticated)
        service.gate = gate
        setenv("KAGISECURE_SOCKET", directory.appendingPathComponent("a.sock").path, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)
        #expect(service.startupError == nil, "the listener should bind a fresh socket")

        let mcp = try RawSidecar(binary: sidecar, socket: directory.appendingPathComponent("a.sock").path, cwd: project)
        defer { mcp.stop() }

        // The tool call blocks in the sidecar until somebody answers, so it runs on its own task.
        let call = Task.detached {
            try mcp.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                    "ttl_seconds": 900,
                ])
        }

        let request = try await Self.waitForRequest(on: service)
        #expect(request.variables == ["TOKEN"])
        #expect(request.mintsLease)
        #expect(request.action == .writeEnvFile)
        #expect(request.targetPath?.hasSuffix("/.env") == true)

        let outcome = await service.allow(
            request, decision: .allowSession(ttlSeconds: 900, uses: 10))
        #expect(outcome == .authenticated)
        #expect(gate.reasons.count == 1, "exactly one biometric per approval")

        let reply = try await call.value
        #expect(!reply.contains("USER_DENIED"), "reply was \(reply)")
        #expect(
            FileManager.default.fileExists(atPath: project.appendingPathComponent(".env").path),
            "approving must actually perform the injection")

        let leases = agentLeases()
        #expect(leases.count == 1)
        #expect(leases.first?.variables == ["TOKEN"])
        #expect(service.current == nil, "the sheet dismisses once answered")

        service.stop()
        #expect(agentLeases().isEmpty, "stopping drops every lease")
        try? FileManager.default.removeItem(at: directory)
    }

    @Test func denyingNeedsNoBiometricAndWritesNothing() async throws {
        guard let sidecar = Self.sidecarPath() else { return }
        let (session, directory, environmentId) = try Self.fixture()
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let service = AgentService()
        // A gate that would refuse, to prove Deny never reaches it.
        let gate = TestBiometricGate(.cancelled)
        service.gate = gate
        setenv("KAGISECURE_SOCKET", directory.appendingPathComponent("b.sock").path, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)

        let mcp = try RawSidecar(binary: sidecar, socket: directory.appendingPathComponent("b.sock").path, cwd: project)
        defer { mcp.stop() }

        let call = Task.detached {
            try mcp.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                ])
        }
        let request = try await Self.waitForRequest(on: service)
        service.deny(request)

        let reply = try await call.value
        #expect(reply.contains("USER_DENIED"), "reply was \(reply)")
        #expect(gate.reasons.isEmpty, "saying no must never ask for a fingerprint")
        #expect(
            !FileManager.default.fileExists(atPath: project.appendingPathComponent(".env").path),
            "a denial leaves no partial write")
        #expect(agentLeases().isEmpty, "a denial mints no lease")

        service.stop()
        try? FileManager.default.removeItem(at: directory)
    }

    @Test func aCancelledBiometricIsNotADenialAndKeepsTheSheetUp() async throws {
        guard let sidecar = Self.sidecarPath() else { return }
        let (session, directory, environmentId) = try Self.fixture()
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let service = AgentService()
        service.gate = TestBiometricGate(.cancelled)
        setenv("KAGISECURE_SOCKET", directory.appendingPathComponent("c.sock").path, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)

        let mcp = try RawSidecar(binary: sidecar, socket: directory.appendingPathComponent("c.sock").path, cwd: project)
        defer { mcp.stop() }

        let call = Task.detached {
            try mcp.tool(
                "write_env_file",
                arguments: [
                    "environment_id": environmentId,
                    "directory": project.resolvingSymlinksInPath().path,
                ])
        }
        let request = try await Self.waitForRequest(on: service)
        let outcome = await service.allow(request, decision: .allowOnce)

        #expect(outcome == .cancelled)
        #expect(service.current?.id == request.id, "a fumbled fingerprint must not dismiss the sheet")
        #expect(agentLeases().isEmpty, "and must not mint a lease")

        // Finish the request so the sidecar's call returns rather than sitting out its 60 s.
        service.deny(request)
        _ = try? await call.value
        service.stop()
        try? FileManager.default.removeItem(at: directory)
    }

    // MARK: - Helpers

    private static func waitForRequest(on service: AgentService) async throws -> ApprovalRequestView
    {
        for _ in 0..<200 {
            if let request = service.current { return request }
            try await Task.sleep(for: .milliseconds(50))
        }
        Issue.record("no approval request arrived within 10 seconds")
        throw CancellationError()
    }

    private static func sampleRequest() -> ApprovalRequestView {
        ApprovalRequestView(
            id: "req-1", action: .writeEnvFile, mintsLease: true, clientName: "claude-code",
            clientPid: 42, clientPidFromKernel: true, clientExecutable: "/usr/bin/kagisecure-mcp",
            clientCwd: "/Users/x/code", environmentId: "e1", environmentName: "acme / staging",
            directory: "/Users/x/code", targetPath: "/Users/x/code/.env", variables: ["TOKEN"],
            command: [], gitignored: false, requestedTtlSeconds: 900, requestedUses: 10,
            maxTtlSeconds: 86_400, createdAt: 0, expiresAt: 60,
            // The M6 browser-fill half. Empty for an agent request, and asserted to be empty in
            // `FillApprovalTests.theTwoKindsDoNotBleedIntoEachOther`.
            origin: nil, topOrigin: nil, itemId: nil, itemTitle: nil, fillFields: [],
            browser: nil, browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil)
    }
}

/// A minimal MCP client over the sidecar's stdio, for the integration tests.
///
/// Not `rmcp`: the test only needs one request and one reply, and a real client library in a
/// Swift test bundle would be a dependency for four lines of JSON.
final class RawSidecar: @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private var buffer = Data()
    private var nextId: UInt64 = 0
    private let lock = NSLock()

    init(binary: String, socket: String, cwd: URL) throws {
        process.executableURL = URL(fileURLWithPath: binary)
        process.currentDirectoryURL = cwd
        var environment = ProcessInfo.processInfo.environment
        environment["KAGISECURE_SOCKET"] = socket
        process.environment = environment
        process.standardInput = input
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()

        _ = try call(
            "initialize",
            params: [
                "protocolVersion": "2025-11-25", "capabilities": [:],
                "clientInfo": ["name": "kagisecure-app-tests", "version": "0"],
            ])
        notify("notifications/initialized")
    }

    func stop() {
        process.terminate()
    }

    func tool(_ name: String, arguments: [String: Any]) throws -> String {
        try call("tools/call", params: ["name": name, "arguments": arguments])
    }

    private func notify(_ method: String) {
        send(["jsonrpc": "2.0", "method": method])
    }

    private func call(_ method: String, params: [String: Any]) throws -> String {
        lock.lock()
        nextId += 1
        let id = nextId
        lock.unlock()
        send(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        while true {
            let line = try readLine()
            guard let data = line.data(using: .utf8),
                let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let replyId = value["id"] as? UInt64 ?? (value["id"] as? Int).map(UInt64.init)
            else { continue }
            if replyId == id { return line }
        }
    }

    private func send(_ body: [String: Any]) {
        guard var data = try? JSONSerialization.data(withJSONObject: body) else { return }
        data.append(0x0A)
        input.fileHandleForWriting.write(data)
    }

    private func readLine() throws -> String {
        while true {
            if let index = buffer.firstIndex(of: 0x0A) {
                let line = buffer.prefix(upTo: index)
                buffer.removeSubrange(buffer.startIndex...index)
                return String(decoding: line, as: UTF8.self)
            }
            let chunk = output.fileHandleForReading.availableData
            if chunk.isEmpty { throw CancellationError() }
            buffer.append(chunk)
        }
    }
}
