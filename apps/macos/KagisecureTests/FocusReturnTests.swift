import AppKit
import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The "return focus before delivery" decision (a real-browser test found the app staying in
/// front of the browser after **Fill**, which leaves `document.visibilityState` never "visible"
/// and delivery failing — `NO_MATCHING_TAB` for an agent fill, `AGENT_FILL_NOT_DELIVERED` in the
/// audit log).
///
/// # What is under test
///
/// `AgentService.returnFocusBeforeDelivery`, through the seams it is built from rather than a real
/// `NSRunningApplication` — which has no public initializer a test could construct:
///
/// * only a fill (`agentFill`, `fillCredential`) returns focus at all;
/// * the browser named by `request.browserPid` is activated in preference to whatever was
///   frontmost when the request arrived;
/// * a fill that arrived with Kagisecure itself frontmost, or whose named browser turns out to be
///   this process, activates nothing;
/// * a captured frontmost app is the fallback when `browserPid` is absent or does not resolve;
/// * `hideSelf` is the last resort, and the fallback when the chosen app refuses to activate;
/// * denying never returns focus at all — only a grant does, and only once.
@MainActor
struct FocusReturnTests {
    typealias ScriptedGate = BiometricGateAdversarialTests.ScriptedGate
    typealias DecisionLog = BiometricGateAdversarialTests.DecisionLog

    /// A `FocusTarget` a test can inspect: what pid it claims, whether `activate` should report
    /// success, and how many times it was asked.
    final class FakeFocusTarget: FocusTarget {
        let processIdentifier: pid_t
        private let succeeds: Bool
        private(set) var activateCount = 0

        init(pid: pid_t, succeeds: Bool = true) {
            self.processIdentifier = pid
            self.succeeds = succeeds
        }

        func activate(options: NSApplication.ActivationOptions) -> Bool {
            activateCount += 1
            return succeeds
        }
    }

    private static func service(gate: BiometricGate, log: DecisionLog) -> AgentService {
        let service = AgentService()
        service.gate = gate
        service.resolver = { id, decision, _ in
            log.record(id, decision)
            return true
        }
        return service
    }

    /// A browser-extension fill (M6's `fillCredential`), with nothing a value could sit in — the
    /// other half of `returnsFocusOnApproval`, alongside `AgentFillApprovalTests.agentFillRequest`.
    private static func fillCredentialRequest(
        id: String = "ks-fill-1", browserPid: UInt32? = 4241
    ) -> ApprovalRequestView {
        ApprovalRequestView(
            id: id, action: .fillCredential, mintsLease: false, clientName: "Google Chrome",
            clientPid: 4242, clientPidFromKernel: true, clientExecutable: "/tmp/kagisecure-nmhost",
            clientCwd: nil, environmentId: nil, environmentName: nil, directory: nil,
            targetPath: nil, variables: [], command: [], gitignored: nil,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 300, requestedUses: 1, maxTtlSeconds: 900, createdAt: 0,
            expiresAt: 600, origin: "https://example.com", topOrigin: nil, topOriginUnknown: false,
            itemId: "item-1", itemTitle: "Example account", fillFields: ["username", "password"],
            browser: "Google Chrome", browserPid: browserPid,
            browserExecutable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            browserIsAppExtension: false, extensionId: "nlijibjnmanccalmafnfbobkcfjiibmd",
            presenceOnly: false)
    }

    // MARK: - Which actions return focus at all

    @Test func onlyAFillReturnsFocus() {
        #expect(AgentService.returnsFocusOnApproval(Self.fillCredentialRequest()))
        #expect(
            AgentService.returnsFocusOnApproval(
                AgentFillApprovalTests.agentFillRequest()))
        #expect(!AgentService.returnsFocusOnApproval(Self.sampleEnvRequest()))
    }

    // MARK: - The browser named by the request wins over whatever was frontmost

    @Test func anAgentFillActivatesTheBrowserItIsGoingIntoRatherThanTheFrontmostApp() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        // The agent's own app (Claude, a terminal) is what is frontmost when the request arrives —
        // exactly the case that motivated preferring `browserPid`.
        let agentApp = FakeFocusTarget(pid: 111)
        let browser = FakeFocusTarget(pid: 4241)
        service.currentFrontmostApp = { agentApp }
        service.runningApplication = { pid in pid == 4241 ? browser : nil }
        service.ownProcessIdentifier = { 999 }

        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(browser.activateCount == 1, "the browser the fill is going into is activated")
        #expect(agentApp.activateCount == 0, "not the app that happened to be frontmost")
    }

    @Test func aBrowserFillAlsoPrefersTheNamedBrowser() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        let frontmost = FakeFocusTarget(pid: 222)
        let browser = FakeFocusTarget(pid: 4241)
        service.currentFrontmostApp = { frontmost }
        service.runningApplication = { pid in pid == 4241 ? browser : nil }
        service.ownProcessIdentifier = { 999 }

        let request = Self.fillCredentialRequest()
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(browser.activateCount == 1)
        #expect(frontmost.activateCount == 0)
    }

    // MARK: - Falling back

    @Test func fallsBackToTheCapturedFrontmostAppWhenTheBrowserCannotBeFound() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        // The browser named by the request has quit, or the lookup otherwise finds nothing.
        let captured = FakeFocusTarget(pid: 333)
        service.currentFrontmostApp = { captured }
        service.runningApplication = { _ in nil }
        service.ownProcessIdentifier = { 999 }

        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(captured.activateCount == 1, "the app frontmost at arrival is the fallback")
    }

    @Test func hidesSelfWhenNothingCanBeActivated() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        var hideCount = 0
        service.currentFrontmostApp = { nil }
        service.runningApplication = { _ in nil }
        service.ownProcessIdentifier = { 999 }
        service.hideSelf = { hideCount += 1 }

        // No facts at all: no `browserPid` to try, and nothing was captured either.
        let request = AgentFillApprovalTests.agentFillRequest(facts: nil)
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(hideCount == 1)
    }

    @Test func hidesSelfWhenTheChosenAppRefusesToActivate() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        var hideCount = 0
        let browser = FakeFocusTarget(pid: 4241, succeeds: false)
        service.currentFrontmostApp = { nil }
        service.runningApplication = { pid in pid == 4241 ? browser : nil }
        service.ownProcessIdentifier = { 999 }
        service.hideSelf = { hideCount += 1 }

        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(browser.activateCount == 1)
        #expect(hideCount == 1, "a refusal to activate falls back to hiding this app")
    }

    @Test func activatesNothingWhenTheChosenAppIsThisProcess() async {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        var hideCount = 0
        // The browser somehow resolves to this very process — defensive, never expected in
        // production, but the decision must not "activate" or hide over it either.
        let ourselves = FakeFocusTarget(pid: 999)
        service.currentFrontmostApp = { nil }
        service.runningApplication = { pid in pid == 4241 ? ourselves : nil }
        service.ownProcessIdentifier = { 999 }
        service.hideSelf = { hideCount += 1 }

        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)
        #expect(await service.allow(request, decision: .allowOnce) == .authenticated)

        #expect(ourselves.activateCount == 0)
        #expect(hideCount == 0)
    }

    // MARK: - Non-fill approvals, and a denial, never return focus

    @Test func aNonFillApprovalNeverActivatesOrHidesAnything() async throws {
        guard let sidecar = Self.sidecarPath() else { return }
        let (session, directory, environmentId) = try Self.fixture()
        let project = directory.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)

        let service = AgentService()
        service.gate = ScriptedGate(.authenticated)
        var activated = 0
        var hidden = 0
        service.currentFrontmostApp = { FakeFocusTarget(pid: 1) }
        service.runningApplication = { _ in nil }
        service.hideSelf = { hidden += 1 }
        setenv("KAGISECURE_SOCKET", directory.appendingPathComponent("focus.sock").path, 1)
        defer { unsetenv("KAGISECURE_SOCKET") }
        service.start(session: session)

        let mcp = try RawSidecar(
            binary: sidecar, socket: directory.appendingPathComponent("focus.sock").path,
            cwd: project)
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
        #expect(await service.allow(request, decision: .allowSession(ttlSeconds: 900, uses: 10)) == .authenticated)
        _ = try await call.value

        #expect(activated == 0)
        #expect(hidden == 0, "an env-file approval has no browser tab to return focus to")

        service.stop()
        try? FileManager.default.removeItem(at: directory)
    }

    @Test func denyingNeverReturnsFocus() {
        let gate = ScriptedGate(.authenticated)
        let log = DecisionLog()
        let service = Self.service(gate: gate, log: log)

        var activated = 0
        var hidden = 0
        service.currentFrontmostApp = { FakeFocusTarget(pid: 1) }
        service.runningApplication = { _ in
            activated += 1
            return nil
        }
        service.hideSelf = { hidden += 1 }

        let request = AgentFillApprovalTests.agentFillRequest()
        service.enqueue(request)
        service.deny(request)

        #expect(log.decisions.map(\.decision) == [.deny])
        #expect(activated == 0, "denying never even looks up the browser")
        #expect(hidden == 0)
    }

    // MARK: - Fixtures shared with `AgentServiceTests`

    private static func sampleEnvRequest() -> ApprovalRequestView {
        ApprovalRequestView(
            id: "req-env", action: .writeEnvFile, mintsLease: true, clientName: "claude-code",
            clientPid: 42, clientPidFromKernel: true, clientExecutable: "/usr/bin/kagisecure-mcp",
            clientCwd: "/Users/x/code", environmentId: "e1", environmentName: "acme / staging",
            directory: "/Users/x/code", targetPath: "/Users/x/code/.env", variables: ["TOKEN"],
            command: [], gitignored: false, overwriteRequested: false, targetExists: false,
            targetWrittenByUs: nil, requestedTtlSeconds: 900, requestedUses: 10,
            maxTtlSeconds: 86_400, createdAt: 0, expiresAt: 60, origin: nil, topOrigin: nil,
            topOriginUnknown: false, itemId: nil, itemTitle: nil, fillFields: [], browser: nil,
            browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil, presenceOnly: false)
    }

    private static func fixture() throws -> (VaultSession, URL, String) {
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ks-focus-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("test.kagivault").path,
            masterPassword: "correct horse battery staple", vaultName: "Personal",
            kdfMKib: 64, kdfT: 1)
        _ = session.takeRecoveryCode()
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
            tags: [], urls: [], notes: nil, revision: item.revision)
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

    private static func sidecarPath() -> String? {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        let candidate = url.appendingPathComponent("target/debug/kagisecure-mcp")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate.path : nil
    }

    private static func waitForRequest(on service: AgentService) async throws -> ApprovalRequestView {
        for _ in 0..<200 {
            if let request = service.current { return request }
            try await Task.sleep(for: .milliseconds(50))
        }
        Issue.record("no approval request arrived within 10 seconds")
        throw CancellationError()
    }
}
