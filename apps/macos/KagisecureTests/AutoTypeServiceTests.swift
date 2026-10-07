import Testing

import KagisecureFFI

@testable import Kagisecure

/// ADR-0050: the typist verifies before it types and stops when focus moves.
@MainActor
struct AutoTypeServiceTests {
    final class FakeInspector: FocusInspector {
        var isTrusted = true
        var front: FrontmostApp? = FrontmostApp(bundleId: "com.example.Term", teamId: "ABCDE12345", windowTitle: "ssh staging")
        var focus: FocusedElement? = FocusedElement(identity: 1, isTextInput: true, isSecure: false)
        var secure = false
        /// Called on every focus read, so a test can move focus mid-typing.
        var onFocusRead: (Int) -> Void = { _ in }
        private var reads = 0

        func frontmost() -> FrontmostApp? { front }
        func focusedElement() -> FocusedElement? {
            reads += 1
            onFocusRead(reads)
            return focus
        }
        func secureInputActive() -> Bool { secure }
    }

    final class FakePoster: KeystrokePoster {
        var events: [String] = []
        var onTab: () -> Void = {}
        func postText(_ text: String) { events.append(text) }
        func postKey(_ keyCode: UInt16) {
            events.append("<key \(keyCode)>")
            onTab()
        }
    }

    let target = AutoTypeService.Target(bundleId: "com.example.Term", teamId: "ABCDE12345", windowTitle: "staging")

    @Test func usernameTabPasswordIsTypedInOrder() {
        let inspector = FakeInspector()
        let poster = FakePoster()
        poster.onTab = { inspector.focus = FocusedElement(identity: 2, isTextInput: true, isSecure: true) }
        let service = AutoTypeService(inspector: inspector, poster: poster)
        let outcome = service.type([(.username, "alice"), (.password, "hunter2")], into: target)
        #expect(outcome == .typed)
        #expect(poster.events == ["alice", "<key 48>", "hunter2"])
    }

    @Test func aFrontmostMismatchTypesNothing() {
        let inspector = FakeInspector()
        inspector.front = FrontmostApp(bundleId: "com.other.App", teamId: "ABCDE12345", windowTitle: "ssh staging")
        let poster = FakePoster()
        let outcome = AutoTypeService(inspector: inspector, poster: poster).type([(.username, "alice")], into: target)
        #expect(outcome == .targetMismatch)
        #expect(poster.events.isEmpty)
    }

    @Test func aTeamOrWindowMismatchTypesNothing() {
        let inspector = FakeInspector()
        inspector.front?.teamId = "ZZZZZ99999"
        let poster = FakePoster()
        #expect(AutoTypeService(inspector: inspector, poster: poster).type([(.username, "a")], into: target) == .targetMismatch)
        inspector.front?.teamId = "ABCDE12345"
        inspector.front?.windowTitle = "Mail"
        #expect(AutoTypeService(inspector: inspector, poster: poster).type([(.username, "a")], into: target) == .targetMismatch)
        #expect(poster.events.isEmpty)
    }

    @Test func aPasswordNeedsASecureField() {
        let inspector = FakeInspector()
        let poster = FakePoster()
        let outcome = AutoTypeService(inspector: inspector, poster: poster).type([(.password, "hunter2")], into: target)
        #expect(outcome == .targetMismatch)
        #expect(poster.events.isEmpty)
    }

    @Test func focusChangeMidTypeStops() {
        let inspector = FakeInspector()
        // The second read is the check after the first chunk: focus has moved.
        inspector.onFocusRead = { read in
            if read >= 2 { inspector.focus = FocusedElement(identity: 9, isTextInput: true, isSecure: false) }
        }
        let poster = FakePoster()
        let outcome = AutoTypeService(inspector: inspector, poster: poster)
            .type([(.username, "a-rather-long-username")], into: target)
        #expect(outcome == .focusChanged(typedAny: true))
        #expect(poster.events.count == 1, "stopped after the first chunk")
    }

    @Test func secureInputRefusesAndAccessibilityIsRequired() {
        let inspector = FakeInspector()
        inspector.secure = true
        let poster = FakePoster()
        #expect(AutoTypeService(inspector: inspector, poster: poster).type([(.username, "a")], into: target) == .secureInput)
        inspector.secure = false
        inspector.isTrusted = false
        #expect(AutoTypeService(inspector: inspector, poster: poster).type([(.username, "a")], into: target) == .accessibilityDenied)
        #expect(poster.events.isEmpty)
    }

    @Test func autoTypeRidesTheGraceWindow() {
        let request = ApprovalRequestView(
            id: "ks-auto-type-1", action: .autoType, mintsLease: false,
            clientName: "Claude Code", clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: nil,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: [], gitignored: nil,
            overwriteRequested: false, targetExists: nil, targetWrittenByUs: nil,
            requestedTtlSeconds: 0, requestedUses: 1, maxTtlSeconds: 0,
            createdAt: 0, expiresAt: 60, origin: "com.example.Term", topOrigin: nil,
            topOriginUnknown: false, itemId: "i", itemTitle: "Staging", fillFields: ["password"],
            browser: nil, browserPid: nil, browserExecutable: nil, browserIsAppExtension: false,
            extensionId: nil, presenceOnly: false, ridesGrace: true)
        #expect(PresenceGrace.applies(to: request))
        #expect(AgentService.needsSheet(request))
        #expect(AgentService.returnsFocusOnApproval(request))
    }
}
