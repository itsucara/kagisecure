import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Shared-vault environments (ADR-0035, ui-spec.md §16.6), through the same Swift bindings the
/// app's sidebar Environments pane calls (`SharedEnvironmentsView`, `EnvironmentEditing`) — real
/// vault files in a temporary directory, nothing mocked, mirroring
/// `crates/kagisecure-ffi/tests/shared_vaults.rs`'s Rust coverage of the same calls.
@MainActor
struct SharedEnvironmentsTests {
    private static let master = "correct horse battery staple"

    private static func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-shared-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private static func personal(_ name: String, in directory: URL) throws -> VaultSession {
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("\(name).kagivault").path,
            masterPassword: master, vaultName: name, kdfMKib: 64, kdfT: 1)
        try session.setPresenceGate(gate: ScriptedPresenceGate(Array(repeating: .confirmed, count: 8)))
        return session
    }

    @Test func anEnvironmentIsCreatedBoundRenamedSharedAndDeleted() async throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let alice = VaultStore(session: try Self.personal("alice", in: directory))
        let id = try alice.shared.create(name: "Team", folder: nil)
        let vault = try #require(alice.shared.session(for: id))

        #expect(vault.environments().isEmpty)
        let created = try vault.createEnvironment(name: "  prod  ", description: "Production")
        #expect(created.name == "prod")
        #expect(created.description == "Production")
        #expect(!created.agentVisible)
        #expect(created.variables.isEmpty)

        // A literal value.
        let withLiteral = try vault.setVariableValue(
            environmentId: created.id, name: "TOKEN", value: "literal-value")
        #expect(withLiteral.variableNames == ["TOKEN"])
        #expect(withLiteral.variables[0].binding == .literal)

        // Bound to a field of an item in this same shared vault.
        alice.selection = .sharedVault(id)
        try alice.createItem(category: "login")
        let item = try #require(alice.selectedItem)
        let field = try #require(item.fields.first { $0.label == "password" })
        let withBinding = try vault.bindVariable(
            environmentId: created.id, name: "DB_PASSWORD", itemId: item.id, fieldId: field.id)
        #expect(withBinding.variableNames == ["TOKEN", "DB_PASSWORD"])
        let bound = try #require(withBinding.variables.first { $0.name == "DB_PASSWORD" })
        #expect(bound.binding == .itemField)
        #expect(bound.itemId == item.id)

        // Renamed, then shared with agents (this device's own setting).
        let renamed = try vault.renameEnvironment(environmentId: created.id, name: "  production  ")
        #expect(renamed.name == "production")
        let shared = try vault.setEnvironmentAgentVisible(environmentId: created.id, visible: true)
        #expect(shared.agentVisible)

        // `SharedVaultsModel.environments` reflects it once refreshed, the way the sidebar's row
        // count and the pane's list do.
        alice.shared.refresh()
        #expect(alice.shared.environments[id]?.first?.name == "production")

        // Removing a variable, then deleting the environment: for everyone, and gone from the
        // list `SharedEnvironmentsView` reads.
        let trimmed = try vault.removeVariable(environmentId: created.id, name: "TOKEN")
        #expect(trimmed.variableNames == ["DB_PASSWORD"])
        try vault.deleteEnvironment(environmentId: created.id)
        #expect(vault.environments().isEmpty)
        #expect(throws: FfiError.self) { try vault.environment(environmentId: created.id) }
    }

    @Test func aReaderViewsButCannotEditAndItsOwnAgentVisibilityStaysLocal() async throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let folder = directory.appendingPathComponent("Team folder")
        let alice = VaultStore(session: try Self.personal("alice", in: directory))
        let id = try alice.shared.create(name: "Team", folder: folder)
        let aliceVault = try #require(alice.shared.session(for: id))
        let env = try aliceVault.createEnvironment(name: "prod", description: nil)
        _ = try aliceVault.setVariableValue(environmentId: env.id, name: "TOKEN", value: "v")

        let invitation = try aliceVault.inviteMember(
            name: "Bob", role: .reader,
            outPath: folder.appendingPathComponent("Bob.kagisecure-invite").path,
            kdfMKib: 64, kdfT: 1)
        let bob = VaultStore(session: try Self.personal("bob", in: directory))
        let joinedId = try await bob.shared.join(
            invitation: URL(fileURLWithPath: invitation.path), passphrase: invitation.passphrase,
            folder: folder)
        let bobVault = try #require(bob.shared.session(for: joinedId))

        let seen = bobVault.environments()
        #expect(seen.first?.variableNames == ["TOKEN"])

        #expect(throws: FfiError.self) {
            try bobVault.createEnvironment(name: "nope", description: nil)
        }
        #expect(throws: FfiError.self) {
            try bobVault.setVariableValue(environmentId: env.id, name: "TOKEN", value: "x")
        }
        #expect(throws: FfiError.self) {
            try bobVault.renameEnvironment(environmentId: env.id, name: "nope")
        }
        #expect(throws: FfiError.self) {
            try bobVault.deleteEnvironment(environmentId: env.id)
        }

        // Local-only: a reader may still flip this device's own agent-visibility flag, and it
        // never reaches Alice's copy.
        let mine = try bobVault.setEnvironmentAgentVisible(environmentId: env.id, visible: true)
        #expect(mine.agentVisible)
        #expect(try aliceVault.environment(environmentId: env.id).agentVisible == false)
    }

    /// `.sharedEnvironments` belongs to its vault and shows no item list, the same two rules every
    /// other agent-machinery and shared-vault row follows (`SidebarSelection`).
    @Test func sidebarSelectionKnowsItsVaultAndShowsNoItems() {
        let selection = SidebarSelection.sharedEnvironments("abc123")
        #expect(selection.sharedVaultId == "abc123")
        #expect(!selection.showsItems)
        #expect(selection.filter == nil)
    }
}
