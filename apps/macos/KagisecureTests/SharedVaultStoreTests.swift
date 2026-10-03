import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Shared vaults through `VaultStore` (ADR-0035, ui-spec.md §16): the same item list, detail and
/// edit calls the personal vault uses, routed to a shared vault by the sidebar selection — against
/// real vault files and a real folder in a temporary directory, nothing mocked.
@MainActor
struct SharedVaultStoreTests {
    private static let master = "correct horse battery staple"

    /// A directory for one test: two personal vaults' worth of room and a shared folder.
    private static func directory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-shared-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    /// A personal vault named `name` in `directory`, unlocked, at KDF parameters that protect
    /// nothing, with a presence gate that always says yes.
    private static func personal(_ name: String, in directory: URL) throws -> VaultSession {
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("\(name).kagivault").path,
            masterPassword: master, vaultName: name, kdfMKib: 64, kdfT: 1)
        try session.setPresenceGate(gate: ScriptedPresenceGate(Array(repeating: .confirmed, count: 8)))
        return session
    }

    /// Save `item` with `password` as its password, through the store, keeping the rest.
    private static func setPassword(_ store: VaultStore, _ item: ItemView, _ password: String) throws {
        try store.save(
            draft: ItemDraft(
                id: item.id, category: item.category, title: item.title,
                fields: item.fields.filter { $0.kind != .totp }.map { field in
                    FieldDraft(
                        id: field.id, label: field.label, kind: field.kind,
                        concealed: field.concealed,
                        value: field.label == "password" ? password : (field.concealed ? nil : "ada"),
                        section: field.section, agentVisible: field.agentVisible)
                },
                tags: [], urls: [], notes: nil, revision: item.revision))
    }

    /// The password `store` reveals for the selected item.
    private static func revealPassword(_ store: VaultStore) async throws -> String? {
        let item = try #require(store.selectedItem)
        let field = try #require(item.fields.first { $0.label == "password" })
        store.releases.announce = { _ in }
        try await store.releases.toggleReveal(item: item, field: field)
        return store.releases.shownValue(field)
    }

    @Test func aNewSharedVaultTakesItemsThroughTheSameStoreCalls() async throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = VaultStore(session: try Self.personal("alice", in: directory))
        #expect(store.shared.vaults.isEmpty)

        let id = try store.shared.create(
            name: "Team", folder: directory.appendingPathComponent("Team folder"))
        #expect(store.shared.summary(for: id)?.name == "Team")
        #expect(store.shared.summary(for: id)?.myRole == .admin)
        #expect(store.shared.isAdmin(id))

        store.selection = .sharedVault(id)
        #expect(store.windowTitle == "Team")
        #expect(store.canEditItems)
        try store.createItem(category: "login")
        // A new shared item stays in the shared vault's list, selected.
        #expect(store.selection == .sharedVault(id))
        let created = try #require(store.selectedItem)
        try Self.setPassword(store, created, "shared-s3cret")
        #expect(store.items.count == 1)
        #expect(try await Self.revealPassword(store) == "shared-s3cret")
        #expect(store.shared.summary(for: id)?.itemCount == 1)

        // None of it went into the personal vault.
        #expect(store.counts.all == 0)
        store.selection = .all
        #expect(store.items.isEmpty)
        // Moving away hid what was shown.
        #expect(store.releases.fields.isEmpty)

        // Deleting a shared item deletes it; there is no shared Trash.
        store.selection = .sharedVault(id)
        let item = try #require(store.selectedItem)
        try store.setTrashed(item, true)
        #expect(store.items.isEmpty)
        #expect(store.counts.trash == 0)
    }

    @Test func anInvitationAndItsWordsJoinASecondMacThatSyncsThroughTheFolder() async throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let folder = directory.appendingPathComponent("Team folder")
        let alice = VaultStore(session: try Self.personal("alice", in: directory))
        let id = try alice.shared.create(name: "Team", folder: folder)
        alice.selection = .sharedVault(id)
        try alice.createItem(category: "login")
        try Self.setPassword(alice, try #require(alice.selectedItem), "first")

        // The invite sheet's call, at a cost that protects nothing.
        let vault = try #require(alice.shared.session(for: id))
        let invitation = try vault.inviteMember(
            name: "Bob", role: .writer,
            outPath: folder.appendingPathComponent("Bob.kagisecure-invite").path,
            kdfMKib: 64, kdfT: 1)
        #expect(invitation.passphrase.split(separator: "-").count == 6)
        alice.shared.refresh()
        #expect(alice.shared.members[id]?.map(\.name).contains("Bob") == true)

        // The join sheet: the folder is found beside the invitation.
        let bob = VaultStore(session: try Self.personal("bob", in: directory))
        let invitationURL = URL(fileURLWithPath: invitation.path)
        #expect(
            SharedPanels.folder(besides: invitationURL)?.standardizedFileURL
                == folder.standardizedFileURL)
        #expect(
            await refusal {
                _ = try await bob.shared.join(
                    invitation: invitationURL, passphrase: "wrong", folder: folder)
            } == "WrongCredential")
        let joined = try await bob.shared.join(
            invitation: invitationURL, passphrase: invitation.passphrase, folder: folder)
        #expect(joined == id)
        bob.selection = .sharedVault(id)
        #expect(bob.shared.summary(for: id)?.myRole == .writer)
        #expect(try await Self.revealPassword(bob) == "first")

        // Bob edits; Alice's sync picks it up, and her open list re-reads.
        try Self.setPassword(bob, try #require(bob.selectedItem), "rotated")

        // `lastSynced[id]` was very likely already non-nil before this point: Alice's own
        // `createItem` and `setPassword` above each end in `changed()` -> `shared.didChangeLocally`
        // -> `sync(id)`, and the several `await`s since (the invite, the wrong-passphrase join, the
        // real join, Bob's reveal) give that earlier sync plenty of time to finish and set it. A
        // bare `lastSynced[id] != nil` wait is therefore satisfied immediately, before the sync
        // this line starts has done anything — the test would then read Bob's edit before Alice's
        // copy has actually picked it up, which is exactly the intermittent failure this guards
        // against. Waiting for the timestamp to change from what it was *right before this sync*
        // instead waits for the sync this line starts (or a later one), not a stale one.
        let syncedBefore = alice.shared.lastSynced[id]
        alice.shared.sync(id)
        #expect(await eventually { alice.shared.lastSynced[id] != syncedBefore })
        #expect(try await Self.revealPassword(alice) == "rotated")
    }

    @Test func lockingThePersonalVaultClosesItsSharedVaults() throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let session = try Self.personal("alice", in: directory)
        let store = VaultStore(session: session)
        let id = try store.shared.create(name: "Team", folder: nil)
        store.selection = .sharedVault(id)
        try store.createItem(category: "login")
        #expect(store.items.count == 1)

        session.lock()
        let vault = try #require(store.shared.session(for: id))
        #expect(vault.listItems(filter: .all, query: nil, sort: .title).isEmpty)
        #expect(vault.summary().problem != nil)
        store.refresh()
        #expect(store.items.isEmpty)
    }

    @Test func aReopenedPersonalVaultFindsItsSharedVaults() throws {
        let directory = try Self.directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let session = try Self.personal("alice", in: directory)
        let id = try VaultStore(session: session).shared.create(name: "Team", folder: nil)
        let path = session.path()
        session.lock()

        let reopened = try VaultSession.unlockWithPassword(path: path, masterPassword: Self.master)
        let store = VaultStore(session: reopened)
        #expect(store.shared.summaries.map(\.id) == [id])
        #expect(store.shared.summary(for: id)?.name == "Team")
    }
}
