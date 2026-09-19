import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Round-trips through the real FFI against a real vault file in a temporary directory.
///
/// Nothing here is mocked. The point of these tests is that the Swift layer and the Rust core
/// agree — a fake `VaultSession` would only prove that the Swift layer agrees with itself.
@MainActor
struct VaultStoreTests {
    /// Argon2id at 8 KiB / 1 pass. These vaults live for milliseconds and protect nothing; the
    /// default desktop profile would add seconds to every test.
    private static func newVault() throws -> (VaultSession, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")
        let session = try VaultSession.create(
            path: path.path, masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 8, kdfT: 1)
        return (session, path)
    }

    @Test func createsAVaultAndHandsOutTheRecoveryCodeExactlyOnce() throws {
        let (session, _) = try Self.newVault()
        let code = session.takeRecoveryCode()
        #expect(code != nil)
        #expect(code?.isEmpty == false)
        #expect(session.takeRecoveryCode() == nil, "a one-time code must be handed out once")
    }

    @Test func createsAnItemFromItsCategoryTemplate() throws {
        let (session, _) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")

        let item = try #require(store.selectedItem)
        #expect(item.title == "New Login")
        // `website` is not a template field (ADR-0029) — `Item.urls`, edited via the Websites
        // field, is the one place a site lives.
        #expect(item.fields.map(\.label) == ["username", "password", "one-time password"])
        #expect(item.fields[1].concealed)
        #expect(!item.agentVisible, "a new item is never visible to agents")
    }

    @Test func roundTripsAConcealedFieldThroughSaveAndReveal() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let item = try #require(store.selectedItem)

        var draft = ItemDraft(
            id: item.id, category: item.category, title: "Acme production",
            fields: item.fields.map { field in
                FieldDraft(
                    id: field.id, label: field.label, kind: field.kind,
                    concealed: field.concealed,
                    value: field.label == "password"
                        ? "sk_live_kagisecure_9f3a" : (field.label == "username" ? "deploy" : ""),
                    section: field.section, agentVisible: field.agentVisible)
            },
            tags: ["prod"], urls: ["https://acme.example"], notes: "a note")
        draft.title = "Acme production"
        try store.save(draft: draft)

        let saved = try #require(store.selectedItem)
        #expect(saved.title == "Acme production")
        #expect(saved.subtitle == "deploy")
        #expect(saved.tags == ["prod"])

        let password = try #require(saved.fields.first { $0.label == "password" })
        #expect(password.concealed)
        #expect(password.hasValue)
        #expect(password.value == nil, "a concealed value never rides along in the list")
        #expect(
            try session.revealField(itemId: saved.id, fieldId: password.id)
                == "sk_live_kagisecure_9f3a")

        // And it survives a lock/unlock cycle, which is what "saved" has to mean.
        let reopened = try VaultSession.unlockWithPassword(
            path: path.path, masterPassword: "correct horse battery staple")
        let again = try #require(reopened.listItems(filter: .all, query: nil, sort: .title).first)
        #expect(
            try reopened.revealField(
                itemId: again.id,
                fieldId: try #require(again.fields.first { $0.label == "password" }).id)
                == "sk_live_kagisecure_9f3a")
    }

    @Test func searchMatchesTitlesTagsAndUrlsButNeverValues() throws {
        let (session, _) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let item = try #require(store.selectedItem)
        try store.save(
            draft: ItemDraft(
                id: item.id, category: item.category, title: "Acme production",
                fields: [
                    FieldDraft(
                        id: nil, label: "password", kind: .concealed, concealed: true,
                        value: "canary-marker-value", section: nil, agentVisible: false)
                ],
                tags: ["prod"], urls: ["https://acme.example"], notes: nil))

        store.query = "acme"
        #expect(store.items.count == 1)
        store.query = "PROD"
        #expect(store.items.count == 1, "search is case-insensitive and matches tags")
        store.query = "example"
        #expect(store.items.count == 1, "search matches URLs")
        store.query = "canary"
        #expect(store.items.isEmpty, "search must never match a secret value")
    }

    @Test func sidebarSectionsFilterTheList() throws {
        let (session, _) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let login = try #require(store.selectedItem)
        try store.createItem(category: "database")
        let database = try #require(store.selectedItem)

        store.selection = .all
        #expect(store.items.count == 2)

        try store.toggleFavorite(login)
        store.selection = .favorites
        #expect(store.items.map(\.id) == [login.id])

        store.selection = .category("database")
        #expect(store.items.map(\.id) == [database.id])

        try store.setArchived(login, true)
        store.selection = .archive
        #expect(store.items.map(\.id) == [login.id])
        store.selection = .all
        #expect(store.items.map(\.id) == [database.id], "archived items leave All Items")

        try store.setTrashed(database, true)
        store.selection = .trash
        #expect(store.items.map(\.id) == [database.id])
        store.selection = .all
        #expect(store.items.isEmpty)

        // Trash is a soft delete: restoring brings the item back intact.
        try store.setTrashed(database, false)
        store.selection = .all
        #expect(store.items.map(\.id) == [database.id])

        // And a permanent delete really removes it.
        try store.deleteForever(database)
        store.selection = .all
        #expect(store.items.isEmpty)
    }

    @Test func agentVisibilityDefaultsOffAndPersists() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "api-credential")
        let item = try #require(store.selectedItem)
        #expect(!item.agentVisible)

        try store.setAgentVisible(item, true)
        let visible = try #require(store.selectedItem)
        #expect(visible.agentVisible)

        let field = try #require(visible.fields.first)
        try store.setFieldAgentVisible(visible, field, true)
        #expect(try #require(store.selectedItem).fields.first?.agentVisible == true)

        // Turning the item off turns every field off with it.
        try store.setAgentVisible(visible, false)
        let hidden = try #require(store.selectedItem)
        #expect(!hidden.agentVisible)
        #expect(hidden.fields.allSatisfy { !$0.agentVisible })

        // It is on disk, not just in memory.
        let reopened = try VaultSession.unlockWithPassword(
            path: path.path, masterPassword: "correct horse battery staple")
        #expect(reopened.listItems(filter: .all, query: nil, sort: .title).first?.agentVisible == false)
    }

    @Test func sidebarCountsCoverEveryCategoryEvenEmptyOnes() throws {
        let (session, _) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "server")

        #expect(store.counts.all == 1)
        #expect(store.counts.categories.count >= 12, "every first-class category keeps its row")
        #expect(store.counts.categories.first { $0.name == "server" }?.count == 1)
        #expect(store.counts.categories.first { $0.name == "identity" }?.count == 0)
    }

    @Test func aWrongPasswordIsRefusedWithoutSayingWhy() throws {
        let (_, path) = try Self.newVault()
        #expect(throws: FfiError.self) {
            _ = try VaultSession.unlockWithPassword(path: path.path, masterPassword: "wrong")
        }
    }

    @Test func aPlatformSlotRoundTripsWithoutTheKeystore() throws {
        // The keystore is stubbed out with the identity function here; the real Secure Enclave
        // path is exercised in PlatformKeyServiceTests, which skips when it cannot run.
        let (session, path) = try Self.newVault()
        #expect(!session.hasPlatformSlot())

        let key = session.exportVaultKeyForPlatformWrapping()
        #expect(key.count == 32)
        try session.installPlatformSlot(slotId: "test", label: "Test", wrappedKey: key)
        #expect(session.hasPlatformSlot())
        #expect(try platformSlotId(path: path.path) == "test")
        #expect(try platformWrappedKey(path: path.path) == key)

        let unlocked = try VaultSession.unlockWithVaultKey(path: path.path, vaultKey: key)
        #expect(unlocked.unlockedBy() == .platformKey)

        #expect(try unlocked.removePlatformSlot())
        #expect(try platformSlotId(path: path.path) == nil)
    }
}
