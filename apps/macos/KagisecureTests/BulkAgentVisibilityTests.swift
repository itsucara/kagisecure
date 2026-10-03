import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Multi-select bulk "Show to Agents" / "Hide from Agents" and the "Show new items to agents"
/// setting (ADR-0007 amendment 2026-10-04), through the real FFI against a real vault file.
@MainActor
struct BulkAgentVisibilityTests {
    private static func newStore() throws -> (VaultStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")
        let session = try VaultSession.create(
            path: path.path, masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 64, kdfT: 1)
        return (VaultStore(session: session), path)
    }

    /// Give `item` exactly these tags, keeping every field's stored value.
    private static func tag(_ store: VaultStore, _ item: ItemView, _ tags: [String]) throws {
        try store.save(
            draft: ItemDraft(
                id: item.id, category: item.category, title: item.title,
                fields: item.fields.map {
                    FieldDraft(
                        id: $0.id, label: $0.label, kind: $0.kind, concealed: $0.concealed,
                        value: nil, section: $0.section, agentVisible: $0.agentVisible)
                },
                tags: tags, urls: [], notes: nil, revision: item.revision))
    }

    @Test func theSettingDefaultsOnAndCanBeTurnedOff() throws {
        let (store, path) = try Self.newStore()
        #expect(store.newItemsAgentVisible)

        store.setNewItemsAgentVisible(false)
        #expect(!store.newItemsAgentVisible)
        try store.createItem(category: "login")
        #expect(try #require(store.selectedItem).agentVisible == false)

        let reopened = try VaultSession.unlockWithPassword(
            path: path.path, masterPassword: "correct horse battery staple")
        #expect(reopened.vaults().first?.newItemsAgentVisible == false)
    }

    @Test func multiSelectionShowsAndHidesTogetherWithOneAuditEntry() throws {
        let (store, _) = try Self.newStore()
        store.setNewItemsAgentVisible(false)
        for _ in 0..<3 { try store.createItem(category: "login") }
        #expect(store.items.count == 3)
        #expect(store.items.allSatisfy { !$0.agentVisible })

        // ⌘-click two rows.
        let chosen = Set(store.items.prefix(2).map(\.id))
        store.listSelection = chosen
        #expect(store.multiSelection == chosen)
        #expect(Set(store.bulkTargetIds) == chosen)

        let before = store.session.auditCount()
        let shown = try store.setSelectionAgentVisible(true)
        #expect(shown.matched == 2 && shown.changed == 2)
        #expect(store.session.auditCount() == before + 1, "one audit entry for the whole change")
        for item in store.items {
            #expect(item.agentVisible == chosen.contains(item.id))
            #expect(item.fields.allSatisfy { $0.agentVisible == chosen.contains(item.id) })
        }
        #expect(store.multiSelection == chosen, "the selection survives the refresh")

        let hidden = try store.setSelectionAgentVisible(false)
        #expect(hidden.changed == 2)
        #expect(store.items.allSatisfy { !$0.agentVisible })

        // Back to one row: the ordinary single selection.
        let one = try #require(store.items.last?.id)
        store.listSelection = [one]
        #expect(store.multiSelection.isEmpty)
        #expect(store.selectedItemId == one)
        #expect(store.bulkTargetIds == [one])
    }

    @Test func aTagActionReachesEveryTaggedItem() throws {
        let (store, _) = try Self.newStore()
        store.setNewItemsAgentVisible(false)
        for _ in 0..<3 { try store.createItem(category: "login") }
        let items = store.items
        try Self.tag(store, items[0], ["imported:chromium"])
        try Self.tag(store, items[1], ["imported:chromium"])

        let result = try store.setAgentVisible(scope: .tag(tag: "imported:chromium"), true)
        #expect(result.matched == 2)
        store.selection = .all
        #expect(store.items.filter { $0.agentVisible }.count == 2)

        let all = try store.setAgentVisible(scope: .all, true)
        #expect(all.matched == 3 && all.changed == 1)
    }

    @Test func changingTheSidebarSectionClearsTheMultiSelection() throws {
        let (store, _) = try Self.newStore()
        for _ in 0..<2 { try store.createItem(category: "login") }
        store.listSelection = Set(store.items.map(\.id))
        #expect(store.multiSelection.count == 2)
        store.selection = .favorites
        #expect(store.multiSelection.isEmpty)
    }
}
