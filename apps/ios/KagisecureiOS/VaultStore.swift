import Foundation
import KagisecureFFI
import Observation

/// The unlocked vault as the list, detail and edit screens need it (ui-spec §3/§4 for iPhone).
@MainActor
@Observable
final class VaultStore {
    let session: VaultSession
    /// The Mac link: the shared vaults this iPhone is a device of (ui-spec §16).
    let link: LinkModel
    /// Every item — the personal vault's and every shared vault's (item ids are UUIDs, unique
    /// across vaults).
    private(set) var items: [ItemView] = []
    /// Which shared vault each shared item belongs to; personal items are not in it.
    private(set) var sharedOwner: [String: String] = [:]
    let categories: [CategoryInfo]
    var query = ""
    var categoryFilter: String?
    var favoritesOnly = false
    var errorMessage: String?

    init(session: VaultSession, containerDirectory: URL) {
        self.session = session
        link = LinkModel(personal: session, containerDirectory: containerDirectory)
        categories = categoryCatalog()
        link.onChange = { [weak self] in self?.refresh() }
        refresh()
    }

    func refresh() {
        var all = session.listItems(filter: .all, query: nil, sort: .title)
        var owners: [String: String] = [:]
        for vault in link.vaults {
            let id = vault.vaultId()
            for item in vault.listItems(filter: .all, query: nil, sort: .title) {
                owners[item.id] = id
                all.append(item)
            }
        }
        sharedOwner = owners
        items = all.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    /// The shared vault `item` is in, if it is in one.
    func sharedVault(of itemId: String) -> SharedVaultSession? {
        sharedOwner[itemId].flatMap { link.session(for: $0) }
    }

    func isShared(_ itemId: String) -> Bool { sharedOwner[itemId] != nil }

    /// Readers see shared items but may not change them (ui-spec §16.6).
    func canEdit(_ itemId: String) -> Bool {
        guard let vault = sharedOwner[itemId] else { return true }
        return link.canWrite(vault)
    }

    /// Where a new item goes: the first shared vault this iPhone may write to, else the personal
    /// vault — the personal vault stays out of sight while it is empty.
    var defaultNewItemVault: String? {
        let personalEmpty = !items.contains { sharedOwner[$0.id] == nil }
        guard personalEmpty else { return nil }
        return link.summaries.first { link.canWrite($0.id) }?.id
    }

    /// The vaults a new item can go to: `nil` = personal.
    var writableVaults: [(id: String?, name: String)] {
        [(nil, String(localized: "Personal"))] + link.summaries.filter { link.canWrite($0.id) }.map { ($0.id, $0.name) }
    }

    /// Items grouped for the list: one section per vault, the personal one left out while empty.
    var visibleSections: [(id: String, name: String, items: [ItemView])] {
        let visible = visibleItems
        var sections: [(id: String, name: String, items: [ItemView])] = []
        let personal = visible.filter { sharedOwner[$0.id] == nil }
        if !personal.isEmpty { sections.append(("personal", String(localized: "Personal"), personal)) }
        for summary in link.summaries {
            let shared = visible.filter { sharedOwner[$0.id] == summary.id }
            if !shared.isEmpty { sections.append((summary.id, summary.name, shared)) }
        }
        return sections
    }

    /// After a change here: re-read, and hand it on through the folder.
    private func changed(sharedItem itemId: String?) {
        refresh()
        if let itemId, isShared(itemId) {
            Task { await link.sync() }
        }
    }

    var visibleItems: [ItemView] {
        items.filter { item in
            (!favoritesOnly || item.favorite)
                && (categoryFilter == nil || item.category == categoryFilter)
                && Self.matches(item, query: query)
        }
    }

    /// Search by title, tag or URL host — case-insensitive substring.
    nonisolated static func matches(_ item: ItemView, query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return true }
        if item.title.lowercased().contains(q) { return true }
        if item.tags.contains(where: { $0.lowercased().contains(q) }) { return true }
        return item.urls.contains { url in
            let host = URL(string: url)?.host() ?? URL(string: "https://\(url)")?.host() ?? url
            return host.lowercased().contains(q)
        }
    }

    func item(id: String) -> ItemView? {
        if let vault = sharedVault(of: id) { return (try? vault.item(itemId: id)) ?? items.first { $0.id == id } }
        return (try? session.item(itemId: id)) ?? items.first { $0.id == id }
    }

    func displayName(forCategory id: String) -> String {
        categories.first { $0.id == id }?.displayName ?? id
    }

    // MARK: Writes (each persists on its own, as on macOS)

    /// `vault` = a shared vault's id, or `nil` for the personal vault.
    func create(category: String, title: String, vault: String? = nil) throws -> ItemView {
        let trimmed = title.trimmingCharacters(in: .whitespaces)
        let title = trimmed.isEmpty ? String(localized: "New \(displayName(forCategory: category))") : trimmed
        let item: ItemView
        if let vault, let shared = link.session(for: vault) {
            item = try shared.createItem(category: category, title: title)
        } else {
            item = try session.createItem(vaultId: nil, category: category, title: title)
        }
        changed(sharedItem: vault == nil ? nil : item.id)
        return item
    }

    /// Throws `FfiError.ItemChangedElsewhere` on a stale revision of a personal item. A shared
    /// item's save always wins (ui-spec §16.6, decision 80).
    @discardableResult
    func save(_ draft: ItemDraft) throws -> ItemView {
        let saved: ItemView
        if let vault = sharedVault(of: draft.id) {
            saved = try vault.saveItem(draft: draft)
        } else {
            saved = try session.saveItem(draft: draft)
        }
        changed(sharedItem: draft.id)
        return saved
    }

    func toggleFavorite(_ item: ItemView) throws {
        if let vault = sharedVault(of: item.id) {
            _ = try vault.setFavorite(itemId: item.id, favorite: !item.favorite)
        } else {
            _ = try session.setFavorite(itemId: item.id, favorite: !item.favorite)
        }
        refresh()
    }

    /// A personal item moves to Trash, as macOS's Move to Trash does. A shared item is deleted
    /// for everyone — there is no shared Trash (ui-spec §16.6).
    func delete(_ item: ItemView) throws {
        if let vault = sharedVault(of: item.id) {
            let current = (try? vault.item(itemId: item.id)) ?? item
            try vault.deleteItem(itemId: item.id, revision: current.revision)
            refresh()
            Task { await link.sync() }
        } else {
            _ = try session.setTrashed(itemId: item.id, trashed: true)
            refresh()
        }
    }

    // MARK: Trash (personal vault only — a shared vault has no Trash, ui-spec §16.6)

    /// The personal vault's trashed items, newest list each time it is asked for.
    var trashedItems: [ItemView] {
        session.listItems(filter: .trash, query: nil, sort: .title)
    }

    func restore(_ item: ItemView) throws {
        _ = try session.setTrashed(itemId: item.id, trashed: false)
        refresh()
    }

    /// Gone for good: macOS's Delete Permanently.
    func deletePermanently(_ item: ItemView) throws {
        let current = (try? session.item(itemId: item.id)) ?? item
        try session.deleteItem(itemId: item.id, revision: current.revision)
        refresh()
    }

    /// Every trashed item, permanently.
    func emptyTrash() throws {
        for item in trashedItems { try deletePermanently(item) }
    }

    // MARK: Secrets — each behind a fresh presence check (ADR-0038)

    func reveal(_ item: ItemView, field: FieldView) async throws -> String {
        let release =
            if let vault = sharedVault(of: item.id) {
                try await vault.releaseField(itemId: item.id, fieldId: field.id, purpose: .reveal)
            } else {
                try await session.releaseField(itemId: item.id, fieldId: field.id, purpose: .reveal)
            }
        defer { release.close() }
        return try release.value()
    }

    func copy(_ item: ItemView, field: FieldView) async throws {
        if !field.concealed {
            Pasteboard.copy(field.value ?? "")
            return
        }
        let release =
            if let vault = sharedVault(of: item.id) {
                try await vault.releaseField(itemId: item.id, fieldId: field.id, purpose: .copy)
            } else {
                try await session.releaseField(itemId: item.id, fieldId: field.id, purpose: .copy)
            }
        defer { release.close() }
        Pasteboard.copy(try release.value())
    }

    func revealNotes(_ item: ItemView) async throws -> String {
        let release =
            if let vault = sharedVault(of: item.id) {
                try await vault.releaseNotes(itemId: item.id, purpose: .reveal)
            } else {
                try await session.releaseNotes(itemId: item.id, purpose: .reveal)
            }
        defer { release.close() }
        return try release.text()
    }

    // MARK: One-time passwords (ADR-0038: showing and copying each take a presence check)

    /// A release that shows the code for a while (five-minute cap, then it ends).
    func releaseTotp(_ item: ItemView, field: FieldView, purpose: ReleasePurpose) async throws -> TotpRelease {
        if let vault = sharedVault(of: item.id) {
            return try await vault.releaseTotp(itemId: item.id, fieldId: field.id, purpose: purpose)
        }
        return try await session.releaseTotp(itemId: item.id, fieldId: field.id, purpose: purpose)
    }

    /// Copy the current code. With a live release that is already showing the code no new check
    /// is asked (Mac's "shown earlier" rule); otherwise a fresh copy release is taken.
    func copyTotp(_ item: ItemView, field: FieldView, shown: TotpRelease?) async throws {
        let now = Self.unixNow()
        if let shown, shown.isLive(), let code = try? shown.copyShownCodeAt(at: now) {
            Pasteboard.copy(code.code)
            return
        }
        let release = try await releaseTotp(item, field: field, purpose: .copy)
        defer { release.close() }
        Pasteboard.copy(try release.codeAt(at: Self.unixNow()).code)
    }

    nonisolated static func unixNow() -> UInt64 { UInt64(Date().timeIntervalSince1970) }
}
