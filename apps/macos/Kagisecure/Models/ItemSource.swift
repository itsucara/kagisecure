import Foundation

import KagisecureFFI

/// Where a release comes from: the personal vault, or one shared vault. Both answer through the
/// same presence gate and hand back the same release objects (ADR-0038), so `ItemReleases` does
/// not need to know which.
protocol ReleaseSource: AnyObject, Sendable {
    func releaseField(itemId: String, fieldId: String, purpose: ReleasePurpose) async throws
        -> FieldRelease
    func releaseTotp(itemId: String, fieldId: String?, purpose: ReleasePurpose) async throws
        -> TotpRelease
    func releaseNotes(itemId: String, purpose: ReleasePurpose) async throws -> NotesRelease
}

/// What the item list, the detail pane and the edit sheet need from a vault: the personal one
/// (`VaultSession`) or a shared one (`SharedVaultSession`). `VaultStore` routes every item call
/// through the source the sidebar selection names, so the three panes work unchanged on either.
///
/// Two differences stay behind this protocol rather than in the views: a shared save never
/// answers `FfiError.ItemChangedElsewhere` (the last writer wins), and moving a shared item to
/// the Trash deletes it for everyone.
protocol ItemSource: ReleaseSource {
    func listItems(filter: ItemFilter, query: String?, sort: ItemSort) -> [ItemView]
    func item(itemId: String) throws -> ItemView
    func newItem(category: String, title: String) throws -> ItemView
    func saveItem(draft: ItemDraft) throws -> ItemView
    func setFavorite(itemId: String, favorite: Bool) throws -> ItemView
    func setArchived(itemId: String, archived: Bool) throws -> ItemView
    func setTrashed(itemId: String, trashed: Bool) throws -> ItemView
    func deleteItem(itemId: String, revision: String) throws
    func setAgentVisible(itemId: String, visible: Bool) throws -> ItemView
    func setFieldAgentVisible(itemId: String, fieldId: String, visible: Bool) throws -> ItemView
}

extension VaultSession: ItemSource {
    /// A new item in the personal vault's default logical vault.
    func newItem(category: String, title: String) throws -> ItemView {
        try createItem(vaultId: nil, category: category, title: title)
    }
}

extension SharedVaultSession: ItemSource {
    func newItem(category: String, title: String) throws -> ItemView {
        try createItem(category: category, title: title)
    }
}
