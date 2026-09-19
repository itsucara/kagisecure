import AppKit
import Foundation
import Observation

import KagisecureFFI

/// Which sidebar row is selected (ui-spec.md §2.2).
enum SidebarSelection: Hashable {
    case all
    case favorites
    case category(String)
    case tag(String)
    case archive
    case trash
    case agentEnvironments
    case agentLeases
    case agentAudit
    case agentSetup
    case browserExtension

    /// Whether this row shows agent machinery rather than items.
    var isAgentSection: Bool {
        switch self {
        case .agentEnvironments, .agentLeases, .agentAudit, .agentSetup, .browserExtension: true
        default: false
        }
    }

    var filter: ItemFilter? {
        switch self {
        case .all: .all
        case .favorites: .favorites
        case .category(let name): .category(category: name)
        case .tag(let name): .tag(tag: name)
        case .archive: .archive
        case .trash: .trash
        case .agentEnvironments, .agentLeases, .agentAudit, .agentSetup, .browserExtension: nil
        }
    }
}

/// The unlocked vault, as the three panes need it.
///
/// Every read and every write goes through `session`, which is the FFI object. The store holds no
/// model state of its own beyond the current selection and query: after any mutation it re-asks
/// Rust rather than patching a local copy, so the UI cannot drift from the file.
@MainActor
@Observable
final class VaultStore {
    let session: VaultSession

    var selection: SidebarSelection = .all {
        didSet { refresh() }
    }
    var query: String = "" {
        didSet { refresh() }
    }
    var sort: ItemSort = .title {
        didSet { refresh() }
    }
    var selectedItemId: String?

    private(set) var items: [ItemView] = []
    private(set) var counts: SidebarCounts
    private(set) var environments: [EnvironmentView] = []
    private(set) var vaultName: String

    /// The audit page the viewer shows, newest first, plus what it needs to say about the chain.
    private(set) var auditRows: [AuditRowView] = []
    private(set) var auditTotal: UInt32 = 0
    private(set) var auditIntact = true

    /// Surfaced as an alert by the root view. Never carries a secret value.
    var errorMessage: String?

    /// Field ids the user has revealed for the currently selected item, with their plaintext.
    ///
    /// Cleared whenever the selection changes or the item is saved, so a revealed value does not
    /// outlive the row that is showing it.
    private(set) var revealed: [String: String] = [:]

    init(session: VaultSession) {
        self.session = session
        self.counts = session.sidebarCounts()
        self.vaultName = session.vaults().first?.name ?? "Vault"
        refresh()
    }

    var selectedItem: ItemView? {
        guard let selectedItemId else { return nil }
        return items.first { $0.id == selectedItemId } ?? (try? session.item(itemId: selectedItemId))
    }

    func refresh() {
        guard let filter = selection.filter else {
            items = []
            environments = session.environments()
            counts = session.sidebarCounts()
            return
        }
        items = session.listItems(
            filter: filter, query: query.isEmpty ? nil : query, sort: sort)
        counts = session.sidebarCounts()
        environments = session.environments()
        if let id = selectedItemId, !items.contains(where: { $0.id == id }) {
            selectedItemId = items.first?.id
        }
        if selectedItemId == nil {
            selectedItemId = items.first?.id
        }
    }

    // MARK: - Mutations

    func createItem(category: String) throws {
        let title = "New \(displayName(forCategory: category))"
        let item = try session.createItem(vaultId: nil, category: category, title: title)
        selection = .all
        refresh()
        selectedItemId = item.id
    }

    func save(draft: ItemDraft) throws {
        _ = try session.saveItem(draft: draft)
        revealed.removeAll()
        refresh()
    }

    func toggleFavorite(_ item: ItemView) throws {
        _ = try session.setFavorite(itemId: item.id, favorite: !item.favorite)
        refresh()
    }

    func setArchived(_ item: ItemView, _ archived: Bool) throws {
        _ = try session.setArchived(itemId: item.id, archived: archived)
        refresh()
    }

    func setTrashed(_ item: ItemView, _ trashed: Bool) throws {
        _ = try session.setTrashed(itemId: item.id, trashed: trashed)
        refresh()
    }

    func deleteForever(_ item: ItemView) throws {
        try session.deleteItem(itemId: item.id)
        refresh()
    }

    func setAgentVisible(_ item: ItemView, _ visible: Bool) throws {
        _ = try session.setAgentVisible(itemId: item.id, visible: visible)
        refresh()
    }

    func setFieldAgentVisible(_ item: ItemView, _ field: FieldView, _ visible: Bool) throws {
        _ = try session.setFieldAgentVisible(
            itemId: item.id, fieldId: field.id, visible: visible)
        refresh()
    }

    // MARK: - Reveal and copy

    func isRevealed(_ field: FieldView) -> Bool {
        revealed[field.id] != nil
    }

    func revealedValue(_ field: FieldView) -> String? {
        revealed[field.id]
    }

    /// Reveal one field (⌘R). One field, one explicit action — see `reveal_field` in the FFI.
    func toggleReveal(item: ItemView, field: FieldView) throws {
        if revealed.removeValue(forKey: field.id) != nil { return }
        revealed[field.id] = try session.revealField(itemId: item.id, fieldId: field.id)
    }

    func clearRevealed() {
        revealed.removeAll()
    }

    /// Copy a field's value without revealing it (ui-spec.md §4.2).
    ///
    /// A TOTP field is copied as its *code*, not as the `otpauth://` URI it stores: the URI is
    /// the credential, and nobody wants it on their clipboard.
    func copy(item: ItemView, field: FieldView) throws {
        if field.kind == .totp {
            let code = try session.totpCode(
                itemId: item.id, fieldId: field.id, at: TotpCountdown.unixNow())
            PasteboardService.copy(code.code, label: field.label)
            return
        }
        let value = try session.revealField(itemId: item.id, fieldId: field.id)
        PasteboardService.copy(value, label: field.label)
    }

    /// Copy an item's current one-time password, for the list's hover action (ui-spec.md §3).
    func copyItemTotp(_ item: ItemView) {
        do {
            guard let code = try session.itemTotpCode(
                itemId: item.id, at: TotpCountdown.unixNow())
            else { return }
            PasteboardService.copy(code.code, label: "One-time password")
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    /// ⌘C on the list: the row's primary field, which is what the subtitle already shows.
    func copySubtitle() {
        guard let subtitle = selectedItem?.subtitle else { return }
        PasteboardService.copy(subtitle, label: "Username")
    }

    func displayName(forCategory id: String) -> String {
        categoryCatalog().first { $0.id == id }?.displayName ?? id
    }

    // MARK: - Agent access

    /// Whether the first logical vault is shared with agents (threat-model M-9).
    var vaultAgentVisible: Bool {
        session.vaults().first?.agentVisible ?? false
    }

    func setVaultAgentVisible(_ visible: Bool) {
        guard let id = session.vaults().first?.id else { return }
        perform { _ = try session.setVaultAgentVisible(vaultId: id, visible: visible) }
    }

    // MARK: - Environments (ui-spec.md §10.4)

    func createEnvironment(name: String, description: String? = nil) {
        perform { _ = try session.createEnvironment(name: name, description: description) }
    }

    func setEnvironmentAgentVisible(_ environment: EnvironmentView, _ visible: Bool) {
        perform {
            _ = try session.setEnvironmentAgentVisible(
                environmentId: environment.id, visible: visible)
        }
    }

    /// Supply a pending variable's value, typed into the app (mcp-server.md §2.6).
    func setVariableValue(_ environment: EnvironmentView, name: String, value: String) {
        perform {
            _ = try session.setVariableValue(
                environmentId: environment.id, name: name, value: value)
        }
    }

    func removeVariable(_ environment: EnvironmentView, name: String) {
        perform { _ = try session.removeVariable(environmentId: environment.id, name: name) }
    }

    func deleteEnvironment(_ environment: EnvironmentView) {
        perform { try session.deleteEnvironment(environmentId: environment.id) }
    }

    /// Re-read the environment list without touching the item list.
    func refreshEnvironments() {
        environments = session.environments()
    }

    // MARK: - Audit

    func refreshAudit(limit: UInt32) {
        auditRows = session.auditPage(limit: limit, offset: 0)
        auditTotal = session.auditCount()
        auditIntact = session.auditIntact()
    }

    private func perform(_ body: () throws -> Void) {
        do {
            try body()
            refreshEnvironments()
            counts = session.sidebarCounts()
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    static func message(for error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .WrongCredential:
                return "That did not unlock the vault."
            case .NotFound(let m), .AlreadyExists(let m), .NoSuchSlot(let m), .NotPresent(let m),
                .Invalid(let m), .Io(let m):
                return m
            }
        }
        return error.localizedDescription
    }
}
