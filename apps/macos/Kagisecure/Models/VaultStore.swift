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
    /// Unattended jobs (ADR-0042 Phase 3).
    case agentUnattended
    case browserExtension
    /// A shared vault's items (ADR-0035), by vault id.
    case sharedVault(String)
    /// A shared vault's members, by vault id.
    case sharedMembers(String)
    /// A shared vault's environments (ui-spec.md §16), by vault id.
    case sharedEnvironments(String)

    /// Whether this row shows items — the three-column arrangement — rather than a pane of its
    /// own: agent machinery, or a shared vault's members or environments.
    var showsItems: Bool { filter != nil }

    /// The shared vault this row belongs to, if any.
    var sharedVaultId: String? {
        switch self {
        case .sharedVault(let id), .sharedMembers(let id), .sharedEnvironments(let id): id
        default: nil
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
        // A shared vault has no sections of its own: every item that is not deleted.
        case .sharedVault: .all
        case .agentEnvironments, .agentLeases, .agentAudit, .agentSetup, .agentUnattended,
            .browserExtension, .sharedMembers, .sharedEnvironments:
            nil
        }
    }
}

/// The unlocked vault, as the three panes need it.
///
/// Every read and every write goes through `session`, which is the FFI object — or, while a shared
/// vault is selected, through that vault's `SharedVaultSession` (`source`), so the item list, the
/// detail pane and the edit sheet work unchanged on either. The store holds no model state of its
/// own beyond the current selection and query: after any mutation it re-asks Rust rather than
/// patching a local copy, so the UI cannot drift from the file.
@MainActor
@Observable
final class VaultStore {
    let session: VaultSession

    var selection: SidebarSelection = .all {
        didSet {
            multiSelection = []
            if selection.sharedVaultId != oldValue.sharedVaultId {
                // What is shown belongs to the vault it came from.
                releases.hideAll(because: .deselected)
                releases.source = source
            }
            refresh()
        }
    }
    var query: String = "" {
        didSet { refresh() }
    }
    var sort: ItemSort = .title {
        didSet { refresh() }
    }
    var selectedItemId: String? {
        // A shown value belongs to the item it was shown for: moving away hides it (ADR-0038
        // user decisions 2 and 5).
        didSet { releases.show(item: selectedItemId) }
    }

    /// Items selected together in the list (⌘-click, ⇧-click, ⌘A). Holds two or more ids, or is
    /// empty: a single selection is `selectedItemId`, so the detail pane, ⌘E and every copy
    /// shortcut keep meaning exactly one item.
    private(set) var multiSelection: Set<String> = []

    /// The list's selection as SwiftUI's multi-select `List` sees it.
    var listSelection: Set<String> {
        get {
            if multiSelection.count > 1 { return multiSelection }
            return selectedItemId.map { [$0] } ?? []
        }
        set {
            if newValue.count > 1 {
                multiSelection = newValue
            } else {
                multiSelection = []
                selectedItemId = newValue.first
            }
        }
    }

    /// The items a bulk "Show to agents" / "Hide from agents" from the list applies to: the
    /// multi-selection, or else the one selected item.
    var bulkTargetIds: [String] {
        if multiSelection.count > 1 { return items.map(\.id).filter(multiSelection.contains) }
        return selectedItemId.map { [$0] } ?? []
    }

    private(set) var items: [ItemView] = []
    private(set) var counts: SidebarCounts
    private(set) var environments: [EnvironmentView] = []
    private(set) var vaultName: String

    /// The audit page the viewer shows, newest first, plus what it needs to say about the chain.
    private(set) var auditRows: [AuditRowView] = []
    private(set) var auditTotal: UInt32 = 0
    private(set) var auditIntact = true

    /// Whether every appended audit entry has actually made it to disk (distinct from
    /// `auditIntact`, which only asks whether what *is* on disk is internally consistent). A
    /// non-zero count here means a save has been failing — the failure mode a hostile
    /// `chflags uchg` on the vault directory or a full disk produces — and a denial's audit entry
    /// could be sitting only in memory.
    private(set) var auditUnsavedEntries: UInt32 = 0
    private(set) var auditSaveError: String?

    /// Surfaced as an alert by the root view. Never carries a secret value.
    var errorMessage: String?

    /// Why writes have stopped, if they have (step 4, user decision 3) — `session.conflict()`,
    /// mirrored here so `RootView`'s conflict alert can bind to it. Kept current by
    /// `syncFromDisk()` and by every mutation that reaches `perform(_:)` or `mutating(_:)`.
    private(set) var conflictKind: VaultConflictKindView?

    /// What "Keep this app's version" would discard, while its confirmation is on screen
    /// (`RootView`'s overwrite alert, `overwriteConfirmationMessage(_:)`). `nil` the rest of the
    /// time; the conflict alert itself only shows while this is `nil`.
    private(set) var overwriteConfirmation: VaultConflictDetailsView?

    /// A one-off note that the conflict resolved itself — the file continues this session again,
    /// so "Keep this app's version" had nothing to overwrite. Not an error, so not
    /// `errorMessage`'s "Something went wrong" alert.
    var conflictNotice: String?

    /// Every value the detail pane shows or copies, each from a presence-gated release
    /// (ADR-0038). The store holds no value of its own.
    let releases: ItemReleases

    /// The shared vaults this Mac belongs to (ADR-0035), open while this store exists.
    let shared: SharedVaultsModel

    /// The shared-vault sheet on screen, if any — presented by `MainView`.
    var sharedSheet: SharedSheet?

    /// Told about every explicit vault mutation — a save, a toggle, an archive, a delete — so
    /// `AutoLockCoordinator` can count it as in-app activity alongside a keystroke or a click in
    /// one of our own windows (docs/investigations/2026-09-27-remote-idle-relock.md). Wired by
    /// `AppModel.adopt(_:)`; a no-op in every test that builds a bare `VaultStore(session:)`. Not
    /// called by `syncFromDisk()` or its timer/`didBecomeActive` callers — a background poll or the
    /// app regaining focus is not evidence that whoever is driving the UI is still there.
    var notifyActivity: () -> Void = {}

    /// `NSApplicationDidBecomeActive` observer for `syncFromDisk()`. Torn down by
    /// `stopSyncMonitor()`, not `deinit`: a `deinit` on a `@MainActor` type cannot touch
    /// actor-isolated state (see `AutoLockCoordinator`'s own note), and this object's lifetime
    /// already exactly matches "the vault is unlocked" — `AppModel.lock(reason:)` stops it right
    /// before dropping the store.
    private var activeObserver: NSObjectProtocol?
    /// Polls `syncFromDisk()` every ~2s while the app is frontmost (design note "App UI ... on a
    /// ~2s timer while the app is frontmost").
    private var syncTimer: Timer?

    init(session: VaultSession) {
        self.session = session
        self.releases = ItemReleases(source: session)
        self.shared = SharedVaultsModel(personal: session)
        self.counts = session.sidebarCounts()
        self.vaultName = session.vaults().first?.name ?? String(localized: "Vault")
        shared.onRemoteChange = { [weak self] id in
            guard let self, self.selection.sharedVaultId == id else { return }
            self.refresh()
        }
        refresh()
    }

    // MARK: - Shared vaults

    /// The shared vault the sidebar selection belongs to, if any.
    var sharedVaultId: String? { selection.sharedVaultId }

    /// Where item calls go: the selected shared vault, or the personal vault.
    var source: any ItemSource {
        if let id = sharedVaultId, let vault = shared.session(for: id) {
            return vault
        }
        return session
    }

    /// Where item writes go. Unlike `source`, never falls back to the personal vault: with a
    /// shared vault selected whose session is not open, a write there would land silently in the
    /// personal vault, so it is refused instead (`VaultStoreError.sharedVaultNotOpen`).
    func writableSource() throws -> any ItemSource {
        guard let id = sharedVaultId else { return session }
        guard let vault = shared.session(for: id) else {
            throw VaultStoreError.sharedVaultNotOpen
        }
        return vault
    }

    /// Whether items can be added and edited where the selection points: always in the personal
    /// vault; in a shared vault, for a writer or an admin.
    var canEditItems: Bool {
        guard let id = sharedVaultId else { return true }
        return shared.canWrite(id)
    }

    /// The window's title: the personal vault's name, or the selected shared vault's.
    var windowTitle: String {
        guard let id = sharedVaultId else { return vaultName }
        return shared.summary(for: id)?.name ?? String(localized: "Shared vault")
    }

    /// After a change in the selected vault: a shared vault re-reads and syncs, then the list.
    private func changed() {
        if let id = sharedVaultId { shared.didChangeLocally(id) }
        refresh()
    }

    // MARK: - Other writers (step 4, user decisions 3 and 4)

    /// Bring the session up to date with the file and refresh what needs it (`VaultSession.sync`).
    /// Called on `didBecomeActive`, on the ~2s frontmost timer, and before the Audit view
    /// refreshes — never on every read, since a read needs no lock and every write already starts
    /// from the file as it is.
    func syncFromDisk() {
        if session.sync() {
            refresh()
        }
        conflictKind = session.conflict()
    }

    /// Start the didBecomeActive/timer sync monitor. Called by `AppModel.adopt(_:)` right after
    /// constructing the store — like `AutoLockCoordinator.start()`, not from `init`, so a test that
    /// builds a bare `VaultStore(session:)` (every existing one does) never leaves a live
    /// `Timer`/`NotificationCenter` observer running past that test.
    func startSyncMonitor() {
        shared.start()
        activeObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncFromDisk() }
        }
        let timer = Timer(timeInterval: 2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, NSApplication.shared.isActive else { return }
                self.syncFromDisk()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        syncTimer = timer
    }

    /// Stop the didBecomeActive/timer monitor. Called by `AppModel.lock(reason:)` before the store
    /// is released, mirroring `AutoLockCoordinator.stop()`.
    func stopSyncMonitor() {
        shared.stop()
        syncTimer?.invalidate()
        syncTimer = nil
        if let activeObserver {
            NotificationCenter.default.removeObserver(activeObserver)
        }
        activeObserver = nil
    }

    /// "Keep this app's version (overwrite the file)" — the conflict alert's other button. Does
    /// not overwrite anything yet: it asks Rust what the file holds that would be lost
    /// (`VaultSession.conflictDetails`) and puts that in front of the person as a confirmation
    /// (`overwriteConfirmation`). Only `confirmKeepAppVersion()` writes.
    func requestKeepAppVersion() {
        do {
            if let details = try session.conflictDetails() {
                overwriteConfirmation = details
            } else {
                // The file continues this session again; nothing is in conflict any more.
                syncFromDisk()
            }
            conflictKind = session.conflict()
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    /// The overwrite confirmation's destructive button: replace the vault file with this app's
    /// version, exactly as described by `overwriteConfirmation` — Rust refuses to act on anything
    /// else, and answers with the file's new details instead, which puts a fresh confirmation on
    /// screen.
    func confirmKeepAppVersion() {
        guard let confirmed = overwriteConfirmation else { return }
        overwriteConfirmation = nil
        do {
            switch try session.keepAppVersionOverConflict(confirmed: confirmed) {
            case .overwritten:
                refresh()
            case .noLongerInConflict:
                refresh()
                conflictNotice =
                    String(localized: "The vault file matches this app's version again, so nothing was overwritten. Changes made elsewhere in the meantime have been loaded.")
            case .fileChangedAgain(let details):
                overwriteConfirmation = details
            }
        } catch {
            errorMessage = Self.message(for: error)
        }
        conflictKind = session.conflict()
    }

    /// The overwrite confirmation's Cancel: back to the conflict alert's two choices.
    func cancelKeepAppVersion() {
        overwriteConfirmation = nil
    }

    var selectedItem: ItemView? {
        guard let selectedItemId else { return nil }
        return items.first { $0.id == selectedItemId } ?? (try? source.item(itemId: selectedItemId))
    }

    /// Called after every `refresh()`, so the AutoFill identity store follows the items
    /// (ADR-0045). The receiver diffs; this does not.
    var onItemsChanged: (() -> Void)?

    func refresh() {
        defer { onItemsChanged?() }
        guard let filter = selection.filter else {
            items = []
            environments = session.environments()
            counts = session.sidebarCounts()
            return
        }
        items = source.listItems(
            filter: filter, query: query.isEmpty ? nil : query, sort: sort)
        counts = session.sidebarCounts()
        environments = session.environments()
        if !multiSelection.isEmpty {
            let shown = Set(items.map(\.id))
            multiSelection.formIntersection(shown)
            if multiSelection.count < 2 {
                if let only = multiSelection.first { selectedItemId = only }
                multiSelection = []
            }
        }
        if let id = selectedItemId, !items.contains(where: { $0.id == id }) {
            selectedItemId = items.first?.id
        }
        if selectedItemId == nil {
            selectedItemId = items.first?.id
        }
    }

    // MARK: - Mutations

    /// Run one throwing session call, recording a conflict (`conflictKind`) if it hits one, then
    /// rethrow so the caller's own `catch` still runs.
    ///
    /// Every mutator below goes through this rather than calling `session` directly, so
    /// `FfiError.Diverged` surfaces in `conflictKind` — and so the conflict alert appears —
    /// whichever button a person happened to press, not only the ones already routed through
    /// `perform(_:)`. It does not swallow anything: `save(draft:)`'s
    /// `FfiError.ItemChangedElsewhere` and every other error still reach the caller unchanged.
    private func mutating<T>(_ body: () throws -> T) throws -> T {
        notifyActivity()
        do {
            return try body()
        } catch {
            if error is FfiError {
                conflictKind = session.conflict()
            }
            throw error
        }
    }

    func createItem(category: String) throws {
        let title = String(localized: "New \(displayName(forCategory: category))")
        let target = try writableSource()
        let item = try mutating { try target.newItem(category: category, title: title) }
        // A new item in a shared vault stays in that vault's list — from its Members or
        // Environments row too, which show no items, so the selection moves to the vault's own row.
        if let id = sharedVaultId {
            if selection != .sharedVault(id) { selection = .sharedVault(id) }
        } else {
            selection = .all
        }
        changed()
        selectedItemId = item.id
    }

    /// # Errors
    ///
    /// `FfiError.ItemChangedElsewhere` if the item was edited elsewhere since the sheet that built
    /// `draft` opened (user decision 4) — the caller should show the "reload" alert and re-read
    /// the item rather than retry the same draft.
    func save(draft: ItemDraft) throws {
        _ = try mutating { try writableSource().saveItem(draft: draft) }
        releases.hideAll(because: .edited)
        changed()
    }

    func toggleFavorite(_ item: ItemView) throws {
        _ = try mutating { try writableSource().setFavorite(itemId: item.id, favorite: !item.favorite) }
        refresh()
    }

    func setArchived(_ item: ItemView, _ archived: Bool) throws {
        _ = try mutating { try writableSource().setArchived(itemId: item.id, archived: archived) }
        changed()
    }

    func setTrashed(_ item: ItemView, _ trashed: Bool) throws {
        _ = try mutating { try writableSource().setTrashed(itemId: item.id, trashed: trashed) }
        changed()
    }

    func deleteForever(_ item: ItemView) throws {
        // `item` is the Trash row the person confirmed: Rust refuses unless the item is still in
        // the Trash and unchanged since that row was drawn (its revision).
        try mutating { try writableSource().deleteItem(itemId: item.id, revision: item.revision) }
        changed()
    }

    func setAgentVisible(_ item: ItemView, _ visible: Bool) throws {
        _ = try mutating { try writableSource().setAgentVisible(itemId: item.id, visible: visible) }
        refresh()
    }

    // MARK: - Bulk agent visibility (ADR-0007 amendment 2026-10-04)

    /// Whether bulk visibility changes are offered where the sidebar points. Personal vault only:
    /// a shared vault's agent visibility is this device's own local state, item by item.
    var canChangeAgentVisibilityInBulk: Bool { sharedVaultId == nil }

    /// Show or hide every item in `scope`, with all its fields, in one transaction with one audit
    /// entry (counts only). Returns what changed.
    @discardableResult
    func setAgentVisible(scope: AgentVisibilityScopeView, _ visible: Bool) throws
        -> BulkVisibilityView
    {
        let result = try mutating { try session.setAgentVisibleBulk(scope: scope, visible: visible) }
        refresh()
        return result
    }

    /// The list's selection (`bulkTargetIds`) shown to agents or hidden.
    @discardableResult
    func setSelectionAgentVisible(_ visible: Bool) throws -> BulkVisibilityView {
        try setAgentVisible(scope: .items(itemIds: bulkTargetIds), visible)
    }

    /// Whether the first logical vault's "Show new items to agents" setting is on.
    var newItemsAgentVisible: Bool {
        session.vaults().first?.newItemsAgentVisible ?? true
    }

    func setNewItemsAgentVisible(_ visible: Bool) {
        guard let id = session.vaults().first?.id else { return }
        perform { _ = try session.setNewItemsAgentVisible(vaultId: id, visible: visible) }
    }

    func setFieldAgentVisible(_ item: ItemView, _ field: FieldView, _ visible: Bool) throws {
        _ = try mutating {
            try writableSource().setFieldAgentVisible(itemId: item.id, fieldId: field.id, visible: visible)
        }
        refresh()
    }

    // MARK: - Reveal and copy

    /// The detail pane's field row that has keyboard focus, if any — what ⌘R acts on.
    var focusedFieldId: String?

    /// ⌘R (ui-spec.md §11): reveal or conceal the focused concealed field — or, with no concealed
    /// field focused, the item's password (`ItemView.passwordField`, the one definition ⇧⌘C and
    /// Quick Access ⏎ use too), or failing that its one-time password, whose code is started or
    /// stopped instead.
    func toggleRevealForShortcut() {
        guard let item = selectedItem else { return }
        notifyActivity()
        let concealed = item.fields.filter { $0.concealed && $0.hasValue }
        guard
            let field = concealed.first(where: { $0.id == focusedFieldId })
                ?? item.passwordField ?? concealed.first(where: { $0.kind == .totp })
        else { return }
        let releases = self.releases
        attemptRelease {
            if field.kind == .totp {
                if releases.isLive(totp: field) {
                    releases.hideTotp(field)
                } else {
                    try await releases.showTotp(item: item, field: field)
                }
            } else {
                try await releases.toggleReveal(item: item, field: field)
            }
        }
    }

    /// ⇧⌘C (ui-spec.md §11): copy the item's password.
    ///
    /// "Password" is `ItemView.passwordField`: the field the vault designates by id as the item's
    /// primary secret (`Item::primary_secret` in the core) — the same field Quick Access ⏎ copies,
    /// ⌘R reveals when nothing is focused, a browser fill writes, and the presence prompt calls
    /// "the password". Not "the field labelled password" and not "the first concealed field":
    /// labels and order can both be changed in the edit sheet without a presence check, so either
    /// rule would let anything driving the UI relabel or reorder a PIN into the slot. Unlike ⌘R,
    /// this ignores keyboard focus on purpose: 1Password 8's ⇧⌘C always copies the password
    /// regardless of what is focused, and "Copy password" is a fixed action.
    ///
    /// A value already shown is copied with no new touch (`ItemReleases.copy`'s existing rule,
    /// ADR-0038 user decision 1); otherwise this takes a one-use `Copy` release through the
    /// presence gate. An item with no password copies nothing — never another secret in its place.
    func copyPasswordForShortcut() {
        guard let item = selectedItem, let field = item.passwordField else { return }
        notifyActivity()
        let releases = self.releases
        attemptRelease {
            try await releases.copy(item: item, field: field)
        }
    }

    /// `attemptRelease`, for a release whose value the caller needs back — the edit sheet's
    /// "Show". `nil` when there is none (cancelled, locked, refused), having reported anything
    /// that is an error.
    func attemptReleaseValue<T>(_ body: @MainActor () async throws -> T?) async -> T? {
        do {
            return try await body()
        } catch FfiError.PresenceCancelled, FfiError.VaultLocked, FfiError.ReleaseEnded {
            return nil
        } catch {
            errorMessage = Self.message(for: error)
            return nil
        }
    }

    /// Run a release — a reveal, a copy, a one-time code, notes — and report what went wrong the
    /// way every other action here does, except for the answers that are not errors: the person
    /// cancelling the prompt, the vault locking under it, or a shown value having already ended.
    /// Each of those leaves the screen exactly as it was, which is the whole of the answer.
    func attemptRelease(_ body: @escaping @MainActor () async throws -> Void) {
        Task { @MainActor in
            do {
                try await body()
            } catch FfiError.PresenceCancelled, FfiError.VaultLocked, FfiError.ReleaseEnded {
                // Not confirmed, locked, or already hidden again: nothing to say.
            } catch {
                errorMessage = Self.message(for: error)
            }
        }
    }

    /// Item ▸ Copy Username (⇧⌥⌘C, ui-spec.md §11): the item's username (`ItemView.username`), a
    /// public value already on the item. With no username field, nothing is copied — never the
    /// subtitle, which may be a website, a hostname or a card's masked digits rather than a
    /// username.
    func copyUsername() {
        guard let username = selectedItem?.username, !username.isEmpty else { return }
        notifyActivity()
        PasteboardService.copy(username, label: "Username")
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

    /// Bind a variable to an item's field instead of a literal (ui-spec.md §10.4, §16.6).
    func bindVariable(_ environment: EnvironmentView, name: String, itemId: String, fieldId: String)
    {
        perform {
            _ = try session.bindVariable(
                environmentId: environment.id, name: name, itemId: itemId, fieldId: fieldId)
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

    /// `syncFromDisk()` first (design note "before the Audit view refreshes"): the log lives in
    /// the vault file, so another process's write — the CLI, the agent, a second app window —
    /// belongs on screen the moment this view is looked at, not just on the next timer tick.
    func refreshAudit(limit: UInt32) {
        syncFromDisk()
        auditRows = session.auditPage(limit: limit, offset: 0)
        auditTotal = session.auditCount()
        auditIntact = session.auditIntact()
        let durability = session.auditDurability()
        auditUnsavedEntries = durability.unsavedEntries
        auditSaveError = durability.lastError
    }

    private func perform(_ body: () throws -> Void) {
        notifyActivity()
        attempt {
            try body()
            refreshEnvironments()
            counts = session.sidebarCounts()
        }
    }

    /// The standard error path for an action a view starts with no error handling of its own —
    /// a toggle, a menu item, a copy button. Never swallows a failure: a conflict raises the
    /// conflict alert (`conflictKind`), anything else — `FfiError.Busy` included — the store's
    /// "Something went wrong" alert (`errorMessage`, `ffiErrorMessage`). Views call this instead
    /// of `try?`, which would make a refused write look like a button that did nothing.
    func attempt(_ body: () throws -> Void) {
        do {
            try body()
        } catch {
            // A conflict gets its own two-choice alert (`conflictKind`, in `RootView`); showing
            // the generic one too would either stack two alerts or silently lose one of them.
            conflictKind = session.conflict()
            if conflictKind == nil {
                errorMessage = Self.message(for: error)
            }
        }
    }

    static func message(for error: Error) -> String {
        describeAnyError(error)
    }
}

/// Errors the store raises itself, before any FFI call.
enum VaultStoreError: LocalizedError, Equatable {
    /// A shared vault is selected but its copy on this Mac is not open.
    case sharedVaultNotOpen

    var errorDescription: String? {
        switch self {
        case .sharedVaultNotOpen:
            String(
                localized:
                    "This shared vault is not open on this Mac, so nothing was saved. Select it again or rebuild it from its folder."
            )
        }
    }
}
