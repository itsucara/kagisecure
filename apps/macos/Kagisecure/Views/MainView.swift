import SwiftUI

import KagisecureFFI

/// The main window (ui-spec.md §2.1): sidebar, item list and item detail for the vault's own
/// sections and each shared vault; sidebar and a full-width pane for the agent ones and a shared
/// vault's members.
///
/// Two `NavigationSplitView`s rather than one, swapped on `SidebarSelection.showsItems`. The
/// item list means nothing beside Environments, Leases, Audit, Set up your agent, Browser
/// extension or a shared vault's Members, and a three-column split has no way to hide its middle column while keeping the
/// sidebar — `.doubleColumn` there hides the *sidebar*. The swap rebuilds the columns, so what a
/// person would notice losing is carried across it by hand: whether the sidebar is collapsed
/// (`sidebarHidden`), how wide they left each column (`widths`), and the keyboard focus when they
/// crossed the boundary from the sidebar itself (`sidebarPick`). The item selection needs nothing:
/// it lives in `VaultStore`, and an agent section leaves it alone.
struct MainView: View {
    @Environment(AppModel.self) private var model
    @Bindable var store: VaultStore

    /// Whether the user collapsed the sidebar. One flag rather than a
    /// `NavigationSplitViewVisibility`, because the two arrangements spell "sidebar hidden"
    /// differently — `.doubleColumn` with three columns, `.detailOnly` with two — and the choice
    /// has to survive the swap.
    @State private var sidebarHidden = false
    @State private var widths = ColumnWidths()
    @FocusState private var sidebarFocused: Bool
    /// The row the user last picked in the sidebar, by click or arrow key. When that pick is what
    /// swapped the arrangement, the rebuilt sidebar takes the keyboard back, so walking the sidebar
    /// with the arrow keys carries on across the boundary instead of stopping at it. A selection
    /// made anywhere else (⌘F, a new item, the menu bar's agent-fill notices) does not match it
    /// and leaves the focus to whatever asked.
    @State private var sidebarPick: SidebarSelection?
    /// The vault section ⌘F goes back to from an agent section, which has no search field.
    @State private var lastVaultSelection: SidebarSelection = .all
    @State private var searchRequested = false

    var body: some View {
        Group {
            if !store.selection.showsItems {
                NavigationSplitView(columnVisibility: visibility(threeColumns: false)) {
                    sidebar
                } detail: {
                    agentPane
                }
            } else {
                NavigationSplitView(columnVisibility: visibility(threeColumns: true)) {
                    sidebar
                } content: {
                    ItemListView(store: store, searchRequested: $searchRequested)
                        .navigationSplitViewColumnWidth(
                            min: ColumnWidths.itemListRange.lowerBound, ideal: widths.itemList,
                            max: ColumnWidths.itemListRange.upperBound)
                        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: {
                            widths.noteItemList($0)
                        }
                } detail: {
                    itemDetail
                }
            }
        }
        .navigationTitle(store.windowTitle)
        .navigationSubtitle(statusLine)
        .toolbar { toolbar }
        // An import writes straight through the session, so the list and the sidebar counts are
        // stale the moment it finishes. Re-asking Rust is the same thing every other mutation
        // does; the store never patches a local copy (import.md §8).
        .onChange(of: model.importCommitCount) { _, _ in
            store.refresh()
        }
        .onChange(of: store.selection, initial: true) { _, selection in
            if selection.showsItems { lastVaultSelection = selection }
        }
        // The search field belongs to the item list, which an agent section does not show. ⌘F
        // there goes back to the vault section the user came from and focuses its search, rather
        // than doing nothing; `ItemListView` picks the request up when it appears.
        .sheet(item: $store.sharedSheet) { sheet in
            SharedSheetView(store: store, sheet: sheet)
        }
        .onChange(of: model.focusSearch) { _, _ in
            guard !store.selection.showsItems else { return }
            searchRequested = true
            store.selection = lastVaultSelection
        }
    }

    private var sidebar: some View {
        SidebarView(store: store, focus: $sidebarFocused) { sidebarPick = $0 }
            .navigationSplitViewColumnWidth(
                min: ColumnWidths.sidebarRange.lowerBound, ideal: widths.sidebar,
                max: ColumnWidths.sidebarRange.upperBound)
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: {
                widths.noteSidebar($0)
            }
            .onAppear {
                let picked = sidebarPick == store.selection
                sidebarPick = nil
                guard picked else { return }
                sidebarFocused = true
                // …and again once the rebuilt list is actually in the window: a focus request made
                // before then is dropped, and the arrow keys go nowhere (QuickAccessView does the
                // same for its panel).
                Task { @MainActor in
                    try? await Task.sleep(for: .milliseconds(60))
                    sidebarFocused = true
                }
            }
    }

    /// The split view's visibility, as the arrangement being built spells `sidebarHidden`.
    ///
    /// Any collapsed state reads back as hidden: `.detailOnly` in either arrangement, and
    /// `.doubleColumn` in the three-column one, where it is what the sidebar button produces.
    private func visibility(threeColumns: Bool) -> Binding<NavigationSplitViewVisibility> {
        Binding(
            get: {
                guard sidebarHidden else { return .all }
                return threeColumns ? .doubleColumn : .detailOnly
            },
            set: { visibility in
                sidebarHidden =
                    visibility == .detailOnly || (threeColumns && visibility == .doubleColumn)
            })
    }

    @ViewBuilder
    private var agentPane: some View {
        switch store.selection {
        case .agentEnvironments:
            AgentAccessView(store: store)
        case .agentLeases:
            LeasesView()
        case .agentAudit:
            AuditView(store: store)
        case .agentSetup:
            AgentSetupView()
        case .agentUnattended:
            UnattendedView(store: store)
        case .browserExtension:
            BrowserExtensionView()
        case .sharedMembers(let id):
            SharedMembersView(store: store, vaultId: id)
        case .sharedEnvironments(let id):
            SharedEnvironmentsView(store: store, vaultId: id)
        case .all, .favorites, .category, .tag, .archive, .trash, .sharedVault:
            // Not reached: `body` only builds this pane when the selection shows no items.
            EmptyView()
        }
    }

    @ViewBuilder
    private var itemDetail: some View {
        if let item = store.selectedItem {
            ItemDetailView(store: store, item: item)
                .id(item.id)
        } else {
            EmptyStateView(
                symbol: "sidebar.squares.left",
                title: emptyTitle,
                message: emptyMessage)
        }
    }

    private var statusLine: String {
        if let id = store.sharedVaultId {
            let summary = store.shared.summary(for: id)
            let items = summary?.itemCount ?? 0
            let members = summary?.memberCount ?? 0
            let itemsText = Self.itemCountText(items)
            let membersText =
                members == 1 ? String(localized: "1 member") : String(localized: "\(members) members")
            return String(localized: "Shared · \(itemsText) · \(membersText)")
        }
        return Self.itemCountText(store.counts.all)
    }

    private static func itemCountText(_ items: UInt32) -> String {
        items == 1 ? String(localized: "1 item") : String(localized: "\(items) items")
    }

    private var emptyTitle: String {
        switch store.selection {
        case .trash: String(localized: "Trash is empty")
        case .archive: String(localized: "Nothing archived")
        case .favorites: String(localized: "No favorites yet")
        case .category(let name): String(localized: "No \(store.displayName(forCategory: name)) items yet")
        case .sharedVault where store.query.isEmpty: String(localized: "No shared items yet")
        default:
            store.query.isEmpty
                ? String(localized: "No items yet") : String(localized: "No items match “\(store.query)”")
        }
    }

    private var emptyMessage: String {
        if store.sharedVaultId != nil, store.query.isEmpty {
            return store.canEditItems
                ? String(localized: "Create one with ⌘N: everyone in this vault gets it.")
                : String(localized: "Items others add appear here.")
        }
        return store.query.isEmpty
            ? String(localized: "Select an item on the left, or create one with ⌘N.")
            : String(localized: "Clear the search field to see everything again.")
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            Button {
                model.lock(reason: .manual)
            } label: {
                Label("Lock Now", systemImage: "lock.open.fill")
            }
            .help("Lock the vault now (⌘\\)")
            .accessibilityIdentifier("ks.toolbar.lock")
        }
        ToolbarItem {
            Menu {
                ForEach(model.categories, id: \.id) { category in
                    Button {
                        model.newItem(category: category.id)
                    } label: {
                        Label(category.displayName, systemImage: category.symbolName)
                    }
                    .accessibilityIdentifier("ks.toolbar.newItem.\(category.id)")
                }
                Divider()
                Button {
                    model.openGenerator()
                } label: {
                    Label("Password Generator…", systemImage: "die.face.5")
                }
                .accessibilityIdentifier("ks.toolbar.generator")
            } label: {
                Label("New Item", systemImage: "plus")
            }
            .help("New item (⌘N)")
            .accessibilityIdentifier("ks.toolbar.newItem")
        }
        ToolbarItem {
            Button {
                model.toggleQuickAccess()
            } label: {
                Label("Quick Access", systemImage: "bolt.horizontal")
            }
            .help("Quick Access (⇧⌘Space) — a floating search that works from any app")
            .accessibilityIdentifier("ks.toolbar.quickAccess")
        }
        ToolbarItem {
            Menu {
                Picker("Sort by", selection: $store.sort) {
                    Text("Title").tag(ItemSort.title)
                    Text("Date modified").tag(ItemSort.dateModified)
                    Text("Date created").tag(ItemSort.dateCreated)
                    Text("Category").tag(ItemSort.category)
                }
                .pickerStyle(.inline)
                .accessibilityIdentifier("ks.toolbar.sortPicker")
            } label: {
                Label("Sort", systemImage: "arrow.up.arrow.down")
            }
            .accessibilityIdentifier("ks.toolbar.sort")
        }
    }
}

/// Each column's width as last laid out, so a swap between the two arrangements rebuilds the
/// sidebar and the item list at the width the user left them rather than at the default.
///
/// A plain reference held in `@State`, not observed state: recording a width must not re-render
/// the window, or a divider being dragged would feed its own width back into `ideal` mid-drag. The
/// value is only read when the columns are built again. A width outside the column's range is a
/// collapsed or collapsing sidebar, not a choice, and is not recorded.
private final class ColumnWidths {
    static let sidebarRange: ClosedRange<CGFloat> = 220...280
    static let itemListRange: ClosedRange<CGFloat> = 300...420

    private(set) var sidebar: CGFloat = 240
    private(set) var itemList: CGFloat = 340

    func noteSidebar(_ width: CGFloat) {
        if Self.sidebarRange.contains(width) { sidebar = width }
    }

    func noteItemList(_ width: CGFloat) {
        if Self.itemListRange.contains(width) { itemList = width }
    }
}

/// The shared "nothing here" panel (ui-spec.md §12).
struct EmptyStateView: View {
    let symbol: String
    let title: String
    var message: String?
    var action: (label: String, run: () -> Void)?

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
            Text(title)
                .font(.title3.weight(.medium))
                .accessibilityIdentifier("ks.emptyState.title")
            if let message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 320)
                    .accessibilityIdentifier("ks.emptyState.message")
            }
            if let action {
                Button(action.label, action: action.run)
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("ks.emptyState.action")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // One identifier for every empty state in the app. There is at most one on screen at a
        // time — they are what a pane shows *instead of* its content — and the title is what tells
        // a test which one it is looking at.
    }
}
