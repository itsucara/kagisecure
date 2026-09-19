import SwiftUI

import KagisecureFFI

/// The three-pane window (ui-spec.md §2.1): sidebar, item list, item detail.
struct MainView: View {
    @Environment(AppModel.self) private var model
    @Bindable var store: VaultStore

    @State private var columnVisibility: NavigationSplitViewVisibility = .all

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            SidebarView(store: store)
                .navigationSplitViewColumnWidth(min: 220, ideal: 240, max: 280)
        } content: {
            ItemListView(store: store)
                .navigationSplitViewColumnWidth(min: 300, ideal: 340, max: 420)
        } detail: {
            detail
        }
        .navigationTitle(store.vaultName)
        .navigationSubtitle(statusLine)
        .toolbar { toolbar }
        // An import writes straight through the session, so the list and the sidebar counts are
        // stale the moment it finishes. Re-asking Rust is the same thing every other mutation
        // does; the store never patches a local copy (import.md §8).
        .onChange(of: model.importCommitCount) { _, _ in
            store.refresh()
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch store.selection {
        case .agentEnvironments:
            AgentAccessView(store: store)
        case .agentLeases:
            LeasesView()
        case .agentAudit:
            AuditView(store: store)
        case .agentSetup:
            AgentSetupView()
        case .browserExtension:
            BrowserExtensionView()
        default:
            itemDetail
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
        let items = store.counts.all
        return "\(items) item\(items == 1 ? "" : "s")"
    }

    private var emptyTitle: String {
        switch store.selection {
        case .trash: "Trash is empty"
        case .archive: "Nothing archived"
        case .favorites: "No favorites yet"
        case .category(let name): "No \(store.displayName(forCategory: name)) items yet"
        default: store.query.isEmpty ? "No items yet" : "No items match “\(store.query)”"
        }
    }

    private var emptyMessage: String {
        store.query.isEmpty
            ? "Select an item on the left, or create one with ⌘N."
            : "Clear the search field to see everything again."
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
