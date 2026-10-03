import SwiftUI

import KagisecureFFI

/// The middle pane (ui-spec.md §3): search, rows with a category icon, title, subtitle and a
/// favourite star, plus hover copy actions.
struct ItemListView: View {
    @Environment(AppModel.self) private var model
    @Bindable var store: VaultStore
    /// ⌘F pressed in an agent section, where this list is not on screen: `MainView` comes back to
    /// a vault section and this list focuses its search as soon as it appears.
    @Binding var searchRequested: Bool
    @FocusState private var searchFocused: Bool

    var body: some View {
        ScrollViewReader { proxy in
            list
                // This list is rebuilt when the window comes back from an agent section
                // (`MainView`) and starts scrolled to the top; the selected item is kept, so show
                // it.
                .onAppear {
                    if let id = store.selectedItemId { proxy.scrollTo(id) }
                    if searchRequested {
                        searchRequested = false
                        focusSearch()
                    }
                }
        }
    }

    private var list: some View {
        List(store.items, id: \.id, selection: $store.selectedItemId) { item in
            ItemRow(store: store, item: item)
                .tag(item.id)
        }
        .searchable(
            text: $store.query, placement: .toolbar, prompt: "Search titles, tags and URLs"
        )
        .searchFocused($searchFocused)
        .overlay {
            if store.items.isEmpty {
                EmptyStateView(
                    symbol: store.query.isEmpty ? "tray" : "magnifyingglass",
                    title: store.query.isEmpty
                        ? String(localized: "Nothing here") : String(localized: "No matches"),
                    message: store.query.isEmpty
                        ? nil : String(localized: "Nothing matches “\(store.query)”."))
            }
        }
        .onChange(of: model.focusSearch) { _, _ in searchFocused = true }
        .accessibilityIdentifier("ks.itemList.list")
    }

    /// Focus the search field of a list that has only just appeared: once now, and again once the
    /// toolbar holding the field is actually in the window, because a request made before then is
    /// dropped (QuickAccessView does the same for its panel).
    private func focusSearch() {
        searchFocused = true
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(60))
            searchFocused = true
        }
    }
}

private struct ItemRow: View {
    @Bindable var store: VaultStore
    let item: ItemView
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: item.categorySymbol)
                .frame(width: 18)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(item.title)
                    .lineLimit(1)
                    .accessibilityIdentifier("ks.itemList.rowTitle")
                if let subtitle = item.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .accessibilityIdentifier("ks.itemList.rowSubtitle")
                }
            }

            Spacer(minLength: 4)

            if hovering, item.fields.contains(where: { $0.kind == .totp && $0.hasValue }) {
                Button {
                    // A one-use copy release behind its own presence prompt — or, if this item's
                    // code is already running in the detail pane, a copy of that with no new
                    // touch (ADR-0038 user decision 1).
                    let releases = store.releases
                    store.attemptRelease { try await releases.copyFirstTotp(of: item) }
                } label: {
                    Image(systemName: "clock.badge.checkmark")
                }
                .buttonStyle(.borderless)
                .disabled(store.releases.pending != nil)
                .help("Copy the current one-time password")
                .accessibilityLabel("Copy one-time password")
                .accessibilityIdentifier("ks.itemList.rowCopyTotp")
            }

            if hovering, let subtitle = item.subtitle, !subtitle.isEmpty {
                Button {
                    PasteboardService.copy(subtitle, label: "Username")
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy \(subtitle)")
                .accessibilityIdentifier("ks.itemList.rowCopySubtitle")
            }

            Button {
                store.attempt { try store.toggleFavorite(item) }
            } label: {
                Image(systemName: item.favorite ? "star.fill" : "star")
                    .foregroundStyle(item.favorite ? AnyShapeStyle(.yellow) : AnyShapeStyle(.tertiary))
            }
            .buttonStyle(.borderless)
            .opacity(item.favorite || hovering ? 1 : 0)
            .help(item.favorite ? Text("Remove from favorites") : Text("Add to favorites"))
            .accessibilityLabel(item.favorite ? Text("Favorited") : Text("Not favorited"))
            .accessibilityIdentifier("ks.itemList.rowFavorite")
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        // The item's id, so a test can address one row without depending on its title — which is
        // exactly what the rename scenario changes underneath it.
        .contextMenu {
            Button(
                item.favorite
                    ? String(localized: "Remove from Favorites") : String(localized: "Add to Favorites")
            ) {
                store.attempt { try store.toggleFavorite(item) }
            }
            if store.sharedVaultId != nil {
                // Deleting a shared item is confirmed in the detail pane, where the item is.
            } else if item.trashed {
                Button("Restore") { store.attempt { try store.setTrashed(item, false) } }
                Divider()
                Button("Delete Permanently", role: .destructive) {
                    store.attempt { try store.deleteForever(item) }
                }
            } else {
                Button(
                    item.archived
                        ? String(localized: "Move out of Archive") : String(localized: "Move to Archive")
                ) {
                    store.attempt { try store.setArchived(item, !item.archived) }
                }
                Button("Move to Trash") { store.attempt { try store.setTrashed(item, true) } }
            }
        }
    }
}
