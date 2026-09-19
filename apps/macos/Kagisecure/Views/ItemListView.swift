import SwiftUI

import KagisecureFFI

/// The middle pane (ui-spec.md §3): search, rows with a category icon, title, subtitle and a
/// favourite star, plus hover copy actions.
struct ItemListView: View {
    @Environment(AppModel.self) private var model
    @Bindable var store: VaultStore
    @FocusState private var searchFocused: Bool

    var body: some View {
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
                    title: store.query.isEmpty ? "Nothing here" : "No matches",
                    message: store.query.isEmpty
                        ? nil : "Nothing matches “\(store.query)”.")
            }
        }
        .onChange(of: model.focusSearch) { _, _ in searchFocused = true }
        .onChange(of: store.selectedItemId) { _, _ in store.clearRevealed() }
        .accessibilityIdentifier("ks.itemList.list")
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
                    store.copyItemTotp(item)
                } label: {
                    Image(systemName: "clock.badge.checkmark")
                }
                .buttonStyle(.borderless)
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
                try? store.toggleFavorite(item)
            } label: {
                Image(systemName: item.favorite ? "star.fill" : "star")
                    .foregroundStyle(item.favorite ? AnyShapeStyle(.yellow) : AnyShapeStyle(.tertiary))
            }
            .buttonStyle(.borderless)
            .opacity(item.favorite || hovering ? 1 : 0)
            .help(item.favorite ? "Remove from favorites" : "Add to favorites")
            .accessibilityLabel(item.favorite ? "Favorited" : "Not favorited")
            .accessibilityIdentifier("ks.itemList.rowFavorite")
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        // The item's id, so a test can address one row without depending on its title — which is
        // exactly what the rename scenario changes underneath it.
        .contextMenu {
            Button(item.favorite ? "Remove from Favorites" : "Add to Favorites") {
                try? store.toggleFavorite(item)
            }
            if item.trashed {
                Button("Restore") { try? store.setTrashed(item, false) }
                Divider()
                Button("Delete Permanently", role: .destructive) {
                    try? store.deleteForever(item)
                }
            } else {
                Button(item.archived ? "Move out of Archive" : "Move to Archive") {
                    try? store.setArchived(item, !item.archived)
                }
                Button("Move to Trash") { try? store.setTrashed(item, true) }
            }
        }
    }
}
