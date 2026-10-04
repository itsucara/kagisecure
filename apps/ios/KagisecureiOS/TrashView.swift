import KagisecureFFI
import SwiftUI

/// The personal vault's Trash (macOS sidebar → Trash): restore an item, or delete it for good
/// after a confirmation. Shared items never come here — they are deleted for everyone.
struct TrashView: View {
    let store: VaultStore
    @State private var items: [ItemView] = []
    @State private var pendingDelete: ItemView?
    @State private var confirmingEmpty = false
    @State private var message: String?

    var body: some View {
        List {
            ForEach(items, id: \.id) { item in
                ItemRow(item: item)
                    .accessibilityIdentifier("trash.\(item.title)")
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            pendingDelete = item
                        } label: {
                            Label("Delete Permanently", systemImage: "trash")
                        }
                        Button {
                            attempt { try store.restore(item) }
                        } label: {
                            Label("Restore", systemImage: "arrow.uturn.backward")
                        }
                        .tint(.blue)
                    }
                    .contextMenu {
                        Button {
                            attempt { try store.restore(item) }
                        } label: {
                            Label("Restore", systemImage: "arrow.uturn.backward")
                        }
                        .accessibilityIdentifier("trash.restore")
                        Button(role: .destructive) {
                            pendingDelete = item
                        } label: {
                            Label("Delete Permanently…", systemImage: "trash")
                        }
                    }
            }
        }
        .overlay {
            if items.isEmpty {
                ContentUnavailableView("Trash is empty", systemImage: "trash")
            }
        }
        .navigationTitle("Trash")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Empty Trash", role: .destructive) { confirmingEmpty = true }
                    .disabled(items.isEmpty)
                    .accessibilityIdentifier("trash.empty")
            }
        }
        .confirmationDialog(
            pendingDelete.map { Text("Permanently delete “\($0.title)”?") } ?? Text(verbatim: ""),
            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
            titleVisibility: .visible,
            presenting: pendingDelete
        ) { item in
            Button("Delete Permanently", role: .destructive) {
                attempt { try store.deletePermanently(item) }
            }
            .accessibilityIdentifier("trash.confirmDelete")
        } message: { _ in
            Text("This cannot be undone.")
        }
        .confirmationDialog(
            "Permanently delete all items in the Trash?", isPresented: $confirmingEmpty,
            titleVisibility: .visible
        ) {
            Button("Empty Trash", role: .destructive) { attempt { try store.emptyTrash() } }
        } message: {
            Text("This cannot be undone.")
        }
        .alert("Error", isPresented: .constant(message != nil)) {
            Button("OK") { message = nil }
        } message: { Text(message ?? "") }
        .onAppear(perform: reload)
    }

    private func reload() { items = store.trashedItems }

    private func attempt(_ body: () throws -> Void) {
        do { try body() } catch { message = AppModel.message(for: error) }
        reload()
    }
}
