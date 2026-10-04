import KagisecureFFI
import SwiftUI

struct ItemListView: View {
    @Bindable var model: AppModel
    @Bindable var store: VaultStore
    @State private var showingAdd = false
    @State private var showingSettings = false
    @State private var editing: ItemEditModel?
    @State private var path = NavigationPath()
    @State private var showingTrash = false

    var body: some View {
        NavigationStack(path: $path) {
            List {
                ForEach(store.visibleSections, id: \.id) { section in
                    Section {
                        ForEach(section.items, id: \.id) { item in
                            NavigationLink(value: item.id) {
                                ItemRow(item: item)
                            }
                            .accessibilityIdentifier("item.\(item.title)")
                            .swipeActions(edge: .leading) {
                                Button {
                                    attempt { try store.toggleFavorite(item) }
                                } label: {
                                    Label(item.favorite ? "Unfavorite" : "Favorite", systemImage: "star")
                                }
                                .tint(.yellow)
                            }
                        }
                    } header: {
                        // One vault alone needs no header.
                        if store.visibleSections.count > 1 { Text(section.name) }
                    }
                }
            }
            .refreshable { if store.link.isLinked { await store.link.sync() } }
            .overlay {
                if store.visibleItems.isEmpty {
                    ContentUnavailableView(
                        store.items.isEmpty ? "No Items" : "No Results",
                        systemImage: "key",
                        description: Text(store.items.isEmpty ? "Tap + to add your first item." : ""))
                }
            }
            .searchable(text: $store.query, prompt: "Title, tag or website")
            .navigationTitle(store.favoritesOnly ? "Favorites" : "Items")
            .navigationDestination(for: String.self) { id in
                ItemDetailView(store: store, itemId: id) { path = NavigationPath() }
            }
            .navigationDestination(isPresented: $showingTrash) { TrashView(store: store) }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showingSettings = true } label: { Image(systemName: "gearshape") }
                        .accessibilityIdentifier("list.settings")
                }
                if store.link.isLinked {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            Task { await store.link.sync() }
                        } label: {
                            if store.link.syncing {
                                ProgressView()
                            } else {
                                Image(systemName: "arrow.triangle.2.circlepath")
                            }
                        }
                        .accessibilityLabel("Sync Now")
                        .accessibilityIdentifier("list.sync")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    filterMenu
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingAdd = true } label: { Image(systemName: "plus") }
                        .accessibilityIdentifier("list.add")
                }
            }
            .sheet(isPresented: $showingAdd) {
                AddItemSheet(store: store) { created in
                    showingAdd = false
                    editing = ItemEditModel(item: created)
                }
            }
            .sheet(item: $editing) { model in
                ItemEditSheet(store: store, model: model) { editing = nil }
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView(model: model, store: store)
            }
            .alert("Error", isPresented: .constant(store.errorMessage != nil)) {
                Button("OK") { store.errorMessage = nil }
            } message: {
                Text(store.errorMessage ?? "")
            }
        }
    }

    private var filterMenu: some View {
        Menu {
            Toggle("Favorites only", isOn: $store.favoritesOnly)
            Picker("Category", selection: $store.categoryFilter) {
                Text("All categories").tag(String?.none)
                ForEach(store.categories, id: \.id) { category in
                    Label(category.displayName, systemImage: category.symbolName)
                        .tag(Optional(category.id))
                }
            }
            Divider()
            Button { showingTrash = true } label: { Label("Trash", systemImage: "trash") }
                .accessibilityIdentifier("list.trash")
        } label: {
            Image(
                systemName: store.favoritesOnly || store.categoryFilter != nil
                    ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
        }
        .accessibilityIdentifier("list.filter")
    }

    private func attempt(_ body: () throws -> Void) {
        do { try body() } catch { store.errorMessage = AppModel.message(for: error) }
    }
}

extension ItemEditModel: Identifiable {
    var id: String { itemId }
}

struct ItemRow: View {
    let item: ItemView
    var body: some View {
        HStack {
            Image(systemName: item.categorySymbol).frame(width: 28).foregroundStyle(.secondary)
            VStack(alignment: .leading) {
                Text(item.title).font(.body)
                if let subtitle = item.subtitle ?? item.username, !subtitle.isEmpty {
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if item.favorite {
                Image(systemName: "star.fill").foregroundStyle(.yellow).font(.caption)
            }
        }
    }
}

struct AddItemSheet: View {
    let store: VaultStore
    let created: (ItemView) -> Void
    @State private var category = "login"
    @State private var title = ""
    @State private var vault: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Picker("Category", selection: $category) {
                    ForEach(store.categories, id: \.id) { info in
                        Label(info.displayName, systemImage: info.symbolName).tag(info.id)
                    }
                }
                TextField("Title", text: $title).accessibilityIdentifier("add.title")
                if store.writableVaults.count > 1 {
                    Picker("Vault", selection: $vault) {
                        ForEach(store.writableVaults, id: \.id) { option in
                            Text(option.name).tag(option.id)
                        }
                    }
                    .accessibilityIdentifier("add.vault")
                }
            }
            .navigationTitle("New Item")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Next") {
                        do {
                            created(try store.create(category: category, title: title, vault: vault))
                        } catch {
                            store.errorMessage = AppModel.message(for: error)
                            dismiss()
                        }
                    }
                    .accessibilityIdentifier("add.next")
                }
            }
            .onAppear {
                vault = store.defaultNewItemVault
                if !store.categories.contains(where: { $0.id == category }),
                    let first = store.categories.first
                {
                    category = first.id
                }
            }
        }
    }
}
