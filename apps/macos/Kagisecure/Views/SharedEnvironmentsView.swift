import SwiftUI

import KagisecureFFI

/// A shared vault's Environments (ui-spec.md §16.6), mirroring §10.4's personal-vault editor
/// through `EnvironmentEditor` and `EnvironmentEditing`: create, bind a variable to either a
/// literal value or one of this vault's own items, rename, share with agents (this device's own
/// setting, decision 22), and delete — a reader sees everything here but cannot change it, the
/// same rule §16.6 gives items.
struct SharedEnvironmentsView: View {
    @Bindable var store: VaultStore
    let vaultId: String

    @State private var selected: String?
    @State private var creating = false
    @State private var newName = ""
    @State private var deleting: EnvironmentView?

    private var shared: SharedVaultsModel { store.shared }
    private var vault: SharedVaultSession? { shared.session(for: vaultId) }
    private var environments: [EnvironmentView] { shared.environments[vaultId] ?? [] }
    private var canEdit: Bool { shared.canWrite(vaultId) }

    var body: some View {
        content
            .navigationTitle("Environments")
            .toolbar {
                if canEdit {
                    Button {
                        creating = true
                    } label: {
                        Label("New Environment", systemImage: "plus")
                    }
                    .help("Create an environment")
                    .accessibilityIdentifier("ks.sharedEnvironments.new")
                }
            }
            .sheet(isPresented: $creating) { newEnvironmentSheet }
            .onAppear { shared.refresh() }
            .confirmationDialog(
                "Delete \(deleting?.name ?? String(localized: "this environment")) for everyone?",
                isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) { delete() }
            } message: {
                Text("Removes it, and every variable in it, from every member's copy.")
            }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if environments.isEmpty {
            EmptyStateView(
                symbol: "list.bullet.rectangle",
                title: String(localized: "No environments yet"),
                message:
                    String(localized: "An environment is a named set of variables agents this Mac shares with can ask to have written into a project."),
                action: canEdit ? (String(localized: "New Environment"), { creating = true }) : nil)
            .accessibilityIdentifier("ks.sharedEnvironments.empty")
        } else {
            HSplitView {
                List(selection: $selected) {
                    ForEach(environments, id: \.id) { environment in
                        environmentRow(environment)
                            .tag(environment.id)
                            .contextMenu { rowMenu(environment) }
                    }
                }
                .frame(minWidth: 160, idealWidth: 200)
                .accessibilityIdentifier("ks.sharedEnvironments.list")

                if let id = selected,
                    let environment = environments.first(where: { $0.id == id }),
                    let vault
                {
                    EnvironmentEditor(environment: environment, editing: editing(vault))
                } else {
                    EmptyStateView(
                        symbol: "sidebar.right",
                        title: String(localized: "Select an environment"),
                        message: String(localized: "Its variables, their bindings, and who may see it."))
                }
            }
        }
    }

    private func environmentRow(_ environment: EnvironmentView) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(environment.name)
                .font(.headline)
                .accessibilityIdentifier("ks.sharedEnvironments.row.\(environment.name)")
            HStack(spacing: 6) {
                Image(systemName: environment.agentVisible ? "eye" : "eye.slash")
                    .accessibilityHidden(true)
                if environment.variableNames.isEmpty {
                    Text("No variables")
                } else if environment.variableNames.count == 1 {
                    Text("1 variable")
                } else {
                    Text("\(environment.variableNames.count) variables")
                }
            }
            .font(.caption)
            .foregroundStyle(environment.agentVisible ? .secondary : .tertiary)
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder
    private func rowMenu(_ environment: EnvironmentView) -> some View {
        if canEdit {
            Button("Delete…", role: .destructive) { deleting = environment }
                .accessibilityIdentifier("ks.sharedEnvironments.delete")
        }
    }

    // MARK: - New environment

    private var newEnvironmentSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New environment")
                .font(.title3.weight(.semibold))
            TextField("Name, e.g. acme-api / staging", text: $newName)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("ks.sharedEnvironments.newName")
            Text(
                "New environments are not shared with agents. Turn sharing on once you have put something in it."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") {
                    creating = false
                    newName = ""
                }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("ks.sharedEnvironments.newCancel")
                Button("Create") { create() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("ks.sharedEnvironments.newCreate")
            }
        }
        .padding(24)
        .frame(width: 420)
    }

    // MARK: - Actions

    private func create() {
        guard let vault else { return }
        let name = newName
        creating = false
        newName = ""
        store.attempt {
            let env = try vault.createEnvironment(name: name, description: nil)
            shared.refresh()
            selected = env.id
        }
    }

    private func delete() {
        guard let environment = deleting, let vault else { return }
        deleting = nil
        store.attempt {
            try vault.deleteEnvironment(environmentId: environment.id)
            shared.refresh()
            if selected == environment.id { selected = nil }
        }
    }

    /// Every item in this same shared vault, its fields named for "Add a variable"'s Bind picker
    /// — never another vault's, so a binding cannot reach outside where it was made (module
    /// documentation of `crates/kagisecure-ffi/src/shared.rs`: "references stay inside the
    /// vault").
    private func bindableItems(_ vault: SharedVaultSession) -> [EnvironmentBindableItem] {
        vault
            .listItems(filter: ItemFilter.all, query: nil, sort: ItemSort.title)
            .map { item in
                EnvironmentBindableItem(
                    id: item.id,
                    title: item.title,
                    fields: item.fields.map {
                        EnvironmentBindableItem.Field(id: $0.id, label: $0.label)
                    })
            }
    }

    /// This vault's `EnvironmentEditing`: every mutation goes through `store.attempt` — the
    /// standard error path (a conflict alert never applies to a shared vault, which has none;
    /// anything else raises the store's ordinary alert) — and refreshes `shared` afterwards, the
    /// same as every other shared-vault mutation in this app.
    private func editing(_ vault: SharedVaultSession) -> EnvironmentEditing {
        EnvironmentEditing(
            canEdit: canEdit,
            setShareWithAgents: { env, visible in
                store.attempt {
                    _ = try vault.setEnvironmentAgentVisible(
                        environmentId: env.id, visible: visible)
                    shared.refresh()
                }
            },
            setVariableValue: { env, name, value in
                store.attempt {
                    _ = try vault.setVariableValue(environmentId: env.id, name: name, value: value)
                    shared.didChangeLocally(vaultId)
                }
            },
            bindVariable: { env, name, itemId, fieldId in
                store.attempt {
                    _ = try vault.bindVariable(
                        environmentId: env.id, name: name, itemId: itemId, fieldId: fieldId)
                    shared.didChangeLocally(vaultId)
                }
            },
            removeVariable: { env, name in
                store.attempt {
                    _ = try vault.removeVariable(environmentId: env.id, name: name)
                    shared.didChangeLocally(vaultId)
                }
            },
            rename: { env, name in
                store.attempt {
                    _ = try vault.renameEnvironment(environmentId: env.id, name: name)
                    shared.didChangeLocally(vaultId)
                }
            },
            bindableItems: bindableItems(vault))
    }
}
