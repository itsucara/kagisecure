import AppKit
import SwiftUI

import KagisecureFFI

/// The sidebar (ui-spec.md §2.2). Sections top to bottom: All Items, Favorites, Categories, Tags,
/// Shared, Agent access, Browser, Archive, Trash.
///
/// Categories with a zero count stay visible and greyed, which §2.2 asks for explicitly: a user
/// looking for where their SSH keys would go should find the row, not an absence.
struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @Environment(AgentService.self) private var agent
    @Environment(ExtensionService.self) private var ext
    @Bindable var store: VaultStore
    /// The list's keyboard focus, owned by `MainView`, which hands it back after rebuilding the
    /// columns.
    var focus: FocusState<Bool>.Binding
    /// Told about every selection the user makes here, as opposed to one made in code.
    var onPick: (SidebarSelection) -> Void = { _ in }

    var body: some View {
        ScrollViewReader { proxy in
            list
                // `MainView` builds a new sidebar each time the window swaps between its two- and
                // three-column arrangements, and a new list starts scrolled to the top. Without
                // this, picking Audit or Browser extension low in a scrolled sidebar would scroll
                // the row just picked out of sight.
                .onAppear { proxy.scrollTo(store.selection) }
        }
    }

    private var list: some View {
        List(
            selection: Binding(
                get: { store.selection },
                set: { selection in
                    store.selection = selection
                    onPick(selection)
                })
        ) {
            Section {
                row(.all, String(localized: "All Items"), "tray.full", count: store.counts.all)
                row(.favorites, String(localized: "Favorites"), "star", count: store.counts.favorites)
            }

            Section("Categories") {
                ForEach(store.counts.categories, id: \.name) { entry in
                    row(
                        .category(entry.name),
                        store.displayName(forCategory: entry.name),
                        symbol(forCategory: entry.name),
                        count: entry.count)
                }
            }

            if !store.counts.tags.isEmpty {
                Section("Tags") {
                    ForEach(store.counts.tags, id: \.name) { entry in
                        row(.tag(entry.name), entry.name, "number", count: entry.count)
                    }
                }
            }

            sharedSection

            Section("Agent access") {
                row(
                    .agentEnvironments, String(localized: "Environments"), "list.bullet.rectangle",
                    count: UInt32(store.environments.count))
                row(
                    .agentLeases, String(localized: "Leases"), "clock.badge.checkmark",
                    count: agent.status.activeLeases)
                Label("Unattended jobs", systemImage: "clock.badge.checkmark")
                    .tag(SidebarSelection.agentUnattended)
                    .id(SidebarSelection.agentUnattended)
                    .accessibilityIdentifier("ks.sidebar.agentUnattended")
                Label("Audit", systemImage: "list.bullet.rectangle.portrait")
                    .tag(SidebarSelection.agentAudit)
                    .id(SidebarSelection.agentAudit)
                    .accessibilityIdentifier("ks.sidebar.agentAudit")
                Label("Set up your agent", systemImage: "sparkles")
                    .tag(SidebarSelection.agentSetup)
                    .id(SidebarSelection.agentSetup)
                    .accessibilityIdentifier("ks.sidebar.agentSetup")
            }

            Section("Browser") {
                row(
                    .browserExtension, String(localized: "Browser extension"), "puzzlepiece.extension",
                    count: ext.status.fillLeases)
            }

            Section {
                row(.archive, String(localized: "Archive"), "archivebox", count: store.counts.archive)
                row(.trash, String(localized: "Trash"), "trash", count: store.counts.trash)
            }
        }
        // Before `.safeAreaInset`, deliberately. An identifier attached after it covers the footer
        // too, and stamps itself over `ks.sidebar.vaultName` and `ks.sidebar.listenerState`.
        .accessibilityIdentifier("ks.sidebar.list")
        .listStyle(.sidebar)
        .focused(focus)
        .safeAreaInset(edge: .bottom) { footer }
    }

    /// Shared vaults (ui-spec.md §16.1): one row per vault — its items — with its Environments and
    /// Members under it, and a "+" menu to create or join one.
    private var sharedSection: some View {
        Section {
            ForEach(store.shared.summaries, id: \.id) { vault in
                row(
                    .sharedVault(vault.id), vault.name,
                    vault.problem == nil ? "person.2" : "exclamationmark.triangle",
                    count: vault.itemCount)
                    .contextMenu { sharedMenu(vault) }
                Label("Environments", systemImage: "list.bullet.rectangle")
                    .badge(store.shared.environments[vault.id]?.count ?? 0)
                    .padding(.leading, 14)
                    .tag(SidebarSelection.sharedEnvironments(vault.id))
                    .id(SidebarSelection.sharedEnvironments(vault.id))
                    .accessibilityLabel(
                        "\(vault.name) environments, \(store.shared.environments[vault.id]?.count ?? 0)"
                    )
                    .accessibilityIdentifier(Self.identifier(for: .sharedEnvironments(vault.id)))
                Label("Members", systemImage: "person.crop.circle")
                    .badge(Int(vault.memberCount))
                    .padding(.leading, 14)
                    .tag(SidebarSelection.sharedMembers(vault.id))
                    .id(SidebarSelection.sharedMembers(vault.id))
                    .accessibilityLabel("\(vault.name) members, \(Int(vault.memberCount))")
                    .accessibilityIdentifier(Self.identifier(for: .sharedMembers(vault.id)))
            }
        } header: {
            HStack {
                Text("Shared")
                Spacer()
                Menu {
                    Button("New Shared Vault…") { store.sharedSheet = .create }
                        .accessibilityIdentifier("ks.sidebar.shared.new")
                    Button("Join Shared Vault…") { store.sharedSheet = .join }
                        .accessibilityIdentifier("ks.sidebar.shared.join")
                } label: {
                    Image(systemName: "plus")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Create or join a shared vault")
                .accessibilityLabel("Add a shared vault")
                .accessibilityIdentifier("ks.sidebar.shared.add")
            }
        }
    }

    @ViewBuilder
    private func sharedMenu(_ vault: SharedVaultSummary) -> some View {
        if vault.myRole == .admin {
            Button("Invite…") { store.sharedSheet = .invite(vaultId: vault.id) }
        }
        Button("Members") { store.selection = .sharedMembers(vault.id) }
        if vault.folder != nil {
            Button("Sync Now") { store.shared.sync(vault.id) }
        }
        if let folder = vault.folder {
            Button("Show Folder in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: folder)])
            }
        }
    }

    private func row(
        _ selection: SidebarSelection, _ title: String, _ symbol: String, count: UInt32
    ) -> some View {
        Label(title, systemImage: symbol)
            .badge(Int(count))
            .foregroundStyle(count == 0 ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
            .tag(selection)
            .id(selection)
            .accessibilityLabel("\(title), \(Int(count)) items")
            .accessibilityIdentifier(Self.identifier(for: selection))
    }

    /// The `ks.sidebar.*` identifier for a row.
    ///
    /// Derived from the selection rather than passed in beside the title, because the selection is
    /// the thing that is actually stable: a category's display name and a tag's text are user- and
    /// locale-facing, and the identifier a test types must not move when either does. Categories
    /// and tags carry their own id, which is the vault's own lower-case name for them.
    static func identifier(for selection: SidebarSelection) -> String {
        switch selection {
        case .all: "ks.sidebar.all"
        case .favorites: "ks.sidebar.favorites"
        case .category(let name): "ks.sidebar.category.\(name)"
        case .tag(let name): "ks.sidebar.tag.\(name)"
        case .archive: "ks.sidebar.archive"
        case .trash: "ks.sidebar.trash"
        case .agentEnvironments: "ks.sidebar.agentEnvironments"
        case .agentLeases: "ks.sidebar.agentLeases"
        case .agentAudit: "ks.sidebar.agentAudit"
        case .agentSetup: "ks.sidebar.agentSetup"
        case .agentUnattended: "ks.sidebar.agentUnattended"
        case .browserExtension: "ks.sidebar.browserExtension"
        case .sharedVault(let id): "ks.sidebar.shared.\(id)"
        case .sharedMembers(let id): "ks.sidebar.sharedMembers.\(id)"
        case .sharedEnvironments(let id): "ks.sidebar.sharedEnvironments.\(id)"
        }
    }

    private func symbol(forCategory id: String) -> String {
        model.categories.first { $0.id == id }?.symbolName ?? "questionmark.square.dashed"
    }

    private var footer: some View {
        HStack(spacing: 6) {
            Image(systemName: "lock.open.fill")
                .foregroundStyle(.green)
                .accessibilityHidden(true)
            Text(store.vaultName)
                .font(.callout)
                .accessibilityIdentifier("ks.sidebar.vaultName")
            Spacer()
            Image(
                systemName: agent.status.running
                    ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash"
            )
            .foregroundStyle(agent.status.running ? AnyShapeStyle(.green) : AnyShapeStyle(.tertiary))
            .help(
                agent.status.running
                    ? String(localized: "Serving agents on \(agent.status.endpoint)")
                    : String(localized: "Not serving agents"))
            .accessibilityLabel(agent.status.running ? Text("Serving agents") : Text("Not serving agents"))
            .accessibilityIdentifier("ks.sidebar.listenerState")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
