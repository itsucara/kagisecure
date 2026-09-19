import SwiftUI

import KagisecureFFI

/// The sidebar (ui-spec.md §2.2). Sections top to bottom: All Items, Favorites, Categories, Tags,
/// Agent access, Archive, Trash.
///
/// Categories with a zero count stay visible and greyed, which §2.2 asks for explicitly: a user
/// looking for where their SSH keys would go should find the row, not an absence.
struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @Environment(AgentService.self) private var agent
    @Environment(ExtensionService.self) private var ext
    @Bindable var store: VaultStore

    var body: some View {
        List(selection: $store.selection) {
            Section {
                row(.all, "All Items", "tray.full", count: store.counts.all)
                row(.favorites, "Favorites", "star", count: store.counts.favorites)
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

            Section("Agent access") {
                row(
                    .agentEnvironments, "Environments", "list.bullet.rectangle",
                    count: UInt32(store.environments.count))
                row(
                    .agentLeases, "Leases", "clock.badge.checkmark",
                    count: agent.status.activeLeases)
                Label("Audit", systemImage: "list.bullet.rectangle.portrait")
                    .tag(SidebarSelection.agentAudit)
                    .accessibilityIdentifier("ks.sidebar.agentAudit")
                Label("Set up your agent", systemImage: "sparkles")
                    .tag(SidebarSelection.agentSetup)
                    .accessibilityIdentifier("ks.sidebar.agentSetup")
            }

            Section("Browser") {
                row(
                    .browserExtension, "Browser extension", "puzzlepiece.extension",
                    count: ext.status.fillLeases)
            }

            Section {
                row(.archive, "Archive", "archivebox", count: store.counts.archive)
                row(.trash, "Trash", "trash", count: store.counts.trash)
            }
        }
        // Before `.safeAreaInset`, deliberately. An identifier attached after it covers the footer
        // too, and stamps itself over `ks.sidebar.vaultName` and `ks.sidebar.listenerState`.
        .accessibilityIdentifier("ks.sidebar.list")
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) { footer }
    }

    private func row(
        _ selection: SidebarSelection, _ title: String, _ symbol: String, count: UInt32
    ) -> some View {
        Label(title, systemImage: symbol)
            .badge(Int(count))
            .foregroundStyle(count == 0 ? AnyShapeStyle(.secondary) : AnyShapeStyle(.primary))
            .tag(selection)
            .accessibilityLabel("\(title), \(count) items")
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
        case .browserExtension: "ks.sidebar.browserExtension"
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
                    ? "Serving agents on \(agent.status.endpoint)"
                    : "Not serving agents")
            .accessibilityLabel(agent.status.running ? "Serving agents" : "Not serving agents")
            .accessibilityIdentifier("ks.sidebar.listenerState")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
