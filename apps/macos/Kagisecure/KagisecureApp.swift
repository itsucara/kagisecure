import AppKit
import SwiftUI

/// The app.
///
/// One window, one `Settings` scene, and the keyboard-shortcut table from ui-spec.md §11.
/// Everything below the root view is driven by `AppModel`, which owns the lock state; the app
/// itself owns nothing but the scenes.
@main
struct KagisecureApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        Window("Kagisecure", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 1_040, minHeight: 620)
        }
        .windowToolbarStyle(.unified)
        .commands { KagisecureCommands(model: model) }

        Settings {
            SettingsView()
                .environment(model)
        }

        // The menu-bar status item (ui-spec.md §6.3). Minimal on purpose: lock state, Quick
        // Access, how many agents are waiting on you, how much is granted right now, and one
        // button to take it all away.
        MenuBarExtra {
            MenuBarPanel()
                .environment(model)
                .environment(model.agent)
                .environment(model.browserExtension)
        } label: {
            Image(systemName: menuBarSymbol)
                // The lock state is what this icon *is*, and a symbol name is not something a
                // test should be matching on — so the state is said out loud here, and the
                // identifier stays constant across all three symbols.
                .accessibilityLabel(menuBarLabel)
                .accessibilityIdentifier("ks.menuBar.icon")
        }
    }

    /// A locked padlock, an open one, or an open one with a badge when something is waiting.
    private var menuBarSymbol: String {
        guard model.store != nil else { return "lock.fill" }
        return model.agent.status.pendingApprovals > 0 ? "lock.open.trianglebadge.exclamationmark" : "lock.open.fill"
    }

    /// The same three states, in words, for VoiceOver and for the UI-test suite.
    private var menuBarLabel: String {
        guard model.store != nil else { return "Kagisecure, vault locked" }
        let pending = model.agent.status.pendingApprovals
        return pending > 0
            ? "Kagisecure, vault unlocked, \(pending) approval(s) waiting"
            : "Kagisecure, vault unlocked"
    }
}

/// What the menu-bar icon drops down.
struct MenuBarPanel: View {
    @Environment(AppModel.self) private var model
    @Environment(AgentService.self) private var agent
    @Environment(ExtensionService.self) private var ext

    var body: some View {
        if model.store == nil {
            Text("Vault locked")
                .accessibilityIdentifier("ks.menuBar.lockState")
            Button("Open Kagisecure") { NSApp.activate(ignoringOtherApps: true) }
                .accessibilityIdentifier("ks.menuBar.openMainWindow")
        } else {
            Text("Vault unlocked")
                .accessibilityIdentifier("ks.menuBar.lockState")
            Button("Quick Access") { model.toggleQuickAccess() }
                .keyboardShortcut(.space, modifiers: [.command, .shift])
                .accessibilityIdentifier("ks.menuBar.quickAccess")
            Divider()
            if agent.status.pendingApprovals > 0 {
                Button("\(agent.status.pendingApprovals) approval(s) waiting — answer now") {
                    NSApp.activate(ignoringOtherApps: true)
                }
                .accessibilityIdentifier("ks.menuBar.pendingApprovals")
            }
            Text(
                agent.status.running
                    ? "Serving agents · \(agent.status.activeLeases) active lease(s)"
                    : "Not serving agents"
            )
            .accessibilityIdentifier("ks.menuBar.agentState")
            Text(
                ext.status.running
                    ? "Serving browsers · \(ext.status.fillLeases) fill lease(s)"
                    : "Not serving browsers"
            )
            .accessibilityIdentifier("ks.menuBar.browserState")
            Divider()
            Button("Revoke All Leases") { agent.revokeAll(); ext.revokeAll() }
                .disabled(agent.status.activeLeases == 0 && ext.status.fillLeases == 0)
                .accessibilityIdentifier("ks.menuBar.revokeAll")
            Button("Lock Vault Now") { model.lock(reason: .manual) }
                .accessibilityIdentifier("ks.menuBar.lockNow")
            Divider()
            Button("Quit Kagisecure") { NSApp.terminate(nil) }
                .accessibilityIdentifier("ks.menuBar.quit")
        }
    }
}

/// The menu bar. Shortcuts follow ui-spec.md §11; the ones whose features are later milestones
/// are present and disabled, so the menu tells the truth about what exists rather than hiding it.
struct KagisecureCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Menu("New Item") {
                ForEach(model.categories, id: \.id) { category in
                    Button(category.displayName) { model.newItem(category: category.id) }
                }
            }
            .disabled(model.store == nil)
            .keyboardShortcut("n", modifiers: .command)
        }

        // File ▸ Import… (import.md §8, ui-spec.md §11). `replacing: .importExport` puts it in
        // the File menu where every Mac app keeps it, and replaces SwiftUI's empty default group
        // rather than adding a second one. Disabled while locked: importing writes into a vault,
        // and there is no vault until one is unlocked.
        CommandGroup(replacing: .importExport) {
            Button("Import…") { model.openImport() }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(model.store == nil)
                .accessibilityIdentifier("ks.import.open")
        }

        CommandGroup(after: .toolbar) {
            Button("Find") { model.focusSearch.toggle() }
                .keyboardShortcut("f", modifiers: .command)
                .disabled(model.store == nil)
            Divider()
            Button("Lock Vault Now") { model.lock(reason: .manual) }
                .keyboardShortcut("\\", modifiers: .command)
                .disabled(model.store == nil)
        }

        CommandMenu("Item") {
            Button("Edit Item") { model.beginEditingSelection() }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(model.store?.selectedItem == nil)
            Button("Copy Username") { model.copyPrimaryField() }
                .keyboardShortcut("c", modifiers: [.command, .shift, .option])
                .disabled(model.store?.selectedItem == nil)
            Divider()
            Button("Quick Access") { model.toggleQuickAccess() }
                .keyboardShortcut(.space, modifiers: [.command, .shift])
                .help("A floating search over every item. Works from any app.")
            Button("Password Generator") { model.openGenerator() }
                .keyboardShortcut("g", modifiers: [.command, .shift])
                .disabled(model.store == nil)
        }
    }
}
