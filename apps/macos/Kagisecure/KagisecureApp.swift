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
    /// Sparkle (ADR-0044). Started here, before any window: an old build must be able to update
    /// itself even when nothing else in it works.
    @State private var updater: AppUpdater

    init() {
        let updater = AppUpdater()
        updater.start()
        _updater = State(initialValue: updater)
    }

    var body: some Scene {
        Window("Kagisecure", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 1_040, minHeight: 620)
        }
        .windowToolbarStyle(.unified)
        .commands {
            KagisecureCommands(model: model)
            UpdateCommands(updater: updater)
        }

        Settings {
            SettingsView()
                .environment(model)
                .environment(updater)
        }

        // The menu-bar status item (ui-spec.md §6.3). Minimal on purpose: lock state, Quick
        // Access, how many agents are waiting on you, how much is granted right now, and one
        // button to take it all away.
        MenuBarExtra {
            MenuBarPanel()
                .environment(model)
                .environment(model.agent)
                .environment(model.browserExtension)
                .environment(model.unattended)
        } label: {
            Image(systemName: menuBarSymbol)
                // The lock state is what this icon *is*, and a symbol name is not something a
                // test should be matching on — so the state is said out loud here, and the
                // identifier stays constant across all three symbols. The label becomes the status
                // item's `AXTitle` (measured), which is what VoiceOver reads for it.
                .accessibilityLabel(menuBarLabel)
                .accessibilityIdentifier("ks.menuBar.icon")
        }
    }

    /// A locked padlock, an open one, or an open one with a badge when something is waiting — an
    /// approval, or an agent-fill notice nobody has looked at yet (ADR-0036 implementation
    /// decision 11).
    private var menuBarSymbol: String {
        guard model.store != nil else { return "lock.fill" }
        let waiting =
            model.agent.status.pendingApprovals > 0 || model.agentFill.unseen > 0
            || model.unattended.attention > 0 || model.testLogins.createdCount > 0
        return waiting ? "lock.open.trianglebadge.exclamationmark" : "lock.open.fill"
    }

    /// The same states, in words, for VoiceOver and for the UI-test suite.
    private var menuBarLabel: String {
        let armed = model.unattended.status.armed ? String(localized: ", unattended jobs armed") : ""
        guard model.store != nil else { return String(localized: "Kagisecure, vault locked\(armed)") }
        let pending = model.agent.status.pendingApprovals
        let notices = model.agentFill.unseen
        var label = String(localized: "Kagisecure, vault unlocked")
        if pending > 0 { label += String(localized: ", \(pending) approval(s) waiting") }
        if notices > 0 { label += String(localized: ", \(notices) agent-fill notice(s)") }
        label += armed
        if model.testLogins.createdCount > 0 {
            label += String(localized: ", \(model.testLogins.createdCount) test login(s) created by agents")
        }
        if model.unattended.attention > 0 {
            label += String(localized: ", \(model.unattended.attention) unattended event(s)")
        }
        return label
    }
}

/// What the menu-bar icon drops down.
///
/// A menu, not a window-style extra: the HIG's advice for a status item whose content is a handful
/// of commands, and a native `NSMenu` is fully accessible — measured, every entry is an
/// `AXMenuItem` under the status item with its title and enabled state, open or closed, kept
/// current as the state changes, so VoiceOver reads it and the arrow keys and type-select work.
///
/// What does not come across is `.accessibilityIdentifier`: the `ks.menuBar.*` identifiers below
/// are not in the tree (a button's comes out as `menuAction:`). They are kept so the entries line
/// up with ui-spec.md §15 the day SwiftUI does carry them; until then the UI-test suite finds these
/// entries by their titles, so a title change here is a change to `L_MenuBarAndDarkModeTests` too.
struct MenuBarPanel: View {
    @Environment(AppModel.self) private var model
    @Environment(AgentService.self) private var agent
    @Environment(ExtensionService.self) private var ext
    @Environment(UnattendedService.self) private var unattended

    var body: some View {
        if model.store == nil {
            Text("Vault locked")
                .accessibilityIdentifier("ks.menuBar.lockState")
            unattendedEntries
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
            if model.agentFill.unseen > 0 {
                Button("\(model.agentFill.unseen) agent-fill notice(s) — review") {
                    model.showAgentFillNotices()
                }
                .accessibilityIdentifier("ks.menuBar.agentFillNotices")
            }
            if model.testLogins.createdCount > 0 {
                Button(TestLoginService.menuTitle(count: model.testLogins.createdCount)) {
                    NSApp.activate(ignoringOtherApps: true)
                    model.testLogins.acknowledge()
                }
                .accessibilityIdentifier("ks.menuBar.testLoginsCreated")
            }
            (agent.status.running
                ? Text("Serving agents · \(agent.status.activeLeases) active lease(s)")
                : Text("Not serving agents"))
            .accessibilityIdentifier("ks.menuBar.agentState")
            (ext.status.running
                ? Text("Serving browsers · \(ext.status.fillLeases) fill lease(s)")
                : Text("Not serving browsers"))
            .accessibilityIdentifier("ks.menuBar.browserState")
            unattendedEntries
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

extension MenuBarPanel {
    /// Unattended jobs (ADR-0042 §9): whether they are armed, what happened since the last look,
    /// and Pause — which asks for nothing and works while the vault is locked.
    @ViewBuilder
    fileprivate var unattendedEntries: some View {
        if unattended.status.armed {
            (unattended.status.runs.isEmpty
                ? Text("Unattended jobs armed")
                : Text("Unattended jobs armed · \(unattended.status.runs.count) running"))
            .accessibilityIdentifier("ks.menuBar.unattendedState")
            if unattended.attention > 0 {
                Button("\(unattended.attention) unattended event(s) — review") {
                    model.showUnattended()
                }
                .disabled(model.store == nil)
                .accessibilityIdentifier("ks.menuBar.unattendedEvents")
            }
            Button("Pause Unattended Jobs") { unattended.pause(session: model.store?.session) }
                .accessibilityIdentifier("ks.menuBar.unattendedPause")
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
            // ui-spec.md §11. Advertised in the reveal button's tooltip long before it was bound
            // to anything; now it asks for presence like the button does (ADR-0038).
            Button("Reveal or Conceal Field") { model.store?.toggleRevealForShortcut() }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(model.store?.selectedItem == nil)
            // ⇧⌥⌘C, not the ⌘C 1Password uses: a menu item bound to plain ⌘C would take the
            // shortcut from Edit ▸ Copy, so ⌘C in the search field, the edit sheet or a selected
            // public value would copy the username instead (ui-spec.md §11 says why).
            Button("Copy Username") { model.copyUsername() }
                .keyboardShortcut("c", modifiers: [.command, .shift, .option])
                .disabled(model.store?.selectedItem?.username == nil)
            // ui-spec.md §11, 1Password parity. Asks for presence unless the password is already
            // shown (ADR-0038); "password" is `ItemView.passwordField`, designated by id.
            Button("Copy Password") { model.store?.copyPasswordForShortcut() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(model.store?.selectedItem?.passwordField == nil)
            Divider()
            // The list's selection — several items, or the one shown (ADR-0007 amendment
            // 2026-10-04). Personal vault only.
            Button("Show to Agents") {
                model.store?.attempt { try model.store?.setSelectionAgentVisible(true) }
            }
            .disabled(
                model.store?.canChangeAgentVisibilityInBulk != true
                    || model.store?.bulkTargetIds.isEmpty != false)
            Button("Hide from Agents") {
                model.store?.attempt { try model.store?.setSelectionAgentVisible(false) }
            }
            .disabled(
                model.store?.canChangeAgentVisibilityInBulk != true
                    || model.store?.bulkTargetIds.isEmpty != false)
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
