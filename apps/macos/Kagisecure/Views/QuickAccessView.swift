import SwiftUI

import KagisecureFFI

/// What the Quick Access panel shows (ui-spec.md §7): a search field and a flat, live-filtered
/// list of every item, with copy actions and nothing else.
///
/// # Its own query, and its own selection
///
/// It deliberately does *not* share `VaultStore.query` or `selectedItemId`. Typing into Quick
/// Access must not re-filter the main window behind it, and dismissing the panel must not leave
/// the three-pane UI showing a search the user has already finished with. So the panel keeps its
/// own two pieces of state and asks the session directly.
///
/// # Locked
///
/// Quick Access does not present Touch ID in v1. With no unlocked store there is nothing to
/// search, so it says so and offers the main window, which is where unlocking lives.
struct QuickAccessView: View {
    @Environment(AppModel.self) private var model

    @State private var query = ""
    @State private var results: [ItemView] = []
    @State private var selection: String?
    @State private var toast: String?
    @FocusState private var searchFocused: Bool

    /// Called for Esc and after a copy, so the panel behaves like Spotlight: do the thing, go away.
    let onDismiss: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            searchField
            Divider()
            if model.store == nil {
                lockedState
            } else {
                list
                Divider()
                legend
            }
        }
        .frame(width: 620, height: 420)
        .background(.regularMaterial)
        // The three copy actions (ui-spec.md §7). `onKeyPress` rather than hidden buttons with
        // `keyboardShortcut`: a zero-sized, fully transparent button is not reliably reachable
        // through the responder chain while a text field holds focus, and this needs to work
        // *while the user is typing* — that is the whole interaction.
        .onKeyPress(keys: [.return], phases: .down) { press in
            if press.modifiers.contains(.command) {
                copyUsername()
            } else if press.modifiers.contains(.option) {
                copyTotp()
            } else {
                copyPassword()
            }
            return .handled
        }
        .onAppear {
            reload()
            searchFocused = true
            // …and again once the panel has actually become key. A focus request made while the
            // window is still on its way to key status is dropped, and the symptom is a panel
            // that looks focused and receives nothing.
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(60))
                searchFocused = true
            }
        }
        .onExitCommand(perform: onDismiss)
    }

    // MARK: - Pieces

    private var searchField: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .font(.title3)
            TextField("Search all items", text: $query)
                .textFieldStyle(.plain)
                .font(.title3)
                .focused($searchFocused)
                .onSubmit { copyPassword() }
                .onChange(of: query) { _, _ in reload() }
                .accessibilityLabel("Search all items")
                .accessibilityIdentifier("ks.quickAccess.search")
            if let toast {
                Text(toast)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(.tint.opacity(0.18), in: Capsule())
                    .transition(.opacity)
                    .accessibilityIdentifier("ks.quickAccess.toast")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var lockedState: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock.fill")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(.tertiary)
            Text("Vault is locked")
                .font(.title3.weight(.medium))
                .accessibilityIdentifier("ks.quickAccess.locked")
            Text("Quick Access does not unlock the vault. Open the main window to unlock it.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 340)
            Button("Open Kagisecure") {
                NSApp.activate(ignoringOtherApps: true)
                onDismiss()
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("ks.quickAccess.openMainWindow")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private var list: some View {
        if results.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: query.isEmpty ? "tray" : "magnifyingglass")
                    .font(.system(size: 26, weight: .light))
                    .foregroundStyle(.tertiary)
                Text(query.isEmpty ? "No items yet" : "Nothing matches “\(query)”")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityIdentifier("ks.quickAccess.empty")
        } else {
            // A `List` with a bound selection is what gives ↑/↓ for free: the field keeps focus
            // for typing, and the arrow keys move the highlight because the list is the only
            // other thing in the responder chain that wants them.
            List(results, id: \.id, selection: $selection) { item in
                QuickAccessRow(item: item, isSelected: selection == item.id)
                    .tag(item.id)
            }
            .listStyle(.inset)
            .scrollContentBackground(.hidden)
            .accessibilityIdentifier("ks.quickAccess.list")
        }
    }

    private var legend: some View {
        HStack(spacing: 16) {
            Legend(key: "⏎", what: "Copy password")
            Legend(key: "⌘⏎", what: "Copy username")
            Legend(key: "⌥⏎", what: "Copy one-time password")
            Spacer()
            Legend(key: "esc", what: "Close")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background(.quaternary.opacity(0.25))
    }

    private struct Legend: View {
        let key: String
        let what: String

        // One identifier per legend entry rather than one on the row: an identifier on the `HStack`
        // would be stamped over both `Text`s inside it, which is how the three shortcuts stopped
        // being readable at all.
        var body: some View {
            HStack(spacing: 4) {
                Text(key)
                    .font(.caption.monospaced())
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
                Text(what)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.quickAccess.legend.\(what)")
            }
        }
    }

    // MARK: - Data and actions

    private func reload() {
        guard let store = model.store else {
            results = []
            return
        }
        // A flat list across everything that is not archived or trashed — ui-spec.md §7 says
        // "across all vaults", and the sidebar's notion of a current section does not apply here.
        results = store.session.listItems(
            filter: .all, query: query.isEmpty ? nil : query, sort: .title)
        if let selection, results.contains(where: { $0.id == selection }) { return }
        selection = results.first?.id
    }

    private var selectedItem: ItemView? {
        guard let selection else { return nil }
        return results.first { $0.id == selection }
    }

    private func copyPassword() {
        guard let store = model.store, let item = selectedItem else { return }
        guard
            let field = item.fields.first(where: {
                $0.concealed && $0.hasValue && $0.kind == .concealed
            })
        else {
            flash("No password on this item")
            return
        }
        do {
            let value = try store.session.revealField(itemId: item.id, fieldId: field.id)
            PasteboardService.copy(value, label: field.label)
            flash("Password copied", thenDismiss: true)
        } catch {
            flash("Could not copy")
        }
    }

    private func copyUsername() {
        guard let item = selectedItem else { return }
        // The username is a public value, so it is on the record already — no reveal call, and
        // nothing to fetch.
        guard
            let value = item.fields.first(where: {
                $0.label.caseInsensitiveCompare("username") == .orderedSame
            })?.value ?? item.subtitle, !value.isEmpty
        else {
            flash("No username on this item")
            return
        }
        PasteboardService.copy(value, label: "Username")
        flash("Username copied", thenDismiss: true)
    }

    private func copyTotp() {
        guard let store = model.store, let item = selectedItem else { return }
        do {
            guard let code = try store.session.itemTotpCode(
                itemId: item.id, at: TotpCountdown.unixNow())
            else {
                flash("No one-time password on this item")
                return
            }
            PasteboardService.copy(code.code, label: "One-time password")
            flash("Code copied — \(code.secondsRemaining)s left", thenDismiss: true)
        } catch {
            flash("Could not copy")
        }
    }

    private func flash(_ message: String, thenDismiss: Bool = false) {
        withAnimation { toast = message }
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(thenDismiss ? 450 : 1_200))
            withAnimation { toast = nil }
            if thenDismiss { onDismiss() }
        }
    }
}

/// One row: the same content ui-spec.md §3 gives the main list, minus the affordances a
/// keyboard-driven panel does not need.
private struct QuickAccessRow: View {
    let item: ItemView
    let isSelected: Bool

    // Every row carries the same identifiers: the panel's rows have no stable per-row key that a
    // test can rely on, so tests address a row by its identifier plus the label it displays.
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: item.categorySymbol)
                .frame(width: 20)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title)
                    .lineLimit(1)
                    .accessibilityIdentifier("ks.quickAccess.rowTitle")
                if let subtitle = item.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .accessibilityIdentifier("ks.quickAccess.rowSubtitle")
                }
            }
            Spacer(minLength: 4)
            if item.fields.contains(where: { $0.kind == .totp && $0.hasValue }) {
                Image(systemName: "clock.badge.checkmark")
                    .foregroundStyle(.secondary)
                    .help("Has a one-time password — ⌥⏎ copies it")
                    .accessibilityLabel("Has a one-time password")
                    .accessibilityIdentifier("ks.quickAccess.rowTotpBadge")
            }
        }
        .padding(.vertical, 3)
        .contentShape(Rectangle())
    }
}
