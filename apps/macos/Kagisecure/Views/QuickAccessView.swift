import SwiftUI

import KagisecureFFI

/// What the Quick Access panel shows (ui-spec.md §7): a search field and a flat, live-filtered
/// list of every item, with copy actions and nothing else.
///
/// # Its own query, and its own selection
///
/// It deliberately does *not* share `VaultStore.query` or `selectedItemId`. Typing into Quick
/// Access must not re-filter the main window behind it, and dismissing the panel must not leave
/// the three-pane UI showing a search the user has already finished with. So the panel has its
/// own model, `QuickAccessModel`, made fresh every time the panel opens and dropped when it
/// closes — which is also where the copy actions live, behind the presence gate (ADR-0038).
///
/// # Locked
///
/// Quick Access does not present Touch ID in v1. With no unlocked store there is nothing to
/// search, so it says so and offers the main window, which is where unlocking lives.
struct QuickAccessView: View {
    @Bindable var model: QuickAccessModel
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            searchField
            Divider()
            if model.isLocked {
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
                model.copyUsername()
            } else if press.modifiers.contains(.option) {
                Task { await model.copyTotp() }
            } else {
                Task { await model.copyPassword() }
            }
            return .handled
        }
        .onAppear {
            model.reload()
            searchFocused = true
            // …and again once the panel has actually become key. A focus request made while the
            // window is still on its way to key status is dropped, and the symptom is a panel
            // that looks focused and receives nothing.
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(60))
                searchFocused = true
            }
        }
        .onExitCommand(perform: model.onDismiss)
    }

    // MARK: - Pieces

    private var searchField: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .font(.title3)
            TextField("Search all items", text: $model.query)
                .textFieldStyle(.plain)
                .font(.title3)
                .focused($searchFocused)
                .onSubmit { Task { await model.copyPassword() } }
                .accessibilityLabel("Search all items")
                .accessibilityIdentifier("ks.quickAccess.search")
            if model.awaitingPresence {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityLabel("Waiting for confirmation")
                    .accessibilityIdentifier("ks.quickAccess.awaitingPresence")
            }
            if let toast = model.toast {
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
                model.onDismiss()
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("ks.quickAccess.openMainWindow")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private var list: some View {
        if model.results.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: model.query.isEmpty ? "tray" : "magnifyingglass")
                    .font(.system(size: 26, weight: .light))
                    .foregroundStyle(.tertiary)
                (model.query.isEmpty ? Text("No items yet") : Text("Nothing matches “\(model.query)”"))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .accessibilityIdentifier("ks.quickAccess.empty")
        } else {
            // A `List` with a bound selection is what gives ↑/↓ for free: the field keeps focus
            // for typing, and the arrow keys move the highlight because the list is the only
            // other thing in the responder chain that wants them.
            List(model.results, id: \.id, selection: $model.selection) { item in
                QuickAccessRow(item: item, isSelected: model.selection == item.id)
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
                // `what` doubles as the identifier suffix, so it stays English; the text shown is
                // its localization (the four keys are in the string catalog).
                Text(LocalizedStringKey(what))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.quickAccess.legend.\(what)")
            }
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
