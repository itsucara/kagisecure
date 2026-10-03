import Foundation
import Observation
import SwiftUI

import KagisecureFFI

/// Quick Access's state and its three copy actions (ui-spec.md §7), out of the view so they can
/// be gated and tested the same way the detail pane's are (ADR-0038 §6).
///
/// # What each key does
///
/// * **⏎** copies the selected item's password through a `QuickAccessCopy` release — one presence
///   prompt, one use, and nothing kept: the value goes from the release to the pasteboard and is
///   dropped with the local that held it. "Password" is `ItemView.passwordField`, the field the
///   vault designates by id — never one picked by label or position, which the edit sheet can
///   change without a presence check.
/// * **⌥⏎** copies its current one-time code the same way (`releaseTotp`, no field named).
/// * **⌘⏎** copies the username — `ItemView.username`, a real username field, public and already
///   on the item: no release, no prompt. Never the subtitle, which can be a website or a card's
///   masked digits.
///
/// Each asks the gate exactly once, and a second press while a prompt is up does nothing: the
/// first is still being answered, and a second prompt beside it is what the app never raises.
///
/// # What it keeps
///
/// A query, a list of item *views* (metadata only), a selection, a status line, and whether a
/// prompt is up. Never a value: there is no property here a secret could be left in after the
/// panel closes, and `QuickAccessController.close()` drops the whole model with the hosting view.
@MainActor
@Observable
final class QuickAccessModel {
    /// What is typed into the search field. Re-filters on every change.
    var query = "" {
        didSet { reload() }
    }
    /// The highlighted row's item id.
    var selection: String?
    private(set) var results: [ItemView] = []
    /// A one-line confirmation or refusal, shown next to the search field.
    private(set) var toast: String?
    /// A copy is waiting on its presence prompt.
    private(set) var awaitingPresence = false

    /// The unlocked session, or `nil` while the vault is locked — the panel then says so.
    let session: VaultSession?

    /// Closes the panel. Called after every successful copy: do the thing, go away.
    var onDismiss: () -> Void

    /// Where a copy goes. Replaced in tests only to observe it; the app always uses
    /// `PasteboardService`, the one place anything reaches the clipboard.
    var copyToPasteboard: (String, String) -> Void = { PasteboardService.copy($0, label: $1) }

    /// How long a toast stays before it goes (and, after a copy, before the panel closes).
    var toastDuration: (_ thenDismiss: Bool) -> Duration = { $0 ? .milliseconds(450) : .milliseconds(1_200) }

    init(session: VaultSession?, onDismiss: @escaping () -> Void) {
        self.session = session
        self.onDismiss = onDismiss
        reload()
    }

    var isLocked: Bool { session == nil }

    var selectedItem: ItemView? {
        guard let selection else { return nil }
        return results.first { $0.id == selection }
    }

    /// Re-run the search. A flat list across everything not archived or trashed — ui-spec.md §7
    /// says "across all vaults", and the sidebar's notion of a current section does not apply.
    func reload() {
        guard let session else {
            results = []
            return
        }
        results = session.listItems(
            filter: .all, query: query.isEmpty ? nil : query, sort: .title)
        if let selection, results.contains(where: { $0.id == selection }) { return }
        selection = results.first?.id
    }

    // MARK: - The three keys

    /// ⏎: the selected item's password, behind one presence prompt.
    func copyPassword() async {
        guard let session, !awaitingPresence, let item = selectedItem else { return }
        guard let field = item.passwordField else {
            flash(String(localized: "No password on this item"))
            return
        }
        awaitingPresence = true
        defer { awaitingPresence = false }
        do {
            let release = try await session.releaseField(
                itemId: item.id, fieldId: field.id, purpose: .quickAccessCopy)
            defer { release.close() }
            copyToPasteboard(try release.value(), field.label)
            flash(String(localized: "Password copied — \(Self.clearPolicy)"), thenDismiss: true)
        } catch {
            flash(Self.refusal(error))
        }
    }

    /// ⌘⏎: the username. Public, already on the item view — nothing to release. Only a real
    /// username field: with none, nothing is copied, rather than whatever the subtitle shows.
    func copyUsername() {
        guard let item = selectedItem else { return }
        guard let value = item.username, !value.isEmpty else {
            flash(String(localized: "No username on this item"))
            return
        }
        copyToPasteboard(value, "Username")
        flash(String(localized: "Username copied — \(Self.clearPolicy)"), thenDismiss: true)
    }

    /// ⌥⏎: the current one-time code, behind one presence prompt.
    func copyTotp() async {
        guard let session, !awaitingPresence, let item = selectedItem else { return }
        guard item.fields.contains(where: { $0.kind == .totp && $0.hasValue }) else {
            flash(String(localized: "No one-time password on this item"))
            return
        }
        awaitingPresence = true
        defer { awaitingPresence = false }
        do {
            let release = try await session.releaseTotp(
                itemId: item.id, fieldId: nil, purpose: .quickAccessCopy)
            defer { release.close() }
            let code = try release.codeAt(at: TotpCountdown.unixNow())
            copyToPasteboard(code.code, "One-time password")
            flash(
                String(localized: "Code copied — \(code.secondsRemaining)s left · \(Self.clearPolicy)"),
                thenDismiss: true)
        } catch {
            flash(Self.refusal(error))
        }
    }

    // MARK: - Helpers

    /// The clipboard clear policy, named at the copy site.
    ///
    /// With `pasteboardClearSeconds = 0` the secret stays on the clipboard until something else
    /// overwrites it, and the moment of copying is the only moment the user can act on that — a
    /// confirmation reading just "Password copied" makes the setting's consequence invisible.
    static var clearPolicy: String {
        PasteboardService.clearDescription(seconds: PasteboardService.clearSeconds).lowercased()
    }

    /// What the toast says when a copy did not happen. Never a value: an `FfiError`'s text is
    /// metadata by construction.
    static func refusal(_ error: Error) -> String {
        switch error as? FfiError {
        case .PresenceCancelled?: String(localized: "Not confirmed — nothing copied")
        case .PresenceBusy?: String(localized: "Another confirmation is in progress")
        case .PresenceUnavailable?, .NoPresenceGate?: String(localized: "Could not confirm it is you — nothing copied")
        case .VaultLocked?: String(localized: "Vault is locked")
        default: String(localized: "Could not copy")
        }
    }

    private func flash(_ message: String, thenDismiss: Bool = false) {
        withAnimation { toast = message }
        let pause = toastDuration(thenDismiss)
        Task { @MainActor in
            try? await Task.sleep(for: pause)
            withAnimation { if self.toast == message { self.toast = nil } }
            if thenDismiss { self.onDismiss() }
        }
    }
}
