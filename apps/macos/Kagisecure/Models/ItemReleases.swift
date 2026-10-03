import Foundation
import Observation
import SwiftUI

import KagisecureFFI

/// Every secret the detail pane shows or copies, and the release behind each one (ADR-0038).
///
/// # The rule this type holds
///
/// Nothing here has a value until Rust hands one over from a release that a granted presence
/// check produced (`releaseField`, `releaseTotp`, `releaseNotes`). There is no other way in: the
/// ungated calls the app used to read values through no longer exist, so this is not a convention
/// a future view could forget — a view that wants a value has nowhere else to get it.
///
/// # One touch, one field (user decision 1)
///
/// Each reveal, and each copy of something not already shown, is its own release and its own
/// prompt. A shown value stays shown, and copying *that* value needs no new touch —
/// `copyShownValue`, which Rust records `SHOWN_EARLIER`. A different field is a different touch.
///
/// # When a value goes away again (user decisions 2 and 5)
///
/// * **Deselect** — `show(item:)` for another item, or `hideAll(because:)`.
/// * **Lock** — `AppModel.lock` calls `hideAll(because: .locked)` before the store is dropped,
///   and Rust refuses every release object after `VaultSession.lock()` anyway.
/// * **Five minutes** after the touch, not extended by use: each shown value carries the
///   release's own deadline, a task hides it then, and Rust refuses a read past it regardless.
///
/// Anything hidden has its release `close()`d, so the capability ends with the pixels.
///
/// # An answer that arrives too late
///
/// Every action captures `generation` before it awaits a prompt. A deselect or a lock bumps it,
/// and a release that comes back afterwards is closed unread: a touch given for an item the
/// person has since moved away from never puts a value on screen or on the clipboard.
///
/// # Accessibility
///
/// Showing and hiding are announced ("password shown", "password hidden"), because a value
/// appearing or disappearing is otherwise silent to a VoiceOver user. What is never done is ask
/// *how* an action was triggered — pointer, keyboard, VoiceOver or anything else. The input source
/// is not evidence of a person (ADR-0038, "The adversary"); the presence prompt is.
@MainActor
@Observable
final class ItemReleases {
    /// What the pane is showing, keyed by what it is.
    enum Key: Hashable, Sendable {
        /// A concealed field, by field id.
        case field(String)
        /// A one-time password's live code, by field id.
        case totp(String)
        /// The item's notes.
        case notes
    }

    /// A value on screen, and the release it came from.
    struct Shown {
        let value: String
        let label: String
        /// The release it came from, closed when the value is hidden.
        let release: any Closable
        /// When the release's five-minute cap ends it.
        let hidesAt: Date
    }

    /// A one-time password running live, and the release it reads through.
    struct LiveTotp {
        let release: TotpRelease
        let label: String
        let hidesAt: Date
    }

    /// Why everything was hidden, for the announcement.
    enum HideReason {
        case deselected
        case locked
        case edited
    }

    /// Where releases are asked for: the personal vault, or the shared vault whose items the
    /// pane shows. `VaultStore` switches it with the sidebar selection, after hiding everything.
    var source: any ReleaseSource

    /// The item these values belong to. Anything shown for another item is hidden first.
    private(set) var itemId: String?
    private(set) var fields: [String: Shown] = [:]
    private(set) var notes: Shown?
    private(set) var totps: [String: LiveTotp] = [:]

    /// The release waiting on its prompt, if any — a view disables its buttons meanwhile.
    private(set) var pending: Key?

    /// Bumped by every hide-all. An action that finds it changed after its await discards what
    /// it got (see the type's documentation).
    private(set) var generation: UInt64 = 0

    /// How a change is told to VoiceOver. Replaced in tests.
    var announce: (String) -> Void = { AccessibilityNotification.Announcement($0).post() }

    /// Where a copy goes. Replaced in tests only to observe the label; the value always goes
    /// through `PasteboardService`, the one place anything reaches the clipboard.
    var copyToPasteboard: (String, String) -> Void = { PasteboardService.copy($0, label: $1) }

    /// Told about every reveal, copy and notes access — the same in-app activity signal
    /// `VaultStore.notifyActivity` sends for a save or a toggle (see its doc comment). Wired by
    /// `AppModel.adopt(_:)` to the same closure; a no-op in every test that builds a bare
    /// `ItemReleases(source:)`.
    var notifyActivity: () -> Void = {}

    private var expiryTasks: [Key: Task<Void, Never>] = [:]

    init(source: any ReleaseSource) {
        self.source = source
    }

    // MARK: - Reading

    func shownValue(_ field: FieldView) -> String? { fields[field.id]?.value }

    func isShown(_ field: FieldView) -> Bool { fields[field.id] != nil }

    func isLive(totp field: FieldView) -> Bool { totps[field.id] != nil }

    var notesText: String? { notes?.value }

    /// The live code for `field` at Unix time `at`, from its release — or `nil`, having hidden it,
    /// once the release has ended (five minutes, a lock, the field gone).
    func totpCode(_ field: FieldView, at: UInt64) -> TotpCodeView? {
        guard let live = totps[field.id] else { return nil }
        do {
            return try live.release.codeAt(at: at)
        } catch {
            hide(.totp(field.id), announcing: String(localized: "\(live.label) hidden"))
            return nil
        }
    }

    // MARK: - Selection

    /// The detail pane now shows `itemId`. Anything shown for another item is hidden.
    func show(item itemId: String?) {
        guard itemId != self.itemId else { return }
        hideAll(because: .deselected)
        self.itemId = itemId
    }

    /// Hide everything, close every release, and discard any answer still on its way.
    func hideAll(because reason: HideReason) {
        generation &+= 1
        let hadAnything = !fields.isEmpty || notes != nil || !totps.isEmpty
        for shown in fields.values { shown.release.close() }
        notes?.release.close()
        for live in totps.values { live.release.close() }
        fields.removeAll()
        notes = nil
        totps.removeAll()
        for task in expiryTasks.values { task.cancel() }
        expiryTasks.removeAll()
        pending = nil
        guard hadAnything else { return }
        switch reason {
        case .deselected: announce(String(localized: "Shown values hidden"))
        case .locked: announce(String(localized: "Vault locked. Shown values hidden"))
        case .edited: break
        }
    }

    // MARK: - Concealed fields

    /// ⌘R and the eye: show one concealed field, or hide it again. Showing asks for presence.
    func toggleReveal(item: ItemView, field: FieldView) async throws {
        notifyActivity()
        // What is shown belongs to one item: showing something of another hides the rest first.
        show(item: item.id)
        if fields[field.id] != nil {
            hide(.field(field.id), announcing: String(localized: "\(Self.spoken(field.label)) hidden"))
            return
        }
        let source = self.source
        guard let release = try await release(.field(field.id), item: item, {
            try await source.releaseField(
                itemId: item.id, fieldId: field.id, purpose: .reveal)
        }) else { return }
        let value: String
        do {
            value = try release.value()
        } catch {
            release.close()
            throw error
        }
        let shown = Shown(
            value: value, label: field.label, release: release,
            hidesAt: Self.deadline(release.secondsRemaining()))
        fields[field.id] = shown
        scheduleExpiry(.field(field.id), at: shown.hidesAt, label: field.label)
        announce(String(localized: "\(Self.spoken(field.label)) shown"))
    }

    /// The copy button (ui-spec.md §4.2). A value already shown is copied from its release with
    /// no new touch; anything else is a one-use copy release, and a new touch.
    ///
    /// A one-time-password field copies its current **code**, never the `otpauth://` URI it
    /// stores.
    func copy(item: ItemView, field: FieldView) async throws {
        notifyActivity()
        if field.kind == .totp {
            try await copyTotp(item: item, field: field)
            return
        }
        guard field.concealed else {
            // A public value is already on the item view, like the username Quick Access's ⌘⏎
            // copies: there is nothing to release.
            copyToPasteboard(field.value ?? "", field.label)
            announceCopied(field.label)
            return
        }
        if let shown = fields[field.id], let release = shown.release as? FieldRelease {
            do {
                let value = try release.copyShownValue()
                copyToPasteboard(value, field.label)
                announceCopied(field.label)
                return
            } catch FfiError.ReleaseEnded {
                // Its five minutes ran out a moment before the expiry task hid it. Hidden now,
                // and this copy is asked for like any other — a new touch.
                hide(.field(field.id), announcing: String(localized: "\(Self.spoken(field.label)) hidden"))
            }
        }
        let source = self.source
        guard let release = try await release(.field(field.id), item: item, {
            try await source.releaseField(itemId: item.id, fieldId: field.id, purpose: .copy)
        }) else { return }
        defer { release.close() }
        let value = try release.value()
        copyToPasteboard(value, field.label)
        announceCopied(field.label)
    }

    /// The value of a concealed field, for the edit sheet to prefill **one** field the person
    /// asked to see (user decision 4: edit mode prefills nothing on its own). Its own release,
    /// purpose `EditReveal`, closed as soon as it is read: from here on the value is the draft's,
    /// being edited, not a shown secret.
    func valueForEditing(itemId: String, fieldId: String) async throws -> String? {
        notifyActivity()
        let source = self.source
        guard let release = try await release(.field(fieldId), itemId: itemId, {
            try await source.releaseField(
                itemId: itemId, fieldId: fieldId, purpose: .editReveal)
        }) else { return nil }
        defer { release.close() }
        return try release.value()
    }

    // MARK: - One-time passwords

    /// Start the live code (user decision 2): masked until this touch, then live until five
    /// minutes after it, a deselect or a lock — use does not extend it.
    func showTotp(item: ItemView, field: FieldView) async throws {
        notifyActivity()
        // What is shown belongs to one item: showing something of another hides the rest first.
        show(item: item.id)
        guard totps[field.id] == nil else { return }
        let source = self.source
        guard let release = try await release(.totp(field.id), item: item, {
            try await source.releaseTotp(
                itemId: item.id, fieldId: field.id, purpose: .reveal)
        }) else { return }
        let live = LiveTotp(
            release: release, label: field.label,
            hidesAt: Self.deadline(release.secondsRemaining()))
        totps[field.id] = live
        scheduleExpiry(.totp(field.id), at: live.hidesAt, label: field.label)
        announce(String(localized: "\(Self.spoken(field.label)) shown"))
    }

    /// Stop the live code now.
    func hideTotp(_ field: FieldView) {
        hide(.totp(field.id), announcing: String(localized: "\(Self.spoken(field.label)) hidden"))
    }

    /// Copy the current code: from the live release with no new touch if the code is on screen,
    /// otherwise from a one-use copy release (the ring, the button, ⌥⌘C).
    func copyTotp(item: ItemView, field: FieldView) async throws {
        notifyActivity()
        let now = TotpCountdown.unixNow()
        if let live = totps[field.id] {
            do {
                let code = try live.release.copyShownCodeAt(at: now)
                copyToPasteboard(code.code, field.label)
                announceCopied(field.label)
                return
            } catch FfiError.ReleaseEnded {
                hide(.totp(field.id), announcing: String(localized: "\(Self.spoken(field.label)) hidden"))
            }
        }
        let source = self.source
        guard let release = try await release(.totp(field.id), item: item, {
            try await source.releaseTotp(
                itemId: item.id, fieldId: field.id, purpose: .copy)
        }) else { return }
        defer { release.close() }
        let code = try release.codeAt(at: TotpCountdown.unixNow())
        copyToPasteboard(code.code, field.label)
        announceCopied(field.label)
    }

    /// The item list's hover action (ui-spec.md §3): the item's first one-time password. Copied
    /// from the detail pane's live code if that is this item's and it is running, otherwise a
    /// one-use copy release.
    func copyFirstTotp(of item: ItemView) async throws {
        guard let field = item.fields.first(where: { $0.kind == .totp && $0.hasValue }) else {
            return
        }
        try await copyTotp(item: item, field: field)
    }

    // MARK: - Notes (user decision 3)

    func toggleNotes(item: ItemView) async throws {
        notifyActivity()
        // What is shown belongs to one item: showing something of another hides the rest first.
        show(item: item.id)
        if notes != nil {
            hide(.notes, announcing: String(localized: "Notes hidden"))
            return
        }
        let source = self.source
        guard let release = try await release(.notes, item: item, {
            try await source.releaseNotes(itemId: item.id, purpose: .reveal)
        }) else { return }
        let text: String
        do {
            text = try release.text()
        } catch {
            release.close()
            throw error
        }
        let shown = Shown(
            value: text, label: "notes", release: release,
            hidesAt: Self.deadline(release.secondsRemaining()))
        notes = shown
        scheduleExpiry(.notes, at: shown.hidesAt, label: String(localized: "notes"))
        announce(String(localized: "Notes shown"))
    }

    func copyNotes(item: ItemView) async throws {
        notifyActivity()
        if let shown = notes, let release = shown.release as? NotesRelease {
            do {
                copyToPasteboard(try release.copyShownText(), "notes")
                announceCopied(String(localized: "notes"))
                return
            } catch FfiError.ReleaseEnded {
                hide(.notes, announcing: String(localized: "Notes hidden"))
            }
        }
        let source = self.source
        guard let release = try await release(.notes, item: item, {
            try await source.releaseNotes(itemId: item.id, purpose: .copy)
        }) else { return }
        defer { release.close() }
        copyToPasteboard(try release.text(), "notes")
        announceCopied(String(localized: "notes"))
    }

    /// The notes, for the edit sheet to prefill once the person asked to see them there.
    func notesForEditing(itemId: String) async throws -> String? {
        notifyActivity()
        let source = self.source
        guard let release = try await release(.notes, itemId: itemId, {
            try await source.releaseNotes(itemId: itemId, purpose: .editReveal)
        }) else { return nil }
        defer { release.close() }
        return try release.text()
    }

    // MARK: - The one path to a release

    private func release<R: Closable>(
        _ key: Key, item: ItemView, _ ask: @escaping () async throws -> R
    ) async throws -> R? {
        try await release(key, itemId: item.id, ask)
    }

    /// Ask Rust for a release — which asks the presence gate — unless one is already pending, and
    /// discard it if the pane moved on (a deselect, a lock) while the prompt was up.
    private func release<R: Closable>(
        _ key: Key, itemId: String, _ ask: @escaping () async throws -> R
    ) async throws -> R? {
        guard pending == nil else { return nil }
        let before = generation
        pending = key
        defer { if generation == before { pending = nil } }
        let release = try await ask()
        guard generation == before else {
            release.close()
            return nil
        }
        return release
    }

    // MARK: - Hiding

    private func hide(_ key: Key, announcing: String?) {
        expiryTasks.removeValue(forKey: key)?.cancel()
        var removed = false
        switch key {
        case .field(let id):
            if let shown = fields.removeValue(forKey: id) {
                shown.release.close()
                removed = true
            }
        case .totp(let id):
            if let live = totps.removeValue(forKey: id) {
                live.release.close()
                removed = true
            }
        case .notes:
            if let shown = notes {
                shown.release.close()
                notes = nil
                removed = true
            }
        }
        if removed, let announcing { announce(announcing) }
    }

    private func scheduleExpiry(_ key: Key, at deadline: Date, label: String) {
        expiryTasks[key]?.cancel()
        let generation = self.generation
        expiryTasks[key] = Task { [weak self] in
            let seconds = max(0, deadline.timeIntervalSinceNow)
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, let self, self.generation == generation else { return }
            self.hide(key, announcing: String(localized: "\(Self.spoken(label)) hidden after five minutes"))
        }
    }

    private func announceCopied(_ label: String) {
        let policy = PasteboardService.clearDescription(seconds: PasteboardService.clearSeconds)
        announce(String(localized: "\(Self.spoken(label)) copied. \(policy)"))
    }

    private static func deadline(_ secondsRemaining: UInt32) -> Date {
        Date().addingTimeInterval(TimeInterval(secondsRemaining))
    }

    /// A field label as the start of a spoken sentence: "password" → "Password".
    static func spoken(_ label: String) -> String {
        guard let first = label.first else { return String(localized: "Value") }
        return first.uppercased() + label.dropFirst()
    }

    /// What VoiceOver reads for a masked value (ADR-0038, "Accessibility"): that it is concealed,
    /// and what revealing it will ask for — never a placeholder that could be mistaken for the
    /// value, and never its length.
    static func concealedLabel(_ label: String, action: String = String(localized: "Reveal")) -> String {
        String(localized: "\(spoken(label)), concealed. \(action) asks for Touch ID or your Mac password.")
    }
}

/// A release object: anything that can be ended early.
protocol Closable: AnyObject, Sendable {
    func close()
}

extension FieldRelease: Closable {}
extension TotpRelease: Closable {}
extension NotesRelease: Closable {}
