import SwiftUI

import KagisecureFFI

/// Edit mode (ui-spec.md §4.3): inline field editing, add/remove fields, ⌘S to save, Esc to
/// cancel.
///
/// The draft is local state. Nothing reaches the vault until Save, so Cancel is genuinely free —
/// there is no partially-applied edit to undo.
///
/// # Nothing secret is prefilled (ADR-0038 user decision 4)
///
/// Every concealed value, the notes and a one-time password's setup open masked. Each has its own
/// "Show", which asks for presence for that one value (`EditReveal`) and puts it in the draft to
/// be edited; "Change" (and, for notes, "Replace") starts a new value without seeing the old one,
/// which releases nothing. A value shown to edit that is still untouched five minutes later is
/// masked again — and, being untouched, kept as it is.
struct ItemEditView: View {
    @Bindable var store: VaultStore
    @State var draft: ItemDraft
    /// Whether the stored item has notes — the sheet does not know what they say.
    let hasStoredNotes: Bool
    /// The id of the password field of an item in the agent test-login vault, which offers only
    /// Regenerate (ADR-0048, Threats): no typing, no revealing, no pasting a real password in.
    var regenerateOnlyFieldId: String?
    let onCancel: () -> Void
    let onSave: (ItemDraft) -> Void

    /// "Replace" or "Remove" was pressed on the stored notes, so the text field is the notes now.
    @State private var notesUnmasked = false
    /// The notes exactly as "Show" put them in the draft, until they are masked again or edited —
    /// what the five-minute cap compares against (`EditReveal`).
    @State private var notesShown: String?

    @State private var tagText: String
    @State private var urlText: String

    /// The single source of truth for the field list while editing — `draft.fields` is only ever
    /// read from at `init` (to seed this) and written to at `save()` (from this) — each row paired
    /// with a `uiId` that survives adds and deletes even though `FieldDraft.id` cannot (see
    /// `EditableField`'s own doc for why `ForEach` needs this and what went wrong without it).
    @State private var fieldRows: [EditableField]

    init(
        store: VaultStore, draft: ItemDraft, hasStoredNotes: Bool,
        regenerateOnlyFieldId: String? = nil,
        onCancel: @escaping () -> Void, onSave: @escaping (ItemDraft) -> Void
    ) {
        self.store = store
        self._draft = State(initialValue: draft)
        self.hasStoredNotes = hasStoredNotes
        self.regenerateOnlyFieldId = regenerateOnlyFieldId
        self.onCancel = onCancel
        self.onSave = onSave
        self._tagText = State(initialValue: draft.tags.joined(separator: ", "))
        self._urlText = State(initialValue: draft.urls.joined(separator: "\n"))
        self._fieldRows = State(initialValue: draft.fields.map { EditableField(draft: $0) })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            LabeledContent("Title") {
                TextField("Title", text: $draft.title)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .accessibilityIdentifier("ks.edit.title")
            }

            VStack(spacing: 0) {
                // Keyed by `EditableField.id` (`$row` gives a `Binding<EditableField>` per row,
                // keyed that way automatically) — see `EditableField`'s own doc for why array
                // position or `FieldDraft.id` cannot serve as this identity, and what silently
                // went wrong when this `ForEach` used to be keyed by index instead.
                ForEach($fieldRows) { $row in
                    FieldEditRow(
                        field: $row.draft, reveal: revealer(for: row.draft),
                        regenerateOnly: regenerateOnlyFieldId != nil && row.draft.id == regenerateOnlyFieldId,
                        onDelete: { removeField(withId: row.uiId) })
                    Divider()
                }
            }
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))

            Menu {
                ForEach(Self.addableKinds, id: \.0) { kind, name in
                    Button(name) { addField(kind: kind) }
                }
            } label: {
                Label("Add field", systemImage: "plus.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityIdentifier("ks.edit.addField")

            LabeledContent("Tags") {
                TextField("comma, separated", text: $tagText)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .accessibilityIdentifier("ks.edit.tags")
            }
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent("Websites") {
                    TextField("one per line", text: $urlText, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...4)
                        .labelsHidden()
                        .accessibilityIdentifier("ks.edit.urls")
                }
                // Renamed from "URLs" in M6, because since the browser extension this field is no
                // longer decoration: it is the allow-list that decides where this item may be
                // filled. A user who does not know that will not think to add the second domain
                // their login actually lives on.
                Text(
                    "Where the browser extension may fill this item. Subdomains of the same site count; a different scheme or port does not."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            LabeledContent("Notes") {
                if notesMasked {
                    maskedNotes
                } else {
                    TextField(
                        "Notes",
                        text: Binding(get: { draft.notes ?? "" }, set: { draft.notes = $0 }),
                        axis: .vertical
                    )
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(3...10)
                    .labelsHidden()
                    .accessibilityIdentifier("ks.edit.notes")
                }
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.edit.cancel")
                Button("Save") { commitAndSave() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("ks.edit.save")
            }
        }
        // User decision 5: notes shown to edit are masked again at five minutes if still
        // untouched — which keeps them exactly as stored — the same cap a shown value has in the
        // detail pane and a shown field has in this sheet. Deselecting or locking ends the sheet,
        // and the value with it.
        .task(id: notesShown) {
            guard notesShown != nil else { return }
            try? await Task.sleep(for: EditReveal.lifetime)
            guard !Task.isCancelled else { return }
            if EditReveal.shouldRemask(shown: notesShown, current: draft.notes) {
                draft.notes = nil
                notesUnmasked = false
            }
            notesShown = nil
        }
    }

    /// The stored notes, untouched: masked, with no copy of them in this process.
    private var notesMasked: Bool {
        hasStoredNotes && draft.notes == nil && !notesUnmasked
    }

    private var maskedNotes: some View {
        HStack(spacing: 8) {
            Text("••••••••••")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityLabel(ItemReleases.concealedLabel(String(localized: "notes"), action: String(localized: "Show")))
                .accessibilityIdentifier("ks.edit.notes")
            Button("Show") {
                let releases = store.releases
                let itemId = draft.id
                Task {
                    if let text = await store.attemptReleaseValue({
                        try await releases.notesForEditing(itemId: itemId)
                    }) {
                        draft.notes = text
                        notesUnmasked = true
                        notesShown = text
                    }
                }
            }
            .buttonStyle(.bordered)
            .help("Asks for Touch ID or your Mac password, then shows the notes to edit")
            .accessibilityIdentifier("ks.edit.notesReveal")
            Button("Replace") {
                // `draft.notes` stays `nil` — keep — until something is typed.
                notesUnmasked = true
            }
            .buttonStyle(.bordered)
            .help("Write new notes in place of the stored ones")
            .accessibilityIdentifier("ks.edit.notesReplace")
            Button("Remove", role: .destructive) {
                // `""` is how `save_item` is told to remove them (ADR-0038).
                draft.notes = ""
                notesUnmasked = true
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("ks.edit.notesRemove")
        }
    }

    /// The "Show" behind one already-saved concealed field — its own `EditReveal` release. `nil`
    /// for a field with nothing stored to show: a new row, or a public one.
    private func revealer(for field: FieldDraft) -> (() async -> String?)? {
        guard let fieldId = field.id, field.concealed else { return nil }
        let releases = store.releases
        let itemId = draft.id
        return { [store] in
            await store.attemptReleaseValue {
                try await releases.valueForEditing(itemId: itemId, fieldId: fieldId)
            }
        }
    }

    private static let addableKinds: [(FieldKind, String)] = [
        (.text, String(localized: "Text")),
        (.concealed, String(localized: "Password")),
        (.email, String(localized: "Email")),
        (.url, String(localized: "URL")),
        (.phone, String(localized: "Phone")),
        (.date, String(localized: "Date")),
        (.monthYear, String(localized: "Month / year")),
        (.totp, String(localized: "One-time password")),
        (.creditCardNumber, String(localized: "Card number")),
        (.address, String(localized: "Address")),
    ]

    /// Delete the row identified by `uiId`. Still a position-based removal underneath
    /// (`[EditableField].removingField(at:)`, mirroring `ItemDraft.removingField(at:)`) — `uiId`
    /// only says *which* position that is right now, resolved fresh at the moment of deletion
    /// rather than trusted from a possibly-stale captured index, which is strictly safer than the
    /// index this replaces ever was.
    /// Whether `fieldId` is the field an agent test login's seal depends on.
    static func isSealed(_ fieldId: String?, regenerateOnlyFieldId: String?) -> Bool {
        fieldId != nil && fieldId == regenerateOnlyFieldId
    }

    private func removeField(withId uiId: UUID) {
        guard let index = fieldRows.firstIndex(where: { $0.uiId == uiId }) else { return }
        // The sealed password of an agent test login must stay (ADR-0048): removing it breaks the seal.
        guard !Self.isSealed(fieldRows[index].draft.id, regenerateOnlyFieldId: regenerateOnlyFieldId) else { return }
        fieldRows = fieldRows.removingField(at: index)
    }

    private func addField(kind: FieldKind) {
        fieldRows.append(
            EditableField(
                draft: FieldDraft(
                    id: nil,
                    label: kind == .totp ? "one-time password" : "New field",
                    kind: kind,
                    // A TOTP field stores its `otpauth://` URI, which carries the shared seed, so
                    // it is secret material from the moment the row exists (vault-format.md §5.3).
                    concealed: kind == .concealed || kind == .creditCardNumber || kind == .totp,
                    // A brand-new field has no stored value for `nil` to mean "keep" — `save_item`
                    // refuses one with `nil` (ADR-0038 step 3) — so it always starts as an
                    // explicit, empty value the user then fills in.
                    value: "",
                    section: nil,
                    agentVisible: false)))
    }

    /// Save, but first end whichever text field is still being edited (a multi-line `TextField`
    /// like Notes' does not push its final keystroke into `draft.notes` until it resigns first
    /// responder — clicking Save alone ends editing and calls `save()` in the same click, but
    /// AppKit sometimes only delivers the former on that click, and `save()` would read the
    /// field's value from before the last keystroke). `makeFirstResponder(nil)` commits it
    /// synchronously, so the very first click after typing saves what was typed.
    private func commitAndSave() {
        NSApp.keyWindow?.makeFirstResponder(nil)
        save()
    }

    private func save() {
        var edited = draft
        edited.fields = fieldRows.map(\.draft)
        edited.tags = tagText.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        edited.urls = urlText.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // `edited.notes` goes as it is: `nil` if the sheet never had a note and nobody typed one
        // (keep — there is nothing), a string otherwise, and `""` when the person cleared it,
        // which is how `save_item` is told to remove it. Turning `""` into `nil` here, as this
        // used to, would now mean "keep" and make a note impossible to delete (ADR-0038).
        onSave(edited)
    }
}

private struct FieldEditRow: View {
    @Binding var field: FieldDraft
    /// Fetches this field's stored value behind its own presence prompt (`EditReveal`), for
    /// "Show". `nil` when there is nothing stored to show.
    let reveal: (() async -> String?)?
    /// The sealed password of an agent test login: only "Regenerate" (ADR-0048).
    var regenerateOnly = false
    let onDelete: () -> Void

    /// "Show" put the stored value in the draft and nothing has been typed since. Five minutes
    /// later such a value is masked again (`field.value = nil`, which keeps it as it is), the same
    /// cap a shown value has in the detail pane (user decision 5).
    @State private var shownUntouched = false

    @State private var showGenerator = false
    @State private var showTotpSetup = false
    /// Set once the user presses "Change" on a masked concealed field, and nothing else.
    /// Deliberately independent of `field.value`: pressing "Change" swaps the mask for a text
    /// field but does **not** touch `field.value`, which stays `nil` — "keep the stored value" —
    /// until the person actually types a character into it. Without this flag, `field.value ==
    /// nil` alone could not tell "untouched, still nil" apart from "the row just switched to
    /// editable and nothing has been typed into it yet, also still nil", and the row would snap
    /// straight back to the mask the instant "Change" was pressed.
    ///
    /// This is also why `field.value` is never set to `""` here: a masked field's stored value
    /// is either kept (`nil` reaches `save_item` unchanged) or replaced by something the person
    /// actually typed — an empty string manufactured by this row itself, rather than typed by a
    /// person, must never be what decides that. `save_item` treats an empty value for an already
    /// concealed field the same as `nil` regardless (ADR-0038 step 3's "keeping" rule), so this
    /// is belt-and-braces, not the only thing standing between "Change" and a wiped secret.
    @State private var enteringNewValue = false

    private var isTotp: Bool { field.kind == .totp }

    /// A concealed, previously-saved field the user has not asked to replace: masked, with no
    /// value held anywhere in this process (ADR-0038 step 3, user decision 4). A brand-new field
    /// (`id == nil`) is never masked — `field.value` is always a real, if empty, string for one,
    /// because `save_item` has nothing stored yet to keep.
    private var isMaskedConcealed: Bool {
        field.concealed && field.id != nil && field.value == nil && !enteringNewValue
    }

    /// A two-way `String` binding onto `field.value`, for the plain-text editing controls, which
    /// know nothing about "keep the stored value" — only `nil` at save time means that, and this
    /// row only ever writes a real string into it once the user is actually typing one.
    private var valueBinding: Binding<String> {
        Binding(
            get: { field.value ?? "" },
            set: {
                field.value = $0
                shownUntouched = false
            })
    }

    // Each control's identifier ends in the row's own label. The label is the only stable key a
    // draft row has: `field.id` is nil for a field that has not been saved yet, so it cannot tell
    // one new row from another.
    var body: some View {
        HStack(spacing: 8) {
            TextField("Label", text: $field.label)
                .textFieldStyle(.roundedBorder)
                .frame(width: 140)
                .disabled(regenerateOnly)
                .accessibilityIdentifier("ks.edit.fieldLabel.\(field.label)")

            if isTotp {
                // The stored value is an `otpauth://` URI, and editing one by hand in a text
                // field is how a second factor gets silently broken. The setup sheet edits it
                // instead, with the live preview ui-spec.md §9 asks for. `field.id == nil` is
                // "already configured" here (not `field.value`, which is never prefilled): an
                // existing TOTP field is never opened with its seed in the process at all.
                Button {
                    showTotpSetup = true
                } label: {
                    Label(
                        field.id == nil
                            ? String(localized: "Set up one-time password")
                            : String(localized: "Change one-time password"),
                        systemImage: "clock.badge.checkmark")
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityIdentifier("ks.edit.fieldTotpSetup.\(field.label)")
            } else if regenerateOnly {
                Text("••••••••••")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("ks.edit.fieldValue.\(field.label)")
                Button(field.value == nil ? "Regenerate" : "Regenerated") {
                    if let fresh = try? generatePassword(recipe: GeneratorRecipe.standard) {
                        field.value = fresh
                        shownUntouched = false
                    }
                }
                .buttonStyle(.bordered)
                .help("Replace this password with a new random one. Test logins take no typed password.")
                .accessibilityIdentifier("ks.edit.fieldRegenerate.\(field.label)")
            } else if isMaskedConcealed {
                // A fixed number of dots, same as the read-mode mask: its length must not leak
                // the stored value's length. "Change" is the only door into replacing it — there
                // is no way to reach this row's text field without going through it.
                Text("••••••••••")
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel(ItemReleases.concealedLabel(field.label, action: String(localized: "Show")))
                    .accessibilityIdentifier("ks.edit.fieldValue.\(field.label)")
                if let reveal {
                    Button("Show") {
                        Task {
                            guard let value = await reveal() else { return }
                            field.value = value
                            enteringNewValue = true
                            shownUntouched = true
                        }
                    }
                    .buttonStyle(.bordered)
                    .help("Asks for Touch ID or your Mac password, then shows this value to edit")
                    .accessibilityIdentifier("ks.edit.fieldReveal.\(field.label)")
                }
                Button("Change") {
                    // `field.value` stays `nil` here on purpose — see `enteringNewValue`'s own
                    // doc comment. `valueBinding` shows a `nil` value as an empty text field
                    // regardless, so this reads as "empty" the same way either way.
                    enteringNewValue = true
                }
                .buttonStyle(.bordered)
                .help("Replace this value")
                .accessibilityIdentifier("ks.edit.fieldChange.\(field.label)")
            } else {
                TextField("Value", text: valueBinding)
                    .textFieldStyle(.roundedBorder)
                    .font(field.concealed ? .system(.body, design: .monospaced) : .body)
                    .accessibilityIdentifier("ks.edit.fieldValue.\(field.label)")

                if field.concealed {
                    Button {
                        showGenerator = true
                    } label: {
                        Image(systemName: "die.face.5")
                    }
                    .buttonStyle(.borderless)
                    .help("Generate a password for this field")
                    .accessibilityLabel("Generate a password for \(field.label)")
                    .accessibilityIdentifier("ks.edit.fieldGenerate.\(field.label)")
                }

                Toggle("Concealed", isOn: $field.concealed)
                    .toggleStyle(.checkbox)
                    .help("Store this value as secret material")
                    .accessibilityIdentifier("ks.edit.fieldConcealed.\(field.label)")
            }

            if !regenerateOnly {
                Button(role: .destructive, action: onDelete) {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Remove \(field.label)")
                .accessibilityIdentifier("ks.edit.fieldRemove.\(field.label)")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .task(id: shownUntouched) {
            guard shownUntouched else { return }
            try? await Task.sleep(for: EditReveal.lifetime)
            guard !Task.isCancelled, shownUntouched else { return }
            // Untouched since "Show": masking it again keeps the stored value byte for byte.
            field.value = nil
            enteringNewValue = false
            shownUntouched = false
        }
        .sheet(isPresented: $showGenerator) {
            GeneratorSheet { password in
                field.value = password
                shownUntouched = false
            }
        }
        .sheet(isPresented: $showTotpSetup) {
            // Never prefilled: edit mode shows no concealed value on its own, seeds included
            // (ADR-0038 §5). Reopened over an already-configured field it starts blank, with a
            // "Show current setup" that asks for presence for this one seed.
            TotpSetupSheet(revealExisting: reveal) { uri in
                field.value = uri
                // A one-time-password seed is always secret material, whatever the row's
                // checkbox said before the sheet opened.
                field.concealed = true
            }
        }
    }
}

/// The five-minute cap on a value shown to edit (ADR-0038 user decision 5), shared by the field
/// rows, the notes and a one-time password's setup in the edit sheet.
///
/// At the cap, a value still exactly as "Show" put it is masked again, which keeps the stored
/// value byte for byte (the draft goes back to `nil`, "keep"). A value the person has edited
/// since is theirs — it is what Save will write — and stays.
enum EditReveal {
    /// How long a value shown to edit stays on screen untouched.
    static let lifetime: Duration = .seconds(5 * 60)

    /// Whether a value shown as `shown` and now `current` should be masked again at the cap.
    static func shouldRemask(shown: String?, current: String?) -> Bool {
        guard let shown else { return false }
        return current == shown
    }
}
