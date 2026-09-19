import SwiftUI

import KagisecureFFI

/// Edit mode (ui-spec.md §4.3): inline field editing, add/remove fields, ⌘S to save, Esc to
/// cancel.
///
/// The draft is local state. Nothing reaches the vault until Save, so Cancel is genuinely free —
/// there is no partially-applied edit to undo.
struct ItemEditView: View {
    @Bindable var store: VaultStore
    @State var draft: ItemDraft
    let onCancel: () -> Void
    let onSave: (ItemDraft) -> Void

    @State private var tagText: String
    @State private var urlText: String

    init(
        store: VaultStore, draft: ItemDraft, onCancel: @escaping () -> Void,
        onSave: @escaping (ItemDraft) -> Void
    ) {
        self.store = store
        self._draft = State(initialValue: draft)
        self.onCancel = onCancel
        self.onSave = onSave
        self._tagText = State(initialValue: draft.tags.joined(separator: ", "))
        self._urlText = State(initialValue: draft.urls.joined(separator: "\n"))
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
                // Indexed, not `id: \.id`. A draft field has no id until the vault mints one, so
                // two newly added rows are indistinguishable by identity — which made `ForEach`
                // ambiguous and made deletion delete the wrong rows. See
                // `ItemDraft.removingField(at:)`.
                ForEach(Array(draft.fields.indices), id: \.self) { index in
                    FieldEditRow(field: $draft.fields[index]) {
                        removeField(at: index)
                    }
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
                    "Where the browser extension may fill this item. Subdomains of the same site "
                    + "count; a different scheme or port does not."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            LabeledContent("Notes") {
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

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.edit.cancel")
                Button("Save") { save() }
                    .keyboardShortcut("s", modifiers: .command)
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("ks.edit.save")
            }
        }
    }

    private static let addableKinds: [(FieldKind, String)] = [
        (.text, "Text"),
        (.concealed, "Password"),
        (.email, "Email"),
        (.url, "URL"),
        (.phone, "Phone"),
        (.date, "Date"),
        (.monthYear, "Month / year"),
        (.totp, "One-time password"),
        (.creditCardNumber, "Card number"),
        (.address, "Address"),
    ]

    /// Delete one row. See `ItemDraft.removingField(at:)` for why it is by position.
    private func removeField(at index: Int) {
        draft = draft.removingField(at: index)
    }

    private func addField(kind: FieldKind) {
        draft.fields.append(
            FieldDraft(
                id: nil,
                label: kind == .totp ? "one-time password" : "New field",
                kind: kind,
                // A TOTP field stores its `otpauth://` URI, which carries the shared seed, so it
                // is secret material from the moment the row exists (vault-format.md §5.3).
                concealed: kind == .concealed || kind == .creditCardNumber || kind == .totp,
                value: "",
                section: nil,
                agentVisible: false))
    }

    private func save() {
        var edited = draft
        edited.tags = tagText.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        edited.urls = urlText.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        edited.notes = (edited.notes?.isEmpty ?? true) ? nil : edited.notes
        onSave(edited)
    }
}

private struct FieldEditRow: View {
    @Binding var field: FieldDraft
    let onDelete: () -> Void

    @State private var showGenerator = false
    @State private var showTotpSetup = false

    private var isTotp: Bool { field.kind == .totp }

    // Each control's identifier ends in the row's own label. The label is the only stable key a
    // draft row has: `field.id` is nil for a field that has not been saved yet, so it cannot tell
    // one new row from another.
    var body: some View {
        HStack(spacing: 8) {
            TextField("Label", text: $field.label)
                .textFieldStyle(.roundedBorder)
                .frame(width: 140)
                .accessibilityIdentifier("ks.edit.fieldLabel.\(field.label)")

            if isTotp {
                // The stored value is an `otpauth://` URI, and editing one by hand in a text
                // field is how a second factor gets silently broken. The setup sheet edits it
                // instead, with the live preview ui-spec.md §9 asks for.
                Button {
                    showTotpSetup = true
                } label: {
                    Label(
                        field.value.isEmpty ? "Set up one-time password" : "Change one-time password",
                        systemImage: "clock.badge.checkmark")
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityIdentifier("ks.edit.fieldTotpSetup.\(field.label)")
            } else {
                // A concealed field shows its value in edit mode, for the one field being edited
                // (ui-spec.md §4.3) — fixing a typo should not need a separate reveal step.
                TextField("Value", text: $field.value)
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

            Button(role: .destructive, action: onDelete) {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Remove \(field.label)")
            .accessibilityIdentifier("ks.edit.fieldRemove.\(field.label)")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .sheet(isPresented: $showGenerator) {
            GeneratorSheet { password in field.value = password }
        }
        .sheet(isPresented: $showTotpSetup) {
            TotpSetupSheet(existingUri: field.value) { uri in
                field.value = uri
                // A one-time-password seed is always secret material, whatever the row's
                // checkbox said before the sheet opened.
                field.concealed = true
            }
        }
    }
}
