import SwiftUI

import KagisecureFFI

/// The detail pane (ui-spec.md §4): header, fields grouped by section, notes, and the
/// kagisecure-specific Agent access panel.
struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    @Bindable var store: VaultStore
    let item: ItemView

    @State private var editing = false
    @State private var draft: ItemDraft?
    /// The field row keyboard focus is on, for ⌘R ("reveal the focused concealed field",
    /// ui-spec.md §11). Mirrored into `VaultStore.focusedFieldId`, where the menu command reads it.
    @FocusState private var focusedField: String?
    /// Shown when `store.save(draft:)` throws `FfiError.ItemChangedElsewhere` (user decision 4):
    /// another window, the CLI or another process saved this item after the sheet opened.
    @State private var showChangedElsewhereAlert = false
    /// "Delete…" on a shared item: confirmed, since it deletes the item for everyone.
    @State private var confirmSharedDelete = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if editing, let draft {
                    ItemEditView(
                        store: store,
                        draft: draft,
                        hasStoredNotes: item.hasNotes,
                        onCancel: { editing = false },
                        onSave: { saved in
                            do {
                                try store.save(draft: saved)
                                editing = false
                            } catch FfiError.ItemChangedElsewhere {
                                showChangedElsewhereAlert = true
                            } catch {
                                model.errorMessage = describeAnyError(error)
                            }
                        })
                } else {
                    fields
                    notes
                    agentAccess
                }
            }
            .padding(24)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .toolbar { toolbar }
        .accessibilityIdentifier("ks.item.root")
        .onChange(of: model.editRequest) { _, _ in
            if store.canEditItems { beginEditing() }
        }
        .confirmationDialog(
            "Delete “\(item.title)” for everyone?", isPresented: $confirmSharedDelete,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                store.attempt { try store.setTrashed(item, true) }
            }
            .accessibilityIdentifier("ks.item.sharedDelete.confirm")
        } message: {
            Text("It is removed from this shared vault on every member's Mac.")
        }
        .onChange(of: item.id) { _, _ in editing = false }
        .onChange(of: focusedField) { _, focused in store.focusedFieldId = focused }
        .alert(
            "This item changed elsewhere",
            isPresented: $showChangedElsewhereAlert
        ) {
            Button("Reload") {
                editing = false
                draft = nil
                store.refresh()
            }
            .accessibilityIdentifier("ks.alert.itemChangedElsewhere.reload")
        } message: {
            Text("This item was changed elsewhere — reload.")
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: item.categorySymbol)
                    .font(.title)
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(.title2.weight(.semibold))
                        .accessibilityIdentifier("ks.item.title")
                    Text(item.categoryDisplayName)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.item.category")
                }
                Spacer()
                Button {
                    store.attempt { try store.toggleFavorite(item) }
                } label: {
                    Image(systemName: item.favorite ? "star.fill" : "star")
                        .foregroundStyle(item.favorite ? AnyShapeStyle(.yellow) : AnyShapeStyle(.secondary))
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(item.favorite ? Text("Favorited") : Text("Not favorited"))
                .accessibilityIdentifier("ks.item.favorite")
            }

            if !item.tags.isEmpty {
                HStack(spacing: 6) {
                    ForEach(item.tags, id: \.self) { tag in
                        Text(tag)
                            .font(.caption)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(.quaternary, in: Capsule())
                            .accessibilityIdentifier("ks.item.tag.\(tag)")
                    }
                }
            }

            if item.trashed {
                Label("In the Trash", systemImage: "trash")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.item.trashedBadge")
            } else if item.archived {
                Label("Archived", systemImage: "archivebox")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.item.archivedBadge")
            }
        }
    }

    // MARK: - Fields

    private var sections: [(String, [FieldView])] {
        var order: [String] = []
        var grouped: [String: [FieldView]] = [:]
        for field in item.fields {
            let key = field.section ?? ""
            if grouped[key] == nil { order.append(key) }
            grouped[key, default: []].append(field)
        }
        return order.map { ($0, grouped[$0] ?? []) }
    }

    @ViewBuilder
    private var fields: some View {
        if item.fields.isEmpty {
            Text("This item has no fields yet. Press ⌘E to add some.")
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.item.noFields")
        } else {
            ForEach(sections, id: \.0) { name, fields in
                VStack(alignment: .leading, spacing: 0) {
                    if !name.isEmpty {
                        Text(name.uppercased())
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.bottom, 6)
                            .accessibilityIdentifier("ks.item.section.\(name)")
                    }
                    VStack(spacing: 0) {
                        ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { Divider() }
                            FieldRow(store: store, item: item, field: field)
                                .focusable(field.concealed && field.hasValue)
                                .focused($focusedField, equals: field.id)
                        }
                    }
                    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    /// The item's notes (user decision 3: every note is secret). Masked until the person asks,
    /// then shown from a `NotesRelease` — one touch — until deselect, lock or five minutes.
    /// Copying them needs no second touch while they are shown.
    @ViewBuilder
    private var notes: some View {
        if item.hasNotes {
            let releases = store.releases
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("NOTES")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        store.attemptRelease { try await releases.toggleNotes(item: item) }
                    } label: {
                        Image(systemName: releases.notesText == nil ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.borderless)
                    .disabled(releases.pending != nil)
                    .help(releases.notesText == nil ? Text("Show the notes") : Text("Hide the notes"))
                    .accessibilityLabel(releases.notesText == nil ? Text("Show notes") : Text("Hide notes"))
                    .accessibilityIdentifier("ks.item.notesReveal")
                    Button {
                        store.attemptRelease { try await releases.copyNotes(item: item) }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .disabled(releases.pending != nil)
                    .help(releases.notesText == nil ? Text("Copy without showing") : Text("Copy"))
                    .accessibilityLabel("Copy notes")
                    .accessibilityIdentifier("ks.item.notesCopy")
                }
                Group {
                    if let text = releases.notesText {
                        // No `.textSelection`: selection would let ⌘C, a drag or the Services
                        // menu take the notes past the concealed clipboard and its clear
                        // (ADR-0038 surface #2). The copy button is the way out.
                        Text(text)
                            .accessibilityIdentifier("ks.item.notes")
                    } else {
                        Text("••••••••••")
                            .foregroundStyle(.secondary)
                            .accessibilityLabel(ItemReleases.concealedLabel(String(localized: "notes"), action: String(localized: "Show")))
                            .accessibilityIdentifier("ks.item.notes")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    // MARK: - Agent access (ui-spec.md §4.4)

    private var agentAccess: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("AGENT ACCESS")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            Toggle(
                "Visible to agents",
                isOn: Binding(
                    get: { item.agentVisible },
                    set: { visible in store.attempt { try store.setAgentVisible(item, visible) } })
            )
            .toggleStyle(.switch)
            .accessibilityIdentifier("ks.item.agentVisible")

            Text(
                "Agents can see this item's title, category, tags and field *names* — never values — over MCP, and can request approved actions (like writing a .env) using it."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            // A shared item's switches are this Mac's own (ADR-0035 §14): kept in this Mac's copy
            // of the shared vault and never sent to the other members.
            if store.sharedVaultId != nil {
                Text(
                    "This is this Mac's setting only: other members decide for their own Macs, and nothing here is sent to them."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.item.agentAccess.thisMacOnly")
            }

            if item.agentVisible {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(item.fields, id: \.id) { field in
                        Toggle(
                            field.label,
                            isOn: Binding(
                                get: { field.agentVisible },
                                set: { visible in
                                    store.attempt {
                                        try store.setFieldAgentVisible(item, field, visible)
                                    }
                                })
                        )
                        .toggleStyle(.checkbox)
                        .font(.callout)
                        .accessibilityIdentifier("ks.item.fieldAgentVisible.\(field.label)")
                    }
                }
                .padding(.leading, 4)
            }

            Text("Last used by an agent: never")
                .font(.footnote)
                .foregroundStyle(.tertiary)
                .accessibilityIdentifier("ks.item.lastUsedByAgent")
                .help("No agent can connect until the MCP integration ships (roadmap M4).")
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem {
            Button {
                if editing { editing = false } else { beginEditing() }
            } label: {
                Label(editing ? String(localized: "Done") : String(localized: "Edit"), systemImage: editing ? "checkmark" : "pencil")
            }
            .help(editing ? Text("Leave edit mode") : Text("Edit this item (⌘E)"))
            .disabled(!store.canEditItems)
            .accessibilityIdentifier("ks.toolbar.edit")
        }
        ToolbarItem {
            Menu {
                if store.sharedVaultId != nil {
                    // A shared vault has no Archive or Trash of its own (ui-spec.md §16.6).
                    Button("Delete…", role: .destructive) { confirmSharedDelete = true }
                        .disabled(!store.canEditItems)
                        .accessibilityIdentifier("ks.item.menu.sharedDelete")
                } else if item.trashed {
                    Button("Restore") { store.attempt { try store.setTrashed(item, false) } }
                        .accessibilityIdentifier("ks.item.menu.restore")
                    Button("Delete Permanently", role: .destructive) {
                        store.attempt { try store.deleteForever(item) }
                    }
                    .accessibilityIdentifier("ks.item.menu.deleteForever")
                } else {
                    Button(item.archived ? String(localized: "Move out of Archive") : String(localized: "Move to Archive")) {
                        store.attempt { try store.setArchived(item, !item.archived) }
                    }
                    .accessibilityIdentifier("ks.item.menu.archive")
                    Button("Move to Trash") { store.attempt { try store.setTrashed(item, true) } }
                        .accessibilityIdentifier("ks.item.menu.trash")
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
            .accessibilityIdentifier("ks.toolbar.more")
        }
    }

    private func beginEditing() {
        draft = ItemDraft(
            id: item.id,
            category: item.category,
            title: item.title,
            fields: item.fields.map { field in
                FieldDraft(
                    id: field.id,
                    label: field.label,
                    kind: field.kind,
                    concealed: field.concealed,
                    // Edit mode never prefills a concealed value (ADR-0038 step 3, user decision
                    // 4): `nil` tells `save_item` to keep this field's stored value untouched, so
                    // a failed or never-attempted reveal cannot turn into an overwrite with an
                    // empty string. `FieldView.value` is already `nil` for every concealed field
                    // (it is only ever populated for a public one), so this is just carrying that
                    // straight through — nothing is fetched, and no secret, including a TOTP
                    // seed, enters this process to build the draft.
                    value: field.concealed ? nil : field.value,
                    section: field.section,
                    agentVisible: field.agentVisible)
            },
            tags: item.tags,
            urls: item.urls,
            // `nil` keeps the stored note (ADR-0038: `ItemDraft.notes` is "keep" when absent,
            // "clear" when empty). Not prefilled, like every other secret (user decision 4): the
            // sheet shows the notes only if the person asks, through their own release.
            notes: nil,
            revision: item.revision)
        editing = true
    }
}

/// One field row in read mode (ui-spec.md §4.2).
///
/// A concealed value is masked until the person asks, and then shown from a `FieldRelease` — one
/// presence prompt, for this field only (user decision 1). Copy uses the shown value's release
/// with no new touch, or a one-use copy release with one.
private struct FieldRow: View {
    @Bindable var store: VaultStore
    let item: ItemView
    let field: FieldView
    @State private var hovering = false

    private var releases: ItemReleases { store.releases }
    private var shown: Bool { releases.isShown(field) }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(field.label)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)
                .accessibilityIdentifier("ks.item.fieldLabel.\(field.label)")

            value
                .frame(maxWidth: .infinity, alignment: .leading)

            // A TOTP row carries its own show and copy controls: the code is what is shown, and
            // the seed behind it is an edit-mode operation.
            if isTotp {
                EmptyView()
            } else if field.concealed && field.hasValue {
                Button {
                    store.attemptRelease {
                        try await releases.toggleReveal(item: item, field: field)
                    }
                } label: {
                    Image(systemName: shown ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .disabled(releases.pending != nil)
                .help(shown ? Text("Conceal (⌘R)") : Text("Reveal (⌘R)"))
                .accessibilityLabel(shown ? Text("Conceal \(field.label)") : Text("Reveal \(field.label)"))
                .accessibilityIdentifier("ks.item.fieldReveal.\(field.label)")
            }

            if field.hasValue && !isTotp {
                Button {
                    store.attemptRelease { try await releases.copy(item: item, field: field) }
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .disabled(field.concealed && releases.pending != nil)
                .opacity(hovering ? 1 : 0.35)
                .help(field.concealed && !shown ? Text("Copy without revealing") : Text("Copy"))
                .accessibilityLabel("Copy \(field.label)")
                .accessibilityIdentifier("ks.item.fieldCopy.\(field.label)")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }

    /// A configured one-time password: the kind says so, and there is a seed to derive from.
    private var isTotp: Bool {
        field.kind == .totp && field.hasValue
    }

    @ViewBuilder
    private var value: some View {
        if isTotp {
            TotpFieldView(store: store, item: item, field: field)
        } else if !field.hasValue {
            (field.kind == .totp ? Text("Not set up — press ⌘E to add one") : Text(verbatim: "—"))
                .foregroundStyle(.tertiary)
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        } else if field.concealed {
            if let revealed = releases.shownValue(field) {
                // No `.textSelection`: selecting a released value would let ⌘C, a drag or the
                // Services menu carry it past the concealed pasteboard type and the timed clear
                // (ADR-0038 surface #2). The copy button is the one way out.
                Text(revealed)
                    .font(.system(.body, design: .monospaced))
                    .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
            } else {
                // A fixed number of dots: the mask must not leak the value's length — and nor may
                // the label VoiceOver reads instead of it.
                Text("••••••••••")
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(ItemReleases.concealedLabel(field.label))
                    .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
            }
        } else if field.kind == .url, let value = field.value, let url = URL(string: value) {
            Link(value, destination: url)
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        } else if field.kind == .email, let value = field.value,
            let url = URL(string: "mailto:\(value)")
        {
            Link(value, destination: url)
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        } else {
            PublicFieldText(value: field.value ?? "")
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        }
    }
}
