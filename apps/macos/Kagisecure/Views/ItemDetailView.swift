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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if editing, let draft {
                    ItemEditView(
                        store: store,
                        draft: draft,
                        onCancel: { editing = false },
                        onSave: { saved in
                            do {
                                try store.save(draft: saved)
                                editing = false
                            } catch {
                                model.errorMessage = error.localizedDescription
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
        .onChange(of: model.editRequest) { _, _ in beginEditing() }
        .onChange(of: item.id) { _, _ in editing = false }
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
                    try? store.toggleFavorite(item)
                } label: {
                    Image(systemName: item.favorite ? "star.fill" : "star")
                        .foregroundStyle(item.favorite ? AnyShapeStyle(.yellow) : AnyShapeStyle(.secondary))
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(item.favorite ? "Favorited" : "Not favorited")
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
                        }
                    }
                    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    @ViewBuilder
    private var notes: some View {
        if let notes = item.notes, !notes.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("NOTES")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(notes)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
                    .accessibilityIdentifier("ks.item.notes")
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
                    set: { try? store.setAgentVisible(item, $0) })
            )
            .toggleStyle(.switch)
            .accessibilityIdentifier("ks.item.agentVisible")

            Text(
                "Agents can see this item's title, category, tags and field *names* — never "
                    + "values — over MCP, and can request approved actions (like writing a .env) "
                    + "using it."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            if item.agentVisible {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(item.fields, id: \.id) { field in
                        Toggle(
                            field.label,
                            isOn: Binding(
                                get: { field.agentVisible },
                                set: { try? store.setFieldAgentVisible(item, field, $0) })
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
                Label(editing ? "Done" : "Edit", systemImage: editing ? "checkmark" : "pencil")
            }
            .help(editing ? "Leave edit mode" : "Edit this item (⌘E)")
            .accessibilityIdentifier("ks.toolbar.edit")
        }
        ToolbarItem {
            Menu {
                if item.trashed {
                    Button("Restore") { try? store.setTrashed(item, false) }
                        .accessibilityIdentifier("ks.item.menu.restore")
                    Button("Delete Permanently", role: .destructive) {
                        try? store.deleteForever(item)
                    }
                    .accessibilityIdentifier("ks.item.menu.deleteForever")
                } else {
                    Button(item.archived ? "Move out of Archive" : "Move to Archive") {
                        try? store.setArchived(item, !item.archived)
                    }
                    .accessibilityIdentifier("ks.item.menu.archive")
                    Button("Move to Trash") { try? store.setTrashed(item, true) }
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
                    // Edit mode shows a concealed field's real value so a typo can be fixed
                    // without a separate reveal step (ui-spec.md §4.3). The value is fetched
                    // per field, through the same one-at-a-time call the reveal button uses.
                    value: field.concealed
                        ? ((try? store.session.revealField(itemId: item.id, fieldId: field.id))
                            ?? "")
                        : (field.value ?? ""),
                    section: field.section,
                    agentVisible: field.agentVisible)
            },
            tags: item.tags,
            urls: item.urls,
            notes: item.notes)
        editing = true
    }
}

/// One field row in read mode (ui-spec.md §4.2).
private struct FieldRow: View {
    @Bindable var store: VaultStore
    let item: ItemView
    let field: FieldView
    @State private var hovering = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(field.label)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: 130, alignment: .leading)
                .accessibilityIdentifier("ks.item.fieldLabel.\(field.label)")

            value
                .frame(maxWidth: .infinity, alignment: .leading)

            // A TOTP row carries its own copy button and has nothing to reveal: the code is
            // already on screen, and revealing the seed is an edit-mode operation.
            if isTotp {
                EmptyView()
            } else if field.concealed && field.hasValue {
                Button {
                    try? store.toggleReveal(item: item, field: field)
                } label: {
                    Image(systemName: store.isRevealed(field) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(store.isRevealed(field) ? "Conceal" : "Reveal (⌘R)")
                .accessibilityLabel(store.isRevealed(field) ? "Conceal value" : "Reveal value")
                .accessibilityIdentifier("ks.item.fieldReveal.\(field.label)")
            }

            if field.hasValue && !isTotp {
                Button {
                    try? store.copy(item: item, field: field)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .opacity(hovering ? 1 : 0.35)
                .help("Copy without revealing")
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
            Text(field.kind == .totp ? "Not set up — press ⌘E to add one" : "—")
                .foregroundStyle(.tertiary)
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        } else if field.concealed {
            if let revealed = store.revealedValue(field) {
                Text(revealed)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
            } else {
                // A fixed number of dots: the mask must not leak the value's length.
                Text("••••••••••")
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("\(field.label), concealed, activate to reveal")
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
            Text(field.value ?? "")
                .textSelection(.enabled)
                .accessibilityIdentifier("ks.item.fieldValue.\(field.label)")
        }
    }
}
