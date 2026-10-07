import KagisecureFFI
import SwiftUI

struct ItemDetailView: View {
    let store: VaultStore
    let itemId: String
    let onDeleted: () -> Void
    @State private var revealed: [String: String] = [:]
    @State private var notes: String?
    @State private var editing: ItemEditModel?
    @State private var confirmingDelete = false
    @State private var message: String?
    @State private var copied: String?
    /// One-time-password releases currently showing a code, by field id.
    @State private var totps: [String: TotpRelease] = [:]
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if let item = store.items.first(where: { $0.id == itemId }) {
                content(item)
            } else {
                ContentUnavailableView("Item not found", systemImage: "questionmark")
            }
        }
    }

    private func content(_ item: ItemView) -> some View {
        List {
            ForEach(sections(of: item), id: \.name) { section in
                Section(section.name) {
                    ForEach(section.fields, id: \.id) { field in
                        if field.kind == .totp {
                            totpRow(item, field)
                        } else {
                            fieldRow(item, field)
                        }
                    }
                }
            }
            if !item.urls.isEmpty {
                Section("Websites") {
                    ForEach(item.urls, id: \.self) { Text($0).textSelection(.enabled) }
                }
            }
            if !item.tags.isEmpty {
                Section("Tags") { Text(item.tags.joined(separator: ", ")) }
            }
            if item.hasNotes {
                Section("Notes") {
                    if let notes {
                        Text(notes).privacySensitive()
                    } else {
                        Button("Show Notes") {
                            run { notes = try await store.revealNotes(item) }
                        }
                    }
                }
            }
            Section {
                Button(store.isShared(item.id) ? "Delete for Everyone…" : "Delete Item", role: .destructive) {
                    confirmingDelete = true
                }
                .disabled(!store.canEdit(item.id))
                .accessibilityIdentifier("detail.delete")
            }
        }
        .navigationTitle(item.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    do { try store.toggleFavorite(item) } catch { message = AppModel.message(for: error) }
                } label: {
                    Image(systemName: item.favorite ? "star.fill" : "star")
                }
                .accessibilityIdentifier("detail.favorite")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button("Edit") {
                    revealed = [:]
                    hideTotps()
                    editing = ItemEditModel(item: store.item(id: item.id) ?? item)
                }
                .disabled(!store.canEdit(item.id))
                .accessibilityIdentifier("detail.edit")
            }
        }
        .sheet(item: $editing) { model in
            ItemEditSheet(store: store, model: model) { editing = nil }
        }
        .confirmationDialog(
            store.isShared(item.id)
                ? "Delete “\(item.title)” for everyone?" : "Move “\(item.title)” to Trash?",
            isPresented: $confirmingDelete, titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                do {
                    try store.delete(item)
                    onDeleted()
                } catch { message = AppModel.message(for: error) }
            }
            .accessibilityIdentifier("detail.confirmDelete")
        } message: {
            if store.isShared(item.id) {
                Text("It is removed from every member's copy of the shared vault. There is no shared Trash.")
            }
        }
        .alert("Error", isPresented: .constant(message != nil)) {
            Button("OK") { message = nil }
        } message: { Text(message ?? "") }
        .overlay(alignment: .bottom) {
            if let copied {
                Text("Copied \(copied) — clears in 60 s")
                    .font(.caption).padding(8).background(.thinMaterial, in: Capsule())
                    .padding()
            }
        }
        .onDisappear { revealed = [:]; notes = nil; hideTotps() }
        // Leaving the app hides what was shown: coming back within the auto-lock time must not
        // find a password or a one-time password still on screen.
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { revealed = [:]; notes = nil; hideTotps() }
        }
    }

    @ViewBuilder
    private func fieldRow(_ item: ItemView, _ field: FieldView) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(field.label).font(.caption).foregroundStyle(.secondary)
            HStack {
                if field.concealed {
                    if let value = revealed[field.id] {
                        Text(value).font(.system(.body, design: .monospaced)).privacySensitive()
                            .accessibilityIdentifier("field.\(field.label).value")
                    } else {
                        Text(field.hasValue ? "••••••••" : "—")
                            .accessibilityIdentifier("field.\(field.label).masked")
                    }
                } else {
                    Text(field.value ?? "").textSelection(.enabled)
                        .accessibilityIdentifier("field.\(field.label).value")
                }
                Spacer()
                if field.concealed && field.hasValue {
                    Button {
                        if revealed[field.id] != nil {
                            revealed[field.id] = nil
                        } else {
                            run { revealed[field.id] = try await store.reveal(item, field: field) }
                        }
                    } label: {
                        Image(systemName: revealed[field.id] == nil ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("field.\(field.label).reveal")
                }
                if field.hasValue {
                    Button {
                        run {
                            try await store.copy(item, field: field)
                            copied = field.label
                            try? await Task.sleep(for: .seconds(2))
                            copied = nil
                        }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("field.\(field.label).copy")
                }
            }
        }
    }

    @ViewBuilder
    private func totpRow(_ item: ItemView, _ field: FieldView) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(field.label).font(.caption).foregroundStyle(.secondary)
            HStack {
                if let release = totps[field.id] {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        if let code = try? release.codeAt(at: UInt64(context.date.timeIntervalSince1970)) {
                            HStack {
                                Text(Self.grouped(code.code))
                                    .font(.system(.title3, design: .monospaced))
                                    .privacySensitive()
                                    .accessibilityIdentifier("totp.code")
                                Spacer()
                                TotpCountdown(remaining: code.secondsRemaining, period: code.params.period)
                            }
                        } else {
                            Text("••• •••").accessibilityIdentifier("totp.masked")
                                .onAppear { totps[field.id]?.close(); totps[field.id] = nil }
                        }
                    }
                } else {
                    Text(field.hasValue ? "••• •••" : "Not set up")
                        .accessibilityIdentifier("totp.masked")
                    Spacer()
                }
                if field.hasValue {
                    Button {
                        if let release = totps.removeValue(forKey: field.id) {
                            release.close()
                        } else {
                            run { totps[field.id] = try await store.releaseTotp(item, field: field, purpose: .reveal) }
                        }
                    } label: {
                        Image(systemName: totps[field.id] == nil ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(totps[field.id] == nil ? "Show the one-time password" : "Hide the one-time password")
                    .accessibilityIdentifier("totp.reveal")
                    Button {
                        run {
                            try await store.copyTotp(item, field: field, shown: totps[field.id])
                            copied = field.label
                            try? await Task.sleep(for: .seconds(2))
                            copied = nil
                        }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Copy the one-time password")
                    .accessibilityIdentifier("totp.copy")
                }
            }
        }
    }

    private func hideTotps() {
        for release in totps.values { release.close() }
        totps = [:]
    }

    /// "123456" → "123 456", as on the Mac.
    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<mid]) \(code[mid...])"
    }

    private func run(_ body: @escaping @MainActor () async throws -> Void) {
        Task { @MainActor in
            do { try await body() } catch { message = AppModel.message(for: error) }
        }
    }

    struct FieldSection { let name: String; let fields: [FieldView] }

    private func sections(of item: ItemView) -> [FieldSection] {
        var order: [String] = []
        var grouped: [String: [FieldView]] = [:]
        for field in item.fields {
            let name = field.section ?? ""
            if grouped[name] == nil { order.append(name) }
            grouped[name, default: []].append(field)
        }
        return order.map { FieldSection(name: $0, fields: grouped[$0] ?? []) }
    }
}

/// The ring around the seconds left in this code's window.
struct TotpCountdown: View {
    let remaining: UInt32
    let period: UInt32

    var body: some View {
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: period == 0 ? 0 : CGFloat(remaining) / CGFloat(period))
                .stroke(remaining <= 5 ? Color.red : Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(verbatim: "\(remaining)").font(.caption2.monospacedDigit())
        }
        .frame(width: 28, height: 28)
        .accessibilityElement()
        .accessibilityLabel(Text("\(remaining) seconds left"))
        .accessibilityIdentifier("totp.countdown")
    }
}
