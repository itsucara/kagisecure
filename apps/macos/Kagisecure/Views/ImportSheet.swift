import SwiftUI

import KagisecureFFI

/// The import preview sheet (import.md §8, ui-spec.md §15).
///
/// # There are no values on this screen
///
/// Not "there are no values shown" — there are none *available*. Everything here comes from an
/// `ImportReportView`, which is a projection of the parsed plan into names, kinds and counts; the
/// plan itself stays behind the FFI boundary and is never handed over. A column of passwords
/// could not be added to the per-item table without first inventing a way to get one across
/// (`crates/kagisecure-ffi/src/import.rs`).
///
/// # Identifiers go on leaves
///
/// ui-spec.md §15 and e2e-harness.md §7.2: an identifier on a SwiftUI layout container is stamped
/// onto every leaf inside it. So `ks.import.sheet` sits on the sheet's title — the one leaf that
/// only this screen has — and every other identifier is on the control or the text it names. The
/// exception is `ks.import.detailTable`, which is on a real `Table` and keeps it to itself.
struct ImportSheet: View {
    @Environment(AppModel.self) private var appModel
    @Environment(\.dismiss) private var dismiss

    /// The open vault. Used for the session the import runs against, and for category names.
    @Bindable var store: VaultStore

    @State private var model: ImportModel

    init(store: VaultStore, sourcePath: String) {
        self.store = store
        _model = State(initialValue: ImportModel(session: store.session, sourcePath: sourcePath))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 720)
        .frame(minHeight: 560)
        .task {
            if case .idle = model.phase { model.load() }
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Import")
                .font(.title2.weight(.semibold))
                // The sheet's marker. A leaf, not the enclosing stack — see the type's header.
                .accessibilityIdentifier("ks.import.sheet")

            HStack(spacing: 8) {
                Image(systemName: "doc.text")
                    .foregroundStyle(.secondary)
                Text(model.sourcePath)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.head)
                    .textSelection(.enabled)
                    .help(model.sourcePath)
                    .accessibilityLabel("Source file")
                    .accessibilityValue(model.sourcePath)
                    .accessibilityIdentifier("ks.import.sourcePath")
            }

            Picker("Format", selection: $model.formatOverride) {
                Text("Detect automatically").tag(ImportFormat?.none)
                ForEach(model.formats, id: \.id) { info in
                    Text(info.displayName).tag(ImportFormat?.some(info.format))
                }
            }
            .pickerStyle(.menu)
            .fixedSize()
            .disabled(!canChangeFormat)
            .help("Override the format if this file was not recognised.")
            .accessibilityIdentifier("ks.import.format")
        }
        .padding(20)
    }

    private var canChangeFormat: Bool {
        switch model.phase {
        case .previewing, .failed, .choosing: true
        default: false
        }
    }

    // MARK: - Body

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .idle, .choosing:
            busy("Reading the file…")
        case .previewing(let report):
            preview(report)
        case .committing:
            busy("Importing…")
        case .done, .shredPrompt, .finished:
            resultPane
        case .failed(let message):
            failure(message)
        }
    }

    private func busy(_ label: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(label).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - The preview

    private func preview(_ report: ImportReportView) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                totals(report)
                duplicates(report)
                categories(report)
                dropped()
                decisions(report)
                detailTable(report)
            }
            .padding(20)
        }
    }

    private func totals(_ report: ImportReportView) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(report.totals.items) item\(report.totals.items == 1 ? "" : "s") to import")
                .font(.headline)
                .accessibilityIdentifier("ks.import.totalItems")
            // Password history *is* imported (import.md §2.7). It is a count here and nowhere
            // else: a list of retired passwords is exactly what a report may not carry.
            Text(
                "\(report.totals.historyEntries) password-history "
                    + "\(report.totals.historyEntries == 1 ? "entry" : "entries") to import"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            Text(
                "\(report.totals.fieldsMapped) fields mapped, "
                    + "\(report.totals.fieldsPreserved) kept as metadata"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
        }
    }

    private func duplicates(_ report: ImportReportView) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(duplicateSentence(report))
                .font(.callout)
                .accessibilityIdentifier("ks.import.duplicates")

            Picker("Items this vault already has", selection: $model.policy) {
                Text("Skip them").tag(DuplicatePolicyView.skip)
                Text("Update them").tag(DuplicatePolicyView.update)
                Text("Keep both").tag(DuplicatePolicyView.keepBoth)
            }
            .pickerStyle(.segmented)
            .fixedSize()
            .accessibilityIdentifier("ks.import.duplicatePolicy")

            Text(policyExplanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func duplicateSentence(_ report: ImportReportView) -> String {
        guard report.vaultAware else { return "Checking this vault for items it already has…" }
        if report.duplicates == 0 {
            return "No duplicates — this vault has none of these items yet."
        }
        return "\(report.duplicates) of these are already in this vault."
    }

    private var policyExplanation: String {
        switch model.policy {
        case .skip:
            "Existing items are left exactly as they are. Nothing is overwritten."
        case .update:
            "Existing items take the source's fields and keep what only this vault knows — your "
                + "tags, agent visibility and environment bindings. History is merged, not replaced."
        case .keepBoth:
            "Existing items are left alone and the imported ones are added beside them, with "
                + "today's date in the title."
        }
    }

    private func categories(_ report: ImportReportView) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("By category").font(.headline)
            ForEach(report.byCategory, id: \.category) { entry in
                Text("\(store.displayName(forCategory: entry.category)): \(entry.items)")
                    .font(.callout)
                    .accessibilityIdentifier("ks.import.category.\(entry.category)")
            }
        }
    }

    /// The three counters import.md §8 requires, each with its one-line explanation.
    ///
    /// Shown at zero as well, and never as a bare badge: a number with no sentence beside it is
    /// the thing ui-spec.md §13 says not to do, and a counter that disappears when it is zero is
    /// a counter a reader cannot trust.
    private func dropped() -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Not imported").font(.headline)
            droppedRow(.attachment, "Attachments", "ks.import.droppedAttachments")
            droppedRow(.passkey, "Passkeys", "ks.import.droppedPasskeys")
            droppedRow(
                .passwordHistory, "Unreadable history entries", "ks.import.droppedHistory")
        }
    }

    private func droppedRow(
        _ kind: ImportDropKindView, _ title: String, _ identifier: String
    ) -> some View {
        let note = model.dropped(kind)
        let count = note?.count ?? 0
        let explanation = note?.explanation ?? Self.explanation(for: kind)
        return Text("\(title): \(count) — \(explanation)")
            .font(.callout)
            .foregroundStyle(count == 0 ? .secondary : .primary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier(identifier)
    }

    /// What to say about a counter the report did not mention, which means it is zero.
    ///
    /// The wording is the core's (`DropKind::explanation`) whenever there is a note to read it
    /// from; these are the same sentences for the empty case, so a zero counter explains itself
    /// rather than going quiet.
    private static func explanation(for kind: ImportDropKindView) -> String {
        switch kind {
        case .attachment:
            "kagisecure items do not hold files yet; keep these in the source app"
        case .passkey:
            "passkeys cannot be exported meaningfully; keep them where they are"
        case .passwordHistory:
            "password history is imported; this counts only entries with no readable value or "
                + "timestamp"
        default:
            ""
        }
    }

    @ViewBuilder
    private func decisions(_ report: ImportReportView) -> some View {
        if !report.decisions.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("Notes").font(.headline)
                ForEach(report.decisions, id: \.code) { decision in
                    Text(decision.detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func detailTable(_ report: ImportReportView) -> some View {
        let rows = report.items.enumerated().map { ImportTableRow(id: $0.offset, row: $0.element) }
        return VStack(alignment: .leading, spacing: 6) {
            Text("Every item").font(.headline)
            Table(rows) {
                TableColumn("Title") { Text($0.row.title) }
                TableColumn("Category") { row in
                    Text(
                        row.row.categoryWasGuessed
                            ? "\(store.displayName(forCategory: row.row.category)) (guessed)"
                            : store.displayName(forCategory: row.row.category))
                }
                TableColumn("Action") { Text(Self.actionName($0.row.action)) }
                TableColumn("Not imported") { Text(Self.droppedSummary($0.row)) }
            }
            // A real `Table`, so the identifier stays on it instead of being stamped onto every
            // cell (e2e-harness.md §7.2).
            .accessibilityIdentifier("ks.import.detailTable")
            .frame(minHeight: 220)
        }
    }

    private static func actionName(_ action: ImportItemActionView?) -> String {
        switch action {
        case .create: "Add"
        case .update: "Update"
        case .skip: "Skip"
        case .keepBoth: "Keep both"
        case nil: "—"
        }
    }

    private static func droppedSummary(_ row: ImportItemRow) -> String {
        row.dropped.isEmpty
            ? "—" : row.dropped.map { "\($0.name) ×\($0.count)" }.joined(separator: ", ")
    }

    // MARK: - The result, and the source file

    @ViewBuilder
    private var resultPane: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let outcome = model.outcome {
                    Label(outcome.headline, systemImage: "checkmark.circle")
                        .font(.headline)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.import.result")

                    if !outcome.vaultsCreated.isEmpty {
                        Text(
                            "Created vault\(outcome.vaultsCreated.count == 1 ? "" : "s"): "
                                + outcome.vaultsCreated.joined(separator: ", ")
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    }

                    Text(
                        "\(outcome.historyAdded) password-history "
                            + "\(outcome.historyAdded == 1 ? "entry" : "entries") imported"
                    )
                    .font(.callout)
                    .foregroundStyle(.secondary)
                }

                if case .shredPrompt = model.phase {
                    shredPrompt
                }
                if case .finished(_, let sentence) = model.phase {
                    Text(sentence)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(20)
        }
    }

    /// The offer, with the caveat on screen *before* the button is pressed (import.md §9).
    private var shredPrompt: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Delete the source file?")
                .font(.headline)
                .accessibilityIdentifier("ks.import.shredPrompt")
            Text(
                "\(model.sourceName) is a complete, unencrypted copy of everything you just "
                    + "imported. \(model.shredWarning)"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                Button("Delete the file") { model.shredSource() }
                    .accessibilityIdentifier("ks.import.shredConfirm")
                Button("Keep it") { model.keepSource() }
                    .accessibilityIdentifier("ks.import.shredSkip")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Failure

    private func failure(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(message, systemImage: "exclamationmark.triangle")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.import.error")
            Text(
                "Nothing was imported and your vault is unchanged. Try naming the format above, "
                    + "or choose a different file."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Button("Try again") { model.retry() }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(20)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Spacer()
            if model.hasCommitted {
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("ks.import.confirm")
            } else {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.import.cancel")
                Button("Import") {
                    model.commit()
                    if model.outcome != nil { appModel.noteImportCommitted() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canImport)
                .accessibilityIdentifier("ks.import.confirm")
            }
        }
        .padding(20)
    }
}

/// A row of the per-item table.
///
/// `Table` needs `Identifiable` and `ImportItemRow` is a generated record; the index is the
/// identity because the report's order is the plan's order and does not change while the sheet is
/// open.
private struct ImportTableRow: Identifiable {
    let id: Int
    let row: ImportItemRow
}
