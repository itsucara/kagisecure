import SwiftUI

import KagisecureFFI

/// Agent access → Audit (mcp-server.md §6, ui-spec.md §10.4).
///
/// Every tool call, whether it succeeded, was denied, or errored. Denials are kept deliberately: a
/// burst of them is the only evidence a user will ever have that a prompt injection tried an
/// exfiltration, so the filter defaults to everything and "Denied" is one click away.
///
/// Entries carry names, never values — enforced in `kagisecure-core`, not here.
struct AuditView: View {
    @Bindable var store: VaultStore

    @State private var outcomeFilter: String = "all"
    @State private var actorFilter: String = "all"
    @State private var toolFilter: String = "all"
    @State private var query = ""
    /// Which log: the personal vault's, or the machine vault's (ADR-0042 §8).
    @State private var log: AuditLog = .personal
    @State private var machineRows: [AuditRowView] = []
    @State private var machineProblem: String?

    /// The two logs the view can show.
    enum AuditLog: Hashable {
        case personal
        case machine
    }

    private static let pageSize: UInt32 = 500

    /// The M6 tool kinds (mcp-server.md, browser-extension.md): filling a credential into a page,
    /// and reading a live one-time code. Called out explicitly in the Tool picker rather than
    /// left to free-text search, because they are the two calls that move a secret toward a page
    /// an agent does not otherwise touch.
    static let fillCredentialTool = "fill_credential"
    static let totpCodeTool = "totp_code"

    var body: some View {
        VStack(spacing: 0) {
            filters
            Divider()
            if rows.isEmpty {
                EmptyStateView(
                    symbol: "list.bullet.rectangle.portrait",
                    title: sourceRows.isEmpty ? String(localized: "Nothing recorded yet") : String(localized: "Nothing matches"),
                    message: sourceRows.isEmpty
                        ? String(localized: "Every agent call lands here — allowed, denied, or failed.")
                        : String(localized: "Clear the filters to see everything again."))
                    .accessibilityIdentifier("ks.audit.empty")
            } else {
                Table(rows) {
                    TableColumn("When") { row in
                        Text(Self.timestamp(row.timestamp))
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .width(150)
                    TableColumn("Who") { row in
                        Text(row.actor)
                            .font(.callout)
                    }
                    .width(60)
                    // Every row's tool and outcome cell carries the same identifier: an audit entry
                    // has no stable user-visible key to interpolate, so a test picks the row it
                    // means by the cell's own label.
                    TableColumn("Action") { row in
                        Text(row.tool)
                            .font(.system(.callout, design: .monospaced))
                            .accessibilityIdentifier("ks.audit.cell.tool")
                    }
                    .width(150)
                    TableColumn("Result") { row in
                        Label(row.outcome, systemImage: symbol(row.outcome))
                            .foregroundStyle(colour(row.outcome))
                            .font(.callout)
                            .accessibilityIdentifier("ks.audit.cell.outcome")
                    }
                    .width(90)
                    TableColumn("Detail") { row in
                        Text(detail(row))
                            .font(.callout)
                            .lineLimit(1)
                            .help(detail(row))
                    }
                }
                .accessibilityIdentifier("ks.audit.table")
            }
            Divider()
            if log == .personal {
                footer
            } else {
                Text(
                    machineProblem
                        ?? String(localized: "The machine vault's log: what unattended jobs did, and what you decided about them.")
                )
                .font(.caption)
                .foregroundStyle(machineProblem == nil ? Color.secondary : Color.red)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityIdentifier("ks.audit.machineState")
            }
        }
        .navigationTitle("Audit")
        .onAppear { reload() }
        .onChange(of: log) { _, _ in reload() }
    }

    private var sourceRows: [AuditRowView] {
        log == .personal ? store.auditRows : machineRows
    }

    private func reload() {
        switch log {
        case .personal:
            store.refreshAudit(limit: Self.pageSize)
        case .machine:
            do {
                machineRows = try unattendedAuditPage(
                    session: store.session, limit: Self.pageSize, offset: 0)
                machineProblem = nil
            } catch {
                machineRows = []
                machineProblem = describeAnyError(error)
            }
        }
    }

    /// The search field on one row and the three pickers under it.
    ///
    /// One row of all five needed about 590 points before the search field got any, and the
    /// detail column of a 1040-point window is about 460 (the item list stays beside it): the
    /// field was squeezed to nothing and the row ran off the window. The pickers also give way,
    /// down to their own minimum, rather than holding a fixed width each.
    private var filters: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                TextField("Filter by tool, variable or path", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 120)
                    .accessibilityIdentifier("ks.audit.query")

                Picker("Log", selection: $log) {
                    Text("Personal vault").tag(AuditLog.personal)
                    Text("Machine vault").tag(AuditLog.machine)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .accessibilityIdentifier("ks.audit.log")

                Button {
                    reload()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Reload")
                .accessibilityIdentifier("ks.audit.reload")
            }
            pickers
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var pickers: some View {
        HStack(spacing: 12) {
            Picker("Result", selection: $outcomeFilter) {
                Text("All results").tag("all")
                Text("Allowed").tag("allowed")
                Text("Denied").tag("denied")
                Text("Failed").tag("failed")
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 160)
            .accessibilityIdentifier("ks.audit.filter.outcome")

            Picker("Caller", selection: $actorFilter) {
                Text("Everyone").tag("all")
                Text("Agents (mcp)").tag("mcp")
                Text("Unattended").tag(Self.unattendedActor)
                Text("This app").tag("app")
                Text("The CLI").tag("cli")
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 160)
            .accessibilityIdentifier("ks.audit.filter.actor")

            Picker("Tool", selection: $toolFilter) {
                Text("All tools").tag("all")
                Text("Fill credential").tag(Self.fillCredentialTool)
                Text("One-time code").tag(Self.totpCodeTool)
                Text("Other").tag("other")
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 160)
            .accessibilityIdentifier("ks.audit.filter.tool")

            Spacer(minLength: 0)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(
                    systemName: store.auditIntact
                        ? "checkmark.seal" : "exclamationmark.triangle.fill"
                )
                .foregroundStyle(store.auditIntact ? .green : .red)
                .accessibilityHidden(true)
                (store.auditIntact
                    ? Text("Hash chain intact — \(Int(store.auditTotal)) entries, names only, never values.")
                    : Text("The hash chain does not verify. Entries may have been dropped or reordered."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.audit.chainState")
                Spacer()
            }
            // Distinct from the chain check above: the chain check only asks whether what *is*
            // on disk is internally consistent. This asks whether disk has everything that has
            // been appended in memory at all — the gap a save that keeps failing (a hostile
            // `chflags uchg` on the vault directory, a full disk) leaves behind.
            if store.auditUnsavedEntries > 0 {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .accessibilityHidden(true)
                    Text(saveWarning)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("ks.audit.saveState")
                    Spacer()
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    /// "N audit entries are not saved to disk yet — the last save failed: <reason>".
    private var saveWarning: String {
        let count = store.auditUnsavedEntries
        guard let reason = store.auditSaveError else {
            return count == 1
                ? String(localized: "1 audit entry is not saved to disk yet.")
                : String(localized: "\(Int(count)) audit entries are not saved to disk yet.")
        }
        return count == 1
            ? String(localized: "1 audit entry is not saved to disk yet — the last save failed: \(reason)")
            : String(localized: "\(Int(count)) audit entries are not saved to disk yet — the last save failed: \(reason)")
    }

    private var rows: [AuditRowView] {
        Self.filteredRows(
            sourceRows, outcome: outcomeFilter, actor: actorFilter, tool: toolFilter,
            query: query)
    }

    /// The filter's actual logic, pulled out of the view so it can run in a test without a live
    /// `VaultStore` or `Table`.
    ///
    /// `tool == "other"` means "anything but the tool kinds the picker names explicitly" — the
    /// picker offers `fill_credential` and `totp_code` by name (M6) and lumps the rest, rather
    /// than hardcoding every MCP tool the audit log has ever recorded a call for.
    static func filteredRows(
        _ rows: [AuditRowView], outcome: String, actor: String, tool: String, query: String
    ) -> [AuditRowView] {
        rows.filter { row in
            (outcome == "all" || row.outcome == outcome)
                && (actor == "all" || actorMatches(row.actor, actor))
                && (tool == "all"
                    || (tool == "other"
                        ? row.tool != fillCredentialTool && row.tool != totpCodeTool
                        : row.tool == tool))
                && (query.isEmpty || matches(row, query.lowercased()))
        }
    }

    /// Whether a row's actor belongs under the Caller filter `actor`.
    ///
    /// Agents are a prefix match: every agent actor starts with `mcp`, and an agent fill's carries
    /// the agent's name, pid and browser after it (ADR-0036, implementation decision 7). Every
    /// other filter is exact.
    static func actorMatches(_ rowActor: String, _ actor: String) -> Bool {
        switch actor {
        case "mcp": rowActor.hasPrefix("mcp")
        // A request from a run (`mcp unattended "<job>" run …`) and what the engine wrote on its
        // own behalf (`unattended`) — ADR-0042 §8.
        case Self.unattendedActor:
            rowActor.hasPrefix("mcp unattended") || rowActor == Self.unattendedActor
        default: rowActor == actor
        }
    }

    /// The Caller filter's tag, and the actor the engine records its own entries under.
    static let unattendedActor = "unattended"

    static func matches(_ row: AuditRowView, _ needle: String) -> Bool {
        row.tool.lowercased().contains(needle)
            || row.variables.contains { $0.lowercased().contains(needle) }
            || (row.targetPath?.lowercased().contains(needle) ?? false)
            || (row.detail?.lowercased().contains(needle) ?? false)
    }

    private func detail(_ row: AuditRowView) -> String {
        var parts: [String] = []
        if !row.variables.isEmpty { parts.append(row.variables.joined(separator: ", ")) }
        if let path = row.targetPath { parts.append(path) }
        if let detail = row.detail { parts.append(detail) }
        return parts.joined(separator: "  ·  ")
    }

    private func symbol(_ outcome: String) -> String {
        switch outcome {
        case "allowed": "checkmark.circle"
        case "denied": "hand.raised"
        default: "exclamationmark.circle"
        }
    }

    private func colour(_ outcome: String) -> Color {
        switch outcome {
        case "allowed": .green
        case "denied": .orange
        default: .red
        }
    }

    /// Local time, to the second. Sortable rather than pretty: an audit log is read by scanning
    /// for a moment, not by reading a sentence.
    static func timestamp(_ unix: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(unix))
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }
}
