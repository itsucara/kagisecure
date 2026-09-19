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
                    title: store.auditRows.isEmpty ? "Nothing recorded yet" : "Nothing matches",
                    message: store.auditRows.isEmpty
                        ? "Every agent call lands here — allowed, denied, or failed."
                        : "Clear the filters to see everything again.")
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
            footer
        }
        .navigationTitle("Audit")
        .onAppear { store.refreshAudit(limit: Self.pageSize) }
    }

    private var filters: some View {
        HStack(spacing: 12) {
            Picker("Result", selection: $outcomeFilter) {
                Text("All results").tag("all")
                Text("Allowed").tag("allowed")
                Text("Denied").tag("denied")
                Text("Failed").tag("failed")
            }
            .pickerStyle(.menu)
            .frame(width: 160)
            .accessibilityIdentifier("ks.audit.filter.outcome")

            Picker("Caller", selection: $actorFilter) {
                Text("Everyone").tag("all")
                Text("Agents (mcp)").tag("mcp")
                Text("This app").tag("app")
                Text("The CLI").tag("cli")
            }
            .pickerStyle(.menu)
            .frame(width: 160)
            .accessibilityIdentifier("ks.audit.filter.actor")

            Picker("Tool", selection: $toolFilter) {
                Text("All tools").tag("all")
                Text("Fill credential").tag(Self.fillCredentialTool)
                Text("One-time code").tag(Self.totpCodeTool)
                Text("Other").tag("other")
            }
            .pickerStyle(.menu)
            .frame(width: 160)
            .accessibilityIdentifier("ks.audit.filter.tool")

            TextField("Filter by tool, variable or path", text: $query)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("ks.audit.query")

            Button {
                store.refreshAudit(limit: Self.pageSize)
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Reload")
            .accessibilityIdentifier("ks.audit.reload")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var footer: some View {
        HStack(spacing: 6) {
            Image(systemName: store.auditIntact ? "checkmark.seal" : "exclamationmark.triangle.fill")
                .foregroundStyle(store.auditIntact ? .green : .red)
                .accessibilityHidden(true)
            Text(
                store.auditIntact
                    ? "Hash chain intact — \(store.auditTotal) entries, names only, never values."
                    : "The hash chain does not verify. Entries may have been dropped or reordered.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.audit.chainState")
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var rows: [AuditRowView] {
        Self.filteredRows(
            store.auditRows, outcome: outcomeFilter, actor: actorFilter, tool: toolFilter,
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
                && (actor == "all" || row.actor == actor)
                && (tool == "all"
                    || (tool == "other"
                        ? row.tool != fillCredentialTool && row.tool != totpCodeTool
                        : row.tool == tool))
                && (query.isEmpty || matches(row, query.lowercased()))
        }
    }

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
