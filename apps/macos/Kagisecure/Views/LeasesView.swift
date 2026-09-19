import SwiftUI

import KagisecureFFI

/// Agent access → Leases (ui-spec.md §10.4, mcp-server.md §5).
///
/// The only place leases are visible, because they are the only place they exist: memory-only,
/// never written to disk, and gone on expiry, use exhaustion, lock, sleep or revoke. The countdown
/// is live off `AgentService.now`, so a lease that runs out disappears while you are looking at it
/// rather than when something happens to refresh.
struct LeasesView: View {
    @Environment(AgentService.self) private var agent
    @Environment(ExtensionService.self) private var ext

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            agentLeases
            if !ext.fillLeases.isEmpty {
                Divider()
                fillLeases
            }
        }
        .navigationTitle("Leases")
        .toolbar {
            Button("Revoke All") {
                agent.revokeAll()
                ext.revokeAll()
            }
            .disabled(agent.leases.isEmpty && ext.fillLeases.isEmpty)
            .help("Drop every lease, shred every file they wrote, and make the next browser fill ask again")
            .accessibilityIdentifier("ks.leases.revokeAll")
        }
    }

    /// The browser-extension half (M6).
    ///
    /// A separate table rather than extra columns on the one above, because a fill lease is a
    /// different thing: it is scoped to an origin and an item, it has no use counter, and what it
    /// grants is "no second fingerprint", not "an injection may happen". Merging them would need
    /// four columns that are empty half the time.
    private var fillLeases: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Browser fills")
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .accessibilityIdentifier("ks.fillLeases.heading")
            // Every fill-lease row's cells share one identifier per column: a lease is
            // memory-only and has no stable user-visible key, so a test tells the rows apart by
            // the website and item their cells read.
            Table(ext.fillLeases) {
                TableColumn("Website") { lease in
                    Text(lease.origin)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.head)
                        .help(lease.origin)
                        .accessibilityIdentifier("ks.fillLeases.cell.website")
                }
                TableColumn("Item") { lease in
                    Text(lease.itemTitle)
                        .font(.callout)
                        .lineLimit(1)
                        .accessibilityIdentifier("ks.fillLeases.cell.item")
                }
                TableColumn("Browser") { lease in
                    Text(lease.clientIdentity)
                        .font(.callout)
                        .lineLimit(1)
                        .help(lease.clientIdentity)
                        .accessibilityIdentifier("ks.fillLeases.cell.browser")
                }
                TableColumn("Expires in") { lease in
                    Text(remainingFill(lease))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(isUrgentFill(lease) ? .red : .primary)
                        .accessibilityIdentifier("ks.fillLeases.cell.expires")
                }
                .width(90)
                TableColumn("") { lease in
                    Button("Revoke") { ext.revoke(lease) }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("ks.fillLeases.revoke")
                }
                .width(70)
            }
            .frame(minHeight: 120)
            .accessibilityIdentifier("ks.fillLeases.table")
        }
    }

    private func remainingFill(_ lease: FillLeaseView) -> String {
        let seconds = Double(lease.expiresAt) - agent.now.timeIntervalSince1970
        if seconds <= 0 { return "expired" }
        return ApprovalSheet.duration(UInt64(seconds))
    }

    private func isUrgentFill(_ lease: FillLeaseView) -> Bool {
        Double(lease.expiresAt) - agent.now.timeIntervalSince1970 < 60
    }

    @ViewBuilder
    private var agentLeases: some View {
        Group {
            if agent.leases.isEmpty && ext.fillLeases.isEmpty {
                EmptyStateView(
                    symbol: "clock.badge.checkmark",
                    title: "No active leases",
                    message:
                        "A lease is minted when you approve an injection or a browser fill, and "
                        + "dies on expiry, use exhaustion, or when the vault locks. Nothing is "
                        + "granted right now.")
                    .accessibilityIdentifier("ks.leases.empty")
            } else if !agent.leases.isEmpty {
                // As in the fill-lease table below: one identifier per column, shared by every
                // row, because a lease has no stable user-visible key. Tests pick a row by the
                // caller, directory or variables its cells read.
                Table(agent.leases) {
                    TableColumn("Caller") { lease in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(caller(lease))
                                .lineLimit(1)
                            Text(lease.kind == "env-file" ? ".env file" : "command")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityIdentifier("ks.leases.cell.caller")
                    }
                    TableColumn("Directory") { lease in
                        Text(lease.directory)
                            .font(.system(.callout, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.head)
                            .help(lease.directory)
                            .accessibilityIdentifier("ks.leases.cell.directory")
                    }
                    TableColumn("Variables") { lease in
                        Text(lease.variables.joined(separator: ", "))
                            .font(.callout)
                            .lineLimit(1)
                            .help(lease.variables.joined(separator: ", "))
                            .accessibilityIdentifier("ks.leases.cell.variables")
                    }
                    TableColumn("Expires in") { lease in
                        Text(remaining(lease))
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(isUrgent(lease) ? .red : .primary)
                            .accessibilityIdentifier("ks.leases.cell.expires")
                    }
                    .width(90)
                    TableColumn("Uses left") { lease in
                        Text("\(lease.usesRemaining)")
                            .font(.callout.monospacedDigit())
                            .accessibilityIdentifier("ks.leases.cell.uses")
                    }
                    .width(70)
                    TableColumn("") { lease in
                        Button("Revoke") { agent.revoke(lease) }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("ks.leases.revoke")
                    }
                    .width(70)
                }
                .accessibilityIdentifier("ks.leases.table")
            }
        }
    }

    /// The caller as the agent library rendered it, trimmed to the part a table cell can show.
    private func caller(_ lease: LeaseView) -> String {
        lease.clientIdentity
    }

    private func remaining(_ lease: LeaseView) -> String {
        let seconds = Double(lease.expiresAt) - agent.now.timeIntervalSince1970
        if seconds <= 0 { return "expired" }
        return ApprovalSheet.duration(UInt64(seconds))
    }

    private func isUrgent(_ lease: LeaseView) -> Bool {
        Double(lease.expiresAt) - agent.now.timeIntervalSince1970 < 60
    }
}
