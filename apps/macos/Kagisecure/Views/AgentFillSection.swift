import AppKit
import SwiftUI

import KagisecureFFI

/// Agent access → Agent fills (ui-spec.md §10.4, ADR-0036 §2 and §9).
///
/// Three things, top to bottom:
///
/// * **The switch**, "Let agents ask to fill logins in your browser". Off by default. Turning it on
///   asks for Touch ID or the login password (`AgentFillService.setEnabled`) and stays off if that
///   is cancelled; turning it off asks nothing. Under it, one sentence of what the feature does and
///   ADR-0036 §8.2's caveat — an agent that can run script in the page can read what was typed.
/// * **Blocked agents**, each with its reported name in quotation marks (it is what the agent
///   said), the program the block is keyed on, why, until when, and an Unblock button.
/// * **Recent notices** — what happened without a sheet: an origin mismatch, an agent over its
///   budget, an agent blocked by its second mismatch. Seeing this section clears the menu-bar
///   badge.
///
/// Metadata only, like every agent surface: names, titles, origins. No value is anywhere here.
struct AgentFillSection: View {
    @Environment(AgentFillService.self) private var agentFill

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            toggle
            if let problem = agentFill.switchProblem {
                Text(problem)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("ks.agentAccess.agentFill.switchProblem")
            }
            if !agentFill.blocks.isEmpty {
                blocks
            }
            if !agentFill.recent.isEmpty {
                notices
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { markSeenIfLooking() }
        .onChange(of: agentFill.unseen) { _, _ in markSeenIfLooking() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            markSeenIfLooking()
        }
    }

    /// The badge is for notices nobody has seen; this section on screen in the active app is
    /// someone seeing them.
    private func markSeenIfLooking() {
        if NSApp.isActive { agentFill.markSeen() }
    }

    // MARK: - The switch

    private var toggle: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text("Agent fills")
                    .font(.callout.weight(.semibold))
                    .accessibilityIdentifier("ks.agentAccess.agentFill.heading")
                Spacer()
                if agentFill.switching {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityIdentifier("ks.agentAccess.agentFill.switching")
                }
                Toggle(
                    "Let agents ask to fill logins in your browser",
                    isOn: Binding(
                        get: { agentFill.enabled },
                        set: { on in Task { await agentFill.setEnabled(on) } })
                )
                .toggleStyle(.switch)
                .disabled(agentFill.switching)
                .help(
                    agentFill.enabled
                        ? String(localized: "Turn off to answer every agent's fill request with “unavailable”")
                        : String(localized: "Turn on to let agents fill saved logins in your browser"))
                .accessibilityIdentifier("ks.agentAccess.agentFill.switch")
            }
            Text(Self.explanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.agentAccess.agentFill.explanation")
        }
    }

    /// What the feature does, in one sentence, then ADR-0036 §8.2's caveat.
    static let explanation = String(
        localized: "An agent can ask kagisecure to type a saved login into a browser tab on the login's site, even one in the background. Once you have confirmed with Touch ID or your login password, fills go through without asking again until the grace period ends or the vault locks. kagisecure never gives the agent a value — but an agent that can run script in that page can read what was typed there.")

    // MARK: - Blocks

    private var blocks: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Blocked agents")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.agentAccess.agentFill.blocksHeading")
            // As in the lease tables: one identifier per column, shared by every row. A block's
            // key is a path, and a test tells rows apart by the name and program they read.
            ForEach(agentFill.blocks, id: \.key) { block in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Image(systemName: "hand.raised.fill")
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(AgentFillText.quoted(block.agentName))
                            .font(.callout)
                            .accessibilityIdentifier("ks.agentAccess.agentFill.blockAgent")
                        Text("Started by \(ApprovalSheet.safe(block.key, limit: 200))")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.head)
                            .help(block.key)
                            .accessibilityIdentifier("ks.agentAccess.agentFill.blockProgram")
                        Text(
                            "\(AgentFillText.reason(block.reason)) · \(AgentFillText.until(block.until))"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.agentAccess.agentFill.blockReason")
                    }
                    Spacer()
                    Button("Unblock") { agentFill.unblock(block) }
                        .help("Let this agent ask for fills again. Each fill still asks you first.")
                        .accessibilityIdentifier("ks.agentAccess.agentFill.unblock")
                }
            }
        }
    }

    // MARK: - Notices

    private var notices: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Recent notices")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.agentAccess.agentFill.noticesHeading")
                Spacer()
                Button("Clear") { agentFill.clearNotices() }
                    .buttonStyle(.borderless)
                    .font(.caption)
                    .help("Empty this list. The audit log keeps every one.")
                    .accessibilityIdentifier("ks.agentAccess.agentFill.clearNotices")
            }
            ForEach(agentFill.recent) { record in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(record.receivedAt.formatted(date: .omitted, time: .shortened))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(AgentFillText.title(for: record.notice))
                            .font(.caption.weight(.medium))
                        Text(AgentFillText.body(for: record.notice))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("ks.agentAccess.agentFill.notice")
            }
        }
    }
}
