import AppKit
import SwiftUI

import KagisecureFFI

/// What an auto-type approval adds to the sheet (ADR-0050 §2): the target app — its icon, name and
/// bundle id — the signing team and window title the agent required, what will be typed, the
/// agent's reason, and the honest statement that the target app receives the value.
struct AutoTypeFactsBlock: View {
    let facts: AutoTypeFactsView

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                if let icon = Self.icon(for: facts.bundleId) {
                    Image(nsImage: icon)
                        .resizable()
                        .frame(width: 32, height: 32)
                        .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(Self.appName(for: facts))
                        .font(.headline)
                    Text(ApprovalSheet.safe(facts.bundleId, limit: 120))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("ks.approval.autoType.app")
            Label {
                Text(Self.notice).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "keyboard")
            }
            .font(.callout.weight(.semibold))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("ks.approval.autoType.notice")
            VStack(alignment: .leading, spacing: 6) {
                ApprovalSheet.row(
                    "Item", "“\(ApprovalSheet.safe(facts.itemTitle, limit: 120))” — \(ApprovalSheet.safe(facts.vaultName, limit: 80))",
                    identifier: "ks.approval.autoType.item")
                ApprovalSheet.row(
                    "Types", Self.fieldsSummary(facts.fields),
                    identifier: "ks.approval.autoType.fields")
                if let team = facts.teamId {
                    ApprovalSheet.row(
                        "Signed by team", ApprovalSheet.safe(team, limit: 20),
                        identifier: "ks.approval.autoType.team")
                }
                if let title = facts.windowTitle {
                    ApprovalSheet.row(
                        "Window title contains", ApprovalSheet.safe(title, limit: 120),
                        identifier: "ks.approval.autoType.window")
                }
                if let reason = facts.reason, !reason.isEmpty {
                    ApprovalSheet.row(
                        "Reason, as written by the agent", ApprovalSheet.safe(reason, limit: 200),
                        identifier: "ks.approval.autoType.reason")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    static let notice = String(
        localized: "kagisecure will type this into the app named here, right where its keyboard focus is. That app receives the value, and an agent that can read that app can read it too.")

    static let summary = String(
        localized: "This types the login once, only if this app is in front with a text field focused. The agent receives only which fields were typed.")

    /// The localized name of the app with `bundleId`, or the bundle id itself when it is not
    /// installed.
    static func appName(for facts: AutoTypeFactsView?) -> String {
        guard let bundleId = facts?.bundleId else { return String(localized: "an app") }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleId) {
            let name = FileManager.default.displayName(atPath: url.path)
            return ApprovalSheet.safe((name as NSString).deletingPathExtension, limit: 80)
        }
        return ApprovalSheet.safe(bundleId, limit: 120)
    }

    static func icon(for bundleId: String) -> NSImage? {
        NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleId)
            .map { NSWorkspace.shared.icon(forFile: $0.path) }
    }

    static func fieldsSummary(_ fields: [String]) -> String {
        if fields == ["one_time_code"] { return String(localized: "A one-time code") }
        if fields == ["username", "password"] {
            return String(localized: "Username, Tab, password")
        }
        if fields == ["password"] { return String(localized: "Password") }
        return String(localized: "Username")
    }

    /// The sentence above the Touch ID prompt: the item and the app, never the agent's name.
    static func reason(for request: ApprovalRequestView) -> String {
        let title = ApprovalSheet.safe(request.autoType?.itemTitle ?? request.itemTitle ?? String(localized: "a login"))
        let app = appName(for: request.autoType)
        return String(localized: "let an agent type “\(title)” into \(app). Continue only if you asked an agent to sign in there")
    }
}
