import SwiftUI

import KagisecureFFI

/// What a "store command output" approval adds to the sheet's generic command, directory,
/// environment and variable blocks (ADR-0049 §3): where the output would be stored, the plain
/// statement that it becomes a secret the agent never sees, the timeout and the agent's reason
/// (labelled as the agent's words).
///
/// Metadata only. The output does not exist yet when this is on screen.
struct StoreCommandOutputFactsBlock: View {
    let facts: StoreOutputFactsView

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                Text(Self.notice)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "lock.doc")
            }
            .font(.callout.weight(.semibold))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("ks.approval.storeOutput.notice")
            VStack(alignment: .leading, spacing: 6) {
                ApprovalSheet.row(
                    "Store in", Self.targetSummary(facts),
                    identifier: "ks.approval.storeOutput.target")
                ApprovalSheet.row(
                    "Field", Self.fieldSummary(facts),
                    identifier: "ks.approval.storeOutput.field")
                ApprovalSheet.row(
                    "Time limit", Self.timeoutSummary(facts),
                    identifier: "ks.approval.storeOutput.timeout")
                if let reason = facts.reason, !reason.isEmpty {
                    ApprovalSheet.row(
                        "Reason, as written by the agent", ApprovalSheet.safe(reason, limit: 200),
                        identifier: "ks.approval.storeOutput.reason")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    static let notice = "What this command prints becomes a stored secret. The agent will not see it."

    static func targetSummary(_ facts: StoreOutputFactsView) -> String {
        let title = ApprovalSheet.safe(facts.itemTitle, limit: 120)
        let vault = ApprovalSheet.safe(facts.vaultName, limit: 80)
        if facts.itemId == nil {
            let category = ApprovalSheet.safe(facts.newItemCategory ?? "api-credential", limit: 40)
            return "New item “\(title)” (\(category)) in vault “\(vault)”"
        }
        return "Existing item “\(title)” in vault “\(vault)”"
    }

    static func fieldSummary(_ facts: StoreOutputFactsView) -> String {
        let label = ApprovalSheet.safe(facts.fieldLabel, limit: 64)
        if facts.itemId == nil { return "“\(label)” (new, concealed)" }
        return facts.fillsEmptyField
            ? "“\(label)” (existing, empty — will be filled)"
            : "“\(label)” (new, concealed — will be added)"
    }

    static func timeoutSummary(_ facts: StoreOutputFactsView) -> String {
        "\(facts.timeoutSeconds) second\(facts.timeoutSeconds == 1 ? "" : "s")"
    }

    /// The target phrase for the sentence and the Touch ID prompt.
    static func leadTarget(_ facts: StoreOutputFactsView?) -> String {
        ApprovalSheet.safe(facts?.itemTitle ?? "an item", limit: 80)
    }
}
