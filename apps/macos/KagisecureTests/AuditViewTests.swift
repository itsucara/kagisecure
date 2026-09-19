import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// `AuditView`'s filter logic (ui-spec.md §10.4), pulled out as a pure static function so it can
/// be exercised without a live `VaultStore` or `Table`.
///
/// The Tool picker (mcp-server.md, browser-extension.md) exists so the two M6 tool kinds —
/// filling a credential and reading a live one-time code — are one click away rather than
/// free-text-only, which a burst of denials is the only evidence of a prompt-injection attempt.
@MainActor
struct AuditViewTests {
    private static func row(
        tool: String, outcome: String = "allowed", actor: String = "mcp",
        variables: [String] = [], targetPath: String? = nil, detail: String? = nil
    ) -> AuditRowView {
        AuditRowView(
            seq: 1, timestamp: 1_700_000_000, actor: actor, tool: tool, outcome: outcome,
            environmentId: nil, itemId: nil, variables: variables, targetPath: targetPath,
            detail: detail)
    }

    @Test func theToolFilterIsolatesFillCredential() {
        let rows = [
            Self.row(tool: "fill_credential"),
            Self.row(tool: "totp_code"),
            Self.row(tool: "list_items"),
        ]
        let filtered = AuditView.filteredRows(
            rows, outcome: "all", actor: "all", tool: AuditView.fillCredentialTool, query: "")
        #expect(filtered.map(\.tool) == ["fill_credential"])
    }

    @Test func theToolFilterIsolatesTotpCode() {
        let rows = [
            Self.row(tool: "fill_credential"),
            Self.row(tool: "totp_code"),
            Self.row(tool: "list_items"),
        ]
        let filtered = AuditView.filteredRows(
            rows, outcome: "all", actor: "all", tool: AuditView.totpCodeTool, query: "")
        #expect(filtered.map(\.tool) == ["totp_code"])
    }

    @Test func otherMeansNeitherM6ToolKind() {
        let rows = [
            Self.row(tool: "fill_credential"),
            Self.row(tool: "totp_code"),
            Self.row(tool: "list_items"),
            Self.row(tool: "run_with_env"),
        ]
        let filtered = AuditView.filteredRows(
            rows, outcome: "all", actor: "all", tool: "other", query: "")
        #expect(filtered.map(\.tool) == ["list_items", "run_with_env"])
    }

    @Test func allCombinesWithTheOutcomeAndActorFilters() {
        let rows = [
            Self.row(tool: "fill_credential", outcome: "denied", actor: "mcp"),
            Self.row(tool: "fill_credential", outcome: "allowed", actor: "mcp"),
            Self.row(tool: "fill_credential", outcome: "denied", actor: "app"),
        ]
        let filtered = AuditView.filteredRows(
            rows, outcome: "denied", actor: "mcp", tool: AuditView.fillCredentialTool, query: "")
        #expect(filtered.count == 1)
        #expect(filtered[0].actor == "mcp")
        #expect(filtered[0].outcome == "denied")
    }

    @Test func theToolFilterStillAllowsAFreeTextSearchWithinIt() {
        let rows = [
            Self.row(tool: "fill_credential", targetPath: nil, detail: "no saved website"),
            Self.row(tool: "fill_credential", targetPath: nil, detail: "origin does not match"),
        ]
        let filtered = AuditView.filteredRows(
            rows, outcome: "all", actor: "all", tool: AuditView.fillCredentialTool,
            query: "no saved")
        #expect(filtered.count == 1)
        #expect(filtered[0].detail == "no saved website")
    }
}
