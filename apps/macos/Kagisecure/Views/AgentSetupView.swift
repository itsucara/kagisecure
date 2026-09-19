import AppKit
import SwiftUI

import KagisecureFFI

/// "Set up your agent" (architecture.md §8, mcp-server.md §9).
///
/// Shows the absolute path to the bundled sidecar for *this* install — which is not knowable from
/// a document, only from the running app — and the exact snippet for each of the four clients,
/// with a copy button. The snippets come from `kagisecure-agent::setup`, the same table
/// `kagisecure mcp install --print` reads, so the app and the CLI cannot drift.
struct AgentSetupView: View {
    @Environment(AgentService.self) private var agent

    @State private var setup: McpSetupView?
    @State private var copied: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                intro
                sidecar
                if let setup {
                    ForEach(Array(setup.snippets.enumerated()), id: \.offset) { _, snippet in
                        snippetBlock(snippet)
                    }
                }
                footer
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .navigationTitle("Set up your agent")
        .onAppear { setup = mcpSetup(bundleHelpersDir: Self.bundleHelpersDirectory()) }
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Let an agent ask")
                .font(.title2.weight(.semibold))
                .accessibilityIdentifier("ks.agentSetup.title")
            Text(
                "kagisecure ships a small MCP server. Your agent spawns it; it talks to this app "
                + "over a local socket; and every injection raises the approval sheet you have to "
                + "put a fingerprint on. The agent never receives a value — only names."
            )
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var sidecar: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("The server binary", systemImage: "shippingbox")
                .font(.subheadline.weight(.semibold))
            if let path = setup?.sidecarPath {
                HStack {
                    Text(path)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.head)
                        .accessibilityIdentifier("ks.agentSetup.sidecarPath")
                    Spacer()
                    copyButton(path, label: path)
                        .accessibilityIdentifier("ks.agentSetup.copy.sidecar")
                }
            } else {
                Label {
                    Text(
                        "kagisecure-mcp was not found next to this app, on your PATH, or at "
                        + "KAGISECURE_MCP. The snippets below show where a normal install puts it; "
                        + "build it with `cargo build -p kagisecure-mcp` if you are running from "
                        + "source, and set KAGISECURE_MCP to the result."
                    )
                    .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .font(.callout)
                .foregroundStyle(.orange)
                .accessibilityIdentifier("ks.agentSetup.sidecarMissing")
            }
            HStack(spacing: 6) {
                Image(systemName: agent.status.running ? "checkmark.circle.fill" : "circle.slash")
                    .foregroundStyle(agent.status.running ? .green : .secondary)
                    .accessibilityHidden(true)
                Text(
                    agent.status.running
                        ? "This app is listening on \(agent.status.endpoint)"
                        : "This app is not listening. Agents will get APP_NOT_RUNNING.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private func snippetBlock(_ snippet: McpSnippetView) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(snippet.title)
                    .font(.headline)
                Text(snippet.language)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
                Spacer()
                copyButton(snippet.body, label: snippet.title)
                    .accessibilityIdentifier("ks.agentSetup.copy.\(slug(snippet.title))")
            }
            if let path = snippet.configPath {
                Text("Put it in \(path)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            } else {
                Text("Claude Code keeps its own registry — run the command instead of editing a file.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(snippet.body)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
        }
        .accessibilityIdentifier("ks.agentSetup.snippet.\(slug(snippet.title))")
    }

    private func copyButton(_ text: String, label: String) -> some View {
        Button {
            // Straight to the pasteboard rather than through `PasteboardService`: this is a
            // configuration snippet, not secret material, and clearing it after a minute would
            // break the one thing the user is about to do with it — paste it into an editor.
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = label
            Task {
                try? await Task.sleep(for: .seconds(2))
                if copied == label { copied = nil }
            }
        } label: {
            Label(copied == label ? "Copied" : "Copy", systemImage: copied == label ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.bordered)
    }

    private var footer: some View {
        Text(
            "The vault must be unlocked for any of this to work. A locked vault answers "
            + "VAULT_LOCKED and kills every lease it had granted."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityIdentifier("ks.agentSetup.footer")
    }

    /// This app's own `Contents/Helpers`, where architecture.md §8 puts the bundled sidecar.
    ///
    /// One implementation, in `ExtensionService`, so the two setup screens cannot come to
    /// different conclusions about where this app keeps its helpers.
    static func bundleHelpersDirectory() -> String? {
        ExtensionService.bundleHelpersDirectory()
    }
}

/// The accessibility-identifier suffix for one client's snippet, e.g. `"Claude Code"` → `claudecode`.
///
/// Derived from the client name rather than hardcoded because the snippet list comes from
/// `kagisecure-agent::setup` over FFI: this screen never knows at compile time which clients are in
/// it, and a hardcoded table would silently stop matching the moment that list gains or renames an
/// entry. Lowercasing and dropping every non-alphanumeric keeps the result ASCII, stable across
/// runs, and unique as long as the client names are.
private func slug(_ s: String) -> String {
    s.lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
}
