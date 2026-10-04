import AppKit
import SwiftUI

/// "Connect your browsers" (ui-spec.md §6.5): offered once per launch after an unlock, listing
/// the browsers on this Mac that Kagisecure cannot fill in yet.
struct BrowserConnectSheet: View {
    @Environment(BrowserConnectModel.self) private var prompt
    /// Opens the main window's Browser extension pane; `nil` hides the link.
    var showSetup: (() -> Void)?

    private var allConnected: Bool { prompt.offered.allSatisfy(\.connected) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 24)
                .padding(.top, 24)
                .padding(.bottom, 18)
            VStack(spacing: 0) {
                ForEach(Array(prompt.offered.enumerated()), id: \.element.id) { index, browser in
                    if index > 0 { Divider().padding(.leading, 64) }
                    BrowserConnectRow(browser: browser)
                }
            }
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(.separator, lineWidth: 0.5))
            .padding(.horizontal, 24)
            footer
                .padding(.horizontal, 24)
                .padding(.vertical, 18)
        }
        .frame(width: 480)
        .onAppear { prompt.sheetAppeared() }
        // `.contain` keeps the children's identifiers (title, Later, Connect…); without it the
        // container's identifier is stamped onto every child.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("ks.browserPrompt")
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            SettingsIconTile(symbol: "puzzlepiece.extension.fill", tint: .blue, size: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text("Fill passwords in your browsers")
                    .font(.title3.weight(.semibold))
                    .accessibilityIdentifier("ks.browserPrompt.title")
                Text("Kagisecure isn't connected to these browsers yet. Connect one and your logins are a click away on every site.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var footer: some View {
        HStack {
            if let showSetup {
                Button("More setup options…", action: showSetup)
                    .buttonStyle(.link)
                    .font(.callout)
                    .accessibilityIdentifier("ks.browserPrompt.moreOptions")
            }
            Spacer()
            if allConnected {
                Button("Done") { prompt.dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("ks.browserPrompt.done")
            } else {
                Button("Later") { prompt.dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.browserPrompt.later")
            }
        }
        .controlSize(.large)
    }
}

private struct BrowserConnectRow: View {
    @Environment(BrowserConnectModel.self) private var prompt
    let browser: BrowserCandidate

    var body: some View {
        @Bindable var prompt = prompt
        HStack(alignment: .center, spacing: 12) {
            BrowserIcon(url: browser.appURL)
            VStack(alignment: .leading, spacing: 4) {
                Text(browser.name)
                    .font(.body.weight(.medium))
                if browser.connected {
                    Text("Ready to fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Toggle(isOn: Binding(
                        get: { prompt.dontAsk.contains(browser.id) },
                        set: { if $0 { prompt.dontAsk.insert(browser.id) } else { prompt.dontAsk.remove(browser.id) } })
                    ) {
                        Text("Don't ask about this browser again")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .accessibilityIdentifier("ks.browserPrompt.dontAsk.\(browser.id)")
                }
            }
            Spacer(minLength: 8)
            if browser.connected {
                Label("Connected", systemImage: "checkmark.circle.fill")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("ks.browserPrompt.connected.\(browser.id)")
            } else {
                Button("Connect") { prompt.connect(browser) }
                    .buttonStyle(.borderedProminent)
                    .disabled(prompt.dontAsk.contains(browser.id))
                    .accessibilityIdentifier("ks.browserPrompt.connect.\(browser.id)")
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .animation(.easeInOut(duration: 0.2), value: browser.connected)
    }
}

/// The browser's own app icon, or a globe when the app could not be located.
struct BrowserIcon: View {
    let url: URL?
    var size: CGFloat = 38

    var body: some View {
        Group {
            if let url {
                Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                    .resizable()
                    .interpolation(.high)
            } else {
                Image(systemName: "globe")
                    .resizable()
                    .scaledToFit()
                    .padding(size * 0.15)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
