import AppKit
import SwiftUI

import KagisecureFFI

/// "Browser extension" (M6, `docs/browser-extension.md` §5).
///
/// The setup screen for autofill. It exists because two of the four things a browser needs are
/// only knowable from the running app: the absolute path of the `kagisecure-nmhost` binary *this
/// install* has, and whether the manifest naming it is currently on disk. A document cannot say
/// either, so this screen says both, and offers a button rather than a `cat > …` snippet.
///
/// # The JSON is shown, not hidden
///
/// Pressing a button here writes a file into the user's browser configuration that names an
/// executable the browser will then launch. That deserves to be readable before it happens, so the
/// exact bytes are on screen under a disclosure triangle, and the button's label says which file
/// it writes.
struct BrowserExtensionView: View {
    @Environment(ExtensionService.self) private var ext

    @State private var copied: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                intro
                listenerState
                hostBinary
                extensionIdentity
                browsers
                install
                safari
            }
            .padding(24)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .navigationTitle("Browser extension")
        .onAppear { ext.refreshSetup() }
    }

    // MARK: - Sections

    private var intro: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Fill logins from your browser")
                .font(.title2.weight(.semibold))
                .accessibilityIdentifier("ks.browserExtension.title")
            Text(
                "The extension asks this app which of your items apply to the page you are on, and "
                + "gets back titles and usernames. A password crosses only when you click to fill "
                + "it and approve it here — once per website, per unlock. Nothing is stored in the "
                + "browser."
            )
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var listenerState: some View {
        if let error = ext.startupError {
            Label {
                Text(error).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .font(.callout)
            .foregroundStyle(.red)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("ks.browserExtension.warning")
        } else {
            HStack(spacing: 8) {
                Image(
                    systemName: ext.status.running
                        ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash"
                )
                .foregroundStyle(ext.status.running ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ext.status.running ? "Listening for browsers" : "Not listening")
                        .font(.callout.weight(.semibold))
                    Text(
                        ext.status.running
                            ? "\(ext.status.endpoint) · \(ext.status.connectedHosts) connected"
                            : "The extension cannot reach this app."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("ks.browserExtension.status")
        }
    }

    @ViewBuilder
    private var hostBinary: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("The helper binary", systemImage: "shippingbox")
                .font(.subheadline.weight(.semibold))
            if let path = ext.setup?.nmhostPath {
                HStack {
                    Text(path)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.head)
                        .accessibilityIdentifier("ks.browserExtension.hostPath")
                    Spacer()
                    copyButton(path, label: "path")
                        .accessibilityIdentifier("ks.browserExtension.copy.hostPath")
                }
                Text(
                    "Your browser launches this. It holds no vault and decides nothing — it "
                    + "forwards messages to this app, which is where every check happens."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                Label {
                    Text(
                        "kagisecure-nmhost was not found next to this app, on your PATH, or at "
                        + "KAGISECURE_NMHOST. Build it with `cargo build -p kagisecure-nmhost` and "
                        + "point KAGISECURE_NMHOST at it, or install the released app."
                    )
                    .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .font(.callout)
                .foregroundStyle(.orange)
                .accessibilityIdentifier("ks.browserExtension.warning.hostPath")
            }
        }
    }

    @ViewBuilder
    private var extensionIdentity: some View {
        if let setup = ext.setup {
            VStack(alignment: .leading, spacing: 8) {
                Label("The extension this app serves", systemImage: "puzzlepiece.extension")
                    .font(.subheadline.weight(.semibold))
                HStack {
                    Text(setup.extensionId)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .accessibilityIdentifier("ks.browserExtension.extensionId")
                    Spacer()
                    copyButton(setup.extensionId, label: "id")
                        .accessibilityIdentifier("ks.browserExtension.copy.extensionId")
                }
                Text(
                    "Check this against the ID your browser shows on its Extensions page. It is "
                    + "fixed by a key committed in the extension's manifest, so it is the same "
                    + "whether the extension is loaded unpacked or installed from a store — and "
                    + "any other extension is refused."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    @ViewBuilder
    private var browsers: some View {
        if let setup = ext.setup {
            VStack(alignment: .leading, spacing: 10) {
                Label("Browsers", systemImage: "globe")
                    .font(.subheadline.weight(.semibold))
                if let error = ext.lastError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.browserExtension.warning.manifest")
                }
                ForEach(Array(setup.manifests.enumerated()), id: \.offset) { _, manifest in
                    browserRow(manifest)
                }
            }
        }
    }

    private func browserRow(_ manifest: BrowserManifestView) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: manifest.installed ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(manifest.installed ? AnyShapeStyle(.green) : AnyShapeStyle(.tertiary))
                VStack(alignment: .leading, spacing: 1) {
                    Text(manifest.browser)
                        .font(.callout.weight(.semibold))
                    Text(
                        manifest.installed
                            ? "Set up"
                            : manifest.browserInstalled
                                ? "Not set up yet" : "Not installed on this Mac"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier(
                        "ks.browserExtension.browserState.\(slug(manifest.browser))")
                }
                Spacer()
                // One row per browser, so the identifier carries the browser's own name: the rows
                // repeat and a bare `installManifest` would not be unique.
                if manifest.installed {
                    Button("Remove") { ext.uninstall(manifest) }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.red)
                        .accessibilityIdentifier(
                            "ks.browserExtension.removeManifest.\(slug(manifest.browser))")
                } else {
                    Button("Set up") { ext.install(manifest) }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier(
                            "ks.browserExtension.installManifest.\(slug(manifest.browser))")
                }
            }
            DisclosureGroup("What this writes") {
                VStack(alignment: .leading, spacing: 6) {
                    Text(manifest.path)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier(
                            "ks.browserExtension.manifestPath.\(slug(manifest.browser))")
                    Text(manifest.body)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
                }
                .padding(.top, 4)
            }
            .font(.caption)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityIdentifier("ks.browserExtension.browserRow.\(slug(manifest.browser))")
    }

    private var install: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Then load the extension", systemImage: "arrow.down.circle")
                .font(.subheadline.weight(.semibold))
            VStack(alignment: .leading, spacing: 4) {
                step(1, "Open chrome://extensions (or edge://extensions).")
                step(2, "Turn on Developer mode.")
                step(3, "Choose “Load unpacked” and pick the extensions/shared folder.")
                step(4, "Check that the ID matches the one above, then reload this app's page.")
            }
            Text(
                "The keyboard shortcut is ⌘\\ in the browser. There is no autofill on page load, "
                + "ever: the extension only asks for a value when you click the key icon in a field "
                + "or press the shortcut."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(number).")
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Safari (M6b).
    ///
    /// Deliberately shaped unlike every other browser row on this screen, because Safari is unlike
    /// them: there is no file to write and therefore no button that writes one. The extension is
    /// already inside this app; what the user has to do is switch it on in Safari's own Settings.
    /// So this section's job is to say whether this build *can* serve Safari, and — when it
    /// cannot — why, in a sentence that names the reason rather than greying a row out.
    @ViewBuilder
    private var safari: some View {
        if let setup = ext.setup {
            VStack(alignment: .leading, spacing: 8) {
                Label("Safari", systemImage: "safari")
                    .font(.subheadline.weight(.semibold))

                // The two Safari warnings share one identifier: they are branches of the same
                // `if`, so only ever one of them is on screen, and a test asserts on the text.
                if setup.safari.appexPath == nil {
                    warning(
                        "This build does not contain the Safari extension. Build the app with "
                        + "`make macos` so its app extension is embedded."
                    )
                    .accessibilityIdentifier("ks.browserExtension.warning.safari")
                } else if setup.safari.appGroup == nil {
                    warning(
                        "This build is not signed with a team identity, so Safari's extension "
                        + "cannot reach this app. Build it with `make macos SIGN=developer-id`."
                    )
                    .accessibilityIdentifier("ks.browserExtension.warning.safari")
                } else {
                    HStack(spacing: 8) {
                        Image(
                            systemName: ext.status.safariRunning
                                ? "checkmark.circle.fill" : "circle"
                        )
                        .foregroundStyle(
                            ext.status.safariRunning ? AnyShapeStyle(.green) : AnyShapeStyle(.tertiary))
                        Text(
                            ext.status.safariRunning
                                ? "Ready for Safari" : "Not listening for Safari"
                        )
                        .font(.callout.weight(.semibold))
                        .accessibilityIdentifier("ks.browserExtension.safariStatus")
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        step(1, "Open Safari → Settings → Extensions.")
                        step(2, "Tick “Kagisecure”.")
                        step(
                            3,
                            "Press “Edit Websites…” (or the toolbar icon) and allow it on the "
                            + "sites you want to fill.")
                        step(4, "Click the key icon in a password field, or press ⌘\\.")
                    }
                    DisclosureGroup("How Safari reaches this app") {
                        VStack(alignment: .leading, spacing: 6) {
                            fact("Extension", setup.safari.bundleId)
                                .accessibilityIdentifier("ks.browserExtension.safari.bundleId")
                            if let group = setup.safari.appGroup {
                                fact("App Group", group)
                                    .accessibilityIdentifier("ks.browserExtension.safari.appGroup")
                            }
                            if let socket = setup.safari.socketPath {
                                fact("Socket", socket)
                                    .accessibilityIdentifier("ks.browserExtension.safari.socketPath")
                            }
                            // The only directory this screen shows the extension itself living in:
                            // Safari's app extension inside this app's bundle. Chrome and Edge load
                            // their copy from a folder the user picks, which the app never learns.
                            if let appex = setup.safari.appexPath {
                                fact("Bundled at", appex)
                                    .accessibilityIdentifier("ks.browserExtension.extensionPath")
                            }
                            Text(
                                "There is no helper binary and no manifest file: the extension is "
                                + "inside this app's own bundle and talks to it over a socket only "
                                + "the two of them can see. Nothing is written outside this app."
                            )
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.top, 4)
                    }
                    .font(.caption)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private func warning(_ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .font(.callout)
        .foregroundStyle(.orange)
    }

    private func fact(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 78, alignment: .leading)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// A "Copy" button that turns into a brief "Copied" confirmation with a checkmark.
    ///
    /// Not a secret value: a path and an extension id. `PasteboardService`'s concealed marker and
    /// auto-clear are for values, and marking these would clear a path out from under somebody
    /// pasting it into a terminal.
    private func copyButton(_ text: String, label: String) -> some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = label
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                if copied == label { copied = nil }
            }
        } label: {
            Label(
                copied == label ? "Copied" : "Copy",
                systemImage: copied == label ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.borderless)
    }
}

/// The accessibility-identifier suffix for one browser's row, e.g. `"Google Chrome"` → `googlechrome`.
///
/// Derived from the browser name rather than hardcoded because the manifest list comes from the
/// core over FFI: this screen does not know at compile time which browsers are in it, and the rows
/// repeat, so each one needs a suffix that is unique, ASCII and the same on every run.
private func slug(_ s: String) -> String {
    s.lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
}
