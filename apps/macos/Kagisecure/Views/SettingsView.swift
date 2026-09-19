import SwiftUI

import KagisecureFFI

/// Settings (⌘,). Security (auto-lock, clipboard, Touch ID) and a vault pane that says where the
/// file lives.
struct SettingsView: View {
    var body: some View {
        TabView {
            // No identifiers on the tabs. `.tabItem` hands AppKit a title and an image and builds
            // its own `NSTabViewItem`; a view modifier on the label reaches nothing, and an
            // identifier that is never in the tree is a hook that looks usable and is not. The
            // UI-test suite clicks the tabs by their titles, which is what a VoiceOver user hears.
            SecuritySettings()
                .tabItem { Label("Security", systemImage: "lock.shield") }
            VaultSettings()
                .tabItem { Label("Vault", systemImage: "externaldrive") }
        }
        .frame(width: 460)
    }
}

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    // `store:` rather than the implicit `.standard`, so that a UI-test run writes into its own
    // throwaway suite instead of the real user's preferences. See `AppDefaults`.
    @AppStorage(AutoLockCoordinator.idleMinutesKey, store: AppDefaults.shared)
    private var idleMinutes = AutoLockCoordinator.defaultIdleMinutes
    @AppStorage(PasteboardService.clearSecondsKey, store: AppDefaults.shared)
    private var clearSeconds = PasteboardService.defaultClearSeconds

    var body: some View {
        Form {
            Section {
                Picker("Lock when idle for", selection: $idleMinutes) {
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("10 minutes").tag(10)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                    Text("Never").tag(0)
                }
                .accessibilityIdentifier("ks.settings.autoLockInterval")
                Text(
                    "The vault always locks when the Mac sleeps, when the screen locks, and when "
                        + "you quit — those are not settings."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            } header: {
                Text("Auto-lock")
            }

            Section {
                Picker("Clear the clipboard after", selection: $clearSeconds) {
                    ForEach(PasteboardService.clearSecondsChoices, id: \.self) { seconds in
                        Text(seconds == 0 ? "Never" : PasteboardService
                            .clearDescription(seconds: seconds)
                            .replacingOccurrences(of: "Cleared after ", with: ""))
                            .tag(seconds)
                    }
                }
                .accessibilityIdentifier("ks.settings.clipboardInterval")
                Text(
                    "Applies to every copy — passwords, one-time codes, anything the app puts on "
                        + "the clipboard. Only kagisecure's own copy is removed: if you copied "
                        + "something else in the meantime, that is left alone."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("Clipboard")
            }

            Section {
                if let error = model.quickAccess.hotKeyError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.settings.quickAccessError")
                } else {
                    LabeledContent("Shortcut") {
                        Text("⇧⌘Space")
                            .font(.callout.monospaced())
                            .accessibilityIdentifier("ks.settings.quickAccessShortcut")
                    }
                }
                Text(
                    "Quick Access needs no Accessibility or Input Monitoring permission: the "
                        + "shortcut is registered with the system, which tells kagisecure only "
                        + "that it fired."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("Quick Access")
            }

            Section {
                switch model.platformAvailability {
                case .available:
                    Toggle(
                        "Unlock with Touch ID",
                        isOn: Binding(
                            get: { model.hasPlatformSlot },
                            set: { $0 ? model.enrollTouchID() : model.disableTouchID() })
                    )
                    .disabled(model.store == nil)
                    .accessibilityIdentifier("ks.settings.touchIdToggle")
                    Text(
                        "Your vault key is wrapped by a key held in this Mac's Secure Enclave. "
                            + "Adding or removing a fingerprint invalidates it and you will be "
                            + "asked for your master password again."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                case .unavailable(let why):
                    Label("Touch ID is unavailable: \(why)", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.settings.touchIdUnavailable")
                case .unknown:
                    ProgressView()
                }
            } header: {
                Text("Touch ID")
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

private struct VaultSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            LabeledContent("Vault file") {
                Text(model.vaultPath)
                    .textSelection(.enabled)
                    .font(.callout)
                    .multilineTextAlignment(.trailing)
                    .accessibilityIdentifier("ks.settings.vaultPath")
            }
            LabeledContent("Audit log") {
                Text(
                    model.store.map { $0.session.auditIntact() ? "Chain intact" : "Chain broken" }
                        ?? "Locked")
                    .accessibilityIdentifier("ks.settings.auditState")
            }
            LabeledContent("Word list") {
                Text("EFF long list — \(generatorLimits().wordlistSize) words")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.settings.wordlist")
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}
