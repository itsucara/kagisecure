import SwiftUI

/// Settings ▸ Updates: whether the app looks for updates by itself, and a button to look now.
struct UpdatesSettings: View {
    @Environment(AppUpdater.self) private var updater

    var body: some View {
        @Bindable var updater = updater
        Form {
            Section {
                Toggle("Check for updates automatically", isOn: $updater.automaticallyChecks)
                    .disabled(!updater.isEnabled)
                LabeledContent {
                    Button("Check Now") { updater.checkNow() }
                        .disabled(!updater.isEnabled)
                } label: {
                    Text("Last checked")
                    lastCheckText
                        .foregroundStyle(.secondary)
                }
            } footer: {
                if updater.isEnabled {
                    Text("Updates are signed and verified before they install. An update found at launch installs and relaunches at once; one found later installs when you quit.")
                } else {
                    Text("This build does not update itself. Only release builds do.")
                }
            }
        }
        .formStyle(.grouped)
    }

    private var lastCheckText: Text {
        if let last = updater.lastCheck {
            Text(last, format: .dateTime.year().month().day().hour().minute())
        } else {
            Text("Not yet")
        }
    }
}
