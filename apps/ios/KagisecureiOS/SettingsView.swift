import SwiftUI

struct SettingsView: View {
    @Bindable var model: AppModel
    let store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage(AutoLock.key) private var autoLockSeconds = AutoLock.defaultSeconds

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button("Lock Now") {
                        dismiss()
                        model.lock()
                    }
                    .accessibilityIdentifier("settings.lock")
                    Picker("Auto-Lock", selection: $autoLockSeconds) {
                        ForEach(AutoLock.choices, id: \.seconds) { Text($0.label).tag($0.seconds) }
                    }
                    .accessibilityIdentifier("settings.autoLock")
                } footer: {
                    Text("Locks after the app has been in the background this long.")
                }
                Section {
                    NavigationLink {
                        LinkView(link: store.link)
                    } label: {
                        LabeledContent("Link with Mac", value: store.link.isLinked ? "Linked" : "Not linked")
                    }
                    .accessibilityIdentifier("settings.link")
                    NavigationLink {
                        TrashView(store: store)
                    } label: {
                        Label("Trash", systemImage: "trash")
                    }
                    .accessibilityIdentifier("settings.trash")
                }
                Section {
                    Toggle(
                        "Unlock with Face ID",
                        isOn: Binding(
                            get: { model.biometricsEnabled },
                            set: { model.setBiometrics($0) })
                    )
                    .disabled(!model.biometricsAvailable)
                } footer: {
                    Text(
                        model.biometricsAvailable
                            ? "The vault key is protected by this iPhone's Secure Enclave and Face ID."
                            : "Face ID is not available on this device.")
                }
                if let error = model.errorMessage {
                    Text(error).foregroundStyle(.red)
                }
                Section("About") {
                    LabeledContent(
                        "Version",
                        value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
                    Text("Kagisecure keeps the personal vault on this iPhone only. It has no server and makes no network requests: the Mac link goes through a folder you choose in iCloud Drive.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}
