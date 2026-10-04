import SwiftUI

struct SetupView: View {
    @Bindable var model: AppModel
    @State private var password = ""
    @State private var confirm = ""
    @State private var useFaceID = true

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Create the vault on this iPhone. It stays on this device and opens with your master password or Face ID.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Section("Master password") {
                    SecureField("Master password", text: $password)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("setup.password")
                    SecureField("Confirm", text: $confirm)
                        .textContentType(.newPassword)
                        .accessibilityIdentifier("setup.confirm")
                }
                if model.biometricsAvailable {
                    Toggle("Unlock with Face ID", isOn: $useFaceID)
                }
                if let error = model.errorMessage {
                    Text(error).foregroundStyle(.red).accessibilityIdentifier("setup.error")
                }
                Button {
                    Task {
                        await model.createVault(
                            password: password, confirm: confirm, enableBiometrics: useFaceID)
                    }
                } label: {
                    if model.busy { ProgressView() } else { Text("Create Vault") }
                }
                .disabled(model.busy || password.isEmpty)
                .accessibilityIdentifier("setup.create")
            }
            .navigationTitle("Welcome")
        }
    }
}

struct RecoveryCodeView: View {
    let code: String
    let done: () -> Void
    @State private var saved = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("This recovery code opens your vault if you forget the master password. It is shown only once. Write it down and keep it somewhere safe.")
                        .font(.callout)
                }
                Section("Recovery code") {
                    Text(code)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .privacySensitive()
                        .accessibilityIdentifier("recovery.code")
                }
                Toggle("I have saved the recovery code", isOn: $saved)
                    .accessibilityIdentifier("recovery.saved")
                Button("Continue", action: done)
                    .disabled(!saved)
                    .accessibilityIdentifier("recovery.continue")
            }
            .navigationTitle("Recovery Code")
        }
    }
}

struct LockView: View {
    @Bindable var model: AppModel
    @State private var password = ""
    @State private var triedBiometrics = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Kagisecure is locked").font(.title2.bold())
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .textFieldStyle(.roundedBorder)
                .submitLabel(.go)
                .onSubmit(unlock)
                .accessibilityIdentifier("lock.password")
            if let error = model.errorMessage {
                Text(error).foregroundStyle(.red).font(.callout)
                    .accessibilityIdentifier("lock.error")
            }
            Button(action: unlock) {
                if model.busy { ProgressView() } else { Text("Unlock").frame(maxWidth: .infinity) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.busy || password.isEmpty)
            .accessibilityIdentifier("lock.unlock")
            if model.biometricsEnabled && model.biometricsAvailable {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Unlock with Face ID", systemImage: "faceid")
                }
                .accessibilityIdentifier("lock.faceid")
            }
            Spacer()
        }
        .padding()
        .task {
            guard !triedBiometrics, model.biometricsEnabled, model.biometricsAvailable else { return }
            triedBiometrics = true
            await model.unlockWithBiometrics()
        }
    }

    private func unlock() {
        let entered = password
        password = ""
        Task { await model.unlock(password: entered) }
    }
}
