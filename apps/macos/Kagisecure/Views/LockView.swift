import SwiftUI

/// The unlock card (ui-spec.md §6.1): Touch ID first when this Mac is enrolled, master password
/// always, recovery code behind a disclosure.
struct LockView: View {
    @Environment(AppModel.self) private var model
    let reason: LockReason

    @State private var password = ""
    @State private var recoveryCode = ""
    @State private var showRecovery = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)
            card
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .onAppear {
            passwordFocused = true
            if model.hasPlatformSlot, model.platformAvailability.isAvailable {
                model.unlockWithTouchID()
            }
        }
    }

    private var card: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill")
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(spacing: 4) {
                Text("Kagisecure")
                    .font(.title.weight(.semibold))
                    .accessibilityIdentifier("ks.lock.title")
                Text(URL(fileURLWithPath: model.vaultPath).lastPathComponent)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.lock.vaultFile")
            }

            if let message = reason.message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.lock.reason")
            }

            VStack(spacing: 10) {
                SecureField("Master password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocused)
                    .onSubmit(unlock)
                    .accessibilityLabel("Master password")
                    .accessibilityIdentifier("ks.lock.password")

                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("ks.lock.unlock")

                if model.hasPlatformSlot {
                    Button {
                        model.unlockWithTouchID()
                    } label: {
                        Label("Unlock with Touch ID", systemImage: "touchid")
                    }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
                    .disabled(!model.platformAvailability.isAvailable)
                    .accessibilityIdentifier("ks.lock.touchId")
                }
            }
            .frame(width: 300)

            // A `Button`, not a `DisclosureGroup`.
            //
            // This was a `DisclosureGroup`, and on macOS 26 the only thing that opened it was a
            // click inside the chevron glyph itself: the words next to it did nothing, and neither
            // did the keyboard. The accessibility tree offers one `AXDisclosureTriangle` whose
            // value stays at 0 however it is pressed, which is how the UI-test suite found this —
            // every synthetic click and both of the keys that should work left it shut.
            //
            // A user who has forgotten their master password and is looking for the way in
            // deserves better than a four-point target. So the whole row is the control now: it
            // has a keyboard path (ui-spec.md §13 asks for one for every action), VoiceOver reads
            // it as a button with a state, and the chevron is decoration rather than the hit area.
            VStack(spacing: 0) {
                Button {
                    withAnimation { showRecovery.toggle() }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: showRecovery ? "chevron.down" : "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                        Text("Use recovery code instead")
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Use recovery code instead")
                .accessibilityValue(showRecovery ? "expanded" : "collapsed")
                .accessibilityIdentifier("ks.lock.recoveryDisclosure")

                if showRecovery {
                    VStack(spacing: 8) {
                    TextField("XXXX-XXXX-…", text: $recoveryCode, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(2...4)
                        .font(.system(.body, design: .monospaced))
                        .accessibilityLabel("Recovery code")
                        .accessibilityIdentifier("ks.lock.recoveryCode")
                    Text(
                        "After unlocking this way you will be asked to set a new master password."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    Button("Unlock with recovery code") {
                        model.unlock(recoveryCode: recoveryCode)
                    }
                        .disabled(recoveryCode.isEmpty)
                        .accessibilityIdentifier("ks.lock.recoveryUnlock")
                    }
                    .padding(.top, 8)
                }
            }
            .frame(width: 300)

            if case .unavailable(let why) = model.platformAvailability, model.hasPlatformSlot {
                Text("Touch ID unavailable: \(why)")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(width: 300)
                    .accessibilityIdentifier("ks.lock.touchIdUnavailable")
            }
        }
        .padding(36)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        .frame(width: 400)
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        model.unlock(password: password)
        password = ""
    }
}

/// The first-run empty state (ui-spec.md §12).
struct CreateVaultView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var confirmation = ""
    @State private var vaultName = "Personal"

    private var mismatch: Bool { !confirmation.isEmpty && confirmation != password }
    private var canCreate: Bool { password.count >= 8 && password == confirmation }

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Create your first vault")
                .font(.title.weight(.semibold))
                .accessibilityIdentifier("ks.createVault.title")
            Text(
                "Your master password protects everything. kagisecure cannot reset it — that is "
                    + "what the one-time recovery code you are about to see is for."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(width: 380)

            VStack(spacing: 10) {
                TextField("Vault name", text: $vaultName)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("ks.createVault.vaultName")
                SecureField("Master password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("ks.createVault.password")
                SecureField("Confirm master password", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(create)
                    .accessibilityIdentifier("ks.createVault.confirmation")
                if mismatch {
                    Text("The two passwords do not match.")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("ks.createVault.mismatch")
                } else if !password.isEmpty && password.count < 8 {
                    Text("Use at least 8 characters.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("ks.createVault.tooShort")
                }
                Button("Create Vault", action: create)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canCreate)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("ks.createVault.create")
            }
            .frame(width: 320)

            Text(model.vaultPath)
                .font(.caption)
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
                .accessibilityIdentifier("ks.createVault.vaultPath")
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
    }

    private func create() {
        guard canCreate else { return }
        model.createVault(password: password, vaultName: vaultName)
        password = ""
        confirmation = ""
    }
}
