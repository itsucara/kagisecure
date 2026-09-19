import SwiftUI

import KagisecureFFI

/// The root view swap that *is* the lock screen (ui-spec.md §6.1).
///
/// A locked vault is not an overlay over a rendered item list — there is no item list, because
/// there is no vault key. Swapping the root view is the honest rendering of that.
struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Group {
            switch model.phase {
            case .noVault:
                CreateVaultView()
            case .locked(let reason):
                LockView(reason: reason)
            case .unlocked:
                if let store = model.store {
                    MainView(store: store)
                } else {
                    ProgressView()
                }
            }
        }
        .environment(model.agent)
        .environment(model.browserExtension)
        // The approval sheet (ui-spec.md §10.1). A sheet on the main window rather than a free
        // panel: the request is about this vault, and macOS brings the window forward for it.
        // `NSApp.requestUserAttention` in `AgentService` bounces the Dock icon when it is not.
        .sheet(item: Binding(get: { model.agent.current.map(IdentifiedApproval.init) }, set: { _ in })) { wrapped in
            ApprovalSheet(
                request: wrapped.request,
                signature: model.agent.currentSignature,
                fillSignature: model.agent.currentFillSignature
            )
            .environment(model.agent)
            .environment(model.browserExtension)
        }
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.errorMessage = nil } })
        ) {
            Button("OK") { model.errorMessage = nil }
                .accessibilityIdentifier("ks.alert.ok")
        } message: {
            // No identifier here on purpose: SwiftUI hands an alert's message to AppKit as a
            // string, so a view modifier on it reaches nothing. The UI-test suite reads the alert's
            // own static texts instead, which is what a VoiceOver user hears too.
            Text(model.errorMessage ?? "")
        }
        .sheet(
            isPresented: Binding(
                get: { model.pendingRecoveryCode != nil },
                set: { if !$0 { model.pendingRecoveryCode = nil } })
        ) {
            RecoveryCodeSheet(code: model.pendingRecoveryCode ?? "")
        }
        // The standalone generator (ui-spec.md §8), from the toolbar's `+` menu and ⇧⌘G. With no
        // field to fill it offers Copy and nothing else; the in-field version is presented by the
        // edit row, which knows where the password is going.
        .sheet(isPresented: $model.showGenerator) {
            GeneratorSheet()
        }
        // The import preview (import.md §8). Presented here rather than from `MainView` for the
        // same reason the generator is: the sheet belongs to the window, and the file was already
        // chosen by the menu command that set this flag. The store is required — an import needs
        // an unlocked vault — so a locked window simply has no sheet to show.
        .sheet(
            isPresented: Binding(
                get: { model.showImport && model.store != nil && model.importSource != nil },
                set: { if !$0 { model.closeImport() } })
        ) {
            if let store = model.store, let source = model.importSource {
                ImportSheet(store: store, sourcePath: source)
                    .environment(model)
            }
        }
    }
}

/// `sheet(item:)` needs an `Identifiable`; `ApprovalRequestView` is a generated record and gains
/// nothing by carrying a conformance for one call site.
struct IdentifiedApproval: Identifiable {
    let request: ApprovalRequestView
    var id: String { request.id }

    init(_ request: ApprovalRequestView) {
        self.request = request
    }
}

/// Shown exactly once, when a vault is created (vault-format.md §3.2).
struct RecoveryCodeSheet: View {
    @Environment(AppModel.self) private var model
    let code: String
    @State private var acknowledged = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Save your recovery code", systemImage: "lifepreserver")
                .font(.title2.weight(.semibold))
                .accessibilityIdentifier("ks.recoveryCode.title")
            Text(
                "This code unlocks your vault if you forget your master password. It is shown "
                    + "once and is not stored anywhere. Write it down and keep it somewhere safe."
            )
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Text(code)
                .font(.system(.title3, design: .monospaced))
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                .accessibilityIdentifier("ks.recoveryCode.code")

            Toggle("I have written this down", isOn: $acknowledged)
                .accessibilityIdentifier("ks.recoveryCode.acknowledge")

            HStack {
                Button("Copy") { PasteboardService.copy(code, label: "Recovery code") }
                    .accessibilityIdentifier("ks.recoveryCode.copy")
                Spacer()
                Button("Done") { model.pendingRecoveryCode = nil }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!acknowledged)
                    .accessibilityIdentifier("ks.recoveryCode.done")
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
