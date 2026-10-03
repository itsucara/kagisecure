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
        .environment(model.agentFill)
        .environment(model.unattended)
        // The approval sheet (ui-spec.md §10.1). A sheet on the main window rather than a free
        // panel: the request is about this vault, and macOS brings the window forward for it.
        // `NSApp.requestUserAttention` in `AgentService` bounces the Dock icon when it is not.
        // `sheetRequest`, not `current`: a presence-only fill at the head is asked with the
        // system's Touch ID prompt alone, by `AgentService.confirmPresence` (ADR-0037).
        // An agent fill gets a sheet of its own (ui-spec.md §10.7, ADR-0036 §5) on the same queue.
        .sheet(item: Binding(get: { model.agent.sheetRequest.map(IdentifiedApproval.init) }, set: { _ in })) { wrapped in
            Group {
                if wrapped.request.action == .agentFill {
                    AgentFillSheetView(
                        request: wrapped.request,
                        signature: model.agent.currentAgentFillSignature)
                } else {
                    ApprovalSheet(
                        request: wrapped.request,
                        signature: model.agent.currentSignature,
                        fillSignature: model.agent.currentFillSignature
                    )
                }
            }
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
        // The store's own errors (busy, and anything a `perform`-routed environment/vault-sharing
        // call hits) — separate from `model.errorMessage` above, which is for unlock-time and
        // Touch ID failures. Never shown at the same time as the conflict alert below: `perform`
        // only sets this when `VaultStore.conflictKind` is `nil` (see its own comment).
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.store?.errorMessage != nil },
                set: { if !$0 { model.store?.errorMessage = nil } })
        ) {
            Button("OK") { model.store?.errorMessage = nil }
                .accessibilityIdentifier("ks.alert.storeOk")
        } message: {
            Text(model.store?.errorMessage ?? "")
        }
        // The Agent-access surface's own failures (today: `AgentService.revoke(_:)`), same
        // pattern as the store's alert just above — a separate alert because it is a separate
        // model with its own lifetime, not because it needs to look any different.
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.agent.errorMessage != nil },
                set: { if !$0 { model.agent.errorMessage = nil } })
        ) {
            Button("OK") { model.agent.errorMessage = nil }
                .accessibilityIdentifier("ks.alert.agentOk")
        } message: {
            Text(model.agent.errorMessage ?? "")
        }
        // The vault file changed while unlocked (step 4, user decision 3): writes have stopped
        // until the human picks a side. Held back while the overwrite confirmation below, or the
        // store's error alert, is up, so two alerts never compete; it comes back when they close
        // and the conflict is still there.
        .alert(
            "The vault file changed",
            isPresented: Binding(
                get: {
                    guard let store = model.store else { return false }
                    return store.conflictKind != nil && store.overwriteConfirmation == nil
                        && store.errorMessage == nil
                },
                set: { _ in }
            )
        ) {
            Button("Keep this app's version (overwrite the file)…") {
                model.store?.requestKeepAppVersion()
            }
            .accessibilityIdentifier("ks.alert.conflict.keepAppVersion")
            Button("Lock and reopen from the file", role: .cancel) {
                model.lockAfterConflict()
            }
            .accessibilityIdentifier("ks.alert.conflict.reopen")
        } message: {
            Text(conflictMessage(model.store?.conflictKind))
        }
        // "Keep this app's version" is destructive to the file, so it is confirmed separately,
        // saying what the file holds that would be lost (`overwriteConfirmationMessage(_:)`).
        .alert(
            "Overwrite the vault file?",
            isPresented: Binding(
                get: { model.store?.overwriteConfirmation != nil },
                set: { _ in }
            )
        ) {
            Button("Overwrite the File", role: .destructive) {
                model.store?.confirmKeepAppVersion()
            }
            .accessibilityIdentifier("ks.alert.overwrite.confirm")
            Button("Cancel", role: .cancel) {
                model.store?.cancelKeepAppVersion()
            }
            .accessibilityIdentifier("ks.alert.overwrite.cancel")
        } message: {
            Text(model.store?.overwriteConfirmation.map(overwriteConfirmationMessage) ?? "")
        }
        .alert(
            "Nothing to overwrite",
            isPresented: Binding(
                get: { model.store?.conflictNotice != nil },
                set: { if !$0 { model.store?.conflictNotice = nil } })
        ) {
            Button("OK") { model.store?.conflictNotice = nil }
                .accessibilityIdentifier("ks.alert.conflictNotice.ok")
        } message: {
            Text(model.store?.conflictNotice ?? "")
        }
        .sheet(
            isPresented: Binding(
                get: { model.pendingRecoveryCode != nil },
                set: { if !$0 { model.pendingRecoveryCode = nil } })
        ) {
            RecoveryCodeSheet(code: model.pendingRecoveryCode ?? "")
        }
        // "While you were away" (ADR-0042 §9): after an unlock, when the machine log recorded
        // anything the person has not acknowledged.
        .sheet(
            isPresented: Binding(
                get: { model.unattended.showWhileAway && model.store != nil },
                set: { if !$0 { model.unattended.showWhileAway = false } })
        ) {
            if let store = model.store {
                WhileAwaySheet(store: store)
                    .environment(model.unattended)
            }
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

/// The conflict alert's body text (step 4, user decision 3): all three kinds land on the same two
/// choices, so this only has to explain *what* is different about the file, not what to do about
/// it — the two buttons already say that.
func conflictMessage(_ kind: VaultConflictKindView?) -> String {
    switch kind {
    case .diverged:
        String(localized: "This vault's history no longer matches what this app last saw here — as if an older copy of the file had been restored.")
    case .replaced:
        String(localized: "The file at this vault's location is no longer the vault this app unlocked.")
    case .unreadable:
        String(localized: "The file at this vault's location is not a vault this app can read — it may be damaged, not a vault at all, or written by a newer version of kagisecure.")
    case .removed:
        String(localized: "The vault file is no longer at its saved location.")
    case nil:
        ""
    }
}

/// The overwrite confirmation's body text: what the file at the vault's location holds that
/// "Keep this app's version" would discard (`VaultConflictDetailsView`, from
/// `VaultSession.conflictDetails`), then what else the overwrite changes.
///
/// The header matters as much as the items: the overwrite writes this app's unlock methods too,
/// so a master password or recovery code that exists only in the file's version stops working,
/// and this app's comes back — including a recovery code someone replaced on purpose.
func overwriteConfirmationMessage(_ details: VaultConflictDetailsView) -> String {
    var paragraphs: [String] = []
    switch details.kind {
    case .diverged:
        paragraphs.append(
            String(localized: "The file is an older or separately changed copy of this vault. It will be replaced with this app's version."))
        let lost = details.diverged
        var losses: [String] = []
        func add(_ count: UInt64, _ singular: String, _ plural: (UInt64) -> String) {
            if count > 0 { losses.append(count == 1 ? singular : plural(count)) }
        }
        if let lost {
            add(
                lost.itemsOnlyInFile, String(localized: "• 1 item that only the file has"),
                { String(localized: "• \($0) items that only the file has") })
            add(
                lost.itemsDiffering, String(localized: "• 1 item whose version in the file differs"),
                { String(localized: "• \($0) items whose version in the file differs") })
            add(
                lost.environmentsOnlyInFile, String(localized: "• 1 environment that only the file has"),
                { String(localized: "• \($0) environments that only the file has") })
            add(
                lost.environmentsDiffering,
                String(localized: "• 1 environment whose version in the file differs"),
                { String(localized: "• \($0) environments whose version in the file differs") })
            add(
                lost.vaultsOnlyInFileOrDiffering,
                String(localized: "• 1 vault, or vault setting, that differs in the file"),
                { String(localized: "• \($0) vaults, or vault settings, that differ in the file") })
            add(
                lost.auditEntriesOnlyInFile, String(localized: "• 1 audit log entry that only the file has"),
                { String(localized: "• \($0) audit log entries that only the file has") })
        }
        if losses.isEmpty {
            paragraphs.append(String(localized: "It holds no items, environments or history that this app's version lacks."))
        } else {
            paragraphs.append(String(localized: "Lost from the file:") + "\n" + losses.joined(separator: "\n"))
        }
        if lost?.masterPasswordDiffers == true {
            paragraphs.append(
                String(localized: "The master password that opens the file now will stop working; the one this app was last unlocked with will work instead."))
        }
        if lost?.recoveryCodeDiffers == true {
            paragraphs.append(
                String(localized: "The recovery code that opens the file now will stop working, and this app's recovery code will work again — even if it was replaced in the file's version because it might have been exposed."))
        }
        if lost?.touchIdDiffers == true {
            paragraphs.append(String(localized: "Touch ID for this vault goes back to how this app last saw it."))
        }
    case .replaced:
        paragraphs.append(
            String(localized: "The file at this location is a different vault, or one this app's key cannot open. Overwriting destroys it entirely, and this app cannot tell what it contains. Keep a copy of it first if it might matter."))
    case .unreadable:
        paragraphs.append(
            String(localized: "The file at this location is not a vault this app can read. Overwriting replaces it entirely. If it was written by a newer version of kagisecure, update instead."))
    case .removed:
        paragraphs.append(
            String(localized: "There is no file at this vault's location. This app's version will be written there. If the vault was moved on purpose, this creates a second copy at the old place."))
    }
    paragraphs.append(String(localized: "The overwrite is recorded in the vault's audit log."))
    return paragraphs.joined(separator: "\n\n")
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
                "This code unlocks your vault if you forget your master password. It is shown once and is not stored anywhere. Write it down and keep it somewhere safe."
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
