import AppKit
import Foundation
import Observation
import SwiftUI

import KagisecureFFI

/// The presence gate's fallback when `LocalAuthentication` cannot run at all: the vault's master
/// password, typed into the app (ADR-0038 user decision 7).
///
/// # What it proves, and what it does not
///
/// Only that whoever answered knows the master password (threat model W-20). That is the vault's
/// existing front door and no stronger, which is why Rust audits a grant reached this way apart
/// from a biometric one (`PRESENCE_CONFIRMED_MASTER_PASSWORD`). It is offered only when the
/// system check cannot run — never as a quicker alternative to it.
///
/// # The check is Rust's
///
/// `VaultSession.verifyMasterPassword` derives and compares; this type only collects the password
/// and shows the answer. Rust rate limits it — one second after a wrong password, doubling to five
/// minutes — and answers `Wrong { retryAfterMs }` or `Throttled { retryAfterMs }`; the panel shows
/// the wait and keeps Confirm disabled until it has run out, rather than letting a person type into
/// a check that will refuse them unread. Argon2id is deliberately slow, so the check runs off the
/// main thread.
///
/// # Where it appears
///
/// In a panel of its own (`MasterPasswordPanel`), not a sheet on the main window: a release can be
/// asked for from Quick Access with the main window closed or minimised, and a sheet on a window
/// nobody can see would hold the one prompt slot forever. A lock closes it
/// (`PresenceCoordinator.addCancelHandler`), answering "not confirmed".
@MainActor
@Observable
final class MasterPasswordFallback {
    /// The question on screen, if there is one.
    struct Request: Identifiable {
        let id = UUID()
        /// Rust's sentence, as the `LocalAuthentication` prompt would have shown it.
        let reason: String
    }

    private(set) var request: Request?
    /// Shown under the field: why the last attempt did not confirm.
    private(set) var message: String?
    /// Confirm is disabled until then.
    private(set) var retryAt: Date?
    /// A check is running.
    private(set) var checking = false

    /// Shows and hides the panel. Replaced in tests.
    var present: (MasterPasswordFallback) -> Void = { _ in }
    var dismiss: () -> Void = {}

    private var session: VaultSession?
    private var continuation: CheckedContinuation<Bool, Never>?

    /// Put the panel up and wait for the person: `true` only once Rust has verified the password.
    /// A second call while one is up answers `false` at once; the coordinator never lets that
    /// happen, and this does not rely on it.
    func ask(reason: String, session: VaultSession) async -> Bool {
        guard continuation == nil else { return false }
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            self.session = session
            self.request = Request(reason: reason)
            self.message = nil
            self.retryAt = nil
            self.checking = false
            present(self)
        }
    }

    /// Check `password`. Verified finishes the prompt; Wrong and Throttled say how long to wait.
    func submit(_ password: String) {
        guard let session, request != nil, !checking, !isWaiting(at: .now) else { return }
        checking = true
        message = nil
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { try session.verifyMasterPassword(password: password) }
            }.value
            // The prompt may have been cancelled (a lock) while Argon2id ran.
            guard self.session === session, self.request != nil else { return }
            self.checking = false
            switch result {
            case .success(.verified):
                self.finish(true)
            case .success(.wrong(let retryAfterMs)):
                self.wait(retryAfterMs, String(localized: "That is not the master password."))
            case .success(.throttled(let retryAfterMs)):
                self.wait(retryAfterMs, String(localized: "Too many attempts."))
            case .failure:
                // Locked, or the vault has no master-password slot: nothing can be confirmed.
                self.finish(false)
            }
        }
    }

    /// The panel's Cancel, Esc, or closing it.
    func cancel() {
        finish(false)
    }

    /// Whether Confirm must still wait out a back-off at `now`.
    func isWaiting(at now: Date) -> Bool {
        guard let retryAt else { return false }
        return now < retryAt
    }

    private func wait(_ retryAfterMs: UInt64, _ why: String) {
        let seconds = Double(retryAfterMs) / 1_000
        retryAt = Date().addingTimeInterval(seconds)
        let whole = Int(seconds.rounded(.up))
        message = whole == 1
            ? String(localized: "\(why) Try again in \(whole) second.")
            : String(localized: "\(why) Try again in \(whole) seconds.")
    }

    private func finish(_ confirmed: Bool) {
        guard let continuation else { return }
        self.continuation = nil
        request = nil
        session = nil
        message = nil
        retryAt = nil
        checking = false
        dismiss()
        continuation.resume(returning: confirmed)
    }
}

/// The floating panel the fallback appears in — see `MasterPasswordFallback` for why not a sheet.
@MainActor
final class MasterPasswordPanel {
    private var panel: NSPanel?

    func show(_ fallback: MasterPasswordFallback) {
        let panel = self.panel ?? makePanel()
        self.panel = panel
        panel.contentView = NSHostingView(rootView: MasterPasswordFallbackView(fallback: fallback))
        panel.center()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        DispatchQueue.main.async { panel.makeKeyAndOrderFront(nil) }
    }

    func hide() {
        panel?.orderOut(nil)
        // The hosting view goes with it, so nothing typed outlives the panel.
        panel?.contentView = nil
    }

    private func makePanel() -> NSPanel {
        let panel = FallbackPanel(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: 240),
            styleMask: [.titled],
            backing: .buffered,
            defer: false)
        panel.title = String(localized: "Confirm it's you")
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.becomesKeyOnlyIfNeeded = false
        return panel
    }
}

private final class FallbackPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// What the panel shows.
struct MasterPasswordFallbackView: View {
    @Bindable var fallback: MasterPasswordFallback
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Confirm with your master password", systemImage: "lock.shield")
                .font(.headline)
                .accessibilityIdentifier("ks.masterPassword.title")
            if let reason = fallback.request?.reason {
                Text("Kagisecure is trying to \(reason).")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.masterPassword.reason")
            }
            Text(
                "Touch ID and your Mac password are not available right now, so the vault's master password stands in for them."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            StableSecureField(
                "Master password",
                text: $password,
                autofocus: true,
                onSubmit: submit
            )
                .accessibilityIdentifier("ks.masterPassword.field")
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let waiting = fallback.isWaiting(at: context.date)
                VStack(alignment: .leading, spacing: 10) {
                    if let message = fallback.message {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .accessibilityIdentifier("ks.masterPassword.message")
                    }
                    HStack {
                        if fallback.checking {
                            ProgressView().controlSize(.small)
                        }
                        Spacer()
                        Button("Cancel", role: .cancel) { fallback.cancel() }
                            .keyboardShortcut(.cancelAction)
                            .accessibilityIdentifier("ks.masterPassword.cancel")
                        Button("Confirm", action: submit)
                            .buttonStyle(.borderedProminent)
                            .disabled(password.isEmpty || fallback.checking || waiting)
                            .accessibilityIdentifier("ks.masterPassword.confirm")
                    }
                }
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func submit() {
        guard !password.isEmpty else { return }
        fallback.submit(password)
        password = ""
    }
}
