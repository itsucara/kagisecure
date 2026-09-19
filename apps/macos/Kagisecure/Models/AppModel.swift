import Foundation
import Observation
import SwiftUI

import KagisecureFFI

/// Why the vault locked. Shown on the lock screen so a user who comes back to a locked window
/// knows whether they did it, or the machine did.
enum LockReason: Equatable {
    case launch
    case manual
    case idle
    case sleep
    case screenLock

    var message: String? {
        switch self {
        case .launch: nil
        case .manual: "Locked."
        case .idle: "Locked after being idle."
        case .sleep: "Locked when the Mac went to sleep."
        case .screenLock: "Locked when the screen locked."
        }
    }
}

/// What the root view is showing.
enum Phase: Equatable {
    /// No vault file at the configured path — offer to create one (ui-spec.md §12).
    case noVault
    /// A vault exists and is locked (ui-spec.md §6.1).
    case locked(LockReason)
    /// Unlocked. The item store is on `AppModel.store`.
    case unlocked
}

/// The app's root state: which phase we are in, and the unlocked vault when there is one.
///
/// `AppModel` is the only thing that constructs and releases a `VaultSession`. Releasing it *is*
/// the lock operation — the Rust side zeroizes the vault key on drop — so every path that locks
/// goes through `lock(reason:)` and nothing else may keep a reference to the store.
@MainActor
@Observable
final class AppModel {
    private(set) var phase: Phase = .locked(.launch)
    private(set) var store: VaultStore?
    private(set) var vaultPath: String
    private(set) var hasPlatformSlot = false
    private(set) var platformAvailability: PlatformKeyAvailability = .unknown

    /// A one-time recovery code waiting to be shown. Non-nil exactly once, right after a vault is
    /// created, and cleared as soon as the user acknowledges it (vault-format.md §3.2).
    var pendingRecoveryCode: String?

    /// Surfaced as an alert. Never carries a secret value: `FfiError`'s messages are metadata.
    var errorMessage: String?

    /// Toggled to move focus into the search field (⌘F).
    var focusSearch = false

    /// Set when the menu asks the detail pane to enter edit mode (⌘E).
    var editRequest = 0

    /// The category catalogue, straight from the core.
    let categories: [CategoryInfo] = categoryCatalog()

    let platformKey = PlatformKeyService()

    /// The IPC listener and the approval queue (architecture.md §2.5 job 3).
    ///
    /// Created once and reused: starting it is what binds the socket, and stopping it is the
    /// first half of locking.
    let agent = AgentService()

    /// The browser-extension listener (M6).
    ///
    /// A second socket, not a second approval mechanism: a fill request arrives on the same queue
    /// `agent` already polls, so there is one sheet, one timeout and one biometric gate. What this
    /// owns is the channel and its own lease store.
    let browserExtension = ExtensionService()

    /// The floating ⇧⌘Space panel (ui-spec.md §7).
    ///
    /// Owned here rather than by a view because its shortcut is registered for the life of the
    /// process, and because it has to render the locked state too — it exists when the store does
    /// not.
    let quickAccess = QuickAccessController()

    /// Set to present the standalone password generator sheet (ui-spec.md §8). The in-field
    /// generator is presented by the edit row instead, because that is where the field it fills
    /// lives.
    var showGenerator = false

    /// Set to present the import sheet (import.md §8). Never set without `importSource`: the file
    /// is chosen *before* the sheet appears, so cancelling the open panel leaves no empty sheet
    /// behind.
    var showImport = false

    /// The export the import sheet is reading. Cleared with the sheet.
    private(set) var importSource: String?

    /// Bumped by a successful import, so the item list can re-read a vault that just grew by four
    /// hundred items. A counter rather than a flag: two imports in a row must both be noticed.
    private(set) var importCommitCount = 0

    private var autoLock: AutoLockCoordinator?

    init(vaultPath: String? = nil) {
        self.vaultPath = vaultPath ?? defaultVaultPath()
        refreshPhase()
        platformAvailability = platformKey.availability()
        autoLock = AutoLockCoordinator { [weak self] reason in
            self?.lock(reason: reason)
        }
        // `kagisecure lock` from a terminal reaches the app this way: the agent library raises a
        // flag, the polling loop notices, and the app — which owns the vault's lifetime — locks.
        agent.onLockRequested = { [weak self] in
            self?.lock(reason: .manual)
        }
        // One ticker for both panes, so a lease countdown and a fill-lease countdown cannot
        // disagree about what time it is.
        agent.extensionService = browserExtension
        // Quick Access is registered at launch and stays registered: the shortcut has to work
        // while the vault is locked too, because "vault is locked, here is the unlock window" is
        // a more useful answer than a dead key combination (ui-spec.md §7).
        quickAccess.setContent { [weak self] in
            if let self {
                QuickAccessView(onDismiss: { self.quickAccess.close() })
                    .environment(self)
            }
        }
        quickAccess.registerHotKey { [weak self] in
            self?.quickAccess.toggle()
        }
        #if DEBUG
            // The XCUITest suite's only channel into this process is the command line it was
            // started with (`UITestSupport`). Applied last, so nothing above can be surprised by
            // a gate that is not the real one.
            if let gate = UITestSupport.biometricGate() {
                agent.gate = gate
            }
            UITestSupport.applyAppearance()
        #endif
    }

    /// Open the Quick Access panel, or close it if it is already up.
    func toggleQuickAccess() {
        quickAccess.toggle()
    }

    /// Re-read what exists on disk. Called at launch and after a lock.
    func refreshPhase(reason: LockReason = .launch) {
        if vaultExists(path: vaultPath) {
            hasPlatformSlot = ((try? platformSlotId(path: vaultPath)) ?? nil) != nil
            phase = .locked(reason)
        } else {
            hasPlatformSlot = false
            phase = .noVault
        }
    }

    // MARK: - Unlocking

    func createVault(password: String, vaultName: String) {
        perform {
            let directory = (self.vaultPath as NSString).deletingLastPathComponent
            try FileManager.default.createDirectory(
                atPath: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let session = try VaultSession.create(
                path: self.vaultPath,
                masterPassword: password,
                vaultName: vaultName.isEmpty ? "Personal" : vaultName,
                kdfMKib: nil,
                kdfT: nil)
            self.pendingRecoveryCode = session.takeRecoveryCode()
            self.adopt(session)
        }
    }

    func unlock(password: String) {
        perform { self.adopt(try VaultSession.unlockWithPassword(path: self.vaultPath, masterPassword: password)) }
    }

    func unlock(recoveryCode: String) {
        perform { self.adopt(try VaultSession.unlockWithRecoveryCode(path: self.vaultPath, code: recoveryCode)) }
    }

    /// The Touch ID path (ADR-0004): read the wrapped key, have the Secure Enclave decrypt it,
    /// hand the plaintext key straight to Rust, and drop it.
    ///
    /// A cancelled or failed biometric is not an error the user needs an alert for — they are
    /// looking at the password field already — so it only reports something that is not a
    /// cancellation. An invalidated key (a changed fingerprint set, per `.biometryCurrentSet`)
    /// prunes the now-dead slot so the lock screen stops offering an unlock it cannot perform.
    func unlockWithTouchID() {
        guard hasPlatformSlot else { return }
        do {
            guard let wrapped = try platformWrappedKey(path: vaultPath) else {
                hasPlatformSlot = false
                return
            }
            var key = try platformKey.unwrap(wrapped)
            defer { key.resetBytes(in: 0..<key.count) }
            adopt(try VaultSession.unlockWithVaultKey(path: vaultPath, vaultKey: key))
        } catch let error as PlatformKeyError {
            switch error {
            case .cancelled:
                break
            case .keyInvalidated, .noKey:
                hasPlatformSlot = false
                errorMessage =
                    "Touch ID no longer unlocks this vault — the fingerprint set on this Mac "
                    + "changed. Unlock with your master password, then turn Touch ID back on in "
                    + "Settings."
            default:
                errorMessage = error.localizedDescription
            }
        } catch {
            errorMessage = message(for: error)
        }
    }

    private func adopt(_ session: VaultSession) {
        let store = VaultStore(session: session)
        self.store = store
        hasPlatformSlot = session.hasPlatformSlot()
        phase = .unlocked
        autoLock?.start()
        // Serving agents is the whole of M4, and it starts the moment there is a key to serve
        // with. A failure to bind is not fatal — the vault still works — so it is recorded on the
        // service and shown in Agent access rather than raised as a modal.
        agent.start(session: session)
        // Started after the agent, because both listeners ask through the queue the agent's poll
        // loop is now draining — a fill that arrived before that loop existed would sit unanswered
        // until it timed out.
        browserExtension.start(session: session)
    }

    // MARK: - Locking

    /// Drop the vault key and every derived view of it.
    ///
    /// Order matters: the store goes first so no view can hold the last reference to the session
    /// past this point, and only then does the phase change.
    func lock(reason: LockReason) {
        guard store != nil else { return }
        autoLock?.stop()
        // Order matters twice over. The agent stops *first*, which denies every approval still
        // waiting and drops every lease, so there is no interval in which a locked vault is still
        // being served. Then the store goes, releasing the last reference to the `VaultSession`,
        // whose `Drop` empties the shared handle and zeroizes the key. Only then does the phase
        // change, so no view can still be holding the session when it does.
        agent.stop()
        browserExtension.stop()
        store = nil
        pendingRecoveryCode = nil
        showGenerator = false
        // A preview of someone's 1Password export must not outlive the vault it was going to be
        // imported into: the sheet holds a plan full of parsed values, and closing it drops it.
        closeImport()
        // A floating list of items must not outlive the key that decrypted it.
        quickAccess.close()
        refreshPhase(reason: reason)
    }

    // MARK: - Touch ID enrolment

    /// Enrol this Mac's Secure Enclave as an unlock method (ADR-0004, ADR-0008 crossing 3).
    func enrollTouchID() {
        guard let store else { return }
        perform {
            var key = store.session.exportVaultKeyForPlatformWrapping()
            defer { key.resetBytes(in: 0..<key.count) }
            let enrolled = try self.platformKey.enroll(vaultKey: key)
            try store.session.installPlatformSlot(
                slotId: enrolled.slotId, label: "Touch ID on this Mac", wrappedKey: enrolled.wrappedKey)
            self.hasPlatformSlot = true
        }
    }

    func disableTouchID() {
        guard let store else { return }
        perform {
            _ = try store.session.removePlatformSlot()
            self.platformKey.deleteKey()
            self.hasPlatformSlot = false
        }
    }

    // MARK: - Menu actions

    func newItem(category: String) {
        guard let store else { return }
        perform { try store.createItem(category: category) }
        editRequest += 1
    }

    func beginEditingSelection() {
        editRequest += 1
    }

    func copyPrimaryField() {
        store?.copySubtitle()
    }

    /// Open the standalone generator sheet.
    func openGenerator() {
        showGenerator = true
    }

    /// File ▸ Import… (⇧⌘I, import.md §8).
    ///
    /// The open panel runs here rather than inside the sheet, which is the order the flow is
    /// specified in: menu → panel → preview. Cancelling the panel is not an error and leaves
    /// nothing on screen. There is no import without an unlocked vault — the menu item is
    /// disabled while locked, and this returns early if it is somehow reached anyway.
    func openImport() {
        guard store != nil else { return }
        guard let path = ImportModel.chooseSourceFile() else { return }
        importSource = path
        showImport = true
    }

    /// Called by the import sheet once a commit has been written to disk.
    func noteImportCommitted() {
        importCommitCount += 1
    }

    /// Dismiss the import sheet and forget which file it was reading.
    func closeImport() {
        showImport = false
        importSource = nil
    }

    // MARK: - Error plumbing

    private func perform(_ body: () throws -> Void) {
        do {
            try body()
        } catch {
            errorMessage = message(for: error)
        }
    }

    private func message(for error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .WrongCredential:
                return "That did not unlock the vault."
            case .NotFound(let message), .AlreadyExists(let message), .NoSuchSlot(let message),
                .NotPresent(let message), .Invalid(let message), .Io(let message):
                return message
            }
        }
        return error.localizedDescription
    }
}
