import Foundation
import LocalAuthentication
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
    /// The human chose "Lock and reopen from the file" on the conflict alert (step 4, user
    /// decision 3) rather than a plain lock — the vault file changed while this session held it
    /// unlocked, and writes had already stopped.
    case conflict

    var message: String? {
        switch self {
        case .launch: nil
        case .manual: String(localized: "Locked.")
        case .idle: String(localized: "Locked after being idle.")
        case .sleep: String(localized: "Locked when the Mac went to sleep.")
        case .screenLock: String(localized: "Locked when the screen locked.")
        case .conflict: String(localized: "Locked because the vault file changed outside kagisecure. Unlock to see the current version.")
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

    /// Set to show "Turn on Touch ID unlock?" after an unlock (ADR-0004 amendment 2026-10-04).
    var showTouchIDOffer = false

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

    /// The one presence prompt the app may have on screen at a time (ADR-0037 §3, ADR-0038 §6),
    /// shared by the approval flow and every reveal and copy.
    let presence: PresenceCoordinator

    /// The presence gate's fallback when `LocalAuthentication` cannot run (ADR-0038 user
    /// decision 7), and the panel it appears in.
    let masterPasswordFallback = MasterPasswordFallback()
    private let masterPasswordPanel = MasterPasswordPanel()

    /// The IPC listener and the approval queue (architecture.md §2.5 job 3).
    ///
    /// Created once and reused: starting it is what binds the socket, and stopping it is the
    /// first half of locking.
    let agent: AgentService

    /// The browser-extension listener (M6).
    ///
    /// A second socket, not a second approval mechanism: a fill request arrives on the same queue
    /// `agent` already polls, so there is one sheet, one timeout and one biometric gate. What this
    /// owns is the channel and its own lease store.
    let browserExtension = ExtensionService()
    /// "Connect your browsers" (ui-spec.md §6.5), offered once per launch after an unlock.
    let browserPrompt = BrowserConnectModel()

    /// System-wide password AutoFill (ADR-0045): the socket the credential provider extension
    /// asks, and the identity store QuickType reads.
    let credentialProvider: CredentialProviderService

    /// Agent-requested browser fills' switch, blocks and notices (ADR-0036 §2, §9). The sheet
    /// itself is `agent`'s, on the same queue as every other approval.
    let agentFill: AgentFillService

    /// Unattended jobs (ADR-0042 Phase 3): the engine is started at launch, and re-armed from the
    /// Keychain, whether or not the vault is ever unlocked.
    let unattended: UnattendedService

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

    /// Set by `lockAfterConflict()`, read once by the next `adopt(_:)`: the file identity
    /// (`VaultSession.vaultFileId()`) of the vault that was conflicting when the user chose "Lock
    /// and reopen from the file", so the audit note (`VaultSession.noteReopenedAfterConflict`) is
    /// written only when the vault actually being adopted is *that same vault file*, reopened —
    /// best-effort, the same as a reveal (user decision 1), never blocking getting back in.
    ///
    /// A file id rather than a plain flag because "reopen from the file" does not always lead
    /// back to `.locked`: a `Removed` conflict sends `refreshPhase` to `.noVault` instead (the
    /// file is gone), and from there the very next `adopt(_:)` might be a brand-new vault the user
    /// creates at the same path — a different file with a freshly minted id, not a reopen of
    /// anything. A bare boolean could not tell those two apart and would misfile the new vault's
    /// very first unlock as a conflict recovery it has nothing to do with.
    private var reopeningAfterConflictFileId: String?

    /// The context an in-flight `enrollTouchID()` created, if one is running — set only for the
    /// duration of one call, so `presence.cancelInFlight()` has something to invalidate (see
    /// `enrollTouchID`).
    private var enrollmentContext: LAContext?

    init(vaultPath: String? = nil) {
        PeerCodeSignature.warmOwnTeamIdentifier()
        self.vaultPath = vaultPath ?? defaultVaultPath()
        let presence = PresenceCoordinator()
        self.presence = presence
        self.agent = AgentService(presence: presence)
        self.agentFill = AgentFillService(presence: presence)
        self.unattended = UnattendedService(presence: presence)
        self.credentialProvider = CredentialProviderService(presence: presence)
        let panel = masterPasswordPanel
        masterPasswordFallback.present = { panel.show($0) }
        masterPasswordFallback.dismiss = { panel.hide() }
        // A lock closes the fallback's panel the way it invalidates a `LAContext`.
        presence.addCancelHandler { [weak fallback = masterPasswordFallback] in fallback?.cancel() }
        // A lock reaches Touch ID enrolment's own context the same way, best-effort: see
        // `enrollTouchID`. `enrollmentContext` is `nil` whenever no enrolment is in flight, so this
        // is a no-op on every lock but the rare one that lands mid-enrolment.
        presence.addCancelHandler { [weak self] in self?.enrollmentContext?.invalidate() }
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
        browserPrompt.bind(browserExtension)
        // Agent-fill notices are drained on the same tick (ADR-0036 implementation decision 11).
        agent.agentFill = agentFill
        // The switch the user chose, pushed to Rust's in-memory flag (off in every new process)
        // at launch. Pushed again on every unlock, in `adopt`, before either listener starts.
        agentFill.applyStoredSwitch()
        // Quick Access is registered at launch and stays registered: the shortcut has to work
        // while the vault is locked too, because "vault is locked, here is the unlock window" is
        // a more useful answer than a dead key combination (ui-spec.md §7).
        // A fresh model every time the panel opens, over whichever session is unlocked then (or
        // none, and the panel says the vault is locked). Closing the panel drops it.
        quickAccess.setContent { [weak self] in
            if let self {
                QuickAccessView(
                    model: QuickAccessModel(
                        session: self.store?.session,
                        onDismiss: { [weak self] in self?.quickAccess.close() }))
            }
        }
        quickAccess.registerHotKey { [weak self] in
            self?.quickAccess.toggle()
        }
        // Armed jobs run whether or not anyone unlocks: the engine starts now and re-arms from the
        // Keychain (ADR-0042 implementation decision 1). Not in a unit-test host, which must not
        // bind the user's socket or read their Keychain item.
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil {
            unattended.launch(vaultPath: self.vaultPath)
            // Bound at launch, not at unlock, so an AutoFill request can bring a locked app
            // forward to be unlocked (ADR-0045). The socket path needs our team identifier, whose
            // first read runs Security.framework code-signing checks that must stay off the main
            // thread; once read it is cached for every later main-thread caller.
            let credentialProvider = self.credentialProvider
            Task { @MainActor in
                _ = await PeerCodeSignature.ownTeamIdentifierOffMain()
                credentialProvider.start()
            }
        }
        // The light/dark choice from Settings › General. Before the test hook below, so a test
        // that pins the appearance still wins.
        AppAppearance.applyStoredAtLaunch()
        #if DEBUG
            // The XCUITest suite's only channel into this process is the command line it was
            // started with (`UITestSupport`). Applied last, so nothing above can be surprised by
            // a gate that is not the real one.
            if let gate = UITestSupport.biometricGate() {
                presence.gate = gate
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
                vaultName: vaultName.isEmpty ? String(localized: "Personal") : vaultName,
                kdfMKib: nil,
                kdfT: nil)
            self.pendingRecoveryCode = session.takeRecoveryCode()
            self.adopt(session)
        }
    }

    func unlock(password: String) {
        perform { self.adopt(try VaultSession.unlockWithPassword(path: self.vaultPath, masterPassword: password)) }
        offerTouchIDAfterUnlock()
    }

    func unlock(recoveryCode: String) {
        perform { self.adopt(try VaultSession.unlockWithRecoveryCode(path: self.vaultPath, code: recoveryCode)) }
        offerTouchIDAfterUnlock()
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
                    String(localized: "Touch ID no longer unlocks this vault — the fingerprint set on this Mac changed. Unlock with your master password, then turn Touch ID back on in Settings.")
            default:
                errorMessage = error.localizedDescription
            }
        } catch {
            errorMessage = message(for: error)
        }
    }

    private func adopt(_ session: VaultSession) {
        // Before anything can ask for a value: with no gate installed every release fails closed,
        // and Rust refuses a second install, so this is the one gate the session will ever have.
        do {
            try session.setPresenceGate(
                gate: AppPresenceGate(
                    coordinator: presence, fallback: masterPasswordFallback, session: session))
        } catch {
            errorMessage = message(for: error)
        }
        let store = VaultStore(session: session)
        self.store = store
        // Every explicit vault operation counts as in-app activity, the same as a keystroke or a
        // click in one of our own windows (docs/investigations/2026-09-27-remote-idle-relock.md).
        store.notifyActivity = { [weak self] in self?.autoLock?.noteInAppActivity() }
        store.releases.notifyActivity = store.notifyActivity
        // Read-once, regardless of outcome: whether or not this turns out to be the same vault,
        // there is nothing left pending after this adoption.
        if let expectedFileId = reopeningAfterConflictFileId {
            reopeningAfterConflictFileId = nil
            if session.vaultFileId() == expectedFileId {
                session.noteReopenedAfterConflict()
            }
        }
        hasPlatformSlot = session.hasPlatformSlot()
        phase = .unlocked
        autoLock?.start()
        store.startSyncMonitor()
        // Before either listener starts, so no `request_fill` reaches the broker under a flag other
        // than the one the user set (ADR-0036 implementation decision 12).
        agentFill.applyStoredSwitch()
        // Serving agents is the whole of M4, and it starts the moment there is a key to serve
        // with. A failure to bind is not fatal — the vault still works — so it is recorded on the
        // service and shown in Agent access rather than raised as a modal.
        agent.start(session: session)
        // Started after the agent, because both listeners ask through the queue the agent's poll
        // loop is now draining — a fill that arrived before that loop existed would sit unanswered
        // until it timed out.
        browserExtension.start(session: session)
        browserPrompt.vaultUnlocked(ext: browserExtension)
        // After the agent: the machine vault's environments are served on its socket too, and
        // "While you were away" is read from the machine log. The shared vaults open now are the
        // store's, for copies of their environments (ADR-0042 §13).
        unattended.sharedSessions = { [weak self] in self?.store?.shared.vaults ?? [] }
        unattended.vaultUnlocked(session: session)
        // AutoFill (ADR-0045): serve the session, publish its logins, and republish whenever the
        // store re-reads its items.
        credentialProvider.vaultUnlocked(session)
        store.onItemsChanged = { [weak self] in self?.credentialProvider.itemsChanged() }
    }

    // MARK: - Locking

    /// "Lock and reopen from the file" — the conflict alert's non-destructive choice (step 4,
    /// user decision 3). An ordinary lock followed by an ordinary unlock already does the "reopen
    /// from the file" half, since unlocking always reads the file fresh; what this adds is
    /// remembering to note the recovery in the audit log once the next `adopt(_:)` succeeds.
    func lockAfterConflict() {
        // Captured before `lock(reason:)` runs: it sets `store = nil`, and the file id has to
        // name the vault that was just conflicting, not whatever (if anything) replaces it.
        reopeningAfterConflictFileId = store?.session.vaultFileId()
        lock(reason: .conflict)
    }

    /// Drop the vault key and every derived view of it.
    ///
    /// The vault is locked by an explicit `VaultSession.lock()` (ADR-0038 §4), not by letting go
    /// of the last reference: a release waiting on its presence prompt holds a reference to the
    /// session in Rust, so dropping ours alone would leave the vault open for as long as the
    /// prompt stayed up.
    func lock(reason: LockReason) {
        guard let store else { return }
        autoLock?.stop()
        store.stopSyncMonitor()
        // Order matters, and every step is synchronous:
        //
        // 1. What is on screen goes: every shown value is hidden and its release closed, and an
        //    answer still on its way is discarded when it arrives.
        // 2. The vault locks: the key is zeroized, the agent's and the extension's lock hooks deny
        //    every approval waiting and drop every lease, and a release waiting on its prompt is
        //    recorded `VAULT_LOCKED` and can no longer hand anything out, whatever the prompt says.
        // 3. The prompt that is up — a Touch ID sheet or the master-password panel — is torn down
        //    (its `LAContext` invalidated). Its slot frees when it has actually gone.
        // 4. The listeners stop, the store goes, and only then does the phase change, so no view
        //    can still be holding the session when it does.
        store.releases.hideAll(because: .locked)
        store.session.lock()
        presence.cancelInFlight()
        agent.stop()
        browserExtension.stop()
        browserPrompt.vaultLocked()
        // The recent agent-fill notices name items; they go with the key. Blocks stay (Rust's).
        agentFill.vaultLocked()
        // What was read from the machine vault goes with the key; armed jobs keep running.
        unattended.vaultLocked()
        credentialProvider.vaultLocked()
        self.store = nil
        pendingRecoveryCode = nil
        showGenerator = false
        showTouchIDOffer = false
        // A preview of someone's 1Password export must not outlive the vault it was going to be
        // imported into: the sheet holds a plan full of parsed values, and closing it drops it.
        closeImport()
        // A floating list of items must not outlive the key that decrypted it.
        quickAccess.close()
        refreshPhase(reason: reason)
    }

    // MARK: - Touch ID enrolment

    /// Enrol this Mac's Secure Enclave as an unlock method (ADR-0004, ADR-0008 crossing 3).
    ///
    /// `PlatformKeyService.enroll` can itself raise a Touch ID sheet (creating a Secure-Enclave key
    /// under a biometry-gated access control can prompt on macOS, per ADR-0011) — a second presence
    /// surface the app-wide `PresenceCoordinator` did not know about until now. It cannot drive that
    /// prompt the way it drives `gate.authenticate` (there is no `BiometricGate.authenticate` call
    /// here to make, only the Secure Enclave's own one, keyed off `enrollmentContext` instead), but
    /// it can still hold the one slot around it: a release or an approval that shows up while this
    /// is running is refused, not raised beside a sheet the person is already looking at, and this
    /// itself is refused, not queued, if something else holds the slot first.
    func enrollTouchID() {
        AppDefaults.shared.removeObject(forKey: TouchIDOffer.explicitlyOffKey)
        _ = enrollTouchID(quietly: false)
    }

    /// - Parameter quietly: an automatic enrolment reports nothing on failure; the caller falls
    ///   back to asking instead.
    /// - Returns: whether a platform slot was installed.
    @discardableResult
    private func enrollTouchID(quietly: Bool) -> Bool {
        guard let store else { return false }
        guard let ticket = presence.begin(.enrolment) else {
            if !quietly { errorMessage = String(localized: "Another confirmation is in progress.") }
            return false
        }
        let context = LAContext()
        enrollmentContext = context
        defer {
            enrollmentContext = nil
            presence.end(ticket)
        }
        do {
            var key = store.session.exportVaultKeyForPlatformWrapping()
            defer { key.resetBytes(in: 0..<key.count) }
            let enrolled = try self.platformKey.enroll(vaultKey: key, context: context)
            try store.session.installPlatformSlot(
                slotId: enrolled.slotId, label: "Touch ID on this Mac", wrappedKey: enrolled.wrappedKey)
            self.hasPlatformSlot = true
            return true
        } catch {
            if !quietly { errorMessage = message(for: error) }
            return false
        }
    }

    /// Touch ID is on by default (ADR-0004 amendment 2026-10-04): after a master-password or
    /// recovery-code unlock, enrol silently unless the person turned it off; otherwise, or if
    /// that fails, offer it once per unlock unless they asked not to be asked.
    private func offerTouchIDAfterUnlock() {
        guard store != nil else { return }
        let defaults = AppDefaults.shared
        var offer = TouchIDOffer.decide(
            available: platformAvailability.isAvailable, hasPlatformSlot: hasPlatformSlot,
            defaults: defaults)
        if offer == .autoEnrol, !enrollTouchID(quietly: true) {
            offer = TouchIDOffer.afterFailedAutoEnrol(
                dontAskAgain: defaults.bool(forKey: TouchIDOffer.dontAskAgainKey))
        }
        showTouchIDOffer = offer == .prompt
    }

    /// The offer sheet's answer.
    func answerTouchIDOffer(turnOn: Bool, dontAskAgain: Bool) {
        showTouchIDOffer = false
        if dontAskAgain { AppDefaults.shared.set(true, forKey: TouchIDOffer.dontAskAgainKey) }
        if turnOn { enrollTouchID() }
    }

    func disableTouchID() {
        AppDefaults.shared.set(true, forKey: TouchIDOffer.explicitlyOffKey)
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

    func copyUsername() {
        store?.copyUsername()
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

    /// The menu bar's agent-fill notice entry: bring the app forward on Agent access, where the
    /// notices and the blocks list are (ui-spec.md §10.4).
    func showAgentFillNotices() {
        store?.selection = .agentEnvironments
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Settings' links into the main window: bring it forward on one of its screens. With the
    /// vault locked there is nothing to select, and the window shows the lock screen.
    func show(_ selection: SidebarSelection) {
        store?.selection = selection
        NSApp.activate(ignoringOtherApps: true)
    }

    /// The menu bar's unattended entry: bring the app forward on Unattended jobs.
    func showUnattended() {
        store?.selection = .agentUnattended
        NSApp.activate(ignoringOtherApps: true)
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
        describeAnyError(error)
    }
}
