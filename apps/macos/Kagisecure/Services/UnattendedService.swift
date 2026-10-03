import AppKit
import Foundation
import Observation
import Security
import ServiceManagement

import KagisecureFFI

/// Unattended jobs, on the app's side (ADR-0042 Phase 3; ui-spec.md §10.8).
///
/// # Arming, and the Keychain
///
/// Arming is a person's act: it asks for Touch ID or the login password through the shared
/// `PresenceCoordinator`, then `unattendedArm` hands back the machine vault's key, which this class
/// keeps in the login Keychain — this device only, never synchronized — so that after a restart
/// the app re-arms at launch (`launch`) with nobody present (ADR-0042 implementation decision 1).
/// Arming has no expiry. Pause asks for nothing and deletes the Keychain item; so does the engine
/// disarming itself (a `lock` request on the unattended socket, a conflicting file), which reaches
/// here as a `DISARMED` notice.
///
/// # What the person decides
///
/// Copying an environment or a login into the machine vault, creating a job (with its command
/// grant and its login grant, in one step) and re-enabling a suspended grant each ask for
/// presence first. Revoking and pausing never
/// do: narrowing is always allowed. Updating a copied environment re-approves the grants over it
/// (owner's answer 10).
///
/// # Noticing
///
/// The engine's notices — a suspension, a disarm, a missed run — are drained every two seconds,
/// whether the vault is locked or not, and posted as local notifications. The machine log since
/// the person last acknowledged it is "While you were away", shown after an unlock when there is
/// anything in it; it and the unseen notices are the menu-bar badge.
@MainActor
@Observable
final class UnattendedService {
    /// The engine's state.
    private(set) var status = UnattendedStatusView(
        running: false, armed: false, armedAt: nil, endpoint: "", runs: [])

    /// The machine vault's environments and jobs, while the personal vault is unlocked.
    private(set) var overview: UnattendedOverviewView?

    /// "While you were away", while the personal vault is unlocked.
    private(set) var summary: UnattendedSummaryView?

    /// The machine vault's logins, for sign-ins (ADR-0042 §12), while unlocked.
    private(set) var logins: [MachineLoginView] = []

    /// Every login grant, while unlocked.
    private(set) var loginGrants: [UnattendedLoginGrantView] = []

    /// Set to show the "While you were away" sheet.
    var showWhileAway = false

    /// Why the last action did not do what was asked.
    var problem: String?

    /// A presence check is up.
    private(set) var confirming = false

    /// The arm sheet is shown. One source of truth for it, so one Arm shows it once (the owner's
    /// GUI check, item 9).
    var armSheetShown = false

    /// An arm is in progress, from the sheet's button until the key is kept.
    private(set) var arming = false

    /// The most recent notices, newest first.
    private(set) var recentNotices: [UnattendedNoticeView] = []

    /// Notices that arrived since the person last looked.
    private(set) var unseenNotices = 0

    /// What the menu-bar badge counts: unseen notices, and the summary's entries.
    var attention: Int { unseenNotices + Int(summary?.total ?? 0) }

    /// How many notices are kept for the pane.
    static let recentLimit = 10

    let presence: PresenceCoordinator
    var keyStore: ArmKeyStore
    var notifier: AgentFillNotifier

    // MARK: - Seams
    //
    // Every FFI call goes through a replaceable closure so the unit tests can drive this class
    // without an engine, a vault or a Keychain.

    var startEngine: (String) throws -> Void = { _ = try unattendedStart(machinePath: $0, socketPath: nil) }
    var resumeEngine: (Data) throws -> Bool = { try unattendedResume(keychain: $0) }
    var armEngine: (VaultSession) throws -> Data = {
        try unattendedArm(session: $0, presence: .confirmed)
    }
    var disarmEngine: (VaultSession?) -> Bool = { unattendedDisarm(session: $0) }
    var fetchStatus: () -> UnattendedStatusView = { unattendedStatus() }
    var takeNotices: () -> [UnattendedNoticeView] = { unattendedTakeNotices() }
    var fetchOverview: (VaultSession) throws -> UnattendedOverviewView = {
        try unattendedOverview(session: $0)
    }
    var fetchSummary: (VaultSession) throws -> UnattendedSummaryView = {
        try unattendedSummary(session: $0)
    }
    var acknowledgeSummary: (VaultSession) throws -> Void = {
        try unattendedAcknowledgeSummary(session: $0)
    }
    var copyEnvironment: (VaultSession, String) throws -> String = {
        try unattendedCopyEnvironment(session: $0, personalEnvironmentId: $1, presence: .confirmed)
    }
    var removeEnvironment: (VaultSession, String) throws -> Bool = {
        try unattendedRemoveEnvironment(session: $0, environmentId: $1)
    }
    var createJob: (VaultSession, UnattendedJobDraft) throws -> String = {
        try unattendedCreateJob(session: $0, draft: $1, presence: .confirmed)
    }
    var revokeJob: (VaultSession, String) throws -> Bool = {
        try unattendedRevokeJob(session: $0, jobId: $1)
    }
    var reenableGrant: (VaultSession, String) throws -> Bool = {
        try unattendedReenableGrant(session: $0, grantId: $1, presence: .confirmed)
    }
    var runJobNow: (String) throws -> Void = { _ = try unattendedRunNow(jobId: $0) }
    var fetchLogins: (VaultSession) throws -> [MachineLoginView] = {
        try unattendedMachineLogins(session: $0)
    }
    var fetchLoginGrants: (VaultSession) throws -> [UnattendedLoginGrantView] = {
        try unattendedLoginGrants(session: $0)
    }
    var copyLoginItem: (VaultSession, String) throws -> String = {
        try unattendedCopyLogin(session: $0, personalItemId: $1, presence: .confirmed)
    }
    /// The browser a job that signs in gets unless the person chooses another.
    var defaultRunBrowser: () -> String? = { unattendedDefaultRunBrowser() }
    var attachToAgent: (VaultSession) throws -> Void = { _ = try agentAttachMachineVault(session: $0) }

    // MARK: Shared vaults (ADR-0042 §13, Phase 4)

    /// The shared vaults open now. Set by the app to its store's; empty while locked.
    var sharedSessions: () -> [SharedVaultSession] = { [] }
    var fetchStale: (VaultSession, [SharedVaultSession]) throws -> [String] = {
        try unattendedStaleCopies(session: $0, shared: $1)
    }
    var fetchSharedCopies: (SharedVaultSession) throws -> [SharedUnattendedCopyView] = {
        try sharedUnattendedCopies(shared: $0)
    }
    var fetchSharedAllowed: (SharedVaultSession) throws -> Bool = {
        try sharedUnattendedCopiesAllowed(shared: $0)
    }
    var storeSharedAllowed: (SharedVaultSession, Bool) throws -> Void = {
        try sharedSetUnattendedCopiesAllowed(shared: $0, allowed: $1)
    }
    var fetchSharedChoices: (SharedVaultSession) throws -> [SharedEnvironmentChoice] = {
        try sharedEnvironmentsForCopy(shared: $0)
    }
    var copySharedEnvironment: (VaultSession, SharedVaultSession, String, String) throws -> String = {
        try unattendedCopySharedEnvironment(
            session: $0, shared: $1, environmentId: $2, holder: $3, presence: .confirmed)
    }
    var removeSharedCopy: (VaultSession, SharedVaultSession, String, String) throws -> Bool = {
        try unattendedRemoveSharedCopy(session: $0, shared: $1, environmentId: $2, holder: $3)
    }

    /// How this Mac describes itself in a shared vault's copy records.
    var holder: () -> String = { Host.current().localizedName ?? String(localized: "a Mac") }

    /// Machine environments whose source changed since they were copied: **Update** copies them
    /// again (the owner's decision: copies stay copies).
    private(set) var staleCopies: Set<String> = []

    /// Who holds unattended copies of each open shared vault's values, by vault id.
    private(set) var sharedCopies: [String: [SharedUnattendedCopyView]] = [:]

    /// Whether each open shared vault allows unattended copies, by vault id.
    private(set) var sharedCopiesAllowed: [String: Bool] = [:]

    // MARK: The login item (ADR-0042 implementation decision 32)

    /// Whether the app opens at login, so armed jobs run after a restart.
    private(set) var loginItemEnabled = false

    var registerLoginItem: () throws -> Void = { try SMAppService.mainApp.register() }
    var unregisterLoginItem: () throws -> Void = { try SMAppService.mainApp.unregister() }
    var loginItemStatus: () -> Bool = { SMAppService.mainApp.status == .enabled }

    /// Set once the app has registered itself on a first arm, so it never does again on its own:
    /// after that only the toggle changes it.
    static let loginItemRegisteredKey = "unattendedLoginItemRegistered"
    private let defaults: UserDefaults

    private var ticker: Task<Void, Never>?

    init(
        presence: PresenceCoordinator,
        keyStore: ArmKeyStore = KeychainArmKeyStore(),
        notifier: AgentFillNotifier = SystemAgentFillNotifier(),
        defaults: UserDefaults = AppDefaults.shared
    ) {
        self.presence = presence
        self.keyStore = keyStore
        self.notifier = notifier
        self.defaults = defaults
    }

    // MARK: - Launch

    /// Start the engine for the machine vault beside `vaultPath`, and re-arm from the Keychain if
    /// the machine vault is still armed; delete the Keychain item if it is not. Then keep ticking.
    func launch(vaultPath: String, tick: Bool = true) {
        let machinePath = unattendedMachineVaultPath(vaultPath: vaultPath)
        do {
            try startEngine(machinePath)
        } catch {
            problem = String(localized: "Unattended jobs cannot run: \(describeAnyError(error))")
            return
        }
        if var bytes = keyStore.read() {
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            do {
                if try !resumeEngine(bytes) {
                    keyStore.delete()
                }
            } catch {
                problem =
                    String(localized: "Unattended jobs could not be armed again after the restart: \(describeAnyError(error))")
            }
        }
        status = fetchStatus()
        if tick { startTicking() }
    }

    private func startTicking() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                self?.tick()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Re-read the engine's state and drain its notices.
    func tick() {
        status = fetchStatus()
        let fresh = takeNotices()
        guard !fresh.isEmpty else { return }
        for notice in fresh {
            // The engine disarmed itself: the key must not come back at the next launch.
            if notice.kind == "DISARMED" { keyStore.delete() }
            recentNotices.insert(notice, at: 0)
        }
        if recentNotices.count > Self.recentLimit {
            recentNotices.removeLast(recentNotices.count - Self.recentLimit)
        }
        unseenNotices += fresh.count
        let texts = fresh.map(UnattendedText.notification)
        let notifier = notifier
        Task {
            for (title, body) in texts { await notifier.post(title: title, body: body) }
        }
    }

    /// The Unattended pane is on screen.
    func markSeen() {
        unseenNotices = 0
    }

    // MARK: - The personal vault

    /// The personal vault unlocked: serve the machine vault's environments on the ordinary socket
    /// too (with the ordinary sheet), read what the machine vault holds, and show "While you were
    /// away" when the machine log has anything the person has not acknowledged.
    func vaultUnlocked(session: VaultSession) {
        try? attachToAgent(session)
        refresh(session: session)
        if let summary, summary.total > 0 { showWhileAway = true }
    }

    /// The personal vault locked. What was read from the machine vault goes with the key; the
    /// engine stays armed.
    func vaultLocked() {
        overview = nil
        summary = nil
        logins = []
        loginGrants = []
        showWhileAway = false
        problem = nil
        staleCopies = []
        sharedCopies = [:]
        sharedCopiesAllowed = [:]
    }

    /// Re-read the machine vault, which copies are stale, and each open shared vault's copies.
    func refresh(session: VaultSession) {
        loginItemEnabled = loginItemStatus()
        do {
            overview = try fetchOverview(session)
            summary = try fetchSummary(session)
            logins = try fetchLogins(session)
            loginGrants = try fetchLoginGrants(session)
        } catch {
            problem = describeAnyError(error)
        }
        let shared = sharedSessions()
        staleCopies = Set((try? fetchStale(session, shared)) ?? [])
        var copies: [String: [SharedUnattendedCopyView]] = [:]
        var allowed: [String: Bool] = [:]
        for vault in shared {
            let id = vault.vaultId()
            copies[id] = (try? fetchSharedCopies(vault)) ?? []
            allowed[id] = (try? fetchSharedAllowed(vault)) ?? true
        }
        sharedCopies = copies
        sharedCopiesAllowed = allowed
    }

    /// "While you were away" was read.
    func acknowledge(session: VaultSession) {
        do {
            try acknowledgeSummary(session)
        } catch {
            problem = describeAnyError(error)
        }
        showWhileAway = false
        refresh(session: session)
    }

    // MARK: - Arming

    /// The sentence above the presence prompt for arming.
    static let armReason = String(
        localized: "arm unattended jobs. They will run on schedule with nobody present, even after a restart, until you pause them")

    /// Show the arm sheet, unless it is up, an arm is in progress, or jobs are armed already.
    func requestArm() {
        guard !arming, !armSheetShown, !status.armed else { return }
        armSheetShown = true
    }

    /// Arm, after a presence check: the key goes to the Keychain so a restart re-arms. The sheet
    /// is dismissed first, before the presence prompt, and a second call while one is in progress
    /// does nothing. A personal vault with no machine vault gets one (`unattendedArm`).
    func arm(session: VaultSession) async {
        armSheetShown = false
        guard !arming, !status.armed else { return }
        arming = true
        defer { arming = false }
        problem = nil
        guard await confirm(Self.armReason) else { return }
        do {
            var bytes = try armEngine(session)
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            do {
                try keyStore.save(bytes)
            } catch {
                problem =
                    String(localized: "Armed, but the key could not be kept in the Keychain, so a restart will pause jobs: \(describeAnyError(error))")
            }
        } catch {
            problem = describeAnyError(error)
            return
        }
        status = fetchStatus()
        // The first arm may have created the machine vault: serve it on the ordinary socket too.
        try? attachToAgent(session)
        // The first arm opens the app at login, so jobs run after a restart; from then on only
        // the person's toggle changes it.
        if !defaults.bool(forKey: Self.loginItemRegisteredKey) {
            defaults.set(true, forKey: Self.loginItemRegisteredKey)
            do {
                try registerLoginItem()
            } catch {
                problem =
                    String(localized: "Kagisecure could not add itself to Login Items (\(describeAnyError(error))). Add it in System Settings so jobs run after a restart.")
            }
        }
        refresh(session: session)
        await notifier.requestAuthorization()
    }

    /// The "Open at login" toggle.
    func setLoginItem(_ on: Bool) {
        do {
            if on { try registerLoginItem() } else { try unregisterLoginItem() }
        } catch {
            problem = describeAnyError(error)
        }
        loginItemEnabled = loginItemStatus()
    }

    /// Pause: disarm and forget the Keychain item. Asks for nothing; works while locked too.
    func pause(session: VaultSession?) {
        _ = disarmEngine(session)
        keyStore.delete()
        status = fetchStatus()
        if let session { refresh(session: session) }
    }

    // MARK: - Decisions

    /// Copy (or update) a personal environment into the machine vault, after a presence check.
    /// Updating re-approves the grants over it.
    func copy(environmentId: String, session: VaultSession) async {
        problem = nil
        guard await confirm(Self.copyReason) else { return }
        if perform(session, { _ = try self.copyEnvironment(session, environmentId) }) {
            // The first copy creates the machine vault: serve it on the ordinary socket too.
            try? attachToAgent(session)
        }
    }

    static let copyReason = String(
        localized: "copy an environment's values into the machine vault, where jobs you define may use them with nobody present")

    /// Remove a machine-vault environment and the jobs that use it. Asks for nothing. A copy of a
    /// shared vault's environment also tells that vault's members it is gone.
    func remove(_ env: MachineEnvironmentView, session: VaultSession) {
        if let (vault, _) = env.copiedFrom.flatMap(Self.sharedSource),
            let shared = sharedSessions().first(where: { $0.vaultId() == vault })
        {
            perform(session) { _ = try self.removeSharedCopy(session, shared, env.id, self.holder()) }
        } else {
            perform(session) { _ = try self.removeEnvironment(session, env.id) }
        }
    }

    /// Copy a shared vault's environment into the machine vault, after a presence check; its
    /// members are told this Mac holds it.
    func copyShared(environmentId: String, from shared: SharedVaultSession, session: VaultSession)
        async
    {
        problem = nil
        guard await confirm(Self.copyReason) else { return }
        if perform(session, {
            _ = try self.copySharedEnvironment(session, shared, environmentId, self.holder())
        }) {
            try? attachToAgent(session)
        }
    }

    /// Update a copy from its source, personal or shared, after a presence check. Re-approves
    /// the grants over it.
    func update(_ env: MachineEnvironmentView, session: VaultSession) async {
        guard let source = env.copiedFrom else { return }
        if let (vault, environment) = Self.sharedSource(source) {
            guard let shared = sharedSessions().first(where: { $0.vaultId() == vault }) else {
                problem = String(localized: "Open the shared vault this copy came from, then Update it.")
                return
            }
            await copyShared(environmentId: environment, from: shared, session: session)
        } else {
            await copy(environmentId: source, session: session)
        }
    }

    /// Whether `env` can be updated from a source open now.
    func canUpdate(_ env: MachineEnvironmentView, personal: [EnvironmentView]) -> Bool {
        guard let source = env.copiedFrom else { return false }
        if let (vault, _) = Self.sharedSource(source) {
            return sharedSessions().contains { $0.vaultId() == vault }
        }
        return personal.contains { $0.id == source }
    }

    /// The environments of `shared` that could be copied.
    func choices(in shared: SharedVaultSession) -> [SharedEnvironmentChoice] {
        (try? fetchSharedChoices(shared)) ?? []
    }

    /// Allow or forbid unattended copies of a shared vault's values, as its admin.
    func setCopiesAllowed(_ allowed: Bool, in shared: SharedVaultSession, session: VaultSession) {
        perform(session) { try self.storeSharedAllowed(shared, allowed) }
    }

    /// `(vault id, environment id)` for a copy of a shared environment (`shared:<vault>:<env>`).
    static func sharedSource(_ copiedFrom: String) -> (String, String)? {
        let parts = copiedFrom.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "shared", !parts[1].isEmpty, !parts[2].isEmpty else {
            return nil
        }
        return (String(parts[1]), String(parts[2]))
    }

    /// Copy (or update) a personal login into the machine vault, after a presence check, so a
    /// job may sign in with it (ADR-0042 §12.1). Updating re-approves the login grants over it.
    func copyLogin(itemId: String, session: VaultSession) async {
        problem = nil
        guard await confirm(Self.copyLoginReason) else { return }
        if perform(session, { _ = try self.copyLoginItem(session, itemId) }) {
            try? attachToAgent(session)
        }
    }

    static let copyLoginReason = String(
        localized: "copy a login into the machine vault, where a job you define may sign in with it with nobody present")

    /// The login grants of one job.
    func loginGrants(ofJob jobId: String) -> [UnattendedLoginGrantView] {
        loginGrants.filter { $0.jobId == jobId }
    }

    /// Create a job and its grant, after a presence check. `true` when it was created.
    func create(_ draft: UnattendedJobDraft, session: VaultSession) async -> Bool {
        problem = nil
        guard await confirm(Self.createReason) else { return false }
        return perform(session) { _ = try self.createJob(session, draft) }
    }

    static let createReason = String(
        localized: "create an unattended job that may use machine credentials with nobody present")

    /// Revoke a job and its grant. Asks for nothing.
    func revoke(jobId: String, session: VaultSession) {
        perform(session) { _ = try self.revokeJob(session, jobId) }
    }

    /// Re-enable a suspended grant, after a presence check.
    func reenable(grantId: String, session: VaultSession) async {
        problem = nil
        guard await confirm(Self.reenableReason) else { return }
        perform(session) { _ = try self.reenableGrant(session, grantId) }
    }

    static let reenableReason = String(localized: "let a suspended unattended job use its grant again")

    /// Start a job now.
    func runNow(jobId: String) {
        do {
            try runJobNow(jobId)
        } catch {
            problem = describeAnyError(error)
        }
        status = fetchStatus()
    }

    // MARK: - Plumbing

    @discardableResult
    private func perform(_ session: VaultSession, _ body: () throws -> Void) -> Bool {
        var ok = true
        do {
            try body()
        } catch {
            problem = describeAnyError(error)
            ok = false
        }
        refresh(session: session)
        return ok
    }

    /// A fresh presence check through the shared coordinator. `false`, with `problem` set, unless
    /// the person authenticated and the vault did not lock meanwhile.
    private func confirm(_ reason: String) async -> Bool {
        guard let ticket = presence.begin(.featureSwitch) else {
            problem = String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
            return false
        }
        confirming = true
        let generation = presence.cancelGeneration
        let outcome = await presence.authenticate(ticket, reason: reason)
        confirming = false
        guard presence.cancelGeneration == generation else {
            problem = String(localized: "The vault locked before you confirmed. Nothing changed.")
            return false
        }
        switch outcome {
        case .authenticated:
            return true
        case .cancelled:
            problem = String(localized: "Authentication cancelled. Nothing changed.")
        case .unavailable(let why):
            problem = String(localized: "Could not ask for authentication: \(why). Nothing changed.")
        case .busy:
            problem = String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
        }
        return false
    }
}

// MARK: - The Keychain

/// Where the machine vault's key is kept while armed.
@MainActor
protocol ArmKeyStore: AnyObject {
    /// The stored bytes, if any.
    func read() -> Data?
    /// Store `bytes`, replacing what was there.
    func save(_ bytes: Data) throws
    /// Forget the stored bytes. Idempotent.
    func delete()
}

/// A Keychain failure, by its `OSStatus`.
struct KeychainError: LocalizedError {
    let status: OSStatus
    var errorDescription: String? {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)"
    }
}

/// The login Keychain: one generic-password item, accessible after the first unlock, this device
/// only, never synchronized (ADR-0042 implementation decision 1).
@MainActor
final class KeychainArmKeyStore: ArmKeyStore {
    static let service = "com.kagisecure.unattended"
    static let account = "machine-vault-key"

    /// The item's account. An instance pointed at another vault (`KAGISECURE_VAULT` or
    /// `KAGISECURE_HOME`: `make run`, the e2e suites, a screenshot build) gets an account of its
    /// own, so its launch can neither re-arm with nor delete the real install's key.
    let account: String

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        if let vault = environment["KAGISECURE_VAULT"] ?? environment["KAGISECURE_HOME"],
            !vault.isEmpty
        {
            account = "\(Self.account)@\(vault)"
        } else {
            account = Self.account
        }
    }

    private var base: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
    }

    func read() -> Data? {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    func save(_ bytes: Data) throws {
        delete()
        var item = base
        item[kSecValueData as String] = bytes
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecAttrLabel as String] = "Kagisecure unattended jobs"
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    func delete() {
        SecItemDelete(base as CFDictionary)
    }
}

// MARK: - Words

/// The strings the unattended surfaces show, kept together so they can be tested.
enum UnattendedText {
    /// ADR-0042's first true sentence, carried verbatim wherever a grant is made.
    static let commandCost = String(
        localized: "kagisecure still never gives an agent a value. Under a standing grant, it hands a machine credential to a command you pinned, at times you scheduled, with nobody watching — and anything that can change what that command does while you are away can obtain that credential.")

    /// What arming means, on the arm sheet.
    static let armCost = String(
        localized: "Jobs you defined will run on schedule and may use their grants with nobody present — across screen lock, sleep and restarts — until you pause them. The key stays in this Mac's login Keychain while armed: a stolen or restarted Mac keeps releasing machine credentials to these jobs once someone is logged in.")

    /// The interpreter box on the New Job sheet (ADR-0042 §5).
    static let interpreterCost = String(
        localized: "A grant for an interpreter is a grant for whatever it reads. Nothing this interpreter runs is pinned: any change to its script changes what the credential is used for, and nothing will be suspended.")

    /// Executables whose grant is a grant for whatever they read (ADR-0042 §5).
    static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "env", "node", "npm", "npx",
        "pnpm", "yarn", "bun", "deno", "python", "python3", "ruby", "perl", "php", "make",
        "osascript",
    ]

    /// Whether `path` names a shell, an interpreter or a package runner.
    static func isInterpreter(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        if interpreters.contains(name) { return true }
        // `python3.12`, `node18`, `ruby3.3`.
        return interpreters.contains { name.hasPrefix($0) && name.dropFirst($0.count).allSatisfy { $0.isNumber || $0 == "." } }
    }

    static let weekdays = [
        String(localized: "Monday"), String(localized: "Tuesday"), String(localized: "Wednesday"),
        String(localized: "Thursday"), String(localized: "Friday"), String(localized: "Saturday"),
        String(localized: "Sunday"),
    ]

    /// "Every day at 02:30", "Sundays at 12:00".
    static func schedule(_ times: [UnattendedTimeView]) -> String {
        guard !times.isEmpty else { return String(localized: "Never") }
        return times.map { time in
            let clock = String(format: "%02d:%02d", time.hour, time.minute)
            guard let day = time.weekday, Int(day) < weekdays.count else {
                return String(localized: "Every day at \(clock)")
            }
            switch Int(day) {
            case 0: return String(localized: "Mondays at \(clock)")
            case 1: return String(localized: "Tuesdays at \(clock)")
            case 2: return String(localized: "Wednesdays at \(clock)")
            case 3: return String(localized: "Thursdays at \(clock)")
            case 4: return String(localized: "Fridays at \(clock)")
            case 5: return String(localized: "Saturdays at \(clock)")
            default: return String(localized: "Sundays at \(clock)")
            }
        }.joined(separator: "; ")
    }

    /// One argument per non-empty line.
    static func arguments(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// ADR-0042's sentence for logins, carried verbatim wherever a login grant is made.
    static let loginCost = String(
        localized: "Under a login grant, kagisecure types a service account's password into one site, in a browser it started for this job, with nobody watching. The job's agent can read what is typed there: treat the account as one the agent holds.")

    /// What the login grant's sheet says of the account (ADR-0042 §12.2).
    static let loginAdvice = String(
        localized: "The job's agent can read this password. Use an account that can do only what this job needs, and that you can reset.")

    /// The one-time-code switch's own box (ADR-0042 §12.5).
    static let oneTimeCodeCost = String(
        localized: "With this on, this account's second factor no longer protects it from anything on this Mac: whoever can drive this job's browser during a run gets the password and a valid code together. It still protects the account if the password leaks from the service.")

    /// Why a grant is suspended, in words.
    static func suspension(_ reason: String) -> String {
        switch reason {
        case "NO_GRANT": String(localized: "the job asked for something its grant does not cover")
        case "PIN_CHANGED": String(localized: "a pinned program or file changed")
        case "VALUE_CHANGED": String(localized: "a value it releases changed outside the app")
        case "WEBSITE_CHANGED": String(localized: "the login's website changed")
        case "ITEM_GONE": String(localized: "the login is gone from the machine vault")
        case "OTHER_ORIGIN":
            String(localized: "its browser was on a site the login is not saved for. Reset this account's password at the service")
        case "UNATTENDED_FILL_UNMASKED":
            String(localized: "the filled password was unmasked on the page. Reset this account's password at the service")
        default: reason
        }
    }

    /// A notification for one engine notice. Names a job and a reason, never a value.
    static func notification(_ notice: UnattendedNoticeView) -> (String, String) {
        let job = notice.job.map { String(localized: "“\($0)”") } ?? String(localized: "A job")
        switch notice.kind {
        case "SUSPENDED":
            return (
                String(localized: "Unattended job suspended"),
                String(localized: "\(job) was stopped: \(suspension(notice.reason)). Review it in Kagisecure.")
            )
        case "DISARMED":
            return (String(localized: "Unattended jobs paused"), String(localized: "No job will run until you arm them again (\(notice.reason))."))
        case "JOB_MISSED":
            return (String(localized: "Unattended job missed"), String(localized: "\(job) did not run at its time (\(notice.reason))."))
        case "JOB_NOT_STARTED":
            return (String(localized: "Unattended job not started"), String(localized: "\(job) did not start (\(notice.reason))."))
        default:
            return (String(localized: "Unattended jobs"), String(localized: "\(job): \(notice.kind) (\(notice.reason))."))
        }
    }
}
