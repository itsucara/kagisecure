import Foundation
import KagisecureFFI
import Observation

/// The folder the person picked for the Mac link, remembered as a security-scoped bookmark in a
/// file beside the personal vault (never in iCloud, never in UserDefaults, so tests stay apart).
struct ExchangeFolderStore: Sendable {
    let containerDirectory: URL

    var bookmarkFile: URL { containerDirectory.appendingPathComponent("exchange-folder.bookmark") }
    /// The mirror Rust syncs with (Rust only ever sees this path).
    var mirrorDirectory: URL { containerDirectory.appendingPathComponent("Exchange", isDirectory: true) }

    /// Remember `url`, a folder the document picker just handed over (its scope already started).
    func remember(_ url: URL) throws {
        let data = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        try data.write(to: bookmarkFile, options: .atomic)
    }

    func forget() {
        try? FileManager.default.removeItem(at: bookmarkFile)
    }

    /// The remembered folder, if any; a stale bookmark is refreshed.
    func resolve() -> URL? {
        guard let data = try? Data(contentsOf: bookmarkFile) else { return nil }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
        else { return nil }
        if stale {
            let scoped = url.startAccessingSecurityScopedResource()
            try? remember(url)
            if scoped { url.stopAccessingSecurityScopedResource() }
        }
        return url
    }
}

/// The iPhone's side of the Mac link (ui-spec §16 for iPhone): the shared vaults this iPhone is a
/// device of, the picked folder and its mirror, joining, and syncing.
///
/// Lives as long as the unlock, like the Mac's `SharedVaultsModel`; `VaultSession.lock()` closes
/// every shared session in Rust.
@MainActor
@Observable
final class LinkModel {
    private let personal: VaultSession
    let folders: ExchangeFolderStore

    private(set) var vaults: [SharedVaultSession] = []
    private(set) var summaries: [SharedVaultSummary] = []
    /// The picked folder's name, while one is remembered.
    private(set) var folderName: String?
    /// Invitations found in the mirror, newest name order.
    private(set) var invitations: [URL] = []
    private(set) var syncing = false
    private(set) var lastSynced: Date?
    private(set) var lastReport: ExchangeMirror.Report?
    var problem: String?

    /// Told after a sync or a join changed what the item list shows.
    var onChange: (() -> Void)?

    private var syncAgain = false
    /// When the last sync finished, so the watcher can ignore our own write-back.
    private(set) var syncEndedAt: ContinuousClock.Instant?
    private var presenter: FolderPresenter?
    @ObservationIgnored private var watcher: FolderChangeDebouncer!

    init(personal: VaultSession, containerDirectory: URL) {
        self.personal = personal
        folders = ExchangeFolderStore(containerDirectory: containerDirectory)
        folderName = folders.resolve()?.lastPathComponent
        reload()
        watcher = FolderChangeDebouncer(
            isSyncing: { [weak self] in self?.syncing ?? false },
            lastSyncEnded: { [weak self] in self?.syncEndedAt },
            sync: { [weak self] in await self?.sync() })
    }

    func reload() {
        vaults = (try? personal.openSharedVaults()) ?? []
        summaries = vaults.map { $0.summary() }
        invitations = ExchangeMirror.list(folders.mirrorDirectory)
            .filter { $0.hasSuffix("." + ExchangeMirror.invitationExtension) }
            .sorted()
            .map { folders.mirrorDirectory.appendingPathComponent($0) }
    }

    var isLinked: Bool { !vaults.isEmpty }

    func session(for id: String) -> SharedVaultSession? { vaults.first { $0.vaultId() == id } }

    func canWrite(_ id: String) -> Bool {
        guard let role = summaries.first(where: { $0.id == id })?.myRole else { return false }
        return role != .reader
    }

    /// This iPhone's fingerprint in each vault, to compare with the Mac's members pane.
    func myFingerprints() -> [String] {
        vaults.flatMap { vault in
            vault.members().flatMap(\.devices).filter(\.isThisDevice).map(\.fingerprint)
        }
    }

    // MARK: - Folder

    /// The picker handed over `url`: remember it and pull its contents into the mirror.
    func choose(folder url: URL) async {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            try folders.remember(url)
            folderName = url.lastPathComponent
            problem = nil
            if presenter != nil { stopWatching(); startWatching() }
        } catch {
            problem = String(localized: "This folder could not be remembered: \(error.localizedDescription)")
            return
        }
        await sync()
    }

    func forgetFolder() {
        stopWatching()
        folders.forget()
        folderName = nil
    }

    // MARK: - Watching

    /// While the app is active: sync when the picked folder changes (the Mac saved something).
    func startWatching() {
        guard presenter == nil, let folder = folders.resolve() else { return }
        presenter = FolderPresenter(folder: folder) { [weak self] in self?.folderChanged() }
    }

    /// Going to the background or locking: stop presenting and give the folder's access back.
    func stopWatching() {
        watcher.cancel()
        presenter?.stop()
        presenter = nil
    }

    var isWatching: Bool { presenter != nil }

    /// The presenter's entry point (and the tests'): something in the folder changed.
    func folderChanged() { watcher.folderChanged() }

    /// Back in the foreground while still unlocked: catch up with what the Mac saved meanwhile.
    /// Skipped with nothing linked, while a sync runs (the running one covers it), and within the
    /// watcher's own-write window right after a sync. Returns whether a sync ran.
    @discardableResult
    func syncOnForeground() async -> Bool {
        guard isLinked || folders.resolve() != nil else { return false }
        guard !syncing, !watcher.isOwnEcho else { return false }
        await sync()
        return true
    }

    /// Whether two folder paths name the same folder (`/var` vs `/private/var`, `..`, a trailing
    /// slash), so a vault is only re-pointed when it really points elsewhere.
    nonisolated static func samePath(_ a: String, _ b: String) -> Bool {
        func norm(_ p: String) -> String {
            URL(fileURLWithPath: p).standardizedFileURL.resolvingSymlinksInPath().path
        }
        return a == b || norm(a) == norm(b)
    }

    // MARK: - Joining

    /// Join with an invitation the Mac saved into the folder (now in the mirror), syncing through
    /// the mirror from then on.
    func join(invitation: URL, words: String) async throws {
        let personal = self.personal
        let mirror = folders.mirrorDirectory.path
        // Joining stretches the words with Argon2id: off the main thread.
        _ = try await Task.detached(priority: .userInitiated) {
            try personal.joinSharedVault(
                invitationPath: invitation.path, passphrase: words, folder: mirror)
        }.value
        reload()
        await sync()
    }

    // MARK: - Sync

    /// Picked folder → mirror, every vault's own sync, mirror → picked folder. Off the main
    /// thread; a sync asked for while one runs runs once more after it.
    func sync() async {
        guard !syncing else {
            syncAgain = true
            return
        }
        syncing = true
        defer {
            syncing = false
            syncEndedAt = ContinuousClock.now
        }
        repeat {
            syncAgain = false
            await syncOnce()
        } while syncAgain
    }

    private func syncOnce() async {
        let remote = folders.resolve()
        let mirror = ExchangeMirror(remote: remote ?? folders.mirrorDirectory, mirror: folders.mirrorDirectory)
        let vaults = self.vaults
        let mirrorPath = folders.mirrorDirectory.path
        let result: Result<(ExchangeMirror.Report, Int), Error> = await Task.detached(priority: .utility) {
            Result {
                let scoped = remote?.startAccessingSecurityScopedResource() ?? false
                defer { if scoped { remote?.stopAccessingSecurityScopedResource() } }
                var report = ExchangeMirror.Report()
                if remote != nil { report = try mirror.sync() }
                // The app container's absolute path changes when the app is reinstalled or
                // updated, so a vault joined earlier may still point at the old mirror path.
                // Re-point every linked vault at today's mirror before it syncs.
                for vault in vaults {
                    if let folder = vault.summary().folder, !LinkModel.samePath(folder, mirrorPath) {
                        _ = try vault.setFolder(folder: mirrorPath)
                    }
                }
                var added = 0
                for vault in vaults where vault.summary().folder != nil {
                    added += Int(try vault.sync().recordsAdded)
                }
                if remote != nil {
                    let out = try mirror.sync()
                    report.pulled += out.pulled
                    report.pushed += out.pushed
                    report.pending = out.pending
                }
                return (report, added)
            }
        }.value
        switch result {
        case .success(let (report, _)):
            lastReport = report
            lastSynced = Date()
            problem = nil
        case .failure(FfiError.VaultLocked):
            return
        case .failure(let error):
            problem = AppModel.message(for: error)
        }
        reload()
        onChange?()
    }
}
