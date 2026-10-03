import AppKit
import Foundation
import Observation

import KagisecureFFI

/// The shared vaults this Mac belongs to (ADR-0035), while the personal vault is unlocked: the
/// sidebar's Shared section, the sheets that create and join one, and the automatic sync.
///
/// # Sync
///
/// A shared vault with a folder — an iCloud Drive or Dropbox folder the members share — syncs by
/// itself, with no button to remember (ui-spec.md §16.5):
///
/// * when anything in the folder changes (`FolderWatcher`, debounced by
///   `FolderWatcher.debounce` so a sync client writing a burst of files is one sync),
/// * when the app becomes active, and
/// * after each change made here (a write has already put its own record in the folder; the
///   sync picks up whatever arrived meanwhile).
///
/// A sync with nothing new reads no record file and writes nothing (decision 87), so running it
/// this often costs nothing. It runs off the main thread: reading a file a sync client has not
/// finished downloading can block.
///
/// Owned by `VaultStore`, so it lives exactly as long as the unlock: `stop()` runs when the store
/// stops its monitors, and `VaultSession.lock()` closes every shared session in Rust.
@MainActor
@Observable
final class SharedVaultsModel {
    private let personal: VaultSession

    /// Every shared vault, in the order they were opened or added.
    private(set) var vaults: [SharedVaultSession] = []
    /// Their summaries, in the same order — refreshed after every change.
    private(set) var summaries: [SharedVaultSummary] = []
    /// Why the last sync of a vault failed, by vault id; cleared by the next one that works.
    private(set) var syncProblems: [String: String] = [:]
    /// When each vault last synced, by vault id.
    private(set) var lastSynced: [String: Date] = [:]
    /// The members of each vault, by vault id, as last read.
    private(set) var members: [String: [SharedMemberView]] = [:]
    /// Each vault's environments (ui-spec.md §16), by vault id, as last read.
    private(set) var environments: [String: [EnvironmentView]] = [:]

    /// Told, on the main actor, when a sync brought something in for a vault — so the item list
    /// showing it can re-read.
    var onRemoteChange: ((String) -> Void)?

    private var watchers: [String: FolderWatcher] = [:]
    private var syncing: Set<String> = []
    private var syncAgain: Set<String> = []
    private var activeObserver: NSObjectProtocol?
    private var running = false

    init(personal: VaultSession) {
        self.personal = personal
        reload()
    }

    // MARK: - Reading

    func session(for id: String) -> SharedVaultSession? {
        vaults.first { $0.vaultId() == id }
    }

    func summary(for id: String) -> SharedVaultSummary? {
        summaries.first { $0.id == id }
    }

    /// Whether this Mac may add and edit items in `id` (a writer or an admin).
    func canWrite(_ id: String) -> Bool {
        guard let role = summary(for: id)?.myRole else { return false }
        return role != .reader
    }

    func isAdmin(_ id: String) -> Bool {
        summary(for: id)?.myRole == .admin
    }

    /// Re-open every shared vault from disk.
    func reload() {
        vaults = (try? personal.openSharedVaults()) ?? []
        refresh()
        if running { rewatch() }
    }

    /// Re-read every summary, member list and environment list.
    func refresh() {
        summaries = vaults.map { $0.summary() }
        members = Dictionary(uniqueKeysWithValues: vaults.map { ($0.vaultId(), $0.members()) })
        environments = Dictionary(
            uniqueKeysWithValues: vaults.map { ($0.vaultId(), $0.environments()) })
    }

    // MARK: - Creating and joining

    /// Create a shared vault, syncing through `folder` if one is given. Returns its id.
    func create(name: String, folder: URL?) throws -> String {
        let vault = try personal.createSharedVault(name: name, folder: folder?.path)
        adopt(vault)
        return vault.vaultId()
    }

    /// Join the vault `invitation` invites this Mac to. Returns its id. The passphrase is
    /// stretched with Argon2id, so this runs off the main thread.
    ///
    /// # Errors
    ///
    /// `FfiError.WrongCredential` for a wrong passphrase — the sheet says so in its own words.
    func join(invitation: URL, passphrase: String, folder: URL?) async throws -> String {
        let personal = self.personal
        let vault = try await Task.detached(priority: .userInitiated) {
            try personal.joinSharedVault(
                invitationPath: invitation.path, passphrase: passphrase, folder: folder?.path)
        }.value
        adopt(vault)
        return vault.vaultId()
    }

    private func adopt(_ vault: SharedVaultSession) {
        let id = vault.vaultId()
        vaults.removeAll { $0.vaultId() == id }
        vaults.append(vault)
        refresh()
        if running { rewatch() }
    }

    // MARK: - Changes made here

    /// After an item change or a member change in `id`: re-read, and sync.
    func didChangeLocally(_ id: String) {
        refresh()
        sync(id)
    }

    /// Sync `id` through `folder` from now on (or through none).
    func setFolder(_ id: String, _ folder: URL?) throws {
        guard let vault = session(for: id) else { return }
        _ = try vault.setFolder(folder: folder?.path)
        syncProblems[id] = nil
        lastSynced[id] = Date()
        refresh()
        rewatch()
    }

    /// Rebuild a damaged copy of `id` from `folder`.
    func rebuild(_ id: String, from folder: URL) throws {
        guard let vault = session(for: id) else { return }
        try vault.rebuild(folder: folder.path)
        refresh()
        rewatch()
        onRemoteChange?(id)
    }

    // MARK: - Sync

    /// Start syncing: watch every folder, sync on activation, and sync once now.
    func start() {
        guard !running else { return }
        running = true
        activeObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncAll() }
        }
        rewatch()
        syncAll()
    }

    /// Stop every watcher and the activation observer. Called when the vault locks.
    func stop() {
        running = false
        if let activeObserver {
            NotificationCenter.default.removeObserver(activeObserver)
        }
        activeObserver = nil
        for watcher in watchers.values { watcher.stop() }
        watchers = [:]
    }

    func syncAll() {
        for vault in vaults { sync(vault.vaultId()) }
    }

    /// Sync one vault, off the main thread. A sync asked for while one is running runs once more
    /// when it ends, so a change is never missed and syncs never pile up.
    func sync(_ id: String) {
        guard let vault = session(for: id), summary(for: id)?.folder != nil else { return }
        guard !syncing.contains(id) else {
            syncAgain.insert(id)
            return
        }
        syncing.insert(id)
        Task.detached(priority: .utility) {
            let result = Result { try vault.sync() }
            await MainActor.run { self.finished(id, result) }
        }
    }

    private func finished(_ id: String, _ result: Result<SharedSyncSummary, Error>) {
        syncing.remove(id)
        switch result {
        case .success(let summary):
            syncProblems[id] = nil
            lastSynced[id] = Date()
            if summary.recordsAdded > 0 {
                refresh()
                onRemoteChange?(id)
            }
        case .failure(FfiError.VaultLocked):
            return
        case .failure(let error):
            syncProblems[id] = describeAnyError(error)
        }
        if syncAgain.remove(id) != nil { sync(id) }
    }

    /// One watcher per vault with a folder; none for the rest.
    private func rewatch() {
        for watcher in watchers.values { watcher.stop() }
        watchers = [:]
        guard running else { return }
        for summary in summaries {
            guard let folder = summary.folder else { continue }
            let id = summary.id
            watchers[id] = FolderWatcher(folder: URL(fileURLWithPath: folder)) { [weak self] in
                self?.sync(id)
            }
        }
    }
}

/// Calls back when anything changes in a folder or its `records` subfolder, at most once per
/// `debounce`.
///
/// A `DispatchSource` on each directory's descriptor: a directory's `write` event is an entry
/// added, removed or renamed in it — which is what a sync client does when a record arrives. The
/// callback runs on the main actor.
@MainActor
final class FolderWatcher {
    /// How long a burst of changes has to be quiet before the callback runs.
    static let debounce: Duration = .milliseconds(1500)

    private var sources: [DispatchSourceFileSystemObject] = []
    private var pending: Task<Void, Never>?
    private let onChange: @MainActor () -> Void

    init(folder: URL, onChange: @escaping @MainActor () -> Void) {
        self.onChange = onChange
        for directory in [folder, folder.appendingPathComponent("records", isDirectory: true)] {
            let descriptor = open(directory.path, O_EVTONLY)
            guard descriptor >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: descriptor, eventMask: [.write, .rename, .delete], queue: .main)
            source.setEventHandler { [weak self] in
                MainActor.assumeIsolated { self?.changed() }
            }
            source.setCancelHandler { close(descriptor) }
            source.resume()
            sources.append(source)
        }
    }

    private func changed() {
        pending?.cancel()
        pending = Task { @MainActor [weak self] in
            try? await Task.sleep(for: Self.debounce)
            guard !Task.isCancelled else { return }
            self?.onChange()
        }
    }

    func stop() {
        pending?.cancel()
        pending = nil
        for source in sources { source.cancel() }
        sources = []
    }
}
