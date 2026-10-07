import Foundation

/// Turns "something in the picked folder changed" into at most one sync per burst.
///
/// Changes are gathered for `debounce` (1.5 s) and then `sync` runs once. Changes seen while our
/// own sync runs, or within `quiet` (3 s) after it ends, are ignored: `LinkModel.syncOnce()` writes
/// the mirror back into the folder, and that write must not start the next sync.
///
/// The presenter (or a test) calls `folderChanged()`; the clock and the sync are injected so tests
/// can drive it without iCloud.
@MainActor
final class FolderChangeDebouncer {
    let debounce: Duration
    let quiet: Duration
    private let now: () -> ContinuousClock.Instant
    private let isSyncing: () -> Bool
    private let lastSyncEnded: () -> ContinuousClock.Instant?
    private let sync: () async -> Void
    private var pending: Task<Void, Never>?

    init(
        debounce: Duration = .milliseconds(1500), quiet: Duration = .seconds(3),
        now: @escaping () -> ContinuousClock.Instant = { ContinuousClock.now },
        isSyncing: @escaping () -> Bool, lastSyncEnded: @escaping () -> ContinuousClock.Instant?,
        sync: @escaping () async -> Void
    ) {
        self.debounce = debounce
        self.quiet = quiet
        self.now = now
        self.isSyncing = isSyncing
        self.lastSyncEnded = lastSyncEnded
        self.sync = sync
    }

    /// Whether a change seen now is our own write-back.
    var isOwnEcho: Bool {
        if isSyncing() { return true }
        if let ended = lastSyncEnded(), now() - ended < quiet { return true }
        return false
    }

    func folderChanged() {
        guard !isOwnEcho else { return }
        pending?.cancel()
        let debounce = self.debounce
        pending = Task { [weak self] in
            try? await Task.sleep(for: debounce)
            guard !Task.isCancelled, let self else { return }
            self.pending = nil
            // A sync that started meanwhile (unlock, pull to refresh) already covers it.
            guard !self.isSyncing() else { return }
            await self.sync()
        }
    }

    func cancel() {
        pending?.cancel()
        pending = nil
    }
}

/// Watches the folder the person picked in Files with `NSFilePresenter` (`NSMetadataQuery` only
/// sees our own iCloud container, not a folder picked elsewhere). Keeps the folder's
/// security-scoped access open for as long as it presents.
final class FolderPresenter: NSObject, NSFilePresenter, @unchecked Sendable {
    let presentedItemURL: URL?
    let presentedItemOperationQueue: OperationQueue = .main
    private let changed: @MainActor () -> Void
    private let scoped: Bool

    init(folder: URL, changed: @escaping @MainActor () -> Void) {
        presentedItemURL = folder
        self.changed = changed
        scoped = folder.startAccessingSecurityScopedResource()
        super.init()
        NSFileCoordinator.addFilePresenter(self)
    }

    /// Stop presenting and give the folder's access back.
    func stop() {
        NSFileCoordinator.removeFilePresenter(self)
        if scoped { presentedItemURL?.stopAccessingSecurityScopedResource() }
    }

    private func notify() {
        let changed = self.changed
        Task { @MainActor in changed() }
    }

    func presentedItemDidChange() { notify() }
    func presentedSubitemDidChange(at url: URL) { notify() }
    func presentedSubitemDidAppear(at url: URL) { notify() }
    func accommodatePresentedSubitemDeletion(at url: URL, completionHandler: @escaping (Error?) -> Void) {
        notify()
        completionHandler(nil)
    }
}
