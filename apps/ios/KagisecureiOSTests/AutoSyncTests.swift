import Foundation
import Testing

@testable import Kagisecure

/// A clock the test moves by hand.
@MainActor
final class FakeClock {
    var now = ContinuousClock.now
    func advance(_ by: Duration) { now = now + by }
}

/// Stands in for `LinkModel.sync()`: counts calls and records when each one ended, the way
/// `LinkModel` does in its `defer`.
@MainActor
final class FakeSync {
    var count = 0
    var syncing = false
    var endedAt: ContinuousClock.Instant?
    /// Run while "syncing": the write-back into the folder.
    var duringSync: (() -> Void)?
    let clock: FakeClock

    init(clock: FakeClock) { self.clock = clock }

    func run() async {
        syncing = true
        count += 1
        duringSync?()
        syncing = false
        endedAt = clock.now
    }
}

@MainActor
struct AutoSyncTests {
    private func make(_ clock: FakeClock, _ fake: FakeSync) -> FolderChangeDebouncer {
        FolderChangeDebouncer(
            debounce: .milliseconds(100), quiet: .seconds(3), now: { clock.now },
            isSyncing: { fake.syncing }, lastSyncEnded: { fake.endedAt },
            sync: { await fake.run() })
    }

    @Test func aBurstOfChangesSyncsExactlyOnce() async throws {
        let clock = FakeClock()
        let fake = FakeSync(clock: clock)
        let watcher = make(clock, fake)
        for _ in 0..<5 {
            watcher.folderChanged()
            try await Task.sleep(for: .milliseconds(20))
        }
        #expect(fake.count == 0)  // still gathering
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.count == 1)
    }

    @Test func ourOwnWriteBackDoesNotSyncAgain() async throws {
        let clock = FakeClock()
        let fake = FakeSync(clock: clock)
        let watcher = make(clock, fake)
        // The sync writes the mirror back into the folder: the presenter reports that change.
        fake.duringSync = { watcher.folderChanged() }
        watcher.folderChanged()
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.count == 1)

        // Late notifications of the same write-back, within the quiet time, are ignored too.
        clock.advance(.seconds(2))
        watcher.folderChanged()
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.count == 1)

        // A change from the Mac after the quiet time syncs again.
        clock.advance(.seconds(2))
        fake.duringSync = nil
        watcher.folderChanged()
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.count == 2)
    }

    @Test func cancelDropsAPendingSync() async throws {
        let clock = FakeClock()
        let fake = FakeSync(clock: clock)
        let watcher = make(clock, fake)
        watcher.folderChanged()
        watcher.cancel()
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.count == 0)
    }

    @Test func linkModelRecordsWhenItsSyncEnds() async throws {
        let (model, _) = await makeUnlockedModel()
        let link = try #require(model.store).link
        #expect(link.syncEndedAt == nil)
        await link.sync()
        let ended = try #require(link.syncEndedAt)
        #expect(ContinuousClock.now - ended < .seconds(3))
        // No folder picked: nothing to watch.
        link.startWatching()
        #expect(!link.isWatching)
    }
}
