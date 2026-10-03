import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Step 4 (transactional vault writes): the busy/conflict/changed-elsewhere paths, against a real
/// vault file — same discipline as `VaultStoreTests`, nothing mocked.
@MainActor
struct VaultConflictTests {
    private static func newVault() throws -> (VaultSession, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-conflict-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")
        let session = try VaultSession.create(
            path: path.path, masterPassword: "correct horse battery staple",
            vaultName: "Personal", kdfMKib: 64, kdfT: 1)
        return (session, path)
    }

    /// `save(draft:)` after another handle changed the very item the draft describes is refused
    /// as `FfiError.ItemChangedElsewhere`, and `ffiErrorMessage` renders the copy the alert shows
    /// (user decision 4: "This item was changed elsewhere — reload.").
    @Test func saveAfterAConcurrentEditIsChangedElsewhere() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let stale = try #require(store.selectedItem)

        // A second handle on the same file changes the item first.
        let other = try VaultSession.unlockWithPassword(
            path: path.path, masterPassword: "correct horse battery staple")
        _ = try other.setFavorite(itemId: stale.id, favorite: true)

        let staleDraft = ItemDraft(
            id: stale.id, category: stale.category, title: "A stale title",
            fields: [], tags: stale.tags, urls: stale.urls, notes: nil,
            revision: stale.revision)

        do {
            try store.save(draft: staleDraft)
            Issue.record("expected FfiError.ItemChangedElsewhere")
        } catch FfiError.ItemChangedElsewhere {
            // Expected.
        }
        #expect(
            ffiErrorMessage(.ItemChangedElsewhere(message: "x"))
                == "This item was changed elsewhere — reload.")

        // The other handle's real edit is still there; the stale title never landed.
        let after = try session.item(itemId: stale.id)
        #expect(after.favorite)
        #expect(after.title != "A stale title")
    }

    /// A file restored from an older copy while a session is unlocked is a conflict
    /// (`VaultConflictKindView.diverged`), reported without a write having to fail first.
    @Test func syncDetectsADivergedFileWithoutAFailedWriteFirst() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        #expect(store.conflictKind == nil)

        let older = try Data(contentsOf: path)
        // An audited write, so this session's memory knows a longer audit log than `older` has.
        store.createEnvironment(name: "test-environment")
        try older.write(to: path)

        store.syncFromDisk()
        #expect(store.conflictKind == .diverged)
        #expect(
            conflictMessage(.diverged).contains("no longer matches"),
            "the conflict alert's copy explains what is different about the file")
    }

    /// Every `VaultConflictKindView` case has a non-empty sentence, and `nil` — no conflict — is
    /// blank rather than a placeholder that could leak onto screen.
    @Test func everyConflictKindHasCopy() {
        #expect(!conflictMessage(.diverged).isEmpty)
        #expect(!conflictMessage(.replaced).isEmpty)
        #expect(!conflictMessage(.unreadable).isEmpty)
        #expect(!conflictMessage(.removed).isEmpty)
        #expect(conflictMessage(nil).isEmpty)
    }

    /// "Keep this app's version" asks first, saying what the file would lose, and only the
    /// confirmation overwrites: afterwards the conflict is gone, the file holds this app's
    /// version, and an ordinary write works again.
    @Test func keepingTheAppsVersionIsConfirmedThenOverwritesTheFile() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        let older = try Data(contentsOf: path)
        store.createEnvironment(name: "test-environment")
        try older.write(to: path)
        store.syncFromDisk()
        #expect(store.conflictKind == .diverged)

        store.requestKeepAppVersion()
        let details = try #require(store.overwriteConfirmation)
        #expect(details.kind == .diverged)
        #expect(store.conflictKind == .diverged, "nothing is written until confirmed")
        #expect(try Data(contentsOf: path) == older)
        #expect(overwriteConfirmationMessage(details).contains("audit log"))

        store.confirmKeepAppVersion()
        #expect(store.overwriteConfirmation == nil)
        #expect(store.conflictKind == nil)
        #expect(store.errorMessage == nil)
        #expect(try Data(contentsOf: path) != older)

        let reopened = try VaultSession.unlockWithPassword(
            path: path.path, masterPassword: "correct horse battery staple")
        #expect(reopened.environments().count == 1)
        store.createEnvironment(name: "after the overwrite")
        #expect(store.errorMessage == nil)
    }

    /// Cancelling the confirmation writes nothing and goes back to the conflict's two choices.
    @Test func cancellingTheOverwriteLeavesTheConflict() throws {
        let (session, path) = try Self.newVault()
        let store = VaultStore(session: session)
        let older = try Data(contentsOf: path)
        store.createEnvironment(name: "test-environment")
        try older.write(to: path)
        store.syncFromDisk()

        store.requestKeepAppVersion()
        #expect(store.overwriteConfirmation != nil)
        store.cancelKeepAppVersion()
        #expect(store.overwriteConfirmation == nil)
        #expect(store.conflictKind == .diverged)
        #expect(try Data(contentsOf: path) == older)
    }

    /// The confirmation copy names the consequences that are easy to miss: a replaced file is
    /// lost whole, and a password or recovery code that differs changes which one works.
    @Test func theOverwriteConfirmationSaysWhatIsLost() {
        let replaced = VaultConflictDetailsView(
            kind: .replaced, fileFingerprint: "00", sessionAuditEntries: 3, diverged: nil)
        #expect(overwriteConfirmationMessage(replaced).contains("destroys it entirely"))

        let removed = VaultConflictDetailsView(
            kind: .removed, fileFingerprint: nil, sessionAuditEntries: 3, diverged: nil)
        #expect(overwriteConfirmationMessage(removed).contains("no file"))

        let diverged = VaultConflictDetailsView(
            kind: .diverged, fileFingerprint: "00", sessionAuditEntries: 3,
            diverged: DivergedFileView(
                auditEntriesOnlyInFile: 2, itemsOnlyInFile: 1, itemsDiffering: 0,
                environmentsOnlyInFile: 0, environmentsDiffering: 0,
                vaultsOnlyInFileOrDiffering: 0, masterPasswordDiffers: true,
                recoveryCodeDiffers: true, touchIdDiffers: false))
        let message = overwriteConfirmationMessage(diverged)
        #expect(message.contains("1 item that only the file has"))
        #expect(message.contains("2 audit log entries that only the file has"))
        #expect(message.contains("master password"))
        #expect(message.contains("recovery code"))
        #expect(!message.contains("Touch ID"))
    }

    /// A toggle that fails is not silent: the error reaches the store's alert instead of being
    /// dropped by a `try?` in the view.
    @Test func aFailedToggleReachesTheStoresErrorAlert() throws {
        let (session, _) = try Self.newVault()
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let item = try #require(store.selectedItem)
        try store.setTrashed(item, true)
        store.selection = .trash
        try store.deleteForever(try #require(store.items.first { $0.id == item.id }))

        store.attempt { try store.toggleFavorite(item) }
        #expect(store.errorMessage != nil, "the failure is shown, not swallowed")
        #expect(store.conflictKind == nil)
    }

    /// "Lock and reopen from the file" after the file was removed sends `AppModel` to `.noVault`
    /// (there is nothing to reopen), not back to `.locked`. If the user then creates a brand-new
    /// vault at that same path rather than restoring the old file, that new vault must not be
    /// stamped `vault_reopened_after_conflict` — it has nothing to do with the conflict, and
    /// `AppModel.reopeningAfterConflictFileId` exists specifically to tell the two apart by the
    /// vault file's own identity rather than a bare "something is pending" flag.
    @Test func aBrandNewVaultAfterARemovedFileIsNotStampedAsAConflictReopen() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-reopen-conflict-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("test.kagivault")

        let model = AppModel(vaultPath: path.path)
        model.createVault(password: "correct horse battery staple", vaultName: "Personal")
        guard case .unlocked = model.phase else {
            Issue.record("expected the freshly created vault to be unlocked")
            return
        }

        // The file disappears while unlocked — the same shape a sync conflict or an external
        // delete takes — and the user picks "Lock and reopen from the file".
        try FileManager.default.removeItem(at: path)
        model.lockAfterConflict()
        guard case .noVault = model.phase else {
            Issue.record("a removed file's conflict must send the phase to .noVault")
            return
        }

        // Instead of restoring the old file, a brand-new vault is created at the same path.
        model.createVault(password: "a different password entirely", vaultName: "Personal")
        guard case .unlocked = model.phase, let store = model.store else {
            Issue.record("expected the new vault to be unlocked")
            return
        }

        let entries = store.session.auditPage(limit: 50, offset: 0)
        #expect(
            entries.allSatisfy { $0.tool != "vault_reopened_after_conflict" },
            "a brand-new vault must never be stamped as a reopen of the one that conflicted")
    }

    /// `ffiErrorMessage` is exhaustive over every `FfiError` case as of step 4, and never echoes
    /// the placeholder payload this test hands it back as the *whole* message for the generic
    /// cases (where the payload *is* the message, by design).
    @Test func everyFfiErrorCaseHasNonEmptyCopy() {
        let cases: [FfiError] = [
            .NotFound(message: "p"), .AlreadyExists(message: "p"),
            .WrongCredential(message: "m"),
            .NoSuchSlot(message: "k"), .NotPresent(message: "w"), .Invalid(message: "m"),
            .Io(message: "m"), .Busy(message: "m"), .Diverged(message: "m"),
            .ItemChangedElsewhere(message: "m"), .VaultLocked(message: "m"),
            .NoPresenceGate(message: "m"), .PresenceCancelled(message: "m"),
            .PresenceUnavailable(message: "m"), .PresenceBusy(message: "m"),
            .ReleaseEnded(message: "m"),
        ]
        for error in cases {
            #expect(!ffiErrorMessage(error).isEmpty, "\(error)")
        }
    }
}
