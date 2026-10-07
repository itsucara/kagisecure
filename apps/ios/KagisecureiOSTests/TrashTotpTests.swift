import Foundation
import KagisecureFFI
import Testing

@testable import Kagisecure

@MainActor
struct TrashTests {
    @Test func trashedItemRestores() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let item = try store.create(category: "login", title: "Keep Me")
        try store.delete(item)
        #expect(store.items.isEmpty)
        #expect(store.trashedItems.map(\.title) == ["Keep Me"])

        try store.restore(try #require(store.trashedItems.first))
        #expect(store.trashedItems.isEmpty)
        #expect(store.items.map(\.title) == ["Keep Me"])
    }

    @Test func deletePermanentlyRemovesForGood() async throws {
        let (model, password) = await makeUnlockedModel()
        let store = try #require(model.store)
        try store.delete(try store.create(category: "login", title: "Gone"))
        try store.delete(try store.create(category: "login", title: "Also Gone"))
        try store.deletePermanently(try #require(store.trashedItems.first { $0.title == "Gone" }))
        #expect(store.trashedItems.map(\.title) == ["Also Gone"])
        try store.emptyTrash()
        #expect(store.trashedItems.isEmpty)
        #expect(store.items.isEmpty)

        // Still gone after locking and opening the file again.
        model.lock()
        await model.unlock(password: password)
        let reopened = try #require(model.store)
        #expect(reopened.trashedItems.isEmpty && reopened.items.isEmpty)
    }
}

@MainActor
struct TotpTests {
    /// RFC 6238's SHA-1 test secret ("12345678901234567890").
    static let rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test func base32AndUriInputsBecomeAUri() throws {
        let uri = try ItemEditModel.totpURI(from: "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", issuer: "Example")
        #expect(uri.hasPrefix("otpauth://totp/"))
        #expect(try totpPreview(uri: uri, at: 59).code == "287082")
        #expect(try ItemEditModel.totpURI(from: " \(uri) ", issuer: "x") == uri)
        #expect(throws: FfiError.self) { _ = try ItemEditModel.totpURI(from: "not base32 !!", issuer: "") }
        #expect(throws: FfiError.self) { _ = try ItemEditModel.totpURI(from: "otpauth://totp/x", issuer: "") }
    }

    @Test func savedTotpShowsCurrentCodeBehindPresence() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        var edit = ItemEditModel(item: try store.create(category: "login", title: "Site"))
        edit.addTotpField()
        let index = try #require(edit.fields.firstIndex { $0.kind == .totp })
        edit.fields[index].newValue = Self.rfcSecret
        let saved = try store.save(edit.validatedDraft())
        let field = try #require(saved.fields.first { $0.kind == .totp && $0.hasValue })
        #expect(field.value == nil)  // the seed is concealed

        let release = try await store.releaseTotp(saved, field: field, purpose: .reveal)
        defer { release.close() }
        let code = try release.codeAt(at: 59)
        #expect(code.code == "287082")
        #expect(code.secondsRemaining == 1)
        #expect(code.params.period == 30)
        let now = try release.codeAt(at: VaultStore.unixNow())
        #expect(now.code.count == 6 && (1...30).contains(now.secondsRemaining))

        // Re-saving without touching the field keeps the seed.
        var again = ItemEditModel(item: saved)
        again.title = "Site 2"
        let kept = try store.save(again.validatedDraft())
        let keptField = try #require(kept.fields.first { $0.kind == .totp })
        let second = try await store.releaseTotp(kept, field: keptField, purpose: .reveal)
        defer { second.close() }
        #expect(try second.codeAt(at: 59).code == "287082")
    }

    @Test func totpFailsClosedWhenPresenceCancelled() async throws {
        let (model, _) = await makeUnlockedModel(presence: .cancelled)
        let store = try #require(model.store)
        var edit = ItemEditModel(item: try store.create(category: "login", title: "Site"))
        edit.addTotpField()
        edit.fields[edit.fields.count - 1].newValue = Self.rfcSecret
        let saved = try store.save(edit.validatedDraft())
        let field = try #require(saved.fields.first { $0.kind == .totp })
        await #expect(throws: FfiError.self) {
            _ = try await store.releaseTotp(saved, field: field, purpose: .reveal)
        }
        await #expect(throws: FfiError.self) { try await store.copyTotp(saved, field: field, shown: nil) }
    }
}

@MainActor
struct NotesTests {
    @Test func noteIsKeptWhenEmptyAndRemovedOnRequest() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        var edit = ItemEditModel(item: try store.create(category: "login", title: "Site"))
        edit.newNotes = "remember this"
        let saved = try store.save(edit.draft)
        #expect(saved.hasNotes)

        var keep = ItemEditModel(item: saved)
        keep.title = "Site 2"
        let kept = try store.save(keep.draft)
        #expect(kept.hasNotes)
        #expect(try await store.revealNotes(kept) == "remember this")

        var remove = ItemEditModel(item: kept)
        remove.setRemoveNotes(true)
        #expect(remove.draft.notes == "")
        let removed = try store.save(remove.draft)
        #expect(!removed.hasNotes)
    }
}

@MainActor
struct ResidualTests {
    @Test func emptyTrashAttemptsEveryItemAndReportsFailures() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        for t in ["A", "B", "C"] { try store.delete(try store.create(category: "login", title: t)) }
        var attempted: [String] = []
        let error = #expect(throws: EmptyTrashError.self) {
            try store.emptyTrash { item in
                attempted.append(item.title)
                if item.title == "A" { throw FfiError.Invalid(message: "boom") }
                let current = try store.session.item(itemId: item.id)
                try store.session.deleteItem(itemId: item.id, revision: current.revision)
            }
        }
        #expect(attempted.sorted() == ["A", "B", "C"])
        #expect(error?.failures.map(\.title) == ["A"])
        #expect(error?.errorDescription?.contains("A") == true)
        #expect(store.trashedItems.map(\.title) == ["A"])
        try store.emptyTrash()
        #expect(store.trashedItems.isEmpty)
    }

    @Test func addedButEmptyTotpFieldIsNotSaved() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let item = try store.create(category: "login", title: "Site")
        let before = item.fields.filter { $0.kind == .totp }.count
        var edit = ItemEditModel(item: item)
        edit.addTotpField()
        #expect(edit.draft.fields.filter { $0.kind == .totp }.count == before)
        let saved = try store.save(edit.validatedDraft())
        #expect(saved.fields.filter { $0.kind == .totp }.count == before)
        edit.fields[edit.fields.count - 1].newValue = "   "
        #expect(edit.draft.fields.filter { $0.kind == .totp }.count == before)
        edit.fields[edit.fields.count - 1].newValue = TotpTests.rfcSecret
        #expect(edit.draft.fields.filter { $0.kind == .totp }.count == before + 1)
    }

    @Test func removeNoteNeedsConfirmationAndClearsTypedNote() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        var first = ItemEditModel(item: try store.create(category: "login", title: "Site"))
        first.newNotes = "old"
        let saved = try store.save(first.draft)
        var edit = ItemEditModel(item: saved)
        #expect(!edit.removeNotesNeedsConfirmation)
        edit.newNotes = "typed"
        #expect(edit.removeNotesNeedsConfirmation)
        edit.setRemoveNotes(true)
        #expect(edit.newNotes.isEmpty && edit.removeNotes)
        #expect(edit.draft.notes == "")
    }

    @Test func foregroundSyncRunsOnlyWhenSomethingIsLinked() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        #expect(await store.link.syncOnForeground() == false)
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("ks-fg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try store.link.folders.remember(folder)
        #expect(await store.link.syncOnForeground() == true)
        #expect(store.link.lastSynced != nil)
        // Right after our own sync: inside the write-back window, so no second sync.
        #expect(await store.link.syncOnForeground() == false)
    }

    @Test func folderPathsAreComparedNormalized() {
        #expect(LinkModel.samePath("/private/var/tmp", "/var/tmp"))
        #expect(LinkModel.samePath("/a/b/../c/", "/a/c"))
        #expect(!LinkModel.samePath("/a/c", "/a/d"))
    }
}

struct LocalizationTests {
    @Test func japaneseCatalogIsBundled() throws {
        let bundle = Bundle(for: AppPresenceGate.self)
        let path = try #require(bundle.path(forResource: "ja", ofType: "lproj"))
        let ja = try #require(Bundle(path: path))
        #expect(ja.localizedString(forKey: "Trash", value: nil, table: nil) == "ゴミ箱")
        #expect(ja.localizedString(forKey: "Sync Now", value: nil, table: nil) == "今すぐ同期")
        #expect(ja.localizedString(forKey: "Delete Permanently", value: nil, table: nil) == "完全に削除")
    }
}

struct AutoLockTests {
    @Test func locksOnlyAfterTheChosenTime() {
        #expect(!AutoLock.shouldLock(away: .seconds(59), seconds: 60))
        #expect(AutoLock.shouldLock(away: .seconds(60), seconds: 60))
        #expect(AutoLock.shouldLock(away: .milliseconds(1), seconds: 0))
        #expect(AutoLock.shouldLock(away: .zero, seconds: -5))
    }

    @Test func awayTimeComesFromAClockThatCannotBeWoundBack() {
        // The instant is ContinuousClock's, not the wall clock's: elapsed time is never negative.
        let start = ContinuousClock.now
        #expect(ContinuousClock.now - start >= .zero)
    }
}

@MainActor
struct TotpScanTests {
    static let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    @Test func scannedURIFillsTheOneTimePasswordField() async throws {
        var model = ItemEditModel(item: try await emptyItem())
        try model.applyScannedTotp("  \(Self.uri)\n")
        #expect(model.fields.filter { $0.kind == .totp }.map(\.newValue) == [Self.uri])
        // Scanning again replaces the setup instead of adding a second field.
        try model.applyScannedTotp(Self.uri.replacingOccurrences(of: "alice", with: "bob"))
        #expect(model.fields.filter { $0.kind == .totp }.count == 1)
        #expect(try model.validatedDraft().fields.first { $0.kind == .totp }?.value?.contains("bob") == true)
    }

    @Test func googleAuthenticatorExportIsRejectedWithItsOwnMessage() async throws {
        var model = ItemEditModel(item: try await emptyItem())
        let before = model
        #expect(throws: TotpScanError.migrationExport) {
            try model.applyScannedTotp("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8")
        }
        #expect(model == before)
        #expect(TotpScanError.migrationExport.errorDescription?.contains("Google Authenticator") == true)
    }

    @Test func otherQRCodesAreRejected() async throws {
        var model = ItemEditModel(item: try await emptyItem())
        let before = model
        #expect(throws: TotpScanError.notOneTimePassword) { try model.applyScannedTotp("https://example.com") }
        #expect(throws: TotpScanError.notOneTimePassword) { try model.applyScannedTotp("otpauth://totp/x?secret=!!") }
        #expect(model == before)
    }

    private func emptyItem() async throws -> ItemView {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        return try store.create(category: "login", title: "Example")
    }
}
