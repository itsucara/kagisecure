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
        remove.removeNotes = true
        #expect(remove.draft.notes == "")
        let removed = try store.save(remove.draft)
        #expect(!removed.hasNotes)
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
