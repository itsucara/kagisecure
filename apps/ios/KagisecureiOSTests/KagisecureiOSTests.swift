import Foundation
import KagisecureFFI
import Testing

@testable import Kagisecure

/// Stands in for the Secure Enclave, which the simulator does not have. Not cryptography: it only
/// proves the slot round trip through the FFI.
final class FakePlatformKeys: PlatformKeyProviding, @unchecked Sendable {
    let mask = Data((0..<32).map { _ in UInt8.random(in: 1...255) })
    func isAvailable() -> Bool { true }
    func enroll(vaultKey: Data) throws -> EnrolledPlatformKey {
        EnrolledPlatformKey(slotId: "ios-secure-enclave", wrappedKey: xor(vaultKey))
    }
    func unwrap(_ wrappedKey: Data) throws -> Data { xor(wrappedKey) }
    func deleteKey() {}
    private func xor(_ data: Data) -> Data {
        Data(zip(data, mask.cycled(to: data.count)).map { $0 ^ $1 })
    }
}

extension Data {
    fileprivate func cycled(to n: Int) -> [UInt8] { (0..<n).map { self[$0 % count] } }
}

func tempEnvironment(presence: PresenceOutcome? = .confirmed) -> AppEnvironment {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("ks-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return AppEnvironment(
        vaultPath: dir.appendingPathComponent(AppEnvironment.fileName).path,
        kdfMKib: 64, kdfT: 1, scriptedPresence: presence, biometricsAllowed: true)
}

func generatedPassword() -> String { "pw-" + UUID().uuidString }

@MainActor
func makeUnlockedModel(biometrics: Bool = false, presence: PresenceOutcome? = .confirmed) async
    -> (AppModel, String)
{
    let model = AppModel(environment: tempEnvironment(presence: presence), platformKeys: FakePlatformKeys())
    let password = generatedPassword()
    await model.createVault(password: password, confirm: password, enableBiometrics: biometrics)
    model.acknowledgeRecoveryCode()
    return (model, password)
}

@MainActor
struct AppModelTests {
    @Test func firstRunStartsInSetup() {
        let model = AppModel(environment: tempEnvironment(), platformKeys: FakePlatformKeys())
        #expect(model.phase == .setup)
    }

    @Test func passwordValidation() {
        #expect(AppModel.validateNewPassword("short", confirm: "short") != nil)
        #expect(AppModel.validateNewPassword("longenough1", confirm: "different1") != nil)
        #expect(AppModel.validateNewPassword("longenough1", confirm: "longenough1") == nil)
    }

    @Test func createShowsRecoveryCodeOnceThenUnlocks() async {
        let model = AppModel(environment: tempEnvironment(), platformKeys: FakePlatformKeys())
        let password = generatedPassword()
        await model.createVault(password: password, confirm: password, enableBiometrics: false)
        guard case .recoveryCode(let code) = model.phase else {
            Issue.record("expected recovery code, got \(model.phase)")
            return
        }
        #expect(!code.isEmpty)
        model.acknowledgeRecoveryCode()
        #expect(model.phase == .unlocked)
        #expect(model.store != nil)
        #expect(FileManager.default.fileExists(atPath: model.vaultPath))
    }

    @Test func lockAndPasswordUnlock() async {
        let (model, password) = await makeUnlockedModel()
        model.lock()
        #expect(model.phase == .locked)
        #expect(model.store == nil)
        await model.unlock(password: "wrong-" + password)
        #expect(model.phase == .locked)
        #expect(model.errorMessage == String(localized: "Wrong master password."))
        await model.unlock(password: password)
        #expect(model.phase == .unlocked)
    }

    @Test func existingVaultStartsLocked() async {
        let (model, _) = await makeUnlockedModel()
        let again = AppModel(environment: model.environment, platformKeys: FakePlatformKeys())
        #expect(again.phase == .locked)
    }

    @Test func biometricSlotRoundTrip() async {
        let (model, _) = await makeUnlockedModel(biometrics: true)
        #expect(model.biometricsEnabled)
        model.lock()
        #expect(model.biometricsEnabled)  // read from the file while locked
        await model.unlockWithBiometrics()
        #expect(model.phase == .unlocked)
        model.setBiometrics(false)
        #expect(!model.biometricsEnabled)
    }
}

@MainActor
struct VaultStoreTests {
    @Test func createEditFavoriteDelete() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let item = try store.create(category: "login", title: "Example")
        #expect(store.items.map(\.title) == ["Example"])

        var edit = ItemEditModel(item: item)
        edit.title = "Example Renamed"
        edit.urls = "https://accounts.example.com/login"
        edit.tags = "work, mail"
        try store.save(edit.draft)
        #expect(store.items.first?.title == "Example Renamed")

        try store.toggleFavorite(try #require(store.items.first))
        store.favoritesOnly = true
        #expect(store.visibleItems.count == 1)

        try store.delete(try #require(store.items.first))
        #expect(store.items.isEmpty)
    }

    @Test func staleRevisionIsRefused() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let item = try store.create(category: "login", title: "One")
        var first = ItemEditModel(item: item)
        var second = ItemEditModel(item: item)
        first.title = "First"
        try store.save(first.draft)
        second.title = "Second"
        #expect(throws: FfiError.self) { try store.save(second.draft) }
        do { try store.save(second.draft) } catch FfiError.ItemChangedElsewhere {
        } catch { Issue.record("unexpected \(error)") }
    }

    @Test func searchMatchesTitleTagsAndHost() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        var edit = ItemEditModel(item: try store.create(category: "login", title: "Bank"))
        edit.tags = "finance"
        edit.urls = "https://secure.mybank.example/login"
        try store.save(edit.draft)
        _ = try store.create(category: "login", title: "Other")
        for q in ["bank", "FIN", "mybank.example"] {
            store.query = q
            #expect(store.visibleItems.map(\.title) == ["Bank"], "query \(q)")
        }
        store.query = "/login"  // the path is not searched
        #expect(store.visibleItems.isEmpty)
        store.query = ""
        store.categoryFilter = "login"
        #expect(store.visibleItems.count == 2)
        store.categoryFilter = "secure_note"
        #expect(store.visibleItems.isEmpty)
    }

    @Test func concealedValueIsKeptRevealedAndNeverPrefilled() async throws {
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let item = try store.create(category: "login", title: "Site")
        var edit = ItemEditModel(item: item)
        let index = try #require(edit.fields.firstIndex { $0.concealed })
        let secret = generatedPassword()
        edit.fields[index].newValue = secret
        let saved = try store.save(edit.draft)

        let reopened = ItemEditModel(item: saved)
        let concealed = try #require(reopened.fields.first { $0.concealed })
        #expect(concealed.newValue.isEmpty)
        #expect(reopened.draft.fields.first { $0.concealed }?.value == nil)

        // Saving with the concealed field untouched keeps the secret.
        var rename = reopened
        rename.title = "Site 2"
        let renamed = try store.save(rename.draft)
        let field = try #require(renamed.fields.first { $0.concealed })
        #expect(field.value == nil)
        #expect(try await store.reveal(renamed, field: field) == secret)
    }

    @Test func revealFailsClosedWhenPresenceCancelled() async throws {
        let (model, _) = await makeUnlockedModel(presence: .cancelled)
        let store = try #require(model.store)
        var edit = ItemEditModel(item: try store.create(category: "login", title: "Site"))
        let index = try #require(edit.fields.firstIndex { $0.concealed })
        edit.fields[index].newValue = generatedPassword()
        let saved = try store.save(edit.draft)
        let field = try #require(saved.fields.first { $0.concealed })
        await #expect(throws: FfiError.self) { _ = try await store.reveal(saved, field: field) }
    }

    @Test func generatorProducesPassword() {
        #expect(ItemEditModel.generatedPassword().count == 20)
    }
}
