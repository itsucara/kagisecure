import Foundation
import KagisecureFFI
import Testing

@testable import Kagisecure

private func tempDir(_ name: String) -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("ks-\(name)-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

private func recordName(_ n: Int) -> String {
    String(format: "%064x", n) + ".ksr"
}

private func write(_ text: String, _ url: URL) {
    try? FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? Data(text.utf8).write(to: url)
}

private func read(_ url: URL) -> String? {
    (try? Data(contentsOf: url)).map { String(decoding: $0, as: UTF8.self) }
}

/// A record envelope (docs/shared-vault-format.md §4.1) — `[1, author(32), body, sig(64)]` —
/// with its real name. The signature is filler: the copier checks the hash, not the signature.
private func record(_ n: Int, bodySize: Int = 20) -> (name: String, data: Data) {
    var body = [UInt8](repeating: UInt8(n & 0xff), count: bodySize)
    body[0] = UInt8(n & 0xff) ^ 0x5a
    var bytes: [UInt8] = [0x84, 0x01, 0x58, 0x20] + [UInt8](repeating: UInt8(n & 0xff), count: 32)
    if bodySize < 24 { bytes.append(0x40 | UInt8(bodySize)) }
    else if bodySize < 256 { bytes += [0x58, UInt8(bodySize)] }
    else { bytes += [0x59, UInt8(bodySize >> 8), UInt8(bodySize & 0xff)] }
    bytes += body
    bytes += [0x58, 0x40] + [UInt8](repeating: 0x77, count: 64)
    let data = Data(bytes)
    return (ExchangeMirror.recordID(of: data)! + ".ksr", data)
}

private func put(_ record: (name: String, data: Data), _ dir: URL) {
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? record.data.write(to: dir.appendingPathComponent(record.name))
}

private func rawPut(_ data: Data, _ dir: URL, _ name: String) {
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? data.write(to: dir.appendingPathComponent(name))
}

private func bytes(_ dir: URL, _ name: String) -> Data? {
    try? Data(contentsOf: dir.appendingPathComponent(name))
}

/// The copier between the picked (iCloud) folder and the container mirror, with plain temporary
/// folders standing in for iCloud Drive.
struct ExchangeMirrorTests {
    let remote = tempDir("remote")
    let mirrorDir = tempDir("mirror")
    var mirror: ExchangeMirror { ExchangeMirror(remote: remote, mirror: mirrorDir) }
    var remoteRecords: URL { remote.appendingPathComponent("records") }
    var mirrorRecords: URL { mirrorDir.appendingPathComponent("records") }

    @Test func recordNamesAreExactlyWhatRustAccepts() {
        #expect(recordName(1).count == 68)
        #expect(ExchangeMirror.isRecordName(recordName(1)))
        #expect(!ExchangeMirror.isRecordName("README.txt"))
        #expect(!ExchangeMirror.isRecordName(String(repeating: "A", count: 64) + ".ksr"))
        #expect(!ExchangeMirror.isRecordName(String(repeating: "0", count: 63) + ".ksr"))
        #expect(ExchangeMirror.placeholderTarget(".\(recordName(2)).icloud") == recordName(2))
        #expect(ExchangeMirror.placeholderTarget("plain.ksr") == nil)
    }

    @Test func copiesWhatEachSideLacksBothWays() throws {
        let a = record(1), b = record(2), shared = record(3)
        put(a, remoteRecords)
        put(b, mirrorRecords)
        put(shared, remoteRecords)
        put(shared, mirrorRecords)
        let report = try mirror.sync()
        #expect(report.pulled == 1)
        #expect(report.pushed == 1)
        #expect(bytes(mirrorRecords, a.name) == a.data)
        #expect(bytes(remoteRecords, b.name) == b.data)
        let names = Set(ExchangeMirror.list(remoteRecords))
        #expect(names == Set(ExchangeMirror.list(mirrorRecords)))
    }

    @Test func aSecondPassCopiesNothing() throws {
        put(record(1), remoteRecords)
        put(record(2), mirrorRecords)
        _ = try mirror.sync()
        let again = try mirror.sync()
        #expect(again == ExchangeMirror.Report())
        // No temporary files left behind on either side.
        #expect(!ExchangeMirror.list(remoteRecords).contains { $0.hasPrefix(".tmp-") })
        #expect(!ExchangeMirror.list(mirrorRecords).contains { $0.hasPrefix(".tmp-") })
    }

    @Test func otherFilesAreNotCopied() throws {
        write("x", remoteRecords.appendingPathComponent("notes.txt"))
        write("x", remoteRecords.appendingPathComponent(".tmp-123"))
        write("x", mirrorRecords.appendingPathComponent("junk.ksr"))
        let report = try mirror.sync()
        #expect(report == ExchangeMirror.Report())
        #expect(!FileManager.default.fileExists(atPath: mirrorRecords.appendingPathComponent("notes.txt").path))
        #expect(!FileManager.default.fileExists(atPath: remoteRecords.appendingPathComponent("junk.ksr").path))
    }

    @Test func aRecordWhoseBytesDoNotHashToItsNameIsNotCopied() throws {
        write("junk", remoteRecords.appendingPathComponent(recordName(1)))
        write("junk", mirrorRecords.appendingPathComponent(recordName(2)))
        let report = try mirror.sync()
        #expect(report == ExchangeMirror.Report())
        #expect(!FileManager.default.fileExists(atPath: mirrorRecords.appendingPathComponent(recordName(1)).path))
        #expect(!FileManager.default.fileExists(atPath: remoteRecords.appendingPathComponent(recordName(2)).path))
    }

    @Test func recordIDFollowsTheFormat() {
        let r = record(5)
        #expect(ExchangeMirror.recordID(of: r.data).map { $0 + ".ksr" } == r.name)
        #expect(ExchangeMirror.isValidRecord(name: r.name, data: r.data))
        // Trailing bytes, a cut, or a flipped bit: not the record any more.
        #expect(!ExchangeMirror.isValidRecord(name: r.name, data: r.data + Data([0])))
        #expect(!ExchangeMirror.isValidRecord(name: r.name, data: r.data.dropLast()))
        var flipped = r.data
        flipped[flipped.count - 1] ^= 1
        #expect(!ExchangeMirror.isValidRecord(name: r.name, data: flipped))
        // A body long enough for a two-byte length head.
        let long = record(6, bodySize: 300)
        #expect(ExchangeMirror.isValidRecord(name: long.name, data: long.data))
    }

    @Test func aPlaceholderIsPendingNotCopiedNorPushedOver() throws {
        let four = record(4), five = record(5)
        // iCloud has the record but not downloaded: a `.name.icloud` placeholder.
        write("stub", remoteRecords.appendingPathComponent(".\(four.name).icloud"))
        // The mirror has the same record already: it must not be pushed over the placeholder.
        put(four, mirrorRecords)
        write("other", remoteRecords.appendingPathComponent(".\(five.name).icloud"))
        let report = try mirror.sync()
        #expect(report.pending == 2)
        #expect(report.pushed == 0)
        #expect(report.pulled == 0)
        #expect(!FileManager.default.fileExists(atPath: mirrorRecords.appendingPathComponent(five.name).path))
        // Downloaded later: picked up by the next pass.
        try FileManager.default.removeItem(at: remoteRecords.appendingPathComponent(".\(five.name).icloud"))
        put(five, remoteRecords)
        let next = try mirror.sync()
        #expect(next.pulled == 1)
        #expect(bytes(mirrorRecords, five.name) == five.data)
    }

    @Test func anEmptyFileIsStillBeingWrittenAndIsSkipped() throws {
        write("", remoteRecords.appendingPathComponent(recordName(6)))
        let report = try mirror.sync()
        #expect(report.pulled == 0)
        #expect(!FileManager.default.fileExists(atPath: mirrorRecords.appendingPathComponent(recordName(6)).path))
    }

    @Test func aCopyCutShortIsReplacedByTheWholeOneEitherWay() throws {
        let seven = record(7), eight = record(8)
        put(seven, remoteRecords)
        rawPut(seven.data.prefix(10), mirrorRecords, seven.name)
        rawPut(eight.data.prefix(10), remoteRecords, eight.name)
        put(eight, mirrorRecords)
        let report = try mirror.sync()
        #expect(report.pulled == 1)
        #expect(report.pushed == 1)
        #expect(bytes(mirrorRecords, seven.name) == seven.data)
        #expect(bytes(remoteRecords, eight.name) == eight.data)
        #expect(try mirror.sync() == ExchangeMirror.Report())
    }

    @Test func aCorruptLargerICloudCopyDoesNotReplaceAValidLocalOne() throws {
        let r = record(10)
        put(r, mirrorRecords)
        rawPut((r.data + Data(repeating: 0xAB, count: 50)), remoteRecords, r.name)
        let report = try mirror.sync()
        #expect(report.pulled == 0)
        #expect(bytes(mirrorRecords, r.name) == r.data)
        // The valid copy fixes the corrupt one instead.
        #expect(report.pushed == 1)
        #expect(bytes(remoteRecords, r.name) == r.data)
        #expect(try mirror.sync() == ExchangeMirror.Report())
    }

    @Test func aValidICloudCopyFixesACorruptLocalOne() throws {
        let r = record(11)
        put(r, remoteRecords)
        rawPut((r.data + Data(repeating: 0, count: 80)), mirrorRecords, r.name)
        let report = try mirror.sync()
        #expect(report.pulled == 1)
        #expect(report.pushed == 0)
        #expect(bytes(mirrorRecords, r.name) == r.data)
        #expect(!ExchangeMirror.list(mirrorRecords).contains { $0.hasPrefix(".tmp-") })
    }

    @Test func whenNeitherCopyIsValidBothAreLeftAlone() throws {
        let name = recordName(12)
        write("short", remoteRecords.appendingPathComponent(name))
        write("much-longer-junk", mirrorRecords.appendingPathComponent(name))
        let report = try mirror.sync()
        #expect(report == ExchangeMirror.Report())
        #expect(read(remoteRecords.appendingPathComponent(name)) == "short")
        #expect(read(mirrorRecords.appendingPathComponent(name)) == "much-longer-junk")
    }

    @Test func invitationsOnlyComeIn() throws {
        write("invite", remote.appendingPathComponent("iPhone – Family.kagisecure-invite"))
        write("local", mirrorDir.appendingPathComponent("mine.kagisecure-invite"))
        let report = try mirror.sync()
        #expect(report.pulled == 1)
        #expect(read(mirrorDir.appendingPathComponent("iPhone – Family.kagisecure-invite")) == "invite")
        #expect(!FileManager.default.fileExists(atPath: remote.appendingPathComponent("mine.kagisecure-invite").path))
    }

    @Test func aMissingRemoteRecordsFolderIsCreatedOnPush() throws {
        let r = record(9)
        put(r, mirrorRecords)
        let report = try mirror.sync()
        #expect(report.pushed == 1)
        #expect(bytes(remoteRecords, r.name) == r.data)
    }
}

/// The Mac and the iPhone converging without the Mac app: a second personal vault in this
/// process plays the Mac (it does what the Mac's members pane does — `inviteDevice` into the
/// shared folder), the iPhone goes through `LinkModel` and the mirror copier, and a temporary
/// folder stands in for iCloud Drive. Proves convergence, not the iCloud path.
@MainActor
struct ConvergenceTests {
    struct Mac {
        let personal: VaultSession
        let shared: SharedVaultSession
        let invitation: SharedInvitation
    }

    func makeMac(folder: URL) throws -> Mac {
        let dir = tempDir("mac")
        let personal = try VaultSession.create(
            path: dir.appendingPathComponent("mac.kagivault").path, masterPassword: generatedPassword(),
            vaultName: "Personal", kdfMKib: 64, kdfT: 1)
        _ = personal.takeRecoveryCode()
        let shared = try personal.createSharedVault(name: "Family", folder: folder.path)
        let me = try #require(shared.members().first { $0.isYou })
        let invitation = try shared.inviteDevice(
            memberId: me.id, outPath: folder.appendingPathComponent("iPhone – Family.kagisecure-invite").path,
            kdfMKib: 64, kdfT: 1)
        return Mac(personal: personal, shared: shared, invitation: invitation)
    }

    /// Change the item's title and its first plain field through the edit sheet's own model.
    func edit(_ item: ItemView, title: String? = nil, field value: String? = nil) -> ItemDraft {
        var model = ItemEditModel(item: item)
        if let title { model.title = title }
        if let value, let i = model.fields.firstIndex(where: { !$0.concealed }) {
            model.fields[i].newValue = value
        }
        return model.draft
    }

    func firstPlain(_ item: ItemView) -> String? { item.fields.first { !$0.concealed }?.value }

    @Test func joinThroughTheFolderThenBothSidesConverge() async throws {
        let icloud = tempDir("icloud")
        let mac = try makeMac(folder: icloud)
        let created = try mac.shared.createItem(category: "login", title: "Bank")
        _ = try mac.shared.sync()

        // The iPhone: personal vault, folder chosen, invitation found in the mirror, joined.
        let (model, _) = await makeUnlockedModel()
        let store = try #require(model.store)
        let link = store.link
        #expect(!link.isLinked)
        await link.choose(folder: icloud)
        let invitation = try #require(link.invitations.first)
        await #expect(throws: FfiError.self) {
            try await link.join(invitation: invitation, words: "wrong words here and there now")
        }
        try await link.join(invitation: invitation, words: mac.invitation.passphrase)
        #expect(link.isLinked)
        #expect(link.myFingerprints().count == 1)
        // The Mac sees the iPhone as a second device of the same member.
        _ = try mac.shared.sync()
        let macDevices = mac.shared.members().first { $0.isYou }?.devices ?? []
        #expect(macDevices.count == 2)
        #expect(macDevices.map(\.fingerprint).contains(link.myFingerprints()[0]))

        // The Mac's item is on the iPhone; the personal vault is empty so only the shared section shows.
        #expect(store.items.map(\.id) == [created.id])
        #expect(store.isShared(created.id))
        #expect(store.visibleSections.map(\.name) == ["Family"])
        #expect(store.defaultNewItemVault == mac.shared.vaultId())

        // Both edit the same item while apart: different fields, and the same field.
        let onMac = try mac.shared.item(itemId: created.id)
        _ = try mac.shared.saveItem(draft: edit(onMac, field: "mac-user"))
        let onPhone = try #require(store.item(id: created.id))
        try store.save(edit(onPhone, title: "Bank (renamed on iPhone)", field: "phone-user"))
        // And each adds an item of its own.
        _ = try mac.shared.createItem(category: "login", title: "Mac only")
        _ = try store.create(category: "login", title: "iPhone only", vault: mac.shared.vaultId())

        // Sync both, twice around.
        for _ in 0..<2 {
            await link.sync()
            _ = try mac.shared.sync()
        }
        await link.sync()

        let macItem = try mac.shared.item(itemId: created.id)
        let phoneItem = try #require(store.item(id: created.id))
        #expect(macItem.title == "Bank (renamed on iPhone)")
        #expect(phoneItem.title == macItem.title)
        #expect(firstPlain(phoneItem) == firstPlain(macItem))
        #expect(["mac-user", "phone-user"].contains(firstPlain(macItem) ?? ""))
        let macTitles = Set(mac.shared.listItems(filter: .all, query: nil, sort: .title).map(\.title))
        let phoneTitles = Set(store.items.map(\.title))
        #expect(macTitles == ["Bank (renamed on iPhone)", "Mac only", "iPhone only"])
        #expect(phoneTitles == macTitles)

        // Delete for everyone from the iPhone reaches the Mac.
        let doomed = try #require(store.items.first { $0.title == "Mac only" })
        try store.delete(doomed)
        await link.sync()
        _ = try mac.shared.sync()
        #expect(!mac.shared.listItems(filter: .all, query: nil, sort: .title).contains { $0.title == "Mac only" })

        // Records in the picked folder and the mirror are the same set.
        let mirrorRecords = Set(ExchangeMirror.list(link.folders.mirrorDirectory.appendingPathComponent("records")))
        let icloudRecords = Set(ExchangeMirror.list(icloud.appendingPathComponent("records")))
        #expect(mirrorRecords == icloudRecords)
        #expect(!mirrorRecords.isEmpty)

        // Locking and unlocking again reopens the link from the container.
        model.lock()
        mac.personal.lock()
    }

    @Test func relinkAfterUnlockKeepsTheVault() async throws {
        let icloud = tempDir("icloud")
        let mac = try makeMac(folder: icloud)
        _ = try mac.shared.createItem(category: "login", title: "Shared")
        _ = try mac.shared.sync()
        let (model, password) = await makeUnlockedModel()
        let link = try #require(model.store?.link)
        await link.choose(folder: icloud)
        try await link.join(invitation: try #require(link.invitations.first), words: mac.invitation.passphrase)
        model.lock()
        await model.unlock(password: password)
        let store = try #require(model.store)
        #expect(store.link.isLinked)
        #expect(store.link.folderName == icloud.lastPathComponent)
        #expect(store.items.map(\.title) == ["Shared"])
        mac.personal.lock()
    }
}
