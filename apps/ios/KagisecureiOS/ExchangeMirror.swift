import CryptoKit
import Foundation

/// Copies a shared vault's exchange folder between the folder the person picked (in iCloud
/// Drive) and a mirror inside the app container.
///
/// Rust never reads iCloud: `SharedVaultSession.setFolder` is given only the mirror's path. A
/// shared vault's records are append-only and one file each (`records/<64 hex>.ksr`, ADR-0035
/// decision 85), so syncing the two folders is "copy whatever the other side lacks", both ways.
/// A record file is only copied — or allowed to replace the other side's — when its bytes hash to
/// its own name (`isValidRecord`); a file that does not is never copied and never overwrites one
/// that does.
/// Invitations (`*.kagisecure-invite` at the top level, where the Mac's invite sheet saves them)
/// only come in.
///
/// Every read and write of the picked folder goes through `NSFileCoordinator`, and a file iCloud
/// has not downloaded yet (a `.name.icloud` placeholder, or a file whose status is not current)
/// is asked for with `startDownloadingUbiquitousItem` and picked up on a later pass.
struct ExchangeMirror: Sendable {
    let remote: URL
    let mirror: URL

    static let recordsFolder = "records"
    static let invitationExtension = "kagisecure-invite"

    struct Report: Equatable, Sendable {
        /// Files copied from the picked folder into the mirror.
        var pulled = 0
        /// Files copied from the mirror into the picked folder.
        var pushed = 0
        /// Files iCloud still has to download; asked for, picked up next time.
        var pending = 0
    }

    /// A record file's name: 64 lower-case hex digits and `.ksr` — what Rust itself accepts.
    static func isRecordName(_ name: String) -> Bool {
        guard name.hasSuffix(".ksr") else { return false }
        let hex = name.dropLast(4)
        return hex.count == 64 && hex.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    static let recordDomain = Array("kagisecure/shared/sig/record/v1".utf8)
    static let maxRecordBytes = 1 << 20

    /// The record id of a record file's bytes, or nil if they are not a record envelope
    /// (docs/shared-vault-format.md §4.1): the CBOR array `[1, author bytes(32), body bytes,
    /// sig bytes(64)]` with every head in its shortest form and nothing after it, at most 1 MiB.
    /// `record_id := SHA-256("kagisecure/shared/sig/record/v1" ‖ 0x00 ‖ author ‖ body ‖ sig)`.
    /// Needs no key: the signature itself is Rust's to verify.
    static func recordID(of data: Data) -> String? {
        let b = [UInt8](data)
        guard b.count <= maxRecordBytes, b.count >= 3, b[0] == 0x84, b[1] == 0x01 else { return nil }
        var i = 2
        func bytes() -> ArraySlice<UInt8>? {
            guard i < b.count, b[i] >> 5 == 2 else { return nil }
            let info = Int(b[i] & 0x1f); i += 1
            var n: Int
            switch info {
            case 0..<24: n = info
            case 24, 25, 26:
                let w = 1 << (info - 24)
                guard i + w <= b.count else { return nil }
                n = b[i..<i + w].reduce(0) { $0 << 8 | Int($1) }; i += w
                let minimum = info == 24 ? 24 : info == 25 ? 0x100 : 0x10000
                guard n >= minimum else { return nil }
            default: return nil
            }
            guard n <= b.count - i else { return nil }
            defer { i += n }
            return b[i..<i + n]
        }
        guard let author = bytes(), author.count == 32, let body = bytes(),
              let sig = bytes(), sig.count == 64, i == b.count else { return nil }
        var hash = SHA256()
        hash.update(data: recordDomain)
        hash.update(data: [0])
        hash.update(data: Array(author))
        hash.update(data: Array(body))
        hash.update(data: Array(sig))
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Whether `data` is the record its file name `name` claims to be.
    static func isValidRecord(name: String, data: Data) -> Bool {
        isRecordName(name) && recordID(of: data).map { $0 + ".ksr" } == name
    }

    /// The same for the file at `url` (read under coordination; an unreadable file is not valid).
    static func isValidRecord(name: String, at url: URL) -> Bool {
        var data: Data?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var error: NSError?
        var ran = false
        coordinator.coordinate(readingItemAt: url, options: [], error: &error) { url in
            ran = true
            data = try? Data(contentsOf: url)
        }
        if !ran { data = try? Data(contentsOf: url) }
        guard let data else { return false }
        return isValidRecord(name: name, data: data)
    }

    /// The real name behind an iCloud placeholder (`.name.icloud` → `name`), if it is one.
    static func placeholderTarget(_ name: String) -> String? {
        guard name.hasPrefix("."), name.hasSuffix(".icloud") else { return nil }
        let inner = String(name.dropFirst().dropLast(".icloud".count))
        return inner.isEmpty ? nil : inner
    }

    /// One pass both ways. Idempotent: a second pass with nothing new copies nothing.
    func sync() throws -> Report {
        var report = Report()
        let fm = FileManager.default
        let remoteRecords = remote.appendingPathComponent(Self.recordsFolder, isDirectory: true)
        let mirrorRecords = mirror.appendingPathComponent(Self.recordsFolder, isDirectory: true)
        try fm.createDirectory(at: mirrorRecords, withIntermediateDirectories: true)

        // In: records, then invitations.
        let remoteListing = listRemote(remoteRecords, accept: Self.isRecordName, report: &report)
        let mirrorNames = Set(Self.list(mirrorRecords).filter(Self.isRecordName))
        for name in remoteListing.ready.sorted() {
            let source = remoteRecords.appendingPathComponent(name)
            let destination = mirrorRecords.appendingPathComponent(name)
            // Both have it: a record never changes, so the two copies differ only if one is
            // damaged (cut short, or junk under the name). The one whose bytes hash to the name
            // replaces the other; if both or neither do, both are left as they are.
            if mirrorNames.contains(name) {
                let hereValid = Self.isValidRecord(name: name, at: destination)
                if hereValid && Self.isValidRecord(name: name, at: source) { continue }
                if !hereValid, try pull(source, to: destination, name: name, replacing: true) {
                    report.pulled += 1
                } else if hereValid, try push(destination, to: remoteRecords, replacing: true) {
                    report.pushed += 1
                }
                continue
            }
            if try pull(source, to: destination, name: name) { report.pulled += 1 }
        }
        let invites = listRemote(remote, accept: { $0.hasSuffix("." + Self.invitationExtension) }, report: &report)
        let mirrorInvites = Set(Self.list(mirror))
        for name in invites.ready.sorted() where !mirrorInvites.contains(name) {
            if try pull(remote.appendingPathComponent(name), to: mirror.appendingPathComponent(name)) {
                report.pulled += 1
            }
        }

        // Out: records the picked folder has under no name at all (a pending download counts as
        // present — it is the same record on its way).
        let remoteKnown = remoteListing.ready.union(remoteListing.pending)
        for name in Self.list(mirrorRecords).filter(Self.isRecordName).sorted() where !remoteKnown.contains(name) {
            guard Self.isValidRecord(name: name, at: mirrorRecords.appendingPathComponent(name)) else { continue }
            if try push(mirrorRecords.appendingPathComponent(name), to: remoteRecords) {
                report.pushed += 1
            }
        }
        return report
    }

    // MARK: - Listing

    private struct Listing {
        var ready: Set<String> = []
        var pending: Set<String> = []
    }

    static func size(_ url: URL) -> Int {
        (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
    }

    static func list(_ dir: URL) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
    }

    /// The picked folder's entries under `dir` that `accept` takes, split into downloaded and
    /// still-to-download (each of which is asked for).
    private func listRemote(_ dir: URL, accept: (String) -> Bool, report: inout Report) -> Listing {
        var listing = Listing()
        var names: [String] = []
        coordinate(reading: dir) { url in names = Self.list(url) }
        for name in names {
            if let target = Self.placeholderTarget(name) {
                guard accept(target) else { continue }
                if !names.contains(target) {
                    listing.pending.insert(target)
                    requestDownload(dir.appendingPathComponent(target))
                }
                continue
            }
            guard accept(name) else { continue }
            let url = dir.appendingPathComponent(name)
            if Self.isDownloaded(url) {
                listing.ready.insert(name)
            } else {
                listing.pending.insert(name)
                requestDownload(url)
            }
        }
        report.pending += listing.pending.count
        return listing
    }

    /// Whether a file in the picked folder can be read now. Outside iCloud (and in tests) there is
    /// no downloading status: a regular file is ready.
    static func isDownloaded(_ url: URL) -> Bool {
        let values = try? url.resourceValues(forKeys: [
            .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey, .isRegularFileKey,
        ])
        guard values?.isRegularFile ?? false else { return false }
        guard values?.isUbiquitousItem == true else { return true }
        return values?.ubiquitousItemDownloadingStatus == .current
    }

    private func requestDownload(_ url: URL) {
        try? FileManager.default.startDownloadingUbiquitousItem(at: url)
    }

    // MARK: - Copying

    /// Copy one file from the picked folder into the mirror: read under coordination, written to
    /// a temporary name and renamed, so Rust never sees half a file. An empty source is a file
    /// still being written: skipped. Answers whether it copied.
    /// With `name`, the bytes must hash to it (a record), or nothing is copied.
    private func pull(_ source: URL, to destination: URL, name: String? = nil, replacing: Bool = false) throws -> Bool {
        var data: Data?
        var readError: Error?
        coordinate(reading: source) { url in
            do { data = try Data(contentsOf: url) } catch { readError = error }
        }
        if let readError { throw readError }
        guard let data, !data.isEmpty else { return false }
        if let name, !Self.isValidRecord(name: name, data: data) { return false }
        try Self.writeNew(data, to: destination, replacing: replacing)
        return true
    }

    /// Copy one record from the mirror into the picked folder, under a coordinated write. Only a
    /// record whose bytes hash to its name is copied.
    private func push(_ source: URL, to dir: URL, replacing: Bool = false) throws -> Bool {
        let data = try Data(contentsOf: source)
        guard !data.isEmpty, Self.isValidRecord(name: source.lastPathComponent, data: data) else { return false }
        var writeError: Error?
        let destination = dir.appendingPathComponent(source.lastPathComponent)
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        coordinator.coordinate(writingItemAt: destination, options: [], error: &coordinationError) { url in
            do {
                try FileManager.default.createDirectory(
                    at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                if !replacing && FileManager.default.fileExists(atPath: url.path) { return }
                try data.write(to: url, options: .atomic)
            } catch { writeError = error }
        }
        if let error = coordinationError ?? writeError { throw error }
        return true
    }

    /// Write `data` at `destination` through a temporary file in the same folder and a rename. An
    /// existing file is left alone unless `replacing` (a copy cut short).
    static func writeNew(_ data: Data, to destination: URL, replacing: Bool = false) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) {
            guard replacing else { return }
            let temp = destination.deletingLastPathComponent()
                .appendingPathComponent(".tmp-\(UUID().uuidString)")
            do {
                try data.write(to: temp)
                _ = try fm.replaceItemAt(destination, withItemAt: temp)
            } catch {
                try? fm.removeItem(at: temp)
                throw error
            }
            return
        }
        let temp = destination.deletingLastPathComponent()
            .appendingPathComponent(".tmp-\(UUID().uuidString)")
        do {
            try data.write(to: temp)
            try fm.moveItem(at: temp, to: destination)
        } catch {
            try? fm.removeItem(at: temp)
            if !fm.fileExists(atPath: destination.path) { throw error }
        }
    }

    private func coordinate(reading url: URL, _ body: (URL) -> Void) {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var error: NSError?
        var ran = false
        coordinator.coordinate(readingItemAt: url, options: [], error: &error) { url in
            ran = true
            body(url)
        }
        if !ran { body(url) }
    }
}
