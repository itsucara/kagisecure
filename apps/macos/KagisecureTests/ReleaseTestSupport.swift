import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// A Swift stand-in for the app's `PresenceGate`, installed on a real `VaultSession`: answers from
/// a script and counts how often Rust asked.
///
/// The Rust side's own suite (`crates/kagisecure-ffi/tests/release_presence_adversarial.rs`) pins
/// what a release does with each answer. What these tests pin is the app's half: how many times a
/// Swift action makes Rust ask, and what the app shows or copies for each answer.
final class ScriptedPresenceGate: PresenceGate, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [PresenceOutcome]
    private var _reasons: [String] = []

    /// `answers` in order; once they run out, every further prompt is `.cancelled` — a person who
    /// never touched the sensor.
    init(_ answers: [PresenceOutcome]) {
        self.answers = answers
    }

    var calls: Int { read { _reasons.count } }
    var reasons: [String] { read { _reasons } }

    func confirm(reason: String) async -> PresenceOutcome {
        lock.withLock {
            _reasons.append(reason)
            return answers.isEmpty ? .cancelled : answers.removeFirst()
        }
    }

    private func read<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// A gate whose prompt stays up until the test answers it — for "the vault locked while the
/// prompt was on screen".
final class HeldPresenceGate: PresenceGate, @unchecked Sendable {
    private let lock = NSLock()
    private var waiting: CheckedContinuation<PresenceOutcome, Never>?
    private var _calls = 0

    var calls: Int {
        lock.lock()
        defer { lock.unlock() }
        return _calls
    }

    var isAsking: Bool {
        lock.lock()
        defer { lock.unlock() }
        return waiting != nil
    }

    func confirm(reason: String) async -> PresenceOutcome {
        await withCheckedContinuation { continuation in
            lock.withLock {
                _calls += 1
                waiting = continuation
            }
        }
    }

    /// Answer the prompt that is up.
    func answer(_ outcome: PresenceOutcome) {
        lock.lock()
        let pending = waiting
        waiting = nil
        lock.unlock()
        pending?.resume(returning: outcome)
    }
}

/// A throwaway vault with one Login — "GitHub" — whose password, one-time password and notes are
/// all canaries, at KDF parameters that protect nothing.
@MainActor
struct ReleaseFixture {
    static let password = "KS_CANARY_RELEASE_g1thub-p4ssw0rd"
    static let notes = "KS_CANARY_NOTES_recovery-codes-1234"
    static let totpUri = "otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME"
    static let master = "correct horse battery staple"

    let session: VaultSession
    let store: VaultStore
    let item: ItemView
    let directory: URL

    var passwordField: FieldView { item.fields.first { $0.label == "password" }! }
    var totpField: FieldView { item.fields.first { $0.kind == .totp }! }

    init() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("kagisecure-release-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.directory = directory
        let session = try VaultSession.create(
            path: directory.appendingPathComponent("r.kagivault").path,
            masterPassword: Self.master, vaultName: "Personal", kdfMKib: 64, kdfT: 1)
        let store = VaultStore(session: session)
        try store.createItem(category: "login")
        let created = try #require(store.selectedItem)
        try store.save(
            draft: ItemDraft(
                id: created.id, category: created.category, title: "GitHub",
                fields: created.fields.map { field in
                    FieldDraft(
                        id: field.id, label: field.label, kind: field.kind,
                        concealed: field.concealed,
                        value: field.kind == .totp
                            ? Self.totpUri
                            : (field.label == "password" ? Self.password : "ada"),
                        section: field.section, agentVisible: field.agentVisible)
                },
                tags: [], urls: ["https://github.com"], notes: Self.notes,
                revision: created.revision))
        self.session = session
        self.store = store
        self.item = try #require(store.selectedItem)
    }

    /// Install `gate` as the session's presence gate — once, as the app does at unlock.
    @discardableResult
    func install<G: PresenceGate>(_ gate: G) throws -> G {
        try session.setPresenceGate(gate: gate)
        return gate
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

/// Wait, briefly, for `condition` — for the moment a prompt is actually up.
@MainActor
func eventually(
    within limit: Duration = .seconds(5), _ condition: @MainActor () -> Bool
) async -> Bool {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: limit)
    while clock.now < deadline {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

/// Where the app's own sources are, for the source scans.
enum AppSources {
    static var root: URL {
        var url = URL(fileURLWithPath: #filePath)
        // …/apps/macos/KagisecureTests/ReleaseTestSupport.swift -> …/apps/macos
        url.deleteLastPathComponent()
        url.deleteLastPathComponent()
        return url
    }

    /// Every Swift file under `apps/macos/<directory>`.
    static func swiftFiles(in directory: String) -> [URL] {
        let base = root.appendingPathComponent(directory)
        let walker = FileManager.default.enumerator(at: base, includingPropertiesForKeys: nil)
        var files: [URL] = []
        while let next = walker?.nextObject() as? URL {
            if next.pathExtension == "swift" { files.append(next) }
        }
        return files.sorted { $0.path < $1.path }
    }

    /// `url`'s source with every comment removed, so a scan finds code, not prose about it.
    static func code(of url: URL) throws -> String {
        let source = try String(contentsOf: url, encoding: .utf8)
        var out = ""
        var inBlock = false
        for line in source.split(separator: "\n", omittingEmptySubsequences: false) {
            var text = Substring(line)
            if inBlock {
                guard let end = text.range(of: "*/") else { continue }
                text = text[end.upperBound...]
                inBlock = false
            }
            while let start = text.range(of: "/*") {
                let before = text[..<start.lowerBound]
                if let end = text[start.upperBound...].range(of: "*/") {
                    text = before + text[end.upperBound...]
                } else {
                    text = before
                    inBlock = true
                }
            }
            if let comment = text.range(of: "//") {
                text = text[..<comment.lowerBound]
            }
            out += text + "\n"
        }
        return out
    }
}

/// The name of the `FfiError` case `body` threw — `"PresenceCancelled"`, `"VaultLocked"` — or
/// `nil` if it threw nothing (or something else). Every `FfiError` case carries a message, so
/// the case is compared by name rather than by value.
@MainActor
func refusal(_ body: @MainActor () async throws -> Void) async -> String? {
    do {
        try await body()
        return nil
    } catch let error as FfiError {
        return String(describing: error).split(separator: "(").first.map(String.init)
    } catch {
        return "not an FfiError: \(error)"
    }
}

/// A presence gate that always says yes — for tests about what a value *is* after a save, not
/// about the gate (`ReleasePresenceTests` is about the gate).
final class ConfirmingPresenceGate: PresenceGate, @unchecked Sendable {
    func confirm(reason: String) async -> PresenceOutcome { .confirmed }
}

/// One field's stored value, through a confirmed release — the only way a value leaves the vault
/// since ADR-0038 removed the ungated calls. Installs `ConfirmingPresenceGate` on first use; a
/// session whose gate is already installed keeps it (Rust refuses a second).
func releasedValue(_ session: VaultSession, itemId: String, fieldId: String) async throws -> String
{
    try? session.setPresenceGate(gate: ConfirmingPresenceGate())
    return try await session.releaseField(itemId: itemId, fieldId: fieldId, purpose: .reveal).value()
}

/// An item's one-time code at `at`, through a confirmed release (`fieldId` `nil`: its first).
func releasedCode(
    _ session: VaultSession, itemId: String, fieldId: String?, at: UInt64
) async throws -> TotpCodeView {
    try? session.setPresenceGate(gate: ConfirmingPresenceGate())
    return try await session.releaseTotp(itemId: itemId, fieldId: fieldId, purpose: .reveal)
        .codeAt(at: at)
}
