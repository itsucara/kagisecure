import Foundation
import XCTest

/// The pieces of the world that are not the app: the CLI that seeds a vault, and a real MCP client
/// talking to a real `kagisecure-mcp` sidecar.
///
/// Suite D's whole point is that the *app* is the approval channel — the same
/// `kagisecure-agent` library suite A drives through `kagisecure daemon`, behind a SwiftUI sheet
/// and a biometric gate instead of a terminal prompt. That claim is only tested if the request
/// arrives the way a real one does: out of a separate process, over the socket, through
/// `ApprovalQueue::ask`. So this file starts real processes and speaks the real protocols. Nothing
/// here fakes a request into the app.
enum Harness {
    /// The checkout. Passed in by the suite adapter; falls back to walking up from this file so the
    /// bundle is still runnable straight from Xcode.
    static var repoRoot: URL {
        if let path = ProcessInfo.processInfo.environment["E2E_REPO_ROOT"] {
            return URL(fileURLWithPath: path)
        }
        // …/apps/macos/KagisecureUITests/Harness.swift → the repository root.
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    static var cliBinary: URL { repoRoot.appending(path: "target/debug/kagisecure") }
    static var sidecarBinary: URL { repoRoot.appending(path: "target/debug/kagisecure-mcp") }

    /// The master password every seeded vault uses. Not a secret: the vault is deleted minutes
    /// later and protects a test fixture.
    static let password = "correct horse battery staple"

    /// Deliberately cheap KDF parameters. The released profile takes about a second per unlock and
    /// this suite unlocks on nearly every scenario; what is under test here is the UI, and suite C
    /// already opens a vault written at the real parameters.
    static let cheapKdf = ["--kdf-m-kib", "8", "--kdf-t", "1"]

    struct CommandResult {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    /// Run the CLI once, with the master password on stdin.
    @discardableResult
    static func cli(_ arguments: [String], vault: String, stdin: [String] = []) throws -> CommandResult {
        let process = Process()
        process.executableURL = cliBinary
        process.arguments = ["--vault", vault, "--password-stdin"] + arguments

        let input = Pipe()
        let output = Pipe()
        let errors = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors

        try process.run()
        let lines = ([password] + stdin).joined(separator: "\n") + "\n"
        input.fileHandleForWriting.write(Data(lines.utf8))
        try? input.fileHandleForWriting.close()

        let out = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let err = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        return CommandResult(status: process.terminationStatus, stdout: out, stderr: err)
    }

    /// Run the CLI and fail the scenario if it did not succeed.
    @discardableResult
    static func cliOk(
        _ arguments: [String], vault: String, stdin: [String] = [],
        file: StaticString = #filePath, line: UInt = #line
    ) throws -> CommandResult {
        let result = try cli(arguments, vault: vault, stdin: stdin)
        XCTAssertEqual(
            result.status, 0,
            "kagisecure \(arguments.joined(separator: " ")) exited \(result.status)\n"
                + "stdout: \(result.stdout)\nstderr: \(result.stderr)",
            file: file, line: line)
        return result
    }

    /// Create a vault at `path` with a handful of items, the way a user who has been using
    /// kagisecure for a week would have one.
    ///
    /// Seeded through the CLI rather than through the app's own first-run screen, because the
    /// first-run screen is itself one of the scenarios and every *other* scenario wants to start
    /// after it.
    static func seedVault(at path: String) throws {
        try cliOk(["vault", "init", "--name", "Personal"] + cheapKdf, vault: path)
        try cliOk(
            [
                "item", "add", "--title", "Acme production database", "--category", "database",
                "--field", "hostname=db.acme.internal", "--field", "username=svc_deploy",
                "--secret", "password", "--value-stdin", "--tag", "prod",
            ],
            vault: path, stdin: ["hunter2-acme-production"])
        try cliOk(
            [
                "item", "add", "--title", "GitHub", "--category", "login",
                "--field", "username=alice@example.test", "--secret", "password",
                "--value-stdin", "--tag", "personal", "--url", "https://github.com",
            ],
            vault: path, stdin: ["g1thub-p4ssw0rd"])
        try cliOk(
            [
                "item", "add", "--title", "Stripe", "--category", "api-credential",
                "--field", "endpoint=https://api.stripe.test", "--secret", "key",
                "--value-stdin", "--tag", "prod",
            ],
            vault: path, stdin: ["sk_test_kagisecure_fixture"])
    }
}

/// A real `kagisecure-mcp`, spoken to as an MCP client over stdio.
///
/// Newline-delimited JSON-RPC, by hand, for the same reason suite A does it by hand: the sidecar's
/// stdout is also the thing a canary assertion has to read raw, and a client library consumes that
/// stream first. Replies are correlated by `id` rather than by arrival order, because a call that
/// is waiting on a human sitting in front of an approval sheet genuinely does come back after a
/// later, faster one.
///
/// `@unchecked Sendable` because this is handed between the main thread (which drives the UI and
/// answers the sheet) and a background queue (which is blocked in the tool call that raised it),
/// and that split is the whole design — a call made on the main thread would be waiting for the
/// thread that has to press the button. Every mutable field is behind `lock`.
final class Sidecar: @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()

    private let lock = NSLock()
    private var replies: [Int: [String: Any]] = [:]
    private var buffer = Data()
    private var nextId = 1

    /// Everything the sidecar has written to stdout, byte for byte.
    private(set) var rawStdout = ""
    /// Everything it has written to stderr.
    private(set) var rawStderr = ""

    init(socket: String, cwd: URL, clientName: String = "kagisecure-uitest") throws {
        // Before anything that captures `self`: the readability handlers below do, and Swift will
        // not let them until every stored property is initialised.
        self.clientName = clientName
        process.executableURL = Harness.sidecarBinary
        process.currentDirectoryURL = cwd
        var environment = ProcessInfo.processInfo.environment
        environment["KAGISECURE_SOCKET"] = socket
        process.environment = environment
        process.standardInput = input
        process.standardOutput = output
        process.standardError = errors

        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            self?.consume(chunk)
        }
        errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty, let self else { return }
            self.lock.lock()
            self.rawStderr += String(decoding: chunk, as: UTF8.self)
            self.lock.unlock()
        }

        try process.run()
    }

    private let clientName: String

    private func consume(_ chunk: Data) {
        lock.lock()
        rawStdout += String(decoding: chunk, as: UTF8.self)
        buffer.append(chunk)
        while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
            let line = buffer[buffer.startIndex..<newline]
            buffer = buffer[buffer.index(after: newline)...]
            if let message = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                let id = message["id"] as? Int
            {
                replies[id] = message
            }
        }
        lock.unlock()
    }

    private func send(_ message: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        input.fileHandleForWriting.write(data)
        input.fileHandleForWriting.write(Data("\n".utf8))
    }

    private func reply(for id: Int, timeout: TimeInterval) -> [String: Any]? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            lock.lock()
            let found = replies.removeValue(forKey: id)
            lock.unlock()
            if let found { return found }
            // The XCUITest main thread is the one driving the UI, and a call that is waiting for an
            // approval is waiting for *this* thread to press the button. So callers run `request`
            // on a background queue; this poll is deliberately dumb and lock-free.
            Thread.sleep(forTimeInterval: 0.02)
        }
        return nil
    }

    /// Send a request and wait for the reply with the matching id.
    func request(_ method: String, _ params: [String: Any] = [:], timeout: TimeInterval = 90)
        -> [String: Any]?
    {
        lock.lock()
        let id = nextId
        nextId += 1
        lock.unlock()
        send(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        return reply(for: id, timeout: timeout)
    }

    /// The MCP handshake.
    @discardableResult
    func initialize() -> [String: Any]? {
        let reply = request(
            "initialize",
            [
                "protocolVersion": "2025-11-25",
                "capabilities": [:],
                "clientInfo": ["name": clientName, "version": "0.0.0"],
            ])
        send(["jsonrpc": "2.0", "method": "notifications/initialized"])
        return reply
    }

    struct ToolResult {
        let ok: Bool
        let text: String
        let structured: [String: Any]?
    }

    /// Call a tool. A tool error is a result, not a throw — several scenarios assert on one.
    func call(_ name: String, _ arguments: [String: Any] = [:], timeout: TimeInterval = 90)
        -> ToolResult?
    {
        guard
            let reply = request(
                "tools/call", ["name": name, "arguments": arguments], timeout: timeout)
        else { return nil }
        guard let result = reply["result"] as? [String: Any] else {
            return ToolResult(ok: false, text: "\(reply)", structured: nil)
        }
        let content = (result["content"] as? [[String: Any]] ?? [])
            .compactMap { $0["text"] as? String }
            .joined()
        return ToolResult(
            ok: (result["isError"] as? Bool) != true,
            text: content,
            structured: result["structuredContent"] as? [String: Any])
    }

    func stop() {
        output.fileHandleForReading.readabilityHandler = nil
        errors.fileHandleForReading.readabilityHandler = nil
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
    }

    deinit { stop() }
}
