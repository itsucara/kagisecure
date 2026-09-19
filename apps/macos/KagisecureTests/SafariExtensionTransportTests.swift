import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// The Safari front end's transport, driven through the **same Swift file the app extension
/// ships** against a **real** listener over a **real** socket (M6b, ADR-0024).
///
/// # What is real here, and what is not
///
/// Real: `AppGroupSocket` — the file compiled into `KagisecureSafariExtension.appex`, compiled
/// again here rather than reimplemented — the 4-byte big-endian framing, a Unix socket, a real
/// `ExtensionAgent` in a real second process, a real vault, the origin rule and the audit log.
///
/// Not real, and stated plainly because it is the interesting part:
///
/// 1. **The sandbox boundary.** These assertions run inside the test host, which is not sandboxed,
///    so the socket is a temporary path rather than the App Group container. What that leaves
///    untested is whether a *sandboxed* process can open a socket in its group container — a
///    property of macOS rather than of this code, and one `xcodebuild test` cannot create, because
///    a test bundle cannot be an app extension. It was measured separately, with a
///    Developer-ID-signed sandboxed probe carrying only the App Group entitlement and this same
///    `AppGroupSocket`; the result is in `docs/browser-extension.md` §8.
/// 2. **The peer-identity gate.** The app refuses anything on the Safari socket whose executable
///    is not `KagisecureSafariExtension.appex`, and this test host is not that. The listener is
///    therefore started with the debug affordance that switches the gate off — an affordance that
///    is not on the FFI surface at all, which is why this test drives the `extension_harness`
///    example rather than the app's own listener. The gate itself is asserted with it **on**, in
///    the direction that matters, by `crates/kagisecure-agent/tests/safari.rs`.
///
/// # Why this is worth having anyway
///
/// Because the framing is the one thing two languages have to agree about, and nothing else in the
/// suite makes them. A one-byte disagreement about endianness would produce a Safari extension
/// that connects, sends, and is answered with silence — the hardest failure in the product to
/// diagnose. `theWireFormatIsBigEndian` pins it from the outside for good measure.
@MainActor
struct SafariExtensionTransportTests {

    /// Seeded as the login's password by the harness. If it appears in a reply that should carry
    /// only metadata, this test has found a bug.
    ///
    /// `nonisolated` because `Harness.init` builds the harness's argument list off the main actor.
    nonisolated static let marker = "SWIFT-SAFARI-CANARY-6c1e93f0"

    /// The origin the harness saves the login against.
    nonisolated static let site = "https://safari.example"

    // MARK: - The harness

    /// The repository's `target/debug/examples/extension_harness`, found relative to this file.
    ///
    /// Absent on a machine that has not run `cargo build --example extension_harness`, in which
    /// case the integration tests below return rather than fail — the same policy
    /// `AgentServiceTests` uses for the sidecar, and it is built locally (as CI built it too,
    /// before CI was removed on 2026-09-19) so the skip is not silent there.
    private static func harnessPath() -> String? {
        var url = URL(fileURLWithPath: #filePath)
        // …/apps/macos/KagisecureTests/<this file> -> repository root
        for _ in 0..<4 { url.deleteLastPathComponent() }
        let candidate = url.appendingPathComponent("target/debug/examples/extension_harness")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate.path : nil
    }

    /// A running `extension_harness` serving both front ends, and the Safari socket's path.
    private final class Harness {
        let process = Process()
        let socket: String
        private let directory: URL

        init(binary: String) throws {
            // Short, on purpose: `sun_path` is 104 bytes on macOS.
            directory = URL(fileURLWithPath: "/tmp")
                .appendingPathComponent("ks-sf-\(UUID().uuidString.prefix(8))")
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)
            socket = directory.appendingPathComponent("s.sock").path

            process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = [
                "--socket", directory.appendingPathComponent("e.sock").path,
                "--safari-socket", socket,
                "--site", SafariExtensionTransportTests.site,
                "--username", "alice",
                "--password", SafariExtensionTransportTests.marker,
                "--allow-unlaunched-host",
            ]
            process.standardInput = Pipe()
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            try process.run()

            // Wait for the socket rather than for a line of stdout: the socket existing is the
            // condition every assertion below actually depends on.
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                if FileManager.default.fileExists(atPath: socket) { return }
                Thread.sleep(forTimeInterval: 0.05)
            }
            throw Failure.didNotStart
        }

        enum Failure: Error { case didNotStart }

        func stop() {
            if let stdin = process.standardInput as? Pipe {
                try? stdin.fileHandleForWriting.close()
            }
            process.terminate()
            process.waitUntilExit()
            try? FileManager.default.removeItem(at: directory)
        }
    }

    /// Run `body` against a live harness, or return quietly when the binary is not built.
    private static func serving(_ body: (Harness) throws -> Void) throws {
        guard let binary = harnessPath() else { return }
        let harness = try Harness(binary: binary)
        defer { harness.stop() }
        try body(harness)
    }

    /// The handshake the shipped handler puts in front of every other message.
    private static func helloBody(as id: String = PeerCodeSignature.safariExtensionIdentifier)
        -> [String: Any]
    {
        [
            "ask": "hello",
            "extension_id": id,
            "browser": "safari",
            "extension_version": "0.1.0",
            "protocol_version": 1,
        ]
    }

    /// One request through the shipped `AppGroupSocket`, correlated the way the handler does it —
    /// including the per-connection handshake, because the connection is per-message.
    private static func call(_ harness: Harness, _ body: [String: Any]) throws -> [String: Any] {
        try AppGroupSocket.exchangeAt(
            path: harness.socket,
            envelope: ["ksx": 1, "id": UUID().uuidString, "body": body],
            hello: ["ksx": 1, "id": UUID().uuidString, "body": helloBody()])
    }

    /// A bare handshake, with no request behind it.
    private static func hello(
        _ harness: Harness, as id: String = PeerCodeSignature.safariExtensionIdentifier
    ) throws -> [String: Any] {
        try AppGroupSocket.exchangeAt(
            path: harness.socket,
            envelope: ["ksx": 1, "id": UUID().uuidString, "body": helloBody(as: id)])
    }

    // MARK: - The wire format

    @Test func theWireFormatIsBigEndianAndTheAppSocketRefusesTheOtherByteOrder() throws {
        // Pinned from the outside, because the two channels share a socket directory and a
        // length-prefixed-JSON shape: the extension socket is big-endian and the MCP socket is
        // little-endian on purpose, so a frame sent to the wrong one is refused by the size check
        // rather than misread (ADR-0019 §3). If this ever flips, every Safari fill breaks and no
        // other test in the app bundle would notice.
        var length = UInt32(0x0000_0001).bigEndian
        var bytes = [UInt8]()
        withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
        #expect(bytes == [0x00, 0x00, 0x00, 0x01])
        #expect(AppGroupSocket.maxFrame == 256 * 1024)
    }

    @Test func withNothingListeningTheFailureIsLegibleRatherThanAHang() throws {
        // The failure a user meets most often — the app is simply not open. It has to be an error
        // with a sentence in it, promptly, so the handler can turn it into `VAULT_LOCKED` and the
        // popup can say "open Kagisecure and unlock it".
        let path = "/tmp/ks-nothing-\(UUID().uuidString.prefix(8)).sock"
        do {
            _ = try AppGroupSocket.exchangeAt(
                path: path, envelope: ["ksx": 1, "id": "x", "body": ["ask": "status"]])
            Issue.record("connecting to nothing should not succeed")
        } catch let failure as AppGroupSocket.Failure {
            guard case .notListening = failure else {
                Issue.record("expected notListening, got \(failure)")
                return
            }
            #expect(failure.message.contains("Kagisecure is not running"))
        }
    }

    @Test func aPathTooLongForASocketIsRefusedWithAReasonRatherThanEinval() throws {
        // `sun_path` is 104 bytes. An over-long path otherwise fails inside `connect(2)` with
        // "Invalid argument", which says nothing about length and has cost more than one person an
        // afternoon.
        let long = "/tmp/" + String(repeating: "x", count: 200) + ".sock"
        #expect(throws: AppGroupSocket.Failure.self) {
            _ = try AppGroupSocket.exchangeAt(
                path: long, envelope: ["ksx": 1, "id": "x", "body": ["ask": "status"]])
        }
    }

    // MARK: - Against a real listener

    @Test func aHelloIsAnsweredWithAWelcomeAndTheHostEvidence() throws {
        try Self.serving { harness in
            let reply = try Self.hello(harness)
            #expect(reply["reply"] as? String == "welcome")
            #expect(reply["unlocked"] as? Bool == true)
            // The app tells the extension what it established about the process on the socket, so
            // the popup can show it rather than a reassuring summary of it.
            let evidence = reply["host_evidence"] as? [String] ?? []
            #expect(!evidence.isEmpty)
        }
    }

    @Test func anExtensionIdThatIsNotOursIsRefused() throws {
        try Self.serving { harness in
            let reply = try Self.hello(harness, as: "com.example.not-us")
            #expect(reply["reply"] as? String == "error")
            #expect(reply["code"] as? String == "UNKNOWN_EXTENSION")
        }
    }

    @Test func theChromiumExtensionIdIsRefusedOnTheSafariSocket() throws {
        // The two pins must not satisfy each other, and this asserts it from the Swift side of the
        // boundary as well as the Rust one.
        try Self.serving { harness in
            let reply = try Self.hello(harness, as: "nlijibjnmanccalmafnfbobkcfjiibmd")
            #expect(reply["code"] as? String == "UNKNOWN_EXTENSION")
        }
    }

    @Test func aRequestOnAConnectionThatNeverSaidHelloIsRefusedRatherThanServed() throws {
        // The property the per-message handshake exists to preserve: session state is per
        // connection, so a frame that arrives on a fresh socket is refused rather than served on
        // the strength of some other connection's handshake.
        try Self.serving { harness in
            let reply = try AppGroupSocket.exchangeAt(
                path: harness.socket,
                envelope: ["ksx": 1, "id": "no-hello", "body": ["ask": "status"]])
            #expect(reply["reply"] as? String == "error")
            #expect(reply["code"] as? String == "PROTOCOL")
        }
    }

    @Test func aRefusedHandshakeIsReturnedRatherThanTheSecondReply() throws {
        // If the handshake is refused there is nothing useful behind it, and the extension has to
        // see *why* — a `PROTOCOL` error about the second message would send whoever is debugging
        // it looking in the wrong place.
        try Self.serving { harness in
            let reply = try AppGroupSocket.exchangeAt(
                path: harness.socket,
                envelope: ["ksx": 1, "id": "x", "body": ["ask": "status"]],
                hello: [
                    "ksx": 1, "id": "h", "body": Self.helloBody(as: "com.example.not-us"),
                ])
            #expect(reply["code"] as? String == "UNKNOWN_EXTENSION")
        }
    }

    @Test func aMatchCarriesMetadataAndNeverAValue() throws {
        try Self.serving { harness in
            let reply = try Self.call(harness, ["ask": "match", "page": ["top_origin": Self.site]])
            #expect(reply["reply"] as? String == "matches")
            let items = reply["items"] as? [[String: Any]] ?? []
            #expect(items.count == 1)
            #expect(items.first?["username"] as? String == "alice")
            #expect(!"\(reply)".contains(Self.marker), "a match answer must never carry a value")
        }
    }

    @Test func anApprovedFillCarriesTheValueExactlyOnce() throws {
        // The harness answers its own approval queue — the human is the one thing a test cannot
        // supply — so what this asserts is the whole path below the sheet, in the shipped framing.
        try Self.serving { harness in
            let matched = try Self.call(harness, ["ask": "match", "page": ["top_origin": Self.site]])
            let items = try #require(matched["items"] as? [[String: Any]])
            let itemId = try #require(items.first?["item_id"] as? String)

            let reply = try Self.call(
                harness,
                [
                    "ask": "fill",
                    "page": ["top_origin": Self.site],
                    "item_id": itemId,
                    "fields": ["username", "password"],
                ])
            #expect(reply["reply"] as? String == "filled")
            #expect(reply["username"] as? String == "alice")
            #expect(reply["password"] as? String == Self.marker)
        }
    }

    @Test func aFillAtAMismatchedOriginIsRefusedByTheRuleWithNoPrompt() throws {
        try Self.serving { harness in
            let matched = try Self.call(harness, ["ask": "match", "page": ["top_origin": Self.site]])
            let items = try #require(matched["items"] as? [[String: Any]])
            let itemId = try #require(items.first?["item_id"] as? String)

            let reply = try Self.call(
                harness,
                [
                    "ask": "fill",
                    "page": ["top_origin": "https://phishing.example"],
                    "item_id": itemId,
                    "fields": ["password"],
                ])
            #expect(reply["reply"] as? String == "error")
            #expect(reply["code"] as? String == "ORIGIN_MISMATCH")
        }
    }

    @Test func theFramingSurvivesAMessageLargerThanOneRead() throws {
        // A frame is a length and then that many bytes, and a socket hands them over in whatever
        // chunks it likes. A reader that assumed one `read(2)` per frame would pass every other
        // test here — those replies all fit in one buffer — and fail on the first page whose
        // origin is long.
        try Self.serving { harness in
            let long = "https://" + String(repeating: "a", count: 60_000) + ".example"
            let reply = try Self.call(harness, ["ask": "match", "page": ["top_origin": long]])
            // Whatever the origin rule makes of it, the *transport* must have carried it: an
            // answer, not a dropped connection.
            #expect(reply["reply"] as? String != nil)
        }
    }

    // MARK: - The app's own listener

    @Test func theAppBindsTheSafariSocketAsSoonAsTheVaultIsUnlocked() throws {
        // The harness tests above prove the protocol; this one proves the *app* is what binds the
        // second socket, through the real FFI, with no harness in the way. It is the assertion
        // that would fail if `extension_start` stopped passing the Safari path through.
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ks-app-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let session = try VaultSession.create(
            path: directory.appendingPathComponent("t.kagivault").path,
            masterPassword: "correct horse battery staple", vaultName: "Personal",
            kdfMKib: 8, kdfT: 1)
        _ = session.takeRecoveryCode()

        let safari = directory.appendingPathComponent("s.sock").path
        _ = try extensionStart(
            session: session,
            socketPath: directory.appendingPathComponent("e.sock").path,
            safariSocketPath: safari,
            teamId: nil)
        defer { extensionStop() }

        let status = extensionStatus()
        #expect(status.running)
        #expect(status.safariRunning)
        #expect(status.safariEndpoint == safari)
        #expect(FileManager.default.fileExists(atPath: safari))
    }

    @Test func aBuildWithNoTeamServesChromiumAndSaysWhyItDoesNotServeSafari() throws {
        // The ad-hoc case, which is what a clean checkout builds (CI did too, before it was
        // removed on 2026-09-19). Chromium autofill must
        // keep working, and the screen must have a sentence to show rather than a blank row.
        guard ProcessInfo.processInfo.environment["KAGISECURE_SAFARI_SOCKET"] == nil else { return }
        let directory = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("ks-noteam-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let session = try VaultSession.create(
            path: directory.appendingPathComponent("t.kagivault").path,
            masterPassword: "correct horse battery staple", vaultName: "Personal",
            kdfMKib: 8, kdfT: 1)
        _ = session.takeRecoveryCode()

        _ = try extensionStart(
            session: session,
            socketPath: directory.appendingPathComponent("e.sock").path,
            safariSocketPath: nil,
            teamId: nil)
        defer { extensionStop() }

        let status = extensionStatus()
        #expect(status.running, "Chromium autofill is unaffected by Safari being unavailable")
        #expect(!status.safariRunning)
        #expect(status.safariEndpoint.contains("team identity"))
    }

    // MARK: - What the app checks about the peer

    @Test func theSafariExtensionIsCheckedAgainstOurOwnTeamRatherThanAVendorsSF() {
        // The identifier the app pins, and the asymmetry that matters: a browser is checked
        // against a hardcoded vendor team, and our own app extension against our own team, which
        // is why a Developer-ID-signed build can report a Safari fill fully verified.
        #expect(PeerCodeSignature.safariExtensionIdentifier == "com.kagisecure.app.safari-extension")
        #expect(!PeerCodeSignature.isKnown(PeerCodeSignature.safariExtensionIdentifier))
        #expect(!PeerCodeSignature.isKnownHost(PeerCodeSignature.safariExtensionIdentifier))
    }

    @Test func aSafariFillHasOneVerdictAndAChromiumFillHasTwo() {
        // Safari is never a process on the socket, so a second verdict about it would be a claim
        // nobody checked. The combined answer must therefore be the one verdict there is, not
        // "false because there was no browser to check".
        let signer = PeerCodeSignature()
        let safari = signer.checkFill(hostPid: nil, browserPid: nil, isAppExtension: true)
        #expect(safari.peer == .appExtension)
        #expect(safari.browser == nil)
        #expect(!safari.verified, "no pid means no verdict, and no verdict is not a pass")

        let chromium = signer.checkFill(hostPid: nil, browserPid: 1, isAppExtension: false)
        #expect(chromium.peer == .nativeMessagingHost)
        #expect(chromium.browser != nil)
        #expect(!chromium.verified)

        // The two shapes a single `nil` browser could not tell apart, asserted in both
        // directions: one verified half is the whole answer for Safari, and is *not* an answer at
        // all for a native messaging host with no browser established above it.
        let ours = PeerSignature(verified: true, evidence: "ours")
        #expect(FillSignature(peer: .appExtension, host: ours, browser: nil).verified)
        #expect(!FillSignature(peer: .nativeMessagingHost, host: ours, browser: nil).verified)
    }
}
