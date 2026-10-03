import Foundation
import Security
import Testing

@testable import Kagisecure

/// Adversarial tests for `PeerCodeSignature` — the app's answer to "who is asking?".
///
/// # Why this file exists
///
/// `PeerCodeSignature.isKnown` is a **prefix** match, for a documented reason: `codesign`'s ad-hoc
/// identifier for a `cargo build` binary is the file name plus a content hash, so an exact match
/// would call our own sidecar a stranger. The cost of that convenience is that
/// `kagisecure-mcp-evil` also matches the prefix, and the question this file answers is whether
/// the prefix buys an attacker anything beyond a flattering noun in the evidence line (B-12/B-22).
///
/// It answers it against *real processes with real signatures*: a three-line C program compiled,
/// ad-hoc signed under a chosen identifier, run, and inspected through the same `SecCode` path the
/// approval sheet uses. A test that only called `isKnown` would be asserting a string comparison;
/// this one asserts the verdict a human would see. When the machine cannot compile or sign, the
/// probe comes back `nil` and the test returns early — the repository's existing convention for
/// "this says something about the build machine, not about the app".
///
/// It also pins `knownBrowsers`. That table hardcodes four vendors' team identifiers with no
/// refresh mechanism anywhere in the repository, so a silent edit to it is a silent change to who
/// the app will call "verified" — and a pinned copy here is what turns such an edit into a failing
/// test rather than a diff nobody reads.
@MainActor
struct PeerCodeSignatureAdversarialTests {
    // MARK: - The known-browser table

    @Test func theHardcodedBrowserTeamsArePinnedSoASilentEditIsCaught() {
        // Deliberately a whole-table comparison rather than a spot check. Adding a browser is a
        // decision about whose signature this app will vouch for; it should require editing this
        // line too.
        let pinned: [(String, String, String)] = [
            ("com.google.Chrome", "EQHXZ8M8AV", "Google Chrome"),
            ("com.google.Chrome.beta", "EQHXZ8M8AV", "Google Chrome Beta"),
            ("com.google.Chrome.dev", "EQHXZ8M8AV", "Google Chrome Dev"),
            ("com.google.Chrome.canary", "EQHXZ8M8AV", "Google Chrome Canary"),
            ("com.microsoft.edgemac", "UBF8T346G9", "Microsoft Edge"),
            ("company.thebrowser.Browser", "S6N382Y83G", "Arc"),
            ("com.brave.Browser", "KL8N8XSYF4", "Brave Browser"),
        ]
        let actual = PeerCodeSignature.knownBrowsers.map { ($0.identifier, $0.team, $0.name) }
        #expect(actual.count == pinned.count, "the browser table changed size")
        for (index, expected) in pinned.enumerated() where index < actual.count {
            #expect(actual[index] == expected, "browser table entry \(index) changed")
        }
        // A team identifier is ten characters of uppercase alphanumerics; a typo that produced a
        // shorter string would silently match nothing, which reads as "no browser is ever
        // verified" rather than as an error.
        for browser in PeerCodeSignature.knownBrowsers {
            #expect(browser.team.count == 10, "\(browser.identifier) has a malformed team")
            #expect(browser.team.allSatisfy { $0.isUppercase || $0.isNumber })
        }
    }

    @Test func aBrowserIsMatchedExactlyRatherThanByPrefix() {
        // The browser table is the one place a prefix match would be catastrophic, because the
        // identifier is somebody else's namespace. `checkBrowser` uses `==`; this pins the
        // consequence: no lookalike identifier resolves to a known browser.
        for hostile in [
            "com.google.Chrome.evil", "com.google.Chromexyz", "com.brave.Browser2",
            "company.thebrowser.Browser.helper",
        ] {
            #expect(
                !PeerCodeSignature.knownBrowsers.contains(where: { $0.identifier == hostile }),
                "\(hostile) resolved to a known browser")
        }
    }

    // MARK: - B-12/B-22: what the sidecar prefix match actually grants

    @Test func theSidecarPrefixMatchAdmitsLookalikeIdentifiers() {
        // Not a defect on its own — it is the documented trade — but it is the fact everything
        // below has to compensate for, so it is stated rather than left implicit.
        #expect(PeerCodeSignature.isKnown("kagisecure-mcp"))
        #expect(
            PeerCodeSignature.isKnown("kagisecure-mcp-evil"),
            "the prefix match admits any suffix; the verdict below is what must still fail closed")
        #expect(PeerCodeSignature.isKnownHost("kagisecure-nmhost-evil"))
        #expect(!PeerCodeSignature.isKnown("evil-kagisecure-mcp"), "the match is anchored at least")
        #expect(
            !PeerCodeSignature.isKnown(PeerCodeSignature.safariExtensionIdentifier),
            "the Safari extension is not a sidecar and must not be mistaken for one")
        #expect(
            !PeerCodeSignature.isKnownHost("kagisecure-mcp"),
            "a sidecar on the extension socket is reported as what it is, not waved through")
    }

    @Test func anAdHocBinaryNamedLikeOurSidecarIsNotVerified() throws {
        // The full path, against a real process: identifier `kagisecure-mcp-evil`, ad-hoc signed,
        // running. It clears `isKnown` by prefix, and must still come back unverified with
        // evidence that names the ad-hoc flag — the one fact that distinguishes it from our own
        // signed sidecar.
        guard let probe = try SignedProbeProcess.make(identifier: "kagisecure-mcp-evil")
        else { return }
        defer { probe.stop() }

        let verdict = PeerCodeSignature().check(pid: probe.pid)
        #expect(!verdict.verified, "a lookalike must never reach a verified verdict")
        #expect(
            verdict.evidence.contains("ad-hoc"),
            "the evidence must name the ad-hoc flag, not just the friendly identifier: \(verdict.evidence)")
        #expect(verdict.evidence.contains("kagisecure-mcp-evil"), "and must show the real name")
    }

    @Test func anAdHocBinaryClaimingToBeChromeIsNotVerified() throws {
        // The browser half: `com.google.Chrome` matches the table exactly, so the only thing
        // standing between this process and a green "Browser: verified" row is the ad-hoc check
        // and the team comparison.
        guard let probe = try SignedProbeProcess.make(identifier: "com.google.Chrome")
        else { return }
        defer { probe.stop() }

        let verdict = PeerCodeSignature().checkBrowser(pid: probe.pid)
        #expect(!verdict.verified)
        #expect(
            verdict.evidence.contains("ad-hoc") || verdict.evidence.contains("team"),
            "evidence: \(verdict.evidence)")
    }

    @Test func anAdHocBinaryClaimingToBeOurSafariExtensionIsNotVerified() throws {
        guard let probe = try SignedProbeProcess.make(
                identifier: PeerCodeSignature.safariExtensionIdentifier) else { return }
        defer { probe.stop() }

        let verdict = PeerCodeSignature().checkSafariExtension(pid: probe.pid)
        #expect(!verdict.verified)
        #expect(verdict.evidence.contains("ad-hoc"))
    }

    @Test func anUnrelatedIdentifierIsReportedAsWhatItIs() throws {
        guard let probe = try SignedProbeProcess.make(identifier: "com.evil.definitely-not-ours")
        else { return }
        defer { probe.stop() }

        let verdict = PeerCodeSignature().check(pid: probe.pid)
        #expect(!verdict.verified)
        #expect(verdict.evidence.contains("not a kagisecure sidecar"))
    }

    // MARK: - The combined fill verdict

    @Test func aMissingBrowserHalfFailsTheChromiumFillAndNotTheSafariOne() {
        // The one `nil` that must mean two different things, per `FillSignature.Peer`. A
        // regression that collapsed the cases would make a Chromium fill with an uninspectable
        // browser look exactly like a Safari fill, which is a verified verdict about a process
        // nobody looked at.
        let ours = PeerSignature(verified: true, evidence: "KS_CANARY_HOST (team AAAAAAAAAA)")
        let chromium = FillSignature(peer: .nativeMessagingHost, host: ours, browser: nil)
        #expect(!chromium.verified, "a Chromium fill with no browser verdict must fail closed")
        let safari = FillSignature(peer: .appExtension, host: ours, browser: nil)
        #expect(safari.verified, "on Safari there is genuinely only one process")
    }

    @Test func aVerifiedBrowserCannotCarryAnUnverifiedHelper() {
        let signedBrowser = PeerSignature(verified: true, evidence: "Google Chrome (team EQHXZ8M8AV)")
        let adHocHelper = PeerSignature(verified: false, evidence: "kagisecure-nmhost, ad-hoc signed")
        let fill = FillSignature(
            peer: .nativeMessagingHost, host: adHocHelper, browser: signedBrowser)
        #expect(!fill.verified, "the combined verdict must not flatter the weaker half")
    }

    // MARK: - G-22: a pid is not an identity

    @Test func aPidThatNoLongerExistsIsRefusedRatherThanTrusted() throws {
        // The observable half of the pid-recycling question. `PeerCodeSignature` never records a
        // process start time, so a pid reused between ancestry resolution and
        // `SecCodeCheckValidity` would be inspected as if it were the original — see this suite's
        // report. What *is* assertable is that a dead pid fails closed rather than resolving to
        // whatever the system hands back.
        guard let probe = try SignedProbeProcess.make(identifier: "kagisecure-mcp")
        else { return }
        let pid = probe.pid
        probe.stop()
        probe.waitUntilExited()

        let verdict = PeerCodeSignature().check(pid: pid)
        #expect(!verdict.verified, "a dead pid must never be verified")
        #expect(PeerCodeSignature().checkBrowser(pid: pid).verified == false)
        #expect(PeerCodeSignature().check(pid: nil) == .noPeer)
    }
}

/// A short-lived real process with a chosen ad-hoc signing identifier.
///
/// Three lines of C, compiled and then ad-hoc signed under a chosen identifier: the cheapest way
/// to get a genuine `SecCode` whose `kSecCodeInfoIdentifier` is a string this test picked. Nothing
/// about it is privileged — which is the point, because nothing about an attacker's binary would
/// be either.
///
/// Compiled rather than copied from `/bin`: re-signing a *platform* binary such as `/bin/sleep`
/// strips the platform identity its arm64e ABI depends on, and AMFI kills the process at exec with
/// SIGKILL before any test can inspect it.
final class SignedProbeProcess {
    let pid: UInt32
    private let process: Process
    private let directory: URL

    private init(pid: UInt32, process: Process, directory: URL) {
        self.pid = pid
        self.process = process
        self.directory = directory
    }

    /// Returns `nil` when this machine cannot re-sign a binary, so the suite degrades to skipped
    /// rather than to a statement about the developer's toolchain.
    static func make(identifier: String) throws -> SignedProbeProcess? {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("ks-probe-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let binary = directory.appendingPathComponent("probe")
        let source = directory.appendingPathComponent("probe.c")
        try "#include <unistd.h>\nint main(void) { sleep(120); return 0; }\n"
            .write(to: source, atomically: true, encoding: .utf8)

        let compile = Process()
        compile.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
        compile.arguments = ["-O0", "-o", binary.path, source.path]
        compile.standardOutput = Pipe()
        compile.standardError = Pipe()
        do {
            try compile.run()
        } catch {
            try? FileManager.default.removeItem(at: directory)
            return nil
        }
        // Bounded, because this suite must not be able to hang the gate. On a machine where the
        // toolchain or the code-signing daemons are wedged, `cc` can sit in `dyld` indefinitely;
        // giving up and skipping is a statement about the machine, and waiting forever is not.
        guard compile.waitUntilExit(within: 60) else {
            compile.terminate()
            try? FileManager.default.removeItem(at: directory)
            return nil
        }
        guard compile.terminationStatus == 0 else {
            try? FileManager.default.removeItem(at: directory)
            return nil
        }

        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["-f", "-s", "-", "--identifier", identifier, binary.path]
        codesign.standardOutput = Pipe()
        codesign.standardError = Pipe()
        do {
            try codesign.run()
        } catch {
            try? FileManager.default.removeItem(at: directory)
            return nil
        }
        guard codesign.waitUntilExit(within: 60) else {
            codesign.terminate()
            try? FileManager.default.removeItem(at: directory)
            return nil
        }
        guard codesign.terminationStatus == 0 else {
            try? FileManager.default.removeItem(at: directory)
            return nil
        }

        let process = Process()
        process.executableURL = binary
        try process.run()
        // The process has to be far enough along that the kernel can hand out a `SecCode` for it.
        Thread.sleep(forTimeInterval: 0.15)
        // A re-signed binary that AMFI refuses is killed at exec, and inspecting its pid would
        // assert something about this machine rather than about the app. Skip instead.
        guard process.isRunning else {
            try? FileManager.default.removeItem(at: directory)
            return nil
        }
        return SignedProbeProcess(
            pid: UInt32(process.processIdentifier), process: process, directory: directory)
    }

    func stop() {
        if process.isRunning { process.terminate() }
        try? FileManager.default.removeItem(at: directory)
    }

    func waitUntilExited() {
        _ = process.waitUntilExit(within: 10)
    }
}

extension Process {
    /// `waitUntilExit()` with a deadline. Returns `false` if the process is still running.
    ///
    /// `Process.waitUntilExit()` has no timeout, and a test bundle that inherits a wedged
    /// toolchain would otherwise hang the whole gate rather than fail or skip.
    func waitUntilExit(within seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        return !isRunning
    }
}
