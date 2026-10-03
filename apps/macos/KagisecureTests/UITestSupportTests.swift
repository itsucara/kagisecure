import Foundation
import Testing

@testable import Kagisecure

/// The scripted presence gate's answer log (`-KSUITestPresenceLog`, `UITestSupport`).
///
/// The XCUITest suite's cancelled-prompt scenario waits on this file to know a refused release
/// has been *answered*: a refusal changes nothing on screen, so without it the scenario could only
/// sleep and hope. These pin the two things that scenario relies on — one line per answer, and
/// the line written by the time the answer is returned.
#if DEBUG
    struct UITestSupportTests {
        private static func scratchLog() -> URL {
            FileManager.default.temporaryDirectory
                .appendingPathComponent("kagisecure-presence-log-\(UUID().uuidString).log")
        }

        private static func lines(_ log: URL) throws -> [String] {
            try String(contentsOf: log, encoding: .utf8).split(separator: "\n").map(String.init)
        }

        @Test func everyAnswerIsOneLineWrittenBeforeItIsReturned() async throws {
            let log = Self.scratchLog()
            defer { try? FileManager.default.removeItem(at: log) }
            let gate = ScriptedBiometricGate(outcome: .cancelled, log: log)

            #expect(!FileManager.default.fileExists(atPath: log.path))
            #expect(await gate.authenticate(reason: "reveal") == .cancelled)
            #expect(try Self.lines(log) == ["cancelled"])
            #expect(await gate.authenticate(reason: "copy") == .cancelled)
            #expect(try Self.lines(log) == ["cancelled", "cancelled"])
        }

        @Test func eachOutcomeIsLoggedByName() async throws {
            let log = Self.scratchLog()
            defer { try? FileManager.default.removeItem(at: log) }

            _ = await ScriptedBiometricGate(outcome: .authenticated, log: log)
                .authenticate(reason: "reveal")
            _ = await ScriptedBiometricGate(outcome: .unavailable("no window server"), log: log)
                .authenticate(reason: "reveal")
            #expect(try Self.lines(log) == ["authenticated", "unavailable"])
        }

        @Test func withNoLogNothingIsWritten() async {
            let gate = ScriptedBiometricGate(outcome: .authenticated)
            #expect(await gate.authenticate(reason: "reveal") == .authenticated)
        }
    }
#endif
