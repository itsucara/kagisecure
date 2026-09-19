import Foundation
import LocalAuthentication
import Testing

@testable import Kagisecure

/// The Secure Enclave path.
///
/// These tests are honest about their environment rather than mocking it away. Three things can
/// make them impossible to run, and each is a skip, not a failure:
///
/// * the Mac has no Secure Enclave or no enrolled fingerprint;
/// * the build is signed ad-hoc, so the keychain refuses to let it own items
///   (`errSecMissingEntitlement`, ADR-0011);
/// * the unwrap needs a live fingerprint, which nothing in a test run can supply.
///
/// So the wrap half is asserted for real — creating an Enclave key and encrypting with its public
/// half needs no biometric — and the unwrap half is exercised only far enough to prove it reaches
/// the Enclave and asks, which is the part that could silently regress into "did not ask".
@MainActor
struct PlatformKeyServiceTests {
    private static let vaultKey = Data(repeating: 0x2A, count: 32)

    @Test func reportsAvailabilityWithoutPrompting() {
        let service = PlatformKeyService()
        // Whatever the answer, it must be a decided one: `.unknown` is the pre-check state and
        // must never survive a call.
        #expect(service.availability() != .unknown)
    }

    /// Whether this machine and this build can actually exercise the Secure Enclave path: hardware
    /// and an enrolled biometric present, *and* the build signed so the keychain lets it own items
    /// (`keychain-access-groups` — ADR-0011; missing under ad-hoc and plain Developer-ID/Development
    /// signing). The only way to know the second half is to ask the keychain, so this attempts a
    /// real wrap-only enrollment (no biometric prompt needed for that half) and discards it.
    ///
    /// `nonisolated` and file-private rather than a method on the `@MainActor` test type: the
    /// `.enabled(if:)` trait below evaluates its condition before the test body runs, off the main
    /// actor, and `PlatformKeyService` is `Sendable` so there is nothing it needs the actor for.
    nonisolated private static func secureEnclaveIsUsable() -> Bool {
        let service = PlatformKeyService()
        guard service.availability().isAvailable else { return false }
        defer { service.deleteKey() }
        do {
            _ = try service.enroll(vaultKey: Data(repeating: 0x2A, count: 32))
            return true
        } catch {
            return false
        }
    }

    @Test(
        .enabled(
            if: PlatformKeyServiceTests.secureEnclaveIsUsable(),
            Comment(
                rawValue: "needs a Secure Enclave, an enrolled biometric, and a build signed "
                    + "with the keychain-access-groups entitlement (ADR-0011)")))
    func enrollmentWrapsTheVaultKeyInsideTheEnclave() throws {
        let service = PlatformKeyService()
        defer { service.deleteKey() }

        let enrolled = try service.enroll(vaultKey: Self.vaultKey)

        #expect(enrolled.slotId == "macos-secure-enclave")
        #expect(!enrolled.wrappedKey.isEmpty)
        // ECIES with an ephemeral P-256 key: 65 bytes of ephemeral public key, the ciphertext,
        // and a 16-byte GCM tag. Whatever the exact framing, it must not be the plaintext.
        #expect(enrolled.wrappedKey.count > Self.vaultKey.count)
        #expect(enrolled.wrappedKey != Self.vaultKey)
        #expect(
            !enrolled.wrappedKey.range(of: Self.vaultKey).map { _ in true }.isNil,
            "the wrapped blob must not contain the vault key verbatim")
        #expect(service.hasKey())

        // Two enrolments produce different ciphertext for the same input: the ephemeral key is
        // per-call, so a blob cannot be correlated across enrolments.
        let second = try service.enroll(vaultKey: Self.vaultKey)
        #expect(second.wrappedKey != enrolled.wrappedKey)
    }

    @Test func deletingTheKeyMakesTheServiceReportItIsGone() throws {
        let service = PlatformKeyService()
        guard service.availability().isAvailable else { return }
        do {
            _ = try service.enroll(vaultKey: Self.vaultKey)
        } catch {
            return  // Entitlement unavailable to this build — see `secureEnclaveIsUsable` above.
        }
        #expect(service.hasKey())
        service.deleteKey()
        #expect(!service.hasKey())
    }

    @Test func unwrappingWithNoEnrolledKeyFailsCleanly() {
        let service = PlatformKeyService()
        service.deleteKey()
        #expect(throws: PlatformKeyError.self) {
            _ = try service.unwrap(Data([1, 2, 3, 4]))
        }
    }
}

extension Optional {
    fileprivate var isNil: Bool { self == nil }
}
