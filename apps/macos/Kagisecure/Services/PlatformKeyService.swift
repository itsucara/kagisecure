import Foundation
import LocalAuthentication
import Security

/// What went wrong reaching for the Secure Enclave.
///
/// These are distinguished because the app reacts differently to each: a cancellation is not an
/// error at all, an invalidated key means the wrapped slot is dead and must be pruned, and a
/// missing entitlement means this build cannot use Touch ID and should say so rather than
/// offering a switch that does nothing.
enum PlatformKeyError: LocalizedError, Equatable {
    /// The Mac has no Secure Enclave, or no enrolled biometric.
    case unavailable(String)
    /// The user cancelled the Touch ID sheet, or fell back to the password field.
    case cancelled
    /// No key has been enrolled on this Mac.
    case noKey
    /// The key existed but the fingerprint set changed, so `.biometryCurrentSet` invalidated it.
    case keyInvalidated
    /// The keychain refused the operation because this build is not signed in a way that lets it
    /// own keychain items — ad-hoc signing, typically (ADR-0011).
    case notEntitled
    /// Anything else, with the `OSStatus` or `CFError` rendered.
    case keychain(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let why):
            "Touch ID is not available on this Mac: \(why)"
        case .cancelled:
            "Touch ID was cancelled."
        case .noKey:
            "This Mac has no Touch ID key for kagisecure yet."
        case .keyInvalidated:
            "The Touch ID key was invalidated because the fingerprint set on this Mac changed."
        case .notEntitled:
            "This build of Kagisecure is not signed with an identity that can own keychain items, "
                + "so Touch ID unlock is unavailable. Unlock with your master password."
        case .keychain(let detail):
            "The keychain refused the operation: \(detail)"
        }
    }
}

/// Whether Touch ID can be offered at all, and why not when it cannot.
enum PlatformKeyAvailability: Equatable {
    case unknown
    case available
    case unavailable(String)

    var isAvailable: Bool { self == .available }
}

/// The result of enrolling: the vault key as the Enclave encrypted it, plus a stable slot id.
struct EnrolledPlatformKey {
    let slotId: String
    let wrappedKey: Data
}

/// The Secure Enclave half of ADR-0004.
///
/// The design in one paragraph: a P-256 key pair is generated *inside* the Secure Enclave, with an
/// access control that says the private key may only be used after a biometric from the
/// fingerprint set that exists right now (`.biometryCurrentSet`). The public key needs no
/// authorisation, so wrapping the vault key at enrolment time is silent; the private key is
/// needed to unwrap, so every unlock costs a fingerprint, and the check is enforced by the
/// Enclave rather than by a branch in this file. Adding or removing a fingerprint destroys the
/// private key, and the wrapped copy of the vault key becomes permanently unopenable — which is
/// the intended behaviour, not a bug (ADR-0004).
final class PlatformKeyService: Sendable {
    /// Identifies our key in the keychain. One key per app, per Mac.
    static let applicationTag = "com.kagisecure.app.vault-key.v1"

    /// The ECIES variant used for both directions. `SecKeyCreateEncryptedData` derives a fresh
    /// ephemeral key per call, so there is no nonce for us to manage and no reuse to get wrong.
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    init() {}

    /// Whether the machine has an Enclave and an enrolled biometric.
    func availability() -> PlatformKeyAvailability {
        var error: NSError?
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .unavailable(error?.localizedDescription ?? "no biometric enrolled")
        }
        return .available
    }

    // MARK: - Enrolment

    /// Create (or replace) the Enclave key and wrap `vaultKey` with its public half.
    ///
    /// Wrapping does not prompt: encryption uses the public key, which carries no access control.
    /// That is deliberate — asking for a fingerprint to *store* something the user has already
    /// unlocked would be theatre, and the fingerprint that matters is the one on the way back.
    func enroll(vaultKey: Data) throws -> EnrolledPlatformKey {
        deleteKey()
        let privateKey = try createKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw PlatformKeyError.keychain("the Enclave key has no public half")
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, Self.algorithm) else {
            throw PlatformKeyError.keychain("this Mac does not support the ECIES variant we use")
        }
        var cfError: Unmanaged<CFError>?
        guard
            let wrapped = SecKeyCreateEncryptedData(
                publicKey, Self.algorithm, vaultKey as CFData, &cfError) as Data?
        else {
            throw Self.error(from: cfError)
        }
        return EnrolledPlatformKey(slotId: Self.slotId(), wrappedKey: wrapped)
    }

    // MARK: - Unwrapping

    /// Decrypt the wrapped vault key. This is the call that raises the Touch ID sheet.
    ///
    /// The prompt's wording comes from the `LAContext` attached to the key *query* via
    /// `kSecUseAuthenticationContext`, not from the decrypt call: `SecKeyCreateDecryptedData` has
    /// no place to put a reason string, and a `SecAccessControl`-protected key picked up without a
    /// context shows the system's generic wording instead. Verified on macOS 26.1.
    func unwrap(_ wrappedKey: Data) throws -> Data {
        let context = LAContext()
        context.localizedReason = "unlock your kagisecure vault"
        context.localizedCancelTitle = "Use Password"
        let privateKey = try loadKey(context: context)
        var cfError: Unmanaged<CFError>?
        guard
            let plaintext = SecKeyCreateDecryptedData(
                privateKey, Self.algorithm, wrappedKey as CFData, &cfError) as Data?
        else {
            throw Self.error(from: cfError)
        }
        return plaintext
    }

    /// Whether an Enclave key for this app exists at all, without prompting.
    ///
    /// The query asks for the key's attributes rather than a usable reference, which is not an
    /// operation the access control gates, so nothing appears on screen.
    func hasKey() -> Bool {
        var query = Self.baseQuery()
        query[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess
    }

    /// Remove the Enclave key. Called when the user turns Touch ID off.
    func deleteKey() {
        SecItemDelete(Self.baseQuery() as CFDictionary)
    }

    // MARK: - Keychain plumbing

    private func createKey() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                // `.privateKeyUsage` says the key may be used for crypto at all;
                // `.biometryCurrentSet` says that use costs a fingerprint from *today's*
                // enrolment set, so enrolling a new finger invalidates the key (ADR-0004).
                [.privateKeyUsage, .biometryCurrentSet],
                &accessError)
        else {
            throw Self.error(from: accessError)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                // Not `isPermanent`. Letting `SecKeyCreateRandomKey` file the key itself goes
                // through the data-protection keychain, which on macOS needs an
                // `application-identifier` entitlement and so a provisioning profile; without one
                // it fails with `errSecMissingEntitlement` (-34018) even for a
                // Developer-ID-signed build. Creating the key and then adding it to the
                // file-based keychain ourselves is the macOS-native path and needs no profile.
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: Data(Self.applicationTag.utf8),
                kSecAttrAccessControl as String: access,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            throw Self.error(from: cfError)
        }
        var add = Self.baseQuery()
        add[kSecValueRef as String] = key
        add[kSecAttrLabel as String] = "Kagisecure vault key"
        let status = SecItemAdd(add as CFDictionary, nil)
        switch status {
        case errSecSuccess, errSecDuplicateItem:
            return key
        case errSecMissingEntitlement:
            throw PlatformKeyError.notEntitled
        default:
            throw PlatformKeyError.keychain(Self.describe(status))
        }
    }

    private func loadKey(context: LAContext) throws -> SecKey {
        var query = Self.baseQuery()
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            // `SecItemCopyMatching` with `kSecReturnRef` on a key class hands back a `SecKey`.
            guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
                throw PlatformKeyError.keychain("the keychain returned something that is not a key")
            }
            return unsafeDowncast(result as AnyObject, to: SecKey.self)
        case errSecItemNotFound:
            throw PlatformKeyError.noKey
        case errSecUserCanceled:
            throw PlatformKeyError.cancelled
        case errSecMissingEntitlement:
            throw PlatformKeyError.notEntitled
        default:
            throw PlatformKeyError.keychain(Self.describe(status))
        }
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(applicationTag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]
    }

    /// A stable identifier for the wrapped-key slot this Mac owns.
    ///
    /// The hardware UUID would be nicer, but reading it needs IOKit and adds nothing: v1 keeps one
    /// platform slot per vault file (single owner, single Mac — ui-spec.md §14), so the id is a
    /// label, not a lookup key.
    private static func slotId() -> String {
        "macos-secure-enclave"
    }

    private static func error(from cfError: Unmanaged<CFError>?) -> PlatformKeyError {
        guard let error = cfError?.takeRetainedValue() else {
            return .keychain("unknown failure")
        }
        let nsError = error as Error as NSError
        switch Int32(nsError.code) {
        case errSecUserCanceled, Int32(LAError.userCancel.rawValue),
            Int32(LAError.userFallback.rawValue), Int32(LAError.appCancel.rawValue),
            Int32(LAError.systemCancel.rawValue):
            return .cancelled
        case Int32(LAError.invalidContext.rawValue), errSecInvalidKeyRef:
            return .keyInvalidated
        case errSecMissingEntitlement:
            return .notEntitled
        case errSecItemNotFound:
            return .noKey
        default:
            return .keychain(nsError.localizedDescription)
        }
    }

    private static func describe(_ status: OSStatus) -> String {
        SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
    }
}
