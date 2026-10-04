import Foundation
import LocalAuthentication
import Security

/// Face ID unlock (ADR-0004/0011), ported from apps/macos PlatformKeyService.swift.
///
/// A Secure Enclave P-256 key with `.biometryCurrentSet` encrypts the vault key that
/// `exportVaultKeyForPlatformWrapping` hands out; the ciphertext is stored in the vault as a
/// platform slot. Unlock decrypts it after Face ID and passes it to `unlockWithVaultKey`.
enum PlatformKeyError: LocalizedError, Equatable {
    case unavailable(String)
    case cancelled
    case noKey
    case keyInvalidated
    case keychain(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let why): String(localized: "Face ID is not available: \(why)")
        case .cancelled: String(localized: "Face ID was cancelled.")
        case .noKey: String(localized: "This iPhone has no Face ID key for kagisecure yet.")
        case .keyInvalidated:
            String(localized: "Face ID no longer unlocks this vault because the enrolled faces changed. Unlock with your master password, then turn Face ID back on in Settings.")
        case .keychain(let detail): String(localized: "The keychain refused the operation: \(detail)")
        }
    }
}

struct EnrolledPlatformKey: Sendable {
    let slotId: String
    let wrappedKey: Data
}

/// What the app model needs from the platform keystore; a fake stands in for it in unit tests
/// (the simulator has no Secure Enclave).
protocol PlatformKeyProviding: Sendable {
    func isAvailable() -> Bool
    func enroll(vaultKey: Data) throws -> EnrolledPlatformKey
    func unwrap(_ wrappedKey: Data) throws -> Data
    func deleteKey()
}

struct SecureEnclaveKeyService: PlatformKeyProviding {
    static let applicationTag = "com.itsucara.kagisecure.ios.vault-key.v1"
    static let slotId = "ios-secure-enclave"
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    func isAvailable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    func enroll(vaultKey: Data) throws -> EnrolledPlatformKey {
        deleteKey()
        let privateKey = try createKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw PlatformKeyError.keychain("the Enclave key has no public half")
        }
        var cfError: Unmanaged<CFError>?
        guard
            let wrapped = SecKeyCreateEncryptedData(
                publicKey, Self.algorithm, vaultKey as CFData, &cfError) as Data?
        else { throw Self.error(from: cfError) }
        return EnrolledPlatformKey(slotId: Self.slotId, wrappedKey: wrapped)
    }

    func unwrap(_ wrappedKey: Data) throws -> Data {
        let context = LAContext()
        context.localizedReason = String(localized: "unlock your kagisecure vault")
        context.localizedCancelTitle = String(localized: "Use Password")
        var query = Self.baseQuery()
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound: throw PlatformKeyError.noKey
        case errSecUserCanceled: throw PlatformKeyError.cancelled
        default: throw PlatformKeyError.keychain(Self.describe(status))
        }
        guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw PlatformKeyError.keychain("the keychain returned something that is not a key")
        }
        let privateKey = unsafeDowncast(result as AnyObject, to: SecKey.self)
        var cfError: Unmanaged<CFError>?
        guard
            let plaintext = SecKeyCreateDecryptedData(
                privateKey, Self.algorithm, wrappedKey as CFData, &cfError) as Data?
        else { throw Self.error(from: cfError) }
        return plaintext
    }

    func deleteKey() {
        SecItemDelete(Self.baseQuery() as CFDictionary)
    }

    private func createKey() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], &accessError)
        else { throw Self.error(from: accessError) }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(Self.applicationTag.utf8),
                kSecAttrAccessControl as String: access,
                kSecAttrLabel as String: "Kagisecure vault key",
            ],
        ]
        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            throw Self.error(from: cfError)
        }
        return key
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(applicationTag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]
    }

    private static func error(from cfError: Unmanaged<CFError>?) -> PlatformKeyError {
        guard let error = cfError?.takeRetainedValue() else { return .keychain("unknown failure") }
        let nsError = error as Error as NSError
        switch Int32(nsError.code) {
        case errSecUserCanceled, Int32(LAError.userCancel.rawValue),
            Int32(LAError.userFallback.rawValue), Int32(LAError.appCancel.rawValue),
            Int32(LAError.systemCancel.rawValue):
            return .cancelled
        case Int32(LAError.invalidContext.rawValue), errSecInvalidKeyRef:
            return .keyInvalidated
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
