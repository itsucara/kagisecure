import Foundation
import KagisecureFFI
import Observation

/// Lifecycle of the iPhone-local personal vault: first run → recovery code → locked ⇄ unlocked.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case setup
        case recoveryCode(String)
        case locked
        case unlocked
    }

    private(set) var phase: Phase
    private(set) var store: VaultStore?
    private(set) var busy = false
    var errorMessage: String?
    /// Whether the vault has a Face ID slot (read from the file, so it is known while locked).
    private(set) var biometricsEnabled = false

    let environment: AppEnvironment
    let platformKeys: any PlatformKeyProviding
    let presence: any PresenceChecking
    private var session: VaultSession?
    /// Bumped by every `lock()`. An unlock that was still running when the app went to the
    /// background (Argon2id or Face ID off the main thread) must not land afterwards.
    private var lockEpoch = 0

    init(environment: AppEnvironment, platformKeys: any PlatformKeyProviding, presence: (any PresenceChecking)? = nil) {
        self.environment = environment
        self.platformKeys = platformKeys
        self.presence =
            presence ?? environment.scriptedPresence.map { ScriptedPresence(outcome: $0) }
            ?? LocalAuthenticationPresence()
        phase = vaultExists(path: environment.vaultPath) ? .locked : .setup
        refreshBiometricState()
    }

    var vaultPath: String { environment.vaultPath }

    /// Face ID can be offered: allowed in this run and the hardware has it enrolled.
    var biometricsAvailable: Bool { environment.biometricsAllowed && platformKeys.isAvailable() }

    nonisolated static let minimumPasswordLength = 8

    nonisolated static func validateNewPassword(_ password: String, confirm: String) -> String? {
        if password.count < minimumPasswordLength {
            return String(localized: "Use at least \(minimumPasswordLength) characters.")
        }
        if password != confirm { return String(localized: "The two passwords do not match.") }
        return nil
    }

    // MARK: First run

    func createVault(password: String, confirm: String, enableBiometrics: Bool) async {
        if let problem = Self.validateNewPassword(password, confirm: confirm) {
            errorMessage = problem
            return
        }
        busy = true
        defer { busy = false }
        let path = vaultPath, m = environment.kdfMKib, t = environment.kdfT
        let epoch = lockEpoch
        do {
            let session = try await Task.detached {
                try VaultSession.create(
                    path: path, masterPassword: password, vaultName: "Personal", kdfMKib: m, kdfT: t)
            }.value
            guard epoch == lockEpoch else {
                // Backgrounded while the vault was being made: it exists now, so the recovery
                // code must still be shown once, but the session does not stay open.
                let code = session.takeRecoveryCode() ?? ""
                session.lock()
                errorMessage = nil
                phase = .recoveryCode(code)
                return
            }
            adopt(session)
            if enableBiometrics && biometricsAvailable {
                try? enrollBiometrics(session)
            }
            errorMessage = nil
            phase = .recoveryCode(session.takeRecoveryCode() ?? "")
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    func acknowledgeRecoveryCode() {
        guard case .recoveryCode = phase else { return }
        phase = session == nil ? .locked : .unlocked
    }

    // MARK: Unlock

    func unlock(password: String) async {
        busy = true
        defer { busy = false }
        let path = vaultPath
        let epoch = lockEpoch
        do {
            let session = try await Task.detached {
                try VaultSession.unlockWithPassword(path: path, masterPassword: password)
            }.value
            guard epoch == lockEpoch else {
                session.lock()
                return
            }
            adopt(session)
            errorMessage = nil
            phase = .unlocked
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    func unlockWithBiometrics() async {
        guard biometricsEnabled else { return }
        busy = true
        defer { busy = false }
        let epoch = lockEpoch
        do {
            guard let wrapped = try platformWrappedKey(path: vaultPath) else {
                biometricsEnabled = false
                return
            }
            let keys = platformKeys
            var key = try await Task.detached { try keys.unwrap(wrapped) }.value
            defer { key.resetBytes(in: 0..<key.count) }
            guard epoch == lockEpoch else { return }
            let session = try VaultSession.unlockWithVaultKey(path: vaultPath, vaultKey: key)
            adopt(session)
            errorMessage = nil
            phase = .unlocked
        } catch PlatformKeyError.cancelled {
            // Fall back to the password field silently.
        } catch let error as PlatformKeyError {
            if error == .keyInvalidated || error == .noKey { biometricsEnabled = false }
            errorMessage = error.localizedDescription
        } catch {
            errorMessage = Self.message(for: error)
        }
    }

    func lock() {
        lockEpoch += 1
        store?.link.stopWatching()
        session?.lock()
        session = nil
        store = nil
        if phase != .setup { phase = .locked }
    }

    // MARK: Face ID setting

    func setBiometrics(_ on: Bool) {
        guard let session else { return }
        do {
            if on {
                try enrollBiometrics(session)
            } else {
                _ = try session.removePlatformSlot()
                platformKeys.deleteKey()
            }
            errorMessage = nil
        } catch {
            errorMessage = Self.message(for: error)
        }
        refreshBiometricState()
    }

    private func enrollBiometrics(_ session: VaultSession) throws {
        var key = session.exportVaultKeyForPlatformWrapping()
        defer { key.resetBytes(in: 0..<key.count) }
        let enrolled = try platformKeys.enroll(vaultKey: key)
        try session.installPlatformSlot(
            slotId: enrolled.slotId, label: "iPhone Face ID", wrappedKey: enrolled.wrappedKey)
        refreshBiometricState()
    }

    private func refreshBiometricState() {
        if let session {
            biometricsEnabled = session.hasPlatformSlot()
        } else {
            biometricsEnabled = ((try? platformSlotId(path: vaultPath)) ?? nil) != nil
        }
    }

    private func adopt(_ session: VaultSession) {
        do {
            try session.setPresenceGate(gate: AppPresenceGate(checker: presence))
        } catch {
            errorMessage = Self.message(for: error)
        }
        self.session = session
        let store = VaultStore(
            session: session,
            containerDirectory: URL(fileURLWithPath: vaultPath).deletingLastPathComponent())
        self.store = store
        refreshBiometricState()
        // Launch and coming back to the foreground both pass through an unlock: sync there.
        if store.link.isLinked || store.link.folderName != nil {
            Task { await store.link.sync() }
        }
        store.link.startWatching()
    }

    nonisolated static func message(for error: Error) -> String {
        guard let ffi = error as? FfiError else { return error.localizedDescription }
        switch ffi {
        case .WrongCredential: return String(localized: "Wrong master password.")
        case .NotFound: return String(localized: "No vault was found on this iPhone.")
        case .AlreadyExists: return String(localized: "A vault already exists on this iPhone.")
        case .ItemChangedElsewhere:
            return String(localized: "This item was changed elsewhere. Reload it and make your edit again.")
        case .VaultLocked: return String(localized: "The vault is locked.")
        case .PresenceCancelled: return String(localized: "Authentication was cancelled.")
        case .PresenceUnavailable:
            return String(localized: "Face ID or a passcode is needed to show or copy secrets.")
        case .PresenceBusy: return String(localized: "Another authentication is already in progress.")
        default: return "\(ffi)"
        }
    }
}
