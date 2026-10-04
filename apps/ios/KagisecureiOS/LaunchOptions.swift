import Foundation
import KagisecureFFI

/// Where the vault lives and which test hooks are on.
///
/// The vault is the iPhone-local personal vault: inside the app container's
/// Application Support, never iCloud. Paths are always passed explicitly to Rust —
/// `defaultVaultPath()` is not used on iOS.
struct AppEnvironment: Sendable {
    /// Full path of the personal vault file.
    var vaultPath: String
    /// Argon2id override for tests (`nil` = the v1 desktop profile, the same as macOS).
    var kdfMKib: UInt32?
    var kdfT: UInt32?
    /// Scripted presence answer for UI tests (`nil` = real LocalAuthentication).
    var scriptedPresence: PresenceOutcome?
    /// Whether Face ID unlock may be offered at all (UI tests turn it off).
    var biometricsAllowed: Bool

    static let fileName = "default.kagivault"

    static func live() -> AppEnvironment {
        var env = AppEnvironment(
            vaultPath: containerDirectory().appendingPathComponent(fileName).path,
            kdfMKib: nil, kdfT: nil, scriptedPresence: nil, biometricsAllowed: true)
        #if DEBUG
            let args = ProcessInfo.processInfo.arguments
            func value(_ name: String) -> String? {
                guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
                return args[i + 1]
            }
            if let dir = value(LaunchArgument.vaultDirectory) {
                try? FileManager.default.createDirectory(
                    atPath: dir, withIntermediateDirectories: true)
                env.vaultPath = (dir as NSString).appendingPathComponent(fileName)
            }
            if args.contains(LaunchArgument.fastKDF) {
                env.kdfMKib = 64
                env.kdfT = 1
            }
            switch value(LaunchArgument.presence) {
            case "allow": env.scriptedPresence = .confirmed
            case "cancel": env.scriptedPresence = .cancelled
            default: break
            }
            if args.contains(LaunchArgument.noBiometrics) { env.biometricsAllowed = false }
        #endif
        return env
    }

    /// `Application Support/Kagisecure` inside the app container, excluded from backups.
    static func containerDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var dir = base.appendingPathComponent("Kagisecure", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }
}

/// Launch arguments understood by DEBUG builds only (UI tests).
enum LaunchArgument {
    static let vaultDirectory = "-KSVaultDir"
    static let fastKDF = "-KSFastKDF"
    static let presence = "-KSUITestPresence"
    static let noBiometrics = "-KSNoBiometrics"
}
