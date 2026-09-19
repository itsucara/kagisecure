import AppKit
import Foundation

/// Where every `UserDefaults`-backed preference in this app reads and writes.
///
/// Normally `.standard`, which is what a shipped app wants. The indirection exists for one reason:
/// the XCUITest suite (`apps/macos/KagisecureUITests`, docs/e2e-harness.md §7) launches the *real*
/// app bundle, with the real bundle identifier, so anything it writes lands in the real user's
/// `com.kagisecure.app` preferences. A suite that sets auto-lock to "Never" and clipboard clearing
/// to fifteen seconds — both of which it has to, to be able to test them — would be changing the
/// security posture of the machine it ran on.
///
/// The alternative that needs no code is NSUserDefaults' *argument domain*: `-someKey value` on the
/// command line is parsed into a domain that outranks everything and is never persisted. It is
/// rejected here because it outranks the app's own writes too, so a test that changes a setting in
/// the Settings pane would watch the control snap back — the suite could observe the preference but
/// never exercise the pane that sets it.
///
/// So instead the whole store moves. `-KSUITestDefaultsSuite <name>` points every preference at a
/// throwaway suite the suite adapter deletes afterwards.
enum AppDefaults {
    /// The store `@AppStorage` and the preference readers use.
    ///
    /// Resolved once: a `UserDefaults` that changed identity mid-run would leave `@AppStorage`
    /// views bound to the old one.
    ///
    /// `nonisolated(unsafe)` because `UserDefaults` is not `Sendable` to the Swift 6 checker,
    /// although it is documented as thread-safe and is read from every actor in this app. The
    /// alternative — pinning this to the main actor — would put `@AppStorage`'s property wrapper
    /// initialiser, which runs wherever a `View` value is constructed, in a different isolation
    /// domain from its store.
    nonisolated(unsafe) static let shared: UserDefaults = {
        #if DEBUG
            if let name = UITestSupport.value(for: UITestSupport.defaultsSuiteArgument),
                let scratch = UserDefaults(suiteName: name)
            {
                return scratch
            }
        #endif
        return .standard
    }()
}

#if DEBUG

    /// The debug-only launch-argument hooks the XCUITest suite drives the app through.
    ///
    /// # Why launch arguments, and why `#if DEBUG`
    ///
    /// ADR-0007 spends its length arguing that a shipped binary must have no way to be talked into
    /// approving an injection without a human, and docs/e2e-harness.md §6 repeats the rule for this
    /// suite: there is deliberately no environment variable that stubs the biometric gate. Three
    /// properties keep that true here:
    ///
    /// 1. **`#if DEBUG`.** None of this compiles into a Release build, so `make release` ships a
    ///    binary in which these strings do not exist.
    /// 2. **Launch arguments, not environment variables.** An environment variable is inherited by
    ///    every child of whatever set it, and a user who exports one in their shell profile has
    ///    silently changed their password manager. An argument is written once, by whoever spawns
    ///    the process, and is visible in `ps`.
    /// 3. **Not a preference.** Nothing here persists. Quitting the app forgets all of it, so there
    ///    is no state a later launch could inherit.
    ///
    /// What the gate double replaces is the *fingerprint*, not the decision: the sheet still has to
    /// be found, read and pressed by the test, `AgentService.allow` still runs, and `agentResolve`
    /// still carries the verdict into Rust. It is a robot's finger on the sensor, not a bypass
    /// around the sensor.
    enum UITestSupport {
        /// `-KSUITestBiometrics allow|cancel|unavailable` — what the injected gate answers.
        static let biometricsArgument = "-KSUITestBiometrics"

        /// `-KSUITestDefaultsSuite <name>` — a throwaway `UserDefaults` suite, so the suite's
        /// settings changes never reach the real user's preferences. See `AppDefaults`.
        static let defaultsSuiteArgument = "-KSUITestDefaultsSuite"

        /// `-KSUITestAppearance dark|light` — pin `NSApp.appearance`, for the dark-mode captures.
        ///
        /// Forcing the *system* appearance from a test would change the user's Mac. Forcing this
        /// one application's is a property of the process and dies with it.
        static let appearanceArgument = "-KSUITestAppearance"

        /// Whether the app was launched by the UI-test suite at all.
        ///
        /// Used only to decide whether to say so in the window's accessibility tree, so a
        /// screenshot in the report cannot be mistaken for one of a normal session.
        static var isActive: Bool {
            ProcessInfo.processInfo.arguments.contains { $0.hasPrefix("-KSUITest") }
        }

        /// The value following `name` in the launch arguments, if it is there.
        ///
        /// Deliberately not `UserDefaults`: `-key value` pairs also land in the argument domain, and
        /// reading them back from there would mean these hooks were reachable by anything that can
        /// write a preference — which is the property this whole type exists to avoid.
        static func value(for name: String) -> String? {
            let arguments = ProcessInfo.processInfo.arguments
            guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else {
                return nil
            }
            let value = arguments[index + 1]
            // A following argument that is itself a flag means the value was omitted.
            return value.hasPrefix("-") ? nil : value
        }

        /// The biometric gate to install, or `nil` to leave the real `LocalAuthenticationGate`.
        static func biometricGate() -> BiometricGate? {
            switch value(for: biometricsArgument) {
            case "allow": ScriptedBiometricGate(outcome: .authenticated)
            case "cancel": ScriptedBiometricGate(outcome: .cancelled)
            case "unavailable":
                ScriptedBiometricGate(
                    outcome: .unavailable("no authentication method available in this test run"))
            default: nil
            }
        }

        /// Pin the application's appearance, if the suite asked for one.
        ///
        /// Scheduled rather than performed. This is called from `AppModel.init`, which SwiftUI runs
        /// from `KagisecureApp.init()` — *before* there is an `NSApplication`. `NSApp` is an
        /// implicitly-unwrapped optional, so touching it there is not a nil check that fails, it is
        /// a trap: the app died at launch with `EXC_BREAKPOINT` inside this function, every time the
        /// dark-mode scenario ran. Hopping to the next main-actor turn puts it after the
        /// application object exists and long before anything is drawn.
        @MainActor
        static func applyAppearance() {
            guard let appearance = value(for: appearanceArgument) else { return }
            Task { @MainActor in
                switch appearance {
                case "dark": NSApplication.shared.appearance = NSAppearance(named: .darkAqua)
                case "light": NSApplication.shared.appearance = NSAppearance(named: .aqua)
                default: break
                }
            }
        }
    }

    /// A `BiometricGate` that answers the same thing every time, without asking anybody.
    ///
    /// The unit tests have their own double in the test bundle. This one lives in the app because
    /// XCUITest drives the app from *outside* its process and cannot inject anything into it; the
    /// only channel is the command line the app was started with.
    struct ScriptedBiometricGate: BiometricGate {
        let outcome: BiometricOutcome

        func isAvailable() -> Bool {
            if case .unavailable = outcome { return false }
            return true
        }

        func authenticate(reason: String) async -> BiometricOutcome {
            // A real Touch ID sheet takes a moment, and a gate that returns on the same run loop
            // turn hides ordering bugs the real one would expose.
            try? await Task.sleep(for: .milliseconds(120))
            return outcome
        }
    }

#endif
