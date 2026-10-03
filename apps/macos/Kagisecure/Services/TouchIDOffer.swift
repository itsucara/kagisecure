import Foundation

/// What to do about Touch ID unlock right after a master-password or recovery-code unlock
/// (ADR-0004, amendment of 2026-10-04): Touch ID is on by default.
enum TouchIDOffer: Equatable {
    /// Enrol silently: available, not enrolled, and the person never turned it off.
    case autoEnrol
    /// Ask "Turn on Touch ID unlock?" — available and not enrolled, but turned off earlier (or
    /// auto-enrolment did not work), and the person has not said "Don't show this again".
    case prompt
    /// Already on, unavailable, or the person asked not to be asked.
    case nothing

    /// `UserDefaults` key: the person turned Touch ID off in Settings, so no silent enrolment.
    /// Cleared when they turn it back on.
    static let explicitlyOffKey = "touchID.explicitlyOff"
    /// `UserDefaults` key: "Don't show this again" was checked on the prompt.
    static let dontAskAgainKey = "touchID.dontAskAgain"

    static func decide(
        available: Bool, hasPlatformSlot: Bool, explicitlyOff: Bool, dontAskAgain: Bool
    ) -> TouchIDOffer {
        guard available, !hasPlatformSlot else { return .nothing }
        if !explicitlyOff { return .autoEnrol }
        return dontAskAgain ? .nothing : .prompt
    }

    /// What follows a failed or cancelled silent enrolment.
    static func afterFailedAutoEnrol(dontAskAgain: Bool) -> TouchIDOffer {
        dontAskAgain ? .nothing : .prompt
    }

    static func decide(available: Bool, hasPlatformSlot: Bool, defaults: UserDefaults) -> TouchIDOffer {
        decide(
            available: available, hasPlatformSlot: hasPlatformSlot,
            explicitlyOff: defaults.bool(forKey: explicitlyOffKey),
            dontAskAgain: defaults.bool(forKey: dontAskAgainKey))
    }
}
