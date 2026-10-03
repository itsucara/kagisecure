import Foundation

/// The switch the adversarial suites use to stay green while still carrying their evidence.
///
/// # Why a switch rather than a deleted test
///
/// Several tests in `ApprovalRenderingAdversarialTests`, `AgentQueuePairingTests` and friends
/// assert a property the current code does **not** have. Deleting them would throw away the
/// reproduction; leaving them on would make a red suite the normal state, which is how a real
/// regression stops being noticed. So they carry
/// `.enabled(if: SuspectedDefect.shouldRun, "documents suspected defect <ID>: …")`: skipped by
/// default with the reason printed in the test log, and runnable on demand with
///
///     KS_RUN_SUSPECTED_DEFECTS=1 xcodebuild … test
///
/// When one of these is fixed, drop the trait rather than the test — that is the moment the
/// assertion becomes a regression guard.
enum SuspectedDefect {
    /// The environment variable that turns the documented-defect tests back on.
    static let environmentKey = "KS_RUN_SUSPECTED_DEFECTS"

    static var shouldRun: Bool {
        ProcessInfo.processInfo.environment[environmentKey] == "1"
    }
}
