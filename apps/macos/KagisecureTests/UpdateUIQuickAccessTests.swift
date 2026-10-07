import Sparkle
import XCTest

@testable import Kagisecure

@MainActor
final class UpdateUIQuickAccessTests: XCTestCase {
    func testSparkleAlertDismissesQuickAccess() {
        let updater = AppUpdater()
        var calls = 0
        updater.onWillPresentUpdateUI = { calls += 1 }
        updater.standardUserDriverWillShowModalAlert()
        XCTAssertEqual(calls, 1)
    }

    func testManualCheckDismissesQuickAccess() {
        let updater = AppUpdater()
        var calls = 0
        updater.onWillPresentUpdateUI = { calls += 1 }
        updater.checkNow()
        XCTAssertEqual(calls, 1)
    }
}
