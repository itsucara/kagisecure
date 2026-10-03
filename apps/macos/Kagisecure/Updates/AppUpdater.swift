import AppKit
import Observation
import OSLog
import Sparkle

/// Keeps the app on the latest release with Sparkle 2 (EdDSA-signed archives and a signed feed
/// from `https://kagisecure.com/mac/appcast.xml`; ADR-0044).
///
/// At launch it checks at once; an update found then is downloaded and installed straight away,
/// and the app relaunches into it while a small panel says “Updating Kagisecure…”. The vault is
/// locked at launch anyway, so the relaunch costs nothing it had. While the app runs it checks
/// every hour (`SUScheduledCheckInterval`); an update found then is downloaded in the background,
/// installed when the app quits, and the panel offers to relaunch now. Builds without a feed URL
/// (every build but `cargo xtask dist`'s) never update themselves.
@MainActor
@Observable
final class AppUpdater: NSObject, SPUUpdaterDelegate {
    private(set) var isEnabled = false
    /// Whether Sparkle looks for an update by itself. It is Sparkle's own setting, which it keeps.
    var automaticallyChecks = false {
        didSet { updater?.automaticallyChecksForUpdates = automaticallyChecks }
    }
    private(set) var lastCheck: Date?

    @ObservationIgnored private var updater: SPUUpdater?
    @ObservationIgnored private let userDriver = SPUStandardUserDriver(hostBundle: .main, delegate: nil)
    @ObservationIgnored private let indicator = UpdateIndicator()
    /// True from launch until the launch check ends: an update it finds is installed right away.
    @ObservationIgnored private var launchCheckPending = true

    private static let log = Logger(subsystem: "com.kagisecure.app", category: "update")

    func start() {
        guard updater == nil else { return }
        guard let feed = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String, !feed.isEmpty,
            let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String, !key.isEmpty
        else {
            Self.log.info("updates are off for this build")
            return
        }
        let updater = SPUUpdater(hostBundle: .main, applicationBundle: .main, userDriver: userDriver, delegate: self)
        do {
            try updater.start()
        } catch {
            Self.log.error("the updater could not start: \(error.localizedDescription, privacy: .public)")
            return
        }
        self.updater = updater
        isEnabled = true
        automaticallyChecks = updater.automaticallyChecksForUpdates
        lastCheck = updater.lastUpdateCheckDate
        // Someone who turned automatic checks off has asked to look for updates only by hand,
        // at launch too.
        if updater.automaticallyChecksForUpdates {
            Self.log.info("checking for an update at launch")
            updater.checkForUpdatesInBackground()
        } else {
            launchCheckPending = false
        }
    }

    /// “Check for Updates…” and Settings ▸ Updates: Sparkle's own window.
    func checkNow() {
        Self.log.info("update check by hand")
        updater?.checkForUpdates()
    }

    // MARK: SPUUpdaterDelegate
    //
    // Sparkle calls these on the main thread, and its Swift interface says so (the same shape as
    // itsustar's updater, which builds under the same strict-concurrency settings).

    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        Self.log.info("update found: \(item.displayVersionString, privacy: .public)")
        if launchCheckPending {
            indicator.showInstalling()
        }
    }

    func updater(_ updater: SPUUpdater, failedToDownloadUpdate item: SUAppcastItem, error: any Error) {
        Self.log.error("update download failed: \(error.localizedDescription, privacy: .public)")
        indicator.hide()
    }

    /// Taking control of the install: at launch it happens now; later it waits for the person or
    /// for quitting, which Sparkle installs on either way.
    func updater(
        _ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem,
        immediateInstallationBlock immediateInstallHandler: @escaping () -> Void
    ) -> Bool {
        if launchCheckPending {
            Self.log.info("installing the update and relaunching")
            immediateInstallHandler()
        } else {
            Self.log.info("update ready; installs on quit")
            indicator.showReady(relaunch: {
                Self.log.info("relaunching to update")
                immediateInstallHandler()
            })
        }
        return true
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: any Error) {
        let nsError = error as NSError
        if !(nsError.domain == SUSparkleErrorDomain && nsError.code == Int(SUError.noUpdateError.rawValue)) {
            Self.log.error("update check failed: \(error.localizedDescription, privacy: .public)")
        }
        indicator.hide()
    }

    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: (any Error)?) {
        launchCheckPending = false
        lastCheck = updater.lastUpdateCheckDate
    }
}
