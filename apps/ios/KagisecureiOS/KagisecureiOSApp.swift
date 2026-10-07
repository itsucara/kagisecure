import SwiftUI

@main
struct KagisecureiOSApp: App {
    @State private var model = AppModel(
        environment: .live(), platformKeys: SecureEnclaveKeyService())
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(AutoLock.key) private var autoLockSeconds = AutoLock.defaultSeconds
    /// When the app went to the background, on a clock that keeps counting while the phone sleeps
    /// and that changing the time in Settings cannot wind back.
    @State private var backgroundedAt: ContinuousClock.Instant?

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                // Hide content in the app switcher snapshot: anything but .active is covered.
                .overlay {
                    if scenePhase != .active { PrivacyCover() }
                }
        }
        .onChange(of: scenePhase) { _, phase in
            // Lock after the chosen time away (Settings → Auto-Lock). "Immediately" locks the
            // moment the app leaves the foreground; otherwise leaving briefly — to copy the six
            // words, to pick a folder in Files — keeps it open.
            switch phase {
            case .background:
                model.store?.link.stopWatching()
                if autoLockSeconds <= 0 { model.lock() } else { backgroundedAt = ContinuousClock.now }
            case .active:
                if let since = backgroundedAt,
                    AutoLock.shouldLock(away: ContinuousClock.now - since, seconds: autoLockSeconds)
                {
                    model.lock()
                }
                backgroundedAt = nil
                if let link = model.store?.link {
                    link.startWatching()
                    Task { await link.syncOnForeground() }
                }
            default:
                break
            }
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
        .accessibilityIdentifier("privacyCover")
    }
}

struct RootView: View {
    @Bindable var model: AppModel

    var body: some View {
        switch model.phase {
        case .setup: SetupView(model: model)
        case .recoveryCode(let code): RecoveryCodeView(code: code) { model.acknowledgeRecoveryCode() }
        case .locked: LockView(model: model)
        case .unlocked:
            if let store = model.store {
                ItemListView(model: model, store: store)
            } else {
                LockView(model: model)
            }
        }
    }
}

/// How long the app may stay in the background before it locks.
enum AutoLock {
    static let key = "autoLockSeconds"
    static let defaultSeconds = 300
    static let choices: [(label: String, seconds: Int)] = [
        (String(localized: "Immediately"), 0), (String(localized: "1 minute"), 60),
        (String(localized: "5 minutes"), 300), (String(localized: "15 minutes"), 900),
    ]

    /// Whether being away for `away` passes the chosen limit. A negative or unknown setting
    /// counts as "Immediately".
    static func shouldLock(away: Duration, seconds: Int) -> Bool {
        seconds <= 0 || away >= .seconds(seconds)
    }
}
