import SwiftUI

@main
struct KagisecureiOSApp: App {
    @State private var model = AppModel(
        environment: .live(), platformKeys: SecureEnclaveKeyService())
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(AutoLock.key) private var autoLockSeconds = AutoLock.defaultSeconds
    @State private var backgroundedAt: Date?

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
                if autoLockSeconds <= 0 { model.lock() } else { backgroundedAt = Date() }
            case .active:
                if let since = backgroundedAt,
                    Date().timeIntervalSince(since) >= Double(autoLockSeconds)
                {
                    model.lock()
                }
                backgroundedAt = nil
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
}
