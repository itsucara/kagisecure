import SwiftUI

/// “Check for Updates…” in the app menu, after “About Kagisecure”.
struct UpdateCommands: Commands {
    let updater: AppUpdater

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button("Check for Updates…") {
                updater.checkNow()
            }
            .disabled(!updater.isEnabled)
        }
    }
}
