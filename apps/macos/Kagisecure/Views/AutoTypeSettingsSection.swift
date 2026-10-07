import SwiftUI

/// Settings ▸ Auto-type (ADR-0050 §4): the Accessibility permission auto-type needs, why, and the
/// switch that lets agents ask for it.
struct AutoTypeSettingsSection: View {
    @AppStorage(AutoTypeService.agentsEnabledKey, store: AppDefaults.shared)
    private var agentsEnabled = true
    @State private var trusted = AutoTypeService.shared.isTrusted

    var body: some View {
        Section {
            HStack {
                Label {
                    Text(trusted ? "Accessibility permission granted" : "Accessibility permission needed")
                } icon: {
                    Image(systemName: trusted ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(trusted ? .green : .orange)
                }
                Spacer()
                if !trusted {
                    Button("Open System Settings…") {
                        AutoTypeService.shared.requestPermission()
                    }
                    .accessibilityIdentifier("ks.settings.autoType.grant")
                }
            }
            Toggle(isOn: $agentsEnabled) {
                Text("Let agents ask kagisecure to type logins")
                Text("Each request rides the confirmation period like an agent fill; outside it you approve with Touch ID.")
            }
            .onChange(of: agentsEnabled) { AutoTypeService.shared.syncReadiness() }
            .accessibilityIdentifier("ks.settings.autoType.agents")
        } header: {
            Text("Auto-type")
        } footer: {
            Caption(
                "kagisecure types a login as keystrokes into the field focused in another app, for apps its browser extension cannot reach. macOS requires the Accessibility permission for that. The app you type into receives the value."
            )
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            trusted = AutoTypeService.shared.isTrusted
            AutoTypeService.shared.syncReadiness()
        }
    }
}
