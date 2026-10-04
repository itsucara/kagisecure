import AppKit
import AuthenticationServices
import SwiftUI

import KagisecureFFI

// MARK: - Panes

/// The Settings window's panes, in sidebar order (ui-spec.md §17).
///
/// Everything a person *chooses* lives here. Screens that show live state they work with — leases,
/// the audit log, unattended jobs, environments, the browser-extension installer — stay in the main
/// window, and the pane that owns their topic links to them.
enum SettingsPane: String, CaseIterable, Identifiable {
    case general
    case security
    case autofill
    case agents
    case vault
    case updates
    case about

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .general: "General"
        case .security: "Security & Unlock"
        case .autofill: "AutoFill"
        case .agents: "AI Agents"
        case .vault: "Vault"
        case .updates: "Updates"
        case .about: "About"
        }
    }

    var subtitle: LocalizedStringKey {
        switch self {
        case .general: "Quick Access, the clipboard and language."
        case .security: "Touch ID, how long one confirmation lasts, and auto-lock."
        case .autofill: "Fill passwords in Safari, Chrome and other apps."
        case .agents: "Let AI agents use your logins without seeing them."
        case .vault: "Where your vault lives, and bringing items in."
        case .updates: "Keep Kagisecure up to date."
        case .about: "Version, licence and source code."
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape.fill"
        case .security: "touchid"
        case .autofill: "key.fill"
        case .agents: "sparkles"
        case .vault: "externaldrive.fill"
        case .updates: "arrow.triangle.2.circlepath"
        case .about: "info.circle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .general: .gray
        case .security: .red
        case .autofill: .blue
        case .agents: .purple
        case .vault: .orange
        case .updates: .green
        case .about: .indigo
        }
    }

    /// The sidebar groups: what the app does day to day, then housekeeping.
    static let groups: [[SettingsPane]] = [
        [.general, .security, .autofill, .agents],
        [.vault, .updates, .about],
    ]

    static let storageKey = "settings.selectedPane"
}

// MARK: - Window

/// Settings (⌘,): a System Settings–style window, a sidebar of colored icon tiles and a grouped
/// form per pane.
struct SettingsView: View {
    @AppStorage(SettingsPane.storageKey, store: AppDefaults.shared)
    private var storedPane = SettingsPane.general.rawValue
    /// Set by the snapshot test, which renders one pane at a time without touching preferences.
    var fixedPane: SettingsPane?

    private var selection: Binding<SettingsPane?> {
        Binding(
            get: { fixedPane ?? SettingsPane(rawValue: storedPane) ?? .general },
            set: { storedPane = ($0 ?? .general).rawValue })
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 230, ideal: 250, max: 320)
            .toolbar(removing: .sidebarToggle)
        } detail: {
            detail(selection.wrappedValue ?? .general)
                .navigationTitle(selection.wrappedValue?.title ?? "General")
        }
        .frame(minWidth: 760, idealWidth: 800, minHeight: 520, idealHeight: 600)
    }

    @ViewBuilder
    private var sidebar: some View {
        if let fixedPane {
            // The snapshot test's stand-in: `cacheDisplay` cannot draw a sidebar `List` (its rows
            // are vibrant layers it skips), so the same rows are drawn as plain views.
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(SettingsPane.groups.enumerated()), id: \.offset) { index, group in
                    if index > 0 { Spacer().frame(height: 14) }
                    ForEach(group) { pane in
                        SettingsSidebarRow(pane: pane)
                            .foregroundStyle(Color(nsColor: .labelColor))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                pane == fixedPane ? AnyShapeStyle(.selection) : AnyShapeStyle(.clear),
                                in: RoundedRectangle(cornerRadius: 6))
                    }
                }
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.top, 52)
            .frame(width: 250)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor))
            .ignoresSafeArea()
        } else {
            List(selection: selection) {
                ForEach(Array(SettingsPane.groups.enumerated()), id: \.offset) { _, group in
                    Section {
                        ForEach(group) { pane in
                            SettingsSidebarRow(pane: pane)
                                .tag(pane)
                                .accessibilityIdentifier("ks.settings.pane.\(pane.rawValue)")
                        }
                    }
                }
            }
            .listStyle(.sidebar)
        }
    }

    @ViewBuilder
    private func detail(_ pane: SettingsPane) -> some View {
        switch pane {
        case .general: GeneralSettings()
        case .security: SecuritySettings()
        case .autofill: AutoFillSettings()
        case .agents: AgentSettings()
        case .vault: VaultSettings()
        case .updates: UpdatesSettings()
        case .about: AboutSettings()
        }
    }
}

// MARK: - Building blocks

/// One sidebar row: a small icon tile and the pane's name.
struct SettingsSidebarRow: View {
    let pane: SettingsPane

    var body: some View {
        Label {
            Text(pane.title)
        } icon: {
            SettingsIconTile(symbol: pane.symbol, tint: pane.tint, size: 22)
        }
    }
}

/// A white SF Symbol on a colored rounded square, the way System Settings draws its panes.
struct SettingsIconTile: View {
    let symbol: String
    let tint: Color
    var size: CGFloat = 22

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.55, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .shadow(color: .black.opacity(0.12), radius: 0.5, y: 0.5)
            .accessibilityHidden(true)
    }
}

/// The large tile, title and one-line summary at the top of every pane.
struct SettingsPaneHeader: View {
    let pane: SettingsPane

    var body: some View {
        Section {
            HStack(spacing: 14) {
                SettingsIconTile(symbol: pane.symbol, tint: pane.tint, size: 44)
                VStack(alignment: .leading, spacing: 3) {
                    Text(pane.title)
                        .font(.title2.weight(.semibold))
                    Text(pane.subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 4)
        }
    }
}

/// A small capsule that says what state something is in.
struct StatusBadge: View {
    enum Tone: Equatable {
        case on, off, warning, neutral

        var color: Color {
            switch self {
            case .on: .green
            case .off: .secondary
            case .warning: .orange
            case .neutral: .blue
            }
        }
    }

    let text: LocalizedStringKey
    let tone: Tone

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(tone.color).frame(width: 6, height: 6)
            Text(text)
        }
        .font(.caption.weight(.medium))
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(tone.color.opacity(0.14), in: Capsule())
        .foregroundStyle(tone == .off ? Color.secondary : Color.primary)
    }
}

/// A footnote under a group of rows.
private struct Caption: View {
    let text: LocalizedStringKey
    init(_ text: LocalizedStringKey) { self.text = text }

    var body: some View {
        Text(text)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A row that opens a screen in the main window.
private struct MainWindowLink: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    let title: LocalizedStringKey
    let symbol: String
    let selection: SidebarSelection
    var badge: Int = 0

    var body: some View {
        Button {
            openWindow(id: "main")
            model.show(selection)
        } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                if badge > 0 {
                    Text("\(badge)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Image(systemName: "arrow.up.forward.app")
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(model.store == nil)
    }
}

/// "Unlock the vault to change this", shown where a setting needs an open vault.
private struct LockedNote: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.store == nil {
            Label("Unlock the vault to change these.", systemImage: "lock.fill")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - General

private struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(PasteboardService.clearSecondsKey, store: AppDefaults.shared)
    private var clearSeconds = PasteboardService.defaultClearSeconds

    var body: some View {
        Form {
            SettingsPaneHeader(pane: .general)

            Section {
                if let error = model.quickAccess.hotKeyError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.settings.quickAccessError")
                } else {
                    LabeledContent("Shortcut") {
                        KeyCaps(keys: ["⇧", "⌘", "Space"])
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel("Shift Command Space")
                            .accessibilityIdentifier("ks.settings.quickAccessShortcut")
                    }
                }
            } header: {
                Text("Quick Access")
            } footer: {
                Caption(
                    "Search and copy from anywhere. No Accessibility or Input Monitoring permission is needed: the system only tells Kagisecure the shortcut was pressed."
                )
            }

            Section {
                Picker("Clear the clipboard after", selection: $clearSeconds) {
                    ForEach(PasteboardService.clearSecondsChoices, id: \.self) { seconds in
                        Text(PasteboardService.clearIntervalDescription(seconds: seconds))
                            .tag(seconds)
                    }
                }
                .accessibilityIdentifier("ks.settings.clipboardInterval")
            } header: {
                Text("Clipboard")
            } footer: {
                Caption(
                    "Applies to every copy. Only Kagisecure's own copy is removed — anything you copied since is left alone."
                )
            }

            Section {
                Picker("Appearance", selection: $appearanceRaw) {
                    // Plain text rows: a `Label` (title + symbol) inside a menu-style picker gave
                    // the popup button a label that SwiftUI resolved through the popup's own role,
                    // which asked for the label again — an accessibility client reading General
                    // recursed until the stack overflowed (0.1.4 crash, 2026-10-04).
                    ForEach(AppAppearance.allCases) { choice in
                        Text(choice.title).tag(choice.rawValue)
                    }
                }
                .accessibilityIdentifier("ks.settings.appearance")
                .onChange(of: appearanceRaw) { _, raw in
                    AppAppearance.choice(from: raw).apply()
                }

                Picker("Language", selection: $language) {
                    Text("System default").tag(String?.none)
                    ForEach(AppLanguage.available(), id: \.self) { code in
                        Text(verbatim: AppLanguage.nativeName(of: code)).tag(String?.some(code))
                    }
                }
                .accessibilityIdentifier("ks.settings.language")
                .onChange(of: language) { _, code in
                    AppLanguage.store(code)
                }

                if language != launchLanguage {
                    HStack {
                        Label("Restart Kagisecure to apply the new language.", systemImage: "arrow.clockwise")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Relaunch") { AppLanguage.relaunch(model: model) }
                            .accessibilityIdentifier("ks.settings.relaunch")
                    }
                    // `.contain` keeps the Relaunch button's own identifier; without it the
                    // container's identifier is stamped onto every child.
                    .accessibilityElement(children: .contain)
                    .accessibilityIdentifier("ks.settings.relaunchNotice")
                }
            } header: {
                Text("Language & Appearance")
            } footer: {
                HStack(alignment: .firstTextBaseline) {
                    Caption("A new language applies after a relaunch, which locks the vault first.")
                    Spacer()
                    Button("Language & Region…") {
                        SystemSettingsLink.open(SystemSettingsLink.languageAndRegion)
                    }
                    .buttonStyle(.link)
                    .font(.footnote)
                }
            }
        }
        .formStyle(.grouped)
    }

    @AppStorage(AppAppearance.defaultsKey, store: AppDefaults.shared)
    private var appearanceRaw = AppAppearance.system.rawValue
    @State private var language: String? = AppLanguage.stored()
    /// The override this process launched with: the notice shows only when the choice differs.
    @State private var launchLanguage: String? = GeneralSettings.languageAtLaunch
    private static let languageAtLaunch = AppLanguage.stored()
}

/// ⇧ ⌘ Space as keyboard keys.
private struct KeyCaps: View {
    let keys: [String]

    var body: some View {
        HStack(spacing: 3) {
            ForEach(keys, id: \.self) { key in
                Text(key)
                    .font(.callout.weight(.medium))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .frame(minWidth: 22)
                    .background(
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .fill(.background)
                            .shadow(color: .black.opacity(0.18), radius: 0, y: 1)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 5, style: .continuous)
                            .strokeBorder(.separator)
                    )
            }
        }
    }
}

// MARK: - Security & Unlock

private struct SecuritySettings: View {
    @Environment(AppModel.self) private var model
    // `store:` rather than the implicit `.standard`, so that a UI-test run writes into its own
    // throwaway suite instead of the real user's preferences. See `AppDefaults`.
    @AppStorage(AutoLockCoordinator.idleMinutesKey, store: AppDefaults.shared)
    private var idleMinutes = AutoLockCoordinator.defaultIdleMinutes
    @AppStorage(PresenceGrace.durationKey, store: AppDefaults.shared)
    private var graceDuration = PresenceGrace.defaultDuration.rawValue
    @AppStorage(PresenceGrace.agentFillRequiresSheetKey, store: AppDefaults.shared)
    private var agentFillRequiresSheet = false
    @AppStorage(CredentialProviderService.requiresConfirmationKey, store: AppDefaults.shared)
    private var nativeAutofillRequiresConfirmation = false
    @State private var showAdvanced = false

    var body: some View {
        Form {
            SettingsPaneHeader(pane: .security)

            Section {
                touchID
            } header: {
                Text("Touch ID")
            }

            Section {
                Picker("Don't ask again for", selection: $graceDuration) {
                    ForEach(PresenceGrace.Duration.allCases) { duration in
                        Text(duration.label).tag(duration.rawValue)
                    }
                }
                .accessibilityIdentifier("ks.settings.graceDuration")
            } header: {
                Text("Confirmation")
            } footer: {
                Caption(
                    "Confirm once with Touch ID or your login password, and reveals, copies, browser fills, AutoFill and agent fills go through without asking again. Each use extends the period; locking the vault always ends it."
                )
            }

            Section {
                Picker("Lock when idle for", selection: $idleMinutes) {
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("10 minutes").tag(10)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                    Text("Never").tag(0)
                }
                .accessibilityIdentifier("ks.settings.autoLockInterval")
            } header: {
                Text("Auto-lock")
            } footer: {
                Caption("The vault always locks when the Mac sleeps, the screen locks, or you quit.")
            }

            Section {
                DisclosureGroup(isExpanded: $showAdvanced) {
                    Toggle(isOn: $agentFillRequiresSheet) {
                        Text("Always show the sheet for agent fills")
                        Text("Every agent fill waits for you, even inside the confirmation period.")
                    }
                    .accessibilityIdentifier("ks.settings.agentFillRequiresSheet")
                    Toggle(isOn: $nativeAutofillRequiresConfirmation) {
                        Text("Always show the AutoFill sheet in other apps")
                        Text("Every password AutoFill puts into another app asks first.")
                    }
                    .accessibilityIdentifier("ks.settings.nativeAutofillRequiresConfirmation")
                } label: {
                    HStack {
                        Text("Stricter confirmation")
                        Spacer()
                        StatusBadge(
                            text: strictCount == 0 ? "Off" : "\(strictCount) on",
                            tone: strictCount == 0 ? .off : .warning)
                    }
                }
                .accessibilityIdentifier("ks.settings.advanced")
            } header: {
                Text("Advanced")
            } footer: {
                Caption("Off by default. Turn these on when you want a sheet every time, not just once.")
            }
        }
        .formStyle(.grouped)
    }

    private var strictCount: Int {
        (agentFillRequiresSheet ? 1 : 0) + (nativeAutofillRequiresConfirmation ? 1 : 0)
    }

    @ViewBuilder
    private var touchID: some View {
        switch model.platformAvailability {
        case .available:
            Toggle(
                isOn: Binding(
                    get: { model.hasPlatformSlot },
                    set: { $0 ? model.enrollTouchID() : model.disableTouchID() })
            ) {
                Text("Unlock with Touch ID")
                Text(
                    "Your vault key is wrapped by a key in this Mac's Secure Enclave. Changing your fingerprints asks for the master password once more."
                )
            }
            .disabled(model.store == nil)
            .accessibilityIdentifier("ks.settings.touchIdToggle")
            LockedNote()
        case .unavailable(let why):
            Label("Touch ID is unavailable: \(why)", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.settings.touchIdUnavailable")
        case .unknown:
            ProgressView()
        }
    }
}

// MARK: - AutoFill

private struct AutoFillSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(CredentialProviderService.requiresConfirmationKey, store: AppDefaults.shared)
    private var nativeAutofillRequiresConfirmation = false
    @State private var nativeEnabled: Bool?

    var body: some View {
        let ext = model.browserExtension.status
        Form {
            SettingsPaneHeader(pane: .autofill)

            Section {
                LabeledContent {
                    StatusBadge.forNativeAutoFill(nativeEnabled)
                        .accessibilityIdentifier("ks.settings.nativeAutofillState")
                } label: {
                    Label("Passwords AutoFill", systemImage: "rectangle.and.pencil.and.ellipsis")
                }
                LabeledContent("Ask before each fill") {
                    Toggle("", isOn: $nativeAutofillRequiresConfirmation)
                        .labelsHidden()
                        .toggleStyle(.switch)
                        .controlSize(.small)
                }
                HStack {
                    Spacer()
                    Button("Open AutoFill Settings…") {
                        SystemSettingsLink.open(SystemSettingsLink.autoFill)
                    }
                    .accessibilityIdentifier("ks.settings.openAutoFillSettings")
                }
            } header: {
                Text("Safari and other apps")
            } footer: {
                Caption(
                    "Turn on Kagisecure under General › AutoFill & Passwords in System Settings, and its logins appear in every password field on this Mac."
                )
            }

            Section {
                LabeledContent {
                    StatusBadge.forBrowserExtension(ext)
                        .accessibilityIdentifier("ks.settings.browserExtensionState")
                } label: {
                    Label("Browser extension", systemImage: "puzzlepiece.extension")
                }
                MainWindowLink(
                    title: "Set up the browser extension…", symbol: "wrench.and.screwdriver",
                    selection: .browserExtension, badge: Int(ext.fillLeases))
            } header: {
                Text("Chrome, Edge, Brave, Firefox")
            } footer: {
                Caption(
                    "The extension shows matching logins on the page. Setup installs a small helper the browser talks to; it stores nothing in the browser."
                )
            }
            BrowsersOnThisMacSection()
        }
        .formStyle(.grouped)
        .task { await refreshNative() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await refreshNative() }
        }
    }

    private func refreshNative() async {
        nativeEnabled = await IdentityStoreCalls.isEnabled()
    }
}

/// Settings › AutoFill › Browsers on this Mac: each browser's connection, and whether the
/// "Connect your browsers" sheet may ask about it (ui-spec.md §6.5, §17).
private struct BrowsersOnThisMacSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let prompt = model.browserPrompt
        let installed = prompt.browsers.filter(\.installed)
        Section {
            if installed.isEmpty {
                Text("No supported browsers found.")
                    .foregroundStyle(.secondary)
            }
            ForEach(installed) { browser in
                HStack(spacing: 10) {
                    BrowserIcon(url: browser.appURL, size: 22)
                    Text(browser.name)
                    Spacer()
                    if browser.connected {
                        StatusBadge(text: "Connected", tone: .on)
                    } else {
                        StatusBadge(text: "Not connected", tone: .off)
                        Toggle("Ask to connect", isOn: Binding(
                            get: { prompt.asksToConnect(browser.id) },
                            set: { prompt.allowPrompt(for: browser.id, $0) }))
                            .toggleStyle(.checkbox)
                            .accessibilityIdentifier("ks.settings.browserPrompt.ask.\(browser.id)")
                    }
                }
                .accessibilityIdentifier("ks.settings.browserRow.\(browser.id)")
            }
            if !prompt.silenced.isEmpty {
                HStack {
                    Spacer()
                    Button("Reset “Don't Ask Again”") { prompt.resetAll() }
                        .accessibilityIdentifier("ks.settings.browserPrompt.reset")
                }
            }
        } header: {
            Text("Browsers on this Mac")
        } footer: {
            Caption(
                "After you unlock, Kagisecure offers to connect browsers that are not connected yet — at most once a launch, and not again for a week after “Later”."
            )
        }
        .task { await prompt.refresh() }
    }
}

extension StatusBadge {
    /// `nil` while the system has not answered yet.
    static func forNativeAutoFill(_ enabled: Bool?) -> StatusBadge {
        switch enabled {
        case .some(true): StatusBadge(text: "On", tone: .on)
        case .some(false): StatusBadge(text: "Off", tone: .off)
        case .none: StatusBadge(text: "Checking…", tone: .neutral)
        }
    }

    static func forBrowserExtension(_ status: ExtensionStatusView) -> StatusBadge {
        let state = SettingsStatus.browserExtension(status)
        switch state {
        case .connected(let browsers): return StatusBadge(text: "\(browsers) connected", tone: .on)
        case .ready: return StatusBadge(text: "Waiting for a browser", tone: .neutral)
        case .locked: return StatusBadge(text: "Vault locked", tone: .off)
        }
    }

    static func forAgents(_ status: AgentStatusView) -> StatusBadge {
        switch SettingsStatus.agentListener(status) {
        case .waiting(let n): StatusBadge(text: "\(n) waiting", tone: .warning)
        case .listening: StatusBadge(text: "Listening", tone: .on)
        case .stopped: StatusBadge(text: "Stopped", tone: .off)
        }
    }
}

/// Status summaries the panes show as badges, kept free of SwiftUI so they can be tested.
enum SettingsStatus {
    enum BrowserExtension: Equatable {
        case connected(Int)
        case ready
        case locked
    }

    static func browserExtension(_ status: ExtensionStatusView) -> BrowserExtension {
        guard status.running || status.safariRunning else { return .locked }
        return status.connectedHosts > 0 ? .connected(Int(status.connectedHosts)) : .ready
    }

    enum AgentListener: Equatable {
        case waiting(Int)
        case listening
        case stopped
    }

    static func agentListener(_ status: AgentStatusView) -> AgentListener {
        guard status.running else { return .stopped }
        return status.pendingApprovals > 0 ? .waiting(Int(status.pendingApprovals)) : .listening
    }
}

/// Deep links into System Settings.
enum SystemSettingsLink {
    static let autoFill = URL(string: "x-apple.systempreferences:com.apple.Passwords-Settings.extension")!
    static let languageAndRegion = URL(string: "x-apple.systempreferences:com.apple.Localization-Settings.extension")!

    @MainActor
    static func open(_ url: URL) {
        NSWorkspace.shared.open(url)
    }
}

// MARK: - AI Agents

private struct AgentSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage(PresenceGrace.agentFillRequiresSheetKey, store: AppDefaults.shared)
    private var agentFillRequiresSheet = false
    /// Mirrors the vault's "Show new items to agents" so the switch redraws at once; the vault is
    /// the source of truth and is re-read on appear.
    @State private var showNewItems = true
    @State private var confirmShowAll = false
    @State private var showAllResult: String?

    var body: some View {
        let agentFill = model.agentFill
        let status = model.agent.status
        Form {
            SettingsPaneHeader(pane: .agents)

            Section {
                LabeledContent {
                    StatusBadge.forAgents(status)
                        .accessibilityIdentifier("ks.settings.agentListenerState")
                } label: {
                    Label("Agent connection (MCP)", systemImage: "point.3.connected.trianglepath.dotted")
                }
                MainWindowLink(title: "Set up your agent…", symbol: "sparkles", selection: .agentSetup)
            } header: {
                Text("Connection")
            } footer: {
                Caption(
                    "Claude Code, Codex and other MCP clients connect while the vault is unlocked. Setup shows the one line to add."
                )
            }

            Section {
                HStack {
                    Toggle(
                        isOn: Binding(
                            get: { agentFill.enabled },
                            set: { on in Task { await agentFill.setEnabled(on) } })
                    ) {
                        Text("Let agents fill logins in your browser")
                        Text("The agent never receives the password; Kagisecure types it into the page.")
                    }
                    .disabled(agentFill.switching)
                    .accessibilityIdentifier("ks.settings.agentFillSwitch")
                    if agentFill.switching {
                        ProgressView().controlSize(.small)
                    }
                }
                if let problem = agentFill.switchProblem {
                    Text(problem)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Toggle(isOn: $agentFillRequiresSheet) {
                    Text("Always show the sheet for agent fills")
                    Text("Stricter: ignore the confirmation period for agents.")
                }
            } header: {
                Text("Agent fills")
            } footer: {
                Caption(
                    "An agent that can run script in that page could still read what was typed. Blocked agents and recent notices are in Environments."
                )
            }

            if let store = model.store {
                Section {
                    Toggle(isOn: $showNewItems) {
                        Text("Show new items to agents")
                        Text("Agents see titles, categories, tags and field names, never values.")
                    }
                    .onChange(of: showNewItems) { _, on in
                        if on != store.newItemsAgentVisible { store.setNewItemsAgentVisible(on) }
                    }
                    .accessibilityIdentifier("ks.settings.newItemsAgentVisible")
                    LabeledContent {
                        Button("Show All Items to Agents…") { confirmShowAll = true }
                            .accessibilityIdentifier("ks.settings.showAllToAgents")
                    } label: {
                        Text(showAllResult ?? String(localized: "Existing items"))
                            .accessibilityIdentifier("ks.settings.showAllResult")
                    }
                } header: {
                    Text("Item visibility")
                } footer: {
                    Caption(
                        "New and imported items start visible to agents, with all their fields. Each value still needs your approval."
                    )
                }
                .onAppear { showNewItems = store.newItemsAgentVisible }
                .confirmationDialog("Show every item to agents?", isPresented: $confirmShowAll) {
                    Button("Show All Items") {
                        store.attempt {
                            let result = try store.setAgentVisible(scope: .all, true)
                            showAllResult = String(localized: "\(Int(result.changed)) items now shown")
                        }
                    }
                } message: {
                    Text(
                        "Every item not in the Trash becomes visible to agents, with all its fields. You can hide items again from the item list or the sidebar."
                    )
                }
            }

            Section {
                MainWindowLink(
                    title: "Environments and agent fills", symbol: "list.bullet.rectangle",
                    selection: .agentEnvironments, badge: agentFill.unseen)
                MainWindowLink(
                    title: "Leases", symbol: "clock.badge.checkmark", selection: .agentLeases,
                    badge: Int(status.activeLeases))
                MainWindowLink(
                    title: "Unattended jobs", symbol: "moon.zzz", selection: .agentUnattended,
                    badge: model.unattended.attention)
                MainWindowLink(title: "Audit log", symbol: "list.bullet.rectangle.portrait", selection: .agentAudit)
                LockedNote()
            } header: {
                Text("Activity")
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Vault

private struct VaultSettings: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Form {
            SettingsPaneHeader(pane: .vault)

            Section {
                LabeledContent {
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: model.vaultPath)])
                    }
                } label: {
                    Text("Vault file")
                    Text((model.vaultPath as NSString).abbreviatingWithTildeInPath)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(model.vaultPath)
                        .accessibilityIdentifier("ks.settings.vaultPath")
                }
                LabeledContent("State") {
                    StatusBadge(
                        text: model.store == nil ? "Locked" : "Unlocked",
                        tone: model.store == nil ? .off : .on)
                }
            } header: {
                Text("Location")
            } footer: {
                Caption(
                    "One encrypted file. Time Machine and other backups copy it like any other file; it is useless without your master password."
                )
            }

            Section {
                LabeledContent("Import") {
                    Button("Import from a File…") {
                        openWindow(id: "main")
                        NSApp.activate()
                        model.openImport()
                    }
                    .disabled(model.store == nil)
                }
                LockedNote()
            } header: {
                Text("Bring items in")
            } footer: {
                Caption("1Password (.1pux), Apple Passwords, Chrome and other CSV exports. You see a preview before anything is saved.")
            }

            Section {
                LabeledContent("Audit log") {
                    Text(model.store.map(Self.auditStateText) ?? String(localized: "Locked"))
                        .accessibilityIdentifier("ks.settings.auditState")
                }
                LabeledContent("Word list") {
                    Text("EFF long list — \(generatorLimits().wordlistSize) words")
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.settings.wordlist")
                }
            } header: {
                Text("Details")
            }
        }
        .formStyle(.grouped)
    }

    /// "Chain intact", or "Chain intact — N unsaved" when a save has been failing
    /// (`VaultStore.auditUnsavedEntries`, `ks.audit.saveState` in `AuditView` has the full
    /// message with the failure reason). Reads `session` directly rather than the store's cached
    /// `auditIntact`/`auditUnsavedEntries`, matching this row's existing behaviour of asking Rust
    /// fresh every time Settings renders rather than waiting for the Audit tab to have been
    /// opened at least once.
    private static func auditStateText(_ store: VaultStore) -> String {
        let chain =
            store.session.auditIntact() ? String(localized: "Chain intact") : String(localized: "Chain broken")
        let unsaved = store.session.auditDurability().unsavedEntries
        guard unsaved > 0 else { return chain }
        return String(localized: "\(chain) — \(unsaved) unsaved")
    }
}

// MARK: - About

private struct AboutSettings: View {
    var body: some View {
        Form {
            Section {
                VStack(spacing: 8) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 96, height: 96)
                    Text("Kagisecure")
                        .font(.title.weight(.semibold))
                    Text("Version \(AboutInfo.version) (\(AboutInfo.build))")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("ks.settings.version")
                    Text("An open-source password manager for people and their AI agents.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
            }

            Section {
                Link(destination: AboutInfo.website) {
                    Label("kagisecure.com", systemImage: "globe")
                }
                Link(destination: AboutInfo.source) {
                    Label("Source code on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                Link(destination: AboutInfo.issues) {
                    Label("Report a problem", systemImage: "exclamationmark.bubble")
                }
            } header: {
                Text("Links")
            }

            Section {
                LabeledContent("Licence", value: "MIT or Apache-2.0")
            } footer: {
                Caption("Free and open source. Your vault never leaves this Mac unless you put it somewhere.")
            }
        }
        .formStyle(.grouped)
    }
}

enum AboutInfo {
    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "–"
    }
    static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "–"
    }
    static let website = URL(string: "https://kagisecure.com")!
    static let source = URL(string: "https://github.com/itsucara/kagisecure")!
    static let issues = URL(string: "https://github.com/itsucara/kagisecure/issues")!
}
