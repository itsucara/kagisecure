import AppKit
import Foundation
import Observation

import KagisecureFFI

/// The app's half of agent test logins (ADR-0048) that is not a sheet: the Settings switch, the
/// allowed-domains list and the passive notice.
///
/// # The switch and the domains
///
/// The policy lives inside the encrypted vault (ADR-0048 §1), not in app defaults, so this class
/// keeps no copy of it beyond `settings`, a read of `agentTestLoginSettings()`. Turning the switch
/// **on** and **adding** an allowed domain each ask for presence first (`PresenceOwner.featureSwitch`,
/// the unattended switch's precedent) and only then call Rust. Turning it off and removing a domain
/// narrow what agents may do, so they ask nothing.
///
/// # The notice
///
/// Rust queues one notice per create. They are drained on `AgentService`'s one-second tick, become
/// a system notification each (if the person authorized them; the request is made when the switch
/// is turned on, never at launch) and are counted for the menu-bar entry "N test logins created by
/// agents". The notice asks nothing of the person. Every string is metadata: the agent's reported
/// name in quotation marks, the item's title and the host. There is no value anywhere in it.
@MainActor
@Observable
final class TestLoginService {
    /// The switch and the allowed domains, as the vault holds them. Never set while locked.
    private(set) var settings = AgentTestLoginSettingsView(enabled: false, autoDomains: [], vaultId: nil)

    /// Test logins created by agents since the vault was unlocked: the menu-bar count.
    private(set) var createdCount = 0

    /// A presence check is up.
    private(set) var confirming = false

    /// Why the last change did not happen. Cleared by the next attempt.
    private(set) var problem: String?

    let presence: PresenceCoordinator

    // MARK: - Seams

    /// `agentTestLoginSettings()`. Defaults to "nothing" until a session is attached.
    var fetchSettings: () -> AgentTestLoginSettingsView = {
        AgentTestLoginSettingsView(enabled: false, autoDomains: [], vaultId: nil)
    }

    /// `setAgentTestLogins(enabled:)`.
    var pushEnabled: (Bool) throws -> Void = { _ in throw TestLoginServiceError.locked }

    /// `addAgentTestLoginDomain(domain:)`, returning the normalised domain.
    var addDomain: (String) throws -> String = { _ in throw TestLoginServiceError.locked }

    /// `removeAgentTestLoginDomain(domain:)`.
    var removeDomain: (String) throws -> Bool = { _ in throw TestLoginServiceError.locked }

    /// `testLoginsTakeNotices()`.
    var takeNotices: () -> [TestLoginNoticeView] = { testLoginsTakeNotices() }

    /// System notifications, the same sender agent fills use.
    var notifier: AgentFillNotifier

    init(presence: PresenceCoordinator, notifier: AgentFillNotifier = SystemAgentFillNotifier()) {
        self.presence = presence
        self.notifier = notifier
    }

    // MARK: - Session

    /// Point the seams at the unlocked vault and read its policy.
    func attach(_ session: VaultSession) {
        fetchSettings = { session.agentTestLoginSettings() }
        pushEnabled = { try session.setAgentTestLogins(enabled: $0) }
        addDomain = { try session.addAgentTestLoginDomain(domain: $0) }
        removeDomain = { try session.removeAgentTestLoginDomain(domain: $0) }
        refresh()
    }

    /// The vault locked: the policy and the count go with the key.
    func vaultLocked() {
        fetchSettings = { AgentTestLoginSettingsView(enabled: false, autoDomains: [], vaultId: nil) }
        pushEnabled = { _ in throw TestLoginServiceError.locked }
        addDomain = { _ in throw TestLoginServiceError.locked }
        removeDomain = { _ in throw TestLoginServiceError.locked }
        settings = fetchSettings()
        createdCount = 0
        problem = nil
    }

    func refresh() {
        settings = fetchSettings()
    }

    // MARK: - The switch

    /// The switch was flipped. On asks for presence first and then creates the vault (Rust);
    /// off asks nothing.
    func setEnabled(_ on: Bool) async {
        guard on != settings.enabled else { return }
        problem = nil
        if on {
            guard await confirm(Self.enableReason) else { return }
            // Asked here and nowhere else: the first notice can only follow this.
            await notifier.requestAuthorization()
        }
        do {
            try pushEnabled(on)
        } catch {
            problem = describeAnyError(error)
        }
        refresh()
    }

    static let enableReason = String(localized: "let agents create test logins")

    // MARK: - The allowed domains

    /// Add a domain agents may create test logins for without a sheet. Presence every time.
    @discardableResult
    func add(domain: String) async -> Bool {
        problem = nil
        let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        guard await confirm(Self.addReason(trimmed)) else { return false }
        var added = true
        do {
            _ = try addDomain(trimmed)
        } catch {
            problem = describeAnyError(error)
            added = false
        }
        refresh()
        return added
    }

    /// Remove an allowed domain. Narrows what agents may do, so it asks nothing.
    func remove(domain: String) {
        problem = nil
        do {
            _ = try removeDomain(domain)
        } catch {
            problem = describeAnyError(error)
        }
        refresh()
    }

    static func addReason(_ domain: String) -> String {
        String(localized: "let agents create test logins for \(ApprovalSheet.safe(domain, limit: 100)) without asking")
    }

    // MARK: - The tick

    /// Drain Rust's notice queue. Called once a second by `AgentService`.
    func tick() {
        let fresh = takeNotices()
        guard !fresh.isEmpty else { return }
        createdCount += fresh.count
        let texts = fresh.map { (Self.notificationTitle, Self.body(for: $0)) }
        let notifier = notifier
        Task {
            for (title, body) in texts {
                await notifier.post(title: title, body: body)
            }
        }
    }

    /// The menu-bar entry was used: the count has been seen.
    func acknowledge() {
        createdCount = 0
    }

    // MARK: - Words

    static let notificationTitle = String(localized: "Agent test login created")

    /// "“Claude Code” created test login “test: shop / buyer #1” for localhost:47800".
    static func body(for notice: TestLoginNoticeView) -> String {
        switch notice {
        case .created(let agent, let title, _, let websites):
            let who = AgentFillText.agentName(fromActor: agent)
            let item = ApprovalSheet.safe(title, limit: 120)
            let host = websites.first.map(hostText) ?? String(localized: "a site")
            return String(localized: "\(who) created test login “\(item)” for \(host)")
        }
    }

    /// `http://localhost:47800/x` → `localhost:47800`; anything unparseable, sanitised as it is.
    static func hostText(_ website: String) -> String {
        if let components = URLComponents(string: website), let host = components.host {
            let port = components.port.map { ":\($0)" } ?? ""
            return ApprovalSheet.safe(host + port, limit: 120)
        }
        return ApprovalSheet.safe(website, limit: 120)
    }

    /// The menu-bar entry's title.
    static func menuTitle(count: Int) -> String {
        count == 1
            ? String(localized: "1 test login created by agents")
            : String(localized: "\(count) test logins created by agents")
    }

    // MARK: - Presence

    private func confirm(_ reason: String) async -> Bool {
        guard let ticket = presence.begin(.featureSwitch) else {
            problem = String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
            return false
        }
        confirming = true
        let generation = presence.cancelGeneration
        let outcome = await presence.authenticate(ticket, reason: reason)
        confirming = false
        guard presence.cancelGeneration == generation else {
            problem = String(localized: "The vault locked before you confirmed. Nothing changed.")
            return false
        }
        switch outcome {
        case .authenticated:
            return true
        case .cancelled:
            problem = String(localized: "Authentication cancelled. Nothing changed.")
        case .unavailable(let why):
            problem = String(localized: "Could not ask for authentication: \(why). Nothing changed.")
        case .busy:
            problem = String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
        }
        return false
    }
}

enum TestLoginServiceError: Error, LocalizedError {
    case locked
    var errorDescription: String? { String(localized: "The vault is locked.") }
}
