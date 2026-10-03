import AppKit
import Foundation
import Observation
import UserNotifications

import KagisecureFFI

/// The app's half of agent-requested browser fills that is not a sheet (ADR-0036 §2, §9;
/// implementation decisions 11, 12, 31–33): the feature switch, the blocks list and the notices.
///
/// # The switch
///
/// "Let agents ask to fill logins in your browser" is stored in `AppDefaults` and pushed to an
/// in-memory flag in Rust (`agentFillSetEnabled`), which starts **off** in every process. The app
/// pushes the stored value at launch (`AppModel.init`) and again on every unlock, before the agent
/// listener starts (`AppModel.adopt`). Since the amendment of 2026-10-03 the switch is **on by
/// default** and flipping it either way asks nothing.
///
/// # Notices
///
/// Rust queues a notice for what the human did not see happen — an origin mismatch, an agent over
/// its budget, an agent blocked by its second mismatch (implementation decision 33). They are
/// drained on `AgentService`'s one-second tick (`tick()`), kept in a short in-memory list for Agent
/// access, counted for the menu-bar badge, and announced with one
/// `NSApp.requestUserAttention(.informationalRequest)` per drain. Each also becomes a system
/// notification, but only if the user authorized them — which the app asks for when the switch is
/// turned on, never at launch. Every string is metadata: the agent's reported name, the item's
/// title and the origin. There is no value anywhere in a notice.
///
/// # Blocks
///
/// Blocks live in Rust's process-wide broker and survive a lock (ADR-0036 §9.3); this class only
/// mirrors `agentFillBlocks()` on the tick and lifts one with `agentFillUnblock(key:)`.
@MainActor
@Observable
final class AgentFillService {
    /// The `AppDefaults` key the switch is stored under.
    static let enabledKey = "agentFillEnabled"

    /// How many notices Agent access keeps. A short list: the audit log is the record.
    static let recentLimit = 5

    /// Whether agents may ask for fills — the switch, as stored and as pushed to Rust.
    private(set) var enabled = false

    /// A presence check for turning the switch on is up.
    private(set) var switching = false

    /// Why the last attempt to turn the switch on left it off. Cleared by the next attempt.
    private(set) var switchProblem: String?

    /// Every agent blocked from asking for fills right now, as Rust reports it.
    private(set) var blocks: [AgentFillBlockView] = []

    /// The most recent notices, newest first, at most `recentLimit`.
    private(set) var recent: [AgentFillNoticeRecord] = []

    /// Notices that arrived since Agent access was last looked at: the menu-bar badge.
    private(set) var unseen = 0

    let presence: PresenceCoordinator

    // MARK: - Seams
    //
    // Each FFI call and each system call goes through a replaceable closure so the unit tests can
    // drive this class without a broker, a Dock icon or a notification center. None of them adds a
    // path to anything: the switch still turns on only after `presence.authenticate` said so.

    /// `agentFillSetEnabled`, in the app.
    var pushEnabled: (Bool) -> Void = { agentFillSetEnabled(enabled: $0) }

    /// `agentFillTakeNotices`, in the app.
    var takeNotices: () -> [AgentFillNoticeView] = { agentFillTakeNotices() }

    /// `agentFillBlocks`, in the app.
    var fetchBlocks: () -> [AgentFillBlockView] = { agentFillBlocks() }

    /// `agentFillUnblock(key:)`, in the app.
    var unblocker: (String) -> Bool = { agentFillUnblock(key: $0) }

    /// Bounce the Dock icon once, informationally (not the critical bounce a waiting sheet gets).
    var requestAttention: @MainActor () -> Void = {
        _ = NSApp.requestUserAttention(.informationalRequest)
    }

    /// System notifications.
    var notifier: AgentFillNotifier

    private let defaults: UserDefaults
    private var nextNoticeId: UInt64 = 0

    init(
        presence: PresenceCoordinator,
        defaults: UserDefaults = AppDefaults.shared,
        notifier: AgentFillNotifier = SystemAgentFillNotifier()
    ) {
        self.presence = presence
        self.defaults = defaults
        self.notifier = notifier
        self.enabled = Self.stored(defaults)
    }

    /// The stored switch, on when nothing was ever stored.
    static func stored(_ defaults: UserDefaults) -> Bool {
        defaults.object(forKey: enabledKey) as? Bool ?? true
    }

    // MARK: - The switch

    /// Push the stored switch to Rust. Called at launch and on every unlock, before the agent
    /// listener starts, so the broker never serves a request under a flag the user did not set.
    func applyStoredSwitch() {
        enabled = Self.stored(defaults)
        pushEnabled(enabled)
    }

    /// The switch was flipped. Neither direction asks for a presence check any more.
    func setEnabled(_ on: Bool) async {
        guard on != enabled else { return }
        switchProblem = nil
        commit(on)
        if on {
            // Asked here and nowhere else: the first time a notice can matter is after this.
            await notifier.requestAuthorization()
        }
    }

    private func commit(_ on: Bool) {
        enabled = on
        defaults.set(on, forKey: Self.enabledKey)
        pushEnabled(on)
    }

    // MARK: - The tick

    /// Drain Rust's notice queue and re-read the blocks. Called once a second by `AgentService`.
    func tick(now: Date = .now) {
        let fresh = takeNotices()
        if !fresh.isEmpty {
            receive(fresh, at: now)
        }
        let current = fetchBlocks()
        if current != blocks {
            blocks = current
        }
    }

    /// File a batch of notices: into the list, onto the badge, one bounce, and — if authorized —
    /// one system notification each.
    private func receive(_ notices: [AgentFillNoticeView], at now: Date) {
        for notice in notices {
            nextNoticeId &+= 1
            recent.insert(
                AgentFillNoticeRecord(id: nextNoticeId, receivedAt: now, notice: notice), at: 0)
        }
        if recent.count > Self.recentLimit {
            recent.removeLast(recent.count - Self.recentLimit)
        }
        unseen += notices.count
        requestAttention()
        let texts = notices.map { (AgentFillText.title(for: $0), AgentFillText.body(for: $0)) }
        let notifier = notifier
        Task {
            for (title, body) in texts {
                await notifier.post(title: title, body: body)
            }
        }
    }

    /// Agent access is on screen: the badge has been seen.
    func markSeen() {
        unseen = 0
    }

    /// Empty the list of notices. The audit log still has every one.
    func clearNotices() {
        recent.removeAll()
        unseen = 0
    }

    /// The vault locked. The list names items, so it goes with the key, as every other view of
    /// the vault does; the blocks stay — they are Rust's, and they survive a lock on purpose.
    func vaultLocked() {
        recent.removeAll()
        unseen = 0
    }

    // MARK: - Blocks

    /// The Unblock button: lift the block on `block`'s key and re-read the list.
    func unblock(_ block: AgentFillBlockView) {
        _ = unblocker(block.key)
        blocks = fetchBlocks()
    }
}

/// One notice as the app keeps it: an id for the list, when it arrived, and what Rust said.
struct AgentFillNoticeRecord: Identifiable, Equatable {
    let id: UInt64
    let receivedAt: Date
    let notice: AgentFillNoticeView
}

/// How agent-fill notices and blocks are put into words (ADR-0036 §9.1, §9.4).
///
/// Every run that came from the agent or the vault goes through `ApprovalSheet.safe`, and the
/// agent's name is always quoted: it is what the agent reported, and nothing checked it.
@MainActor
enum AgentFillText {
    /// The agent's self-reported name out of an actor string as the audit log renders it
    /// (`mcp "<name>" [UNVERIFIED] pid N <exe>`, implementation decision 7), in the app's own
    /// quotation marks — or "An agent" when there is no name to quote.
    static func agentName(fromActor actor: String) -> String {
        var rest = Substring(actor)
        if rest.hasPrefix("mcp ") { rest = rest.dropFirst(4) }
        guard rest.first == "\"" else { return String(localized: "An agent") }
        var name = ""
        var escaped = false
        for character in rest.dropFirst() {
            if escaped {
                name.append(character)
                escaped = false
            } else if character == "\\" {
                escaped = true
            } else if character == "\"" {
                return quoted(name)
            } else {
                name.append(character)
            }
        }
        return String(localized: "An agent")
    }

    /// A self-reported name, sanitized and in quotation marks.
    static func quoted(_ name: String) -> String {
        "“\(ApprovalSheet.safe(name))”"
    }

    /// The origin, host first, as the sheet leads with it — and the browser's Unicode rendering
    /// beside it, never instead of it, when a label is `xn--`.
    static func site(_ origin: AgentOriginView) -> String {
        let parts = AgentFillSheetView.hostParts(origin)
        var site = parts.dimmed + parts.emphasized + parts.port
        if origin.notEncrypted { site = "http://" + site }
        if let unicode = origin.unicodeHost {
            let shown = ApprovalSheet.safe(unicode, limit: 253)
            site += " " + String(localized: "(shown by the browser as \(shown))")
        }
        return site
    }

    static func title(for notice: AgentFillNoticeView) -> String {
        switch notice {
        case .originMismatch: String(localized: "Agent fill refused: not a saved site")
        case .rateLimited: String(localized: "Agent fills paused")
        case .blocked: String(localized: "Agent blocked from fills")
        case .unmasked: String(localized: "Filled password was revealed")
        }
    }

    /// The sentence the notice says. ADR-0036 §9.4's wording for a mismatch, §9.1's for the budget.
    static func body(for notice: AgentFillNoticeView) -> String {
        switch notice {
        case .originMismatch(let agent, let itemTitle, let origin):
            String(localized: "\(agentName(fromActor: agent)) asked to fill “\(ApprovalSheet.safe(itemTitle))” on \(site(origin)), which is not a site saved for it. Nothing was filled.")
        case .rateLimited(let agent, _, let requests, let windowMinutes):
            String(localized: "\(agentName(fromActor: agent)) has asked to fill logins \(Int(requests)) times in \(Int(windowMinutes)) minutes; further requests are refused for \(Int(windowMinutes)) minutes.")
        case .blocked(let agent, _, .originMismatch):
            String(localized: "\(agentName(fromActor: agent)) asked twice for a site not saved for the login and is blocked from asking for fills until you unblock it in Agent access.")
        case .blocked(let agent, _, .deniedAndBlocked):
            // Rust never queues this one — Deny and block is the human's own act (implementation
            // decision 33) — but the switch is exhaustive, and the sentence stays true if it did.
            String(localized: "\(agentName(fromActor: agent)) is blocked from asking for fills for 30 minutes.")
        case .unmasked(let agent, let itemTitle, let origin):
            // ADR-0036 §8.3: the tripwire fired. Says what happened, truthfully, and no more —
            // this is a notice about what the human did not see, not a claim the agent read it.
            String(localized: "\(agentName(fromActor: agent)) filled a password from “\(ApprovalSheet.safe(itemTitle))” on \(site(origin)) and the page made it visible within seconds; kagisecure cleared the field. The agent may have read it.")
        }
    }

    /// Why a block in the list is there.
    static func reason(_ reason: AgentFillBlockReasonView) -> String {
        switch reason {
        case .deniedAndBlocked: String(localized: "You chose Deny and block")
        case .originMismatch: String(localized: "Asked twice for a site not saved for the login")
        }
    }

    /// "until 14:32", or "until you unblock it".
    static func until(_ until: UInt64?) -> String {
        guard let until else { return String(localized: "until you unblock it") }
        let date = Date(timeIntervalSince1970: TimeInterval(until))
        return String(localized: "until \(date.formatted(date: .omitted, time: .shortened))")
    }
}

/// System notifications for agent-fill notices.
@MainActor
protocol AgentFillNotifier: AnyObject {
    /// Ask the user whether this app may post notifications. Called when the switch is turned on.
    func requestAuthorization() async

    /// Post one notification — if, and only if, the user authorized them.
    func post(title: String, body: String) async
}

/// `UNUserNotificationCenter`, asked nothing until the switch is turned on.
@MainActor
final class SystemAgentFillNotifier: AgentFillNotifier {
    func requestAuthorization() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert])
    }

    func post(title: String, body: String) async {
        let center = UNUserNotificationCenter.current()
        let status = await center.notificationSettings().authorizationStatus
        guard status == .authorized || status == .provisional else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(
            identifier: "agent-fill-\(UUID().uuidString)", content: content, trigger: nil)
        try? await center.add(request)
    }
}
