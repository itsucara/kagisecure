import AppKit
import Foundation
import Observation

import KagisecureFFI

/// The app's half of the MCP approval flow (architecture.md §2.5 job 3, ui-spec.md §10).
///
/// # How this drives Rust without Rust driving it
///
/// `kagisecure-agent` runs the IPC listener on its own threads and *queues* approvals. Rust never
/// calls up into Swift (ADR-0001, architecture.md §4.1), so this class pulls: a detached task sits
/// in `agentNextRequest(timeoutMs:)`, which blocks in Rust for up to half a second and returns
/// either a question or nothing. Anything it gets is handed to the main actor, shown as a sheet,
/// and answered with `agentResolve`.
///
/// The same loop polls `agentTakeLockRequest()`, which is how `kagisecure lock` from a terminal
/// reaches an app that owns the vault: the library raises a flag, the app performs the lock, since
/// the app is what holds the `VaultSession`.
///
/// # Ordering
///
/// One question at a time. Requests arrive on `queue` and the head of it is `current`; a second
/// caller waits its turn rather than stacking sheets, and each waits out its own 60-second window
/// independently — a request that expires while queued is dropped here and has already been told
/// `APPROVAL_TIMEOUT` on the wire.
///
/// # Two ways to ask, one way to grant
///
/// A head request is asked in one of two ways. Most get the approval sheet (`sheetRequest`). A
/// browser fill whose exact scope the user already reviewed at a sheet in this unlock session
/// arrives `presenceOnly`, and gets no sheet: `confirmPresence` raises the LocalAuthentication
/// prompt directly, with a reason naming the item and the site, and a cancelled or unavailable
/// check denies it (ADR-0037).
///
/// An agent fill (ADR-0036) is always the full sheet — its own, `AgentFillSheetView` — and never
/// the presence prompt alone, whatever its `presenceOnly` flag says: Rust never sets it for one,
/// and this class would not honour it if it did (`needsSheet`).
///
/// Either way the grant goes through `allow(_:decision:)`, which is the **only** place in the app
/// that answers the queue with anything but a denial, and which does so only after
/// `gate.authenticate` returned `.authenticated` — or, for a fill, while a presence grace window
/// opened by such a check is still open (`PresenceGrace`, ADR-0037's amendments of 2026-09-27 and
/// 2026-10-03). That is the app's half of the invariant ADR-0037 states — every grant in the app
/// went through the gate since the last lock, within the user's grace setting — and the reason the
/// presence path calls `allow` rather than resolving on its own.
@MainActor
@Observable
final class AgentService {
    /// The listener's state, refreshed on the tick.
    private(set) var status: AgentStatusView = AgentStatusView(
        running: false, endpoint: "", pendingApprovals: 0, activeLeases: 0, vaultUnlocked: false)

    /// Approvals waiting for the user, oldest first. `first` is the one on screen.
    private(set) var queue: [ApprovalRequestView] = []

    /// The code-signature verdict for `queue.first`, computed once when it reaches the head.
    private(set) var currentSignature: PeerSignature?

    /// Every verdict computed so far, keyed by request id.
    ///
    /// The head's verdict alone is not enough: `allow(_:decision:)` parks in a biometric that can
    /// take seconds, and the head can change underneath it. The verdict that travels back into
    /// Rust has to be the one computed for *that* request, so it is looked up by id rather than
    /// read off whatever is current when the await returns.
    private var signatures: [String: PeerSignature] = [:]
    private var fillSignatures: [String: FillSignature] = [:]
    private var agentFillSignatures: [String: AgentFillSignature] = [:]

    /// Whatever app was frontmost when a fill request arrived (`enqueue`), so approving it can
    /// hand activation back before the grant reaches Rust.
    ///
    /// A real-browser test found the app staying in front of the browser after **Fill**: macOS
    /// treats a window behind another app's window as occluded, `document.visibilityState` never
    /// says "visible" while it is, and delivery fails outright — `NO_MATCHING_TAB` for an agent
    /// fill, `AGENT_FILL_NOT_DELIVERED` in the audit log. Keyed by request id, since more than one
    /// fill can be queued, each with its own browser in front when it arrived.
    private var frontmostBeforeFill: [String: FocusTarget] = [:]

    /// Where "whatever app is in front right now" comes from — real `NSWorkspace` in production,
    /// injected in `KagisecureTests` because `NSRunningApplication` has no public initializer a
    /// test could construct, and `NSWorkspace.shared` has no per-test isolation.
    var currentFrontmostApp: () -> FocusTarget? = { NSWorkspace.shared.frontmostApplication }

    /// Look up the running app behind a pid — `request.browserPid`, when the request names one —
    /// so a fill can activate **the browser it is going into** rather than whatever else happened
    /// to be frontmost. For an agent fill that is usually the agent's own app or a terminal, not
    /// the browser, so the captured frontmost app is only the fallback (`returnFocusBeforeDelivery`).
    /// Injected for the same reason `currentFrontmostApp` is.
    var runningApplication: (pid_t) -> FocusTarget? = { NSRunningApplication(processIdentifier: $0) }

    /// This app's own pid, so `returnFocusBeforeDelivery` can tell "the person was already in
    /// Kagisecure, there is nothing to hand back" from "hand it to this other, real app".
    var ownProcessIdentifier: () -> pid_t = { ProcessInfo.processInfo.processIdentifier }

    /// The fallback when the captured app refuses to activate — quit, or unable for some other
    /// reason. Gets Kagisecure's own window out of the way even when the browser never comes
    /// forward, which is at least half of what occluded it.
    var hideSelf: () -> Void = { NSApp.hide(nil) }

    /// For a browser-extension fill, the two verdicts the sheet shows: the native messaging host's
    /// and the browser's (M6). `nil` for every other kind of request.
    private(set) var currentFillSignature: FillSignature?

    /// For an agent fill, the verdicts its sheet shows: the agent's side (our sidecar and the
    /// program that started it) and the browser's (ADR-0036 §5). `nil` for every other request.
    private(set) var currentAgentFillSignature: AgentFillSignature?

    /// The browser-extension listener, ticked from this class's one-second loop so the two panes
    /// cannot disagree about what time it is.
    var extensionService: ExtensionService?

    /// Agent fills' notices and blocks (ADR-0036 implementation decision 11), drained on this
    /// class's one-second tick — the app's one clock.
    var agentFill: AgentFillService?

    /// Live leases, refreshed on the tick.
    private(set) var leases: [LeaseView] = []

    /// Why the listener could not start, if it could not. Shown in Agent access, verbatim: this
    /// is where "the CLI daemon already owns the socket" has to be legible (architecture.md §4.2).
    private(set) var startupError: String?

    /// The app's standard "Something went wrong" alert (`FfiErrorMessages`), for an action here
    /// that has no more specific place to put its failure — `revoke(_:)` today. Never carries a
    /// secret value, same as `VaultStore.errorMessage`, whose alert this mirrors.
    var errorMessage: String?

    /// Ticks once a second so countdowns and expiry are live without a timer in every view.
    private(set) var now: Date = .now

    /// The app-wide one-prompt-at-a-time slot (ADR-0037 §3, ADR-0038 §6), shared with the
    /// app's own reveal and copy releases (`AppPresenceGate`), so an approval's prompt and a
    /// reveal's prompt can never be on screen together.
    let presence: PresenceCoordinator

    /// The biometric gate — the coordinator's. Replaced by a test double in `KagisecureTests`.
    var gate: BiometricGate {
        get { presence.gate }
        set { presence.gate = newValue }
    }

    init(presence: PresenceCoordinator = PresenceCoordinator()) {
        self.presence = presence
        // A presence-only fill waiting at the head of the queue is raised the moment no other
        // prompt is up — including a reveal's, which it could not be raised beside.
        presence.addIdleObserver { [weak self] in self?.confirmPresenceIfNeeded() }
    }

    /// How an answer reaches Rust: `agentResolve`, always, in the app.
    ///
    /// Replaceable so a unit test can see *which* decision was sent for a request that no Rust
    /// queue is holding — "a cancelled presence prompt answered deny, and nothing else" is not
    /// observable from `agentResolve`'s `false` for an unknown id. It adds no path to a grant: the
    /// only caller that passes anything but `.deny` is still `allow`, after the gate.
    var resolver: (String, ApprovalDecision, ClientVerificationView) -> Bool = {
        agentResolve(requestId: $0, decision: $1, verification: $2)
    }

    /// Called when something asked the vault to lock over IPC.
    var onLockRequested: (() -> Void)?

    private let signer = PeerCodeSignature()
    private var pollTask: Task<Void, Never>?
    private var tickTask: Task<Void, Never>?

    /// Signalled by the poll loop when it has actually stopped.
    ///
    /// Since M6 the approval queue is a **process global**, shared with the browser-extension
    /// listener so that both raise the same sheet. That makes `stop()` needing to be synchronous a
    /// correctness problem rather than a tidiness one: `Task.cancel()` returns immediately, but the
    /// loop may already be parked inside `agentNextRequest`, and a loop that wakes up after this
    /// service has stopped would take a request off a queue that now belongs to somebody else and
    /// drop it on the floor. So `stop()` waits for the loop to be gone.
    private var pollStopped: DispatchSemaphore?

    /// The request at the head of the queue — the one being asked about right now, by a sheet or
    /// by a presence prompt.
    var current: ApprovalRequestView? { queue.first }

    /// The request the approval **sheet** shows, if the head needs one.
    ///
    /// `nil` while the head is a presence-only fill: that one is asked by `confirmPresence`, with
    /// the system's LocalAuthentication prompt and nothing in front of it.
    var sheetRequest: ApprovalRequestView? {
        guard let head = queue.first, Self.needsSheet(head), !skipsSheet(head) else { return nil }
        return head
    }

    /// Whether `request`, which would normally show a sheet, is granted without one because the
    /// grace window is open (ADR-0037 amendment of 2026-10-03): an agent fill — including a
    /// one-time code — unless the stricter `agentFillRequiresSheetKey` setting is on.
    func skipsSheet(_ request: ApprovalRequestView) -> Bool {
        guard request.action == .agentFill, !agentFillRequiresSheet() else { return false }
        return presenceGraceCovers(request)
    }

    /// The stricter setting: an agent fill always shows its sheet. Replaceable for tests.
    var agentFillRequiresSheet: () -> Bool = {
        AppDefaults.shared.bool(forKey: PresenceGrace.agentFillRequiresSheetKey)
    }

    /// Whether `request` is asked with a sheet rather than the presence prompt alone.
    ///
    /// Everything but a presence-only browser fill. An agent fill is a sheet even if it arrived
    /// flagged presence-only (ADR-0036 implementation decision 5): its sheet is the only place the
    /// person learns which site, which item and which agent, and a bare Touch ID prompt for it
    /// would be a fingerprint on a question nobody read.
    static func needsSheet(_ request: ApprovalRequestView) -> Bool {
        request.action == .agentFill || !request.presenceOnly
    }

    /// The presence prompt that is on screen, if one is.
    ///
    /// Set when the prompt is raised and cleared **only** when that prompt's own `authenticate`
    /// has returned — matched by `token`, never by whichever request happens to be at the head.
    /// In particular a lock does not clear it: the prompt it describes may still be on screen
    /// until the system finishes dismissing it, and clearing the flag early is what would let the
    /// next unlock raise a second prompt on top of the first, where one touch could be read as an
    /// answer to the prompt the person did not look at.
    private(set) var presencePrompt: PresencePrompt?

    /// One raised presence prompt: a serial that is never reused, and the request it is about.
    struct PresencePrompt: Equatable {
        let token: UInt64
        let requestId: String
    }

    /// The id of the presence-only request whose prompt is up.
    var presencePromptFor: String? { presencePrompt?.requestId }

    private var nextPresenceToken: UInt64 = 0

    /// Which unlock session the service is in. Bumped by every `stop()`.
    ///
    /// `allow` captures it before the biometric and refuses to resolve if it changed while the
    /// prompt was up: a touch that lands after a lock answers a request the lock already denied,
    /// and must not reach Rust as a grant in whatever session comes next.
    private(set) var lockGeneration: UInt64 = 0

    /// The app-wide grace window (`PresenceGrace`), held by the shared `PresenceCoordinator` so
    /// in-app releases and approvals open and ride the same one. Cleared by `stop()`.
    var presenceGrace: PresenceGrace { presence.grace }

    /// The clock the grace window is measured against — the coordinator's.
    var clock: () -> Date {
        get { presence.clock }
        set { presence.clock = newValue }
    }

    /// Whether `request`, if allowed now, would be granted without a new presence check — so the
    /// sheet can say so instead of promising a prompt that will not come.
    func presenceGraceCovers(_ request: ApprovalRequestView) -> Bool {
        PresenceGrace.applies(to: request) && presence.graceIsOpen
    }

    // MARK: - Lifecycle

    /// Bind the socket and start serving. Safe to call when already running.
    func start(session: VaultSession) {
        guard pollTask == nil else { return }
        startupError = nil
        do {
            _ = try agentStart(session: session, socketPath: Self.socketOverride())
        } catch {
            startupError = Self.message(for: error)
            status = agentStatus()
            return
        }
        status = agentStatus()
        let stopped = DispatchSemaphore(value: 0)
        pollStopped = stopped
        pollTask = Task.detached(priority: .utility) { [weak self] in
            defer { stopped.signal() }
            while !Task.isCancelled {
                // Blocks in Rust. `Self.pollTimeoutMs` is short enough that `stop()`'s wait is not
                // noticeable and long enough that this is not a spin.
                let request = agentNextRequest(timeoutMs: Self.pollTimeoutMs)
                let lockRequested = agentTakeLockRequest()
                if Task.isCancelled {
                    // Cancelled while parked. Anything taken off the queue in that window is
                    // answered rather than dropped: the vault is on its way to locked, and
                    // `USER_DENIED` is the truthful outcome for a request nobody will ever see.
                    if let request {
                        _ = agentResolve(
                            requestId: request.id,
                            decision: .deny,
                            verification: ClientVerificationView(
                                verified: false,
                                evidence: "the vault locked before the request reached a human"))
                    }
                    return
                }
                guard let self else { return }
                await self.received(request: request, lockRequested: lockRequested)
            }
        }
        tickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                self.tick()
            }
        }
    }

    /// Stop serving. Denies everything waiting and drops every lease.
    ///
    /// The app calls this *before* releasing the vault session, so the gap between "the user
    /// locked" and "the agent stopped" is not a gap at all.
    func stop() {
        pollTask?.cancel()
        pollTask = nil
        tickTask?.cancel()
        tickTask = nil
        // Wait for the loop to actually be gone — see `pollStopped`. Bounded, so a wedged Rust
        // call cannot hang a lock: the worst case is one poll interval plus a little, and locking
        // proceeds regardless.
        if let stopped = pollStopped {
            _ = stopped.wait(timeout: .now() + .milliseconds(Int(Self.pollTimeoutMs) * 3))
            pollStopped = nil
        }
        // Everything asked before this line belongs to the session that is ending. Bumped before
        // the prompts are torn down, so an `allow` that wakes up because of the teardown already
        // sees that its answer is stale.
        lockGeneration &+= 1
        presence.cancelInFlight()
        agentStop()
        queue.removeAll()
        signatures.removeAll()
        fillSignatures.removeAll()
        agentFillSignatures.removeAll()
        frontmostBeforeFill.removeAll()
        currentSignature = nil
        currentFillSignature = nil
        currentAgentFillSignature = nil
        // `presencePrompt` is deliberately left alone. The prompt it names was just invalidated,
        // but it is gone only when its `authenticate` returns, and `confirmPresence` clears the
        // flag then. Until that happens a quick unlock queues its presence-only fills rather than
        // raising a second prompt beside the first.
        leases.removeAll()
        // A lock — manual, idle, sleep or screen lock — ends every grace window: the next unlock
        // starts with every fill asking again.
        presence.clearGrace()
        status = agentStatus()
    }

    // MARK: - The loop

    private func received(request: ApprovalRequestView?, lockRequested: Bool) {
        if let request, enqueue(request) {
            NSApp.requestUserAttention(.criticalRequest)
        }
        if lockRequested {
            onLockRequested?()
        }
        status = agentStatus()
    }

    /// Put a request taken off the Rust queue at the back of this one, and ask about it if it is
    /// now the head.
    ///
    /// Internal rather than private so the unit tests can hand the service a request without a
    /// listener, a socket and a browser in front of it; everything after this point is the
    /// production path.
    ///
    /// Returns whether the request was queued for a human — always, today. An agent fill
    /// (ADR-0036) is queued like any other and asked with its own sheet (`needsSheet`).
    @discardableResult
    func enqueue(_ request: ApprovalRequestView) -> Bool {
        // Captured at arrival, not when the request reaches the head: a fill queued behind
        // another one still arrived with a real browser in front of it, and that is the app this
        // request's own approval should hand activation back to.
        if Self.returnsFocusOnApproval(request) {
            frontmostBeforeFill[request.id] = currentFrontmostApp()
        }
        queue.append(request)
        if queue.count == 1 {
            adoptSignature(for: request)
            confirmPresenceIfNeeded()
        }
        return true
    }

    /// Whether granting `request` should hand activation back to whatever was frontmost when it
    /// arrived, before the grant reaches Rust. Only a fill needs it: an agent fill or a
    /// browser-extension fill delivers into a browser tab that has to be visible to receive it,
    /// and Kagisecure's own window — raised for the sheet — is what would otherwise still be in
    /// front of it. Everything else grants no browser-facing thing that visibility could gate.
    static func returnsFocusOnApproval(_ request: ApprovalRequestView) -> Bool {
        request.action == .agentFill || request.action == .fillCredential
    }

    /// Hand activation back to the browser a fill is going into, so it lands on a visible tab (a
    /// real-browser test found the app staying in front otherwise). Called right before the grant
    /// reaches Rust: activation is asynchronous, and the tab has to have a chance at being visible
    /// by the time delivery gets there, not after.
    ///
    /// **The browser the request names, first.** `request.browserPid` is the browser the fill is
    /// actually delivered into; for an agent fill the app frontmost when the request arrived is
    /// usually the agent itself — Claude, a terminal — never the browser, so activating *that*
    /// would leave the tab exactly as covered as Kagisecure's own window did. The frontmost app
    /// captured at arrival (`frontmostBeforeFill`) is the fallback, for the case `browserPid` is
    /// absent or the lookup fails; `hideSelf` is the last resort, when neither names anything to
    /// activate, or the one found refuses.
    ///
    /// A no-op for anything `returnsFocusOnApproval` said no to.
    private func returnFocusBeforeDelivery(for request: ApprovalRequestView) {
        guard Self.returnsFocusOnApproval(request) else { return }
        let captured = frontmostBeforeFill.removeValue(forKey: request.id)
        let target =
            request.browserPid.flatMap { Int32(exactly: $0) }.flatMap(runningApplication) ?? captured
        guard let target else {
            hideSelf()
            return
        }
        guard target.processIdentifier != ownProcessIdentifier() else { return }
        if !target.activate(options: []) {
            // The chosen app quit, or refused for some other reason. Hiding Kagisecure at least
            // gets our own window out of the way, so occlusion is not this app's doing even if the
            // browser never comes forward on its own.
            hideSelf()
        }
    }

    private func tick() {
        now = .now
        status = agentStatus()
        leases = agentLeases()
        extensionService?.tick()
        agentFill?.tick(now: now)
        dropExpired()
        // A sheet that went up before the grace window opened (say, the person revealed a value
        // in the app meanwhile) is answered now.
        confirmPresenceIfNeeded()
    }

    /// Work out what to show about the caller of `request`, once, when it reaches the head.
    ///
    /// A Chromium fill names two processes — the native host that connected, and the browser above
    /// it — and both are checked. A Safari fill names one, our own app extension. Everything else
    /// names one.
    private func adoptSignature(for request: ApprovalRequestView) {
        // Computed once per request and then remembered: re-checking a pid that has since exited
        // would turn a verdict into a different verdict just because the head moved.
        if let cached = signatures[request.id] {
            currentSignature = cached
            currentFillSignature = fillSignatures[request.id]
            currentAgentFillSignature = agentFillSignatures[request.id]
            return
        }
        currentAgentFillSignature = nil
        if request.action == .agentFill, let facts = request.agentFill {
            // Two identity stories: the agent's (our sidecar, and the program the kernel says
            // started it) and the browser's, which is the fill sheet's pair. The single verdict
            // that travels into Rust is all of them together, weakest first.
            let agentFill = signer.checkAgentFill(facts)
            currentAgentFillSignature = agentFill
            agentFillSignatures[request.id] = agentFill
            currentFillSignature = agentFill.browser
            fillSignatures[request.id] = agentFill.browser
            currentSignature = PeerSignature(
                verified: agentFill.verified, evidence: agentFill.evidence)
        } else if request.action == .agentFill {
            // Rust always sends the facts with an agent fill. Without them the sheet has nothing
            // to name, and the verdict says exactly that.
            currentFillSignature = nil
            currentSignature = PeerSignature(
                verified: false, evidence: "the agent fill arrived without its facts")
        } else if request.action == .fillCredential {
            let fill = signer.checkFill(
                hostPid: request.clientPid, hostAuditToken: request.clientAuditToken,
                browserPid: request.browserPid,
                isAppExtension: request.browserIsAppExtension)
            currentFillSignature = fill
            fillSignatures[request.id] = fill
            // The single verdict that travels back into Rust with the decision is the *combined*
            // one: a lease and an audit entry that said "verified" because the browser was signed,
            // while our own helper was not, would be a record that flatters the weaker half.
            currentSignature = PeerSignature(
                verified: fill.verified,
                evidence: [fill.host.evidence, fill.browser?.evidence]
                    .compactMap { $0 }
                    .joined(separator: "; "))
        } else {
            currentFillSignature = nil
            currentSignature = signer.check(
                pid: request.clientPid, auditToken: request.clientAuditToken)
        }
        signatures[request.id] = currentSignature
    }

    /// Point `currentSignature`/`currentFillSignature` at whatever is now on screen.
    private func refreshHead() {
        currentSignature = nil
        currentFillSignature = nil
        currentAgentFillSignature = nil
        if let head = queue.first { adoptSignature(for: head) }
        confirmPresenceIfNeeded()
    }

    // MARK: - Presence prompts

    /// If the head is a presence-only fill and no prompt is up — this service's own, or any other
    /// in the app (`PresenceCoordinator`) — raise one. Otherwise it waits: the coordinator calls
    /// this again when its slot frees, and `confirmPresence` when this service's prompt ends.
    private func confirmPresenceIfNeeded() {
        // An agent fill is always the full sheet, whatever its flag says (ADR-0036 §5).
        guard presencePrompt == nil, let head = queue.first,
            !Self.needsSheet(head) || skipsSheet(head)
        else { return }
        // Taken here, synchronously, so nothing can raise a prompt between deciding to ask and
        // asking.
        guard let ticket = presence.begin(.approval(head.id)) else { return }
        nextPresenceToken &+= 1
        let prompt = PresencePrompt(token: nextPresenceToken, requestId: head.id)
        presencePrompt = prompt
        Task { await confirmPresence(head, prompt: prompt, ticket: ticket) }
    }

    /// Ask for Touch ID, the login password or an Apple Watch — and nothing else — for a fill the
    /// user already reviewed at a sheet in this unlock session (ADR-0037).
    ///
    /// Inside a presence grace window for this site and this item (`PresenceGrace`) nothing is
    /// asked at all: `allow` grants it without raising a prompt.
    ///
    /// Goes through `allow`, the one granting path, with **Allow once**: a presence confirmation
    /// re-proves that a person is there and never extends the review's memory (Rust clamps it to
    /// once regardless). Unlike the sheet, there is nothing to return to after a cancelled or
    /// unavailable check — no sheet was up — so either is a denial, answered at once rather than
    /// left to time out. A fumbled fingerprint costs the user one more click in the page; a prompt
    /// that lingered would be one an automation agent could wait out.
    ///
    /// If the vault locked while the prompt was up, the lock already denied the request and
    /// `allow` resolved nothing; there is nothing left to deny, only the flag to clear.
    private func confirmPresence(
        _ request: ApprovalRequestView, prompt: PresencePrompt, ticket: PresenceTicket
    ) async {
        let generation = lockGeneration
        let outcome = await allow(request, decision: .allowOnce, ticket: ticket)
        if outcome != .authenticated && lockGeneration == generation {
            deny(request)
        }
        if presencePrompt == prompt {
            presencePrompt = nil
        }
        // The head may have moved to another presence-only fill while this prompt was up;
        // `advance` could not raise it then, because this one was still open.
        confirmPresenceIfNeeded()
    }

    /// Retire anything whose 60-second window closed, answering it on the way out. The wire side
    /// has normally answered `APPROVAL_TIMEOUT` already; leaving the sheet up would invite an
    /// answer nobody is listening for.
    private func dropExpired() {
        let cutoff = UInt64(now.timeIntervalSince1970)
        let expired = queue.filter { $0.expiresAt <= cutoff }
        guard !expired.isEmpty else { return }
        for request in expired {
            // Answered, not merely dropped. The wire side has usually said `APPROVAL_TIMEOUT`
            // already and this second answer is a no-op there — but a request retired from the UI
            // while a biometric is parked on it would otherwise sit out its own window with
            // nobody watching, and "denied" is the truthful outcome for a question that expired.
            _ = resolver(
                request.id, .deny,
                ClientVerificationView(
                    verified: false,
                    evidence: "the request expired before it was answered"))
            forget(request.id)
        }
        queue.removeAll { $0.expiresAt <= cutoff }
        refreshHead()
    }

    private func forget(_ requestId: String) {
        signatures.removeValue(forKey: requestId)
        fillSignatures.removeValue(forKey: requestId)
        agentFillSignatures.removeValue(forKey: requestId)
        frontmostBeforeFill.removeValue(forKey: requestId)
    }

    // MARK: - Answering

    /// Deny the request on screen. No biometric: saying no is always allowed (ui-spec.md §10.3).
    func deny(_ request: ApprovalRequestView) {
        _ = resolver(request.id, .deny, verification(for: request))
        advance(resolved: request.id)
    }

    /// Deny the agent fill on screen **and** block the agent that asked for thirty minutes
    /// (ADR-0036 §9.3, implementation decision 31). A denial: no biometric, like `deny`.
    ///
    /// Rust keys the block on the program the kernel says started the sidecar, never on the name
    /// the agent reported. On any request but an agent fill it is a plain `.deny` — the button
    /// only exists on the agent-fill sheet, and Rust would treat it as one anyway.
    func denyAndBlock(_ request: ApprovalRequestView) {
        let decision: ApprovalDecision = request.action == .agentFill ? .denyAndBlock : .deny
        _ = resolver(request.id, decision, verification(for: request))
        advance(resolved: request.id)
        // The new block shows in Agent access now rather than on the next tick.
        agentFill?.tick(now: now)
    }

    /// Allow, after a successful biometric — or, for a fill, inside the grace window one opened.
    ///
    /// **The only place in the app that sends Rust anything but a denial**, and it does so only
    /// after `gate.authenticate` returned `.authenticated` — the app's half of ADR-0037's
    /// invariant. The sheet's Allow buttons and `confirmPresence` both come through here.
    ///
    /// The one exception is the app-wide presence grace window (ADR-0037, amendment of
    /// 2026-10-03): while it is open any fill is granted without asking again, reported
    /// `.authenticated`, and the use extends the window. Any successful check opens it.
    ///
    /// Returns the outcome so the caller can keep the sheet up on a cancellation — a fumbled
    /// fingerprint is not a policy decision (ui-spec.md §10.3). `.busy` if another presence prompt
    /// is on screen anywhere in the app: nothing is asked and nothing is sent, and the sheet
    /// stays up to be answered once that prompt has gone.
    ///
    /// An agent fill's sheet comes through here too. It mints no lease (ADR-0036 §5, §6), but since
    /// the grace window it can ride an earlier touch for the same site, like any other fill. Its
    /// decision is **Allow once** whatever the caller passed — Rust clamps it the same way.
    @discardableResult
    func allow(_ request: ApprovalRequestView, decision: ApprovalDecision) async -> BiometricOutcome
    {
        guard let ticket = presence.begin(.approval(request.id)) else { return .busy }
        // Only an allow is clamped to once for an agent fill. A denial — `.deny`, or the agent-fill
        // sheet's `.denyAndBlock` (ADR-0036 §9.3) — needs no biometric and belongs in `deny`, but
        // one that arrives here anyway stays a denial rather than becoming an allow.
        let decision: ApprovalDecision =
            switch decision {
            case .allowOnce, .allowSession: request.action == .agentFill ? .allowOnce : decision
            case .deny, .denyAndBlock: decision
            }
        return await allow(request, decision: decision, ticket: ticket)
    }

    /// `allow`, in a prompt slot already taken — by the sheet's `allow` just above, or by
    /// `confirmPresenceIfNeeded` for a presence-only fill.
    private func allow(
        _ request: ApprovalRequestView, decision: ApprovalDecision, ticket: PresenceTicket
    ) async -> BiometricOutcome {
        // Captured *before* the await. `dropExpired()` runs on the tick and can retire this
        // request — and re-adopt a signature for a different one — while the biometric is open,
        // so a verdict read after the await could describe somebody else entirely.
        let captured = verification(for: request)
        if PresenceGrace.applies(to: request) && presence.rideGrace() {
            // Inside the grace window: no prompt. Nothing is awaited, so no lock can land in
            // between. Resolved before the slot is given up, so the idle observer that runs when
            // it frees sees the queue as it is after this answer, not before.
            returnFocusBeforeDelivery(for: request)
            _ = resolver(request.id, decision, captured)
            advance(resolved: request.id)
            presence.end(ticket)
            return .authenticated
        }
        let generation = lockGeneration
        let outcome = await presence.authenticate(ticket, reason: Self.reason(for: request))
        // A lock while the prompt was up: the request was denied by the lock, and a touch that
        // landed anyway is an answer to a question that no longer exists. Reported as a
        // cancellation, and nothing is sent.
        guard lockGeneration == generation else { return .cancelled }
        guard outcome == .authenticated else { return outcome }
        // A real check opens (or extends) the app-wide grace window.
        presence.touchGrace()
        returnFocusBeforeDelivery(for: request)
        _ = resolver(request.id, decision, captured)
        advance(resolved: request.id)
        return outcome
    }

    /// The verdict to record with the decision, so the lease and the audit entry say what was
    /// actually established about the caller rather than what the sheet happened to show.
    private func verification(for request: ApprovalRequestView) -> ClientVerificationView {
        guard let signature = signatures[request.id] else {
            return ClientVerificationView(verified: false, evidence: "code signature not checked")
        }
        return ClientVerificationView(
            verified: signature.verified, evidence: signature.evidence)
    }

    /// Retire the request that was actually resolved.
    ///
    /// By id, and a no-op when it is no longer queued: removing `queue.first` unconditionally
    /// would take a request nobody has seen off the sheet while it is still pending in Rust.
    private func advance(resolved requestId: String) {
        queue.removeAll { $0.id == requestId }
        forget(requestId)
        refreshHead()
        status = agentStatus()
        leases = agentLeases()
        extensionService?.tick()
    }

    // MARK: - Leases

    func revoke(_ lease: LeaseView) {
        // `try?` here used to swallow a thrown `FfiError` outright: the person presses "Revoke",
        // sees the row disappear from `leases` on the next tick regardless, and has no way to
        // learn a failure ever happened. Route it through the same alert every other model uses
        // instead (`FfiErrorMessages`, `VaultStore.errorMessage`'s pattern).
        do {
            _ = try agentRevokeLease(leaseId: lease.id)
        } catch {
            errorMessage = Self.message(for: error)
        }
        leases = agentLeases()
        status = agentStatus()
    }

    func revokeAll() {
        agentRevokeAllLeases()
        leases = agentLeases()
        status = agentStatus()
    }

    // MARK: - Helpers

    /// How long each `agentNextRequest` parks in Rust.
    ///
    /// Also the unit `stop()` bounds its wait by, which is why it is a named constant rather than
    /// a literal in two places.
    nonisolated static let pollTimeoutMs: UInt32 = 250

    /// The sentence above the Touch ID sheet. Names the action and the caller, never a value.
    static func reason(for request: ApprovalRequestView) -> String {
        switch request.action {
        case .writeEnvFile:
            request.variables.count == 1
                ? String(localized: "approve writing \(request.variables.count) variable to a .env file")
                : String(localized: "approve writing \(request.variables.count) variables to a .env file")
        case .runWithEnv:
            String(localized: "approve running \(ApprovalSheet.safe(request.command.first ?? String(localized: "a command"))) with secrets in its environment")
        case .createEnvironment:
            String(localized: "approve creating an environment")
        case .addVariables:
            String(localized: "approve adding variables to an environment")
        case .fillCredential:
            // Names the item and the origin, never a value — the same rule the sheet follows,
            // including its sanitization: this string is attacker-influenced too, and the Touch ID
            // prompt is no place for a bidi override.
            request.presenceOnly
                ? presenceReason(for: request)
                : String(localized: "fill \(ApprovalSheet.safe(request.itemTitle ?? String(localized: "a login"))) into \(ApprovalSheet.safe(request.origin ?? String(localized: "this page"), limit: 120))")
        case .agentFill:
            agentFillReason(for: request)
        }
    }

    /// The sentence above an agent fill's Touch ID prompt (ADR-0036 §5, §7.3, §7.4).
    ///
    /// The sheet is behind it, but the prompt is what the finger answers, so it restates the
    /// things that matter in the order the sheet leads with them — the site, the item, and what
    /// kind of request this is — and when to refuse. The agent's name is not in it: it is the one
    /// thing on the sheet the agent chose. Three kinds, distinguished so the finger is never given
    /// for a broader thing than the sheet showed: a plain sign-in, the first page of a two-page
    /// sign-in (the password follows without asking again), and a one-time code (never the
    /// password).
    static func agentFillReason(for request: ApprovalRequestView) -> String {
        let site = ApprovalSheet.safe(
            request.agentFill?.pageOrigin.ascii ?? request.origin ?? String(localized: "a page"), limit: 120)
        let title = ApprovalSheet.safe(request.agentFill?.itemTitle ?? request.itemTitle ?? String(localized: "a login"))
        if request.agentFill?.fields == [.oneTimeCode] {
            return String(localized: "let an agent fill the one-time code for “\(title)” into \(site). Continue only if you asked an agent to sign in there")
        }
        if request.agentFill?.twoStep == true {
            return String(localized: "let an agent sign in to \(site) with “\(title)” — the username now, the password on the next page without asking again. Continue only if you asked an agent to sign in there")
        }
        return String(localized: "let an agent fill “\(title)” into \(site). Continue only if you asked an agent to sign in there")
    }

    /// The sentence above a presence-only prompt, which has no sheet in front of it.
    ///
    /// This prompt can appear with the user looking at something else entirely — that is the
    /// case ADR-0037 exists for: an automation agent clicked the icon, and this prompt is the only
    /// thing between it and the value. So the sentence has three jobs: say which item, say which
    /// site, and tell the person that touching the sensor for a request they did not make is how
    /// the value would leak. A one-time code is named as one, because it gets its own prompt.
    static func presenceReason(for request: ApprovalRequestView) -> String {
        let title = ApprovalSheet.safe(request.itemTitle ?? String(localized: "a login"))
        let origin = ApprovalSheet.safe(request.origin ?? String(localized: "this page"), limit: 120)
        return request.fillFields == ["one-time password"]
            ? String(localized: "fill the one-time code for “\(title)” into \(origin). Continue only if you just asked Kagisecure to fill this")
            : String(localized: "fill “\(title)” into \(origin). Continue only if you just asked Kagisecure to fill this")
    }

    /// `KAGISECURE_SOCKET` moves the listener, which is how a second vault — or a test — runs
    /// without touching the user's own (architecture.md §4.2).
    private static func socketOverride() -> String? {
        ProcessInfo.processInfo.environment["KAGISECURE_SOCKET"]
    }

    private static func message(for error: Error) -> String {
        describeAnyError(error)
    }
}

/// What `AgentService.returnFocusBeforeDelivery` hands activation back to.
///
/// `NSRunningApplication` in production, conforming for free below; a recorder in
/// `KagisecureTests`, because the real type has no public initializer a test could construct and
/// `NSWorkspace.shared.frontmostApplication` has no per-test isolation.
protocol FocusTarget {
    var processIdentifier: pid_t { get }

    /// Bring this app frontmost. `NSRunningApplication.activate(options:)` already returns
    /// whether it worked; a test double reports whatever the scenario calls for. Not the
    /// options-free `activate()` macOS 14 added: a default-valued parameter is still a real
    /// parameter, and `NSRunningApplication`'s witness for a truly zero-argument requirement is
    /// not guaranteed across SDKs the way this one, stable since 10.9, is.
    @discardableResult
    func activate(options: NSApplication.ActivationOptions) -> Bool
}

extension NSRunningApplication: FocusTarget {}

