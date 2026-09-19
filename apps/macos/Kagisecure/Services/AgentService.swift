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
/// One sheet at a time. Requests arrive on `queue` and the head of it is `current`; a second
/// caller waits its turn rather than stacking sheets, and each waits out its own 60-second window
/// independently — a request that expires while queued is dropped here and has already been told
/// `APPROVAL_TIMEOUT` on the wire.
@MainActor
@Observable
final class AgentService {
    /// The listener's state, refreshed on the tick.
    private(set) var status: AgentStatusView = AgentStatusView(
        running: false, endpoint: "", pendingApprovals: 0, activeLeases: 0, vaultUnlocked: false)

    /// Approvals waiting for the user, oldest first. `first` is the one on screen.
    private(set) var queue: [ApprovalRequestView] = []

    /// The code-signature verdict for `queue.first`, computed once when it arrives.
    private(set) var currentSignature: PeerSignature?

    /// For a browser-extension fill, the two verdicts the sheet shows: the native messaging host's
    /// and the browser's (M6). `nil` for every other kind of request.
    private(set) var currentFillSignature: FillSignature?

    /// The browser-extension listener, ticked from this class's one-second loop so the two panes
    /// cannot disagree about what time it is.
    var extensionService: ExtensionService?

    /// Live leases, refreshed on the tick.
    private(set) var leases: [LeaseView] = []

    /// Why the listener could not start, if it could not. Shown in Agent access, verbatim: this
    /// is where "the CLI daemon already owns the socket" has to be legible (architecture.md §4.2).
    private(set) var startupError: String?

    /// Ticks once a second so countdowns and expiry are live without a timer in every view.
    private(set) var now: Date = .now

    /// The biometric gate. Replaced by a test double in `KagisecureTests`.
    var gate: BiometricGate = LocalAuthenticationGate()

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

    /// The request currently on screen, if any.
    var current: ApprovalRequestView? { queue.first }

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
        agentStop()
        queue.removeAll()
        currentSignature = nil
        currentFillSignature = nil
        leases.removeAll()
        status = agentStatus()
    }

    // MARK: - The loop

    private func received(request: ApprovalRequestView?, lockRequested: Bool) {
        if let request {
            queue.append(request)
            if queue.count == 1 {
                adoptSignature(for: request)
            }
            NSApp.requestUserAttention(.criticalRequest)
        }
        if lockRequested {
            onLockRequested?()
        }
        status = agentStatus()
    }

    private func tick() {
        now = .now
        status = agentStatus()
        leases = agentLeases()
        extensionService?.tick()
        dropExpired()
    }

    /// Work out what to show about the caller of `request`, once, when it reaches the head.
    ///
    /// A Chromium fill names two processes — the native host that connected, and the browser above
    /// it — and both are checked. A Safari fill names one, our own app extension. Everything else
    /// names one.
    private func adoptSignature(for request: ApprovalRequestView) {
        if request.action == .fillCredential {
            let fill = signer.checkFill(
                hostPid: request.clientPid, browserPid: request.browserPid,
                isAppExtension: request.browserIsAppExtension)
            currentFillSignature = fill
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
            currentSignature = signer.check(pid: request.clientPid)
        }
    }

    /// Drop anything whose 60-second window closed. The wire side has already answered
    /// `APPROVAL_TIMEOUT`; leaving the sheet up would invite an answer nobody is listening for.
    private func dropExpired() {
        let cutoff = UInt64(now.timeIntervalSince1970)
        let before = queue.count
        queue.removeAll { $0.expiresAt <= cutoff }
        if queue.count != before {
            currentSignature = nil
            currentFillSignature = nil
            if let head = queue.first { adoptSignature(for: head) }
        }
    }

    // MARK: - Answering

    /// Deny the request on screen. No biometric: saying no is always allowed (ui-spec.md §10.3).
    func deny(_ request: ApprovalRequestView) {
        _ = agentResolve(
            requestId: request.id, decision: .deny, verification: verification())
        advance()
    }

    /// Allow, after a successful biometric.
    ///
    /// Returns the outcome so the caller can keep the sheet up on a cancellation — a fumbled
    /// fingerprint is not a policy decision (ui-spec.md §10.3).
    @discardableResult
    func allow(_ request: ApprovalRequestView, decision: ApprovalDecision) async -> BiometricOutcome
    {
        let outcome = await gate.authenticate(reason: Self.reason(for: request))
        guard outcome == .authenticated else { return outcome }
        _ = agentResolve(
            requestId: request.id, decision: decision, verification: verification())
        advance()
        return outcome
    }

    /// The verdict to record with the decision, so the lease and the audit entry say what was
    /// actually established about the caller rather than what the sheet happened to show.
    private func verification() -> ClientVerificationView {
        guard let signature = currentSignature else {
            return ClientVerificationView(verified: false, evidence: "code signature not checked")
        }
        return ClientVerificationView(
            verified: signature.verified, evidence: signature.evidence)
    }

    private func advance() {
        if !queue.isEmpty { queue.removeFirst() }
        currentSignature = nil
        currentFillSignature = nil
        if let head = queue.first { adoptSignature(for: head) }
        status = agentStatus()
        leases = agentLeases()
        extensionService?.tick()
    }

    // MARK: - Leases

    func revoke(_ lease: LeaseView) {
        _ = try? agentRevokeLease(leaseId: lease.id)
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
            "approve writing \(request.variables.count) variable\(request.variables.count == 1 ? "" : "s") to a .env file"
        case .runWithEnv:
            "approve running \(request.command.first ?? "a command") with secrets in its environment"
        case .createEnvironment:
            "approve creating an environment"
        case .addVariables:
            "approve adding variables to an environment"
        case .fillCredential:
            // Names the item and the origin, never a value — the same rule the sheet follows.
            "fill \(request.itemTitle ?? "a login") into \(request.origin ?? "this page")"
        }
    }

    /// `KAGISECURE_SOCKET` moves the listener, which is how a second vault — or a test — runs
    /// without touching the user's own (architecture.md §4.2).
    private static func socketOverride() -> String? {
        ProcessInfo.processInfo.environment["KAGISECURE_SOCKET"]
    }

    private static func message(for error: Error) -> String {
        if let ffi = error as? FfiError {
            switch ffi {
            case .WrongCredential:
                return "That did not unlock the vault."
            case .NotFound(let m), .AlreadyExists(let m), .NoSuchSlot(let m), .NotPresent(let m),
                .Invalid(let m), .Io(let m):
                return m
            }
        }
        return error.localizedDescription
    }
}
