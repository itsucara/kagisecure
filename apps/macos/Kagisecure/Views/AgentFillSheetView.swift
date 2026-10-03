import AppKit
import SwiftUI

import KagisecureFFI

/// The agent-fill approval sheet (ui-spec.md §10.7, ADR-0036 §5 and §9.2).
///
/// An agent asked, over MCP, for a login to be typed into the browser tab in front. This is where a
/// person decides whether it may — and, since an agent with input control can click any button in
/// any window, the click here decides nothing on its own: **Fill on example.com…** goes through
/// `AgentService.allow`, which asks for Touch ID or the login password — unless a fill on the same
/// site passed that check less than ten minutes ago (`PresenceGrace`, ADR-0037's amendment of
/// 2026-09-27), in which case the click is the whole approval and the sheet says so.
///
/// # What the layout is for
///
/// The origin rule already refuses a look-alike before any sheet is raised; this sheet is defence
/// in depth for what the rule allows by design, which is any subdomain of a saved site. So the
/// sentence leads with **the site**, not the agent's name (the name is what an attacker would
/// choose), the registrable domain is emphasized and everything before it dimmed, a punycode
/// host's Unicode rendering is shown beside the ASCII one with a warning when scripts mix, `http`
/// is "not encrypted" in red, and a non-default port is always shown.
///
/// # What the buttons refuse to do
///
/// No default button: `Return` does nothing, `Esc` denies (`AgentFillSheetKeys`). The Allow button
/// is enabled while the sheet is key and visible (`AllowDelay`); the 1.5-second hold it used to
/// have was removed on 2026-10-03 (ADR-0036 amendment) for convenience.
///
/// **Deny and block this agent for 30 minutes** sits between Deny and Fill (ADR-0036 §9.3). It is
/// a denial — no presence check — and has no keyboard shortcut; `Esc` stays a plain Deny.
///
/// Everything here is metadata. There is no value on this sheet and no field one could be put in.
struct AgentFillSheetView: View {
    @Environment(AgentService.self) private var agent
    let request: ApprovalRequestView
    /// The agent's and the browser's verdicts, computed once when the request reached the head.
    let signature: AgentFillSignature?

    @State private var delay = AllowDelay()
    @State private var delayTask: Task<Void, Never>?
    @State private var busy = false
    @State private var answered = false
    @State private var biometricProblem: String?

    private var facts: AgentFillFactsView? { request.agentFill }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let facts {
                        agentIdentity(facts)
                        browserIdentity(facts)
                        target(facts)
                        SharedSourceFacts(request: request)
                    } else {
                        missingFacts
                    }
                }
                .padding(20)
            }
            .frame(maxHeight: 420)
            Divider()
            footer
        }
        // Wide enough for three buttons on one row: Deny, Deny and block, and "Fill on <domain>…".
        .frame(width: 640)
        // Whether this sheet's window is key and visible — the clock the Allow hold runs on.
        .background(WindowKeyReporter { keyAndVisible in windowStateChanged(keyAndVisible) })
        // Return and Enter are swallowed, Esc denies. With no `.defaultAction` button on the sheet
        // Return already has nothing to press; this makes sure a focused control cannot take it
        // either.
        .onKeyPress(keys: AgentFillSheetKeys.handledKeys) { press in
            switch AgentFillSheetKeys.response(to: press.key) {
            case .deny:
                deny()
                return .handled
            case .swallow:
                return .handled
            case .ignore:
                return .ignored
            }
        }
        .onDisappear { delayTask?.cancel() }
        // No `.accessibilityLabel` on this stack, for the reason `ApprovalSheet` gives: a label on
        // a layout container is stamped onto every leaf inside it.
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: ApprovalSheet.symbol(for: request))
                .font(.system(size: 26))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                styledSentence
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel(Self.sentence(for: request))
                    .accessibilityIdentifier("ks.approval.sentence")
                Text(Self.readableByTheAgent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.headline")
                if facts?.twoStep == true {
                    Text(Self.twoStepExplanation)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("ks.approval.agentFill.twoStepExplanation")
                }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
    }

    /// The sentence, with the registrable domain in bold and the labels before it dimmed.
    ///
    /// A one-time-code request (ADR-0036 §7.4) leads with what it fills instead of "sign in" — it
    /// is a second factor, not a password, and the sheet says so before anything else.
    private var styledSentence: Text {
        let title = Self.itemTitle(for: request)
        guard let origin = facts?.pageOrigin else {
            return Text(Self.sentence(for: request))
        }
        let parts = Self.hostParts(origin)
        let site = Text(parts.dimmed).foregroundStyle(.secondary)
            + Text(parts.emphasized).bold()
            + Text(parts.port)
        if facts?.fields == [.oneTimeCode] {
            return Text("An agent asks to fill the one-time code for “\(title)” on ") + site
        }
        return Text("An agent asks to sign in to ") + site + Text(" with “\(title)”")
    }

    // MARK: - The agent

    private func agentIdentity(_ facts: AgentFillFactsView) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Agent")
            Text("“\(ApprovalSheet.safe(facts.agentName))” — reports itself; the name is unverified.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.approval.agentFill.reportedName")
            BrowserIdentityBlock.verdictRow(
                String(localized: "Started by"), signature?.startedBy,
                fallback: String(localized: "The program that started the agent could not be checked."))
                .accessibilityIdentifier("ks.approval.agentFill.verdict.startedBy")
            ApprovalSheet.row(
                "Started by",
                "\(facts.parentExecutable ?? String(localized: "unknown — the system could not say"))"
                    + "  ·  pid \(facts.parentPid.map(String.init) ?? "?")",
                identifier: "ks.approval.agentFill.startedBy")
            ApprovalSheet.row(
                "Via",
                "\(facts.sidecarExecutable ?? "kagisecure-mcp")  ·  pid \(facts.sidecarPid)",
                identifier: "ks.approval.agentFill.sidecar")
            Text(signature?.sidecar.evidence ?? String(localized: "The sidecar could not be checked."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.approval.agentFill.verdict.sidecar")
            Text(
                "“Started by” is the program the system says launched the agent's connection to this app — not what the agent says about itself."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - The browser

    private func browserIdentity(_ facts: AgentFillFactsView) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionTitle("Browser")
            Text("Typed into \(facts.browser ?? String(localized: "a browser this app could not name")).")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.approval.agentFill.browser")
            BrowserIdentityBlock(
                fillSignature: signature?.browser,
                extensionId: facts.extensionId,
                hostExecutable: facts.hostExecutable, hostPid: facts.hostPid,
                browserExecutable: facts.browserExecutable, browserPid: facts.browserPid)
        }
    }

    // MARK: - Where, and what

    private func target(_ facts: AgentFillFactsView) -> some View {
        let origin = facts.pageOrigin
        return VStack(alignment: .leading, spacing: 8) {
            ApprovalSheet.row(
                "Where", String(localized: "The tab in front, top of the page — not a frame"),
                identifier: "ks.approval.agentFill.where")
            site(origin)
            VStack(alignment: .leading, spacing: 2) {
                ApprovalSheet.row(
                    "Saved as", facts.savedWebsite, identifier: "ks.approval.agentFill.savedAs")
                if facts.pageHostDiffers {
                    Label("This page is a subdomain of it.", systemImage: "arrow.turn.down.right")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier("ks.approval.agentFill.subdomain")
                }
            }
            ApprovalSheet.row(
                "Item", ApprovalSheet.safe(facts.itemTitle, limit: 120),
                identifier: "ks.approval.agentFill.item")
            ApprovalSheet.row(
                "Fill", Self.fillSummary(facts), identifier: "ks.approval.agentFill.fields")
        }
    }

    /// The page's origin in the look-alike rendering (ADR-0036 §5).
    private func site(_ origin: AgentOriginView) -> some View {
        let parts = Self.hostParts(origin)
        return VStack(alignment: .leading, spacing: 4) {
            Text("Site")
                .font(.caption)
                .foregroundStyle(.secondary)
            (Text("\(ApprovalSheet.safe(origin.scheme, limit: 16))://")
                .foregroundStyle(origin.notEncrypted ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                + Text(parts.dimmed).foregroundStyle(.secondary)
                + Text(parts.emphasized).bold().underline()
                + Text(parts.port).bold())
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel(Self.siteText(origin))
                .accessibilityIdentifier("ks.approval.agentFill.site")
            Text("Underlined: the registrable domain — the part a site's owner registers. Check it.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let port = origin.port {
                Text("Port \(String(port)) — not the usual one for \(ApprovalSheet.safe(origin.scheme, limit: 16)).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("ks.approval.agentFill.port")
            }
            if origin.notEncrypted {
                warning(
                    "Not encrypted. This login is saved for an http site, so what is typed travels over the network in the clear.",
                    systemImage: "lock.open.fill", color: .red)
                    .accessibilityIdentifier("ks.approval.agentFill.notEncrypted")
            }
            if let unicode = origin.unicodeHost {
                ApprovalSheet.row(
                    "Shown by the browser as", ApprovalSheet.safe(unicode, limit: 253),
                    identifier: "ks.approval.agentFill.unicodeHost")
            }
            if origin.mixedScript {
                warning(
                    "This name mixes writing systems, or has a part that does not decode. That is how one site's name is made to look like another's — compare it with the site you meant.",
                    systemImage: "exclamationmark.triangle.fill", color: .red)
                    .accessibilityIdentifier("ks.approval.agentFill.mixedScript")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var missingFacts: some View {
        warning(
            "This request arrived without the facts this sheet needs to name the site, the item and the agent, so it cannot be allowed. Deny it.",
            systemImage: "exclamationmark.triangle.fill", color: .red)
            .accessibilityIdentifier("ks.approval.agentFill.missingFacts")
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(spacing: 8) {
            if let biometricProblem {
                Text(biometricProblem)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("ks.approval.biometricProblem")
            }
            if agent.presenceGraceCovers(request) {
                Text(PresenceGrace.sheetCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.presenceGrace")
            }
            countdown
            if !delay.isOpen && facts != nil {
                Text("Read the site first — “Fill on…” turns on in a moment.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .accessibilityIdentifier("ks.approval.agentFill.allowDelay")
            }
            HStack {
                Spacer()
                // Deny first; nothing is the default action (ADR-0036 §9.2, ui-spec.md §10.3).
                Button("Deny") { deny() }
                    .keyboardShortcut(AgentFillSheetKeys.denyShortcut)
                    .accessibilityIdentifier("ks.approval.deny")
                // ADR-0036 §9.3: a denial, so no presence check, and never the default button.
                // Esc stays a plain Deny — blocking is a choice made with the pointer.
                Button(Self.denyAndBlockLabel) { denyAndBlock() }
                    .help(
                        "Refuse this fill, and refuse every fill this agent asks for in the next 30 minutes without asking you. The block covers the program that started the agent, not the name it reports; you can lift it in Agent access.")
                    .accessibilityIdentifier("ks.approval.agentFill.denyAndBlock")
                Button(Self.allowLabel(for: request)) { approve() }
                    .disabled(!Self.allowEnabled(delay: delay, hasFacts: facts != nil))
                    .accessibilityIdentifier("ks.approval.agentFill.allow")
            }
            .disabled(busy || answered)
        }
        .padding(20)
    }

    private var countdown: some View {
        let remaining = max(0, Double(request.expiresAt) - agent.now.timeIntervalSince1970)
        let total = max(1, Double(request.expiresAt - request.createdAt))
        return VStack(alignment: .leading, spacing: 2) {
            ProgressView(value: remaining, total: total)
                .progressViewStyle(.linear)
                .tint(remaining < 15 ? .red : .secondary)
            Text("\(Int(remaining)) s to answer, then the agent is told nobody replied.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .accessibilityLabel("\(Int(remaining)) seconds left to answer")
        .accessibilityIdentifier("ks.approval.countdown")
    }

    // MARK: - Actions

    private func deny() {
        guard !answered, !busy else { return }
        answered = true
        agent.deny(request)
    }

    /// Deny, and block the agent for thirty minutes (ADR-0036 §9.3). Saying no needs no biometric.
    private func denyAndBlock() {
        guard !answered, !busy else { return }
        answered = true
        agent.denyAndBlock(request)
    }

    /// Always through `AgentService.allow`, which asks for a presence check (outside a grace
    /// window) and sends Rust **Allow once**. A cancelled check leaves the sheet up — a fumbled fingerprint is
    /// not a decision (ui-spec.md §10.3) — and grants nothing.
    private func approve() {
        guard Self.allowEnabled(delay: delay, hasFacts: facts != nil), !busy, !answered else {
            return
        }
        busy = true
        biometricProblem = nil
        Task {
            let outcome = await agent.allow(request, decision: .allowOnce)
            busy = false
            switch outcome {
            case .authenticated:
                answered = true
            case .cancelled:
                biometricProblem = String(localized: "Authentication cancelled. Nothing has been filled.")
            case .unavailable(let why):
                biometricProblem = String(localized: "Could not ask for authentication: \(why)")
            case .busy:
                biometricProblem =
                    String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
            }
        }
    }

    /// The window became, or stopped being, key and visible. Becoming so (re)starts the hold.
    private func windowStateChanged(_ keyAndVisible: Bool) {
        delayTask?.cancel()
        delayTask = nil
        guard keyAndVisible else {
            delay.resignedKey()
            return
        }
        let now = ContinuousClock.now
        delay.becameKey(at: now)
        guard let deadline = delay.deadline else { return }
        delayTask = Task { @MainActor in
            try? await Task.sleep(until: deadline, clock: .continuous)
            guard !Task.isCancelled else { return }
            delay.refresh(at: ContinuousClock.now)
        }
    }

    // MARK: - Pieces

    private func sectionTitle(_ title: LocalizedStringKey) -> some View {
        Text(title)
            .font(.subheadline.weight(.semibold))
    }

    private func warning(_ text: LocalizedStringKey, systemImage: String, color: Color) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: systemImage)
        }
        .font(.callout)
        .foregroundStyle(color)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Strings, static so the tests can read them

    /// ADR-0036 §8.2's sentence, verbatim. It is the truth about this feature — kagisecure types
    /// the value; it cannot stop an agent that runs script in the page from reading it there — and
    /// it is on the sheet so that approving is done knowing it.
    static let readableByTheAgent = String(
        localized: "kagisecure never gives the agent a value. It types the value into a page the agent is driving, on a site saved for that login, after you approve — and an agent that can run script in that page can read it there.")

    /// The host split for rendering: the dimmed labels, the emphasized registrable domain, and
    /// `:port` when there is one. Each run is sanitized; none is ever truncated, because a cut
    /// host is a different host.
    static func hostParts(_ origin: AgentOriginView) -> (dimmed: String, emphasized: String, port: String) {
        (
            dimmed: origin.dimmedPrefix.isEmpty ? "" : ApprovalSheet.safe(origin.dimmedPrefix, limit: 253),
            emphasized: ApprovalSheet.safe(origin.emphasized, limit: 253),
            port: origin.port.map { ":\($0)" } ?? ""
        )
    }

    /// The whole origin as one plain string: scheme, host, and a non-default port.
    static func siteText(_ origin: AgentOriginView) -> String {
        let parts = hostParts(origin)
        return "\(ApprovalSheet.safe(origin.scheme, limit: 16))://\(parts.dimmed)\(parts.emphasized)\(parts.port)"
    }

    static func itemTitle(for request: ApprovalRequestView) -> String {
        ApprovalSheet.safe(request.agentFill?.itemTitle ?? request.itemTitle ?? String(localized: "an item"))
    }

    /// The sentence the sheet leads with. The **site** comes first — it is what the person has to
    /// check — and the agent's self-reported name is not in it at all (ADR-0036 §9.2).
    ///
    /// A one-time-code request (ADR-0036 §7.4) says plainly that it fills a code, not the
    /// password: the pair is the account, and the sheet must not let "sign in" be misread as
    /// handing over both.
    static func sentence(for request: ApprovalRequestView) -> String {
        let site: String
        if let origin = request.agentFill?.pageOrigin {
            let parts = hostParts(origin)
            site = parts.dimmed + parts.emphasized + parts.port
        } else {
            site = ApprovalSheet.safe(request.origin ?? String(localized: "a page"), limit: 120)
        }
        let title = itemTitle(for: request)
        if request.agentFill?.fields == [.oneTimeCode] {
            return String(localized: "An agent asks to fill the one-time code for “\(title)” on \(site)")
        }
        return String(localized: "An agent asks to sign in to \(site) with “\(title)”")
    }

    /// The extra sentence a two-step, identifier-first sign-in (ADR-0036 §7.3) adds under the
    /// headline: what happens now, what happens without asking again, and how long the approval
    /// stays good for.
    static let twoStepExplanation = String(
        localized: "The username is filled now. The password follows on the next page of the same site, without asking you again. This approval is good for up to 60 seconds.")

    /// ADR-0036 §9.3's button, between Deny and Fill.
    static let denyAndBlockLabel = String(localized: "Deny and block this agent for 30 minutes")

    /// "Fill on example.com…": the button that approves names what it approves (ADR-0036 §9.2).
    static func allowLabel(for request: ApprovalRequestView) -> String {
        guard let origin = request.agentFill?.pageOrigin else { return String(localized: "Fill…") }
        return String(localized: "Fill on \(hostParts(origin).emphasized)…")
    }

    /// Whether the Allow button may be pressed: the hold has run out, and there is something to
    /// approve.
    static func allowEnabled(delay: AllowDelay, hasFacts: Bool) -> Bool {
        hasFacts && delay.isOpen
    }

    /// What the Fill row says: the field names — or, for page one of an identifier-first sign-in
    /// (ADR-0036 §7.3), that the password goes onto the next page of the same site under this
    /// same approval, without asking again, within the 60-second flow window; or, for a one-time
    /// code (§7.4), that it is a code and not the password.
    static func fillSummary(_ facts: AgentFillFactsView) -> String {
        if facts.twoStep {
            return String(localized: "username now, password on the next page of this site — without asking again, within 60 seconds")
        }
        if facts.fields == [.oneTimeCode] {
            return String(localized: "a one-time code — not the password")
        }
        return fieldNames(facts.fields)
    }

    /// "username, password" — names, in the order the agent asked for them.
    static func fieldNames(_ fields: [AgentFillFieldView]) -> String {
        fields.map { field in
            switch field {
            case .username: String(localized: "username")
            case .password: String(localized: "password")
            case .oneTimeCode: String(localized: "one-time code")
            }
        }
        .joined(separator: ", ")
    }
}

/// The hold on an agent fill's Allow button (ADR-0036 §5): closed while the sheet is not key and
/// visible. The hold length is zero since the amendment of 2026-10-03 (it was 1.5 seconds). A value type with the clock passed in, so the rule can be tested without a window.
struct AllowDelay: Equatable, Sendable {
    /// How long the sheet must have been key and visible before Allow enables.
    static let hold: Duration = .zero

    /// When the sheet last became key and visible; `nil` while it is not.
    private(set) var keySince: ContinuousClock.Instant?

    /// Whether Allow may be pressed. Only `refresh(at:)` opens it.
    private(set) var isOpen = false

    /// When the hold runs out, if the sheet is key.
    var deadline: ContinuousClock.Instant? { keySince.map { $0.advanced(by: Self.hold) } }

    /// The sheet became key and visible: (re)start the hold, closed.
    mutating func becameKey(at now: ContinuousClock.Instant) {
        keySince = now
        isOpen = Self.hold <= .zero
    }

    /// The sheet stopped being key or visible: close, and forget when it started.
    mutating func resignedKey() {
        keySince = nil
        isOpen = false
    }

    /// Open if the sheet has been key for the whole hold by `now`; otherwise stay closed.
    mutating func refresh(at now: ContinuousClock.Instant) {
        guard let deadline else {
            isOpen = false
            return
        }
        isOpen = now >= deadline
    }
}

/// The keyboard on the agent-fill sheet (ADR-0036 §9.2): no default button, `Return` does nothing,
/// `Esc` denies.
enum AgentFillSheetKeys {
    /// What the sheet does with a key it handles.
    enum Response: Equatable {
        /// Deny the request.
        case deny
        /// Consume the key and do nothing.
        case swallow
        /// Not ours: let it through.
        case ignore
    }

    /// The keypad's Enter, which macOS treats as Return for a default button.
    static let enter = KeyEquivalent("\u{03}")

    /// The keys `onKeyPress` is asked to see.
    static let handledKeys: Set<KeyEquivalent> = [.escape, .return, enter]

    /// The Deny button's shortcut: Esc.
    static let denyShortcut: KeyboardShortcut = .cancelAction

    /// The Allow button's shortcut: none, ever. A keyboard path to Allow that skips reading the
    /// sheet is what the no-default-button rule is there to prevent.
    static let allowShortcut: KeyboardShortcut? = nil

    static func response(to key: KeyEquivalent) -> Response {
        switch key {
        case .escape: .deny
        case .return, enter: .swallow
        default: .ignore
        }
    }
}

/// Reports whether the window this view is in is key **and** visible, every time that changes.
///
/// `controlActiveState` would say "key" but not "on screen", and the hold is about both: a sheet
/// behind another window is key-less, and a key sheet under a full-screen app is not being read.
/// Selector-based observers, which the notification center drops by itself when the view goes.
struct WindowKeyReporter: NSViewRepresentable {
    let onChange: @MainActor (Bool) -> Void

    func makeNSView(context: Context) -> ReporterView {
        let view = ReporterView()
        view.onChange = onChange
        return view
    }

    func updateNSView(_ view: ReporterView, context: Context) {
        view.onChange = onChange
        // Every SwiftUI update re-reads the window, so a missed notification costs at most the
        // one-second tick the countdown re-renders on.
        view.evaluate()
    }

    final class ReporterView: NSView {
        var onChange: (@MainActor (Bool) -> Void)?
        private var last: Bool?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            NotificationCenter.default.removeObserver(self)
            if let window {
                for name in [
                    NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
                    NSWindow.didChangeOcclusionStateNotification,
                    NSWindow.didMiniaturizeNotification, NSWindow.didDeminiaturizeNotification,
                ] {
                    NotificationCenter.default.addObserver(
                        self, selector: #selector(windowChanged(_:)), name: name, object: window)
                }
            }
            evaluate()
        }

        @objc private func windowChanged(_ notification: Notification) {
            evaluate()
        }

        func evaluate() {
            let now = window.map { $0.isKeyWindow && $0.occlusionState.contains(.visible) } ?? false
            guard now != last else { return }
            last = now
            // Deferred a turn: this can run inside a SwiftUI update, which must not change state.
            let onChange = onChange
            Task { @MainActor in onChange?(now) }
        }
    }
}
