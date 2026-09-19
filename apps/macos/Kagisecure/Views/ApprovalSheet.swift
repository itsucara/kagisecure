import SwiftUI

import KagisecureFFI

/// The approval dialog (ui-spec.md §10).
///
/// The centerpiece of the product: rendered by the app, in the app's own window, never by the
/// agent's UI. The model can cause the *request*; it cannot see this, fill it, or fabricate its
/// outcome.
///
/// Everything on it is metadata. There is no value here and no field one could be put in — the
/// record this is built from, `ApprovalRequestView`, has none.
struct ApprovalSheet: View {
    @Environment(AgentService.self) private var agent
    let request: ApprovalRequestView
    let signature: PeerSignature?

    /// The two verdicts a browser-extension fill has, when this is one (M6). `nil` otherwise.
    var fillSignature: FillSignature?

    /// Seconds the user has shortened the lease to. Starts at what the agent asked for and can
    /// only go down (mcp-server.md §5: "the user may shorten what the agent requested").
    @State private var ttlSeconds: Double
    @State private var busy = false
    @State private var biometricProblem: String?

    init(
        request: ApprovalRequestView, signature: PeerSignature?,
        fillSignature: FillSignature? = nil
    ) {
        self.request = request
        self.signature = signature
        self.fillSignature = fillSignature
        _ttlSeconds = State(initialValue: Double(request.requestedTtlSeconds))
    }

    /// Whether this sheet is about a browser fill rather than an agent injection.
    private var isFill: Bool { request.action == .fillCredential }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    identity
                    if isFill {
                        fillTarget
                        if request.topOrigin != nil { frameWarning }
                    }
                    if !request.variables.isEmpty { variables }
                    if !request.command.isEmpty { command }
                    location
                    if request.gitignored == false { gitWarning }
                    if request.mintsLease || isFill { lease }
                    scopeSummary
                }
                .padding(20)
            }
            .frame(maxHeight: 380)
            Divider()
            footer
        }
        .frame(width: 520)
        // No `.accessibilityLabel` on this stack. It used to carry one — "kagisecure approval
        // request" — and a label on a SwiftUI layout container is not a title for the group: it is
        // stamped onto every leaf AppKit flattens into it. VoiceOver announced the verdict, the
        // variable names, the path, the countdown and all three buttons as "kagisecure approval
        // request", which on the one screen in this product where reading carefully is the entire
        // point made the sheet unusable without sight. The UI-test suite found it by asking the
        // sheet what its sentence said and being told the label instead.
        //
        // The window the sheet is presented in supplies the title; every element below says what
        // it is.
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 26))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(sentence)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.sentence")
                Text(
                    isFill
                        ? "The value goes to the browser only if you allow it, and only for this page."
                        : "No secret value is shown to the caller either way."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.approval.headline")
            }
            Spacer(minLength: 0)
        }
        .padding(20)
    }

    private var symbol: String { Self.symbol(for: request) }

    /// The icon for a request kind.
    static func symbol(for request: ApprovalRequestView) -> String {
        switch request.action {
        case .writeEnvFile: "doc.badge.gearshape"
        case .runWithEnv: "terminal"
        case .createEnvironment: "folder.badge.plus"
        case .addVariables: "text.badge.plus"
        case .fillCredential: "key.horizontal"
        }
    }

    private var sentence: String { Self.sentence(for: request) }

    /// The plain-language sentence ui-spec.md §10.2 asks for. The caller's self-reported name is
    /// quoted, so a caller named `Claude Code (verified)` cannot borrow our vocabulary.
    ///
    /// `static`, and taking the request, so the tests can assert it. This one string is the whole
    /// approval: it is what a human reads before they put a fingerprint on something, and a
    /// mistake in it — the wrong origin, the wrong item, an unquoted self-reported name — is the
    /// most consequential bug this file could have.
    static func sentence(for request: ApprovalRequestView) -> String {
        let who = "“\(request.clientName)”"
        switch request.action {
        case .writeEnvFile:
            let n = request.variables.count
            return "\(who) wants to write \(n) variable\(n == 1 ? "" : "s") to a .env file"
        case .runWithEnv:
            return "\(who) wants to run \(request.command.joined(separator: " ")) with environment variables"
        case .createEnvironment:
            return "\(who) wants to create the environment \(request.environmentName ?? "")"
        case .addVariables:
            return "\(who) wants to add variables to \(request.environmentName ?? "an environment")"
        case .fillCredential:
            // The browser name here is the app's own conclusion from the native host's process
            // ancestry, not a claim the extension made, so it is *not* quoted — the quotation
            // marks in this file mean "the caller said so".
            let browser = request.browser ?? "A browser"
            let what = request.fillFields.contains("one-time password")
                ? "the one-time code for" : "the password for"
            return "\(browser) wants \(what) “\(request.itemTitle ?? "an item")”"
        }
    }

    // MARK: - Sections

    /// The two-process identity block a fill gets: the native host, and the browser above it.
    ///
    /// Two rows rather than one word, because on this build they genuinely differ: Chrome is
    /// signed by Google and can be *verified*; a `cargo build` native host is ad-hoc and cannot.
    /// Collapsing them would either claim a verification our own helper does not have, or discard
    /// the one real fact on the sheet.
    @ViewBuilder
    private var fillIdentity: some View {
        VStack(alignment: .leading, spacing: 8) {
            verdictRow(
                "Browser", fillSignature?.browser,
                fallback: "No recognized browser launched the helper.")
                .accessibilityIdentifier("ks.approval.verdict.browser")
            verdictRow("Helper", fillSignature?.host, fallback: "The helper could not be checked.")
                .accessibilityIdentifier("ks.approval.verdict.helper")
            if let extensionId = request.extensionId {
                Text("Extension \(extensionId) — pinned in this app and in the browser's manifest.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.extensionId")
            }
            if let exe = request.clientExecutable {
                row("Helper process", "\(exe)  ·  pid \(request.clientPid.map(String.init) ?? "?")")
                    .accessibilityIdentifier("ks.approval.helperProcess")
            }
            if let browserExe = request.browserExecutable {
                row(
                    "Browser process",
                    "\(browserExe)  ·  pid \(request.browserPid.map(String.init) ?? "?")"
                )
                .accessibilityIdentifier("ks.approval.browserProcess")
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private func verdictRow(
        _ label: String, _ verdict: PeerSignature?, fallback: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            if verdict?.verified == true {
                Label("\(label): verified", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.callout.weight(.semibold))
            } else {
                Label("\(label): unverified", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout.weight(.semibold))
            }
            Text(verdict?.evidence ?? fallback)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What would be written, and where. Names only — there is no field on the record a value
    /// could be in, which is the point.
    private var fillTarget: some View {
        VStack(alignment: .leading, spacing: 6) {
            row("Item", request.itemTitle ?? request.itemId ?? "unknown")
                .accessibilityIdentifier("ks.approval.fill.item")
            row("Website", request.origin ?? "unknown")
                .accessibilityIdentifier("ks.approval.fill.website")
            row("Fields", request.fillFields.joined(separator: ", "))
                .accessibilityIdentifier("ks.approval.fill.fields")
            Text(
                "kagisecure matched this page against the websites saved on the item. It will not "
                + "fill anywhere else."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The form is inside a frame on another site. Loud, because it is the case worth pausing on.
    private var frameWarning: some View {
        Label {
            Text(
                "This form is inside a frame on \(request.topOrigin ?? "another site"). kagisecure "
                + "matched the frame, not the page — check that you meant to sign in here."
            )
            .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "square.on.square.dashed")
        }
        .font(.callout)
        .foregroundStyle(.orange)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityIdentifier("ks.approval.frameWarning")
    }

    @ViewBuilder
    private var identity: some View {
        if isFill {
            fillIdentity
        } else {
            agentIdentity
        }
    }

    @ViewBuilder
    private var agentIdentity: some View {
        VStack(alignment: .leading, spacing: 6) {
            if signature?.verified == true {
                Label("Verified", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .font(.callout.weight(.semibold))
                    .accessibilityIdentifier("ks.approval.verdict")
            } else {
                Label("Unverified — proceed with caution", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout.weight(.semibold))
                    .accessibilityIdentifier("ks.approval.verdict")
            }
            if let evidence = signature?.evidence {
                Text(evidence)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("ks.approval.evidence")
            }
            Text(
                "Reports itself as “\(request.clientName)”. That name is unverified — it is whatever the caller said."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("ks.approval.reportedName")
            if let exe = request.clientExecutable {
                row(
                    "Process",
                    "\(exe)  ·  pid \(request.clientPid.map(String.init) ?? "?")"
                        + (request.clientPidFromKernel ? "" : " (self-reported)")
                )
                .accessibilityIdentifier("ks.approval.process")
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    private var variables: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Variables")
                .font(.subheadline.weight(.semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(request.variables, id: \.self) { name in
                        Text(name)
                            .font(.system(.callout, design: .monospaced))
                            .accessibilityIdentifier("ks.approval.variable.\(name)")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 110)
            .accessibilityIdentifier("ks.approval.variables")
            Text("Names only. kagisecure never shows a value, or a length, to the caller.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("ks.approval.variablesNote")
        }
    }

    private var command: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Command")
                .font(.subheadline.weight(.semibold))
            Text(request.command.joined(separator: " "))
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .accessibilityIdentifier("ks.approval.command")
            Text("Run directly, with no shell: ; | $() in an argument are just characters.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var location: some View {
        if let path = request.targetPath {
            row("File", path)
                .accessibilityIdentifier("ks.approval.targetPath")
        } else if let dir = request.directory {
            row("Directory", dir)
                .accessibilityIdentifier("ks.approval.directory")
        }
        if let env = request.environmentName {
            row("Environment", env)
                .accessibilityIdentifier("ks.approval.environment")
        }
        if let cwd = request.clientCwd, cwd != request.directory {
            row("Caller started in", cwd)
                .accessibilityIdentifier("ks.approval.callerCwd")
        }
    }

    private var gitWarning: some View {
        Label {
            Text("Not gitignored — this file is inside a git work tree and would be committable.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .font(.callout)
        .foregroundStyle(.red)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityIdentifier("ks.approval.gitignoreWarning")
    }

    private var lease: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Access expires after")
                .font(.subheadline.weight(.semibold))
            HStack {
                Slider(
                    value: $ttlSeconds, in: 60...Double(max(request.requestedTtlSeconds, 60)),
                    step: 60
                )
                .accessibilityIdentifier("ks.approval.ttlSlider")
                Text(Self.duration(UInt64(ttlSeconds)))
                    .font(.callout.monospacedDigit())
                    .frame(width: 90, alignment: .trailing)
                    .accessibilityIdentifier("ks.approval.ttlValue")
            }
            Text(
                isFill
                    ? "“Allow for this session” lets this item fill on this website for that long "
                      + "without asking again. Every fill still needs your click in the page, and "
                      + "locking the vault ends it."
                    : "The caller asked for \(Self.duration(request.requestedTtlSeconds)). You can shorten it, never lengthen it."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var scopeSummary: some View {
        Text(summary)
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("ks.approval.summary")
    }

    private var summary: String { Self.summary(for: request, ttlSeconds: UInt64(ttlSeconds)) }

    /// The one-line scope sentence from ui-spec.md §10.2.
    static func summary(for request: ApprovalRequestView, ttlSeconds: UInt64) -> String {
        if request.action == .fillCredential {
            let fields = request.fillFields.joined(separator: " and ")
            return "This sends the \(fields) for “\(request.itemTitle ?? "this item")” to "
                + "\(request.origin ?? "this page"), once. Nothing else is sent, and nothing is "
                + "stored in the browser."
        }
        guard request.mintsLease else {
            return "This changes the structure of your vault. It grants no access to any value."
        }
        let names = request.variables.isEmpty ? "no variables" : request.variables.joined(separator: ", ")
        let place = request.directory ?? request.targetPath ?? "this directory"
        return "This grants access to \(names) in \(place) for \(Self.duration(ttlSeconds)), up to \(request.requestedUses) use\(request.requestedUses == 1 ? "" : "s")."
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
            countdown
            HStack {
                Spacer()
                // Deny first, and nothing is the default action: Return does nothing here
                // (ui-spec.md §11), Esc denies.
                Button("Deny") { agent.deny(request) }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.approval.deny")
                Button("Allow once") { approve(.allowOnce) }
                    .accessibilityIdentifier("ks.approval.allowOnce")
                Button("Allow for this session") {
                    approve(.allowSession(ttlSeconds: UInt64(ttlSeconds), uses: request.requestedUses))
                }
                .accessibilityIdentifier("ks.approval.allowSession")
            }
            .disabled(busy)
        }
        .padding(20)
    }

    private var countdown: some View {
        let remaining = max(
            0, Double(request.expiresAt) - agent.now.timeIntervalSince1970)
        let total = max(1, Double(request.expiresAt - request.createdAt))
        return VStack(alignment: .leading, spacing: 2) {
            ProgressView(value: remaining, total: total)
                .progressViewStyle(.linear)
                .tint(remaining < 15 ? .red : .secondary)
            Text("\(Int(remaining)) s to answer, then the caller is told nobody replied.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .accessibilityLabel("\(Int(remaining)) seconds left to answer")
        .accessibilityIdentifier("ks.approval.countdown")
    }

    private func approve(_ decision: ApprovalDecision) {
        busy = true
        biometricProblem = nil
        Task {
            let outcome = await agent.allow(request, decision: decision)
            busy = false
            switch outcome {
            case .authenticated:
                break
            case .cancelled:
                // Back to the dialog: a cancelled fingerprint is not a decision.
                biometricProblem = "Authentication cancelled. Nothing has been granted."
            case .unavailable(let why):
                biometricProblem = "Could not ask for authentication: \(why)"
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// `900` → `15 minutes`. Used on the sheet and in the leases table, so they agree.
    static func duration(_ seconds: UInt64) -> String {
        if seconds < 60 { return "\(seconds) s" }
        let minutes = seconds / 60
        if minutes < 60 { return "\(minutes) minute\(minutes == 1 ? "" : "s")" }
        let hours = Double(seconds) / 3600
        return String(format: "%.1f hours", hours)
    }
}
