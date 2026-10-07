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
                    SharedSourceFacts(request: request)
                    if isFill {
                        fillTarget
                        if request.topOrigin != nil { frameWarning }
                    }
                    if let facts = request.testLogin { TestLoginFactsBlock(facts: facts) }
                    if request.action == .storeCommandOutput, let facts = request.storeOutput {
                        StoreCommandOutputFactsBlock(facts: facts)
                    }
                    if !request.variables.isEmpty { variables }
                    if !request.command.isEmpty { command }
                    location
                    if request.gitignored == false { gitWarning }
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
                (isFill
                    ? Text("The value goes to the browser only if you allow it, and only for this page.")
                    : Text("No secret value is shown to the caller either way."))
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
        case .agentFill: "person.badge.key"
        case .createTestLogin: "person.badge.plus"
        case .storeCommandOutput: "terminal.fill"
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
        let who = "“\(safe(request.clientName))”"
        switch request.action {
        case .writeEnvFile:
            let n = request.variables.count
            return n == 1
                ? String(localized: "\(who) wants to write \(n) variable to a .env file")
                : String(localized: "\(who) wants to write \(n) variables to a .env file")
        case .runWithEnv where request.stdinDelivery:
            // ADR-0047: the values go to the command's standard input, once. The environment's
            // name is the one the user gave it, so it names *which* secrets; the command names
            // where they go.
            let n = request.variables.count
            return "\(who) wants to pass \(n) value\(n == 1 ? "" : "s") from \(safe(request.environmentName ?? "an environment")) "
                + "to \(safe(request.command.joined(separator: " "), limit: 80)) on its standard input, once"
        case .runWithEnv:
            let cmd = safe(request.command.joined(separator: " "), limit: 80)
            return String(localized: "\(who) wants to run \(cmd) with environment variables")
        case .createEnvironment:
            let env = safe(request.environmentName ?? "")
            return String(localized: "\(who) wants to create the environment \(env)")
        case .addVariables:
            let env = safe(request.environmentName ?? String(localized: "an environment"))
            return String(localized: "\(who) wants to add variables to \(env)")
        case .fillCredential:
            // The browser name here is the app's own conclusion from the native host's process
            // ancestry, not a claim the extension made, so it is *not* quoted — the quotation
            // marks in this file mean "the caller said so".
            let browser = request.browser ?? String(localized: "A browser")
            let item = safe(request.itemTitle ?? String(localized: "an item"))
            return request.fillFields.contains("one-time password")
                ? String(localized: "\(browser) wants the one-time code for “\(item)”")
                : String(localized: "\(browser) wants the password for “\(item)”")
        case .agentFill:
            // Its own sheet, and its own sentence, which leads with the site rather than the
            // agent's name (ADR-0036 §9.2).
            return AgentFillSheetView.sentence(for: request)
        case .createTestLogin:
            let site = request.testLogin.map(TestLoginFactsBlock.leadDomain) ?? String(localized: "an unknown site")
            return String(localized: "\(who) wants to create a test login for \(site)")
        case .storeCommandOutput:
            let cmd = safe(request.command.joined(separator: " "), limit: 80)
            let item = StoreCommandOutputFactsBlock.leadTarget(request.storeOutput)
            return "\(who) wants to run \(cmd) and store its output in “\(item)”"
        }
    }

    // MARK: - Untrusted text

    /// Quote characters an untrusted run could use to close — or forge — the sheet's own quoting.
    ///
    /// The sheet opens exactly one `“` and closes exactly one `”` around a self-reported name, and
    /// that pair is what tells a human "the caller said so". A name of `” is verified by Apple — “`
    /// otherwise reads as the app's own verification clause.
    private static let quoteScalars: Set<Unicode.Scalar> = [
        "\u{0022}", "\u{00AB}", "\u{00BB}", "\u{2018}", "\u{2019}", "\u{201A}", "\u{201B}",
        "\u{201C}", "\u{201D}", "\u{201E}", "\u{201F}", "\u{2033}", "\u{2036}", "\u{2039}",
        "\u{203A}", "\u{301D}", "\u{301E}", "\u{301F}", "\u{FF02}",
    ]

    /// How much of an untrusted run the sentence will carry before it is cut.
    private static let untrustedRunLimit = 64

    /// Sanitize one attacker-controlled run for display inside the app's own sentence.
    ///
    /// Four separate holes, all of them the same shape — the caller supplies the string and the
    /// app supplies the frame around it:
    ///
    ///   * **quoting**: any quote glyph becomes `'`, so the caller cannot close our quotation and
    ///     continue in the app's voice;
    ///   * **direction**: Unicode format characters (the bidi overrides, embeds, isolates and
    ///     marks, and the zero-width joiners) and surrogates/private-use scalars are dropped, so
    ///     the run cannot reorder or hide the words around it;
    ///   * **shape**: every control character, line/paragraph separator and whitespace run
    ///     collapses to a single space, so the sentence stays one line;
    ///   * **length**: bounded, with a visible `…`, so the verb can never be pushed out of view.
    ///
    /// A structural fix — rendering the untrusted run as its own `Text` — was the first choice and
    /// was rejected: the sentence is also `AgentService.reason(for:)`'s neighbour, it is what the
    /// UI tests and `#expect`s read as one string, and splitting it would leave a second,
    /// unsanitized copy of the same text in the accessibility tree and the Touch ID prompt. One
    /// sanitizer on the string, applied at every site that quotes untrusted text, is the boring
    /// version and it covers all of them.
    static func safe(_ raw: String, limit: Int = untrustedRunLimit) -> String {
        var scalars = String.UnicodeScalarView()
        var pendingSpace = false
        for scalar in raw.unicodeScalars {
            if quoteScalars.contains(scalar) {
                if pendingSpace, !scalars.isEmpty { scalars.append(" ") }
                pendingSpace = false
                scalars.append("'")
                continue
            }
            switch scalar.properties.generalCategory {
            case .format, .surrogate, .privateUse:
                // Invisible by construction: dropped outright rather than turned into a space.
                continue
            case .control, .lineSeparator, .paragraphSeparator:
                pendingSpace = true
                continue
            default:
                break
            }
            if scalar.properties.isWhitespace {
                pendingSpace = true
                continue
            }
            if pendingSpace, !scalars.isEmpty { scalars.append(" ") }
            pendingSpace = false
            scalars.append(scalar)
        }
        let collapsed = String(scalars)
        if collapsed.isEmpty { return String(localized: "unnamed") }
        guard collapsed.count > limit else { return collapsed }
        return String(collapsed.prefix(limit - 1)) + "…"
    }

    // MARK: - Sections

    /// The two-process identity block a fill gets: the native host, and the browser above it.
    /// Shared with the agent-fill sheet, which shows the browser exactly this way.
    private var fillIdentity: some View {
        BrowserIdentityBlock(
            fillSignature: fillSignature,
            extensionId: request.extensionId,
            hostExecutable: request.clientExecutable, hostPid: request.clientPid,
            browserExecutable: request.browserExecutable, browserPid: request.browserPid)
    }

    /// What would be written, and where. Names only — there is no field on the record a value
    /// could be in, which is the point.
    private var fillTarget: some View {
        VStack(alignment: .leading, spacing: 6) {
            // The title is the string the user compares against their own vault, so it gets the
            // same sanitization the sentence gives it — an invisible character here is a
            // different item wearing the same name.
            Self.row(
                "Item", Self.safe(request.itemTitle ?? request.itemId ?? String(localized: "unknown"), limit: 120),
                identifier: "ks.approval.fill.item")
            Self.row("Website", request.origin ?? String(localized: "unknown"), identifier: "ks.approval.fill.website")
            Self.row(
                "Fields", request.fillFields.joined(separator: ", "),
                identifier: "ks.approval.fill.fields")
            Text(
                "kagisecure matched this page against the websites saved on the item. It will not fill anywhere else."
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
                "This form is inside a frame on \(request.topOrigin ?? String(localized: "another site")). kagisecure matched the frame, not the page — check that you meant to sign in here."
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
                "Reports itself as “\(Self.safe(request.clientName))”. That name is unverified — it is whatever the caller said."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityIdentifier("ks.approval.reportedName")
            if let exe = request.clientExecutable {
                Self.row(
                    "Process",
                    "\(exe)  ·  pid \(request.clientPid.map(String.init) ?? "?")"
                        + (request.clientPidFromKernel ? "" : " " + String(localized: "(self-reported)")),
                    identifier: "ks.approval.process")
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
            if request.stdinDelivery {
                Text(Self.stdinCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.stdinCaption")
            }
        }
    }

    /// What a stdin delivery does with the values, and the one thing to check before allowing it
    /// (ADR-0047): the values reach whatever the command does with its input.
    static let stdinCaption =
        "The values are written to this command's standard input, once, and are not placed in its "
        + "environment or arguments. Allow it only if this is the command you expect: it can do "
        + "anything with what it reads."

    @ViewBuilder
    private var location: some View {
        if let path = request.targetPath {
            Self.row("File", path, identifier: "ks.approval.targetPath")
        } else if let dir = request.directory {
            Self.row("Directory", dir, identifier: "ks.approval.directory")
        }
        if let env = request.environmentName {
            Self.row("Environment", env, identifier: "ks.approval.environment")
        }
        if let cwd = request.clientCwd, cwd != request.directory {
            Self.row("Caller started in", cwd, identifier: "ks.approval.callerCwd")
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

    /// The longest lease the user may pick: what the caller asked for (mcp-server.md §5 — the
    /// user may shorten, never lengthen), and never less than the one-minute floor.
    private var ttlCeiling: Double { Double(max(request.requestedTtlSeconds, 60)) }

    /// The TTL in whole minutes, for the field and stepper. Rounded *up*, so that a request that is
    /// not a whole number of minutes — 90 s — still has its own value as the top of the range; and
    /// written back clamped to the ceiling, so the top of the range is exactly what was asked for.
    private var ttlMinutes: Binding<Int> {
        Binding(
            get: { Int((ttlSeconds / 60).rounded(.up)) },
            set: { ttlSeconds = min(Double($0 * 60), ttlCeiling) })
    }

    private var lease: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Access expires after")
                .font(.subheadline.weight(.semibold))
            HStack(spacing: 10) {
                Slider(value: $ttlSeconds, in: 60...ttlCeiling, step: 60)
                    .accessibilityLabel("Access expires after")
                    .accessibilityValue(Self.duration(UInt64(ttlSeconds)))
                    .accessibilityIdentifier("ks.approval.ttlSlider")
                // The exact value, and the keyboard's way in: a slider takes key focus only with
                // Full Keyboard Access on, and this is the one control on the sheet that changes
                // what is granted (`ExactNumberField`, ui-spec.md §10.2 and §13).
                ExactNumberField(
                    label: String(localized: "Access expires after, in minutes"),
                    value: ttlMinutes,
                    range: 1...Int((ttlCeiling / 60).rounded(.up)),
                    identifier: "ks.approval.ttlMinutes")
                Text("min")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(Self.duration(UInt64(ttlSeconds)))
                    .font(.callout.monospacedDigit())
                    .frame(width: 90, alignment: .trailing)
                    .accessibilityIdentifier("ks.approval.ttlValue")
            }
            (isFill
                ? Text("“Allow for this session” lets this item fill on this website for that long without showing this sheet again. A fill asks for Touch ID or your login password unless you confirmed recently, and locking the vault ends both.")
                : Text("The caller asked for \(Self.duration(request.requestedTtlSeconds)). You can shorten it, never lengthen it."))
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
        if request.action == .storeCommandOutput {
            return "This runs the command once and stores what it prints as a secret. The agent never receives the output, and each run asks for Touch ID."
        }
        if request.action == .createTestLogin {
            return String(localized: "This saves a new login in the Agent test logins vault with a password kagisecure generates. The agent never receives the password, and each create here asks for Touch ID.")
        }
        if request.action == .fillCredential {
            let fields = request.fillFields.joined(separator: " and ")
            // `origin` is `Url::origin().ascii_serialization()` and is shown exactly as it
            // arrived: nothing in this app decodes punycode back into the lookalike it encodes,
            // because that field is the one a human can use to spot a homograph. `safe` is a
            // no-op on an ASCII serialization and is applied only so that a malformed one cannot
            // carry invisible characters either.
            let fieldsText = safe(fields, limit: 80)
            let item = safe(request.itemTitle ?? String(localized: "this item"))
            let origin = safe(request.origin ?? String(localized: "this page"), limit: 120)
            return String(localized: "This sends the \(fieldsText) for “\(item)” to \(origin), once. Nothing else is sent, and nothing is stored in the browser.")
        }
        guard request.mintsLease else {
            return String(localized: "This changes the structure of your vault. It grants no access to any value.")
        }
        if request.stdinDelivery {
            let names = request.variables.isEmpty
                ? "no variables" : safe(request.variables.joined(separator: ", "), limit: 100)
            return "This passes \(names) to this one run of the command. The next run asks again."
        }
        let names = request.variables.isEmpty
            ? String(localized: "no variables") : safe(request.variables.joined(separator: ", "), limit: 100)
        let place = safe(request.directory ?? request.targetPath ?? String(localized: "this directory"), limit: 100)
        let time = Self.duration(ttlSeconds)
        let uses = Int(request.requestedUses)
        return uses == 1
            ? String(localized: "This grants access to \(names) in \(place) for \(time), up to \(uses) use.")
            : String(localized: "This grants access to \(names) in \(place) for \(time), up to \(uses) uses.")
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
            // Out of the scroll area and next to the buttons, so the TTL is on screen whenever
            // "Allow for this session" is — it is that button's argument, and a sheet with a
            // long variable list used to scroll it out of sight (ui-spec.md §10.2).
            // A stdin delivery is one run, whatever is picked here (ADR-0047): no lease to size.
            if (request.mintsLease && !request.stdinDelivery && request.action != .storeCommandOutput) || isFill {
                lease
                Divider()
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
            HStack {
                Spacer()
                // Deny first, and nothing is the default action: Return does nothing here
                // (ui-spec.md §11), Esc denies.
                Button("Deny") { agent.deny(request) }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.approval.deny")
                Button("Allow once") { approve(.allowOnce) }
                    .accessibilityIdentifier("ks.approval.allowOnce")
                if !request.stdinDelivery && request.action != .createTestLogin
                    && request.action != .storeCommandOutput {
                    Button("Allow for this session") {
                        approve(.allowSession(ttlSeconds: UInt64(ttlSeconds), uses: request.requestedUses))
                    }
                    .accessibilityIdentifier("ks.approval.allowSession")
                }
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
                biometricProblem = String(localized: "Authentication cancelled. Nothing has been granted.")
            case .unavailable(let why):
                biometricProblem = String(localized: "Could not ask for authentication: \(why)")
            case .busy:
                // Another prompt — a reveal, a copy, another fill — is on screen. Not raised beside
                // it (ADR-0037 §3, ADR-0038 §6): the sheet stays, to be answered once it is gone.
                biometricProblem =
                    String(localized: "Another confirmation is already on screen. Finish or cancel it, then try again.")
            }
        }
    }

    /// A caption over a value — "File" over the path it names.
    ///
    /// `identifier` goes on the **value**, the leaf a reader (or a test) wants, and not on the
    /// stack: an identifier on a SwiftUI layout container is stamped onto every leaf inside it
    /// (ui-spec.md §15), so `ks.approval.targetPath` on the `VStack` named the caption "File" as
    /// well as the path, and the first element answering to it was the caption.
    static func row(_ label: LocalizedStringKey, _ value: String, identifier: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier(identifier)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// `900` → `15 minutes`. Used on the sheet and in the leases table, so they agree.
    static func duration(_ seconds: UInt64) -> String {
        if seconds < 60 { return String(localized: "\(seconds) s") }
        let minutes = seconds / 60
        if minutes < 60 {
            return minutes == 1
                ? String(localized: "\(minutes) minute") : String(localized: "\(minutes) minutes")
        }
        let hours = Double(seconds) / 3600
        return String(format: String(localized: "%.1f hours"), hours)
    }
}

/// A release from a shared vault (ADR-0035 §14): where the values come from, and every value that
/// changed since this Mac last approved releasing it — or is released from this Mac for the first
/// time — with who changed it and when. Nothing at all for the personal vault. Shared by the
/// approval sheet and the agent-fill sheet.
///
/// Every line is a name, a label this Mac's person typed, and a time — never a value — and is
/// sanitized like every other string on the sheet.
struct SharedSourceFacts: View {
    let request: ApprovalRequestView

    var body: some View {
        if let source = request.sharedSource {
            VStack(alignment: .leading, spacing: 6) {
                ApprovalSheet.row(
                    "From", ApprovalSheet.safe(source, limit: 160),
                    identifier: "ks.approval.sharedSource")
                if !request.changedSinceApproval.isEmpty {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(request.changedSinceApproval.enumerated()), id: \.offset) {
                                _, line in
                                Text(ApprovalSheet.safe(line, limit: 200))
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    } icon: {
                        Image(systemName: "arrow.triangle.2.circlepath")
                    }
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                    .accessibilityIdentifier("ks.approval.changedSinceApproval")
                }
            }
        }
    }
}

/// The browser half of a fill's identity: the native messaging helper's verdict and the browser's,
/// stacked, with the pinned extension id and both processes below them (ui-spec.md §10.5).
///
/// Two rows rather than one word, because on this build they genuinely differ: Chrome is signed by
/// its vendor and can be *verified*; a `cargo build` native host is ad-hoc and cannot. Collapsing
/// them would either claim a verification our own helper does not have, or discard the one real
/// fact on the sheet. Shared by the browser-fill sheet and the agent-fill sheet (§10.7), which
/// show the browser identically because the value lands in it the same way.
struct BrowserIdentityBlock: View {
    let fillSignature: FillSignature?
    let extensionId: String?
    let hostExecutable: String?
    let hostPid: UInt32?
    let browserExecutable: String?
    let browserPid: UInt32?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Self.verdictRow(
                String(localized: "Browser"), fillSignature?.browser,
                fallback: String(localized: "No recognized browser launched the helper."))
                .accessibilityIdentifier("ks.approval.verdict.browser")
            Self.verdictRow(
                String(localized: "Helper"), fillSignature?.host,
                fallback: String(localized: "The helper could not be checked."))
                .accessibilityIdentifier("ks.approval.verdict.helper")
            if let extensionId {
                Text("Extension \(extensionId) — pinned in this app and in the browser's manifest.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("ks.approval.extensionId")
            }
            if let hostExecutable {
                ApprovalSheet.row(
                    "Helper process", "\(hostExecutable)  ·  pid \(hostPid.map(String.init) ?? "?")",
                    identifier: "ks.approval.helperProcess")
            }
            if let browserExecutable {
                ApprovalSheet.row(
                    "Browser process",
                    "\(browserExecutable)  ·  pid \(browserPid.map(String.init) ?? "?")",
                    identifier: "ks.approval.browserProcess")
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }

    /// A green "verified" or red "unverified" label over the evidence line.
    static func verdictRow(
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
}
