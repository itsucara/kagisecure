import SwiftUI

import KagisecureFFI

/// A one-time password in the detail pane, with the countdown ring from ui-spec.md §4.2.
///
/// # Masked until touched (ADR-0038 user decision 2)
///
/// The code is a secret for as long as it is valid, so the field starts masked. "Show" asks for
/// presence once and starts it running live, from a `TotpRelease`, for at most five minutes after
/// that touch — use does not extend it — or until the item is deselected or the vault locks.
/// Copying a running code needs no second touch; copying a masked one is its own one-use release
/// and its own touch (the ring, the button, ⌥⌘C alike).
///
/// # Why it recomputes rather than counts down
///
/// The obvious implementation keeps the code and decrements a number once a second. That drifts:
/// `Timer` fires late under load, and after ten minutes the ring and the code disagree about
/// which window they are in — which is precisely the roadmap's soak-test criterion. So every tick
/// asks the release for the code *at the current wall-clock second* instead (`codeAt`). That is
/// one HMAC; doing it once a second costs nothing measurable, and it cannot drift because it
/// never counts.
struct TotpFieldView: View {
    @Bindable var store: VaultStore
    let item: ItemView
    let field: FieldView

    @State private var snapshot: TotpSnapshot?
    @State private var copied = false

    private var releases: ItemReleases { store.releases }
    private var live: Bool { releases.isLive(totp: field) }

    var body: some View {
        Group {
            if live {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    running
                        .onChange(of: context.date) { _, _ in refresh() }
                }
                .onAppear(perform: refresh)
            } else {
                masked
            }
        }
        // A hidden code leaves nothing behind in the view's own state.
        .onChange(of: live) { _, isLive in
            if !isLive {
                snapshot = nil
                copied = false
            }
        }
    }

    // MARK: - Masked

    private var masked: some View {
        HStack(spacing: 12) {
            Text("••• •••")
                .font(.system(.title2, design: .monospaced).weight(.medium))
                .foregroundStyle(.secondary)
                .accessibilityLabel(ItemReleases.concealedLabel(field.label, action: String(localized: "Show")))
                .accessibilityIdentifier("ks.totp.masked")
            Button("Show") {
                store.attemptRelease { try await releases.showTotp(item: item, field: field) }
            }
            .buttonStyle(.bordered)
            .disabled(releases.pending != nil)
            .help("Show the code (⌘R)")
            .accessibilityLabel("Show the one-time password")
            .accessibilityIdentifier("ks.totp.show")
            Spacer(minLength: 4)
            copyButton
        }
    }

    // MARK: - Running

    @ViewBuilder
    private var running: some View {
        if let snapshot {
            HStack(spacing: 12) {
                Button(action: copy) {
                    TotpRing(snapshot: snapshot)
                }
                .buttonStyle(.plain)
                .help("Copy the code")
                .accessibilityLabel("Copy the one-time password")
                .accessibilityIdentifier("ks.totp.ring")

                VStack(alignment: .leading, spacing: 2) {
                    // No `.textSelection`: a code is a secret for its whole window, and selecting
                    // it would carry it past the concealed pasteboard type and the timed clear
                    // (ADR-0038 surface #2). The ring and the copy button are the way out.
                    Text(snapshot.grouped)
                        .font(.system(.title2, design: .monospaced).weight(.medium))
                        .foregroundStyle(snapshot.isExpiring ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
                        .contentTransition(.numericText())
                        .animation(.default, value: snapshot.code)
                        .accessibilityIdentifier("ks.totp.code")
                    if let caption = snapshot.caption {
                        Text(caption)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("ks.totp.caption")
                    }
                }

                Spacer(minLength: 4)

                Button {
                    releases.hideTotp(field)
                } label: {
                    Image(systemName: "eye.slash")
                }
                .buttonStyle(.borderless)
                .help("Hide the code (⌘R)")
                .accessibilityLabel("Hide the one-time password")
                .accessibilityIdentifier("ks.totp.hide")

                copyButton
            }
            // The code is spoken once shown — necessary for a VoiceOver user to use it at all, and
            // the same value that is on screen for everybody else (W-19). Masked, it is not.
            .accessibilityElement(children: .contain)
            .accessibilityLabel(
                "One-time password \(snapshot.grouped), \(Int(snapshot.secondsRemaining)) seconds left")
            .accessibilityIdentifier("ks.totp.field")
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }

    private var copyButton: some View {
        Button(action: copy) {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .disabled(!live && releases.pending != nil)
        .keyboardShortcut("c", modifiers: [.command, .option])
        .help(live ? Text("Copy the code (⌥⌘C)") : Text("Copy the code without showing it (⌥⌘C)"))
        .accessibilityLabel("Copy the one-time password")
        .accessibilityIdentifier("ks.totp.copy")
    }

    private func refresh() {
        guard let view = releases.totpCode(field, at: TotpCountdown.unixNow()) else {
            snapshot = nil
            return
        }
        if snapshot?.code != view.code {
            copied = false
        }
        snapshot = TotpSnapshot(view)
    }

    private func copy() {
        store.attemptRelease {
            try await releases.copyTotp(item: item, field: field)
            copied = true
        }
    }
}

/// The ring itself: a track, an arc that empties over the period, and the digit count in the
/// middle so a glance says both "how long" and "is this the 6- or 8-digit one".
struct TotpRing: View {
    let snapshot: TotpSnapshot
    var diameter: CGFloat = 30

    var body: some View {
        ZStack {
            Circle()
                .stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: snapshot.fraction)
                .stroke(
                    snapshot.isExpiring ? AnyShapeStyle(.orange) : AnyShapeStyle(.tint),
                    style: StrokeStyle(lineWidth: 3, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 0.9), value: snapshot.fraction)
            Text(verbatim: "\(snapshot.secondsRemaining)")
                .font(.system(size: diameter * 0.38, weight: .medium, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
        .frame(width: diameter, height: diameter)
        .accessibilityHidden(true)
    }
}

// -------------------------------------------------------------------------------------------
// Setup
// -------------------------------------------------------------------------------------------

/// The one-time-password setup flow (ui-spec.md §9): paste a URI, or type the secret by hand.
///
/// Both paths end in an `otpauth://` URI, because that is what the field stores
/// (vault-format.md §5.3) and because assembling it in Rust means one implementation of the
/// escaping rules rather than two. Whichever path is used, a live preview appears before anything
/// is saved — a wrong secret is otherwise a silent failure discovered at the next login.
///
/// QR scanning is not here; see the roadmap's M5 notes.
struct TotpSetupSheet: View {
    @Environment(\.dismiss) private var dismiss

    /// For a field that is already set up: fetch its stored setup, behind its own presence
    /// prompt (`EditReveal`). `nil` for a new field. The sheet never prefills on its own
    /// (ADR-0038 §5, user decision 4) — this runs only when the person presses
    /// "Show current setup".
    var revealExisting: (() async -> String?)?

    /// Where the finished `otpauth://` URI goes.
    let onSave: (String) -> Void

    @State private var mode: SetupMode = .uri
    @State private var uriText = ""
    /// The stored setup exactly as "Show current setup" put it in `uriText`, until it is masked
    /// again or edited — what the five-minute cap compares against (`EditReveal`).
    @State private var shownUri: String?
    @State private var secretText = ""
    @State private var issuer = ""
    @State private var account = ""
    @State private var algorithm: TotpAlgorithm = .sha1
    @State private var digits = 6
    @State private var period = 30

    enum SetupMode: Hashable {
        case uri
        case manual
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Add a one-time password", systemImage: "clock.badge.checkmark")
                .font(.title3.weight(.semibold))

            Picker("How", selection: $mode) {
                Text("Paste otpauth:// URI").tag(SetupMode.uri)
                Text("Enter the secret").tag(SetupMode.manual)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("ks.totpSetup.mode")

            if let revealExisting, uriText.isEmpty {
                Button {
                    Task {
                        if let uri = await revealExisting() {
                            mode = .uri
                            uriText = uri
                            shownUri = uri
                        }
                    }
                } label: {
                    Label("Show current setup", systemImage: "eye")
                }
                .buttonStyle(.borderless)
                .help("Asks for Touch ID or your Mac password, then fills in the stored setup")
                .accessibilityIdentifier("ks.totpSetup.showCurrent")
            }

            switch mode {
            case .uri: uriForm
            case .manual: manualForm
            }

            Divider()
            preview

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("ks.totpSetup.cancel")
                Button("Save") {
                    if let uri = composedUri {
                        onSave(uri)
                        dismiss()
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(composedUri == nil)
                .accessibilityIdentifier("ks.totpSetup.save")
            }
        }
        .padding(22)
        .frame(width: 480)
        // User decision 5: a seed shown to edit is cleared again at five minutes if untouched,
        // like every other value shown in edit mode. Clearing it keeps the stored setup: the sheet
        // only ever writes what Save composes.
        .task(id: shownUri) {
            guard shownUri != nil else { return }
            try? await Task.sleep(for: EditReveal.lifetime)
            guard !Task.isCancelled else { return }
            if EditReveal.shouldRemask(shown: shownUri, current: uriText) {
                uriText = ""
            }
            shownUri = nil
        }
    }

    private var uriForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("otpauth://totp/Service:you@example.com?secret=…", text: $uriText, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .font(.system(.callout, design: .monospaced))
                .lineLimit(2...4)
                .accessibilityIdentifier("ks.totpSetup.uri")
            Text(
                "This is what a service's QR code encodes. Most sites offer it as “can't scan the code?” — the whole URI, including the secret."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var manualForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledContent("Secret") {
                TextField("Base32, spaces and case ignored", text: $secretText)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.callout, design: .monospaced))
                    .labelsHidden()
                    .accessibilityIdentifier("ks.totpSetup.secret")
            }
            LabeledContent("Service") {
                TextField("GitHub", text: $issuer)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .accessibilityIdentifier("ks.totpSetup.issuer")
            }
            LabeledContent("Account") {
                TextField("you@example.com", text: $account)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .accessibilityIdentifier("ks.totpSetup.account")
            }
            HStack(spacing: 14) {
                Picker("Algorithm", selection: $algorithm) {
                    Text("SHA-1").tag(TotpAlgorithm.sha1)
                    Text("SHA-256").tag(TotpAlgorithm.sha256)
                    Text("SHA-512").tag(TotpAlgorithm.sha512)
                }
                .frame(width: 190)
                .accessibilityIdentifier("ks.totpSetup.algorithm")
                Picker("Digits", selection: $digits) {
                    Text("6").tag(6)
                    Text("7").tag(7)
                    Text("8").tag(8)
                }
                .frame(width: 110)
                .accessibilityIdentifier("ks.totpSetup.digits")
            }
            Stepper("Period  \(period)s", value: $period, in: 10...120, step: 5)
                .accessibilityIdentifier("ks.totpSetup.period")
            Text("SHA-1, six digits and 30 seconds are what almost every service uses.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    /// The live preview from ui-spec.md §9 — the reason this sheet exists rather than a text field.
    private var preview: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let uri = composedUri,
                let view = try? totpPreview(uri: uri, at: TotpCountdown.unixNow())
            {
                let snapshot = TotpSnapshot(view)
                HStack(spacing: 12) {
                    TotpRing(snapshot: snapshot, diameter: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(snapshot.grouped)
                            .font(.system(.title2, design: .monospaced).weight(.medium))
                            .accessibilityIdentifier("ks.totpSetup.previewCode")
                        (snapshot.caption.map { Text($0) } ?? Text("Check this against the service before saving."))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("ks.totpSetup.previewCaption")
                    }
                    Spacer()
                }
                .frame(height: 44)
            } else {
                HStack(spacing: 8) {
                    Image(systemName: "questionmark.circle")
                        .foregroundStyle(.tertiary)
                    (mode == .uri
                        ? Text("Paste a URI to see the code it produces.")
                        : Text("Enter a Base32 secret to see the code it produces."))
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("ks.totpSetup.previewEmpty")
                    Spacer()
                }
                .frame(height: 44)
            }
        }
    }

    /// The URI both paths converge on, or `nil` when what is on screen is not usable yet.
    private var composedUri: String? {
        switch mode {
        case .uri:
            let trimmed = uriText.trimmingCharacters(in: .whitespacesAndNewlines)
            return totpUriIsValid(uri: trimmed) ? trimmed : nil
        case .manual:
            let params = TotpParamsView(
                algorithm: algorithm,
                digits: UInt8(digits),
                period: UInt32(period),
                issuer: issuer.isEmpty ? nil : issuer,
                account: account.isEmpty ? nil : account,
                caption: nil)
            return try? totpUriFromParts(secretBase32: secretText, params: params)
        }
    }
}
