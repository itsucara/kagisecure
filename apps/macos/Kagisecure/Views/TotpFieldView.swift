import SwiftUI

import KagisecureFFI

/// A live one-time password with the countdown ring from ui-spec.md §4.2.
///
/// # Why it recomputes rather than counts down
///
/// The obvious implementation keeps the code and decrements a number once a second. That drifts:
/// `Timer` fires late under load, and after ten minutes the ring and the code disagree about
/// which window they are in — which is precisely the roadmap's soak-test criterion. So every tick
/// asks Rust for the code *at the current wall-clock second* instead. `Totp::code_at` is one
/// HMAC; doing it once a second costs nothing measurable, and it cannot drift because it never
/// counts.
struct TotpFieldView: View {
    @Bindable var store: VaultStore
    let item: ItemView
    let field: FieldView

    @State private var snapshot: TotpSnapshot?
    @State private var failure: String?
    @State private var copied = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            content
                .onChange(of: context.date) { _, _ in refresh() }
        }
        .onAppear(perform: refresh)
        .onChange(of: field.id) { _, _ in refresh() }
    }

    @ViewBuilder
    private var content: some View {
        if let failure {
            Label(failure, systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("ks.totp.error")
        } else if let snapshot {
            HStack(spacing: 12) {
                Button(action: copy) {
                    TotpRing(snapshot: snapshot)
                }
                .buttonStyle(.plain)
                .help("Copy the code")
                .accessibilityLabel("Copy the one-time password")
                .accessibilityIdentifier("ks.totp.ring")

                VStack(alignment: .leading, spacing: 2) {
                    Text(snapshot.grouped)
                        .font(.system(.title2, design: .monospaced).weight(.medium))
                        .foregroundStyle(snapshot.isExpiring ? AnyShapeStyle(.orange) : AnyShapeStyle(.primary))
                        .contentTransition(.numericText())
                        .animation(.default, value: snapshot.code)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("ks.totp.code")
                    if let caption = snapshot.caption {
                        Text(caption)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("ks.totp.caption")
                    }
                }

                Spacer(minLength: 4)

                Button(action: copy) {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .keyboardShortcut("c", modifiers: [.command, .option])
                .help("Copy the code (⌥⌘C)")
                .accessibilityLabel("Copy the one-time password")
                .accessibilityIdentifier("ks.totp.copy")
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel(
                "One-time password \(snapshot.grouped), \(snapshot.secondsRemaining) seconds left")
            .accessibilityIdentifier("ks.totp.field")
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }

    private func refresh() {
        do {
            let view = try store.session.totpCode(
                itemId: item.id, fieldId: field.id, at: TotpCountdown.unixNow())
            if snapshot?.code != view.code {
                copied = false
            }
            snapshot = TotpSnapshot(view)
            failure = nil
        } catch {
            snapshot = nil
            failure = VaultStore.message(for: error)
        }
    }

    private func copy() {
        guard let snapshot else { return }
        PasteboardService.copy(snapshot.code, label: field.label)
        copied = true
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
            Text("\(snapshot.secondsRemaining)")
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

    /// The URI already stored on the field, if this is an edit rather than a first setup.
    var existingUri: String = ""
    /// Where the finished `otpauth://` URI goes.
    let onSave: (String) -> Void

    @State private var mode: SetupMode = .uri
    @State private var uriText = ""
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
        .onAppear {
            guard !existingUri.isEmpty else { return }
            uriText = existingUri
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
                "This is what a service's QR code encodes. Most sites offer it as “can't scan the "
                    + "code?” — the whole URI, including the secret."
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
                        Text(snapshot.caption ?? "Check this against the service before saving.")
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
                    Text(
                        mode == .uri
                            ? "Paste a URI to see the code it produces."
                            : "Enter a Base32 secret to see the code it produces.")
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
