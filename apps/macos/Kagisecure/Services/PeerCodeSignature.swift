import Foundation
import Security

/// What a code-signature check concluded about a connecting process.
struct PeerSignature: Equatable, Sendable {
    /// Whether the peer satisfied the requirement below.
    let verified: Bool
    /// One line for the sheet and for the audit log: an identifier and team, or why not.
    let evidence: String

    /// The honest answer when there was no pid to check.
    static let noPeer = PeerSignature(verified: false, evidence: "no process id to check")
}

/// What was established about a browser-extension fill: the process on the socket, and — on the
/// Chromium front end only — the browser above it.
///
/// On Chromium both are shown, because they answer different questions and one of them can be
/// genuinely *verified* on a machine where the other cannot. Chrome is signed by Google with a
/// Developer ID; `kagisecure-nmhost` built from source is ad-hoc. Collapsing the pair into one
/// word would either claim a verification the native host does not have, or throw away the one
/// real fact on the sheet.
///
/// On Safari there is one process — our own app extension — and `browser` is `nil`. That is the
/// truthful shape: Safari is not on the socket, nothing inspected it, and a second verdict here
/// would be about a process nobody looked at (ADR-0024 §5).
struct FillSignature: Equatable, Sendable {
    /// Which front end the fill arrived on, and therefore how many verdicts there are to combine.
    ///
    /// An explicit case rather than "`browser` is `nil`", because on the Chromium front end a
    /// missing browser verdict means *the browser could not be established*, which must never
    /// pass — and on the Safari front end it means *there is no second process*, which must not
    /// fail. One `nil` cannot honestly mean both.
    enum Peer: Equatable, Sendable {
        /// `kagisecure-nmhost`, with a browser above it. Two processes, two verdicts.
        case nativeMessagingHost
        /// The Safari app extension inside our own bundle. One process, one verdict.
        case appExtension
    }

    /// Which front end this is.
    var peer: Peer = .nativeMessagingHost
    /// The process that connected: the native messaging host, or the Safari app extension.
    let host: PeerSignature
    /// The browser the app established launched it. Always `nil` on the Safari front end.
    let browser: PeerSignature?

    /// Whether every verdict that was actually taken checks out.
    ///
    /// On Chromium that is both halves — and a missing browser half is a failure, not an excuse —
    /// so it is false on any build whose own native messaging host is ad-hoc. On Safari it is the
    /// one half there is, which is why a Developer-ID-signed build can reach a genuinely verified
    /// fill through Safari and cannot through Chrome.
    var verified: Bool {
        switch peer {
        case .appExtension:
            return host.verified
        case .nativeMessagingHost:
            return host.verified && (browser?.verified ?? false)
        }
    }
}

/// The macOS half of architecture.md §5: given the kernel's pid for the peer, decide whether the
/// process behind it is a signed kagisecure sidecar.
///
/// # Why this is Swift and not Rust
///
/// `SecCodeCopyGuestWithAttributes` and `SecCodeCheckValidity` live in Security.framework.
/// Reaching them from `kagisecure-core` would mean `unsafe` in a crate that is
/// `forbid(unsafe_code)`, a CoreFoundation dependency in the shared core, and platform integration
/// on the wrong side of the layering rule — the same argument
/// [ADR-0008](../../../../docs/decisions/0008-ffi-secret-crossings.md) makes for the Secure
/// Enclave. So the check happens here, the verdict is shown on the sheet, and the verdict travels
/// *down* into Rust with the decision, where it is written into the lease and the audit entry.
///
/// # What "verified" means here, exactly
///
/// Three things must hold, and the evidence string says which one failed when one does:
///
/// 1. the pid resolves to a `SecCode` (the process exists and is inspectable);
/// 2. `SecCodeCheckValidity` passes against a **designated requirement built from this app's own
///    signing identity** — same team, for a Developer ID build; ad-hoc self-signed pairs cannot
///    express "same signer", so an ad-hoc build only gets to say "signed, ad-hoc" and reports
///    `verified: false`, which is the truthful answer rather than a flattering one;
/// 3. the signing identifier is one of ours.
///
/// A caller that fails any of these still reaches the sheet. It is shown with the red
/// "Unverified — proceed with caution" banner ui-spec.md §10.2 specifies, because refusing
/// outright would break everyone who builds the sidecar from source — architecture.md §5's own
/// assumption, kept.
struct PeerCodeSignature: Sendable {
    /// Signing identifiers this app recognizes as its own sidecar.
    ///
    /// A prefix match rather than an exact one, because `codesign`'s ad-hoc identifier for a
    /// `cargo build` binary is the file name plus a content hash (`kagisecure_mcp-43e7de07…`).
    /// Matching the prefix lets the sheet say "an ad-hoc kagisecure sidecar" instead of "not a
    /// kagisecure sidecar", which is the difference between a true statement and a misleading
    /// one. It grants nothing: an ad-hoc signature is still reported `verified: false`.
    static let knownIdentifierPrefixes = ["kagisecure-mcp", "kagisecure_mcp", "com.kagisecure.mcp"]

    /// Signing identifiers this app recognizes as its own native messaging host (M6).
    ///
    /// Separate from the sidecar list rather than merged into it, so that a *sidecar* connecting
    /// to the extension socket, or a native host connecting to the MCP socket, is reported as what
    /// it is rather than waved through because it is also ours.
    static let knownHostIdentifierPrefixes = [
        "kagisecure-nmhost", "kagisecure_nmhost", "com.kagisecure.nmhost",
    ]

    /// The bundle identifier of the Safari Web Extension shipped inside this app.
    ///
    /// Matches `kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID`. Unlike a browser's, this is
    /// checked against **our own** team: the app extension is our code, in our bundle, signed with
    /// our identity — which is why the Safari front end's identity evidence is stronger than the
    /// Chromium one's rather than weaker (ADR-0024 §5).
    static let safariExtensionIdentifier = "com.kagisecure.app.safari-extension"

    /// Signing identifiers of browsers this app recognizes, with the team that must own them.
    ///
    /// A team identifier is required here where the sidecar check compares against *our* team,
    /// because a browser is by definition somebody else's program. A hardcoded team is exactly
    /// what ADR-0015 avoided for our own binaries and exactly what is needed for a third party's:
    /// "signed by Google" is a claim only Google's team identifier can support.
    static let knownBrowsers: [(identifier: String, team: String, name: String)] = [
        ("com.google.Chrome", "EQHXZ8M8AV", "Google Chrome"),
        ("com.google.Chrome.beta", "EQHXZ8M8AV", "Google Chrome Beta"),
        ("com.google.Chrome.dev", "EQHXZ8M8AV", "Google Chrome Dev"),
        ("com.google.Chrome.canary", "EQHXZ8M8AV", "Google Chrome Canary"),
        ("com.microsoft.edgemac", "UBF8T346G9", "Microsoft Edge"),
        ("company.thebrowser.Browser", "S6N382Y83G", "Arc"),
        ("com.brave.Browser", "KL8N8XSYF4", "Brave Browser"),
    ]

    /// Whether `identifier` names one of our sidecars.
    static func isKnown(_ identifier: String) -> Bool {
        knownIdentifierPrefixes.contains { identifier.hasPrefix($0) }
    }

    /// Whether `identifier` names one of our native messaging hosts.
    static func isKnownHost(_ identifier: String) -> Bool {
        knownHostIdentifierPrefixes.contains { identifier.hasPrefix($0) }
    }

    init() {}

    /// What `SecCodeCopySigningInformation` had to say about a process.
    private struct SigningInfo {
        let identifier: String?
        let teamID: String?
        let adhoc: Bool
    }

    /// The two outcomes of looking at a process: what it is signed as, or why we cannot tell.
    ///
    /// A plain enum rather than `Result`, because `Result`'s failure type must conform to `Error`
    /// and `PeerSignature` is not an error — it is a verdict, and one that reaches the sheet
    /// either way.
    private enum Inspection {
        case signed(SigningInfo)
        case refused(PeerSignature)
    }

    /// Resolve `pid` and read its signature, or return the `PeerSignature` explaining why not.
    ///
    /// Shared by all three checks below, so "the process exists, is inspectable, and its pages
    /// match its signature" is established once and worded once.
    private func inspect(pid: UInt32) -> Inspection {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        guard status == errSecSuccess, let code else {
            return .refused(
                PeerSignature(
                    verified: false,
                    evidence: "the system would not inspect pid \(pid) (\(Self.describe(status)))"))
        }

        // A dynamic validity check: the pages the process is running are the pages it was signed
        // with, and the signature itself is intact.
        let valid = SecCodeCheckValidity(code, [], nil)
        guard valid == errSecSuccess else {
            return .refused(
                PeerSignature(
                    verified: false,
                    evidence: "unsigned or invalid signature (\(Self.describe(valid)))"))
        }

        var infoRef: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            unsafeBitCast(code, to: SecStaticCode.self),
            SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef)
        guard infoStatus == errSecSuccess, let info = infoRef as? [String: Any] else {
            return .refused(
                PeerSignature(
                    verified: false,
                    evidence: "signature present but unreadable (\(Self.describe(infoStatus)))"))
        }

        return .signed(
            SigningInfo(
                identifier: info[kSecCodeInfoIdentifier as String] as? String,
                teamID: info[kSecCodeInfoTeamIdentifier as String] as? String,
                // `kSecCodeSignatureAdhoc` is 2. An ad-hoc signature binds a binary to nothing: it
                // proves the bytes have not changed since *somebody* signed them, and says nothing
                // about who.
                adhoc: ((info[kSecCodeInfoFlags as String] as? UInt32 ?? 0) & 2) != 0))
    }

    /// Check the process behind `pid` against the sidecar requirement.
    func check(pid: UInt32?) -> PeerSignature {
        checkOurs(pid: pid, isKnown: Self.isKnown, what: "a kagisecure sidecar")
    }

    /// Check the process behind `pid` against the native-messaging-host requirement (M6).
    func checkHost(pid: UInt32?) -> PeerSignature {
        checkOurs(pid: pid, isKnown: Self.isKnownHost, what: "a kagisecure native messaging host")
    }

    /// The shared body of the two checks above: one of ours, signed by us, not ad-hoc.
    private func checkOurs(
        pid: UInt32?, isKnown: (String) -> Bool, what: String
    ) -> PeerSignature {
        guard let pid else { return .noPeer }
        let info: SigningInfo
        switch inspect(pid: pid) {
        case .signed(let value): info = value
        case .refused(let refusal): return refusal
        }

        let name = info.identifier ?? "unknown identifier"
        guard let identifier = info.identifier, isKnown(identifier) else {
            return PeerSignature(
                verified: false,
                evidence:
                    "signed as \(name)\(info.teamID.map { " (team \($0))" } ?? ""), not \(what)")
        }
        if info.adhoc {
            return PeerSignature(
                verified: false,
                evidence: "\(identifier), ad-hoc signed — identity not attributable to a developer")
        }
        guard let teamID = info.teamID, teamID == Self.ownTeamIdentifier() else {
            return PeerSignature(
                verified: false,
                evidence: "\(identifier) is signed by a different team (\(info.teamID ?? "none"))")
        }
        return PeerSignature(verified: true, evidence: "\(identifier) (team \(teamID))")
    }

    /// Check the process behind `pid` against the *browser* requirement (M6).
    ///
    /// Unlike the two checks above, this compares against a **hardcoded** team identifier per
    /// browser. That is the opposite of what ADR-0015 decided for our own binaries, and for the
    /// opposite reason: our own team is knowable at runtime from `SecCodeCopySelf`, and a browser
    /// vendor's is not. "Signed by Google" is a claim that only Google's team identifier supports,
    /// and a check that accepted any valid signature would accept a signed program called
    /// `Google Chrome` from anybody with a Developer ID.
    ///
    /// This is the one check in the app that can report **verified** on an ad-hoc build of
    /// kagisecure, because the browser is not ours and is signed by its vendor. The fill sheet
    /// shows it next to the native host's verdict rather than instead of it.
    func checkBrowser(pid: UInt32?) -> PeerSignature {
        guard let pid else { return .noPeer }
        let info: SigningInfo
        switch inspect(pid: pid) {
        case .signed(let value): info = value
        case .refused(let refusal): return refusal
        }

        let name = info.identifier ?? "unknown identifier"
        guard let identifier = info.identifier,
            let known = Self.knownBrowsers.first(where: { $0.identifier == identifier })
        else {
            return PeerSignature(
                verified: false, evidence: "signed as \(name), which is not a browser this app knows")
        }
        if info.adhoc {
            return PeerSignature(
                verified: false, evidence: "\(known.name) is ad-hoc signed — that is not \(known.name)")
        }
        guard let teamID = info.teamID, teamID == known.team else {
            return PeerSignature(
                verified: false,
                evidence:
                    "\(identifier) is signed by team \(info.teamID ?? "none"), not \(known.name)'s "
                    + "(\(known.team))")
        }
        return PeerSignature(verified: true, evidence: "\(known.name) (team \(teamID))")
    }

    /// Check the process behind `pid` against the **Safari app extension** requirement (M6b).
    ///
    /// The odd one out among the three, and in the direction that helps: a browser is somebody
    /// else's program and is checked against a hardcoded vendor team, but the Safari extension is
    /// *ours*, in our own bundle, so it is checked against our own team exactly as the sidecar and
    /// the native messaging host are. That means a Developer-ID-signed build can report the Safari
    /// front end **verified** on both halves, which no Chromium build of ours can — there, our own
    /// native messaging host is the half that cannot be attributed (ADR-0024 §5).
    func checkSafariExtension(pid: UInt32?) -> PeerSignature {
        checkOurs(
            pid: pid,
            isKnown: { $0 == Self.safariExtensionIdentifier },
            what: "this app's Safari extension")
    }

    /// Both halves of a browser-extension fill.
    ///
    /// On the Chromium front end those are two different processes — the native messaging host we
    /// ship, and the browser above it — and they get two verdicts because one can be verified on a
    /// machine where the other cannot.
    ///
    /// On the Safari front end there is only **one** process: the app extension. Safari itself is
    /// never on the socket, so there is no second pid to inspect and the sheet says so rather than
    /// inventing a verdict about a process nobody looked at.
    func checkFill(hostPid: UInt32?, browserPid: UInt32?, isAppExtension: Bool) -> FillSignature {
        if isAppExtension {
            return FillSignature(
                peer: .appExtension, host: checkSafariExtension(pid: hostPid), browser: nil)
        }
        return FillSignature(
            peer: .nativeMessagingHost,
            host: checkHost(pid: hostPid),
            browser: browserPid.map { checkBrowser(pid: $0) })
    }

    /// This app's own team identifier, or `nil` when it has none (an ad-hoc build).
    ///
    /// Comparing against our own team rather than a hardcoded one means a fork that signs both
    /// halves with its own identity works, and a stranger's signed binary does not.
    static func ownTeamIdentifier() -> String? {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else { return nil }
        var infoRef: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                unsafeBitCast(selfCode, to: SecStaticCode.self),
                SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
            let info = infoRef as? [String: Any]
        else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private static func describe(_ status: OSStatus) -> String {
        SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
    }
}
