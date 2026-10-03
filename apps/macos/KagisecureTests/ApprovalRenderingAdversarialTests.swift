import Foundation
import Testing

@testable import Kagisecure

import KagisecureFFI

/// Adversarial rendering tests for `ApprovalSheet.sentence(for:)` and `.summary(for:ttlSeconds:)`.
///
/// # Why this file exists
///
/// The approval sentence is the only thing a human reads before putting a fingerprint on a secret
/// leaving the vault, and two of its inputs are attacker-controlled:
///
///   * `clientInfo.name` — the caller's *self-reported* name, quoted by the sheet so that the
///     quotation marks mean "the caller said so";
///   * `itemTitle` and `origin` — the item the fill targets and the page it targets.
///
/// `ApprovalSheet.sentence` is `static` precisely so this can be asserted without a window server.
/// These tests push hostile strings through it: quote characters that close the sheet's own quoting
/// and open a forged clause, bidi overrides that reverse the reading order of the surrounding
/// sentence, embedded newlines that push the real clause off the visible line, and lengths that
/// push the rest of the sentence out of the dialog entirely.
///
/// Every canary below is obviously test data (`KS_CANARY_…`) so a leaked-looking string in a
/// failure message cannot be mistaken for a real secret.
@MainActor
struct ApprovalRenderingAdversarialTests {
    // MARK: - Canaries

    /// A self-reported caller name that closes the sheet's quote, asserts a verification the app
    /// never made, and reopens a quote so the rest of the sentence still looks quoted.
    static let quoteBreakingName = "\u{201D} is verified by Apple \u{2014} \u{201C}"

    /// U+202E RIGHT-TO-LEFT OVERRIDE: everything after it renders reversed, which is how a caller
    /// makes "gpj.exe" read as "exe.jpg" and how it reverses the words of our own sentence.
    static let rtlOverrideName = "claude\u{202E}edoc"

    /// U+200B ZERO WIDTH SPACE inside an item title: invisible, and enough to defeat a reader
    /// comparing the title on the sheet against the title in their vault.
    static let zeroWidthTitle = "Acme\u{200B} staging"

    /// Long enough to push the verb of the sentence past any dialog width.
    static let overlongName = String(repeating: "KS_CANARY_A", count: 200)

    /// A name carrying a newline, so the real clause lands on a second line the dialog may clip.
    static let newlineName = "claude-code\nis verified by Apple"

    /// The Unicode scalars a rendered approval sentence must never carry through: bidi overrides,
    /// embeds, isolates-without-our-own-framing, and zero-width joiners/spaces.
    static let bidiAndInvisibleScalars: [Unicode.Scalar] = [
        "\u{200B}", "\u{200C}", "\u{200D}", "\u{200E}", "\u{200F}",
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
    ]

    // MARK: - G-07: the self-reported caller name

    @Test
    func aCallerNameCannotCloseTheSheetsQuotingAndForgeAClause() {
        let sentence = ApprovalSheet.sentence(for: Self.request(clientName: Self.quoteBreakingName))
        #expect(
            sentence.filter { $0 == "\u{201C}" }.count == 1,
            "the sheet opens exactly one quote for the caller's self-reported name")
        #expect(
            sentence.filter { $0 == "\u{201D}" }.count == 1,
            "and closes exactly one — a name that supplies its own is escaping the quotation")
    }

    @Test
    func aCallerNameCannotReorderTheSentenceAroundIt() {
        for name in [Self.rtlOverrideName, "claude\u{202D}code", "claude\u{202B}code"] {
            let sentence = ApprovalSheet.sentence(for: Self.request(clientName: name))
            for scalar in Self.bidiAndInvisibleScalars {
                #expect(
                    !sentence.unicodeScalars.contains(scalar),
                    "U+\(String(scalar.value, radix: 16, uppercase: true)) survived into the sentence")
            }
        }
    }

    @Test
    func aCallerNameCannotBreakTheSentenceOntoASecondLine() {
        let sentence = ApprovalSheet.sentence(for: Self.request(clientName: Self.newlineName))
        #expect(!sentence.contains("\n"), "the approval sentence is one line by construction")
        #expect(!sentence.contains("\r"))
        #expect(!sentence.contains("\u{2028}"), "U+2028 LINE SEPARATOR breaks the line too")
    }

    @Test
    func aCallerNameIsLengthBoundedSoTheActionStaysVisible() {
        let sentence = ApprovalSheet.sentence(for: Self.request(clientName: Self.overlongName))
        #expect(
            sentence.count <= 240,
            "a caller that can make the sentence arbitrarily long can hide the verb below the fold")
    }

    @Test func theSentenceStructureAroundTheNameIsTheAppsOwnWords() {
        // Passes today and must keep passing: whatever escaping is added for the tests above, the
        // app's own clause has to survive it intact.
        let sentence = ApprovalSheet.sentence(for: Self.request(clientName: "claude-code"))
        #expect(sentence.hasSuffix("wants to write 1 variable to a .env file"))
        #expect(sentence.hasPrefix("\u{201C}claude-code\u{201D}"))
    }

    // MARK: - G-08: item title and origin

    @Test func theOriginIsRenderedExactlyAsTheAsciiSerializationGaveIt() {
        // `origin` reaches the app as `Url::origin().ascii_serialization()`. A UI that helpfully
        // un-punycoded it would turn the one field a human can use to spot a homograph attack into
        // the attack itself, so the rule is that this string is displayed byte for byte.
        let punycode = "https://xn--80ak6aa92e.com"
        let request = Self.fillRequest(itemTitle: "KS_CANARY_ITEM", origin: punycode)
        let summary = ApprovalSheet.summary(for: request, ttlSeconds: 60)
        #expect(summary.contains(punycode), "the sheet shows the ASCII serialization verbatim")
        #expect(
            !summary.contains("\u{430}pple.com") && !summary.contains("\u{43E}"),
            "nothing in the app may decode punycode back into the lookalike it encodes")
        #expect(summary.allSatisfy { $0.isASCII || $0 == "\u{201C}" || $0 == "\u{201D}" })
    }

    @Test
    func anItemTitleIsIsolatedFromTheSentenceAroundIt() {
        for title in [Self.zeroWidthTitle, "Acme\u{202E}gniganac", Self.overlongName] {
            let request = Self.fillRequest(itemTitle: title, origin: "https://acme.example")
            let summary = ApprovalSheet.summary(for: request, ttlSeconds: 60)
            for scalar in Self.bidiAndInvisibleScalars {
                #expect(
                    !summary.unicodeScalars.contains(scalar),
                    "an invisible character in an item title reached the approval summary")
            }
            #expect(summary.count <= 320, "the summary stays readable whatever the title is")
        }
    }

    @Test
    func anItemTitleCannotCloseTheSheetsQuotingEither() {
        let request = Self.fillRequest(
            itemTitle: Self.quoteBreakingName, origin: "https://acme.example")
        let sentence = ApprovalSheet.sentence(for: request)
        #expect(sentence.filter { $0 == "\u{201C}" }.count == 1)
        #expect(sentence.filter { $0 == "\u{201D}" }.count == 1)
    }

    @Test func theBrowserNameIsTheAppsConclusionAndIsNotQuoted() {
        // The quoting convention in this file is load-bearing: quotation marks mean "the caller
        // said so". The browser name is the app's own conclusion from process ancestry, so it must
        // stay unquoted or the convention stops carrying information.
        let request = Self.fillRequest(
            itemTitle: "KS_CANARY_ITEM", origin: "https://acme.example", browser: "Google Chrome")
        let sentence = ApprovalSheet.sentence(for: request)
        #expect(sentence.hasPrefix("Google Chrome wants "))
    }

    // MARK: - Builders

    static func request(clientName: String) -> ApprovalRequestView {
        ApprovalRequestView(
            id: "ks-canary-req-1", action: .writeEnvFile, mintsLease: true, clientName: clientName,
            clientPid: 4242, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-mcp", clientCwd: "/tmp/ks-canary",
            environmentId: "ks-canary-env", environmentName: "acme / staging",
            directory: "/tmp/ks-canary", targetPath: "/tmp/ks-canary/.env",
            variables: ["KS_CANARY_TOKEN"], command: [], gitignored: false,
            overwriteRequested: false, targetExists: false, targetWrittenByUs: nil,
            requestedTtlSeconds: 900, requestedUses: 10, maxTtlSeconds: 86_400, createdAt: 0,
            expiresAt: 60, origin: nil, topOrigin: nil, topOriginUnknown: false, itemId: nil,
            itemTitle: nil,
            fillFields: [], browser: nil, browserPid: nil, browserExecutable: nil,
            browserIsAppExtension: false, extensionId: nil, presenceOnly: false)
    }

    static func fillRequest(
        itemTitle: String, origin: String, browser: String? = nil, presenceOnly: Bool = false
    ) -> ApprovalRequestView {
        ApprovalRequestView(
            id: "ks-canary-req-2", action: .fillCredential, mintsLease: true,
            clientName: "kagisecure-nmhost", clientPid: 4243, clientPidFromKernel: true,
            clientExecutable: "/usr/bin/kagisecure-nmhost", clientCwd: nil,
            environmentId: nil, environmentName: nil, directory: nil, targetPath: nil,
            variables: [], command: [], gitignored: false, overwriteRequested: false,
            targetExists: nil, targetWrittenByUs: nil, requestedTtlSeconds: 60,
            requestedUses: 1, maxTtlSeconds: 300, createdAt: 0, expiresAt: 60,
            origin: origin, topOrigin: nil, topOriginUnknown: false,
            itemId: "ks-canary-item", itemTitle: itemTitle,
            fillFields: ["password"], browser: browser, browserPid: 4244,
            browserExecutable: "/Applications/Google Chrome.app", browserIsAppExtension: false,
            extensionId: "ks-canary-extension", presenceOnly: presenceOnly)
    }
}
