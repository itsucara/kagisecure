import Foundation
import SafariServices
import os

/// The Safari Web Extension's native half: what `browser.runtime.sendNativeMessage` reaches.
///
/// # What this process is, and what it is deliberately not
///
/// It is the exact Safari analogue of `kagisecure-nmhost` (ADR-0019): a pipe. It holds no vault,
/// makes no decision, and would be no more dangerous if somebody else were running it. Everything
/// that matters — the origin rule, the approval sheet, the biometric, the lease, the audit entry —
/// happens in the app on the other end of the socket.
///
/// It is *unlike* `kagisecure-nmhost` in one way that improves the threat model: there is no
/// manifest naming an arbitrary binary, because there is no separate binary. This code ships
/// inside the app's own signed bundle, and the app verifies exactly that — the peer's executable
/// must be this `.appex`, and its code signature must carry our team and this bundle identifier
/// (ADR-0024 §5). T-10 in `docs/threat-model-browser-extension.md`, the rogue native host, does
/// not exist on this front end.
///
/// # The one field this handler rewrites
///
/// `extension_id` on a `hello`. In Safari `browser.runtime.id` is a per-install UUID — different
/// on every Mac, regenerated on reinstall — so there is nothing there to pin. The stable identity
/// is this app extension's bundle identifier, which *this process* knows about itself and web
/// content does not. So a `hello` arriving from the JavaScript side has its `extension_id` and
/// `browser` replaced with facts rather than claims, before it is forwarded. Every other message
/// is forwarded byte for byte.
///
/// # What is logged
///
/// The message's `ask` and a failure's code. Never a reply body: two of them carry a value, and a
/// log line is the one place a value would outlive the request. There is no `os_log` of a
/// response anywhere in this target.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    private static let log = Logger(
        subsystem: "com.kagisecure.app.safari-extension", category: "native")

    /// The App Group this extension shares with the app, from its own entitlement.
    ///
    /// Read from the entitlement rather than hardcoded, so a fork that signs with its own team
    /// works with no source edit. There is exactly one, and a build with none cannot reach the
    /// app at all — which the popup then says in words.
    private static let appGroup: String? = {
        guard
            let task = SecTaskCreateFromSelf(nil),
            let value = SecTaskCopyValueForEntitlement(
                task, "com.apple.security.application-groups" as CFString, nil)
                as? [String]
        else { return nil }
        return value.first
    }()

    func beginRequest(with context: NSExtensionContext) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: reply(to: incoming(from: context))]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    // MARK: - The message

    /// The `{ksx, id, body}` envelope the extension sent, or `nil` if there was not one.
    private func incoming(from context: NSExtensionContext) -> [String: Any]? {
        guard let item = context.inputItems.first as? NSExtensionItem,
            let message = item.userInfo?[SFExtensionMessageKey] as? [String: Any]
        else { return nil }
        return message
    }

    /// Forward one envelope to the app and return the reply body.
    ///
    /// Every failure comes back as the protocol's own `error` shape rather than as a thrown error
    /// or an empty reply, so the extension's `native.js` branches on one thing — `reply` — whether
    /// the refusal came from the app, from the socket, or from here.
    private func reply(to message: [String: Any]?) -> [String: Any] {
        guard let message, var body = message["body"] as? [String: Any] else {
            return Self.error("PROTOCOL", "The extension sent a message with no body.")
        }

        let ask = body["ask"] as? String ?? "?"
        if ask == "hello" {
            // The rewrite. See the type documentation for why.
            body["extension_id"] = Bundle.main.bundleIdentifier ?? ""
            body["browser"] = "safari"
        }

        guard let group = Self.appGroup else {
            Self.log.error("no App Group entitlement; cannot reach the app")
            return Self.error("INTERNAL", AppGroupSocket.Failure.noContainer.message)
        }

        let envelope: [String: Any] = [
            "ksx": 1,
            "id": message["id"] as? String ?? UUID().uuidString,
            "body": body,
        ]

        do {
            // The reply is returned without being read. Two of its shapes carry a value.
            return try AppGroupSocket.exchange(
                envelope, hello: Self.helloEnvelope(from: body), groupIdentifier: group)
        } catch let failure as AppGroupSocket.Failure {
            Self.log.error("\(ask, privacy: .public) failed: \(String(describing: failure))")
            return Self.error(Self.code(for: failure), failure.message)
        } catch {
            Self.log.error("\(ask, privacy: .public) failed unexpectedly")
            return Self.error("INTERNAL", "The connection to Kagisecure failed.")
        }
    }

    /// Map a transport failure onto the protocol's own vocabulary.
    ///
    /// `VAULT_LOCKED` for "the app is not there" is the same answer the Chromium side gives when
    /// its port will not open, and it is the one the popup already knows how to explain: open
    /// Kagisecure and unlock it.
    private static func code(for failure: AppGroupSocket.Failure) -> String {
        switch failure {
        case .notListening: return "VAULT_LOCKED"
        case .noContainer, .io, .malformed: return "INTERNAL"
        }
    }

    /// The handshake that precedes every non-`hello` message on its own connection.
    ///
    /// Built here, from facts this process knows about itself, rather than copied from whatever
    /// the JavaScript side last sent: the bundle identifier is the app extension's own, and the
    /// protocol version is the one this build was compiled against. `extension_version` is carried
    /// over from the message when it is there, because that one genuinely is the *extension's*
    /// claim about itself and is display-only.
    private static func helloEnvelope(from body: [String: Any]) -> [String: Any] {
        [
            "ksx": 1,
            "id": UUID().uuidString,
            "body": [
                "ask": "hello",
                "extension_id": Bundle.main.bundleIdentifier ?? "",
                "browser": "safari",
                "extension_version": body["extension_version"] as? String ?? "0.1.0",
                "protocol_version": 1,
            ],
        ]
    }

    private static func error(_ code: String, _ message: String) -> [String: Any] {
        ["reply": "error", "code": code, "message": message]
    }
}
