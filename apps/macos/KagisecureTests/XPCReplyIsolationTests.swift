import AppKit
import Foundation
import Testing
@testable import Kagisecure

/// Safari and the AutoFill identity store answer on SafariServices' XPC queue. Awaited from the
/// main actor, a reply that inherited main-actor isolation trapped there (0.1.4 crash after
/// unlock). These await the real calls from the main actor; a regression crashes the test run.
@MainActor
struct XPCReplyIsolationTests {
    @Test func safariStateReplyDoesNotTrap() async {
        _ = await BrowserConnectModel.safariExtensionEnabled("com.kagisecure.app.safari-extension")
    }

    @Test func identityStoreStateReplyDoesNotTrap() async {
        _ = await IdentityStoreCalls.isEnabled()
    }
}

/// Our own team identifier is read once, off the main thread (Security.framework's code-signing
/// checks log "should not be called on the main thread" there), and every later read — from any
/// thread — is the same cached answer.
struct OwnTeamIdentifierCacheTests {
    @Test func offMainReadMatchesDirectReadAndCache() async {
        let offMain = await PeerCodeSignature.ownTeamIdentifierOffMain()
        #expect(offMain == PeerCodeSignature.readOwnTeamIdentifier())
        #expect(await MainActor.run { PeerCodeSignature.ownTeamIdentifier() } == offMain)
    }
}

/// The master-password field must not invite macOS Passwords AutoFill.
@MainActor
struct SecureFieldAutoFillTests {
    @Test func stableSecureFieldOptsOutOfAutoFill() {
        let field = NSSecureTextField()
        StableSecureField.configureAgainstAutoFill(field)
        #expect(field.contentType?.rawValue == "")
        #expect(!field.isAutomaticTextCompletionEnabled)
    }
}
