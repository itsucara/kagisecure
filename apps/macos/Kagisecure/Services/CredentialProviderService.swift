import AppKit
import AuthenticationServices
import Foundation
import os

import KagisecureFFI

/// The app's half of system-wide password AutoFill (ADR-0045).
///
/// `KagisecureCredentialProvider.appex` is what macOS loads when a native app — or any text field
/// with QuickType — asks for a password. It holds no vault and never opens one: it asks this app,
/// over a Unix socket in the App Group container (`AutoFillChannel`), and this app answers with
/// the same rules every other front end follows:
///
/// * **Inside the grace window** (`PresenceGrace`): a credential is handed out with no prompt,
///   also to `provideCredentialWithoutUserInteraction` — one Touch ID, everything fills until lock.
/// * **Outside it**: a request that may not show UI is answered `interactionRequired`, and the
///   system then shows the extension's sheet; a request from the sheet goes through one presence
///   check here (`VaultSession.releaseField` → `AppPresenceGate`), which opens the window.
/// * **Locked or not running**: answered `locked`, and an interactive request brings the app
///   forward so the person can unlock; the sheet says to try again.
///
/// Also keeps `ASCredentialIdentityStore` current — website host and username of every login,
/// never a password — so QuickType can suggest logins before the extension is even launched.
@MainActor
final class CredentialProviderService {
    /// `AppDefaults` key for the stricter behaviour: never fill without the AutoFill sheet, even
    /// inside the grace window. Off by default; a hook for a future organization policy, like
    /// `PresenceGrace.agentFillRequiresSheetKey`.
    static let requiresConfirmationKey = "nativeAutofillRequiresConfirmation"

    private static let log = Logger(subsystem: "com.kagisecure.app", category: "autofill")

    let handler: CredentialProviderHandler
    private var server: AutoFillSocketServer?
    private let identities = CredentialIdentitySync()

    /// Why the socket is not up, if it is not. Shown nowhere yet; logged.
    private(set) var startupError: String?

    init(presence: PresenceCoordinator) {
        handler = CredentialProviderHandler(presence: presence)
        handler.raiseApp = {
            NSApp.activate()
            NSApp.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
        }
    }

    // MARK: - Lifecycle

    /// Bind the socket. Called at launch, so an AutoFill request finds the app even while the vault
    /// is locked and can bring it forward to unlock. Safe to call twice.
    func start() {
        guard server == nil else { return }
        guard let path = Self.socketPath() else {
            startupError = "no App Group container (ad-hoc build); AutoFill provider unavailable"
            Self.log.info("AutoFill socket not started: no App Group container")
            return
        }
        let skipSignature = Self.socketOverride() != nil
        let handler = self.handler
        do {
            server = try AutoFillSocketServer(
                path: path,
                verifyPeer: { fd in Self.peerIsOurProvider(fd, skipSignature: skipSignature) },
                handle: { request in await handler.handle(request) })
        } catch {
            startupError = "\(error)"
            Self.log.error("AutoFill socket could not start: \(String(describing: error))")
        }
    }

    func stop() {
        server?.stop()
        server = nil
    }

    /// The vault unlocked: serve it, and publish its logins to the identity store.
    func vaultUnlocked(_ session: VaultSession) {
        handler.vault = SessionAutoFillVault(session: session)
        identities.sync(SessionAutoFillVault(session: session).logins())
    }

    /// Items changed (the store refreshed): republish if the set of identities changed.
    func itemsChanged() {
        guard let vault = handler.vault else { return }
        identities.sync(vault.logins())
    }

    /// The vault locked. The identity store is **kept** — convenience first (ADR-0045 §5): it holds
    /// host names and usernames only, and keeping it means QuickType still offers a login, whose
    /// selection then brings the app forward to unlock.
    func vaultLocked() {
        handler.vault = nil
    }

    // MARK: - Helpers

    /// `KAGISECURE_AUTOFILL_SOCKET` moves the socket and skips the peer's signature check, so the
    /// unit tests can talk to the server without our signed `.appex`. Honoured only in a DEBUG
    /// build or while XCTest is actually running: in a release build any same-user process can
    /// `launchctl setenv` it before the app starts, and with the check gone it could then ask for
    /// every password during the grace window (ADR-0045, 2026-10-04 amendment).
    private static func socketOverride() -> String? {
        AutoFillTestOverride.value(
            isDebugBuild: AutoFillTestOverride.isDebugBuild,
            xcTestLoaded: AutoFillTestOverride.xcTestLoaded,
            environment: ProcessInfo.processInfo.environment)
    }

    static func socketPath() -> String? {
        if let override = socketOverride() { return override }
        guard let team = PeerCodeSignature.ownTeamIdentifier() else { return nil }
        return AutoFillChannel.socketPath(groupIdentifier: "\(team).\(AutoFillChannel.groupSuffix)")
    }

    /// Same user, and — unless a test socket was named explicitly — our own signed `.appex`.
    nonisolated private static func peerIsOurProvider(_ fd: Int32, skipSignature: Bool) -> Bool {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return false }
        if skipSignature { return true }
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else {
            return false
        }
        // The audit token, not the pid, is what the signature check runs on: a pid can be handed
        // to another process between the connect and the check; a token cannot. No token, no
        // answer — the kernel always supplies one on a local socket.
        guard let token = PeerCodeSignature.auditToken(socket: fd) else { return false }
        return PeerCodeSignature().checkCredentialProvider(pid: UInt32(pid), auditToken: token)
            .verified
    }
}

// MARK: - The decision

/// What the handler needs from an unlocked vault. A protocol so the unit tests can drive the
/// grace and refusal logic without a real vault or a real Touch ID sheet.
@MainActor
protocol AutoFillVault: AnyObject {
    func logins() -> [AutoFillLogin]
    func username(itemId: String) -> String?
    /// The password, through the presence-gated release (grace window or one check).
    func releasePassword(itemId: String) async throws -> String
    /// The current one-time code, through the presence-gated release.
    func releaseOneTimeCode(itemId: String) async throws -> String
}

/// Answers one `AutoFillRequest`. Pure policy: no socket, no AppKit.
@MainActor
final class CredentialProviderHandler {
    let presence: PresenceCoordinator
    /// The unlocked vault, or `nil` while locked.
    var vault: AutoFillVault?
    /// Brings the app forward (to unlock). Replaced in tests.
    var raiseApp: () -> Void = {}
    /// The stricter setting. Read on every request so a change applies at once.
    var requiresConfirmation: () -> Bool = {
        AppDefaults.shared.bool(forKey: CredentialProviderService.requiresConfirmationKey)
    }

    init(presence: PresenceCoordinator) {
        self.presence = presence
    }

    func handle(_ request: AutoFillRequest) async -> AutoFillResponse {
        switch request {
        case .status:
            return .status(unlocked: vault != nil, graceOpen: vault != nil && presence.graceIsOpen)
        case .logins(let query, let services):
            guard let vault else { return locked(raise: false) }
            return .logins(AutoFillMatching.rank(
                vault.logins(), query: query, services: services,
                matches: autofillHostMatches(saved:requested:)))
        case .credential(let itemId, let interactive):
            guard let vault else { return locked(raise: interactive) }
            if let refusal = gate(interactive: interactive) { return refusal }
            guard vault.logins().contains(where: { $0.id == itemId }) else {
                return .refused(.notFound, message: "No such login.")
            }
            do {
                let password = try await vault.releasePassword(itemId: itemId)
                return .credential(username: vault.username(itemId: itemId) ?? "", password: password)
            } catch {
                return Self.refusal(for: error)
            }
        case .oneTimeCode(let itemId, let interactive):
            guard let vault else { return locked(raise: interactive) }
            if let refusal = gate(interactive: interactive) { return refusal }
            do {
                return .oneTimeCode(code: try await vault.releaseOneTimeCode(itemId: itemId))
            } catch {
                return Self.refusal(for: error)
            }
        }
    }

    /// The no-UI rule. A request that may not show UI is served only from the grace window — the
    /// release below would otherwise raise a Touch ID sheet nobody asked to see — and never when
    /// the stricter setting is on.
    private func gate(interactive: Bool) -> AutoFillResponse? {
        guard !interactive else { return nil }
        if requiresConfirmation() || !presence.graceIsOpen {
            return .refused(.interactionRequired, message: "Confirm in the AutoFill sheet.")
        }
        return nil
    }

    private func locked(raise: Bool) -> AutoFillResponse {
        if raise { raiseApp() }
        return .refused(.locked, message: "Kagisecure is locked.")
    }

    static func refusal(for error: Error) -> AutoFillResponse {
        switch error as? FfiError {
        case .PresenceCancelled?: .refused(.cancelled, message: "Not confirmed.")
        case .PresenceBusy?: .refused(.busy, message: "Another confirmation is in progress.")
        case .VaultLocked?: .refused(.locked, message: "Kagisecure is locked.")
        case .NotPresent?: .refused(.notFound, message: "No such login.")
        default: .refused(.failed, message: "The value could not be released.")
        }
    }
}

/// The real vault, through the FFI session.
@MainActor
final class SessionAutoFillVault: AutoFillVault {
    private let session: VaultSession

    init(session: VaultSession) {
        self.session = session
    }

    func logins() -> [AutoFillLogin] {
        session.listItems(filter: .all, query: nil, sort: .title).compactMap(Self.login(from:))
    }

    /// A login is any item with a password field. Its domains are its saved websites' hosts.
    static func login(from item: ItemView) -> AutoFillLogin? {
        guard item.passwordField != nil else { return nil }
        // Test logins are never offered to the person (ADR-0048 §8): the URL is agent-chosen.
        guard !item.inAgentTestVault else { return nil }
        let domains = item.urls.compactMap(AutoFillMatching.host(of:))
        return AutoFillLogin(
            id: item.id, title: item.title, username: item.username, domains: domains,
            hasOneTimeCode: item.fields.contains { $0.kind == .totp && $0.hasValue })
    }

    func username(itemId: String) -> String? {
        (try? session.item(itemId: itemId))?.username
    }

    func releasePassword(itemId: String) async throws -> String {
        guard let field = try session.item(itemId: itemId).passwordField else {
            throw FfiError.NotPresent(message: "no password")
        }
        // `.copy`: the closest existing purpose — one use, nothing shown in the app. The audit
        // log records it as a copy (ADR-0045 §3).
        let release = try await session.releaseField(itemId: itemId, fieldId: field.id, purpose: .copy)
        defer { release.close() }
        return try release.value()
    }

    func releaseOneTimeCode(itemId: String) async throws -> String {
        let release = try await session.releaseTotp(itemId: itemId, fieldId: nil, purpose: .copy)
        defer { release.close() }
        return try release.codeAt(at: TotpCountdown.unixNow()).code
    }
}

// MARK: - The identity store

/// Keeps `ASCredentialIdentityStore` equal to the vault's logins: one password identity per
/// (host, username), one one-time-code identity per host of a login with a code. Never a value.
@MainActor
final class CredentialIdentitySync {
    private var published: [String]?

    /// The identities `logins` produce, as stable keys — for change detection and tests.
    static func keys(for logins: [AutoFillLogin]) -> [String] {
        logins.flatMap { login in
            login.domains.map { "pw|\($0)|\(login.username ?? "")|\(login.id)" }
                + (login.hasOneTimeCode ? login.domains.map { "otp|\($0)|\(login.id)" } : [])
        }
    }

    func sync(_ logins: [AutoFillLogin]) {
        let keys = Self.keys(for: logins)
        guard keys != published else { return }
        published = keys
        let identities: [ASCredentialIdentity] = logins.flatMap { login -> [ASCredentialIdentity] in
            var out: [ASCredentialIdentity] = login.domains.map { domain in
                ASPasswordCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: domain, type: .domain),
                    user: login.username ?? login.title, recordIdentifier: login.id)
            }
            if login.hasOneTimeCode {
                out += login.domains.map { domain in
                    ASOneTimeCodeCredentialIdentity(
                        serviceIdentifier: ASCredentialServiceIdentifier(
                            identifier: domain, type: .domain),
                        label: login.title, recordIdentifier: login.id)
                }
            }
            return out
        }
        Task {
            // Not enabled in System Settings yet: nothing to publish to. Published on the next
            // change or unlock after it is.
            guard await IdentityStoreCalls.isEnabled() else { return }
            if let error = await IdentityStoreCalls.replace(.init(value: identities)) {
                Logger(subsystem: "com.kagisecure.app", category: "autofill")
                    .error("identity store update failed: \(String(describing: error))")
            }
        }
    }
}

/// `ASCredentialIdentityStore`, called through its completion handlers from nonisolated code.
///
/// The store answers on SafariServices' XPC queue. Its `async` overloads, awaited from the main
/// actor, ran the reply with main-actor isolation on that queue, and Swift's isolation check
/// killed the app right after unlock (0.1.4, `_dispatch_assert_queue_fail`).
enum IdentityStoreCalls {
    @concurrent nonisolated static func isEnabled() async -> Bool {
        await withCheckedContinuation { continuation in
            ASCredentialIdentityStore.shared.getState { @Sendable state in
                continuation.resume(returning: state.isEnabled)
            }
        }
    }

    /// The identities are built fresh for this call and never touched again by the caller.
    struct Identities: @unchecked Sendable { let value: [any ASCredentialIdentity] }

    @concurrent nonisolated static func replace(_ identities: Identities) async -> (any Error)? {
        await withCheckedContinuation { continuation in
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities.value) { @Sendable _, error in
                continuation.resume(returning: error)
            }
        }
    }
}

// MARK: - The socket

/// A Unix stream socket served one connection per request, on background threads, with each
/// request answered on the main actor.
final class AutoFillSocketServer: @unchecked Sendable {
    private let fd: Int32
    private let path: String
    private let lock = NSLock()
    private var stopped = false

    init(
        path: String,
        verifyPeer: @escaping @Sendable (Int32) -> Bool,
        handle: @escaping @Sendable (AutoFillRequest) async -> AutoFillResponse
    ) throws {
        self.path = path
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        unlink(path)
        var address = try AutoFillWire.socketAddress(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AutoFillWire.Failure.io(String(cString: strerror(errno))) }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 16) == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            throw AutoFillWire.Failure.io(message)
        }
        self.fd = fd
        let thread = Thread { [self] in acceptLoop(verifyPeer: verifyPeer, handle: handle) }
        thread.name = "kagisecure-autofill-accept"
        thread.start()
    }

    func stop() {
        lock.lock()
        let already = stopped
        stopped = true
        lock.unlock()
        guard !already else { return }
        shutdown(fd, SHUT_RDWR)
        close(fd)
        unlink(path)
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    private func acceptLoop(
        verifyPeer: @escaping @Sendable (Int32) -> Bool,
        handle: @escaping @Sendable (AutoFillRequest) async -> AutoFillResponse
    ) {
        while !isStopped {
            let client = accept(fd, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                Self.serve(client, verifyPeer: verifyPeer, handle: handle)
            }
        }
    }

    /// One request, one reply, close.
    static func serve(
        _ client: Int32,
        verifyPeer: @Sendable (Int32) -> Bool,
        handle: @escaping @Sendable (AutoFillRequest) async -> AutoFillResponse
    ) {
        guard verifyPeer(client) else {
            try? AutoFillWire.write(
                AutoFillResponse.refused(.untrusted, message: "Not this app's AutoFill provider."),
                to: client)
            close(client)
            return
        }
        guard let request = try? AutoFillWire.read(AutoFillRequest.self, from: client) else {
            try? AutoFillWire.write(
                AutoFillResponse.refused(.failed, message: "Unreadable request."), to: client)
            close(client)
            return
        }
        Task {
            let response = await handle(request)
            try? AutoFillWire.write(response, to: client)
            close(client)
        }
    }
}

/// When the AutoFill socket's test override (`KAGISECURE_AUTOFILL_SOCKET`) may be honoured.
///
/// A pure decision so the release-build answer can be unit-tested from a DEBUG test run.
enum AutoFillTestOverride {
    static let environmentKey = "KAGISECURE_AUTOFILL_SOCKET"

    #if DEBUG
        static let isDebugBuild = true
    #else
        static let isDebugBuild = false
    #endif

    /// Whether XCTest is really loaded in this process — not merely named in the environment,
    /// which a same-user process can set as easily as the override itself.
    static var xcTestLoaded: Bool { NSClassFromString("XCTestCase") != nil }

    /// The override path, or `nil` when it must be ignored. Outside a DEBUG build it takes both
    /// XCTest's configuration variable *and* XCTest actually loaded; a hardened-runtime release
    /// build cannot have XCTest injected, so there the override is dead.
    static func value(
        isDebugBuild: Bool, xcTestLoaded: Bool, environment: [String: String]
    ) -> String? {
        guard let path = environment[environmentKey], !path.isEmpty else { return nil }
        if isDebugBuild { return path }
        let underXCTest = environment["XCTestConfigurationFilePath"] != nil && xcTestLoaded
        return underXCTest ? path : nil
    }
}
