import Foundation

/// The AutoFill credential provider's channel to the app (ADR-0045).
///
/// Compiled into **both** the app and `KagisecureCredentialProvider.appex`, so the two halves
/// cannot disagree about a field name. The transport is the one the Safari extension already uses
/// (ADR-0024): a Unix stream socket in the App Group container, one connection per message, frames
/// of a four-byte big-endian length followed by a JSON object. What differs is who answers: the
/// Safari socket is served by Rust's extension listener, this one by Swift
/// (`CredentialProviderService`), because the decision it needs — is the presence grace window
/// open? — lives in Swift (`PresenceCoordinator`), and the value it hands out goes through the
/// same presence-gated release every in-app copy uses (`VaultSession.releaseField`).
///
/// # What this file may hold
///
/// Types and framing. Nothing here logs, caches or re-encodes a reply: `AutoFillResponse.credential`
/// carries a password for exactly as long as it takes to hand it to the system.
enum AutoFillChannel {
    /// The socket's file name inside `<App Group container>/run/`.
    static let socketName = "autofill.sock"

    /// The App Group suffix both halves share — the same group the Safari extension uses.
    static let groupSuffix = "com.kagisecure"

    /// The code-signing identifier the app requires of the process on the other end.
    static let providerBundleIdentifier = "com.kagisecure.app.credential-provider"

    /// Largest frame either side will send or accept. Matches the Safari channel's.
    static let maxFrame = 256 * 1024

    /// `<App Group container>/run/autofill.sock`, or `nil` when there is no container (an ad-hoc
    /// build has no team and so no group).
    static func socketPath(groupIdentifier: String) -> String? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
            .appendingPathComponent("run", isDirectory: true)
            .appendingPathComponent(socketName, isDirectory: false)
            .path
    }
}

/// What the extension asks.
enum AutoFillRequest: Codable, Equatable, Sendable {
    /// Is the vault unlocked, and would a fill go through without a prompt?
    case status
    /// Logins for the list UI: metadata only, never a value. `query` filters by title, username
    /// and website; `services` are the service identifiers the system handed the extension, used
    /// to put matching logins first.
    case logins(query: String?, services: [String])
    /// The username and password of one login.
    ///
    /// `interactive` is `false` for `provideCredentialWithoutUserInteraction`: the app must then
    /// answer at once — from the grace window, or with `interactionRequired` — and never raise a
    /// prompt. `true` means the AutoFill sheet is on screen and one presence check in the app is
    /// fine.
    case credential(itemId: String, interactive: Bool)
    /// The current one-time code of one login. Same `interactive` rule.
    case oneTimeCode(itemId: String, interactive: Bool)

    private enum CodingKeys: String, CodingKey {
        case ask, query, services, itemId = "item_id", interactive
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .ask) {
        case "status": self = .status
        case "logins":
            self = .logins(
                query: try c.decodeIfPresent(String.self, forKey: .query),
                services: try c.decodeIfPresent([String].self, forKey: .services) ?? [])
        case "credential":
            self = .credential(
                itemId: try c.decode(String.self, forKey: .itemId),
                interactive: try c.decodeIfPresent(Bool.self, forKey: .interactive) ?? false)
        case "one_time_code":
            self = .oneTimeCode(
                itemId: try c.decode(String.self, forKey: .itemId),
                interactive: try c.decodeIfPresent(Bool.self, forKey: .interactive) ?? false)
        case let other:
            throw DecodingError.dataCorruptedError(
                forKey: .ask, in: c, debugDescription: "unknown ask \(other)")
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try c.encode("status", forKey: .ask)
        case .logins(let query, let services):
            try c.encode("logins", forKey: .ask)
            try c.encodeIfPresent(query, forKey: .query)
            try c.encode(services, forKey: .services)
        case .credential(let itemId, let interactive):
            try c.encode("credential", forKey: .ask)
            try c.encode(itemId, forKey: .itemId)
            try c.encode(interactive, forKey: .interactive)
        case .oneTimeCode(let itemId, let interactive):
            try c.encode("one_time_code", forKey: .ask)
            try c.encode(itemId, forKey: .itemId)
            try c.encode(interactive, forKey: .interactive)
        }
    }
}

/// One login, as the list shows it. Never a value.
struct AutoFillLogin: Codable, Equatable, Sendable, Identifiable {
    var id: String
    var title: String
    var username: String?
    /// Host names of the item's saved websites, lowercased, `www.` kept as saved.
    var domains: [String]
    var hasOneTimeCode: Bool

    private enum CodingKeys: String, CodingKey {
        case id, title, username, domains, hasOneTimeCode = "has_totp"
    }
}

/// Why nothing was handed out. Stable tokens; the extension branches on them.
enum AutoFillRefusal: String, Codable, Equatable, Sendable {
    /// The vault is locked (or the app is not running). The app was asked to come forward.
    case locked
    /// A fill would need a presence check, and the request said no UI.
    case interactionRequired = "interaction_required"
    /// The person cancelled the presence check.
    case cancelled
    /// Another prompt is on screen.
    case busy
    /// No such login, or it has no password / one-time code.
    case notFound = "not_found"
    /// The peer is not this app's credential provider.
    case untrusted
    /// Anything else.
    case failed
}

/// What the app answers.
enum AutoFillResponse: Codable, Equatable, Sendable {
    case status(unlocked: Bool, graceOpen: Bool)
    case logins([AutoFillLogin])
    /// **The one message that carries a password.**
    case credential(username: String, password: String)
    case oneTimeCode(code: String)
    case refused(AutoFillRefusal, message: String)

    private enum CodingKeys: String, CodingKey {
        case reply, unlocked, graceOpen = "grace_open", items, username, password, code, reason,
            message
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .reply) {
        case "status":
            self = .status(
                unlocked: try c.decode(Bool.self, forKey: .unlocked),
                graceOpen: try c.decode(Bool.self, forKey: .graceOpen))
        case "logins":
            self = .logins(try c.decode([AutoFillLogin].self, forKey: .items))
        case "credential":
            self = .credential(
                username: try c.decode(String.self, forKey: .username),
                password: try c.decode(String.self, forKey: .password))
        case "one_time_code":
            self = .oneTimeCode(code: try c.decode(String.self, forKey: .code))
        case "refused":
            self = .refused(
                (try? c.decode(AutoFillRefusal.self, forKey: .reason)) ?? .failed,
                message: try c.decodeIfPresent(String.self, forKey: .message) ?? "")
        case let other:
            throw DecodingError.dataCorruptedError(
                forKey: .reply, in: c, debugDescription: "unknown reply \(other)")
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status(let unlocked, let graceOpen):
            try c.encode("status", forKey: .reply)
            try c.encode(unlocked, forKey: .unlocked)
            try c.encode(graceOpen, forKey: .graceOpen)
        case .logins(let items):
            try c.encode("logins", forKey: .reply)
            try c.encode(items, forKey: .items)
        case .credential(let username, let password):
            try c.encode("credential", forKey: .reply)
            try c.encode(username, forKey: .username)
            try c.encode(password, forKey: .password)
        case .oneTimeCode(let code):
            try c.encode("one_time_code", forKey: .reply)
            try c.encode(code, forKey: .code)
        case .refused(let reason, let message):
            try c.encode("refused", forKey: .reply)
            try c.encode(reason, forKey: .reason)
            try c.encode(message, forKey: .message)
        }
    }
}

/// Framing over a connected stream socket: a four-byte big-endian length, then the JSON body —
/// the Safari channel's framing (`kagisecure_extension_ipc::frame`).
enum AutoFillWire {
    enum Failure: Error, Equatable {
        case notListening
        case io(String)
        case malformed
    }

    static func write<T: Encodable>(_ value: T, to fd: Int32) throws {
        let body: Data
        do { body = try JSONEncoder().encode(value) } catch { throw Failure.malformed }
        guard body.count <= AutoFillChannel.maxFrame else { throw Failure.io("frame too large") }
        var frame = Data()
        var length = UInt32(body.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(body)
        try writeAll(fd, frame)
    }

    static func read<T: Decodable>(_ type: T.Type, from fd: Int32) throws -> T {
        let prefix = try readExactly(fd, 4)
        let length = prefix.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard length <= UInt32(AutoFillChannel.maxFrame) else { throw Failure.io("frame too large") }
        let body = try readExactly(fd, Int(length))
        do { return try JSONDecoder().decode(type, from: body) } catch { throw Failure.malformed }
    }

    /// Connect, send one request, read one reply. A connection per message, as on the Safari
    /// channel: the system starts and stops the extension at will, so a kept socket is usually
    /// dead by the time it is next used.
    static func exchange(path: String, _ request: AutoFillRequest) throws -> AutoFillResponse {
        let fd = try connect(to: path)
        defer { close(fd) }
        try write(request, to: fd)
        return try read(AutoFillResponse.self, from: fd)
    }

    static func connect(to path: String) throws -> Int32 {
        var address = try socketAddress(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.io(String(cString: strerror(errno))) }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, size)
            }
        }
        guard result == 0 else {
            let code = errno
            close(fd)
            if code == ENOENT || code == ECONNREFUSED { throw Failure.notListening }
            throw Failure.io(String(cString: strerror(code)))
        }
        return fd
    }

    static func socketAddress(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count < capacity else { throw Failure.io("socket path too long") }
        withUnsafeMutablePointer(to: &address.sun_path) { raw in
            raw.withMemoryRebound(to: CChar.self, capacity: capacity) { buffer in
                for (index, byte) in bytes.enumerated() { buffer[index] = CChar(bitPattern: byte) }
                buffer[bytes.count] = 0
            }
        }
        return address
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            while offset < data.count {
                let written = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                throw Failure.io(String(cString: strerror(errno)))
            }
        }
    }

    private static func readExactly(_ fd: Int32, _ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var buffer = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let got = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base.advanced(by: offset), count - offset)
            }
            if got > 0 {
                offset += got
                continue
            }
            if got == 0 { throw Failure.io("connection closed") }
            if errno == EINTR { continue }
            throw Failure.io(String(cString: strerror(errno)))
        }
        return Data(buffer)
    }
}

/// Ordering and filtering for the list UI, shared so the app and the extension rank alike.
enum AutoFillMatching {
    /// The host of a service identifier: a bare domain is kept, a URL gives its host. Lowercased.
    static func host(of serviceIdentifier: String) -> String? {
        let trimmed = serviceIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return nil }
        if trimmed.contains("://"), let host = URL(string: trimmed)?.host { return host }
        // "example.com/path" or "example.com:443"
        let head = trimmed.split(separator: "/").first.map(String.init) ?? trimmed
        return head.split(separator: ":").first.map(String.init)
    }

    /// Whether `domain` (a saved website's host) serves `host` (what the system asked for):
    /// equal, or one is a subdomain of the other's registrable part. Deliberately loose —
    /// convenience first (ADR-0045 §4); the person still picks the login.
    static func matches(domain: String, host: String) -> Bool {
        let d = strip(domain)
        let h = strip(host)
        guard !d.isEmpty, !h.isEmpty else { return false }
        return d == h || h.hasSuffix("." + d) || d.hasSuffix("." + h)
    }

    private static func strip(_ value: String) -> String {
        let lower = value.lowercased()
        return lower.hasPrefix("www.") ? String(lower.dropFirst(4)) : lower
    }

    /// `logins` filtered by `query` and ordered with those matching `services` first, each group
    /// by title.
    static func rank(
        _ logins: [AutoFillLogin], query: String?, services: [String]
    ) -> [AutoFillLogin] {
        let hosts = services.compactMap(host(of:))
        let needle = query?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        let filtered = logins.filter { login in
            guard !needle.isEmpty else { return true }
            return login.title.lowercased().contains(needle)
                || (login.username?.lowercased().contains(needle) ?? false)
                || login.domains.contains { $0.contains(needle) }
        }
        func isMatch(_ login: AutoFillLogin) -> Bool {
            login.domains.contains { domain in hosts.contains { matches(domain: domain, host: $0) } }
        }
        return filtered.enumerated().sorted { a, b in
            let am = isMatch(a.element)
            let bm = isMatch(b.element)
            if am != bm { return am }
            let order = a.element.title.localizedCaseInsensitiveCompare(b.element.title)
            if order != .orderedSame { return order == .orderedAscending }
            return a.offset < b.offset
        }.map(\.element)
    }
}
