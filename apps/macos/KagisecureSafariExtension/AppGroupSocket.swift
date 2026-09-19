import Foundation

/// The Safari extension's half of the app socket: a Unix stream socket inside the App Group
/// container, framed the way `kagisecure_extension_ipc::frame` frames it.
///
/// # Why a socket and not XPC
///
/// The obvious answer for an app extension talking to its container app is a Mach service and
/// `NSXPCListener`. It is not available here: vending a *global* Mach name is a launchd
/// registration, which a plain `.app` does not have, and the alternatives (an embedded XPC
/// service, a login item) put the vault-holding process somewhere the user cannot see or quit.
/// A Unix socket in the App Group container is reachable from inside the extension's sandbox,
/// needs no registration, and — the reason that settles it — is the *same* socket type, the same
/// framing and the same `Request`/`Response` types the Chromium front end already uses, so the app
/// sees one client kind with a `browser` tag rather than two protocols
/// (`docs/decisions/0024-safari-app-group-socket.md`).
///
/// # What this file may hold
///
/// One reply, for as long as it takes to hand it back to Safari. `Filled` and `TotpCode` carry a
/// value; nothing here inspects, logs, caches or re-encodes them — the bytes are read off the
/// socket, parsed once into `Any`, and passed straight out. There is no `os_log` of a response in
/// this target at all, and the error paths log a *code*, never a body.
enum AppGroupSocket {

    /// What can go wrong on the way to the app.
    enum Failure: Error {
        /// This build has no App Group, so there is nowhere to connect.
        case noContainer
        /// The socket is not there, or the app is not listening on it.
        case notListening(String)
        /// The connection failed mid-message.
        case io(String)
        /// The app sent something this extension could not parse.
        case malformed(String)

        /// The sentence the popup shows. Never contains anything from a reply body.
        var message: String {
            switch self {
            case .noContainer:
                return
                    "This copy of Kagisecure has no App Group, so its Safari extension cannot "
                    + "reach it. Reinstall the signed app."
            case .notListening:
                return "Kagisecure is not running. Open it and unlock your vault."
            case .io(let detail):
                return "The connection to Kagisecure failed: \(detail)"
            case .malformed:
                return "Kagisecure sent a reply this extension could not read."
            }
        }
    }

    /// Largest frame either side will send or accept — `kagisecure_extension_ipc::frame::MAX_FRAME`.
    static let maxFrame = 256 * 1024

    /// The App Group container's `run/safari.sock`.
    ///
    /// Derived from the extension's own App Group entitlement rather than from a constant, so a
    /// fork that signs with its own team gets its own group with no source edit. The suffix and
    /// the file name match `kagisecure_extension_ipc::endpoint`.
    static func socketPath(groupIdentifier: String) -> String? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier)?
            .appendingPathComponent("run", isDirectory: true)
            .appendingPathComponent("safari.sock", isDirectory: false)
            .path
    }

    /// Send one envelope and read one reply, saying hello on the way in.
    ///
    /// # A connection per message
    ///
    /// Rather than one kept open, and that is a deliberate trade. Safari starts and stops the app
    /// extension process at its own discretion, so a cached socket is usually dead by the time it
    /// is next used — and a dead cached socket fails as a request that hangs until the extension's
    /// 70-second timeout, which is the worst possible answer to a click. The cost is one
    /// `connect(2)` on a path that is about to show a human an approval sheet.
    ///
    /// # Which is why `hello` is a parameter
    ///
    /// The app's session state is per **connection**: it refuses everything until the connection
    /// has identified itself, which is the property that stops a stranger's frame being served on
    /// the strength of somebody else's handshake. A connection per message therefore means a
    /// handshake per message. So the caller hands in the `Hello` it would have sent, and it goes
    /// first on the same connection — two frames out, two back, one `connect`.
    ///
    /// - Parameters:
    ///   - envelope: the `{ksx, id, body}` object, already correlated.
    ///   - hello: the `Hello` envelope to send first. Skipped when `envelope` is itself a hello.
    /// - Returns: the reply's `body`. A refused handshake is returned as *its* body, because the
    ///   extension can do nothing with the second reply if the first was a refusal.
    static func exchange(
        _ envelope: [String: Any], hello: [String: Any]?, groupIdentifier: String
    ) throws -> [String: Any] {
        guard let path = socketPath(groupIdentifier: groupIdentifier) else {
            throw Failure.noContainer
        }
        return try exchangeAt(path: path, envelope: envelope, hello: hello)
    }

    /// The same exchange against an explicit path.
    ///
    /// Exists because a test bundle cannot be an app extension and therefore has no App Group
    /// container to resolve — see `KagisecureTests/SafariExtensionTransportTests.swift`. Splitting
    /// it here rather than reimplementing the framing in the test is the whole point: the bytes
    /// the test puts on the wire are the bytes the shipped extension puts on the wire.
    static func exchangeAt(
        path: String, envelope: [String: Any], hello: [String: Any]? = nil
    ) throws -> [String: Any] {
        let fd = try connect(to: path)
        defer { close(fd) }

        if let hello, !isHello(envelope) {
            try writeFrame(fd, hello)
            let welcome = try body(of: try readFrame(fd))
            if welcome["reply"] as? String == "error" { return welcome }
        }

        try writeFrame(fd, envelope)
        return try body(of: try readFrame(fd))
    }

    private static func isHello(_ envelope: [String: Any]) -> Bool {
        (envelope["body"] as? [String: Any])?["ask"] as? String == "hello"
    }

    private static func body(of reply: [String: Any]) throws -> [String: Any] {
        guard let body = reply["body"] as? [String: Any] else {
            throw Failure.malformed("no body")
        }
        return body
    }

    // MARK: - The socket

    private static func connect(to path: String) throws -> Int32 {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        // `sun_path` is a fixed 104-byte buffer. A path that does not fit produces `EINVAL` from
        // `connect` with nothing in the message about length, so it is refused here instead.
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count < capacity else {
            throw Failure.io("the socket path is too long for a Unix socket")
        }
        withUnsafeMutablePointer(to: &address.sun_path) { raw in
            raw.withMemoryRebound(to: CChar.self, capacity: capacity) { buffer in
                for (index, byte) in bytes.enumerated() { buffer[index] = CChar(bitPattern: byte) }
                buffer[bytes.count] = 0
            }
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.io(String(cString: strerror(errno))) }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                Darwin.connect(fd, generic, size)
            }
        }
        guard result == 0 else {
            let code = errno
            close(fd)
            // The two ordinary reasons — nothing bound, or a stale socket file — are both "the app
            // is not running", which is what the popup needs to say.
            if code == ENOENT || code == ECONNREFUSED {
                throw Failure.notListening(String(cString: strerror(code)))
            }
            throw Failure.io(String(cString: strerror(code)))
        }
        return fd
    }

    private static func writeFrame(_ fd: Int32, _ message: [String: Any]) throws {
        let body: Data
        do {
            body = try JSONSerialization.data(withJSONObject: message, options: [])
        } catch {
            throw Failure.malformed("the request could not be encoded")
        }
        guard body.count <= maxFrame else { throw Failure.io("the request is too large") }
        var frame = Data()
        // Four bytes, big-endian, matching `kagisecure_extension_ipc::frame`. The MCP socket in
        // the same product is little-endian on purpose, so a frame sent to the wrong socket is
        // refused by the size check rather than misread (ADR-0019 §3).
        var length = UInt32(body.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(body)
        try writeAll(fd, frame)
    }

    private static func readFrame(_ fd: Int32) throws -> [String: Any] {
        let prefix = try readExactly(fd, 4)
        let length = prefix.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard length <= UInt32(maxFrame) else { throw Failure.io("the reply is too large") }
        let body = try readExactly(fd, Int(length))
        guard let object = try? JSONSerialization.jsonObject(with: body, options: []),
            let dictionary = object as? [String: Any]
        else {
            throw Failure.malformed("the reply was not an object")
        }
        return dictionary
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            while offset < data.count {
                let written = write(fd, base.advanced(by: offset), data.count - offset)
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
                return read(fd, base.advanced(by: offset), count - offset)
            }
            if got > 0 {
                offset += got
                continue
            }
            if got == 0 { throw Failure.io("Kagisecure closed the connection") }
            if errno == EINTR { continue }
            throw Failure.io(String(cString: strerror(errno)))
        }
        return Data(buffer)
    }
}
