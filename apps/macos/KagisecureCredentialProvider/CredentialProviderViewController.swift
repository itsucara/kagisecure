import AppKit
import AuthenticationServices
import os

/// System-wide password AutoFill (ADR-0045): what macOS loads when a native app, or QuickType in
/// any text field, asks kagisecure for a login.
///
/// # What this process is not
///
/// A vault. It never opens one, never sees a master password, and holds a value only for as long
/// as it takes to hand it to the system. Every decision — is the vault unlocked, is the grace
/// window open, does a presence check have to run — is made by the app on the other end of the
/// App Group socket (`AutoFillChannel`, `CredentialProviderService`). A request this process makes
/// with `interactive: false` can never raise a prompt there; the app answers from the grace
/// window or says `interaction_required`, and the system then shows this sheet.
///
/// # What is logged
///
/// The request kind and a refusal's reason. Never a reply body.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private static let log = Logger(
        subsystem: AutoFillChannel.providerBundleIdentifier, category: "provider")

    /// The App Group, from this extension's own entitlement — so a fork's team follows.
    private static let appGroup: String? = {
        guard
            let task = SecTaskCreateFromSelf(nil),
            let value = SecTaskCopyValueForEntitlement(
                task, "com.apple.security.application-groups" as CFString, nil) as? [String]
        else { return nil }
        return value.first
    }()

    // MARK: - State

    private enum Mode {
        case passwords
        case oneTimeCodes
    }

    private var mode: Mode = .passwords
    private var services: [String] = []
    private var logins: [AutoFillLogin] = []
    /// Retried by "Try Again" after the person unlocked the app.
    private var retry: (() -> Void)?

    // MARK: - Views

    private let searchField = NSSearchField()
    private let table = NSTableView()
    private let scroll = NSScrollView()
    private let status = NSTextField(wrappingLabelWithString: "")
    private let fillButton = NSButton()
    private let retryButton = NSButton()
    private let cancelButton = NSButton()

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 360))

        searchField.placeholderString = String(localized: "Search logins")
        searchField.target = self
        searchField.action = #selector(searchChanged)

        let column = NSTableColumn(identifier: .init("login"))
        column.resizingMask = .autoresizingMask
        table.addTableColumn(column)
        table.headerView = nil
        table.rowHeight = 36
        table.style = .inset
        table.dataSource = self
        table.delegate = self
        table.target = self
        table.doubleAction = #selector(fillSelected)
        scroll.documentView = table
        scroll.hasVerticalScroller = true

        status.textColor = .secondaryLabelColor

        fillButton.title = String(localized: "Fill")
        fillButton.bezelStyle = .push
        fillButton.keyEquivalent = "\r"
        fillButton.target = self
        fillButton.action = #selector(fillSelected)

        retryButton.title = String(localized: "Try Again")
        retryButton.bezelStyle = .push
        retryButton.target = self
        retryButton.action = #selector(retryTapped)
        retryButton.isHidden = true

        cancelButton.title = String(localized: "Cancel")
        cancelButton.bezelStyle = .push
        cancelButton.keyEquivalent = "\u{1b}"
        cancelButton.target = self
        cancelButton.action = #selector(cancelTapped)

        let buttons = NSStackView(views: [status, cancelButton, retryButton, fillButton])
        buttons.orientation = .horizontal
        status.setContentHuggingPriority(.defaultLow, for: .horizontal)
        status.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let stack = NSStackView(views: [searchField, scroll, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            stack.topAnchor.constraint(equalTo: root.topAnchor),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            searchField.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28),
            buttons.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -28),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 220),
        ])
        view = root
    }

    // MARK: - The system's entry points

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        mode = .passwords
        services = serviceIdentifiers.map(\.identifier)
        loadLogins()
    }

    override func prepareOneTimeCodeCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        mode = .oneTimeCodes
        services = serviceIdentifiers.map(\.identifier)
        loadLogins()
    }

    /// QuickType picked an identity and the app must answer with no UI. Succeeds only inside the
    /// grace window; otherwise the system is told to show the sheet.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        guard let itemId = credentialRequest.credentialIdentity.recordIdentifier else {
            fail(.credentialIdentityNotFound)
            return
        }
        let oneTimeCode = credentialRequest.type == .oneTimeCode
        let request: AutoFillRequest =
            oneTimeCode
            ? .oneTimeCode(itemId: itemId, interactive: false)
            : .credential(itemId: itemId, interactive: false)
        send(request) { [weak self] response in
            guard let self else { return }
            switch response {
            case .credential, .oneTimeCode:
                self.complete(response)
            case .refused(.notFound, _):
                self.fail(.credentialIdentityNotFound)
            default:
                self.fail(.userInteractionRequired)
            }
        }
    }

    /// The sheet is up for one identity: one presence check in the app, then fill.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        searchField.isHidden = true
        scroll.isHidden = true
        fillButton.isHidden = true
        guard let itemId = credentialRequest.credentialIdentity.recordIdentifier else {
            fail(.credentialIdentityNotFound)
            return
        }
        let request: AutoFillRequest =
            credentialRequest.type == .oneTimeCode
            ? .oneTimeCode(itemId: itemId, interactive: true)
            : .credential(itemId: itemId, interactive: true)
        fetchInteractively(request)
    }

    override func prepareInterfaceForExtensionConfiguration() {
        searchField.isHidden = true
        scroll.isHidden = true
        fillButton.isHidden = true
        retryButton.isHidden = true
        cancelButton.title = String(localized: "Done")
        status.stringValue = String(
            localized:
                "Kagisecure is now an AutoFill provider. Unlock Kagisecure once, confirm with Touch ID, and your logins fill everywhere until the vault locks.")
    }

    // MARK: - Actions

    @objc private func searchChanged() {
        loadLogins()
    }

    @objc private func fillSelected() {
        let row = table.selectedRow
        guard row >= 0, row < logins.count else { return }
        let itemId = logins[row].id
        fetchInteractively(
            mode == .oneTimeCodes
                ? .oneTimeCode(itemId: itemId, interactive: true)
                : .credential(itemId: itemId, interactive: true))
    }

    @objc private func retryTapped() {
        retryButton.isHidden = true
        retry?()
    }

    @objc private func cancelTapped() {
        if cancelButton.title == String(localized: "Done") {
            extensionContext.completeExtensionConfigurationRequest()
        } else {
            fail(.userCanceled)
        }
    }

    // MARK: - Flow

    private func loadLogins() {
        let query = searchField.stringValue
        send(.logins(query: query.isEmpty ? nil : query, services: services)) { [weak self] response in
            guard let self else { return }
            switch response {
            case .logins(let items):
                self.logins = self.mode == .oneTimeCodes ? items.filter(\.hasOneTimeCode) : items
                self.table.reloadData()
                if !self.logins.isEmpty { self.table.selectRowIndexes([0], byExtendingSelection: false) }
                self.status.stringValue =
                    self.logins.isEmpty ? String(localized: "No matching logins") : ""
                self.retryButton.isHidden = true
            case .refused(.locked, _):
                self.showLocked { [weak self] in self?.loadLogins() }
            default:
                self.status.stringValue = Self.sentence(for: response)
            }
        }
    }

    private func fetchInteractively(_ request: AutoFillRequest) {
        status.stringValue = String(localized: "Confirm in Kagisecure…")
        send(request) { [weak self] response in
            guard let self else { return }
            switch response {
            case .credential, .oneTimeCode:
                self.complete(response)
            case .refused(.locked, _):
                self.showLocked { [weak self] in self?.fetchInteractively(request) }
            case .refused(.notFound, _):
                self.fail(.credentialIdentityNotFound)
            default:
                self.status.stringValue = Self.sentence(for: response)
            }
        }
    }

    private func showLocked(retry: @escaping () -> Void) {
        self.retry = retry
        retryButton.isHidden = false
        status.stringValue = String(
            localized: "Kagisecure is locked or not running. Unlock it, then click Try Again.")
        openApp()
    }

    /// Launch or raise the app so the person can unlock it.
    private func openApp() {
        // The containing app: two levels above this .appex (Contents/PlugIns/X.appex).
        let app = Bundle.main.bundleURL
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: app, configuration: configuration) { _, _ in }
    }

    private func complete(_ response: AutoFillResponse) {
        switch response {
        case .credential(let username, let password):
            extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: username, password: password),
                completionHandler: nil)
        case .oneTimeCode(let code):
            extensionContext.completeOneTimeCodeRequest(
                using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
        default:
            fail(.failed)
        }
    }

    private func fail(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }

    /// Exchange off the main thread; answer on it. A socket failure reads as "locked", which is
    /// what it almost always means: the app is not running.
    private func send(_ request: AutoFillRequest, then: @escaping @MainActor (AutoFillResponse) -> Void) {
        let group = Self.appGroup
        DispatchQueue.global(qos: .userInitiated).async {
            let response: AutoFillResponse
            if let path = ProcessInfo.processInfo.environment["KAGISECURE_AUTOFILL_SOCKET"]
                ?? group.flatMap({ AutoFillChannel.socketPath(groupIdentifier: $0) })
            {
                do {
                    response = try AutoFillWire.exchange(path: path, request)
                } catch {
                    Self.log.error("exchange failed: \(String(describing: error), privacy: .public)")
                    response = .refused(.locked, message: "")
                }
            } else {
                response = .refused(.failed, message: "")
            }
            if case .refused(let reason, _) = response {
                Self.log.info("refused: \(reason.rawValue, privacy: .public)")
            }
            DispatchQueue.main.async { MainActor.assumeIsolated { then(response) } }
        }
    }

    private static func sentence(for response: AutoFillResponse) -> String {
        guard case .refused(let reason, _) = response else { return "" }
        switch reason {
        case .cancelled: return String(localized: "Not confirmed — nothing filled")
        case .busy: return String(localized: "Another confirmation is in progress")
        case .untrusted, .failed:
            return String(localized: "Kagisecure could not provide this login")
        case .interactionRequired, .locked, .notFound:
            return String(localized: "Kagisecure could not provide this login")
        }
    }
}

extension CredentialProviderViewController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { logins.count }

    func tableView(
        _ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int
    ) -> NSView? {
        let login = logins[row]
        let title = NSTextField(labelWithString: login.title)
        title.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
        let detail = NSTextField(
            labelWithString: [login.username, login.domains.first].compactMap { $0 }
                .joined(separator: " · "))
        detail.textColor = .secondaryLabelColor
        detail.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        detail.lineBreakMode = .byTruncatingTail
        let stack = NSStackView(views: [title, detail])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 1
        return stack
    }
}
