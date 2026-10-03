import XCTest

/// The approval sheet, raised by a real request from a real MCP sidecar (ui-spec.md §10,
/// mcp-server.md §4).
///
/// # Why this is the scenario the suite exists for
///
/// Suite A already proves the nine tools, the lease rules and the audit chain — against
/// `kagisecure daemon`, whose approval channel is a `y`/`N` on a terminal. The *product's* approval
/// channel is this sheet, behind `LAContext`, and docs/e2e-harness.md §6 says in as many words that
/// there is deliberately no environment variable that stubs it: "XCUITest can press the real
/// button." This is that.
///
/// What is real here: `kagisecure-mcp`, the unix socket, the app's `kagisecure-agent` listener,
/// `ApprovalQueue::ask`, the sheet, `agentResolve`, the lease store, the `.env` writer and the audit
/// chain. What is replaced: the fingerprint, by `ScriptedBiometricGate`, injected through a
/// `#if DEBUG` launch argument that does not exist in a release build.
final class K_ApprovalTests: UITestCase {
    private var sidecar: Sidecar?
    private var project: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        project = scratch.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        sidecar?.stop()
        sidecar = nil
        try super.tearDownWithError()
    }

    // MARK: - Scenarios

    func testAWriteEnvFileRequestRaisesTheSheetAndDenyReturnsUserDenied() throws {
        try seedAgentVault()
        launch()
        unlock()
        let environmentId = try startSidecarAndFindEnvironment()

        let call = callWriteEnvFile(environmentId: environmentId)

        step("the sheet says who is asking, what for, and where") {
            waitFor("ks.approval.sentence", timeout: Self.timeout)
            capture("approval-sheet", "The approval sheet, on a real write_env_file request")

            let sentence = text("ks.approval.sentence")
            XCTAssertTrue(
                sentence.contains("wants to write"),
                "the sheet must say in plain language what is about to happen: \(sentence)")
            XCTAssertTrue(
                sentence.contains("\u{201C}kagisecure-uitest\u{201D}"),
                "a caller's self-reported name is shown in quotation marks, because that is all it "
                    + "is — a claim (ui-spec.md §10.2). Sentence was: \(sentence)")

            // Under ad-hoc signing nothing can be attributed to a developer, so the honest verdict
            // is "unverified" — and the sheet saying "verified" here would be the single worst bug
            // this suite could miss (ADR-0015).
            let verdict = text("ks.approval.verdict")
            XCTAssertTrue(
                verdict.lowercased().contains("unverified"),
                "an ad-hoc-signed sidecar is not attributable to anybody; the sheet said: \(verdict)")
            XCTAssertTrue(element("ks.approval.evidence").exists, "the verdict needs its reason")
            XCTAssertTrue(element("ks.approval.process").exists, "the pid and path belong on it")

            XCTAssertTrue(
                element("ks.approval.variable.ACME_TOKEN").exists,
                "the variable names are the point of the sheet")
            XCTAssertTrue(
                text("ks.approval.variablesNote").contains("Names only"),
                "and the sheet has to say that names are all it is showing")

            let path = text("ks.approval.targetPath")
            XCTAssertTrue(
                path.contains(project.path) || path.contains(project.lastPathComponent),
                "the canonicalized target path belongs on the sheet; saw \(path)")

            XCTAssertTrue(
                element("ks.approval.ttlSlider").exists,
                "the TTL is editable down, never up (mcp-server.md §5)")
            // Beside the buttons, not in the scroll area: it is "Allow for this session"'s
            // argument, and it has to be on screen whenever that button is (ui-spec.md §10.2).
            XCTAssertTrue(
                element("ks.approval.ttlMinutesField").isHittable,
                "the TTL's exact control is on screen without scrolling; its frame is "
                    + "\(element("ks.approval.ttlMinutesField").frame)")
            XCTAssertTrue(element("ks.approval.countdown").exists, "the 60-second window is shown")
            XCTAssertTrue(
                text("ks.approval.summary").contains("ACME_TOKEN"),
                "the one-line scope summary names what is granted")

            record(
                "approval-sheet-text",
                [
                    text("ks.approval.sentence"),
                    text("ks.approval.verdict"),
                    text("ks.approval.evidence"),
                    text("ks.approval.reportedName"),
                    text("ks.approval.summary"),
                ].joined(separator: "\n"),
                "Every sentence the sheet showed")
        }

        step("the gitignore callout is there, because the project is a git work tree") {
            XCTAssertTrue(
                element("ks.approval.gitignoreWarning").exists,
                "a .env inside a git work tree that does not ignore it is committable, and the "
                    + "sheet says so in red (ui-spec.md §10.2)")
            capture("approval-gitignore", "The \"Not gitignored\" callout")
        }

        try step("Deny returns USER_DENIED and writes nothing") {
            click("ks.approval.deny")
            waitForDisappearance("ks.approval.sentence")

            let result = try XCTUnwrap(call.wait(), "the tool call never came back")
            XCTAssertFalse(result.ok, "a denied request is a tool error")
            XCTAssertTrue(
                result.text.contains("USER_DENIED"),
                "mcp-server.md §7 spells a refusal USER_DENIED; got: \(result.text)")
            XCTAssertFalse(
                FileManager.default.fileExists(atPath: project.appendingPathComponent(".env").path),
                "nothing may be written when the user said no")
            record("approval-denied", result.text, "What the agent was told")
            capture("approval-after-deny", "Back to the main window, nothing granted")
        }

        try step("and the denial is in the audit log") {
            let audit = try Harness.cliOk(["audit", "--limit", "50"], vault: vaultPath)
            XCTAssertTrue(
                audit.stdout.contains("write_env_file") && audit.stdout.lowercased().contains("denied"),
                "a denial is kept deliberately — it is the only evidence a user gets that "
                    + "something tried (mcp-server.md §6). Log was:\n\(audit.stdout)")
            record("approval-audit-denied", audit.stdout, "The audit log after the denial")
        }
    }

    func testAllowOnceWritesTheFileAndMintsNoReusableLease() throws {
        try seedAgentVault()
        launch()
        unlock()
        let environmentId = try startSidecarAndFindEnvironment()

        let call = callWriteEnvFile(environmentId: environmentId)
        waitFor("ks.approval.sentence")

        step("Allow once goes through the biometric gate") {
            click("ks.approval.allowOnce")
            waitForDisappearance("ks.approval.sentence", timeout: Self.timeout)
        }

        try step("the file is on disk, 0600, with the variable in it") {
            let result = try XCTUnwrap(call.wait(), "the tool call never came back")
            XCTAssertTrue(result.ok, "the write should have succeeded: \(result.text)")

            let envFile = project.appendingPathComponent(".env")
            XCTAssertTrue(FileManager.default.fileExists(atPath: envFile.path))
            let contents = try String(contentsOf: envFile, encoding: .utf8)
            XCTAssertTrue(contents.contains("ACME_TOKEN="), "the variable should be in the file")

            let attributes = try FileManager.default.attributesOfItem(atPath: envFile.path)
            XCTAssertEqual(
                attributes[.posixPermissions] as? NSNumber, 0o600,
                "a .env full of secrets is not world-readable (mcp-server.md §2.7)")

            // The canary: the value reached the *file*, which is the point, and must not have
            // reached the agent's result text on the way.
            XCTAssertFalse(
                result.text.contains(Self.canary),
                "the value must never come back to the caller")
            record("approval-allow-once", result.text, "What the agent was told")
        }

        step("\"Allow once\" leaves nothing behind to reuse") {
            // `uses_remaining: 1`, consumed by the write. The next identical request re-prompts,
            // which is the whole difference between this button and the other one (ui-spec.md §10.3).
            clickSidebarRow("ks.sidebar.agentLeases")
            waitFor("ks.leases.revokeAll")
            XCTAssertTrue(
                element("ks.leases.empty").waitForExistence(timeout: Self.shortTimeout),
                "an \"Allow once\" lease is used up by the write it authorised")
            capture("approval-leases-empty-after-allow-once", "No lease survives \"Allow once\"")
        }

        step("so a second identical request asks again") {
            let second = callWriteEnvFile(environmentId: environmentId, overwrite: true)
            XCTAssertTrue(
                element("ks.approval.sentence").waitForExistence(timeout: Self.timeout),
                "the next identical request must re-prompt")
            capture("approval-second-prompt", "The same request, asked again")
            click("ks.approval.deny")
            _ = second.wait()
        }
    }

    func testAllowForThisSessionMintsALeaseThatLockingRevokes() throws {
        try seedAgentVault()
        launch()
        unlock()
        let environmentId = try startSidecarAndFindEnvironment()

        let call = callWriteEnvFile(environmentId: environmentId)
        waitFor("ks.approval.sentence")

        step("the TTL can be shortened, never lengthened") {
            // Through the minutes field and its stepper (`ExactNumberField`): the keyboard's way
            // to the TTL, and an exact one — see `UITestCase.setNumber`. The caller asked for the
            // default, 900 s (mcp-server.md §5).
            let field = "ks.approval.ttlMinutesField"
            XCTAssertEqual(element(field).value as? String, "15", "the sheet opens at what was asked")
            XCTAssertEqual(text("ks.approval.ttlValue"), "15 minutes")

            setNumber("99", in: "ks.approval.ttlMinutes")
            XCTAssertTrue(
                waitForValue(field, equals: "15"),
                "the user may shorten what the agent asked for, never lengthen it "
                    + "(mcp-server.md §5); typed 99, the field reads "
                    + "\(String(describing: element(field).value))")
            nudge("ks.approval.ttlMinutes", up: true)
            XCTAssertEqual(
                element(field).value as? String, "15", "and the stepper stops at the request too")
            XCTAssertEqual(text("ks.approval.ttlValue"), "15 minutes")

            setNumber("0", in: "ks.approval.ttlMinutes")
            XCTAssertTrue(
                waitForValue(field, equals: "1"), "the floor is one minute; typed 0, it took 1")
            XCTAssertEqual(text("ks.approval.ttlValue"), "1 minute")

            setNumber("10", in: "ks.approval.ttlMinutes")
            XCTAssertTrue(waitForValue(field, equals: "10"), "a TTL inside the range is taken as typed")
            nudge("ks.approval.ttlMinutes", up: false)
            XCTAssertTrue(waitForValue(field, equals: "9"), "the stepper moves it by one minute")
            nudge("ks.approval.ttlMinutes", up: true)
            XCTAssertTrue(waitForValue(field, equals: "10"))
            XCTAssertEqual(text("ks.approval.ttlValue"), "10 minutes")
            XCTAssertTrue(
                text("ks.approval.summary").contains("for 10 minutes"),
                "the scope summary says what will actually be granted; it said "
                    + "\(text("ks.approval.summary"))")
            record("approval-ttl", "requested: 15 minutes\nshortened to: 10 minutes", "The TTL control")
            capture("approval-ttl", "The TTL control, after being shortened to ten minutes")
        }

        try step("Allow for this session") {
            click("ks.approval.allowSession")
            waitForDisappearance("ks.approval.sentence", timeout: Self.timeout)
            let result = try XCTUnwrap(call.wait())
            XCTAssertTrue(result.ok, result.text)
        }

        step("the lease is in the table, with what it grants") {
            clickSidebarRow("ks.sidebar.agentLeases")
            waitFor("ks.leases.revokeAll")
            XCTAssertTrue(
                element("ks.leases.table").waitForExistence(timeout: Self.shortTimeout),
                "an approved session should be a row in the only place leases are visible")
            XCTAssertTrue(
                elements("ks.leases.cell.variables").allElementsBoundByIndex
                    .contains { text(of: $0).contains("ACME_TOKEN") },
                "the row says which variables it covers")
            // The shortened TTL is what was minted, not the 15 minutes asked for. "Expires in"
            // counts down and rounds down, so a ten-minute lease a few seconds old reads 9.
            let expires = text("ks.leases.cell.expires")
            XCTAssertTrue(
                ["10 minutes", "9 minutes"].contains(expires),
                "the lease carries the TTL the user shortened it to; it expires in \(expires)")
            capture("approval-lease", "The lease minted by \"Allow for this session\"")
        }

        step("locking the vault takes it all away, and shreds the file") {
            let envFile = project.appendingPathComponent(".env")
            XCTAssertTrue(FileManager.default.fileExists(atPath: envFile.path))

            app.typeKey("\\", modifierFlags: .command)
            waitFor("ks.lock.title")
            capture("approval-locked", "Locked — every lease is gone with the key")

            XCTAssertFalse(
                FileManager.default.fileExists(atPath: envFile.path),
                "locking shreds what a lease wrote (ADR-0004, mcp-server.md §5)")

            type(Harness.password, into: "ks.lock.password")
            click("ks.lock.unlock")
            waitFor("ks.sidebar.all")
            clickSidebarRow("ks.sidebar.agentLeases")
            XCTAssertTrue(
                element("ks.leases.empty").waitForExistence(timeout: Self.shortTimeout),
                "leases are memory-only and do not come back with the vault")
            capture("approval-leases-after-lock", "No leases survived the lock")
        }

        try step("the audit log has the allowed call, and its chain still verifies") {
            let audit = try Harness.cliOk(["audit", "--limit", "50"], vault: vaultPath)
            XCTAssertTrue(audit.stdout.contains("write_env_file"))
            record("approval-audit-allowed", audit.stdout, "The audit log after the approval")

            clickSidebarRow("ks.sidebar.agentAudit")
            waitFor("ks.audit.chainState")
            XCTAssertTrue(
                text("ks.audit.chainState").contains("intact"),
                "the audit viewer's footer is where a broken chain would show")
            capture("approval-audit-view", "The audit viewer after the approval")
        }
    }

    func testTheSheetComesBackWhenTheFingerprintIsCancelled() throws {
        try seedAgentVault()
        // The gate answers "cancelled", which ui-spec.md §10.3 is explicit is **not** a denial: a
        // fumbled fingerprint must return to the dialog rather than be mistaken for a policy
        // decision. Nothing else in the suite exercises that distinction.
        launch(biometrics: "cancel")
        unlock()
        let environmentId = try startSidecarAndFindEnvironment()

        let call = callWriteEnvFile(environmentId: environmentId)
        waitFor("ks.approval.sentence")

        step("a cancelled fingerprint keeps the sheet up and says nothing was granted") {
            click("ks.approval.allowOnce")
            let problem = waitFor("ks.approval.biometricProblem", timeout: Self.timeout)
            XCTAssertTrue(
                text(of: problem).contains("Nothing has been granted"),
                "the sheet must say the cancellation granted nothing: \(text(of: problem))")
            XCTAssertTrue(
                element("ks.approval.sentence").exists,
                "the sheet stays up — a cancelled biometric is not a decision (ui-spec.md §10.3)")
            capture("approval-biometric-cancelled", "A cancelled fingerprint, back at the sheet")
        }

        try step("and the request is still answerable") {
            click("ks.approval.deny")
            let result = try XCTUnwrap(call.wait())
            XCTAssertTrue(result.text.contains("USER_DENIED"), result.text)
        }
    }

    func testABrowserFillRequestIsPendingBecauseTheHostNeedsABrowserParent() throws {
        throw XCTSkip(
            "The fill_credential variant of this sheet is not driven here. kagisecure-nmhost "
                + "refuses to serve unless its process ancestry names a real browser — that gate is "
                + "the feature (threat-model-browser-extension.md), and an XCUITest runner is not a "
                + "browser. Driving it would mean either launching Edge from inside the UI-test "
                + "bundle, which duplicates suite B's whole apparatus one process further away, or "
                + "switching the ancestry gate off, which would test a build nobody ships. Suite B "
                + "covers the channel with a real browser and the real host; what stays uncovered "
                + "is only the SwiftUI rendering of §10.5, which "
                + "apps/macos/KagisecureTests/FillApprovalTests.swift asserts against the same "
                + "request record this sheet is built from.")
    }

    // MARK: - The world

    /// A 32-byte marker seeded as the environment's only value. If it reaches the agent, the sheet,
    /// or the audit log, the product has failed at the one thing it exists to do.
    private static let canary = "KSUI-C4N4RY-7f3a1e9d052b46c8a1de"

    /// A vault shaped like the one suite A uses: one agent-visible environment bound to one
    /// concealed field, and a second, private one that proves default-deny is refusing rather than
    /// the vault being empty.
    private func seedAgentVault() throws {
        try Harness.cliOk(["vault", "init", "--name", "Personal"] + Harness.cheapKdf, vault: vaultPath)
        try Harness.cliOk(
            [
                "item", "add", "--title", "Acme staging", "--category", "api-credential",
                "--field", "endpoint=https://api.acme.example", "--secret", "token",
                "--value-stdin",
            ],
            vault: vaultPath, stdin: [Self.canary])
        try Harness.cliOk(
            ["env", "create", "acme / staging", "--agent-visible"], vault: vaultPath)
        try Harness.cliOk(
            [
                "env", "add-var", "--environment", "acme / staging", "--name", "ACME_TOKEN",
                "--bind", "Acme staging/token",
            ],
            vault: vaultPath)
        try Harness.cliOk(
            ["env", "agent-access", "--allow", "--logical-vault", "Personal"], vault: vaultPath)
        try Harness.cliOk(
            ["env", "agent-access", "--allow", "--item", "Acme staging"], vault: vaultPath)

        // A git work tree with no `.gitignore`, so the sheet's "Not gitignored" callout has
        // something true to say. `git init` rather than a hand-made `.git` directory: the check is
        // `envfile::gitignore_status`, and it walks a real repository.
        let git = Process()
        git.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        git.arguments = ["init", "--quiet", project.path]
        git.standardOutput = FileHandle.nullDevice
        git.standardError = FileHandle.nullDevice
        try git.run()
        git.waitUntilExit()
    }

    private func unlock() {
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
        // The listener binds on unlock. Until the sidebar footer says so, a sidecar that connects
        // gets a closed socket and the scenario fails for the wrong reason.
        XCTAssertTrue(
            element("ks.sidebar.listenerState").waitForExistence(timeout: Self.timeout))
        let deadline = Date().addingTimeInterval(Self.timeout)
        while Date() < deadline {
            if text("ks.sidebar.listenerState") == "Serving agents" { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
        XCTFail(
            "the app never bound its IPC listener at \(socketPath!). "
                + "Agent access would say why: "
                + (element("ks.agentAccess.listenerError").exists
                    ? text("ks.agentAccess.listenerError") : "nothing shown"))
    }

    /// Start a real sidecar against the app's socket and find the environment an agent can see.
    private func startSidecarAndFindEnvironment() throws -> String {
        let sidecar = try Sidecar(socket: socketPath, cwd: project)
        self.sidecar = sidecar
        XCTAssertNotNil(sidecar.initialize(), "the sidecar did not answer initialize")

        let listed = try XCTUnwrap(sidecar.call("list_environments"), "list_environments timed out")
        XCTAssertTrue(listed.ok, listed.text)
        XCTAssertFalse(
            listed.text.contains(Self.canary), "a listing must never carry a value")
        XCTAssertFalse(
            listed.text.contains("private"),
            "an environment nobody shared must not be listed at all")

        let environments = (listed.structured?["environments"] as? [[String: Any]]) ?? []
        let match = environments.first { ($0["name"] as? String) == "acme / staging" }
        return try XCTUnwrap(
            match?["id"] as? String,
            "the shared environment should be listed; the agent saw: \(listed.text)")
    }

    /// A `write_env_file` call, made from a background queue.
    ///
    /// It has to be off the main thread: the call blocks until somebody answers the sheet, and the
    /// thing that answers the sheet is this test, on the main thread. A synchronous call here would
    /// deadlock against its own approval.
    private func callWriteEnvFile(environmentId: String, overwrite: Bool = false) -> PendingCall {
        let pending = PendingCall()
        let sidecar = self.sidecar
        let directory = project.path
        DispatchQueue.global().async {
            pending.finish(
                sidecar?.call(
                    "write_env_file",
                    [
                        "environment_id": environmentId,
                        "directory": directory,
                        "overwrite": overwrite,
                    ],
                    timeout: 120))
        }
        return pending
    }
}

/// A tool call in flight, so the main thread can drive the sheet and then collect the answer.
///
/// `@unchecked Sendable` for the same reason `Sidecar` is: it exists to cross exactly one thread
/// boundary, and its one mutable field is behind `lock`.
final class PendingCall: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Sidecar.ToolResult?

    func finish(_ value: Sidecar.ToolResult?) {
        lock.lock()
        result = value
        lock.unlock()
        semaphore.signal()
    }

    /// Block until the call comes back, or give up.
    func wait(timeout: TimeInterval = 120) -> Sidecar.ToolResult? {
        guard semaphore.wait(timeout: .now() + timeout) == .success else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return result
    }
}
