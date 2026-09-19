import XCTest

/// Agent access: environments, the pending-input flow, the leases table and the audit viewer
/// (ui-spec.md §10.4, mcp-server.md §2.6 and §6).
final class J_AgentAccessTests: UITestCase {
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

    func testAnEnvironmentIsCreatedAndGivenAVariableFromTheApp() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()

        step("Agent access starts empty, and explains itself") {
            clickSidebarRow("ks.sidebar.agentEnvironments")
            waitFor("ks.agentAccess.listenerState")
            XCTAssertTrue(
                element("ks.agentAccess.empty").waitForExistence(timeout: Self.shortTimeout),
                "a vault with no environments should offer to make one (ui-spec.md §12)")
            capture("agent-access-empty", "Agent access with no environments yet")
        }

        step("the listener says where it is serving") {
            XCTAssertEqual(
                text("ks.agentAccess.listenerState"), "Serving agents",
                "the pane's header carries the listener's state (ui-spec.md §10.4). "
                    + (element("ks.agentAccess.listenerError").exists
                        ? "It said: \(text("ks.agentAccess.listenerError"))" : ""))
            XCTAssertTrue(
                text("ks.agentAccess.endpoint").contains(socketPath),
                "and the socket it bound — this suite's, never the user's")
        }

        step("a new environment is not shared by default") {
            click("ks.agentAccess.newEnvironment")
            waitFor("ks.newEnvironment.name")
            type("acme / staging", into: "ks.newEnvironment.name")
            capture("agent-access-new-environment", "Creating an environment")
            click("ks.newEnvironment.create")

            waitFor("ks.agentAccess.row.acme / staging")
            waitFor("ks.environment.name")
            let share = waitFor("ks.environment.share")
            XCTAssertEqual(
                share.value as? Int ?? (share.value as? String).map { $0 == "1" ? 1 : 0 }, 0,
                "a new environment is hidden from agents until the user says otherwise — the "
                    + "middle of the three default-deny gates")
            XCTAssertTrue(element("ks.environment.noVariables").exists)
            capture("agent-access-environment", "The environment editor")
        }

        try step("a variable typed here never leaves the app") {
            type("DATABASE_URL", into: "ks.environment.newVariableName")
            type("postgres://svc_deploy@db.acme.internal/acme", into: "ks.environment.newVariableValue")
            click("ks.environment.addVariable")

            waitFor("ks.environment.variable.DATABASE_URL")
            XCTAssertEqual(
                text("ks.environment.binding.DATABASE_URL"), "Stored here",
                "a literal value is labelled as one, so a user can tell it from a field reference")
            capture("agent-access-variable", "A variable added by hand")

            // `env list` never prints a value, so its output is safe to attach — and it is the
            // independent check that the write reached the file rather than the view.
            let listing = try Harness.cliOk(["env", "list"], vault: vaultPath)
            XCTAssertTrue(listing.stdout.contains("DATABASE_URL"))
            XCTAssertFalse(
                listing.stdout.contains("postgres://"),
                "`env list` must never print a value")
            record("agent-access-env-list", listing.stdout, "`kagisecure env list`")
        }

        step("sharing it is one switch, and it says what sharing means") {
            click("ks.environment.share")
            let share = element("ks.environment.share")
            XCTAssertEqual(
                share.value as? Int ?? (share.value as? String).map { $0 == "1" ? 1 : 0 }, 1)
            XCTAssertTrue(
                element("ks.environment.description").exists
                    || element("ks.agentAccess.shareVault").exists)
            capture("agent-access-shared", "The environment, now shared with agents")
        }
    }

    func testTheAgentsPendingVariableIsFilledInTheAppAndNotInTheChat() throws {
        try seedAgentVault()
        launch()
        unlock()

        let sidecar = try Sidecar(socket: socketPath, cwd: project)
        self.sidecar = sidecar
        XCTAssertNotNil(sidecar.initialize())

        let listed = try XCTUnwrap(sidecar.call("list_environments"))
        let environments = (listed.structured?["environments"] as? [[String: Any]]) ?? []
        let environmentId = try XCTUnwrap(
            (environments.first { ($0["name"] as? String) == "acme / staging" })?["id"] as? String,
            listed.text)

        // `add_variables` is the one tool whose whole point is that it *cannot* carry a value:
        // the agent declares a name and a hint, and the schema gives it nowhere to put a secret.
        // The value is then typed here, in this window (mcp-server.md §2.6).
        let pending = PendingCall()
        DispatchQueue.global().async {
            pending.finish(
                sidecar.call(
                    "add_variables",
                    [
                        "environment_id": environmentId,
                        "variables": [
                            [
                                "name": "STRIPE_SECRET_KEY",
                                "hint": "the restricted key from the Stripe dashboard",
                            ]
                        ],
                    ],
                    timeout: 120))
        }

        step("the request raises the sheet, naming the variable and nothing else") {
            waitFor("ks.approval.sentence", timeout: Self.timeout)
            XCTAssertTrue(
                text("ks.approval.sentence").contains("add variables"),
                "the sentence should say what is being asked: "
                    + text("ks.approval.sentence"))
            XCTAssertTrue(element("ks.approval.variable.STRIPE_SECRET_KEY").exists)
            capture("agent-access-add-variables", "An agent asking to declare a variable")
            click("ks.approval.allowSession")
            waitForDisappearance("ks.approval.sentence", timeout: Self.timeout)
        }

        try step("the agent is told to go and ask the human") {
            let result = try XCTUnwrap(pending.wait())
            XCTAssertTrue(result.ok, result.text)
            XCTAssertTrue(
                result.text.lowercased().contains("pending")
                    || result.text.lowercased().contains("kagisecure"),
                "the reply should send the model to the app rather than invite it to supply a "
                    + "value: \(result.text)")
            record("agent-access-add-variables", result.text, "What the agent was told")
        }

        step("and the value is typed here, in a SecureField, with the agent's hint above it") {
            clickSidebarRow("ks.sidebar.agentEnvironments")
            waitFor("ks.agentAccess.listenerState")
            clickEnvironmentRow("acme / staging")

            waitFor("ks.environment.variable.STRIPE_SECRET_KEY")
            XCTAssertEqual(
                text("ks.environment.binding.STRIPE_SECRET_KEY"), "Pending",
                "a declared-but-unfilled variable is badged Pending (mcp-server.md §2.6)")
            XCTAssertTrue(
                text("ks.environment.hint.STRIPE_SECRET_KEY").contains("Stripe dashboard"),
                "the agent's hint is what tells the user what to paste")
            XCTAssertTrue(
                element("ks.agentAccess.pendingBadge.acme / staging").exists,
                "and the list row carries the count, so it is findable without opening it")
            capture("agent-access-pending", "A pending variable, waiting for the human")

            type("sk_live_typed_by_the_human", into: "ks.environment.pendingValue.STRIPE_SECRET_KEY")
            click("ks.environment.pendingSave.STRIPE_SECRET_KEY")

            XCTAssertEqual(
                text("ks.environment.binding.STRIPE_SECRET_KEY"), "Stored here",
                "once filled it is an ordinary literal")
            capture("agent-access-pending-filled", "The variable after the human filled it in")
        }

        try step("the agent still cannot read it") {
            let after = try XCTUnwrap(sidecar.call("list_environments"))
            XCTAssertTrue(after.text.contains("STRIPE_SECRET_KEY"), "the name is not a secret")
            XCTAssertFalse(
                after.text.contains("sk_live_typed_by_the_human"),
                "the value the human typed must never reach the caller")
            record("agent-access-after-fill", after.text, "What the agent sees afterwards")
        }
    }

    func testTheAuditViewerFiltersByToolAndVerifiesItsChain() throws {
        try Harness.seedVault(at: vaultPath)
        // A few CLI calls, so the log has more than one kind of row to filter.
        try Harness.cliOk(["item", "list"], vault: vaultPath)
        try Harness.cliOk(["env", "create", "scratch"], vault: vaultPath)
        launch()
        unlock()

        step("the viewer opens with everything, denials included") {
            clickSidebarRow("ks.sidebar.agentAudit")
            waitFor("ks.audit.chainState")
            XCTAssertTrue(
                element("ks.audit.table").waitForExistence(timeout: Self.shortTimeout)
                    || element("ks.audit.empty").exists)
            capture("audit-all", "The audit viewer")
        }

        step("the chain verdict is in the footer, where a broken chain would be") {
            let footer = text("ks.audit.chainState")
            XCTAssertTrue(
                footer.contains("intact"),
                "a vault this suite has only ever written through kagisecure must verify: \(footer)")
        }

        step("the Tool filter narrows to the two calls that move a secret toward a page") {
            // `fill_credential` and `totp_code` are named in the picker rather than left to
            // free-text search, because they are the two that matter most (AuditView's own note).
            click("ks.audit.filter.tool")
            app.menuItems["Fill credential"].click()
            XCTAssertTrue(
                element("ks.audit.empty").waitForExistence(timeout: Self.shortTimeout),
                "nothing in this scenario filled a credential, so the filter should empty the table")
            capture("audit-filter-fill", "The Tool filter, narrowed to fill_credential")

            click("ks.audit.filter.tool")
            app.menuItems["All tools"].click()
            XCTAssertTrue(
                element("ks.audit.table").waitForExistence(timeout: Self.shortTimeout),
                "and clearing it should bring the rows back")
        }

        step("the free-text filter works over the tool name") {
            type("env", into: "ks.audit.query")
            capture("audit-filter-query", "The audit viewer, filtered by text")
        }
    }

    func testTheLeasesTableSaysNothingIsGrantedOnAFreshVault() throws {
        try Harness.seedVault(at: vaultPath)
        launch()
        unlock()

        clickSidebarRow("ks.sidebar.agentLeases")
        waitFor("ks.leases.revokeAll")
        XCTAssertTrue(
            element("ks.leases.empty").waitForExistence(timeout: Self.shortTimeout),
            "the empty state is informational and is the truthful answer: nothing is granted")
        XCTAssertFalse(
            element("ks.leases.revokeAll").isEnabled,
            "Revoke All should be disabled when there is nothing to revoke")
        capture("leases-empty", "The leases table with nothing granted")
    }

    // MARK: - Helpers

    private func unlock() {
        type(Harness.password, into: "ks.lock.password")
        click("ks.lock.unlock")
        waitFor("ks.sidebar.all")
        let deadline = Date().addingTimeInterval(Self.timeout)
        while Date() < deadline {
            if text("ks.sidebar.listenerState") == "Serving agents" { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    /// Click a row in the environments list, falling back to the row's title text.
    private func clickEnvironmentRow(_ name: String) {
        let row = element("ks.agentAccess.row.\(name)")
        if row.waitForExistence(timeout: Self.shortTimeout), row.isHittable {
            row.click()
            return
        }
        let byLabel = app.descendants(matching: .any).matching(
            NSPredicate(format: "label == %@", name)
        ).firstMatch
        XCTAssertTrue(byLabel.waitForExistence(timeout: Self.shortTimeout), "no row called \(name)")
        byLabel.click()
    }

    private func seedAgentVault() throws {
        try Harness.cliOk(["vault", "init", "--name", "Personal"] + Harness.cheapKdf, vault: vaultPath)
        try Harness.cliOk(["env", "create", "acme / staging", "--agent-visible"], vault: vaultPath)
        try Harness.cliOk(
            ["env", "agent-access", "--allow", "--logical-vault", "Personal"], vault: vaultPath)
    }
}
