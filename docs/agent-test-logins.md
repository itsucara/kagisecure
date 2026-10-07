# Agent test logins

Status: **built for macOS** ([ADR-0048](decisions/0048-agent-test-logins.md), Phases 1a, 1b and
3). An AI agent testing an app creates test users whose passwords kagisecure generates and keeps.
No tool ever returns the password; the agent fills it into the app's sign-up and login forms with
`request_fill`, or hands it to a test process with `run_with_env`. Not on Windows, not in
`kagisecure daemon`, and not on the unattended socket.

> **What this does not protect.** ACCEPTED. kagisecure never returns the password through any
> tool, so a well-behaved agent keeps it out of its transcript and the provider's logs. It types
> the value into a page the agent drives, or pipes it to a command the agent chose, and the app
> under test receives it. An agent that runs script in that page, chooses that command, or
> controls that app can read it. Agent test logins accept this: the value is random, protects only
> a test account on a site you allowed, and is never anyone's real password.

## 1. Turning it on

**Settings › AI Agents › Agent test logins › "Let agents create test logins"** — off by default;
turning it on asks for Touch ID once and creates a personal vault named **Agent test logins**.
While it is off, `create_test_login`, `list_test_logins` and `trash_test_logins` answer
`TEST_LOGINS_OFF`, and no fill or run takes the no-sheet paths below. Items already created stay.

The same section holds the **allowed domains**: registrable domains (`example.com`, never an IP
address, a single label or a public suffix) where test logins need no sheet. Adding one asks for
Touch ID. `localhost`, loopback addresses, `*.localhost` and `*.test` are always allowed. Private
LAN addresses are not.

## 2. The tools

[mcp-server.md](mcp-server.md) §2.11–§2.13 has the schemas. In short:

| Tool | What it does | Sheet |
| --- | --- | --- |
| `create_test_login` | Generates and seals a login in the test vault; returns its id, username, websites and title. `status: "exists"` (nothing written) when a sealed login with that username already covers the websites | none when every website is allowed; otherwise a sheet and Touch ID, every time |
| `list_test_logins` | Sealed, live test logins: id, title, username, websites, tags, purpose, creation time | none |
| `trash_test_logins` | Moves the sealed test logins matching `website` and/or `tag` to the trash, in one transaction with one audit entry | none; refused outright if any match is saved for a website that is not allowed |
| `request_fill` with `["username", "new_password"]` | Fills a sealed login into an app's sign-up form | none at an allowed origin |
| `request_fill` with `["username", "password"]` | Signs in with it | none at an allowed origin |

The password is generated inside the vault transaction from a fixed menu (length 20, 24, 32, 48
or 64; symbols on or off; ambiguous characters avoided or not; at least 100 bits), sealed with an
HMAC under a key derived from the vault key, and never crosses FFI, IPC or MCP. Editing it by hand
breaks the seal, and the item becomes an ordinary login from then on. Test logins are never
offered to you by the browser extension or by system AutoFill; you can still open them in the app.

Creates are limited to **10 per agent in any 10 minutes** and **200 live items** in the vault
(`RATE_LIMITED`). Every create, fill, bind and trash is audited with the agent's full identity.

The order matters: **create the user in kagisecure first, then in the app** — with a sign-up fill
or by seeding (§4). An agent that created the user in the app first would have chosen the password
itself.

## 3. Cleaning up

When a test environment is rebuilt, the agent calls `trash_test_logins` with a `website` or a
`tag` (one is required) and a `reason`, then creates fresh users. It is a soft trash: you can
restore the items, and emptying the trash stays your act. A trashed login is no longer listed, no
longer reused as `exists`, and no longer fills.

From a terminal:

```console
$ kagisecure test-logins list --tag app:shop
$ kagisecure test-logins trash --website http://localhost:47800
```

`kagisecure test-logins trash` is yours, not an agent's: it is not limited to allowed websites,
and it works with the switch off. It still touches only sealed logins in the test vault, in one
transaction with one audit entry (actor `cli`).

## 4. Tests outside a browser

For XCUITest, API tests, or a seeding script, the password reaches the test process through
`run_with_env` (or `write_env_file`). Bind the login to two variables when creating it:

```json
{
  "name": "create_test_login",
  "arguments": {
    "app": "shop", "purpose": "buyer", "username": "buyer1@example.test",
    "websites": ["http://localhost:47800"],
    "bind": { "environment": "shop-e2e", "username_var": "SHOP_USER", "credential_var": "SHOP_PASS" }
  }
}
```

The environment is created in the test vault if none has that name, and both bindings are written
in the same transaction as the login. **You approve the binding once**, on the ordinary
`add_variables` sheet — a binding is a standing route to the value. Calling again with the same
username and a new environment binds the existing login there (`status: "exists"`, one more
sheet); calling again with a binding already in place asks nothing. The reply's `binding` carries
the `environment_id` to pass to `run_with_env`.

A `run_with_env` or `write_env_file` whose **every** selected variable is bound to a sealed test
login rides the app's presence grace window, as agent fills do: inside it, no sheet and no Touch
ID; outside it, the sheet and Touch ID. A request that selects any other variable is unchanged.

Delivering the values:

- **Environment delivery is the default and the right one for test runners.** The variables land
  in the child's environment block.
- **XCUITest.** `xcodebuild test` passes a variable named `TEST_RUNNER_<NAME>` to the test runner
  as `<NAME>`. Bind `TEST_RUNNER_SHOP_USER` and `TEST_RUNNER_SHOP_PASS`, run
  `/usr/bin/xcodebuild test …` through `run_with_env`, and read
  `ProcessInfo.processInfo.environment["SHOP_PASS"]` in the test. To hand it on to the app under
  test, copy it into `XCUIApplication().launchEnvironment`.
- **Playwright and other Node runners.** Run `/opt/homebrew/bin/npx playwright test` (or your
  absolute path) through `run_with_env` and read `process.env.SHOP_PASS`.
- **API seeding.** A script that `POST`s the user to the app's own sign-up or admin API, run
  through `run_with_env`, reading the variables from its environment.
- **Standard input** (`delivery: "stdin"`) only for a consumer that parses `NAME\0VALUE\0` pairs —
  a secret store's `--value-stdin` style command, or a small wrapper of your own. A test runner
  does not read that format.
- **Use absolute paths.** The command inherits the app's environment, and an app started from the
  Finder or the Dock has launchd's minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`): `npx`, `node`
  or a Homebrew tool will not be found by name.
- **8 KiB.** Stdin delivery writes at most 8 KiB, all pairs together; credentials are far shorter.

Output is scrubbed of the injected values by default, so a test that prints the password shows a
redaction marker, not the value — but the command is the agent's, which is the accepted risk
above.

## 5. Browser tests driven by Playwright

The sign-up and login fills need the kagisecure extension in the browser the agent drives.
[browser-extension.md](browser-extension.md) §5 has the recipe: branded Google Chrome 137 and later
ignores `--load-extension`, so launch Microsoft Edge or Playwright's own Chromium with a persistent
profile that loads the extension from the installed app and carries the native-messaging manifest.

## 6. The test app

`e2e/lib/test-app.mjs` is a small, dependency-free web app with real register and login forms
(passwords kept only as scrypt hashes, bodies never logged). Run `node e2e/lib/test-app.mjs` and
open `http://localhost:47800/register` to try the flow by hand; the e2e suite starts it on its own
port.
