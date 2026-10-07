# The end-to-end harness

> Status: phase 2. Four suites run: the MCP sidecar, the browser extension, the CLI, and the
> macOS app through XCUITest (§7).

> **Warning — suite D takes over the mouse and keyboard for about thirty minutes.** XCUITest
> synthesizes real clicks and keystrokes at the window server, so anything else the machine is
> doing during that window gets typed into or clicked on instead. Run it only when the Mac is not
> in use. `make e2e` leaves it out by default; `make e2e SUITE=mcp,extension,cli` is the explicit
> way to skip it, and `E2E_GUI=1` is the explicit way to run it. See §7.7.

`make e2e` builds what it needs, runs every scenario across real processes, and writes a
self-contained HTML report and a merged JUnit XML. It exits non-zero if anything failed.

```console
$ make e2e                      # every suite except D (the macOS app)
$ make e2e SUITE=mcp            # one suite
$ make e2e SUITE=mcp,cli        # several
$ make e2e SUITE=app E2E_GUI=1  # the macOS app, on its own — only when the Mac is not in use
$ make e2e E2E_GUI=1            # every suite, D included
$ make e2e E2E_KEEP=1           # keep the temporary vaults, sockets and artifacts
$ node e2e/run.mjs --help       # the same thing, without make
```

Output:

| Path | What it is |
| --- | --- |
| `e2e/report/index.html` | Pass/fail per scenario with durations, embedded screenshots and log excerpts, failures in red, and an environment header |
| `e2e/report/junit.xml` | The same run, merged into one JUnit document for CI |

Both are regenerated every run and both are gitignored.

## 1. What "end to end" means here

The unit and integration tests already cover a great deal — 476 Rust tests, 91 Swift, 43
JavaScript. What they cannot cover is the seams: a real MCP client talking to a real sidecar over
a real socket to a real daemon; a real browser launching a real native host; the CLI's exit codes
as a script actually sees them. Those seams are where this harness lives.

Every scenario drives **production code paths**. The one thing that is replaced, everywhere, is the
human:

| Suite | What is real | What stands in for the human |
| --- | --- | --- |
| A — MCP | `kagisecure-mcp`, the socket, `kagisecure daemon` | `--auto-approve` / `--non-interactive` (ADR-0007) |
| B — extension | Edge, the unpacked extension, `kagisecure-nmhost`, the socket | `extension_harness`, a `cargo --example` binary |
| C — CLI | `kagisecure`, scratch vaults, the committed golden vector | nothing; the CLI needs no approval |
| D — app | The real `Kagisecure.app`, its `kagisecure-agent` listener, a real `kagisecure-mcp`, the approval sheet | `ScriptedBiometricGate`, injected by a `#if DEBUG` launch argument (§7) |

In A, B and D the stand-in still goes through `ApprovalQueue::ask` and answers through
`ApprovalQueue::resolve`. It is a robot in the chair, not a bypass around the chair, and a release
build refuses to do it at all. Suite D replaces less than the others: the sheet is found, read and
pressed by the test, and the only thing standing in for a human is the fingerprint — `LAContext`
cannot be answered by automation, so a `BiometricGate` double takes its place behind a launch
argument that does not exist outside a debug build.

**Nothing touches `~/Library/Application Support/kagisecure/`.** Every vault is created fresh under
the run directory, every socket is an explicit path, every CLI invocation passes `--vault`, and the
browser profile is a throwaway. The one thing the harness reads from the repo is the committed
golden vault vector, and it copies it out before opening it.

Suite D runs the **real app bundle**, with the real bundle identifier, so it has two more of these
to get right and does: `KAGISECURE_HOME` moves the vault, `KAGISECURE_SOCKET` moves the listener,
and `-KSUITestDefaultsSuite` moves `UserDefaults` into a throwaway suite the scenario deletes
afterwards. Without the third, a suite that has to set auto-lock to "Never" to test auto-lock would
be changing the security posture of the machine it ran on.

## 2. Why the runner is Node

The alternative was `cargo xtask e2e`, which is what the repo's own task-runner convention
(architecture §7) would suggest. Node won on three counts, and the trade is worth writing down
because the convention is real:

1. **Two of the three suites are already Node.** Playwright drives the browser one, and Playwright
   is a Node library. A Rust runner would shell out to Node for suite B either way.
2. **The MCP sidecar needs no client library.** It speaks newline-delimited JSON-RPC on stdio, so
   an MCP "client" here is forty lines of `JSON.parse` — and it *has* to be, because the
   secret-marker canary asserts on the sidecar's raw stdout bytes and any client library consumes
   that stream first. `crates/kagisecure-cli/tests/mcp.rs` hand-rolls the same protocol for the
   same reason.
3. **`node --test --test-reporter=junit` produces per-scenario JUnit for free**, which is exactly
   the artifact the runner needs from each suite.

What the convention buys elsewhere — one toolchain, no `package.json` sprawl — is preserved by the
runner having **no dependencies at all**. `e2e/run.mjs` and `e2e/lib/*.mjs` import nothing but
`node:` builtins, including the JUnit reader and the HTML renderer. The only third-party package in
the picture is Playwright, resolved out of `extensions/chrome/`'s existing install rather than a
second copy (see `loadPlaywright` in suite B).

## 3. How the runner and a suite fit together

The runner knows almost nothing about a suite. It:

1. Reads every `e2e/suites/*/suite.json`, sorted by `order`.
2. Runs each suite's `build` steps, and fails the suite if one does.
3. Runs the suite's `command`, with four environment variables set.
4. Reads back a JUnit XML file and an artifact manifest.
5. Merges everything into one report and one JUnit document.

```text
  e2e/run.mjs
    ├── lib/environment.mjs   measures the machine for the report header
    ├── lib/junit.mjs         reads JUnit fragments, writes the merged document
    ├── lib/report.mjs        renders index.html, with images and logs inlined
    ├── lib/harness.mjs       the CLI, the daemon and an MCP client, for suites to use
    └── lib/artifacts.mjs     the manifest a suite appends evidence to
```

| Variable | What a suite does with it |
| --- | --- |
| `E2E_JUNIT` | Write JUnit XML here. Anything the runner can find `<testcase>` elements in works. |
| `E2E_ARTIFACTS` | Write screenshots and logs here, and append a line to `manifest.jsonl` per item. |
| `E2E_RUN_DIR` | Scratch state: vaults, sockets, project directories, browser profiles. |
| `E2E_REPO_ROOT` | The checkout, for finding `target/debug/…`. |

`manifest.jsonl` is one JSON object per line — `{test, file, label, kind}` — where `test` equals
the JUnit `testcase` name and `kind` is `"image"` or `"log"`. JSON Lines rather than one document
because suites append from several scenarios and an append-only format has no read-modify-write
window to lose an entry in.

**That is the whole contract.** A suite in another language contributes to the same report by
writing the same two files, which is how phase 2's XCUITest bundle will plug in without the runner
changing.

### Where the temporary state lives, and why it is not under `e2e/`

`E2E_RUN_DIR` is `/tmp/kse2e-<run id>-<suite>`, not `e2e/tmp/`. A unix domain socket path has to
fit in `sockaddr_un::sun_path`, which is 104 bytes on macOS, and
`<repo>/e2e/tmp/<timestamp>/<suite>/daemon.sock` is most of that before accounting for a checkout
deeper than the author's. The failure is not subtle — the daemon refuses to start with `local
socket name length exceeds capacity of sun_path` — but it is exactly the kind of thing that works
on one machine and not another. `e2e/tmp/` holds the artifacts, which have no such limit.

Both are deleted at the end of a run unless `E2E_KEEP=1`, which prints the paths instead.

## 4. Adding a scenario

A scenario is a `test()` in the suite's test file. Two rules:

- **It builds its own world and tears it down.** Register the teardown *before* anything that can
  throw, so a failing assertion still stops the daemon or browser it started.
- **It asserts on the canary.** Every suite seeds a marker as a secret value; a scenario that could
  conceivably return one checks that it did not.

```js
test("a thing that should happen, happens", async (t) => {
  const fx = await fixture(t);              // registers t.after itself
  const result = await fx.sidecar.call("list_items");
  assert.equal(result.ok, true, result.text);
  recordText(t.name, "listing.txt", result.text, "what the agent saw");
  fx.assertNoLeak(result.text);
});
```

`recordText`, `record` and `screenshot` from `e2e/lib/artifacts.mjs` attach evidence. They are
no-ops outside the runner, so a suite is still runnable on its own:

```console
$ cd e2e/suites/mcp && node --test mcp.test.mjs
```

## 5. Adding a suite

Create `e2e/suites/<name>/suite.json`:

```json
{
  "name": "example",
  "title": "Suite D — something new",
  "order": 40,
  "description": "One sentence for the report.",
  "note": "Anything a reader needs to know about what this does and does not cover.",
  "build": [["cargo", "build", "-p", "whatever"]],
  "timeoutSeconds": 900,
  "command": ["node", "--test", "--test-reporter=junit",
              "--test-reporter-destination=${E2E_JUNIT}", "example.test.mjs"]
}
```

`${E2E_JUNIT}` and `${E2E_ARTIFACTS}` are substituted in `command`. The command runs with the suite
directory as its working directory. It does not have to be Node: a shell script that ends up
writing JUnit XML to `$E2E_JUNIT` is a suite.

A suite that exits non-zero without reporting a failing scenario gets one synthesised, with the log
tail attached — a crash before the reporter flushed must not be able to report itself green.

## 6. The first three suites

### Suite A — MCP agent flow (`e2e/suites/mcp/`)

Three processes: this runner as the MCP client, a real `kagisecure-mcp`, and a real `kagisecure
daemon`. 22 scenarios covering ten of the thirteen tools — the three agent test-login tools are served only by
the app, and the daemon's `TEST_LOGINS_OFF` for them is asserted by `crates/kagisecure-cli/tests/mcp.rs` — (`request_fill` only as far as the headless
daemon's `FILL_UNAVAILABLE` — for a visible item, a hidden one, an absent one and a one-time code
alike, before the item is looked up and with no audit entry; suite B drives it into a browser), the
default-deny rule, `describe_item` returning names only, the
`add_variables` pending flow, `write_env_file`'s 0600/atomic/gitignore behaviour, `run_with_env`
masking and `output: "none"`, lease reuse, use-count exhaustion, lease expiry, revocation, locking,
the audit chain, and a 32-byte random canary checked against every tool result and the sidecar's
raw streams.

**The slow one.** "A lease expires on its own" waits a real minute, because `ttl_seconds` is clamped
to a 60-second floor and the IPC boundary exposes no clock. It is the only scenario over a second,
and it is there because "leases are memory-only and die on expiry" is a claim that is either true
against a real clock or not made at all.

**The app-hosted variant is §7.** The daemon and the app run the same `kagisecure-agent` library
over the same socket; what differs is the approval channel — a terminal prompt versus a SwiftUI
sheet behind `LAContext`. Driving the app's half means driving its UI, which is what suite D does.
There is still deliberately no debug env var to stub the app's biometric gate: the double is
injected by a launch argument compiled out of a release build, because adding an env-var bypass to a
shipped binary is the thing ADR-0007 spends its length arguing against. XCUITest presses the real
button.

### Suite B — browser extension autofill (`e2e/suites/extension/`)

A real Chromium-family browser, the real unpacked extension from `extensions/shared/`, the real
`kagisecure-nmhost` **launched by the browser** so the process-ancestry gate is exercised rather
than switched off, a real socket, and `extension_harness` holding a real `ExtensionAgent`.
27 scenarios (25 run automatically; 2 report `skipped` on Safari), every state screenshotted into
the report.

**Asking about the active tab.** The popup is opened as an ordinary tab rather than the browser's
own toolbar popup, because that is the only way Playwright can drive it (§ below). That has one
consequence: `background.js`'s relay for `matches-active-tab` and `totp-active-tab` refuses any
request whose `sender.tab` is set — hardening added by commit `ded6bd3` so a content script cannot
forge the popup's own relay message and reach another tab's fill path with no trusted gesture
behind it — and a popup running as a tab now carries exactly that. So the harness's `ask()` answers
those two kinds by evaluating inside the **service worker** instead (`askActiveTabViaServiceWorker`
in `extension.test.mjs`), a devtools capability no page has, reproducing the relay's own logic
without going through `chrome.runtime.onMessage` at all — the same kind of capability
`the tab memory expires` already uses for `KsTabMemory.sweep`.

**Which browser.** Chrome 137 removed `--load-extension`; on Chrome 152 the switch is silently
ignored, the extension is not installed, and nothing is logged. Edge is the same Chromium with the
same MV3 and still honours it, so it is the automated browser. If no installed browser accepts the
switch, every scenario reports `skipped` with instructions rather than failing.

**Why the origins look like real websites.** The origin rule is "same scheme, same port, same
registrable domain under the Public Suffix List". Two ports on `localhost` exercise only the port
half, because `localhost` has no registrable domain and falls back to exact host equality. So the
browser is launched with `--host-resolver-rules=MAP * 127.0.0.1`, one local server answers for
every hostname, and the hostnames are chosen for where they sit on the list:

| Origin | Against an item saved for `app.example.com` and `alice.github.io` |
| --- | --- |
| `app.example.com:PORT` | fills — one of the saved sites |
| `www.example.com:PORT` | fills — same registrable domain |
| `alice.github.io:PORT` | fills — the item's second saved site |
| `mallory.github.io:PORT` | refused — `github.io` is a public suffix, so these are siblings |
| `app.example.com:OTHER` | refused — the port is part of the origin |
| `127.0.0.1:PORT` | refused — an IP literal, exact host match only |
| `app.examp1e.com:PORT` | refused — a look-alike one character off, used by the agent-fill scenarios |

Nothing leaves the machine.

**Several worlds, not one.** The allow-path scenarios share a browser and a harness. The denial
scenario gets its own, started with `extension_harness --deny` (a thread answering the queue with
`Decision::Deny`). The presence scenario gets its own, started with `extension_harness
--presence` — a thread that allows every full sheet for the session and denies every presence-only
prompt, which is the app with nobody at the keyboard after the first login; it asserts that a
`page.mouse.click` on the icon, trusted input synthesized over CDP exactly as an automation agent
sends it, fills nothing inside the lease's window
([ADR-0037](decisions/0037-every-fill-needs-a-fresh-presence-proof.md)). The lock scenario gets its
own, because a locked `VaultHandle` cannot be unlocked from outside. A suite whose scenarios only
pass in one order hides bugs.

**Agent-requested fills** ([ADR-0036](decisions/0036-agent-requested-browser-fill.md)) get four
worlds, one per scenario, each started with `extension_harness --agent-socket <path>
--agent-fill`: the harness also serves the MCP socket there, turns the broker's switch on and makes
the test item agent-visible, and the scenario speaks MCP to a real `kagisecure-mcp` pointed at it —
the same `Sidecar` client suite A uses. The scenarios are: an approved fill lands in the tab in
front; a look-alike (`app.examp1e.com`) raises no sheet, fills nothing, and a second mismatch
blocks the agent even on the real site; an identifier-first sign-in fills the password on page two
without a second sheet; and a one-time code lands in the page's code field and leaves the
clipboard as it was. Each has its own world because the broker's limits are per agent, and every
sidecar here has the same parent — this runner — which is what an agent is keyed on: three sheets
or one mismatch spent in one scenario would otherwise change what the next one is told. The robot
answering the queue prints a `sheet` event for every request it answers, which is how "no sheet"
and "no second sheet" are counted rather than inferred from the audit log.

> **Not yet run.** The four agent-fill scenarios are written and wired in, and load under
> `node --test`, but suite B opens a visible browser window and has not been run since they were
> added. The Rust tests in `crates/kagisecure-agent/tests/agent_fill*.rs` cover the same paths with
> a scripted service worker; what only this suite can show is the real extension answering the
> push in a real browser.

**The manifest.** This suite writes the native messaging manifest **only** into the throwaway
profile — on Edge 152 that is the copy a browser launched with `--user-data-dir` actually reads —
and never into `~/Library/Application Support/<browser>/NativeMessagingHosts/`. Its predecessor,
`extensions/chrome/e2e/fill.test.js`, wrote both and restored afterwards, which left the user's
real everyday browser pointing at a `target/debug` binary if the run was killed in between. That
test was removed when this one landed; `npm run e2e` no longer exists.

**Unattended sign-ins** ([ADR-0042](decisions/0042-unattended-agent-access.md) §12) are one more
scenario, in `unattended.test.mjs`, and it is **headless only** — it opens no window and takes no
focus, so it can run on a machine someone is working on:

    cargo build -p kagisecure-nmhost -p kagisecure-mcp
    cargo build -p kagisecure-agent --example unattended_harness
    cd e2e/suites/extension && node --test unattended.test.mjs

`unattended_harness` stands in for the app's unattended half: it writes a personal vault, a machine
vault with one Login item (a canary password), one job and one login grant, starts the real engine
with `run_browser` pointed at `extensions/shared` and the built `kagisecure-nmhost`, arms it and
starts the job once. The engine launches the **run browser** — Playwright's Chromium, else Microsoft
Edge, with `--headless=new`, `--ignore-certificate-errors` and the host-resolver rule above — and
the job, `unattended-job.mjs`, attaches to it at `KAGISECURE_RUN_BROWSER_CDP`, opens
`https://app.example.com:PORT/unattended-login.html` (served over https with a certificate
`openssl` makes for the run, since a login grant names an exact https origin), asks its own
`kagisecure-mcp` for `request_fill`, and submits the form. While the run is still up, the test
points a **second** headless browser at the run's own extension endpoint. It asserts: the page's
form post carried the canary; the machine log has `UNATTENDED_FILL_APPROVED (grant … run 1)` at
that exact origin and a `HOST_REFUSED` for the second browser; the grant was counted once and not
suspended; the run's profile is gone; and the canary is in no tool result, sidecar byte, harness
byte or audit entry. If no browser loads the extension headless, or `openssl` is missing, it
reports `skipped`.

**Safari** cannot be driven by automation here. Its two scenarios report `skipped` with the manual
steps attached to the report, never as failures. What is *not* skipped by that: the Safari wire
format is covered without Safari, by `SafariExtensionTransportTests` in the app's test bundle and
by `crates/kagisecure-agent/tests/safari.rs`.

### Suite C — CLI and vault format (`e2e/suites/cli/`)

20 scenarios against scratch vaults: creation and the recovery code, recovery setting a new
password, wrong-password exit codes, tampered headers and bodies and truncation, KDF parameter
bounds, the item lifecycle, the `--reveal` / `--json` rules, the generator's modes and clamps,
`totp` against an independent RFC 6238 implementation in Python, the audit chain, `import`, and the
committed golden vector opening at its released parameters.

The scratch vaults use `CHEAP_KDF` from `e2e/lib/harness.mjs` (`--kdf-m-kib 64 --kdf-t 1`) — the
cheapest Argon2id parameters `kagisecure-core` will still open a file at. That floor is `MIN_M_KIB`
/ `MIN_T` in `crates/kagisecure-core/src/crypto/kdf.rs`, which is not a policy choice weakened for
testing but the v1 golden vector's own parameters: the golden vector was written at m = 64 KiB,
t = 1, and a vault format rule against editing golden vectors makes that the strongest floor the
*open* path can carry without breaking format compatibility, so no scratch vault can legitimately
be cheaper than the fixture the suite also opens at its released parameters. Read the floor from
`CHEAP_KDF` rather than a literal — every suite that creates its own scratch vaults does. It is
still the difference between a suite that runs in seconds and one nobody runs.

## 7. Suite D — the macOS app (`e2e/suites/app/`, `apps/macos/KagisecureUITests/`)

> **Warning: this suite takes over the mouse and keyboard for about thirty minutes.** XCUITest
> drives the real app through real clicks and keystrokes at the window server, and it is not the
> only thing that gets them for as long as it runs. Run it only when the Mac is not in use.
> `make e2e` leaves it out unless `E2E_GUI=1` is set — see §7.7.

An XCUITest bundle that launches the real `Kagisecure.app` against a scratch vault and walks every
screen and modal in [ui-spec.md](ui-spec.md). 21 scenarios in twelve classes, every state
screenshotted into the report.

The centrepiece is the **approval sheet, raised by a real request**. A scenario starts a real
`kagisecure-mcp`, speaks MCP to it on stdio, and the request arrives at the app over a real unix
socket, through the same `kagisecure-agent` listener the daemon runs — so `ApprovalQueue::ask`
blocks, the sheet appears, and the test reads the identity verdict, the variable names, the
canonicalized path, the gitignore callout, the TTL control and the countdown before pressing one of
the three buttons. Deny returns `USER_DENIED`; "Allow once" writes a 0600 `.env` and leaves no
reusable lease; "Allow for this session" puts a row in the Leases table, and locking the vault takes
the lease away and shreds the file. §6's note that the app-hosted MCP variant was "phase 2" is what
this is.

### 7.1 What is replaced, and what is not

Only the fingerprint. `LAContext` cannot be answered by automation, and ADR-0007 is explicit that a
shipped binary must have no way to be talked into approving an injection without a human. Three
properties keep that true:

1. **`#if DEBUG`.** `UITestSupport` and `ScriptedBiometricGate` are not compiled into a Release
   build, so the strings below do not exist in a shipped binary.
2. **Launch arguments, not environment variables.** An environment variable is inherited by every
   child of whatever set it, and a user who exports one in their shell profile has silently changed
   their password manager. An argument is written once, by whoever spawns the process.
3. **Not a preference.** Nothing persists. Quitting forgets all of it.

| Launch argument | What it does |
| --- | --- |
| `-KSUITestBiometrics allow\|cancel\|unavailable` | Injects `ScriptedBiometricGate` in place of `LocalAuthenticationGate`. `cancel` is how the suite asserts ui-spec.md §10.3's rule that a fumbled fingerprint returns to the dialog rather than counting as a denial. |
| `-KSUITestDefaultsSuite <name>` | Points `AppDefaults.shared` — and therefore every `@AppStorage`, `AutoLockCoordinator.idleMinutes` and `PasteboardService.clearSeconds` — at a throwaway `UserDefaults` suite. |
| `-KSUITestAppearance dark\|light` | Pins `NSApp.appearance`, for the dark-mode captures. Not the *system* appearance: a test that flipped the Mac into dark mode would be changing the machine it measured. |

`KAGISECURE_HOME` and `KAGISECURE_SOCKET` are ordinary, shipped environment variables and need no
debug hook; the suite sets both on every launch.

### 7.2 Accessibility identifiers: `ks.<screen>.<element>`

Every control a test presses and every string a test asserts on carries an identifier. The
convention is `ks.<screen>.<element>`, lowerCamelCase segments, ASCII, stable across runs; a row in
a repeating list interpolates its own key (`ks.item.fieldCopy.password`,
`ks.environment.pendingValue.STRIPE_SECRET_KEY`). [ui-spec.md](ui-spec.md) §15 lists them.

**One rule, and it is not optional: put the identifier on a leaf.**

`.accessibilityIdentifier` on a SwiftUI layout container — `VStack`, `HStack`, `Group`,
`DisclosureGroup` — is stamped onto *every descendant that AppKit flattens into it*, overwriting the
identifiers those descendants set for themselves. A screen-level `ks.lock.root` on the lock card's
`VStack` does not produce one addressable container with five addressable children; it produces five
elements all called `ks.lock.root` and nothing else. This was measured, and it is why there are no
`ks.*.root` identifiers in this app.

Real AppKit containers behave differently and are safe: `List`, `Table` and `ScrollView` keep the
identifier on themselves and leave their rows alone — `ks.sidebar.list` and `ks.itemList.list` are
exactly that. Even there, order matters: an identifier applied *after* `.safeAreaInset` covers the
inset's content too, which is why `SidebarView` sets its one before.

A scenario that wants to know "is this screen up?" therefore waits on a leaf that only that screen
has — `ks.lock.title`, `ks.approval.sentence`, `ks.audit.chainState` — rather than on a wrapper.

Two more things worth knowing before writing an assertion:

- **A `Text` keeps its string in `value`, not `label`** — and an `.accessibilityLabel` does not
  move it there. Measured on macOS (an `NSHostingView` read back through `AXUIElement`):

  | view                                                   | `label` | `value`       |
  |--------------------------------------------------------|---------|---------------|
  | `Text(s)`                                              | empty   | `s`           |
  | `Text(s).accessibilityLabel(l)`                        | empty   | `l`, not `s`  |
  | `Text(s).accessibilityLabel(l).accessibilityValue(v)`  | `l`     | `v`           |

  The second row is the surprise: the label *replaces* the string as the value, which is what
  VoiceOver reads, and what is drawn is not in the tree at all — so a concealed field's mask reads
  as "Password, concealed. Reveal asks for Touch ID or your Mac password.", never as its dots.
  `UITestCase.text(_:)` reads `label` and then `value`, which serves the first two rows; a view in
  the third (the generator's candidate, the import sheet's source path) is read by `.value`.
- **A number interpolated into a `Text` is formatted for the locale.** `Text("\(7776) words")`
  reads "7,776 words" here. Assert on the digits, not on a grouping.
- **A menu-style `MenuBarExtra` drops identifiers, and nothing else.** Measured on macOS 27 (a
  probe app read through `AXUIElement`): the status item's `AXTitle` is the icon's
  `.accessibilityLabel` and follows it live — XCUITest's `title`, not its `label`, which is
  empty. Its menu is an `AXMenu` child of the status item whether open or closed, one
  `AXMenuItem` per entry with its title and enabled state, kept current while closed; no entry
  carries its `.accessibilityIdentifier` (a button's comes out as `menuAction:`). So the suite
  reads the lock state from `icon.title` and the entries by title from the status item's own
  subtree, which keeps them apart from the main menu bar's commands of the same name. Closed,
  the menu's frame is zero-size; open, it is real — that is how a scenario knows it is open, not
  `isHittable`.
- **A status item's frame is not always where it can be clicked.** A menu-bar manager that
  collapses status items (BetterTouchTool's, on the Mac this was measured on) leaves a collapsed
  item reporting a frame under its own chevron; XCUITest's click lands on the chevron and expands
  the hidden items instead of opening the menu, after which the item's frame is its real one.
  `L_MenuBarAndDarkModeTests.openStatusMenu` clicks until the menu's frame says it is open, at
  most three times. Allowing Kagisecure in the manager's settings takes the question away.
- **Settings remembers its tab.** SwiftUI keeps the selected Settings tab in the app's
  `UserDefaults.standard` (`com_apple_SwiftUI_Settings_selectedTabIndex`), which
  `-KSUITestDefaultsSuite` does not redirect, so a scenario selects the tab it needs rather than
  assuming where ⌘, lands.
- **A number is typed, not slid.** `adjust(toNormalizedSliderPosition:)` does not reliably move a
  SwiftUI `Slider`, the arrow keys reach an `NSSlider` only with Full Keyboard Access on, and a
  drag lands wherever the knob stops. Every slider in the app has an `ExactNumberField` beside it
  — `<id>Field` and `<id>Stepper` — which is the keyboard's path to the value (ui-spec.md §13);
  `UITestCase.setNumber` types into the field and commits with Return, `UITestCase.nudge` clicks
  the stepper's arrow, and the scenario asserts the field's exact value.
- **Selection lives on the cell.** A sidebar row's `Selected` attribute is on the `AXOutlineRow` and
  `AXCell`; the static text carrying the identifier never has one. `UITestCase.clickSidebarRow`
  clicks the cell and checks the cell.

**Import sheet (M8).** File ▸ Import… adds nineteen identifiers, listed in
[ui-spec.md](ui-spec.md) §15 and repeated here because this is the file a test author reads:

- `ks.import.cancel`
- `ks.import.category.<name>`
- `ks.import.confirm`
- `ks.import.detailTable`
- `ks.import.droppedAttachments`
- `ks.import.droppedHistory`
- `ks.import.droppedPasskeys`
- `ks.import.duplicatePolicy`
- `ks.import.duplicates`
- `ks.import.error`
- `ks.import.format`
- `ks.import.open`
- `ks.import.result`
- `ks.import.sheet`
- `ks.import.shredConfirm`
- `ks.import.shredPrompt`
- `ks.import.shredSkip`
- `ks.import.sourcePath`
- `ks.import.totalItems`

> The XCUITest scenario that drives them, `apps/macos/KagisecureUITests/M_ImportTests.swift`, is
> **written and compiled but not yet run** — it is a stub against the M8 sheet, so the scenario
> counts elsewhere in this document do not include it yet.

### 7.3 How the suite plugs into the runner

`e2e/suites/app/run-xcuitest.mjs` is an ordinary suite command (§5). It runs `xcodebuild test`
against the `KagisecureUITests` scheme, converts the `.xcresult` with `xcrun xcresulttool get
test-results tests` into the JUnit document at `$E2E_JUNIT`, and rewrites the scenario names from
Swift selectors into sentences. Screenshots are **not** extracted from the result bundle: the test
bundle writes each PNG into `$E2E_ARTIFACTS` itself and appends its own `manifest.jsonl` line, the
same contract every other suite follows, *and* attaches the same screenshot to the result bundle for
anybody opening it in Xcode. Extracting attachments back out of an `.xcresult` is possible and is a
moving target across Xcode versions; a suite whose evidence disappears on an Xcode upgrade is a
suite nobody trusts.

The UI-test target is **not sandboxed**, and that is a deliberate entry in `project.yml`. Xcode's
default for a macOS UI-testing bundle is a sandboxed `XCTRunner.app` with a read-only exception for
`/`, and a sandboxed runner cannot create a scratch vault, bind a socket, write a screenshot into
the harness's artifact directory, or spawn a `kagisecure-mcp` that can reach the app's socket — a
child of a sandboxed process inherits the container. The app under test is not sandboxed either
(ADR-0010), so this loosens nothing the product relies on, and the bundle ships nowhere.

### 7.4 UI testing has to be authorized once, per machine

macOS can refuse to let a test runner drive another process — the `system.privilege.taskport`
authorization right, which developer mode grants. When it does, `XCTRunner` never attaches and
*every* scenario fails with "The test runner failed to initialize for UI testing", a wall of red
that says nothing about kagisecure.

The adapter recognises that message in the result bundle and reports the suite as `skipped` with the
fix attached:

```console
$ security authorize -ue system.privilege.taskport      # this login session, ten hours
$ sudo DevToolsSecurity -enable                         # permanently, what Xcode offers you
```

Both need an administrator, and `make e2e` will do neither: this suite does not change the security
posture of the machine it is measuring.

**Recognised afterwards, not predicted beforehand.** An earlier version of the adapter probed
`security authorize system.privilege.taskport` before running anything, and got it wrong: the right
not being *cached* is not the same as it being refused, so the suite skipped itself on a machine
where it ran perfectly well. A guard that is only correlated with the thing it guards against is
worse than no guard, because it fails in the direction nobody checks.

The credential can also lapse **mid-run**, which looks different: the scenario in flight loses its
connection to the app, or its teardown cannot terminate it, rather than being politely refused — and
the *next* one gets the refusal. On their own "Lost connection to the application" and "Failed to
terminate" are ambiguous; they are also what a crashed or hung app looks like, which is precisely
what this suite exists to catch. So they count as a refusal only in a run where something else was
explicitly refused. In a clean run either one stays a failure.

A refused run also cannot clean up after itself — `XCUIApplication.terminate()` goes through the
runner — so `UITestCase` kills anything left over directly, matching on the **built product's**
path rather than on the bundle identifier, so that a copy of kagisecure the person at that Mac
installed and is using cannot be caught by it.

### 7.5 Adding a screen

1. Give the controls and the assertable strings `ks.<screen>.<element>` identifiers **on leaves**,
   and add them to ui-spec.md §15.
2. Add a `final class X_YourTests: UITestCase` under `apps/macos/KagisecureUITests/`. The class
   prefix orders the report; nothing depends on the order, because every scenario builds its own
   world.
3. Seed the vault with `Harness.seedVault(at: vaultPath)` or `Harness.cliOk(...)`, `launch()`, and
   unlock. Use `step("a lower-case sentence") { … }` around each phase and `capture("kebab-name",
   "A sentence")` at every state worth looking at in the report.
4. If the screen needs an agent request, start a `Sidecar` and make the call **on a background
   queue** — it blocks until somebody answers the sheet, and the thing that answers the sheet is the
   test, on the main thread.

### 7.6 What suite D does not cover

The **browser-fill variant** of the approval sheet (ui-spec.md §10.5). `kagisecure-nmhost` refuses
to serve unless its process ancestry names a real browser, and that gate is the feature — an
XCUITest runner is not a browser. Driving it would mean either launching Edge from inside the
UI-test bundle, duplicating suite B's apparatus one process further away, or switching the ancestry
gate off, which would test a build nobody ships. Suite B covers the channel with a real browser and
the real host; what stays uncovered is only the SwiftUI rendering of §10.5, which
`apps/macos/KagisecureTests/FillApprovalTests.swift` asserts against the same request record the
sheet is built from. The scenario is present and reports `skipped` with that reason attached.

The **vault switcher** (ui-spec.md §2.2) is skipped too, because it is not built — the spec's own
preamble records that there is one logical vault and a fixed sidebar. The scenario asserts what *is*
built and then skips, so the report says "pending, and here is why" rather than passing silently
over a missing feature.

### 7.7 Why suite D is opt-in

XCUITest does not simulate input. It synthesizes real clicks and keystrokes at the window server,
and for about half an hour they land wherever the app under test is — which is to say, on top of
whatever else the person at that Mac was doing. The suite also raises and dismisses sheets, opens
menus, and takes the keyboard focus back every few seconds.

So `make e2e` leaves it out and prints a line saying it did, and `make e2e SUITE=app` — where the
intent is unambiguous — is **refused** rather than silently dropped, because a command that names a
suite and then runs nothing is the more confusing surprise. `E2E_GUI=1` is the opt-in:

```console
$ E2E_GUI=1 make e2e SUITE=app     # just the app
$ E2E_GUI=1 make e2e               # all four
```

The other three suites are safe to run while the machine is in use. Suite B launches a browser, but
into its own throwaway profile and without taking the keyboard.

### 7.8 The keystrokes have to arrive as typed

XCUITest's keystrokes go through the input source the Mac has selected, like anybody's. With an
input method selected rather than a plain keyboard layout, a typed string is composed rather than
typed: what reaches a field is not what the scenario sent. On the run that found this, a
synthesized keystroke also brought System Settings to the front, and the scenarios after it typed
into System Settings instead of the app — failures that read as product bugs and are not.

So before suite D starts — before its build, so the answer comes in seconds — the runner
(`e2e/lib/gui-preflight.mjs`) reads two things and **refuses the run** if either is wrong:

* **The selected input source**, from `AppleSelectedInputSources` in `com.apple.HIToolbox`
  (`AppleCurrentKeyboardLayoutInputSourceID` goes into the message). A `Keyboard Layout` entry
  must be selected and no input method may be: an entry whose `InputSourceKind` is `Input Mode`,
  `Input Method` or `Keyboard Input Method` refuses. `Non Keyboard Input Method` entries — the
  character palette, press-and-hold accents, the emoji row — are selected on every Mac, never
  compose keystrokes, and do not count. A list that cannot be read is reported as not checked
  rather than refused.
* **Whether System Settings is running** (`pgrep -x "System Settings"`). Quit it first.

The refusal says what it found and how to fix it — switch to a plain layout such as ABC from the
input menu, quit System Settings — and the runner does neither for you, for §7.4's reason: this
suite does not change the machine it is measuring. Nor is this the kind of guard §7.4 warns about:
the selected input source is not correlated with the keystrokes going wrong, it is what they go
through.

To check a Mac without running anything:

```console
$ node e2e/run.mjs --preflight
   preflight  input source: keyboard layout ABC
   preflight  System Settings: not running
   preflight  ready for suite "app"
```

### 7.9 Status

Implemented, not yet observed green end to end. `KagisecureUITests` builds and links
(`xcodebuild build-for-testing`), and every scenario is wired to a real accessibility identifier and
a real fixture, but no run on record has finished clean.

The two attempts under `e2e/tmp/` both ended the same way: partway through, `xcodebuild` starts
reporting `Lost connection to the application` and then `Not authorized for performing UI testing
actions` on every scenario after — the signature of the Mac's mouse and keyboard being taken by
something other than the test runner mid-click, which is exactly what §7.7's `E2E_GUI` gate exists
to prevent. One run was then interrupted outright, corrupting its `.xcresult` before the adapter
could read it. Neither is a product failure; both are a suite that was run on a machine in use.

What is known to have passed, from the attempt that got furthest before losing its connection:

* first launch creates a vault and shows the recovery code exactly once
* the lock screen unlocks with the right password and refuses a wrong one

Everything after that — the recovery-code unlock path, the sidebar, the item lifecycle, search, the
generator, TOTP, Quick Access, Settings, the approval sheet, and menu-bar/dark-mode — is unknown
rather than failing: the run never reached a clean answer for them. §7.4's adapter fix (recognising
a lost or refused runner mid-suite and reporting those scenarios `skipped` rather than `failed`) is
new since the interrupted runs and has not yet been exercised by one that gets past them. The next
`E2E_GUI=1 make e2e SUITE=app`, on a Mac nobody is using, is what turns this into a real answer.

## 8. Continuous integration (removed 2026-09-19)

Until 2026-09-19 CI ran `make e2e SUITE=mcp,cli` on a macOS runner; those two suites are headless
and now run the same way locally, on demand.

**Suite D was attempted, with `E2E_GUI=1` and `continue-on-error: true`.** A runner is nobody's
desktop, so §7.7's opt-in was simply set. GitHub's macOS runners did have a window server and a
logged-in session, which is the hard part. Whether they would let a test runner drive
another process (§7.4) was never established; if they would not, the adapter reports the suite as
`skipped` and exits 0, so the job stayed honest rather than red. This suite now only runs locally,
with `E2E_GUI=1 make e2e SUITE=app` on a Mac nobody is using.

The browser suite is **local-only**. An MV3 extension does not load in a headless Chromium, so
suite B needs a real login session with a window server. The repository has no CI at all now; if
CI is reintroduced, this suite would need a runner with Edge installed.

Safari is local-and-manual on every machine, including when CI existed.

## 9. The local test app (`e2e/lib/test-app.mjs`)

A dependency-free Node server with real register and login forms, used by the extension suite
and the agent-test-login work (ADR-0048). Users live in memory; passwords are stored only as
scrypt hashes with a per-user salt, request bodies are never logged, and no response echoes a
password. Pages are in `e2e/suites/extension/pages/test-app/`.

By hand: `node e2e/lib/test-app.mjs [--port 47800] [--host 127.0.0.1]`, then open
http://localhost:47800/register. From a suite: `const app = await startTestApp({ port: 0 })`
returns `{ url, close, users }`; `users` is a `Map` a test can use to assert a hash exists for
a username. Its own test: `node --test e2e/lib/test-app.test.mjs`.
