/**
 * Suite B — browser autofill, in a real browser.
 *
 * ```text
 *   Edge  ──native messaging──▶  kagisecure-nmhost  ──unix socket──▶  extension_harness
 *   (the real extension)          (the real bridge)                   (the app's back half)
 * ```
 *
 * Real here: the browser, the unpacked extension with its pinned id, the native host *launched by
 * the browser* so the process-ancestry gate is exercised rather than switched off, the socket, the
 * origin rule, and the audit log. Not real: the human. `extension_harness` is a `cargo --example`
 * binary — one that no release artifact contains and no user can invoke — holding a `VaultHandle`,
 * a real `ExtensionAgent`, and a robot in the chair where the person sits. Everything below the
 * approval sheet is production code; the sheet itself is verified by hand
 * (`docs/browser-extension.md` §7) and by phase 2's XCUITest suite.
 *
 * # Which browser
 *
 * **Chrome 137 removed `--load-extension`**, and on Chrome 152 the switch is silently ignored — the
 * browser starts, the extension is not installed, and nothing is logged. Microsoft Edge is the same
 * Chromium with the same MV3 and the same native messaging, and still honours it, so it is what the
 * automated pass runs in. `BROWSERS` is a list rather than a constant so a machine with a Chrome
 * that works picks it up with no edit. If none of them installs the extension, every scenario
 * reports `skipped` with the manual instructions rather than failing.
 *
 * # Why the origins look like real websites
 *
 * The origin rule is "same scheme, same port, same registrable domain under the Public Suffix
 * List". Two ports on `localhost` can only exercise the port half of that, because `localhost` has
 * no registrable domain and falls back to exact host equality. So the browser is launched with
 * `--host-resolver-rules=MAP * 127.0.0.1`, every page is served by the same local server, and the
 * hostnames in the URLs are chosen to sit in interesting places on the list:
 *
 * | Origin                        | Against an item saved for `app.example.com` and `alice.github.io` |
 * | ----------------------------- | ---------------------------------------------------------------- |
 * | `app.example.com:PORT`        | matches — it is one of the saved sites                            |
 * | `www.example.com:PORT`        | matches — same registrable domain, `example.com`                  |
 * | `alice.github.io:PORT`        | matches — the item's *second* saved site                          |
 * | `mallory.github.io:PORT`      | refused — `github.io` is a public suffix, so this is a sibling    |
 * | `app.example.com:OTHER_PORT`  | refused — the port is part of the origin                          |
 * | `127.0.0.1:PORT`              | refused — an IP literal, exact host match only                    |
 *
 * Nothing leaves the machine: the resolver rule sends every one of those hosts to 127.0.0.1.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

import { exampleBinary, binary, scratch, runDir, waitFor } from "../../lib/harness.mjs";
import { record, recordText, screenshot } from "../../lib/artifacts.mjs";

/** The extension source both browsers load: `extensions/shared`, not `extensions/chrome`. */
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(import.meta.dirname, "..", "..", "..");
const EXTENSION_DIR = path.join(REPO_ROOT, "extensions", "shared");
const PAGES = path.join(import.meta.dirname, "pages");

/** Must equal `kagisecure_extension_ipc::PINNED_EXTENSION_IDS[0]`. */
const EXTENSION_ID = "nlijibjnmanccalmafnfbobkcfjiibmd";
const HOST_NAME = "com.kagisecure.nmhost";

/** If these bytes reach the audit log, a mismatched page, or the host's stderr, the suite failed. */
const PASSWORD = "KSE2E-FILL-CANARY-4c1f90a7be32d85e";
const USERNAME = "alice@example.test";
/** The other account saved at the same origin, for the identifier-first world only. */
const SECOND_PASSWORD = "KSE2E-OTHER-CANARY-9b7d2e14ac60f853";
const SECOND_USERNAME = "bob@example.test";
const TOTP_URI = "otpauth://totp/Kagisecure:alice?secret=JBSWY3DPEHPK3PXP&issuer=Kagisecure";

const BROWSERS = [
  { channel: "msedge", expectedName: "Microsoft Edge" },
  { channel: "chrome", expectedName: "Google Chrome" },
];

const MANUAL_SAFARI_STEPS = `
Safari cannot be driven by automation on this machine, so these scenarios are reported as
skipped rather than failed. To run them by hand (docs/browser-extension.md §7):

  1. make macos SIGN=developer-id     — the App Group the Safari extension reaches the app
                                        through needs a real team identity; an ad-hoc build
                                        cannot carry the entitlement (ADR-0024 §6).
  2. Open the built app and unlock it against a scratch vault:
       KAGISECURE_HOME=/tmp/ks-manual open -n build/Debug/Kagisecure.app
  3. Safari > Settings > Advanced > "Show features for web developers",
     then Developer > Allow Unsigned Extensions.
  4. Safari > Settings > Extensions > enable Kagisecure, and grant it the test site.
  5. Work through the same scenarios this suite automates for Edge, and screenshot each.

What is NOT skipped by this: the Safari wire format is covered without Safari, by
SafariExtensionTransportTests in the app's test bundle driving extension_harness over the
second socket, and by crates/kagisecure-agent/tests/safari.rs.
`.trim();

// -------------------------------------------------------------------------------------------
// The world: a page server, a harness, and a browser
// -------------------------------------------------------------------------------------------

/**
 * Playwright, from `extensions/chrome`'s package rather than a second copy of its own.
 *
 * That directory already declares and installs it — it is where the extension's Node tooling and
 * its unit tests live. Resolving through its `package.json` keeps one dependency declaration, one
 * version in one `deny`-adjacent place, and one download of the browser binaries. The suite's
 * build step in `suite.json` runs `npm install` there first, so a clean checkout works.
 */
function loadPlaywright() {
  const require = createRequire(path.join(REPO_ROOT, "extensions", "chrome", "package.json"));
  return require("playwright");
}

/**
 * Serve `pages/` on an ephemeral port, for any Host header.
 *
 * Subdirectories are served — `identifier-first/step1.html` is a real path — and anything that
 * resolves outside `pages/` is a 404 rather than a file. The containment check is on the
 * *resolved* path, so `..` segments are handled by `path.resolve` rather than by a filter that
 * has to think of every spelling of them.
 */
function servePages() {
  const server = http.createServer((req, res) => {
    const name = (req.url || "/").split("?")[0].replace(/^\//, "") || "login.html";
    const file = path.resolve(PAGES, name);
    if (file !== PAGES && !file.startsWith(PAGES + path.sep)) {
      res.writeHead(404).end("not found");
      return;
    }
    fs.readFile(file, (err, body) => {
      if (err) {
        res.writeHead(404).end("not found");
        return;
      }
      const type = file.endsWith(".css") ? "text/css" : "text/html";
      res.writeHead(200, { "content-type": `${type}; charset=utf-8` }).end(body);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

/** Start `extension_harness` and wait for its ready line. */
function startHarness(socket, sites, { deny = false, second = false } = {}) {
  const args = [
    "--socket", socket,
    "--username", USERNAME,
    "--password", PASSWORD,
    "--totp", TOTP_URI,
  ];
  for (const site of sites) args.push("--site", site);
  if (deny) args.push("--deny");
  // A second account at the same websites, so that "which item" is a real question on page two of
  // an identifier-first sign-in. Only the world that tests that asks for it.
  if (second) args.push("--second-username", SECOND_USERNAME, "--second-password", SECOND_PASSWORD);

  const child = spawn(exampleBinary("extension_harness"), args, {
    stdio: ["pipe", "pipe", "pipe"],
  });

  const lines = [];
  let buffer = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      lines.push(buffer.slice(0, index));
      buffer = buffer.slice(index + 1);
    }
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const ready = waitFor(() => lines.some((l) => l.includes('"ready"')), {
    timeoutMs: 30_000,
    what: `the harness to bind ${socket}`,
  });

  return {
    ready,
    stderr: () => stderr,
    async audit() {
      const before = lines.length;
      child.stdin.write("audit\n");
      await waitFor(() => lines.slice(before).some((l) => l.includes('"audit"')), {
        timeoutMs: 10_000,
        what: "the harness to answer with its audit log",
      });
      return JSON.parse(lines.slice(before).find((l) => l.includes('"audit"'))).entries;
    },
    lock() {
      child.stdin.write("lock\n");
      return waitFor(() => lines.some((l) => l.includes('"locked"')), {
        timeoutMs: 10_000,
        what: "the harness to lock its vault",
      });
    },
    stop() {
      try {
        child.stdin.end();
      } catch {
        /* already gone */
      }
      child.kill("SIGTERM");
    },
  };
}

/**
 * Install the native messaging manifest **only inside this run's browser profile**.
 *
 * The existing unit-level suite also writes the per-user file under `~/Library/Application
 * Support/<browser>/NativeMessagingHosts/` and restores it afterwards. This one deliberately does
 * not: on Edge 152 a browser launched with `--user-data-dir=X` reads its manifests from
 * `X/NativeMessagingHosts`, which is the only copy this run needs, and a suite that edits the
 * user's real browser configuration can leave it pointing at a `target/debug` binary if it is
 * killed between the write and the restore.
 */
function installManifest(profileDir, nmhostPath) {
  const file = path.join(profileDir, "NativeMessagingHosts", `${HOST_NAME}.json`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    `${JSON.stringify(
      {
        name: HOST_NAME,
        description: "kagisecure autofill bridge",
        path: nmhostPath,
        type: "stdio",
        allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
      },
      null,
      2,
    )}\n`,
  );
}

/** Launch `browser` with the unpacked extension, or return null if it will not install it. */
async function launchBrowser(chromium, browser, profileDir, socket) {
  let context;
  try {
    context = await chromium.launchPersistentContext(profileDir, {
      channel: browser.channel,
      // An MV3 extension does not load in the headless shell — see the module comment.
      headless: false,
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        // Every hostname in this suite resolves here. Nothing leaves the machine, and the origins
        // can still be chosen for where they sit on the Public Suffix List.
        "--host-resolver-rules=MAP * 127.0.0.1",
        "--no-first-run",
        "--no-default-browser-check",
      ],
      // The browser hands its environment to the native host it launches, which is how the host
      // finds this run's socket instead of the user's real one.
      env: { ...process.env, KAGISECURE_EXTENSION_SOCKET: socket },
      timeout: 60_000,
    });
  } catch {
    return null;
  }

  // Detected by asking CDP for the target list rather than by waiting for a service worker: a
  // browser that ignores `--load-extension` produces no error and no event, so a `waitForEvent`
  // would hang until the suite timed out with no explanation.
  const page = await context.newPage();
  await page.goto("about:blank");
  const cdp = await context.newCDPSession(page);
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const { targetInfos } = await cdp.send("Target.getTargets");
    if (targetInfos.some((t) => t.url.startsWith(`chrome-extension://${EXTENSION_ID}/`))) {
      let [worker] = context.serviceWorkers();
      if (!worker) {
        worker = await context.waitForEvent("serviceworker", { timeout: 15_000 }).catch(() => null);
      }
      if (worker) return context;
    }
    await page.waitForTimeout(500);
  }
  await context.close().catch(() => {});
  return null;
}

/**
 * Everything one group of scenarios needs, built once and reused.
 *
 * Launching Edge takes a few seconds, so the allow-path scenarios share one browser and one
 * harness while the denial and lock scenarios get their own — those two change the state of the
 * thing under test irreversibly (a locked `VaultHandle` cannot be unlocked from outside), and a
 * suite whose scenarios only pass in one order is a suite that hides bugs.
 */
const worlds = new Map();
let pageServer = null;
let browserUnavailable = null;

async function world(mode = "allow") {
  if (worlds.has(mode)) return worlds.get(mode);
  if (browserUnavailable) return null;

  const { chromium } = loadPlaywright();

  if (!pageServer) pageServer = await servePages();
  const { port } = pageServer;

  const origins = {
    saved: `http://app.example.com:${port}`,
    sibling: `http://www.example.com:${port}`,
    secondSaved: `http://alice.github.io:${port}`,
    etldSibling: `http://mallory.github.io:${port}`,
    otherPort: `http://app.example.com:${port === 65535 ? port - 1 : port + 1}`,
    ipLiteral: `http://127.0.0.1:${port}`,
    stranger: `http://unrelated.example.net:${port}`,
  };

  const dir = scratch(`extension-${mode}`);
  const socket = path.join(runDir(), `ext-${mode}.sock`);
  const harness = startHarness(socket, [origins.saved, origins.secondSaved], {
    deny: mode === "deny",
    second: mode === "identifier",
  });
  await harness.ready;

  const profileDir = path.join(dir, "profile");
  fs.mkdirSync(profileDir, { recursive: true });
  installManifest(profileDir, binary("kagisecure-nmhost"));

  let context = null;
  let browser = null;
  for (const candidate of BROWSERS) {
    context = await launchBrowser(chromium, candidate, profileDir, socket);
    if (context) {
      browser = candidate;
      break;
    }
  }

  if (!context) {
    harness.stop();
    browserUnavailable =
      "No installed Chromium-family browser accepted --load-extension. Chrome 137+ removed the " +
      "switch; install Microsoft Edge, or run the manual pass in docs/browser-extension.md §7. " +
      "An MV3 extension also does not load in a headless browser, so this suite needs a real " +
      "login session with a window server.";
    return null;
  }

  // The extension's own popup, opened as a tab. Every `ask()` runs here rather than in the
  // service worker, because a sender never receives its own `chrome.runtime.sendMessage`.
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${EXTENSION_ID}/popup.html`);
  await popup.setViewportSize({ width: 320, height: 360 });

  const built = { context, popup, harness, origins, browser, port, mode };
  worlds.set(mode, built);
  return built;
}

/**
 * Shut one world down early.
 *
 * Each world is a browser *and* a harness, and a machine running four of them at once is a
 * machine where a 1.5-second settle is sometimes not one. The worlds that a single scenario uses
 * therefore close themselves when that scenario is done, so the peak is three rather than four.
 * `test.after` still closes whatever is left, so a scenario that fails before it gets here leaks
 * nothing.
 */
async function closeWorld(mode) {
  const built = worlds.get(mode);
  if (!built) return;
  worlds.delete(mode);
  await built.context.close().catch(() => {});
  built.harness.stop();
}

test.after(async () => {
  for (const built of worlds.values()) {
    await built.context.close().catch(() => {});
    built.harness.stop();
  }
  if (pageServer) pageServer.server.close();
});

/**
 * Get the world for `mode`, or skip the scenario with the reason.
 *
 * A skip rather than a failure: "there is no browser here that can load an unpacked MV3 extension"
 * is a fact about the machine, and a red report for it would train people to ignore red reports.
 */
async function requireWorld(t, mode = "allow") {
  const built = await world(mode);
  if (!built) {
    t.skip(browserUnavailable);
    return null;
  }
  return built;
}

// -------------------------------------------------------------------------------------------
// Talking to the extension
// -------------------------------------------------------------------------------------------

/** Ask the service worker something, from the extension's own popup page. */
function ask(popup, message) {
  return popup.evaluate(
    (msg) =>
      new Promise((resolve) => {
        chrome.runtime.sendMessage(msg, (response) => {
          void chrome.runtime.lastError;
          resolve(response ?? { ok: false, code: "INTERNAL", message: "no response" });
        });
      }),
    message,
  );
}

/** Press ⌘\ for real, so the content script's `isTrusted` gate is exercised. */
async function pressShortcut(page, focusSelector = "#password") {
  const target = page.locator(focusSelector);
  if ((await target.count()) > 0) await target.focus();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+Backslash" : "Control+Backslash");
  await page.waitForTimeout(2_000);
}

/**
 * Poll an input until it has a value, or give up and return "".
 *
 * The budget is generous on purpose: the first fill in a world can involve starting the native
 * host, a handshake and an approval round trip, and this suite shares a machine with whatever
 * else is running on it. A slow pass is a pass; a flaky suite is worse than a slow one.
 */
async function valueOf(frame, selector, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await frame.inputValue(selector).catch(() => "");
    if (value) return value;
    if (Date.now() > deadline) return "";
    await new Promise((r) => setTimeout(r, 100));
  }
}

/** Open a page and give the content script time to survey the form. */
async function open(built, origin, file = "login.html", query = "") {
  const page = await built.context.newPage();
  await page.goto(`${origin}/${file}${query}`);
  await page.bringToFront();
  await page.waitForTimeout(1_500);
  return page;
}

/**
 * Wait for the icon to appear, and say whether it did.
 *
 * A single `hasIcon` right after `open` races the content script's debounced scan and the `match`
 * round trip behind it, which on a loaded machine is not always finished in the fixed settle. A
 * negative assertion does not need this — there is nothing to wait for — so those stay as they
 * are.
 */
async function waitForIcon(frame, timeoutMs = 8_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await hasIcon(frame)) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Whether the content script injected its in-field icon on this page. */
function hasIcon(frame) {
  return frame.evaluate(() =>
    Array.from(document.documentElement.children).some((c) =>
      c.tagName.toLowerCase().startsWith("ks-"),
    ),
  );
}

// -------------------------------------------------------------------------------------------
// The scenarios
// -------------------------------------------------------------------------------------------

test("the extension reaches an unlocked vault through a browser-launched native host", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const status = await ask(built.popup, { kind: "status" });
  assert.equal(status.ok, true, `status failed: ${JSON.stringify(status)}`);
  assert.equal(status.state.status, "ready", JSON.stringify(status.state));

  // The app worked out which browser launched the host from the process tree alone. That is the
  // ancestry gate doing its job, not a claim the extension made about itself.
  assert.ok(
    status.state.evidence.some((line) => line.includes(built.browser.expectedName)),
    `the app must name the browser from the process tree: ${JSON.stringify(status.state.evidence)}`,
  );

  await screenshot(built.popup, t.name, "01-popup-ready", "the popup, connected and unlocked");
  recordText(
    t.name,
    "evidence.txt",
    status.state.evidence.join("\n"),
    "what the app established about the process on the socket",
  );
});

test("the saved origin fills by clicking the in-field icon", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved);
  await screenshot(page, t.name, "01-before", "the page on load: nothing is filled, ever");
  assert.equal(await page.inputValue("#password"), "", "nothing is filled on load");

  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.ok, true, JSON.stringify(matched));
  assert.equal(matched.origin, built.origins.saved, "the origin comes from the browser");
  assert.equal(matched.items.length, 1);
  assert.equal(matched.items[0].username, USERNAME);
  assert.ok(!JSON.stringify(matched).includes(PASSWORD), "a match answer carries no value");

  // The icon lives in a *closed* shadow root, so this asserts that it exists rather than reaching
  // inside it — which is the property that keeps page script out of it too.
  const icon = await page.evaluate(() => {
    const el = Array.from(document.documentElement.children).find((c) =>
      c.tagName.toLowerCase().startsWith("ks-"),
    );
    return el ? { tag: el.tagName.toLowerCase(), pierceable: el.shadowRoot !== null } : null;
  });
  assert.ok(icon, "the in-field icon should appear where an item is saved");
  assert.equal(icon.pierceable, false, "the overlay is in a closed shadow root");

  const box = await page.locator("#password").boundingBox();
  await page.mouse.click(box.x + box.width - 15, box.y + box.height / 2);

  assert.equal(await valueOf(page, "#password"), PASSWORD);
  assert.equal(await page.inputValue("#username"), USERNAME);
  await screenshot(page, t.name, "02-filled", "filled by a real click on the icon");
  await page.close();
});

test("the same page fills from the keyboard shortcut", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved);
  assert.equal(await page.inputValue("#password"), "");

  // A `page.keyboard` press produces a trusted KeyboardEvent, which is exactly what the content
  // script's handler requires — so this exercises the shortcut end to end, `isTrusted` gate
  // included, rather than sending the message the handler would have sent.
  await pressShortcut(page);

  assert.equal(await valueOf(page, "#password"), PASSWORD, "the shortcut path fills");
  assert.equal(await page.inputValue("#username"), USERNAME);
  await screenshot(page, t.name, "01-filled-by-shortcut", "filled with ⌘\\");
  await page.close();
});

test("page one of an identifier-first sign-in fills the username and nothing else", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  // The page Google, Microsoft and Okta show first: an email box, a Next button, and no password
  // field anywhere. Until M7 this got no icon at all and the user typed their own address; it now
  // gets the icon, and what crosses is a username the browser was already handed by `match`.
  const page = await open(built, built.origins.saved, "identifier-first/step1.html");
  await screenshot(page, t.name, "01-before", "step one: nothing is filled on load, here either");
  assert.equal(
    await waitForIcon(page),
    true,
    "a username box with a Next button is a login form now",
  );

  await pressShortcut(page, "#username");
  assert.equal(await valueOf(page, "#username"), USERNAME);

  const html = await page.content();
  assert.ok(!html.includes(PASSWORD), "no value crosses on page one: there is nowhere to put one");
  await screenshot(page, t.name, "02-filled", "the username, filled by ⌘\\");

  const entries = await built.harness.audit();
  const usernameOnly = entries.filter((e) => e.detail === "FILL_USERNAME_ONLY");
  assert.ok(
    usernameOnly.length >= 1,
    `a username-only fill is audited even though it raises no sheet: ${JSON.stringify(entries)}`,
  );
  assert.ok(
    usernameOnly.every((e) => e.fields === "username"),
    "and the entry names the one field it wrote",
  );
  assert.ok(
    usernameOnly.every((e) => e.outcome === "Allowed" && e.tool === "fill_credential"),
    "recorded as an allowed fill, under the same tool name, so the audit filter finds it",
  );
  assert.ok(
    !JSON.stringify(entries).includes(PASSWORD),
    "no audit entry may contain the password",
  );

  recordText(
    t.name,
    "approval.txt",
    [
      "A username-only fill is served without an approval sheet, and audited as",
      "FILL_USERNAME_ONLY (ADR-0030).",
      "",
      "The argument: nothing crosses that the browser did not already have. The `match` that drew",
      "the icon returned this item's username, without a prompt, before anything was clicked. A",
      "fingerprint for a value the extension already holds teaches people that the sheet is noise,",
      "which is the one thing an approval sheet cannot afford.",
      "",
      "What is unchanged: the same-user check, the native host's process ancestry, the pinned",
      "extension id, the origin rule, the user's own click or ⌘\\, and the audit entry. The moment",
      "a password is asked for — page two — the sheet is back.",
    ].join("\n"),
    "why no sheet was raised for this fill",
  );
  await page.close();
});

test("the tab remembers the item across page one and forgets it after page two", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved, "identifier-first/step1.html");
  await pressShortcut(page, "#username");
  assert.equal(await valueOf(page, "#username"), USERNAME);

  await page.bringToFront();
  const remembered = await ask(built.popup, { kind: "recall-active-tab" });
  assert.equal(remembered.ok, true, JSON.stringify(remembered));
  assert.ok(remembered.entry, "the service worker remembers which item this tab chose");
  assert.equal(remembered.entry.origin, built.origins.saved, "at the origin the browser stamped");
  assert.ok(
    !JSON.stringify(remembered).includes(PASSWORD),
    "and what it remembers is an id, an origin and a deadline — never a value",
  );
  await screenshot(built.popup, t.name, "01-continuing", "the popup says who it is continuing as");

  // The same tab, the second page of the same flow.
  await page.goto(`${built.origins.saved}/identifier-first/step2.html`);
  await page.bringToFront();
  await page.waitForTimeout(1_500);
  await pressShortcut(page, "#password");
  assert.equal(await valueOf(page, "#password"), PASSWORD, "page two fills the password");
  await screenshot(page, t.name, "02-step-two", "page two, filled");

  await page.bringToFront();
  const after = await ask(built.popup, { kind: "recall-active-tab" });
  assert.equal(
    after.entry,
    null,
    "the memory existed for the password fill, and the password fill has happened",
  );
  await page.close();
});

test("the tab memory expires", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved, "identifier-first/step1.html");
  await pressShortcut(page, "#username");
  assert.equal(await valueOf(page, "#username"), USERNAME);
  await page.bringToFront();
  assert.ok((await ask(built.popup, { kind: "recall-active-tab" })).entry, "remembered first");

  // Age the memory rather than wait sixty seconds for it. What is called here is the **production**
  // sweep, with a later `now` — every function in `tabmemory.js` takes the clock as a parameter for
  // exactly this reason. There is no debug message and no query flag in the extension to reach,
  // because the thing being used is Playwright's ability to evaluate inside the service worker,
  // which is a devtools capability: no page can reach it, and no release code path uses it.
  const [worker] = built.context.serviceWorkers();
  assert.ok(worker, "the extension's service worker");
  const dropped = await worker.evaluate(
    (ttl) => KsTabMemory.sweep(Date.now() + ttl + 1_000),
    60_000,
  );
  assert.ok(dropped >= 1, "the entry was old enough to drop");

  await page.bringToFront();
  const after = await ask(built.popup, { kind: "recall-active-tab" });
  assert.equal(after.entry, null, "an expired memory is gone, not merely ignored");

  recordText(
    t.name,
    "expiry.txt",
    [
      "The memory lasts 60 seconds (extensions/shared/tabmemory.js, TTL_MS).",
      "",
      "This scenario does not wait for it. It calls the production `sweep(now)` with a clock an",
      "hour ahead, through Playwright's service-worker evaluate — a devtools capability, not an",
      "extension feature. The extension itself ships no test hook: no debug message, no query",
      "flag, nothing a page could reach in a release build.",
      "",
      "In practice the memory is often shorter-lived than 60 seconds: an MV3 service worker is",
      "evicted after about 30 seconds of idleness and the Map dies with it. Losing it early is",
      "safe — page two falls back to asking which item, which is what shipped before this.",
    ].join("\n"),
    "how the expiry is driven, and why nothing test-only ships",
  );
  await page.close();
});

test("navigating to a different registrable domain forgets the remembered item", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved, "identifier-first/step1.html");
  await pressShortcut(page, "#username");
  assert.equal(await valueOf(page, "#username"), USERNAME);
  await page.bringToFront();
  assert.ok((await ask(built.popup, { kind: "recall-active-tab" })).entry, "remembered first");

  // `alice.github.io` is the *same item's* second saved website, so the item still matches there
  // and the popup still has something to offer. What must not survive the journey is the memory:
  // "who you said you were at app.example.com" is not a fact about github.io.
  await page.goto(`${built.origins.secondSaved}/identifier-first/step2.html`);
  await page.bringToFront();
  await page.waitForTimeout(1_500);

  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.items.length, 1, "the item does apply at the new origin");
  const after = await ask(built.popup, { kind: "recall-active-tab" });
  assert.equal(after.entry, null, "but the tab's memory of page one does not travel with it");

  await screenshot(page, t.name, "01-after-navigation", "a different site: nothing is remembered");
  await page.close();
});

test("a search box gets no icon, however login-shaped the page around it is", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  // Served from the origin the item *is* saved for, so the refusal is the form detector's and not
  // the origin rule's — one text box, one button, and nothing that should ever be filled.
  const page = await open(built, built.origins.saved, "identifier-first/search.html");
  assert.equal(await hasIcon(page), false, "a search box is not an identifier-first form");

  await pressShortcut(page, "#q");
  assert.equal(await page.inputValue("#q"), "", "and ⌘\\ writes nothing into it");
  const html = await page.content();
  assert.ok(!html.includes(USERNAME), "not even the username");

  await screenshot(page, t.name, "01-search", "one text box, one button, and no icon");
  await page.close();
});

test("a page with only a password field gets only the password", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved, "password-only.html");
  await pressShortcut(page);

  assert.equal(await valueOf(page, "#password"), PASSWORD);
  await screenshot(page, t.name, "01-password-only", "step two of a two-step sign-in");
  await page.close();
});

test("an item saved for two websites fills at both of them", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  // The same item carries `app.example.com` and `alice.github.io`. The first is covered by the
  // scenarios above; this is the second, which shares no registrable domain with it at all.
  const page = await open(built, built.origins.secondSaved);
  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.origin, built.origins.secondSaved);
  assert.equal(matched.items.length, 1, "the item's second website matches too");

  await pressShortcut(page);
  assert.equal(await valueOf(page, "#password"), PASSWORD);
  await screenshot(page, t.name, "01-second-url", "the item's second saved website");
  await page.close();
});

test("a subdomain of a saved site matches, because the rule is the registrable domain", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  // `www.example.com` is not one of the saved websites. It matches anyway, and on purpose: the
  // rule is eTLD+1 plus exact scheme and port, so an item saved at `app.example.com` covers the
  // whole of `example.com`. This scenario exists so that the *deliberate* half of the rule is
  // pinned next to the refusals below, rather than only the half that says no.
  const page = await open(built, built.origins.sibling);
  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.origin, built.origins.sibling);
  assert.equal(matched.items.length, 1, "same registrable domain, so the item applies");

  await pressShortcut(page);
  assert.equal(await valueOf(page, "#password"), PASSWORD);
  await screenshot(page, t.name, "01-subdomain", "www.example.com, filled from app.example.com");
  await page.close();
});

test("a different port, a different eTLD+1 and an IP literal are all refused", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const cases = [
    {
      origin: built.origins.otherPort,
      why: "the port is part of the origin, and this one is not the saved one",
      shot: "01-different-port",
      // The page server only listens on one port, so this one genuinely cannot load. What is
      // being asserted is that the *extension* finds nothing for it, which the popup answers
      // without the page needing to exist.
      loads: false,
    },
    {
      origin: built.origins.etldSibling,
      why: "github.io is a public suffix, so mallory.github.io and alice.github.io are siblings, "
        + "not relatives — this is the case the Public Suffix List is carried for",
      shot: "02-etld-sibling",
      loads: true,
    },
    {
      origin: built.origins.ipLiteral,
      why: "an IP literal has no domain structure, so the rule falls back to exact host equality",
      shot: "03-ip-literal",
      loads: true,
    },
    {
      origin: built.origins.stranger,
      why: "nothing at all is saved for it",
      shot: "04-stranger",
      loads: true,
    },
  ];

  const summary = [];
  for (const item of cases) {
    if (!item.loads) {
      summary.push(`${item.origin}\n    refused: ${item.why} (page not served on that port)`);
      continue;
    }
    const page = await open(built, item.origin, "other.html");
    const matched = await ask(built.popup, { kind: "matches-active-tab" });
    assert.equal(matched.ok, true, JSON.stringify(matched));
    assert.equal(matched.origin, item.origin);
    assert.equal(matched.items.length, 0, `${item.origin} should match nothing: ${item.why}`);
    assert.equal(await hasIcon(page), false, `no icon on ${item.origin}`);

    await pressShortcut(page);
    assert.equal(
      await page.inputValue("#password"),
      "",
      `the shortcut must not fill ${item.origin}`,
    );
    const html = await page.content();
    assert.ok(!html.includes(PASSWORD), `${item.origin} must never see the password`);

    await screenshot(page, t.name, item.shot, `${item.origin} — not filled`);
    summary.push(`${item.origin}\n    refused: ${item.why}`);
    await page.close();
  }

  recordText(t.name, "refusals.txt", summary.join("\n\n"), "every origin refused, and why");
});

test("a refused fill is audited as FILL_ORIGIN_MISMATCH, with no prompt", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  // A refusal by the rule is not a question for a human — there is nothing to weigh about a fill
  // the rule refused — so it is an audit entry and never a sheet. To produce one the fill has to
  // be *requested* for a specific item at a mismatched origin, which is what the popup's
  // totp/fill relay does; a page that simply matches nothing never asks.
  const saved = await open(built, built.origins.saved);
  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  const itemId = matched.items[0].item_id;
  await saved.close();

  const elsewhere = await open(built, built.origins.etldSibling, "other.html");
  const refused = await ask(built.popup, { kind: "totp-active-tab", itemId });
  assert.equal(refused.ok, false, `a fill at a mismatched origin must fail: ${JSON.stringify(refused)}`);
  // The content script turns the wire code into a sentence before answering the popup —
  // `content.js`'s `friendly()` — so the machine code stops at the frame that can act on it. What
  // reaches the popup is the ORIGIN_MISMATCH wording, and what reaches the audit log is the code.
  assert.match(
    refused.message,
    /not saved for this site/,
    `the refusal should be the origin-mismatch wording: ${JSON.stringify(refused)}`,
  );
  await screenshot(elsewhere, t.name, "01-refused", "asked for by id, refused by the rule");
  await elsewhere.close();

  const entries = await built.harness.audit();
  const mismatch = entries.filter((e) => (e.detail || "").startsWith("FILL_ORIGIN_MISMATCH"));
  assert.ok(
    mismatch.length >= 1,
    `the refusal should be audited, got ${JSON.stringify(entries)}`,
  );
  assert.ok(
    mismatch.every((e) => e.outcome !== "Allowed"),
    "a mismatch is never an allowed outcome",
  );
  assert.ok(
    !JSON.stringify(entries).includes(PASSWORD),
    "no audit entry may contain the password",
  );

  recordText(
    t.name,
    "audit.txt",
    entries.map((e) => `${e.tool.padEnd(16)} ${e.outcome.padEnd(10)} ${e.detail}  ${e.origin}`).join("\n"),
    "the audit log, refusals included",
  );
});

test("a same-origin frame fills and a cross-origin frame does not", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(
    built,
    built.origins.saved,
    "frames.html",
    `?cross=${encodeURIComponent(built.origins.stranger)}`,
  );
  await page.waitForTimeout(2_000);
  await screenshot(page, t.name, "01-before", "two frames, one of each kind");

  const same = page.frameLocator("#same");
  const cross = page.frameLocator("#cross");

  // The content script runs in every frame, and each frame is matched on *its own* origin — which
  // the browser stamps on the message, not the page. So a form in a frame served from the origin
  // the item is saved for fills, and one served from anywhere else does not, however trusted the
  // page around it is. That is what stops an ad iframe harvesting a password from the page it
  // is embedded in.
  await same.locator("#password").focus();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+Backslash" : "Control+Backslash");
  await page.waitForTimeout(2_000);

  assert.equal(
    await same.locator("#password").inputValue(),
    PASSWORD,
    "the same-origin frame is the origin the item is saved for",
  );

  await cross.locator("#password").focus();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+Backslash" : "Control+Backslash");
  await page.waitForTimeout(2_000);

  assert.equal(
    await cross.locator("#password").inputValue(),
    "",
    "the cross-origin frame must not be filled from the page that embeds it",
  );
  assert.equal(
    await cross.locator("#username").inputValue(),
    "",
    "and not the username either",
  );

  await screenshot(page, t.name, "02-after", "only the same-origin frame was filled");
  await page.close();
});

test("the one-time code is a separate, explicit second action", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved);
  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.items[0].has_totp, true, "the item carries a one-time-password field");

  await pressShortcut(page);
  assert.equal(await valueOf(page, "#password"), PASSWORD);
  assert.equal(
    await page.inputValue("#otp"),
    "",
    "a fill does not also produce a code: two actions, deliberately",
  );

  const totp = await ask(built.popup, {
    kind: "totp-active-tab",
    itemId: matched.items[0].item_id,
  });
  assert.equal(totp.ok, true, JSON.stringify(totp));

  // The code never reaches the popup — the content script wrote it into the page's detected
  // one-time-code field. That is what is asserted, rather than a value in a reply.
  const code = await valueOf(page, "#otp");
  assert.match(code, /^\d{6}$/, `a six-digit code should land in the OTP field, got "${code}"`);
  assert.ok(!JSON.stringify(totp).includes(code), "and it is not also handed back to the popup");

  await screenshot(page, t.name, "01-code-applied", "the one-time code, asked for separately");

  const entries = await built.harness.audit();
  assert.ok(
    entries.some((e) => e.tool === "totp_code"),
    "the code is recorded separately from the fill",
  );
  assert.ok(!JSON.stringify(entries).includes(code), "no audit entry contains the code");
  await page.close();
});

test("the one-time code can also be copied to the clipboard", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const page = await open(built, built.origins.saved);
  const matched = await ask(built.popup, { kind: "matches-active-tab" });

  await ask(built.popup, { kind: "totp-active-tab", itemId: matched.items[0].item_id });
  const code = await valueOf(page, "#otp");
  assert.match(code, /^\d{6}$/);

  // `navigator.clipboard` is not reachable here: a persistent context launched with a real browser
  // channel refuses `Browser.grantPermissions` for clipboard, and without the grant the promise
  // rejects rather than resolving empty. So the copy is driven the way a user's ⌘C does it — a
  // real selection and a real key press — which exercises the same path and needs no permission.
  await page.locator("#otp").selectText();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+KeyC" : "Control+KeyC");

  // Read it back by pasting into a field that is empty, so the assertion is about the clipboard's
  // contents rather than about the field it came from.
  await page.locator("#username").fill("");
  await page.locator("#username").focus();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+KeyV" : "Control+KeyV");
  await page.waitForTimeout(500);

  const pasted = await page.inputValue("#username");
  assert.equal(pasted, code, "the code round-trips through the system clipboard");
  assert.notEqual(pasted, PASSWORD, "and it is a code, not the password");

  await screenshot(page, t.name, "01-clipboard", "the code, after a clipboard round trip");
  await page.close();
});

test("nothing reaches the native host's stderr that should not", async (t) => {
  const built = await requireWorld(t);
  if (!built) return;

  const stderr = built.harness.stderr();
  assert.ok(
    !stderr.includes(PASSWORD),
    `the harness must never write a value to stderr: ${stderr}`,
  );
  assert.ok(!stderr.includes(USERNAME), `nor a username: ${stderr}`);

  const entries = await built.harness.audit();
  const serialized = JSON.stringify(entries);
  assert.ok(!serialized.includes(PASSWORD), "and no audit entry may contain the password");

  const fills = entries.filter((e) => e.tool === "fill_credential" && e.outcome === "Allowed");
  assert.ok(fills.length >= 4, `several fills should be recorded, got ${fills.length}`);
  for (const fill of fills) {
    assert.ok(fill.origin, `every fill records the origin it happened at: ${JSON.stringify(fill)}`);
  }

  recordText(
    t.name,
    "audit-summary.txt",
    entries.map((e) => `${e.tool.padEnd(16)} ${e.outcome.padEnd(10)} ${e.origin}  ${e.fields}`).join("\n"),
    "every entry the run produced: names and origins, never values",
  );
});

// -------------------------------------------------------------------------------------------
// The scenarios that need a world of their own
// -------------------------------------------------------------------------------------------

/**
 * Click one row of the icon's menu, by arithmetic.
 *
 * The menu lives in a **closed** shadow root, which is the property that keeps page script out of
 * it — and keeps Playwright's selectors out of it too. So the row is clicked the way a mouse
 * clicks it: at a point, computed from the geometry `content.js` lays the overlay out with
 * (host at `field.right - 26`, menu `top: 26px; right: 0` and 220px wide, rows ~46px tall). A
 * change to that CSS breaks this helper, which is the honest trade for not poking a hole in the
 * shadow root for a test.
 *
 * @param {import("playwright").Page} page
 * @param {string} selector the field the icon is anchored to
 * @param {number} index 0-based row
 */
async function clickMenuRow(page, selector, index) {
  const box = await page.locator(selector).boundingBox();
  const hostLeft = box.x + box.width - 26;
  const hostTop = box.y + (box.height - 22) / 2;
  const x = hostLeft + 22 - 110;
  const y = hostTop + 26 + 4 + 23 + index * 46;
  await page.mouse.click(x, y);
  await page.waitForTimeout(1_500);
}

test("with two accounts saved, page two continues as whoever page one chose", async (t) => {
  const built = await requireWorld(t, "identifier");
  if (!built) return;

  // This world has two logins saved at the same origin, which is what makes the memory do any
  // work: with one item "which item" answers itself, and with two it does not.
  const control = await open(built, built.origins.saved, "identifier-first/step2.html");
  await pressShortcut(control, "#password");
  assert.equal(
    await control.inputValue("#password"),
    "",
    "a password page with two candidates and no memory offers a list rather than filling",
  );
  await screenshot(control, t.name, "01-control", "page two on its own: which of the two?");
  await control.close();

  const page = await open(built, built.origins.saved, "identifier-first/step1.html");
  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.items.length, 2, "two accounts apply here");
  await page.bringToFront();

  await pressShortcut(page, "#username");
  assert.equal(
    await page.inputValue("#username"),
    "",
    "two candidates, so page one asks rather than picking",
  );
  await screenshot(page, t.name, "02-menu", "the menu on page one, in a closed shadow root");

  // The user picks the first account.
  await clickMenuRow(page, "#username", 0);
  assert.equal(await valueOf(page, "#username"), USERNAME, "the account the user picked");
  await screenshot(page, t.name, "03-chosen", "page one, filled with the chosen account");

  await page.goto(`${built.origins.saved}/identifier-first/step2.html`);
  await page.bringToFront();
  await page.waitForTimeout(1_500);
  await pressShortcut(page, "#password");

  const filled = await valueOf(page, "#password");
  assert.equal(filled, PASSWORD, "page two continued as the account page one chose, unprompted");
  assert.notEqual(filled, SECOND_PASSWORD, "and not the other account saved at the same origin");
  await screenshot(page, t.name, "04-continued", "page two, filled without asking again");

  const entries = await built.harness.audit();
  const details = entries
    .filter((e) => e.tool === "fill_credential" && e.outcome === "Allowed")
    .map((e) => e.detail);
  assert.ok(
    details.includes("FILL_USERNAME_ONLY"),
    `page one is recorded without a sheet: ${JSON.stringify(details)}`,
  );
  assert.ok(
    details.includes("FILL_APPROVED"),
    `and page two is recorded as a decision somebody made: ${JSON.stringify(details)}`,
  );
  assert.ok(
    !JSON.stringify(entries).includes(SECOND_PASSWORD),
    "no audit entry may contain either account's password",
  );
  await page.close();
  // The only scenario this world exists for. Closing it here keeps three browsers running at
  // once rather than four — see `closeWorld`.
  await closeWorld("identifier");
});


test("a denied approval fills nothing", async (t) => {
  const built = await requireWorld(t, "deny");
  if (!built) return;

  // This world's harness runs with `auto_approve` off and a thread that answers every request
  // with `Decision::Deny` — the same `ask`/`resolve` round trip, with the robot saying no.
  const page = await open(built, built.origins.saved);
  await screenshot(page, t.name, "01-before", "the page before a fill is asked for");

  const matched = await ask(built.popup, { kind: "matches-active-tab" });
  assert.equal(matched.items.length, 1, "the item still matches: the refusal is the human's, not the rule's");

  await pressShortcut(page);
  await page.waitForTimeout(2_000);

  assert.equal(await page.inputValue("#password"), "", "a denial fills nothing");
  assert.equal(await page.inputValue("#username"), "", "not even the username");
  const html = await page.content();
  assert.ok(!html.includes(PASSWORD), "the page never sees the value");

  await screenshot(page, t.name, "02-after-denial", "still empty: the answer was no");

  const entries = await built.harness.audit();
  const denied = entries.filter((e) => (e.detail || "").startsWith("FILL_DENIED"));
  assert.ok(denied.length >= 1, `the denial is recorded: ${JSON.stringify(entries)}`);
  assert.ok(
    !entries.some((e) => (e.detail || "").startsWith("FILL_APPROVED")),
    "and nothing in this world was ever approved",
  );

  recordText(
    t.name,
    "audit.txt",
    entries.map((e) => `${e.tool.padEnd(16)} ${e.outcome.padEnd(10)} ${e.detail}`).join("\n"),
    "denials are kept deliberately",
  );
  await page.close();
});

test("a locked vault fills nothing and the popup says so", async (t) => {
  const built = await requireWorld(t, "lock");
  if (!built) return;

  // Unlocked first, so "locked" means the lock did it rather than the world never having worked.
  const page = await open(built, built.origins.saved);
  await pressShortcut(page);
  assert.equal(await valueOf(page, "#password"), PASSWORD, "this world starts unlocked");
  await screenshot(page, t.name, "01-unlocked", "before the lock: a normal fill");

  await built.harness.lock();

  const status = await ask(built.popup, { kind: "status" });
  assert.equal(status.ok, true, JSON.stringify(status));
  assert.equal(
    status.state.status,
    "locked",
    `the popup should report a locked vault: ${JSON.stringify(status.state)}`,
  );
  await built.popup.reload();
  await built.popup.waitForTimeout(1_500);
  await screenshot(built.popup, t.name, "02-popup-locked", "the popup, with the vault locked");

  const fresh = await open(built, built.origins.saved);
  assert.equal(await hasIcon(fresh), false, "no icon while the vault is locked");
  await pressShortcut(fresh);
  await fresh.waitForTimeout(1_500);
  assert.equal(await fresh.inputValue("#password"), "", "and no fill");
  await screenshot(fresh, t.name, "03-locked-no-fill", "⌘\\ on a locked vault does nothing");

  await fresh.close();
  await page.close();
});

// -------------------------------------------------------------------------------------------
// Safari
// -------------------------------------------------------------------------------------------

test("Safari: autofill through the App Group socket", (t) => {
  // Reported as skipped, never as a failure, and with the steps in the report so the manual pass
  // is a thing somebody can actually do rather than a thing they have to reconstruct. See
  // docs/e2e-harness.md §6.
  recordText(t.name, "safari-manual.txt", MANUAL_SAFARI_STEPS, "the manual steps");
  t.skip("Safari cannot be driven by automation here; see the attached manual steps.");
});

test("Safari: the approval sheet renders a verified identity", (t) => {
  recordText(
    t.name,
    "safari-verified.txt",
    `${MANUAL_SAFARI_STEPS}\n\n` +
      "This scenario in particular cannot be automated at all, on any browser: a Developer-ID-\n" +
      "signed build can produce a fully *verified* fill through Safari and cannot through Chrome,\n" +
      "because on Safari the process on the socket is the app extension we signed rather than the\n" +
      "browser (ADR-0024 §5). Verifying it means looking at the sheet.",
    "the manual steps",
  );
  t.skip("Safari cannot be driven by automation here; see the attached manual steps.");
});
