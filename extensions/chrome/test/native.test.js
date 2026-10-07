/**
 * The one channel to the app: what it caches, and what it must not.
 *
 * `native.js` is an IIFE that attaches `KsNative` to the global, and it talks to a native
 * messaging port. Both are stubbed here — a fake `chrome.runtime` and a fake port that answers
 * whatever the test queued — because what is under test is the *state machine*, not the transport.
 * The transport is covered for real by the Playwright suite in `e2e/suites/extension/` and, on the
 * Rust side, by `crates/kagisecure-agent/tests/extension.rs`.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

// ---------------------------------------------------------------------------------------
// A fake browser
// ---------------------------------------------------------------------------------------

/** The replies the fake app will give, in order, one per request. */
let scripted = [];
/** Every request body the extension sent, in order. */
let sent = [];
let disconnected = null;

function installFakeChrome() {
  scripted = [];
  sent = [];

  const listeners = { message: [], disconnect: [] };
  const port = {
    postMessage(envelope) {
      sent.push(envelope.body);
      const next = scripted.shift();
      const body =
        next || { reply: "error", code: "INTERNAL", message: "the test scripted no reply" };
      // Asynchronous, like the real thing: the resolver must be registered before the answer
      // arrives, and a synchronous stub would hide an ordering bug here.
      setTimeout(() => {
        for (const fn of listeners.message) fn({ ksx: 1, id: envelope.id, body });
      }, 0);
    },
    disconnect() {
      for (const fn of listeners.disconnect) fn();
    },
    onMessage: { addListener: (fn) => listeners.message.push(fn) },
    onDisconnect: { addListener: (fn) => listeners.disconnect.push(fn) },
  };
  disconnected = () => port.disconnect();

  globalThis.chrome = {
    runtime: {
      id: "nlijibjnmanccalmafnfbobkcfjiibmd",
      lastError: null,
      // Chromium, not Safari: the transport is chosen from this scheme and nothing else.
      getURL: () => "chrome-extension://nlijibjnmanccalmafnfbobkcfjiibmd/",
      getManifest: () => ({ version: "0.1.0" }),
      connectNative: () => port,
    },
  };
}

/** Load a fresh `KsNative` with the fake browser in place. */
function loadNative() {
  installFakeChrome();
  delete globalThis.KsNative;
  delete require.cache[require.resolve("../../shared/native.js")];
  require("../../shared/native.js");
  return globalThis.KsNative;
}

/**
 * Wait until `condition()` holds, instead of sleeping for a guessed time: how long the retry
 * schedule takes to get somewhere depends on how loaded the machine is, what it gets to does not.
 * The deadline only turns a real hang into a failure with a message.
 */
async function until(condition, what, deadlineMs = 5000) {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > deadlineMs) assert.fail(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 1));
  }
}

const hellosSent = () => sent.filter((b) => b.ask === "hello").length;

const welcome = (unlocked) => ({
  reply: "welcome",
  protocol_version: 1,
  app_version: "0.1.0",
  unlocked,
  host_evidence: ["Native host: /tmp/kagisecure-nmhost (pid 1)"],
});

// ---------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------

test("the handshake establishes the session and is not repeated", async () => {
  const native = loadNative();
  scripted = [welcome(true), welcome(true)];

  const first = await native.ensureHello();
  assert.equal(first.status, "ready");
  assert.deepEqual(first.evidence, ["Native host: /tmp/kagisecure-nmhost (pid 1)"]);

  await native.ensureHello();
  assert.equal(
    sent.filter((body) => body.ask === "hello").length,
    1,
    "ensureHello exists so every other call has a session behind it, not to re-handshake",
  );
});

test("a locked vault at handshake time is reported as locked", async () => {
  const native = loadNative();
  scripted = [welcome(false)];

  const state = await native.ensureHello();
  assert.equal(state.status, "locked");
  assert.equal(state.detail, "The vault is locked.");
});

/**
 * The regression this file was added for.
 *
 * The app keeps its extension listener up while the vault is locked and answers `VAULT_LOCKED`, so
 * the native port never drops and nothing invalidates a cached `ready`. The popup asked
 * `ensureHello`, got the cache, and drew a green dot and "Connected." over a vault the user had
 * just locked — the one lie a password manager must never tell.
 */
test("after a lock, the state refreshes to locked even though the port is still up", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  assert.equal((await native.ensureHello()).status, "ready");

  // The vault locks. Nothing tells the extension; the port is still open.
  scripted = [{ reply: "error", code: "VAULT_LOCKED", message: "The vault is locked." }];

  const refreshed = await native.refreshState();
  assert.equal(refreshed.status, "locked", "the popup must not be told the vault is connected");
  assert.equal(native.state().status, "locked", "and the cached state is corrected, not bypassed");
  assert.equal(
    sent.filter((body) => body.ask === "status").length,
    1,
    "refreshed with one `status` message rather than a second handshake",
  );
});

test("refreshState reports a still-unlocked vault as ready", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  await native.ensureHello();

  scripted = [{ reply: "status", unlocked: true }];
  const refreshed = await native.refreshState();
  assert.equal(refreshed.status, "ready");
  assert.equal(refreshed.detail, "Connected.");
  assert.deepEqual(
    refreshed.evidence,
    ["Native host: /tmp/kagisecure-nmhost (pid 1)"],
    "a refresh keeps what the handshake established about the host",
  );
});

test("refreshState reports an app that has locked between the two messages", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  await native.ensureHello();

  scripted = [{ reply: "status", unlocked: false }];
  assert.equal((await native.refreshState()).status, "locked");
});

test("a session that was locked picks up an unlock", async () => {
  const native = loadNative();
  scripted = [welcome(false)];
  assert.equal((await native.ensureHello()).status, "locked");

  // `ensureHello` only caches a *ready* session, so anything else re-handshakes — which is how a
  // vault the user has since unlocked becomes usable again without reloading the extension.
  scripted = [welcome(true), { reply: "status", unlocked: true }];
  const refreshed = await native.refreshState();
  assert.equal(refreshed.status, "ready");
  assert.equal(
    sent.filter((body) => body.ask === "hello").length,
    2,
    "the second handshake is what established the session again",
  );
});

test("a dropped port fails everything waiting rather than hanging", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  await native.ensureHello();

  // No scripted reply, so the request is in flight when the helper goes away.
  const inFlight = native.call({ ask: "status" });
  disconnected();
  const reply = await inFlight;
  assert.equal(reply.reply, "error");
  assert.equal(native.state().status, "disconnected");
});

// ---------------------------------------------------------------------------------------
// Pushes and capabilities (ADR-0036)
// ---------------------------------------------------------------------------------------

/** The port's message listeners, reached through a fresh Chromium `KsNative`. */
function loadNativeWithPort() {
  const native = loadNative();
  const listeners = [];
  const realConnect = globalThis.chrome.runtime.connectNative;
  globalThis.chrome.runtime.connectNative = (name) => {
    const port = realConnect(name);
    const addListener = port.onMessage.addListener;
    port.onMessage.addListener = (fn) => {
      listeners.push(fn);
      addListener(fn);
    };
    return port;
  };
  return { native, deliver: (frame) => listeners.forEach((fn) => fn(frame)) };
}

test("chromium declares agent_fill at hello", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  await native.ensureHello();
  const hello = sent.find((body) => body.ask === "hello");
  assert.deepEqual(hello.capabilities, ["agent_fill"]);
  assert.deepEqual(Array.from(native.CAPABILITIES), ["agent_fill"]);
});

test("safari_never_declares_agent_fill", async () => {
  // The Safari build: the same file, told apart by the scheme of its own URL and nothing else.
  const safariSent = [];
  globalThis.chrome = {
    runtime: {
      id: "5A1B2C3D-0000-4000-8000-000000000000",
      lastError: null,
      getURL: () => "safari-web-extension://5A1B2C3D-0000-4000-8000-000000000000/",
      getManifest: () => ({ version: "0.1.0" }),
      // Safari has a `connectNative` of its own; it must not be what decides anything.
      connectNative: () => {
        throw new Error("the Safari build must not open a port");
      },
      sendNativeMessage: (_application, envelope, callback) => {
        safariSent.push(envelope.body);
        setTimeout(() => callback(welcome(true)), 0);
      },
    },
  };
  delete globalThis.KsNative;
  delete require.cache[require.resolve("../../shared/native.js")];
  require("../../shared/native.js");
  const native = globalThis.KsNative;

  assert.equal(native.isSafari, true);
  assert.deepEqual(Array.from(native.CAPABILITIES), []);
  await native.ensureHello();
  const hello = safariSent.find((body) => body.ask === "hello");
  assert.ok(hello, "no hello was sent");
  assert.equal(
    Object.prototype.hasOwnProperty.call(hello, "capabilities"),
    false,
    "the Safari hello declared capabilities",
  );

  // And the native handler, which rewrites the JavaScript side's `hello` and builds its own for
  // every other connection, strips the list in the one and never adds it to the other — so a
  // Safari session declares nothing even if this file ever did.
  const swift = fs.readFileSync(
    path.join(
      __dirname,
      "..",
      "..",
      "..",
      "apps",
      "macos",
      "KagisecureSafariExtension",
      "SafariWebExtensionHandler.swift",
    ),
    "utf8",
  );
  assert.match(swift, /body\["capabilities"\]\s*=\s*\[String\]\(\)/);
  assert.match(swift, /"capabilities":\s*\[String\]\(\)/);
  assert.doesNotMatch(swift, /"agent_fill"/, "the handler names the capability as a value");
});

test("a push frame goes to the push listener and never answers a request", async () => {
  const { native, deliver } = loadNativeWithPort();
  scripted = [welcome(true)];
  await native.ensureHello();

  const pushes = [];
  native.onPush((push) => pushes.push(push));

  // A request in flight: its reply is queued behind the two pushes below.
  scripted = [{ reply: "status", unlocked: true }];
  const inFlight = native.call({ ask: "status" });
  deliver({ ksx: 1, push: { push: "locate", probe_id: "probe-1" } });
  deliver({ ksx: 1, push: { push: "deliver", probe_id: "probe-1", grant_id: "grant-1" } });
  assert.deepEqual(pushes, [
    { push: "locate", probe_id: "probe-1" },
    { push: "deliver", probe_id: "probe-1", grant_id: "grant-1" },
  ]);
  // The request is answered by its own reply, not by either push.
  assert.deepEqual(await inFlight, { reply: "status", unlocked: true });
});

test("a frame that is both a reply and a push, or neither, is no push", async () => {
  const { native, deliver } = loadNativeWithPort();
  scripted = [welcome(true)];
  await native.ensureHello();
  const pushes = [];
  native.onPush((push) => pushes.push(push));

  deliver({ ksx: 1, id: "x99", push: { push: "locate", probe_id: "p" } });
  deliver({ ksx: 1, body: {}, push: { push: "locate", probe_id: "p" } });
  deliver({ ksx: 2, push: { push: "locate", probe_id: "p" } });
  deliver({ ksx: 1, push: "locate" });
  deliver({ ksx: 1 });
  deliver(null);
  assert.deepEqual(pushes, []);
});

test("a push listener that throws does not break the port", async () => {
  const { native, deliver } = loadNativeWithPort();
  scripted = [welcome(true)];
  await native.ensureHello();
  native.onPush(() => {
    throw new Error("listener bug");
  });
  deliver({ ksx: 1, push: { push: "locate", probe_id: "p" } });
  scripted = [{ reply: "status", unlocked: true }];
  assert.equal((await native.call({ ask: "status" })).reply, "status");
});

// ---------------------------------------------------------------------------------------
// Automatic reconnect after the port drops
// ---------------------------------------------------------------------------------------

test("auto-reconnect is off by default: a dropped port is left disconnected", async () => {
  const native = loadNative();
  scripted = [welcome(true)];
  await native.ensureHello();
  disconnected();
  assert.equal(native.state().status, "disconnected");

  // Long enough to cross the real schedule's first step, several times over, if anything had
  // been scheduled.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(
    sent.filter((b) => b.ask === "hello").length,
    1,
    "nothing retries on its own until background.js opts in",
  );
});

test("once enabled, a dropped port retries hello on its own, with backoff", async () => {
  const native = loadNative();
  native.enableAutoReconnect([5, 10, 15]);
  try {
    scripted = [welcome(true)];
    await native.ensureHello();
    assert.equal(native.state().status, "ready");

    // The port drops — a lock, a crash of the helper, or the helper going away.
    disconnected();
    assert.equal(native.state().status, "disconnected");

    // Nothing was scripted to answer with, as if the app were still unreachable: the retry's own
    // `hello` gets the fake port's default "no reply scripted" error, so it must try again.
    await until(
      () => hellosSent() >= 2 && native.state().status === "error",
      "an automatic retry that found nothing to answer it",
    );

    // The app comes back: the next retry's `hello` gets a real welcome and the loop stops.
    scripted.push(welcome(true));
    await until(() => native.state().status === "ready", "a later retry to re-establish the session");

    const afterSuccess = sent.filter((b) => b.ask === "hello").length;
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(
      sent.filter((b) => b.ask === "hello").length,
      afterSuccess,
      "the schedule stops once hello succeeds again",
    );
  } finally {
    native.disableAutoReconnect();
  }
});

test("a welcome that reports the vault as locked still stops the retry loop", async () => {
  const native = loadNative();
  native.enableAutoReconnect([5, 10]);
  try {
    scripted = [welcome(true)];
    await native.ensureHello();
    disconnected();

    // The retry's own hello succeeds, but the vault is locked — a legitimate `welcome`, not a
    // failure to reach the app at all, so nothing further should be scheduled.
    scripted.push(welcome(false));
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(native.state().status, "locked");

    const afterWelcome = sent.filter((b) => b.ask === "hello").length;
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(
      sent.filter((b) => b.ask === "hello").length,
      afterWelcome,
      "a locked-but-reachable app is not retried further",
    );
  } finally {
    native.disableAutoReconnect();
  }
});

test("disableAutoReconnect cancels a pending retry", async () => {
  const native = loadNative();
  native.enableAutoReconnect([20]);
  scripted = [welcome(true)];
  await native.ensureHello();
  disconnected();

  native.disableAutoReconnect();
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(
    sent.filter((b) => b.ask === "hello").length,
    1,
    "turning it off cancels whatever was pending",
  );
});

test("Safari never schedules a reconnect: there is no port for it", async () => {
  const safariSent = [];
  globalThis.chrome = {
    runtime: {
      id: "5A1B2C3D-0000-4000-8000-000000000000",
      lastError: null,
      getURL: () => "safari-web-extension://5A1B2C3D-0000-4000-8000-000000000000/",
      getManifest: () => ({ version: "0.1.0" }),
      connectNative: () => {
        throw new Error("the Safari build must not open a port");
      },
      sendNativeMessage: (_application, envelope, callback) => {
        safariSent.push(envelope.body);
        setTimeout(() => callback(welcome(true)), 0);
      },
    },
  };
  delete globalThis.KsNative;
  delete require.cache[require.resolve("../../shared/native.js")];
  require("../../shared/native.js");
  const native = globalThis.KsNative;
  native.enableAutoReconnect([5]);
  try {
    await native.ensureHello();
    // Safari has no `dropPort` path at all — nothing here should ever schedule anything — but the
    // guard in `scheduleReconnect` is asserted directly by there being no port to disconnect and
    // no further hellos appearing on their own.
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(safariSent.filter((b) => b.ask === "hello").length, 1);
  } finally {
    native.disableAutoReconnect();
  }
});
