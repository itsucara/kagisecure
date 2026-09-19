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
