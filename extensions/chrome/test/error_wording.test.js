/**
 * What the content script tells the person when the app refuses a fill or a code.
 *
 * Driven through the real `content.js` in a `vm` context over a `linkedom` document, by the one
 * message path that hands the wording back rather than drawing it into the closed shadow root: the
 * popup's `totp-please`, whose failure reply carries the sentence `friendly()` chose.
 *
 * `AUDIT_UNAVAILABLE` (ADR-0040) is the case this file exists for: the app filled nothing because
 * the audit record could not be saved, and the person has to be told that — and where to look —
 * rather than shown a bare protocol token.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseHTML } = require("linkedom");

const SHARED = path.join(__dirname, "..", "..", "shared");
const CONTENT_SOURCE = fs.readFileSync(path.join(SHARED, "content.js"), "utf8");
const PAGE_URL = "https://example.com/login";

/**
 * Run `content.js` with a background that answers every `totp` with `failure`, and return the
 * content script's own `onMessage` listener.
 *
 * @param {{ code: string, message: string }} failure
 */
async function contentScriptAnsweringTotpWith(failure) {
  const parsed = parseHTML("<!doctype html><html><body></body></html>");
  const global = parsed.window;
  let listener = null;
  const clipboard = [];
  global.chrome = {
    runtime: {
      id: "nlijibjnmanccalmafnfbobkcfjiibmd",
      lastError: undefined,
      onMessage: { addListener: (fn) => (listener = fn) },
      sendMessage: (message, callback) => {
        if (message.kind === "totp") {
          callback({ ok: false, ...failure });
          return;
        }
        if (message.kind === "match") {
          callback({ ok: true, reply: { reply: "matches", origin: "https://example.com", items: [] } });
          return;
        }
        callback({ ok: true, reply: { reply: "ok" } });
      },
    },
  };
  Object.defineProperty(global, "navigator", {
    value: { clipboard: { writeText: async (text) => clipboard.push(text) } },
    configurable: true,
  });
  global.KsForms = require(path.join(SHARED, "forms.js"));
  global.KsOrigin = require(path.join(SHARED, "origin.js"));
  global.console = console;
  global.setTimeout = setTimeout;
  global.clearTimeout = clearTimeout;
  Object.defineProperty(global, "location", {
    value: { href: PAGE_URL, ancestorOrigins: null },
    configurable: true,
  });
  global.top = global;
  global.globalThis = global;
  global.self = global;
  vm.createContext(global);
  vm.runInContext(CONTENT_SOURCE, global, { filename: "content.js" });
  assert.ok(listener, "content.js registered no message listener");
  return { listener, clipboard };
}

/** Ask for a code the way the popup does, and return the content script's reply. */
function askForCode(listener) {
  return new Promise((resolve) => {
    const asynchronous = listener({ kind: "totp-please", itemId: "item-1" }, {}, resolve);
    assert.equal(asynchronous, true, "the reply should come back asynchronously");
  });
}

test("AUDIT_UNAVAILABLE says nothing was filled and where to look, not the bare code", async () => {
  const { listener, clipboard } = await contentScriptAnsweringTotpWith({
    code: "AUDIT_UNAVAILABLE",
    message: "AUDIT_UNAVAILABLE",
  });
  const reply = await askForCode(listener);
  assert.equal(reply.ok, false);
  assert.match(reply.message, /audit log/);
  assert.match(reply.message, /nothing was filled/);
  assert.match(reply.message, /Open Kagisecure/);
  assert.doesNotMatch(reply.message, /AUDIT_UNAVAILABLE/);
  assert.deepEqual(clipboard, [], "a refused code must not reach the clipboard");
});

test("VAULT_CONFLICT says to open Kagisecure, not the bare code", async () => {
  const { listener, clipboard } = await contentScriptAnsweringTotpWith({
    code: "VAULT_CONFLICT",
    message: "VAULT_CONFLICT",
  });
  const reply = await askForCode(listener);
  assert.equal(reply.ok, false);
  assert.match(reply.message, /Open Kagisecure/);
  assert.doesNotMatch(reply.message, /VAULT_CONFLICT/);
  assert.deepEqual(clipboard, [], "a refused code must not reach the clipboard");
});

test("a code this build does not know still shows the app's own sentence", async () => {
  // Why a new error code needs no protocol version bump: an older content script falls through
  // to the message the app wrote for it.
  const { listener } = await contentScriptAnsweringTotpWith({
    code: "SOME_FUTURE_CODE",
    message: "The app explains itself here.",
  });
  const reply = await askForCode(listener);
  assert.equal(reply.message, "The app explains itself here.");
});
