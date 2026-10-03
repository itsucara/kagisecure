/**
 * B-29 and B-17: what a web page can reach, and which extension the app agrees to talk to.
 *
 * # B-29 — no page-callable surface
 *
 * `chrome.runtime.sendMessage(EXTENSION_ID, …)` from page script reaches an extension **only** if
 * that extension declares `externally_connectable` and registers `onMessageExternal`. Kagisecure
 * declares neither, which is why a page cannot ask the service worker for a fill directly and has
 * to go through a content script that checks `isTrusted`. Both halves of that are asserted here as
 * regression guards: adding `externally_connectable` to the manifest for a marketing site, or
 * adding an `onMessageExternal` listener for a "companion app", would hand every page on the web a
 * direct line to the vault channel. The service worker's own listener is also exercised with a
 * sender that carries no `tab`, which is the shape an external or hostile caller would have.
 *
 * # B-17 — the id pin
 *
 * The app refuses any extension whose id is not in `PINNED_EXTENSION_IDS`
 * (`crates/kagisecure-extension-ipc/src/lib.rs`). The id is not a free choice: Chromium derives it
 * from the committed `key` in the manifest — SHA-256 of the DER public key, first sixteen bytes,
 * each nibble mapped onto `a`..`p`. So the pin can be checked without a browser, and a stale pin —
 * the key rotated, the constant not — means either that the shipped extension is refused, or worse
 * that the app still trusts an id nobody controls any more. This derives the id from the manifest
 * and compares it with the Rust constant read out of the source, editing neither.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SHARED = path.join(__dirname, "..", "..", "shared");
const REPO = path.join(__dirname, "..", "..", "..");
const IPC_LIB = path.join(REPO, "crates", "kagisecure-extension-ipc", "src", "lib.rs");

const manifest = JSON.parse(fs.readFileSync(path.join(SHARED, "manifest.json"), "utf8"));
const backgroundSource = fs.readFileSync(path.join(SHARED, "background.js"), "utf8");

/** A page pretending to be our own UI. Obvious test data. */
const CANARY_PAGE_ORIGIN = "https://evil.test";

test("the manifest never declares externally_connectable", () => {
  assert.equal(
    Object.prototype.hasOwnProperty.call(manifest, "externally_connectable"),
    false,
    "externally_connectable would let page script message the service worker directly",
  );
});

test("no source file in the extension registers onMessageExternal", () => {
  for (const name of fs.readdirSync(SHARED)) {
    if (!name.endsWith(".js") && !name.endsWith(".html")) continue;
    const source = fs.readFileSync(path.join(SHARED, name), "utf8");
    assert.equal(
      /onMessageExternal|onConnectExternal/.test(source),
      false,
      `${name} registers an externally reachable listener`,
    );
  }
});

test("the manifest asks for no permission beyond the one the design needs", () => {
  // A regression guard, not a defect probe: `tabs`, `storage`, `<all_urls>` host permissions and
  // `webRequest` are each a step this extension's threat model says it does not take.
  assert.deepEqual(manifest.permissions.slice().sort(), ["nativeMessaging"]);
  assert.equal(Object.prototype.hasOwnProperty.call(manifest, "host_permissions"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(manifest, "optional_permissions"), false);
});

test("content scripts are injected only into http and https documents", () => {
  const matches = manifest.content_scripts.flatMap((entry) => entry.matches);
  assert.deepEqual(matches.slice().sort(), ["http://*/*", "https://*/*"]);
  for (const pattern of matches) {
    assert.equal(/^(file|ftp|\*):/.test(pattern), false, pattern);
  }
});

test("no part of the extension uses chrome.storage", () => {
  // The service worker's header states this as a property of the whole extension; it is cheap to
  // keep true and expensive to notice once broken.
  for (const name of fs.readdirSync(SHARED)) {
    if (!name.endsWith(".js")) continue;
    const source = fs.readFileSync(path.join(SHARED, name), "utf8");
    const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    assert.equal(/chrome\.storage|browser\.storage/.test(code), false, `${name} uses storage`);
  }
});

/**
 * Load `background.js` with the app end and the tabs API replaced by recorders.
 *
 * @returns {{ listeners: Function[], relayed: object[] }}
 */
function loadServiceWorker() {
  const listeners = [];
  const relayed = [];
  const context = {
    console,
    setTimeout,
    clearTimeout,
    Date,
    URL,
    chrome: {
      runtime: { onMessage: { addListener: (fn) => listeners.push(fn) } },
      tabs: {
        onRemoved: { addListener: () => {} },
        query: async () => [{ id: 42 }],
        sendMessage: async (tabId, forwarded) => {
          relayed.push({ tabId, forwarded });
          return { ok: true };
        },
      },
    },
  };
  context.self = context;
  context.globalThis = context;
  context.importScripts = (...names) => {
    for (const name of names) {
      if (name === "native.js") {
        context.KsNative = {
          ensureHello: async () => ({ status: "ready" }),
          refreshState: async () => ({ status: "ready" }),
          onPush: () => {},
          call: async () => {
            throw new Error("the app must not be reached for an unowned message kind");
          },
        };
      } else if (name === "origin.js") {
        context.KsOrigin = require(path.join(SHARED, "origin.js"));
      } else if (name === "tabmemory.js") {
        context.KsTabMemory = require(path.join(SHARED, "tabmemory.js"));
      }
    }
  };
  vm.createContext(context);
  vm.runInContext(backgroundSource, context, { filename: "background.js" });
  return { listeners, relayed };
}

/** Offer `message` to every listener; returns the ones that claimed it. */
function claimants(listeners, message, sender) {
  const claimed = [];
  for (let i = 0; i < listeners.length; i += 1) {
    if (listeners[i](message, sender, () => {}) === true) claimed.push(i);
  }
  return claimed;
}

test("the service worker ignores request kinds no listener owns", () => {
  const { listeners, relayed } = loadServiceWorker();
  const sender = { origin: CANARY_PAGE_ORIGIN, url: `${CANARY_PAGE_ORIGIN}/`, frameId: 0 };
  for (const message of [
    { kind: "unlock" },
    { kind: "hello" },
    { kind: "" },
    { kind: "fill-active-tab-x" },
    {},
    null,
    "fill",
    { kind: 7 },
    { kind: ["fill"] },
  ]) {
    assert.deepEqual(claimants(listeners, message, sender), [], JSON.stringify(message));
  }
  assert.deepEqual(relayed, []);
});

test(
  "a request kind borrowed from Object.prototype is not treated as a relay name",
  () => {
    const { listeners, relayed } = loadServiceWorker();
    const sender = { origin: CANARY_PAGE_ORIGIN, url: `${CANARY_PAGE_ORIGIN}/`, frameId: 0 };
    for (const kind of ["__proto__", "constructor", "toString", "valueOf", "hasOwnProperty"]) {
      assert.deepEqual(
        claimants(listeners, { kind }, sender),
        [],
        `a listener claimed the inherited key ${kind}`,
      );
    }
    assert.deepEqual(relayed, []);
  },
);

test(
  "the popup relay refuses a message that came from a content script rather than the popup",
  async () => {
    const { listeners, relayed } = loadServiceWorker();
    // `sender.tab` is stamped by Chrome only for a message from a content script. The popup's
    // sender has no `tab` at all, which is how the worker could tell the two apart if it looked.
    const contentScriptSender = {
      origin: CANARY_PAGE_ORIGIN,
      url: `${CANARY_PAGE_ORIGIN}/`,
      frameId: 0,
      tab: { id: 42 },
    };
    claimants(listeners, { kind: "fill-active-tab" }, contentScriptSender);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.deepEqual(
      relayed,
      [],
      "a content script made the worker relay a gesture-free fill to the active tab",
    );
  },
);

test("the extension id derived from the committed manifest key is the id the app pins", () => {
  const der = Buffer.from(manifest.key, "base64");
  const digest = crypto.createHash("sha256").update(der).digest();
  const derivedId = Array.from(digest.subarray(0, 16))
    .flatMap((byte) => [byte >> 4, byte & 0x0f])
    .map((nibble) => String.fromCharCode("a".charCodeAt(0) + nibble))
    .join("");

  assert.equal(derivedId.length, 32);
  assert.match(derivedId, /^[a-p]{32}$/);

  const rust = fs.readFileSync(IPC_LIB, "utf8");
  const pinned = /PINNED_EXTENSION_IDS:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]/.exec(rust);
  assert.ok(pinned, "PINNED_EXTENSION_IDS not found in the ipc crate");
  const ids = Array.from(pinned[1].matchAll(/"([^"]+)"/g), (m) => m[1]);

  // The committed key's id must be pinned, and must come first: `PINNED_EXTENSION_IDS[0]` is the
  // id the setup screen shows. Further entries are allowed — the Chrome Web Store item's id, added
  // after its first upload (ADR-0021, amendment of 2026-10-03; docs/chrome-web-store.md) — but
  // each must still be a well-formed id, and none may repeat.
  assert.equal(
    ids[0],
    derivedId,
    `the app pins ${JSON.stringify(ids)} first but the committed manifest key yields ${derivedId}`,
  );
  for (const id of ids) assert.match(id, /^[a-p]{32}$/, `${id} is not a Chromium extension id`);
  assert.equal(new Set(ids).size, ids.length, `PINNED_EXTENSION_IDS repeats an id: ${ids}`);
});
