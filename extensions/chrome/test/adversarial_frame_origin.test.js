/**
 * D-7 / B-03: what the service worker forwards about a cross-origin sub-frame.
 *
 * `trustedPageContext` in `background.js` takes the frame's own origin from `sender.origin`, which
 * Chrome stamps and a page cannot forge. That part is right, and the tests below pin it. What it
 * does *not* do is take the **top** origin from anywhere trustworthy: it uses the content script's
 * claimed `page.top_origin` whenever one parses, and falls back to the frame's own origin
 * otherwise.
 *
 * The comment above that function argues a lying page "can only make the app's iframe policy
 * stricter, never looser, because the frame origin it is compared against is the trusted one".
 * That is true of the **match**. It is not true of the **disclosure**: the app raises `top_origin`
 * on the approval request only when it differs from the matched origin
 * (`crates/kagisecure-agent/src/extension.rs`), and that is what renders the "this form is inside a
 * frame on X" warning. So a cross-origin sub-frame whose content script has been replaced can
 * claim `top_origin == its own origin`, the claim survives the service worker unchanged, and the
 * approval sheet for a third-party-frame fill renders as an ordinary top-frame fill. Telling the
 * human where the form actually is (mitigation M-5) is the whole defence against a fill that is
 * technically to the right origin but visually somewhere else.
 *
 * This file runs the real `background.js` in a `vm` context with stubs for `importScripts`,
 * `chrome` and the native channel, and inspects the request body that reaches `KsNative.call` —
 * the last thing the extension controls before the app sees it.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SHARED = path.join(__dirname, "..", "..", "shared");

/** A stand-in embedder, so an origin appearing in a diff is obviously test data. */
const CANARY_TOP_SITE = "https://bank.test";
/** The cross-origin sub-frame doing the lying. */
const CANARY_FRAME_SITE = "https://widget.evil.test";
const CANARY_ITEM_ID = "item-canary-0000";

/**
 * Load `background.js` with the app end replaced by a recorder.
 *
 * @returns {{ dispatch: (message: object, sender: object) => Promise<object>, calls: object[] }}
 */
function loadServiceWorker({ reply = { reply: "matches", items: [] } } = {}) {
  const calls = [];
  const nativeStub = {
    ensureHello: async () => ({ status: "ready" }),
    refreshState: async () => ({ status: "ready" }),
    onPush: () => {},
    call: async (body) => {
      calls.push(JSON.parse(JSON.stringify(body)));
      return reply;
    },
  };
  const listeners = [];
  const context = {
    console,
    setTimeout,
    clearTimeout,
    Date,
    URL,
    chrome: {
      runtime: { onMessage: { addListener: (fn) => listeners.push(fn) } },
      tabs: { onRemoved: { addListener: () => {} } },
    },
  };
  context.self = context;
  context.globalThis = context;
  context.importScripts = (...names) => {
    for (const name of names) {
      if (name === "native.js") {
        context.KsNative = nativeStub;
      } else if (name === "origin.js") {
        context.KsOrigin = require(path.join(SHARED, "origin.js"));
      } else if (name === "tabmemory.js") {
        context.KsTabMemory = require(path.join(SHARED, "tabmemory.js"));
      } else {
        throw new Error(`unexpected importScripts(${name})`);
      }
    }
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(SHARED, "background.js"), "utf8"), context, {
    filename: "background.js",
  });

  const dispatch = (message, sender) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no listener answered")), 1000);
      for (const listener of listeners) {
        const owned = listener(message, sender, (response) => {
          clearTimeout(timer);
          resolve(response);
        });
        if (owned) return;
      }
    });

  return { dispatch, calls };
}

/** A `sender` shaped the way Chrome stamps one for a content script in a sub-frame. */
function subFrameSender(origin) {
  return { origin, url: `${origin}/widget`, frameId: 3, tab: { id: 11 } };
}

/** A `sender` for the top frame of a tab. */
function topFrameSender(origin) {
  return { origin, url: `${origin}/login`, frameId: 0, tab: { id: 11 } };
}

test("the frame's own origin always comes from the browser, never from the message", async () => {
  const worker = loadServiceWorker();
  await worker.dispatch(
    {
      kind: "match",
      // The content script claims to be somewhere else entirely.
      page: { top_origin: CANARY_TOP_SITE, frame_origin: CANARY_TOP_SITE },
    },
    subFrameSender(CANARY_FRAME_SITE),
  );
  assert.equal(worker.calls.length, 1);
  assert.equal(worker.calls[0].page.frame_origin, CANARY_FRAME_SITE);
});

test("a top-frame sender always reports frame_origin null, whatever it claims", async () => {
  const worker = loadServiceWorker();
  await worker.dispatch(
    { kind: "match", page: { top_origin: CANARY_TOP_SITE, frame_origin: CANARY_FRAME_SITE } },
    topFrameSender(CANARY_TOP_SITE),
  );
  assert.equal(worker.calls[0].page.frame_origin, null);
  assert.equal(worker.calls[0].page.top_origin, CANARY_TOP_SITE);
});

test("an unparseable claimed top origin falls back to the browser-stamped frame origin", async () => {
  const worker = loadServiceWorker();
  await worker.dispatch(
    { kind: "match", page: { top_origin: "not a url", frame_origin: null } },
    subFrameSender(CANARY_FRAME_SITE),
  );
  assert.equal(worker.calls[0].page.top_origin, CANARY_FRAME_SITE);
  assert.equal(worker.calls[0].page.frame_origin, CANARY_FRAME_SITE);
});

test("a sender with no usable origin is refused before the app is asked", async () => {
  const worker = loadServiceWorker();
  const response = await worker.dispatch(
    { kind: "match", page: { top_origin: CANARY_TOP_SITE, frame_origin: null } },
    { origin: "about:blank", url: "about:blank", frameId: 4, tab: { id: 11 } },
  );
  assert.equal(response.ok, false);
  assert.equal(response.code, "PROTOCOL");
  assert.equal(worker.calls.length, 0);
});

test(
  "a cross-origin sub-frame cannot make a fill look like a top-frame fill",
  async () => {
    const worker = loadServiceWorker();
    // A content script inside a cross-origin frame on CANARY_TOP_SITE, with the page's own
    // JavaScript in control of what it says. It tells the truth about nothing it does not have to.
    await worker.dispatch(
      {
        kind: "fill",
        itemId: CANARY_ITEM_ID,
        fields: ["username", "password"],
        page: { top_origin: CANARY_FRAME_SITE, frame_origin: CANARY_FRAME_SITE },
      },
      subFrameSender(CANARY_FRAME_SITE),
    );

    const page = worker.calls[0].page;
    assert.equal(page.frame_origin, CANARY_FRAME_SITE, "the frame origin is the trusted one");
    // The app decides whether to show "this form is inside a frame on X" by comparing the two.
    // For a genuine third-party frame they must differ, or the human is shown a sheet that is
    // indistinguishable from a fill into the page they are looking at.
    assert.notEqual(
      page.top_origin,
      page.frame_origin,
      "a sub-frame fill reached the app with top_origin == frame_origin, so the approval sheet " +
        "will not disclose that the form is inside a third-party frame",
    );
  },
);
