/**
 * B-30, B-31, B-32: what page script can do to the content script from inside the same document.
 *
 * A content script runs in an isolated world but shares a DOM with the page. Everything the page
 * can reach through that DOM is in scope here:
 *
 * * **B-30 — synthetic gestures.** The only two ways to start a fill are a click on the icon and
 *   `⌘\`. Both are DOM events, and page script can dispatch both. `event.isTrusted` is the only
 *   thing that tells them apart, and it is the gate this file drives: a synthetic `click` on the
 *   overlay host and a synthetic `⌘\` `keydown` must leave no `fill` on the wire.
 * * **B-31 — the overlay.** A *closed* shadow root, so `host.shadowRoot` is `null` from page
 *   script and the icon cannot be queried, restyled into invisibility, or clicked at.
 * * **B-32 — the value after the write.** `applyFill` takes the reply as a parameter and lets it
 *   go out of scope. Nothing longer-lived may still be holding the password.
 *
 * The real `content.js` is executed in a `vm` context over a `linkedom` document, with `chrome`
 * and `KsForms`/`KsOrigin` supplied the way a content script receives them. `linkedom` is not a
 * rendering engine, so geometry is stubbed per element — the geometry rule has its own tests in
 * `forms.test.js`. Synthetic events built in this harness have `isTrusted === false`, which is
 * exactly what a browser reports for an event page script dispatched.
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

/** The value the fake app hands back. Obvious test data if it ever shows up somewhere it should not. */
const CANARY_PASSWORD = "canary-password-DO-NOT-SHIP-7f3a";
const CANARY_USERNAME = "canary-user@example.test";
const CANARY_ITEM_ID = "item-canary-0000";
const PAGE_URL = "https://example.com/login";

const LOGIN_FORM = `
  <form id="signin">
    <label for="u">Email</label><input id="u" name="username" type="text">
    <label for="p">Password</label><input id="p" name="password" type="password">
    <button type="submit">Sign in</button>
  </form>
`;

/**
 * What the fake app answers. Metadata for a `match`, a value only for a `fill` — the same split
 * the real service worker enforces.
 *
 * @param {{ kind: string }} message
 */
function replyTo(message) {
  switch (message.kind) {
    case "match":
      return {
        ok: true,
        reply: {
          reply: "matches",
          origin: "https://example.com",
          items: [
            {
              item_id: CANARY_ITEM_ID,
              title: "Example",
              username: CANARY_USERNAME,
              has_totp: false,
            },
          ],
        },
      };
    case "recall":
      return { ok: true, itemId: null };
    case "fill":
      return {
        ok: true,
        reply: { reply: "filled", username: CANARY_USERNAME, password: CANARY_PASSWORD },
      };
    default:
      return { ok: true, reply: { reply: "ok" } };
  }
}

/**
 * Run `content.js` over `html` with a recording `chrome.runtime`.
 *
 * @param {string} html
 * @returns {Promise<object>} the harness
 */
async function runContentScript(html = LOGIN_FORM) {
  const parsed = parseHTML(`<!doctype html><html><body>${html}</body></html>`);
  const { document } = parsed;
  const global = parsed.window;

  const rect = () => ({ width: 220, height: 32, top: 40, left: 10, right: 230, bottom: 72 });
  const stubGeometry = () => {
    for (const el of document.querySelectorAll("*")) {
      if (!el.__ksStubbed) {
        el.getBoundingClientRect = rect;
        el.__ksStubbed = true;
        Object.defineProperty(el, "offsetParent", { value: document.body, configurable: true });
      }
    }
  };
  stubGeometry();
  const geometryTimer = setInterval(stubGeometry, 5);

  const sent = [];
  global.chrome = {
    runtime: {
      id: "nlijibjnmanccalmafnfbobkcfjiibmd",
      onMessage: { addListener: () => {} },
      // `content.js` calls the callback form, which is what Chrome gives a content script.
      lastError: undefined,
      sendMessage: (message, callback) => {
        sent.push(message);
        callback(replyTo(message));
      },
    },
  };
  global.KsForms = require(path.join(SHARED, "forms.js"));
  global.KsOrigin = require(path.join(SHARED, "origin.js"));
  global.console = console;
  global.setTimeout = setTimeout;
  global.clearTimeout = clearTimeout;
  global.scrollX = 0;
  global.scrollY = 0;
  Object.defineProperty(global, "location", {
    value: { href: PAGE_URL, ancestorOrigins: null },
    configurable: true,
  });
  global.top = global;
  global.globalThis = global;
  global.self = global;
  // `linkedom` has no MouseEvent / KeyboardEvent, and leaves `isTrusted` undefined rather than
  // false. These shims restore what a browser reports for an event page script constructed:
  // `isTrusted === false`, which only the browser itself can set to true.
  global.MouseEvent = class MouseEvent extends parsed.Event {
    constructor(type, init = {}) {
      super(type, init);
      Object.defineProperty(this, "isTrusted", { value: false, configurable: true });
    }
  };
  global.KeyboardEvent = class KeyboardEvent extends parsed.Event {
    constructor(type, init = {}) {
      super(type, init);
      Object.assign(this, init);
      Object.defineProperty(this, "isTrusted", { value: false, configurable: true });
    }
  };

  vm.createContext(global);
  vm.runInContext(CONTENT_SOURCE, global, { filename: "content.js" });

  // `content.js` debounces its first scan by 250ms and then awaits a `match`.
  await new Promise((resolve) => setTimeout(resolve, 450));

  return {
    document,
    global,
    parsed,
    sent,
    stop: () => clearInterval(geometryTimer),
    /** The overlay host element, as page script would have to find it: by walking the DOM. */
    overlayHost: () =>
      Array.from(document.documentElement.children).find((el) =>
        el.tagName.toLowerCase().startsWith("ks-"),
      ) || null,
    kinds: () => sent.map((m) => m.kind),
  };
}

test("the automatic scan asks only for metadata, never for a value", async () => {
  const harness = await runContentScript();
  try {
    assert.deepEqual(harness.kinds(), ["match"]);
    assert.equal(harness.sent[0].itemId, undefined);
  } finally {
    harness.stop();
  }
});

test("B-31: the overlay host exposes no shadow root to page script", async () => {
  const harness = await runContentScript();
  try {
    const host = harness.overlayHost();
    assert.ok(host, "the overlay was never created");
    // A closed root: this is what `document.querySelector('ks-…').shadowRoot` returns in a page.
    assert.equal(host.shadowRoot, null);
    // And the tag name is unguessable, so a stylesheet cannot target it by name either.
    assert.match(host.tagName.toLowerCase(), /^ks-[a-z0-9]{6,}$/);
    // The icon is not reachable through an ordinary document query.
    assert.equal(harness.document.querySelector("button[aria-label]"), null);
  } finally {
    harness.stop();
  }
});

test("B-30: a synthetic click on the overlay host starts no fill", async () => {
  const harness = await runContentScript();
  try {
    const host = harness.overlayHost();
    assert.ok(host);
    const before = harness.sent.length;
    host.dispatchEvent(new harness.global.MouseEvent("click", { bubbles: true }));
    // And the same click aimed at the icon inside the closed root, which page script cannot
    // actually reach — done here through the internal handle, to prove the gate and not the
    // unreachability.
    const button = host.__ksButton;
    assert.ok(button, "the icon button was not built");
    const synthetic = new harness.global.MouseEvent("click", { bubbles: true });
    assert.equal(synthetic.isTrusted, false, "the harness must produce untrusted events");
    button.dispatchEvent(synthetic);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(harness.sent.length, before, `extra traffic: ${JSON.stringify(harness.kinds())}`);
    assert.equal(harness.kinds().includes("fill"), false);
  } finally {
    harness.stop();
  }
});

test("B-30: a synthetic command-backslash keydown starts no fill", async () => {
  const harness = await runContentScript();
  try {
    const before = harness.sent.length;
    for (const init of [
      { key: "\\", metaKey: true, bubbles: true },
      { key: "\\", ctrlKey: true, bubbles: true },
    ]) {
      const event = new harness.global.KeyboardEvent("keydown", init);
      assert.equal(event.isTrusted, false);
      harness.global.dispatchEvent(event);
      harness.document.dispatchEvent(new harness.global.KeyboardEvent("keydown", init));
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(harness.sent.length, before, `extra traffic: ${JSON.stringify(harness.kinds())}`);
    assert.equal(harness.kinds().includes("fill"), false);
  } finally {
    harness.stop();
  }
});

test("B-30: a synthetic focusin and a synthetic submit start no fill either", async () => {
  const harness = await runContentScript();
  try {
    const before = harness.sent.length;
    const password = harness.document.getElementById("p");
    password.dispatchEvent(new harness.parsed.Event("focusin", { bubbles: true }));
    password.dispatchEvent(new harness.parsed.Event("focus", { bubbles: true }));
    harness.document
      .getElementById("signin")
      .dispatchEvent(new harness.parsed.Event("submit", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(harness.sent.length, before);
    assert.equal(password.value, "", "a value appeared in the field without a real gesture");
  } finally {
    harness.stop();
  }
});

test("B-32: after a fill the content script holds no reference to the password", async () => {
  const harness = await runContentScript();
  try {
    const host = harness.overlayHost();
    // Drive the fill the way a real click would, past the `isTrusted` gate — which is what makes
    // this a test about the *value* rather than about the gate.
    const trusted = new harness.global.MouseEvent("click", { bubbles: true });
    Object.defineProperty(trusted, "isTrusted", { value: true });
    host.__ksButton.dispatchEvent(trusted);
    await new Promise((resolve) => setTimeout(resolve, 100));

    assert.equal(harness.kinds().includes("fill"), true, "the trusted click did not fill");
    const password = harness.document.getElementById("p");
    assert.equal(password.value, CANARY_PASSWORD, "the fill did not reach the field");

    // The field itself legitimately holds the value — see W-7 below. Nothing *else* may.
    const leaks = [];
    for (const key of Object.getOwnPropertyNames(harness.global)) {
      let value;
      try {
        value = harness.global[key];
      } catch {
        continue;
      }
      if (typeof value === "string" && value.includes(CANARY_PASSWORD)) leaks.push(key);
    }
    assert.deepEqual(leaks, [], "the password is reachable as a global in the content script world");

    // The overlay's own internal handles must not be carrying it around either.
    assert.equal(JSON.stringify(host.__ksRoot.innerHTML || "").includes(CANARY_PASSWORD), false);
    assert.equal((host.outerHTML || "").includes(CANARY_PASSWORD), false);
  } finally {
    harness.stop();
  }
});

test("W-7 (accepted risk): the page can read the filled value out of its own field", async () => {
  // This documents current, *intended* behaviour rather than asserting a defect away. A fill
  // writes into the page's own input, and an input's `value` is readable by the page's JavaScript
  // by definition — there is no DOM in which it is not. The mitigation is that the fill happens
  // only after a real gesture and only on an origin the app matched, not that the value is hidden
  // from a page the user just told the app to fill. If this test ever *fails*, something has
  // changed about where fills are written, and that change deserves a look.
  const harness = await runContentScript();
  try {
    const host = harness.overlayHost();
    const trusted = new harness.global.MouseEvent("click", { bubbles: true });
    Object.defineProperty(trusted, "isTrusted", { value: true });
    host.__ksButton.dispatchEvent(trusted);
    await new Promise((resolve) => setTimeout(resolve, 100));
    const asThePageWouldReadIt = harness.document.querySelector("input[type=password]").value;
    assert.equal(asThePageWouldReadIt, CANARY_PASSWORD);
  } finally {
    harness.stop();
  }
});

test("positive control: a trusted command-backslash does fill, so the gate is what stopped it", async () => {
  // Without this, the two B-30 tests above could be passing because the harness never wires the
  // shortcut up at all rather than because `isTrusted` refused it.
  const harness = await runContentScript();
  try {
    const event = new harness.global.KeyboardEvent("keydown", { key: "\\", metaKey: true });
    Object.defineProperty(event, "isTrusted", { value: true });
    harness.global.dispatchEvent(event);
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(harness.kinds().includes("fill"), true, "a real shortcut did not reach the app");
    assert.equal(harness.document.getElementById("p").value, CANARY_PASSWORD);
  } finally {
    harness.stop();
  }
});
