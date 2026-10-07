/**
 * B-33: is the field that gets written the field the user was shown an icon next to?
 *
 * A fill is two separate moments. Detection picks a field and draws an icon beside it; some time
 * later — after a click, after an approval sheet the human may sit on for seconds — a value is
 * written. Everything in between belongs to the page, which can retype the input, move it, swap it
 * for a decoy, or install a `MutationObserver` that does any of those at the moment of the write.
 *
 * So this file drives two things:
 *
 * 1. A corpus of adversarial form shapes through `KsForms.detectLoginForm` /
 *    `detectIdentifierForm`, asserting that decoys, hidden and zero-size fields, `readonly` and
 *    `disabled` fields, registration forms, shadow-DOM hosts and nested frames each resolve the
 *    way the design says they should — or are refused outright, which is the safe answer.
 * 2. The **write** itself, through the real `content.js`, with the page mutating the field between
 *    the click and the reply. That is the part detection cannot cover, because by then detection
 *    has already happened.
 *
 * Geometry is stubbed per element, exactly as in `forms.test.js`: `linkedom` is not a rendering
 * engine, so `getBoundingClientRect` would otherwise be all zeros and every field would look
 * invisible. The rectangles below are therefore the *claim being tested*, not an artifact.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseHTML } = require("linkedom");

const SHARED = path.join(__dirname, "..", "..", "shared");
const KsForms = require(path.join(SHARED, "forms.js"));
const CONTENT_SOURCE = fs.readFileSync(path.join(SHARED, "content.js"), "utf8");

const CANARY_PASSWORD = "canary-password-DO-NOT-SHIP-7f3a";
const CANARY_USERNAME = "canary-user@example.test";
const CANARY_ITEM_ID = "item-canary-0000";

/** The `id` of an element, or `null`. Never compare `linkedom` nodes directly: see `forms.test.js`. */
function nameOf(el) {
  return el ? el.id || (el.getAttribute && el.getAttribute("name")) || "<unnamed>" : null;
}

const VISIBLE = { width: 220, height: 32, top: 40, left: 10, right: 230, bottom: 72 };
const INVISIBLE = { width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 };
const TINY = { width: 1, height: 1, top: 0, left: 0, right: 1, bottom: 1 };
const OFFSCREEN = { width: 220, height: 32, top: -9999, left: -9999, right: -9779, bottom: -9967 };

/**
 * Parse `html` and give each element a rectangle. An element carrying `data-rect` picks a named
 * rectangle; everything else is plainly visible.
 *
 * @param {string} html
 */
function dom(html) {
  const parsed = parseHTML(`<!doctype html><html><body>${html}</body></html>`);
  const { document } = parsed;
  const named = { visible: VISIBLE, invisible: INVISIBLE, tiny: TINY, offscreen: OFFSCREEN };
  for (const el of document.querySelectorAll("*")) {
    const rect = named[el.getAttribute("data-rect") || "visible"] || VISIBLE;
    el.getBoundingClientRect = () => rect;
    Object.defineProperty(el, "offsetParent", {
      value: rect.width === 0 ? null : document.body,
      configurable: true,
    });
  }
  parsed.window.CSS = { escape: (s) => String(s).replace(/[^\w-]/g, (c) => `\\${c}`) };
  if (!globalThis.CSS) globalThis.CSS = parsed.window.CSS;
  return parsed;
}

/** The detected password field's name, or `null`. */
function detectedPassword(document) {
  const found = KsForms.detectLoginForm(document);
  return found ? nameOf(found.password) : null;
}

// ---------------------------------------------------------------------------------------------
// Detection: the adversarial corpus
// ---------------------------------------------------------------------------------------------

test("a zero-size decoy password field is never the one detected", () => {
  const { document } = dom(`
    <form>
      <input id="decoy" type="password" data-rect="invisible" autocomplete="current-password">
      <input id="user" name="username" type="text">
      <input id="real" type="password">
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(detectedPassword(document), "real");
});

test("a one-pixel decoy password field is never the one detected", () => {
  const { document } = dom(`
    <form>
      <input id="decoy" type="password" data-rect="tiny">
      <input id="user" name="username" type="text">
      <input id="real" type="password">
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(detectedPassword(document), "real");
});

test("a hidden password field is never the one detected", () => {
  const { document } = dom(`
    <form>
      <input id="decoy" type="hidden" name="password">
      <input id="user" name="username" type="text">
      <input id="real" type="password">
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(detectedPassword(document), "real");
});

test("readonly and disabled password fields are never the one detected", () => {
  for (const attribute of ["readonly", "disabled"]) {
    const { document } = dom(`
      <form>
        <input id="decoy" type="password" ${attribute}>
        <input id="user" name="username" type="text">
        <input id="real" type="password">
        <button type="submit">Sign in</button>
      </form>
    `);
    assert.equal(detectedPassword(document), "real", attribute);
  }
});

test("a form whose only password field is readonly or disabled is refused outright", () => {
  for (const attribute of ["readonly", "disabled"]) {
    const { document } = dom(`
      <form>
        <input id="user" name="username" type="text">
        <input id="only" type="password" ${attribute}>
        <button type="submit">Sign in</button>
      </form>
    `);
    // Refusing is the safe answer: there is nothing here a fill could land in.
    assert.equal(detectedPassword(document), null, attribute);
  }
});

test("a registration form with two password boxes is not treated as a sign-in", () => {
  const { document } = dom(`
    <form>
      <input id="user" name="username" type="text">
      <label for="p1">Choose a password</label><input id="p1" type="password" autocomplete="new-password">
      <label for="p2">Confirm password</label><input id="p2" type="password" autocomplete="new-password">
      <button type="submit">Create account</button>
    </form>
  `);
  assert.equal(detectedPassword(document), null);
});

test("a change-password form is not treated as a sign-in", () => {
  const { document } = dom(`
    <form>
      <label for="old">Current password</label><input id="old" type="password" autocomplete="current-password">
      <label for="n1">New password</label><input id="n1" type="password" autocomplete="new-password">
      <label for="n2">Repeat new password</label><input id="n2" type="password" autocomplete="new-password">
      <button type="submit">Change password</button>
    </form>
  `);
  const found = detectedPassword(document);
  assert.notEqual(found, "n1", "a login fill never lands in a new-password box");
  assert.notEqual(found, "n2", "a fill must never land in a confirm-password box");
});

test("a password field inside a nested same-origin iframe is invisible to the outer document", () => {
  // Content scripts run in every frame (`all_frames: true`), so the inner document gets its own
  // copy of this code and answers for itself. The outer document must not reach across into it,
  // or the icon would be drawn in the wrong document and `⌘\` would target a field the user is
  // not looking at.
  const { document } = dom(`
    <iframe id="inner"></iframe>
    <p>Nothing fillable out here.</p>
  `);
  const frame = document.getElementById("inner");
  const innerDoc = parseHTML(
    `<!doctype html><html><body><form><input id="iu" name="username"><input id="ip" type="password"><button>Sign in</button></form></body></html>`,
  ).document;
  frame.contentDocument = innerDoc;
  assert.equal(detectedPassword(document), null);
});

test("a shadow-DOM-hosted password field is not detected, which is the safe direction", () => {
  // `querySelectorAll` does not pierce a shadow root, so a component that keeps its login form in
  // one is simply not offered a fill. That is a gap in *coverage*, deliberately chosen over the
  // alternative of walking every open root on every mutation — and it can only produce a missing
  // icon, never a fill into the wrong field. If this ever starts returning a field, the new
  // traversal needs its own adversarial pass.
  const { document } = dom(`<div id="host"></div>`);
  const host = document.getElementById("host");
  const root = host.attachShadow({ mode: "open" });
  root.innerHTML =
    `<form><input id="su" name="username"><input id="sp" type="password"><button>Sign in</button></form>`;
  for (const el of root.querySelectorAll("*")) {
    el.getBoundingClientRect = () => VISIBLE;
    Object.defineProperty(el, "offsetParent", { value: document.body, configurable: true });
  }
  assert.equal(detectedPassword(document), null);
  assert.equal(KsForms.detectIdentifierForm(document), null);
});

test(
  "an off-screen password field does not attract the fill away from the visible one",
  () => {
    const { document } = dom(`
      <form>
        <input id="decoy" type="password" data-rect="offscreen">
        <input id="user" name="username" type="text">
        <input id="real" type="password">
        <button type="submit">Sign in</button>
      </form>
    `);
    assert.equal(detectedPassword(document), "real");
  },
);

test(
  "a decoy that merely declares autocomplete=current-password does not win the fill",
  () => {
    const { document } = dom(`
      <form>
        <input id="user" name="username" type="text">
        <label for="real">Password</label><input id="real" type="password">
        <button type="submit">Sign in</button>
      </form>
      <div><input id="decoy" type="password" autocomplete="current-password"></div>
    `);
    assert.equal(detectedPassword(document), "real");
  },
);

test("a search box is never mistaken for an identifier field", () => {
  const { document } = dom(`
    <form role="search"><input id="q" type="search" name="q" placeholder="Search"><button>Go</button></form>
  `);
  assert.equal(KsForms.detectIdentifierForm(document), null);
});

test("setFieldValue refuses nothing, so the caller is the only place a type check can live", () => {
  // Stated as a test because it is the premise of the race below: `setFieldValue` writes into
  // whatever element it is handed. It does not look at `type`, `readonly` or `disabled`.
  const { document } = dom(`<input id="t" type="text">`);
  const field = document.getElementById("t");
  assert.equal(KsForms.setFieldValue(field, CANARY_PASSWORD), true);
  assert.equal(field.value, CANARY_PASSWORD);
});

// ---------------------------------------------------------------------------------------------
// The write: what the page can change between the click and the reply
// ---------------------------------------------------------------------------------------------

/**
 * Run `content.js` over `html`, with `duringApproval` invoked while the `fill` request is in
 * flight — the window in which the human is looking at the approval sheet and the page is free.
 *
 * @param {string} html
 * @param {(document: Document) => void} duringApproval
 */
async function fillUnderMutation(html, duringApproval, reply) {
  const parsed = parseHTML(`<!doctype html><html><body>${html}</body></html>`);
  const { document } = parsed;
  const global = parsed.window;

  const stubGeometry = () => {
    for (const el of document.querySelectorAll("*")) {
      if (el.__ksStubbed) continue;
      el.__ksStubbed = true;
      el.getBoundingClientRect = () => VISIBLE;
      Object.defineProperty(el, "offsetParent", { value: document.body, configurable: true });
    }
  };
  stubGeometry();
  const timer = setInterval(stubGeometry, 5);

  const sent = [];
  global.chrome = {
    runtime: {
      id: "nlijibjnmanccalmafnfbobkcfjiibmd",
      lastError: undefined,
      onMessage: { addListener: () => {} },
      sendMessage: (message, callback) => {
        sent.push(message);
        if (message.kind === "match") {
          callback({
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
          });
          return;
        }
        if (message.kind === "recall") {
          callback({ ok: true, itemId: null });
          return;
        }
        if (message.kind === "fill") {
          // The approval sheet is up. The page gets its turn.
          duringApproval(document);
          setTimeout(
            () =>
              callback({
                ok: true,
                reply: reply || {
                  reply: "filled",
                  username: CANARY_USERNAME,
                  password: CANARY_PASSWORD,
                },
              }),
            20,
          );
          return;
        }
        callback({ ok: true, reply: { reply: "ok" } });
      },
    },
  };
  global.KsForms = KsForms;
  global.KsOrigin = require(path.join(SHARED, "origin.js"));
  global.console = console;
  global.setTimeout = setTimeout;
  global.clearTimeout = clearTimeout;
  global.scrollX = 0;
  global.scrollY = 0;
  Object.defineProperty(global, "location", {
    value: { href: "https://example.com/login", ancestorOrigins: null },
    configurable: true,
  });
  global.top = global;
  global.globalThis = global;
  global.self = global;
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
  await new Promise((resolve) => setTimeout(resolve, 450));

  const event = new global.KeyboardEvent("keydown", { key: "\\", metaKey: true });
  Object.defineProperty(event, "isTrusted", { value: true });
  global.dispatchEvent(event);
  await new Promise((resolve) => setTimeout(resolve, 250));

  clearInterval(timer);
  return { document, sent, kinds: sent.map((m) => m.kind) };
}

const RACE_FORM = `
  <form id="signin">
    <label for="u">Email</label><input id="u" name="username" type="text">
    <label for="p">Password</label><input id="p" name="password" type="password">
    <button type="submit">Sign in</button>
  </form>
`;

test("a fill into an untouched form still lands in the password field", async () => {
  // The control for the two races below.
  const run = await fillUnderMutation(RACE_FORM, () => {});
  assert.equal(run.kinds.includes("fill"), true);
  assert.equal(run.document.getElementById("p").value, CANARY_PASSWORD);
});

test(
  "the field is re-checked as a password field immediately before the value is written",
  async () => {
    const run = await fillUnderMutation(RACE_FORM, (document) => {
      // The page's own script, during the approval. No privilege needed: it owns this element.
      document.getElementById("p").setAttribute("type", "text");
      document.getElementById("p").type = "text";
    });
    assert.equal(run.kinds.includes("fill"), true, "no fill was requested");
    assert.equal(
      run.document.getElementById("p").value,
      "",
      "the value was written into a field that is no longer a password field",
    );
  },
);

test(
  "the field is re-checked as fillable immediately before the value is written",
  async () => {
    const run = await fillUnderMutation(RACE_FORM, (document) => {
      const field = document.getElementById("p");
      field.setAttribute("readonly", "");
      field.getBoundingClientRect = () => INVISIBLE;
    });
    assert.equal(run.kinds.includes("fill"), true, "no fill was requested");
    assert.equal(
      run.document.getElementById("p").value,
      "",
      "the value was written into a field that is no longer fillable",
    );
  },
);

test("a page that swaps in a second password field during the approval does not redirect the fill", async () => {
  // The rescan is debounced by 250ms, so a swap performed during a short approval does not
  // re-point `form` before the write. This asserts the behaviour that actually holds: the value
  // lands in the originally detected field, not in whatever the page injected afterwards.
  const run = await fillUnderMutation(RACE_FORM, (document) => {
    const injected = document.createElement("input");
    injected.id = "injected";
    injected.type = "password";
    document.getElementById("signin").prepend(injected);
  });
  assert.equal(run.document.getElementById("p").value, CANARY_PASSWORD);
  assert.equal(run.document.getElementById("injected").value, "");
});

// ---------------------------------------------------------------------------------------------
// Sign-up fills (ADR-0048 §7): only into new-password boxes, and never from a `password` member
// ---------------------------------------------------------------------------------------------

test("a sign-up fill lands only in new-password boxes", () => {
  // Every shape where a sign-up target could include a box that is not a new password: the
  // detector either names exactly the new-password boxes or refuses the page.
  const shapes = [
    `<form><input id="u" type="text"><input id="cur" type="password" autocomplete="current-password">
       <input id="n1" type="password" autocomplete="new-password"></form>`,
    `<form><input id="a" type="password" autocomplete="new-password"><input id="b" type="password">
       <input id="c" type="password"></form>`,
    `<form id="f1"><input id="u" type="text"><input id="p" type="password"></form>
     <form id="f2"><input id="n1" type="password" autocomplete="new-password"></form>`,
    `<form><input id="n1" type="password" autocomplete="new-password">
       <input id="n2" type="password" autocomplete="new-password" data-rect="offscreen"></form>`,
    `<form><input id="n1" type="password" autocomplete="new-password">
       <input id="n2" type="password" autocomplete="new-password" data-rect="invisible"></form>`,
    `<form><input id="n1" type="password" autocomplete="new-password"></form>
     <form><input id="n2" type="password" autocomplete="new-password"></form>`,
  ];
  for (const html of shapes) {
    const { document } = dom(html);
    assert.equal(KsForms.detectSignupForm(document), null, html);
  }
  const { document } = dom(`
    <form>
      <input id="user" type="text" autocomplete="username">
      <input id="p1" type="password" autocomplete="new-password">
      <input id="p2" type="password" autocomplete="new-password">
    </form>
  `);
  const found = KsForms.detectSignupForm(document);
  assert.deepEqual(found.passwords.map(nameOf), ["p1", "p2"]);
  assert.equal(nameOf(found.username), "user");
  // And the login detector never takes the same page.
  assert.equal(detectedPassword(document), null);
});

test("a new_password reply on a login form writes nothing", async () => {
  // The human path never asks for a new password; a reply that carries one anyway, onto a login
  // form, is written nowhere — not into the password box, not into the username box.
  const run = await fillUnderMutation(RACE_FORM, () => {}, {
    reply: "filled",
    username: CANARY_USERNAME,
    new_password: CANARY_PASSWORD,
  });
  assert.equal(run.kinds.includes("fill"), true);
  assert.equal(run.document.getElementById("p").value, "");
  assert.equal(run.document.getElementById("u").value, "");
});
