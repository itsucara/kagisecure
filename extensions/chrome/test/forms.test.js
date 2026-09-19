/**
 * Form detection, against real DOM shapes.
 *
 * Uses `linkedom` for a DOM without a browser. It is not a rendering engine, so
 * `getBoundingClientRect` returns zeros for everything — which would make `isFillable` reject
 * every field. The helper below stubs geometry per element, which is honest: the geometry check is
 * about *visibility*, and a headless DOM has no such concept to be right or wrong about. The
 * geometry rule itself gets its own test with explicit rectangles.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseHTML } = require("linkedom");

const KsForms = require("../../shared/forms.js");

/**
 * The `id` (or `name`) of an element, or `null`.
 *
 * Every assertion below goes through this rather than comparing elements directly. A failed
 * `assert.equal(node, null)` asks Node to render the node into the diff, and rendering a
 * `linkedom` element walks a cyclic object graph until the runner is killed — so a single wrong
 * expectation would produce an eighty-second SIGKILL with no message instead of a one-line
 * failure. Comparing strings keeps a failure readable.
 *
 * @param {Element | null} el
 * @returns {string | null}
 */
function nameOf(el) {
  if (!el) return null;
  return el.id || (el.getAttribute && el.getAttribute("name")) || "<unnamed>";
}

/**
 * The detected password field's name, or `null` when nothing was detected.
 *
 * Same reasoning as [`nameOf`]: a `detectLoginForm` result holds two DOM nodes, and comparing the
 * whole object against `null` would put those nodes in the diff.
 *
 * @param {{ password: Element, username: Element | null } | null} found
 * @returns {string | null}
 */
function detected(found) {
  return found ? nameOf(found.password) : null;
}

/**
 * Parse `html` and give every element a plausible on-screen rectangle.
 *
 * @param {string} html
 * @param {(el: Element) => {width: number, height: number} | null} [geometry]
 */
function dom(html, geometry) {
  const { document, CSS } = parseHTML(
    `<!doctype html><html><body>${html}</body></html>`,
  );
  // `forms.js` calls `CSS.escape` when building a `label[for=…]` selector, and reads it as a
  // global exactly as a content script would. Nothing else is installed onto `globalThis`:
  // shadowing Node's own globals from a test would be a way to make the tests pass against a
  // world the extension never runs in.
  globalThis.CSS = CSS || { escape: (s) => s.replace(/["\\]/g, "\\$&") };

  for (const el of document.querySelectorAll("*")) {
    const size = geometry ? geometry(el) : { width: 200, height: 30 };
    Object.defineProperty(el, "getBoundingClientRect", {
      value: () => ({
        width: size ? size.width : 0,
        height: size ? size.height : 0,
        top: 10,
        left: 10,
        right: 10 + (size ? size.width : 0),
        bottom: 10 + (size ? size.height : 0),
      }),
      configurable: true,
    });
    Object.defineProperty(el, "offsetParent", { value: document.body, configurable: true });
  }
  return document;
}

// ---------------------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------------------

test("a plain login form is detected", () => {
  const document = dom(`
    <form>
      <input name="username" type="text" />
      <input name="password" type="password" />
      <button type="submit">Sign in</button>
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.ok(found, "a form with a username and a password is a login form");
  assert.equal(nameOf(found.password), "password");
  assert.equal(nameOf(found.username), "username");
});

test("autocomplete beats every other signal", () => {
  // The username field here is named `q`, which the keyword scan scores *negatively*. The site
  // said what it is, so the site wins.
  const document = dom(`
    <form>
      <input name="q" autocomplete="username" type="text" />
      <input name="pw" autocomplete="current-password" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.equal(nameOf(found.username), "q");
  assert.equal(nameOf(found.password), "pw");
});

test("an email field is accepted as the username", () => {
  const document = dom(`
    <form>
      <input id="email" type="email" />
      <input id="pass" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.equal(nameOf(found.username), "email");
});

test("a label names a field that has no name or placeholder", () => {
  const document = dom(`
    <form>
      <label for="a">Email address</label><input id="a" type="text" />
      <input id="b" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.equal(nameOf(found.username), "a");
});

test("a wrapping label counts too", () => {
  const document = dom(`
    <form>
      <label>Username <input id="a" type="text" /></label>
      <input id="b" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.equal(nameOf(found.username), "a");
});

test("an aria-label counts, because plenty of sites label only for assistive technology", () => {
  const document = dom(`
    <form>
      <input id="a" type="text" aria-label="Account name" />
      <input id="b" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.equal(nameOf(found.username), "a");
});

// ---------------------------------------------------------------------------------------
// The refusals — the half that matters
// ---------------------------------------------------------------------------------------

test("a page with no password field is not a login form", () => {
  const document = dom(`<form><input name="search" type="text" /></form>`);
  assert.equal(detected(KsForms.detectLoginForm(document)), null);
});

test("a registration form is refused, because new-password is a disqualifier", () => {
  const document = dom(`
    <form>
      <input name="email" type="email" />
      <input name="password" type="password" autocomplete="new-password" />
    </form>
  `);
  assert.equal(
    detected(KsForms.detectLoginForm(document)),
    null,
    "filling the current password into a sign-up form is useless at best",
  );
});

test("a change-password form is refused, because two password fields mean a new one", () => {
  const document = dom(`
    <form>
      <input name="new" type="password" />
      <input name="confirm" type="password" />
    </form>
  `);
  assert.equal(
    detected(KsForms.detectLoginForm(document)),
    null,
    "overwriting a 'confirm new password' box with the old password is actively harmful",
  );
});

test("two password fields in different forms are still two separate login boxes", () => {
  const document = dom(`
    <form id="header">
      <input name="header_username" type="text" />
      <input name="header_password" type="password" />
    </form>
    <form id="body">
      <input name="body_username" type="text" />
      <input name="body_password" type="password" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.ok(found, "two login boxes are still login boxes, not a change-password form");
  assert.equal(nameOf(found.password), "header_password", "first in document order wins");
  assert.equal(
    nameOf(found.username),
    "header_username",
    "and its own form's username comes with it, not the other form's",
  );
});

test("a hidden password field is not fillable", () => {
  const document = dom(
    `<form><input id="u" type="text" /><input id="p" type="password" /></form>`,
    (el) => (el.id === "p" ? { width: 0, height: 0 } : { width: 200, height: 30 }),
  );
  assert.equal(
    detected(KsForms.detectLoginForm(document)),
    null,
    "a zero-sized password field is a honeypot or an off-screen form, not a login box",
  );
});

test("a one-by-one honeypot field is not fillable", () => {
  const document = dom(
    `<form><input id="u" type="text" /><input id="p" type="password" /></form>`,
    (el) => (el.id === "p" ? { width: 1, height: 1 } : { width: 200, height: 30 }),
  );
  assert.equal(detected(KsForms.detectLoginForm(document)), null);
});

test("a disabled or readonly field is not fillable", () => {
  const disabled = dom(`<form><input id="p" type="password" disabled /></form>`);
  assert.equal(detected(KsForms.detectLoginForm(disabled)), null);

  const readonly = dom(`<form><input id="p" type="password" readonly /></form>`);
  assert.equal(detected(KsForms.detectLoginForm(readonly)), null);
});

test("a search box next to a password field is not adopted as the username", () => {
  const document = dom(`
    <input name="search" type="text" placeholder="Search the site" />
    <form><input name="password" type="password" /></form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.ok(found, "the password field is still a login field");
  assert.equal(
    nameOf(found.username),
    null,
    "a search box scores negatively and must not be filled with a username",
  );
});

test("with no candidate before the password and no keywords, no username is guessed", () => {
  const document = dom(`
    <form>
      <input name="password" type="password" />
      <input name="captcha" type="text" />
    </form>
  `);
  const found = KsForms.detectLoginForm(document);
  assert.ok(found);
  assert.equal(
    nameOf(found.username),
    null,
    "a captcha box after the password is not a username",
  );
});

// ---------------------------------------------------------------------------------------
// Identifier-first: the page that has a username box and no password box
// ---------------------------------------------------------------------------------------

/** The detected identifier field's name, or `null`. */
function identified(found) {
  return found ? nameOf(found.username) : null;
}

test("an email box with a Next button is an identifier-first form", () => {
  const document = dom(`
    <form>
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username" />
      <button type="submit">Next</button>
    </form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "email");
  assert.equal(
    detected(KsForms.detectLoginForm(document)),
    null,
    "and the password-anchored detector still sees nothing, which is the point",
  );
});

test("a declared autocomplete=username is enough on its own", () => {
  // Named `q`, which the keyword scan scores negatively. The site said what it is.
  const document = dom(`
    <form><input id="q" name="q" type="text" autocomplete="username" /><button type="submit">Continue</button></form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "q");
});

test("a keyword names the identifier field when the site declares nothing", () => {
  const document = dom(`
    <form>
      <input id="login" name="login" type="text" />
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "login");
});

test("a label alone names it, the same way it does on a login form", () => {
  const document = dom(`
    <form>
      <label for="a">Account identifier</label><input id="a" type="text" />
      <button type="submit">Next</button>
    </form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "a");
});

test("a standalone field outside a form counts when something says Next", () => {
  const document = dom(`
    <div>
      <input id="ident" name="user_email" type="text" />
      <div role="button">Next</div>
    </div>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "ident");
});

test("a standalone field with nothing to press is not a sign-in step", () => {
  const document = dom(`<div><input id="ident" name="user_email" type="text" /></div>`);
  assert.equal(
    identified(KsForms.detectIdentifierForm(document)),
    null,
    "a username box with no way to submit is a filter or a widget",
  );
});

test("a page with a password field is never an identifier-first page", () => {
  const document = dom(`
    <form>
      <input id="email" type="email" autocomplete="username" />
      <input id="pw" type="password" />
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(
    identified(KsForms.detectIdentifierForm(document)),
    null,
    "the two detectors must never claim the same page",
  );
  assert.equal(detected(KsForms.detectLoginForm(document)), "pw");
});

test("a search box is not an identifier field, however it is spelled", () => {
  const cases = [
    `<form><input id="a" type="search" /><button type="submit">Go</button></form>`,
    `<form><input id="a" type="text" role="searchbox" /><button type="submit">Go</button></form>`,
    `<form><input id="a" type="text" name="q" /><button type="submit">Go</button></form>`,
    `<form><input id="a" type="text" name="search_term" /><button type="submit">Go</button></form>`,
    `<form><input id="a" type="text" aria-label="Search this site" /><button type="submit">Go</button></form>`,
  ];
  for (const html of cases) {
    assert.equal(
      identified(KsForms.detectIdentifierForm(dom(html))),
      null,
      `a search box must get no icon: ${html}`,
    );
  }
});

test("a newsletter signup is not an identifier-first sign-in", () => {
  const document = dom(`
    <form>
      <label for="n">Email</label>
      <input id="n" name="newsletter_email" type="email" />
      <button type="submit">Subscribe</button>
    </form>
  `);
  assert.equal(
    identified(KsForms.detectIdentifierForm(document)),
    null,
    "a newsletter box asks for the same value and is not a login",
  );
});

test("an address field is not an identifier field", () => {
  const document = dom(`
    <form>
      <input id="a" name="street_address" type="text" />
      <button type="submit">Continue</button>
    </form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), null);
});

test("a one-time-code page is not an identifier-first page", () => {
  const document = dom(`
    <form>
      <input id="c" type="text" autocomplete="one-time-code" />
      <button type="submit">Verify</button>
    </form>
  `);
  assert.equal(
    identified(KsForms.detectIdentifierForm(document)),
    null,
    "step three of a sign-in is a code box, and a username in it helps nobody",
  );
  assert.equal(nameOf(KsForms.detectOtpField(document)), "c");
});

test("two text boxes are too ambiguous to guess between", () => {
  const document = dom(`
    <form>
      <input id="first" name="first_name" type="text" />
      <input id="email" name="email" type="email" />
      <button type="submit">Continue</button>
    </form>
  `);
  assert.equal(
    identified(KsForms.detectIdentifierForm(document)),
    null,
    "a form asking for more than one thing is not step one of a sign-in",
  );
});

test("a header search box does not stop the real identifier field being found", () => {
  // The search box is excluded before the "exactly one candidate" count, so a site with a search
  // box in its header — which is most sites — still gets an icon on its sign-in page.
  const document = dom(`
    <header><input id="q" type="search" placeholder="Search" /></header>
    <form>
      <input id="email" type="email" autocomplete="username" />
      <button type="submit">Next</button>
    </form>
  `);
  assert.equal(identified(KsForms.detectIdentifierForm(document)), "email");
});

test("a hidden identifier field is not fillable", () => {
  const document = dom(
    `<form><input id="email" type="email" autocomplete="username" /><button type="submit">Next</button></form>`,
    (el) => (el.id === "email" ? { width: 0, height: 0 } : { width: 200, height: 30 }),
  );
  assert.equal(identified(KsForms.detectIdentifierForm(document)), null);
});

test("a page with nothing on it is not an identifier-first page", () => {
  assert.equal(identified(KsForms.detectIdentifierForm(dom(`<p>Hello</p>`))), null);
});

// ---------------------------------------------------------------------------------------
// The one-time-code field
// ---------------------------------------------------------------------------------------

test("an autocomplete=one-time-code field is found", () => {
  const document = dom(`<form><input id="c" type="text" autocomplete="one-time-code" /></form>`);
  assert.equal(nameOf(KsForms.detectOtpField(document)), "c");
});

test("a keyword names a one-time-code field when the site declares nothing", () => {
  const document = dom(`
    <form>
      <input id="a" type="text" name="user" />
      <input id="b" type="text" name="verification_code" />
    </form>
  `);
  assert.equal(nameOf(KsForms.detectOtpField(document)), "b");
});

test("a page with no code field has none, rather than the first text box", () => {
  const document = dom(`<form><input id="a" type="text" name="street" /></form>`);
  assert.equal(nameOf(KsForms.detectOtpField(document)), null);
});

test("a one-time-code field is found on a page with no password field at all", () => {
  // The second step of a two-step login: the password page is gone and only the code remains.
  const document = dom(`<form><input id="c" type="tel" name="otp" /></form>`);
  assert.equal(detected(KsForms.detectLoginForm(document)), null);
  assert.equal(nameOf(KsForms.detectOtpField(document)), "c");
});

// ---------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------

test("a write dispatches input and change, so a framework does not throw it away", () => {
  const document = dom(`<form><input id="p" type="password" /></form>`);
  const field = document.getElementById("p");
  const seen = [];
  field.addEventListener("input", () => seen.push("input"));
  field.addEventListener("change", () => seen.push("change"));

  assert.equal(KsForms.setFieldValue(field, "hunter2"), true);
  assert.equal(field.value, "hunter2");
  assert.deepEqual(seen, ["input", "change"]);
});

test("writing to nothing is false rather than a crash", () => {
  assert.equal(KsForms.setFieldValue(null, "x"), false);
  assert.equal(KsForms.setFieldValue(undefined, "x"), false);
});

test("autocomplete tokens are split, because the attribute is a list", () => {
  const document = dom(
    `<input id="a" autocomplete="section-blue shipping username" />`,
  );
  assert.deepEqual(KsForms.autocompleteTokens(document.getElementById("a")), [
    "section-blue",
    "shipping",
    "username",
  ]);
  const bare = dom(`<input id="a" />`);
  assert.deepEqual(KsForms.autocompleteTokens(bare.getElementById("a")), []);
});

test("the keyword haystack is lowercased and includes every attribute worth reading", () => {
  const document = dom(
    `<input id="MyID" name="UserName" placeholder="Your Email" aria-label="Account" />`,
  );
  const text = KsForms.haystack(document.getElementById("MyID"));
  assert.match(text, /username/);
  assert.match(text, /your email/);
  assert.match(text, /account/);
  assert.match(text, /myid/);
});
