/**
 * The extension's origin helpers.
 *
 * The security rule is asserted in Rust — `crates/kagisecure-extension-ipc/src/origin.rs` has the
 * table with the Public Suffix List cases. What is asserted here is the narrower claim this file
 * is allowed to make: that the origin *string* the extension sends is byte-identical to the one
 * the Rust side produces from the same URL, and that the browser-side pre-check is stricter than
 * the app's rule rather than looser.
 *
 * The first of those matters more than it looks: the app matches on this string, and a
 * disagreement about, say, whether to print `:443` would make every https fill fail with an
 * origin mismatch nobody could explain.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const KsOrigin = require("../../shared/origin.js");

test("an origin keeps only scheme, host and port", () => {
  assert.equal(
    KsOrigin.originOf("https://Example.COM:8443/login?next=/a#frag"),
    "https://example.com:8443",
  );
  assert.equal(KsOrigin.originOf("http://localhost:8765/index.html"), "http://localhost:8765");
});

test("a default port is filled in and then hidden, exactly as the Rust side renders it", () => {
  // These four pairs are the ones a mismatch would be invisible in: the app would refuse and the
  // message would say "the origin does not match a saved website" about two identical origins.
  assert.equal(KsOrigin.originOf("https://example.com"), "https://example.com");
  assert.equal(KsOrigin.originOf("https://example.com:443"), "https://example.com");
  assert.equal(KsOrigin.originOf("http://example.com"), "http://example.com");
  assert.equal(KsOrigin.originOf("http://example.com:80"), "http://example.com");
  assert.equal(KsOrigin.originOf("http://example.com:8080"), "http://example.com:8080");
});

test("an IPv6 host is bracketed and an IPv4 host is not", () => {
  assert.equal(KsOrigin.originOf("http://[::1]:3000/"), "http://[::1]:3000");
  assert.equal(KsOrigin.originOf("http://127.0.0.1:3000/"), "http://127.0.0.1:3000");
});

test("an IDN is punycoded, so both spellings produce one origin", () => {
  const punycode = "https://xn--hxajbheg2az3al.xn--jxalpdlp";
  assert.equal(KsOrigin.originOf("https://παράδειγμα.δοκιμή"), punycode);
  assert.equal(KsOrigin.originOf(punycode), punycode);
});

test("non-web schemes are refused, so autofill never reaches a file or an extension page", () => {
  for (const input of [
    "file:///etc/passwd",
    "about:blank",
    "data:text/html,<h1>hi",
    "chrome-extension://nlijibjnmanccalmafnfbobkcfjiibmd/popup.html",
    "chrome://settings",
    "javascript:alert(1)",
    "ftp://example.com",
    "",
    "   ",
    "not a url",
  ]) {
    assert.equal(KsOrigin.originOf(input), null, `${input} should not be an origin`);
  }
});

test("a non-string is not an origin", () => {
  for (const input of [null, undefined, 42, {}, []]) {
    assert.equal(KsOrigin.originOf(input), null);
  }
});

test("an opaque origin — a sandboxed frame — is refused", () => {
  // `document.origin` is the literal string "null" in a sandboxed iframe or a `data:` document.
  // Filling into one is filling into a document with no identity at all.
  assert.equal(
    KsOrigin.currentOrigin({ href: "https://example.com/" }, "null"),
    null,
  );
  assert.equal(
    KsOrigin.currentOrigin({ href: "https://example.com/" }, "https://example.com"),
    "https://example.com",
  );
});

test("the top frame reports no frame origin", () => {
  const win = {
    location: { href: "https://example.com/login" },
    document: { origin: "https://example.com" },
  };
  win.top = win;
  assert.deepEqual(KsOrigin.pageContext(win), {
    top_origin: "https://example.com",
    frame_origin: null,
  });
});

test("a frame reports both origins, so the app can apply its iframe policy", () => {
  const win = {
    location: {
      href: "https://bank.test/embed",
      ancestorOrigins: { length: 1, 0: "https://shop.test" },
    },
    document: { origin: "https://bank.test" },
    top: {},
  };
  assert.deepEqual(KsOrigin.pageContext(win), {
    top_origin: "https://shop.test",
    frame_origin: "https://bank.test",
  });
});

test("a frame that cannot read its ancestors falls back to the strict answer", () => {
  // Without `ancestorOrigins` the frame cannot know the page above it. Reporting its own origin as
  // both means the app applies the top-frame rule — which can only make a fill *less* likely, not
  // more, so a frame that lies here cannot talk its way into an approval.
  const win = {
    location: { href: "https://bank.test/embed" },
    document: { origin: "https://bank.test" },
    top: {},
  };
  assert.deepEqual(KsOrigin.pageContext(win), {
    top_origin: "https://bank.test",
    frame_origin: "https://bank.test",
  });
});

test("a page with no usable origin produces no context at all", () => {
  const win = { location: { href: "about:blank" }, document: { origin: "null" }, top: {} };
  assert.equal(KsOrigin.pageContext(win), null);
});

test("the browser-side pre-check is whole-origin equality, stricter than the app's rule", () => {
  assert.equal(
    KsOrigin.mightMatch(["https://example.com"], "https://example.com"),
    true,
  );
  // The app *would* fill this — same eTLD+1 — and the extension deliberately does not claim so
  // without asking. The consequence is an icon that appears after the `match` answer instead of
  // before it, never a fill that does not happen.
  assert.equal(
    KsOrigin.mightMatch(["https://example.com"], "https://www.example.com"),
    false,
  );
  assert.equal(
    KsOrigin.mightMatch(["https://example.com"], "https://evil.test"),
    false,
  );
  assert.equal(KsOrigin.mightMatch([], "https://example.com"), false);
  assert.equal(KsOrigin.mightMatch(null, "https://example.com"), false);
  assert.equal(KsOrigin.mightMatch(["https://example.com"], ""), false);
});

test("unparseable saved websites are skipped rather than throwing", () => {
  assert.equal(
    KsOrigin.mightMatch(["", "not a url", "https://example.com"], "https://example.com"),
    true,
  );
});
