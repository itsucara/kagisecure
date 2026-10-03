/**
 * The per-tab memory of an identifier-first sign-in.
 *
 * Every function under test takes `now` as a parameter, so expiry is asserted by arithmetic
 * rather than by sleeping. The module's state is a single module-level Map shared by every test
 * in this file, so each test clears it first — `forgetAll` is production code, and using it here
 * means the teardown path is exercised on every run.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const KsTabMemory = require("../../shared/tabmemory.js");

const T0 = 1_700_000_000_000;
const SITE = "https://accounts.example.com";

test.beforeEach(() => KsTabMemory.forgetAll());

test("an item chosen on page one is recalled on page two of the same tab", () => {
  assert.equal(KsTabMemory.remember(7, "item-1", SITE, T0), true);
  const recalled = KsTabMemory.recall(7, SITE, T0 + 1_000);
  assert.equal(recalled.itemId, "item-1");
  assert.equal(recalled.origin, SITE);
});

test("another tab remembers nothing, because the memory is per tab", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  assert.equal(KsTabMemory.recall(8, SITE, T0 + 1_000), null);
});

test("a second choice in the same tab replaces the first", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  KsTabMemory.remember(7, "item-2", SITE, T0 + 5_000);
  assert.equal(KsTabMemory.recall(7, SITE, T0 + 6_000).itemId, "item-2");
  assert.equal(KsTabMemory.size(), 1);
});

test("nothing is remembered without a tab id, an item and an origin", () => {
  assert.equal(KsTabMemory.remember(undefined, "item-1", SITE, T0), false);
  assert.equal(KsTabMemory.remember(7, "", SITE, T0), false);
  assert.equal(KsTabMemory.remember(7, "item-1", "", T0), false);
  assert.equal(KsTabMemory.size(), 0);
});

// ---------------------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------------------

test("the memory expires, and the entry is dropped rather than merely ignored", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  assert.ok(KsTabMemory.recall(7, SITE, T0 + KsTabMemory.TTL_MS - 1), "still live one tick before");
  assert.equal(
    KsTabMemory.recall(7, SITE, T0 + KsTabMemory.TTL_MS),
    null,
    "the deadline is inclusive: at expiresAt it is gone",
  );
  assert.equal(KsTabMemory.size(), 0, "and it is not left behind for the popup to find");
});

test("the sixty-second budget is the one the documentation claims", () => {
  assert.equal(KsTabMemory.TTL_MS, 60_000);
});

test("a sweep drops what has expired and keeps what has not", () => {
  KsTabMemory.remember(1, "old", SITE, T0);
  KsTabMemory.remember(2, "new", SITE, T0 + 30_000);
  assert.equal(KsTabMemory.sweep(T0 + 40_000), 0, "neither has expired yet");
  assert.equal(KsTabMemory.sweep(T0 + 70_000), 1, "the older one has");
  assert.equal(KsTabMemory.size(), 1);
  assert.equal(KsTabMemory.recall(2, SITE, T0 + 70_000).itemId, "new");
});

// ---------------------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------------------

test("the memory carries down into a subdomain of the origin it was made at", () => {
  KsTabMemory.remember(7, "item-1", "https://example.com", T0);
  assert.ok(KsTabMemory.recall(7, "https://login.example.com", T0 + 1_000));
});

test("a different registrable domain forgets, which is the case the PSL exists for", () => {
  KsTabMemory.remember(7, "item-1", "https://alice.github.io", T0);
  assert.equal(
    KsTabMemory.recall(7, "https://mallory.github.io", T0 + 1_000),
    null,
    "two sites under a public suffix are strangers, not relatives",
  );
  assert.equal(KsTabMemory.size(), 0, "and a navigation away forgets rather than parks");
});

test("a sibling subdomain forgets too, because this rule is stricter than the app's", () => {
  KsTabMemory.remember(7, "item-1", "https://accounts.example.com", T0);
  assert.equal(
    KsTabMemory.recall(7, "https://login.example.com", T0 + 1_000),
    null,
    "the app would allow this; the browser half prefers to ask",
  );
});

test("a scheme or port change is a different origin", () => {
  KsTabMemory.remember(7, "item-1", "https://example.com", T0);
  assert.equal(KsTabMemory.recall(7, "http://example.com", T0 + 1_000), null);

  KsTabMemory.remember(8, "item-1", "http://example.com:8080", T0);
  assert.ok(KsTabMemory.recall(8, "http://example.com:8080", T0 + 1_000), "the same port is fine");
  assert.equal(
    KsTabMemory.recall(8, "http://example.com:9090", T0 + 1_000),
    null,
    "and a port change is a different origin — which also drops the entry",
  );
  assert.equal(KsTabMemory.size(), 0);
});

test("a host that merely ends with the remembered one is not a subdomain of it", () => {
  assert.equal(
    KsTabMemory.sameSite("https://example.com", "https://notexample.com"),
    false,
    "the dot is what makes it a subdomain",
  );
  assert.equal(KsTabMemory.sameSite("https://example.com", "https://example.com.evil.test"), false);
});

test("a malformed origin is never the same site as anything", () => {
  assert.equal(KsTabMemory.sameSite("example.com", "https://example.com"), false);
  assert.equal(KsTabMemory.sameSite("https://example.com", "null"), false);
  assert.equal(KsTabMemory.sameSite("https://example.com", ""), false);
  assert.equal(KsTabMemory.sameSite(null, undefined), false);
});

// ---------------------------------------------------------------------------------------
// Forgetting on purpose
// ---------------------------------------------------------------------------------------

test("a closed tab is forgotten", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  assert.equal(KsTabMemory.forget(7), true);
  assert.equal(KsTabMemory.forget(7), false, "and forgetting twice is not an error");
  assert.equal(KsTabMemory.recall(7, SITE, T0 + 1_000), null);
});

test("a lock forgets every tab at once", () => {
  KsTabMemory.remember(1, "a", SITE, T0);
  KsTabMemory.remember(2, "b", SITE, T0);
  KsTabMemory.forgetAll();
  assert.equal(KsTabMemory.size(), 0);
});

test("peek answers without an origin, for the popup, and still honours expiry", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  assert.equal(KsTabMemory.peek(7, T0 + 1_000).itemId, "item-1");
  assert.equal(KsTabMemory.peek(7, T0 + KsTabMemory.TTL_MS), null);
  assert.equal(KsTabMemory.peek(99, T0), null);
});

test("what comes back is a copy, so a caller cannot edit the memory in place", () => {
  KsTabMemory.remember(7, "item-1", SITE, T0);
  const recalled = KsTabMemory.recall(7, SITE, T0 + 1_000);
  recalled.itemId = "item-tampered";
  recalled.expiresAt = T0 + 10_000_000;
  assert.equal(KsTabMemory.recall(7, SITE, T0 + 2_000).itemId, "item-1");
  assert.equal(KsTabMemory.recall(7, SITE, T0 + KsTabMemory.TTL_MS), null);
});

// -----------------------------------------------------------------------------------------------
// B-28: adversarial recall — which origins may inherit an entry, and which must not.
//
// The design accepts one carry: down from an origin to a subdomain of it, because that is the
// shape of `example.com` → `login.example.com` that identifier-first sign-ins have. Everything
// else is a wrong *yes*: it would offer to continue as somebody at a site the user did not start
// at. The tests below are the ones that must say no, written as a sibling-suffix attack, a scheme
// downgrade, a port change and a registrable-domain confusable.
// -----------------------------------------------------------------------------------------------

/** A look-alike registrable domain. The `.test` TLD makes it obviously not a real site. */
const CANARY_LOOKALIKE = "https://notexample.test";
const CANARY_BASE = "https://example.test";

test("B-28: an entry does not carry to a domain that merely ends with the same letters", () => {
  // `notexample.test` ends with `example.test` as a *string*, which is exactly the mistake a
  // suffix comparison without the leading dot would make.
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(KsTabMemory.recall(7, CANARY_LOOKALIKE, T0 + 1_000), null);
  // And the failed recall removed the entry rather than leaving it for the next attempt.
  assert.equal(KsTabMemory.peek(7, T0 + 1_000), null);
});

test("B-28: an entry does not carry from a subdomain up to its parent", () => {
  // The carry is one-directional. Remembering at `login.example.test` must not answer at
  // `example.test`, or at a sibling under it.
  KsTabMemory.remember(7, "item-1", "https://login.example.test", T0);
  assert.equal(KsTabMemory.recall(7, CANARY_BASE, T0 + 1_000), null);
  KsTabMemory.remember(7, "item-1", "https://login.example.test", T0);
  assert.equal(KsTabMemory.recall(7, "https://evil.example.test", T0 + 1_000), null);
});

test("B-28: an entry does not carry across a scheme downgrade", () => {
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(KsTabMemory.recall(7, "http://example.test", T0 + 1_000), null);
  KsTabMemory.remember(7, "item-1", "http://example.test", T0);
  assert.equal(KsTabMemory.recall(7, CANARY_BASE, T0 + 1_000), null);
});

test("B-28: an entry does not carry across a port change", () => {
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(KsTabMemory.recall(7, "https://example.test:8443", T0 + 1_000), null);
  KsTabMemory.remember(7, "item-1", "https://example.test:8443", T0);
  assert.equal(KsTabMemory.recall(7, CANARY_BASE, T0 + 1_000), null);
  // And a subdomain on a different port is not a carry either, because the port is part of the
  // host string `sameSite` compares.
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(KsTabMemory.recall(7, "https://login.example.test:8443", T0 + 1_000), null);
});

test("B-28: the accepted carry is exactly one subdomain hop down, and it still works", () => {
  // The case the whole feature exists for. Asserted alongside the refusals so that a future
  // tightening that breaks it is visible here rather than only in the e2e suite.
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(KsTabMemory.recall(7, "https://login.example.test", T0 + 1_000).itemId, "item-1");
  KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
  assert.equal(
    KsTabMemory.recall(7, "https://a.b.c.example.test", T0 + 1_000).itemId,
    "item-1",
    "a deeper subdomain is still under the same origin",
  );
});

test("B-28: two siblings under one registrable domain do not share a memory", () => {
  // Deliberately stricter than the app's eTLD+1 rule: `accounts.example.test` and
  // `login.example.test` are siblings, and the memory says no.
  KsTabMemory.remember(7, "item-1", "https://accounts.example.test", T0);
  assert.equal(KsTabMemory.recall(7, "https://login.example.test", T0 + 1_000), null);
});

test("B-28: a user-hosted site does not carry across to another user on the same host", () => {
  // The `github.io` case the Public Suffix List is carried for on the Rust side. The browser half
  // gets this right without the list, because it compares whole origins.
  KsTabMemory.remember(7, "item-1", "https://alice.github.io", T0);
  assert.equal(KsTabMemory.recall(7, "https://mallory.github.io", T0 + 1_000), null);
});

test("B-28: a malformed or empty origin is never a recall", () => {
  for (const origin of ["", "example.test", "https://", "://example.test", "null", "about:blank"]) {
    KsTabMemory.remember(7, "item-1", CANARY_BASE, T0);
    assert.equal(KsTabMemory.recall(7, origin, T0 + 1_000), null, JSON.stringify(origin));
  }
  for (const origin of ["", null, undefined, 0]) {
    assert.equal(KsTabMemory.remember(8, "item-1", origin, T0), false, JSON.stringify(origin));
  }
});

test("B-28: an entry made at a trailing-dot host does not answer for the dotless one", () => {
  // `origin.js` keeps the trailing dot, so the two are different origin strings and must stay
  // different here — a fold in only one of the two halves is a disagreement.
  KsTabMemory.remember(7, "item-1", "https://example.test.", T0);
  assert.equal(KsTabMemory.recall(7, CANARY_BASE, T0 + 1_000), null);
});
