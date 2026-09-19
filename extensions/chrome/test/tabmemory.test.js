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
