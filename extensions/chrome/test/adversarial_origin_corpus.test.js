/**
 * B-11: the browser half and the app half of origin serialization must agree byte for byte.
 *
 * The extension sends a string; the app matches a saved website against that string. If
 * `KsOrigin.originOf` here and `Origin::ascii_serialization` in
 * `crates/kagisecure-extension-ipc/src/origin.rs` disagree about even one URL, the disagreement is
 * either a fill the app refuses for no reason the user can see, or — the direction that matters —
 * a fill the app grants for an origin that is not the one the browser is actually on.
 *
 * `test/fixtures/origin_corpus.json` is **the contract**, not a snapshot of this file's behaviour:
 * ~500 URLs covering IDN, trailing dots, default and explicit ports, userinfo confusables,
 * uppercase schemes and hosts, IP literals in every notation WHATWG accepts, embedded control
 * characters, and the non-web schemes (`file:`, `data:`, `blob:`, `about:`) autofill refuses. The
 * expected values follow WHATWG URL serialization, which is the specification both halves claim to
 * implement. A Rust-side test is expected to read the same file and assert the same strings; a
 * divergence between the two runs is the finding, and whichever side moved is the side that broke.
 *
 * This file asserts the JavaScript half only.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const KsOrigin = require("../../shared/origin.js");

const FIXTURE = path.join(__dirname, "fixtures", "origin_corpus.json");

/** An origin that is obviously a stand-in, so a leaked-looking value in a diff reads as test data. */
const CANARY_ATTACKER_ORIGIN = "https://evil.test";

const corpus = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));

test("the shared origin corpus is large enough to be worth calling a contract", () => {
  assert.ok(corpus.cases.length >= 500, `corpus holds only ${corpus.cases.length} cases`);
  assert.equal(corpus.count, corpus.cases.length);
});

test("every URL in the shared corpus appears exactly once", () => {
  const seen = new Set();
  for (const entry of corpus.cases) {
    assert.ok(!seen.has(entry.url), `duplicate corpus entry: ${JSON.stringify(entry.url)}`);
    seen.add(entry.url);
  }
});

test("the shared corpus covers every category the two halves can disagree about", () => {
  const origins = corpus.cases.map((c) => c.origin);
  const refused = origins.filter((o) => o === null).length;
  assert.ok(refused >= 40, "corpus must exercise plenty of refusals, not only successes");
  assert.ok(
    origins.some((o) => o && o.includes("xn--")),
    "corpus must carry punycoded IDN hosts",
  );
  assert.ok(
    origins.some((o) => o && /:\d+$/.test(o)),
    "corpus must carry non-default ports",
  );
  assert.ok(
    origins.some((o) => o && o.endsWith(".")),
    "corpus must carry a trailing-dot host",
  );
  assert.ok(
    origins.some((o) => o && o.startsWith("https://[")),
    "corpus must carry an IPv6 literal",
  );
});

test("KsOrigin.originOf reproduces the shared corpus byte for byte", () => {
  const mismatches = [];
  for (const entry of corpus.cases) {
    const actual = KsOrigin.originOf(entry.url);
    if (actual !== entry.origin) {
      mismatches.push(
        `${JSON.stringify(entry.url)} (${entry.note}): expected ${JSON.stringify(entry.origin)}, got ${JSON.stringify(actual)}`,
      );
    }
  }
  assert.deepEqual(mismatches, []);
});

test("originOf strips userinfo, so a confusable authority resolves to the real host", () => {
  // The classic phish: the text before `@` is not the host, and both halves have to know that.
  assert.equal(KsOrigin.originOf(`https://example.com@evil.test/`), CANARY_ATTACKER_ORIGIN);
  assert.equal(KsOrigin.originOf(`https://example.com:443@evil.test/`), CANARY_ATTACKER_ORIGIN);
  assert.equal(KsOrigin.originOf(`https://example.com%2f@evil.test/`), CANARY_ATTACKER_ORIGIN);
});

test("originOf treats a backslash the way a special scheme does, not as part of the host", () => {
  // `https://example.com\@evil.test` is `https://example.com/@evil.test` per WHATWG. A half that
  // parsed it as a host would serialize the attacker's origin.
  assert.equal(KsOrigin.originOf("https://example.com\\@evil.test"), "https://example.com");
});

test("originOf keeps a trailing dot, because the app's matcher has to see the same host", () => {
  // `example.com.` and `example.com` are different DNS names but reach the same server. Silently
  // folding one into the other on only one side of the channel is a disagreement.
  assert.equal(KsOrigin.originOf("https://example.com."), "https://example.com.");
  assert.notEqual(
    KsOrigin.originOf("https://example.com."),
    KsOrigin.originOf("https://example.com"),
  );
});

test("originOf refuses every scheme autofill does not serve", () => {
  for (const url of [
    "file:///etc/passwd",
    "about:blank",
    "data:text/html,<b>hi</b>",
    "blob:https://example.com/2b1f-4c",
    "javascript:alert(1)",
    "chrome-extension://abcdefghijklmnop/popup.html",
    "ws://example.com/s",
    "ftp://example.com/",
    "view-source:https://example.com/",
  ]) {
    assert.equal(KsOrigin.originOf(url), null, url);
  }
});
