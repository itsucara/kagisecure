/**
 * The extension's UI strings: every locale has every key (and the same placeholders), every
 * `localized("key", "English")` call names a key that exists, and its inline English fallback —
 * what the unit tests and a browser without `chrome.i18n` see — is the `_locales/en` text.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SHARED = path.join(__dirname, "..", "..", "shared");
const LOCALES = path.join(SHARED, "_locales");
const locales = Object.fromEntries(
  fs
    .readdirSync(LOCALES)
    .map((lang) => [lang, JSON.parse(fs.readFileSync(path.join(LOCALES, lang, "messages.json"), "utf8"))]),
);

/** A message with its `$name$` placeholders put back as the `$1`… they stand for. */
function resolved(entry) {
  return entry.message.replace(/\$(\w+)\$/g, (_, name) => entry.placeholders[name].content);
}

test("English and Japanese are both present", () => {
  assert.ok(locales.en);
  assert.ok(locales.ja);
});

test("every locale has exactly the English keys and placeholders", () => {
  const keys = Object.keys(locales.en).sort();
  for (const [lang, messages] of Object.entries(locales)) {
    assert.deepEqual(Object.keys(messages).sort(), keys, `${lang} keys`);
    for (const key of keys) {
      const want = resolved(locales.en[key]).match(/\$\d/g) || [];
      const got = resolved(messages[key]).match(/\$\d/g) || [];
      assert.deepEqual([...new Set(got)].sort(), [...new Set(want)].sort(), `${lang}.${key} placeholders`);
      assert.ok(messages[key].message.trim(), `${lang}.${key} is empty`);
    }
  }
});

test("every localized() call names a key, and its fallback is the English text", () => {
  const call = /localized\(\s*"([^"]+)",\s*("(?:[^"\\]|\\.)*")/g;
  let seen = 0;
  for (const file of fs.readdirSync(SHARED).filter((f) => f.endsWith(".js"))) {
    const source = fs.readFileSync(path.join(SHARED, file), "utf8");
    for (const [, key, literal] of source.matchAll(call)) {
      seen++;
      assert.ok(locales.en[key], `${file}: unknown key ${key}`);
      assert.equal(JSON.parse(literal), resolved(locales.en[key]), `${file}: fallback for ${key}`);
    }
  }
  const html = fs.readFileSync(path.join(SHARED, "popup.html"), "utf8");
  for (const [, key, text] of html.matchAll(/data-i18n="([^"]+)"[^>]*>([^<]*)</g)) {
    seen++;
    assert.ok(locales.en[key], `popup.html: unknown key ${key}`);
    assert.equal(text, resolved(locales.en[key]), `popup.html: text for ${key}`);
  }
  assert.ok(seen > 40, `only ${seen} localized strings found`);
});

test("manifest __MSG_ references exist and fit the store limits in every locale", () => {
  for (const manifest of ["shared/manifest.json", "safari/manifest.json"]) {
    const text = fs.readFileSync(path.join(SHARED, "..", manifest), "utf8");
    assert.match(text, /"default_locale": "en"/);
    for (const [, key] of text.matchAll(/__MSG_(\w+)__/g)) {
      for (const [lang, messages] of Object.entries(locales)) {
        assert.ok(messages[key], `${manifest}: ${lang} lacks ${key}`);
        const limit = key === "extName" ? 75 : 132;
        assert.ok([...messages[key].message].length <= limit, `${lang}.${key} over ${limit} chars`);
      }
    }
  }
});
