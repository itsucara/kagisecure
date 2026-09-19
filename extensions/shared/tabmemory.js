/**
 * Which item the user picked on page one of an identifier-first sign-in, per tab.
 *
 * # What this remembers, and what it refuses to
 *
 * One entry per tab: `{ itemId, origin, expiresAt }`. An item **id**, the origin it was chosen
 * at, and a deadline. That is the whole record. There is no username in it, no title, and above
 * all no value: an id is the same opaque string the extension already quoted back in the fill
 * request that created the entry, and the origin is the one the *browser* stamped on that
 * request. Nothing here is a secret, and nothing here would be worth stealing from a service
 * worker that an attacker already controls.
 *
 * # And what it refuses to persist
 *
 * `chrome.storage` is not used — not here, not anywhere in this extension. The Map lives in the
 * service worker and dies with it, which in MV3 can be as little as thirty seconds of idleness.
 * That is a feature twice over: a memory that cannot outlive the worker cannot outlive a browser
 * restart either, and the failure mode of losing it early is that page two offers the user a list
 * instead of continuing silently — the behaviour that shipped before this file existed.
 *
 * # The five ways an entry goes away
 *
 * 1. **Expiry.** Sixty seconds. Long enough to type a password on page two, short enough that a
 *    tab left open over lunch has forgotten by the time anyone comes back to it.
 * 2. **The tab closes.** `chrome.tabs.onRemoved`, in `background.js`.
 * 3. **The tab leaves the site.** Checked on every request that arrives from that tab, against
 *    the origin the browser stamped on it — see [`sameSite`].
 * 4. **The vault locks.** Everything, at once.
 * 5. **The password fill happens.** The thing the memory existed for is done.
 *
 * # Time is a parameter
 *
 * Every function takes `now` rather than reading the clock, which is what makes expiry testable
 * without sleeping — and is how the e2e suite ages an entry, by calling [`sweep`] with a later
 * `now` through Playwright's service-worker evaluate. There is deliberately no debug message and
 * no query flag: the product has no test-only surface to be reachable in a release build, because
 * the "test hook" is a devtools capability no page and no release code path can use.
 *
 * Loaded both by `importScripts` in the service worker (assigning to `self`) and by `node --test`
 * (through `module.exports`), so the same code is what the tests test.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.KsTabMemory = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function () {
  /** How long a chosen item is remembered for a tab. */
  const TTL_MS = 60_000;

  /** @type {Map<number, { itemId: string, origin: string, expiresAt: number }>} */
  const entries = new Map();

  /**
   * Split an origin into scheme, host and port, or `null` if it is not one.
   *
   * Deliberately string surgery rather than `new URL`: this file is loaded by the service worker
   * and by `node --test`, the origins it sees have already been normalized by `KsOrigin.originOf`
   * on the way in, and re-parsing a normalized origin can only introduce a disagreement between
   * the two halves.
   *
   * @param {string} origin
   * @returns {{ scheme: string, host: string } | null}
   */
  function parts(origin) {
    if (typeof origin !== "string") return null;
    const marker = origin.indexOf("://");
    if (marker <= 0) return null;
    const scheme = origin.slice(0, marker);
    const rest = origin.slice(marker + 3);
    if (!rest) return null;
    return { scheme, host: rest };
  }

  /**
   * Whether an entry made at `remembered` may still be used at `current`.
   *
   * The rule is **the same origin, or a subdomain of it**, with the scheme and port compared
   * verbatim because they are part of the host string here. So `https://example.com` carries down
   * to `https://login.example.com`, which is the case this whole feature exists for, and
   * `https://alice.github.io` does not carry across to `https://mallory.github.io`, which is the
   * case the Public Suffix List is carried for on the Rust side.
   *
   * This is **stricter** than the app's eTLD+1 rule, on purpose and for the same reason
   * `origin.js` does not ship the Public Suffix List: nothing in the browser half is a security
   * boundary, so the half that is cheap to be right about is the half that says no. Two siblings
   * under one registrable domain — `accounts.example.com` then `login.example.com` — lose the
   * memory and fall back to the list the user had before. A wrong *yes* would be worse: it would
   * offer to continue as somebody at a site they did not start at.
   *
   * @param {string} remembered
   * @param {string} current
   * @returns {boolean}
   */
  function sameSite(remembered, current) {
    const a = parts(remembered);
    const b = parts(current);
    if (!a || !b) return false;
    if (a.scheme !== b.scheme) return false;
    if (a.host === b.host) return true;
    return b.host.endsWith(`.${a.host}`);
  }

  /**
   * Remember that `itemId` was chosen in `tabId` at `origin`.
   *
   * @param {number} tabId
   * @param {string} itemId
   * @param {string} origin the origin **the browser stamped** on the request, never a claim
   * @param {number} now milliseconds
   * @returns {boolean} whether anything was stored
   */
  function remember(tabId, itemId, origin, now) {
    if (typeof tabId !== "number" || !itemId || !origin) return false;
    entries.set(tabId, { itemId, origin, expiresAt: now + TTL_MS });
    return true;
  }

  /**
   * The item remembered for `tabId` at `origin`, or `null`.
   *
   * An entry that has expired, or whose origin no longer applies, is **removed** rather than
   * merely ignored: a recall is the only moment this file learns that a tab has moved on, and
   * leaving a dead entry in the Map would mean the popup could still show it.
   *
   * @param {number} tabId
   * @param {string} origin
   * @param {number} now
   * @returns {{ itemId: string, origin: string, expiresAt: number } | null}
   */
  function recall(tabId, origin, now) {
    const entry = entries.get(tabId);
    if (!entry) return null;
    if (now >= entry.expiresAt) {
      entries.delete(tabId);
      return null;
    }
    if (!sameSite(entry.origin, origin)) {
      entries.delete(tabId);
      return null;
    }
    return { ...entry };
  }

  /**
   * What is remembered for `tabId`, without an origin to check it against.
   *
   * For the popup, which knows a tab id and deliberately cannot know that tab's URL — reading it
   * would mean the `tabs` permission over every tab, for a caption. Expiry still applies; the
   * origin in the entry is the one that gets displayed, and it is the origin the memory was
   * *made* at rather than a claim about where the tab is now.
   *
   * @param {number} tabId
   * @param {number} now
   * @returns {{ itemId: string, origin: string, expiresAt: number } | null}
   */
  function peek(tabId, now) {
    const entry = entries.get(tabId);
    if (!entry) return null;
    if (now >= entry.expiresAt) {
      entries.delete(tabId);
      return null;
    }
    return { ...entry };
  }

  /**
   * Forget `tabId`.
   *
   * @param {number} tabId
   * @returns {boolean} whether there was anything to forget
   */
  function forget(tabId) {
    return entries.delete(tabId);
  }

  /** Forget everything. The vault locking, or the user asking. */
  function forgetAll() {
    entries.clear();
  }

  /**
   * Drop every entry that has expired by `now`.
   *
   * @param {number} now
   * @returns {number} how many were dropped
   */
  function sweep(now) {
    let dropped = 0;
    for (const [tabId, entry] of entries) {
      if (now >= entry.expiresAt) {
        entries.delete(tabId);
        dropped += 1;
      }
    }
    return dropped;
  }

  /** How many tabs are remembered. Diagnostics; carries nothing. */
  function size() {
    return entries.size;
  }

  return { TTL_MS, sameSite, remember, recall, peek, forget, forgetAll, sweep, size };
});
