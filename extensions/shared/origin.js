/**
 * The browser's half of the origin rule.
 *
 * # This is not the security boundary
 *
 * The rule that decides whether a fill happens lives in Rust
 * (`crates/kagisecure-extension-ipc/src/origin.rs`) and runs in the app, behind the approval
 * sheet. What is here is the same rule *approximated* for one job only: deciding whether to draw
 * an icon in a field before anyone has asked the app anything. A page that talks this code into
 * saying "yes" gets an icon, and then the app says no.
 *
 * Nothing here is trusted by the app, so nothing here is allowed to matter. The one property it
 * must have is that it is not *looser* in a way that would make the icon appear on pages the app
 * would refuse — a lying icon teaches people that the sheet is noise.
 *
 * # No Public Suffix List here, on purpose
 *
 * Shipping a copy of the list into the extension would be ~250 KB of data that has to be kept in
 * step with the crate's copy, in a place where it decides nothing. So this file does not attempt
 * eTLD+1 at all: it normalizes and compares whole origins, which is *stricter* than the app's
 * rule, never looser. The consequence is visible and small: on `gist.github.com`, with only
 * `github.com` saved, the icon appears once the app has answered a `match` — which the content
 * script asks for anyway — rather than before.
 *
 * Loaded both as a classic content script (assigning to `globalThis`) and by `node --test`
 * (through `module.exports`), so the same code is what the tests test.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.KsOrigin = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function () {
  /** Schemes autofill will serve. Everything else — `file:`, `about:`, `data:` — is refused. */
  const WEB_SCHEMES = ["http:", "https:"];

  /**
   * The ASCII origin of a URL string, or `null` if autofill will not serve it.
   *
   * Matches `Origin::ascii_serialization` in the Rust crate: lowercase scheme and host, punycode
   * for an IDN, the port shown only when it is not the scheme's default. The two have to agree
   * exactly, because this string is what the extension sends and what the app matches on.
   *
   * @param {string} input
   * @returns {string | null}
   */
  function originOf(input) {
    if (typeof input !== "string" || input.trim() === "") return null;
    let url;
    try {
      url = new URL(input.trim());
    } catch {
      return null;
    }
    if (!WEB_SCHEMES.includes(url.protocol)) return null;
    if (!url.hostname) return null;
    const scheme = url.protocol.slice(0, -1);
    const defaultPort = scheme === "https" ? "443" : "80";
    const port = url.port === "" ? defaultPort : url.port;
    // `URL.hostname` is already lowercased, punycoded, and bracketed for IPv6 — the same
    // normalization `url::Host` performs on the Rust side.
    return port === defaultPort
      ? `${scheme}://${url.hostname}`
      : `${scheme}://${url.hostname}:${port}`;
  }

  /**
   * Where this document is, as an origin the app will accept — or `null` when it is somewhere
   * autofill does not go (`about:blank`, a `data:` frame, a sandboxed iframe whose origin is
   * opaque and serializes as the string `"null"`).
   *
   * @param {Location | { href: string }} location
   * @param {string} [documentOrigin] `document.origin`, when the caller has one
   * @returns {string | null}
   */
  function currentOrigin(location, documentOrigin) {
    // An opaque origin — a sandboxed frame, a `data:` document — serializes as the literal
    // string "null". Filling into one is filling into a document with no identity at all.
    if (documentOrigin === "null") return null;
    return originOf(location && location.href);
  }

  /**
   * The page context to send with a request.
   *
   * `frameOrigin` is set only when this document is not the top frame, so the app can apply its
   * iframe policy: a cross-origin frame is matched against the *frame*, never against the page
   * that embedded it.
   *
   * @param {Window} win
   * @returns {{ top_origin: string, frame_origin: string | null } | null}
   */
  function pageContext(win) {
    const here = currentOrigin(win.location, win.document && win.document.origin);
    if (!here) return null;
    const isTop = win === win.top;
    if (isTop) return { top_origin: here, frame_origin: null };

    // A cross-origin ancestor's location is unreadable, which is the whole point of the same
    // origin policy — so "what is the top origin" is a question this frame usually cannot answer.
    // `ancestorOrigins` answers it in Chromium; where it does not, the frame's own origin is sent
    // as both, and the app then applies the top-frame rule. That is the strict direction: it
    // cannot turn a refusal into an approval, only the reverse.
    let top = here;
    try {
      const ancestors = win.location.ancestorOrigins;
      if (ancestors && ancestors.length > 0) {
        const outermost = ancestors[ancestors.length - 1];
        if (outermost && outermost !== "null") top = outermost;
      }
    } catch {
      /* keep `top === here` */
    }
    return { top_origin: top, frame_origin: here };
  }

  /**
   * Whether a fill *might* be offered here without asking the app first.
   *
   * Whole-origin equality, deliberately stricter than the app's eTLD+1 rule. See the module
   * comment for why this file does not carry the Public Suffix List.
   *
   * @param {string[]} savedWebsites
   * @param {string} pageOrigin
   * @returns {boolean}
   */
  function mightMatch(savedWebsites, pageOrigin) {
    if (!Array.isArray(savedWebsites) || !pageOrigin) return false;
    return savedWebsites.some((saved) => originOf(saved) === pageOrigin);
  }

  return { originOf, currentOrigin, pageContext, mightMatch, WEB_SCHEMES };
});
