/**
 * Finding the login form on a page.
 *
 * # What this is allowed to get wrong
 *
 * Everything, safely. Form detection is a *convenience* layer: it decides where to draw an icon
 * and which two elements to write into after the user has clicked it and the app has approved the
 * fill. It cannot cause a fill, cannot widen one, and cannot read a value. The worst outcome of a
 * bad guess is an icon in an odd place or a password written into the wrong box on the *same*
 * page the user just approved — which is why the ranking below prefers a false negative (no icon,
 * user opens the popup) to a false positive (an icon on a search box).
 *
 * # The ranking, and why it is in this order
 *
 * 1. **`autocomplete`.** `current-password`, `username`, `email` are the web platform's own way
 *    of saying what a field is for. When a site says it, believe it: nothing else on the page is
 *    better evidence, and sites that bother are the sites that got the rest right too.
 * 2. **`type="password"`.** Unambiguous, and the anchor for everything else — the username is
 *    found *relative to* the password field, not on its own, because "a text input" describes
 *    every search box on the internet.
 * 3. **Names, ids, labels and placeholders.** A keyword scan, deliberately last, deliberately
 *    scored rather than matched: `login` and `user` and `email` appear in newsletter forms too.
 *
 * `new-password` is treated as a **disqualifier**, not a signal. A registration or change-password
 * form is exactly where filling the current password is both useless and, on a change form,
 * actively harmful.
 *
 * # Two detectors, not one looser one
 *
 * [`detectLoginForm`] is anchored on `input[type=password]` and stays that way. Identifier-first
 * sign-ins — Google's, Microsoft's, Okta's — put the username on a page that has no password
 * field at all, and that page is [`detectIdentifierForm`]'s: a separate function, with its own
 * stricter evidence, whose result can only ever cause a *username* to be written. The two are
 * mutually exclusive by construction — the identifier detector refuses any page with a usable
 * password field — so no page is ever claimed by both.
 *
 * Loaded both as a classic content script and by `node --test`.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.KsForms = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function () {
  /** Words that suggest a field holds a username. Scored, not matched. */
  const USERNAME_WORDS = [
    "username",
    "userid",
    "user_id",
    "user-id",
    "user",
    "login",
    "loginid",
    "email",
    "e-mail",
    "account",
    "identifier",
    "handle",
  ];

  /** Words that suggest a field is a one-time code. */
  const OTP_WORDS = [
    "otp",
    "totp",
    "2fa",
    "twofactor",
    "two-factor",
    "onetime",
    "one-time",
    "authcode",
    "auth_code",
    "verificationcode",
    "verification_code",
    "securitycode",
    "mfa",
  ];

  /** Words that mean "this is not the field you are looking for". */
  const NEGATIVE_WORDS = ["search", "query", "q", "coupon", "promo", "zip", "postcode"];

  /**
   * Words that disqualify a lone text box from being an identifier-first username field.
   *
   * A superset of [`NEGATIVE_WORDS`], because a page with *no password field at all* is a much
   * weaker context than a page with one: on a login form the password anchors the guess, and
   * here there is nothing to anchor it but the field itself. So the list is longer and the
   * refusals are cheaper — the cost of a false negative is that the user opens the popup.
   *
   * `name` is deliberately absent: every substring test here is `includes`, and `name` matches
   * `username`.
   */
  const IDENTIFIER_NEGATIVE_WORDS = NEGATIVE_WORDS.concat([
    "newsletter",
    "subscribe",
    "address",
    "street",
    "city",
    "state",
    "country",
    "company",
    "organization",
    "comment",
    "message",
    "coupon",
    "gift",
    "invite",
    "referral",
  ]);

  /** Words on a button that mean "this takes me to the next step of a sign-in". */
  const SUBMIT_WORDS = [
    "next",
    "continue",
    "sign in",
    "signin",
    "log in",
    "login",
    "submit",
    "proceed",
    "go",
  ];

  /** `autocomplete` tokens that name a one-time code. */
  const OTP_AUTOCOMPLETE = ["one-time-code"];

  /**
   * `Node.DOCUMENT_POSITION_PRECEDING`, as the number the DOM specification fixes it to.
   *
   * Written out rather than read off a global `Node`, because this module is also loaded by the
   * unit tests against a DOM implementation that has the *method* but not the constant — and a
   * missing constant would turn `position & Node.DOCUMENT_POSITION_PRECEDING` into `NaN`, which is
   * falsy, which would silently disable the "the username comes before the password" heuristic
   * with nothing failing anywhere.
   */
  const DOCUMENT_POSITION_PRECEDING = 2;

  /**
   * The `<form>` an element belongs to.
   *
   * `HTMLInputElement.form` is the direct answer and is what a browser gives us; `closest("form")`
   * is the fallback, which is also the right answer for the `form=""` attribute case nobody uses.
   *
   * @param {Element} el
   * @returns {Element | null}
   */
  function formOf(el) {
    if (!el) return null;
    if (el.form) return el.form;
    return el.closest ? el.closest("form") : null;
  }

  /**
   * Every attribute worth reading a keyword out of, joined and lowercased.
   *
   * `aria-label` and the associated `<label>` are included because a growing number of sites label
   * a field only for assistive technology, which is the same information autofill needs.
   *
   * @param {Element} el
   * @returns {string}
   */
  function haystack(el) {
    const parts = [
      el.getAttribute && el.getAttribute("name"),
      el.id,
      el.getAttribute && el.getAttribute("placeholder"),
      el.getAttribute && el.getAttribute("aria-label"),
      el.getAttribute && el.getAttribute("autocomplete"),
      labelTextFor(el),
    ];
    return parts.filter(Boolean).join(" ").toLowerCase();
  }

  /**
   * The text of the `<label>` that names `el`, if there is one.
   *
   * Both spellings: `<label for="…">` and a `<label>` wrapping the input.
   *
   * @param {Element} el
   * @returns {string}
   */
  function labelTextFor(el) {
    try {
      if (el.id && el.ownerDocument) {
        const explicit = el.ownerDocument.querySelector(
          `label[for="${CSS.escape(el.id)}"]`,
        );
        if (explicit && explicit.textContent) return explicit.textContent;
      }
      if (el.closest) {
        const wrapping = el.closest("label");
        if (wrapping && wrapping.textContent) return wrapping.textContent;
      }
    } catch {
      /* a malformed id, a detached node: no label, not a crash */
    }
    return "";
  }

  /**
   * The `autocomplete` tokens on an element, lowercased.
   *
   * The attribute is a token *list* — `section-a shipping username` is legal — so it is split
   * rather than compared whole.
   *
   * @param {Element} el
   * @returns {string[]}
   */
  function autocompleteTokens(el) {
    const raw = el.getAttribute && el.getAttribute("autocomplete");
    if (!raw) return [];
    return raw.toLowerCase().split(/\s+/).filter(Boolean);
  }

  /**
   * Whether an element is a real, usable, visible input rather than a hidden honeypot.
   *
   * `offsetParent === null` catches `display: none` and detached nodes; the size check catches the
   * 1×1 and zero-height fields that bot traps and off-screen forms use. Both are cheap and both
   * matter: writing a password into a hidden field is a fill the user cannot see.
   *
   * @param {Element} el
   * @returns {boolean}
   */
  function isFillable(el) {
    if (!el) return false;
    // Both the IDL property and the content attribute. The property is what a browser reflects;
    // the attribute is what is actually in the markup, and reading it keeps this check honest
    // under a DOM implementation that does not reflect every attribute as a property — which is
    // exactly the situation the unit tests run in.
    const attr = (name) => el.hasAttribute && el.hasAttribute(name);
    if (el.disabled || attr("disabled")) return false;
    if (el.readOnly || attr("readonly")) return false;
    if (el.type === "hidden" || (el.getAttribute && el.getAttribute("type") === "hidden")) {
      return false;
    }
    if (typeof el.getBoundingClientRect !== "function") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 8) return false;
    // `offsetParent` is null for `position: fixed` too, so it is checked only when the rect is
    // also empty — a fixed-position login dialog is a real login dialog.
    if (el.offsetParent === null && rect.width === 0) return false;
    return true;
  }

  function score(text, words) {
    let total = 0;
    for (const word of words) {
      if (text.includes(word)) total += word.length;
    }
    return total;
  }

  /**
   * Whether a password field belongs to a form that is *setting* a password rather than using one.
   *
   * Two signals: an explicit `autocomplete="new-password"`, and more than one password field on
   * the same form (a "new password" plus "confirm password" pair).
   *
   * @param {HTMLInputElement} field
   * @param {HTMLInputElement[]} allPasswords
   * @returns {boolean}
   */
  function isNewPasswordField(field, allPasswords) {
    if (autocompleteTokens(field).includes("new-password")) return true;
    const form = formOf(field);
    if (!form) {
      // No form element at all: fall back to "more than one password field on the page", which is
      // the same signal one level coarser. A page with two loose password inputs is a
      // change-password widget more often than it is two login boxes.
      return allPasswords.length > 1;
    }
    const inSameForm = allPasswords.filter((p) => formOf(p) === form);
    return inSameForm.length > 1;
  }

  /**
   * The username field that goes with `password`, or `null`.
   *
   * Searched among the text-like inputs that appear *before* the password in document order,
   * because that is where login forms put it and because a text field after the password is
   * usually a "confirm email" or a captcha answer. An explicit `autocomplete` beats position;
   * position beats keywords.
   *
   * @param {HTMLInputElement} password
   * @param {Document | ShadowRoot} scope
   * @returns {HTMLInputElement | null}
   */
  function usernameFor(password, scope) {
    const candidates = Array.from(
      scope.querySelectorAll("input[type=text], input[type=email], input[type=tel], input:not([type])"),
    ).filter(isFillable);
    if (candidates.length === 0) return null;

    const passwordForm = formOf(password);
    const sameForm = candidates.filter((c) => !passwordForm || formOf(c) === passwordForm);
    const pool = sameForm.length > 0 ? sameForm : candidates;

    // 1. The site said so.
    const declared = pool.find((c) => {
      const tokens = autocompleteTokens(c);
      return tokens.includes("username") || tokens.includes("email");
    });
    if (declared) return declared;

    // 2. Before the password, best keyword score, ties broken by proximity (last one wins).
    const before = pool.filter(
      (c) => password.compareDocumentPosition(c) & DOCUMENT_POSITION_PRECEDING,
    );
    const ordered = before.length > 0 ? before : pool;

    let best = null;
    let bestScore = -1;
    for (const candidate of ordered) {
      const text = haystack(candidate);
      const value = score(text, USERNAME_WORDS) - score(text, NEGATIVE_WORDS) * 2;
      if (value >= bestScore) {
        bestScore = value;
        best = candidate;
      }
    }
    // A negative score means every keyword said "search box". Prefer nothing to that.
    if (bestScore < 0) return null;
    // With no keywords at all, the field immediately before the password is still the best guess
    // a login form offers, and `before` is non-empty exactly when that guess is available.
    if (bestScore === 0 && before.length === 0) return null;
    return best;
  }

  /**
   * The one-time-code field on this page, if there is one.
   *
   * Separate from [`detectLoginForm`] because the TOTP action is a separate, explicit second
   * action: a page may show the code field only *after* the password has been submitted, on a
   * page with no password field at all.
   *
   * @param {Document | ShadowRoot} scope
   * @returns {HTMLInputElement | null}
   */
  function detectOtpField(scope) {
    const inputs = Array.from(
      scope.querySelectorAll("input[type=text], input[type=tel], input[type=number], input:not([type])"),
    ).filter(isFillable);

    const declared = inputs.find((el) =>
      autocompleteTokens(el).some((t) => OTP_AUTOCOMPLETE.includes(t)),
    );
    if (declared) return declared;

    let best = null;
    let bestScore = 0;
    for (const el of inputs) {
      const value = score(haystack(el), OTP_WORDS);
      if (value > bestScore) {
        bestScore = value;
        best = el;
      }
    }
    return best;
  }

  /**
   * The login form on this page, or `null`.
   *
   * @param {Document | ShadowRoot} scope
   * @returns {{ password: HTMLInputElement, username: HTMLInputElement | null } | null}
   */
  function detectLoginForm(scope) {
    const passwords = Array.from(scope.querySelectorAll("input[type=password]"));
    const usable = passwords.filter(isFillable);
    if (usable.length === 0) return null;

    const current = usable.filter((p) => !isNewPasswordField(p, usable));
    if (current.length === 0) return null;

    // With more than one candidate left, prefer the one the site declared, then the first in
    // document order — a page with a login box in the header and one in the body means the header.
    const password =
      current.find((p) => autocompleteTokens(p).includes("current-password")) || current[0];

    return { password, username: usernameFor(password, scope) };
  }

  /**
   * Whether `el` is a search box rather than a field anything should be filled into.
   *
   * Checked by kind before it is checked by keyword: `type="search"` and `role="searchbox"` are
   * declarations, and a site that makes one is telling the truth about it. The keyword half is
   * the fallback for the very many search boxes that are a plain `input[type=text]` called `q`.
   *
   * @param {Element} el
   * @returns {boolean}
   */
  function isSearchField(el) {
    const type = (
      (el.getAttribute && el.getAttribute("type")) ||
      el.type ||
      ""
    ).toLowerCase();
    if (type === "search") return true;
    const role = (el.getAttribute && el.getAttribute("role") || "").toLowerCase();
    if (role === "searchbox" || role === "search") return true;
    const form = formOf(el);
    if (form && (form.getAttribute("role") || "").toLowerCase() === "search") return true;
    return score(haystack(el), ["search", "query"]) > 0;
  }

  /**
   * Whether a lone text box is plausibly *the* username box of an identifier-first sign-in.
   *
   * The ranking is the same one the module header describes, with one field instead of two:
   * a declared `autocomplete` wins outright, then `type="email"`, then keywords — and the
   * negative list vetoes anything the site did not declare.
   *
   * @param {Element} el
   * @returns {boolean}
   */
  function looksLikeIdentifier(el) {
    const tokens = autocompleteTokens(el);
    if (tokens.includes("username") || tokens.includes("email")) return true;
    // A site that says `one-time-code`, `new-password`, `tel` or an address token has told us
    // what this is, and it is not a username.
    if (tokens.some((t) => OTP_AUTOCOMPLETE.includes(t) || t === "new-password")) return false;

    const text = haystack(el);
    if (score(text, IDENTIFIER_NEGATIVE_WORDS) > 0) return false;
    if (score(text, OTP_WORDS) > 0) return false;

    const type = (
      (el.getAttribute && el.getAttribute("type")) ||
      el.type ||
      ""
    ).toLowerCase();
    if (type === "email") return true;
    return score(text, USERNAME_WORDS) > 0;
  }

  /**
   * Whether there is something to press after typing into `field`.
   *
   * A username box with no way to submit is a filter, a search, or a widget — not step one of a
   * sign-in. A real `<form>` counts on its own (pressing Return submits it); outside a form,
   * something has to look like a button that moves the flow on.
   *
   * @param {Element} field
   * @param {Document | ShadowRoot} scope
   * @returns {boolean}
   */
  function hasSubmitAffordance(field, scope) {
    if (formOf(field)) return true;
    const buttons = Array.from(
      scope.querySelectorAll(
        "button, input[type=submit], input[type=button], [role=button], a[href='#']",
      ),
    );
    return buttons.some((b) => {
      const type = ((b.getAttribute && b.getAttribute("type")) || "").toLowerCase();
      if (type === "submit") return true;
      const text = [
        b.textContent,
        b.getAttribute && b.getAttribute("value"),
        b.getAttribute && b.getAttribute("aria-label"),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return SUBMIT_WORDS.some((word) => text.includes(word));
    });
  }

  /**
   * The identifier-first form on this page, or `null`.
   *
   * # What this is for
   *
   * Google, Microsoft, Okta and everything built on them ask for the username on one page and the
   * password on the next. [`detectLoginForm`] is anchored on `input[type=password]` and therefore
   * sees nothing at all on page one, which used to mean the user typed their own email before the
   * manager woke up. This function is the page-one half, and it is deliberately a *separate*
   * function rather than a looser `detectLoginForm`: the password-anchored rule is the one that
   * decides where a secret gets written, and it does not get weaker so that a username can be
   * filled.
   *
   * # Why it is stricter than it looks
   *
   * A page with a password field is not this case — the existing path owns it. Beyond that, the
   * evidence has to be positive (a declared `autocomplete`, an `email` type, or a username
   * keyword), the negative list vetoes search boxes, newsletters and address fields, and there
   * has to be exactly **one** candidate text box on the page: two of them is a form asking for
   * something else as well, and this is not the moment to guess which.
   *
   * The worst outcome of a wrong guess is bounded by the protocol rather than by this function:
   * the only thing a fill can write here is the username, which the app has already handed the
   * extension in a `match` answer ([ADR-0030](../../docs/decisions/0030-identifier-first-login.md)).
   *
   * @param {Document | ShadowRoot} scope
   * @returns {{ username: HTMLInputElement } | null}
   */
  function detectIdentifierForm(scope) {
    // A page with a usable password field is the other function's business, whatever else is on
    // it. This is checked first so the two detectors can never both claim the same page.
    const passwords = Array.from(scope.querySelectorAll("input[type=password]")).filter(isFillable);
    if (passwords.length > 0) return null;

    const candidates = Array.from(
      scope.querySelectorAll(
        "input[type=text], input[type=email], input:not([type]), input[type=search]",
      ),
    )
      .filter(isFillable)
      .filter((el) => !isSearchField(el));
    if (candidates.length !== 1) return null;

    const field = candidates[0];
    if (!looksLikeIdentifier(field)) return null;
    if (!hasSubmitAffordance(field, scope)) return null;
    return { username: field };
  }

  /**
   * Write `value` into `el` the way a person typing would.
   *
   * React, Vue and every other framework that owns an input's value listen for `input`; some
   * validation runs only on `change`; and React in particular tracks the value on the DOM node
   * and will *revert* a plain assignment on its next render unless the native setter is used. All
   * three are handled here, because a fill the framework throws away is a fill that did not
   * happen.
   *
   * Returns `true` when the write stuck. **Never logs `value`.**
   *
   * @param {HTMLInputElement} el
   * @param {string} value
   * @returns {boolean}
   */
  function setFieldValue(el, value) {
    if (!el) return false;
    try {
      const proto = Object.getPrototypeOf(el);
      const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
      if (descriptor && typeof descriptor.set === "function") {
        descriptor.set.call(el, value);
      } else {
        el.value = value;
      }
      // The element's *own* `Event`, not the ambient global. In a content script inside an iframe
      // the two are different constructors and the wrong one throws; in the unit tests there is no
      // ambient `Event` at all. Falling back to the global keeps this working in a plain page.
      const view =
        (el.ownerDocument && el.ownerDocument.defaultView) || globalThis;
      const Ctor = view.Event || globalThis.Event;
      el.dispatchEvent(new Ctor("input", { bubbles: true }));
      el.dispatchEvent(new Ctor("change", { bubbles: true }));
      return el.value === value;
    } catch {
      return false;
    }
  }

  return {
    USERNAME_WORDS,
    OTP_WORDS,
    NEGATIVE_WORDS,
    IDENTIFIER_NEGATIVE_WORDS,
    SUBMIT_WORDS,
    haystack,
    labelTextFor,
    autocompleteTokens,
    formOf,
    isFillable,
    isNewPasswordField,
    isSearchField,
    looksLikeIdentifier,
    hasSubmitAffordance,
    usernameFor,
    detectOtpField,
    detectLoginForm,
    detectIdentifierForm,
    setFieldValue,
  };
});
