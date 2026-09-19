/**
 * The content script: an icon in the field, a keyboard shortcut, and a write.
 *
 * # The three rules this file exists to keep
 *
 * 1. **Never fill on page load.** There is no code path from "a form appeared" to "a value was
 *    requested". The only two things that ask the app for a value are the click handler on the
 *    icon and the ⌘\ handler, and both are reached only through a real user gesture. What *does*
 *    happen automatically is a `match` — titles and usernames, no values — so the icon knows
 *    whether to appear at all.
 * 2. **Never log a value.** The password exists in this file inside exactly one function,
 *    `applyFill`, as a parameter that is written into a field and then goes out of scope. There is
 *    no `console.log` of it, no assignment to anything longer-lived, and no `catch` that
 *    stringifies the object holding it.
 * 3. **Never let the page reach any of it.** The overlay lives in a closed shadow root inside an
 *    element with a random name, so the page cannot query it, style it into invisibility, or
 *    dispatch a synthetic click at it — `event.isTrusted` is checked anyway, because a synthetic
 *    click is exactly how a page would try to trigger a fill the user did not ask for.
 *
 * # Identifier-first sign-ins
 *
 * Google, Microsoft and Okta ask for the username on one page and the password on the next. Both
 * pages are handled here, and neither of them weakens the three rules above: page one detects a
 * username box with no password box (`KsForms.detectIdentifierForm`) and asks for the **username
 * alone**, which is a fill that carries no secret; page two is an ordinary password fill that
 * asks the service worker which item this tab chose a moment ago, so the user is not made to pick
 * twice. Both still need the same click or the same ⌘\ as any other fill — the memory decides
 * *which* item, never *whether*. See ADR-0030.
 */

"use strict";

(function () {
  /** How long a "no match here" answer is believed before asking again. */
  const MATCH_TTL_MS = 20_000;

  /** A name the page cannot guess, so it cannot style or query the overlay. */
  const HOST_TAG = `ks-${Math.random().toString(36).slice(2, 10)}`;

  /**
   * The detected form on this document, refreshed as the page changes.
   *
   * One of two shapes, never both — see `forms.js` for why the two detectors are separate:
   *
   * * `{ kind: "login", password, username }` — a page with a password box, which is every page
   *   this extension has ever filled;
   * * `{ kind: "identifier", username }` — page one of an identifier-first sign-in, where the
   *   only thing that can be written is the username.
   */
  let form = null;

  /**
   * The field the icon is drawn next to, and the one ⌘\ aims at.
   *
   * @returns {HTMLInputElement | null}
   */
  function anchorField() {
    if (!form) return null;
    return form.kind === "identifier" ? form.username : form.password;
  }

  /** The last `match` answer: `{ at: number, origin: string, items: [] }`, or `null`. */
  let matched = null;

  /** The overlay host element, or `null`. */
  let overlay = null;

  /** Set while a request is in flight, so a double-click is one fill. */
  let busy = false;

  const page = () => KsOrigin.pageContext(window);

  // ---------------------------------------------------------------------------------------
  // Talking to the service worker
  // ---------------------------------------------------------------------------------------

  function send(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          // Reading `lastError` is what stops Chrome logging "Unchecked runtime.lastError" on
          // every message sent while the service worker is starting.
          const failed = chrome.runtime.lastError;
          if (failed || !response) {
            resolve({ ok: false, code: "INTERNAL", message: "kagisecure is not reachable." });
            return;
          }
          resolve(response);
        });
      } catch {
        resolve({ ok: false, code: "INTERNAL", message: "kagisecure is not reachable." });
      }
    });
  }

  /**
   * Ask which items apply here. Metadata only — this is safe to call without a user gesture, and
   * is the reason the icon can know whether it has anything to offer.
   */
  async function refreshMatches(force) {
    const context = page();
    if (!context) return null;
    if (!force && matched && Date.now() - matched.at < MATCH_TTL_MS) return matched;
    const result = await send({ kind: "match", page: context });
    if (!result.ok || result.reply.reply !== "matches") {
      matched = { at: Date.now(), origin: context.frame_origin || context.top_origin, items: [] };
      return matched;
    }
    matched = { at: Date.now(), origin: result.reply.origin, items: result.reply.items };
    return matched;
  }

  // ---------------------------------------------------------------------------------------
  // The overlay
  // ---------------------------------------------------------------------------------------

  /**
   * The in-field icon.
   *
   * A **closed** shadow root: `element.shadowRoot` is `null` from the page's side, so page script
   * cannot reach in to read it, restyle it or click it. The host element is positioned absolutely
   * in the document rather than inside the form, because a form with `overflow: hidden` would clip
   * a child and a page that re-renders its form would throw the icon away with it.
   */
  function ensureOverlay() {
    if (overlay && overlay.isConnected) return overlay;
    overlay = document.createElement(HOST_TAG);
    overlay.style.cssText = [
      "position:absolute",
      "z-index:2147483647",
      "margin:0",
      "padding:0",
      "border:0",
      "background:transparent",
      "pointer-events:auto",
    ].join(";");
    const root = overlay.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      button {
        all: unset;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 22px; height: 22px;
        border-radius: 5px;
        cursor: pointer;
        background: rgba(120,120,128,0.14);
        font: 13px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: #1c1c1e;
      }
      button:hover { background: rgba(120,120,128,0.26); }
      button:focus-visible { outline: 2px solid #0a84ff; outline-offset: 1px; }
      button[disabled] { opacity: 0.5; cursor: default; }
      @media (prefers-color-scheme: dark) {
        button { background: rgba(120,120,128,0.32); color: #f2f2f7; }
      }
      .menu {
        position: absolute; top: 26px; right: 0;
        min-width: 220px; max-width: 320px;
        background: Canvas; color: CanvasText;
        border: 1px solid rgba(120,120,128,0.35);
        border-radius: 8px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.18);
        padding: 4px;
        font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      .menu .row {
        all: unset; display: block; box-sizing: border-box;
        width: 100%; padding: 6px 8px; border-radius: 5px; cursor: pointer;
      }
      .menu .row:hover { background: rgba(10,132,255,0.14); }
      .menu .title { font-weight: 600; }
      .menu .sub { opacity: 0.65; font-size: 12px; }
      .menu .note { padding: 6px 8px; opacity: 0.7; }
    `;
    root.append(style);
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-label", "Fill with Kagisecure");
    button.setAttribute("title", "Fill with Kagisecure (⌘\\)");
    button.textContent = "\u{1F511}";
    button.addEventListener("click", onIconClick);
    root.append(button);
    overlay.__ksRoot = root;
    overlay.__ksButton = button;
    document.documentElement.append(overlay);
    return overlay;
  }

  function positionOverlay(field) {
    const host = ensureOverlay();
    const rect = field.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      host.style.display = "none";
      return;
    }
    host.style.display = "block";
    host.style.top = `${window.scrollY + rect.top + (rect.height - 22) / 2}px`;
    host.style.left = `${window.scrollX + rect.right - 26}px`;
  }

  function hideOverlay() {
    if (overlay) overlay.style.display = "none";
    closeMenu();
  }

  function closeMenu() {
    if (!overlay || !overlay.__ksRoot) return;
    const menu = overlay.__ksRoot.querySelector(".menu");
    if (menu) menu.remove();
  }

  function showMenu(children) {
    closeMenu();
    const menu = document.createElement("div");
    menu.className = "menu";
    menu.append(...children);
    overlay.__ksRoot.append(menu);
  }

  function note(text) {
    const el = document.createElement("div");
    el.className = "note";
    el.textContent = text;
    return el;
  }

  function itemRow(item, onPick) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "row";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = item.title;
    row.append(title);
    if (item.username) {
      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = item.username;
      row.append(sub);
    }
    row.addEventListener("click", () => onPick(item));
    return row;
  }

  // ---------------------------------------------------------------------------------------
  // Acting
  // ---------------------------------------------------------------------------------------

  /**
   * The icon was clicked.
   *
   * `isTrusted` is the gate: a synthetic `click` dispatched by page script is exactly how a page
   * would try to start a fill nobody asked for, and it is the one thing the browser can tell us
   * about a gesture that the page cannot forge.
   */
  async function onIconClick(event) {
    if (!event.isTrusted) return;
    event.preventDefault();
    event.stopPropagation();
    await offerFill();
  }

  /**
   * Which item this tab chose on page one of an identifier-first sign-in, if that is still true.
   *
   * The answer comes from the service worker, which keyed it on the tab id and the origin the
   * *browser* stamped on the request — neither of which this frame could have supplied. It is an
   * item id and nothing else; the content script still has to ask for the fill, the user still
   * has to click, and the app still applies every gate it applies to any other fill.
   *
   * @returns {Promise<string | null>}
   */
  async function recalledItemId() {
    const context = page();
    if (!context) return null;
    const result = await send({ kind: "recall", page: context });
    return result && result.ok && typeof result.itemId === "string" ? result.itemId : null;
  }

  /** Show what applies here, and fill it when there is exactly one thing it could be. */
  async function offerFill() {
    if (busy) return;
    busy = true;
    try {
      const answer = await refreshMatches(true);
      if (!answer || answer.items.length === 0) {
        showMenu([note("No kagisecure item is saved for this site.")]);
        return;
      }
      if (answer.items.length === 1) {
        await requestFill(answer.items[0]);
        return;
      }
      // Page two of an identifier-first sign-in: the user already said who they are, so filling
      // somebody *else* in would be worse than useless. If the remembered item is still one of
      // the matches, it is the answer; if it is not — the vault changed, the site moved — the
      // list is, exactly as before.
      const remembered = await recalledItemId();
      const continuing = remembered
        ? answer.items.find((item) => item.item_id === remembered)
        : null;
      if (continuing) {
        await requestFill(continuing);
        return;
      }
      showMenu(
        answer.items.map((item) =>
          itemRow(item, (picked) => {
            closeMenu();
            requestFill(picked);
          }),
        ),
      );
    } finally {
      busy = false;
    }
  }

  /** Ask the app for one item's values, and write them. */
  async function requestFill(item) {
    const context = page();
    if (!context || !form) return;
    // The identifier-first page asks for the username and nothing else, which is what makes the
    // app serve it without an approval sheet — and what makes the service worker remember the
    // choice for this tab. See ADR-0030.
    const fields =
      form.kind === "identifier"
        ? ["username"]
        : form.username
          ? ["username", "password"]
          : ["password"];
    setBusy(true);
    const result = await send({
      kind: "fill",
      page: context,
      itemId: item.item_id,
      fields,
    });
    setBusy(false);

    if (!result.ok) {
      showMenu([note(friendly(result))]);
      return;
    }
    applyFill(result.reply);
    closeMenu();
    // Offer the second, separate action only when this item has one — and only as an offer.
    if (item.has_totp) offerTotp(item);
  }

  /**
   * Write the values into the fields.
   *
   * The one function in this extension that sees a password. It takes the reply, writes it, and
   * returns; the reply is not stored, not logged, and not passed anywhere else. The parameter goes
   * out of scope on return, which is as close to "dropped" as JavaScript gets.
   *
   * @param {{ username?: string, password?: string }} reply
   */
  function applyFill(reply) {
    if (!form) return;
    if (form.username && typeof reply.username === "string") {
      const ok = KsForms.setFieldValue(form.username, reply.username);
      // On an identifier-first page the username *is* the fill, so it takes the focus the
      // password would otherwise have taken — the next thing the user does is press Next.
      if (ok && form.kind === "identifier") form.username.focus();
    }
    if (form.kind !== "identifier" && typeof reply.password === "string") {
      const ok = KsForms.setFieldValue(form.password, reply.password);
      if (ok) form.password.focus();
    }
  }

  /** The TOTP action: a second, explicit click, never automatic. */
  function offerTotp(item) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = "Copy one-time code";
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = item.title;
    button.append(title, sub);
    button.addEventListener("click", async (event) => {
      if (!event.isTrusted) return;
      const context = page();
      if (!context) return;
      const result = await send({ kind: "totp", page: context, itemId: item.item_id });
      if (!result.ok) {
        showMenu([note(friendly(result))]);
        return;
      }
      applyTotp(result.reply.code);
    });
    showMenu([button]);
  }

  /**
   * Put the code where it is useful: into a detected one-time-code field if the page has one,
   * otherwise onto the clipboard.
   *
   * The clipboard write uses `navigator.clipboard`, which needs the transient user activation the
   * click just provided. The app clears its own clipboard copies after a delay
   * ([ADR-0017](../../docs/decisions/0017-quick-access-hotkey-and-pasteboard.md)); a page's
   * clipboard is the browser's and we cannot, which is recorded as a residual risk in the
   * threat-model addendum.
   *
   * @param {string} code
   */
  function applyTotp(code) {
    const field = KsForms.detectOtpField(document);
    if (field) {
      if (KsForms.setFieldValue(field, code)) {
        field.focus();
        closeMenu();
        return;
      }
    }
    navigator.clipboard
      .writeText(code)
      .then(() => showMenu([note("One-time code copied. It expires in under a minute.")]))
      .catch(() =>
        showMenu([note("Could not copy the code. Open Kagisecure and copy it there.")]),
      );
  }

  function setBusy(value) {
    if (overlay && overlay.__ksButton) overlay.__ksButton.disabled = value;
  }

  /** Turn an error code into a sentence, without ever echoing a value. */
  function friendly(result) {
    switch (result.code) {
      case "VAULT_LOCKED":
        return "Kagisecure is locked. Unlock it and try again.";
      case "USER_DENIED":
        return "You declined this fill.";
      case "APPROVAL_TIMEOUT":
        return "Nobody answered the approval in Kagisecure.";
      case "ORIGIN_MISMATCH":
        return "That item is not saved for this site, so kagisecure refused to fill it.";
      case "NO_MATCH":
        return "No kagisecure item applies here.";
      case "UNKNOWN_EXTENSION":
      case "UNTRUSTED_HOST":
        return "Kagisecure does not recognize this browser connection. Re-run setup in the app.";
      default:
        return result.message || "Kagisecure could not complete that.";
    }
  }

  // ---------------------------------------------------------------------------------------
  // Watching the page
  // ---------------------------------------------------------------------------------------

  async function refreshForm() {
    // The password-anchored detector first, always: a page with a password box is a login form
    // and is filled the way login forms have always been filled here. Only a page with no usable
    // password field at all is offered to the identifier-first detector, which is what makes the
    // two mutually exclusive rather than merely ordered.
    const login = KsForms.detectLoginForm(document);
    const found = login
      ? { kind: "login", password: login.password, username: login.username }
      : identifierForm();
    form = found;
    if (!found) {
      hideOverlay();
      return;
    }
    const answer = await refreshMatches(false);
    // The icon appears only where there is something behind it. A key on a field with nothing
    // saved for the site is an invitation to a dead end.
    if (!answer || answer.items.length === 0) {
      hideOverlay();
      return;
    }
    positionOverlay(
      document.activeElement === found.username ? found.username : anchorField(),
    );
  }

  /** The identifier-first form on this page, in the shape `form` holds. */
  function identifierForm() {
    const found = KsForms.detectIdentifierForm(document);
    return found ? { kind: "identifier", username: found.username } : null;
  }

  function onFocusIn(event) {
    if (!form) return;
    const target = event.target;
    if (target === form.password || target === form.username) {
      positionOverlay(target);
    }
  }

  function onDocumentClick(event) {
    // Anywhere outside the overlay closes the menu. `composedPath` sees through the shadow root
    // for our own clicks and stops at the host for the page's.
    if (!overlay) return;
    const path = event.composedPath ? event.composedPath() : [];
    if (!path.includes(overlay)) closeMenu();
  }

  /**
   * Requests from the extension's own UI.
   *
   * Everything the popup wants to know about *this page* is answered here rather than in the
   * service worker, and that is a security decision, not a convenience one: the origin a request
   * is judged against must be the one **the browser stamps on the sender**, and only a content
   * script has one. A popup asking the worker directly would be asking about
   * `chrome-extension://…`, and the only way to turn that into a page origin would be to read tab
   * URLs — a permission this extension deliberately does not request.
   */
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || typeof message.kind !== "string") return false;
    switch (message.kind) {
      case "shortcut-fill":
        runShortcut();
        sendResponse({ ok: true });
        return false;
      case "matches-please":
        // Metadata only: titles and usernames, which the popup renders as a list.
        refreshMatches(true).then((answer) =>
          sendResponse({
            ok: true,
            origin: answer ? answer.origin : null,
            items: answer ? answer.items : [],
          }),
        );
        return true;
      case "totp-please":
        // The code is handled *here* — written into a detected field, or copied — and never
        // returned to the popup. One fewer context that sees it.
        runTotp(message.itemId).then(sendResponse);
        return true;
      default:
        return false;
    }
  });

  /** Fetch and apply a one-time code for `itemId`, reporting only whether it worked. */
  async function runTotp(itemId) {
    const context = page();
    if (!context) return { ok: false, message: "This page has no usable origin." };
    const result = await send({ kind: "totp", page: context, itemId });
    if (!result.ok) return { ok: false, message: friendly(result) };
    applyTotp(result.reply.code);
    return { ok: true };
  }

  /**
   * The ⌘\ handler.
   *
   * Handled here rather than through `chrome.commands`, because Chrome's command key whitelist has
   * no entry for a backslash — a `commands` manifest naming `\` produces a shortcut that never
   * fires, with no error anywhere. See the note at the bottom of `background.js`.
   *
   * `isTrusted` is the gate. A `KeyboardEvent` the page dispatches has `isTrusted === false`, so a
   * page cannot press this on the user's behalf; only a real key can. Registered in the **capture**
   * phase on `window` so that a page which stops propagation on its own `keydown` handlers does not
   * silently eat the user's shortcut.
   */
  function onKeyDown(event) {
    if (!event.isTrusted) return;
    if (event.key !== "\\") return;
    // ⌘ on macOS; Ctrl elsewhere, so the same file works on a Linux or Windows Chromium.
    if (!(event.metaKey || event.ctrlKey)) return;
    if (event.altKey || event.shiftKey) return;
    event.preventDefault();
    event.stopPropagation();
    runShortcut();
  }

  function runShortcut() {
    if (!form) {
      refreshForm().then(() => {
        if (form) offerFill();
      });
      return;
    }
    positionOverlay(anchorField());
    offerFill();
  }

  // Debounced, because a single-page app can mutate the DOM hundreds of times a second and
  // `detectLoginForm` walks the document.
  let pendingScan = null;
  function scheduleScan() {
    if (pendingScan) return;
    pendingScan = setTimeout(() => {
      pendingScan = null;
      refreshForm();
    }, 250);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scheduleScan, { once: true });
  } else {
    scheduleScan();
  }

  new MutationObserver(scheduleScan).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
  window.addEventListener("keydown", onKeyDown, true);
  document.addEventListener("focusin", onFocusIn, true);
  document.addEventListener("click", onDocumentClick, true);
  window.addEventListener("scroll", () => form && positionOverlay(anchorField()), {
    passive: true,
  });
  window.addEventListener("resize", () => form && positionOverlay(anchorField()), {
    passive: true,
  });
})();
