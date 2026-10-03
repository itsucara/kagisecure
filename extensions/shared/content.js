/**
 * The content script: an icon in the field, a keyboard shortcut, and a write.
 *
 * # The three rules this file exists to keep
 *
 * 1. **Never fill on page load.** There is no code path from "a form appeared" to "a value was
 *    requested". The only two things in the page that ask the app for a value are the click
 *    handler on the icon and the ⌘\ handler, and both are reached only through a trusted gesture.
 *    "Trusted" means "not dispatched by page script"; it does not mean "made by a person" —
 *    DevTools-protocol and OS-injected input are trusted too — so the person is established in the
 *    app, by a Touch ID, login-password or Apple Watch check on every fill that crosses a secret
 *    (ADR-0037). What *does* happen automatically is a `match` — titles and usernames, no values —
 *    so the icon knows whether to appear at all. The third way a value is asked for starts outside
 *    the page altogether: an agent's `deliver`, which the service worker sends only after a human
 *    approved that fill in the app with a biometric (see "Agent-requested fills" below).
 * 2. **Never log a value.** The password exists in this file inside exactly one function,
 *    `applyFill`, as a parameter that is written into a field and then goes out of scope. There is
 *    no `console.log` of it, no assignment to anything longer-lived, and no `catch` that
 *    stringifies the object holding it. The agent path writes through the same function.
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
 *
 * # Agent-requested fills
 *
 * An agent that is driving this browser can ask the app to fill a saved login into the tab in
 * front (ADR-0036). This file's part is two answers, both from the **top frame only**:
 *
 * * **`agent-locate`** — "what is here?" Answered with a fresh message to the service worker, so
 *   the browser stamps it, carrying only whether the document is visible and which of username,
 *   password and one-time-code fields the same detectors the icon uses found. No value, and
 *   nothing that names a field.
 * * **`agent-deliver`** — "the human approved; fill it." Sent by the service worker to exactly the
 *   document that reported. The detectors and `stillWritable` run again from scratch, the grant is
 *   redeemed with an `agent-fill` message the browser stamps again, the value is written by
 *   `applyFill` — all of it or none of it, and a password only into a real `type=password` input
 *   re-checked immediately before the write — and the outcome is reported as field **names** and
 *   a reason. The content script writes and stops; the agent presses the page's own button.
 *
 * Three shapes of delivery, told apart only by what the app's reply carries — the content script
 * holds no memory of a grant between documents, and never touches the human path's tab memory:
 *
 * * **A login** — `filled` with a username, a password or both, written all or nothing.
 * * **Identifier-first** — page one reports a username and no password; the app's reply carries
 *   the username alone, which is all that is written. When the next page loads the app starts
 *   again with a new `locate` and a new `deliver`, and that document is filled as a login. The app
 *   runs the two-step flow; here, each step is an ordinary delivery.
 * * **A one-time code** — `totp_code`, written into the field `KsForms.detectOtpField` detects,
 *   re-detected in the same task as the write, or not at all. Never onto the clipboard: that is
 *   the human path's fallback (`applyTotp`), and this path does not call it.
 *
 * After an agent fill writes a password, a **tripwire** watches that input for ten seconds: if
 * its `type` stops being `password`, the value is cleared and the app is told `UNMASKED`. It is
 * hygiene against the crudest read, not a guard (ADR-0036 §8.3), and a human fill never arms it.
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
   * `isTrusted` keeps out **page script**: a synthetic `click` dispatched by the page is exactly
   * how a page would try to start a fill nobody asked for, and the page cannot forge the flag.
   *
   * It is not proof that a **person** clicked. Input synthesized over the DevTools protocol — what
   * a browser-automation agent, or this repo's own Playwright suite, sends — is trusted, and so is
   * input injected at the OS level. So nothing here is the security boundary for a secret: every
   * fill that carries a password or a one-time code needs a fresh Touch ID, login-password or
   * Apple Watch check in the app, which a program cannot supply (ADR-0037). This check only stops
   * the page from raising that prompt at will.
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
    applyFill(result.reply, form);
    closeMenu();
    // Offer the second, separate action only when this item has one — and only as an offer.
    if (item.has_totp) offerTotp(item);
  }

  /**
   * Write the values into the fields.
   *
   * The one function in this extension that sees a password. It takes the reply, writes it, and
   * returns; the reply is not stored, not logged, and not passed anywhere else. The parameter goes
   * out of scope on return, which is as close to "dropped" as JavaScript gets. What it returns is
   * field **names** and a reason, never a value.
   *
   * A human fill writes whatever still can be written. An agent fill passes `{ whole: true }`:
   * every field the reply carries must still be writable, checked in the same task as the writes
   * so no page script runs in between, or nothing is written at all — the human approved that
   * form, not whatever part of it survived.
   *
   * @param {{ username?: string, password?: string }} reply
   * @param {{ kind: string, username?: Element | null, password?: Element } | null} target
   * @param {{ whole?: boolean }} [options]
   * @returns {{ written: string[], failure: string | null }}
   */
  function applyFill(reply, target, options) {
    const outcome = { written: [], failure: null };
    const fail = (why) => {
      if (!outcome.failure) outcome.failure = why;
    };
    if (!target) {
      fail("FORM_CHANGED");
      return outcome;
    }
    const wantsUsername = typeof reply.username === "string";
    const wantsPassword = typeof reply.password === "string";
    const usernameWritable = !!target.username && stillWritable(target.username);
    const passwordWritable = target.kind !== "identifier" && stillWritable(target.password, true);
    if (
      options &&
      options.whole &&
      ((wantsUsername && !usernameWritable) || (wantsPassword && !passwordWritable))
    ) {
      fail("NOT_WRITABLE");
      return outcome;
    }
    if (wantsUsername && usernameWritable) {
      if (KsForms.setFieldValue(target.username, reply.username)) {
        outcome.written.push("username");
        // On an identifier-first page the username *is* the fill, so it takes the focus the
        // password would otherwise have taken — the next thing the user does is press Next.
        if (target.kind === "identifier") target.username.focus();
      } else {
        fail("WRITE_REJECTED");
      }
    }
    if (wantsPassword && passwordWritable) {
      if (KsForms.setFieldValue(target.password, reply.password)) {
        outcome.written.push("password");
        target.password.focus();
      } else {
        fail("WRITE_REJECTED");
      }
    }
    return outcome;
  }

  /**
   * Whether the field detection picked is still the field a value may be written into.
   *
   * Detection and the write are separated by the approval sheet, which the human may sit on for
   * seconds, and the page owns every millisecond of that. It can retype `input#p` from `password`
   * to `text` — and then the password is rendered in plain sight — or make it `readonly`,
   * `disabled` or zero-size, none of which requires any privilege it does not already have over
   * its own DOM. So the element is re-examined here, immediately before the write, against the
   * same rules detection applied.
   *
   * Refusing is the right answer rather than re-detecting: the page changed the form under the
   * user, the approval they gave was for the form they were shown, and retrying costs one click.
   *
   * @param {Element} field
   * @param {boolean} [mustBePassword] Whether the field has to still be a real password input.
   * @returns {boolean}
   */
  function stillWritable(field, mustBePassword) {
    if (!field || !field.isConnected) return false;
    if (field.ownerDocument !== document) return false;
    if (mustBePassword && !isPasswordInput(field)) return false;
    return KsForms.isFillable(field);
  }

  /**
   * Whether `field` is a `type=password` input by both the property and the attribute, so a page
   * cannot pass by changing only the one a given check happens to read.
   *
   * @param {Element} field
   * @returns {boolean}
   */
  function isPasswordInput(field) {
    const attr = field.getAttribute && field.getAttribute("type");
    if (String(field.type || attr || "").toLowerCase() !== "password") return false;
    if (attr !== null && attr !== undefined && attr.toLowerCase() !== "password") return false;
    return true;
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
   * The human path only. An agent's code is written by `applyAgentCode`, which has no clipboard
   * branch at all (ADR-0036 §7.4).
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
      case "AUDIT_UNAVAILABLE":
        // Nothing was filled: a value leaves the app only once its audit record is saved, and
        // this one could not be (ADR-0040). The app says why; trying again later can work.
        return (
          "Kagisecure could not save this fill to its audit log, so nothing was filled. " +
          "Open Kagisecure to see why, then try again."
        );
      case "VAULT_CONFLICT":
        // The vault file on disk no longer matches the unlocked vault (restored from a backup,
        // replaced, or removed) and the app is refusing every request until a person resolves it
        // there. Retrying here cannot help, unlike VAULT_LOCKED or AUDIT_UNAVAILABLE.
        return "Kagisecure needs your attention to continue. Open Kagisecure to resolve it.";
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
      case "agent-origin":
        // Which origin this top frame is on, so the service worker can pick a tab for an agent
        // fill. A hint only: the report that follows is stamped by the browser.
        sendResponse({ origin: isTopFrame() ? location.origin : null });
        return false;
      case "agent-locate":
        answerLocate(message.probeId).then(sendResponse, () => sendResponse({ ok: false }));
        return true;
      case "agent-deliver":
        answerDelivery(message.grantId).then(sendResponse, () => sendResponse({ ok: false }));
        return true;
      default:
        return false;
    }
  });

  // ---------------------------------------------------------------------------------------
  // Agent-requested fills (ADR-0036)
  // ---------------------------------------------------------------------------------------

  /**
   * How long a delivery waits for the document to become visible before filling anyway.
   *
   * Since the amendment of 2026-10-03 a hidden document is still filled — an agent may work in a
   * background tab — but a window the approval sheet covered usually becomes visible again a
   * moment after the sheet closes, and filling a visible page is what the person expects to see.
   */
  const AGENT_VISIBILITY_WAIT_MS = 1_000;

  /** Whether this is the top frame. The service worker addresses frame 0; this is the second lock. */
  function isTopFrame() {
    try {
      return window === window.top;
    } catch {
      return false;
    }
  }

  /**
   * Whether the document is visible, read in this isolated world, where page script cannot
   * redefine `visibilityState`.
   */
  function isVisible() {
    return document.visibilityState === "visible";
  }

  /** Resolve `true` as soon as the document is visible, or with the state after `timeoutMs`. */
  function becomesVisible(timeoutMs) {
    if (isVisible()) return Promise.resolve(true);
    return new Promise((resolve) => {
      let timer = null;
      const finish = () => {
        clearTimeout(timer);
        document.removeEventListener("visibilitychange", onChange);
        resolve(isVisible());
      };
      // The event is only a cue to look again: page script can dispatch a fake one, and what is
      // believed is the state read afterwards.
      const onChange = () => {
        if (isVisible()) finish();
      };
      timer = setTimeout(finish, timeoutMs);
      document.addEventListener("visibilitychange", onChange);
    });
  }

  /**
   * How long the tripwire watches a password an agent fill wrote (ADR-0036 §8.3).
   *
   * Long enough for a "show password" click that follows the fill, short enough that a human who
   * later reveals their own password on purpose is not second-guessed.
   */
  const AGENT_TRIPWIRE_MS = 10_000;

  /**
   * What an agent fill would write into, detected afresh: a login form, or failing that the
   * username box of an identifier-first page — the same two detectors, in the same order, as the
   * icon — plus the one-time-code field, if the page has one. Never the cached `form`, which is as
   * old as the last debounced scan.
   *
   * `{ kind: "login" | "identifier" | "code", username?, password?, code }`, or `null` when there
   * is nothing to write into at all. A box both the identifier and the code detector claim is a
   * code box: a username is never written where the page asks for a code.
   */
  function detectAgentTarget() {
    const code = KsForms.detectOtpField(document);
    const login = KsForms.detectLoginForm(document);
    if (login) {
      return { kind: "login", password: login.password, username: login.username, code };
    }
    const identifier = identifierForm();
    if (identifier && identifier.username !== code) return { ...identifier, code };
    return code ? { kind: "code", code } : null;
  }

  /**
   * Which fields are there, as three booleans. With `writable`, a field counts only if a value
   * could be written into it right now — for the password, a real `type=password` input.
   */
  function foundIn(target, writable) {
    const username = !!(target && target.username) && (!writable || stillWritable(target.username));
    const password =
      !!(target && target.kind === "login" && target.password) &&
      (!writable || stillWritable(target.password, true));
    const oneTimeCode = !!(target && target.code) && (!writable || stillWritable(target.code));
    return { username, password, one_time_code: oneTimeCode };
  }

  /**
   * Write an agent's one-time code into the page's code field, and nowhere else.
   *
   * Deliberately not `applyTotp`: that function falls back to the clipboard when the page has no
   * code field, and the clipboard is readable by every process the user runs — the agent's
   * included — so an agent's code goes into the detected field or is not written at all
   * (ADR-0036 §7.4). The field is re-detected here, in the same task as the write, and must still
   * be the one the delivery found: a page that swapped its code box while the app answered gets
   * nothing.
   *
   * @param {unknown} code
   * @param {{ code?: Element | null } | null} target
   * @returns {{ written: string[], failure: string | null }}
   */
  function applyAgentCode(code, target) {
    const field = target ? target.code : null;
    if (typeof code !== "string" || !field || !stillWritable(field)) {
      return { written: [], failure: "NOT_WRITABLE" };
    }
    if (KsForms.detectOtpField(document) !== field) {
      return { written: [], failure: "FORM_CHANGED" };
    }
    if (!KsForms.setFieldValue(field, code)) return { written: [], failure: "WRITE_REJECTED" };
    field.focus();
    return { written: ["one_time_code"], failure: null };
  }

  /**
   * The tripwire (ADR-0036 §8.3): for ten seconds after an agent fill wrote `field`, clear it if
   * its `type` stops being `password` — the site's own "show password" control, clicked — and call
   * `onUnmasked` once.
   *
   * Hygiene, not a guard: an agent with script access reads `input.value` without touching the
   * type, and this does nothing about that. What it catches is the screenshot agent that clicks
   * the eye icon. Armed only from the agent path, never by a human fill. It holds the element and
   * never the value, stops at the first trip, after ten seconds, or when the page is left.
   *
   * @param {Element} field
   * @param {() => void} onUnmasked
   */
  function armTripwire(field, onUnmasked) {
    let done = false;
    let timer = null;
    let observer = null;
    const stop = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (observer) observer.disconnect();
      window.removeEventListener("pagehide", stop);
    };
    const check = () => {
      if (done || isPasswordInput(field)) return;
      stop();
      KsForms.setFieldValue(field, "");
      onUnmasked();
    };
    // The attribute is what a `type` change reflects to, whether the page set the attribute or
    // the property. The observer is this isolated world's, which page script cannot replace.
    observer = new MutationObserver(check);
    observer.observe(field, { attributes: true, attributeFilter: ["type"] });
    timer = setTimeout(stop, AGENT_TRIPWIRE_MS);
    window.addEventListener("pagehide", stop);
    // A page that flipped the type from its own `input` handler, during the write, did it before
    // there was anything observing.
    check();
  }

  /** `agent-locate`: report what is here, through the service worker, which stamps the sender. */
  async function answerLocate(probeId) {
    if (!isTopFrame()) return { ok: false };
    const result = await send({
      kind: "agent-report",
      probeId,
      visible: isVisible(),
      found: foundIn(detectAgentTarget(), false),
    });
    return { ok: result.ok === true };
  }

  /**
   * `agent-deliver`: re-check, redeem, write, report.
   *
   * Every failure before the grant is redeemed is reported at once, so the agent hears
   * `NO_MATCHING_TAB` now rather than after the grant has expired. A refusal from the app needs no
   * report: the app made it.
   */
  async function answerDelivery(grantId) {
    if (!isTopFrame()) return { ok: false };
    const report = (written, failure) =>
      send({ kind: "agent-fill-outcome", grantId, written, failure });

    // A background tab is a fine target (ADR-0036 amendment of 2026-10-03): give a covered
    // window a moment to come back, but fill whether or not it does.
    await becomesVisible(AGENT_VISIBILITY_WAIT_MS);
    const target = detectAgentTarget();
    if (!target) {
      await report([], "FORM_CHANGED");
      return { ok: true };
    }
    const found = foundIn(target, true);
    if (!found.username && !found.password && !found.one_time_code) {
      await report([], "NOT_WRITABLE");
      return { ok: true };
    }

    // What the grant is for is the app's to say, in the reply: a login (both fields, or only the
    // password on page two of an identifier-first sign-in), the username alone (page one), or a
    // one-time code. Whatever it carries must fit this document, all of it, or nothing is written.
    let result = await send({ kind: "agent-fill", grantId, visible: isVisible(), found });
    let outcome;
    let watch = null;
    if (!result.ok) {
      outcome = null;
    } else if (!result.reply) {
      outcome = { written: [], failure: "NOT_WRITABLE" };
    } else if (result.reply.reply === "filled") {
      outcome = applyFill(result.reply, target, { whole: true });
      if (outcome.written.includes("password")) watch = target.password;
    } else if (result.reply.reply === "totp_code") {
      outcome = applyAgentCode(result.reply.code, target);
    } else {
      outcome = { written: [], failure: "NOT_WRITABLE" };
    }
    // Dropped before anything else is awaited, so no suspended frame is still holding the reply.
    result = null;
    if (!outcome) return { ok: true };
    const reported = report(outcome.written, outcome.failure);
    // Armed in the same task as the write, so no page script runs between the two; its report
    // waits for the first one, which the service worker has to have counted before it accepts a
    // second.
    if (watch) {
      armTripwire(watch, () => {
        reported.then(() => report(["password"], "UNMASKED"));
      });
    }
    await reported;
    return { ok: true };
  }

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
   * `isTrusted` keeps out page script: a `KeyboardEvent` the page dispatches has
   * `isTrusted === false`, so a page cannot press this on the user's behalf. A key press synthesized
   * over the DevTools protocol or injected at the OS level *is* trusted, though, so this is not
   * what stands between an automation agent and a password — the app's per-fill Touch ID check is
   * (ADR-0037). Registered in the **capture** phase on `window` so that a page which stops
   * propagation on its own `keydown` handlers does not silently eat the user's shortcut.
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
