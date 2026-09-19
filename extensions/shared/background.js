/**
 * The service worker: the extension's only route to the app, and the only place a value is ever
 * held — for the length of one `sendResponse`.
 *
 * # Why the native channel lives here and not in the content script
 *
 * Neither `chrome.runtime.connectNative` nor `chrome.runtime.sendNativeMessage` is available to
 * content scripts, which is the platform doing the right thing: a content script shares a document
 * with the page's own JavaScript, and a page that found a way to reach the channel would be
 * talking to the vault. So the channel is here, in the extension's own process (`native.js`), and
 * content scripts reach it only through `chrome.runtime.sendMessage` — which carries a request and
 * returns one answer, with the sender's tab and frame stamped on it by the browser rather than
 * claimed by the caller.
 *
 * # One file, two browsers
 *
 * Everything in this file is identical in Chrome and Safari. The transport underneath it is not,
 * and that difference is confined to `native.js` behind `KsNative.call` — see its header for the
 * table.
 *
 * # What this file stores
 *
 * Nothing that survives it, and nothing that is a secret. There is no `chrome.storage` call
 * anywhere in this extension — not for a value, not for a URL, not for a match. The
 * connected/locked flag the popup renders lives in `native.js`; the per-tab memory of an
 * identifier-first sign-in lives in `tabmemory.js` and holds an item id, an origin and a deadline
 * (see that file's header for why none of those is a secret). Both die with the service worker.
 * Every answer that carries a value is forwarded to exactly one `sendResponse` and then dropped.
 *
 * The roadmap's criterion is "no secret value is held by the extension's own storage at rest".
 * This file makes it true by having no storage at all, which is a shorter thing to check.
 */

"use strict";

importScripts("origin.js", "tabmemory.js", "native.js");

/** Say hello if this connection has not yet, so every other call has a session behind it. */
const ensureHello = () => KsNative.ensureHello();

/** The vault's lock state right now, not as of the last handshake. */
const refreshState = () => KsNative.refreshState();

/** Send one request to the app and resolve with its reply body. */
const call = (body) => KsNative.call(body);

/**
 * The page context a request may use.
 *
 * **The frame's own origin is taken from the browser, not from the message.** `sender.origin` and
 * `sender.frameId` are stamped by Chrome; a content script in a compromised page could otherwise
 * claim to be anywhere. The content script's own `page_context` is used only for the *top* origin,
 * which the browser does not hand us here and which the app treats as a claim either way — a page
 * that lies about its top origin can only make the app's iframe policy stricter, never looser,
 * because the frame origin it is compared against is the trusted one.
 *
 * @param {chrome.runtime.MessageSender} sender
 * @param {{ top_origin?: string, frame_origin?: string | null } | undefined} claimed
 * @returns {{ top_origin: string, frame_origin: string | null } | null}
 */
function trustedPageContext(sender, claimed) {
  const real = KsOrigin.originOf(sender && sender.origin ? sender.origin : sender && sender.url);
  if (!real) return null;
  const isTopFrame = sender && sender.frameId === 0;
  if (isTopFrame) return { top_origin: real, frame_origin: null };
  const claimedTop =
    claimed && typeof claimed.top_origin === "string"
      ? KsOrigin.originOf(claimed.top_origin)
      : null;
  return { top_origin: claimedTop || real, frame_origin: real };
}

/** The requests the socket listener below answers. Anything else falls through to the relay. */
const DIRECT = new Set(["status", "match", "fill", "totp", "recall"]);

/**
 * Whether a fill request names the username and nothing else.
 *
 * The one shape that creates a tab memory, and the one the app serves without an approval sheet
 * (ADR-0030). Everything else — including a request with no `fields` at all, which the app reads
 * as both — is a fill that can carry a password.
 *
 * @param {unknown} fields
 * @returns {boolean}
 */
function isUsernameOnly(fields) {
  return Array.isArray(fields) && fields.length === 1 && fields[0] === "username";
}

/**
 * The tab a content-script message came from, or `null`.
 *
 * `sender.tab` is stamped by the browser on a message from a content script and is absent on one
 * from the popup or another extension page, so this is both the identifier and the check that the
 * caller is a page rather than our own UI. It needs no `tabs` permission — the id is not the URL.
 *
 * @param {chrome.runtime.MessageSender} sender
 * @returns {number | null}
 */
function tabIdOf(sender) {
  return sender && sender.tab && typeof sender.tab.id === "number" ? sender.tab.id : null;
}

// A tab that has gone away remembers nothing. `onRemoved` carries the id and nothing else, which
// is all this needs and is why it costs no permission.
chrome.tabs.onRemoved.addListener((tabId) => {
  KsTabMemory.forget(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Two listeners share this event. A listener that answered messages it does not own would
  // shadow the other one, so each checks its own set and returns `false` for everything else —
  // `false` means "not mine", and Chrome then offers the message to the next listener.
  if (!message || typeof message.kind !== "string" || !DIRECT.has(message.kind)) return false;

  (async () => {
    switch (message.kind) {
      case "status": {
        // The one caller that wants the truth rather than a session: see `refreshState`.
        const state = await refreshState();
        // A vault that is no longer unlocked takes the tab memories with it, the same way it
        // takes the app's fill leases. The popup polls this on every open, so a lock is noticed
        // without a listener for an event Chrome does not have.
        if (state.status !== "ready") KsTabMemory.forgetAll();
        sendResponse({ ok: true, state });
        return;
      }
      case "match": {
        const state = await ensureHello();
        if (state.status !== "ready") {
          KsTabMemory.forgetAll();
          sendResponse({ ok: false, code: "VAULT_LOCKED", message: state.detail });
          return;
        }
        const page = trustedPageContext(sender, message.page);
        if (!page) {
          sendResponse({ ok: false, code: "PROTOCOL", message: "This page has no usable origin." });
          return;
        }
        // A `match` is the first thing a content script asks on a new document, which makes it
        // the moment the worker learns that a tab has navigated — without the `tabs` permission
        // it has no other way to find out. `recall` drops an entry whose origin no longer
        // applies, so calling it for its effect is how "navigated away" becomes "forgotten".
        //
        // Top frame only: a cross-origin iframe asks about *its* origin, and letting an ad frame
        // on page two clear the memory the top frame made on page one would be a bug on the safe
        // side, but a bug.
        const tabId = tabIdOf(sender);
        if (tabId !== null && page.frame_origin === null) {
          KsTabMemory.recall(tabId, page.top_origin, Date.now());
        }
        const reply = await call({ ask: "match", page });
        sendResponse(toResult(reply));
        return;
      }
      case "fill": {
        const state = await ensureHello();
        if (state.status !== "ready") {
          KsTabMemory.forgetAll();
          sendResponse({ ok: false, code: "VAULT_LOCKED", message: state.detail });
          return;
        }
        const page = trustedPageContext(sender, message.page);
        if (!page) {
          sendResponse({ ok: false, code: "PROTOCOL", message: "This page has no usable origin." });
          return;
        }
        const reply = await call({
          ask: "fill",
          page,
          item_id: message.itemId,
          fields: message.fields,
        });
        // The only thing kept from a fill is *which item*, and only for the identifier-first
        // case, and only for a minute. The id and the origin are taken from what the app was
        // actually asked — the origin in particular is the browser's, from `trustedPageContext`,
        // never the page's claim.
        const tabId = tabIdOf(sender);
        if (tabId !== null && reply && reply.reply === "filled") {
          if (isUsernameOnly(message.fields)) {
            KsTabMemory.remember(
              tabId,
              message.itemId,
              page.frame_origin || page.top_origin,
              Date.now(),
            );
          } else {
            // Page two happened. Whatever the memory was for is done with.
            KsTabMemory.forget(tabId);
          }
        }
        // Forwarded once, to the caller that asked. Nothing is kept.
        sendResponse(toResult(reply));
        return;
      }
      case "recall": {
        // Which item this tab picked on page one, if that is still true — no app round trip, no
        // value, and nothing the content script could have told us instead: the tab id and the
        // origin are both the browser's.
        const tabId = tabIdOf(sender);
        const page = trustedPageContext(sender, message.page);
        if (tabId === null || !page) {
          sendResponse({ ok: true, itemId: null });
          return;
        }
        const entry = KsTabMemory.recall(
          tabId,
          page.frame_origin || page.top_origin,
          Date.now(),
        );
        sendResponse({ ok: true, itemId: entry ? entry.itemId : null });
        return;
      }
      case "totp": {
        const state = await ensureHello();
        if (state.status !== "ready") {
          KsTabMemory.forgetAll();
          sendResponse({ ok: false, code: "VAULT_LOCKED", message: state.detail });
          return;
        }
        const page = trustedPageContext(sender, message.page);
        if (!page) {
          sendResponse({ ok: false, code: "PROTOCOL", message: "This page has no usable origin." });
          return;
        }
        const reply = await call({ ask: "totp", page, item_id: message.itemId });
        sendResponse(toResult(reply));
        return;
      }
      default:
        // Unreachable: `DIRECT` is the same list as the arms above. Kept so that adding a name to
        // one and not the other fails loudly rather than silently.
        sendResponse({ ok: false, code: "PROTOCOL", message: "Unknown request." });
    }
  })().catch((e) => {
    // Never let an exception's message carry a reply body with it.
    sendResponse({ ok: false, code: "INTERNAL", message: e && e.name ? e.name : "failed" });
  });

  // `true` keeps the message channel open for the async `sendResponse` above.
  return true;
});

/** Normalize an app reply into the `{ ok, … }` shape the content script and popup branch on. */
function toResult(reply) {
  if (!reply || typeof reply.reply !== "string") {
    return { ok: false, code: "INTERNAL", message: "No answer from kagisecure." };
  }
  if (reply.reply === "error") {
    return { ok: false, code: reply.code, message: reply.message };
  }
  return { ok: true, reply };
}

/**
 * The keyboard shortcut is **not** a `chrome.commands` entry, and that is not an oversight.
 *
 * Chrome's `commands` API accepts a fixed set of keys — letters, digits, a handful of named keys —
 * and `\\` is not among them. `⌘\\` therefore cannot be registered as a browser-level command at
 * all, and a manifest that tries produces a shortcut that silently never fires. So the shortcut is
 * handled by the content script, on a capture-phase `keydown` with `event.isTrusted`.
 *
 * What that costs, stated plainly:
 *
 * * it works only when focus is inside a page, not in the browser's own chrome;
 * * a page that swallows `keydown` at the window level in the capture phase before us could stop
 *   it — the content script registers on `window` in the capture phase to make that hard rather
 *   than impossible.
 *
 * What it does not cost is safety: `isTrusted` is false for any event page script dispatches, so
 * a page cannot press the shortcut on the user's behalf.
 *
 * This listener is kept for the popup, which asks a tab to run the same path.
 */
/**
 * Relay the popup's requests to the active tab's content script.
 *
 * The popup cannot ask about a page directly: a message it sends carries
 * `chrome-extension://<id>` as its origin, and turning that into a page origin would mean reading
 * tab URLs — `tabs` permission, over every tab, for a convenience. So the popup asks the worker,
 * the worker forwards to the active tab, and the content script answers with the origin the
 * browser stamped on *it*. One relay hop buys one fewer permission and one fewer place an origin
 * could be claimed rather than established.
 */
const RELAYED = {
  "fill-active-tab": { kind: "shortcut-fill" },
  "matches-active-tab": { kind: "matches-please" },
};

/**
 * The popup's two questions about the tab memory, answered here rather than relayed.
 *
 * These are the exception to the rule above, and they are an exception because they involve no
 * origin *judgement*: what the popup renders is the origin stored in the entry — the one the
 * browser stamped on the request that created it — rather than anything about where the tab is
 * now. So there is nothing for a content script to establish, and one fewer hop is one fewer
 * place to get it wrong. "Forget" needs no page at all.
 */
const TAB_MEMORY_ASKS = new Set(["recall-active-tab", "forget-active-tab"]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.kind !== "string") return false;
  if (!TAB_MEMORY_ASKS.has(message.kind)) return false;

  (async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number") {
      sendResponse({ ok: true, entry: null });
      return;
    }
    if (message.kind === "forget-active-tab") {
      KsTabMemory.forget(tab.id);
      sendResponse({ ok: true, entry: null });
      return;
    }
    sendResponse({ ok: true, entry: KsTabMemory.peek(tab.id, Date.now()) });
  })();
  return true;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.kind !== "string") return false;
  const relayed = RELAYED[message.kind];
  const isTotp = message.kind === "totp-active-tab";
  if (!relayed && !isTotp) return false;

  (async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number") {
      sendResponse({ ok: false, code: "PROTOCOL", message: "No active tab." });
      return;
    }
    try {
      const forwarded = isTotp
        ? { kind: "totp-please", itemId: message.itemId }
        : relayed;
      const answer = await chrome.tabs.sendMessage(tab.id, forwarded);
      sendResponse(answer ?? { ok: true });
    } catch {
      // No content script on this tab — an internal page, the store, a PDF.
      sendResponse({
        ok: false,
        code: "PROTOCOL",
        message: "Autofill does not run on this page.",
      });
    }
  })();
  return true;
});
