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
 *
 * The agent-fill section at the bottom keeps two small maps in memory — which tab and document a
 * probe was answered from, and which grant was delivered where — so that a `deliver` push lands in
 * exactly the document the human approved. They hold browser ids and the app's opaque ids, never
 * an origin claim, an item or a value, and they expire in seconds.
 */

"use strict";

importScripts("origin.js", "tabmemory.js", "native.js");

// Findings #14: after an app lock the native port can drop, and an already-open tab neither
// navigates nor opens the popup, so nothing else would ever say `hello` again — `request_fill`
// then kept answering `FILL_UNAVAILABLE` until the person reloaded the page by hand. Turned on
// only here, in production, so every test in `native.test.js` that drops the port on purpose
// keeps seeing exactly what it asserts. The `typeof` guard is for the other extension tests,
// which run this file with a smaller stub in place of the real `native.js` and have no reason to
// know about a method they never call.
if (typeof KsNative.enableAutoReconnect === "function") KsNative.enableAutoReconnect();

/** Say hello if this connection has not yet, so every other call has a session behind it. */
const ensureHello = () => KsNative.ensureHello();

/** The vault's lock state right now, not as of the last handshake. */
const refreshState = () => KsNative.refreshState();

/** Send one request to the app and resolve with its reply body. */
const call = (body) => KsNative.call(body);

/**
 * The top origin of a sub-frame whose embedder the extension could not establish.
 *
 * `"null"` is how the platform serialises an opaque origin, so it is a string the app can render
 * and can never confuse with a real site.
 */
const UNKNOWN_ORIGIN = "null";

/**
 * The page context a request may use.
 *
 * **The frame's own origin is taken from the browser, not from the message.** `sender.origin` and
 * `sender.frameId` are stamped by Chrome; a content script in a compromised page could otherwise
 * claim to be anywhere. The content script's own `page_context` is used only for the *top* origin,
 * which the browser does not hand us here.
 *
 * A lying top origin cannot loosen the **match** — that is applied to the frame origin, which is
 * the trusted one. What it could loosen is the **disclosure**: the app shows "this form is inside
 * a frame on X" by comparing the two origins, so a sub-frame claiming its own origin as the top
 * origin would render as an ordinary top-frame fill. `top_origin_established` is therefore
 * reported alongside them, taken straight from `sender.frameId`, and a sub-frame's self-claim is
 * dropped rather than forwarded.
 *
 * @param {chrome.runtime.MessageSender} sender
 * @param {{ top_origin?: string, frame_origin?: string | null } | undefined} claimed
 * @returns {{ top_origin: string, frame_origin: string | null, top_origin_established: boolean }
 *   | null}
 */
function trustedPageContext(sender, claimed) {
  const real = KsOrigin.originOf(sender && sender.origin ? sender.origin : sender && sender.url);
  if (!real) return null;
  const isTopFrame = sender && sender.frameId === 0;
  // `top_origin_established` is the one thing here the browser told us rather than the page: it is
  // true exactly when `sender.frameId === 0`, which no message can influence. Everything else
  // about the top origin of a sub-frame is a claim, and the app needs to be able to tell the two
  // apart before it decides whether to show the "this form is inside a frame on X" disclosure.
  if (isTopFrame) return { top_origin: real, frame_origin: null, top_origin_established: true };
  const claimedTop =
    claimed && typeof claimed.top_origin === "string"
      ? KsOrigin.originOf(claimed.top_origin)
      : null;
  // A sub-frame claiming that the top origin *is* its own origin is claiming to be the top frame,
  // which the browser has already contradicted. Forwarding that claim would make a third-party
  // frame's fill arrive looking exactly like an ordinary top-frame fill. So the claim is dropped
  // and the top origin is reported as opaque — "we could not establish the embedder" — which is
  // never equal to the frame origin and so can never suppress the disclosure.
  // An absent or unparseable claim says nothing at all, and the frame's own origin stays the
  // conservative stand-in it has always been.
  let top = real;
  if (claimedTop) top = claimedTop === real ? UNKNOWN_ORIGIN : claimedTop;
  return { top_origin: top, frame_origin: real, top_origin_established: false };
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
  forgetAgentTab(tabId);
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
const RELAYED = Object.assign(Object.create(null), {
  "fill-active-tab": { kind: "shortcut-fill" },
  "matches-active-tab": { kind: "matches-please" },
});

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
  // These three exist for the popup, which has no `sender.tab`. A message that carries one came
  // from a content script, and relaying it would hand a page the keyboard-shortcut fill path —
  // the one path `content.js` runs without an `isTrusted` gesture behind it. Not ours: `false`
  // leaves the message to any other listener, of which there are none.
  if (tabIdOf(sender) !== null) return false;

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

// -------------------------------------------------------------------------------------------------
// Agent-requested fills (ADR-0036)
// -------------------------------------------------------------------------------------------------

/**
 * An agent asked the app, on the MCP socket, to fill a saved login into the tab the human is
 * looking at. The app cannot see tabs, so it rings the doorbell — a *push* — and everything it
 * learns comes back as a request this worker sends and the browser stamps.
 *
 * ```text
 *   app ── push locate{probe, origin} ──▶ worker ── the tab on `origin`, any visibility, else front
 *                                   │  tabs.sendMessage(tab, agent-locate, {frameId: 0})
 *                                   ▼
 *                         content script, top frame ── runtime.sendMessage(agent-report) ──▶ worker
 *   app ◀── target_report{probe, page, tab, found} ── worker stamps page and tab from `sender`
 *
 *   app ── push deliver{probe, grant} ──▶ worker
 *                                   │  tabs.sendMessage(tab, agent-deliver, {frameId: 0, documentId})
 *                                   ▼
 *                         content script re-checks ── runtime.sendMessage(agent-fill) ──▶ worker
 *   app ◀── agent_fill{grant, page, tab, found} ── stamped again; the `filled` reply goes back
 *                         to that one content script, which writes it and drops it
 *   app ◀── agent_fill_outcome{grant, written, failure} ── field names and a reason only
 * ```
 *
 * **Who establishes what.** The tab is the browser's answer to "which tab is in front", never
 * the app's or the agent's: the push carries no tab. The origin, the tab id, the frame id, the
 * document id and whether the tab is active are copied from the `sender` the browser attached to
 * the content script's message — exactly as `trustedPageContext` does for a human fill — and
 * anything the content script says about them is ignored. What only the document can say comes
 * from the content script: whether it is visible, and which fields the detectors found. A report
 * or a fill request is accepted only from frame 0 of the tab this worker asked, for a probe or a
 * grant it is holding; anything else is dropped without telling the sender why.
 *
 * **Where a delivery lands** is enforced by the browser: `tabs.sendMessage` with the stored
 * `documentId` reaches that document or nothing, so a navigation, a reload or a redirect between
 * the approval and the write is a delivery that goes nowhere. The app re-checks the tab, the
 * document and the origin on the `agent_fill` request again, from scratch.
 *
 * **The value** travels exactly as a human fill's does: the `filled` reply is passed to one
 * `sendResponse` and dropped. Nothing in this section stores, logs or inspects it.
 */

/**
 * How long after a `locate` its report is accepted. The app waits about two seconds for reports;
 * the extra margin is for a busy service worker, not for a slow page.
 */
const AGENT_REPORT_WINDOW_MS = 5_000;

/**
 * How long a probe's tab and document are remembered for a `deliver`: the app's 60-second approval
 * timeout, plus the time before the sheet was raised, with margin. Past this the app's own grant is
 * long dead, so forgetting is only housekeeping.
 */
const AGENT_PROBE_TTL_MS = 90_000;

/**
 * How long a delivered grant is remembered, for the `agent_fill` request and the outcome that
 * follows it. The app lets a grant be picked up for 30 seconds.
 */
const AGENT_DELIVERY_TTL_MS = 60_000;

/** The field names an outcome may report, matching `AgentFillField`. */
const AGENT_FIELDS = ["username", "password", "one_time_code"];

/** The reasons an outcome may give, matching `AgentFillFailure` on the wire. */
const AGENT_FAILURES = new Set([
  "FORM_CHANGED",
  "NOT_WRITABLE",
  "NOT_VISIBLE",
  "WRITE_REJECTED",
  "UNMASKED",
]);

/**
 * Probes this worker has been asked about: probe id → `{ tabId, at, reported, documentId }`.
 *
 * `tabId` is the tab `tabs.query` returned, which is where the report must come from;
 * `documentId` is the one the browser stamped on that report, which is where a delivery must go.
 */
const agentProbes = new Map();

/**
 * Grants delivered to a tab: grant id →
 * `{ tabId, documentId, at, asked, outcomes, wrotePassword }`.
 *
 * `asked` flips when the content script redeems the grant, so it is redeemed once; `outcomes`
 * counts what the content script reported about it; `wrotePassword` records whether the first
 * outcome named a password, which is the only thing the tripwire's follow-up can be about.
 */
const agentDeliveries = new Map();

/** Drop probes and deliveries past their lifetime. */
function pruneAgentState(now) {
  for (const [id, probe] of agentProbes) {
    if (now - probe.at > AGENT_PROBE_TTL_MS) agentProbes.delete(id);
  }
  for (const [id, delivery] of agentDeliveries) {
    if (now - delivery.at > AGENT_DELIVERY_TTL_MS) agentDeliveries.delete(id);
  }
}

/** A closed tab can neither report nor be delivered to. */
function forgetAgentTab(tabId) {
  for (const [id, probe] of agentProbes) {
    if (probe.tabId === tabId) agentProbes.delete(id);
  }
  for (const [id, delivery] of agentDeliveries) {
    if (delivery.tabId === tabId) agentDeliveries.delete(id);
  }
}

/** Whether `value` can be one of the app's opaque ids. */
function isOpaqueId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

/**
 * The report for "there is no tab to report on": no eligible tab, no content script there (an
 * internal page, the store, a PDF), or a page that did not answer.
 *
 * Sent rather than left unsaid so the app can answer the agent `NO_MATCHING_TAB` without waiting
 * out its probe window. It parses, and it is ineligible on every count the app checks: no
 * established top frame, an opaque origin, not active, not visible, nothing found.
 */
function emptyTargetReport(probeId) {
  return {
    ask: "target_report",
    probe_id: probeId,
    page: { top_origin: UNKNOWN_ORIGIN, frame_origin: null, top_origin_established: false },
    tab: { tab_id: 0, document_id: null, tab_active: false, visible: false },
    found: { username: false, password: false, one_time_code: false },
  };
}

/**
 * The tab facts for a message from a content script: the browser's, not the message's.
 *
 * `visible` is the one field taken from the content script — only the document knows it — and it
 * counts only as a literal `true`.
 */
function stampedTabFacts(sender, visible) {
  return {
    tab_id: sender.tab.id,
    document_id: typeof sender.documentId === "string" ? sender.documentId : null,
    tab_active: sender.tab.active === true,
    visible: visible === true,
  };
}

/** Which fields the content script found, as three booleans and nothing else. */
function foundFields(claimed) {
  const found = claimed && typeof claimed === "object" ? claimed : {};
  return {
    username: found.username === true,
    password: found.password === true,
    one_time_code: found.one_time_code === true,
  };
}

/**
 * Whether `sender` is frame 0 of the tab and document a grant was delivered to.
 *
 * The document check is skipped only when the report carried no document id, which Chromium
 * always stamps; the app records that degradation (ADR-0036 §4).
 */
function isDeliveryTarget(delivery, sender) {
  if (!sender || sender.frameId !== 0 || tabIdOf(sender) !== delivery.tabId) return false;
  return delivery.documentId === null || sender.documentId === delivery.documentId;
}

/** The app's answer to a report or an outcome is `noted` whatever it concluded; nothing to read. */
async function tellApp(body) {
  try {
    await call(body);
  } catch {
    // A report the app did not get is a probe that times out there; nothing to do here.
  }
}

/** How long a tab is given to say which origin its top frame is on, while choosing one. */
const AGENT_ORIGIN_ASK_MS = 800;

/** Ask a tab's top frame for its origin, or `null` if it cannot or does not answer in time. */
async function topOriginOf(tabId) {
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(null), AGENT_ORIGIN_ASK_MS);
  });
  const asked = chrome.tabs
    .sendMessage(tabId, { kind: "agent-origin" }, { frameId: 0 })
    .then((answer) => (answer && typeof answer.origin === "string" ? answer.origin : null))
    .catch(() => null);
  try {
    return await Promise.race([asked, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The tab an agent fill for `origin` should go to (ADR-0036 §3.2 as amended on 2026-10-03):
 * the one tab, in any normal window and whether or not it is in front, whose top frame is on
 * `origin` — the active one of the last-focused window first, then any active one, then the most
 * recently used. With no tab on `origin`, or no origin given, the tab in front, as before, so the
 * app can still tell a look-alike site in front from no target at all.
 *
 * The origin a tab gives here only chooses which tab is asked to report; the report itself is
 * stamped by the browser, and the app checks it from scratch.
 */
async function agentTargetTab(origin) {
  let front = null;
  try {
    [front] = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true,
      windowType: "normal",
    });
  } catch {
    front = null;
  }
  const wanted = typeof origin === "string" ? KsOrigin.originOf(origin) : null;
  if (!wanted) return front || null;
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({ windowType: "normal" });
  } catch {
    tabs = [];
  }
  tabs = tabs.filter((t) => t && typeof t.id === "number" && t.id >= 0);
  const origins = await Promise.all(tabs.map((t) => topOriginOf(t.id)));
  const matches = tabs.filter((t, i) => origins[i] && KsOrigin.originOf(origins[i]) === wanted);
  if (matches.length === 0) return front || null;
  const rank = (t) => [
    front && t.id === front.id ? 1 : 0,
    t.active === true ? 1 : 0,
    typeof t.lastAccessed === "number" ? t.lastAccessed : 0,
  ];
  matches.sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    for (let i = 0; i < ra.length; i += 1) {
      if (ra[i] !== rb[i]) return rb[i] - ra[i];
    }
    return 0;
  });
  return matches[0];
}

/** `locate`: find the tab for the agent's origin (or the one in front) and ask it to report. */
async function agentLocate(probeId, origin) {
  const now = Date.now();
  pruneAgentState(now);
  // A probe is answered once. A repeated id is the app's bug or somebody else's frame; either way
  // the first answer stands.
  if (agentProbes.has(probeId)) return;
  const probe = { tabId: null, at: now, reported: false, documentId: null };
  agentProbes.set(probeId, probe);

  let tab = null;
  try {
    tab = await agentTargetTab(origin);
  } catch {
    tab = null;
  }

  if (tab && typeof tab.id === "number" && tab.id >= 0) {
    probe.tabId = tab.id;
    let answer = null;
    try {
      // Frame 0 only, by the API rather than by convention: a sub-frame is never asked (§4).
      answer = await chrome.tabs.sendMessage(
        tab.id,
        { kind: "agent-locate", probeId },
        { frameId: 0 },
      );
    } catch {
      answer = null;
    }
    // The report itself arrived as its own message, below; this answer only says it was sent.
    if (answer && answer.ok === true) return;
  }

  if (!probe.reported) {
    probe.reported = true;
    await tellApp(emptyTargetReport(probeId));
  }
}

/** `deliver`: hand the grant to exactly the document that reported, and nothing else. */
async function agentDeliver(probeId, grantId) {
  const now = Date.now();
  pruneAgentState(now);
  if (agentDeliveries.has(grantId)) return;
  const probe = agentProbes.get(probeId);
  // One delivery per probe: the report that was approved is spent.
  agentProbes.delete(probeId);

  const delivery = {
    tabId: probe ? probe.tabId : null,
    documentId: probe ? probe.documentId : null,
    at: now,
    asked: false,
    outcomes: 0,
    wrotePassword: false,
  };
  agentDeliveries.set(grantId, delivery);

  let answer = null;
  if (probe && probe.reported && probe.tabId !== null && delivery.tabId !== null) {
    const options = { frameId: 0 };
    if (typeof delivery.documentId === "string") options.documentId = delivery.documentId;
    try {
      // The browser delivers to that tab, frame and document, or not at all: a navigation since
      // the report makes this reject rather than reach the new page.
      answer = await chrome.tabs.sendMessage(
        delivery.tabId,
        { kind: "agent-deliver", grantId },
        options,
      );
    } catch {
      answer = null;
    }
  }
  if (answer && answer.ok === true) return;

  // Nothing redeemed the grant: the probe is unknown here, the document is gone, or the page did
  // not answer. Say so now rather than letting the agent wait out the grant. If the content script
  // did ask, the app already knows how far it got, and nothing is added to that.
  if (!delivery.asked && delivery.outcomes === 0) {
    delivery.outcomes += 1;
    await tellApp({
      ask: "agent_fill_outcome",
      grant_id: grantId,
      written: [],
      failure: "FORM_CHANGED",
    });
  }
}

KsNative.onPush((push) => {
  if (!push || typeof push !== "object") return;
  if (push.push === "locate" && isOpaqueId(push.probe_id)) {
    agentLocate(push.probe_id, push.origin).catch(() => {});
  } else if (push.push === "deliver" && isOpaqueId(push.probe_id) && isOpaqueId(push.grant_id)) {
    agentDeliver(push.probe_id, push.grant_id).catch(() => {});
  }
  // Any other push is one this build does not know, and is ignored.
});

/** What the content script sends on the agent path. Everything else is not this listener's. */
const AGENT_ASKS = new Set(["agent-report", "agent-fill", "agent-fill-outcome"]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.kind !== "string" || !AGENT_ASKS.has(message.kind)) return false;
  // Only a content script has a `sender.tab`. The popup has no business here.
  if (tabIdOf(sender) === null) return false;

  (async () => {
    switch (message.kind) {
      case "agent-report": {
        const probe = isOpaqueId(message.probeId) ? agentProbes.get(message.probeId) : null;
        const fresh = probe && Date.now() - probe.at <= AGENT_REPORT_WINDOW_MS;
        // From the top frame of the tab this worker asked, once, in time — or not at all. A
        // sub-frame, another tab or a late page gets the same bare refusal.
        if (
          !fresh ||
          probe.reported ||
          probe.tabId === null ||
          sender.frameId !== 0 ||
          tabIdOf(sender) !== probe.tabId
        ) {
          sendResponse({ ok: false });
          return;
        }
        probe.reported = true;
        const page = trustedPageContext(sender, undefined);
        if (!page) {
          sendResponse({ ok: true });
          await tellApp(emptyTargetReport(message.probeId));
          return;
        }
        const tab = stampedTabFacts(sender, message.visible);
        probe.documentId = tab.document_id;
        sendResponse({ ok: true });
        await tellApp({
          ask: "target_report",
          probe_id: message.probeId,
          page,
          tab,
          found: foundFields(message.found),
        });
        return;
      }
      case "agent-fill": {
        const delivery = isOpaqueId(message.grantId)
          ? agentDeliveries.get(message.grantId)
          : null;
        if (!delivery || delivery.asked || !isDeliveryTarget(delivery, sender)) {
          sendResponse({ ok: false, code: "PROTOCOL", message: "No fill is waiting here." });
          return;
        }
        delivery.asked = true;
        const page = trustedPageContext(sender, undefined);
        if (!page) {
          sendResponse({ ok: false, code: "PROTOCOL", message: "This page has no usable origin." });
          return;
        }
        const reply = await call({
          ask: "agent_fill",
          grant_id: message.grantId,
          page,
          tab: stampedTabFacts(sender, message.visible),
          found: foundFields(message.found),
        });
        // Forwarded once, to the content script that asked. Nothing is kept.
        sendResponse(toResult(reply));
        return;
      }
      case "agent-fill-outcome": {
        const delivery = isOpaqueId(message.grantId)
          ? agentDeliveries.get(message.grantId)
          : null;
        const failure = AGENT_FAILURES.has(message.failure) ? message.failure : null;
        // One outcome per delivery, and a second only for the tripwire, which follows a
        // password write and says nothing else: `UNMASKED`, naming the password it cleared.
        const first = delivery && delivery.outcomes === 0 && failure !== "UNMASKED";
        const tripwire =
          delivery && delivery.outcomes === 1 && delivery.wrotePassword && failure === "UNMASKED";
        if (!delivery || !isDeliveryTarget(delivery, sender) || !(first || tripwire)) {
          sendResponse({ ok: false });
          return;
        }
        delivery.outcomes += 1;
        const claimed = Array.isArray(message.written) ? message.written : [];
        const written = tripwire
          ? ["password"]
          : AGENT_FIELDS.filter((field) => claimed.includes(field));
        if (first) delivery.wrotePassword = written.includes("password");
        sendResponse({ ok: true });
        await tellApp({ ask: "agent_fill_outcome", grant_id: message.grantId, written, failure });
        return;
      }
      default:
        sendResponse({ ok: false, code: "PROTOCOL", message: "Unknown request." });
    }
  })().catch((e) => {
    // Never let an exception's message carry a reply body with it.
    sendResponse({ ok: false, code: "INTERNAL", message: e && e.name ? e.name : "failed" });
  });

  return true;
});
