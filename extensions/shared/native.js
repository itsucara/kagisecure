/**
 * The one channel to the app, in the two shapes the two browser families offer.
 *
 * # Why this file exists
 *
 * Everything above it — the content script, the popup, the message routing in `background.js` —
 * is identical in Chrome and Safari. What is not identical is the four lines that actually reach
 * a native program:
 *
 * | | Chromium | Safari |
 * | --- | --- | --- |
 * | API | `chrome.runtime.connectNative(name)` | `chrome.runtime.sendNativeMessage(id, message)` |
 * | Shape | a long-lived port, many messages | one request, one answer |
 * | On the other end | `kagisecure-nmhost`, a child process | `SafariWebExtensionHandler`, in the app's own bundle |
 *
 * Rather than branch on the browser in five places, the branch is here once, behind
 * `KsNative.call(body)` — a promise of one reply body, whichever transport carried it.
 *
 * # What this file stores
 *
 * Nothing that outlives the service worker. `state` is the connected/locked flag the popup
 * renders; `pending` holds the resolver for a request that is in flight and is cleared the moment
 * it answers. A reply that carries a password is handed to exactly one `resolve` and dropped —
 * it is never assigned to anything longer-lived, logged, or stringified into an error.
 *
 * # Pushes: the app speaking first
 *
 * On Chromium the port also carries **pushes** (ADR-0036 §3.1): `{"ksx":1,"push":{…}}`, a frame
 * with no `id` and no `body`, which the app sends when an agent has asked for a fill and it needs
 * the tab in front. A push is a doorbell — two opaque ids, never a value or an origin — and is
 * handed to the one listener `background.js` registers with `KsNative.onPush`. It is never routed
 * as a reply: a frame with an `id` is a reply, a frame with a `push` and no `id` is a push, and
 * anything else is dropped.
 *
 * Only a session that declared the `agent_fill` capability at `hello` is ever pushed to, and only
 * the Chromium transport declares it. Safari's handler opens one connection per message, so there
 * is no port for the app to speak on, and its `hello` says nothing it cannot do (ADR-0036 §12).
 *
 * # Which transport, and how that is decided
 *
 * From the **scheme of the extension's own URL**: Chromium serves extension resources from
 * `chrome-extension://` and Safari from `safari-web-extension://`. That is a fact about the
 * runtime rather than a guess about it, which matters here because the obvious feature test no
 * longer works — Safari has grown a `connectNative` of its own, so `typeof
 * chrome.runtime.connectNative` does not distinguish the two, and a wrong answer fails as silence
 * rather than as an error.
 *
 * The same source tree ships to both browsers unchanged (`extensions/shared/`); only the manifest
 * differs, and it differs in keys neither browser reads from the other's.
 */

"use strict";

(function (root) {

  /**
   * A UI string in the browser's language (`_locales/<lang>/messages.json`). `fallback` is the
   * English text, used where `chrome.i18n` is absent (the unit tests) and kept identical to
   * `_locales/en` by `test/i18n.test.js`. `$1`… are filled from `subs` either way.
   */
  function localized(key, fallback, ...subs) {
    try {
      const text = globalThis.chrome && chrome.i18n && chrome.i18n.getMessage(key, subs.map(String));
      if (text) return text;
    } catch {
      // No i18n here; the English fallback below is the answer.
    }
    return subs.reduce((t, v, i) => t.split(`$${i + 1}`).join(String(v)), fallback);
  }
  /** Matches `kagisecure_extension_ipc::PROTOCOL_VERSION`. */
  const PROTOCOL_VERSION = 1;

  /**
   * The native messaging host name, matching `kagisecure_extension_ipc::NATIVE_HOST_NAME` and the
   * file name of the manifest each Chromium-family browser reads.
   */
  const CHROMIUM_HOST_NAME = "com.kagisecure.nmhost";

  /**
   * The Safari app extension's bundle identifier, matching
   * `kagisecure_extension_ipc::SAFARI_EXTENSION_BUNDLE_ID`.
   *
   * Safari ignores the application argument — a Safari Web Extension has exactly one native
   * application, the app extension it lives inside — but it is required, and naming the real
   * bundle identifier is more useful in a stack trace than a placeholder.
   */
  const SAFARI_BUNDLE_ID = "com.kagisecure.app.safari-extension";

  /** Which browser family this copy was loaded into. See the header. */
  const isSafari = (() => {
    try {
      return chrome.runtime.getURL("/").startsWith("safari-web-extension://");
    } catch {
      // No runtime at all is not a browser this code can serve; the Chromium path then fails
      // loudly at `connectNative` rather than silently doing nothing.
      return false;
    }
  })();

  /**
   * What the extension reports about itself at `hello`.
   *
   * On Chromium this is `chrome.runtime.id`. Loaded unpacked, that is the id pinned by the public
   * `key` in `manifest.json`, the same on every machine (ADR-0021). Installed from the Chrome Web
   * Store it is the store item's own id — the store package carries no `key` — which the app pins
   * as a second entry in `PINNED_EXTENSION_IDS` (ADR-0021, amendment of 2026-10-03).
   *
   * On Safari it is **not** `chrome.runtime.id`: that is a per-install UUID, different on every
   * Mac and regenerated when the extension is reinstalled, so there is nothing to pin. The app
   * extension's bundle identifier is the stable identity, and the native handler overwrites this
   * field with its own `Bundle.main.bundleIdentifier` before the message reaches the app — so what
   * the app pins against is a fact the appex knows about itself rather than a string web content
   * chose (ADR-0024 §4).
   */
  const extensionId = () => (isSafari ? SAFARI_BUNDLE_ID : chrome.runtime.id);

  /** The native application to address. */
  const nativeApplication = isSafari ? SAFARI_BUNDLE_ID : CHROMIUM_HOST_NAME;

  /**
   * What this copy declares it can do at `hello`, matching `kagisecure_extension_ipc::Capability`.
   *
   * `agent_fill` means "push to me": only a long-lived port can carry a push, so only the Chromium
   * transport declares it. Safari declares nothing — its `hello` carries no `capabilities` field,
   * which the app reads as none — until app-to-extension messaging on Safari has been measured
   * (ADR-0036 §12, Phase 4). The Safari handler strips the field as well.
   */
  const CAPABILITIES = Object.freeze(isSafari ? [] : ["agent_fill"]);

  /**
   * How long to wait for the app before giving up on one request.
   *
   * Longer than the app's own 60-second approval timeout on purpose: the app answers
   * `APPROVAL_TIMEOUT` itself, and a shorter timeout here would race it and report the wrong
   * reason for the same event.
   */
  const REQUEST_TIMEOUT_MS = 70_000;

  /**
   * What the popup shows. Not persisted: a service worker that has been evicted has no connection
   * either, so a remembered "connected" would be a lie the moment it was read.
   *
   * @type {{ status: string, detail: string, evidence: string[] }}
   */
  let state = { status: "disconnected", detail: localized("detailNotConnectedYet", "Not connected yet."), evidence: [] };

  /** The live native port, for the Chromium transport only. */
  let port = null;

  /** Requests waiting for an answer, by correlation id. Chromium transport only. */
  const pending = new Map();

  /**
   * The one function a push is handed to, set by `background.js` through `onPush`.
   *
   * @type {((push: { push: string }) => void) | null}
   */
  let pushListener = null;

  /**
   * Whether `message` is a push frame: the channel marker, a `push` object naming its kind, and
   * neither of the two fields a reply has. Mirrors `kagisecure_extension_ipc::HostBound`, which
   * refuses a frame that is both.
   */
  function isPushFrame(message) {
    return (
      message.ksx === PROTOCOL_VERSION &&
      !Object.prototype.hasOwnProperty.call(message, "id") &&
      !Object.prototype.hasOwnProperty.call(message, "body") &&
      !!message.push &&
      typeof message.push === "object" &&
      typeof message.push.push === "string"
    );
  }

  let nextId = 0;

  function newId() {
    nextId += 1;
    return `x${nextId}`;
  }

  function errorReply(code, message) {
    return { reply: "error", code, message };
  }

  /** Tear the port down and fail everything still waiting, so nothing hangs forever. */
  function dropPort(reason) {
    const failing = Array.from(pending.values());
    pending.clear();
    port = null;
    state = { status: "disconnected", detail: reason, evidence: [] };
    for (const entry of failing) {
      clearTimeout(entry.timer);
      entry.resolve(errorReply("VAULT_LOCKED", reason));
    }
    scheduleReconnect();
  }

  // -------------------------------------------------------------------------------------
  // Reconnecting on our own, after the port drops
  // -------------------------------------------------------------------------------------

  /**
   * A lock that outlives the helper's connection to the browser, a crash of the helper, or the
   * helper simply not being installed yet all end up here, at `dropPort` — and until now nothing
   * afterward said `hello` again on its own. An already-open tab does not navigate and does not
   * open the popup, so `request_fill` kept answering `FILL_UNAVAILABLE` after an unlock until the
   * person reloaded the page by hand, because nothing had told the app a browser was connected
   * again.
   *
   * The schedule is a parameter, not only a constant, so a test can shrink it to milliseconds and
   * exercise the real backoff without a slow suite or fake timers.
   */
  const DEFAULT_RECONNECT_DELAYS_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000];

  /**
   * Off until `background.js` calls `enableAutoReconnect` once, at load — never from inside this
   * file. That keeps every existing test below, which drops the port on purpose and asserts
   * nothing else happens, unaffected; the reconnect tests turn it on themselves, with a short
   * schedule, and turn it back off when they are done.
   */
  let autoReconnect = false;
  let reconnectDelays = DEFAULT_RECONNECT_DELAYS_MS;
  let reconnectTimer = null;
  let reconnectAttempt = 0;

  function stopReconnecting() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    reconnectAttempt = 0;
  }

  /**
   * Try `hello` again after the next delay in the schedule, unless a retry is already pending —
   * `onDisconnect` and a failed attempt's own retry can both ask for one, and only one clock
   * should be running at a time. Safari has no port to reconnect; every request there is already
   * its own connection (`native.js`'s header).
   */
  function scheduleReconnect() {
    if (!autoReconnect || isSafari || reconnectTimer) return;
    const delay = reconnectDelays[Math.min(reconnectAttempt, reconnectDelays.length - 1)];
    reconnectAttempt += 1;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      // A `welcome` reply — locked or not — means a session is registered again, which is the
      // whole point; anything else, including the port dropping again mid-attempt, is worth
      // another try. `dropPort` schedules its own retry when that happens, so this only needs to
      // cover the case where `ensurePort` succeeded but the reply itself was not a `welcome`.
      ensureHello().then((result) => {
        if (result.status !== "ready" && result.status !== "locked") scheduleReconnect();
      });
    }, delay);
  }

  // -------------------------------------------------------------------------------------
  // Chromium: a long-lived port to a child process
  // -------------------------------------------------------------------------------------

  /**
   * Connect, or return the live port.
   *
   * A failure here is almost always "kagisecure is not running" or "the native messaging manifest
   * is not installed", and both are things the popup has to be able to say in words.
   */
  function ensurePort() {
    if (port) return port;
    try {
      port = chrome.runtime.connectNative(nativeApplication);
    } catch (e) {
      dropPort(`Could not start the kagisecure helper: ${e && e.message ? e.message : e}`);
      return null;
    }
    state = { status: "connecting", detail: localized("detailConnecting", "Connecting…"), evidence: [] };

    port.onMessage.addListener((message) => {
      if (!message || typeof message !== "object") return;
      if (isPushFrame(message)) {
        // A doorbell, not an answer: nothing is waiting for it, so it goes to the push listener
        // and never near `pending`.
        if (pushListener) {
          try {
            pushListener(message.push);
          } catch {
            // A listener that throws must not take the port's message handling down with it.
          }
        }
        return;
      }
      if (typeof message.id !== "string") return;
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id);
      clearTimeout(entry.timer);
      // The body is handed straight on and never inspected, stored or logged. When it is a
      // `filled` it holds a password, and the only thing done with it is pass it to the one
      // resolver that asked for it.
      entry.resolve(message.body);
    });

    port.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError;
      dropPort(
        error && error.message
          ? localized("detailHelperDisconnectedWith", "The kagisecure helper disconnected: $1", error.message)
          : localized("detailHelperDisconnected", "The kagisecure helper disconnected."),
      );
    });

    return port;
  }

  function callOverPort(body) {
    return new Promise((resolve) => {
      const live = ensurePort();
      if (!live) {
        resolve(errorReply("VAULT_LOCKED", state.detail));
        return;
      }
      const id = newId();
      const timer = setTimeout(() => {
        pending.delete(id);
        resolve(errorReply("APPROVAL_TIMEOUT", localized("detailTimeout", "kagisecure did not answer in time.")));
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, timer });
      try {
        live.postMessage({ ksx: PROTOCOL_VERSION, id, body });
      } catch (e) {
        pending.delete(id);
        clearTimeout(timer);
        dropPort(localized("detailCouldNotReach", "Could not reach kagisecure: $1", e && e.message ? e.message : e));
        resolve(errorReply("VAULT_LOCKED", state.detail));
      }
    });
  }

  // -------------------------------------------------------------------------------------
  // Safari: one message, one answer, to the app extension in our own bundle
  // -------------------------------------------------------------------------------------

  /**
   * Send one message to `SafariWebExtensionHandler` and resolve with the reply body.
   *
   * There is no port to keep alive and nothing to reconnect: Safari starts the app extension when
   * a message arrives and the handler owns its own socket to the app. So a failure here is a
   * failure of *this* request rather than of a connection, and the state flag is updated from the
   * answer rather than from a disconnect event that will never come.
   *
   * Safari's `sendNativeMessage` accepts both the promise form and the callback form. The
   * callback form is used because it is the one Chromium also accepts, so this function reads the
   * same in both places even though only Safari runs it.
   */
  function callOverMessage(body) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (reply) => {
        if (settled) return;
        settled = true;
        resolve(reply);
      };
      const timer = setTimeout(
        () => finish(errorReply("APPROVAL_TIMEOUT", localized("detailTimeout", "kagisecure did not answer in time."))),
        REQUEST_TIMEOUT_MS,
      );
      const done = (reply) => {
        clearTimeout(timer);
        const failed = chrome.runtime.lastError;
        if (failed || !reply) {
          const detail =
            failed && failed.message
              ? localized("detailCouldNotReach", "Could not reach kagisecure: $1", failed.message)
              : localized("detailSafariNotConnected", "Kagisecure is not running, or its Safari extension is not connected.");
          state = { status: "disconnected", detail, evidence: [] };
          finish(errorReply("VAULT_LOCKED", detail));
          return;
        }
        finish(reply);
      };
      try {
        const returned = chrome.runtime.sendNativeMessage(
          nativeApplication,
          { ksx: PROTOCOL_VERSION, id: newId(), body },
          done,
        );
        // Safari also resolves a promise. Whichever settles first wins; `finish` makes the second
        // one a no-op rather than a double resolve.
        if (returned && typeof returned.then === "function") returned.then(done, () => done(null));
      } catch (e) {
        clearTimeout(timer);
        const detail = localized("detailCouldNotReach", "Could not reach kagisecure: $1", e && e.message ? e.message : e);
        state = { status: "disconnected", detail, evidence: [] };
        finish(errorReply("VAULT_LOCKED", detail));
      }
    });
  }

  // -------------------------------------------------------------------------------------
  // The interface everything above this file uses
  // -------------------------------------------------------------------------------------

  /**
   * Send one request to the app and resolve with its reply body.
   *
   * @param {object} body
   * @returns {Promise<object>}
   */
  function call(body) {
    return isSafari ? callOverMessage(body) : callOverPort(body);
  }

  /**
   * Say hello if this connection has not yet, so every other call has a session behind it.
   */
  async function ensureHello() {
    if (state.status === "ready" && (isSafari || port)) return state;
    const hello = {
      ask: "hello",
      extension_id: extensionId(),
      browser: isSafari ? "safari" : "chrome",
      extension_version: chrome.runtime.getManifest().version,
      protocol_version: PROTOCOL_VERSION,
    };
    // Absent rather than empty on Safari: an older app and a newer one read both as "none", and
    // leaving it out keeps Safari's `hello` byte-identical to what it has always sent.
    if (CAPABILITIES.length > 0) hello.capabilities = CAPABILITIES.slice();
    const reply = await call(hello);
    if (reply && reply.reply === "welcome") {
      // A session is registered again, locked or not: the app only answers `hello` at all while
      // its listener is up, so there is nothing further to retry for.
      stopReconnecting();
      state = {
        status: reply.unlocked ? "ready" : "locked",
        detail: reply.unlocked ? localized("detailConnected", "Connected.") : localized("detailVaultLocked", "The vault is locked."),
        evidence: Array.isArray(reply.host_evidence) ? reply.host_evidence : [],
      };
    } else {
      state = {
        status: "error",
        detail: (reply && reply.message) || localized("detailRefused", "kagisecure refused the connection."),
        evidence: [],
      };
    }
    return state;
  }

  /**
   * The vault's state **now**, rather than when the session was established.
   *
   * [`ensureHello`] deliberately caches: it exists so that every other call has a session behind
   * it, and re-handshaking before each one would be a round trip per keystroke. But the cache
   * survives a lock — the app keeps its listener up while locked and answers `VAULT_LOCKED`, so
   * the port never drops and nothing invalidates a `ready` — and the popup was therefore showing
   * a green dot and localized("detailConnected", "Connected.") over a vault the user had just locked. A password manager that
   * says it is unlocked when it is not is telling the one lie it must never tell.
   *
   * So the popup asks. `status` is a request the protocol already has for exactly this, and it is
   * one message rather than a handshake. A locked vault is refused before that arm is reached, so
   * `VAULT_LOCKED` coming back *is* the answer.
   */
  async function refreshState() {
    const established = await ensureHello();
    if (established.status !== "ready") return established;

    const reply = await call({ ask: "status" });
    if (reply && reply.reply === "status") {
      state = {
        status: reply.unlocked ? "ready" : "locked",
        detail: reply.unlocked ? localized("detailConnected", "Connected.") : localized("detailVaultLocked", "The vault is locked."),
        evidence: state.evidence,
      };
    } else if (reply && reply.code === "VAULT_LOCKED") {
      state = {
        status: "locked",
        detail: localized("detailVaultLocked", "The vault is locked."),
        evidence: state.evidence,
      };
    } else if (reply && reply.reply === "error") {
      state = {
        status: "error",
        detail: reply.message || localized("detailRefused", "kagisecure refused the connection."),
        evidence: state.evidence,
      };
    }
    return state;
  }

  /**
   * Register the one function pushes are handed to. A later registration replaces an earlier
   * one; there is one service worker and it registers once.
   *
   * @param {(push: { push: string }) => void} listener
   */
  function onPush(listener) {
    pushListener = typeof listener === "function" ? listener : null;
  }

  /**
   * Turn automatic reconnect on. `background.js` calls this once, at load, in production; a test
   * calls it itself, with a short `delaysMs`, to exercise the schedule without a slow suite.
   *
   * @param {number[]} [delaysMs] Overrides the default backoff, for tests.
   */
  function enableAutoReconnect(delaysMs) {
    autoReconnect = true;
    if (Array.isArray(delaysMs) && delaysMs.length > 0) reconnectDelays = delaysMs;
  }

  /** Turn it back off, and cancel anything pending. Mainly for test teardown. */
  function disableAutoReconnect() {
    autoReconnect = false;
    reconnectDelays = DEFAULT_RECONNECT_DELAYS_MS;
    stopReconnecting();
  }

  root.KsNative = {
    PROTOCOL_VERSION,
    CAPABILITIES,
    isSafari,
    call,
    ensureHello,
    refreshState,
    onPush,
    enableAutoReconnect,
    disableAutoReconnect,
    state: () => state,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
