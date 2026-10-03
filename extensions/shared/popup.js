/**
 * The popup: connection status, what applies to the current tab, and the two actions.
 *
 * # Why the popup does nothing itself
 *
 * Every question about the page, and both actions, are relayed to the content script in the active
 * tab. Two reasons, and neither is tidiness:
 *
 * 1. **Origin.** A message this popup sends carries `chrome-extension://<id>` as the origin the
 *    browser stamps on it. The only context whose stamped origin is the *page's* is a content
 *    script, so that is the only context allowed to ask the app about a page. The alternative is
 *    reading tab URLs, which is a permission over every tab, for a convenience.
 * 2. **One writer.** There is exactly one function in this extension that writes a value into a
 *    field, and it lives in the content script. A popup that filled would be a second one.
 *
 * So this file renders a list and forwards clicks. It never sees a password, and since M6's TOTP
 * relay it never sees a one-time code either.
 *
 * The one thing it renders that is not a match is the "Continuing as …" banner: which item this
 * tab picked on page one of an identifier-first sign-in, and a button to forget it. That comes
 * from the service worker's per-tab memory (`tabmemory.js`) rather than from the app, because it
 * is a fact about this browser rather than about the vault.
 *
 * # What the popup shows about trust
 *
 * The `host_evidence` lines the app sent back at `Hello` — the native host's path, and which
 * browser the app established launched it. On an ad-hoc build one of those lines says the identity
 * could not be attributed to a developer, and the popup shows it verbatim rather than summarizing
 * it into a reassuring word.
 */

"use strict";

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

// The static labels in popup.html, each naming its message in `data-i18n`.
for (const el of document.querySelectorAll("[data-i18n]")) {
  el.textContent = localized(el.dataset.i18n, el.textContent);
}

const dot = document.getElementById("dot");
const heading = document.getElementById("heading");
const detail = document.getElementById("detail");
const evidence = document.getElementById("evidence");
const items = document.getElementById("items");
const empty = document.getElementById("empty");
const continuing = document.getElementById("continuing");
const continuingTitle = document.getElementById("continuing-title");
const continuingOrigin = document.getElementById("continuing-origin");

function send(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      const failed = chrome.runtime.lastError;
      resolve(
        failed || !response
          ? { ok: false, code: "INTERNAL", message: localized("appNotReachable", "kagisecure is not reachable.") }
          : response,
      );
    });
  });
}

function setStatus(state) {
  dot.className = `dot ${state.status === "ready" ? "ready" : state.status === "locked" ? "locked" : state.status === "error" ? "error" : ""}`;
  heading.textContent =
    state.status === "ready"
      ? localized("statusConnected", "Connected")
      : state.status === "locked"
        ? localized("statusLocked", "Vault locked")
        : state.status === "error"
          ? localized("statusNotConnected", "Not connected")
          : "Kagisecure";
  detail.textContent = state.detail || "";
  evidence.replaceChildren(
    ...(state.evidence || []).map((line) => {
      const el = document.createElement("div");
      el.textContent = line;
      return el;
    }),
  );
}

/**
 * Render the "continuing as …" banner, or hide it.
 *
 * What the service worker remembers for a tab is an item id, an origin and a deadline — never a
 * username, and certainly never a value. So the name shown here is resolved from the *match* list
 * this popup already has, and when the remembered item is not in that list (the tab has moved on,
 * the item was archived) the banner says the honest, shorter thing rather than inventing a name.
 *
 * @param {{ itemId: string, origin: string } | null} entry
 * @param {{ item_id: string, title: string, username?: string }[]} matched
 */
function showContinuing(entry, matched) {
  if (!entry) {
    continuing.hidden = true;
    return;
  }
  const item = (matched || []).find((i) => i.item_id === entry.itemId);
  const who = item && item.username ? item.username : item ? item.title : null;
  continuingTitle.textContent = who ? localized("continuingAs", "Continuing as $1", who) : localized("continuingSaved", "Continuing with a saved login");
  continuingOrigin.textContent = localized("continuingFor", "for $1", entry.origin);
  continuing.hidden = false;
}

function showEmpty(text) {
  items.replaceChildren();
  empty.hidden = false;
  empty.textContent = text;
}

function row(title, subtitle, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "row";
  const t = document.createElement("div");
  t.className = "title";
  t.textContent = title;
  button.append(t);
  if (subtitle) {
    const s = document.createElement("div");
    s.className = "sub";
    s.textContent = subtitle;
    button.append(s);
  }
  button.addEventListener("click", onClick);
  return button;
}

async function refresh() {
  const state = await send({ kind: "status" });
  if (!state.ok) {
    setStatus({ status: "error", detail: state.message, evidence: [] });
    showContinuing(null, []);
    showEmpty(localized("emptyOpenAndUnlock", "Open Kagisecure and unlock your vault."));
    return;
  }
  setStatus(state.state);
  if (state.state.status !== "ready") {
    // A locked vault has already taken the tab memories with it, in the service worker.
    showContinuing(null, []);
    showEmpty(
      state.state.status === "locked"
        ? localized("emptyUnlockToSee", "Unlock Kagisecure to see what applies to this page.")
        : localized("emptyRunSetup", "Run “Browser extension” setup in Kagisecure."),
    );
    return;
  }

  // What applies here is answered by the content script in the active tab, not by this popup —
  // see the relay comment in `background.js` for why.
  const result = await send({ kind: "matches-active-tab" });
  if (!result.ok) {
    showContinuing(null, []);
    showEmpty(result.message || localized("autofillNotOnPage", "Autofill does not run on this page."));
    return;
  }
  const matched = result.items || [];

  // Page one of an identifier-first sign-in chose an item for this tab. Saying so — and offering
  // to undo it — is the difference between a manager that continues the flow and one that decides
  // things on your behalf without telling you.
  const recalled = await send({ kind: "recall-active-tab" });
  showContinuing(recalled.ok ? recalled.entry : null, matched);
  if (matched.length === 0) {
    showEmpty(
      result.origin
        ? localized("noItemForOrigin", "No item is saved for $1.", result.origin)
        : localized("noItemForPage", "No item is saved for this page."),
    );
    return;
  }

  empty.hidden = true;
  const rows = [];
  for (const item of matched) {
    rows.push(
      row(localized("fillItem", "Fill “$1”", item.title), item.username || undefined, async () => {
        const filled = await send({ kind: "fill-active-tab" });
        if (!filled.ok) {
          showEmpty(filled.message || localized("fillFailed", "Kagisecure could not fill this page."));
          return;
        }
        window.close();
      }),
    );
    if (item.has_totp) {
      rows.push(
        row(localized("copyOneTimeCode", "Copy one-time code"), item.title, async () => {
          // The code never comes back here: the content script writes it into a detected field or
          // onto the clipboard, and this only learns whether that worked.
          const totp = await send({ kind: "totp-active-tab", itemId: item.item_id });
          showEmpty(
            totp.ok
              ? localized("totpApplied", "One-time code applied. It expires in under a minute.")
              : totp.message || localized("declined", "Kagisecure declined."),
          );
        }),
      );
    }
  }
  items.replaceChildren(...rows);
}

document.getElementById("forget").addEventListener("click", async () => {
  await send({ kind: "forget-active-tab" });
  showContinuing(null, []);
  refresh();
});

document.getElementById("open").addEventListener("click", async () => {
  // There is no URL scheme to open the app with, and inventing one would be a new attack surface
  // for anything that can navigate. Asking the app to come forward is the app's job; the popup
  // just tells the user where to look.
  const state = await send({ kind: "status" });
  showEmpty(
    state.ok && state.state.status === "ready"
      ? localized("alreadyConnected", "Kagisecure is already connected.")
      : localized("openFromApplications", "Open Kagisecure from your Applications folder or the menu bar, and unlock it."),
  );
});

refresh();
