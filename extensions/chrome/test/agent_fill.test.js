/**
 * Agent-requested fills (ADR-0036), the browser half: from a push to a write, and nothing else.
 *
 * The real `background.js` and the real `content.js` run here together, each in its own `vm`
 * context, joined by a fake browser that does what Chromium does and nothing more:
 *
 * * `chrome.tabs.query` answers from a list of tabs, and records what it was asked;
 * * `chrome.tabs.sendMessage(tabId, message, { frameId, documentId })` reaches that frame of that
 *   tab — and, when `documentId` is given, only if that frame still holds that document;
 * * a content script's `chrome.runtime.sendMessage` reaches the service worker with a `sender`
 *   **the fake browser stamps** — origin, tab id, `tab.active`, frame id, document id — whatever the
 *   message itself says.
 *
 * The app is `KsNative`, replaced by a recorder that answers what the test scripts and captures
 * the push listener `background.js` registers, so a test can ring the doorbell itself. What is
 * asserted is what reaches the app, what reaches each frame, and what ends up in the page.
 *
 * `linkedom` is not a rendering engine, so geometry is stubbed per element exactly as in
 * `adversarial_content_isolation.test.js`, and `document.visibilityState` is a property the test
 * controls. Each frame has a `navigator.clipboard` that counts writes, and can hold its long
 * timers for the test to fire, so the tripwire's ten seconds do not have to be waited out.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseHTML } = require("linkedom");

const SHARED = path.join(__dirname, "..", "..", "shared");
const CONTENT_SOURCE = fs.readFileSync(path.join(SHARED, "content.js"), "utf8");
const BACKGROUND_SOURCE = fs.readFileSync(path.join(SHARED, "background.js"), "utf8");

/** Values the fake app releases. Obvious test data wherever they turn up. */
const CANARY_PASSWORD = "canary-agent-password-DO-NOT-SHIP-51c0";
const CANARY_USERNAME = "canary-agent-user@example.test";
const CANARY_ITEM_ID = "item-canary-agent-0000";
const CANARY_CODE = "730514";

const SITE = "https://example.com";
const FRAME_SITE = "https://widget.example-cdn.test";
const EXTENSION_ID = "nlijibjnmanccalmafnfbobkcfjiibmd";

const LOGIN_FORM = `
  <form id="signin">
    <label for="u">Email</label><input id="u" name="username" type="text">
    <label for="p">Password</label><input id="p" name="password" type="password">
    <button type="submit">Sign in</button>
  </form>
`;

const IDENTIFIER_FORM = `
  <form id="first">
    <label for="u">Email or phone</label>
    <input id="u" name="identifier" type="email" autocomplete="username">
    <button type="submit">Next</button>
  </form>
`;

/** Page one of an identifier-first sign-in, and the page Next leads to. */
const PASSWORD_PAGE = `
  <form id="second">
    <label for="p">Enter your password</label>
    <input id="p" name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
`;

/** A second-factor page: a code box, and a search box that must never take the code. */
const CODE_PAGE = `
  <input id="q" name="q" type="search" placeholder="Search help">
  <form id="verify">
    <label for="c">Verification code</label>
    <input id="c" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code">
    <label for="n">Name this device</label>
    <input id="n" name="device" type="text">
    <button type="submit">Verify</button>
  </form>
`;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Poll until `predicate()` is truthy, or fail after `timeoutMs`. */
async function waitFor(predicate, what, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = predicate();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

/** Every console method, recording its arguments, so a test can assert nothing was logged. */
function recordingConsole(sink) {
  const record =
    (level) =>
    (...args) =>
      sink.push({ level, args });
  return {
    log: record("log"),
    info: record("info"),
    warn: record("warn"),
    error: record("error"),
    debug: record("debug"),
    trace: record("trace"),
    dir: record("dir"),
  };
}

/** A `chrome.storage` that records any touch. The extension must never use one. */
function trippedStorage(touches) {
  return new Proxy(
    {},
    {
      get(_target, key) {
        touches.push(String(key));
        return () => Promise.resolve({});
      },
    },
  );
}

// ---------------------------------------------------------------------------------------------
// The fake browser
// ---------------------------------------------------------------------------------------------

/**
 * A browser with a service worker, some tabs, and an app behind the native channel.
 *
 * @param {{
 *   onAgentFill?: (body: object) => object | Promise<object>,
 *   onFill?: (body: object) => object | Promise<object>,
 *   matchItems?: object[],
 * }} [options]
 */
function createBrowser(options = {}) {
  const logs = [];
  const storageTouches = [];
  const browser = {
    /** Every request body the extension sent the app, in order. */
    requests: [],
    /** Every `tabs.query` argument. */
    queries: [],
    /** Every `tabs.sendMessage` the service worker made: `{ tabId, message, options }`. */
    toTabs: [],
    /** Tabs by id: `{ id, active, windowId, frames: Map<frameId, world> }`. */
    tabs: new Map(),
    /** The tab `tabs.query({ active, lastFocusedWindow })` finds, or `null`. */
    frontTabId: null,
    logs,
    storageTouches,
    /** Called before a message reaches a frame; may answer instead of the frame. */
    intercept: null,
    push: null,
  };

  // --- the app ---------------------------------------------------------------------------------
  const app = {
    ensureHello: async () => ({ status: "ready" }),
    refreshState: async () => ({ status: "ready" }),
    onPush: (listener) => {
      browser.push = listener;
    },
    call: async (body) => {
      browser.requests.push(JSON.parse(JSON.stringify(body)));
      switch (body.ask) {
        case "match":
          return {
            reply: "matches",
            origin: body.page.top_origin,
            items: options.matchItems || [],
          };
        case "fill":
          if (options.onFill) return options.onFill(body);
          return { reply: "error", code: "PROTOCOL", message: "not scripted" };
        case "target_report":
        case "agent_fill_outcome":
          return { reply: "noted" };
        case "agent_fill":
          if (options.onAgentFill) return options.onAgentFill(body);
          return {
            reply: "filled",
            item_id: CANARY_ITEM_ID,
            username: CANARY_USERNAME,
            password: CANARY_PASSWORD,
          };
        default:
          return { reply: "error", code: "PROTOCOL", message: "not scripted" };
      }
    },
  };

  // --- the service worker ----------------------------------------------------------------------
  const workerListeners = [];
  const worker = {
    console: recordingConsole(logs),
    setTimeout,
    clearTimeout,
    Date,
    URL,
    chrome: {
      runtime: { id: EXTENSION_ID, onMessage: { addListener: (fn) => workerListeners.push(fn) } },
      storage: trippedStorage(storageTouches),
      tabs: {
        onRemoved: { addListener: () => {} },
        query: async (query) => {
          browser.queries.push({ ...query });
          const tab = browser.frontTabId === null ? null : browser.tabs.get(browser.frontTabId);
          return tab ? [{ id: tab.id, active: tab.active, windowId: tab.windowId }] : [];
        },
        sendMessage: async (tabId, message, sendOptions) => {
          browser.toTabs.push({
            tabId,
            message: JSON.parse(JSON.stringify(message)),
            options: sendOptions ? { ...sendOptions } : undefined,
          });
          const tab = browser.tabs.get(tabId);
          if (!tab) throw new Error(`No tab with id: ${tabId}`);
          const frameIds =
            sendOptions && typeof sendOptions.frameId === "number"
              ? [sendOptions.frameId]
              : Array.from(tab.frames.keys());
          for (const frameId of frameIds) {
            const world = tab.frames.get(frameId);
            if (!world) continue;
            // Chromium: a `documentId` that is not the frame's current document is a message
            // with no receiver, not a message to whatever document is there now.
            if (sendOptions && sendOptions.documentId !== undefined) {
              if (world.documentId !== sendOptions.documentId) {
                throw new Error("Could not establish connection. Receiving end does not exist.");
              }
            }
            if (browser.intercept) {
              const answered = await browser.intercept({ tab, world, message });
              if (answered) return answered.response;
            }
            return world.receive(message);
          }
          throw new Error("Could not establish connection. Receiving end does not exist.");
        },
      },
    },
  };
  worker.self = worker;
  worker.globalThis = worker;
  worker.importScripts = (...names) => {
    for (const name of names) {
      if (name === "native.js") worker.KsNative = app;
      else if (name === "origin.js") worker.KsOrigin = require(path.join(SHARED, "origin.js"));
      else if (name === "tabmemory.js") {
        worker.KsTabMemory = require(path.join(SHARED, "tabmemory.js"));
      } else throw new Error(`unexpected importScripts(${name})`);
    }
  };
  vm.createContext(worker);
  vm.runInContext(BACKGROUND_SOURCE, worker, { filename: "background.js" });
  browser.worker = worker;

  /** Deliver a message from a content script to the worker, stamped as the browser would. */
  browser.toWorker = (world, message) =>
    new Promise((resolve) => {
      const tab = world.tab;
      // The browser's stamp, built from its own records at the moment of sending.
      const sender = {
        id: EXTENSION_ID,
        origin: world.origin,
        url: `${world.origin}/login`,
        frameId: world.frameId,
        documentId: world.documentId,
        tab: { id: tab.id, active: tab.active, windowId: tab.windowId },
      };
      let answered = false;
      const sendResponse = (response) => {
        if (answered) return;
        answered = true;
        resolve(response);
      };
      for (const listener of workerListeners) {
        if (listener(message, sender, sendResponse) === true) return;
      }
      resolve(undefined);
    });

  /** Open a tab; `front` makes it the active tab of the last-focused window. */
  browser.openTab = async ({ id = 7, active = true, windowId = 1, front = true } = {}) => {
    const tab = { id, active, windowId, frames: new Map() };
    browser.tabs.set(id, tab);
    if (front) browser.frontTabId = id;
    return tab;
  };

  /** Load a document into `frameId` of `tab`, replacing whatever was there: a navigation. */
  browser.load = async (
    tab,
    {
      frameId = 0,
      documentId,
      origin = SITE,
      html = LOGIN_FORM,
      visibility = "visible",
      holdTimersFrom = null,
    } = {},
  ) => {
    const world = await runContentScript(browser, tab, {
      frameId,
      documentId: documentId || `doc-${tab.id}-${frameId}-${Math.random().toString(36).slice(2)}`,
      origin,
      html,
      visibility,
      holdTimersFrom,
    });
    const previous = tab.frames.get(frameId);
    if (previous) previous.stop();
    tab.frames.set(frameId, world);
    return world;
  };

  browser.stopAll = () => {
    for (const tab of browser.tabs.values()) for (const world of tab.frames.values()) world.stop();
  };

  browser.asks = (ask) => browser.requests.filter((body) => body.ask === ask);

  return browser;
}

/**
 * Run the real `content.js` in a document, as the content script of one frame.
 *
 * @returns {Promise<object>} the world: its document, its listeners, and how to message it
 */
async function runContentScript(
  browser,
  tab,
  { frameId, documentId, origin, html, visibility, holdTimersFrom },
) {
  const parsed = parseHTML(`<!doctype html><html><body>${html}</body></html>`);
  const { document } = parsed;
  // A global of its own. `linkedom`'s `window` writes through to Node's `globalThis`, so two
  // content scripts loaded into it would share one `chrome` — and one sender stamp.
  const global = {};

  const rect = () => ({ width: 220, height: 32, top: 40, left: 10, right: 230, bottom: 72 });
  const stubGeometry = () => {
    for (const el of document.querySelectorAll("*")) {
      if (!el.__ksStubbed) {
        el.getBoundingClientRect = rect;
        el.__ksStubbed = true;
        Object.defineProperty(el, "offsetParent", { value: document.body, configurable: true });
      }
    }
  };
  stubGeometry();
  const geometryTimer = setInterval(stubGeometry, 5);

  const world = {
    tab,
    frameId,
    documentId,
    origin,
    document,
    global,
    parsed,
    visibility,
    listeners: [],
    /** How many times the content script wrote to the clipboard. Counted, never kept. */
    clipboardWrites: 0,
    /** Timers of `holdTimersFrom` ms or more, held for the test: `{ ms, fire }`. */
    heldTimers: [],
    stop: () => clearInterval(geometryTimer),
    /** Hand `message` to this frame's `runtime.onMessage` listeners, as `tabs.sendMessage` does. */
    receive: (message) =>
      new Promise((resolve) => {
        let answered = false;
        const sendResponse = (response) => {
          if (answered) return;
          answered = true;
          resolve(response);
        };
        for (const listener of world.listeners) {
          if (listener(message, { id: EXTENSION_ID }, sendResponse) === true) return;
        }
        if (!answered) resolve(undefined);
      }),
    /** Change the page's visibility, firing the event the browser would. */
    setVisibility: (state) => {
      world.visibility = state;
      document.dispatchEvent(new parsed.Event("visibilitychange"));
    },
  };

  Object.defineProperty(document, "visibilityState", {
    get: () => world.visibility,
    configurable: true,
  });

  // With `holdTimersFrom`, a long timer is not scheduled but held, and the test fires it: time
  // passing, without the wait.
  const held = new Set();
  const frameSetTimeout = (fn, ms, ...args) => {
    if (holdTimersFrom !== null && holdTimersFrom !== undefined && ms >= holdTimersFrom) {
      const handle = { held: true };
      held.add(handle);
      world.heldTimers.push({
        ms,
        fire: () => {
          if (held.delete(handle)) fn(...args);
        },
      });
      return handle;
    }
    return setTimeout(fn, ms, ...args);
  };
  const frameClearTimeout = (handle) => {
    if (handle && handle.held) held.delete(handle);
    else clearTimeout(handle);
  };

  Object.assign(global, {
    document,
    chrome: {
      runtime: {
        id: EXTENSION_ID,
        lastError: undefined,
        onMessage: { addListener: (fn) => world.listeners.push(fn) },
        sendMessage: (message, callback) => {
          browser.toWorker(world, message).then((response) => callback(response));
        },
      },
      storage: trippedStorage(browser.storageTouches),
    },
    KsForms: require(path.join(SHARED, "forms.js")),
    KsOrigin: require(path.join(SHARED, "origin.js")),
    console: recordingConsole(browser.logs),
    setTimeout: frameSetTimeout,
    clearTimeout: frameClearTimeout,
    MutationObserver: parsed.MutationObserver,
    navigator: {
      clipboard: {
        writeText: async () => {
          world.clipboardWrites += 1;
        },
      },
    },
    scrollX: 0,
    scrollY: 0,
    location: { href: `${origin}/login`, ancestorOrigins: frameId === 0 ? null : [SITE] },
    addEventListener: () => {},
    removeEventListener: () => {},
  });
  global.window = global;
  global.self = global;
  global.globalThis = global;
  // A sub-frame's `window.top` is its embedder's window, never itself.
  global.top = frameId === 0 ? global : { embedder: true };

  vm.createContext(global);
  vm.runInContext(CONTENT_SOURCE, global, { filename: "content.js" });
  // `content.js` debounces its first scan by 250 ms and then awaits a `match`.
  await sleep(350);
  return world;
}

/** A top-frame login page in tab 7, in front. */
async function loginPageInFront(browser, overrides = {}) {
  const tab = await browser.openTab();
  const top = await browser.load(tab, { documentId: "doc-A", ...overrides });
  return { tab, top };
}

/** Ring `locate` and wait until the app has the report. */
async function locate(browser, probeId) {
  const before = browser.asks("target_report").length;
  browser.push({ push: "locate", probe_id: probeId });
  await waitFor(() => browser.asks("target_report").length > before, "a target report");
  return browser.asks("target_report")[before];
}

/**
 * Ring `deliver` and wait until the app has heard how it went.
 *
 * `timeoutMs` only matters for a delivery that stays hidden the whole time: `content.js` then
 * waits out its own `AGENT_VISIBILITY_WAIT_MS` before filling anyway.
 */
async function deliver(browser, probeId, grantId, timeoutMs = 3000) {
  browser.push({ push: "deliver", probe_id: probeId, grant_id: grantId });
  await waitFor(
    () => browser.asks("agent_fill_outcome").some((body) => body.grant_id === grantId),
    "an agent fill outcome",
    timeoutMs,
  );
  // Let any straggling message settle so a test sees the final state.
  await sleep(20);
  return browser.asks("agent_fill_outcome").filter((body) => body.grant_id === grantId);
}

// ---------------------------------------------------------------------------------------------
// Locate
// ---------------------------------------------------------------------------------------------

test("agent_locate_reports_only_from_the_top_frame", async () => {
  const browser = createBrowser();
  try {
    const tab = await browser.openTab();
    await browser.load(tab, { documentId: "doc-A" });
    const frame = await browser.load(tab, {
      frameId: 3,
      documentId: "doc-frame",
      origin: FRAME_SITE,
    });

    // Before the top frame answers, the sub-frame — whose page script may control what its
    // content script says — sends a report for the same probe, as if it were the one in front.
    let forged = null;
    browser.intercept = async ({ message }) => {
      if (message.kind === "agent-locate" && forged === null) {
        forged = await browser.toWorker(frame, {
          kind: "agent-report",
          probeId: message.probeId,
          visible: true,
          found: { username: true, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
        });
      }
      return null;
    };

    const report = await locate(browser, "probe-1");
    await sleep(20);

    assert.equal(forged.ok, false, "the worker accepted a report from a sub-frame");
    assert.equal(browser.asks("target_report").length, 1, "one probe, one report");
    assert.deepEqual(report.page, {
      top_origin: SITE,
      frame_origin: null,
      top_origin_established: true,
    });
    assert.equal(report.tab.document_id, "doc-A");

    // The worker asked frame 0 and nothing else, through the API rather than by convention.
    const asked = browser.toTabs.filter((sent) => sent.message.kind === "agent-locate");
    assert.equal(asked.length, 1);
    assert.deepEqual(asked[0].options, { frameId: 0 });
    assert.equal(asked[0].tabId, tab.id);
    assert.deepEqual(browser.queries, [
      { active: true, lastFocusedWindow: true, windowType: "normal" },
    ]);

    // And a sub-frame's content script refuses the question even if it were asked.
    const direct = await frame.receive({ kind: "agent-locate", probeId: "probe-2" });
    assert.equal(direct.ok, false);
  } finally {
    browser.stopAll();
  }
});

test("the_report_takes_origin_tab_and_document_from_the_sender", async () => {
  const browser = createBrowser();
  try {
    // The browser's view: tab 7, not the active tab of its window, document doc-A, example.com.
    const tab = await browser.openTab({ active: false });
    const top = await browser.load(tab, { documentId: "doc-A" });

    // A content script whose world has been subverted claims to be somewhere and something else.
    browser.intercept = async ({ message }) => {
      if (message.kind !== "agent-locate") return null;
      await browser.toWorker(top, {
        kind: "agent-report",
        probeId: message.probeId,
        page: { top_origin: "https://bank.test", frame_origin: null, top_origin_established: true },
        tab: { tab_id: 99, document_id: "forged-doc", tab_active: true, visible: true },
        tabId: 99,
        documentId: "forged-doc",
        origin: "https://bank.test",
        visible: true,
        found: { username: "yes", password: true, one_time_code: 1, value: CANARY_PASSWORD },
      });
      return { response: { ok: true } };
    };

    const report = await locate(browser, "probe-stamp");
    assert.deepEqual(report, {
      ask: "target_report",
      probe_id: "probe-stamp",
      page: { top_origin: SITE, frame_origin: null, top_origin_established: true },
      tab: { tab_id: tab.id, document_id: "doc-A", tab_active: false, visible: true },
      found: { username: false, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
    });
  } finally {
    browser.stopAll();
  }
});

test("a real report carries what the detectors found and nothing that names a field", async () => {
  const browser = createBrowser();
  try {
    await loginPageInFront(browser);
    const report = await locate(browser, "probe-login");
    assert.deepEqual(report.found, { username: true, password: true, one_time_code: false, sign_up: false, sign_up_username: false });
    assert.deepEqual(report.tab, {
      tab_id: 7,
      document_id: "doc-A",
      tab_active: true,
      visible: true,
    });
    assert.deepEqual(Object.keys(report).sort(), ["ask", "found", "page", "probe_id", "tab"]);
  } finally {
    browser.stopAll();
  }
});

test("an identifier-only page reports a username and no password", async () => {
  const browser = createBrowser();
  try {
    await loginPageInFront(browser, { html: IDENTIFIER_FORM });
    const report = await locate(browser, "probe-identifier");
    assert.equal(report.found.username, true);
    assert.equal(report.found.password, false);
  } finally {
    browser.stopAll();
  }
});

test("a hidden document is reported as not visible, without waiting", async () => {
  const browser = createBrowser();
  try {
    await loginPageInFront(browser, { visibility: "hidden" });
    const started = Date.now();
    const report = await locate(browser, "probe-hidden");
    assert.equal(report.tab.visible, false);
    assert.ok(Date.now() - started < 1000, "a report must describe the page as it is");
  } finally {
    browser.stopAll();
  }
});

test("with no tab in front the app still gets a report, ineligible on every count", async () => {
  const browser = createBrowser();
  try {
    const report = await locate(browser, "probe-nothing");
    assert.deepEqual(report, {
      ask: "target_report",
      probe_id: "probe-nothing",
      page: { top_origin: "null", frame_origin: null, top_origin_established: false },
      tab: { tab_id: 0, document_id: null, tab_active: false, visible: false },
      found: { username: false, password: false, one_time_code: false, sign_up: false, sign_up_username: false },
    });
  } finally {
    browser.stopAll();
  }
});

test("a tab with no content script is reported the same as no tab", async () => {
  const browser = createBrowser();
  try {
    // An internal page, the store, a PDF: a tab, but nothing in it to ask.
    await browser.openTab();
    const report = await locate(browser, "probe-internal");
    assert.equal(report.page.top_origin_established, false);
    assert.equal(report.tab.tab_active, false);
  } finally {
    browser.stopAll();
  }
});

test("an unknown push, or a push with a malformed id, reaches no tab", async () => {
  const browser = createBrowser();
  try {
    await loginPageInFront(browser);
    for (const push of [
      { push: "fill", probe_id: "p" },
      { push: "locate" },
      { push: "locate", probe_id: 7 },
      { push: "locate", probe_id: "" },
      { push: "deliver", probe_id: "p" },
      null,
      "locate",
    ]) {
      browser.push(push);
    }
    await sleep(50);
    assert.deepEqual(browser.toTabs, []);
    assert.deepEqual(browser.asks("target_report"), []);
  } finally {
    browser.stopAll();
  }
});

// ---------------------------------------------------------------------------------------------
// Deliver
// ---------------------------------------------------------------------------------------------

test("an approved delivery writes the login and reports field names only", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-ok");
    const outcomes = await deliver(browser, "probe-ok", "grant-ok");

    assert.equal(top.document.getElementById("u").value, CANARY_USERNAME);
    assert.equal(top.document.getElementById("p").value, CANARY_PASSWORD);
    assert.deepEqual(outcomes, [
      {
        ask: "agent_fill_outcome",
        grant_id: "grant-ok",
        written: ["username", "password"],
        failure: null,
      },
    ]);

    // The delivery went to exactly the reported tab, frame and document.
    const delivered = browser.toTabs.filter((sent) => sent.message.kind === "agent-deliver");
    assert.deepEqual(delivered, [
      {
        tabId: 7,
        message: { kind: "agent-deliver", grantId: "grant-ok" },
        options: { frameId: 0, documentId: "doc-A" },
      },
    ]);
    // And the grant was redeemed with facts the browser stamped, again.
    assert.deepEqual(browser.asks("agent_fill"), [
      {
        ask: "agent_fill",
        grant_id: "grant-ok",
        page: { top_origin: SITE, frame_origin: null, top_origin_established: true },
        tab: { tab_id: 7, document_id: "doc-A", tab_active: true, visible: true },
        found: { username: true, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
      },
    ]);
  } finally {
    browser.stopAll();
  }
});

test("a_delivery_rechecks_the_form_before_writing", async (t) => {
  await t.test("a password field retyped after the report takes no value", async () => {
    // The worst-case app: it releases both fields whatever the delivery says it found. What
    // stops the write is the content script's own re-check.
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser);
      await locate(browser, "probe-retype");
      // While the human reads the sheet, the page turns its password box into a text box.
      top.document.getElementById("p").setAttribute("type", "text");

      const outcomes = await deliver(browser, "probe-retype", "grant-retype");
      assert.equal(top.document.getElementById("p").value, "", "a value went into a text box");
      assert.equal(top.document.getElementById("u").value, "", "half a fill was written");
      assert.equal(outcomes.length, 1);
      assert.deepEqual(outcomes[0].written, []);
      assert.ok(
        ["FORM_CHANGED", "NOT_WRITABLE"].includes(outcomes[0].failure),
        String(outcomes[0].failure),
      );
      for (const body of browser.asks("agent_fill")) {
        assert.equal(body.found.password, false, "the delivery claimed a password field");
      }
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a password field retyped while the app answers takes no value", async () => {
    let page = null;
    const browser = createBrowser({
      onAgentFill: () => {
        // The last moment the page has: after the request left, before the reply lands.
        page.document.getElementById("p").setAttribute("type", "text");
        return {
          reply: "filled",
          item_id: CANARY_ITEM_ID,
          username: CANARY_USERNAME,
          password: CANARY_PASSWORD,
        };
      },
    });
    try {
      const { top } = await loginPageInFront(browser);
      page = top;
      await locate(browser, "probe-race");
      const outcomes = await deliver(browser, "probe-race", "grant-race");
      assert.equal(browser.asks("agent_fill").length, 1);
      assert.equal(top.document.getElementById("p").value, "");
      assert.equal(top.document.getElementById("u").value, "", "all of it or none of it");
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "NOT_WRITABLE"]],
      );
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a form removed after the report is not asked for", async () => {
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser);
      await locate(browser, "probe-gone");
      top.document.getElementById("signin").remove();
      const outcomes = await deliver(browser, "probe-gone", "grant-gone");
      assert.deepEqual(browser.asks("agent_fill"), [], "the grant was redeemed for no form");
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "FORM_CHANGED"]],
      );
    } finally {
      browser.stopAll();
    }
  });
});

test("a_deliver_for_a_different_document_id_writes_nothing", async () => {
  const browser = createBrowser();
  try {
    const { tab } = await loginPageInFront(browser);
    await locate(browser, "probe-nav");
    // The tab navigates — to the same site, the same form — before the delivery arrives.
    const next = await browser.load(tab, { documentId: "doc-B" });

    const outcomes = await deliver(browser, "probe-nav", "grant-nav");
    assert.equal(next.document.getElementById("p").value, "");
    assert.equal(next.document.getElementById("u").value, "");
    assert.deepEqual(browser.asks("agent_fill"), [], "the new document redeemed the grant");
    assert.deepEqual(
      outcomes.map((o) => [o.written, o.failure]),
      [[[], "FORM_CHANGED"]],
    );

    // Nor can the new document redeem the grant by quoting its id itself.
    const forged = await browser.toWorker(next, {
      kind: "agent-fill",
      grantId: "grant-nav",
      visible: true,
      found: { username: true, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
    });
    assert.equal(forged.ok, false);
    assert.deepEqual(browser.asks("agent_fill"), []);
  } finally {
    browser.stopAll();
  }
});

test("a grant is redeemed once, and only by the document it was delivered to", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser);
    const other = await browser.load(await browser.openTab({ id: 8, front: false }), {
      documentId: "doc-other",
    });
    await locate(browser, "probe-once");
    await deliver(browser, "probe-once", "grant-once");
    assert.equal(browser.asks("agent_fill").length, 1);

    for (const world of [top, other]) {
      const again = await browser.toWorker(world, {
        kind: "agent-fill",
        grantId: "grant-once",
        visible: true,
        found: { username: true, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
      });
      assert.equal(again.ok, false);
    }
    assert.equal(browser.asks("agent_fill").length, 1, "a grant was redeemed twice");
  } finally {
    browser.stopAll();
  }
});

test("a hidden document at delivery is given time to come back", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-cover");
    // The approval sheet covered the window; the document reads hidden until it is gone.
    top.visibility = "hidden";
    setTimeout(() => top.setVisibility("visible"), 150);
    const outcomes = await deliver(browser, "probe-cover", "grant-cover");
    assert.equal(top.document.getElementById("p").value, CANARY_PASSWORD);
    assert.deepEqual(
      outcomes.map((o) => o.failure),
      [null],
    );
  } finally {
    browser.stopAll();
  }
});

test("a document that stays hidden is still filled (background tabs are targets)", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-hidden-2");
    top.visibility = "hidden";
    const outcomes = await deliver(browser, "probe-hidden-2", "grant-hidden-2", 5000);
    assert.equal(browser.asks("agent_fill").length, 1);
    assert.equal(top.document.getElementById("p").value, CANARY_PASSWORD);
    assert.deepEqual(
      outcomes.map((o) => o.failure),
      [null],
    );
  } finally {
    browser.stopAll();
  }
});

test("a refusal from the app writes nothing and needs no outcome", async () => {
  const browser = createBrowser({
    onAgentFill: () => ({ reply: "error", code: "PROTOCOL", message: "No fill is waiting." }),
  });
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-refused");
    browser.push({ push: "deliver", probe_id: "probe-refused", grant_id: "grant-refused" });
    await waitFor(() => browser.asks("agent_fill").length === 1, "the agent fill request");
    await sleep(50);
    assert.equal(top.document.getElementById("p").value, "");
    assert.deepEqual(browser.asks("agent_fill_outcome"), []);
  } finally {
    browser.stopAll();
  }
});

// ---------------------------------------------------------------------------------------------
// Identifier-first: one approval, two pages (ADR-0036 §7.3)
// ---------------------------------------------------------------------------------------------

/** What the app releases for each step of a two-step grant, keyed on the grant id. */
function twoStepReplies(body) {
  if (body.grant_id === "grant-step-1") {
    return { reply: "filled", item_id: CANARY_ITEM_ID, username: CANARY_USERNAME };
  }
  if (body.grant_id === "grant-step-2") {
    return { reply: "filled", item_id: CANARY_ITEM_ID, password: CANARY_PASSWORD };
  }
  return { reply: "error", code: "PROTOCOL", message: "No fill is waiting." };
}

test("an_identifier_only_page_takes_only_the_username", async (t) => {
  await t.test("a reply with the username alone writes it and reports it", async () => {
    const browser = createBrowser({ onAgentFill: twoStepReplies });
    try {
      const { top } = await loginPageInFront(browser, {
        html: IDENTIFIER_FORM,
        holdTimersFrom: 10_000,
      });
      const report = await locate(browser, "probe-step-1");
      assert.deepEqual(report.found, { username: true, password: false, one_time_code: false, sign_up: false, sign_up_username: false });

      const outcomes = await deliver(browser, "probe-step-1", "grant-step-1");
      assert.equal(top.document.getElementById("u").value, CANARY_USERNAME);
      assert.deepEqual(outcomes, [
        {
          ask: "agent_fill_outcome",
          grant_id: "grant-step-1",
          written: ["username"],
          failure: null,
        },
      ]);
      // The redeeming request told the app the same thing the report did.
      assert.deepEqual(browser.asks("agent_fill")[0].found, {
        username: true,
        password: false,
        one_time_code: false,
        sign_up: false,
        sign_up_username: false,
      });
      // A username is not what the tripwire is for.
      assert.deepEqual(top.heldTimers, [], "a username-only fill armed the tripwire");
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a reply that also carries a password writes nothing", async () => {
    // The worst-case app releases both fields to page one. There is nowhere for the password to
    // go, and all or nothing means the username stays unwritten too.
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser, { html: IDENTIFIER_FORM });
      await locate(browser, "probe-greedy");
      const outcomes = await deliver(browser, "probe-greedy", "grant-greedy");
      assert.equal(top.document.getElementById("u").value, "");
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "NOT_WRITABLE"]],
      );
      assert.equal(
        top.document.querySelectorAll("input[type=password]").length,
        0,
        "a password field appeared from nowhere",
      );
    } finally {
      browser.stopAll();
    }
  });
});

test("the_second_page_reports_its_password_field", async () => {
  const browser = createBrowser({ onAgentFill: twoStepReplies });
  try {
    const { tab, top } = await loginPageInFront(browser, {
      html: IDENTIFIER_FORM,
      documentId: "doc-step-1",
    });
    await locate(browser, "probe-step-1");
    const first = await deliver(browser, "probe-step-1", "grant-step-1");
    assert.deepEqual(first[0].written, ["username"]);
    assert.equal(top.document.getElementById("u").value, CANARY_USERNAME);

    // The agent presses Next; the site loads its password page as a new document in the same tab.
    // The app starts again with a new probe and a new grant id — at once, with nothing on this
    // side waiting out a window first.
    const next = await browser.load(tab, { html: PASSWORD_PAGE, documentId: "doc-step-2" });
    const report = await locate(browser, "probe-step-2");
    assert.deepEqual(report, {
      ask: "target_report",
      probe_id: "probe-step-2",
      page: { top_origin: SITE, frame_origin: null, top_origin_established: true },
      tab: { tab_id: 7, document_id: "doc-step-2", tab_active: true, visible: true },
      found: { username: false, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
    });

    const second = await deliver(browser, "probe-step-2", "grant-step-2");
    assert.equal(next.document.getElementById("p").value, CANARY_PASSWORD);
    assert.deepEqual(second, [
      {
        ask: "agent_fill_outcome",
        grant_id: "grant-step-2",
        written: ["password"],
        failure: null,
      },
    ]);
    const delivered = browser.toTabs
      .filter((sent) => sent.message.kind === "agent-deliver")
      .map((sent) => [sent.message.grantId, sent.options.documentId]);
    assert.deepEqual(delivered, [
      ["grant-step-1", "doc-step-1"],
      ["grant-step-2", "doc-step-2"],
    ]);

    // Page one's grant is spent, and was never page two's to redeem.
    const replay = await browser.toWorker(next, {
      kind: "agent-fill",
      grantId: "grant-step-1",
      visible: true,
      found: { username: false, password: true, one_time_code: false, sign_up: false, sign_up_username: false },
    });
    assert.equal(replay.ok, false);
    assert.equal(browser.asks("agent_fill").length, 2);
    // The two steps are the app's; the human path's tab memory was neither read nor made.
    assert.equal(browser.worker.KsTabMemory.peek(7, Date.now()), null);
  } finally {
    browser.stopAll();
  }
});

// ---------------------------------------------------------------------------------------------
// One-time codes (ADR-0036 §7.4)
// ---------------------------------------------------------------------------------------------

const codeReply = () => ({
  reply: "totp_code",
  item_id: CANARY_ITEM_ID,
  code: CANARY_CODE,
  seconds_remaining: 21,
});

test("a_code_is_written_only_into_the_detected_code_field", async (t) => {
  await t.test("into the code box, and no other box on the page", async () => {
    const browser = createBrowser({ onAgentFill: codeReply });
    try {
      const { top } = await loginPageInFront(browser, { html: CODE_PAGE });
      const report = await locate(browser, "probe-code");
      assert.deepEqual(report.found, { username: false, password: false, one_time_code: true, sign_up: false, sign_up_username: false });

      const outcomes = await deliver(browser, "probe-code", "grant-code");
      assert.equal(top.document.getElementById("c").value, CANARY_CODE);
      assert.equal(top.document.getElementById("q").value, "");
      assert.equal(top.document.getElementById("n").value, "");
      assert.deepEqual(outcomes, [
        {
          ask: "agent_fill_outcome",
          grant_id: "grant-code",
          written: ["one_time_code"],
          failure: null,
        },
      ]);
      assert.equal(top.clipboardWrites, 0);
      assert.deepEqual(browser.logs, []);
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a code box the page moved while the app answered takes nothing", async () => {
    let page = null;
    const browser = createBrowser({
      onAgentFill: () => {
        // The page declares a different box to be the code box after the request left.
        page.document.getElementById("c").removeAttribute("autocomplete");
        page.document.getElementById("n").setAttribute("autocomplete", "one-time-code");
        return codeReply();
      },
    });
    try {
      const { top } = await loginPageInFront(browser, { html: CODE_PAGE });
      page = top;
      await locate(browser, "probe-moved");
      const outcomes = await deliver(browser, "probe-moved", "grant-moved");
      for (const id of ["c", "n", "q"]) {
        assert.equal(top.document.getElementById(id).value, "", `#${id} took a value`);
      }
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "FORM_CHANGED"]],
      );
      assert.equal(top.clipboardWrites, 0);
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a login reply on a code page writes nothing", async () => {
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser, { html: CODE_PAGE });
      await locate(browser, "probe-cross");
      const outcomes = await deliver(browser, "probe-cross", "grant-cross");
      for (const id of ["c", "n", "q"]) {
        assert.equal(top.document.getElementById(id).value, "", `#${id} took a value`);
      }
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "NOT_WRITABLE"]],
      );
    } finally {
      browser.stopAll();
    }
  });
});

test("no_clipboard_fallback_for_an_agent_code", async (t) => {
  await t.test("a page with no code field", async () => {
    // The worst-case app answers a code to a login page. The human path would copy it.
    const browser = createBrowser({ onAgentFill: codeReply });
    try {
      const { top } = await loginPageInFront(browser);
      await locate(browser, "probe-no-box");
      const outcomes = await deliver(browser, "probe-no-box", "grant-no-box");
      assert.equal(top.clipboardWrites, 0, "an agent's code went to the clipboard");
      assert.equal(top.document.getElementById("u").value, "");
      assert.equal(top.document.getElementById("p").value, "");
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "NOT_WRITABLE"]],
      );
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a code field removed while the app answered", async () => {
    let page = null;
    const browser = createBrowser({
      onAgentFill: () => {
        page.document.getElementById("verify").remove();
        return codeReply();
      },
    });
    try {
      const { top } = await loginPageInFront(browser, { html: CODE_PAGE });
      page = top;
      await locate(browser, "probe-gone-box");
      const outcomes = await deliver(browser, "probe-gone-box", "grant-gone-box");
      assert.equal(top.clipboardWrites, 0, "an agent's code went to the clipboard");
      assert.equal(top.document.getElementById("q").value, "");
      assert.deepEqual(
        outcomes.map((o) => [o.written, o.failure]),
        [[[], "NOT_WRITABLE"]],
      );
      assert.deepEqual(browser.logs, []);
    } finally {
      browser.stopAll();
    }
  });
});

// ---------------------------------------------------------------------------------------------
// The tripwire (ADR-0036 §8.3)
// ---------------------------------------------------------------------------------------------

test("the_tripwire_clears_a_field_whose_type_flips", async (t) => {
  await t.test("a show-password click after the fill", async () => {
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser);
      await locate(browser, "probe-peek");
      await deliver(browser, "probe-peek", "grant-peek");
      const password = top.document.getElementById("p");
      assert.equal(password.value, CANARY_PASSWORD);

      // The site's own eye icon, clicked by an agent that reads screenshots.
      password.setAttribute("type", "text");
      await waitFor(
        () => browser.asks("agent_fill_outcome").length === 2,
        "the tripwire's outcome",
      );
      assert.equal(password.value, "", "the unmasked password stayed in the field");
      assert.equal(top.document.getElementById("u").value, CANARY_USERNAME);
      assert.deepEqual(browser.asks("agent_fill_outcome"), [
        {
          ask: "agent_fill_outcome",
          grant_id: "grant-peek",
          written: ["username", "password"],
          failure: null,
        },
        {
          ask: "agent_fill_outcome",
          grant_id: "grant-peek",
          written: ["password"],
          failure: "UNMASKED",
        },
      ]);

      // It trips once. Flipping again reports nothing more.
      password.setAttribute("type", "password");
      password.setAttribute("type", "text");
      await sleep(50);
      assert.equal(browser.asks("agent_fill_outcome").length, 2);
    } finally {
      browser.stopAll();
    }
  });

  await t.test("a page that flips the type from its own input handler", async () => {
    const browser = createBrowser();
    try {
      const { top } = await loginPageInFront(browser);
      await locate(browser, "probe-handler");
      const password = top.document.getElementById("p");
      // The type is re-checked immediately before the write; the page flips it during the write.
      password.addEventListener("input", () => password.setAttribute("type", "text"));
      await deliver(browser, "probe-handler", "grant-handler");
      await waitFor(
        () => browser.asks("agent_fill_outcome").length === 2,
        "the tripwire's outcome",
      );
      assert.equal(password.value, "");
      assert.deepEqual(
        browser.asks("agent_fill_outcome").map((o) => [o.written, o.failure]),
        [
          [["username", "password"], null],
          [["password"], "UNMASKED"],
        ],
      );
    } finally {
      browser.stopAll();
    }
  });

  await t.test("the worker takes an UNMASKED follow-up only after a password", async () => {
    const browser = createBrowser({ onAgentFill: twoStepReplies });
    try {
      const { top } = await loginPageInFront(browser, { html: IDENTIFIER_FORM });
      await locate(browser, "probe-step-1");
      await deliver(browser, "probe-step-1", "grant-step-1");
      const forged = await browser.toWorker(top, {
        kind: "agent-fill-outcome",
        grantId: "grant-step-1",
        written: ["password"],
        failure: "UNMASKED",
      });
      assert.equal(forged.ok, false);
      assert.equal(browser.asks("agent_fill_outcome").length, 1);
    } finally {
      browser.stopAll();
    }
  });
});

test("the_tripwire_ignores_human_fills", async () => {
  const browser = createBrowser({
    matchItems: [
      { item_id: CANARY_ITEM_ID, title: "Example", username: "", has_totp: false },
    ],
    onFill: () => ({
      reply: "filled",
      item_id: CANARY_ITEM_ID,
      username: CANARY_USERNAME,
      password: CANARY_PASSWORD,
    }),
  });
  try {
    const { top } = await loginPageInFront(browser, { holdTimersFrom: 10_000 });
    // ⌘\ from the extension's own command: the human path, end to end.
    await top.receive({ kind: "shortcut-fill" });
    const password = top.document.getElementById("p");
    await waitFor(() => password.value === CANARY_PASSWORD, "the human fill");
    assert.equal(browser.asks("fill").length, 1);

    // The human reveals their own password. That is theirs to do.
    password.setAttribute("type", "text");
    await sleep(50);
    assert.equal(password.value, CANARY_PASSWORD, "a human fill was cleared");
    assert.deepEqual(browser.asks("agent_fill_outcome"), []);
    assert.deepEqual(top.heldTimers, [], "a human fill armed a tripwire");
  } finally {
    browser.stopAll();
  }
});

test("the_tripwire_stops_after_ten_seconds", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser, { holdTimersFrom: 10_000 });
    await locate(browser, "probe-late");
    await deliver(browser, "probe-late", "grant-late");
    const password = top.document.getElementById("p");
    assert.equal(password.value, CANARY_PASSWORD);

    // One watch, for exactly ten seconds — which pass now.
    assert.deepEqual(
      top.heldTimers.map((timer) => timer.ms),
      [10_000],
    );
    top.heldTimers[0].fire();

    password.setAttribute("type", "text");
    await sleep(50);
    assert.equal(password.value, CANARY_PASSWORD, "the tripwire outlived its ten seconds");
    assert.deepEqual(
      browser.asks("agent_fill_outcome").map((o) => o.failure),
      [null],
    );
  } finally {
    browser.stopAll();
  }
});

// ---------------------------------------------------------------------------------------------
// What the value touches
// ---------------------------------------------------------------------------------------------

/** Every string reachable from `root`, walking objects, arrays, maps and sets, cycles cut. */
function reachableStrings(root, seen = new Set(), out = [], depth = 0) {
  if (typeof root === "string") {
    out.push(root);
    return out;
  }
  if (root === null || typeof root !== "object") return out;
  if (seen.has(root) || depth > 8) return out;
  seen.add(root);
  if (root instanceof Map) {
    for (const [k, v] of root) {
      reachableStrings(k, seen, out, depth + 1);
      reachableStrings(v, seen, out, depth + 1);
    }
    return out;
  }
  if (root instanceof Set) {
    for (const v of root) reachableStrings(v, seen, out, depth + 1);
    return out;
  }
  for (const key of Object.getOwnPropertyNames(root)) {
    let value;
    try {
      value = root[key];
    } catch {
      continue;
    }
    reachableStrings(value, seen, out, depth + 1);
  }
  return out;
}

test("a push never causes a value to be stored or logged", async () => {
  const browser = createBrowser();
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-canary");
    await deliver(browser, "probe-canary", "grant-canary");
    // A second probe after the fill: nothing about the first one's value may ride along.
    await locate(browser, "probe-after");

    assert.equal(top.document.getElementById("p").value, CANARY_PASSWORD, "the fill happened");
    const leaks = (strings) =>
      strings.filter((s) => s.includes(CANARY_PASSWORD) || s.includes(CANARY_USERNAME));

    // Nothing was logged, by either side, at any level.
    assert.deepEqual(browser.logs, [], "the extension wrote to the console");
    // No storage was touched.
    assert.deepEqual(browser.storageTouches, [], "the extension touched chrome.storage");
    // Nothing the extension sent the app, or sent a tab, carries a value.
    assert.deepEqual(leaks(reachableStrings(browser.requests)), [], "a request carried a value");
    assert.deepEqual(leaks(reachableStrings(browser.toTabs)), [], "a tab message carried a value");

    // The service worker holds none of it: not as a global, not in its agent-fill bookkeeping,
    // not in the tab memory.
    const workerGlobals = {};
    for (const key of Object.getOwnPropertyNames(browser.worker)) {
      if (key !== "KsNative") workerGlobals[key] = browser.worker[key];
    }
    assert.deepEqual(leaks(reachableStrings(workerGlobals)), [], "a worker global holds a value");
    const bookkeeping = vm.runInContext(
      "[Array.from(agentProbes.entries()), Array.from(agentDeliveries.entries())]",
      browser.worker,
    );
    assert.deepEqual(leaks(reachableStrings(bookkeeping)), []);
    assert.equal(
      browser.worker.KsTabMemory.peek(7, Date.now()),
      null,
      "an agent fill made a tab memory",
    );

    // The content script holds none of it outside the field it was written into.
    const contentGlobals = [];
    for (const key of Object.getOwnPropertyNames(top.global)) {
      let value;
      try {
        value = top.global[key];
      } catch {
        continue;
      }
      if (typeof value === "string") contentGlobals.push(value);
    }
    assert.deepEqual(leaks(contentGlobals), [], "a content-script global holds a value");
  } finally {
    browser.stopAll();
  }
});

// ---------------------------------------------------------------------------------------------
// Sign-up fills (ADR-0048 §7)
// ---------------------------------------------------------------------------------------------

/** The test app's register form: a username and two new-password boxes. */
const SIGNUP_FORM = `
  <form id="register" method="post" action="/register">
    <label for="u">Email or username</label>
    <input id="u" name="username" type="text" autocomplete="username">
    <label for="p1">Password</label>
    <input id="p1" name="password" type="password" autocomplete="new-password">
    <label for="p2">Confirm password</label>
    <input id="p2" name="confirm" type="password" autocomplete="new-password">
    <button type="submit">Create account</button>
  </form>
`;

const signUpReply = () => ({
  reply: "filled",
  item_id: CANARY_ITEM_ID,
  username: CANARY_USERNAME,
  new_password: CANARY_PASSWORD,
});

test("a_sign_up_delivery_writes_both_boxes_and_reports_names_only", async () => {
  const browser = createBrowser({ onAgentFill: signUpReply });
  try {
    const { top } = await loginPageInFront(browser, { html: SIGNUP_FORM });
    const report = await locate(browser, "probe-signup");
    assert.deepEqual(report.found, {
      username: false,
      password: false,
      one_time_code: false,
      sign_up: true,
      sign_up_username: true,
    });
    const outcomes = await deliver(browser, "probe-signup", "grant-signup");
    assert.equal(top.document.getElementById("u").value, CANARY_USERNAME);
    assert.equal(top.document.getElementById("p1").value, CANARY_PASSWORD);
    assert.equal(top.document.getElementById("p2").value, CANARY_PASSWORD);
    assert.deepEqual(outcomes, [
      {
        ask: "agent_fill_outcome",
        grant_id: "grant-signup",
        written: ["username", "new_password"],
        failure: null,
      },
    ]);
    assert.equal(browser.asks("agent_fill")[0].found.sign_up, true);
    assert.deepEqual(browser.logs, []);
  } finally {
    browser.stopAll();
  }
});

test("a_sign_up_form_changed_between_report_and_delivery_takes_nothing", async () => {
  const browser = createBrowser({ onAgentFill: signUpReply });
  try {
    const { top } = await loginPageInFront(browser, { html: SIGNUP_FORM });
    await locate(browser, "probe-signup-dom");
    // A third password box appears: no longer a sign-up form the detector accepts.
    const extra = top.document.createElement("input");
    extra.id = "p3";
    extra.setAttribute("type", "password");
    top.document.getElementById("register").appendChild(extra);
    const outcomes = await deliver(browser, "probe-signup-dom", "grant-signup-dom");
    for (const id of ["u", "p1", "p2", "p3"]) {
      assert.equal(top.document.getElementById(id).value, "", id);
    }
    assert.deepEqual(outcomes[0].written, []);
    assert.ok(outcomes[0].failure, "a failure was reported");
  } finally {
    browser.stopAll();
  }
});

test("a_sign_up_reply_carrying_both_members_writes_nothing", async () => {
  const browser = createBrowser({
    onAgentFill: () => ({ ...signUpReply(), password: CANARY_PASSWORD }),
  });
  try {
    const { top } = await loginPageInFront(browser, { html: SIGNUP_FORM });
    await locate(browser, "probe-both");
    const outcomes = await deliver(browser, "probe-both", "grant-both");
    for (const id of ["u", "p1", "p2"]) {
      assert.equal(top.document.getElementById(id).value, "", id);
    }
    assert.deepEqual(outcomes.map((o) => [o.written, o.failure]), [[[], "NOT_WRITABLE"]]);
  } finally {
    browser.stopAll();
  }
});

test("a_password_reply_on_a_sign_up_target_writes_nothing", async () => {
  const browser = createBrowser({
    onAgentFill: () => ({
      reply: "filled",
      item_id: CANARY_ITEM_ID,
      username: CANARY_USERNAME,
      password: CANARY_PASSWORD,
    }),
  });
  try {
    const { top } = await loginPageInFront(browser, { html: SIGNUP_FORM });
    await locate(browser, "probe-pw-on-signup");
    const outcomes = await deliver(browser, "probe-pw-on-signup", "grant-pw-on-signup");
    for (const id of ["u", "p1", "p2"]) {
      assert.equal(top.document.getElementById(id).value, "", id);
    }
    assert.deepEqual(outcomes[0].written, []);
  } finally {
    browser.stopAll();
  }
});

test("a_new_password_reply_on_a_login_form_writes_nothing", async () => {
  const browser = createBrowser({ onAgentFill: signUpReply });
  try {
    const { top } = await loginPageInFront(browser);
    await locate(browser, "probe-new-on-login");
    const outcomes = await deliver(browser, "probe-new-on-login", "grant-new-on-login");
    assert.equal(top.document.getElementById("p").value, "", "a login fill never lands in a new-password box, nor the reverse");
    assert.equal(top.document.getElementById("u").value, "");
    assert.deepEqual(outcomes[0].written, []);
  } finally {
    browser.stopAll();
  }
});

test("the_tripwire_fires_on_the_confirm_box", async () => {
  const browser = createBrowser({ onAgentFill: signUpReply });
  try {
    const { top } = await loginPageInFront(browser, { html: SIGNUP_FORM });
    await locate(browser, "probe-signup-peek");
    await deliver(browser, "probe-signup-peek", "grant-signup-peek");
    const confirm = top.document.getElementById("p2");
    assert.equal(confirm.value, CANARY_PASSWORD);
    confirm.setAttribute("type", "text");
    await waitFor(
      () => browser.asks("agent_fill_outcome").length === 2,
      "the tripwire's outcome",
    );
    assert.equal(confirm.value, "", "the unmasked confirm box kept the password");
    assert.equal(top.document.getElementById("p1").value, "", "the other box kept the password");
    assert.deepEqual(
      browser.asks("agent_fill_outcome").map((o) => [o.written, o.failure]),
      [
        [["username", "new_password"], null],
        [["new_password"], "UNMASKED"],
      ],
    );
  } finally {
    browser.stopAll();
  }
});
