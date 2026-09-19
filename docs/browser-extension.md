# The browser extension

How autofill works, how to set it up, and what is deliberately not built yet.

Companion documents: [threat-model-browser-extension.md](threat-model-browser-extension.md) for
what it costs and what is done about it, and [architecture.md](architecture.md) for everything
below the socket.

---

## 1. What it does

Two things, and only on an explicit action:

- **Fill a login.** Click the key icon that appears in a matched site's password field, or press
  **⌘\\**. The app raises its approval sheet; you approve it once per website per unlock; the
  username and password are written into the form.
- **Fill the username on an identifier-first page.** Google, Microsoft and Okta ask for the
  username on one page and the password on the next. The icon appears in that first page's
  username box too, and the click writes **the username and nothing else** — which carries no
  secret, so there is no approval sheet and no fingerprint. Your click is still required, the
  origin rule still applies, and the fill is still audited, as `FILL_USERNAME_ONLY`
  ([ADR-0030](decisions/0030-identifier-first-login.md)).
- **Copy or fill a one-time code.** A second, separate click. Never bundled into the fill.

There is **no autofill on page load**, ever. Not as a default, not as a setting.

**Page two continues where page one left off.** Having picked an item on the identifier page, the
extension remembers *which item* for that tab — an id and an origin, in memory, for **60 seconds**
— so the password page fills that account instead of asking you to choose again. The popup says so
("Continuing as …") and has a **Forget** button. The memory is dropped when it expires, when the
tab is closed, when the tab leaves the site (subdomains of the site you started at still count;
nothing else does), when the vault locks, or when the password fill happens. Nothing about it is
written to disk, and it chooses *which* item, never *whether* to fill — the click is still yours.

## 2. The shape

```text
   the page                    the extension                    the app
  ┌──────────┐         ┌───────────────────────────┐      ┌──────────────────┐
  │  form    │◀───────▶│ content script            │      │ ExtensionAgent   │
  │  fields  │  writes │  · finds the form         │      │  · origin rule   │
  └──────────┘         │  · draws the icon         │      │  · approval sheet│
                       │  · ⌘\ handler             │      │  · biometric     │
                       │  · writes the value       │      │  · fill leases   │
                       └─────────────┬─────────────┘      │  · audit         │
                          runtime    │  message           └────────┬─────────┘
                       ┌─────────────▼─────────────┐               │ Unix socket
                       │ service worker            │               │ 0600 in a 0700 dir
                       │  · the native port        │               │
                       │  · stamps the real origin │      ┌────────▼─────────┐
                       │  · caches nothing         │◀────▶│ kagisecure-nmhost│
                       └───────────────────────────┘ stdio│  a pipe, no vault│
                                                          └──────────────────┘
```

Four processes, three boundaries, and one value that crosses all of them — once, per approval.

**Safari takes a shorter route.** There is no helper binary and no manifest, because the extension
is an app extension *inside this app's own bundle*; it talks to the app over a second socket in the
App Group container the two of them share ([ADR-0024](decisions/0024-safari-app-group-socket.md)).
Everything to the left of the transport — the content script, the icon, ⌘\, the popup — is the
same code, from the same directory.

```text
   the page                    the extension                    the app
  ┌──────────┐         ┌───────────────────────────┐      ┌──────────────────┐
  │  form    │◀───────▶│ content script (shared)   │      │ ExtensionAgent   │
  └──────────┘         └─────────────┬─────────────┘      │  · one origin    │
                          runtime    │  message           │    rule          │
                       ┌─────────────▼─────────────┐      │  · one sheet     │
                       │ service worker (shared)   │      │  · one lease     │
                       └─────────────┬─────────────┘      │    store         │
                        sendNative-  │  Message           └────────┬─────────┘
                       ┌─────────────▼─────────────┐               │ Unix socket
                       │ SafariWebExtensionHandler │◀──────────────┘ 0600 in a 0700 dir
                       │  inside Kagisecure.app    │        inside the App Group container
                       └───────────────────────────┘
```

### Why a native messaging host at all

A browser extension cannot open a Unix socket. `chrome.runtime.connectNative` is the only channel
Chromium offers to a local program, and it launches a child process and speaks length-prefixed
JSON over its stdio. So `kagisecure-nmhost` exists to be that child.

It is deliberately nothing else: it links one crate, cannot name `Secret`, cannot open a vault, and
makes no decisions. Chrome performs **no signature check** on a native host — it launches whatever
the manifest names — so the correct amount of authority to give the thing Chrome launches is none
([ADR-0019](decisions/0019-native-messaging-forwarder.md)).

## 3. The protocol

A second socket, beside the agent socket in the same `0700` directory, with a **different wire
format**: 4-byte big-endian length + JSON, where the MCP channel is little-endian
([ADR-0019](decisions/0019-native-messaging-forwarder.md) §3). Frames written for one channel are
refused by the other before their body is read.

Every message is wrapped in an envelope carrying a `ksx` channel marker and a correlation id.

| Ask | Answers | Prompts? | Carries a value? |
| --- | --- | --- | --- |
| `hello` | `welcome` — protocol version, unlocked, what the app established about the host | no | no |
| `status` | `status` — unlocked | no | no |
| `match` | `matches` — item ids, titles, usernames, whether a code exists | no | no |
| `fill` | `filled` — only the fields that were asked for | only if `fields` names the password: first time per (origin, item) per unlock | **only if asked for** |
| `totp` | `totp_code` — **the code**, seconds remaining | same | **yes** |

`fill` carries a `fields` selector — `["username","password"]`, or `["username"]` on an
identifier-first page, or `["password"]`. The app **enforces** it: the reply is built by a
constructor that drops anything the request did not name, so a username-only fill cannot carry a
password. A request that names only the username crosses no secret and is therefore served without
an approval sheet, without a biometric, and without minting or spending a fill lease — every other
gate is unchanged, and the audit entry reads `FILL_USERNAME_ONLY`
([ADR-0030](decisions/0030-identifier-first-login.md)). Absent, `fields` means both, which is what
a fill has always meant.

Every failure is `error` with a stable code: `VAULT_LOCKED`, `USER_DENIED`, `APPROVAL_TIMEOUT`,
`ORIGIN_MISMATCH`, `NO_MATCH`, `UNKNOWN_EXTENSION`, `UNTRUSTED_HOST`, `PROTOCOL`, `INTERNAL`.

`matches` returns titles and usernames and **no URLs**: the extension already knows the origin it
asked about, and returning the item's other saved sites would leak the user's site list one page at
a time.

### The order of checks

1. **Same user.** Another local uid is refused before a byte is read.
2. **The right peer for this socket.** On the Chromium socket the native host's ancestry must
   contain a recognized browser within three hops. On the Safari socket the peer *is* the
   extension, so its executable must be the `.appex` inside this app's own bundle. Either failure
   is `UNTRUSTED_HOST` before anything is served, and the refusal is audited.
3. **Pinned extension id.** `hello` from anything else is refused — the key-pinned Chromium id on
   one socket, the app extension's bundle identifier on the other. The two lists are separate, so
   neither id passes on the other's socket.
4. **Origin match.** eTLD+1 + exact scheme/port. A mismatch is `ORIGIN_MISMATCH` and an audit
   entry, never a prompt — there is nothing for a human to weigh about a fill the rule refused.
5. **The human.** Sheet plus biometric, first time per (origin, item) per unlock session. Skipped
   by a fill that asks for the username alone, because nothing crosses that step 4 did not already
   hand over — checks 1–4 and the click in the page are not skipped
   ([ADR-0030](decisions/0030-identifier-first-login.md)).

## 4. Approvals and leases

The fill sheet is the **same sheet** as an agent approval, on the same queue, with the same
60-second timeout and the same biometric gate — one mechanism, not two
([ADR-0020](decisions/0020-fill-approvals-and-origin-leases.md)).

What is different is what it shows and what it grants:

- **Identity verdicts.** On Chromium, two side by side: the native messaging host's code signature
  and the browser's. On an unsigned build these differ — Chrome verifies, our helper does not — and
  collapsing them into one word would either claim a verification we do not have or throw away the
  one real fact on the sheet. On Safari there is **one**, because Safari is never the process on
  the socket: the app extension is, and it is signed by us. That is why a Developer-ID-signed build
  can produce a fully *verified* fill through Safari and cannot through Chrome
  ([ADR-0024](decisions/0024-safari-app-group-socket.md) §5).
- **A frame warning.** When the form is in a cross-origin iframe, the sheet says so and names both
  origins.
- **A fill lease**, not an env lease. Scoped to one origin and one item, five minutes by default,
  fifteen at most, session-only, dead the moment the vault locks. It excuses **the biometric and
  nothing else**: every fill still needs your click in the page.
- **Allow once** mints no lease at all.

Fill leases appear in **Agent access → Leases**, under "Browser fills", with their own Revoke.

Audit entries are written for every fill: `FILL_APPROVED`, `FILL_LEASED`, `FILL_DENIED`,
`FILL_ORIGIN_MISMATCH`, `FILL_USERNAME_ONLY`, `HOST_REFUSED`, each with the origin and the field
**names**. `FILL_USERNAME_ONLY` is the one that names no human, which is why it is its own word
rather than a quieter `FILL_APPROVED`.

## 5. Setting it up

In the app: **Browser extension** in the sidebar.

1. **Check the helper path.** The screen shows where `kagisecure-nmhost` is. Building from source,
   run `cargo build -p kagisecure-nmhost` and set `KAGISECURE_NMHOST` to
   `target/debug/kagisecure-nmhost` before launching the app. A released build ships it at
   `/Applications/Kagisecure.app/Contents/Helpers/kagisecure-nmhost` and the screen shows that
   path — signed and notarized with the app, which is what makes the manifest's absolute path
   point at something the browser can trust
   ([ADR-0026](decisions/0026-helper-binaries-inside-the-app-bundle.md)).
2. **Press "Set up" next to your browser.** That writes
   `~/Library/Application Support/<browser>/NativeMessagingHosts/com.kagisecure.nmhost.json`. The
   exact JSON and the exact path are shown under "What this writes" first. **Remove** deletes it.
3. **Load the extension.** `chrome://extensions` (or `edge://extensions`) → Developer mode → Load
   unpacked → pick **`extensions/shared`**. That is the extension itself; `extensions/chrome` holds
   only the Node test package (§6).
4. **Check the id.** The screen shows the id the app serves; the browser shows the id it loaded.
   They must match. They will: the extension's `manifest.json` carries a committed public `key`
   that pins the id ([ADR-0021](decisions/0021-pinned-extension-id.md)).

Supported: Chrome, Edge, Arc, Brave and Chromium — one native-messaging manifest per browser, same
extension, same id. **Safari** is supported too and needs none of the above: no helper binary, no
manifest file, no id to check. See §8.

### The source layout

```text
extensions/
  shared/       the extension. Chromium loads THIS unpacked; the Safari app extension embeds it.
    manifest.json     the Chromium MV3 manifest, with the pinned key (ADR-0021)
    background.js     the service worker: message routing, the origin stamping
    native.js         the one file that differs per browser at run time — the transport
    content.js        the icon, ⌘\, and the only function that writes a value into a field
    tabmemory.js      which item a tab chose on an identifier page: in memory, 60s (ADR-0030)
    origin.js  forms.js  popup.html  popup.js
  safari/
    manifest.json     Safari's manifest. Copied over shared/manifest.json by the Xcode target.
  chrome/       the Node package: unit tests, the Playwright suite. No extension code.
```

Two files differ between the browsers and neither is code the user sees: the manifest (Safari's
omits the Chromium-only `key` and `minimum_chrome_version`) and the four lines in `native.js` that
choose the transport. `native.js` decides from the **scheme of the extension's own URL** —
`chrome-extension://` versus `safari-web-extension://` — which is a fact about the runtime rather
than a guess about it. The obvious feature test no longer works: Safari has grown a `connectNative`
of its own, and a wrong guess there fails as silence rather than as an error.

### Making an item fillable

Put the site in the item's **Websites** field (the edit sheet). Subdomains of the same registrable
domain are covered; a different scheme or port is not. `http://localhost:3000` and
`http://localhost:3001` are different sites, and so are `http://` and `https://` versions of the
same host.

## 6. Building and testing

```sh
cargo test -p kagisecure-extension-ipc -p kagisecure-nmhost   # protocol, framing, origin rule
cargo test -p kagisecure-agent                                # listener, leases, cross-process
cargo test -p kagisecure-agent --test safari                  # the Safari front end's gates
make macos-test                                               # incl. SafariExtensionTransportTests
cd extensions/chrome && npm install && npm test               # form detection, origin helpers
make e2e SUITE=extension                                      # a real browser, end to end
```

The extension is plain modern JavaScript with **no build step**: `npm install` is only for the two
test dependencies. `origin.js` and `forms.js` are loaded both as classic content scripts and by
`node --test`, through a small UMD wrapper, so the tests test the shipped file.

`SafariExtensionTransportTests` compiles the app extension's own `AppGroupSocket.swift` into the
test bundle — the file itself, not a copy of the framing — and drives it against a real listener
started by `extension_harness`. That is what makes the two languages agree about a 4-byte
big-endian length prefix; a disagreement there would produce a Safari extension that connects,
sends, and is answered with silence.

## 7. The manual pass

What the automated suite cannot do is put a fingerprint on the sheet. To check the human half:

```sh
# 1. a scratch vault with a login saved at the page you will visit
export KAGISECURE_VAULT=/tmp/kagisecure-m6/m6.kagivault
cargo run -p kagisecure-cli -- vault init
cargo run -p kagisecure-cli -- item add --title "Demo" --category login \
    --field username=alice@example.test --secret password --url http://localhost:8788

# 2. serve a login form
(cd e2e/suites/extension/pages && python3 -m http.server 8788 --bind 127.0.0.1)

# 3. the app, pointed at that vault  (KAGISECURE_VAULT works in the app since M6)
export KAGISECURE_NMHOST=$PWD/target/debug/kagisecure-nmhost
make macos && open -a Kagisecure

# 4. Browser extension → Set up → load extensions/shared unpacked → visit the page,
#    click the key icon or press ⌘\
```

Expect: the approval sheet naming the item, the origin, the two fields and the two signature
verdicts; a Touch ID prompt; the form filled; a `FILL_APPROVED` entry in the audit viewer; a lease
under Agent access → Leases.

**The same pass for Safari** — which is the one gate M6b could not close, so run it. Steps 1 and 2
are unchanged; steps 3 and 4 become:

```sh
# 3. a signed build, because Safari needs the App Group  (ADR-0025)
make macos SIGN=developer-id
KAGISECURE_VAULT=/tmp/kagisecure-m6/m6.kagivault \
  "$(xcodebuild -project apps/macos/Kagisecure.xcodeproj -scheme Kagisecure \
       -destination 'platform=macOS' -showBuildSettings 2>/dev/null \
     | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{print $2}' | head -1)/Kagisecure.app/Contents/MacOS/Kagisecure"

# 4. Safari → Settings → Extensions → tick "Kagisecure" → allow it on localhost,
#    then visit the page and click the key icon or press ⌘\
```

Expect the same things, plus one that only Safari can show: the sheet's identity line reading
**verified**, naming `com.kagisecure.app.safari-extension` and the team. Check the audit entry says
`Launched by: Safari (extension com.kagisecure.app.safari-extension, pid N)`, and that
`Browser extension → Safari` shows "Ready for Safari" with the App Group and socket underneath.

## 8. Safari

Supported since M6b. It works differently from every other browser here, and the differences are
all in its favour.

**There is nothing to install and nothing to configure.** No helper binary, no manifest file, no
extension id to check against the app. The extension is an *app extension* inside
`Kagisecure.app` itself, so installing the app installs it; enabling it is a switch in Safari.

```text
Safari → Settings → Extensions → tick "Kagisecure"
       → "Edit Websites…"  (or the toolbar icon) → allow it on the sites you want to fill
```

Then use it exactly as in Chrome: the key icon in a password field, or **⌘\**.

### How it reaches the app

`browser.runtime.sendNativeMessage` → `SFSafariWebExtensionHandler`, inside the app's own bundle →
a Unix socket in the App Group container the app and the extension share
([ADR-0024](decisions/0024-safari-app-group-socket.md)):

```text
~/Library/Group Containers/<TEAMID>.com.kagisecure/run/safari.sock   0600, in a 0700 directory
```

The app derives `<TEAMID>` from its own code signature, so a fork signing with its own identity
gets its own group with no source edit. The Browser extension screen shows the group, the socket
and where the `.appex` is, under "How Safari reaches this app".

Above the socket, **nothing is different**: the same `Request`/`Response`, the same 4-byte
big-endian framing, the same origin rule, the same approval sheet on the same queue, the same fill
leases, the same audit entries.

### What the app checks about the caller

The Chromium gate — "a recognized browser is within three hops of the native host" — cannot apply,
because macOS launches an app extension from `launchd` and Safari is nowhere in its ancestry. It is
replaced by a check on the peer *itself*:

1. **Same user**, before a byte is read.
2. **The peer's executable is our `.appex`**: it must end in
   `KagisecureSafariExtension.appex/Contents/MacOS/KagisecureSafariExtension`. Anything else is
   `UNTRUSTED_HOST`, audited, and served nothing.
3. **The `hello` names the app extension's bundle identifier**,
   `com.kagisecure.app.safari-extension`. The handler builds that field from its own
   `Bundle.main.bundleIdentifier` rather than forwarding what the page's JavaScript sent, because
   `browser.runtime.id` in Safari is a per-install UUID with nothing in it to pin.
4. **A code-signature check in Swift**, against **our own team** — not a hardcoded vendor's, the way
   a browser has to be checked. The audit entry and the sheet then read
   `Launched by: Safari (extension com.kagisecure.app.safari-extension, pid N)`.

That is why a Safari fill on a Developer-ID-signed build can be reported *verified* while a Chrome
fill on the same build cannot: on Chrome, our own native messaging host is the half that is ad-hoc.

### Building it

Safari autofill needs an App Group, and an App Group identifier must begin with a team identifier,
so it needs a signed build ([ADR-0025](decisions/0025-developer-id-for-local-builds.md)):

```sh
make macos SIGN=developer-id
```

An **ad-hoc build still works for every other browser** and says so on the Browser extension
screen, in a sentence naming this command. It does not offer a Safari row that does nothing.

### What is verified, and what is not

Stated plainly, because the difference matters.

**Verified, by test:**

- The Safari socket binds as soon as the vault is unlocked, at the App Group path, `0600` in a
  `0700` directory (`SafariExtensionTransportTests`, `crates/kagisecure-agent/tests/safari.rs`).
- The two languages agree about the framing: `hello`, `match`, `fill` and an origin mismatch all
  round-trip through the app extension's own `AppGroupSocket.swift`.
- A peer that is not the `.appex` is refused with `UNTRUSTED_HOST` and the refusal is audited, with
  the gate **on**.
- The Chromium extension id does not pass on the Safari socket, and the Safari bundle id does not
  pass on the Chromium socket.
- An ad-hoc build serves Chromium and explains why it does not serve Safari.

**Verified, by measurement on this machine:** a Developer-ID-signed, **sandboxed** probe carrying
only `com.apple.security.app-sandbox` and `com.apple.security.application-groups`, running this
repository's `AppGroupSocket.swift` unchanged, completed `hello` → `match` → `fill` against the
listener through the group-container socket and received the password. That is the one property
`xcodebuild test` cannot establish — a test bundle cannot be an app extension — and it is the
property the whole transport rests on.

**Not verified:** the last hop. Safari loading the extension, its own per-site permission model,
and the icon and ⌘\ behaving in a Safari page as they do in a Chromium one. The session that built
M6b could not drive Safari's interface, so **no fill has been performed in Safari by a human**. The
`.appex` *is* registered with the system as a `com.apple.Safari.web-extension`
(`pluginkit -m -p com.apple.Safari.web-extension` lists it), which is the step before Safari will
show it — but "the system accepts the extension" is not "a password was typed into a form in
Safari", and this document will not pretend otherwise. The manual pass in §7, run against Safari
instead of Chrome, is what closes it.

## 9. Continuous integration (removed 2026-09-19)

`npm test` runs anywhere: it is Node plus a DOM library, no browser.

The **e2e needs a real display and a browser that will load an unpacked extension**, which is a
sharper constraint than it looks:

- **MV3 extensions do not load in the headless shell.** `headless: false` is required.
- **Chrome 137 removed `--load-extension`.** On Chrome 152 the switch is silently ignored — the
  browser starts, the extension is not installed, nothing is logged. Verified here with a
  three-line probe extension. `--enable-unsafe-extension-debugging` does not bring it back.
- **The native messaging manifest directory follows `--user-data-dir` now.** It did not, and this
  document used to say so. On **Edge 152**, a browser launched with `--user-data-dir=X` reads its
  manifests from `X/NativeMessagingHosts` and does **not** find one in
  `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts`; `connectNative` answers
  *"Specified native messaging host not found"*. Measured with a probe extension against a host of
  `/bin/cat`, which reports *"Native host has exited"* when the manifest is found. The suite now
  writes both files — the real per-user one, which is what a user with a default profile gets, and
  a copy inside the throwaway profile, which is what the run's browser reads. Nothing in the
  product changed: a default launch's user-data-dir *is* `~/Library/Application Support/<browser>`,
  so the app's setup screen still writes the right file.
- **Chromium will not load a symlinked content script.** A symlinked service worker loads; a
  symlinked content script silently never runs — the extension installs, the page loads, and
  nothing happens. Measured on Edge 152 with a two-file probe. This is why `extensions/shared` is
  the extension root itself rather than a directory of per-browser symlink farms pointing into it
  (§5).

So the suite tries browsers in order and uses the first that actually installs the extension —
today, **Microsoft Edge**. It skips with an explanatory message when none will.

**Run locally:** `make e2e SUITE=extension`, with Edge installed. A macOS machine has a window
server, so `headless: false` works without Xvfb. On Linux the same suite
would need `xvfb-run -a make e2e SUITE=extension` and a Chromium that still honours
`--load-extension`. This suite was never run in CI even before CI was removed on 2026-09-19: a
macOS runner would not ship Edge, and installing it per run would be a
multi-hundred-megabyte download for a suite whose failures are overwhelmingly about the extension
source, which the JavaScript unit tests already cover. This is a **documented local gate**; see
[e2e-harness.md](e2e-harness.md) §8.

**The old `npm run e2e` is gone.** `extensions/chrome/e2e/fill.test.js` predated the harness and
wrote the native messaging manifest into the user's **real** browser profile
(`~/Library/Application Support/<browser>/NativeMessagingHosts/`), restoring it afterwards — so a
run killed between the write and the restore left a real, everyday browser pointing at a
`target/debug` binary. Suite B does the same work against a throwaway profile and never touches
the real one, so the older test was removed rather than kept alongside it.

**Safari would have been further out of CI's reach still.** It needs a signed build, an enabled
extension and a
per-site permission grant, all of which are interface actions in Safari's own Settings. The parts
that *can* be automated are: `crates/kagisecure-agent/tests/safari.rs` and
`SafariExtensionTransportTests`, both of which run locally under ad-hoc signing (and ran in CI
until CI was removed on 2026-09-19).
