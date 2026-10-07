# Publishing the extension on the Chrome Web Store

Everything needed to put the Chromium extension (`extensions/shared`) on the Chrome Web Store and
keep it updated: the package, the text and answers each dashboard field takes, the images to
capture, and the order of the steps. The answers below describe what the code does today; if the
extension changes, re-read §3 and §4 against the code before the next submission.

Companion documents: [browser-extension.md](browser-extension.md) for how the extension works,
[ADR-0021](decisions/0021-pinned-extension-id.md) (and its amendment of 2026-10-03) for why the
store install has a different id from an unpacked load.

Decided by the owner: **publicly listed from the first release**, published under the same
publisher as the macOS app's Developer ID (ITSUCARA, K.K.). The first upload is made by hand in the
developer dashboard — the store's API can update an item but cannot create one. Updates go
through the API (§8).

---

## 1. The package

```sh
cargo xtask chrome-package      # or: make chrome-package
```

writes `dist/kagisecure-chrome-<version>.zip` (`dist/` is gitignored) and lists what is in it.
What it does, so the zip can be trusted without unzipping it:

- **Removes `key` from the manifest.** The store refuses a new item whose manifest has one. The
  committed manifest keeps it, so `Load unpacked` still gets the pinned id (ADR-0021).
- **Sets `version` from `Cargo.toml`** (`[workspace.package] version`). The committed manifests
  must already say the same — the task stops if they do not, and so does `cargo xtask version` and
  the xtask unit test `version::tests::the_extension_manifests_carry_the_workspace_version`.
- **Ships only the extension**: every `.js`, `.html`, `.css`, `.json` and `.png` under
  `extensions/shared`, `icons/` included; no dotfiles, nothing named `*.test.*` or `*.spec.*`. Any
  other file type there stops the task rather than being shipped or dropped silently.
- **Checks every reference**: the service worker, the content scripts, the popup, every icon, the
  scripts `background.js` loads with `importScripts`, and the `<script src>` in `popup.html` must
  all be in the zip.
- **Checks what the store would reject**: manifest V3, a valid Chrome version string, a name of at
  most 75 characters, a description of at most 132.
- **Is deterministic**: sorted entries, every timestamp 1980-01-01, mode 0644. The same tree gives
  the same bytes, so `shasum -a 256` of two builds of one commit agree.

The store re-signs the package; nothing here needs a private key.

To look at what was built: `unzip -l dist/kagisecure-chrome-*.zip`, and
`unzip -p dist/kagisecure-chrome-*.zip manifest.json`. To try it before uploading, unzip it into
a folder and `Load unpacked` it in a scratch profile — it then gets a path-derived id, which the
app refuses (`UNKNOWN_EXTENSION`); that is expected and is exactly why §6 exists.

## 2. Store listing

### Name

`Kagisecure` (from the manifest).

### Summary (the manifest `description`, at most 132 characters)

> Fill saved logins from the Kagisecure Mac app into web pages. Requires the Kagisecure app for macOS; does nothing on its own.

The dashboard takes this from the manifest; change it there, not in the dashboard.

### Description

> Kagisecure is a password manager that keeps your vault on your Mac. This extension is the part
> of it that lives in your browser: it fills the logins you saved in the Kagisecure app into the
> sign-in forms of the websites they belong to.
>
> **It requires the Kagisecure app for macOS** (https://kagisecure.com). On its own the extension
> does nothing — it has no vault, no account and no server of its own. Install the app, open
> **Browser extension** in its sidebar, and press **Set up** next to your browser.
>
> How it works
>
> - On a page with a sign-in form, a key icon appears in the password field when your vault has a
>   login saved for that site. Click it, or press ⌘\, to fill.
> - Kagisecure asks you to approve the fill in the app and confirm with Touch ID, your login
>   password or an Apple Watch. Nothing is filled on page load, ever.
> - A login is offered only on the site it was saved for: subdomains of the same site count, a
>   look-alike domain does not, and a different scheme or port does not.
> - Sign-ins that ask for the username on one page and the password on the next (as Google,
>   Microsoft and Okta do) are filled on both pages.
> - One-time codes for two-step verification are a separate click, with their own confirmation.
>
> Privacy
>
> - The extension talks only to the Kagisecure app on your Mac, through the browser's native
>   messaging. It makes no network requests and has no analytics.
> - Passwords pass through the extension only on the way into the form you approved, and are never
>   stored by it. It keeps no browsing history and uses no browser storage.
> - Every fill is recorded in the app's audit log, on your Mac.
>
> Kagisecure is open source (MIT or Apache-2.0): https://github.com/itsucara/kagisecure

### Category, language, links

- **Category:** the closest security or productivity category the dashboard offers (a
  privacy-and-security category if one is listed, otherwise Productivity → Tools).
- **Language:** English.
- **Homepage URL:** `https://kagisecure.com`
- **Support URL:** the repository's issue tracker, `https://github.com/itsucara/kagisecure/issues`.

### Images (§5)

## 3. Privacy practices tab

### Single purpose

> Fill logins saved in the Kagisecure password manager app on the user's Mac into sign-in forms
> on the websites they were saved for, when the user asks for it.

### Permission justifications

**`nativeMessaging`**

> The extension has no vault and no network access of its own. Every login it fills comes from the
> Kagisecure macOS app on the same computer, and native messaging is the only channel Chrome
> offers between an extension and a local application. The extension connects to exactly one
> native host, `com.kagisecure.nmhost`, which the Kagisecure app installs and which forwards
> messages to the app over a local socket. Nothing is sent anywhere else.

**No other permission.** The Chromium manifest asks for `nativeMessaging` only. The toolbar
popup reaches the tab the user is looking at with `chrome.tabs.query` and `chrome.tabs.sendMessage`,
which need no permission; nothing reads a tab's URL or title. (`activeTab` was dropped before the
first submission because nothing in Chromium used it.)

### Host permission justification (the content script on all `http`/`https` pages)

The manifest requests **no `host_permissions`**. The dashboard asks about the content script's
`matches` (`http://*/*`, `https://*/*`, `all_frames: true`) as host access, so it needs this
answer:

> The extension's job is to put a fill icon in the password field of any site the user has saved a
> login for, before the user clicks anything. Which sites those are is known only to the user's
> Kagisecure app, and the extension deliberately does not ask the app for the list (it would be
> the user's whole site list, held in the browser). So the content script has to run on every
> http and https page, and in frames too, because many sign-in forms are embedded in an iframe
> from the identity provider's own origin.
>
> On each page, the content script only looks at the page's form fields to find a sign-in form
> (a password field, or the username field of a username-first sign-in). If it finds one, it asks
> the local Kagisecure app which saved logins apply to the page's origin — scheme, host and port,
> never the path or query — and draws the icon only if one does. It writes a username, password or
> one-time code into the form only after the user has clicked the icon or pressed the shortcut and
> approved the fill in the app.
>
> It does not read what the user types, does not read or send page text, does not change a page
> beyond drawing its own icon (in a closed shadow root) and writing an approved fill, makes no
> network requests, does not read cookies, and keeps no history. Pages
> cannot message the extension: it declares no externally_connectable and registers no external
> message listener. On pages with no sign-in form it does nothing beyond the scan.

### Remote code

**No, I am not using remote code.** Every script the extension runs is in the package:
`background.js` loads `origin.js`, `tabmemory.js` and `native.js` with `importScripts` from the
package itself, and `popup.html` loads `popup.js`. There is no `eval`, no `new Function`, no
remotely hosted script, no `fetch` of anything, and no bundler (the files in the zip are the files
in the repository).

### Data usage

The dashboard asks which categories the extension collects, where "collect" includes data that is
only handled on the device (the store's user-data FAQ says disclosure is required "even when data
is processed or stored locally on a user's device"). What the extension handles, and where it goes:

| Category | Tick? | What, exactly |
| --- | --- | --- |
| Personally identifiable information | **Yes** | Usernames of saved logins (often email addresses), which the app sends to show in the icon's menu and the popup, and writes into forms. |
| Health information | No | — |
| Financial and payment information | No | — |
| Authentication information | **Yes** | Passwords and one-time codes from the user's vault, which pass through the extension into the form the user approved. Never stored by the extension; a value is held only long enough to be written. |
| Personal communications | No | — |
| Location | No | — |
| Web history | **Yes** (conservative) | The extension keeps no history. But it sends the origin of each page that has a sign-in form to the local app to ask what applies there, and the app's audit log records the origin and time of each fill. Ticked because the store's definition covers "the domains or URLs the browser interacts with". |
| User activity | No | It listens for one keyboard shortcut (⌘\ / Ctrl+\) and for clicks on its own icon. It does not record keystrokes, clicks, mouse movement or scrolling. |
| Website content | **Yes** (conservative) | It inspects form fields' attributes (type, name, id, label, placeholder, `autocomplete`) to find the sign-in form. That stays in the page; only the origin and, for an agent fill, whether username / password / code fields were found, are sent to the app. |

**Where it goes.** Only to the Kagisecure app on the same Mac, through the native messaging host
the app installs. Nothing is sent to Kagisecure's developers, to any server, or to any third party.
The extension makes no network requests at all.

The three certifications, all of which are true:

- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

### Privacy policy URL

`https://kagisecure.com/privacy/` — the page must be live before submitting, and must cover the
extension specifically: that it communicates only with the local app, sends nothing off the
device, stores nothing, and what the app's audit log records.

## 4. Test instructions for the reviewer

The reviewer cannot exercise the extension without the macOS app, so the dashboard's test
instructions should say how:

> This extension requires the Kagisecure app for macOS and does nothing without it. To test:
> 1. On a Mac with macOS 15 or later, download Kagisecure from https://kagisecure.com, drag it to
>    Applications, open it and create a vault.
> 2. Add a login item with a username, a password and the website of a test sign-in page.
> 3. In the app, open **Browser extension** and press **Set up** next to Chrome.
> 4. Install this extension, visit that sign-in page, and click the key icon in the password field
>    (or press ⌘\). Approve the fill in the app with Touch ID or your login password.

Submit only once §6 step 4's app release is out: until the app knows the store item's id, the
store install cannot connect to it (Chrome refuses the native host for an id its manifest does not
list, and the app refuses an id it does not pin), and a reviewer following these steps sees an
extension that never connects.

## 5. Images

| Asset | Size | Required | Status |
| --- | --- | --- | --- |
| Store icon | 128×128 PNG, artwork 96×96 with 16 px transparent margin | yes | `extensions/shared/icons/icon-128.png`, already padded; upload the same file |
| Screenshot | 1280×800 (or 640×400), full bleed, square corners; 1 to 5 | at least one | **to capture** |
| Small promo tile | 440×280 | listed as required by the store's image guidelines | **to make** |
| Marquee promo tile | 1400×560 | no | optional |

The extension's icons are rendered from the brand mark (`apps/macos/Artwork/icon.svg`) by
`extensions/make-icons.sh`; re-run it if the mark changes.

Screenshots to take (each at 1280×800, Chrome window cropped to content, a demo vault with
obviously fake data such as `alice@example.test`, nothing from a real account):

1. A sign-in page with the key icon in the password field — the core of the product.
2. The icon's menu open with two saved logins for the site.
3. The Kagisecure approval sheet over the browser, naming the site and the item.
4. The toolbar popup: "Connected", the logins for the page, "Copy one-time code".
5. The app's **Browser extension** screen with Chrome set up.

The small promo tile: the brand mark and "Kagisecure" on the brand blue, nothing else.

## 6. The first upload

In this order — the point of it is that nobody can install the store version before an app
release that accepts it.

1. **Prepare.** The privacy policy page is live. `cargo xtask version` passes. Build the package:
   `cargo xtask chrome-package`.
2. **Create the item.** Developer dashboard → **New item** → upload
   `dist/kagisecure-chrome-<version>.zip`. The store creates a draft and **assigns the item's id**
   now. Note it: it is in the dashboard and in the item's URL. Do not submit yet.
3. **Fill in the item** from §2–§5: Store listing, Privacy practices, Distribution (**Public**, all
   regions), and Test instructions.
4. **Allow-list the id in the app.** Add it as the second entry of `PINNED_EXTENSION_IDS` in
   `crates/kagisecure-extension-ipc/src/lib.rs`:

   ```rust
   pub const PINNED_EXTENSION_IDS: &[&str] = &[
       // Unpacked, pinned by the committed `key` (ADR-0021). Keep first.
       "nlijibjnmanccalmafnfbobkcfjiibmd",
       // The Chrome Web Store item.
       "<the 32-letter id from step 2>",
   ];
   ```

   That one list is both halves of the check: the app's `Hello` check, and the `allowed_origins`
   of every native messaging manifest the setup screen writes. Run
   `cargo test -p kagisecure-extension-ipc -p kagisecure-agent` and `npm test` in
   `extensions/chrome` (the id-pin test there accepts extra ids as long as the committed key's id
   stays first). Then cut an app release as usual ([releasing.md](releasing.md)).
5. **Regenerate the host manifests.** After updating the app, each browser row on its
   **Browser extension** screen shows **Not set up yet** — the manifest on disk no longer matches
   the one the app would write — and pressing **Set up** rewrites it with both origins. Say so in
   the release notes: a store install does not connect until this has been done once, and Chrome
   reports a manifest without the store's origin as "Access to the specified native messaging host
   is forbidden".
6. **Submit for review**, with publishing deferred until the app release from step 4 is out (or
   submit after it ships). Once approved, publish.
7. **Update the docs**: the setup steps in [browser-extension.md](browser-extension.md) §5 gain the
   store link next to `Load unpacked`.

### Optionally: one id for unpacked and store installs

The dashboard shows the item's public key under **Package → View public key**. Putting it in the
committed manifest's `key` (replacing the current one) makes an unpacked load get the store id too.
If that is done:

- swap the order of `PINNED_EXTENSION_IDS`, so the store id is `[0]` — the setup screen shows `[0]`,
  and the test in `extensions/chrome/test/adversarial_extension_surface.test.js` requires `[0]` to
  be the id the committed key derives;
- **keep** `nlijibjnmanccalmafnfbobkcfjiibmd` in the list for a transition, so existing unpacked
  installs (and run browsers on older app builds) keep working until they are reloaded;
- the store package still has its `key` stripped; nothing else changes.

## 7. Updates

1. Bump `[workspace.package] version` in `Cargo.toml`, `MARKETING_VERSION` and
   `CURRENT_PROJECT_VERSION` in `apps/macos/project.yml`, and `"version"` in both
   `extensions/shared/manifest.json` and `extensions/safari/manifest.json`; `cargo xtask version`
   says which one was missed. The store refuses an upload whose version is not higher than the
   published one.
2. `cargo xtask chrome-package`.
3. Upload and submit for review with `cargo xtask chrome-publish` (§8). Update the listing or the
   privacy answers in the dashboard first if what the extension does changed — a new permission, a
   new data flow or a broader match pattern needs new justifications and is reviewed more closely.
   The dashboard route (**Package → Upload new package**, then **Submit for review**) still works
   as a fallback.
4. If the update needs a newer app (a protocol change), publish it only once that app release is
   out: `chrome-publish` submits with the default publish type, which makes the version live as
   soon as review approves it.

Nothing about ids changes on an update.

## 8. Publishing with the API

Updates are uploaded and submitted by `cargo xtask chrome-publish` through Google's Chrome Web
Store API. Chrome does not let any extension script Chrome Web Store pages — Claude in Chrome
included — so the dashboard cannot be driven from a browser; the API is the supported unattended
path.

**API version: v2** (publisher-scoped resources,
[reference](https://developer.chrome.com/docs/webstore/api/reference/rest),
[guide](https://developer.chrome.com/docs/webstore/using-api)). v1.1 is supported only until
2026-10-15 ([announcement](https://developer.chrome.com/blog/cws-api-v2)). The calls used:

| Step | Request |
|------|---------|
| Access token | `POST https://oauth2.googleapis.com/token` (`grant_type=refresh_token`) |
| Upload | `POST https://chromewebstore.googleapis.com/upload/v2/publishers/{publisher}/items/{item}:upload`, the zip as the body |
| Upload status | `GET https://chromewebstore.googleapis.com/v2/publishers/{publisher}/items/{item}:fetchStatus` (`lastAsyncUploadState`, while the upload answered `IN_PROGRESS`) |
| Submit | `POST https://chromewebstore.googleapis.com/v2/publishers/{publisher}/items/{item}:publish` (empty body: default publish type, reviewed) |

OAuth scope: `https://www.googleapis.com/auth/chromewebstore`. Publisher id
`3edd5ef8-a197-45cc-b770-5ba58afbefa3`, item id `aacppfmljihmjacphgpkbmanhbhphjgl`, both
constants in `xtask/src/chrome_publish.rs`.

The API cannot create an item (§6) and publishes with the visibility already set in the
dashboard; if the visibility is changed there, publish once by hand before using the API again.

### One-time setup (owner)

1. **Google Cloud project.** In the [Google Cloud console](https://console.cloud.google.com/),
   signed in as the account that owns the publisher, create a project (for example
   `kagisecure-cws`) and enable the **Chrome Web Store API** (APIs & Services → Library).
2. **OAuth consent screen** (Google Auth Platform → Branding / Audience): user type **External**,
   app name `kagisecure release`, support and developer contact emails. Add the owner's account as
   a **test user**, and add the scope `https://www.googleapis.com/auth/chromewebstore` under Data
   Access.
   - While the app is in **Testing**, Google expires its refresh tokens **after 7 days**, which
     would mean running `chrome-auth` before almost every release. Switch Audience → **Publish
     app** → **In production**. An app used only by its own developer account does not need to
     complete verification to work; if the console lists this scope as *sensitive*, the consent
     page shows an "unverified app" warning that the owner passes with **Advanced → Go to
     kagisecure release**, and the refresh token then lasts until it is revoked or unused for six
     months. Check the scope's classification on the Data Access page; nothing here depends on it.
3. **OAuth client**: Clients → Create client → application type **Desktop app**. (Google's guide
   uses a Web application with the OAuth Playground; a Desktop client is what the loopback flow
   below needs, and needs no redirect URI registered.) **Download the client JSON** (for example
   to `~/Downloads/client_secret.json`). Do not open it, copy from it, or paste it anywhere.
4. **Client credentials into kagisecure**, with no one seeing them. An agent calls
   `store_command_output` ([ADR-0049](decisions/0049-store-command-output.md)) once per value; the
   owner approves each call on the sheet with Touch ID, and the agent never receives the value:

   ```text
   store_command_output
     command: /usr/bin/jq          (or /opt/homebrew/bin/jq; an absolute path)
     args:    ["-r", ".installed.client_secret", "/Users/<you>/Downloads/client_secret.json"]
     cwd:     <repo>
     new_item: { title: "Chrome Web Store API" }
     field_label: client_secret

   store_command_output
     command: /usr/bin/jq
     args:    ["-r", ".installed.client_id", "/Users/<you>/Downloads/client_secret.json"]
     cwd:     <repo>
     item_id: <the item id the first call returned>
     field_label: client_id
   ```

   Then the agent creates the environment **`chrome-web-store`** (`create_environment`) and binds
   `CWS_CLIENT_ID` and `CWS_CLIENT_SECRET` to the two fields (`add_variables` with `bind_to`; the
   field ids come from `describe_item`). The item and its fields are agent-visible because an
   approved agent request made them.
5. **Refresh token, once.** The agent calls `store_command_output` again, with the environment
   fed to the command's standard input:

   ```text
   store_command_output
     command: <repo>/target/debug/xtask
     args:    ["chrome-auth"]
     cwd:     <repo>
     timeout_seconds: 600
     item_id: <the Chrome Web Store API item>
     field_label: refresh_token
     stdin_environment: { environment_id: <chrome-web-store>,
                          variables: ["CWS_CLIENT_ID", "CWS_CLIENT_SECRET"] }
   ```

   One sheet covers both the values written to the command and the stored output. `chrome-auth`
   opens Google's consent page (loopback redirect on `127.0.0.1`, PKCE); the owner consents in the
   browser; it exchanges the code and writes **only** the refresh token to its standard output,
   which kagisecure stores in the concealed field `refresh_token`. Its status lines go to standard
   error, which the agent sees, scrubbed. `chrome-auth` refuses to run with a terminal on standard
   output, so the token cannot be printed on a screen: `store_command_output` is the only way to
   run it. The agent then binds `CWS_REFRESH_TOKEN` in `chrome-web-store` to the new field
   (`add_variables`).
6. **Delete the downloaded JSON** (`~/Downloads/client_secret.json`) and empty the trash; the
   vault holds the only copy.

Run step 5 again whenever `chrome-publish` reports `invalid_grant`. `store_command_output` never
replaces a value, so first delete the old `refresh_token` field in the app (or store into a new
label and rebind `CWS_REFRESH_TOKEN`).

### Each release

1. `cargo xtask chrome-package`, and `cargo build -p xtask` so the binary below is current.
2. Run, with stdin delivery from `chrome-web-store` (`run_with_env`, delivery `stdin`, cwd the
   repository):

   ```text
   command: <repo>/target/debug/xtask chrome-publish
   ```

   Options: `--zip PATH` for a package other than `dist/kagisecure-chrome-<version>.zip`,
   `--dry-run` to check the package and the credentials' presence and print the requests without
   sending anything.

`run_with_env` children get the app's minimal `PATH`, so the command is the built binary's
absolute path: it finds the repository from its own build location, and calls `/usr/bin/curl`
and `/usr/bin/open` by absolute path. (`cargo xtask chrome-publish` by its absolute path, `$HOME/.cargo/bin/cargo`, with
the repository as cwd works too, but rebuilds through rustup under that minimal `PATH`.)

What it does: reads `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET` and `CWS_REFRESH_TOKEN` from the stdin
frame (`NAME\0VALUE\0` pairs, ADR-0047) and from nowhere else; refuses a package whose
`manifest.json` version is not the workspace version; exchanges the refresh token; uploads;
polls `fetchStatus` while the upload is `IN_PROGRESS` (up to 5 minutes); submits; prints the item
id, the uploaded version and the resulting state (normally `PENDING_REVIEW`). Every value travels
to curl on its standard input as a config file, never as an argument, and any API error is shown
with Google's message and with the credential values redacted.

## 9. Open points for the owner

1. **The ticked data categories** in §3 are deliberately conservative (Web history, Website
   content). Untick only with a reason that would survive a reviewer reading this extension's code.
2. **Publisher display name and verification.** The dashboard's publisher name should match the
   Developer ID (ITSUCARA, K.K.). Verifying `kagisecure.com` for the publisher account shows the site on
   the listing.
