# Importing into kagisecure

Status: **design complete, scheduled** as [M8 — Import](roadmap.md#m8--import-1pux-and-the-csv-family).
The design decisions behind this document are recorded in
[ADR-0031](decisions/0031-the-import-crate-and-its-intermediate-representation.md).

kagisecure imports from five sources. All of them are parsed by one crate,
`kagisecure-import`, into one source-agnostic intermediate representation, and committed by one
code path — so dedupe, the report, the safety rules and the `agent_visible` default behave
identically no matter where the data came from.

| Source | `--format` | Fidelity | Notes |
| --- | --- | --- | --- |
| 1PUX (1Password 8 export) | `1pux` | High — full item tree, typed fields, sections, vaults | Recommended path |
| 1Password CSV | `1password-csv` | Low — Login items only | Lossy by construction; the CLI says so and points at 1PUX |
| Apple Passwords CSV | `apple-csv` | Low — Login items only | Passwords app ▸ Export |
| Chromium CSV | `chromium-csv` | Low — Login items only | Chrome, Edge, Arc, Brave |
| Firefox CSV | `firefox-csv` | Low — Login items only | Carries per-item timestamps and a GUID |

`.env` import is described in §10 and is **not part of this plan** — see that section.

## 1. What the importer guarantees

Five properties hold for every source, and each is a test, not a convention:

1. **The report carries no values.** The import report — printed, written to a file, or rendered
   in the app — contains item titles, field *labels*, counts and decisions. Never a value. This
   is structural: `Secret` does not implement `Serialize`, and every report type does, so a value
   cannot be added to a report without a compile error. A canary test seeds every parser with a
   unique marker as a password and asserts the marker appears in no byte of the Markdown report,
   the JSON report, any `Debug` of the plan, or any error.
2. **Concealment fails closed.** A field whose source metadata suggests concealment in *any* way
   is imported as a `Secret`, even when its type is unrecognized (§2.4). A wrongly-concealed field
   is an annoyance; a wrongly-public one is a breach.
3. **No intermediate plaintext on disk.** Zip entries are read through `std::io::Read` into
   `Zeroizing` buffers. Nothing is extracted to a temp file, and nothing is written until
   `Vault::save()` — which is atomic and `0600`. A failure mid-apply leaves the vault file
   untouched, and `--dry-run` never calls `save()` at all.
4. **Everything lands invisible to agents.** Every imported item gets `agent_visible = false`
   ([threat-model.md](threat-model.md) M-9). The post-import screen shows a count and a one-click
   "make this vault visible to agents"; nothing happens until a human presses it. Imported password
   history is stronger still: it is never agent-visible, whatever that flag later says (§2.7).
5. **Parsing is bounded before it is trusted.** Hard limits (§2.2) are checked from the zip's
   central directory *before* any entry is read, so a zip bomb is refused rather than survived.

The importer treats every source file as untrusted parser input
([threat-model.md](threat-model.md) §8, M-21) and has fuzz targets for both the 1PUX and CSV
paths.

## 2. 1PUX

### 2.1 What a 1PUX file is

A `.1pux` file is a **zip archive** containing:

| Entry | Contents |
| --- | --- |
| `export.attributes` | JSON: export metadata — version, description, `createdAt` |
| `export.data` | JSON: the account → vault → item tree |
| `files/<documentID>___<filename>` | Attachment/document binaries referenced by items |

`export.data` is shaped roughly:

```
{ "accounts": [ { "attrs": {...},
                  "vaults": [ { "attrs": { "uuid", "desc", "name", "type" },
                                "items": [ Item, ... ] } ] } ] }
```

Each item carries `uuid`, `categoryUuid`, `favIndex`, `createdAt`, `updatedAt`, `state`
(`"active"` / `"archived"` / `"trashed"`), `overview` (title, url, urls, tags), and `details`
(`loginFields`, `sections`, `notesPlain`, `passwordHistory`, `documentAttributes`).

Entry names are handled flat and one level nested, matched exactly, and resolved through
`ZipFile::enclosed_name()` — a `../` in an entry name is never honoured, and no entry is ever
written to disk.

### 2.2 Limits

Checked from the central directory before anything is read:

| Limit | Value |
| --- | --- |
| Total uncompressed size | 500 MB |
| Per-entry compression ratio | 1000:1 |
| `export.data` read | through `.take(256 MiB)` |
| Items | 100 000 |
| Fields per item | 10 000 |
| Sections per item | 1 000 |
| JSON nesting | serde_json's 128-level recursion limit |

Exceeding any of them is an error that names the limit, not a truncation.

### 2.3 Category mapping

1PUX categories map onto kagisecure's twelve first-class `Category` kinds
([vault-format.md](vault-format.md) §5, mirroring [ui-spec.md](ui-spec.md) §5's 1Password-8-styled
category set). Anything unmapped becomes `Category::Other(<raw category uuid>)` and is preserved,
not dropped. The raw code is **always** written to `extra["onepassword_category_uuid"]`, mapped or
not, so a wrong row here is recoverable after the fact.

| 1Password category | `categoryUuid` | kagisecure `Category` | Verified |
| --- | --- | --- | --- |
| Login | `001` | `Login` | yes — published |
| Credit Card | `002` | `CreditCard` | **no** |
| Secure Note | `003` | `SecureNote` | **no** |
| Identity | `004` | `Identity` | **no** |
| Password | `005` | `Password` | **no** |
| Document | `006` | `Document` | **no** |
| Software License | `100` | `SoftwareLicense` | **no** |
| Database | `102` | `Database` | **no** |
| Server | `110` | `Server` | **no** |
| API Credential | `112` | `ApiCredential` | **no** |
| SSH Key | `114` | `SshKey` | **no** |
| *(anything else, incl. Bank Account, Wireless Router, Passport, Crypto Wallet, …)* | *(any)* | `Other(<uuid>)` | — by design |

> **The `categoryUuid` codes marked "no" are unverified.**
> https://support.1password.com/1pux-format/ confirms only `Login` = `"001"` in worked-example
> text; it publishes no complete table, and neither 1Password's own docs nor third-party importers
> supply an authoritative one. They are treated as unverified in code as well
> (`Verified::No` in `onepux/category.rs`) until a real export confirms them. An
> ignored-by-default test, `probe_sample_categories`, reads `$KAGISECURE_1PUX_SAMPLE` and prints
> the `categoryUuid → title` pairs it finds, which is how the table gets confirmed. A wrong code
> fails safe as `Other(<uuid>)` plus the preserved raw code, not as a silent mis-mapping.

kagisecure has one category with no 1Password equivalent: **`Environment`**. Import never produces
it; users create environments afterwards, usually by binding to imported fields.

### 2.4 Field mapping

Login fields (`details.loginFields[]`) are discriminated by `type`:

| Login field `type` | `FieldKind` | `FieldValue` | Concealed |
| --- | --- | --- | --- |
| `T` | `Text` | `Public` | no |
| `E` | `Email` | `Public` | no |
| `U` | `Url` | `Public` | no |
| `N` | `Text` | `Public` | no |
| `P` | `Concealed` | `Secret` | **yes** |
| `A` | `Text` | `Public` | no |
| `TEL` | `Phone` | `Public` | no |

Section fields (`details.sections[].fields[]`) carry a single-key value object whose key *is* the
type — `{"concealed": "…"}`, `{"totp": "…"}`, `{"address": {…}}`:

| Value key | `FieldKind` | `FieldValue` | Concealed |
| --- | --- | --- | --- |
| `string` | `Text` | `Public` | no |
| `concealed` | `Concealed` | `Secret` | **yes** |
| `email` | `Email` | `Public` | no |
| `url` | `Url` | `Public` | no |
| `phone` | `Phone` | `Public` | no |
| `date` | `Date` | `Public` (ISO-8601) | no |
| `monthYear` | `MonthYear` | `Public` | no |
| `menu` | `Menu` | `Public` | no |
| `totp` | `Totp` | `Secret` (`otpauth://` URI) | **yes** |
| `creditCardNumber` | `CreditCardNumber` | `Secret` | **yes** |
| `creditCardType` | `CreditCardType` | `Public` | no |
| `reference` | `Reference` | `Public` | no |
| `gender` | `Text` | `Public` | no |
| `address` | one `Address`-kind `Public` string, plus one `Text` field per component | `Public` | no |
| `file` | — | — | **dropped** as an attachment (§4) |
| *(unknown)* | `Text`, or `Concealed` if any hint applies | `Public` / `Secret` | see the rule below |

> The JSON keys in the left column are **unverified** against a real export for the same reason as
> §2.3: the published format page lists human-readable type names (Address, Concealed, Credit Card
> Number, …) but not the wire keys. They are marked as such in `onepux/schema.rs`. An unrecognized
> key is not a failure — it falls through to the fail-closed rule.

**The fail-closed rule** lives in one function, `onepux::conceal::is_concealed`, which is a
property-test target. It returns true when any of these hold:

- the value key is `concealed`, `totp` or `creditCardNumber`;
- the section field's `guarded` flag is set;
- the login field's `designation` is `"password"`;
- the login field's `type` is `"P"`;
- the field's title or id matches
  `(?i)(password|passphrase|secret|pin|cvv|cvc|token|private.?key|api.?key)`.

An unknown value key plus any one of those hints is imported as a `Secret`.

**TOTP** values are validated with `kagisecure_core::totp::Totp::parse_uri`. A bare base32 seed is
wrapped as `otpauth://totp/<title>?secret=<seed>` and re-validated. If it still does not parse, the
value is stored as a `Concealed` field labelled `one-time password (unrecognized)` and noted in the
report — **a secret is never dropped for failing to parse.**

### 2.5 Item-level mapping

| 1PUX | kagisecure `Item` | Notes |
| --- | --- | --- |
| `uuid` | `extra["onepassword_uuid"]`, new `ItemId` generated | Foreign ids are never primary keys; they are kept for re-import dedupe (§5) |
| `overview.title` | `title` | Empty → `"Untitled"` |
| `overview.url`, `overview.urls[].url` | `urls` | Deduplicated |
| `overview.tags[]` | `tags` | Plus an `imported:1password` tag |
| `favIndex` | `favorite` | `favIndex != 0` → true |
| `state == "archived"` | `archived` | |
| `state == "trashed"` | skipped | `--include-trashed` opts in, and then sets `trashed_at` |
| `createdAt`, `updatedAt` | `created_at`, `updated_at` | Preserved, not reset to import time |
| `details.notesPlain` | **`Item.notes`** | `Item.notes` is a real `Option<String>` on the item; notes are not turned into a field |
| `details.sections[].title` | `Field.section` | Section titles preserved |
| `details.loginFields[]` | `fields` | `designation: "username"` → label `username`; `"password"` → label `password`, `Concealed`. Empty-valued form fields are dropped and counted as `EmptyFormField` |
| `details.passwordHistory[]` `{ value, time }` | **`Item.history`** — one `FieldRevision` per entry, `Secret`-typed value, `retired_at` from `time` | §2.7. Entries that cannot be parsed are dropped and counted |
| `details.documentAttributes`, `files/` | **dropped**, counted; `fileName` / `documentId` / `decryptedSize` kept in `extra["onepassword_documents"]` | Metadata only — no bytes, §4 |
| vault `attrs.name` | logical vault name | One kagisecure logical vault per 1Password vault |
| account | prefix on the vault name, **only when the export has more than one account** | `"Acme Corp / Engineering"` |

### 2.6 Vaults and accounts

One `VaultMeta` per 1PUX vault, created on commit through `Vault::add_logical_vault`. With a
single account in the export the name is `<vault.name>`; with more than one it is
`<account.name> / <vault.name>`. `--logical-vault <NAME>` collapses everything into one existing
logical vault instead.

### 2.7 Password history

**1Password's password history is imported.** Each `details.passwordHistory[]` entry becomes one
`FieldRevision` on the item: the retired value as a `Secret`, the label and kind of the field it
belonged to, and `retired_at` taken from the entry's `time`. The home for these is `Item.history`,
added to `kagisecure_core::model::Item` as an additive `#[serde(default)]` field — its exact shape
is defined by the core change in this milestone, which also records whether a vault-format version
bump is needed (see [vault-format.md](vault-format.md) §5.5).

Three rules make importing history safe rather than merely convenient:

- **The values are `Secret`-typed**, like any other secret on the item. Nothing retired is ever
  stored in `extra`, which is plaintext (§4).
- **History is never agent-visible.** No MCP tool can reach it, independent of the item's
  `agent_visible` flag, and it is **excluded from search** — an old password should not be what
  makes an item findable.
- **The report shows a count, never a value** (§6), the same rule as everything else.

`Drop::PasswordHistory` survives only for entries the parser cannot make sense of — a missing or
unparsable `time`, or an entry with no value. Those are dropped and counted like any other drop
(§4). The CSV dialects carry no history at all, so nothing is imported and nothing is dropped for
them.

## 3. The CSV family

Four dialects, detected **by header signature only**. The header is BOM-stripped, lowercased,
unquoted and trimmed before comparison; column meaning is never guessed from content.

| Format | Signature |
| --- | --- |
| `apple-csv` | `title,url,username,password,notes,otpauth` |
| `chromium-csv` | `name,url,username,password,note` (also accepts `notes`, and the 4-column pre-2021 form) |
| `firefox-csv` | `url,username,password,httprealm,formactionorigin,guid,timecreated,timelastused,timepasswordchanged` |
| `1password-csv` | `title,url,username,password,otpauth,favorite,archived,tags,notes` — **unverified**; also accepts `website` for `url` and `one-time password` for `otpauth` |

No match, or two matches, is an error that names the candidates and tells the user to pass
`--format`. `--format` wins and skips detection, but still validates that the required columns are
present.

**Encoding.** A UTF-8 BOM is stripped. A UTF-16 BOM is a hard error ("re-export or re-save as
UTF-8") rather than a mojibake import. Invalid UTF-8 is an error naming the byte offset and row
number — never the content. Quoted commas, embedded newlines and CRLF line endings are handled by
the `csv` crate.

**Mapping.** Every row becomes a `Category::Login` item tagged `imported:<source>`:

| Column | kagisecure |
| --- | --- |
| title / name | `Item.title` (Firefox has none: the URL host is used) |
| url / website | `Item.urls[0]` |
| username | field `username`, `Text`, `Public` |
| password | field `password`, `Concealed`, `Secret` |
| otpauth / one-time password | field `otp`, `Totp`, `Secret` — validated as in §2.4 |
| notes / note | `Item.notes` |
| favorite, archived, tags (1Password CSV only) | `Item.favorite`, `Item.archived`, `Item.tags` |
| `timeCreated`, `timePasswordChanged` (Firefox, milliseconds) | `created_at`, `updated_at` |
| `guid` (Firefox) | `extra["firefox_guid"]` — the dedupe foreign key |
| `httpRealm`, `formActionOrigin` (Firefox) | `extra`, preserved (§4) |

Apple and Chromium exports carry no timestamps, so `created_at = updated_at = import time`. The
preview says so before anything is written.

**Losses, stated in the preview before the user commits:** no sections, no custom fields, no
attachments, no password history, no vault structure, no non-Login categories, and multiple URLs
collapse to one. For `1password-csv` the CLI additionally prints that 1PUX is the
higher-fidelity path.

## 4. Three tiers: mapped, preserved, dropped

In order of preference:

1. **Mapped** — a first-class kagisecure field or item property. Round-trips.
2. **Preserved** — no first-class mapping, stored verbatim as CBOR in `Item.extra` or
   `Field.extra`. Visible in the app under "Imported data (unmapped)", editable as raw text, never
   lost on save. SSH key metadata, credit-card expiry quirks, Firefox's `httpRealm` and future
   1Password additions land here.
3. **Dropped** — with an explicit, counted entry in the report.

> **`extra` is metadata only.** Neither `Item.extra` nor `Field.extra` is a `Secret`, so anything
> put there is plaintext outside the guarded type. The rule, enforced by review and by the
> fail-closed function in §2.4: **anything carrying a concealment hint becomes a real `Secret`
> field; only non-secret metadata goes in `extra`.** `Field.extra` is added to
> `kagisecure_core::model::Field` for this purpose (additive, `#[serde(default)]`, no schema
> bump).

Deliberately dropped, each counted and reported by reason:

| Dropped | Why |
| --- | --- |
| **Attachments and documents** (`documentAttributes`, `files/`, `file`-typed fields) | kagisecure has no attachment storage today — `Item` has no `attachments` field. The file names, document ids and sizes are preserved as metadata in `extra["onepassword_documents"]`; the bytes are not imported. The report says how many, and the CLI's summary line names the count. |
| **Unparsable password-history entries** | Password history itself is **imported** (§2.7). This counter covers only entries the parser cannot use — no value, or a missing/unparsable `time`. An entry is never silently coerced into a revision with a made-up timestamp. |
| **Passkeys** | kagisecure has no passkey support. The report says how many and tells the user to keep them in 1Password. |
| 1Password Watchtower flags (breach reports, reused-password scores) | Derived data, recomputed if an equivalent is ever added |
| Item sharing links and vault ACLs | kagisecure v1 is single-user; representing them would be misleading |
| Empty-valued login form fields | Structure with no content; counted as `EmptyFormField` |
| Trashed items | Skipped by default; `--include-trashed` opts in |

Nothing in this table is imported. No screen, report or message says otherwise.

## 5. Dedupe

Imports are re-runnable. The importer must not double a 400-item vault when someone re-exports
after adding two logins.

**Identity, in order of confidence:**

1. A **foreign id** match — `extra["onepassword_uuid"]` or `extra["firefox_guid"]` against the
   same key on an existing item. This makes 1PUX and Firefox re-import exact.
2. A **content fingerprint** —
   `SHA-256(lowercase(title) ‖ 0x00 ‖ lowercase(primary_url_host) ‖ 0x00 ‖ lowercase(username))`.
   Values are never part of the fingerprint, so a rotated password does not create a duplicate.
3. Neither matches → **a new item**.

**Policy, chosen once per run** (`--on-duplicate`, or the picker in the app's preview sheet):

| Policy | Behavior on a match |
| --- | --- |
| `skip` (default) | Keep the existing item untouched; count it in the report. Skip means skip — nothing is written, not even `updated_at`. Reported as `skipped: 396`. |
| `update` | Overwrite the fields the source carries; keep everything kagisecure-only — locally added tags, `agent_visible`, environment bindings, `trashed_at`. **History is merged, not replaced:** source revisions are appended to `Item.history` and deduplicated by value hash plus `retired_at`, so re-importing an export twice does not double the history |
| `keep-both` | Import as a new item, title suffixed ` (imported YYYY-MM-DD)` |

There is no `interactive` policy. A per-conflict prompt would either show values (which the report
rule forbids) or show only field names, which is not enough to decide by — and it turns a 400-item
import into 400 questions. `--dry-run` plus `--report` is the answer instead: read the whole plan,
then pick one policy.

Environment bindings (`VarSource::ItemField`) survive `update` — that is the entire point of
binding rather than copying.

## 6. The report

One report per run: printed to stdout, written as Markdown with `--report <PATH>` (mode `0600`),
serialized as JSON with `--json`, or rendered as a scrollable pane in the app. It lists every item
touched, every field that landed in "preserved", every drop with its reason and count, and every
dedupe decision. Imported password history appears as a count per item and nothing more (§2.7).

**It contains names only, never values** — see §1.1. In the app, the preview *is* the report: the
parsed plan stays behind the FFI boundary as an opaque object and values never cross it.

One audit entry per run (`actor: "import"`, `tool: "import"`), with a detail like
`1pux: 412 created, 8 updated, 3 skipped` and the source file's *name*. No values, no field labels.

## 7. CLI

```
kagisecure import <PATH>
  [--format 1pux|apple-csv|chromium-csv|firefox-csv|1password-csv]
  [--logical-vault <NAME>]
  [--dry-run]
  [--on-duplicate skip|update|keep-both]
  [--include-trashed]
  [--report <PATH>]
  [--json]
  [--yes]
  [--shred-source]
```

Spelled `--logical-vault` rather than `--vault`: the global `--vault` already names *which vault
file* to open, so a subcommand flag of the same name would silently let one win over the other.

```console
$ kagisecure import ~/Downloads/export.1pux --dry-run
$ kagisecure import ~/Downloads/export.1pux --logical-vault Personal --report ./import-report.md
$ kagisecure import ~/Downloads/firefox-logins.csv --format firefox-csv --on-duplicate update
```

- Default output is a summary — counts per category, duplicates by resolution, drops by reason —
  ending in a line like
  `Imported 412 items into "Personal". 8 updated, 3 skipped. 17 attachments and 2 passkeys were not imported — see the report.`
- `--dry-run` prints the identical report, exits 0, and writes nothing.
- Unlocking follows the existing pattern: a master-password prompt, or `--password-stdin`. There is
  no biometric path in the CLI.
- An import of more than 100 items asks for confirmation, showing the source path and the count,
  unless `--yes` or `--dry-run`.
- `--shred-source` runs only after a successful save, and prints the best-effort caveat (§9).
- **Exit code 7** (`EXIT_IMPORT_FAILED`) means "the import source could not be read or parsed",
  alongside the existing 0/1/2/3/4.

## 8. The macOS app

**File ▸ Import…** (⇧⌘I) → an `NSOpenPanel` → a preview sheet → **Import** → a result pane → an
offer to delete the source file → Done.

The preview sheet shows the source file name, the detected format (with a picker to override it),
the total item count, a per-category breakdown, the number of duplicates found with a
`skip / update / keep both` picker, and three dropped counters — attachments, passkeys, and
unparsable history entries — each with a one-line explanation. Below that is a scrollable per-item
table: title,
category, action, and what was dropped. **No values anywhere on the sheet.**

The FFI surface adds no new secret crossing ([ADR-0008](decisions/0008-ffi-secret-crossings.md)):
`import_preview` returns an opaque plan handle whose only readable projection is the report, and
`import_commit` returns counts. The accessibility identifiers for these screens are listed in
[ui-spec.md](ui-spec.md) §15.

## 9. Shredding the source

An exported `.1pux` or `.csv` is a **complete plaintext copy of the password manager it came
from**, sitting in `~/Downloads`. Deleting it afterwards matters more than almost anything else in
this document, which is why both entry points offer to do it and neither ever does it implicitly.

`--shred-source` (CLI) and the "Delete the source file?" prompt (app) overwrite the file's full
length with CSPRNG bytes, `sync_data`, truncate, `sync_all`, and remove it — dropping extended
attributes first on macOS.

> **This is best effort, not secure erase.** The file may survive in a snapshot, a backup or
> unallocated SSD blocks: APFS is copy-on-write, SSDs wear-level and remap, Spotlight may hold an
> index, and Time Machine or a local snapshot may hold the whole file. The wording the UI uses says
> exactly that. The reliable step is the user's own: do not leave the export anywhere it can be
> backed up.

## 10. `.env` import — **not in this plan**

Everything in this section is design only. It is **out of scope for M8** and is not implemented by
the import crate described above; it is kept here so the design is not lost.

The most kagisecure-native import: point it at a project.

```bash
kagisecure import env ./.env --vault "Acme Corp" --environment "acme-api / local"
kagisecure import env-scan ~/code --dry-run
```

- `import env <file>` creates (or appends to) one `Environment`, with one `EnvVar` per line,
  `VarSource::Literal`.
- `import env-scan <dir>` walks a directory tree for `.env`, `.env.local`, `.env.development`,
  `.env.staging`, `.env.production`, `.env.*.local`, proposes one environment per file named
  `<project-dir> / <suffix>`, and shows a dry-run plan before writing anything.

Parsing rules (documented because `.env` has no standard):

| Input | Behavior |
| --- | --- |
| `KEY=value` | literal value |
| `KEY="value with spaces"` | quotes stripped, `\n` `\t` `\\` `\"` unescaped |
| `KEY='raw value'` | quotes stripped, **no** escape processing |
| `export KEY=value` | `export ` prefix stripped |
| `# comment`, blank lines | ignored, but retained as `EnvVar.comment` when immediately above a key |
| Multi-line double-quoted values | supported |
| `KEY=$OTHER` / `${OTHER}` | **not** interpolated; stored literally, with a warning in the report |
| Duplicate `KEY` | last wins, with a warning |
| Invalid key (not `^[A-Za-z_][A-Za-z0-9_]*$`) | skipped, reported |

After import the source `.env` would not be deleted automatically; the CLI would print the exact
`kagisecure env write` / `revoke_env_file` commands and offer `--shred-source` as an explicit
opt-in, exactly as §9 describes.

> Assumption: no interpolation. `.env` interpolation semantics differ between dotenv
> implementations; silently resolving `$DATABASE_HOST` at import time would produce a value the
> user never wrote. Storing it literally is wrong in a different, more visible way.

## 11. Open questions

- **The `categoryUuid` table.** Unverified beyond `001`; confirmed against a real export before the
  1PUX parser merges (§2.3).
- **Attachments.** Dropped and counted because there is no attachment storage. If
  [vault-format.md](vault-format.md) §6's encrypted-blob design is ever built, the 1PUX path
  already preserves the metadata needed to import them on a second pass.
- Should the importer *propose* Environments from imported items (detect a Database item and
  suggest `DATABASE_URL`)? Useful, but it means guessing variable names.
- Bitwarden, KeePass and macOS Keychain import. Not planned; the IR and dedupe are source-agnostic,
  so each would be one new parser module and nothing else.
- SSH Key's obvious agent use case (`run_with_env` with `SSH_AUTH_SOCK`-style injection) remains
  unscheduled — see [roadmap.md](roadmap.md#post-v1-unscheduled).
