# ADR-0029: `Login`'s `website` field is removed; `Item::urls` is the one source of truth

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** Cleanup pass following M6/M7

## Context

The `Login` category template (`Category::default_fields` in `crates/kagisecure-core/src/proto.rs`)
put a `website` field — `FieldKind::Url`, `FieldValue::Public` — beside `Item::urls`, a top-level
list every item already carries. Both fed the same downstream decision: the browser-extension
origin allow-list. `saved_websites` in `crates/kagisecure-agent/src/extension.rs` unioned
`Item::urls` with every `FieldKind::Url` field on the item, `website` included, precisely because
either place could hold the site a credential belonged to.

Two places for one fact is a bug shape, not a feature:

- The macOS item editor's Websites field (`ItemEditView.swift`) only ever reads and writes
  `Item::urls`. A `Login` item's `website` field could drift from `urls` — edit one, forget the
  other — with no error and no indication which one the extension actually trusted.
- A new item from the `Login` template started with the *same* website typed into two different UI
  rows if a user filled in both the field and the Websites box, for no benefit.
- Every future reader of "what sites does this item cover" (the FFI layer, the CLI, a future
  import path) had to know to check both places, not one.

## Decision

**`Item::urls` is canonical. The `website` template field is removed, not kept as an alias.**

1. `Category::default_fields` for `Login` no longer includes a `website` field. The "+ New" flow's
   only way to record a site is the Websites editor, which already writes `Item::urls` — nothing
   in the macOS app changes.
2. An item written by an older build may still carry a `website` field from the old template (or a
   user may have typed "website" as a custom field's label independently — nothing stops that).
   `kagisecure_core::vault` folds any `FieldKind::Url` field labeled `website` (case-insensitive)
   into `Item::urls` every time a vault body is decoded (`fold_legacy_website_field_into_urls`,
   called from `decrypt_body`), deduplicating against URLs already present, then drops the field.
3. `saved_websites` in `kagisecure-agent` keeps unioning `Item::urls` with any `FieldKind::Url`
   field. This is deliberate, not leftover duplication: a user can still add a custom URL-kind
   field by hand (it is one of the addable kinds in `ItemEditView`), and the fold above only runs
   when a vault is *opened* — an item edited and saved without a reopen in between still has to be
   read correctly. Removing this union would silently stop a manually added URL field from
   authorizing a fill, which is a behavior change this cleanup does not intend to make.

### Alternatives considered

**(b) Keep `website` as a display alias that reads/writes `Item::urls`.** Rejected: `Field` has no
concept of "this field's value lives somewhere else on `Item`" — every reader of `Field::value`
(the FFI layer's summaries, the CLI, the audit log, a future import path) would need a special case
for the label `website`, and every writer would need to keep the alias and `urls` in sync on every
edit rather than on save. That is more surface, not less, for the same outcome. Removing the field
and migrating its value once is the smaller change.

### Why folding on read, not a `body.schema` migration

vault-format.md §9 rule 2 requires an explicit upgrade prompt and a `.bak` copy before a
`body.schema` bump changes what is written to disk. That machinery governs *schema* changes; this
is not one — `Item`'s shape (`urls: Vec<String>`, `fields: Vec<Field>`) is unchanged, and
`BODY_SCHEMA_VERSION` does not move. The fold is an in-memory normalization of redundant data the
old schema already allowed, exactly like any other edit the app makes to an `Item` in memory: it
does not touch the file until the caller calls `Vault::save`, at which point it is one edit among
the ones a save already persists. Rule 1 (nothing destroyed) holds: the value moves into `urls`
rather than being dropped.

### 1PUX import

`docs/import.md` already maps `overview.url` / `overview.urls[]` to `Item.urls` (§2.5 and the CSV
mapping table) and never mentions a `website` field, so this decision needs no change there.

## Consequences

**Positive**

- One place decides what sites an item covers going forward: `Item::urls`, editable from one UI
  control (`ItemEditView`'s Websites field).
- A `Login` item from the template no longer shows two rows for the same fact.
- Existing vaults do not lose data: the fold runs on open and merges rather than drops.

**Negative — accepted**

- An item saved by a pre-ADR-0029 build and never reopened by a build that includes this change
  keeps its redundant `website` field until it is opened once. `saved_websites`'s union covers
  this window; nothing loses matching ability in the meantime.
- `saved_websites` still has two things to check, not one — that union is now a compatibility and
  custom-field affordance rather than the origin of a template's duplication, and is expected to
  stay that way rather than collapse further, since custom URL fields are a legitimate use of the
  field-editor's "Add field" menu.
