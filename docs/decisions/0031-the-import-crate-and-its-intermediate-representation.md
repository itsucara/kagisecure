# ADR-0031: Import lives in its own crate, behind one source-agnostic IR whose report cannot carry a value

- **Status:** Accepted
- **Date:** 2026-09-13
- **Deciders:** M8 — Import
- **Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0005](0005-secret-material-in-m1.md), [ADR-0008](0008-ffi-secret-crossings.md),
  [import.md](../import.md), [threat-model.md](../threat-model.md) M-21, W-9

## Context

Import is the one feature that asks kagisecure to read a large, untrusted, attacker-shaped file
and turn its contents into secrets. Five sources are in scope — 1PUX, and CSV exports from
1Password, Apple Passwords, Chromium and Firefox — and each of them arrives as a **complete
plaintext copy of somebody's password manager**.

That combination is unusual for this codebase. Everything else the core crate parses is either
something it wrote itself (the vault file, with a MAC over the header) or something small and
well-shaped (an `otpauth://` URI). A `.1pux` is a zip archive of JSON of arbitrary depth, produced
by another vendor, possibly downloaded over a network, possibly modified in between. It needs a
zip reader, an inflate implementation, a CSV reader and a JSON reader, none of which the workspace
depends on today.

Three questions had to be answered before any of it was written:

1. Where does that dependency subtree live, given that `kagisecure-core` is on the manual review
   checklist and `kagisecure-mcp` is built specifically so it *cannot name* `Secret`?
2. What shape does the parsed data take, so that five sources do not become five commit paths,
   five dedupe implementations and five ways to leak a value into a report?
3. What is the import *preview* — the thing a user reads before committing, and the thing that
   crosses the FFI boundary into the app — and how is it prevented from containing a password?

## Decision

### 1. A separate crate, `kagisecure-import`, that mcp and ipc must never depend on

```
kagisecure-import → kagisecure-core { features = ["secret-material"] }
kagisecure-cli    → kagisecure-import
kagisecure-ffi    → kagisecure-import
```

Not a module in `kagisecure-core`, for four reasons that are each independently sufficient:

- **The audited graph stays narrow.** `zip`, `flate2`, `csv` and `serde_json` are the kind of
  dependency this project otherwise does not have: large, C-shaped in origin, and written to be
  fast on adversarial input. Putting them in core would add them to the build graph of *every*
  consumer — the sidecar, the IPC crate, the extension protocol crate — none of which will ever
  parse a 1PUX.
- **Core is under the manual review checklist** ([threat-model.md](../threat-model.md) §8). Growing
  it by several thousand lines of parser makes that checklist worse at the job it exists for.
- **Fuzz targets need a home.** `crates/kagisecure-import/fuzz/` is a cargo-fuzz workspace excluded
  from the main one. It has somewhere natural to sit only if the parsers are a crate.
- **`cargo deny` can see the subtree.** A license or advisory hit on an import dependency is
  legible as "the import crate pulled this in", not as a change to the security-critical core.

**`kagisecure-mcp` and `kagisecure-ipc` must never depend on `kagisecure-import`.** This is stated
in the crate's `lib.rs` header next to the ADR-0002 argument, and the existing dependency-graph
guard in `crates/kagisecure-cli/tests/mcp.rs` — the one that already asserts the sidecar cannot
reach the `Secret`-defining module — gains a `kagisecure-import` clause. The reasoning is the same
one ADR-0002 makes: the sidecar's security property is that the capability does not exist in its
build, and a crate that constructs `Secret` from parsed bytes is exactly the capability.

`kagisecure-import` enables `secret-material` explicitly, the same posture as `kagisecure-cli` and
`kagisecure-ffi`. It is the only place in the import path that constructs a `Secret`: parsers
produce `ImportedValue::Secret(Secret::from_string(s))`, moving the plaintext `String` in so it is
zeroized on drop rather than left as a copy.

### 2. One source-agnostic IR, five parsers

Every parser produces the same `ImportedItem`, and `ImportPlan { source, source_path, items,
decisions }` is the whole of a parse. Nothing downstream of a parser knows which source it came
from except through `SourceKind`, which exists for wording in the report and for the dedupe foreign
key.

The consequence that matters: **`commit`, `dedupe`, `report` and the shred prompt are written
once.** A sixth source — Bitwarden, KeePass, the macOS keychain — is one new module under
`src/`, with no new commit path, no new dedupe rule, and no new opportunity to write a value where
values do not belong. The four CSV dialects already demonstrate this: they differ only in a header
signature and a column map.

`commit(vault, plan, policy)` mutates only the in-memory body; the caller then calls
`Vault::save()`, which is already atomic and `0600`. Parsing is complete before commit begins, so
a parse failure cannot leave a half-imported vault, and `--dry-run` is simply the path that never
calls `save()`.

### 3. "The report carries no values" is a type-level property, not a review rule

`ImportReport`, `ItemReport`, `DropNote` and `Totals` derive `Serialize`. `Secret` does **not**
implement `Serialize` and never will ([ADR-0002](0002-no-secret-values-over-mcp.md),
[threat-model.md](../threat-model.md) M-2). Therefore a field holding a value cannot be added to a
report type without a compile failure. This is the same mechanism ADR-0002 uses for the MCP
surface and [ADR-0030](0030-identifier-first-login.md) §1 uses for `Response::filled`: the
property is enforced by what will build, not by what a reviewer noticed.

`plan.report()` — names, labels, counts and decisions — is the only thing that crosses stdout, a
`--report` file, or the FFI boundary. **The preview is the report.** In the app the plan itself is
an opaque UniFFI object whose only readable projection is the report, which is why this feature
adds no new secret crossing to [ADR-0008](0008-ffi-secret-crossings.md)'s list.

A canary test closes the gap the type system does not cover — `Debug`, `Display` and error
strings. It seeds every parser with a unique marker as a password and asserts the marker appears
in no byte of the Markdown report, the JSON report, any `Debug` rendering of `ImportPlan` or
`ImportReport`, or any `Error`.

### 4. Dedupe: foreign id, then a fingerprint of names, then new — with three policies

Identity is decided in this order:

1. A foreign id (`extra["onepassword_uuid"]`, `extra["firefox_guid"]`) matching the same key on an
   existing item. Re-importing the same 1PUX is then exact.
2. `SHA-256(lower(title) ‖ 0x00 ‖ lower(primary_url_host) ‖ 0x00 ‖ lower(username))`.
3. Otherwise, a new item.

**Values are not in the fingerprint, deliberately.** Hashing the password would make a rotated
password look like a different account and silently double the item — which is the exact failure
this mechanism exists to prevent. It would also put a value-derived artifact in a code path whose
whole discipline is that values do not appear in it.

One policy per run: `skip` (default), `update`, `keep-both`. **There is no `interactive` mode.**
A per-conflict prompt would have to show either values — which §3 forbids outright — or only field
names, which is not enough information to decide on; and it converts a 400-item import into 400
modal questions, which is how people learn to click through prompts. `--dry-run` plus `--report`
is the supported way to inspect before deciding, and it shows the *whole* plan rather than one
conflict at a time.

### 5. Password history is imported into a `Secret`-typed home; attachments are dropped and counted

**Password history is imported.** Each `details.passwordHistory[]` entry becomes a revision on the
item, with the retired value held as a `Secret` — the same type, and therefore the same
zeroize-on-drop, no-`Serialize`, no-`Debug` guarantees as a live password. The home is an additive
`Item.history` field on `kagisecure_core::model::Item` (`#[serde(default)]`, carrying the retired
value, the label and kind of the field it belonged to, and a `retired_at` timestamp). **The exact
shape is defined by the core change in this milestone**, which also determines whether the vault
format version needs a bump; the format version is unchanged unless that change reports otherwise.

Three constraints come with it, and they are the reason importing history is acceptable rather
than merely convenient:

- **`Secret`, not `extra`.** The one place history must never go is `Item.extra`, because `extra`
  is not a `Secret` (§6) and putting retired passwords there would mean plaintext outside the
  guarded type, in a map whose entire purpose is to be lossless rather than careful.
- **Never agent-visible, unconditionally.** History is invisible to every MCP tool regardless of
  the item's `agent_visible` flag, and it is excluded from search — a password the user retired
  should not be the string that makes an item findable.
- **Counts only in reports** (§3). `Drop::PasswordHistory` survives, but only for entries the
  parser cannot use: no value, or a missing or unparsable timestamp. Nothing is coerced into a
  revision with an invented `retired_at`.

Under the `update` policy history is **merged rather than replaced** — source revisions are
appended and deduplicated by value hash plus `retired_at` — so re-importing an export twice does
not double it.

**Attachments are dropped and counted.** `kagisecure_core::model::Item` has no `attachments` field;
the sibling-blob design in [vault-format.md](../vault-format.md) §6 is a written design, not
implemented code, and building it is a core-crate project of its own (a new HKDF path, new golden
vectors, a migration) rather than part of an importer. Dropping is therefore the honest option, and
the only question was whether to drop silently. It is counted, reported per item, named in the
CLI's summary line, and given its own counter on the app's preview sheet. The metadata —
`fileName`, `documentId`, `decryptedSize` — is preserved in `extra["onepassword_documents"]`, so
whenever attachment storage does exist, a second pass can find what is missing without asking the
user to re-derive it.

Passkeys are dropped the same way, for the same reason: there is nothing to import them into.

### 6. `extra` is metadata only; anything with a concealment hint becomes a `Secret` field

`Item.extra` and the newly added `Field.extra` are `BTreeMap<String, ciborium::Value>` — lossless
passthrough for data with no first-class mapping. They are **not** `Secret`, so the rule is
absolute: **only non-secret metadata goes in `extra`; anything carrying a concealment hint becomes
a real `Secret` field.**

The hint test is one function, `onepux::conceal::is_concealed`, and it is a property-test target
rather than a scattering of `if` branches — because "did we check every way this source can say
*this is a password*" is a question that only has an answer if there is one place to look. It is
fail-closed: an unrecognized field type plus any hint (a `guarded` flag, a `password` designation,
a `concealed`/`totp`/`creditCardNumber` value key, or a title matching the secret-word pattern)
yields a `Secret`. A wrongly-concealed field is an annoyance the user fixes in the editor; a
wrongly-public one is a breach.

`Field.extra` is added additively (`#[serde(default)]`), which needs no schema bump: an older
build reading a newer body sees a field it does not know and CBOR round-trips it.

### 7. Shredding the source is best effort, and says so

`shred_file` opens the file write-only, overwrites its full length with CSPRNG bytes, `sync_data`s,
truncates, `sync_all`s and removes it, dropping extended attributes first on macOS. It runs only
behind an explicit `--shred-source` flag or an explicit button, and in the CLI only after a
successful `save()`.

**It is not a secure erase, and the wording never implies one.** APFS is copy-on-write, so the
overwrite may land in newly allocated blocks while the originals stay reachable in a snapshot;
SSDs wear-level and remap, so the physical blocks are not necessarily the ones written; Spotlight
may hold an index; Time Machine or a local snapshot may hold the entire file. The UI says "best
effort — the file may survive in a snapshot, a backup or unallocated SSD blocks" and the CLI prints
the same sentence.

Offering it anyway is still right. The realistic alternative is not a cryptographic erase; it is
the export sitting in `~/Downloads` forever, which is [threat-model.md](../threat-model.md) W-9.

### 8. Parser limits are checked before the data is read, not while it is read

From the zip's central directory, before any entry is decompressed: total uncompressed size
≤ 500 MB, per-entry compression ratio ≤ 1000:1. Then `export.data` is read through
`.take(256 MiB)`, and the item tree is bounded at 100 000 items, 10 000 fields per item and 1 000
sections per item. Entry paths are resolved with `ZipFile::enclosed_name()`, so `../` is never
honoured, and no entry is ever written to disk — everything is read through `std::io::Read` into
`Zeroizing` buffers.

Checking the directory first is the part that matters: a ratio check performed *during*
decompression has already allocated the memory it was meant to refuse. JSON depth is bounded by
serde_json's own 128-level recursion limit, which is why the schema uses concrete structs
everywhere except the flattened `extra` maps.

### Alternatives considered

**(a) `kagisecure_core::import`, a module behind a feature flag.** Rejected. A default-off feature
still puts the dependencies in `Cargo.lock` and in every `cargo deny` and `cargo audit` run, and
feature unification in a workspace build turns "off by default" into "on, because something else
in the graph asked for it". The guard that actually holds is a crate the sidecar does not depend
on — which is precisely the mechanism ADR-0002's `secret-material` split already proved.

**(b) Parse straight into `Vault` items, with no IR.** Rejected. `--dry-run` and the app's preview
both need the entire plan *before* anything is committed, which means the plan is a data structure
whether or not it is named one. Making it explicit is what buys one commit path, one dedupe
implementation, and a report type that can be constrained.

**(c) Let the report hold values and redact them on the way out.** Rejected on the same grounds as
ADR-0002 rejects a redaction filter for MCP: a filter is a thing that can have a bug, and the bug
is unobservable until someone reads a report and finds a password in it. A type that cannot hold
the value has no such failure mode.

**(d) Import attachments into `extra` as base64.** Rejected twice over: it puts file contents —
including, for a 1Password Document item, an SSH private key — in plaintext outside `Secret`, and
it inflates the vault body, which is decrypted whole into memory on every unlock.

**(e) An `interactive` dedupe policy.** Rejected: see §4.

**(f) Shred by default after a successful import.** Rejected. Deleting a file the user did not ask
to have deleted is not a safety feature, and the guarantee is too weak to justify the surprise.
The prompt is the right shape: offered every time, never assumed.

## Consequences

### Positive

- The sidecar's dependency graph is unchanged, and the property that makes it trustworthy —
  it cannot name `Secret` — is unchanged with it.
- Adding a sixth source is a parser module, nothing else.
- "No value can appear in a report" is checked by the compiler, with a canary test covering the
  `Debug`/error paths the compiler does not.
- The app's preview and the CLI's `--dry-run` are, by construction, the same artifact.
- Password history survives the move into kagisecure with the same protection as a live password,
  which is what makes 1Password parity honest rather than partial.

### Negative — accepted

- **A ninth crate**, with its own `Cargo.toml`, its own local test/lint setup and its own fuzz
  workspace.
- **Four new dependencies** — `zip`, `flate2` (transitively), `csv`, `serde_json` — in a project
  that has been deliberate about having few. They are confined to one crate, and `cargo deny`
  gates them.
- **An unverified `categoryUuid` table.** Only `001` (Login) is confirmed by published
  documentation. The fallback is `Other(<uuid>)` plus the raw code preserved in `extra`, so a wrong
  row is visible and recoverable, but the table is a known guess until a real export confirms it
  ([import.md](../import.md) §2.3).
- **Attachments and passkeys are a real gap**, not a rounding error, for anyone whose 1Password
  vault leans on Documents. The report is honest about it; that is all it can be.
- **`Item.history` is new persisted state that no earlier build knows about.** It is additive and
  `#[serde(default)]`, and the format version stays where it is unless the core change says
  otherwise — but a vault written after an import and then opened by an older build is a case the
  golden-vector tests now have to cover.
- **Fuzzing does not run as part of `cargo test`**, because cargo-fuzz needs nightly. `proptest`
  runs over `is_concealed` and the CSV row splitter as part of `cargo test` (in CI until CI was
  removed on 2026-09-19, locally since); the fuzz targets are a `make fuzz` target for
  contributors ([threat-model.md](../threat-model.md) §8).
