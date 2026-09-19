# ADR-0012: M3 scope deviations — aarch64-only, no attachments, and a `trashed_at` field

- **Status:** Accepted; §1 superseded by [ADR-0027](0027-universal-binaries.md) (2026-09-10)
- **Date:** 2026-09-09
- **Deciders:** M3 implementation

Three smaller decisions, each of which departs from something written down earlier. Grouped
because none of them warrants its own document and none of them should be discovered by reading a
diff.

## 1. M3 builds `aarch64-apple-darwin` only; the universal binary is deferred

> **Superseded by [ADR-0027](0027-universal-binaries.md), 2026-09-10.** M7 ships universal, as
> this section said it would. The cross-build succeeded on the first attempt and the "contained
> change" predicted below was exactly that. Everything under this heading is kept as the record of
> why M3 shipped one architecture, not as a description of what the project does now.

**Written down as:** [architecture.md](../architecture.md) §7 — "`aarch64-apple-darwin` +
`x86_64-apple-darwin` → universal"; roadmap M3 — "The app builds as a universal binary and runs
on the two most recent macOS majors."

**What M3 does:** `cargo xtask bindgen` builds one static library, for `aarch64-apple-darwin`, and
packages a single-slice xcframework. The implementation machine has only that target installed,
and `rustup target add x86_64-apple-darwin` plus a `lipo` step would add a second slice that
nothing in this milestone can run or test.

**Why that is the right call for now:** a universal binary is a *release* concern, and release
engineering is M7. Shipping an untested x86_64 slice is worse than shipping none — it is a claim
of support with no evidence behind it. The change when it comes is contained: build both targets,
`lipo -create` them, and pass two `-library` pairs to `-create-xcframework`. The xtask is
structured so that is a loop, not a rewrite.

**Consequence:** M3's "universal binary" acceptance criterion is **not met**, deliberately, and
the roadmap records it as deferred to M7 rather than ticked. An Intel Mac cannot run this build.
(As of M7 it can: see [ADR-0027](0027-universal-binaries.md).)
The "two most recent macOS majors" half is met by the deployment target (macOS 15), though it has
only been *run* on macOS 26.1.

## 2. Attachments stay deferred

**Written down as:** roadmap M1's carry-over list — "Attachments — still deferred, to M3 (they
need the app's UI to be worth anything)"; roadmap M3 scope includes "custom sections,
attachments".

**What M3 does:** neither. `FieldKind::File` exists in the model and in the FFI enum, so an
imported attachment field round-trips, but there is no attachment storage, no Quick Look, no
drag-out, and the "+ Add field" menu does not offer `File`.

**Why:** attachments are not UI work with a small model behind them. [vault-format.md](../vault-format.md)
§6 specifies a sibling `<vault>.attachments/` directory, per-blob AEAD with an
`HKDF(VK, "kagisecure/attachment/" || id)` subkey, and an `AttachmentRef` on the item — a new
on-disk artifact, a new key-derivation path, a new set of golden vectors and a new answer to
"what happens when the sidecar directory is missing". That is a milestone-sized piece of
`kagisecure-core`, and doing it badly in the last third of M3 would put an under-tested crypto
path next to the vault.

**Consequence:** the Document category exists and holds notes; it cannot hold a document yet. The
roadmap moves attachments to their own line rather than leaving them inside M3's scope
paragraph. Custom *sections* are half-done: existing sections render as collapsible groups and
survive an edit, but the edit sheet cannot create or rename one.

## 3. `Item.trashed_at` is a new field, additively

**Written down as:** [vault-format.md](../vault-format.md) §5's item sketch, which has `archived:
bool` and nothing about a trash; [ui-spec.md](../ui-spec.md) §2.2, which asks for a Trash section
holding "soft-deleted items, permanent-delete after a retention window".

Those two cannot both be satisfied by the format as written: with only `archived`, Archive and
Trash are the same bit and the sidebar has two rows for one state.

**What M3 does:** adds `trashed_at: Option<u64>` to `Item`, `#[serde(default)]`, and a matching
`trashed: bool` to the metadata-only `ItemSummary`.

**Why a timestamp and not a boolean:** the retention window ui-spec asks for needs to know *when*,
and a boolean would have to be replaced by exactly this field the moment anyone implements it.

**Why this does not bump `body.schema`:** [vault-format.md](../vault-format.md) §9 — additive
changes do not bump it, and unknown keys survive round-trip. An M1- or M2-era vault reads back
with `trashed_at: None`, and a vault written by this build opens in an older one, which preserves
the key it does not understand via `extra` and shows the item as untrashed. That is the intended
behaviour of rule 1, exercised by the golden vector test.

**Consequence for the agent surface:** trashed items are now filtered out of `list_items` and
refused by `describe_item` in the daemon. An item the user threw away should not be offered to an
agent, and before this change nothing would have stopped it, because nothing could be thrown
away. vault-format.md §5 gains the field in its item sketch.
