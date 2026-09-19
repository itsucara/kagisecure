# ADR-0008: What secret material crosses the UniFFI boundary, and why

- **Status:** Accepted
- **Date:** 2026-09-09 (revised the same day for M4, then for M5)
- **Deciders:** M3 implementation, revised by M4 and M5
- **Refines:** [ADR-0001](0001-rust-core-native-ui.md),
  [ADR-0004](0004-biometric-key-wrapping.md), [ADR-0005](0005-secret-material-in-m1.md),
  [architecture.md](../architecture.md) §4

## Context

[architecture.md](../architecture.md) §4 puts a single word in the "may carry plaintext" cell for
the UniFFI boundary: **Yes**. That is correct — the app and `kagisecure-core` are one process and
one trust domain — but it is not a design. Left as-is it licenses anything, and the first time
someone adds a `dump_all_items()` for convenience there is no rule to point at.

The IPC boundary got the treatment it deserved in [ADR-0002](0002-no-secret-values-over-mcp.md):
the protocol has *no message* whose reply can carry a value, enforced by the crate graph. The FFI
boundary cannot have that property — the app is the thing that shows a user their own password —
so it needs the next best thing: an enumerated, justified, reviewable list.

## Decision

**Exactly five kinds of secret material cross `kagisecure-ffi`. Each is listed below with its
direction and its justification. Adding a sixth requires an edit to this ADR in the same commit.**

| # | Crossing | Direction | Function |
| --- | --- | --- | --- |
| 1 | Master password / recovery code | app → Rust | `VaultSession::create`, `unlock_with_password`, `unlock_with_recovery_code`, `change_master_password` |
| 2 | A single field or variable value | both | `VaultSession::reveal_field` (out), `save_item` via `FieldDraft.value` (in), `set_variable_value` (in, **added in M4**) |
| 3 | The raw vault key | Rust → app | `VaultSession::export_vault_key_for_platform_wrapping` |
| 4 | The unwrapped vault key | app → Rust | `VaultSession::unlock_with_vault_key` |
| 5 | A generated password, or a one-time code and the `otpauth://` URI it comes from | both | `generate_password` (out), `VaultSession::totp_code` / `item_totp_code` / `totp_preview` (out), `totp_describe` / `totp_preview` / `totp_uri_from_parts` / `totp_uri_is_valid` (in), **added in M5** |

**M6 added no sixth kind *here*.** The browser extension is a genuine new place a value crosses,
but it crosses a **socket**, not this boundary — so it is enumerated in
[ADR-0018](0018-browser-extension-secret-crossing.md) rather than added as a sixth row. The FFI
surface M6 added (`extension_start`, `extension_status`, `extension_fill_leases`,
`extension_revoke_fill_lease`, `extension_revoke_all_fill_leases`, `extension_setup`,
`extension_install_manifest`, `extension_uninstall_manifest`, and the browser fields on
`ApprovalRequestView`) carries none: origins, item ids, titles, field **names**, pids, executable
paths and a JSON manifest. The reason is the same structural one §6 gives for M4's twenty
functions — the record is built from `kagisecure_agent::ApprovalRequest`, which has no field a
value could occupy.

**M4 added no fifth kind.** It widened crossing 2 by one function and added a large surface
(`agent_start`, `agent_next_request`, `agent_resolve`, `agent_leases`, `agent_revoke_lease`,
`agent_revoke_all_leases`, `agent_pending_requests`, `agent_status`, `agent_take_lock_request`,
`agent_stop`, `mcp_setup`, `VaultSession::audit_page`, `audit_count`, `create_environment`,
`environment`, `set_environment_agent_visible`, `set_vault_agent_visible`, `bind_variable`,
`remove_variable`, `delete_environment`) that carries **none**. See §6.

### 1. Credentials going in

Unavoidable: the user types them, and the KDF lives in Rust. Nothing to design.

The honest caveat is the one [vault-format.md](../vault-format.md) §7 already states and this
crossing makes worse: a Swift `String` is immutable and garbage-collected, so the password exists
on the Swift heap in copies nobody can zeroize, from the moment `SecureField` produces it. Rust
zeroizes its own copy; Swift's is beyond reach. This is the same weakness ADR-0003 records for
C#, and it applies to Swift too — it was simply not written down before.

### 2. One field value at a time

The detail pane must render a revealed password (ui-spec.md §4.2) and the edit sheet must show a
concealed field's value so a typo can be fixed (§4.3). So values cross.

What is *designed* is the granularity. There is:

- **no** call that returns every value in an item;
- **no** value on `FieldView`, the record the item list and detail pane are built from — a
  concealed field's `value` is `None` there, always, and the plaintext is a separate call;
- **one** function, `reveal_field(item_id, field_id)`, returning one string.

So a bug in the view layer can leak the field the user asked to see, and not the other nine. The
edit sheet calls `reveal_field` once per concealed field precisely because it needs them all —
that is a deliberate, visible cost rather than a convenient bulk accessor that would then be
available to everything else.

`FieldView.hasValue` is a boolean, not a length, matching
[mcp-server.md](../mcp-server.md) §2.4: the mask in the UI is a fixed ten dots regardless of the
value, so the rendering does not leak what the record refuses to.

#### M4: `set_variable_value`

`add_variables` lets an agent name a variable it is forbidden to supply a value for
(mcp-server.md §2.6). The value has to arrive somehow, and the whole design of that flow is that
it arrives **in the native app, from the user's keyboard**, rather than through the agent's chat.
That is a `SecureField` in `EnvironmentEditor` and one FFI call.

It is the same crossing as `save_item`'s `FieldDraft.value` — one value, named by the caller,
going in — applied to an environment's inline binding instead of an item's field. It is listed
rather than waved through because the rule is that the table is the list, and a reviewer asking
"which of these is it?" should find the answer written down.

The same granularity discipline applies: there is no call that sets several variables at once, and
no call that reads one back. `EnvironmentView` reports `populated: bool` and never a value.

### 3 and 4. The vault key, for the Secure Enclave

These are the two that needed a decision, and they exist because of a hard constraint: **only the
keystore can produce and consume its own ciphertext.** `SecKeyCreateEncryptedData` takes
plaintext and a `SecKey`; there is no way to hand the Secure Enclave a Rust closure, and no way
for Rust to construct the ECIES blob itself.

The alternatives, and why they lose:

| Alternative | Why not |
| --- | --- |
| Rust calls up into Swift to wrap/unwrap (foreign callback) | ADR-0001 and architecture §4.1: no foreign callbacks. Building the biometric path on the least-settled part of the binding generator is exactly the trade we already refused. |
| Swift passes the `SecKey` handle down to Rust | A `SecKey` is an opaque CoreFoundation pointer. Passing it over FFI means `unsafe` in a crate that is `forbid(unsafe_code)`, and Rust would then have to link Security.framework — moving the platform integration into the shared core, which is the layering bug architecture §2.5 warns about. |
| Wrap something *derived* from the vault key instead | Any derivation still has to happen on one side of a boundary the key must cross. It adds a step and moves nothing. |
| Keep the whole platform slot in Swift, in the keychain | Then the vault format does not describe how the vault opens, and a second implementation could not open a Touch-ID-enrolled vault at all. Worse, the slot would live outside the file the user backs up. |

So the key crosses, twice, in the narrowest form available:

- **Crossing 3** happens exactly once per enrolment, is named
  `export_vault_key_for_platform_wrapping` rather than `vault_key`, and is documented in the core
  as the single function that lets the key leave. The Rust side returns a `Zeroizing<Vec<u8>>`;
  the Swift side wipes its `Data` in a `defer` block.
- **Crossing 4** happens once per Touch ID unlock, immediately after
  `SecKeyCreateDecryptedData`, and the Swift side wipes its buffer in a `defer` as well.

Everything *else* about the platform slot stays in the core: the blob is stored, selected,
validated and removed by `kagisecure-core`, which is why Swift never learns what a wrapped-key
slot is (see also the `platform-opaque` AEAD marker in `crypto::wrap`).

### 5. Generated passwords and one-time codes (M5)

This is a genuinely new kind, and it points both ways.

**Out.** `generate_password` returns a password the user just asked to be generated, and
`totp_code` / `item_totp_code` / `totp_preview` return a six-to-eight digit code. There is no
version of these features in which the value stays in Rust: a generator whose output cannot be
shown, or a TOTP field whose code cannot be read, is not the feature. The core holds both as
`Secret` right up to the boundary — `generator::Recipe::generate` and `Totp::code_at` both return
`Secret`, not `String` — and the `expose_str()` call is at the FFI edge where it is greppable, the
same discipline `reveal_field` follows.

**In.** `totp_describe`, `totp_preview`, `totp_uri_from_parts` and `totp_uri_is_valid` take an
`otpauth://` URI or a Base32 seed that the user pasted or typed. This is crossing 2's shape — one
value, named by the caller, going in — applied to a field the setup sheet has not saved yet. It
exists because ui-spec.md §9 requires a live preview *before* the field is committed, which means
the code has to be derivable from something the vault does not hold yet.

The granularity rules from crossing 2 hold. There is no call that returns codes for several
fields; every call that returns a code names one item and one field, or one item and takes the
first (`item_totp_code`, which the list's hover action and Quick Access's ⌥⏎ need because they know
a row, not a field); and `FieldView` still carries no value for a TOTP field, so a rendered field
list contains no seeds. `TotpCodeView` carries the code, the seconds remaining and the parameters
— it does **not** carry the seed.

Why the code is `Secret` in the core at all, when it expires in thirty seconds: because anyone
holding it inside its window can complete a second factor with it, and "short-lived" is not
"public". It is also why the code never crosses the *IPC* boundary — `kagisecure_core::totp` is
compiled only under `secret-material`, which `kagisecure-mcp` and `kagisecure-ipc` do not enable,
so those crates cannot name `Totp`, cannot call `code_at`, and have no type a code could sit in
(mcp-server.md §2.4, [ADR-0016](0016-totp-field-storage.md)).

**Zeroization, honestly.** Both values reach Swift as `String`, which is immutable, reference-
counted and not zeroizable — the same limitation this ADR already records for a revealed password,
now applying to two more things. What the app does instead is keep the window short: a generated
candidate lives only while the sheet is open (the history list is at most eight entries and is
released with the sheet), and a TOTP code is recomputed from the wall clock each second rather than
cached. Anything copied to the clipboard is a separate exposure with its own mitigations
([ADR-0017](0017-quick-access-hotkey-and-pasteboard.md) §3).

## 6. The M4 agent surface carries no value

`kagisecure-ffi` grew twenty exported functions in M4 for the approval flow, the leases table, the
audit viewer and the setup screen. None of them is a fifth crossing, and the reason is structural
rather than careful:

- **`ApprovalRequestView`** is built from `kagisecure_agent::ApprovalRequest`, which is built from
  a `kagisecure_ipc::Request` and a `PeerIdentity`. `kagisecure-ipc` compiles without
  `secret-material` and cannot name `Secret`, so nothing in that chain has a value to hand on.
  The record's fields are names, paths, pids, counts and timestamps.
- **`LeaseView`** is `kagisecure_core::proto::LeaseSummary`, which lives in the `proto` module —
  the metadata-only half of the core, compiled with and without `secret-material`.
- **`AuditRowView`** is an `AuditEntry`, whose `variables` field is documented in the core as
  "Variable **names**. Never values" and whose `detail` is written from a fixed vocabulary.
- **`McpSetupView`** is a file path and four configuration snippets.
- **`agent_resolve`** takes a decision and a verification verdict, both of which are the app's own
  conclusions travelling downward.

Two of these are asserted rather than merely argued:
`crates/kagisecure-agent/tests/sidecar.rs` seeds a 32-byte marker as a secret value, drives a real
`write_env_file` through a real sidecar, and asserts the marker appears in the written `.env` and
in **neither** the `ApprovalRequest` the UI was handed nor any audit entry nor the sidecar's
stdout.

## Consequences

**Positive**

- The list is short enough to review, and a reviewer has a concrete question to ask of any FFI
  addition: which of these four is it, or is it a fifth?
- The M5 additions did not need a new *kind* of argument or a new escape hatch in the core: they
  reuse `Secret` and `expose_str`, and the new modules are behind the same feature flag as the
  vault. A crate that may not hold plaintext still cannot.
- `reveal_field`'s granularity is the FFI-level echo of `Secret::expose`'s greppability
  (ADR-0005): both are the narrow, loudly-named hole in an otherwise closed surface.
- The Windows port inherits the shape. `KeyCredentialManager` has the same constraint, so
  crossings 3 and 4 will exist there too, with the same justification already written down.

**Negative — accepted**

- **Swift-heap plaintext is not zeroizable.** Passwords and revealed values linger in Swift
  `String`s until the allocator reuses the memory. `Data` buffers we can and do wipe; `String`s we
  cannot. Documented, minimized (the app holds a revealed value only while its row is on screen
  and drops it when the selection changes), not eliminated.
- **Crossings 3 and 4 mean the vault key is in Swift memory, briefly, twice.** For the length of
  one function call, in a `Data` that is explicitly wiped. Against an attacker who can read the
  app's memory at that moment (threat-model T-3 and worse), this changes nothing that was not
  already true — the same process holds the key for the whole unlocked session anyway.

**Neutral**

- The five crossings are asserted by tests only indirectly (the round-trip tests exercise all of
  them). There is no test that asserts *no fifth crossing exists*; that is a review property, like
  `expose()`.

## Addendum 2026-09-13 — import surface

[ADR-0031](0031-the-import-crate-and-its-intermediate-representation.md) adds an import feature,
and with it a new corner of `kagisecure-ffi`: [`ImportPlanHandle`], `VaultSession::import_preview`
/ `import_preview_against` / `import_commit`, and the free functions `shred_source_file` /
`shred_caveat` / `import_formats`. None of this is a sixth crossing.

`ImportPlanHandle` is a `uniffi::Object` — an opaque handle Swift holds a pointer to, not a
record copied across the boundary. The parsed plan lives inside it on the Rust heap for as long as
the handle exists, and `import_commit` consumes the underlying `kagisecure_import::ImportPlan` by
value, leaving the handle spent. Every value the app can read out of a preview or a commit is a
projection of `kagisecure_import::report::ImportReport`, converted field by field into records
that hold names, kinds, counts and timestamps — never a value. That is enforced by the type system
rather than by discipline: `kagisecure_import::ir::ImportedValue` and `kagisecure_core::Secret` are
not `Serialize` and have no conversion into any FFI record, so a column that carried one could not
be written. See the `kagisecure-ffi/src/import.rs` module doc for the full accounting, including
why even imported password history crosses as a count and nothing else.

**M8 added no sixth kind.** The plan never leaves Rust, and the report it hands back is
values-free by construction, not by convention.
