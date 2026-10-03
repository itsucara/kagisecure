# ADR-0003: C# bindings — evaluate `uniffi-bindgen-cs`, fall back to `csbindgen`

- **Status:** Accepted. The evaluation gate ran on 2026-09-25 and chose the fallback; see
  [Evaluation record](#evaluation-record). One presence-gate callback crosses the C ABI since
  2026-09-26 — see the amendment at the end.
- **Date:** 2026-09-09 (evaluation recorded 2026-09-25)
- **Deciders:** project owner

## Context

The Rust core must be callable from two managed languages. Swift is straightforward: UniFFI
(0.32.0, released 2026-06-30) treats Swift as a first-class target, and the Swift bindings are
maintained in-tree by Mozilla.

C# is not first-class. The options:

| Option | What it is | Risk |
| --- | --- | --- |
| **A. `uniffi-bindgen-cs`** | Third-party C# backend for UniFFI, maintained by NordSecurity. Reuses our existing UDL/proc-macro definitions. | Tracks a **pinned** UniFFI version and lags upstream. Last observed alignment: uniffi **0.29.4** — three minor versions behind 0.32.0. |
| **B. `csbindgen` + hand-written P/Invoke** | Generate C# `DllImport` declarations from a `extern "C"` surface we write ourselves; marshal by hand. | Full control, no version coupling — but we write and maintain the marshalling, including strings, byte arrays, errors, and object lifetimes. |
| C. C++/CLI or a COM layer | — | More machinery than either A or B for no benefit. |
| D. Duplicate the core in C# | — | Rejected by ADR-0001. |

The tension is specific: option A saves real work *if* it supports the UniFFI version we pin. If
it does not, we must either downgrade UniFFI for the whole project (degrading the Swift path,
which is the better-supported one) or maintain a fork of a binding generator — both worse than
option B.

Note also that our FFI surface is deliberately small. Per ADR-0001 and architecture §4.1, the
approval flow does **not** cross FFI as an async callback; it goes over IPC. What crosses FFI is
synchronous, app→Rust, value-returning calls: unlock, lock, list, CRUD, import, inject, audit
read. That is on the order of 20–30 functions with simple types (strings, byte arrays, enums,
records, results). Hand-marshalling that is a finite, boring job — not an open-ended one.

## Decision

**Pin UniFFI at the version the Swift path needs (0.32.0 as of today). Do not downgrade UniFFI to
suit the C# backend.**

At the start of M4, evaluate `uniffi-bindgen-cs` against the pinned version, using these criteria:

| # | Criterion | Pass condition |
| --- | --- | --- |
| C1 | Version support | Supports the pinned UniFFI version, or a release supporting it exists with a credible cadence |
| C2 | Type coverage | Handles every type in `kagisecure-ffi`: records, enums with data, `Result`/error types, `Vec<u8>`, `Option`, and callback-free interfaces |
| C3 | Byte-array fidelity | `Vec<u8>` round-trips without a UTF-8 assumption anywhere (we pass key material and attachment bytes) |
| C4 | Lifetime correctness | Generated handles free deterministically; no reliance on the C# finalizer queue for anything holding plaintext |
| C5 | Build integration | Works from `cargo xtask bindgen` on Windows without manual steps (ran on CI's `windows-latest` until CI was removed on 2026-09-19) |
| C6 | Maintenance signal | Commits and releases within the last ~6 months; open issues do not include unfixed memory-safety bugs |

**If all six pass:** use `uniffi-bindgen-cs`. One binding definition serves both platforms.

**If any fail:** fall back to `csbindgen` plus a hand-written P/Invoke layer in
`apps/windows/Kagisecure.Interop/`, over an explicit `extern "C"` surface added to
`kagisecure-ffi` behind a `capi` feature. The Swift path is unaffected either way.

Regardless of which path is chosen, these rules apply:

1. **The FFI surface stays small and synchronous.** No async, no foreign callbacks, no trait
   objects crossing the boundary. This is what makes the fallback tractable.
2. **The evaluation result is recorded in this ADR** — which criteria passed, which failed, and
   the version numbers observed on the evaluation date. M4's acceptance criteria require it.
3. **A shared conformance test suite** runs the same scenario matrix through Swift and C#
   bindings, asserting identical results — so a marshalling bug in either path is caught by tests
   rather than by a user with a corrupted vault.
4. **Byte arrays are never marshalled as strings** on either side. Key material and attachment
   contents are `byte[]` / `[UInt8]` end to end.
5. **Managed-side secret handling is minimized.** C# strings are immutable, GC-moved, and cannot
   be reliably zeroized. Plaintext must not linger on the managed heap: values stay in Rust,
   and the C# app passes identifiers, not contents. Where a value must transit (the user typing a
   new secret into the app), use a `SecureString`-adjacent pattern or a pinned `byte[]` that is
   cleared and unpinned promptly — and get it into Rust in as few copies as possible.

## Consequences

**Positive**

- The Swift path — the better-supported one, and the platform we ship first — is never held back
  by a third-party backend's release cadence.
- The decision is deferred to the point where evidence is available (M4), rather than guessed
  now, but the criteria are fixed in advance so the decision cannot be rationalized later.
- The fallback is genuinely viable because ADR-0001's "no async callbacks over FFI" rule keeps
  the surface small. The two decisions reinforce each other.

**Negative — accepted**

- **Possible duplication of binding definitions.** If we fall back, the C ABI surface is
  maintained alongside the UniFFI one, and every FFI addition is two edits. Mitigated by keeping
  the surface small and by the conformance test suite.
- **Hand-written P/Invoke is a memory-safety boundary we own.** Mismatched signatures produce
  corruption, not compile errors. Mitigated by generating declarations with `csbindgen` rather
  than typing them, and by the conformance tests.
- **Windows may lag macOS** in a release where the FFI surface changed. Acceptable; the roadmap
  already sequences M3 before M4.
- **Managed-heap plaintext is a real, unfixable-in-C# weakness** for the brief window when a user
  types a new secret into the WinUI app. Documented; minimized; not eliminated. This is one more
  reason the macOS security story is slightly stronger than the Windows one
  (see [ADR-0004](0004-biometric-key-wrapping.md)).

**Neutral**

- If `uniffi-bindgen-cs` catches up to the pinned version later, switching to it from the
  `csbindgen` fallback is a contained change behind the conformance suite. The decision is
  reversible in that direction; it is not reversible in the other (we would not un-pin UniFFI).

## Evaluation record

Run on Windows 11 Pro (10.0.26200), Rust 1.98.1 (MSVC), .NET SDK 8.0.425, against
`kagisecure-ffi` built with **uniffi 0.32.0** (the version `Cargo.lock` pins). The generator was
`uniffi-bindgen-cs` **v0.11.0+v0.31.0** (commit `e10ce41`, tagged 2026-06-23 — the newest tag, and
`main` is the same commit), installed with
`cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --tag v0.11.0+v0.31.0 --locked`.

| Criterion | Result | Evidence | Date |
| --- | --- | --- | --- |
| C1 | **Fail** | No tag, release or branch of the official repository targets uniffi 0.32. Run against our DLL, v0.11.0 does not get as far as writing a file: `extracting metadata for 'UNIFFI_META_KAGISECURE_FFI_CONSTRUCTOR_VAULTSESSION_CREATE'` → `Invalid string data` → `invalid utf-8 sequence`. The cause is structural, not a bug: 0.32 changed the metadata wire format (an `orig_name` optional string on functions, methods, constructors, records, fields, enums and variants; a trait-kind byte on trait interfaces; `by_ref` on arguments; new `Box`/`Set` type codes — diff of `uniffi_meta` 0.31.0 → 0.32.0 `reader.rs`), which a 0.31 reader misparses. The UniFFI contract version is 30 in both, so the runtime handshake alone would not have caught the mismatch; the per-method checksums would have. An upgrade exists only as an **unmerged third-party pull request** (#176, from a fork, opened 2026-07-10, one contributor's review request and no maintainer review as of its last update 2026-09-04); issue #183 ("Update for 0.32 uniffi", 2026-08-28) has no reply. Cadence of the tags that did ship: `+v0.28.3` 2025-04-07, `+v0.29.4` 2025-08-22, `+v0.31.0` 2026-06-23 — 0.30 was skipped, and the lag behind upstream has been months each time. Neither "supports the pinned version" nor "a release supporting it exists" holds. | 2026-09-25 |
| C2 | Not measurable (blocked by C1) | Nothing can be generated for our crate, so no generated C# could be compiled or exercised. Reading the v0.11.0 templates: records, data-carrying enums, `flat_error` errors (one exception subclass per variant), `Option`, `Vec<u8>` and objects all have templates, and the shapes we use are the well-trodden ones. The fallback proof below exercises each shape by hand instead. | 2026-09-25 |
| C3 | Not measurable for the generator; **Pass** for the fallback proof | v0.11.0's `BytesTemplate.cs` writes a length prefix and copies bytes, with no text decoding — it would likely pass. The fallback proof measures it: a 32-byte vault key exported through `kgs_session_export_vault_key` unlocks the vault again through `kgs_session_unlock_with_vault_key` (a byte-exact round trip, since one flipped bit fails), and a key made of alternating `0x00`/`0xFF` — not UTF-8, full of NULs — arrives as `WrongCredential`, not as a truncated or decoded string. | 2026-09-25 |
| C4 | Not measurable for the generator; **Pass** for the fallback proof | v0.11.0 generates `IDisposable` objects with a call counter that defers the free past in-flight calls, plus a finalizer as backstop — it would likely pass. The fallback proof uses a `SafeHandle` for `VaultSession`: `Dispose` frees the Rust reference at once (the lock), the marshaller add-refs across each call, a call after `Dispose` throws `ObjectDisposedException`, and a second `Dispose` is a no-op. The finalizer exists only as a backstop; the API tells callers to use `using`. Tests assert the use-after-`Dispose` exception, the idempotent `Dispose`, and that two sessions on one file are independent references; the add-ref across a call is the `SafeHandle` marshaller's documented behaviour and is not separately race-tested, and the key's zeroization on the Rust side is the core's existing `Drop`, not observable from C#. | 2026-09-25 |
| C5 | **Fail** for the generator; **Pass** for the fallback proof | With C1 failing, no invocation produces C#. For the fallback, `cargo xtask bindgen-cs` builds `kagisecure_ffi.dll` with the `capi` feature and stages it in `target/windows/<Configuration>/`, and `dotnet test apps/windows/Kagisecure.Windows.sln` then passes (13 tests) — no manual step in between, verified from a clean `target/windows`. | 2026-09-25 |
| C6 | Pass (marginal) | Last release and last commit to `main` 2026-06-23 (three months old); third-party pull requests keep arriving (six open, latest 2026-09-14), but nothing has merged since 2026-06-23 and #176 — the one we would need — has no maintainer review. No open issue describes a memory-safety bug on a path we would use; the one crash report (#175) is in callback-interface vtable code under full AOT on iOS/Mac Catalyst, and we have no callbacks. | 2026-09-25 |

**Outcome: the fallback.** C1 and C5 fail, and "if any fail" was fixed in advance for exactly this
case. The C# layer is a hand-written P/Invoke assembly, `apps/windows/Kagisecure.Interop/`, over
an explicit `extern "C"` surface in `kagisecure-ffi` behind the `capi` feature
(`crates/kagisecure-ffi/src/capi.rs`). UniFFI stays at 0.32.0; the Swift path is untouched.

What exists today is the **minimal proof**, not the surface: one C function per shape this ADR
worries about, each exercised from C# against a real vault by
`apps/windows/Kagisecure.Interop.Tests`:

| Shape | C ABI | C# |
| --- | --- | --- |
| record in | `KgsGeneratorRecipe` → `kgs_generate_password` | `GeneratorRecipe` → `PasswordGenerator.Generate` |
| record out, owned strings | `KgsItemSummary` from `kgs_session_create_item` / `kgs_session_item`, freed by `kgs_item_summary_free` | `ItemSummary` |
| enum with data in | `KgsItemFilter` (tag + one payload slot) → `kgs_session_count_items` | closed `ItemFilter` record hierarchy |
| errors | `KgsStatus` return + message `KgsBuffer` | `KagisecureException.<Variant>` |
| bytes in / out | `KgsSlice` / `KgsBuffer` (zeroized on free) | `ReadOnlySpan<byte>` / `byte[]` |
| Arc-style object | `*mut KgsSession` (one `Arc<VaultSession>`), `kgs_session_free` | `VaultSession : IDisposable` over a `SafeHandle` |
| version handshake | `kgs_abi_version` | checked once before the first call |

The marshalling rules the proof settles — no NUL-terminated strings anywhere, everything Rust
allocates Rust frees (and zeroizes), out-parameters claimed before any work, panics caught at the
boundary, runtime marshalling disabled on the C# side so only blittable types can cross — are
written at the top of `capi.rs` and `NativeMethods.cs`. The `capi` feature is off by default, so
the library the Swift app links still compiles under `#![forbid(unsafe_code)]`; a `capi` build
downgrades that to `deny` with a single `allow` on the one module that needs it.

**What the fallback now costs, measured rather than assumed.** The Context above sized the
surface at "20–30 functions". It has grown since: `kagisecure-ffi` exports **85 entry points**
(36 free functions, 46 `VaultSession` methods, 3 `ImportPlanHandle` methods) over **55 records,
enums, objects and errors**. The proof covers 10 of the 85. Every one of the remaining 75 is a Rust
adapter plus a C# wrapper, and every future FFI addition is two edits — the negative consequence
this ADR already accepted, now roughly three times the size it was accepted at.

**Plan for the rest**, in order. Items 1–3 are **done** (2026-09-25, ABI version 2); the proof
tables above describe the ABI as it was at version 1. What each step settled:

1. **Generate the declarations — done.** `csbindgen` 1.9.8 (MIT) is a dependency of `xtask` only —
   not a `build-dependency` of `kagisecure-ffi`, so neither the Swift build nor the DLL compiles
   it — and `cargo xtask bindgen-cs` emits `Kagisecure.Interop/Native/NativeMethods.g.cs` from
   `crates/kagisecure-ffi/src/capi/` (split into `mod`, `enums`, `items`, `session`, `generate`,
   `agent`, `import`) before building the DLL. The hand-typed `NativeMethods.cs` is gone; the
   ABI version the C# checks at load is the generated `KGS_ABI_VERSION` constant, so the two cannot
   be bumped apart. The generated file is **checked in**, for the reasons ADR-0009 gives for the
   Swift; the DLL is **not**. Drift is caught in three places: xtask's
   `generated_csharp_is_up_to_date` (regenerate, compare with the checked-in file) and
   `generation_is_idempotent` (run twice, compare) — ADR-0009's check, as tests; xtask's
   `every_export_and_every_tag_enum_is_declared`, which scans the sources for `#[unsafe(no_mangle)]`
   and requires each in the output; and the C# `AbiTests`, which require every declared entry
   point to be exported by the DLL on disk. `cargo deny check` passes with the new dependency.
   Declarations are `[DllImport]`, csbindgen's output, which is sound here because the assembly
   runs with runtime marshalling disabled and every type crossing is blittable. Handles cross as
   raw `KgsSession*`/`KgsImportPlan*`, so the `SafeHandle` add-ref across a call that the proof got
   from the marshaller is now an explicit `NativeHandle<T>.Borrow()` around every call.
2. **Settle the missing shapes — done**, once, in `capi/mod.rs`'s rules:
   * **Lists out** are one concrete `#[repr(C)] Kgs<Elem>Array { ptr, len, cap }` per element type
     — a `Vec`'s raw parts; the struct is written out (not macro-generated) because csbindgen reads
     source. Each out type has exactly one `kgs_<name>_free`, which frees every buffer and nested
     list inside it recursively, zeroizes every string, resets the record to all-zero, and is a
     no-op on a zeroed record — so C# frees in a `finally` without tracking success.
   * **Lists in** are borrowed `{ptr, len}` (`KgsSliceList`, `KgsFieldDraftList`).
   * **Optionals** are `KgsOpt* { present: u8, value }`, both ways, so `None` and `""` differ; an
     absent value going out is all-zero, which is why its free can run unconditionally.
   * **Fieldless enums** cross as `u32`, never as a Rust enum type — a value C# made up must be
     `Invalid`, not undefined behaviour. The names are `#[repr(u32)]` `Kgs*` enums that csbindgen
     generates into C#, and the public C# enums take their values from them.
   * **Enums with data** are `{ tag, <every variant's payload, flattened> }`, a payload field read
     only for the variants that carry it (`KgsItemFilter`, `KgsApprovalDecision`). None comes out.
   * **Records going both ways** get an owned `Kgs<Name>` out and a borrowed `Kgs<Name>Ref` in.
   * **Every** export except `kgs_abi_version` and the frees returns a `KgsStatus`, infallible
     Rust functions included, so a panic in any of them is a status rather than an abort.
   * **The one blocking call**, `kgs_agent_next_request`, keeps ADR-0014's shape: the host polls
     from one dedicated background thread with a short timeout and checks its own cancellation
     between polls; a parked poll is never interrupted. C# wraps it as `Agent.NextRequestAsync`,
     a `LongRunning` task, which never drops a request it has already dequeued.
3. **Wrap the rest — done.** All **85** UniFFI entry points (36 free functions, 46 `VaultSession`
   methods, 3 `ImportPlanHandle` methods) and every record and enum they carry cross, as **113** C
   exports: the 85, one free per out type (24), `kgs_buffer_free`, the two handle frees, and
   `kgs_abi_version`. Only macOS-only Safari / App Group parts are left out: `extension_start`'s
   `safari_socket_path` and `team_id` (passed as `None`), `extension_setup`'s `bundle_plugins_dir`,
   `team_id` and `SafariSetupView`, and `ExtensionStatusView`'s `safari_running` /
   `safari_endpoint`. The platform-slot calls do cross: Windows Hello wraps the vault key through
   them exactly as Touch ID does. On the C# side, DTOs are records (lists are `ValueList<T>`, so
   records keep value equality), handles are `SafeHandle`s behind `IDisposable` classes, the
   agent and the extension listener are static classes (they are process globals), and errors
   are the existing `KagisecureException` subclasses. Secrets going in are spans held in pinned,
   zeroed UTF-8 copies; byte secrets coming out are a `byte[]` the caller clears; the values that
   are unavoidably a `string` (a revealed field, the recovery code, a generated password, a TOTP
   code, a `FieldDraft.Value`) are listed in `apps/windows/README.md` — the same limit Swift's
   `String` has.
4. **Grow the conformance suite with the surface — C# half in place.** `Kagisecure.Interop.Tests`
   exercises every public member end to end against real vaults, including the agent over its
   named pipe (a request arrives from a client speaking the real frame protocol, is answered
   through the queue, and mints and revokes a lease). `capi/tests.rs` checks the null, UTF-8,
   free, optional, enum-tag and panic rules on representative functions. The shared Swift/C#
   scenario matrix rule 3 asks for is still to be written.

**Re-evaluation trigger.** Rerun this table when `uniffi-bindgen-cs` publishes a tag whose suffix
matches the UniFFI version in `Cargo.lock` (`+v0.32.x`, or later if we have moved on). Doing so is
one `cargo install --tag …` and one `uniffi-bindgen-cs --library target/…/kagisecure_ffi.dll
--crate kagisecure_ffi --out-dir … --no-format`. If it then passes, switching is the contained
change the Neutral consequence describes: `Kagisecure.Interop`'s public types are the app's
contract, and what sits underneath them can change. With the whole surface now wrapped by hand,
the saving a switch would bring is the second edit per FFI addition, not the initial wrapping.

## Amendment (2026-09-26): one callback crosses, for the presence gate

`feat/vault-transactions` (ADR-0038) replaced the ungated reveal/TOTP calls with presence-gated
releases whose gate is an async foreign trait, and removed the ungated calls from the FFI. That
bends rule 1 on the UniFFI side, deliberately, and ADR-0038's spike records why. The C ABI cannot
carry an async foreign trait, so it carries the narrowest thing that keeps the guarantee: **one C
function pointer**, `kgs_session_set_presence_gate`'s `confirm(context, reason) -> u32`, generated
into C# as a `delegate* unmanaged[Cdecl]` (runtime marshalling stays disabled; the C# side hands
over an `[UnmanagedCallersOnly]` static method and looks the gate up by key, so no delegate has to
be kept alive and a stale key answers "cancelled"). It is called only **synchronously, on the
thread that called the release, inside that call** — Rust never starts a thread that calls into
C#, never keeps a callback pending after the call returns, and calls it for nothing but a release —
and it fails closed: no gate or a null one means no release, a second install is refused, and any
answer but the `Confirmed` tag is a cancel. The three release handles are opaque, like
`KgsSession`. ABI version 4, 147 C exports (121 at `main`'s `bdd9a47`): the releases and their
handles, `lock`, `is_unlocked`, `sync` and the vault-conflict calls are added; the ungated
`reveal_field`, `totp_code` and `item_totp_code` are gone. Everything else on this ABI is still
synchronous and app→Rust; `capi/presence.rs` has the full contract. ABI version 5 adds one tag and
nothing else: `KgsApprovalAction::AgentFill = 5`, for [ADR-0036](0036-agent-requested-browser-fill.md)'s
agent-requested fill, which Windows never offers — the facts its sheet shows and its `agent_fill_*`
calls stay on the UniFFI side.
