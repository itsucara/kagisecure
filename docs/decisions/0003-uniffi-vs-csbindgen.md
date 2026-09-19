# ADR-0003: C# bindings — evaluate `uniffi-bindgen-cs`, fall back to `csbindgen`

- **Status:** Accepted (with a deferred evaluation gate at M4)
- **Date:** 2026-09-09
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

*(To be filled in at M4. Leave blank until the evaluation actually happens; an empty table here is
a signal, not an oversight.)*

| Criterion | Result | Evidence | Date |
| --- | --- | --- | --- |
| C1 | | | |
| C2 | | | |
| C3 | | | |
| C4 | | | |
| C5 | | | |
| C6 | | | |

**Outcome:** _pending_
