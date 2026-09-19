# ADR-0018: The browser extension is a deliberate sixth place a value crosses

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6 implementation
- **Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0008](0008-ffi-secret-crossings.md),
  [threat-model-browser-extension.md](../threat-model-browser-extension.md)

## Context

This project has one property that makes most of its threat model easy to state: **no protocol the
app speaks can carry a secret value.** [ADR-0002](0002-no-secret-values-over-mcp.md) made that
structural for the MCP channel — `kagisecure-ipc` compiles without `secret-material` and therefore
cannot *name* `Secret`, so a message carrying one is a compile error rather than a review finding.
[ADR-0008](0008-ffi-secret-crossings.md) could not do the same for the FFI, because the app is the
thing that shows a user their own password, so it did the next best thing: an enumerated,
justified list of five crossings, with the rule that adding a sixth requires editing that document
in the same commit.

M6 adds a browser extension that fills password fields. There is no version of that feature in
which the value stays in the app.

## Decision

**Autofill is a new crossing, on a new channel, and it is enumerated here rather than folded into
ADR-0008's table.**

The value's route, and what each hop may hold:

| Hop | May hold a value | Why |
| --- | --- | --- |
| `kagisecure-core` → `kagisecure-agent` | yes | the agent library reads the vault; this is not new |
| `kagisecure-agent::extension` → the socket | **yes, new** | the fill reply |
| `kagisecure-extension-ipc` | **yes, in one type** | `FillValue`, in two response fields |
| `kagisecure-nmhost` | in transit only | it forwards frames; it cannot name `Secret` |
| extension service worker | for one `postMessage` | forwarded to one `sendResponse`, never stored |
| content script | for one function call | written into the field, then out of scope |
| the page's DOM | until the form is gone | residual risk R-1 |

### Why this is not a sixth row in ADR-0008's table

ADR-0008 is about the **UniFFI boundary**, which is one process and one trust domain. This crossing
leaves the process and lands in a browser. Filing it there would make that table mean two different
things, and the reviewer's question — *"which of these is it?"* — would stop having a crisp answer.
So it is its own decision, with its own document, and ADR-0008's list stays five.

### What makes it reviewable

Three properties, each asserted rather than argued:

1. **Exactly two response fields are typed `FillValue`.** `Response::Filled.password` and
   `Response::TotpCode.code`. `protocol.rs`'s `only_two_response_fields_are_fill_values` builds
   every response shape, serializes each, and asserts a canary survives in those two and in none
   of the others.
2. **`FillValue` is the narrow, loudly-named hole.** No `Display`, so it cannot be interpolated
   into a message by accident. A `Debug` that prints `FillValue(<redacted>)`, so `{:?}` on a whole
   `Response` is safe. `ZeroizeOnDrop`. One constructor, `FillValue::new`, called in exactly two
   places, both immediately after an approved fill — the same greppability discipline
   `Secret::expose` and `reveal_field` follow.
3. **The channel that carries it cannot open a vault.** `kagisecure-extension-ipc` depends on
   `kagisecure-core` with `proto` only. That is what keeps `kagisecure-nmhost` — the process a
   browser launches, with no signature check of any kind — unable to name `Secret`, unable to open
   a vault file, and unable to hold a key.

### What is *not* granted

- **No bulk read.** There is no message that returns more than one item's value, and no message
  that returns a value without an item id the extension got from a prior `match`.
- **No values at rest.** The extension makes no `chrome.storage` call at all — not for a value,
  not for a URL, not for a match result. The roadmap's criterion is "no secret value is held by the
  extension's own storage at rest"; having no storage is a shorter thing to check than having
  careful storage.
- **No URL disclosure.** `match` returns titles and usernames. Returning the item's saved websites
  would teach a compromised extension the user's site list one page at a time.
- **No value without a human.** First fill per (origin, item) per unlock session: sheet plus
  biometric. A lease excuses the biometric and nothing else.

### `agent_visible` is not consulted, on purpose

`Item::agent_visible` answers *"may a language model learn this item exists"*. The extension is the
user's own browser, filling their own login, at their own click, behind a biometric. Gating
autofill on the agent flag would mean granting an LLM visibility over an item in order to log into
a website with it. The consequence — an agent-invisible item is extension-visible as a title and a
username, at a matching origin — is recorded in the threat-model addendum §5 rather than left to be
discovered.

## Consequences

**Positive**

- The one place the "no values on the wire" property is broken is a single named type in a single
  crate, with a test that says so.
- The native host, which is the component an attacker can most easily replace, gains nothing by
  being replaced: it is a pipe with no vault.
- The rule for a *seventh* crossing is the same as ADR-0008's: edit this document in the same
  commit.

**Negative — accepted**

- **The value is in a browser.** Once filled, page JavaScript can read it. That is what filling a
  form is, and every password manager has it (threat-model addendum R-1).
- **`FillValue` is not `Secret`.** It cannot be: the crate that defines it must stay unable to open
  a vault, and `Secret` lives behind `secret-material`. So there are now two secret-ish wrapper
  types in the workspace, with different guarantees, and a reader has to know which is which. The
  documentation on both says so.
- **Zeroization is best-effort past the socket.** `FillValue` zeroizes on drop; the JSON bytes it
  was serialized into are an ordinary buffer, and everything after the socket is JavaScript, where
  strings are immutable and not zeroizable — the same limitation ADR-0008 already records for
  Swift, now applying one layer further out.
