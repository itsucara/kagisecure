# ADR-0016: A TOTP field stores its whole `otpauth://` URI as one `Secret`

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M5 implementation
- **Refines:** [vault-format.md](../vault-format.md) §5, §5.3,
  [ADR-0002](0002-no-secret-values-over-mcp.md)

## Context

[vault-format.md](../vault-format.md) §5 sketches a `FieldValue` with a dedicated variant:

```rust
enum FieldValue {
    Public(String),
    Secret(Secret),
    Totp(Secret),          // seed is Secret; generated codes are also Secret
    Address(AddressValue),
    File(AttachmentRef),
}
```

§5.3 then says something slightly different: "TOTP seeds are stored as `otpauth://` URIs in a
`Totp` field, seed material held as `Secret`." Both are in the document. Implementing M5 forced a
choice, and a third option presented itself: store the seed as a `Secret` **and** the parameters
(algorithm, digit count, period, issuer, account) beside it as public metadata, so the UI could
render "GitHub · ada@example.com" without touching secret material.

## Decision

**A one-time-password field is `FieldKind::Totp` carrying `FieldValue::Secret`, whose bytes are
the entire `otpauth://` URI. There is no new `FieldValue` variant, and no public sibling holding
the parameters.** `Field::totp_generator()` parses the URI on demand and hands back a
`totp::Totp`; `TotpParams` — algorithm, digits, period, issuer, account — is a *derived* value, not
a stored one.

### Why not the separate variant

Three reasons, in order of weight.

1. **The URI is the credential, and its parameters are part of it.** `secret=` is obviously
   sensitive. `issuer=GitHub` is less obviously so, and that is the trap: an attacker who learns
   that a vault contains a GitHub second factor learns something, and moving that string into the
   plaintext-adjacent half of a record to save a parse is a real disclosure for no real gain. The
   encrypted body protects both equally today; splitting them creates a category of "TOTP metadata
   we treat as public" that would then have to be defended at every boundary.

2. **It is what a service hands the user, and what round-trips.** Every provider's "can't scan the
   code?" link is a URI. Storing exactly those bytes means import is lossless, export is trivial,
   and a parameter this build does not understand — a future `algorithm=`, a vendor extension —
   survives a save/reopen instead of being dropped by a decomposing parser. The
   `otpauth_round_trips` test asserts the format is a fixed point.

3. **Adding a `FieldValue` variant is a body-schema change; this is not.** Every existing vault
   reads back unchanged, `describe_item`'s wire shape does not move, and the five places in the
   workspace that match on `FieldValue` exhaustively did not have to grow an arm each. The M5
   scope did not include a format migration and did not need one.

### What the UI gets instead

The parameters cross the FFI as a *computed* `TotpParamsView`, alongside the code, in
`TotpCodeView` — one call, one field, one instant (see
[ADR-0008](0008-ffi-secret-crossings.md) crossing 5). The detail pane's caption line and the ring's
period both come from there. The cost is one URI parse per render, which is a few hundred
nanoseconds against an HMAC that has to happen anyway.

### What MCP sees

Exactly what it saw before: `FieldSummary` is unchanged, so an agent-visible item with a TOTP
field discloses `label: "one-time password"`, `kind: Totp`, `concealed: true`, `has_value: true`
and nothing else. No issuer, no period, no digits, and — structurally — no code: `kagisecure_core`
compiles the `totp` module only under the `secret-material` feature, which `kagisecure-mcp` and
`kagisecure-ipc` do not enable, so neither crate can name `Totp` or call `code_at`. The canary in
`crates/kagisecure-cli/tests/mcp.rs` asserts it end to end.

## Consequences

**Positive**

- vault-format.md §5.3's sentence is now the whole truth rather than one of two descriptions.
- Nothing about a user's second factor sits outside `Secret`.
- Unknown `otpauth://` parameters survive a round trip.

**Negative — accepted**

- **A TOTP field cannot be searched or sorted by issuer.** Item titles can, which is where users
  look. If a "show me every 2FA account" view is ever wanted, it will need either a decrypt-and-
  scan pass or a stored index, and the second one would revisit this decision.
- **`reveal_field` on a TOTP field returns the URI, not a code.** That is correct — edit mode needs
  the URI, and `totp_code` is the call that returns a code — but it is a surprise if you expect
  "reveal shows what the detail pane shows". The FFI documents it; the app never calls it for a
  TOTP field except when opening the setup sheet.
- **The parse happens on every render.** Once a second, per visible field. Measured against the
  HMAC it is noise; if it ever were not, the fix is a cache in `VaultSession`, not a schema change.

**Neutral**

- vault-format.md §5's `enum FieldValue` sketch still lists `Totp(Secret)`, `Address` and `File` as
  unimplemented shapes. §5.3 and this ADR are the normative account of the first one.
