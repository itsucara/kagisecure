# ADR-0006: Wrapped-key slots carry their own KDF descriptor

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** M1 implementation
- **Amends:** [vault-format.md](../vault-format.md) §2.1, §3, §3.2

## Context

vault-format §2.1 puts **one** `kdf` map in the header, and says of its salt:

> `salt` | bytes(16) | random, per vault, **regenerated on password change**

§3.2 then says the recovery code is "stretched with Argon2id using the same parameters as the
password path" and stored as a third `wrapped_keys` entry, and that it must unlock the vault
"independent of the master password".

Those two sentences cannot both hold. If the recovery slot derives its KEK from the single header
salt, then changing the master password — which rerolls that salt — silently invalidates the
recovery slot. The user would discover this at the worst possible moment: after forgetting the
new password, holding a recovery code that no longer works, with no way back.

The wrapped-key entry schema in §3 has no place to put a per-slot salt, so this is not something
the implementation could work around within the documented format.

## Decision

The wrapped-key entry gains one optional key:

```
{
  "kind": "password" | "platform" | "recovery",
  "id": text, "label": text, "aead": text,
  "nonce": bytes(24), "ct": bytes, "added_at": u64,
  "kdf": { alg, salt, m_kib, t, p, out_len }   // OPTIONAL
}
```

Rules:

- When a slot carries `kdf`, that descriptor stretches the secret for **that slot only**.
- When it does not, the header's `kdf` applies, exactly as the document specifies. A file written
  strictly to vault-format §2.1 still opens.
- v1 writes: password slot **without** `kdf` (it uses the header's, and a password change rerolls
  the header salt as documented); recovery slot **with** `kdf` — same algorithm and same cost as
  the password path, its own salt.
- The `"platform"` kind stays reserved and unimplemented (M3/M4). When it lands it will carry no
  `kdf`, since a hardware-held key is not stretched from a password.

This is additive under vault-format §9's own compatibility rule ("additive keys do not bump
`header.v`; readers ignore unknown keys"), so `header.v` stays at 1. An older reader that ignored
the key would derive the wrong KEK for the recovery slot and get a clean AEAD failure — a refusal,
not a silent misread.

Both `header.kdf` and every slot's `kdf` are validated before use, and their cost parameters are
bounded (`m_kib` ≤ 1 GiB, `t` ≤ 64, `p` ≤ 16). The header is authenticated only *after* the KDF
has run, so an unbounded `m_kib` in a corrupt or hostile header would be an out-of-memory abort
before the AEAD ever got the chance to reject it.

## Consequences

- Changing the master password no longer touches the recovery slot. Tested:
  `a_password_change_does_not_invalidate_the_recovery_code`.
- Raising Argon2 cost on the password slot (`Vault::upgrade_kdf`) likewise leaves recovery alone.
- vault-format.md §3 should be amended to include the optional `kdf` key in the entry schema, and
  §2.1's salt row reworded to "regenerated on password change; slots with their own `kdf` are
  unaffected".
- A future "re-stretch the recovery code at a higher cost" operation is now expressible without a
  format change.
