# ADR-0004: Biometric approval via hardware-wrapped vault keys

- **Status:** Accepted
- **Date:** 2026-09-09
- **Deciders:** project owner

## Context

Every injection — writing a `.env`, spawning a process with secrets in its environment — must be
approved by a human, and that approval must be something an agent cannot produce, replay, or
auto-answer. The candidate mechanisms:

| Option | Why not |
| --- | --- |
| Confirm in the agent's UI (MCP elicitation / SEP-2322 `InputRequiredResult`) | The MCP **client** collects the answer. A compromised or hostile client auto-answers; the prompt is rendered in the surface where injected content already lives. |
| A password prompt in the native app on every injection | Unusable at the frequency agents work at (dozens of times an hour), so users will disable it. Also trains password-entry-on-prompt behavior, which is phishable. |
| A one-time unlock, then unlimited access while unlocked | This is the status quo it exists to replace. A single prompt injection at hour three gets everything. |
| **Per-request biometric, gating a hardware-wrapped key, prompted by the native app** | — |

A biometric prompt is the right primitive precisely because it is *not* data: it cannot be
supplied by a process, forwarded over a socket, or produced by a model. It requires a body.

The design must also decide what the biometric actually *gates*. "Ask Touch ID, and if it says
yes, use the key we already had in memory" is theater — a compromised app could skip the check.
The biometric must be cryptographically load-bearing: the key is unusable without it.

## Decision

**The vault key (VK) has a hardware-wrapped copy in the vault header, unwrappable only through a
platform key that the biometric gates. Every injection request requires either a fresh biometric
or an unexpired lease minted by one.**

Recall the key hierarchy (vault-format §3): VK is 32 random bytes; the header holds wrapped copies
of it — one wrapped under the password-derived KEK, and one (per device) wrapped under a
hardware-held key.

### macOS

- The wrapping key is a Secure Enclave–backed private key
  (`kSecAttrTokenIDSecureEnclave`), created with a `SecAccessControl` combining
  `.privateKeyUsage` and **`.biometryCurrentSet`**.
- `LocalAuthentication` presents the Touch ID sheet; the Secure Enclave performs the operation
  that unwraps VK. Without a successful biometric, the key is not usable — the check is enforced
  by the Enclave, not by our code.
- `.biometryCurrentSet` (not `.biometryAny`) means **enrolling or removing a fingerprint
  invalidates the wrapped key**, forcing a password unlock and re-enrollment. This is intentional:
  an attacker who adds their own finger inherits nothing.
- The key never leaves the Enclave; the vault file on another Mac requires the password.

### Windows

- The wrapping key comes from `KeyCredentialManager` (TPM-backed where a TPM exists), and each
  use is gated by `UserConsentVerifier.RequestVerificationAsync` — Windows Hello face, fingerprint,
  or PIN.
- **Caveat, stated plainly: Windows Hello credentials are scoped to the user and device, not to
  the application.** They do not provide the per-app isolation that a Secure Enclave key with a
  keychain ACL provides on macOS. Another process running as the same user can, in principle,
  obtain Hello consent.
- Mitigation (defense in depth, **not** equivalence): the header's platform-wrapped VK is wrapped
  under a key derived from *both* the `KeyCredential` operation **and** an app-specific secret
  stored via DPAPI (`CryptProtectData`, current-user scope) inside the app's own storage. Hello
  consent alone is therefore insufficient; an attacker also needs to be able to read the app's
  protected storage, which puts them at threat-model T-3-and-beyond.
- On a machine with no TPM, `KeyCredentialManager` availability is checked and the user is told
  explicitly that biometric unlock is unavailable — with a password fallback, never a silent
  downgrade.

### Common rules

1. **The prompt is rendered by the native app**, in its own window, out of band from MCP. The
   model cannot see it, fill it, or distinguish "denied" from "user was away".
2. **The prompt shows unforgeable facts**: the *verified* caller identity (code signature of the
   peer process, not self-reported `clientInfo`), the canonical target directory, the variable
   names, and the requested TTL. Injected content can cause the request; it cannot change what
   the user reads.
3. **A successful biometric mints a lease**, not permanent access: scoped to one environment, one
   canonical directory (exact match, no prefix matching), a variable set, a TTL (default 15 min,
   max 24 h), and a use count (default 10).
4. **Leases are memory-only** and die on expiry, use exhaustion, vault lock, screen lock, sleep,
   app exit, or explicit revoke. Nothing about a lease survives a restart.
5. **Any request broader than an existing lease re-prompts.** No privilege creep.
6. **There is no "always allow" in v1.** The prompt is the product.
7. **The biometric is never the only factor for the vault itself.** The password-wrapped slot
   always exists, and v1 additionally issues a one-time printable recovery code as a third
   wrapped-key slot (see [vault-format.md §3.2](../vault-format.md#32-recovery)), so a broken
   sensor, a new device, a changed fingerprint set, or a forgotten password is a recoverable
   situation rather than data loss.

## Consequences

**Positive**

- The approval is unforgeable by software. This is the property the whole threat model rests on
  (mitigations M-3, M-4, M-5).
- The biometric is cryptographically load-bearing, not a UI gesture: without it the key is not
  unwrappable, enforced by the Enclave/TPM rather than by a branch in our code.
- Rotating a fingerprint set invalidates access automatically on macOS — a security property that
  costs us nothing.
- Frequency is workable: the lease model means an agent doing ten operations in one task prompts
  once, not ten times, while a task that reaches for a different directory or environment prompts
  again.

**Negative — accepted**

- **Windows is weaker than macOS**, and we say so in the docs rather than claiming parity. The
  DPAPI binding raises the bar but does not reach Secure Enclave-grade per-app isolation
  (threat-model W-1).
- **Prompt fatigue is a real failure mode.** A user who approves without reading defeats M-5. We
  mitigate with clear, scannable prompts (directory and variable names prominent, unexpected
  paths flagged) and by *not* prompting when a lease legitimately covers the request. We do not
  mitigate it fully; nobody has.
- **`.biometryCurrentSet` will surprise users** who add a fingerprint and are asked for their
  master password. Needs a good explanatory message, not just an error.
- **Hardware without biometrics** (an old iMac, a TPM-less PC, a Linux box) falls back to a
  password prompt per injection, which is slower and pushes users toward longer TTLs. Documented,
  not solved.
- **A lost device with the vault file** is protected by the password-wrapped slot's Argon2id cost,
  not by the biometric — the hardware slot is device-bound and useless to the attacker.
  So master password strength still matters, which is worth saying out loud in the UI.
- **Screen-lock-triggered lease death** will occasionally interrupt a long agent run. Correct
  behavior; will generate issues.

**Neutral**

- SEP-2322 (`InputRequiredResult`) remains documented as a **fallback for headless/CLI-only
  setups** where no native app exists. If used, it is opt-in per vault and labelled as a weaker
  approval channel in the UI and in the audit log. It is not the primary path and must not become
  one by convenience creep.
