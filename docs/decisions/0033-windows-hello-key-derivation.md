# ADR-0033: Windows Hello unlock wraps the vault key under HKDF(Hello signature ‖ DPAPI secret) — and enrolling lowers the vault's protection on that PC to "can sign in to this Windows account"

- **Status:** Proposed — for review; implemented in `apps/windows/Kagisecure.App`, not yet exercised
  with a real Windows Hello prompt (see Consequences). Revised after an independent security
  review: §2 and §5 no longer overstate what the construction buys.
- **Date:** 2026-09-25
- **Deciders:** Windows port, Tier 3
- **Refines:** [ADR-0004](0004-biometric-key-wrapping.md) (Windows section),
  [ADR-0008](0008-ffi-secret-crossings.md) crossings 1, 3 and 4,
  [windows-port.md](../windows-port.md) §3.2, [threat-model.md](../threat-model.md) W-1, T-3

## Context

[ADR-0004](0004-biometric-key-wrapping.md) says the Windows platform slot's vault key is wrapped
"under a key derived from *both* the `KeyCredential` operation **and** an app-specific secret stored
via DPAPI", and that each use is gated by Windows Hello. It does not say which `KeyCredential`
operation, how the two are combined, where the secret lives, or what the slot's bytes look like.

One fact decides the first question. A `Windows.Security.Credentials.KeyCredential` offers exactly
two operations: `RetrievePublicKey` and `RequestSignAsync`. There is no decrypt and no unwrap — the
Secure Enclave's `SecKeyCreateDecryptedData` has no Windows Hello counterpart reachable from an
unpackaged desktop app. So the only secret a Hello key can contribute is a **signature**.

## Decision

### 1. The construction (blob version 2)

```text
slotId    = "windows-hello-v2-" || hex(16 random bytes)                 (the platform slot's id)
challenge = SHA-256("kagisecure/windows-hello/v2/challenge" || 0x00 || slotId)
signature = KeyCredential("Kagisecure vault unlock " || slotId).RequestSignAsync(challenge)
appSecret = 32 random bytes, CryptProtectData(CurrentUser,
              entropy = "kagisecure/windows-hello/v2/app-secret" || 0x00 || slotId)
            stored at %LOCALAPPDATA%\Kagisecure\windows-hello\<slotId>.dpapi
KEK       = HKDF-SHA256(ikm  = signature || appSecret,
                        salt = "kagisecure/windows-hello/v2",
                        info = "kagisecure/windows-hello/v2/kek" || 0x00 || slotId,  L = 32)
blob      = "KGH2" || nonce(12) || AES-256-GCM(KEK, nonce, VK, aad) || tag(16)
aad       = "KGH2" || len(vaultId) || vaultId || slotId            (vaultId: the header's file id)
```

`blob` (64 bytes) is the platform slot's opaque wrapped key, installed with
`VaultSession.InstallPlatformSlot(slotId, "Windows Hello on <machine>", blob)`. Binding the vault
file's id into the associated data means a blob copied into another vault file does not unwrap
there. Version 1 (no vault id, `KGH1`, `windows-hello-v1-`) was never released; a v1 slot is shown
as "a Windows Hello unlock this PC cannot use" and re-enrolment replaces it.

Unlock reads the slot id, the blob and the vault-file id from **one** read of the header
(`platform_slot_info`, added to the FFI for this), asks Hello to sign the challenge (one prompt),
loads the DPAPI secret, derives the KEK, decrypts, and hands the 32 bytes to
`VaultSession.UnlockWithVaultKey` (ADR-0008 crossing 4), whose Rust side now holds the key it is
handed in a `Zeroizing` buffer. Every managed buffer holding the vault key, the signature, the app
secret or the KEK is allocated on the pinned object heap (`GC.AllocateUninitializedArray(pinned:
true)`) so the GC cannot leave an unzeroed copy behind across the flow's awaits, and is cleared in a
`finally`; the WinRT `IBuffer` the signature arrives in is overwritten in place after it is copied.
Code: `Services/WindowsHelloCrypto.cs`, `WindowsHelloPlatform.cs`, `WindowsHelloService.cs`.

### 2. Why a signature can be a key — and what that makes it

A Windows Hello key is an RSA-2048 key, and `RequestSignAsync` signs with RSASSA-PKCS1-v1_5 over
SHA-256, which has no randomness: the same key over the same challenge yields the same bytes every
time. Enrolment checks this rather than assuming it — the fresh signature must verify under the
credential's public key with `RSASignaturePadding.Pkcs1`, or enrolment is refused and the
credential deleted.

Stated plainly, **that makes the signature a static, long-term secret**. Whoever obtains it once
holds half of the KEK until the slot is re-enrolled; with the DPAPI secret and the blob (the other
half and the ciphertext, both readable by any process running as the user — §5) they hold the vault
key, offline. And the challenge is not secret: the credential name and the challenge are both
functions of the slot id, which is in the plaintext vault header.

**Challenge rotation was considered and not adopted.** Re-wrapping under a fresh random challenge
after every successful Hello unlock (an extra prompt each time) would make an *old* signature
useless. It does not help against the attacker who can get a signature: that attacker runs as the
user, can read the current blob and DPAPI file at the same moment, and unwraps the vault key
immediately — and the vault key itself never rotates, so one success is a permanent compromise
whatever happens to the slot afterwards. The same attacker can also read the unlocked app's memory
(T-3 on Windows, below). Rotation would cost a second Hello prompt per unlock — which trains exactly
the habit the attack needs, approving prompts — for no protection against the attacker it is aimed
at. The honest mitigations are the ones in §6: never prompt unasked, and say what enrolling costs.

### 3. One Hello prompt per unlock, not two

ADR-0004 says each use is gated by `UserConsentVerifier.RequestVerificationAsync`. For unlock, the
gate is the Hello prompt `RequestSignAsync` raises itself: the signature *is* the consent, and it is
cryptographically load-bearing — no gesture, no signature, no KEK. A `UserConsentVerifier` prompt in
front would be a second prompt for a yes/no that gates nothing. `UserConsentVerifier` is used where
ADR-0004's reasoning applies to it — **approvals**, where no key material is involved. Enrolment
costs two prompts (`RequestCreateAsync`, then the first `RequestSignAsync`).

### 4. Approval consent, and the password fallback macOS does not have

The approval sheet asks `UserConsentVerifier` (parented to the sheet's window through
`IUserConsentVerifierInterop`). `Canceled` and `RetriesExhausted` grant nothing and leave the sheet
up (ui-spec.md §10.3). An availability value this build does not recognise is treated as a failure,
not as "unavailable".

When Hello reports itself **unavailable** — `DeviceNotPresent`, `NotConfiguredForUser`,
`DisabledByPolicy` — the sheet offers the master password instead: ADR-0004's "falls back to a
password prompt per injection". **This is a Windows-only addition.** macOS has no in-app password
fallback; it relies on `LAPolicy.deviceOwnerAuthentication`, whose system sheet falls back to the
*login* password inside the OS's own UI. On Windows the app renders the password box itself, which
has two consequences worth writing down:

- The password is checked **against the unlocked session in memory**
  (`VaultSession::verify_master_password`: the KDF runs with the in-memory header's password-slot
  parameters, the slot is unwrapped, the resulting vault key is compared in constant time with the
  session's own) — never against the file on disk, which a same-user process could swap for one
  with a password it knows, or with Argon2id parameters large enough to hang the app.
- **The box is an ordinary window a same-user process can type into.** `SendInput`/UI Automation
  from a process at the same integrity level can fill the password box and press the button,
  exactly as the end-to-end check in apps/windows/README.md does. Such a process must already know
  the master password — in which case it can open the vault file directly and needs no approval —
  so the fallback adds no capability; but it is not "a body at the keyboard" the way a biometric
  is, and it is offered only when Hello is genuinely unavailable, never as a way around an available
  Hello.

### 5. What each half is worth — the honest version

| Half | Where | Who can reach it |
| --- | --- | --- |
| Hello signature | TPM-held key (enrolment requires a TPM 2.0 **and** a successful `KeyCredential.GetAttestationAsync`) | Any process running as the user, **with one approved Hello prompt** |
| DPAPI secret | `%LOCALAPPDATA%\Kagisecure\windows-hello\`, DPAPI CurrentUser | Any process running as the user, **silently** |
| Blob | The vault file's header | Anyone with the vault file |

What enrolling costs, said plainly — and said in the app, on the Security page and the lock screen:

- **The vault's protection on that PC drops to "anyone who can sign in to this Windows account."**
  Windows Hello always accepts the account's PIN; a signature needs a Hello gesture, and the PIN is
  a Hello gesture. There is no Windows counterpart of `.biometryCurrentSet`: enrolling a new
  fingerprint or face does **not** invalidate the key, so someone who adds their own finger inherits
  the unlock. On a Mac it would not.
- **Hello keys are user/device-scoped, not per-app (W-1).** A same-user process can open this
  app's credential by name (derivable from the header) and raise a Hello prompt for it. If the user
  approves that prompt once, the process has the signature (§2), reads the DPAPI secret silently,
  and opens the vault offline, until the slot is re-enrolled — and the vault key itself for good.
- **The DPAPI half barely helps against that attacker.** DPAPI's current-user scope is not per-app
  either. What it does buy: a copied vault file, or a stolen disk without the user's Windows logon,
  gets neither the TPM key nor the DPAPI master key; and a process that can trigger Hello consent
  but cannot read files (a narrower sandbox) is not enough. That is defence in depth against
  *other* attackers, not against same-user malware.
- **Same-user malware does not need any of this anyway** while the vault is unlocked: on Windows a
  process at the same integrity level can open another process of the same user with
  `PROCESS_VM_READ` and read its memory, without `SeDebugPrivilege` (threat-model T-3). Zeroization,
  DPAPI and Hello do not stop that attacker; they shorten how long secrets sit in memory and keep
  them off disk.

So the Windows Hello unlock is a convenience with a stated cost, **weaker than Touch ID on a Mac**
in every row above. ADR-0004's "Windows is weaker than macOS" stands, with the reasons now spelled
out rather than softened.

### 6. Lifecycle, and the prompts the app will and will not show

- **No automatic prompt.** Unlike the Mac, the lock screen never raises Hello by itself; the only
  Hello prompt the app shows for unlocking is the one the user just clicked for. An automatic
  prompt would both train users to approve prompts they did not ask for and give a same-user process
  a moment to raise its own prompt that looks like the expected one.
- **The Hello dialog is only brought forward if it is the system's.** An unpackaged app has no
  window-parented `KeyCredentialManager` API, so the app brings the "Credential Dialog Xaml Host"
  window forward — but only a window of that class whose owning process image (read with
  `GetWindowThreadProcessId` + `QueryFullProcessImageNameW`) is exactly
  `%SystemRoot%\System32\CredentialUIBroker.exe`. A same-user process can register a window with
  that class name; it will not be foregrounded. No match, no foregrounding (cosmetic only).
- **One credential per enrolment**, named for its slot, so turning Hello off (`RemovePlatformSlot`,
  then `KeyCredentialManager.DeleteAsync`, then delete the DPAPI file) leaves nothing behind, and
  re-enrolling replaces the slot and then forgets the old key and secret. **Re-enrolling is also the
  only remedy after a suspected compromise of the slot** — and it does not change the vault key.
- **One platform slot per vault** (vault-format v1). The Security page names what is there — this
  PC's Windows Hello, a Windows Hello slot from another PC or profile (no local DPAPI secret), a
  Mac's Touch ID, or something unrecognised — and asks before replacing anything that is not this
  PC's.
- **A dead slot falls back to the password**: credential not found, DPAPI secret missing or not
  unprotecting, a signature that no longer unwraps, or a key the vault rejects. The lock screen
  stops offering Hello and says why; the Security page offers to re-enrol. The master password and
  the recovery code always work (ADR-0004 rule 7). Three non-cancel failures hide the button for
  that lock screen, as three Touch ID failures do (ui-spec.md §6.1).
- **A lock during the unlock wins.** Argon2id or the Hello prompt can take seconds; if the vault is
  told to lock meanwhile (screen lock, sleep, `kagisecure lock`), the new session is disposed without
  being served and the lock screen says so.

## Assumptions, stated plainly — review these

1. Hello keys sign with RSASSA-PKCS1-v1_5/SHA-256 (checked at enrolment, §2).
2. Every `RequestSignAsync` requires a fresh gesture, and the PIN always counts as one (§5). The
   first is Windows' documented behaviour; neither has been observed here, because this machine has
   no Hello device and Hello cannot be driven non-interactively.
3. `GetAttestationAsync` returning `Success` means the key is TPM 2.0-bound. It returns
   `NotSupported` on TPM 1.2, on software keys and in many virtual machines; enrolment is then
   **refused** with that reason rather than accepted unattested — so Hello unlock is unavailable on
   such hardware, by design, and the password keeps working.
4. The Hello UI for `KeyCredentialManager` is hosted by `%SystemRoot%\System32\CredentialUIBroker.exe`.
   Unverified here; if it is hosted elsewhere, the dialog is simply not brought forward.
5. `KeyCredentialManager` credentials are addressed by name within the user's scope for an
   unpackaged app (W-1); the design assumes this rather than relying on the opposite.

## Consequences

**Positive**

- A Windows Hello slot is fully specified: a later build, or another implementation, can open it
  from the vault header, the DPAPI file and the Hello key alone, and a blob cannot be moved between
  vault files.
- The approval fallback's password check can no longer be pointed at a different file.

**Negative — accepted**

- Enrolling lowers the vault's protection on that PC to "can sign in to this Windows account"
  (§5), is not invalidated by new fingerprints, and one approved rogue prompt compromises the vault
  key for good. The app says so where the switch is.
- Hello unlock is unavailable where attestation is (TPM 1.2, most VMs).
- **Not exercised end to end.** Every decision is unit-tested against fakes (`FakeHelloKeys` signs
  with a real RSA key and PKCS#1 v1.5; the DPAPI store is tested against real DPAPI), and the Rust
  password check against real vault files. No real Windows Hello prompt was answered while writing
  it; the first interactive enrolment on a machine with Hello is the test this ADR is waiting for.
