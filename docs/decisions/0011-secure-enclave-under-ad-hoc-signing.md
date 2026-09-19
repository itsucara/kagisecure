# ADR-0011: The Secure Enclave needs a provisioning profile, so M3 ships the fallback

- **Status:** Accepted
- **Date:** 2026-09-09
- **Updated:** 2026-09-10 (M6b — the Developer ID row of the table below, and §"Measured again")
- **Deciders:** M3 implementation
- **Refines:** [ADR-0004](0004-biometric-key-wrapping.md)
- **Refined by:** [ADR-0025](0025-developer-id-for-local-builds.md)

## Context

[ADR-0004](0004-biometric-key-wrapping.md) specifies the macOS half of biometric approval: a
Secure Enclave P-256 key created with `SecAccessControlCreateWithFlags(.privateKeyUsage |
.biometryCurrentSet)`, the vault key wrapped with its public half and unwrapped with its private
half, so the Touch ID check is enforced by the Enclave rather than by a branch in our code. Nothing
in that ADR says anything about code signing, because at design time nothing appeared to depend on
it — the Enclave is hardware and the key is per-app.

Implementing it produced a result worth recording, measured on **macOS 26.1, Xcode 26.2 (17C52),
Swift 6.2.3**, on an Apple-silicon Mac with Touch ID enrolled:

| Signing | `SecKeyCreateRandomKey(kSecAttrIsPermanent: true)` | Explicit `SecItemAdd` of the key |
| --- | --- | --- |
| Ad-hoc (`CODE_SIGN_IDENTITY=-`) | `errSecMissingEntitlement` (-34018) | `errSecMissingEntitlement` (-34018) |
| Apple Development, team set, no profile | `errSecMissingEntitlement` (-34018) | `errSecMissingEntitlement` (-34018) |
| Apple Development + `keychain-access-groups` | *not reached* — no provisioning profile could be issued | *not reached* |
| **Developer ID + `keychain-access-groups`, no profile** (added 2026-09-10) | *not reached* — **the process is killed at exec** | *not reached* |

Two things fall out of that table.

**Filing a Secure Enclave key in the keychain requires the `keychain-access-groups` entitlement,
on macOS, even for a single-process app.** The design note that it "is not needed for
single-process use" is true of iOS-style usage and of *reading back* a key, but not of putting one
there in the first place on macOS 26. Neither the data-protection keychain
(`kSecUseDataProtectionKeychain: true`) nor the file-based keychain accepts the add without it.

**`keychain-access-groups` is a restricted entitlement.** Its mere presence in the entitlements
file makes Xcode require a provisioning profile — even with `CODE_SIGN_STYLE=Manual` and
`CODE_SIGN_IDENTITY=-`. So a project that always carries it cannot be built from a clean checkout
without a developer account, and CI (before its removal on 2026-09-19) could not have built the
app at all.

On the implementation machine the profile could not be obtained either: automatic signing
reported *"Device … isn't registered in your developer account"* and *"No profiles for
'com.kagisecure.app' were found"*. Registering a device and an App ID is an account action on the
owner's Apple Developer account, outside this milestone's scope — the same class of blocker M2 hit
with `claude -p` on an unauthenticated install.

## Measured again under Developer ID signing (2026-09-10, M6b)

M6b obtained a **Developer ID Application** identity and asked the obvious question: does signing
with a real distribution identity make the entitlement acceptable without a provisioning profile?

**No, and the failure is one step earlier and much louder than the table above suggested.**

Xcode still refuses to build a target carrying `keychain-access-groups` without a profile — the
same refusal as before, at build time. Forcing the entitlement on afterwards with
`codesign --force --entitlements`, which bypasses Xcode entirely, produces a binary that does not
run at all:

```text
$ ./Kagisecure.app/Contents/MacOS/Kagisecure ; echo $?
137                                    # SIGKILL, before main

taskgated-helper: Disallowing … because no eligible provisioning profiles found
amfid: … not valid: Error Domain=AppleMobileFileIntegrityError Code=-413 "No matching profile found"
kernel: (AppleMobileFileIntegrity) AMFI: … Code has restricted entitlements, but the validation
        of its code signature failed. Unsatisfied Entitlements:
```

Reproduced on a bare Mach-O and on the real `Kagisecure.app`, on macOS 26.1.

So `keychain-access-groups` is a **restricted entitlement that AMFI validates against a
provisioning profile at every exec**. A Developer ID signature does not satisfy it, and no amount of
signing does; what satisfies it is a profile, which needs a registered device and an App ID on the
owner's account. That account action remains the only unblocker, and it remains outside every
milestone so far.

Two useful corollaries, both recorded in [ADR-0025](0025-developer-id-for-local-builds.md):

- **`com.apple.security.application-groups` is *not* restricted in this way.** It builds and runs
  under Developer ID with no profile, which is why the Safari Web Extension
  ([ADR-0024](0024-safari-app-group-socket.md)) could ship in M6b while this could not. ADR-0023
  had assumed the two were blocked by the same thing; they are not.
- **The Touch ID prompt has still never been seen**, and this ADR's "not verified on this machine"
  list below is unchanged.

## Decision

**Ship the Secure Enclave implementation, and ship the password fallback as the path that is
actually verified. Split the entitlements so that the default build needs no account.**

1. `Kagisecure/Kagisecure.entitlements` (generated from `project.yml`) carries **only**
   `com.apple.security.app-sandbox: false`. Every checkout builds and tests with ad-hoc
   signing and no account (as CI did too, until it was removed on 2026-09-19).
2. `Signing/Provisioned.entitlements` is committed, hand-written, and adds
   `keychain-access-groups: [$(AppIdentifierPrefix)com.kagisecure.app]`. It is selected by
   passing `CODE_SIGN_ENTITLEMENTS=Signing/Provisioned.entitlements` together with a team, an
   identity and `-allowProvisioningUpdates`.
3. **The app degrades loudly, not silently.** `errSecMissingEntitlement` is mapped to its own
   error case, `PlatformKeyError.notEntitled`, whose message is *"This build of Kagisecure is not
   signed with an identity that can own keychain items, so Touch ID unlock is unavailable. Unlock
   with your master password."* Turning the Settings switch on in an ad-hoc build shows that
   sentence and leaves the vault exactly as it was — no half-written platform slot.
4. **The test skips rather than fails.** `PlatformKeyServiceTests` records a known issue naming
   the reason (no Enclave, no biometric, or not entitled) so the run stays green on a machine that
   cannot exercise the path, and the reason is in the log rather than invisible.

## What is and is not verified

Stated plainly, because the difference matters for anyone reading the M3 acceptance checklist:

- **Verified on this machine:** the vault-side half end to end — the vault key is handed out,
  a wrapped blob is installed as a `platform` slot, the file round-trips, and
  `Vault::open_with_vault_key` unlocks from the unwrapped key. Slot replacement, slot removal,
  survival across a master-password change, and a wrong key being refused indistinguishably from a
  wrong password are all covered by tests in `crates/kagisecure-core/tests/vault.rs`.
- **Verified on this machine:** the fallback. An ad-hoc build offers Touch ID in Settings, fails
  with the message above, and unlocks with the master password.
- **Not verified on this machine:** `SecKeyCreateRandomKey` actually creating an Enclave key,
  `SecKeyCreateEncryptedData` wrapping with it, and `SecKeyCreateDecryptedData` raising a real
  Touch ID sheet. These need a provisioning profile this machine could not be issued.
- **Unverified detail, recorded as implemented but untested:** the `LAContext` plumbing. The
  reason string is attached to the *key query* via `kSecUseAuthenticationContext`, not to the
  decrypt call, because `SecKeyCreateDecryptedData` has no parameter for one. That is the shape
  the API forces; whether the resulting prompt reads as intended has not been seen.

M3's acceptance criterion "first run creates a vault, enrols Touch ID, and the app relaunches into
a Touch ID unlock" is therefore **not met**, and the roadmap says so rather than claiming it.

## Consequences

**Positive**

- A clean checkout builds and tests the app with no Apple Developer account at all (CI did too,
  until it was removed on 2026-09-19), which is
  the difference between an OSS project people can contribute to and one they cannot.
- The failure mode is a sentence the user can act on, not a switch that silently does nothing.
- The vault format is unaffected: a platform slot written by a provisioned build opens on any
  build, and its absence costs nothing.

**Negative — accepted**

- **The headline feature of ADR-0004 is unproven on hardware.** The code is written to the API
  Apple documents and the vault-side contract is fully tested, but "it compiles and the surrounding
  machinery works" is not "a fingerprint unlocked a vault". Closing this needs a registered device
  and an App ID, and it is the first thing to do when M7's signing work starts — earlier, if the
  owner wants the biometric path proven before then.
- **Two entitlements files** is one more thing to keep in step. Mitigated by keeping the
  provisioned one a two-key superset, and by a comment in it explaining why it exists.
