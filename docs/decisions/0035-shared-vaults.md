# ADR-0035: Shared vaults are separate files of signed records, exchanged by hand, with one key per computer

- **Status:** Accepted (2026-09-26). Not implemented; see "Implementation plan".
- **Date:** 2026-09-25 (proposed); accepted 2026-09-26
- **Deciders:** the owner
- **Refines:** [vault-format.md](../vault-format.md) §2.2, §3, §9;
  [threat-model.md](../threat-model.md); [ADR-0004](0004-biometric-key-wrapping.md);
  [roadmap.md](../roadmap.md) "Post-v1, unscheduled"

> **Nothing in this ADR is implemented.** It is an accepted design. Every mechanism below is
> described in the present tense because that is how the other ADRs read, not because code exists.
> Threat-model entries it adds are marked as accepted but not yet built.

## Context

kagisecure was scoped as a single-user product. The roadmap's platform decision says it "is
single-user, no teams/sharing", and its post-v1 list records the gap precisely:

> Team/shared vaults, which would need a key-sharing design the current format anticipates
> (per-item subkeys) but does not implement.

Two needs now argue for filling it, and they turn out to be the same problem:

1. **A small group sharing a set of secrets.** A household, a handful of colleagues, the
   maintainers of one project: a few people who all need the same deploy keys, the same router
   password, the same staging database. Today each of them keeps a private copy and they drift the
   first time anyone rotates anything.
2. **One person moving to a new computer**, or using two. Copying the vault file already works — it
   is a single portable file ([vault-format.md](../vault-format.md) §1) — but it gives the new
   machine exactly the same keys as the old one, so the old one cannot later be cut off without
   changing everything, and two machines editing two copies of one file lose edits.

The second need is the first with a group of one person and two computers. A design that serves a
group must therefore treat *computers* as the unit that holds keys, and it must merge edits made on
different copies.

### Constraints that do not move

- **No networking.** kagisecure adds no socket, no HTTP client, no sync service and no account
  system; [architecture.md](../architecture.md) §9 ("No network stack, no sync server, no account
  system") and threat-model non-goal N-9 stay true. Files move between people and machines by
  whatever the users already have — a private git repository, AirDrop, a USB stick, a sync folder —
  and kagisecure only reads and writes files at a path the user chose.
- **[ADR-0002](0002-no-secret-values-over-mcp.md) is unchanged.** No MCP tool returns a value from a
  shared vault, in whole or in part. Nothing about sharing gives an agent a new way to see one.
- **Approvals stay on the machine where the value is released.** A lease minted on one member's
  computer exists only in that computer's memory ([ADR-0004](0004-biometric-key-wrapping.md) rule 4).
  Sharing a vault shares the vault, not anyone's approvals.

### What the format already anticipated

[vault-format.md](../vault-format.md) §3 derives per-item keys `HKDF(VK, "kagisecure/item/" ||
item_id)` "so that a later format can adopt per-item encryption without a key-hierarchy change",
and §2.2 records the single-file choice with a condition attached:

> The alternative (one file per vault) makes selective sharing easier later but multiplies unlock
> prompts. Chosen for simplicity; revisit if team sharing ever lands.

This ADR is that revisit.

### Related work

Three ADRs were written alongside this one, and this design is written against them. They were
drafted as ADR-0032, ADR-0033 and ADR-0034 and renumbered on `main` before this ADR was accepted;
the numbers below are the current ones.

- **[ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) (accepted and implemented),
  transactional vault writes:** a sibling `<vault>.lock` file, a SHA-256
  *generation* of the exact file bytes, and a `transact` API so that several **local processes**
  (the app, the CLI, the daemon) can write one vault file without losing each other's changes.
- **[ADR-0040](0040-audit-before-release.md) (accepted; the fail-closed set implemented), audit
  before release:** an injection or fill is refused unless its audit
  entry is durable first.
- **[ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md) (proposed), an
  external freshness anchor** for the audit log, kept outside the file,
  addressing [threat-model.md](../threat-model.md) W-11 (and the key-holder truncation case recorded
  as C-11 there).

Those coordinate processes on **one machine**. None of them can coordinate two machines that never
talk to each other, which is what this ADR has to do.

## Decision

**A shared vault is its own file type: a growing set of immutable, individually signed and
encrypted records. Its content key is an *epoch key* wrapped to every member device's public key;
each record's key is derived from it. Members are people; every person has one device key per
computer, and every recipient and every signer is a device. Copies are exchanged out of band and
merged as a set union, so no copy can overwrite another, and conflicting edits are shown to a human
rather than resolved by a clock. Removing a device rotates the epoch key and produces an exact list
of the values that device could have read.**

### 1. A shared vault is a separate file, not a logical vault inside the personal file

The personal vault stays what it is: one file, one password, many logical vaults, one AEAD body.
A shared vault is a different kind of object with a different lifecycle — several writers, no
password slot, merge rather than replace — and folding it into the personal file would force every
personal-vault reader to understand records, rosters and merges. So:

- Each shared vault has its own **local replica**: a file in the app's data directory (`0600`,
  inside the `0700` directory, M-13), holding every record this device has accepted plus a
  local-only section (§15) that is never exported. The replica is written with ADR-0039's lock and
  transaction like any vault file.
- Each shared vault has zero or more **exchange copies**: what actually travels (§7). The replica is
  never itself placed in a sync folder or a repository.
- One shared vault is one audience. "These five secrets go to everyone, those two go to two of us"
  is two shared vaults. Access control is per file, not per item (§3 explains why).

This answers the §2.2 question for sharing only: shared vaults are one file each; the personal
vault keeps its logical vaults.

### 2. Members are people; recipients and signers are devices

Three models were considered:

| Model | Why not / why |
| --- | --- |
| **Members are devices.** Each computer is an independent member. | "Remove Bob" must remove every one of Bob's computers at once, and a role (admin, writer) belongs to a person, not to a laptop. A roster of anonymous machines is also what a human reads when deciding whom to trust, and it reads badly. |
| **Members are people with one key**, copied to each of their computers. | A stolen laptop then forces a new key for that person on every other machine, and nothing distinguishes which computer did what. It is the "copy the vault file" status quo, relabelled. |
| **Members are people, each with one or more device keys.** | — |

**Decision: a member is a person with a role; a member has one or more devices; each device has
its own key pair, generated on that device.** Epoch keys are wrapped to devices, records are signed
by devices, and the roster maps devices to members. Removing a member removes all their devices in
one operation; retiring one laptop removes one device.

**A new computer is a new device of an existing member**, not a new member. It generates its own
keys, and any existing device of the *same* member — or an admin — adds it (§11). This is what
migration looks like:

1. Install kagisecure on the new computer and bring the personal vault over — copying the file,
   exactly as today. That remains the whole migration for someone who shares nothing.
2. For each shared vault, the new computer creates an enrollment request (§10); the old computer
   (same member) or an admin accepts it after comparing fingerprints.
3. When the old computer is done, it is **retired** from each shared vault (§11), which rotates the
   epoch key so that a machine later sold or recycled without a wipe reads nothing new.

A single person with two computers and one shared vault is a group of one member and two devices.
That is offline sync between one's own machines, and it needs no separate feature.

### 3. Keys: one epoch key per vault, per-record keys derived from it

**This departs from the starting sketch**, which proposed per-item content keys wrapped to each
member. Evaluated:

| Option | Cost | What it buys |
| --- | --- | --- |
| Per-item keys, each wrapped to each member | items × devices wraps; every removal re-wraps every item; per-item recipient lists that can disagree, which makes "what could Bob have read" a per-item question with a per-item answer | Per-item access control inside one file |
| **One epoch key per vault, wrapped per device; per-record keys derived by HKDF** | devices wraps per rotation | One recipient set per file, so every member of a vault can read the same thing and the exposure question has one answer |

Per-item access control is the only thing the first option buys, and it is better expressed as two
shared vaults: an audience a human can see in the sidebar, rather than a recipient list hidden on
each item. The derivation is the one the format already anticipated, moved one level down
(`record_salt` is 16 random bytes carried, signed, in each record):

```text
epoch key EK_e      32 random bytes, one per epoch e
record key          HKDF-SHA256(EK_e, salt = record_salt, info = "kagisecure/shared/record/v1" || vault_id)
epoch wrap          HPKE.Seal(device_pub, info = "kagisecure/shared/epoch/v1" || vault_id || e, EK_e)
epoch chain         AEAD(EK_e, EK_{e-1})        # the new key can open the previous one
```

**Rotation never re-encrypts old records.** Records are signed (§6), and re-encrypting one would
invalidate its author's signature. It would also be pointless: a removed device already holds the
old epoch keys and, very likely, a copy of the old records. What rotation protects is everything
written *afterwards*. Old epoch keys are reachable from the newest one through the epoch chain, so a
device added later can read the vault's history, and a removed device can read nothing new.

### 4. Cryptographic primitives

The workspace today has `chacha20poly1305` 0.11 (XChaCha20-Poly1305), `hkdf` 0.13, `sha2` 0.11,
`hmac` 0.13, `argon2` 0.6 and `rand_core` 0.9, and **no public-key cryptography at all**: no
X25519, no Ed25519, no HPKE, no P-256 in `Cargo.lock`. Sharing needs two new capabilities.

| Purpose | Choice | Notes |
| --- | --- | --- |
| Record bodies | XChaCha20-Poly1305, random 24-byte nonce | Already used for the vault body; same reasoning as [vault-format.md](../vault-format.md) §4 |
| Key derivation | HKDF-SHA256 | Already used |
| Record ids, fingerprints, chains | SHA-256 | Already used, and available without `secret-material` |
| Wrapping an epoch key to a device | **HPKE (RFC 9180) Base mode**: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | A published standard with test vectors, so a second implementation can interoperate — the property [vault-format.md](../vault-format.md) and the roadmap's M0 criteria ask of the format |
| Signatures | **Ed25519 (RFC 8032)**, strict verification | Rejects non-canonical encodings and small-order keys, so a signature cannot be mauled into a second valid one |

New dependencies: `x25519-dalek` and `ed25519-dalek` (and `curve25519-dalek` beneath them), and
possibly the `hpke` crate. They are permissively licensed (within `deny.toml`'s allow-list, to be
confirmed at adoption). **Preference order for HPKE:** the `hpke` crate if its audit record is
acceptable and its RustCrypto versions line up with the workspace's (`multiple-versions = "warn"`
would otherwise report a second `chacha20poly1305` or `hkdf`); failing that, RFC 9180 Base mode
composed from `x25519-dalek` and the crates already present, pinned to the RFC's published test
vectors. A hand-rolled "sealed box" that is *like* HPKE is not an option: it would be a construction
nobody else can check against anything. The audit status of whichever crates are adopted is
recorded the way W-6 records the RustCrypto AEAD audit.

**Cryptographic parameters are data** ([vault-format.md](../vault-format.md) §1, goal 4). Every
device key and every shared vault names a suite, `x25519-ed25519-v1`. A later suite — P-256 for
Secure Enclave-held keys (§5), or a post-quantum hybrid KEM — is a new suite value, not a format
break.

**Where the code lives.** Record parsing is untrusted-input parsing, the same situation
[ADR-0031](0031-the-import-crate-and-its-intermediate-representation.md) §1 resolved by giving
import its own crate. Shared vaults get one too, `kagisecure-shared`, depending on
`kagisecure-core` with `secret-material`. **`kagisecure-mcp` and `kagisecure-ipc` must never depend
on it**, and the existing dependency-graph guard gains a clause for it.

### 5. Where device private keys live

**In the personal vault body, as `Secret` values** — a new `devices` list of `{ device_key_id,
suite, label, created_at, secret_keys: Secret }`. Not in the Keychain, and not in the Secure
Enclave.

- **Protection is the personal vault's.** A device key is usable only while the personal vault is
  unlocked, which means through the password slot, the platform (Touch ID) slot of
  [ADR-0004](0004-biometric-key-wrapping.md), or the recovery code
  ([vault-format.md](../vault-format.md) §3.2). No new unlock path exists, and locking the personal
  vault locks every shared vault with it (M-11).
- **No new entitlement.** A Keychain item bound to an access group, or an Enclave key, needs
  `keychain-access-groups`, which [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) measured
  as requiring a provisioning profile that a clean checkout cannot obtain. Storing device keys in
  the vault means a source build can share vaults.
- **The Secure Enclave cannot hold these keys anyway.** It performs P-256 only; X25519 and Ed25519
  keys cannot be created in it. An Enclave-held device key would need a P-256 suite (ECDH for HPKE,
  ECDSA for signatures). That is recorded as a later suite, not rejected: it would make a device
  key genuinely non-exportable, and it becomes worth doing when ADR-0011's blocker is cleared.
- **The cost, stated plainly:** until then a device key is a software key, and "device-bound" is a
  convention rather than a hardware property. A copied personal vault carries its device keys to
  the new machine (threat-model W-14). The app mitigates the confusion rather than the property: it
  records, in local preferences outside any vault, which device keys it created on this computer,
  and when it opens a personal vault whose device keys it did not create, it offers to enroll this
  computer as a new device and retire the old one.
- **Device keys are not items.** They are never agent-visible, never covered by `item show
  --reveal` ([ADR-0005](0005-secret-material-in-m1.md)), never exported, and never shown.

### 6. Records, signatures and the authenticated roster

Every change to a shared vault is a **record**, and a record is immutable once written:

```text
record := {
  v, kind,                # "roster" | "epoch" | "item" | "env" | "ack"
  vault_id,
  author,                 # device_key_id of the signer
  seq, prev,              # the author's own counter and the id of its previous record
  parents,                # the versions (item/env) or roster heads this record builds on
  epoch,                  # which epoch key encrypts the payload (item/env)
  created_at,             # the author's claim; displayed, never used to decide anything
  record_salt,            # 16 random bytes; input to the record key (§3)
  payload,                # ciphertext for item/env; structured, mostly plaintext for roster/epoch
  sig                     # Ed25519 over the canonical encoding of everything above
}
record_id := SHA-256(signed bytes || sig)
```

- **Encrypt, then sign, and bind the author into the ciphertext.** The payload's AEAD associated
  data includes `vault_id`, `author`, `kind`, `parents` and `epoch`. Signing the ciphertext lets a
  reader verify a record before decrypting or parsing any of it; putting the author in the AAD
  stops another member stripping the signature and re-signing someone else's ciphertext as their
  own, because the payload then fails to decrypt.
- **The roster is a chain of signed roster records**, starting from a genesis record signed by the
  creator's device: add member, add device, remove device, remove member, set role. A reader
  computes membership by verifying that chain from genesis; nothing about membership is taken from
  a field that is not signed by someone who had the authority to set it. Device public keys and
  roles are plaintext (they are needed before anything can be decrypted); member and device
  *labels* are encrypted under the epoch key.
- **Roles.** `admin` may change the roster and edit items; `writer` may edit items; `reader` may
  only read and acknowledge. Every item record is checked against its author's role in the roster
  state it names as its parent, so a reader — who holds the epoch key and could produce a perfectly
  good ciphertext — cannot produce an accepted change.
- **Concurrent roster changes** are linearized deterministically (topological order, ties broken by
  record id) and each is re-validated against the linearized state: an operation whose signer was
  removed earlier in that order is void. Two admins removing each other at the same time therefore
  resolves to the same single outcome on every replica, and the UI says it was decided by rule and
  asks the surviving admin to confirm.
- **A per-device chain.** `seq` and `prev` make every device's records a hash chain. Two different
  records with the same author and the same `seq` are **equivocation** — a device showing different
  histories to different peers — and are flagged on every replica that sees both, with both kept.

### 7. Transport is out of band: an exchange directory or a bundle, never a socket

kagisecure writes and reads files. It does not run `git`, does not open a connection, and does not
watch anything but a local path. Two containers carry the same records:

- **Exchange directory** — for a sync folder or a git working copy. A small descriptor file
  written once at creation (magic, `format_ver`, `vault_id`, genesis record id), and one file per
  record, **named by its record id**. Files are created with create-new semantics and never
  modified or deleted. Two writers can never produce the same name with different contents, so a
  git merge of two members' directories cannot conflict, and a sync tool's "conflicted copy" of a
  file can only be a byte-identical duplicate or an unrelated name that is ignored.
- **Bundle** — one file, for AirDrop, a USB stick or an email attachment: magic, `format_ver`,
  `vault_id`, and a sequence of records. "Export changes since…" writes one; "Import" accepts one.

Import is: parse with bounded limits, verify every signature against the roster, merge the
accepted records into the local replica in one ADR-0039 transaction. Export is: write the records
the destination lacks. Neither ever writes to the replica from outside a transaction, and the
exchange copy is never opened as a vault — which is also why ADR-0039's "file replaced underneath
us" checks never fire on a sync tool's behaviour: the sync tool never touches a file ADR-0039
guards.

**Git as a first-class integration was considered and rejected** (see Alternatives): the directory
form is designed so that git needs no help, and the user runs it.

### 8. Concurrent edits across copies: a union of versions, conflicts surfaced

Copies are edited offline, on different machines, and exchanged whenever someone gets round to it.
The merge model is chosen for one property: **no merge can lose a value.**

- **The replica is a grow-only set of records**, and merging two copies is their set union. Union is
  commutative, associative and idempotent, so every replica that has seen the same records computes
  the same state regardless of order, repetition or which copy arrived first. (In CRDT terms: a
  grow-only set of signed versions, with multi-value register semantics per item.)
- **Each item and environment is a version graph.** Every item record carries the full item as of
  that version and names its parent versions. One head means no conflict. Two heads are two edits
  that did not see each other.
- **Two heads are merged automatically only where that is provably safe**: a field-by-field
  three-way merge against their common ancestor, where only one side changed a field, or both sides
  changed it to the same value. **Where both sides changed the same field differently, the item is
  conflicted**, and it stays conflicted until a human picks. Deletion against an edit is a conflict
  too, and the edit stays visible until resolved.
- **No last-writer-wins, ever, for anything that can hold a value.** Clocks on different machines
  are not trustworthy and not comparable, and the failure mode is concrete: two people rotate the
  same credential, the service keeps only the second rotation, and a timestamp rule keeps the first.
  Silently dropping a *current* password is data loss of the worst kind, because the one kept no
  longer works.
- **A conflicted field is never injected or filled.** An agent request or a fill that would release
  it is refused with a distinct error until a human resolves the conflict in the app. The approval
  sheet never has to choose between two values on the user's behalf. (This adds an error code to
  the IPC and extension protocols, the same kind of addition ADR-0040 makes.)
- **Resolution is a new record** whose parents are both heads, so it merges like any other edit and
  every replica converges on it.

**Relation to ADR-0039.** ADR-0039 serializes local processes on the replica file; this section
merges replicas across machines. They compose because the exchange never writes the replica: an
import is simply one more local transaction. ADR-0039's rule for local processes (the
edit sheet's save is rejected as "changed elsewhere — reload", while single toggles are
last-writer-wins) applies *within one replica*, where two processes see the same file under a
lock. Across machines there is no lock and no shared file, and last-writer-wins is not used.

### 9. Rollback and freshness

Freshness is where an offline design is weakest, and this section says what is and is not
achieved.

- **A stale exchange copy is harmless to an existing replica.** Merge is a union; an older copy
  adds nothing and removes nothing. Presenting a member with last month's bundle does not roll them
  back. This is strictly better than the personal vault, where W-11's whole-file rollback is exactly
  "present an older copy".
- **A stale copy given to a new device is not.** A device joining from an old copy could learn an
  old roster and start writing under an epoch a removed device still holds. So an **invitation**
  (§10) carries the roster head and epoch id at the moment the admin accepted the device, signed by
  the admin, and the joining device refuses any copy that does not contain that roster head.
- **Withholding is detectable only after the fact.** Whoever carries the files — a repository host,
  a sync provider, a member who "forgets" to pass something on — can withhold a removal from one
  device, which then keeps writing new values under the old epoch, readable by the removed device.
  No offline design can prevent that. What this one does is **account for it**: each device signs an
  `ack` record when it adopts a new epoch, the admin's removal screen lists devices that have not
  acknowledged, and the rotation list (§12) is computed from which epoch each value was actually
  encrypted under — so a value written late under a stale epoch appears on the list automatically.
- **There is no global "latest".** kagisecure can show, per device, the newest record it has from
  that device and the epoch it last acknowledged. It cannot know that nothing newer exists somewhere
  else, and it does not claim to.
- **Local rollback of the replica** (T-3 copying an old replica file back) is W-11 again, with one
  sharper consequence: a device whose replica is rolled back would reissue `seq` numbers it has
  already published and **equivocate against itself**. Two mitigations: before writing, a device
  checks its configured exchange location for its own records with a higher `seq` than its replica
  knows; and, once ADR-0041's anchor exists, the anchor records per shared vault the replica's
  generation, the roster head and this device's own highest `seq`, so a rollback is detected before
  the first write rather than after. The anchor inherits whatever storage ADR-0041 settles on,
  including any dependency on the signing situation ADR-0011 records.

### 10. Verifying keys offline

Every mechanism above rests on the roster containing the right public keys. Key substitution —
someone swapping the public key in an enrollment request on its way through email or a sync
folder — would make every later epoch key readable by the attacker, without any signature failing.
So enrollment is where a human has to do something.

- **An enrollment request** is a small file the joining device writes: suite, member and device
  labels, the X25519 and Ed25519 public keys, and an Ed25519 self-signature binding them. It
  contains nothing secret and can travel by any channel.
- **A fingerprint** is a fixed-length SHA-256 digest of the suite and both public keys, at least
  128 bits, rendered as groups of digits for reading aloud and as a QR code for in-person
  comparison. The exact encoding is Phase 1 work with golden vectors.
- **The admin compares the full fingerprint** with the one the joining device displays — side by
  side, over a call, or by scanning — and confirms. The add-device record stores how it was
  verified (`in_person`, `voice`, `unverified`), so every member sees not just who added a device
  but whether they checked.
- **Verification is mutual.** The admin's reply is an **invitation**: `vault_id`, genesis record id,
  the admin device's fingerprint, the current roster head and epoch id, signed. The joining device
  shows the admin's fingerprint for the same comparison. Joining without comparing is allowed and is
  trust-on-first-use: the vault is labelled "not verified" on that device until the comparison is
  done, and the label does not fade on its own.
- **Short confirmation codes are rejected.** "Type the last six digits the other person reads out"
  looks like verification and is not: without a commitment protocol, an attacker who knows which
  digits will be checked can grind a key pair whose fingerprint matches them in seconds. Either the
  whole fingerprint is compared, or the verification is recorded as not done.
- **Keys never change in place.** There is no "update Alice's key". A reinstalled computer is a new
  device, added by a record every member sees ("Alice added device *Laptop 2*, verified in person by
  Bob"), and the old one is removed by another. A member can also mark any device "verified by me"
  locally after their own comparison.

### 11. Adding, removing, revocation and compromise

- **Adding a device** is one roster record plus one epoch record: the new device's public keys, and
  the current epoch key wrapped to it. No rotation is needed; the new device reads the history.
  Admins add devices for anyone; a member's existing device may add a device for the *same* member
  (the migration path, §2) — announced to all members like any other addition (whether to allow
  this without an admin is an open question).
- **Removing a device or a member** is one roster record carrying a **cut**, and a new epoch:
  - the **cut** is the set of the removed devices' records the remover accepts — by default,
    everything the remover's replica holds from them. Every replica rejects any record from a
    removed device that is not in the cut. This closes backdating: a removed device cannot
    fabricate a record that claims to predate its removal, because the only such records that
    count are ones the remover had already seen. The cost is that a genuine last edit the remover
    had not yet received is dropped everywhere; replicas that had accepted it show the reverted
    field as a conflict for a human to settle, rather than losing it silently.
  - the **new epoch key** is wrapped to every remaining device, and the previous epoch key is
    wrapped under it (§3).
- **Epoch rotation needs no special authority.** It discloses nothing new: it only wraps a fresh key
  to the signed roster. So any writer or admin that finds the current epoch's recipients differ from
  the current roster devices (after concurrent roster changes, for example) mints a new epoch.
  Writes are never paused waiting for an admin.

**Revocation and compromise are different events**, and the UI asks which one it is:

| | Revocation (a person leaves; a computer is retired) | Compromise (a device lost while unlocked, malware, a member acting in bad faith) |
| --- | --- | --- |
| Cut | Everything the remover has from the device | Only the device's records up to a point in its own chain (`seq`) the admin chooses, shown with their claimed times as a guide but not decided by them; later ones are rejected on every replica, which reverts their versions and may surface conflicts |
| Rotation list (§12) | Shown. For a retired computer that stayed in the owner's hands, rotation is offered but not recommended | Shown and recommended, including metadata exposure |
| Roster review | — | Every roster change the device signed after that point is listed for an admin to revert with new records |
| What it cannot do | Take back what the device already read | The same, and more so |

**A stolen old device** whose personal vault was locked is T-5: its device key is behind the
personal vault's Argon2id-stretched password. Remove it anyway, promptly — an offline password
guess is a matter of time and password strength — and treat the rotation list as "if the password
was weak".

### 12. The rotation list: what a removed device could have read

When a device leaves, the honest question is not "what did they look at" — that was recorded, if at
all, on their own machine, which nobody else can inspect or trust — but **"what could they have
read"**. That question has an exact answer, computed from the replica:

> A value is exposed to device D if the record holding it is encrypted under any epoch that was
> wrapped to D.

Because old epochs are reachable only forwards from new ones (§3), that is every value written in
any epoch up to the last one D held — plus any value written later under a stale epoch by a device
that had not yet seen the removal (§9).

The list shows **current** values that are exposed: item, field label, who last set it, and a
status. An entry clears when the field's current version is in an epoch not wrapped to D — that is,
when someone rotates the value — and the list is recomputed rather than stored, so every replica
agrees on it. It also shows:

- **Hard-to-rotate kinds**, flagged: TOTP seeds (the second factor must be re-enrolled at the
  service), SSH private keys, recovery codes.
- **Retired values** from item history that D could have read, separately and as "confirm these
  were revoked at the service", since a retired password that still works is a live one.
- **Metadata** — titles, usernames, URLs, environment and variable names — as exposed, full stop.
- **Devices that have not acknowledged the new epoch**, because until they do, anything they write
  is readable by D.

"Could have read" is deliberately conservative. It will list values D never opened. Narrowing it
would require trusting D's own audit log, which is exactly the thing that cannot be trusted about a
departed or compromised device.

### 13. Recovery when a member loses their key

- **Lost computer, personal vault backed up:** restore the personal vault (password or recovery
  code); the device keys come with it. If the hardware is gone for good, enroll the replacement as a
  new device and remove the old one.
- **Personal vault lost with no backup:** the device keys are gone, but the shared vault is not — it
  lives in every other member's replica. Enroll a new device (verified again) and remove the lost
  one. Nothing is lost except for a vault whose only device it was.
- **The last admin device lost:** the roster can never change again. Writers can keep editing items;
  the way forward is a new shared vault and moving the items across. The app warns whenever a shared
  vault has exactly one admin device, and recommends two — two admins, or one admin with two
  computers.
- **A paper recovery recipient** — a printed key added to the roster as a reader, able to decrypt
  every epoch — would cover the single-person, single-computer case. It is an open question, not a
  decision, because a printed key that can read everything is a second master key with no password
  in front of it.

### 14. AI agents and approvals

- **ADR-0002 holds unchanged and structurally.** Shared items are items. Decryption of records lives
  in `kagisecure-shared`, which `kagisecure-mcp` and `kagisecure-ipc` cannot depend on (§4); the
  canary tests gain a value seeded into a shared vault.
- **No agent can change who a vault is shared with.** There is no MCP tool and no IPC message that
  creates, joins, imports into, exports from, or changes the roster of a shared vault, verifies a
  fingerprint, or resolves a conflict. Adding a device is a disclosure of every value to a key: an
  injected agent able to do it would exfiltrate the vault without ever seeing a value. These are
  human actions in the native app and the CLI, and the IPC protocol has no message for them.
- **Agents cannot write to a shared vault** in the first version. `create_environment` and
  `add_variables` target the personal vault; putting something in front of other people is a human
  decision.
- **Agent visibility is local and default-hidden.** Whether an agent on *this* computer may see a
  shared item's metadata is this device's decision, stored in the replica's local-only section and
  never exported; everything received from a shared vault starts hidden (M-9's default, as for
  imported items). A member cannot make an item visible to someone else's agents.
- **Approvals are per machine.** Leases, approval decisions and lease audit never leave the computer
  they were made on.
- **The approval sheet gains two facts** (M-5): the source ("Shared vault *Ops* — 4 members"), and,
  when any value about to be released has changed since this device last approved releasing it,
  who changed it and when ("`DATABASE_URL` changed by Bob's *Desktop*, 2 days ago"). A malicious
  writer can still change a value your agent will use — that is inherent to sharing (W-16) — but the
  sheet stops it from happening unannounced.
- **References stay inside the vault.** A shared environment's `ItemField` may reference only items
  in the same shared vault. A reference into a member's personal vault would be meaningless to
  everyone else and would disclose an item id.
- **The browser extension** fills shared login items exactly as it fills personal ones: the same
  origin rule, the same per-machine fill approvals and fill leases.

### 15. Audit semantics: whose log is it?

There are three different things people mean by "the audit log" of a shared vault, and they get
three different answers:

1. **What changed, and who changed it** — is the shared history itself. Every change is a signed
   record in a per-device chain (§6); attribution is cryptographic, and every member has the same
   history once they have the same records. Nothing needs to be appended to a separate log for it.
2. **What this computer released** — approvals, injections, fills, reveals, imports, exports,
   fingerprint verifications, conflict resolutions — stays in the **local-only section of this
   device's replica**, with the same schema as [vault-format.md](../vault-format.md) §8 and the same
   rules as the personal vault: ADR-0040's audit-before-release applies to a release from a shared
   vault exactly as to one from the personal vault, and ADR-0041's anchor covers it when it exists.
   It is never exported: it holds local paths, process identities and approval decisions that are
   private to that machine and meaningless — or worse, misleading — to anyone else.
3. **What other members' computers released** — is not knowable. A member's machine could publish
   signed "usage" records, but a dishonest member's machine would simply not publish them, so such a
   log proves use and never proves non-use. Whether to offer it anyway, opt-in per vault, is an open
   question.

The answer to "whose log" is therefore: **each device's own**, and nobody's log is authoritative
about someone else's machine.

### 16. Format and versioning

- **Three new file types**, each with its own magic and `format_ver`, following
  [vault-format.md](../vault-format.md) §9's rules: the local replica, the exchange directory's
  descriptor, and the bundle. Older readers refuse a newer `format_ver` with a clear error.
- **Records carry their own `v`.** They are stored and forwarded byte for byte — they have to be,
  since they are signed — which gives §9 rule 1 ("an older kagisecure … must not destroy data it did
  not understand") for free: a record a build does not understand is kept and passed on untouched.
  A build that meets an unknown **item** field keeps it; a build that meets an unknown **roster or
  epoch** kind becomes **read-only** for that vault, because computing membership wrongly is worse
  than not writing.
- **An unknown suite** makes the vault refuse to open, like an unknown `format_ver`.
- **The personal vault changes too**, and this is the part that needs care. It gains a `devices`
  list (§5). §9 says additive body keys need no bump because "unknown fields survive round-trip" —
  but the current `Body` type (`crates/kagisecure-core/src/vault/mod.rs`) has no unknown-key
  passthrough, and nothing checks `body.schema` on read. A shipped build would open a personal vault
  holding device keys and **drop them on its next save**, silently cutting that computer out of
  every shared vault. Therefore:
  1. `Body` and `Header` gain unknown-key passthrough regardless of this ADR, because §9 rule 1
     already promises it.
  2. A personal vault that holds device keys is written with the next `format_ver`, so builds that
     predate the passthrough refuse to open it rather than damage it. That stretches §9's
     "byte layout changes" meaning of `format_ver`, deliberately: it is the only version check a
     shipped build performs. The upgrade happens on write when the first device key is created,
     states what changes, and takes the `<name>.vault.bak-<format_ver>` backup (§9 rule 2).
  3. The alternative — storing device keys as an item of a reserved `Other(...)` category, which
     older builds preserve — was rejected: it puts key material in something the user can see, edit,
     move and delete in an older build.
- **Golden vectors** for each new file type and for a `format_ver` 2 personal vault, plus RFC 9180
  and RFC 8032 test vectors for the primitives, added the day they ship and never edited
  (§9 rule 4).

### 17. UX sketch

At the level of [ui-spec.md](../ui-spec.md); details belong to that document once this is accepted.

- **Sidebar:** a *Shared* section under the personal vaults, one row per shared vault, with a member
  count and an exchange state: "Exported 2 h ago · 1 device behind", "Not verified", "3 conflicts".
- **Create:** name, then an exchange location — a folder (a git working copy or a sync folder) or
  "I'll export bundles myself". The creator is the first admin.
- **Join:** *Join a shared vault…* writes an enrollment request and shows this device's fingerprint
  in large groups with a QR code. The joiner sends the request however they like.
- **Add member / add device:** choose the request file; the sheet shows the fingerprint beside a
  prompt to compare it with the other person's screen, a role picker, and "How did you verify?".
  Confirming requires a fresh biometric (or the master password), because adding a device discloses
  every value in the vault.
- **Import / export:** automatic against a configured folder when the app becomes active and after
  each change; manual for bundles. The result is summarized in names only: "4 changes from Alice,
  1 conflict, Bob's *Laptop* removed".
- **Conflicts:** a banner on the item — "Two versions: Alice (Tue), Bob (Wed)" — and a resolution
  sheet listing changed fields by name, with values revealable under the ordinary reveal rules.
- **Members:** people, their devices, each device's verification state, last record seen, and epoch
  acknowledged. *Remove* asks "left / retired" or "lost / compromised" and then shows the rotation
  checklist (§12), which stays in the sidebar until it is empty.
- **CLI parity:** `kagisecure shared create | join | add | remove | import | export | status |
  rotation-list | resolve`, all human-only, all refused under `--auto-approve`.

### Alternatives considered

**(a) One shared password or symmetric key for the group.** Rejected. Removing anyone means choosing
and distributing a new secret to everyone else through some channel; nobody can tell who wrote
what, because anyone with the key can write anything; and a key that everyone has is a key nobody
can revoke from one person. It is the "shared spreadsheet password" pattern this product exists to
replace.

**(b) A sync server or hosted service.** Rejected by the offline constraint, and not only by it. A
server gives a global order and instant revocation, and in exchange becomes a party that must be
trusted with availability, metadata and, eventually, an account system — every one of which
[architecture.md](../architecture.md) §9 excludes. What is lost is recorded honestly in §9 and W-13.

**(c) Per-item keys wrapped to each member.** Rejected in §3: it buys per-item access control at the
cost of items × devices wraps, a re-wrap of every item per removal, and a rotation question with a
different answer per item. Two shared vaults express the same thing visibly.

**(d) Put the personal vault file in a shared folder, as-is.** Rejected. The file is replaced whole
on every save, so two machines editing it lose edits at file granularity; there is no attribution;
and it needs the password shared. It is what users can do today, and it is why this ADR exists.

**(e) Git as a first-class integration** — kagisecure running `git pull`, `commit` and `push`.
Rejected. It would make kagisecure the process that initiates network traffic, even if through a
child; it would bring credential handling for remotes into a password manager's surface; and it
would tie the design to one tool. The exchange directory (§7) is instead designed so that git merges
it without ever conflicting, and the user runs git the way they already do.

**(f) An existing file-encryption tool's format** (recipient-based encryption such as `age`).
Considered and partly adopted in spirit — X25519 recipients wrapping a file key is essentially
§3's epoch wrap. Rejected as the format because it has no signatures, no authenticated roster, no
roles and no merge, which are most of this ADR.

**(g) A group key-agreement protocol such as MLS (RFC 9420).** Rejected for now. It offers
post-compromise security through tree-based rekeying, but it assumes a delivery service that
totally orders group changes; concurrent commits exchanged by hand are exactly what it does not
handle. For groups of a few people, wrapping one key to each device is cheap and understandable.

**(h) Members as devices, or as people with one copied key.** Rejected in §2.

**(i) Last-writer-wins merge.** Rejected in §8.

**(j) Device keys in the Keychain or the Secure Enclave.** Deferred in §5, not rejected: blocked by
[ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) today, and the Enclave needs a P-256 suite.

### Where this departs from the starting sketch

The sketch this ADR was developed from proposed per-member wrapping of content keys, out-of-band
transport, re-wrapping for membership changes, a list of values to rotate, per-machine approvals,
and a new computer enrolled as a member. It departs in six places, deliberately:

1. **Per-vault epoch keys, not per-item wrapping** (§3) — simpler, and the exposure question gets
   one answer.
2. **A new computer is a device of an existing member**, not a member (§2) — roles and removal are
   about people.
3. **"A removed member cannot read new versions" holds only once every remaining device has seen the
   removal** (§9). The sketch implied it held immediately; offline, it cannot. The rotation list
   accounts for the gap rather than hiding it.
4. **Signatures, roles, the cut and equivocation detection are added** (§6, §11). The sketch was
   about confidentiality; with several writers, integrity and attribution are at least as important.
5. **The replica and the exchange copy are separate files** (§1, §7), and the exchange has a
   directory form made for git and sync folders.
6. **Device keys live in the personal vault, not in the Keychain or the Enclave** (§5).

## Changes in the threat model

Recorded in [threat-model.md](../threat-model.md), each marked as accepted but not yet built, and
numbered after the entries that existed when it was written (T-8…T-11, T-15 and A8 are in
[threat-model-browser-extension.md](../threat-model-browser-extension.md)). The T-12…T-14,
M-22…M-28 and W-12…W-17 blocks were reserved for this ADR while it was a draft; ADR-0036, drafted
at the same time, first used some of the same numbers and was renumbered when both were accepted
(its entries are T-17, M-31 and W-21):

- **Assets** A9 (device private keys), A10 (the roster and epoch keys), A11 (exchange copies held by
  third parties).
- **Boundaries** TB-5 (an exchange copy entering the local replica) and TB-6 (one member and
  another).
- **Adversaries** T-12 (a malicious or compromised member), T-13 (a departed member, or a retired
  or stolen device), T-14 (whoever carries, alters, replays or withholds the exchange copy —
  including key substitution during enrollment).
- **Mitigations** M-22 (signed records verified before decryption), M-23 (full-fingerprint
  verification), M-24 (epoch rotation and the cut), M-25 (the rotation list), M-26 (union merge,
  conflicts to a human, equivocation flagged), M-27 (sharing decisions are human-only; agents gain
  nothing), M-28 (exchange copies parsed as untrusted input).
- **Weak points** W-12 (members read everything; departed members keep it), W-13 (no global
  freshness; withholding), W-14 (device keys are software keys), W-15 (exchange metadata), W-16
  (poisoned values from a legitimate writer), W-17 (no forward secrecy; not post-quantum).

N-9 ("v1 has no network code") is unchanged and remains true.

## Consequences

**Positive**

- Both needs — a group sharing secrets, and a person on more than one computer — are one mechanism,
  and neither needs a byte of network code.
- No exchange can lose an edit or undo a removal on a device that has already seen it: merge is a
  union, and conflicts are shown to a person.
- Every change is attributable to a device and a person, verified before it is decrypted.
- Departure produces a concrete, checkable to-do list instead of a vague "rotate everything".
- ADR-0002's guarantee and the per-machine approval model carry over unchanged, and the one new
  capability an agent could abuse — adding a key — has no path from an agent at all.
- The format moves in the direction it already anticipated (derived per-record keys, one file per
  shared audience), and every parameter that might need to change is a suite value.

**Negative — accepted**

- **A member can read everything in a vault they belong to, and a departed member keeps it.** That
  is what sharing is (W-12). The rotation list is the whole mitigation.
- **Freshness is weak.** Withholding a removal from one device leaves it writing under a stale epoch
  until it catches up; kagisecure can show the lag and account for its consequences, not prevent it
  (W-13).
- **Device keys are software keys** until an Enclave-backed suite exists; a copied personal vault
  carries them (W-14).
- **The exchange copy leaks metadata** to whoever carries it: how many devices, how often each one
  writes, record sizes, and pseudonymous author ids (W-15).
- **A legitimate writer can poison a value** another member's agent will use (W-16). Attribution and
  the "changed since" line on the approval sheet bound it; nothing prevents it.
- **No forward secrecy, and not post-quantum.** Exchange copies sit with third parties indefinitely,
  and X25519 is harvestable by a future quantum adversary (W-17). A hybrid suite is the answer and
  is an open question.
- **Three or four new cryptographic dependencies** in a project that has had none for public
  keys, and one more crate.
- **A `format_ver` bump for personal vaults that hold device keys**, the first since the format was
  written, with the migration and golden-vector work that comes with it.
- **Conflicts need people.** Two people editing one credential offline will have to choose, and an
  agent cannot use that field until they do.
- **Growth is unbounded.** Records are never deleted; a busy vault grows by roughly one small record
  per edit, forever, until compaction is designed.

**Neutral**

- The personal vault does not change, apart from holding device keys; users who share nothing see
  nothing new.
- The roadmap's "Sync" stance — no first-party sync service — stays true. What changes is that file
  sync the user already runs becomes safe to use with multiple writers.

## Open questions

1. **HPKE implementation:** adopt the `hpke` crate, or compose RFC 9180 Base mode from
   `x25519-dalek` and the existing RustCrypto crates? Depends on audit record and version alignment
   under `cargo deny`.
2. **Roles:** are three roles right, or is `admin` / `member` enough? Is `reader` worth its test
   surface?
3. **Self-enrollment:** may a member's existing device add a new device for the same member without
   an admin (§11)? It is the smoothest migration path and also the persistence path for a
   compromised device.
4. **Paper recovery recipient** (§13): offer it, and with which role?
5. **Shared usage records** (§15): offer an opt-in "who released what" log that can prove use but
   never non-use?
6. **A shared agent-visibility ceiling:** should admins be able to mark a vault "never visible to any
   agent", enforced by every member's build?
7. **History on add:** does a newly added device see item history (retired values), or only current
   values? And does moving an item from a personal vault into a shared one carry its history? The
   draft says no for the move.
8. **Compaction:** a signed snapshot that lets old records be dropped from exchange copies without
   breaking verification.
9. **Post-quantum hybrid suite:** when, given that exchange copies are exposed to third parties for
   years?
10. **Secure Enclave suite:** a P-256 device key held by the Enclave, once ADR-0011's blocker is
    cleared.
11. **The `format_ver` lever** (§16): acceptable, or should the passthrough fix ship in a release of
    its own first, with device keys only added once enough users have it?
12. **Group size:** the design assumes a few people and a few dozen devices. Is there a stated
    ceiling?
13. **Name:** "shared vault" (used here), "team vault", or something else?

## Implementation plan

No code is written by this ADR. Each phase ends with something testable on its own.

- **Phase 0 — prerequisites.** ADR-0039 and ADR-0040 implemented (the replica relies on
  transactions, and releases from shared vaults on audit-before-release) — both done on `main` by
  the time this ADR was accepted. `Body`/`Header`
  unknown-key passthrough. The dependency decision for X25519, Ed25519 and HPKE, passing
  `cargo deny`.
- **Phase 1 — crypto and records, no UI.** `kagisecure-shared`: device keys, HPKE wrap, Ed25519
  sign/verify, record encoding and verification, the roster state machine, the epoch chain,
  fingerprints. RFC test vectors, golden vectors, property tests over roster linearization, a
  `cargo-fuzz` target for the record and bundle parsers, and the dependency-graph guard.
- **Phase 2 — replica, merge, exchange; CLI.** Local replica under ADR-0039, union merge, version
  graphs and field-level three-way merge, conflicts, cut enforcement, equivocation detection,
  bundle and directory import/export, the rotation list. CLI commands. Cross-process tests: two
  replicas diverge and converge in any order; a removed device's later records are rejected; a
  stale-epoch write appears on the rotation list; a rolled-back replica does not reuse a `seq`.
- **Phase 3 — enrollment and verification.** Requests, invitations, fingerprint display, verified
  state, TOFU labelling. The personal vault's `devices` list and the `format_ver` migration.
- **Phase 4 — agents and approvals.** Local agent visibility, the two new approval-sheet facts, the
  conflicted-field refusal and its error code, extension fills from shared items, the canary test
  extended to shared vaults, and a test that no IPC message reaches a roster operation.
- **Phase 5 — macOS app.** Sidebar section, members screen, conflict resolution, rotation checklist,
  the copied-personal-vault prompt.
- **Phase 6 — later.** ADR-0041 anchor fields for shared replicas, and whichever of the open
  questions are accepted: paper recipient, usage records, compaction, Enclave and post-quantum
  suites.

**Documents that change on acceptance:** [vault-format.md](../vault-format.md) (§2.2's assumption,
§3, §9, and a new section or companion document for the shared formats),
[architecture.md](../architecture.md) (§2 components, the new crate; §9 stays as written),
[mcp-server.md](../mcp-server.md) (§7 error code; shared vaults in `list_vaults`),
[ui-spec.md](../ui-spec.md) (§2.2 sidebar, §10.2 approval sheet facts),
[threat-model.md](../threat-model.md) (the entries this ADR adds, promoted from proposed), and
[roadmap.md](../roadmap.md) as below.

## Proposed roadmap changes

These are **proposals for the owner, not edits**: `docs/roadmap.md` is unchanged by this ADR.
Accepting the ADR (2026-09-26) did not apply them: where the milestone slots in depends on the
order in which this ADR and [ADR-0036](0036-agent-requested-browser-fill.md), accepted the same
day, are implemented, and they are applied when that order is set.

**1. The platform decision paragraph** (currently lines 22–24). Replace:

```text
**Platform decision (2026-09-09):** kagisecure is macOS-first. The product is modeled on
1Password 8's desktop look and feel (see [ui-spec.md](ui-spec.md)) and is single-user, no
teams/sharing. Windows (formerly M4) and iOS are demoted to unscheduled optional work — see
```

with:

```text
**Platform decision (2026-09-09):** kagisecure is macOS-first. The product is modeled on
1Password 8's desktop look and feel (see [ui-spec.md](ui-spec.md)) and has no accounts, no
server and no network code. It was scoped as single-user; sharing a vault with a small group, or
between one person's computers, is designed in
[ADR-0035](decisions/0035-shared-vaults.md) (accepted) as an offline feature in which the users
move files themselves and kagisecure adds no networking. Windows (formerly M4) and iOS are
demoted to unscheduled optional work — see
```

**2. The post-v1 bullet** (currently lines 884–885). Replace:

```text
- Team/shared vaults, which would need a key-sharing design the current format anticipates
  (per-item subkeys) but does not implement.
```

with, if a milestone is scheduled:

```text
- ~~Team/shared vaults~~ Scheduled as M9 — see
  [ADR-0035](decisions/0035-shared-vaults.md) and the M9 section above.
```

or, if it is not yet scheduled:

```text
- Shared vaults — a small group, or one person's several computers, sharing a vault by
  exchanging signed, encrypted files out of band, with no networking. Designed in
  [ADR-0035](decisions/0035-shared-vaults.md) (accepted); not implemented.
```

**3. The "Sync" subsection** (currently lines 872–875). Append one sentence:

```text
Shared vaults ([ADR-0035](decisions/0035-shared-vaults.md), accepted) make an existing file sync
safe for several writers by merging exchanged copies instead of replacing the file; they do not
add a sync service.
```

**4. Where a milestone slots in.** After M8, and after the implementation of ADR-0039 and
ADR-0040, which it depends on (both implemented on `main` without a milestone number of their own).
The next free number is M9, unless [ADR-0036](0036-agent-requested-browser-fill.md)'s milestone is
scheduled first. Proposed table row:

```text
| M9 | Shared vaults (offline, file exchange) | M1, M3, M4, M8; ADR-0039/0040 implemented | proposed |
```

and a milestone section whose acceptance criteria are the Phase 1–5 test lists above, plus:

```text
- [ ] Two replicas edited offline and exchanged in any order, any number of times, converge to the
      same state, and no value present in either is lost.
- [ ] A removed device's records created after the cut are rejected on every replica.
- [ ] The rotation list for a removed device matches, exactly, the set of current values encrypted
      under an epoch wrapped to it — including values written late under a stale epoch.
- [ ] No MCP tool and no IPC message can add a device, change a role, import, export or resolve a
      conflict; asserted by test.
- [ ] A value seeded into a shared vault never appears in any byte the sidecar writes (the ADR-0002
      canary, extended).
- [ ] No crate and no part of the app gains a network-capable dependency or a socket other than
      the existing local ones; asserted by a dependency check.
```

## Addendum, 2026-09-27: implementation decisions, corrections and the encoding contract

As Phase 0 begins, this addendum settles every open question this ADR left, records the decisions
implementation needed that the ADR did not anticipate, corrects five places where the ADR's text no
longer matches the code it is decided against, reorders the phases against what already exists on
`main`, and fixes the exact byte-level encodings — domain-separation strings, derivations, limits
and magic — that later phases' golden vectors depend on getting right once. The format's own
description stays in §3–§7 above; this addendum is the contract for building it.

### Two findings that reshape the plan before any of it

The code this ADR is decided against has moved since 2026-09-26. Two findings matter enough to
state up front, because everything below follows from them:

- **Most of §16's format migration is already built.** `Body` and `Header`
  (`crates/kagisecure-core/src/vault/mod.rs`, `vault/header.rs`) already carry
  `#[serde(flatten)] unknown: BTreeMap<String, ciborium::Value>` and a `body.schema` field, landed
  in commit 447a325 ("fix(core): preserve vault fields this build does not understand") —
  unreleased. §16's text describing this as not yet done (Correction A below) is stale. What is
  *not* built, and remains this plan's own Phase 0 work, is the `format_ver` bump itself: released
  version 0.1.1 predates the passthrough fix, so a 0.1.1 build that opens a vault holding device
  keys under `format_ver` 1 would still silently drop them on its next save. The bump protects
  exactly those users; it does not need to add passthrough that already exists.
- **ADR-0039's primitives are not reusable as written.** `Vault::transact` (ADR-0039) is typed to
  the personal vault's header/body pair; `lock::VaultLock` is `pub(crate)`; `write_atomically` is a
  private function inside `vault/mod.rs`. A shared vault's replica is a different file with a
  different header, so Phase 0 must lift the lock and the atomic write out of the personal-vault
  module into primitives both can call, before Phase 2 builds a replica on top of them
  (Correction B).

### 1. Open questions resolved

1. **HPKE implementation (OQ1):** the `hpke` crate, version `0.14.1`, `default-features = false`,
   features `alloc`, `x25519`, `chacha` — RFC 9180 Base mode, DHKEM(X25519, HKDF-SHA256) /
   HKDF-SHA256 / ChaCha20-Poly1305. Not composed by hand from `x25519-dalek`: the crate's
   dependency versions line up with the workspace's existing RustCrypto crates closely enough that
   `cargo deny`'s `multiple-versions = "warn"` is not expected to fire, and a maintained
   implementation of a published standard is preferred over a hand-composed one even when both
   claim the same construction. Randomness comes from `kagisecure-core`'s own RNG rather than
   pulling in `getrandom` a second way (see "Encoding contract" below); not independently audited,
   recorded the way W-6 records the RustCrypto AEAD audit.
2. **Roles (OQ2):** kept as three — `admin`, `writer`, `reader` — as designed in §6. `reader`'s test
   surface is accepted as the cost of a role a departed member's remaining permissions can be
   checked against explicitly, rather than folding it into `writer`.
3. **Self-enrollment (OQ3):** no. Only an admin device may add a device, for any member. §11's "a
   member's existing device may add a device for the same member" is not implemented in this plan;
   every roster-changing action in the app and the CLI requires an admin device, without exception,
   until a later ADR revisits it.
4. **Paper recovery recipient (OQ4):** not offered. A recipient that can decrypt every epoch with no
   password in front of it is a second master key, and this plan does not build one.
5. **Shared usage records (OQ5):** not offered. §15's "signed usage records prove use, never
   non-use" holds as written; no opt-in log is built.
6. **Admin agent-visibility ceiling (OQ6):** deferred, and where it lands is advisory only: an admin
   can be shown, in the app, whether any member's agent-visibility setting differs from a
   vault-wide recommendation, but nothing in Phase 4 lets one member's setting override another's
   device. Enforcement, if ever built, is a later ADR.
7. **History on add (OQ7):** a newly added device reads the shared vault's full history — every
   retired value an epoch it holds can decrypt — because the epoch chain (§3) makes anything less
   unavailable without re-encrypting older records, which §3 already rejects. Moving an item from a
   personal vault into a shared one drops its history: the new item record starts a fresh version
   graph with no parent, and the CLI and app say so before the move.
8. **Compaction (OQ8):** out of scope for this plan. The hard limits in the encoding contract below
   (record count, bundle and replica size) bound how much damage unbounded growth can do before
   compaction is designed; they are not a substitute for it.
9. **Post-quantum and Secure Enclave suites (OQ9, OQ10):** both deferred. The `suite` field on every
   device key and every shared vault (§4) is exactly what makes either additive later: a new suite
   value, not a format break. Nothing in this plan blocks on either.
10. **The `format_ver` lever (OQ11):** accepted as §16 describes it — stretching `format_ver`'s
    "byte layout changed" meaning to also mean "an older build must refuse this file outright" is
    deliberate, and is the only version check a shipped build performs. Shipping the passthrough fix
    alone, in a release of its own, before device keys ship, was considered and rejected: it would
    mean two releases where one delivers the whole protection, and 0.1.1 already predates the fix
    regardless of how many releases follow it.
11. **Group size (OQ12):** a stated ceiling, enforced, not merely assumed: 32 members and 64 devices
    per shared vault (see limits below).
12. **Name (OQ13):** "Shared vault," used throughout this ADR, is the name that ships — in the CLI,
    the app and this plan.

### 2. Decisions filling gaps the design left open

The ADR's mechanisms (§3, §6–§9) leave several questions unanswered that a working implementation
cannot leave unanswered. These are decided here, conservatively, so that Phase 1 onward has one
contract to build against:

13. **Acceptance rules for a record**, checked in this order, from the record set alone (no
    external state): it parses within the bounds below; its signature verifies for an author that
    is a device in the roster; its body's `vault_id` is the vault being read — the first thing
    checked about the body, by the verification itself, which is always told which vault the
    caller is reading and refuses a record naming any other, so the payload's AAD and record key
    are only ever built from that vault's id (amended 2026-09-27: a member of two shared vaults
    could otherwise replay another member's records from one into the other under a reused epoch
    id and key; and amended again the same day: the `vault_id` is read before the body's
    version, so another vault's record in a version this build does not know is refused as
    another vault's rather than making this one read-only); that author is not removed, not demoted below the role the record
    needs, and the record is not one that author's own cut (§11) excludes — all three judged at
    the roster the record's own heads reach, with the cuts those heads do not reach (amended
    2026-09-27, decisions 45, 66); the record's named
    parents, roster heads and epoch all exist in the state already accepted; its payload's AAD
    decrypts; its `prev`/`seq` chain is consistent with every other record already accepted from
    that author. A record that fails any check is either pending (kept, in case a record it depends
    on arrives later) or rejected outright (a bad signature, an impossible chain); never silently
    dropped.
14. **Epoch identity** is a 16-byte `epoch_id` plus a `height`, not the sequential epoch
    number `e` §3's formulas write for readability — see Correction E. The id is derived from the
    record that mints the epoch, not drawn at random (amended 2026-09-27, decision 67).
15. **Item and environment records carry a `roster` heads field separate from `parents`.** `parents`
    names the version graph the record edits; `roster` names the roster state its author's role was
    checked against. Conflating them (as §6's prose sketch does) makes "which roster state does
    this record's authority come from" depend on which version graph it happens to touch — see
    Correction F.
16. **A role downgrade (admin → writer, writer → reader) carries a cut**, exactly as removal does
    (§11): a record from the downgraded device dated after the downgrade, using authority it no
    longer has, must be checked against the roster state that already reflects the downgrade, not a
    later one it could try to point past.
17. **Automatic three-way merges (§8) write no record.** Two heads that merge without conflict do
    not mint a synthetic "merge" record; the next genuine edit simply names both heads as its
    `parents`, and the merge is recomputed by every replica from the same rule, not stored.
18. **A record rejected because a cut arrived after it was already accepted somewhere is listed as
    "reverted by removal,"** not silently dropped and not treated as a conflict requiring a human's
    value choice — see Correction I.
19. **Equivocation (§6, two records from one author at one `seq`) is flagged on every replica that
    has seen both, and both are kept** — neither is preferred over the other by any rule, including
    arrival order.
20. **An unknown record `kind` is kept and forwarded byte-for-byte** (§16 rule 1, already the ADR's
    position); an unknown roster or epoch *op* makes the vault read-only for that build, because
    computing membership from an operation the build cannot interpret is worse than refusing to
    write.
21. **Vault id is 16 random bytes**, usable directly as a `VaultId`, generated once at genesis and
    carried in the header of every file type below; the vault's display name lives in the
    (encrypted) genesis record, and renaming is not supported in v1.
22. **Local-only state, held in the replica's local section (§15) and never exported under any
    circumstance:** agent visibility per item, favourites, an environment's `default_paths`, which
    item/environment versions this device has approved for release, "verified by me" state, the
    configured exchange directory, this device's own highest written `seq` (the rollback guard,
    §9), and TOFU state (§10). None of these fields ever appears in a bundle or an
    exchange-directory file.
23. **The replica lives at `<personal vault file>.shared/<32 hex vault id>.kagishared`**, alongside
    a `.lock` file of its own, under the same directory permissions (`0700`) the personal vault
    already uses.
24. **Shared releases are logged in the personal vault's own audit log, carrying the shared vault's
    `vault_id`** — not in the replica, which has no audit log of its own — because `audited_release`
    (ADR-0040) is already tied to the personal vault handle, and giving the replica a second log
    would mean two logs to keep consistent under one lock order for no benefit over the one that
    already exists. See Correction D.
25. **A new IPC and extension-protocol error code, `UNRESOLVED_CONFLICT`**, refused before the
    approval sheet is shown and re-checked inside the release itself, for any request that would
    release a conflicted field (§8). (Superseded on 2026-09-27 by decision 80: the merge is
    last-writer-wins and leaves no conflicted field, so `UNRESOLVED_CONFLICT` and every plan to
    refuse a release on it — in the IPC, the extension protocol and the approval sheet — are
    withdrawn.)
26. **"Changed since [this device] last approved" is tracked per field or per environment variable,
    not per item**; a field never approved for release before counts as changed, so the very first
    release of a shared value always shows its author.
27. **An agent's request to write to a shared vault (`create_environment`, `add_variables` targeting
    a shared environment) is refused with `INVALID_ARGUMENT` and one fixed sentence**, not a new
    error code of its own — §14 already says agents cannot write to a shared vault; this is how that
    refusal surfaces.
28. **Item-id collisions across vaults:** a personal-vault item wins over a shared item with the
    same id; a collision between two *different* shared vaults' items hides both from every
    agent-visible listing, rather than picking one arbitrarily.
    (Amended 2026-09-27 by decision 89: kept for ids; two entries with the same *name* are both
    listed, the shared one qualified by its vault's name.)
29. **No roster-changing or admin command has a daemon or IPC path, and none is ever
    auto-approved.** Creating a vault, adding or removing a device, changing a role, joining,
    importing or exporting all require the personal vault's password (or platform unlock) on that
    run, in the CLI or the app, never through the daemon; verified enrollment additionally requires
    a full `--expect-fingerprint`, never a partial one.
30. **Hard-to-rotate kinds (§12), for the rotation list:** TOTP seeds and the concealed fields of
    SSH-key items. Both need action at the far end (re-enrolling a second factor, replacing a key
    pair) that rotating the shared vault's epoch key cannot do by itself.
31. **Golden vectors are committed in the step that introduces them and never edited afterward.** If
    a later step needs a golden vector's format to change, that is escalated to whoever is reviewing
    this plan, not silently patched.
32. **Threat-model numbering:** none of the numbers "Changes in the threat model" above already
    assigned (A9–A11, TB-5–TB-6, T-12–T-14, M-22–M-28, W-12–W-17) need to change for anything in
    this plan. If a later phase needs a new entry, its number is allocated at merge time, not
    reserved now — another ADR drafted separately may already claim a nearby number by then — and
    any new ADR this plan's work spawns is numbered 0043 or higher.

### 3. Corrections to this ADR's own text

A. **§16's claim that `Body`/`Header` lack unknown-key passthrough is now stale.** Passthrough and
   the `body.schema` field exist on `main` (commit 447a325, unreleased). What §16 still gets right,
   and what remains this plan's Phase 0 work, is the `format_ver` bump itself: a released 0.1.1
   build predates the passthrough fix and needs the version bump to refuse a device-key-bearing
   file rather than silently damage it, exactly as §16 describes the bump's purpose — only its
   premise about the current state of `Body`/`Header` needed updating.

B. **ADR-0039's `transact`, `VaultLock` and `write_atomically` cannot be reused as this ADR implies**
   (§1, "written with ADR-0039's lock and transaction like any vault file"): `transact` is typed to
   the personal vault's header/body pair, `VaultLock` is `pub(crate)` to `kagisecure-core`, and
   `write_atomically` is a private function. Phase 0 exposes the file lock and the atomic write as
   reusable primitives (a public `FileLock`, a public `atomic` module) before Phase 2 builds the
   replica on them; the replica does not call `Vault::transact` itself, and its own transaction adds
   the union-merge semantics §8 needs on top.

C. **The phase order in "Implementation plan" above does not match what the CLI and its
   cross-process tests need.** The Phase 2 CLI commands and their cross-process convergence tests
   cannot be written or tested without device keys existing and without a device being able to join
   a vault at all — both filed under Phase 3 above. This plan moves the device-key list and its
   `format_ver` migration into Phase 0, and moves enrollment requests and invitations (the mechanics
   of joining and adding a device) into Phase 2, alongside the CLI and cross-process tests that
   exercise them. Phase 3 keeps only the verification layer on top: full-fingerprint comparison,
   `--expect-fingerprint`, and TOFU labelling — the parts of §10 that are about trusting a key
   already exchanged, not about exchanging one.

D. **§15 describes a replica-side audit log this plan does not build.** "What this computer
   released… stays in the local-only section of this device's replica, with the same schema as
   vault-format.md §8" is corrected to: shared releases are logged in the *personal* vault's own
   audit log, tagged with the shared vault's `vault_id`, because `audited_release` (ADR-0040) is
   already tied to the personal vault handle, and a second log living in the replica would need its
   own lock ordering and its own continuity story for no benefit over the one that already exists.

E. **§3's `epoch key EK_e … one per epoch e` formula, read literally, breaks under concurrent
   rotation:** two devices that each mint a new epoch at the same time, both reasonably numbering it
   "the next one," cannot use a sequential integer to identify which is which without a coordinator
   to hand them out, which this design does not have. Epoch identity is a random 16-byte `epoch_id`
   plus a `height` (§2 item 14 above); the chain and commitment formulas in §3 and in the encoding
   contract below use `epoch_id`, not `e`.

F. **§6's `parents` field is asked to mean two different things** — the version(s) an item or
   environment record edits, and the roster state its author's authority is checked against — which
   lets an author pick a stale roster state to justify a record editing a current version, or vice
   versa. Item and environment records carry a separate `roster` heads field for the second meaning
   (§2 item 15); `parents` keeps its one meaning, the version graph.

G. **§6's record layout needs the author available before the payload is decrypted, for
   verify-before-decrypt (§6, "signing the ciphertext lets a reader verify a record before
   decrypting"), but a naive envelope that signs the whole record including its own author field
   does not obviously support reading the author out first.** The envelope (encoding contract below)
   places `author` as a plaintext field of the outer CBOR array, outside what is encrypted, and the
   signature covers it directly; a reader reads `author`, verifies the signature over the exact
   bytes that produced it, and only then decrypts, in that order, with no chicken-and-egg step.

H. **§9's claim that rollback of a device's own replica is guarded by "checking its configured
   exchange location for higher `seq` records" is true only when a configured exchange directory
   exists and is checked before writing;** a device that writes with no exchange directory
   configured, or that skips the check, has no guard until ADR-0041's anchor exists. §9 and
   threat-model W-13 are corrected to say this plainly rather than implying the check is
   unconditional.

I. **§11's "replicas that had accepted [a reverted record] show the reverted field as a conflict"
   requires a replica to remember that it once accepted something it no longer does — state this
   design otherwise avoids keeping.** It is replaced by a "reverted by removal" notice (§2 item 18):
   computed fresh from the current record set (the cut plus what depends on it), not from any
   replica's memory of an earlier state, so every replica that recomputes its view independently
   reaches the same notice without needing history of its own prior views.

### 4. The encoding contract

Every domain-separated string, derivation and limit below is exact and frozen from the moment the
golden vector that exercises it is committed (decision 31); a later step that needs one of these to
change stops and escalates rather than silently editing a committed vector.

- **Device key id:** `DeviceKeyId = SHA-256("kagisecure/shared/device/v1" ‖ 0x00 ‖ suite ‖ 0x00 ‖
  kem_pk ‖ sig_pk)`, where `suite` is the suite's ASCII name (e.g. `x25519-ed25519-v1`) and
  `kem_pk`/`sig_pk` are the device's raw public keys.
- **Fingerprint:** the first 20 bytes of the device id, read as ten big-endian `u16`s, each rendered
  as five zero-padded decimal digits and space-separated — ten groups, read aloud or compared side
  by side (§10). The QR payload is `kagisecure-fp:1:<64 lowercase hex characters>` of the full
  32-byte device id.
- **Record envelope:** a CBOR array `[v, author(32 bytes), body(byte string), sig(64 bytes)]`. The
  signed message is `"kagisecure/shared/sig/record/v1" ‖ 0x00 ‖ author ‖ body`;
  `record_id = SHA-256(signed message ‖ sig)`. `author` sits outside the signed body itself but is
  fed into what the signature covers, which is what makes Correction G's verify-before-decrypt order
  sound.
- **Epoch wrap:** HPKE `info = "kagisecure/shared/epoch/v1" ‖ vault_id(16) ‖ epoch_id(16)`, empty
  AAD.
- **Record key:** `HKDF-SHA256(EK, salt = record_salt, info = "kagisecure/shared/record/v1" ‖
  vault_id)`.
- **Epoch chain key:** `HKDF-SHA256(EK_new, info = "kagisecure/shared/chain/v1" ‖ vault_id ‖
  new_epoch_id)`, sealing `EK_old` with AAD `vault_id ‖ new_epoch_id ‖ prev_epoch_id`.
- **Epoch commitment:** `HKDF-SHA256-expand(EK, "kagisecure/shared/epoch-commit/v1" ‖ vault_id ‖
  epoch_id)` — a value every device holding the epoch key can recompute and compare, catching a
  garbage wrap before it is trusted.
- **Payload AAD:** CBOR array `["kagisecure/shared/payload/v1", vault_id, author, kind, parents,
  roster, epoch_id]`.
- **Local-section key:** `HKDF-SHA256(device secret bytes, info = "kagisecure/shared/local/v1" ‖
  vault_id)`.
- **Limits, enforced before any decode of a length-bearing field:** a record, 1 MiB; `parents`, 16
  entries; roster heads, 16 entries; devices per vault, 64; members per vault, 32; a bundle, 256 MiB
  or 200,000 records, whichever is hit first; a replica file, 256 MiB; pending (unresolved) records
  held per replica, 10,000; an enrollment request or invitation file, 64 KiB; a member or device
  label, 128 characters.
- **File magic**, each file type's first 8 bytes: replica `KAGISHR\0`; bundle `KAGISBN\0`; exchange
  directory descriptor `KAGISXD\0`; enrollment request `KAGISRQ\0`; invitation `KAGISIV\0`.

Every `‖` above is plain byte concatenation, and every domain-separation string is ASCII, with no
byte beyond the explicit `0x00` separators shown.

This addendum does not change the Decision, the threat-model entries, or the Consequences recorded
above; it is the contract Phase 0 onward builds against, and later phases inherit its numbering
(decisions 1–32, corrections A–I) when they cite a choice made here.

### 5. Decisions made while building Phase 1

The encoding contract above fixes the strings and derivations; building Phase 1 against it met
the points below that it leaves open. Each is decided the conservative way and numbered on from
decision 32, and each is pinned by the golden vector or test named with it.

33. **Deterministic CBOR, refused otherwise, and a device's public keys as a closed map.**
    Everything this format signs, hashes or compares as bytes is written in RFC 8949 §4.2.1's
    core deterministic encoding (shortest integers and lengths, definite lengths, map keys in the
    bytewise order of their encodings, no key twice), and a reader **refuses** any other encoding
    rather than normalising it: two readers that disagree about what a signed byte string says is
    how one signature comes to vouch for two things. Input is scanned before it is decoded — one
    linear pass over the heads, copying nothing, refusing a length or count larger than what is
    left, an indefinite length, a head not in its shortest form, nesting deeper than 64, a key
    twice, keys out of order and trailing bytes — and only then decoded, re-encoded and compared
    (amended 2026-09-27). A device's public keys are the map
    `{"suite": text, "kem_pk": bytes(32), "sig_pk": bytes(32)}` with exactly those keys — a key
    this build does not know could change what the device key means, so a later need is a new
    suite, not an extra key (`crates/kagisecure-shared/tests/vectors/device-v1.cbor`). "Strict"
    for a device's public keys means: the X25519 key is a canonical field element (below
    2^255 − 19, top bit clear) and not of small order on the curve or its twist; the Ed25519 key
    decompresses, re-encodes to the same bytes, is not of small order, and is torsion-free — in
    the prime-order subgroup, with no small-order component for cofactored and cofactorless
    verifiers to disagree about (amended 2026-09-27). Both are checked when the key is read,
    before anything is wrapped to it or verified with it.
34. **Every signature is domain-separated the same way.** A signed message is always
    `domain ‖ 0x00 ‖ …`, where `domain` is an ASCII string of the form
    `kagisecure/shared/sig/<purpose>/v1`; the record's is the contract's
    `kagisecure/shared/sig/record/v1`. The enrollment request's self-signature and the
    invitation (Phase 2) each get their own string of that form when they are built, and no two
    purposes ever share one. What follows the separator is framed so that it has one reading:
    every part but the last is fixed-length or length-prefixed, and structured data is signed as
    one deterministic-CBOR part — never two variable-length byte strings written back to back,
    whose boundary a verifier could not see. The record's content is the fixed 32-byte author id
    and then the body, the one tail, so its message is unchanged. The code signs only a typed
    per-purpose content (`sign::Signed`), with no way to sign loose parts (amended 2026-09-27).
    Verification is always `verify_strict`.
35. **An epoch wrap is 80 bytes, and HPKE's randomness is drawn from the core first.** A wrap is
    HPKE's `enc` (32 bytes), then the sealed epoch key (32), then the tag (16). `hpke` is built
    without `getrandom`; each wrap draws 32 bytes from `kagisecure-core`'s generator into a
    buffer and hands `hpke` only that. Reading `hpke` 0.14.1 confirmed that Base-mode setup draws
    randomness only for the ephemeral key pair, filling exactly `Nsk` = 32 bytes in one call and
    running RFC 9180 `DeriveKeyPair` over them; the RFC 9180 A.2.1 test prefills the RFC's `ikmE`
    and gets the RFC's `enc`. The buffer panics if asked for more than it holds rather than
    produce anything predictable, so a future `hpke` that draws differently fails its tests
    instead of weakening a wrap.
36. **The symmetric pieces the contract names without an encoding.** Every key is 32 bytes, and
    every AEAD is XChaCha20-Poly1305 (the personal vault's, §4) with a fresh random 24-byte nonce
    written in front of its ciphertext and tag. A **record key** is HKDF-SHA256 with the record's
    16-byte `record_salt` as salt, and what it seals is `nonce ‖ ciphertext ‖ tag`. The **chain
    key** is HKDF-SHA256 with no salt, and a chain link is `nonce (24) ‖ ciphertext (32) ‖ tag
    (16)`, 72 bytes. The **commitment** is 32 bytes of HKDF-Expand with the epoch key itself as the
    pseudorandom key (the contract's "expand"), and is compared in constant time.
37. **The record envelope has one encoding, read by hand within bounds.** The envelope is the
    contract's `[v, author, body, sig]` with `v` = 1, every CBOR head in its shortest form and a
    definite length, and nothing after it; the 1 MiB limit applies to the whole envelope and is
    checked before a byte is read, and every length is checked against what remains before
    anything is sliced. An envelope version other than 1 is refused by name (the bytes are the
    caller's to keep), as is a body version other than 1 after the signature verifies. The order
    is fixed: parse the envelope, check that the named author is the key being used, verify the
    signature over the exact bytes, and only then decode the body — as a body of the vault the
    caller names, refusing any other `vault_id` before its other fields are checked (decision
    13) (`crates/kagisecure-shared/tests/vectors/record-item-v1.ksr`).
38. **The record body's fields, all always present.** The body is a deterministic CBOR map with
    the text keys `v`, `kind`, `vault_id` (16 bytes), `seq`, `prev` (32 bytes, or null exactly
    when `seq` is 0 — an author's counter starts at 0), `parents` and `roster` (arrays of 32-byte
    record ids, at most 16 each, counted from the encoded body's array heads during the scan,
    before the body is decoded — amended 2026-09-27), `epoch` (16 bytes, or
    null; required for `item` and `env`), `created_at`, `record_salt` (16 bytes) and `payload`
    (bytes). `kind` is the text `roster`, `epoch`, `item`, `env` or `ack`; any other kind, and any
    other key, is kept as read and forwarded untouched (decision 20), but this build writes only
    the kinds it knows. An `item` or `env` payload is the record key's seal (decision 36) under the
    contract's payload AAD, whose `kind` is that text and whose ids are the raw bytes above.
39. **What an item or environment record carries.** Its plaintext is `{"id": ItemId, "item": Item
    | null}` or `{"id": EnvId, "env": Environment | null}`, with the item or environment encoded
    exactly as the personal vault's body encodes it (vault-format §5), and `null` meaning deleted.
    That encoding is `serde`'s — map keys in field order, and an indefinite-length map for a
    struct with flattened unknown keys — so it is not deterministic CBOR and is not required to
    be, but it is read strictly: scanned before it is decoded, and refused unless it is exactly
    one well-formed item with shortest heads, no key twice in any map and nothing after it, so no
    two readers can take a repeated key two ways (amended 2026-09-27). Its `vault_id` is the
    shared vault's on writing and must be on reading. The local-only fields
    of decision 22 that live on the item and environment themselves — `agent_visible` (item and
    each field), `favorite`, and an environment's `agent_visible` and `default_paths` — are
    cleared on writing, so they never leave the device, **and again on reading**, so a record from
    an older or hostile build cannot make anything visible to this device's agents. A key of the
    outer map this build does not know is ignored; the item's and environment's own unknown keys
    survive as they do in the personal vault.
The roster (step 9) met the points below, decided the same way and continuing the numbering.

40. **Roster operations and their encoding.** A roster record's payload is one deterministic CBOR
    map: `"op"` (text) and exactly that operation's fields — `genesis` {`suite`, `member`,
    `device`, `labels`}, `add-member` {`member`, `role`, `labels`}, `add-device` {`member`,
    `device`, `verified`, `labels`}, `remove-device` {`device`, `cut`, `reason`},
    `remove-member` {`member`, `cuts`, `reason`}, `set-role` {`member`, `role`, `cuts`}. A member
    id is 16 random bytes and is never reused; `device` is decision 33's closed map; `role` is
    `admin`, `writer` or `reader`; `verified` is `in_person`, `voice` or `unverified` (§10);
    `reason` is `left`, `retired` or `compromised`; `labels` is null or an opaque byte string of
    at most 4096 bytes — the encrypted member, device and (in the genesis) vault names of §6 and
    decision 21, whose sealing is decided by the first step that writes them; nothing about the
    roster depends on them. A cut is `{"device": bytes(32), "through": null | {"seq": uint,
    "record": bytes(32)}}`: the device's records on its own `prev` chain up to and including that
    record, or none — a chain position rather than a list of ids, so it is bounded, and accepting
    a record accepts exactly the records it names as `prev`, never another branch of an
    equivocating chain. `cuts` are in strictly increasing device-id order, at most 64. An `op`
    this build does not know, or a known one with a field, role, reason, verification or device
    suite it does not know, is *not understood*: kept, never applied, and — written by an admin
    with authority at that point — makes the vault read-only for this build (decision 20). A
    known `op` with a missing or ill-shaped field is void. No roster record names `parents`;
    every one but the genesis names at least one roster head
    (`crates/kagisecure-shared/tests/vectors/record-roster-genesis-v1.ksr`).
41. **The genesis is named, not found.** A roster is computed from the genesis record id the
    caller holds — the replica's own header, or an invitation whose signature verified — and a
    missing or invalid one is an error, never a fallback to another record. **Never from an
    exchange directory's descriptor** or anything else the exchange channel carries unsigned
    (amended 2026-09-27): the vault id is random and not bound to the genesis, so whoever can
    write to a sync folder can sign a valid genesis of their own for the same vault id, and only
    a source this device trusts can say which genesis is the vault's. (Deriving the vault id from
    the genesis instead would bind them in the format itself; it was weighed and not chosen now,
    because pinning from the header and the invitation already covers every path a device joins
    by, and the derivation would reshape every record and test for a second line of the same
    defence.) The genesis is the one record whose key is read from its own body before its
    signature is checked: the device it introduces must have the envelope's author id, a
    SHA-256 of that very key, so nothing read before verification can vouch for anything else,
    and the body and its operation are decoded again from the verified record after, and must
    read the same. It must be its author's `seq` 0, of this vault, with no parents or roster heads,
    introducing a device of the suite it names; its member is an admin; every device added later
    must be of that suite. Any other genesis is void, and the genesis itself is never voided by a
    cut.
42. **What is checked before the rules.** Records are verified as their authors become known —
    the genesis's device, then each device a verified roster record introduces — and the first
    thing checked about a verified body is that its `vault_id` is this vault's: a record of
    another vault is void, and no key is ever learned from one. A record whose author is not
    known, whose roster heads are missing or pending (a roster record pending on a cut not yet
    decided included — it grants nothing until the cut is decided; amended 2026-09-27), or whose
    `prev` chain does not reach `seq` 0
    through present, verified records of its own author is pending; a `prev` that is another
    author's record, not one `seq` lower, or a refused record is a broken chain, and void. A
    roster head that is a record of another kind is void. Naming a *void* roster record as a
    head is allowed: whether a roster record applies is decided by the linear order, not by which
    heads it names.
43. **One order, and cuts enforced across it.** Roster records are ordered by Kahn's topological
    sort over their roster heads, the genesis first, ready records taken by their author's
    device id, then `seq`, then record id. (Amended twice on 2026-09-27. First: record id alone
    was grindable. Second, decision 70: a device id is a hash of keys its owner generated, so it
    is grindable too, at enrollment; the order is therefore given no say in anyone's authority.)
    Every roster operation needs an active admin device (decision 3). A removal or downgrade
    that applies puts a cut in force on each device it concerns — a device the record gives no
    cut for keeps none of its records, and every device ever added for a removed or demoted
    member is concerned — and a roster record of those devices beyond the cut is void,
    **except**: a record in the closure of the cutting record's own heads, which its author saw
    and built on (a removal could otherwise void the records that made its own author an admin
    and so void itself); the other half of a mutual removal (decision 65); and a record whose
    own heads reach an applied removal or demotion of the cutting record's author (decision 71).
    A removal is never beyond its own cut. These are decided by rules, record by record, once
    what each depends on is decided — never by applying records in the order and taking them
    back later — so a record voided by a cut is void exactly while that cut's record applies
    (decision 70; the earlier "monotone voiding across restarts" is withdrawn, since it let the
    order decide). A compromise cut voids roster records beyond it like any other, so §11's
    "roster review" is the list of those void records rather than records an admin must revert
    by hand — except the ones the removal was built on, which the roster reports (decision 74)
    and its author reverts by hand if it should not have. A record voided by a cut is always
    concurrent with the record carrying it — neither built on the other — and is reported as
    decided by rule, so the survivor can be asked to confirm (§6).
44. **Membership rules.** A member id and a device id are each added once: a removed device
    cannot return under its old key. A device that shares either public key with any device ever
    added is refused, as is one of another suite or for a member not in the roster. The limits
    count what is in the roster at that point: 32 members, 64 devices. Removal and `set-role`
    apply only to an active member or device; setting a member's current role is void; an
    upgrade carries no cuts; every cut names a device of that member. Removing or demoting the
    last admin is computed like anything else, with a warning ("no admin device", and "single
    admin device" when one is left, §13); refusing to write it is the writing command's job.
45. **The authority of every other record.** An item, environment, epoch or acknowledgement
    record's author holds, for that record, the role their device has in the roster as of the
    roster heads the record names — the applied roster records among those heads and their
    ancestors (never a void or pending one), replayed in the linear order. That role is then
    lowered to a downgrade's new role for every downgrade cut the record lies beyond **and its
    heads do not reach** — a device demoted and then promoted again holds, for a record naming
    the promotion, the role the promotion gives (amended 2026-09-27); beyond a removal's cut
    the record is void,
    and where a cut cannot be decided yet (its point is not in the set) it is pending. Naming
    older heads therefore never restores authority a cut took away (decision 16), and naming
    newer ones never grants authority the author did not have.
46. **A record in a body version this build does not read** is kept and forwarded like a record
    of an unknown kind (decision 20); written by a device that is an active admin, it also makes
    the vault read-only for this build, since it may be a roster change.

Epochs (step 10) met these, continuing the numbering.

47. **Epoch operations and their encoding.** An `epoch` record's payload is `{"op": "new",
    "epoch_id": bytes(16), "height": uint, "wraps": {device id bytes(32): wrap bytes(80), …},
    "chain": [{"prev": bytes(16), "seal": bytes(72)}, …], "commitment": bytes(32)}` or
    `{"op": "grant", "epoch_id", "wraps"}`; an `ack` record's is `{"op": "ack", "epoch_id"}`.
    Deterministic CBOR throughout: `wraps` is a map keyed by device id, so one wrap per device in
    id order, between 1 and 64 of them, counted before any is read; `chain` links are in strictly
    increasing `prev` order, at most 16, and present exactly when the height is not 0. The
    record's body names the operation's epoch as its `epoch`, names roster heads, and names no
    `parents`; an operation in the other kind of record is malformed. An unknown `op`, or a known
    one with a field this build does not know, is not understood and — from a writer or admin
    with authority — makes the vault read-only for this build (decision 20)
    (`crates/kagisecure-shared/tests/vectors/record-epoch-new-v1.ksr`, the creation epoch of
    the genesis vector's vault).
48. **Which epoch records are accepted.** `new` and `grant` need a writer or an admin, with
    authority as decision 45 computes it — rotation needs no special authority (§11) — and `ack`
    any member. Every wrap must be to a device in the roster as of the record's roster heads; a
    record wrapping to anyone else is void, which is what keeps an epoch minted by a writer that
    has seen a removal from reaching the removed device. (Amended 2026-09-27: a writer naming
    older heads can still wrap to a device removed since; that is why the current epoch's
    exposure is judged against the roster now (decision 50), and item acceptance (Phase 2) must
    flag a record written under an epoch whose recipients include a device removed by a removal
    its heads do not reach.) Height 0, with no chain, is the creation epoch alone:
    written by the genesis device, naming the genesis as its only roster head. Any other `new`
    chains to one or more accepted epochs and is higher than all of them — not necessarily by
    one, so that a rotation can take a height above an epoch it cannot chain to (below), but by
    at most `MAX_EPOCH_STEP` (decision 68). A writer
    chains to every epoch head it holds, which rejoins concurrent rotations. A `new` whose
    `epoch_id` is not the one its record derives is void (decision 67). Two accepted `new`
    records claiming one `epoch_id` — possible now only when one author equivocates — void each
    other, whatever their commitments, but not the epochs others built on them (decision 76). A record about an epoch no record introduces, or one
    still pending, waits.
49. **An epoch key is trusted only against its commitment.** A device holds an epoch's key when a
    wrap addressed to it — the `new` record's, then each valid grant's in record-id order —
    unwraps to a key that matches the epoch's commitment (compared in constant time), or when a
    chain link of an epoch it holds opens to a key matching the previous epoch's commitment. Both
    comparisons are made inside the operations that produce the key — the unwrap and the chain
    opening each take the commitment — so no caller ever holds a key that was not checked
    (amended 2026-09-27). A wrap that fails either way is ignored ("bad wrap"). A chain link that fails marks its epoch
    *rejected* on that device: the epoch's own key, which matched its commitment, still reads
    what was written under it, but nothing is derived through its chain and nothing is written
    under it. Holders of the right key all reach the same verdict on a chain, since the seal and
    the commitment are the same for every recipient.
50. **The current epoch, and when to rotate.** The current epoch is the accepted epoch of greatest
    height, ties broken by the smaller jump above the epochs it chains to, then the smallest
    minting device id and `seq` (amended 2026-09-27: not the record id, which a writer could
    grind; decisions 68, 76) — a public rule, the same on every
    replica whether or not it holds the key. A new epoch is needed when there is none; when the current epoch's
    recipients (its wraps and its valid grants') include a device no longer in the roster, so a
    removal is finished only when an epoch not wrapped to the removed device is current; or when
    this device was sent the current epoch's key and could not trust it (a bad wrap or a rejected
    chain). A new epoch takes a height one above every accepted epoch's, so it becomes current
    even over an epoch nobody can use — within the bound of decision 68, which may take a
    second rotation. An active device with no wrap of the current epoch needs a
    grant, not a rotation; the devices that have not acknowledged the current epoch (its minter
    counts as having done so) are listed for the removal screen (§9).

60. **Bundle byte layout, beyond the contract's magic.** A bundle is the contract's `KAGISBN\0`
    magic, then a one-byte version (`1`), then a big-endian `u32` record count — refused above
    `MAX_BUNDLE_RECORDS` (200,000, the contract's bundle limit) before a single record is read —
    then that many records, each a big-endian `u32` length (refused above the contract's 1 MiB
    record limit before it is sliced) followed by exactly that many bytes, read as one envelope
    the way `record::Envelope::parse` reads one. The count and length fields are plain integers,
    not CBOR: nothing about the container itself is signed or hashed, so it needs only bounds
    checked before the bytes they name are read, not the record format's deterministic-encoding
    discipline (`crates/kagisecure-shared/src/bundle.rs`).
61. **A bundle's records are always written sorted by id, ascending, with duplicate ids collapsed
    to the first one given.** Two callers handed the same record set in a different order, or one
    that repeats a record, produce byte-identical bundles either way; a bundle read back is
    deduplicated and sorted the same way on the way in, whether or not the writer that produced it
    did the same.
62. **An exchange-directory import that finds a file that is not exactly what its name claims
    skips it, quietly.** A name other than `<64 lowercase hex>.ksr`, a file over the record size
    limit, one that does not parse as a record envelope, or one whose envelope's own id
    (`record::Envelope::id`) is not the id its name claims — a misnamed file — is excluded from
    what `exchange::import` returns, with the rest of the directory still read. No side channel
    reports which files were skipped or why: step 11's contract is that import returns envelopes
    only, and an accounting of what did not make it in is a later phase's, once there is a caller
    (an admin command's summary, say) that would use it.
63. **An exchange-directory export that finds its own name already taken succeeds without
    writing.** A record's file name is a hash of its own signed bytes, so a second export of the
    same record lands on the same name as the first; treating that as success, rather than an
    error, means a caller can re-export a record set it has already exported without first
    checking what is on disk. Whatever is already at that name — the same record, or (a tampered
    sync, a stale copy) something else entirely — is left exactly as it is either way: the
    create-new write (`kagisecure_core::vault::atomic::write_new_file`) never overwrites it.
    (Superseded 2026-09-27 by decision 75: a file under the name that is not the record is now
    replaced; one that is the record is still never touched.)
64. **The exchange directory's own bounded-scan limit is 200,000 entries**, the same order of
    magnitude as a bundle's record limit (decision 60) and for the same reason, but not added to
    the ADR-0035 addendum's encoding-contract limits list above: it bounds how much work one
    `exchange::import` call does against a directory grown unreasonably large, not a value this
    format ever hashes, signs or compares across replicas. Exceeding it refuses the whole scan
    outright rather than silently returning a partial, unannounced result. (Amended 2026-09-27:
    only records that are what their name claims count against it, so neither a directory
    stuffed with other names nor junk under record names blocks every import; entries of any
    kind are bounded separately, at eight times as many, and bytes read at 1 GiB in all. A file
    is opened with `O_NOFOLLOW | O_NONBLOCK` and read only if the opened handle is a regular
    file within the record limit, so a symbolic link or a FIFO planted under a record's name is
    neither followed nor waited on.)

Reviewing steps 9–11 found an attack on the roster and several weaker points; the owner decided
the first rule below (2026-09-27), and the rest follow from it or from the review.

65. **A removal always wins (the owner's rule).** Two removals or downgrades are *mutual* when
    each takes admin from the other's author — removes that device, removes its member, or
    lowers its member below admin — and neither record's heads reach the other. Both apply,
    never one of them by which record sorts first: neither author keeps admin, each is removed
    or demoted as the other's record says, and every other record of each author beyond the
    other's cut stays void. The roster carries a "removed each other" warning. If no admin
    device is left, the roster is **frozen**: no roster change can apply again, members keep
    reading and writing with the roles they hold, and a vault that must change again is
    re-created by one of them — which the interface says as plainly as that. This closes the
    counter-removal: an admin removed for being compromised answers with a removal of its
    remover, backdated to before its own removal (so beyond its cut) and with its record id
    ground, or published in equivocating variants, so that one sorts first. Under the old order
    rule its record applied first and voided the removal; now its own removal applies whatever
    the order, and the most it achieves is taking its remover's admin with it
    (`roster::tests::a_backdated_counter_removal_does_not_undo_the_removal_it_answers`).
66. **A roster record's authority is decided at its own heads; the order decides only what an
    operation lands on.** A roster record needs its author to be an active admin in the roster
    its own heads reach — the applied roster records in their closure — and not to lie beyond a
    cut on its author that those heads do not reach (a record whose heads reach the cut is
    judged by the roster there instead). Whether the operation makes sense — the member or
    device it names added and active — is checked at its own heads too; only a clash between
    concurrent operations — one member id or device added twice, a limit passed, two admins
    setting one member's role differently — is left to the linear order (decision 70). So a
    concurrent record a remover's cut accepts applies whatever order the two sort in, as item
    and epoch records already did (decision 45). (Amended 2026-09-27: this decision said the
    order was "no longer something an author can move" and that "an admin cannot choose how
    that falls". Both were wrong: a device id is a hash of keys its owner generates, so an owner
    can grind where its records sort. The order is now given no say in authority at all.)
67. **An epoch's id is derived from the record that mints it.** `epoch_id` is the first 16 bytes
    of `SHA-256("kagisecure/shared/epoch-id/v1" ‖ vault_id (16) ‖ author (32) ‖ seq (u64,
    big-endian))`, the minting record's vault, author and `seq`, and a `new` record whose
    `epoch_id` is not that is void on reading (`epoch::KeyRing::build`) and refused on writing
    (`EpochOp::sign`). With random ids, any writer could mint a `new` under an existing epoch's
    id — the creation epoch's, say — and, since two epochs claiming one id void each other, void
    it and leave every epoch chained to it waiting forever, so nothing could be read; removing
    the writer did not help, because the duplicate could sit within its cut. Now a second claim
    to an id can only be the same author writing twice at one `seq`, an equivocation that is
    flagged, and a removal whose cut goes through one of the two records restores the other.
    The golden epoch vector, `record-epoch-new-v1.ksr`, was committed earlier the same day with
    a fixed id and regenerated for this rule before any release (decision 31's "never edited"
    applies from release on).
68. **Epoch heights are bounded, ties are not grindable, and a device trusts only chains it
    verified.** A `new` epoch is at most `MAX_EPOCH_STEP` (2^16) above the highest epoch it
    chains to; above that it is void. Without a bound a writer could mint at the top of the
    height range, where no rotation can pass it and a tie went to the smallest — grindable —
    record id. The current epoch's tie-break is now the smallest minting device id, then `seq`.
    `next_height` is one above every accepted epoch but no more than the bound above the highest
    epoch this device holds, so an epoch minted as far above its chain as allowed, whose key a
    device cannot trust, is passed by that device's second rotation at the latest
    (`epoch::tests::epoch_heights_are_bounded_and_ties_are_not_grindable`). The epochs a new epoch
    chains to (`epoch_heads`) are the ones this device holds that no epoch whose chain it
    verified chains to: an epoch it holds no key of, or whose chain did not open to its previous
    epochs' committed keys, no longer hides the epochs it claims to chain to. And a device whose
    only wrap of the current epoch is one it could not trust — a grant of garbage — lists itself
    among the devices needing a grant; the others, who cannot tell, see it among the devices
    that have not acknowledged the epoch.
69. **An exchange directory on a file system without hard links still takes records.** The
    create-new write under `exchange::export` — `kagisecure_core::vault::atomic::write_new_file`
    — links a flushed temporary into place, which FAT, exFAT and some network and sync file
    systems refuse; it now falls back, on a link refused as unsupported or not permitted, to
    creating the file in place with `O_CREAT | O_EXCL` and the same owner-only mode, writing and
    flushing it, and removing it if the write fails. It never replaces anything either way. What
    the fallback gives up is atomicity: a crash mid-write can leave a short file under a
    record's name, which import skips (its content is not the record its name claims, decision
    62) and the next export of that record repairs (decision 75). The format-upgrade backup
    takes the same path on such a file system. If the write fails, the fallback removes the
    file only if the name still holds the file it created (compared by device and inode on
    Unix; elsewhere the standard library gives no stable identity and it is taken to be its
    own).

A second review, after these, found that a removed admin could still permanently void another
admin's roster records through the order, and that a late counter-removal voided its remover's
later work. The owner decided the rule of decision 71 (2026-09-27), and answered two earlier
questions (decisions 72 and 75).

70. **Roster records are decided by rules, not by replaying the order.** Each ordered roster
    record is decided once everything it depends on is: its author's standing at its own heads
    (the applied records among its ancestors), whether its operation makes sense there, and
    every applied removal or downgrade whose cut it lies beyond (decision 43's exceptions
    aside). A record is never applied and later taken back, so no restart is needed and no order
    can change who has authority. The earlier replay applied records in the order, let a cut
    void earlier-applied records, and kept those refusals across restarts; with a removed
    admin's backdated removal of another admin sorted between that admin's removal of the
    accomplice it had added and its own removal, the accomplice's removal stayed void for good
    (`roster::tests::a_removed_admin_cannot_undo_another_admins_removal_under_any_order`, run
    under all six orders of the three devices' ids). Removals that wait only on one another, in
    a cycle — three admins removing one another in a circle — all apply (a removal always wins)
    and are reported as decided together. Only if that leaves records undecided, which takes
    several concurrent removals whose authors' authority depends on one another's outcome, is
    the first of them in the order decided as if the removals it waits on did not reach it, and
    reported as decided by order for a person to review. The applied records are then replayed
    in the order on one roster, and only a clash between concurrent operations is decided there
    (decision 66): the later one is void, and everything is decided again without it.
71. **Work done after a removal survives a late counter-removal (the owner's rule).** A cut from
    a device X never voids a record whose own heads reach an applied removal or demotion of X:
    at those heads X had no admin authority to cut anyone with. Remove-wins still holds for the
    mutual pair (decision 65), but an admin removed for compromise who answers late with a
    removal of its remover no longer voids everything the remover did after removing it
    (`roster::tests::work_done_after_a_removal_survives_a_late_counter_removal`).
72. **Admin devices: at least three recommended, and a frozen roster said plainly (the owner's
    answer).** The roster warns while fewer than three admin devices are left
    (`RosterWarning::FewAdminDevices`, one or two): losing them, or two of them removing each
    other, freezes the roster; admins should be added, each on a separate device, until three
    remain. With none left the roster is frozen (`RosterWarning::NoAdminDevice`,
    `RosterState::is_frozen`): no one can be added, removed or given another role; members keep
    their roles; a vault that must change again is re-created.
73. **At most 4,096 applied roster records, and no unbounded caches.** A vault's roster applies
    at most `MAX_ROSTER_RECORDS` (4,096) roster records — far above any real roster's history
    — and further ones are void; the vault is re-created past it. It bounds the work and memory
    computing a roster takes when an admin floods it. Which records reach which is computed per
    record asked about and kept up to a bound; the roster at a head set is no longer cached by
    the head lists a record's author chose, and a record's authority is computed from the few
    records about its author, not from a copied snapshot.
74. **A removal that keeps records of the device it removes beyond its own cut is reported.** A
    removal keeps every record of the removed device its own heads reach, even beyond its cut
    (decision 43). The roster reports each such record
    (`RosterWarning::RemovalKeepsRecordBeyondItsCut`). **Requirement on Phase 2's writing
    command:** a command that removes a device or a member chooses heads that do not reach the
    removed device's records beyond the cut it writes — or lists those records and has the
    admin revert them — so that a removal does not silently keep what its cut refuses.
76. **An equivocated epoch takes nothing else down; height ties favour the smaller jump; heads
    are chained in turns.** A writer that mints a second `new` at the same `seq` voids its own
    epoch (decision 67), but an epoch someone else built on it is no longer voided with it: its
    link to the equivocated epoch is kept, opens nothing, and counts for its height as the
    lowest height the equivocating records claim. Before, the equivocation cascaded through
    every chain link and left nothing readable. Between epochs of equal height, the current one
    is the one that jumped least above the epochs it chains to, then the smallest minting device
    id and `seq`: a garbage epoch minted `MAX_EPOCH_STEP` above its chain, from a device whose
    id its owner ground to sort first, no longer holds the current slot against an honest epoch
    that climbed to the same height. And `epoch_heads` returns at most `MAX_CHAIN_LINKS` (16)
    heads, the highest first, so a writer holding more can always mint; the rest stay heads and
    are chained by the next rotation.
75. **Export repairs a file under a record's name that is not the record (the owner's answer).**
    When `exchange::export` finds its record's name taken, it reads what is there — without
    following a link, within the record limit — and leaves it exactly as it is if it parses and
    its id is its name. Anything else is replaced with the record, atomically, by a temporary
    renamed over it: a short file a crash left on a file system without hard links (decision
    69), a stale or tampered copy, a link. A file that is the record is never replaced. This
    supersedes decision 63's "left alone": a name is a hash of the record's own bytes, so
    nothing else legitimately lives there, and leaving it meant that record never reached that
    directory.

### 6. Decisions made while building Phase 2

Phase 2 met the points below, continuing the numbering. Each is marked for the owner's review
in the step that introduced it. **The trusted-admin amendment below ("Amendment 2026-09-27:
trusted-admin simplification") governs:** where a decision here names a cut, a pending record,
an equivocation or the adversarial roster, the amendment's roster and epochs are what the code
is built against, and decisions 79 and 80 are stated in its terms.

77. **The replica's byte layout, and a local section that authenticates the whole file.** A
    replica is `KAGISHR\0`, a one-byte version (`1`), a big-endian `u32` header length (at most
    64 KiB) and a deterministic-CBOR header `{"v": 1, "vault_id", "genesis", "device", "suite",
    "generation", "created_at"}` (unknown keys kept), a big-endian `u32` record count (at most
    200,000, a bundle's limit, so a replica always fits one bundle) and that many
    length-prefixed envelopes in strictly increasing id order, then the local section's 24-byte
    nonce and its XChaCha20-Poly1305 ciphertext under the contract's local-section key. The
    local section's AAD is **every byte before its nonce**, header and records included, so the
    whole file is authenticated by this device's key: a record slipped in or taken out by a sync
    tool or another program makes the file refuse to open rather than quietly change what this
    device holds (the records are still verified one by one when a view is computed). The
    header names the device whose key opens the local section, and the genesis this device
    trusts (decision 41). `generation` counts writes, for ADR-0041's anchor to compare later;
    nothing decides anything by it now. A transaction takes the replica's own `FileLock`, reads
    the file as it is, starts from the union of its records and the handle's, keeps the file's
    local state except the highest `seq` written — which is the largest of the file's, the
    handle's and every `seq` of this device's own records, and never goes down — and writes
    nothing when nothing changed (`crates/kagisecure-shared/src/replica.rs`).
78. **The first view (superseded the same day by decision 79).** The first version of the view
    applied decision 13's rules in full to item and environment records, parents first. Once the
    owner's priorities changed and the trusted-admin amendment replaced the roster, all of it was
    withdrawn; decision 79 is what is built.

The owner changed priorities on 2026-09-27, after decision 78: convenience first, looser
security accepted, no backward compatibility or data migration, and the roster to be simplified
to a "trusted admins" model. The decisions below follow from that and supersede what they name.

79. **The view accepts a version on the amendment's checks only (the owner's priorities;
    supersedes decision 78 and decision 13's rules for item and environment records).** An item
    or environment record is read when its signature verifies for a device the roster added;
    its author holds a writer's or an admin's role at the roster heads it names
    (`RosterState::authority`, the amendment's "role from the state after the latest roster
    head it names"); and this device holds its epoch's key and the payload decrypts to one
    version. A device removed at those heads holds no role, so **a removed device's records are
    ignored from its removal on** in the roster's order; one that names heads from before its
    removal is still read, the limit the amendment's threat-model entry accepts. A record
    naming a roster head this replica does not have yet waits. Missing parents, the author's
    chain, equivocation, "reverted by removal" and exposure flags are not computed. The roster
    and the key ring are read through one adapter (`view::Access`). Records not read are
    listed with why (`crates/kagisecure-shared/src/view.rs`).
80. **The merge is last-writer-wins per attribute, field and variable, with nothing to resolve
    (the owner's priorities; supersedes §8's "no last-writer-wins, ever", its conflicts and
    their refusal, and decision 17).** What a version sets is each attribute, field (by id) or
    environment variable (by name) whose encoding — absent counting as a value — differs from
    every parent among the item's accepted versions; a version with no such parent sets all it
    holds. A version beats every version it descends from through its parents, whatever times
    either claims; only concurrent versions — neither descending from the other — are ordered
    by their author's claimed `created_at`, then record id. For each part, of the versions that
    set it, those no other of them descends from are kept and the latest of these wins; parts
    no standing edit set come from the latest edit, chosen the same way. A deletion beats every
    edit it descends from and every concurrent edit before it, and an edit that descends from a
    deletion beats it; the edits no deletion beats stand. With none the item is deleted;
    otherwise it is built from the standing edits only, so an edit after a deletion brings the
    item back without the edits the deletion beat. `created_at` is the earliest of those edits',
    `updated_at` the latest, and the field history their union. The cost accepted is §8's own
    example: two people rotating one credential concurrently keep only the later-claimed
    rotation, and a device with a clock set ahead wins every tie between concurrent versions
    it enters. (Corrected 2026-09-27: the first text ordered every version by claimed time and
    record id alone, so an edit written in the same second as the version it edited — a new
    item saved right after its template — could lose to it, and the app wrote a second later
    to avoid that; ancestry now decides, and the workaround is gone.) `MaterializedItem` and `MaterializedEnv` carry the result and, per part, the version
    it came from; there is no conflict list, and `UNRESOLVED_CONFLICT` (decision 25) has nothing
    left to report (`crates/kagisecure-shared/src/merge.rs`).
81. **Writing (the owner's priorities: fewest steps).** A write — `put_item`, `delete_item`,
    `put_env`, `delete_env` — is one replica transaction: this device's own records are first
    taken in from the configured exchange directory, so a replica restored from an older copy
    never reuses a published `seq` (`next_seq`; Correction H's guard, now on every write); the
    next `seq` is one above the larger of this device's highest record and the replica's
    rollback guard, and a write is refused if the guard knows of records the replica no longer
    holds. The writer must be a writer or an admin holding the current epoch's key, on a vault
    this build may write to. A version names as parents the versions of its item no other
    version names (at most 16, the latest). The new record is exported to the configured
    exchange directory at once, so writing needs no second step. The item's and environment's
    local-only settings go to the replica's local state instead of the record. **The vault's
    name** lives in each device's local state — set by its creator, carried by the invitation —
    and in no record, since roster labels' sealing is still undecided; there is no `resolve`
    (`crates/kagisecure-shared/src/write.rs`, `admin/create.rs`).
82. **Enrolling and joining in three steps, trusted on first use (superseded the same day by
    decision 86).** A joining device writes an
    enrollment request (`KAGISRQ\0`, version 1, a deterministic CBOR map of its public keys, a
    label of at most 128 characters and a time; at most 64 KiB). An admin's `add_device`, in one
    transaction, adds a member (or uses an existing one), adds the device with how its
    fingerprint was checked — unverified by default — and grants it every epoch key the admin
    holds. It returns an invitation (`KAGISIV\0`, version 1, a `u32` header length and a
    deterministic CBOR header naming the vault, its genesis, its name, the invited device and
    the inviting device, then a bundle of **every** record the admin holds), so `join` is the
    joiner's only step and needs no second exchange. The contract's 64 KiB invitation limit is
    raised to a bundle's, since it now carries the records. Neither file is signed: under the
    amendment's trusted admins, a signature by a key the joiner does not yet know adds nothing
    the file itself does not. Comparing fingerprints is optional: with an expected fingerprint,
    `join` refuses an invitation from any other inviting device or one that is not an admin,
    and records it as verified; otherwise every device of the roster is recorded as first seen
    in the local state. Joining twice adds the records to the existing replica
    (`crates/kagisecure-shared/src/admin/enroll.rs`).
83. **Removing and changing roles.** `remove_device` and `remove_member` write the removal and,
    in the same transaction, a new epoch named after it and wrapped to every device left, so
    nothing written afterwards reaches the removed device; there are no cuts. `set_role` writes
    the change alone. Two changes are refused: one that would leave no admin (the roster would
    freeze), and removing this very device or its own member, whose new epoch would be minted
    by a device already out of the roster (`crates/kagisecure-shared/src/admin/remove.rs`).
84. **The rotation list is informational (supersedes decision 30's use).** For each device
    removed from the roster that was sent an epoch key, `rotation_list` names those epochs and
    the items and environments with a version under one of them. Nothing is enforced and
    nothing refuses a write; hard-to-rotate kinds are not singled out
    (`crates/kagisecure-shared/src/rotation.rs`).
85. **Importing, exporting, syncing and rebuilding.** An exchange directory keeps its records in
    `records/`. Import — from a directory or a bundle — adds every new record in one
    transaction and reports by name only: the titles of the items and names of the environments
    whose versions changed, and whether the roster did. Export writes every record the directory
    is missing, or the whole replica as one bundle; `sync` imports from and exports to the
    configured directory in one call. **Recovery from decision 77's refusal:**
    `Replica::rebuild_from` rebuilds a replica that no longer opens from an exchange directory or
    a bundle. The vault and genesis come from the old header if it still parses and names this
    device — read without authentication, which the trusted-admin model accepts — else from the
    file's name and the one genesis whose roster includes this device. The old file is kept as
    `<name>.damaged-<time>`; the local state starts empty, with the rollback guard set from this
    device's own records (`crates/kagisecure-shared/src/admin/exchange.rs`, `replica.rs`).
86. **An invitation is one file and a passphrase (the owner's decision; supersedes decision 82
    and the enrollment request).** The admin's `invite` generates the joining device's key pair
    on the admin's device, and in one transaction adds the member (or uses an existing one),
    adds the device as unverified, and grants it every epoch key the admin holds. The
    invitation (`KAGISIV\0`, version 1, a `u32` header length, a deterministic CBOR header
    carrying the Argon2id parameters and salt, a 24-byte nonce, then the sealed body) is sealed
    with XChaCha20-Poly1305 under `Argon2id(passphrase)` at the personal vault's default cost,
    with every byte before the nonce as AAD. The body is the metadata (vault id, genesis, vault
    name, device label), the device's 64 secret bytes and a bundle of every record the admin
    holds. The passphrase is six words from the personal vault's generator word list (about 77
    bits), compared lower-case with any separators read as one hyphen. The joiner's `join(file,
    passphrase)` adds the device key to the personal vault, creates the replica, trusts the
    genesis the file names and records every other device as first seen; joining again adds the
    records to the existing replica. No request file and no round trip. Accepted limits (threat
    model): the admin knows the joining device's secret keys, and anyone holding the file and
    the passphrase can join as that device. Adding a member needs no presence check beyond the
    personal vault being unlocked (`crates/kagisecure-shared/src/admin/enroll.rs`).
87. **Syncing is cheap enough to run on every folder change.** A record file is named by its
    record's id, a hash of its content, so a name decides: import lists the directory and opens
    only files whose names this replica does not hold; with none, it runs no transaction,
    computes nothing and writes nothing. When records are added, the state is computed once,
    after, and the summary names the items and environments the added versions belong to.
    Export lists the directory once and writes only records it has no file for; a damaged file
    under a record's name is not repaired by `admin::exchange::export_dir` (decision 75's repair
    still happens in `exchange::export`, which a write's own publish uses)
    (`crates/kagisecure-shared/src/admin/exchange.rs`, `exchange.rs`).

### 7. Decisions made while building Phase 4

Phase 4 (agents and approvals) was built on 2026-09-27 under the owner's priorities of that day —
convenience first, looser security accepted, no compatibility or migration — and the merge of
decision 80, which leaves nothing to resolve: `UNRESOLVED_CONFLICT` (decision 25) was never built,
and no release is refused over a conflict. The steps' plan is otherwise as listed; the decisions it
needed continue the numbering.

88. **Agent visibility of a shared vault's contents is this device's own, and hidden by default
    (the owner's question: "the same default as personal items").** Items, their fields and
    environments start hidden to this device's agents, as a personal item or environment does
    (threat-model M-9); the setting is kept in the replica's local section (decision 22) and set
    in the app's item detail — the Agent access panel, now shown for shared items with a line
    saying the setting is this Mac's alone — or with `kagisecure env agent-access --shared-vault`
    (`kagisecure_shared::admin::visibility`). A shared vault has no vault-wide switch of its own:
    it is listed to agents (`list_vaults`, `shared: true`) exactly when something in it is
    visible, with counts of what is visible, so a vault nobody made visible does not even put its
    name in front of a model. The browser extension's own fills — started by a person — do not
    consult agent visibility, for a shared login as for a personal one
    (`crates/kagisecure-agent/src/catalog.rs`).
89. **Collisions: personal wins an id, and a shared name is qualified (amends decision 28).** An
    agent names an item or environment by id, so an id must name one thing: a personal item or
    environment wins over a shared one with the same id — the shared one is absent to agents,
    whatever either's visibility — and an id two shared vaults hold names neither (decision 28,
    kept for ids). Names are what a model reads, and hiding both of two same-named entries was
    the inconvenient half of decision 28: both are listed now, a personal one under its own name
    and every shared one whose name another listed entry also has as `name (vault)`, qualified by
    the shared vault's name on this device. The approval sheet uses the same name and also states
    the vault (decision 91). The rule is `Catalog` in `kagisecure-agent`, the one view over the
    personal vault and the attached shared vaults every agent-facing lookup goes through.
90. **The host attaches a shared vault to the agent; the lock detaches it.** A shared vault is
    served to agents only while the host that opened it keeps it attached to the personal
    vault's `VaultHandle` (`attach_shared`, a `SharedSource`): the app's `SharedVaultSession`
    attaches the copy it already holds when it opens the vault and detaches when dropped;
    `kagisecure daemon` attaches every replica a device key of the personal vault opens
    (`ReplicaSource`). Taking the personal vault out of the handle — the lock — detaches every
    shared vault before any lock hook runs, and with them the device keys. Each request first
    asks every attached vault to pick up what another process wrote to its copy (the CLI's
    `agent-access --shared-vault`, say) and reads a snapshot of it (`kagisecure_shared::read`:
    the merged items and environments with this device's settings applied, and where each value
    came from); a release reads the snapshot again inside its own transaction, with the personal
    vault's handle held — the lock order is the personal vault's handle, then a shared vault's
    state, then file locks. A shared environment's bindings resolve inside its own vault only
    (§14), through the same resolution the personal vault uses
    (`kagisecure_core::model::env::resolve_injections`).
91. **"Changed since you approved it" compares records, and a change always gets the full sheet
    (decision 26 as built).** For each variable about to be released, the record its value comes
    from — the variable's own and, for a binding, the bound field's (`Provenance::slots`) — is
    compared with the record this device last approved releasing (`approved_vars`,
    `approved_fields`); a part never approved counts as changed. The sheet — the approval sheet,
    the agent-fill sheet and the daemon's prompt — gains two facts: `Shared vault “Ops” — 4
    members`, and one line per changed value naming who wrote the version (this device's own name
    for their member, "you", or "another member") and when their computer said it was. A granted
    sheet records what it showed. A value that changed is never released under an earlier
    approval: the lease is not reused and a fill that would have been presence-only gets the full
    sheet, so a change is always in front of a person before it is released. The presence rules
    are otherwise unchanged: within the ten-minute presence grace (ADR-0037, amended), pressing
    Allow on that sheet may need no new Touch ID, as for any fill sheet. A value changed in the
    seconds between the sheet and the release is released and named on the next sheet
    (threat-model §7).
92. **Agents never write to a shared vault, and releases are audited as the personal vault's.**
    `create_environment` naming a shared vault, and `add_variables` naming a shared environment,
    that the agent can see are refused with `INVALID_ARGUMENT` and one fixed sentence, before any
    sheet (decision 27); one it cannot see is `NOT_FOUND`. A personal environment cannot be bound
    to a shared item (references stay inside a vault). Every release and refusal from a shared
    vault is recorded in the personal vault's audit log with the shared vault's id as `vault_id`
    and the usual actor — `mcp`, or the extension's (decision 24).
93. **Nothing agent-facing can reach the admin module.** `kagisecure-agent` now depends on
    `kagisecure-shared`, so the dependency-graph test alone no longer keeps roster changes out of
    an agent's reach. A lexical guard beside it asserts that no source file of
    `kagisecure-agent`, `kagisecure-ipc`, `kagisecure-mcp`, `kagisecure-extension-ipc` or
    `kagisecure-nmhost` names `kagisecure_shared::admin`; `no_ipc_message_changes_a_shared_roster`
    sends every IPC message at a shared vault, approved, and finds its records unchanged; and the
    ADR-0002 canary holds for a value seeded into a shared vault
    (`crates/kagisecure-agent/tests/shared_vaults.rs`,
    `crates/kagisecure-shared/tests/dependency_guard.rs`).

## Amendment 2026-09-27: trusted-admin simplification

**Status:** accepted by the owner, 2026-09-27. **Supersedes** the adversarial roster and epoch
decisions listed below. Convenience comes first: admins are trusted, members are trusted not to
attack the roster, and backward compatibility with the Phase 1 build (never released) is not
kept. Every defence dropped here is listed as a known limitation in
[threat-model.md](../threat-model.md) §7, "Shared vaults: limits of the trusted-admin model".

**The roster, now.** Roster records are put in one order — a topological sort over the roster
heads each names and its author's previous roster record, the genesis first, ties by smallest
record id — and applied linearly. A record needs its author to be an active device of an admin
member in the state reached so far, and its operation to make sense there; otherwise it is
ignored (kept and forwarded, never applied). A removed device's records are ignored from its
removal on in that order; what was applied before stays. Two roster records from one device at
one `seq`: the smaller record id is kept, the other ignored. At most 4,096 roster records are
considered, in the order. The genesis is still named by the replica's header or a verified
invitation (decision 41). Any other record takes its author's role from the state after the
latest roster head it names. The roster operations lose their cuts: `remove-device` is
`{device, reason}`, `remove-member` `{member, reason}`, `set-role` `{member, role}`. Warnings:
fewer than two admins, and a frozen roster (no admin left).

**Epochs, now.** A new epoch is minted when the vault is created, whenever a device is removed,
and on demand; its key is wrapped with HPKE to every current device. A `new` operation is
`{op, epoch_id, height, wraps}`: no chain and no commitment. A device added later is granted
older epochs' keys by `grant` records. Readers use every epoch key they can open; a writer
writes under the newest epoch it holds (greatest height, then smallest record id). `epoch_id` is
still derived from the minting record (decision 67); two epochs claiming one id keep the smaller
record id. `new` and `grant` need a writer or an admin, `ack` any member.

**Superseded decisions.** In full: 16 (a downgrade's cut), 18 (records rejected by a late cut),
19 (equivocation flagged with both kept — now the smaller id is kept, nothing reported), 36's
chain key, chain seal and commitment, 42 and 43 (verification order beyond the genesis, the
linear order with cuts enforced across it), 45 (authority limited by cuts), 47's `chain` and
`commitment` fields, 48 (acceptance of epoch records beyond "a writer or an admin"), 49 (keys
trusted only against a commitment), 50 (the current epoch and the rotation rules), 65 (remove
wins), 66 (authority at a record's own heads), 68 (height bounds and tie-breaks), 70 (deciding
by rules), 71 (work after a removal), 73 (the applied-record limit, replaced by the 4,096-record
limit on the order), 74 (a removal keeping records beyond its cut), 76 (equivocated epochs,
jumps, heads in turns). In part: 13 (the acceptance rules reduce to: the signature verifies, the
body is this vault's, the author is an active device with the needed role at that point), 40
(the operations above, without cuts), 72 (the warning is now "fewer than two admins"). Kept:
the encoding contract, decisions 1–12, 14, 15, 17, 20–35, 37–39, 41, 44, 46, 60–64, 67, 69 and
75.
