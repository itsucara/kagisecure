# Shared vault formats

Status: **Phase 1 of [ADR-0035](decisions/0035-shared-vaults.md) built (2026-09-27), as a
library, and Phase 2 under way: the local replica (§10), the view and the merge computed from
it, and writing, invitations (§11) and exchange (§12).** Everything below is implemented in
`crates/kagisecure-shared` and pinned by golden vectors and known-answer tests (§9). Nothing a
person can run reads or writes these formats yet: there is no CLI command and no app screen —
those are the rest of Phase 2 and Phases 3 to 5.
This document is the companion [vault-format.md](vault-format.md) §2.2 points to; the personal
vault's side of sharing — where a device's secret keys are stored — stays in
[vault-format.md](vault-format.md) §2.3.

The normative source is the ADR-0035 addendum: its encoding contract and decisions 33–76, as
amended by "Amendment 2026-09-27: trusted-admin simplification", which replaces the roster and
epoch rules (admins are trusted; see the threat model's limits of that model), and decisions
77–87 (the replica, the view, the merge, writing, invitations and exchange), built against that
amendment. This document describes what was built, section by section, and names the decision
each rule comes from. Where the two ever disagree, that is a bug in one of them; the golden
vectors decide which.

## 1. Conventions

- `‖` is plain byte concatenation. Every domain-separation string is ASCII, with no byte beyond
  the explicit `0x00` separators shown.
- A **vault id** is the shared vault's 16 random bytes (decision 21), fed into derivations as
  those 16 bytes. An **epoch id** is 16 bytes derived from the record that mints the epoch
  (§5; decisions 14, 67). A **device key id** and a **record id** are 32 bytes.
- **Deterministic CBOR, refused otherwise** (decision 33). Everything this format signs, hashes
  or compares as bytes is written in RFC 8949 §4.2.1's core deterministic encoding: shortest
  integers and lengths, definite lengths, map keys in the bytewise order of their encodings, no
  key twice. A reader first **scans** the input — one linear pass over the heads, copying
  nothing — refusing a length or count larger than what is left, an indefinite length, a head not
  in its shortest form, an unsupported simple value, nesting deeper than 64, a key twice, keys
  out of order and trailing bytes; then decodes it, re-encodes it and requires the same bytes
  back. Nothing is normalised.
- **Item and environment plaintexts** are `serde`'s encoding (map keys in field order, an
  indefinite-length map for a struct with flattened unknown keys), so they are not
  deterministic, but they are read strictly: scanned the same way, except that key order and
  indefinite-length maps and arrays are allowed; a key twice at any depth, trailing bytes and a
  head not in its shortest form are still refused (decision 39).
- **Unknown is kept, not guessed.** A record of a kind this build does not know, a body key it
  does not know, and a record in a body version it does not read are kept and forwarded byte for
  byte and not interpreted (decisions 20, 46). A device's public keys are a closed map: an
  unknown key there is refused, because it could change what the key means (decision 33).

## 2. Device keys

A device is one computer's pair of keys — X25519 for receiving epoch keys, Ed25519 for signing
records — under a named **suite**; the one suite is `x25519-ed25519-v1`. The secret half is the
personal vault's `DeviceKey` ([vault-format.md](vault-format.md) §2.3).

```
DevicePublic := {                     # deterministic CBOR, exactly these keys
  "suite":  text,                     # "x25519-ed25519-v1"
  "kem_pk": bytes(32),                # X25519 public key
  "sig_pk": bytes(32)                 # Ed25519 public key
}
```

- **Device key id** = `SHA-256("kagisecure/shared/device/v1" ‖ 0x00 ‖ suite ‖ 0x00 ‖ kem_pk ‖
  sig_pk)`.
- **Fingerprint:** the device key id's first 20 bytes read as ten big-endian `u16`s, each written
  as five zero-padded decimal digits, space-separated. The QR payload is
  `kagisecure-fp:1:<64 lower-case hex digits of the whole id>`. (Displaying and comparing it is
  Phase 3.)
- **Strict public keys** (decision 33), checked whenever a key is read, before anything is wrapped
  to it or verified with it: the X25519 key is a canonical field element (below 2^255 − 19, top
  bit clear) and not of small order on the curve or its twist; the Ed25519 key decompresses,
  re-encodes to the same bytes, is not of small order and is torsion-free.

## 3. Signatures

Every signature is Ed25519 (RFC 8032) over `domain ‖ 0x00 ‖ content`, verified with
`verify_strict` (decision 34). `domain` is `kagisecure/shared/sig/<purpose>/v1`, one per purpose;
the only one built is the record's, `kagisecure/shared/sig/record/v1`. `content` is framed so
that it has one reading: every part but the last is fixed-length or length-prefixed, and
structured data is one deterministic-CBOR part. The record's content is the author's 32-byte
device key id followed by the body bytes.

## 4. Records

### 4.1 Envelope

```
Record := [ v, author, body, sig ]    # a CBOR array, every head in its shortest form
  v       uint        1
  author  bytes(32)   the signing device's key id
  body    bytes       the body's deterministic CBOR (§4.2), exactly as signed
  sig     bytes(64)   Ed25519 over "kagisecure/shared/sig/record/v1" ‖ 0x00 ‖ author ‖ body

record_id := SHA-256("kagisecure/shared/sig/record/v1" ‖ 0x00 ‖ author ‖ body ‖ sig)
```

The envelope is read by hand, not by a general decoder: the whole record is refused above 1 MiB
before a byte is read, every length is checked against what is left before anything is sliced,
and nothing may follow the four items (decision 37). An envelope version other than 1 is refused
by name.

**Verification order** (decisions 13, 37; correction G): parse the envelope; check that the named
author is the key being used; verify the signature over the exact bytes; decode the body — as a
body of the shared vault the caller is reading, refusing any other `vault_id` before its other
fields are checked — and only then, for an item or environment record, decrypt. A record is
never decrypted, or its body trusted, before its signature has verified.

### 4.2 Body

A deterministic CBOR map with these text keys, all always present (decision 38):

```
v            uint             body version, 1
kind         text             "roster" | "epoch" | "item" | "env" | "ack" | "policy" | "unattended_copy" | a kind this build keeps unread
vault_id     bytes(16)
seq          uint             the author's own counter, from 0
prev         bytes(32) | null the author's previous record's id; null exactly when seq is 0
parents      [bytes(32)]      the versions this record edits (item, env); at most 16
roster       [bytes(32)]      the roster heads the author's authority is checked against; at most 16
epoch        bytes(16) | null the epoch whose key encrypts the payload; required for item and env
created_at   uint             unix seconds, as the author claims; orders concurrent versions only (§4.3)
record_salt  bytes(16)        input to the record key
payload      bytes            §4.3–§4.5
```

`parents` and `roster` are counted from their array heads while the body is scanned, before it is
decoded. Any other key is kept as read.

### 4.3 Item and environment payloads

The payload is sealed under the **record key** with XChaCha20-Poly1305 and a fresh random 24-byte
nonce, written as `nonce (24) ‖ ciphertext ‖ tag (16)` (decision 36):

```
record_key  := HKDF-SHA256(IKM = epoch key, salt = record_salt,
                           info = "kagisecure/shared/record/v1" ‖ vault_id)            # 32 bytes
payload AAD := deterministic CBOR [ "kagisecure/shared/payload/v1", vault_id(16), author(32),
                                    kind (text), parents ([bytes(32)]), roster ([bytes(32)]),
                                    epoch_id(16) ]
```

so a member who strips the signature and re-signs the ciphertext as their own produces a record
that verifies and then fails to decrypt. The plaintext (decision 39) is

```
ItemVersion := { "id": ItemId, "item": Item | null }         # null: deleted
EnvVersion  := { "id": EnvId,  "env":  Environment | null }
```

with the item or environment encoded exactly as the personal vault's body encodes it
([vault-format.md](vault-format.md) §5). Its `vault_id` is the shared vault's. The device-local
settings — `agent_visible` on the item, each field and the environment, `favorite`, and an
environment's `default_paths` — are cleared on writing and cleared again on reading, so nothing
received from a shared vault starts visible to an agent.

**How versions merge** (decision 80, as corrected on 2026-09-27). A version *sets* each attribute,
field (by id) or variable (by name) whose encoding — absent counting as a value — differs from
every parent among the item's accepted versions; a version with no such parent sets all it holds.
A version beats every version it descends from through `parents`, whatever `created_at` either
claims; only concurrent versions — neither descending from the other — are ordered by
`created_at`, then record id. For each part, of the versions that set it, those no other of them
descends from are kept and the latest of these in that order wins; the rest comes from the latest
edit, chosen the same way. A deletion beats every edit it descends from and every concurrent edit
before it; an edit descending from a deletion beats it. The edits no deletion beats stand: with
none, the item is deleted; otherwise it is built from them only. The result depends only on the
set of accepted versions.

### 4.4 Roster payloads

A roster record's payload is one deterministic CBOR map: `"op"` and exactly that operation's
fields (decision 40, as amended) — `genesis` {`suite`, `member`, `device`, `labels`},
`add-member` {`member`, `role`, `labels`}, `add-device` {`member`, `device`, `verified`,
`labels`}, `remove-device` {`device`, `reason`}, `remove-member` {`member`, `reason`},
`set-role` {`member`, `role`}. A member id is 16 bytes; `device` is §2's map (in
`remove-device`, a device key id); `labels` is null or opaque bytes of at most 4096. An `op`, a
field, a role, a reason or a suite this build does not know is kept and not understood; written
by an admin, it makes the vault read-only for this build (decision 20).

How a roster is computed (the trusted-admin amendment): the genesis is the one the caller names,
from the replica's own header or a verified invitation. Roster records are ordered by the roster
heads each names and its author's previous roster record, the genesis first, ties by smallest
record id; of two from one device at one `seq`, the smaller record id is kept. At most 4,096 are
considered. They apply in that order, each needing its author to be an active device of an admin
member in the state reached so far; any other is ignored. A removed device's records are ignored
from its removal on; nothing applied before is undone. Any other record takes its author's role
from the roster after the latest roster head it names.

### 4.5 Epoch and acknowledgement payloads

An `epoch` record's payload is `{"op": "new", "epoch_id": bytes(16), "height": uint, "wraps":
{bytes(32): bytes(80), …}}` or `{"op": "grant", "epoch_id", "wraps"}`; an `ack` record's is
`{"op": "ack", "epoch_id"}` (decision 47, as amended: no chain, no commitment). A `new` record's
`epoch_id` must be the one its record derives (§5); of two `new` records claiming one id, the
smaller record id is kept. `wraps` is keyed by device key id, 1 to 64 of them. `new` and `grant`
need a writer or an admin, `ack` any member. A device holds every key wrapped to it that opens;
it reads with all of them, and writes under the newest it holds (greatest height, then smallest
record id). A new epoch is minted when the vault is created, whenever a device is removed, and
on demand; a device added later is granted the older epochs' keys.

### 4.6 Unattended-copy payloads (ADR-0042 §13)

`policy` and `unattended_copy` records are sealed under an epoch key like `item` and `env`. A
`policy` payload is `{"copies_allowed": bool}`, read only from an admin's device, the latest by
`created_at` then record id winning; a vault with none allows copies. An `unattended_copy`
payload is `{"copy": uuid, "source": uuid, "name": text, "variables": [text], "holder": text,
"held": bool}` — this device holds (or no longer holds) machine-vault environment `copy`, copied
from environment `source`; any member may write one, and for each author and `copy` the latest
stands (ADR-0042 implementation decision 35).

## 5. Epoch keys

An epoch key is 32 random bytes; its epoch's id is derived from the record that mints it
(decision 67):

```
epoch_id    := SHA-256("kagisecure/shared/epoch-id/v1" ‖ vault_id (16) ‖ author (32) ‖
                       seq (u64, big-endian))[..16]
```

From the key (decisions 35, 36; the encoding contract):

```
wrap        := HPKE Base mode (RFC 9180), DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
               ChaCha20-Poly1305, to the device's kem_pk, with
               info = "kagisecure/shared/epoch/v1" ‖ vault_id ‖ epoch_id and empty AAD;
               written as enc (32) ‖ sealed epoch key (32) ‖ tag (16) = 80 bytes
```

A wrap is trusted as it opens: there is no key commitment and no epoch chain (the trusted-admin
amendment). The wrap's randomness — the ephemeral key's 32
bytes of input — is drawn from `kagisecure-core`'s generator before `hpke` runs; `hpke` is pinned
to exactly 0.14.1, whose consumption of randomness this depends on (decision 35).

## 6. Bundle

One shared vault's records as a single file (decisions 60, 61):

```
magic     8 bytes     "KAGISBN\0"
version   1 byte      1
count     u32, BE     refused above 200,000 before any record is read
records   count times:
  length  u32, BE     refused above 1 MiB before the record is sliced
  record  length bytes, one envelope (§4.1)
```

The whole bundle is refused above 256 MiB. Records are written sorted by id, duplicates
collapsed; a bundle read back is deduplicated and sorted the same way. The container is not
signed or hashed; each record is verified on its own. No golden vector pins the bundle yet.

## 7. Exchange directory

One file per record, `records/<64 lower-case hex record id>.ksr`, holding exactly the envelope
(decisions 62–64, 69, 75). Export never replaces a file that is the record — a second export of
the same record writes nothing — and replaces, atomically, anything else under the record's
name (a short file, a stale or tampered copy, a link). It links a flushed temporary into place;
on a file system without hard links it creates the file in place, create-new, which a crash can
leave short and the next export repairs. Import accepts at most 200,000 records, reads at most
1 GiB and lists at most 1,600,000 entries, opens each file without following a symbolic link or
waiting on a FIFO, and quietly skips any file whose name is not of the record shape, that is not
a regular file, that is over 1 MiB, that does not parse, or whose content's record id is not its
name. The directory's descriptor (`KAGISXD\0`) is not built yet, and is never a
source of the genesis id (decision 41).

## 8. Limits

| What | Limit | Enforced |
| --- | --- | --- |
| A record | 1 MiB | before a byte is read |
| `parents`, roster heads | 16 each | from the array heads, before the body is decoded |
| Nesting in any CBOR structure | 64 | during the scan, before decoding |
| Epoch wraps | 64 | counted before any is converted |
| Roster labels | 4096 bytes | on reading and writing |
| Members; devices per vault | 32; 64 | when the roster is computed |
| Roster records considered | 4,096, in the roster's order | when the roster is computed |
| A bundle | 256 MiB or 200,000 records | before any record is read |
| Exchange directory import | 200,000 records; 1 GiB read; 1,600,000 entries | while listing |

A replica is refused above 256 MiB (§10) and an invitation above a bundle's limit plus 128 KiB
(§11); a vault name or device label is at most 128
characters. The contract's pending-record limit (10,000) no longer applies: nothing waits in the
view (decision 79).

## 9. Golden vectors and known answers

Committed once and never edited once released (decision 31); each test also checks this build
still writes the file byte for byte. (`record-epoch-new-v1.ksr` was regenerated once, before any
release, when epoch ids became derived — decision 67 — and again when the trusted-admin
amendment removed the chain and commitment from its payload.) All keys are public test data: the
golden device is RFC 7748's Alice (X25519) and RFC 8032's TEST 1 (Ed25519), the device `kagisecure-core`'s own
`v2-devices-argon2id-64k.kagivault` holds.

| File (`crates/kagisecure-shared/tests/vectors/`) | What it pins |
| --- | --- |
| `device-v1.cbor` | the golden device's public keys (§2), its id and fingerprint |
| `record-item-v1.ksr` | an item record: envelope, body, record key, payload AAD and seal (§4.1–§4.3) |
| `record-roster-genesis-v1.ksr` | a vault's genesis: the golden device making the golden member its first admin (§4.4) |
| `record-epoch-new-v1.ksr` | that vault's creation epoch, its id derived from its record, wrapped to the golden device (§4.5, §5) |

Known-answer tests in `src/golden.rs` pin, as hex, a record key and a wrap with RFC 9180's `ikmE` — each cross-checked, when written,
against a separate implementation. The primitives are also run against RFC 8032 §7.1 and RFC 9180
A.2.1 directly.

## 10. Replica

This device's copy of one shared vault (decisions 22, 23, 77), at `<personal vault
file>.shared/<32 lower-case hex vault id>.kagishared`, beside a `.lock` file of its own, in a
directory created owner-only (`0700`). It is never exchanged.

```
magic        8 bytes    "KAGISHR\0"
version      1 byte     1
header_len   u32, BE    at most 64 KiB, refused before the header is read
header       deterministic CBOR { "v": 1, "vault_id": bytes(16), "genesis": bytes(32),
                                  "device": bytes(32), "suite": text, "generation": uint,
                                  "created_at": uint, …unknown keys kept }
count        u32, BE    at most 200,000, refused before a record is read
records      count times: length (u32, BE; at most 1 MiB) and one envelope (§4.1),
             in strictly increasing record-id order
local_nonce  24 bytes
local_ct     XChaCha20-Poly1305 of the local state, AAD = every byte before local_nonce

local key   := HKDF-SHA256(IKM = the device's 64 secret bytes (X25519 secret ‖ Ed25519 seed),
                           no salt, info = "kagisecure/shared/local/v1" ‖ vault_id)
```

The whole file is authenticated by the local section: a record added or removed by anything
but this device's writer makes it refuse to open. The local state is decision 22's list —
agent visibility of items, fields and environments, favourites, default paths, the record whose
value was approved per field and per variable (`approved_fields`: item id → field id → record
id; `approved_vars`: environment id → name → record id — the record a released value came from
when this device last approved releasing it, compared by the approval sheet, decision 91),
devices verified and first seen, the exchange
directory, the highest `seq` this device wrote, the vault's name (decision 81) and the names this
device's person gave other members (`member_names`: 16-byte member id → text, written only when
not empty; the app's members pane) — as a CBOR map (`serde`'s encoding, unknown keys kept). A
write takes the lock, reads the file, starts from the union of its records and the writer's, and
never lowers the highest `seq`. The whole file is refused above 256 MiB.

## 11. Invitation

Joining is one file and a passphrase (decision 86).

```
magic      8 bytes    "KAGISIV\0"
version    1 byte     1
header_len u32, BE    at most 4 KiB
header     deterministic CBOR { "v": 1, "kdf": { "alg": "argon2id", "salt": bytes(16),
                                               "m_kib": uint, "t": uint, "p": uint } }
nonce      24 bytes
sealed     XChaCha20-Poly1305 under Argon2id(passphrase), AAD = every byte before the nonce, of:
             meta_len u32, BE; meta = deterministic CBOR { "vault_id": bytes(16),
               "genesis": bytes(32), "name": text | null, "label": text }
             the invited device's 64 secret bytes (X25519 secret ‖ Ed25519 seed)
             a bundle (§6) of every record the inviting replica holds
```

The file's extension is `.kagisecure-invite`. The passphrase is six words of the generator's word
list joined by hyphens; it is compared lower case, with any run of separators read as one hyphen.
The whole file is refused above a bundle's limit plus 128 KiB, and a header naming an Argon2id
cost above four times the personal vault's default — `m_kib` above 4 × 65,536, or `m_kib × t`
above 4 × 65,536 × 3 — is refused before any stretching, both when inviting and when joining.

## 12. Exchange directory layout

An exchange directory keeps its records in its `records` subdirectory (§7; decision 85). Its
descriptor (`KAGISXD\0`) is not built, and is never a source of the genesis.

## 13. Not yet specified

How roster labels are sealed.
