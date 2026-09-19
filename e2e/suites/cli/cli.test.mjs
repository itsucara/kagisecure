/**
 * Suite C — the CLI and the vault format, end to end.
 *
 * Every scenario here drives the **real** `kagisecure` binary against a vault it created itself,
 * under `E2E_RUN_DIR`. Nothing reads or writes the per-user default location, and no scenario
 * depends on another having run: each makes its own vault, so `--suite cli` can be run repeatedly
 * and the scenarios can be reordered without breaking.
 *
 * The KDF is deliberately weakened to `--kdf-m-kib 8 --kdf-t 1` for the scratch vaults. That is
 * not a shortcut around the crypto — the *golden vector* scenario opens a real file written at
 * the released parameters — it is the difference between a suite that runs in seconds and one
 * nobody runs.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

import { cli, cliOk, scratch, tryExec, canary } from "../../lib/harness.mjs";
import { recordText } from "../../lib/artifacts.mjs";

const PASSWORD = "correct horse battery staple";
const CHEAP_KDF = ["--kdf-m-kib", "8", "--kdf-t", "1"];

/** Exit codes the CLI documents in `--help`. */
const EXIT = {
  ok: 0,
  error: 1,
  usage: 2,
  unlockFailed: 3,
  noVault: 4,
  vaultExists: 5,
  notFound: 6,
  importFailed: 7,
};

let vaultCounter = 0;

/** A fresh vault for one scenario, with the recovery code it printed. */
function newVault(label) {
  vaultCounter += 1;
  const dir = scratch(`cli-${vaultCounter}-${label}`);
  const vault = path.join(dir, "test.kagivault");
  const created = cliOk(["vault", "init", "--password-stdin", ...CHEAP_KDF], {
    vault,
    stdin: [PASSWORD],
  });
  const code = /\n\s{2,}([A-Z0-9]{6}(?:-[A-Z0-9]{6})+)\s*\n/.exec(created.stdout);
  assert.ok(code, `vault init should print a recovery code, got:\n${created.stdout}`);
  return { dir, vault, recoveryCode: code[1] };
}

// -------------------------------------------------------------------------------------------
// Creation, recovery and the wrong password
// -------------------------------------------------------------------------------------------

test("vault init prints a one-time recovery code and refuses to overwrite", () => {
  const { vault, recoveryCode } = newVault("init");

  assert.match(
    recoveryCode,
    /^[A-Z0-9]{6}(-[A-Z0-9]{6}){5,}$/,
    "the recovery code is printed as groups of six characters",
  );
  assert.equal(fs.statSync(vault).mode & 0o777, 0o600, "the vault file is owner read/write only");

  const again = cli(["vault", "init", "--password-stdin", ...CHEAP_KDF], {
    vault,
    stdin: [PASSWORD],
  });
  assert.equal(again.code, EXIT.vaultExists, again.stderr);
  assert.match(again.stderr, /already exists/);
});

test("the recovery code unlocks the vault and sets a new master password", () => {
  const { vault, recoveryCode } = newVault("recover");
  const newPassword = "a brand new master password";

  cliOk(["item", "add", "--password-stdin", "--title", "Before recovery"], {
    vault,
    stdin: [PASSWORD],
  });

  const recovered = cliOk(["recover", "--password-stdin"], {
    vault,
    stdin: [recoveryCode, newPassword],
  });
  assert.match(recovered.stdout + recovered.stderr, /unlock|password|recover/i);

  const withNew = cliOk(["item", "list", "--password-stdin"], { vault, stdin: [newPassword] });
  assert.match(withNew.stdout, /Before recovery/, "the items survive a recovery");

  const withOld = cli(["item", "list", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.equal(
    withOld.code,
    EXIT.unlockFailed,
    "the old master password must stop working after recovery",
  );
});

test("a wrong master password fails with exit code 3 and says nothing about the vault", () => {
  const { vault } = newVault("wrong-password");
  const secret = canary("WRONGPW");
  cliOk(["item", "add", "--password-stdin", "--value-stdin", "--title", "Hidden", "--secret", "k"], {
    vault,
    stdin: [PASSWORD, secret],
  });

  const wrong = cli(["item", "list", "--password-stdin"], { vault, stdin: ["not the password"] });
  assert.equal(wrong.code, EXIT.unlockFailed);
  assert.match(wrong.stderr, /decryption failed/);
  assert.ok(
    !`${wrong.stdout}${wrong.stderr}`.includes(secret),
    "a failed unlock must not leak anything from the body",
  );
  assert.ok(
    !/Hidden/.test(`${wrong.stdout}${wrong.stderr}`),
    "a failed unlock must not leak item titles either",
  );
});

test("no vault at the given path is its own exit code, not a decryption failure", () => {
  const dir = scratch("cli-missing");
  const missing = cli(["item", "list", "--password-stdin"], {
    vault: path.join(dir, "nothing-here.kagivault"),
    stdin: [PASSWORD],
  });
  assert.equal(missing.code, EXIT.noVault, missing.stderr);
  assert.match(missing.stderr, /no vault at/);
});

// -------------------------------------------------------------------------------------------
// Tamper detection
// -------------------------------------------------------------------------------------------

/**
 * Flip one bit at `offset` and assert the file no longer opens.
 *
 * The header is plaintext CBOR but is **authenticated** — the byte range from `MAGIC` through the
 * end of the header is the AEAD's associated data (vault-format §2) — so a single flipped bit in
 * the KDF salt has to be as fatal as a flipped bit in the ciphertext. That is the property these
 * two scenarios exist for, and it is why they flip a byte rather than truncating the file: a
 * truncation is caught by a length check that proves nothing about the AEAD.
 */
function assertTamperRejected(vault, offset, what) {
  const bytes = fs.readFileSync(vault);
  assert.ok(offset < bytes.length, `${what}: offset ${offset} is past the end of the file`);
  bytes[offset] ^= 0x01;
  fs.writeFileSync(vault, bytes);

  const opened = cli(["item", "list", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.equal(
    opened.code,
    EXIT.unlockFailed,
    `${what} should be refused with exit ${EXIT.unlockFailed}, got ${opened.code}: ` +
      `${opened.stdout}${opened.stderr}`,
  );
  assert.ok(
    !/^\s*ID\s+TITLE/m.test(opened.stdout),
    `${what} must not produce a listing`,
  );
  return opened;
}

test("a tampered header is refused, whether or not the CBOR survives", (t) => {
  const said = [];

  // (a) A flipped bit that leaves the CBOR *well formed*: it changes a value inside the
  // authenticated byte range, so it has to fail the body's AEAD tag exactly as a flipped bit in
  // the ciphertext does. This is the case the "the header is authenticated" claim is about.
  {
    const { vault } = newVault("tamper-header-value");
    cliOk(["item", "add", "--password-stdin", "--title", "Tampered"], { vault, stdin: [PASSWORD] });
    const bytes = fs.readFileSync(vault);
    const at = bytes.indexOf("vault_id", 0, "latin1");
    assert.ok(at > 0, "the plaintext header names vault_id");
    // Past the key and the one-byte `bytes(16)` marker, so the flip lands on the id itself.
    const refused = assertTamperRejected(vault, at + "vault_id".length + 1, "an edited header value");
    assert.match(refused.stderr, /tampered/, refused.stderr);
    said.push(`edited header value:\n  ${refused.stderr.trim()}`);
  }

  // (b) A flipped bit that breaks the CBOR structure. The decoder rejects it before the AEAD is
  // reached — a different code path, and it must still be exit 3, because which of the two a
  // corruption produces depends only on where the byte fell.
  {
    const { vault } = newVault("tamper-header-structure");
    cliOk(["item", "add", "--password-stdin", "--title", "Tampered"], { vault, stdin: [PASSWORD] });
    const refused = assertTamperRejected(vault, 24, "a broken header structure");
    said.push(`broken header structure:\n  ${refused.stderr.trim()}`);
  }

  recordText(t.name, "tampered-header.txt", said.join("\n\n"), "what the CLI said");
});

test("a truncated vault is refused", () => {
  const { vault } = newVault("truncated");
  cliOk(["item", "add", "--password-stdin", "--title", "Truncated"], { vault, stdin: [PASSWORD] });
  const bytes = fs.readFileSync(vault);
  fs.writeFileSync(vault, bytes.subarray(0, Math.floor(bytes.length / 2)));

  const opened = cli(["item", "list", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.equal(opened.code, EXIT.unlockFailed, `${opened.stdout}${opened.stderr}`);
});

test("a tampered body is refused", (t) => {
  const { vault } = newVault("tamper-body");
  cliOk(["item", "add", "--password-stdin", "--title", "Tampered"], { vault, stdin: [PASSWORD] });

  const size = fs.statSync(vault).size;
  const refused = assertTamperRejected(vault, size - 8, "a flipped bit in the ciphertext");
  recordText(t.name, "tampered-body.txt", refused.stderr, "what the CLI said");
});

// -------------------------------------------------------------------------------------------
// KDF parameter bounds
// -------------------------------------------------------------------------------------------

test("KDF parameters outside their bounds are refused at vault creation", () => {
  const dir = scratch("cli-kdf-bounds");

  // Argon2's own minimums: m_cost 8 KiB, t_cost 1, p_cost 1. The maximums kagisecure sets are
  // 1 GiB, 64 and 16 (crates/kagisecure-core/src/crypto/kdf.rs).
  const outOfBounds = [
    { flags: ["--kdf-m-kib", "4"], what: "memory below Argon2's 8 KiB minimum" },
    { flags: ["--kdf-m-kib", "2097152"], what: "memory above the 1 GiB maximum" },
    { flags: ["--kdf-t", "0"], what: "zero iterations" },
    { flags: ["--kdf-t", "65"], what: "more than 64 iterations" },
    { flags: ["--kdf-p", "0"], what: "zero parallelism" },
    { flags: ["--kdf-p", "17"], what: "parallelism above 16" },
  ];

  for (const [index, item] of outOfBounds.entries()) {
    const vault = path.join(dir, `bounds-${index}.kagivault`);
    const result = cli(["vault", "init", "--password-stdin", ...CHEAP_KDF, ...item.flags], {
      vault,
      stdin: [PASSWORD],
    });
    assert.notEqual(result.code, EXIT.ok, `${item.what} should be refused`);
    assert.equal(
      fs.existsSync(vault),
      false,
      `${item.what} must not leave a vault file behind`,
    );
  }
});

test("KDF parameters at the edge of their bounds are accepted and recorded in the header", () => {
  const dir = scratch("cli-kdf-edge");
  const vault = path.join(dir, "edge.kagivault");
  cliOk(
    [
      "vault",
      "init",
      "--password-stdin",
      "--kdf-m-kib",
      "8",
      "--kdf-t",
      "1",
      "--kdf-p",
      "1",
      "--kdf-hint",
      "e2e-minimum",
    ],
    { vault, stdin: [PASSWORD] },
  );

  const opened = cliOk(["vault", "unlock", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.match(opened.stdout, /8/, `the summary should report the parameters: ${opened.stdout}`);

  // The header is plaintext CBOR, so the hint is readable without the password. That is by
  // design — the hint exists to tell a future reader which profile wrote the file.
  const header = fs.readFileSync(vault).toString("latin1").slice(0, 1024);
  assert.match(header, /e2e-minimum/, "the KDF hint is recorded in the plaintext header");
});

// -------------------------------------------------------------------------------------------
// The item lifecycle, and the two rules about revealing
// -------------------------------------------------------------------------------------------

test("item add, list, show and rm round-trip", () => {
  const { vault } = newVault("items");
  const secret = canary("ITEM");

  const added = cliOk(
    [
      "item",
      "add",
      "--password-stdin",
      "--value-stdin",
      "--title",
      "Acme staging",
      "--category",
      "api-credential",
      "--field",
      "endpoint=https://api.acme.example",
      "--secret",
      "key",
      "--tag",
      "work",
      "--url",
      "https://acme.example",
    ],
    { vault, stdin: [PASSWORD, secret] },
  );
  const id = /Added ([0-9a-f-]{36})/.exec(added.stdout);
  assert.ok(id, `item add should print the new id: ${added.stdout}`);

  const listed = cliOk(["item", "list", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.match(listed.stdout, /Acme staging/);
  assert.match(listed.stdout, /api-credential/);
  assert.ok(!listed.stdout.includes(secret), "a listing never contains a value");

  const shown = cliOk(["item", "show", "--password-stdin", "Acme staging"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.match(shown.stdout, /endpoint/);
  assert.match(shown.stdout, /key/);
  assert.ok(!shown.stdout.includes(secret), "`item show` without --reveal never prints a value");

  const removed = cliOk(["item", "rm", "--password-stdin", id[1]], { vault, stdin: [PASSWORD] });
  assert.ok(removed.code === 0);

  const gone = cli(["item", "show", "--password-stdin", "Acme staging"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.equal(gone.code, EXIT.notFound, gone.stderr);
});

test("--reveal prints the value and --json never does, even together", (t) => {
  const { vault } = newVault("reveal");
  const secret = canary("REVEAL");
  cliOk(
    ["item", "add", "--password-stdin", "--value-stdin", "--title", "Revealable", "--secret", "key"],
    { vault, stdin: [PASSWORD, secret] },
  );

  const revealed = cliOk(["item", "show", "--password-stdin", "--reveal", "Revealable"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(
    revealed.stdout.includes(secret),
    "--reveal is the CLI's own trusted affordance and must show the value",
  );

  // The rule that matters: `--json` is a machine-readable *metadata* format, and adding --reveal
  // does not change that. ADR-0002 and ADR-0005; the CLI's help says so in as many words.
  const both = cliOk(["item", "show", "--password-stdin", "--reveal", "--json", "Revealable"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(
    !both.stdout.includes(secret),
    "`--json --reveal` must still not contain the value",
  );
  const parsed = JSON.parse(both.stdout);
  assert.equal(parsed.title, "Revealable");
  const field = parsed.fields.find((f) => f.label === "key");
  assert.equal(field.concealed, true);
  assert.equal(field.has_value, true);
  assert.ok(!("value" in field), "a JSON field carries no `value` property at all");

  recordText(
    t.name,
    "show-json.txt",
    both.stdout,
    "`item show --reveal --json` — metadata, no value",
  );
});

test("agent access is default-deny on a new item", () => {
  const { vault } = newVault("default-deny");
  cliOk(["item", "add", "--password-stdin", "--title", "Fresh"], { vault, stdin: [PASSWORD] });

  const shown = cliOk(["item", "show", "--password-stdin", "--json", "Fresh"], {
    vault,
    stdin: [PASSWORD],
  });
  const parsed = JSON.parse(shown.stdout);
  assert.equal(parsed.agent_visible, false, "a new item is not visible to agents");
  for (const field of parsed.fields) {
    assert.equal(field.agent_visible, false, `field ${field.label} is not visible to agents`);
  }
});

// -------------------------------------------------------------------------------------------
// The generator
// -------------------------------------------------------------------------------------------

test("generate honours every mode and the character-class switches", (t) => {
  const samples = {};

  const plain = cliOk(["generate", "--length", "40"]).stdout.trim();
  samples.default = plain;
  assert.equal(plain.length, 40);

  const digitsOnly = cliOk([
    "generate",
    "--length", "32",
    "--no-lowercase",
    "--no-uppercase",
    "--no-symbols",
  ]).stdout.trim();
  samples.digitsOnly = digitsOnly;
  assert.match(digitsOnly, /^[0-9]{32}$/, "only digits were allowed");

  const noSymbols = cliOk(["generate", "--length", "48", "--no-symbols"]).stdout.trim();
  samples.alphanumeric = noSymbols;
  assert.match(noSymbols, /^[A-Za-z0-9]{48}$/);

  const unambiguous = cliOk([
    "generate",
    "--length", "64",
    "--avoid-ambiguous",
    "--no-symbols",
  ]).stdout.trim();
  samples.unambiguous = unambiguous;
  assert.ok(
    !/[0O1lI]/.test(unambiguous),
    `--avoid-ambiguous must leave out 0 O 1 l I, got ${unambiguous}`,
  );

  const words = cliOk(["generate", "--words", "5", "--separator", "hyphen"]).stdout.trim();
  samples.words = words;
  assert.equal(words.split("-").length, 5, `five words: ${words}`);

  const capitalized = cliOk([
    "generate",
    "--words", "4",
    "--capitalize",
    "--include-digit",
    "--separator", "period",
  ]).stdout.trim();
  samples.capitalized = capitalized;
  assert.ok(/\d/.test(capitalized), `--include-digit must add a digit: ${capitalized}`);
  assert.ok(/[A-Z]/.test(capitalized), `--capitalize must capitalize: ${capitalized}`);

  const several = cliOk(["generate", "--count", "5", "--length", "16"]).stdout.trim().split("\n");
  assert.equal(several.length, 5);
  assert.equal(new Set(several).size, 5, "five generated passwords should not repeat");

  // Two runs of the same recipe must differ. A generator that is deterministic across processes
  // is the single worst bug this tool could have, and it is invisible to every other test.
  const again = cliOk(["generate", "--length", "40"]).stdout.trim();
  assert.notEqual(again, plain, "two invocations must not produce the same password");

  recordText(
    t.name,
    "generated.txt",
    Object.entries(samples)
      .map(([k, v]) => `${k.padEnd(14)} ${v}`)
      .join("\n"),
    "one sample per mode (thrown away with the run directory)",
  );
});

test("generate clamps a length outside its range rather than producing a weak password", () => {
  // The core clamps to MIN_LENGTH..=MAX_LENGTH (8..=128) and MIN_WORDS..=MAX_WORDS (3..=10)
  // rather than erroring — see `crates/kagisecure-core/src/generator/mod.rs`. What matters to a
  // caller is that the *floor* is enforced: `--length 1` must never hand back a one-character
  // password. This asserts the CLI passes the value through to that clamp rather than doing its
  // own validation, which is the way the two could drift apart.
  assert.equal(cliOk(["generate", "--length", "1"]).stdout.trim().length, 8);
  assert.equal(cliOk(["generate", "--length", "7"]).stdout.trim().length, 8);
  assert.equal(cliOk(["generate", "--length", "129"]).stdout.trim().length, 128);
  assert.equal(cliOk(["generate", "--length", "99999"]).stdout.trim().length, 128);
  assert.equal(cliOk(["generate", "--words", "1"]).stdout.trim().split("-").length, 3);
  assert.equal(cliOk(["generate", "--words", "99"]).stdout.trim().split("-").length, 10);

  // An empty alphabet is a recipe that cannot be satisfied at all, and that *is* an error rather
  // than something to clamp: there is no safe password to fall back to.
  const noAlphabet = cli([
    "generate",
    "--no-lowercase",
    "--no-uppercase",
    "--no-digits",
    "--no-symbols",
  ]);
  assert.notEqual(noAlphabet.code, EXIT.ok, "an empty alphabet must be refused, not looped on");
  assert.match(noAlphabet.stderr, /no character class is enabled/);
});

// -------------------------------------------------------------------------------------------
// TOTP, against an implementation that shares no code with ours
// -------------------------------------------------------------------------------------------

/**
 * RFC 6238 in Python, from `hmac` and `base64` and nothing else.
 *
 * The point of an independent implementation is that it shares no code with the thing under test:
 * a bug in our base32 decoding, our counter endianness or our dynamic truncation shows up here as
 * a disagreement, where a Rust test written against the same helpers would agree with itself.
 */
function referenceTotp(secretBase32, counter, digits = 6) {
  const script = [
    "import base64, hmac, hashlib, struct, sys",
    "key = base64.b32decode(sys.argv[1], casefold=True)",
    "counter = int(sys.argv[2])",
    "digits = int(sys.argv[3])",
    "mac = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()",
    "offset = mac[-1] & 0x0f",
    "code = struct.unpack('>I', mac[offset:offset+4])[0] & 0x7fffffff",
    "print(str(code % (10 ** digits)).zfill(digits))",
  ].join("\n");
  const out = tryExec("/usr/bin/python3", [
    "-c",
    script,
    secretBase32,
    String(counter),
    String(digits),
  ]);
  return out === null ? null : out.trim();
}

test("totp agrees with an independent RFC 6238 implementation", (t) => {
  const secret = "JBSWY3DPEHPK3PXP";
  const uri = `otpauth://totp/Kagisecure%20E2E:alice@example.test?secret=${secret}&issuer=Kagisecure`;

  const probe = referenceTotp(secret, 0);
  if (probe === null) {
    t.skip("no /usr/bin/python3 on this machine, so there is nothing to check against");
    return;
  }

  const { vault } = newVault("totp");
  cliOk(
    ["item", "add", "--password-stdin", "--value-stdin", "--title", "TOTP item", "--totp", "code"],
    { vault, stdin: [PASSWORD, uri] },
  );

  // The counter can tick between the reference and the CLI, so both windows are computed and the
  // CLI's answer must be one of them. Anything else is a real disagreement rather than a race.
  const before = Math.floor(Date.now() / 1000 / 30);
  const produced = cliOk(["totp", "--password-stdin", "TOTP item"], {
    vault,
    stdin: [PASSWORD],
  }).stdout.trim();
  const after = Math.floor(Date.now() / 1000 / 30);

  const acceptable = [...new Set([before, after])].map((c) => referenceTotp(secret, c));
  const code = /\d{6}/.exec(produced);
  assert.ok(code, `the CLI should print a six-digit code, got ${JSON.stringify(produced)}`);
  assert.ok(
    acceptable.includes(code[0]),
    `kagisecure produced ${code[0]}; Python says ${acceptable.join(" or ")} ` +
      `for counter ${before}${before === after ? "" : `/${after}`}`,
  );

  recordText(
    t.name,
    "totp.txt",
    [
      `secret       ${secret}   (a public RFC test vector, not anybody's)`,
      `counter      ${before}${before === after ? "" : ` or ${after}`}`,
      `kagisecure   ${code[0]}`,
      `python3      ${acceptable.join(" or ")}`,
    ].join("\n"),
    "kagisecure against Python's hmac",
  );
});

test("totp on an item with no one-time-password field is an error, not an empty code", () => {
  const { vault } = newVault("totp-missing");
  cliOk(["item", "add", "--password-stdin", "--title", "No code here"], {
    vault,
    stdin: [PASSWORD],
  });
  const result = cli(["totp", "--password-stdin", "No code here"], { vault, stdin: [PASSWORD] });
  assert.notEqual(result.code, EXIT.ok);
  assert.equal(result.stdout.trim(), "", "nothing that looks like a code is printed");
});

// -------------------------------------------------------------------------------------------
// The golden vector
// -------------------------------------------------------------------------------------------

test("the committed golden vault still opens at its released KDF parameters", (t) => {
  const source = path.join(
    process.env.E2E_REPO_ROOT || path.resolve(import.meta.dirname, "..", "..", ".."),
    "crates/kagisecure-core/tests/vectors/v1-argon2id-64k.kagivault",
  );
  assert.ok(fs.existsSync(source), `the golden vector should be committed at ${source}`);

  // Copied out, because opening does not write today but a future change might, and a test that
  // mutates a committed fixture is a test that destroys the thing it exists to protect.
  const dir = scratch("cli-golden");
  const vault = path.join(dir, "golden.kagivault");
  fs.copyFileSync(source, vault);
  fs.chmodSync(vault, 0o600);

  const goldenPassword = "golden vector password";
  const listed = cliOk(["item", "list", "--password-stdin"], { vault, stdin: [goldenPassword] });
  assert.match(listed.stdout, /Golden vector/, listed.stdout);

  const shown = cliOk(["item", "show", "--password-stdin", "--json", "Golden vector"], {
    vault,
    stdin: [goldenPassword],
  });
  const item = JSON.parse(shown.stdout);
  assert.equal(item.category, "ApiCredential");
  assert.deepEqual(
    item.fields.map((f) => f.label),
    ["username", "token"],
  );

  const revealed = cliOk(["item", "show", "--password-stdin", "--reveal", "Golden vector"], {
    vault,
    stdin: [goldenPassword],
  });
  assert.match(
    revealed.stdout,
    /vector-token-value/,
    "the golden vector's known value must still decrypt to the same bytes",
  );

  recordText(
    t.name,
    "golden.txt",
    `${listed.stdout}\n${shown.stdout}`,
    "the golden vector, opened by today's binary",
  );

  assert.equal(
    fs.readFileSync(source).equals(fs.readFileSync(vault)),
    true,
    "the committed fixture is byte-identical after the run",
  );
});

test("the audit chain of a vault the CLI wrote verifies", (t) => {
  const { vault } = newVault("audit");
  cliOk(["env", "create", "--password-stdin", "audit / demo"], { vault, stdin: [PASSWORD] });
  cliOk(["item", "add", "--password-stdin", "--title", "Audited"], { vault, stdin: [PASSWORD] });

  const verified = cliOk(["audit", "--password-stdin", "--verify"], { vault, stdin: [PASSWORD] });
  assert.match(verified.stdout, /intact/i, verified.stdout);
  recordText(t.name, "audit.txt", verified.stdout, "kagisecure audit --verify");
});

// -------------------------------------------------------------------------------------------
// `kagisecure import` (plan §4, §6) — a synthetic 1PUX archive, built here rather than checked
// in, so a marker password can be planted in it and traced all the way through.
// -------------------------------------------------------------------------------------------

/** CRC-32 (IEEE 802.3), the checksum every zip entry carries. */
function crc32(buf) {
  let crc = ~0;
  for (const byte of buf) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return ~crc >>> 0;
}

/**
 * A minimal zip archive: `entries` as `{ name, data }` pairs, each deflated and given a local
 * file header, a matching central-directory record, and one end-of-central-directory record.
 * No third-party zip library — this is the "minimal zip writer" the plan calls for, built with
 * `node:zlib` for the compression and hand-rolled framing for the rest.
 */
function buildZip(entries) {
  const DOS_TIME = 0; // no timestamp claimed
  const DOS_DATE = 0x21; // 1980-01-01, the zip epoch's own placeholder date
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const compressed = zlib.deflateRawSync(data);
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed to extract
    local.writeUInt16LE(0, 6); // general purpose flag
    local.writeUInt16LE(8, 8); // method: deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    localParts.push(local, nameBuf, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed to extract
    central.writeUInt16LE(0, 8); // general purpose flag
    central.writeUInt16LE(8, 10); // method: deflate
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); // extra field length
    central.writeUInt16LE(0, 32); // file comment length
    central.writeUInt16LE(0, 34); // disk number start
    central.writeUInt16LE(0, 36); // internal file attributes
    central.writeUInt32LE(0, 38); // external file attributes
    central.writeUInt32LE(offset, 42); // relative offset of local header
    centralParts.push(central, nameBuf);

    offset += local.length + nameBuf.length + compressed.length;
  }

  const centralDirOffset = offset;
  const centralDirSize = centralParts.reduce((sum, buf) => sum + buf.length, 0);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk where central directory starts
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirSize, 12);
  eocd.writeUInt32LE(centralDirOffset, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

/**
 * A minimal hand-written 1PUX archive: one login item, shaped as `docs/import.md` §2.1
 * describes it. The field names marked "unverified" there are reproduced as documented.
 */
function buildOnePux({ title, username, password }) {
  const attributes = {
    version: 1,
    description: "kagisecure e2e test fixture",
    createdAt: 1_700_000_000,
  };
  const data = {
    accounts: [
      {
        attrs: {
          accountName: "Test Account",
          name: "Ada",
          email: "ada@example.com",
          uuid: "account-0001",
        },
        vaults: [
          {
            attrs: { uuid: "vault-0001", desc: "", name: "Personal", type: "U" },
            items: [
              {
                uuid: "item-0001",
                favIndex: 0,
                createdAt: 1_700_000_000,
                updatedAt: 1_700_000_000,
                state: "active",
                categoryUuid: "001",
                overview: {
                  title,
                  url: "https://acme.example.com/login",
                  urls: [{ label: "website", url: "https://acme.example.com/login" }],
                  tags: [],
                },
                details: {
                  loginFields: [
                    { value: username, name: "username", type: "T", designation: "username" },
                    { value: password, name: "password", type: "P", designation: "password" },
                  ],
                  notesPlain: "",
                  sections: [],
                  passwordHistory: [],
                },
              },
            ],
          },
        ],
      },
    ],
  };

  return buildZip([
    { name: "export.attributes", data: Buffer.from(JSON.stringify(attributes)) },
    { name: "export.data", data: Buffer.from(JSON.stringify(data)) },
  ]);
}

test("import: a garbage source is refused with exit code 7, not 1 or 2", () => {
  const dir = scratch("cli-import-garbage");
  const { vault } = newVault("import-garbage");
  const source = path.join(dir, "export.1pux");
  fs.writeFileSync(source, "not an export of anything\n");

  const result = cli(["import", source, "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.equal(result.code, EXIT.importFailed, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});

test("import: a synthetic 1PUX round-trips through --dry-run and --report without the marker ever appearing, then lands as the item's real value", (t) => {
  const { vault } = newVault("import");
  const marker = canary("KSIMPORT");

  const dir = scratch("cli-import-source");
  const source = path.join(dir, "export.1pux");
  fs.writeFileSync(source, buildOnePux({ title: "Acme staging", username: "ada", password: marker }));
  const reportPath = path.join(dir, "report.md");

  // `--dry-run`: the report is built and printed, but nothing is written to the vault, and the
  // marker never appears in the process's own output.
  const dryRun = cliOk(["import", source, "--password-stdin", "--dry-run"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(!dryRun.stdout.includes(marker), `dry-run stdout leaked the marker:\n${dryRun.stdout}`);
  const beforeCommit = cli(["item", "show", "--password-stdin", "Acme staging"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.equal(beforeCommit.code, EXIT.notFound, "a dry run must not have created the item");

  // The real import, with a Markdown report written alongside it.
  const imported = cliOk(["import", source, "--password-stdin", "--report", reportPath], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(!imported.stdout.includes(marker), `import stdout leaked the marker:\n${imported.stdout}`);
  assert.match(imported.stdout, /Imported 1 item/);

  const report = fs.readFileSync(reportPath, "utf8");
  assert.ok(!report.includes(marker), `the report leaked the marker:\n${report}`);
  assert.match(report, /Acme staging/, "the title is metadata and is expected in the report");
  assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600, "the report is written mode 0600");

  // `item list`: titles and categories only, never the marker.
  const listed = cliOk(["item", "list", "--password-stdin"], { vault, stdin: [PASSWORD] });
  assert.match(listed.stdout, /Acme staging/);
  assert.ok(!listed.stdout.includes(marker), `item list leaked the marker:\n${listed.stdout}`);

  // Proof the marker actually landed as the item's password, and only shows up with --reveal.
  const hidden = cliOk(["item", "show", "--password-stdin", "Acme staging"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(!hidden.stdout.includes(marker), `item show without --reveal leaked the marker`);

  const revealed = cliOk(["item", "show", "--password-stdin", "--reveal", "Acme staging"], {
    vault,
    stdin: [PASSWORD],
  });
  assert.ok(
    revealed.stdout.includes(marker),
    `item show --reveal should print the imported password:\n${revealed.stdout}`,
  );

  recordText(
    t.name,
    "import-report.md",
    report,
    "the import report kagisecure wrote — values-free by construction",
  );
});
