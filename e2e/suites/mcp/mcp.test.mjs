/**
 * Suite A — the MCP agent flow, across three real processes.
 *
 * ```text
 *   this file  ──stdio JSON-RPC──▶  kagisecure-mcp  ──unix socket──▶  kagisecure daemon
 *   (the MCP client)                (the sidecar)                     (holds the vault)
 * ```
 *
 * Nothing in that picture is a stub except the human. `kagisecure daemon --auto-approve` is the
 * debug-only affordance from ADR-0007: the request still goes through `ApprovalQueue::ask` and is
 * answered through `ApprovalQueue::resolve`, so the production approval path runs with a robot in
 * the chair rather than a bypass around it, and a release build refuses the flag outright.
 *
 * # The canary
 *
 * Every fixture seeds a 32-byte random marker as a **secret value** in the vault, and every
 * scenario that could conceivably return one asserts the marker is absent from the tool result,
 * from the sidecar's raw stdout, and from its stderr. The marker is random per run, so a scenario
 * cannot accidentally pass by matching a stale constant, and it is compared against the *raw byte
 * stream* rather than a parsed object — which is why this file speaks JSON-RPC directly instead of
 * using an MCP client library, since a client library consumes the stream before a test can see it
 * (`crates/kagisecure-cli/tests/mcp.rs` hand-rolls the protocol for the same reason).
 *
 * # Scenario independence
 *
 * Each scenario builds its own vault, its own socket and its own daemon, and tears them down in
 * `t.after` — registered *before* anything that can throw, so a failing assertion still stops the
 * daemon it started. Scenarios can therefore be reordered, run alone with `--test-name-pattern`,
 * or run repeatedly.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import {
  canary,
  cli,
  cliOk,
  scratch,
  socketPath,
  startDaemon,
  Sidecar,
  waitFor,
  CHEAP_KDF,
} from "../../lib/harness.mjs";
import { recordText } from "../../lib/artifacts.mjs";

const PASSWORD = "correct horse battery staple";

/**
 * The fifteen tools, and no sixteenth. `docs/mcp-server.md` §2 and the pinned list in
 * `crates/kagisecure-mcp/src/server.rs` are what this is held to. ADR-0048 added the three
 * `*_test_login*` tools; ADR-0049 added `store_command_output`; ADR-0050 added
 * `request_type`.
 */
const EXPECTED_TOOLS = [
  "add_variables",
  "create_environment",
  "create_test_login",
  "describe_item",
  "list_environments",
  "list_items",
  "list_test_logins",
  "list_vaults",
  "request_fill",
  "request_type",
  "revoke_env_file",
  "run_with_env",
  "store_command_output",
  "trash_test_logins",
  "write_env_file",
];

let counter = 0;

/**
 * A vault, a daemon and a project directory, all fresh.
 *
 * The vault holds two logical trees on purpose:
 *
 * * `Acme staging` / `acme / staging` — made visible to agents, with the canary as its value.
 * * `Private thing` / `private / env` — explicitly hidden from agents (`item agent-visible off`,
 *   and an environment created without `--agent-visible`), so "the agent cannot see it" means
 *   the rule refused rather than the vault being empty.
 *
 * Since 2026-10-04 a new item is agent-visible by default (the vault's "Show new items to
 * agents" setting is on), so `Acme staging` is shared by that default alone; a vault itself is
 * still hidden from agents until the user allows it. `hideVault` skips that grant.
 *
 * @param {{ daemonArgs?: string[], label?: string, hideVault?: boolean }} options
 */
async function fixture(
  t,
  { daemonArgs = ["--auto-approve"], label = "mcp", hideVault = false } = {},
) {
  counter += 1;
  const name = `${label}-${counter}`;
  const dir = scratch(name);
  const vault = path.join(dir, "test.kagivault");
  const socket = socketPath(name);
  const project = path.join(dir, "project");
  fs.mkdirSync(project, { recursive: true });

  const marker = canary("KSE2E");
  const pw = { vault, stdin: [PASSWORD] };

  cliOk(["vault", "init", "--password-stdin", ...CHEAP_KDF], pw);
  cliOk(
    [
      "item", "add", "--password-stdin", "--value-stdin",
      "--title", "Acme staging",
      "--category", "api-credential",
      "--field", "endpoint=https://api.acme.example",
      "--secret", "token",
    ],
    { vault, stdin: [PASSWORD, marker] },
  );
  cliOk(
    ["item", "add", "--password-stdin", "--value-stdin", "--title", "Private thing", "--secret", "key"],
    { vault, stdin: [PASSWORD, `${marker}-PRIVATE`] },
  );
  cliOk(["item", "agent-visible", "--password-stdin", "off", "--item", "Private thing"], pw);
  cliOk(["env", "create", "--password-stdin", "acme / staging", "--agent-visible"], pw);
  cliOk(
    ["env", "add-var", "--password-stdin", "--environment", "acme / staging",
      "--name", "ACME_TOKEN", "--bind", "Acme staging/token"],
    pw,
  );
  cliOk(["env", "create", "--password-stdin", "private / env"], pw);
  if (!hideVault) {
    cliOk(
      ["env", "agent-access", "--password-stdin", "--allow", "--logical-vault", "Personal"],
      pw,
    );
  }

  const logPath = path.join(dir, "daemon.log");
  const daemon = await startDaemon({
    vault,
    socket,
    password: PASSWORD,
    args: daemonArgs,
    logPath,
  });

  const sidecar = new Sidecar(socket, { cwd: project });
  const fx = {
    vault, socket, project, marker, daemon, sidecar, logPath, dir,
    /** The `acme / staging` environment id, as the agent itself would discover it. */
    async agentVisibleEnvId() {
      const listed = await sidecar.call("list_environments");
      assert.equal(listed.ok, true, listed.text);
      const env = listed.structured.environments.find((e) => e.name === "acme / staging");
      assert.ok(env, `the shared environment should be listed: ${listed.text}`);
      return env.id;
    },
    /** The audit log, read out of the vault by the CLI rather than over MCP. */
    audit() {
      const out = cliOk(["audit", "--password-stdin", "--json", "--limit", "500"], {
        vault,
        stdin: [PASSWORD],
      });
      return JSON.parse(out.stdout);
    },
    /**
     * Assert the marker is nowhere it could have leaked to.
     *
     * `extra` is whatever the scenario has in hand — a tool result, a file it read — so that a
     * value which escaped into a reply is caught by the scenario that caused it rather than by
     * whichever one happened to look at stdout last.
     */
    assertNoLeak(...extra) {
      const haystacks = [
        ["the sidecar's stdout", sidecar.rawStdout],
        ["the sidecar's stderr", sidecar.rawStderr],
        ["the daemon's output", daemon.output()],
        ...extra.map((value, i) => [
          `the scenario's own value #${i + 1}`,
          typeof value === "string" ? value : JSON.stringify(value),
        ]),
      ];
      for (const [where, haystack] of haystacks) {
        assert.ok(
          !haystack.includes(marker),
          `the canary reached ${where}. That is a secret value crossing the MCP boundary.`,
        );
      }
    },
  };

  // Registered first, and with no assertion between here and the caller's first statement, so a
  // failure anywhere below still stops the daemon and the sidecar this scenario started.
  t.after(() => {
    sidecar.stop();
    daemon.stop();
  });

  await sidecar.initialize();
  return fx;
}

// -------------------------------------------------------------------------------------------
// The tool surface
// -------------------------------------------------------------------------------------------

test("the sidecar exposes exactly fifteen tools, and none of them can take a value", async (t) => {
  const fx = await fixture(t, { label: "tools" });

  const tools = await fx.sidecar.tools();
  const names = tools.map((tool) => tool.name).sort();
  assert.deepEqual(
    names,
    EXPECTED_TOOLS,
    "the tool surface is a fixed list; a sixteenth tool is a design change, not a patch",
  );

  // The invariant ADR-0002 exists for: there is no property anywhere in any schema that a secret
  // value could be passed in or asked for by. `add_variables` is the one people reach for. The
  // walk is over property *names*, at every depth: `request_fill` names the field it fills as an
  // enum member ("password"), which is a choice of field, not a place for a value.
  const schemas = JSON.stringify(tools.map((tool) => tool.inputSchema));
  const properties = [];
  const walk = (node) => {
    if (Array.isArray(node)) {
      node.forEach(walk);
    } else if (node && typeof node === "object") {
      for (const [key, child] of Object.entries(node)) {
        if (key === "properties" && child && typeof child === "object") {
          properties.push(...Object.keys(child));
        }
        walk(child);
      }
    }
  };
  tools.forEach((tool) => walk(tool.inputSchema));
  assert.ok(properties.length > 10, `the walk found only ${properties.length} properties`);
  for (const property of properties) {
    for (const forbidden of ["value", "secret", "password", "reveal"]) {
      assert.ok(
        !property.toLowerCase().includes(forbidden),
        `no tool schema may offer a property named like ${forbidden}; found ${property}`,
      );
    }
  }

  assert.equal(fx.sidecar.serverInfo.name, "kagisecure-mcp");
  assert.match(
    fx.sidecar.instructions,
    /You cannot read a value/,
    "the server instructions tell the model the capability does not exist",
  );

  recordText(
    t.name,
    "tools.txt",
    tools.map((tool) => `${tool.name}\n  ${tool.description}`).join("\n\n"),
    "the fifteen tools as the model sees them",
  );
  fx.assertNoLeak(schemas);
});

// -------------------------------------------------------------------------------------------
// Default-deny
// -------------------------------------------------------------------------------------------

test("list_vaults, list_items and list_environments respect agent visibility", async (t) => {
  const fx = await fixture(t, { label: "deny" });

  const vaults = await fx.sidecar.call("list_vaults");
  assert.equal(vaults.ok, true, vaults.text);
  assert.equal(vaults.structured.vaults.length, 1);
  assert.equal(vaults.structured.vaults[0].name, "Personal");
  assert.equal(vaults.structured.vaults[0].agent_visible, true);

  const items = await fx.sidecar.call("list_items");
  assert.equal(items.ok, true, items.text);
  const titles = items.structured.items.map((i) => i.title);
  assert.deepEqual(
    titles,
    ["Acme staging"],
    "`Acme staging` is listed by the new-items default alone; `Private thing`, explicitly hidden, is not",
  );

  const environments = await fx.sidecar.call("list_environments");
  assert.equal(environments.ok, true, environments.text);
  assert.deepEqual(
    environments.structured.environments.map((e) => e.name),
    ["acme / staging"],
    "an environment created without --agent-visible stays hidden",
  );

  // A vault itself stays hidden until allowed, and hides everything in it, whatever its items say.
  const hidden = await fixture(t, { label: "deny-vault", hideVault: true });
  const hiddenVaults = await hidden.sidecar.call("list_vaults");
  assert.equal(hiddenVaults.ok, true, hiddenVaults.text);
  assert.deepEqual(hiddenVaults.structured.vaults, [], "a vault not allowed to agents is not listed");
  const hiddenItems = await hidden.sidecar.call("list_items");
  assert.equal(hiddenItems.ok, true, hiddenItems.text);
  assert.deepEqual(
    hiddenItems.structured.items,
    [],
    "agent-visible items in a hidden vault are not listed either",
  );
  hidden.assertNoLeak(hiddenVaults.text, hiddenItems.text);

  recordText(
    t.name,
    "default-deny.txt",
    `list_vaults\n${vaults.text}\n\nlist_items\n${items.text}\n\n` +
      `list_environments\n${environments.text}`,
    "what an agent can see of a vault with two items (one hidden) and two environments",
  );
  fx.assertNoLeak(vaults.text, items.text, environments.text);
});

test("an item hidden from agents is indistinguishable from one that does not exist", async (t) => {
  const fx = await fixture(t, { label: "not-visible" });

  // The agent has to name the hidden item somehow. It cannot get the id from `list_items`, which
  // is the point — so this reads it out of the vault the way the *user* would, and asks for it.
  const shown = cliOk(["item", "show", "--password-stdin", "--json", "Private thing"], {
    vault: fx.vault,
    stdin: [PASSWORD],
  });
  const hiddenId = JSON.parse(shown.stdout).id;

  const described = await fx.sidecar.call("describe_item", { item_id: hiddenId });
  assert.equal(described.ok, false, `a hidden item must not be described: ${described.text}`);

  const missing = await fx.sidecar.call("describe_item", {
    item_id: "00000000-0000-4000-8000-000000000000",
  });
  assert.equal(missing.ok, false);

  // One answer for both, code and message. A distinguishable pair would let a caller walk ids
  // and learn which ones name something real in a vault it is not allowed to read — the
  // enumeration `agent_visible` exists to prevent (threat-model M-8, docs/mcp-server.md §7).
  // An earlier draft deliberately separated them; that was an oracle, and the code
  // `NOT_AGENT_VISIBLE` no longer exists.
  assert.equal(described.structured.code, "NOT_FOUND");
  assert.equal(missing.structured.code, "NOT_FOUND");
  assert.equal(
    described.structured.message,
    missing.structured.message,
    "the message must not distinguish a real item from an imaginary one either",
  );

  fx.assertNoLeak(described.text, missing.text);
});

test("describe_item returns labels and kinds, and no value under any argument", async (t) => {
  const fx = await fixture(t, { label: "describe" });

  const items = await fx.sidecar.call("list_items");
  const item = items.structured.items.find((i) => i.title === "Acme staging");

  const described = await fx.sidecar.call("describe_item", { item_id: item.id });
  assert.equal(described.ok, true, described.text);
  const fields = described.structured.fields;
  assert.deepEqual(fields.map((f) => f.label), ["endpoint", "token"]);

  const token = fields.find((f) => f.label === "token");
  assert.equal(token.concealed, true);
  assert.equal(token.has_value, true, "the model is told a value exists");
  assert.ok(!("value" in token), "and is not given it");

  // There is no argument that changes that. Every one of these is either ignored or refused; none
  // of them produces a value, which is the property being pinned.
  for (const extra of [{ reveal: true }, { include_values: true }, { unmask: true }]) {
    const attempt = await fx.sidecar.call("describe_item", { item_id: item.id, ...extra });
    const text = attempt.text || "";
    assert.ok(
      !text.includes(fx.marker),
      `describe_item with ${JSON.stringify(extra)} returned a value`,
    );
  }

  recordText(t.name, "describe.txt", described.text, "describe_item on the shared item");
  fx.assertNoLeak(described.text);
});

// -------------------------------------------------------------------------------------------
// The structural tools
// -------------------------------------------------------------------------------------------

test("create_environment then add_variables leaves the value for the human to type", async (t) => {
  const fx = await fixture(t, { label: "pending" });

  const created = await fx.sidecar.call("create_environment", {
    name: "agent-made / staging",
    description: "created by the e2e suite",
  });
  assert.equal(created.ok, true, created.text);
  const envId = created.structured.id;
  assert.deepEqual(created.structured.variables, []);

  // A variable with no binding is *pending*: the agent named it, and the human supplies the value
  // in the app. There is no round trip in which the agent could supply it instead.
  const added = await fx.sidecar.call("add_variables", {
    environment_id: envId,
    variables: [
      { name: "STRIPE_SECRET_KEY", hint: "the test-mode key from the Stripe dashboard" },
      { name: "DATABASE_URL" },
    ],
  });
  assert.equal(added.ok, true, added.text);
  assert.equal(added.structured.status, "pending_user_input");
  assert.deepEqual(added.structured.pending.sort(), ["DATABASE_URL", "STRIPE_SECRET_KEY"]);
  assert.deepEqual(added.structured.bound, []);
  assert.match(
    added.structured.deep_link,
    /^kagisecure:\/\/environments\/[0-9a-f-]+\/pending$/,
    "the agent is handed a link that opens the app at the place the human types the value",
  );

  // A variable bound to an existing field is not pending: the value already exists in the vault
  // and the agent still never sees it. `bind_to`'s target must itself be marked visible to
  // agents (docs/mcp-server.md §2.6) — a stricter, per-field grant the item-level
  // `--allow --item` the fixture already ran does not imply, so the human shares this one field
  // explicitly first, the same way `VaultSession.setFieldAgentVisible` does in the app.
  cliOk(
    [
      "env",
      "agent-access",
      "--password-stdin",
      "--allow",
      "--item",
      "Acme staging",
      "--field",
      "token",
    ],
    { vault: fx.vault, stdin: [PASSWORD] },
  );

  const items = await fx.sidecar.call("list_items");
  const item = items.structured.items.find((i) => i.title === "Acme staging");
  const described = await fx.sidecar.call("describe_item", { item_id: item.id });
  const tokenField = described.structured.fields.find((f) => f.label === "token");

  const bound = await fx.sidecar.call("add_variables", {
    environment_id: envId,
    variables: [{ name: "ACME_TOKEN", bind_to: { item_id: item.id, field_id: tokenField.id } }],
  });
  assert.equal(bound.ok, true, bound.text);
  assert.deepEqual(bound.structured.bound, ["ACME_TOKEN"]);

  recordText(
    t.name,
    "pending.txt",
    `create_environment\n${created.text}\n\nadd_variables (pending)\n${added.text}\n\n` +
      `add_variables (bound)\n${bound.text}`,
    "the environment flow, with no value anywhere in it",
  );
  fx.assertNoLeak(created.text, added.text, bound.text);
});

test("add_variables refuses more than fifty variables in one call", async (t) => {
  const fx = await fixture(t, { label: "too-many" });
  const created = await fx.sidecar.call("create_environment", { name: "bulk" });

  const tooMany = await fx.sidecar.call("add_variables", {
    environment_id: created.structured.id,
    variables: Array.from({ length: 51 }, (_, i) => ({ name: `VAR_${i}` })),
  });
  assert.equal(tooMany.ok, false, tooMany.text);
  assert.match(tooMany.structured.message, /At most 50/);
});

// -------------------------------------------------------------------------------------------
// Injection: the .env file
// -------------------------------------------------------------------------------------------

test("write_env_file writes 0600 bytes the caller never sees", async (t) => {
  const fx = await fixture(t, { label: "write-env" });
  const envId = await fx.agentVisibleEnvId();

  const written = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
    ttl_seconds: 900,
  });
  assert.equal(written.ok, true, written.text);
  assert.deepEqual(written.structured.variables_written, ["ACME_TOKEN"]);
  assert.ok(written.structured.lease_id, "a lease id comes back to revoke with");
  assert.ok(written.structured.expires_at, "and an expiry");

  // The reply names the path and the variables. It does not carry the bytes.
  const file = written.structured.path;
  assert.equal(fs.statSync(file).mode & 0o777, 0o600, "the file is owner read/write only");
  const body = fs.readFileSync(file, "utf8");
  assert.match(body, /^# Written by kagisecure\. Do not commit\./);
  assert.ok(body.includes(fx.marker), "the value really did reach the file");
  assert.ok(
    !written.text.includes(fx.marker),
    "and did not reach the caller: the sidecar returned the path, not the bytes",
  );

  // The write is atomic: nothing half-written and no temporary file left behind.
  const strays = fs.readdirSync(fx.project).filter((n) => n.endsWith(".tmp"));
  assert.deepEqual(strays, [], "a completed write leaves no temporary files");

  recordText(t.name, "write-env-file.txt", written.text, "the tool result (no bytes in it)");
  fx.assertNoLeak(written.text);
});

test("write_env_file reports whether the target is gitignored", async (t) => {
  const fx = await fixture(t, { label: "gitignore" });
  const envId = await fx.agentVisibleEnvId();

  // (a) Outside a git work tree there is nothing to say, and the tool says nothing.
  const outside = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(outside.ok, true, outside.text);
  assert.equal(
    outside.structured.gitignored,
    null,
    "null means 'not inside a git work tree', which is not the same as 'not ignored'",
  );

  // (b) Inside one with nothing ignoring it: the warning path. This is the red callout on the
  // approval sheet, and the fact the tool reports it is what lets the sheet show it.
  const repo = scratch(`${path.basename(fx.project)}-repo`);
  cli(["--version"]);
  const { execFileSync } = await import("node:child_process");
  execFileSync("git", ["init", "-q", repo]);
  const exposed = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: repo,
  });
  assert.equal(exposed.ok, true, exposed.text);
  assert.equal(
    exposed.structured.gitignored,
    false,
    "a .env inside a work tree that nothing ignores is the case worth warning about",
  );

  // (c) And with a .gitignore that covers it, the warning goes away.
  fs.writeFileSync(path.join(repo, ".gitignore"), ".env\n");
  const covered = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: repo,
    filename: ".env",
    overwrite: true,
  });
  assert.equal(covered.ok, true, covered.text);
  assert.equal(covered.structured.gitignored, true);

  recordText(
    t.name,
    "gitignore.txt",
    [
      `outside a work tree   gitignored: ${outside.structured.gitignored}`,
      `inside, not ignored   gitignored: ${exposed.structured.gitignored}   <- the warning`,
      `inside, ignored       gitignored: ${covered.structured.gitignored}`,
    ].join("\n"),
    "the three answers write_env_file can give",
  );
  fx.assertNoLeak(outside.text, exposed.text, covered.text);
});

test("write_env_file refuses a file that is already there unless asked to overwrite", async (t) => {
  const fx = await fixture(t, { label: "exists" });
  const envId = await fx.agentVisibleEnvId();

  const first = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(first.ok, true, first.text);

  const second = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(second.ok, false, "a second write must not silently replace the first");
  assert.equal(second.structured.code, "FILE_EXISTS");

  const forced = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
    overwrite: true,
  });
  assert.equal(forced.ok, true, forced.text);
  fx.assertNoLeak(first.text, second.text, forced.text);
});

test("a relative or non-existent directory is INVALID_PATH", async (t) => {
  const fx = await fixture(t, { label: "bad-path" });
  const envId = await fx.agentVisibleEnvId();

  for (const directory of ["relative/path", path.join(fx.project, "does-not-exist")]) {
    const refused = await fx.sidecar.call("write_env_file", {
      environment_id: envId,
      directory,
    });
    assert.equal(refused.ok, false, `${directory} should be refused: ${refused.text}`);
    assert.equal(refused.structured.code, "INVALID_PATH");
  }
});

test("revoke_env_file shreds the file and kills the lease", async (t) => {
  const fx = await fixture(t, { label: "revoke" });
  const envId = await fx.agentVisibleEnvId();

  const written = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  const file = written.structured.path;
  assert.equal(fs.existsSync(file), true);

  const revoked = await fx.sidecar.call("revoke_env_file", {
    lease_id: written.structured.lease_id,
  });
  assert.equal(revoked.ok, true, revoked.text);
  assert.equal(fs.existsSync(file), false, "the file is gone, not just forgotten");

  // Revoking is always allowed and is idempotent: giving access back never needs an approval and
  // never fails because it already happened.
  const again = await fx.sidecar.call("revoke_env_file", {
    lease_id: written.structured.lease_id,
  });
  assert.equal(again.ok, true, `a second revoke should be harmless: ${again.text}`);

  recordText(t.name, "revoke.txt", `${written.text}\n\n${revoked.text}`, "write then revoke");
  fx.assertNoLeak(written.text, revoked.text);
});

// -------------------------------------------------------------------------------------------
// Injection: running a command
// -------------------------------------------------------------------------------------------

test("run_with_env injects into the child and masks the value back out", async (t) => {
  const fx = await fixture(t, { label: "run" });
  const envId = await fx.agentVisibleEnvId();

  const ran = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/usr/bin/printenv",
    args: ["ACME_TOKEN"],
    cwd: fx.project,
  });
  assert.equal(ran.ok, true, ran.text);
  assert.equal(ran.structured.exit_code, 0, "the child really did see the variable");
  assert.equal(
    ran.structured.stdout.trim(),
    "[kagisecure:redacted:ACME_TOKEN]",
    "printenv printed the value and kagisecure replaced it before the caller saw it",
  );
  assert.equal(ran.structured.scrubbed, 1, "one value was masked");
  assert.equal(ran.structured.truncated, false);

  // `output: "none"` still runs the child, still consumes the lease, still audits — it simply
  // does not hand the streams back. The exit code is the whole answer.
  const quiet = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/usr/bin/printenv",
    args: ["ACME_TOKEN"],
    cwd: fx.project,
    output: "none",
  });
  assert.equal(quiet.ok, true, quiet.text);
  assert.equal(quiet.structured.exit_code, 0);
  assert.equal(quiet.structured.stdout, undefined, "no stdout key at all, not an empty string");
  assert.equal(quiet.structured.stderr, undefined);

  // There is no third mode, and asking for one is an error rather than a silent downgrade.
  const unmasked = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/usr/bin/printenv",
    args: ["ACME_TOKEN"],
    cwd: fx.project,
    output: "raw",
  });
  assert.equal(unmasked.ok, false, unmasked.text);
  assert.match(unmasked.structured.message, /There is no unmasked mode/);

  recordText(
    t.name,
    "run-with-env.txt",
    `scrubbed\n${ran.text}\n\nnone\n${quiet.text}\n\nraw (refused)\n${unmasked.text}`,
    "the three things `output` can be",
  );
  fx.assertNoLeak(ran.text, quiet.text, unmasked.text);
});

test("run_with_env with delivery stdin writes the values to the child's input and nowhere else", async (t) => {
  const fx = await fixture(t, { label: "stdin" });
  const envId = await fx.agentVisibleEnvId();

  // ADR-0047: the frame is NAME\0VALUE\0, the environment and the arguments stay clean, and the
  // command's echo of what it read is scrubbed like an echoed environment.
  const ran = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/bin/sh",
    args: ["-c", "cat > stdin.bin; env > environment.txt; cat stdin.bin | tr '\\0' '\\n'"],
    cwd: fx.project,
    delivery: "stdin",
  });
  assert.equal(ran.ok, true, ran.text);
  assert.equal(ran.structured.exit_code, 0);
  assert.deepEqual(
    fs.readFileSync(path.join(fx.project, "stdin.bin")),
    Buffer.from(`ACME_TOKEN\0${fx.marker}\0`),
    "the child read exactly one NAME\\0VALUE\\0 pair",
  );
  const environment = fs.readFileSync(path.join(fx.project, "environment.txt"), "utf8");
  assert.ok(!environment.includes(fx.marker), "the value reached the child's environment");
  assert.ok(!/^ACME_TOKEN=/m.test(environment), "the variable reached the child's environment");
  assert.match(ran.structured.stdout, /\[kagisecure:redacted:ACME_TOKEN\]/);

  // Not an option the tool invents on the fly.
  const odd = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/bin/sh",
    args: ["-c", "true"],
    cwd: fx.project,
    delivery: "argv",
  });
  assert.equal(odd.ok, false, odd.text);

  const entries = fx.audit();
  const allowed = entries.filter(
    (e) => e.tool === "run_with_env" && e.outcome === "Allowed" && `${e.detail || ""}`.startsWith("STDIN "),
  );
  assert.equal(allowed.length, 1, JSON.stringify(entries.map((e) => [e.tool, e.outcome, e.detail])));
  assert.match(allowed[0].detail, /"\/bin\/sh"/);

  recordText(t.name, "run-with-env-stdin.txt", ran.text, "a stdin delivery, as the agent saw it");
  fx.assertNoLeak(ran.text, odd.text, JSON.stringify(entries));
});

test("run_with_env does not invoke a shell", async (t) => {
  const fx = await fixture(t, { label: "no-shell" });
  const envId = await fx.agentVisibleEnvId();

  // `;` and `$(...)` are ordinary characters in an argument, not syntax. If a shell were involved
  // this would create the file.
  const sentinel = path.join(fx.project, "shell-ran");
  const ran = await fx.sidecar.call("run_with_env", {
    environment_id: envId,
    command: "/bin/echo",
    args: [`hello; touch ${sentinel}`, "$(id -un)"],
    cwd: fx.project,
  });
  assert.equal(ran.ok, true, ran.text);
  assert.equal(fs.existsSync(sentinel), false, "no shell interpreted the semicolon");
  assert.match(ran.structured.stdout, /\$\(id -un\)/, "the substitution is literal text");
});

// -------------------------------------------------------------------------------------------
// Leases
// -------------------------------------------------------------------------------------------

test("a live lease is reused, and a use-exhausted one is not", async (t) => {
  const fx = await fixture(t, { label: "uses" });
  const envId = await fx.agentVisibleEnvId();

  // `--auto-approve` grants AllowSession { uses: 10 }, so ten identical requests ride the same
  // lease and the eleventh has to be approved again — which mints a new lease id. That change of
  // id is the only thing a caller can observe about exhaustion, and it is what this asserts.
  const request = {
    environment_id: envId,
    command: "/usr/bin/true",
    args: [],
    cwd: fx.project,
    output: "none",
  };

  const ids = [];
  for (let i = 0; i < 11; i += 1) {
    const ran = await fx.sidecar.call("run_with_env", request);
    assert.equal(ran.ok, true, `call ${i + 1}: ${ran.text}`);
    ids.push(ran.structured.lease_id);
  }

  const first = ids[0];
  assert.equal(
    ids.slice(0, 10).every((id) => id === first),
    true,
    `the first ten calls should share one lease, got ${JSON.stringify(ids.slice(0, 10))}`,
  );
  assert.notEqual(
    ids[10],
    first,
    "the eleventh call exhausted the ten uses and had to be approved again",
  );

  recordText(
    t.name,
    "lease-uses.txt",
    ids.map((id, i) => `${String(i + 1).padStart(2)}  ${id}`).join("\n"),
    "one lease id per call: the same ten times, then a new one",
  );
});

test("a request broader than the lease is approved again rather than widened", async (t) => {
  const fx = await fixture(t, { label: "broader" });
  const envId = await fx.agentVisibleEnvId();

  const narrow = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
    variables: ["ACME_TOKEN"],
  });
  assert.equal(narrow.ok, true, narrow.text);

  // A different directory is a different lease. The match is exact after canonicalization — no
  // prefix matching, which is what stops `/Users/x/code` authorizing `/Users/x/code/../../tmp`.
  const elsewhere = scratch(`${path.basename(fx.project)}-elsewhere`);
  const wider = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: elsewhere,
    variables: ["ACME_TOKEN"],
  });
  assert.equal(wider.ok, true, wider.text);
  assert.notEqual(
    wider.structured.lease_id,
    narrow.structured.lease_id,
    "a second directory needs its own approval, however recent the first one was",
  );
  fx.assertNoLeak(narrow.text, wider.text);
});

test("a lease expires on its own, and the next request is approved afresh", async (t) => {
  const fx = await fixture(t, { label: "expiry" });
  const envId = await fx.agentVisibleEnvId();

  // 60 seconds is the floor: `write_env_file` clamps `ttl_seconds` to 60..=86400 (server.rs), so
  // this scenario cannot be made faster without a clock the IPC boundary does not expose. It is
  // the one slow scenario in the harness, and it is here because "leases are memory-only and die
  // on expiry" is a claim that is either true against a real clock or not made at all.
  const request = {
    environment_id: envId,
    directory: fx.project,
    ttl_seconds: 60,
    overwrite: true,
  };

  const first = await fx.sidecar.call("write_env_file", request);
  assert.equal(first.ok, true, first.text);
  const expiresAt = Date.parse(first.structured.expires_at);
  assert.ok(
    Math.abs(expiresAt - (Date.now() + 60_000)) < 5_000,
    `expires_at should be about a minute out, got ${first.structured.expires_at}`,
  );

  const reused = await fx.sidecar.call("write_env_file", request);
  assert.equal(reused.structured.lease_id, first.structured.lease_id, "still live, still reused");

  await waitFor(() => Date.now() > expiresAt + 2_000, {
    timeoutMs: 90_000,
    intervalMs: 1_000,
    what: "the lease to pass its expiry",
  });

  const afterwards = await fx.sidecar.call("write_env_file", request);
  assert.equal(afterwards.ok, true, afterwards.text);
  assert.notEqual(
    afterwards.structured.lease_id,
    first.structured.lease_id,
    "past its expiry the lease is gone and the request is approved from scratch",
  );

  recordText(
    t.name,
    "lease-expiry.txt",
    [
      `granted   ${first.structured.lease_id}  expires ${first.structured.expires_at}`,
      `reused    ${reused.structured.lease_id}`,
      `after     ${afterwards.structured.lease_id}`,
    ].join("\n"),
    "the lease id before and after the expiry",
  );
});

// -------------------------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------------------------

test("lock kills every lease and every later call is VAULT_LOCKED", async (t) => {
  const fx = await fixture(t, { label: "lock" });
  const envId = await fx.agentVisibleEnvId();

  const written = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(written.ok, true, written.text);
  const file = written.structured.path;
  assert.equal(fs.existsSync(file), true);

  // Locking is an IPC message, not a signal: the same one the app sends and the menu bar's
  // "Lock Now" sends.
  const locked = cliOk(["lock"], { env: { KAGISECURE_SOCKET: fx.socket } });
  assert.match(locked.stdout, /Locked/);

  await waitFor(() => !fs.existsSync(file), {
    timeoutMs: 10_000,
    what: "the lock to shred the file it had written",
  });

  for (const tool of ["list_vaults", "list_items", "list_environments"]) {
    const attempt = await fx.sidecar.call(tool, {});
    assert.equal(attempt.ok, false, `${tool} after a lock should fail: ${attempt.text}`);
    assert.equal(attempt.structured.code, "VAULT_LOCKED", tool);
  }

  const injection = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
    overwrite: true,
  });
  assert.equal(injection.structured.code, "VAULT_LOCKED");

  recordText(
    t.name,
    "lock.txt",
    `${written.text}\n\nafter lock:\n${injection.text}`,
    "an injection, a lock, and what the next call gets",
  );
  fx.assertNoLeak(injection.text);
});

test("with no daemon at all the answer is APP_NOT_RUNNING, immediately", async (t) => {
  const socket = socketPath("nobody-is-listening");
  const sidecar = new Sidecar(socket);
  t.after(() => sidecar.stop());

  await sidecar.initialize();
  const started = Date.now();
  const attempt = await sidecar.call("list_vaults", {}, { timeoutMs: 15_000 });
  const elapsed = Date.now() - started;

  assert.equal(attempt.ok, false, attempt.text);
  assert.equal(attempt.structured.code, "APP_NOT_RUNNING");
  assert.match(
    attempt.structured.message,
    /Do not retry in a loop/,
    "the message is written for the model and tells it what to do next",
  );
  assert.ok(elapsed < 5_000, `it should fail fast, took ${elapsed}ms`);
});

// -------------------------------------------------------------------------------------------
// The audit log
// -------------------------------------------------------------------------------------------

test("every call is audited by name, the chain verifies, and the caller is identified", async (t) => {
  const fx = await fixture(t, { label: "audit" });
  const envId = await fx.agentVisibleEnvId();

  await fx.sidecar.call("list_items");
  const written = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(written.ok, true, written.text);

  const entries = fx.audit();
  const fromMcp = entries.filter((e) => e.actor === "mcp");
  assert.ok(fromMcp.length >= 3, `every tool call is audited: ${JSON.stringify(fromMcp)}`);

  const tools = fromMcp.map((e) => e.tool);
  for (const expected of ["list_environments", "list_items", "write_env_file"]) {
    assert.ok(tools.includes(expected), `${expected} should be in the log, got ${tools}`);
  }

  const injection = fromMcp.find((e) => e.tool === "write_env_file");
  assert.equal(injection.outcome, "Allowed");
  assert.deepEqual(injection.variables, ["ACME_TOKEN"], "names, never values");
  assert.ok(injection.target_path.endsWith("/.env"));
  assert.equal(injection.lease_id, written.structured.lease_id);

  // The caller is identified by the **kernel**, not by what it said about itself: `client_pid`
  // comes from getsockopt(LOCAL_PEERPID). Every entry carries it, which is what makes a burst of
  // denials attributable to a process rather than to "something".
  const sidecarPid = fx.sidecar.child.pid;
  for (const entry of fromMcp) {
    assert.equal(
      entry.client_pid,
      sidecarPid,
      `${entry.tool} should record the sidecar's pid (${sidecarPid}), got ${entry.client_pid}`,
    );
  }

  const verified = cliOk(["audit", "--password-stdin", "--verify"], {
    vault: fx.vault,
    stdin: [PASSWORD],
  });
  assert.match(verified.stdout, /Hash chain intact/, verified.stdout);

  recordText(t.name, "audit.txt", verified.stdout, "kagisecure audit --verify after the run");
  fx.assertNoLeak(JSON.stringify(entries), verified.stdout);
});

test("a refused caller is audited too, and the daemon says the signature is unverified", async (t) => {
  // `--non-interactive` is the daemon with nobody at the terminal: it refuses anything not
  // already covered by a lease. This is the denial path, which the audit log keeps deliberately.
  const fx = await fixture(t, { label: "denied", daemonArgs: ["--non-interactive"] });
  const envId = await fx.agentVisibleEnvId();

  const refused = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  assert.equal(refused.ok, false, refused.text);
  assert.equal(refused.structured.code, "USER_DENIED");
  assert.equal(
    fs.existsSync(path.join(fx.project, ".env")),
    false,
    "a denial writes nothing at all",
  );

  const denial = fx.audit().find((e) => e.tool === "write_env_file");
  assert.ok(denial, "the denial is recorded, not dropped");
  assert.equal(denial.outcome, "Denied");
  assert.equal(denial.detail, "USER_DENIED");
  assert.equal(denial.client_pid, fx.sidecar.child.pid, "and it names who was refused");

  // The headless daemon performs no code-signature check — that is the app's job, and an ad-hoc
  // build could only ever answer "unverified" anyway (ADR-0015). What matters is that the daemon
  // is honest about it rather than presenting a self-reported name as established fact: the name
  // the caller gave for itself is the one this suite made up.
  assert.ok(
    !fx.daemon.output().includes("verified"),
    `the daemon must not claim a verification it did not perform:\n${fx.daemon.output()}`,
  );

  recordText(
    t.name,
    "denied.txt",
    `${refused.text}\n\naudit entry:\n${JSON.stringify(denial, null, 1)}`,
    "a denial, and what the log kept about it",
  );
  fx.assertNoLeak(refused.text);
});

// -------------------------------------------------------------------------------------------
// request_fill, where there is no browser
// -------------------------------------------------------------------------------------------

test("request_fill is FILL_UNAVAILABLE on the headless daemon", async (t) => {
  const fx = await fixture(t, { label: "fill" });
  const items = await fx.sidecar.call("list_items");
  const visible = items.structured.items.find((i) => i.title === "Acme staging");
  assert.ok(visible, items.text);
  // The hidden item's id, read by the CLI — the agent itself cannot see it, which is the point.
  const all = JSON.parse(
    cliOk(["item", "list", "--password-stdin", "--json"], { vault: fx.vault, stdin: [PASSWORD] }).stdout,
  );
  const hidden = (Array.isArray(all) ? all : all.items).find((i) => i.title === "Private thing");
  assert.ok(hidden, "the fixture's hidden item");

  // The daemon has no browser listener and no agent-fill broker, so the tool is refused at its
  // first gate — before the item is looked up (ADR-0036 §11.1). An agent-visible item, a hidden
  // one and an id that exists nowhere therefore get the byte-identical answer, and so does a
  // request for a one-time code.
  const asks = [
    { item_id: visible.id, origin: "https://api.acme.example" },
    { item_id: hidden.id, origin: "https://api.acme.example" },
    { item_id: "00000000-0000-4000-8000-000000000000", origin: "https://api.acme.example" },
    { item_id: visible.id, origin: "https://api.acme.example", fields: ["one_time_code"] },
  ];
  const answers = [];
  for (const args of asks) {
    const answer = await fx.sidecar.call("request_fill", args);
    assert.equal(answer.ok, false, answer.text);
    assert.equal(answer.structured.code, "FILL_UNAVAILABLE", answer.text);
    answers.push(answer);
  }
  for (const answer of answers.slice(1)) {
    assert.equal(
      answer.structured.message,
      answers[0].structured.message,
      "the answer cannot depend on the item it names",
    );
  }
  assert.match(
    answers[0].structured.message,
    /do not retry/i,
    "the message tells the model what to do next",
  );

  // Nothing was asked of anybody, and nothing about the request was looked at, so nothing is
  // recorded (implementation decision 37: the switch off leaves no entry).
  const entries = fx.audit();
  assert.ok(
    !entries.some((e) => e.tool === "request_fill" || e.tool === "totp_code"),
    `a refusal at the first gate writes no audit entry: ${JSON.stringify(entries)}`,
  );

  // Locked, the answer is the same: gate 1 comes before the lock check.
  cliOk(["lock"], { env: { KAGISECURE_SOCKET: fx.socket } });
  const locked = await fx.sidecar.call("request_fill", asks[0]);
  assert.equal(locked.structured.code, "FILL_UNAVAILABLE", locked.text);
  assert.equal(locked.structured.message, answers[0].structured.message);

  recordText(
    t.name,
    "fill-unavailable.txt",
    answers.map((a, i) => `${JSON.stringify(asks[i])}\n→ ${a.text}`).join("\n\n"),
    "four requests, one answer",
  );
  fx.assertNoLeak(...answers, locked);
});

// -------------------------------------------------------------------------------------------
// The canary, on its own
// -------------------------------------------------------------------------------------------

test("the canary never appears in any tool result or on the sidecar's streams", async (t) => {
  const fx = await fixture(t, { label: "canary" });
  const envId = await fx.agentVisibleEnvId();
  const items = await fx.sidecar.call("list_items");
  const item = items.structured.items.find((i) => i.title === "Acme staging");

  // Every tool, in one pass, including the injections. Whatever comes back, the marker is not in
  // it — and afterwards, nor is it anywhere in the bytes the sidecar wrote to either stream.
  const everything = [];
  everything.push(await fx.sidecar.call("list_vaults"));
  everything.push(await fx.sidecar.call("list_items", { query: "acme" }));
  everything.push(await fx.sidecar.call("list_environments"));
  everything.push(await fx.sidecar.call("describe_item", { item_id: item.id }));
  const made = await fx.sidecar.call("create_environment", { name: "canary / env" });
  everything.push(made);
  everything.push(
    await fx.sidecar.call("add_variables", {
      environment_id: made.structured.id,
      variables: [{ name: "SOMETHING" }],
    }),
  );
  const written = await fx.sidecar.call("write_env_file", {
    environment_id: envId,
    directory: fx.project,
  });
  everything.push(written);
  everything.push(
    await fx.sidecar.call("run_with_env", {
      environment_id: envId,
      command: "/usr/bin/printenv",
      cwd: fx.project,
    }),
  );
  everything.push(
    await fx.sidecar.call("revoke_env_file", { lease_id: written.structured.lease_id }),
  );
  // The headless daemon has no browser to ask, so this is FILL_UNAVAILABLE; it is here so the
  // sweep names every tool, including the one whose purpose is to put a value somewhere.
  const fill = await fx.sidecar.call("request_fill", {
    item_id: item.id,
    origin: "https://api.acme.example",
  });
  everything.push(fill);
  assert.equal(fill.structured.code, "FILL_UNAVAILABLE", fill.text);

  assert.equal(everything.length, 10, "one call per tool");
  for (const [index, result] of everything.entries()) {
    assert.ok(
      !JSON.stringify(result).includes(fx.marker),
      `tool call ${index + 1} returned the canary`,
    );
  }

  // `run_with_env` with no `variables` injects *all* of them, so the child genuinely had the
  // value in its environment — this is not a pass by the value never being used.
  const ran = everything[7];
  assert.match(
    ran.structured.stdout,
    /\[kagisecure:redacted:ACME_TOKEN\]/,
    "the child printed the value and it was masked on the way back",
  );

  fx.assertNoLeak(JSON.stringify(everything));
  recordText(
    t.name,
    "canary.txt",
    `marker length ${fx.marker.length} (32 random bytes, hex)\n` +
      `checked against: every tool result, the sidecar's stdout (${fx.sidecar.rawStdout.length} B),\n` +
      `its stderr (${fx.sidecar.rawStderr.length} B), and the daemon's output.`,
    "what the canary was checked against",
  );
});
