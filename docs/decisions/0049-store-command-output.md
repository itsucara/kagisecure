# ADR-0049: Store a command's output in the vault — the reverse of `run_with_env`

- **Status:** Accepted (2026-10-07, by the owner)
- **Date:** 2026-10-07
- **Deciders:** the owner, who asked for a way to set up API credentials (the Chrome Web Store
  client secret and refresh token) with no one typing, pasting or seeing a secret
- **Refines:** [ADR-0002](0002-no-secret-values-over-mcp.md) (a tool whose result could have
  carried a value, and does not); [ADR-0046](0046-agents-propose-item-drafts.md) §8 (agents still
  never change an existing secret); [ADR-0047](0047-stdin-delivery.md) (its stdin frame, reused)
- **Relates to:** [ADR-0035](0035-shared-vaults.md) §14,
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md),
  [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md),
  [ADR-0040](0040-audit-before-release.md), [ADR-0042](0042-unattended-agent-access.md),
  [ADR-0048](0048-agent-test-logins.md) §10

> **Accepted; built in the core, the agent, the MCP sidecar, the FFI and `kagisecure daemon`.**
> The macOS app's sheet is separate work. Mechanisms are described in the present tense.

## Context

Some secrets are born on the command line. An OAuth client secret sits in a JSON file a console
downloaded; a refresh token is printed by a one-off consent helper (`xtask chrome-auth`). Getting
either into kagisecure today means a person copies it from a terminal into the app — or an agent
reads it, which puts it in the transcript and the model provider's logs. `run_with_env` moves
values *out* of the vault into a command; nothing moves a command's result *in*.

The owner wants the agent that is setting up a project to say "run this, and keep what it prints
as field `refresh_token` of item *Chrome Web Store API*", the person to approve with one sheet and
Touch ID, and the value to go from the child's standard output straight into a concealed field,
never returning to the agent.

## Decision

### 1. A new tool, `store_command_output`

```
store_command_output {
  command, args?, cwd, timeout_seconds?,
  item_id? | new_item?: { title, category?, vault_id? },
  field_label,
  stdin_environment?: { environment_id, variables? },
  reason?
}
→ { status: "stored", item_id, field_label, item_created }
| { status: "not_stored", reason, exit_code, stderr, stderr_truncated }
```

- `command`, `args` (at most 64), `cwd` (absolute; symlinks resolved before the sheet) and
  `timeout_seconds` (1–3600, default 300) mean exactly what they mean for `run_with_env`: no shell,
  argv passed verbatim.
- Exactly one of `item_id` and `new_item` names the target (§2). `field_label` is the field's
  label: one line, 1–64 characters, `display_text_ok`.
- `reason` is one line, at most 200 characters, shown on the sheet as agent-written data.
- No argument name contains `value`, `secret`, `password`, `reveal`, `plaintext` or `unmask`, the
  tool name contains none of `grant`, `job`, `arm`, `unattended`, `schedule`, and the description
  says the output is "not returned to you" — the three MCP invariant tests pass unchanged.

A separate tool, not a `run_with_env` argument: `run_with_env` releases values and returns
scrubbed output; this tool writes the vault and must never return stdout at all. Sharing a request
would put one `output` switch between the two.

### 2. Where the value may go: only somewhere empty

The write never replaces a value. An injected agent that could overwrite an existing secret could
swap a real password for one it knows, and the person would find out at the next sign-in, if ever
(ADR-0046 §8's silent overwrite). So:

- **A new item** (`new_item`): title 1–128 characters; category `api-credential` (default),
  `password`, `server` or `database`; in the vault named, or the default one. It gets one concealed
  field, `field_label`, which is its primary secret. **No websites and no username**: an item this
  tool creates is never an autofill target, so ADR-0046's look-alike-domain threat does not arise.
  The person adds websites by hand if they want them.
- **An existing item** (`item_id`): agent-visible by the rule `describe_item` uses, in the personal
  vault, not archived, not trashed. If no field carries `field_label` (case-insensitively), a new
  concealed field is added. If one does and it is concealed and **empty**, it is filled. A field
  with that label that has a value, or that is not concealed, is refused
  (`INVALID_ARGUMENT`, before the sheet, and again inside the transaction).
- **The primary secret of an item with websites is never written**, neither by filling it nor by
  adding a field that would become it (an item with no designated primary secret takes its first
  concealed field). That is the field autofill types for the person; an agent-known value there,
  on a site the person signs in to, is the ADR-0046 §8 threat in a different shape. Filling any
  other empty concealed field is allowed: it held nothing, and the item's websites do not route it
  anywhere.
- **Shared vaults are refused** (`INVALID_ARGUMENT`, `SHARED_IS_READ_ONLY`'s sentence): agents never
  write to one (ADR-0035 §14). A hidden vault or item is `NOT_FOUND`, as everywhere.
- **Agent visibility.** A new item and its field are agent-visible, whatever the vault's "Show new
  items to agents" setting — the item was made by an approved agent request, as
  `create_environment`'s environments are, and the agent needs its field id to bind the value to an
  environment next. A field added to an existing item is agent-visible too (the item already is).

### 3. Approval: one sheet, Touch ID, every time

A new approval kind, `StoreCommandOutput`. The sheet states:

- the agent's identity, as every agent sheet does;
- the full argv and the canonical working directory;
- the target: "new item *T* (category) in vault *V*", or the existing item's title and vault;
  the field label; and whether the field is new or an empty one being filled;
- in plain words: *"What this command prints becomes a stored secret. The agent will not see it."*;
- when `stdin_environment` is given, the environment's name and the variable names that are written
  to the command's standard input (§5) — the run's values and the write share this one sheet;
- the timeout and the agent's reason.

It is **Allow once** only. `outcome_for` clamps any allow to one use, no lease life and never
presence-only, exactly as it does for `AgentFill` and `CreateTestLogin`; there is no grace window
(ADR-0048 §9's `rides_grace` is always `false` for it), so every call costs a fingerprint. Granting
it mints **no lease** — not even the single-use lease a stdin `run_with_env` carries — because
there is nothing to revoke afterwards. The debug-only `--auto-approve` of `kagisecure daemon`
refuses this kind, as it refuses `AgentFill` and `CreateTestLogin`.

### 4. Audit before anything happens

Every entry carries the agent's full identity (`actor_for`, ADR-0048 §10), not the bare `mcp`.

1. Before the sheet: the audit pre-flight, so a person is never asked about a run that could not be
   recorded.
2. After the grant, before the child starts: an `Allowed` entry, through `audited_release`
   (ADR-0040), with the argv in its detail — `STORE_OUTPUT [argv]` — and, with a stdin environment,
   the environment and variable names. Recorded whether or not any value is released, because the
   command is the agent's and the person approved running it.
3. After the child: if the output is stored, one `Allowed` entry `STORED` naming the item, in the
   **same transaction** as the write (ADR-0039) — both are written, or neither. If not, a `Failed`
   entry `NOT_STORED <reason>`. Denials are `Denied` with the code.

### 5. Execution: `run_with_env`'s machinery

The child is spawned by `kagisecure_core::inject::run_with_env_tracked`, exactly as for
`run_with_env`: no shell, its own process group, the deadline, registration with the agent's child
registry so a vault lock kills it at once (`KILLED_ON_LOCK`), and `LOCKED_BEFORE_START` if the lock
lands between the grant and the spawn.

`stdin_environment` feeds an existing environment's values to the command through ADR-0047's frame
(`NAME\0VALUE\0` per variable, 8 KiB cap, then standard input closed). This is how
`xtask chrome-auth` receives `CWS_CLIENT_ID` and `CWS_CLIENT_SECRET` and prints the refresh token.
Every named variable must have a value (`NOT_POPULATED` before the sheet, naming them); a shared
environment is allowed as a *source* (reading is not writing) and its sheet carries the shared
source line. The values are released by the same `prepare_release` as a stdin `run_with_env`, so
the environment is re-checked inside the release transaction. Without `stdin_environment`, the
child's standard input is `/dev/null`, and its environment is the agent's own, as for
`run_with_env`.

### 6. What counts as output

- **Standard output only** is captured for the vault, never masked (masking would corrupt it), held
  in a zeroizing buffer and dropped as soon as it is written or refused.
- One trailing `\n` (or `\r\n`) is removed — `jq -r` and `println!` add one.
- Refused, nothing stored: a non-zero exit, a timeout, a kill on lock; empty output; more than
  **16 KiB**; a NUL byte; anything that is not UTF-8; and **more than one line** after the trailing
  newline is removed. A multi-line value (a PEM key) is out of scope: the common case is one token,
  and refusing a second line catches a command that printed a banner beside its token.
- **Standard error is returned** to the agent, scrubbed, for diagnostics: injected values and the
  captured standard output (if it appears there) are replaced by `[kagisecure:redacted:NAME]` /
  `[kagisecure:redacted:output]`, best effort, as in `run_with_env`. It is capped at 16 KiB.
- **The agent learns** `stored` or `not_stored` with a fixed reason token (`exit_status`,
  `timed_out`, `killed_on_lock`, `empty`, `too_large`, `nul_byte`, `not_utf8`, `multi_line`), the
  item id, the field label, and whether the item was created. **Never the length**, never a hash,
  never a prefix: the length of a token says something about which kind it is and is not needed to
  use it.

### 7. Not unattended, not Windows

The unattended socket answers `NO_GRANT`, recording the refusal, as for every vault change
(ADR-0042 §6). Windows refuses it with `INVALID_ARGUMENT` until its app has a sheet for it, the
rule ADR-0047 applied to stdin delivery.

### 8. Protocol 5

`Request::StoreCommandOutput` and `Response::StoredCommandOutput` are new, so `PROTOCOL_VERSION`
goes to 5: a stale peer would decode the request as a garbled frame. The sidecar, the app and
`kagisecure daemon` ship together, as for version 4.

## What the person sees

1. Claude, setting up Chrome Web Store publishing, downloads nothing itself: the person has saved
   the OAuth client JSON to `~/Downloads/client_secret.json`.
2. Claude calls `store_command_output` with `command: "/opt/homebrew/bin/jq"`,
   `args: ["-r", ".installed.client_secret", "/Users/me/Downloads/client_secret.json"]`,
   `new_item: { title: "Chrome Web Store API" }`, `field_label: "client_secret"`.
3. A sheet: "“Claude Code” wants to run `/opt/homebrew/bin/jq -r .installed.client_secret …` in
   `/Users/me/project` and store what it prints as **client_secret** of a new item **Chrome Web
   Store API** in *Personal*. The agent will not see it." **Allow once** — Touch ID.
4. Claude gets `{status: "stored", item_id, field_label: "client_secret", item_created: true}`.
   It stores `client_id` the same way, binds both fields to an environment, then runs
   `xtask chrome-auth` with `stdin_environment` and `field_label: "refresh_token"` on the same item;
   the person completes Google's consent in the browser, and approves one more sheet.
5. Claude asks the person to delete the downloaded JSON. No value ever appeared in a terminal or a
   transcript.

## Threats

- **The agent chose the command, so it could have run it itself.** ACCEPTED, and stated plainly in
  the tool description, the docs and here: an agent that can run `jq` on a file can read the file.
  This tool keeps a value out of **transcripts and the model provider's logs** for an agent that
  uses it; it does not protect a value from a malicious agent, which could also run the command a
  second time, or pick one that writes the output somewhere else as well. Its other gain is that the
  person no longer copies secrets by hand.
- **Overwriting a real secret with an agent-known one.** Excluded structurally (§2): nothing with a
  value is replaced, and an item's autofill password is never written.
- **A planted autofill target.** New items have no websites (§2).
- **Shared vaults.** Refused as targets (§2).
- **A misleading item title or field label.** Both are one-line, capped, `display_text_ok`, and shown
  on the sheet as agent-written data; a new item lands in a vault the person can see.
- **A command that prints the secret to standard error too.** The captured output is scrubbed from
  standard error before it is returned (§6), best effort; a command that re-encodes it defeats
  that, which the agent controlling the command could do anyway.
- **Approval fatigue.** One sheet per stored value is the price; there is no grace window because
  every call writes a new secret the person has not seen.
- **Values fed through `stdin_environment`.** Released only after the sheet that names them, audited
  first, single use (ADR-0047).

## Out of scope

- Replacing or rotating an existing value (a later "rotate with command" would need its own
  sheet showing the item's current use).
- Multi-line values, binary output, files.
- Websites or usernames on new items.
- Unattended and Windows use.

## Consequences

### Positive

- API credentials go from a command into the vault with no human copy and no transcript exposure.
- The `xtask chrome-auth` refresh token never touches a terminal or the clipboard: the helper
  refuses a terminal on standard output and prints only the token.
- `run_with_env`'s spawn, timeout, lock and audit paths are reused, not re-implemented.

### Negative — accepted

- A fingerprint per stored value.
- `PROTOCOL_VERSION` 5: the sidecar, the app and the daemon ship together.
- The macOS app does not compile until its sheet handles the new kind.
