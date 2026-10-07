# ADR-0047: Stdin delivery for `run_with_env`

- **Status:** Accepted. Implemented in the core (`inject::Delivery::Stdin`), the agent, the MCP
  sidecar, `kagisecure daemon`'s prompt and the macOS app's approval sheet. The Windows app refuses
  it (`INVALID_ARGUMENT`) until its sheet can say where the values go.
- **Date:** 2026-09-30
- **Deciders:** the project owner, who asked for a way to hand a set of freshly created credentials
  to a secrets tool with one fingerprint and no copy-and-paste into a terminal.
- **Refines:** [mcp-server.md](../mcp-server.md) §2.8, §5 and §7,
  [ADR-0002](0002-no-secret-values-over-mcp.md), [ADR-0040](0040-audit-before-release.md)

## Context

`run_with_env` puts the values in the child's environment. That is what most programs want, and it
is the wrong place for one class of command: a tool whose job is to *store* secrets somewhere else —
an encrypted file (`sops set --value-stdin`), a hosted secret store (`gh secret set NAME` and
`wrangler secret put NAME` read the value from a piped standard input). Those tools read the value
from their standard input precisely so that it is not in an environment or an argument vector:

- An environment is inherited by every descendant of the child, whether or not it needs the value,
  and a process of the same user can read another's environment (`ps -E` on macOS,
  `/proc/<pid>/environ` on Linux) for as long as it runs.
- Wrapping such a tool with `run_with_env` today means a shim that reads `$NAME` and pipes it on,
  which puts the value in exactly the place the tool was designed to keep it out of.

The person asking wanted: create the keys on a dashboard, put them into kagisecure, then let an
agent run the storing command, approving once with Touch ID, the agent never seeing a value.

## Decision

1. **A `delivery` argument on `run_with_env`, not a new tool.** `"environment"` (the default, what
   the tool always did) or `"stdin"`. The tool surface stays at ten; the approval sheet, the lease
   store, audit-before-release, output scrubbing, the process group and the deadline are the same
   code for both.
2. **The frame is `NAME\0VALUE\0`, per variable, in the order selected,** written once to the
   child's standard input, which is then closed. NUL cannot occur in a name, and a value containing
   one is refused before anything starts (`Error::UnsendableOnStdin`, `SPAWN_FAILED` for the
   agent). A shell reads it with `read -r -d ''`; nothing needs escaping. The whole payload is
   capped at 8 KiB, under every supported platform's pipe capacity, so the write completes whether
   or not the child reads and the writing thread never lingers holding the values. The buffer is
   `Zeroizing`. The writing end has `F_SETNOSIGPIPE` on Apple platforms, because the macOS app does
   not ignore `SIGPIPE` and a child that exits unread must not take the app down.
3. **Nothing goes into the child's environment or argv.** Masking still runs over the output with
   the same values.
4. **One approval, one run.** A stdin request never looks for a lease — neither one minted by an
   earlier stdin approval nor an environment-delivery lease for the same command — and any allow of
   it is granted as a single use (`outcome_for`), whatever the UI sends. The app's sheet offers only
   **Allow once** and **Deny**; `kagisecure daemon` asks `[o = once / N = deny]`. The sheet itself
   still times out after 60 seconds (`APPROVAL_TIMEOUT`).
5. **The sheet says where the values go.** `ApprovalRequest::stdin_delivery` (and
   `ApprovalRequestView::stdin_delivery` over FFI): the headline reads *“Claude Code” wants to pass
   N values from ‹environment› to ‹command› on its standard input, once*, the command section adds
   that the command can do anything with what it reads, and the Touch ID prompt restates it. No
   agent-supplied "purpose" text is shown: the environment's name (which the user approved when it
   was created) says *which* secrets, the argv says *where*.
6. **Missing values are named before any sheet.** If a selected variable is still pending (declared
   by `add_variables`, never filled in), a stdin request is refused with the new code
   `NOT_POPULATED`, whose message lists those variable names. Names are metadata —
   `list_environments` already reports `populated` — and a fingerprint spent on a run that cannot
   succeed is a fingerprint the user learns to give without reading.
7. **The audit entry names the command.** The `Allowed` entry's `detail` is `STDIN` followed by the
   argv in Rust's debug form (`STDIN ["/path/tool", "import", "prod"]`), because the lease that
   would otherwise remember the command is gone the moment the run uses it.
8. **Not on the unattended socket.** No standing grant covers a stdin run; asking for one there is
   a strike (`NO_GRANT`), like `write_env_file`.
9. **`PROTOCOL_VERSION` 3.** A build that predates `delivery` would deserialize a stdin request with
   the field ignored and put the values in the environment. The version mismatch refuses that peer
   at `Hello` instead.

## Consequences

- A stdin run costs a fingerprint every time. That is the point: the command receives the values
  in the one form that is easy to persist, so there is no "for this session". The one exception is
  a run whose every selected variable is bound to a sealed agent test login, which rides the grace
  window ([ADR-0048](0048-agent-test-logins.md) §9); the single use stands.
- The residual risk is the command. `cat` given `delivery: "stdin"` prints the values; scrubbing
  catches the plain echo but is not a boundary (mcp-server.md §2.8). The sheet shows the full argv
  and says the command can do anything with what it reads; a user who allows a command they did not
  expect has released the values to it, as with an environment delivery.
- Windows gets the argument but refuses it until its sheet renders `stdin_delivery`
  (`KgsApprovalRequest` has no field for it yet).
- `kagisecure run` (the CLI's own terminal wrapper) does not take the flag: the person at the
  terminal can pipe as they like.
