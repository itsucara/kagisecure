# ADR-0046: Agents propose item drafts; a person completes and approves them

- **Status:** Proposed
- **Date:** 2026-10-04
- **Deciders:** the owner (pending)
- **Refines:** [ADR-0035](0035-shared-vaults.md) §14 ("Agents cannot write to a shared vault"),
  for item drafts only — see §6
- **Relates to:** [ADR-0002](0002-no-secret-values-over-mcp.md), [ADR-0020](0020-fill-approvals-and-origin-leases.md), [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md),
  [ADR-0022](0022-public-suffix-list.md), [ADR-0035](0035-shared-vaults.md),
  [ADR-0036](0036-agent-requested-browser-fill.md),
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md),
  [ADR-0038](0038-app-release-needs-presence.md), [ADR-0040](0040-audit-before-release.md),
  [ADR-0042](0042-unattended-agent-access.md),
  [ADR-0045](0045-system-wide-autofill-credential-provider.md)

> **Proposed; nothing is built.** Mechanisms are described in the present tense because that is how
> the other ADRs read, not because code exists for them.

## Context

An agent can already shape the vault's *structure*: `create_environment` and `add_variables` create
environments and declare variable names, some of them "awaiting user input", and every such change
goes through the approval queue (`ApprovalKind::CreateEnvironment`, `AddVariables` in
`crates/kagisecure-agent/src/approval.rs`). It cannot create or change an **item**. The MCP tools
(`crates/kagisecure-mcp/src/server.rs`) only list and describe items, and ask for fills.

That leaves a gap the owner hits in practice. An agent that has just helped sign up for a service,
or that is setting up a project and knows it needs a login for `dashboard.example.com`, has every
non-secret fact the item needs — the title, the URL, the username, which vault it belongs in — and
no way to hand them over. The person re-types them by hand, or the agent asks the person to paste
the password into the chat, which is exactly what [ADR-0002](0002-no-secret-values-over-mcp.md)
exists to prevent.

The facts an agent would supply are not secret, but they are not harmless either. An item's
**website** is what browser fills ([ADR-0020](0020-fill-approvals-and-origin-leases.md),
[ADR-0036](0036-agent-requested-browser-fill.md)) and system-wide AutoFill
([ADR-0045](0045-system-wide-autofill-credential-provider.md), and the iOS extension on
`feat/ios-autofill`) match against. An item whose URL was chosen by a prompt-injected agent is a
standing instruction to offer a real password to whatever site that URL names. A draft is
therefore a security-relevant write and must be treated as one, even though no value crosses MCP.

## Decision

### 1. The shape

An agent **proposes** an item draft: non-secret fields only. The draft is a pending approval, not an
item. Nothing is written to any vault until a person opens the draft in the app, completes it —
typing or generating the secret there — and approves it with presence. The agent learns only the
outcome and, on success, the new item's id.

### 2. The MCP tool: `propose_item`

Arguments, all non-secret, all length-limited and validated by the agent before queueing:

| Field | Notes |
|---|---|
| `title` | Plain text, single line. |
| `category` | `login`, `secure_note`, `api_credential`, `server` — the categories that exist today. No category whose *defining* field is a value an agent would have to supply. |
| `websites` | Zero or more URLs. Parsed with the same `Origin::parse` the fill path uses; IP literals and non-`https` schemes are accepted but flagged (§5). |
| `username` | Optional. A username is not a secret in this product's model (ADR-0036 §7.2 treats it as fillable metadata), but it is shown as proposed, not as fact. |
| `tags` | Optional. |
| `notes` | Optional, plain text, length-capped. The sheet labels it "written by the agent". |
| `vault` | `personal` (default) or a shared vault id from `list_vaults`. |
| `reason` | Required one line, shown on the sheet, as for other agent approvals. |

There is **no field for a password, a TOTP seed, a private key, a token, or any custom field marked
concealed**, and no free-form "extra fields" map through which one could be smuggled. A field the
schema does not name is rejected, not ignored. The tool returns `{ status, item_id? }`; it never
returns anything the person typed.

### 3. A new approval kind: `CreateItemDraft`

The draft rides the existing approval queue as `ApprovalKind::CreateItemDraft`, with the existing
decisions (approve, deny, timeout) and these differences:

- **It mints nothing.** No env lease, no fill lease, no "for this session". Like `AgentFill`, an
  approval of one draft never excuses the next.
- **Its timeout is the person's, not the agent's.** The 60-second `APPROVAL_TIMEOUT_SECONDS` is
  too short for "go and generate a password". The draft waits in the queue (and in the app's
  agent-activity list) until the person acts or dismisses it; the tool call returns `PENDING` after
  the usual timeout with a draft id, and `get_item_draft_status` reports the outcome later. Pending
  drafts are memory-only and die with the vault lock, as leases do.
- **Rate-limited.** At most a handful of open drafts per agent connection; further proposals are
  refused with `TOO_MANY_PENDING`, so an agent cannot bury a real draft under decoys.

### 4. Completing and approving: presence, then the audited write

The approval sheet is a small item editor (see "What the person sees"). Every agent-supplied field
is editable, and marked as agent-supplied until the person edits it. The secret fields are empty
and only the person can fill them: by typing, pasting, or the built-in generator.

Approving needs a fresh presence proof, as every other vault write from an agent request does —
[ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md)'s rule and
[ADR-0038](0038-app-release-needs-presence.md)'s gate, without the grace window: a draft is rare
and its consequences (a new autofill target) last, so it pays one Touch ID every time. The write is
a normal transactional item write ([ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md))
and is audited per [ADR-0040](0040-audit-before-release.md): the audit record — agent identity,
the draft's fields as proposed, which the person changed, the resulting item id — is committed
before the item is, and an audit failure fails the write closed. Denials and dismissals are
audited too, best-effort.

### 5. URL handling: the registrable domain is the fact the person approves

- The sheet shows each website's **registrable domain** (eTLD+1 by the public suffix list,
  [ADR-0022](0022-public-suffix-list.md)) large and separately from the full URL, punycode-decoded
  only alongside its ASCII form (`xn--` shown), so `examp1e.com` and `exаmple.com` (Cyrillic а) are
  visible as what they are.
- **Near-host warning.** The app compares each proposed host against the hosts of existing items
  in the target vault and the personal vault. Exact registrable-domain equality is decided by the
  existing `host_match` in `kagisecure-extension-ipc::origin` — no second matcher. A host that
  does **not** match but is *close* to an existing item's registrable domain (small edit distance
  on the label left of the suffix, confusable characters, the same label under a different suffix
  such as `example.co` vs `example.com`, or an existing domain embedded as a subdomain such as
  `example.com.login-check.net`) produces a warning that names the existing item: "Close to
  *GitHub* (github.com) but is a different site."
- IP literals, single-label hosts, and non-`https` URLs are flagged; a host that is itself a
  public suffix is refused.
- A draft with a warning cannot be approved with one click: the person must acknowledge the
  warning on the sheet first.

### 6. Shared vaults respect roles

A draft may target a shared vault, which refines ADR-0035 §14's "agents cannot write to a shared
vault": the agent still writes nothing — the person who approves is the author of the record, under
their own device key, exactly as if they had created the item by hand. The tool refuses a vault in
which this device's member is a `reader` (ADR-0035 §6) with `FORBIDDEN_ROLE`, before anything is
queued; the app re-checks the role at approval time, against the authenticated roster then current.
A shared vault hidden from agents on this device (ADR-0035 §14) cannot be named. The sheet shows
the source line ADR-0035 already uses ("Shared vault *Ops* — 4 members"): putting an item in front
of other people is a decision the person should see they are making.

### 7. Unattended cannot approve drafts

[ADR-0042](0042-unattended-agent-access.md)'s standing grants do not cover `CreateItemDraft`, and no
grant can be written that does. The unattended socket has no `propose_item`. A draft proposed by an
interactive agent while nobody is at the computer waits for the person; it is never auto-approved,
and the debug-only `--auto-approve` refuses this kind as it refuses `AgentFill`.

### 8. Updates to existing items: out of scope for now

Proposing changes to an existing item is **not** part of this decision. It has the same shape
(non-secret field changes only, presence, audit) but a sharper threat: changing the website of a
login that already holds a real password redirects that password with no new secret ever being
typed — the silent-overwrite attack in its strongest form. A later ADR may add
`propose_item_change` as a field-level diff sheet that, at minimum, treats any website change as a
new-domain warning and never touches secret fields. Until then, `propose_item` only creates; it
never merges into, replaces, or deduplicates against an existing item, even one with the same title
and domain — a duplicate is shown as a warning (§9), and the person can cancel and edit the
existing item by hand.

## What the person sees

1. Claude, setting up a project, says it will save the new staging login and calls `propose_item`
   (`title: "Acme staging"`, `websites: ["https://staging.acme.dev/login"]`, `username: "ci-bot"`,
   vault *Ops*).
2. kagisecure's agent-activity badge shows one pending draft; the notification reads "Claude Code
   proposes a new login for **acme.dev** in *Ops*".
3. The sheet opens: the agent's name and code-signature identity, its reason, and the domain
   **acme.dev** in large type above the full URL. If the person already has an item for
   `acme.io`, an amber line says the new domain is close to it and is a different site.
4. Title, username and tags are pre-filled and marked "from Claude Code". The password field is
   empty, with the generator next to it.
5. The person generates a password (or pastes the one the site showed them), adjusts anything,
   and clicks **Save to Ops** — Touch ID.
6. The item appears in *Ops*; Claude's tool call (or its later status check) gets `approved` and
   the new item id, and can now ask for a fill through `request_fill` like any other item — with
   that request's own approval.

## Threats

- **Impersonation and spoofed titles.** An injected agent proposes "GitHub" with
  `https://github-sso.example.net`. Mitigation: the sheet leads with the registrable domain, not the
  title; agent-supplied fields are marked as such; the near-host warning names the real GitHub item;
  approval needs presence and, with a warning, an explicit acknowledgement.
- **Silent overwrite of existing items.** Excluded structurally: the tool only creates (§8), there
  is no update path, and a same-title or same-domain draft is shown as a duplicate warning, never
  merged.
- **An AI-supplied URL becomes the autofill match target (look-alike domains).** The most serious
  one. Once saved, the item is offered by the browser extensions and by system-wide AutoFill
  ([ADR-0045](0045-system-wide-autofill-credential-provider.md), whose matching is by registrable
  domain since its 2026-10-04 amendment, and the iOS provider on `feat/ios-autofill`), which inside
  the grace window fill with one click and no prompt. A look-alike URL would turn a password the
  person later types for the real site — or reuses — into one offered to the attacker's. Mitigations:
  §5's prominent registrable domain, the PSL-aware near-host warning built on the existing
  `host_match`, confusable and punycode display, no auto-approve under any mode (§7), and no lease
  of any kind (§3). Residual risk: a draft for a genuinely new, unrelated attacker domain triggers
  no near-host warning; the domain on the sheet is the person's only defence there, as it is when
  they save a login by hand from a phishing page.
- **Approval fatigue / decoy flooding.** Rate limit on open drafts (§3); no "approve all".
- **Exfiltration through the draft.** The agent never receives what the person typed; the result
  carries only the status and item id. `describe_item` keeps returning metadata only (ADR-0002).
- **Writing into a shared vault one should not.** Role check at the tool and again at approval
  (§6); agent-hidden shared vaults cannot be named.
- **Unattended abuse.** No unattended path exists (§7).

## Out of scope

- Proposals that change, merge or delete existing items (§8).
- Any secret field in a proposal, including "the agent generates the password and passes it in" —
  the generator runs in the app, on the person's click.
- Agents creating, joining or changing the roster of shared vaults (unchanged, ADR-0035 §14).
- Importing items in bulk from an agent.
- Drafts proposed by the browser extension or by the AutoFill extensions (those are save-on-submit
  flows with their own design).
- Approving drafts on another device (an iPhone approving a Mac agent's draft).
- Logins whose password kagisecure generates on the agent's request, for test accounts on local and
  allowed origins only: [ADR-0048](0048-agent-test-logins.md) refines this decision for those.

## Consequences

### Positive

- The common "the agent knows everything except the password" case no longer pushes people to paste
  secrets into chats.
- No new way for a secret value to cross MCP; ADR-0002's canary tests apply unchanged.
- Every agent-originated item is attributable in the audit log.

### Negative — accepted

- One more approval kind, and the first whose sheet is an editor rather than a yes/no.
- A Touch ID on every draft, with no grace window.
- The near-host heuristic will have false positives (two genuinely related company domains) and
  false negatives (an unrelated attacker domain); the registrable domain on the sheet remains the
  real check.
