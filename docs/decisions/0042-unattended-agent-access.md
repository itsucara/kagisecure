# ADR-0042: Unattended use is a separate machine vault that a person arms, released only to jobs kagisecure starts, under standing grants

- **Status:** **Accepted (2026-09-27) for macOS.** Headless hosts (§15) are not part of this
  acceptance: they stay in [ADR-0043](0043-unattended-access-on-headless-hosts.md), which is
  Proposed. Accepted with the owner's convenience-first priority and a change the owner made the
  same day — **arming persists across restarts, with no expiry** — recorded in "Owner's answers"
  (answer 2, amended) and "Implementation decisions". Phases 0 to 5 are implemented (the
  documentation page, the core, the engine, the macOS app, shared-vault copies and unattended
  sign-ins; see "Implementation plan").
- **Date:** 2026-09-27
- **Deciders:** the owner
- **Refines:** [ADR-0004](0004-biometric-key-wrapping.md) rules 3, 4 and 6;
  [mcp-server.md](../mcp-server.md) §5 and §7; [threat-model.md](../threat-model.md) M-3, M-6,
  M-7, M-11, M-29, M-31; [architecture.md](../architecture.md) §2.6; for machine-vault logins only,
  [ADR-0036](0036-agent-requested-browser-fill.md) §3.2 and §5 and
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md)'s invariant (§12)
- **Relates to:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0007](0007-m2-daemon-and-ipc-deviations.md) §2,
  [ADR-0018](0018-browser-extension-secret-crossing.md),
  [ADR-0019](0019-native-messaging-forwarder.md), [ADR-0022](0022-public-suffix-list.md),
  [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md),
  [ADR-0013](0013-agent-library-split.md), [ADR-0015](0015-peer-code-signature-verification.md),
  [ADR-0020](0020-fill-approvals-and-origin-leases.md), [ADR-0035](0035-shared-vaults.md),
  [ADR-0036](0036-agent-requested-browser-fill.md),
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md),
  [ADR-0038](0038-app-release-needs-presence.md),
  [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md),
  [ADR-0040](0040-audit-before-release.md),
  [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)

> **Accepted for macOS; implemented through Phase 5.** Built: the page
> [unattended-credentials.md](../unattended-credentials.md) (Phase 0); in `kagisecure-core`, the
> machine vault file, its key in the personal vault's body, its structural rules, and its job and
> grant records (Phase 1); in `kagisecure-agent`, the engine — arming from the Keychain's bytes,
> the scheduler, runs, ancestry binding, the unattended socket, the release path for command
> grants, suspension, both logs — and the ordinary socket's reads of the machine vault, with the
> `kagisecure-ffi` calls the app will use (Phase 2); and in the macOS app, the Keychain, arming,
> jobs and their grants, Agent access → Unattended jobs, the menu bar, "While you were away",
> notifications and the machine log in the Audit view (Phase 3); and copies of shared vaults'
> environments, the vaults' policy on them and the records that tell every member who holds one
> (Phase 4). The unattended fills (Phase 5) are built too. Mechanisms are described in the present tense because that is how the
> other ADRs read, not because code exists for them. Where "Implementation decisions" below
> changes what a section says — above all §3, whose key is no longer memory-only — the decision
> wins, and the section is marked.

## Context

The owner wants AI agents — Claude Code, Claude Desktop, and scheduled jobs driven by them — to use
secrets fully automatically, including when nobody is at the computer. Two examples frame it: a
nightly job that runs a deploy command with a token, and an agent that signs in to a web service on
a schedule.

Today kagisecure refuses both, by design, at every layer:

- **Every release needs a person.** An injection needs a fresh biometric or a lease a biometric
  minted ([ADR-0004](0004-biometric-key-wrapping.md), threat-model M-3). Leases are memory-only,
  15 minutes by default and 24 hours at most, and die on expiry, use exhaustion, vault lock, screen
  lock, sleep, app exit or revoke ([mcp-server.md](../mcp-server.md) §5). The table in that section
  ends with the sentence this ADR has to answer: *No "always allow" / "remember forever" option
  exists in v1 — the whole product is the prompt.*
- **The key is not there when nobody is.** The app locks the vault on screen lock, on sleep and
  after an idle timeout (M-11, `apps/macos/Kagisecure/Services/AutoLockCoordinator.swift`), and
  locking drops the key, every lease and the agent listener.
- **Every fill needs a fresh presence proof**, lease or not
  ([ADR-0020](0020-fill-approvals-and-origin-leases.md) as superseded by
  [ADR-0037](0037-every-fill-needs-a-fresh-presence-proof.md), M-29), and every agent-requested
  fill needs its own sheet and biometric ([ADR-0036](0036-agent-requested-browser-fill.md), M-31).
- **Every reveal or copy from the app needs one too**
  ([ADR-0038](0038-app-release-needs-presence.md), M-30).
- **A shipped binary has no code path to an unattended approval.** `kagisecure daemon
  --auto-approve` is refused in a release build ([ADR-0007](0007-m2-daemon-and-ipc-deviations.md)
  §2, [architecture.md](../architecture.md) §2.6).

### Unattended is three problems, not one

"Let the agent use the secret when I am away" asks kagisecure to do three things it currently
refuses, and each has its own price:

1. **Release without a person.** Something other than a biometric at release time must decide that
   a release is allowed. Whatever decides it was set up earlier, by a person who could not see the
   request it would later cover.
2. **Unlock without a person.** The key that decrypts the value must be usable while the screen is
   locked, while the machine sleeps and wakes, and — if "fully automatic" is taken literally — after
   a restart. It has to be somewhere, and wherever it is, it is not behind a finger.
3. **Identify the requester without a person.** Today the human reading the sheet is the last check
   on *who* is asking. Without that human, kagisecure has only what the kernel tells it, and on this
   platform that is not much (§"What unattended costs", point 3).

### What happens if nothing is built

Doing nothing is not free, and it is fair to say what users do today instead:

- **A long-lived `.env`.** `write_env_file` accepts a TTL of up to 24 hours, and under
  `kagisecure daemon` — which has no screen-lock or sleep trigger — the file stays on disk until the
  daemon locks or exits. That is a plaintext file readable by every process the user runs (W-2).
- **A daemon left running** with a terminal approval: weaker than the app's sheet by the daemon's
  own admission (ADR-0007 §1), holding the whole personal vault's key for as long as it runs.
- **The token in the job's own configuration** — a shell profile, a scheduler's environment block,
  a plain login-keychain item — with no scope, no audit and no expiry.

Each of these is worse than a narrow design on scope, on audit and at rest. That is the argument
for building something. It is not an argument for building anything broad.

### Constraints that do not move

- **[ADR-0002](0002-no-secret-values-over-mcp.md) is unchanged.** No MCP tool returns a value, in
  whole or in part; no IPC message carries one. Nothing here gives an agent a new way to see a
  value.
- **No networking** ([architecture.md](../architecture.md) §9, threat-model N-9). No push approval
  to a phone, no remote alert, no token minted by calling a service.
- **The personal vault never becomes unattended.** Every release from it keeps its fresh presence
  proof — M-3, M-29, M-30 and M-31 hold for it, and for shared vaults, exactly as they do today.
  What this ADR relaxes, it relaxes for the machine vault (§2) alone.
- **The user's own browser is never filled unattended.** An unattended fill (§12) lands only in a
  browser kagisecure launched for one job run.
- **A person makes every decision that widens access**: creating, widening, extending or
  re-enabling a grant; defining a job; arming; moving a value into the unattended store. None of
  these is reachable from an agent — the same rule ADR-0035 §14 applies to sharing (M-27).
- **Audit before release** ([ADR-0040](0040-audit-before-release.md)) holds for every unattended
  release, fail-closed.
- **Shared vaults** ([ADR-0035](0035-shared-vaults.md), accepted, being implemented): approvals and
  leases never leave the machine that made them, and no agent can change who a vault is shared
  with. Unattended use must compose with that, not route around it.

## What unattended costs, stated before anything is claimed

This section decides what the rest of the ADR may claim, the way ADR-0036 §8 did for agent fills.

**1. The last human decision is the grant.** At release time nobody reads a sheet. The facts M-5
puts in front of a person — caller, directory, variable names — are shown once, when the grant is
created, and then cover every later release the grant matches, including ones requested by an agent
that was steered somewhere in between. W-3 ("the user can approve a malicious injection if they do
not read the prompt") becomes "the user approved, weeks ago, a class of injections they will never
see". M-3 does not hold for these releases. That is not a side effect of the design; it is the
feature.

**2. The key is available while nobody is there.** Either it sits in memory for the whole
unattended period, or it sits at rest somewhere a process can use it without a person. On macOS
there is today **no at-rest place a same-user process cannot read** that this project can use:

- a plain login-keychain item has no code-signature gate against another process running as the
  same user ([ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md),
  "Alternatives considered");
- a Secure Enclave key or an access-group-scoped keychain item needs the `keychain-access-groups`
  entitlement, which needs a provisioning profile the project cannot yet obtain
  ([ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md)), and whether an access group actually
  resists a same-user process is ADR-0041's unmeasured Phase 0.

So today the only honest answer is memory, and memory does not survive a restart (§3).

**3. The requester is "some process running as this user" unless kagisecure started it.** The code
signature check ([ADR-0015](0015-peer-code-signature-verification.md)) verifies that the peer on the
socket is a kagisecure sidecar, not which client launched it. The sidecar's parent is
kernel-resolved (ADR-0036 decision 28), but any same-user process can start that same program —
`claude` with a prompt of its own choosing included. A grant bound to "requests from Claude Code"
is therefore a grant to anything that can run Claude Code as this user. The one identity the kernel
can vouch for is ancestry: *this request came from a process tree kagisecure itself started, at a
time kagisecure chose.* §4 builds on that and nothing weaker.

**4. The command is defined by files the account can write.** A grant can pin a command, its
arguments, its directory, the executable's bytes and a list of input files. It cannot pin
everything the command reads: `npm run deploy` is whatever `package.json`, the deploy script and
`node_modules` say at the moment it runs. Anything that can write those — the job's own agent,
steered by a prompt injection, or same-user malware (T-3) — can make the granted command send the
credential somewhere else. kagisecure can detect a change to a file it was told to pin (§5); it
cannot detect a change to one it was not.

**5. An unattended fill hands the login to the job's agent.** An agent that drives a browser can
read what is typed into it — one script call, or the submitted request in the network log (W-21,
ADR-0036 §8.1). With a person present, ADR-0036 makes that a decision: *approving an agent fill is
trusting that agent with that login*. Unattended, the trust is given in advance, to the agent as its
inputs will have made it on the night. So for a login, the grant does not protect the password from
the agent; it protects **where** the value is typed (one exact origin, in a browser nobody else
uses), **that** it never enters a transcript, and **how often** — and the account's own scope is
the real bound on the damage. A fill grant is strictly weaker than a command grant, and the sheet
says so.

The true sentences for this feature, which the documentation and the sheets carry verbatim:

> kagisecure still never gives an agent a value. Under a standing grant, it hands a machine
> credential to a command you pinned, at times you scheduled, with nobody watching — and anything
> that can change what that command does while you are away can obtain that credential.

> Under a login grant, kagisecure types a service account's password into one site, in a browser it
> started for this job, with nobody watching. The job's agent can read what is typed there: treat
> the account as one the agent holds.

## Recommendation

**Never make the personal vault, a shared vault, or the user's own browser usable without a
person, at any scope. For credentials that belong somewhere else, say so and point there. For the
remainder — credentials of service and bot accounts used by jobs that must run on this Mac — build
a separate machine vault that a person arms for a bounded time with a presence proof. Its values
are released only to processes descended from a job kagisecure itself started on a schedule, and
only under standing grants that fail closed on anything unexpected: command grants, released by
`run_with_env` to a pinned command; and login grants, filled through the extension channel into one
exact origin, in a browser kagisecure launched for that run, with one-time codes behind a separate
switch that is off by default.**

In short: option (c) first and by default; then (b), (a) and three of the (d) variants combined —
narrower than what was asked for in every dimension except the one the owner decided (logins,
§12), where it is as narrow as the design can defend and says what it cannot defend. The option
comparison follows; §1–§14 describe the design.

### The options, against the threat model

**(a) Standing grants, on their own.** A person pre-authorizes, with a presence proof, a grant
scoped to an exact command, directory, environment, client identity, time window, rate, use count
and expiry. As a *release rule* this is right, and it is adopted (§5). As the whole design it fails
on problems 2 and 3: grants over the personal vault need the personal vault's key while nobody is
there, which exposes every login and one-time code in it (A1, A3) for the whole unattended period
and breaks M-11 for the vault that matters most; and "verified client identity" is, per point 3,
any process that can start the client.

**(b) A separate unattended vault or device class.** A second vault whose key is available without
presence, holding only machine credentials. Right about separation — it confines what problem 2
exposes to values that were put there for this purpose — and adopted (§2, §3). On its own it is the
login keychain with extra steps: with no grants, any same-user process that reaches its socket can
ask for anything in it.

**(c) Stay presence-only, and document where unattended credentials belong.** A job that runs on a
CI service or a serverless platform should use that platform's secret store or, better, its
workload identity. kagisecure gives up nothing, and the credential never touches this Mac. This is
the best answer wherever it applies, and it is adopted as the default recommendation and Phase 0.
It does not cover a job that has to run on this Mac, where "the platform's secret store" is a shell
profile.

**(d1) Short-lived credentials minted by the target service** — OIDC federation, workload
identity, deploy tokens scoped to one action with an expiry. They shrink what any store holds, and
kagisecure cannot mint them itself (N-9). Adopted as guidance for what goes *into* the machine
vault (§2), not as a mechanism.

**(d2) Jobs kagisecure launches.** kagisecure starts the job on its schedule and accepts a request
only from that job's own process tree, during that run. This is the only requester identity the
kernel can support (point 3), and it confines grants to their schedule. Adopted as the only caller
binding (§4).

**(d3) An armed window.** A person, with a presence proof, makes the machine vault's key available
in memory for a bounded time — days, not months. No key is ever at rest without a person in front
of it, and a restart ends it. Adopted as the key mechanism (§3). The owner has decided there is no
persistent variant on the Mac (see "Owner's answers"); headless hosts are §15's.

**(d4) A person approving remotely** (a push to a phone) — rejected: it needs network code (N-9)
and still needs the person, so it is not unattended.

**(d5) A browser kagisecure launches for the run.** For logins, the analogue of (d2): the value can
land only in a browser instance kagisecure started, with a throwaway profile, as part of one run —
never in the user's own browser, whose tabs, sessions and other accounts a job has no business
near. Adopted for unattended fills (§12).

| | (a) alone | (b) alone | (c) | (d1) | **Recommended: (b)+(a)+(d2)+(d3)+(d5)** |
| --- | --- | --- | --- | --- | --- |
| Key usable without a person | personal VK, whole vault | machine VK | none held | n/a | machine VK, in memory, bounded, gone on restart |
| Who can cause a release | any caller matching the scope | any same-user process | the platform's workload | the platform's workload | a process in a run kagisecure started, matching a pinned grant |
| M-3 (person per release) | broken | broken | holds | holds | broken, for machine-vault releases only |
| M-11 (lock on screen lock, sleep) | broken for the personal vault | broken for the machine vault | holds | holds | holds for the personal vault; broken for the machine vault |
| T-2, an injected *interactive* session | can use grants | can use anything | nothing | nothing | cannot use grants |
| T-2, the injected *job* | within grants | anything | nothing | nothing | within its grants; broader requests suspend them |
| T-3, same-user malware | within grants, any time | anything, any time | nothing on this Mac | nothing | through the job's inputs, at the scheduled time (W-23) |
| T-5, stolen Mac | personal vault key in RAM | depends on storage | nothing | nothing | machine VK in RAM while armed; nothing after a restart |
| Unattended logins | any login in the personal vault, in any browser | any login stored there, in any browser | none | only where the service offers tokens instead | machine-vault logins only, one exact origin, only in the run's own browser; readable by the job's agent (W-26) |
| M-29 / M-31 (presence per fill) | broken for every login | broken for its logins | holds | holds | holds for the personal and shared vaults; broken for machine-vault logins |
| Audit | personal log | machine log | the platform's | the platform's | machine log, before release; summarized to the person |
| Fits N-9 | yes | yes | yes | yes, if the job does the minting | yes |

## Decision

### 1. What may be released unattended, and what never is

| Unattended — allowed | Never unattended, at any scope |
| --- | --- |
| `run_with_env`, for variables of an environment in the **machine vault** (§2), under a command grant (§5), from inside a run of a job kagisecure started (§4), with output `none` | Anything from the personal vault, or from a shared vault's replica (§13) |
| `request_fill` for a **machine-vault login**, under a login grant (§12), from inside a run, into that run's own browser, at the grant's one exact origin | A fill into any browser but the run's own — the user's everyday browser above all — or at any other origin |
| A one-time code for that login, in the same sign-in, only if the login grant's one-time-code switch is on (off by default, §12.5) | One-time codes by any other route; TOTP seeds, ever; one-time codes into a process or file |
| The metadata tools, answering only with what the calling run's grants cover | `write_env_file`: a file outlives the run and is readable by every same-user process for its lifetime (W-2); `run_with_env` confines the value to a process group kagisecure ends when the run ends |
| | Reveals and copies |
| | `create_environment`, `add_variables`; any change to a vault |
| | Creating, widening, extending, re-enabling or proposing a grant or a job; arming; any shared-vault roster operation |
| | The job's root process: it receives no value at launch |

### 2. The machine vault

- **A separate vault file**, in the ordinary format ([vault-format.md](../vault-format.md)), with
  its own vault key and its own audit log — and, since implementation decision 2, **no recovery
  slot of its own**: recovering the personal vault recovers it. It is not a logical vault inside
  the personal file: the personal file has one body under one key, and making that key available
  unattended would make every login in it available too.
- **Its vault key is held, at rest, in the personal vault body** as a `Secret` — the same place
  ADR-0035 §5 keeps device keys, for the same reasons (no new unlock path, no new entitlement). It
  is usable only while the personal vault is unlocked, which is how arming (§3) gets it. This makes
  ADR-0035's Phase 0 — `Body`/`Header` unknown-key passthrough and the `format_ver` lever of its §16
  — a prerequisite here too; the two share it.
- **What goes in it: machine credentials.** API tokens, deploy keys, database URLs, service-account
  keys used by a job — and the sign-ins of **dedicated service or bot accounts** a job uses on a
  website (§12). The guidance, surfaced where items are added, is (d1): prefer a token scoped to the
  one action the job performs, with an expiry set at the service; a website login only where the
  service offers nothing else.
- **Structural rules**, enforced in `kagisecure-core` rather than by the UI:
  - a website on a machine item is an **exact https origin** — scheme, host and port, no path, no
    subdomain wildcard — and only a Login item may have one; a login grant (§12) names one of them;
  - one-time-password fields only on such a Login item; the seed is never released as such, only a
    code — unattended, only by a login grant whose one-time-code switch is on (§12.5);
    interactively, as a personal-vault code is filled, with a sheet and a presence proof (owner's
    answer 20);
  - no references to items outside it (the rule ADR-0035 §14 applies to shared environments).
- **Unattended, only a run's own browser is filled.** The unattended extension endpoint of §12
  serves a run's own browser and nothing else, and never the user's browsers. The user's browsers
  receive machine-vault logins only interactively, below.
- **What cannot be enforced, stated plainly:** kagisecure cannot tell a person's password from a
  service account's. The sheet that moves an item in asks, in words, whether this is an account a
  job owns or one a person signs in with, and says that a person's account moved here becomes one
  the job's agent can read (point 5). The answer is the owner's; kagisecure records it and cannot
  check it.
- **Items enter only by a person, in the app, with a presence proof:** created in the machine vault,
  or **moved** from the personal vault (a move, not a copy, so there is one value to rotate). Both
  logs record it. Shared items are §13's.
- **Unattended, it is reachable only through the unattended socket** (§4), and there only as far
  as the calling run's grants reach.
- **Interactively, it is used like the personal vault** (owner's answer 12). An agent on the
  ordinary socket may use a machine-vault environment through the ordinary tools, with the ordinary
  sheet and a presence proof per release (or a lease one minted), exactly as for a personal-vault
  environment. The ordinary socket reads the machine vault only while the personal vault is
  unlocked — its key comes from the personal body — and answers `VAULT_LOCKED` otherwise, armed or
  not, so arming never makes the ordinary socket answer while the screen is locked. Such a release
  is not a run: it uses no standing grant, counts against none and strikes nothing (§7), and it is
  recorded in the machine vault's log under the ordinary `mcp` actor. The answer covers *use*, not
  change: items still enter only by a person in the app (above), so `create_environment` and
  `add_variables` never target the machine vault.
- **Interactive fills of machine-vault logins, likewise** (owner's answer 20). The ordinary
  extension listener fills a machine-vault login into the user's own browser — an agent's
  `request_fill` or the human fill path — exactly as it fills a personal-vault login: ADR-0036's or
  ADR-0037's sheet and a fresh presence proof every time, and only while the personal vault is
  unlocked, armed or not. M-29 and M-31 hold for these fills; they use no login grant, count against
  none and strike nothing, and are recorded in the machine vault's log under the ordinary actor. The
  unattended endpoint is unchanged: it serves only a run's own browser (§12.4).

### 3. Arming: how the key is there when nobody is

**Arming** is a person, in the app, with the personal vault unlocked, choosing "Arm unattended jobs
until …" and passing a fresh presence proof — the same `PresenceGate` ADR-0038 uses (Touch ID, an
Apple Watch, the login password, or the master-password fallback, W-20). Rust then reads the machine
vault key from the personal vault body and opens the machine vault **in the app process's memory**.
*Amended by implementation decisions 1 and 5:* the key crosses the FFI to Swift once per arm, so
the app can keep it in the Keychain, and [ADR-0008](0008-ffi-secret-crossings.md)'s list gains that
crossing when the app side is built (Phase 3).

- **In the Keychain, and in memory** *(amended 2026-09-27, implementation decision 1; this bullet
  first read "Memory only")*. Arming stores the key in the login Keychain, this device only and
  never synchronized; the app reads it back at launch and re-arms with nobody present.
- **No expiry** *(amended 2026-09-27; this bullet first read "Bounded", default 7 days, at most
  14)*. An arm lasts until a person pauses it, or a `lock` request on the unattended socket
  disarms it; either deletes the Keychain item and zeroizes the key.
- **Arming is not a grant.** Nothing is released because the vault is armed; grants (§5) decide
  that. A disarmed machine vault releases nothing, whatever the grants say.
- **Disarming needs nothing.** Pause from the menu bar, Agent access, `kagisecure unattended pause`,
  or a `lock` request on the unattended socket from any same-user process. Refusing is always
  allowed, as revoking is today; the cost is that an injected job or malware can pause the jobs,
  which is a denial of service and not a disclosure.

What each event does:

| Event | Personal vault | Machine vault | A run in progress |
| --- | --- | --- | --- |
| Screen lock, idle timeout | locks (M-11, unchanged) | **stays armed** | continues |
| Personal vault locked by hand (⌘\, Lock Now, `kagisecure lock` on the ordinary socket) | locks | stays armed — locking when you leave is exactly when jobs should keep running | continues |
| Sleep, lid closed | locks | stays armed (memory survives sleep). No job starts while asleep; kagisecure does not schedule wakes, which needs root | frozen; on wake, ended if past its deadline (`TIMED_OUT`) |
| Wake after a scheduled time passed | — | a run whose start is later than its catch-up window (default: none) is not started, and is recorded `JOB_MISSED` | — |
| Restart, logout, power loss, app quit | gone | **stays armed** *(amended, implementation decision 1)*: the app re-arms from the Keychain when it next starts in a login session | while the app is down the unattended socket is gone, so nothing is released; see below for the process group |
| `lock` on the unattended socket, Pause | — | disarmed, and the Keychain item deleted | ended (process group, as `run_with_env` today, including the run's browser, §12) |
| The machine vault file diverges or is replaced ([ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md) `VaultDiverged`, `VaultConflict`) | — | disarmed, with a notice | ended |

*Superseded 2026-09-27 by implementation decision 1 — kept as the reasoning the owner overrode:*
**After a restart, nothing runs until the owner arms again.** A macOS update that restarts the Mac
overnight stops every job until someone comes back. This is the largest thing the recommendation
gives up against "fully automatic", and it is given up on purpose: the alternative is a key at rest
that a same-user process can use, which point 2 says does not exist today. The owner has accepted
this and decided against a persistent mode on the Mac ("Owner's answers", answer 2). Headless hosts,
where the owner decided the opposite, are §15's and change nothing here.

**An app that crashes** leaves a running job's process group alive, as it leaves a `run_with_env`
child alive today, because the registry that ends children lives in the app. The socket goes with
the app, so nothing further is released; values already in children's environments are N-6's.

**The cost, stated plainly.** The machine vault key sits in the app's memory for up to 14 days,
across screen lock and sleep. On macOS a same-user process without a debugging entitlement cannot
read another process's memory (T-3's stated capability); root can (N-1); a cold-boot attack is N-3.
A Mac stolen while armed and asleep holds the key in RAM behind the lock screen (T-5). On Windows a
same-user process *can* read the app's memory (T-3's Windows paragraph), which is why §14 excludes
Windows outright.

### 4. Jobs: kagisecure starts them, and only their process trees may ask

A **job** is defined by a person in the app, with a presence proof, and stored in the machine
vault:

- a name;
- a **root executable** by absolute path, pinned by its code-signing identity when it has a team
  identifier and by SHA-256 of its bytes otherwise;
- exact arguments and a canonical working directory;
- a **schedule** — calendar times (daily or weekly at a given time); no "every N seconds";
- a **run deadline** (default 30 minutes, at most 6 hours) and a **catch-up window** (default none);
- the grants its runs may use (§5).

**A run** is kagisecure starting the root at a scheduled time: from the app's engine, in a process
group of its own (as `run_with_env` children are), with the app's environment plus one variable,
`KAGISECURE_SOCKET`, naming the **unattended socket**. kagisecure records the root's kernel pid and
kernel-recorded start time as the run's identity. The run ends when the root exits or at its
deadline, when the whole group is ended the way `run_with_env` ends one (`SIGTERM`, then `SIGKILL`).
Grants are usable only while a run is live.

**The unattended socket** is a second endpoint in the same `0700` directory as `daemon.sock`, mode
`0600`, with the same same-user gate (M-13), served by a second `kagisecure-agent` instance hosted
by the app over the machine vault's own `VaultHandle`. It is bound while the app runs and a job
exists; while disarmed it answers every request `UNATTENDED_PAUSED` and holds no key. The ordinary
socket, its protocol and every answer it gives are unchanged, so an interactive session's
`VAULT_LOCKED` while the screen is locked stays exactly what it is.

**Binding a request to a run.** For every request on the unattended socket, the engine takes the
peer's kernel pid and walks its parents — `kagisecure_extension_ipc::peer::parent_pid`, with each
hop's start time from `kagisecure_ipc::server::process_start_time`, the binding ADR-0036 decision 34
introduced — until it reaches a live run's root with the recorded pid *and* start time, within 16
hops. A chain that breaks (a process re-parented to `launchd`), times out, or reaches no run is not
in a run, and is refused. The code signature of the peer is still checked and recorded (ADR-0015),
as evidence, not as the gate.

What this buys, and what it does not:

- **It buys confinement to the schedule, and to the job.** A prompt injection in an *interactive*
  agent session — the most likely attack there is (T-2) — cannot use a grant at all, because that
  session is not in a run's tree. Neither can same-user malware that simply connects to the socket.
- **It does not bind the job's inputs.** The root executable is pinned; its configuration, its
  prompt file, the agent's settings and hooks, and the repository it works in are not. Anything that
  can write them runs inside the next run (W-23, proposed). Against T-3 this narrows *when* and *how
  often*, not *whether*.
- **Callers kagisecure did not start get nothing** — including a client's own built-in scheduler.
  There is no weaker, labelled mode for them, now or later (owner's answer 4).

### 5. Standing grants

There are two kinds of standing grant, and neither can stand in for the other: **command grants**,
this section, and **login grants**, §12. A **command grant** answers one question: *during a run of
this job, may this exact command run with these variables from the machine vault?* It holds:

| Field | Rule |
| --- | --- |
| Job | The one job whose runs may use it |
| Environment and variables | One machine-vault environment; a request's variables must be those or a subset (the lease rule, M-6) |
| Executable | Absolute path — a bare name is refused, so `PATH` decides nothing — pinned by code-signing identity (team and signing identifier) where it has one, so an update from the same signer keeps the grant, and by SHA-256 otherwise (owner's answer 7); re-checked at every release |
| Arguments | Exact, the whole argv; no prefixes, no patterns |
| Working directory | Canonical, exact match (as leases) |
| Pinned inputs | Files, each by canonical path and SHA-256, re-checked at every release. The sheet proposes every argument that names an existing file; the person can add more |
| Output | `none` only (owner's answer 8): scrubbing is not a boundary, and with nobody reading the output there is no one it would serve. No `scrubbed`, no unmasked option |
| Timeout | As `run_with_env`'s, at most the run's remaining time |
| Limits | Releases per run (default 1), total uses (default 60), hard expiry (default 30 days, at most 90) — owner's answer 5 |
| Provenance | Created when, through which presence path (`PRESENCE_CONFIRMED` or `PRESENCE_CONFIRMED_MASTER_PASSWORD`) |

The environment the child sees is the app's own environment plus the injected variables — the
caller's environment never reaches it, so a requester cannot add `DYLD_INSERT_LIBRARIES` or change
`PATH`. "Environment" in a grant therefore means the kagisecure environment and its variable names,
and nothing the caller supplies.

**Creating a grant** happens only in the app, started by the person, on a sheet (a new
[ui-spec.md](../ui-spec.md) §10.8) that shows every bound fact above, the job's schedule, and two
sentences that are not optional:

- *"Not pinned: anything else this command reads."* — with the working directory named;
- for an executable that is a shell, an interpreter or a package runner (`sh`, `bash`, `zsh`,
  `env`, `node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `deno`, `python`, `ruby`, `perl`, `make`, …):
  *"A grant for an interpreter is a grant for whatever it reads."* — and, when no input is pinned,
  a warning in its own box: *"Nothing this interpreter runs is pinned: any change to its script
  changes what the credential is used for, and nothing will be suspended."* The grant can still be
  created without a pinned input (owner's answer 6).

Then a presence proof. Changing a grant is creating a new one. **No MCP tool and no IPC message
creates, widens, extends, re-enables or proposes a grant or a job**; there is deliberately no
"pending grant" an agent could raise the way `add_variables` raises a pending entry, because one
approval of a grant is months of access, and approval fatigue at that exchange rate is not a risk
worth taking. This is asserted by test, as M-27's equivalent is.

Grants are **persistent** — stored in the machine vault body, surviving restarts — which is what
makes them "always allow" in the sense M-6 and ADR-0004 rule 6 forbid. They are shown in Agent
access with Revoke, and counted in the menu bar (§9). No grant can name anything outside the
machine vault.

### 6. The release path, in order

Each check is answered before the next is made, in the manner of ADR-0036 §11.1:

1. **Armed.** Otherwise `UNATTENDED_PAUSED`, before anything else is looked at.
2. **In a run** (§4). Otherwise `NOT_GRANTED`.
3. **Arguments** valid by the tool's schema. Otherwise `INVALID_ARGUMENT`.
4. **A grant of this run's job covers the request** exactly as §5 defines, and it is not suspended,
   expired, used up or over its per-run limit. Otherwise `NOT_GRANTED` — one code and one message
   for every reason, so the job's agent learns nothing about which grants exist or why one did not
   apply; the reason goes into the audit entry only.
5. **Pins hold now**: the executable's identity, every pinned input's hash, the working directory's
   canonical form. A mismatch is `NOT_GRANTED`, and the grant is suspended (§7).
6. **Audit pre-flight** (ADR-0040 §3). Otherwise `AUDIT_UNAVAILABLE`.
7. **Release** through `audited_release` on the machine vault: re-check, resolve and commit the
   `Allowed` entry in one transaction; then spawn, with no lock held, in a process group registered
   to the run, so the run's end ends it.
8. **Reply**: exit code only; output is always `none` unattended (§5).

`NOT_GRANTED` ("Stop. Do not retry or try variations; the owner has been told.") and
`UNATTENDED_PAUSED` ("Tell the user unattended jobs are paused; do not retry.") are new codes, and
only the unattended socket returns them, keeping [mcp-server.md](../mcp-server.md) §7's rule that
every documented code is one the sidecar can actually return. On the unattended socket
`request_fill` follows §12's own order of checks, and `write_env_file`, `create_environment` and
`add_variables` answer `NOT_GRANTED`.

**This is a second exception to M-7.** M-7 says kagisecure does not rate-limit, because approval and
leases bound a hostile agent; ADR-0036 made the first exception, a limiter that bounds the human's
attention. Here there is no approval at release time, so the per-run and total limits are what bound
*access*, beside the scope — the reason M-7 gives for having no limiter is exactly what is absent.

### 7. Suspension: a grant fails closed on anything unexpected

A grant is **suspended** — kept, refused, and flagged to the person — when:

- **one strike:** anything inside a run asks for a release no grant covers — another command,
  other arguments, another directory, more variables, `write_env_file`, a fill no login grant
  covers (each still answered as §6 or §12 says). Every grant of that job, of both kinds, is
  suspended and the run is ended (owner's answer 11). A job that behaves never trips this; an
  injected one trips it on its first try, which makes injection self-limiting and visible rather
  than a search;
- **a pin changed**: the executable's identity or a pinned input's hash (§6 step 5);
- **a value or binding it releases changed** since the grant was approved — unless the change was
  made by the person in the app with a presence proof, which carries the grants that use it
  forward (owner's answer 10). The edit sheet names those grants before the presence proof, so the
  person sees what the edit re-approves. A change from the CLI, another writer, a shared-vault
  merge, or anything made without presence suspends. No value reaches unattended use that no person
  on this Mac has seen change — the unattended counterpart of the approval sheet's "changed since"
  line (ADR-0035 §14, W-16). A grant already suspended is not re-enabled by a later edit;
  re-enabling stays creating it again (below);
- **the machine vault conflicts** (§3, disarms rather than suspends).

Re-enabling a suspended grant is creating it again: the person, the sheet — which says why it was
suspended — and a presence proof. Exhausted uses, expiry and per-run limits are not suspensions;
they simply answer `NOT_GRANTED` until a person acts.

### 8. Audit

- **Two logs, each with one job.** The machine vault's own log
  ([vault-format.md](../vault-format.md) §8, in its own file) records what happened unattended:
  every release, refusal, suspension, run, arm and disarm. The personal vault's log records the
  person's decisions — arming, grant and job creation and revocation, moves into the machine vault
  — with the presence path that authorized each, as ADR-0038's audit does.
- **Releases are fail-closed** exactly as ADR-0040 makes `run_with_env`: the `Allowed` entry is
  committed before the child exists, `AUDIT_UNAVAILABLE` releases nothing, and a failure or abnormal
  end adds a `Failed` entry naming it (`SPAWN_FAILED`, `TIMED_OUT`, `KILLED_ON_LOCK`, …). Everything
  else is best-effort through the pending queue (ADR-0039 §5).
- **Vocabulary**, in `detail`, with no `AuditEntry` schema change (as ADR-0040 and ADR-0036 avoid
  one): `UNATTENDED_GRANT <grant> RUN <run>` on an `Allowed` release; `NOT_GRANTED (<reason>)`, with
  reasons `OUTSIDE_RUN`, `NO_GRANT`, `SUSPENDED`, `EXPIRED`, `USED_UP`, `PER_RUN_LIMIT`,
  `PIN_CHANGED`; `GRANT_SUSPENDED (<reason>)`; `JOB_STARTED`, `JOB_ENDED`, `JOB_MISSED`;
  `ARMED (<presence detail>)`, `DISARMED (<reason>)`; `SUMMARY_ACKNOWLEDGED`.
- **Actors, and the Audit view's filters.** A request from a run is recorded with the actor
  `mcp unattended "<job name>" run <id> pid <n> <executable>`. The `mcp` prefix is deliberate: the
  macOS Audit view already filters agents by that prefix (`AuditView.swift`, ADR-0036 decision 7),
  so unattended requests appear under "agents" with no change, and a new **Unattended** filter
  matches the `mcp unattended` prefix. Entries the engine writes on its own behalf — runs, arm,
  disarm, suspension — use the actor `unattended`. The app's Audit view shows the machine vault's
  log beside the personal vault's.
- **Freshness.** While armed, the engine is the session that saw the newest machine-vault file, so
  ADR-0039's continuity check refuses — and disarms on — a rollback of it during the unattended
  period. After a disarm, W-11 applies to the machine log until
  [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)'s anchor exists — and
  the machine log is the one an attacker would most want shortened. As a partial, cheap witness,
  `SUMMARY_ACKNOWLEDGED` in the *personal* log records the machine log's entry count and head as
  the person saw them, so a later rollback of the machine vault below that point shows as a gap,
  unless both files are rolled back together.

### 9. How the owner notices

- **The menu bar** ([ui-spec.md](../ui-spec.md) §6.3) shows the armed state and its end in words —
  "Kagisecure, vault locked, unattended jobs armed until Friday 18:00" — with a badge counting
  unattended releases, refusals and suspensions since the last summary was acknowledged.
- **"While you were away."** The first personal-vault unlock after unattended activity shows a
  summary, from the machine log: runs, releases (job, command, variable names — never values),
  refusals and their reasons, suspensions, missed runs, arm expiry. It does not block; acknowledging
  it writes `SUMMARY_ACKNOWLEDGED` (§8).
- **System notifications**, local only, through `UNUserNotificationCenter` once the person has
  authorized them (asked when arming), for every suspension and disarm as it happens — named by job,
  never by value or command line.
- **Nothing leaves the Mac** (N-9). The owner learns what happened when they next look at this
  Mac. A job that must alert someone remotely does so itself, outside kagisecure.

What noticing is worth, honestly: it bounds *repetition*. An attacker who obtained a credential on
the first try does not need a second, and the summary tells the owner what to rotate, not that
nothing happened.

### 10. Prompt injection

A scheduled agent reads things — issues, pages, other tools' output — and nobody is watching it
read them. That is T-2 with the human removed, and it is why the design is shaped as it is.

**What an injection can do:**

- make the job's agent call `run_with_env` within that run's grants: the pinned command runs, with
  the pinned variables, up to the per-run limit — perhaps at a moment the owner would not have
  chosen, never with other arguments;
- make the agent edit files the granted command reads. If they are pinned, the next release is
  refused and the grant suspended; if they are not, the credential can be redirected (W-23). This is
  the real risk for command grants, and the sheet says so (§5);
- under a login grant, make the agent read the password it just had filled, in the run's browser,
  and send it anywhere (W-26). Nothing in kagisecure prevents this; the account's scope bounds it,
  and the summary tells the owner to reset it (§12.8);
- pause unattended jobs (a denial of service).

**What it cannot do:**

- **widen a grant.** No tool and no IPC message creates, widens, extends, re-enables or proposes a
  grant or a job (§5). A request broader than a grant is `NOT_GRANTED` and suspends every grant of
  that job (§7), so the second attempt finds nothing to try against;
- use a grant outside a run, or from any other process tree (§4);
- have a login typed anywhere but the grant's exact origin in the run's own browser — a look-alike,
  another site, or the user's browser — without suspending the job (§12.4, §12.7);
- reach the personal vault: the ordinary socket still asks a person, and at night nobody answers
  (`APPROVAL_TIMEOUT`, or `VAULT_LOCKED` while the screen is locked);
- see a value over MCP (ADR-0002), or learn which grants exist (§6 step 4).

### 11. ADR-0002 stays true, unchanged

The unattended socket speaks the existing `kagisecure-ipc` protocol through the same
`kagisecure-agent` code; no new message carries a value, and `run_with_env`'s reply is what it is
today; `request_fill`'s reply still names fields only. An unattended fill's value crosses the
extension channel and nothing else, in the one response type and the one module ADR-0018 and
ADR-0037 already allow. Machine-vault decryption stays in crates `kagisecure-mcp` and
`kagisecure-ipc` cannot depend on, under the same dependency-graph test (M-2). The canary sweep
gains a value seeded into the machine vault, a *successful* unattended release and a *successful*
unattended fill, and the marker must still appear in no byte the sidecar writes. What changes is the
product-level sentence (§"What unattended costs"), not the channel's guarantee.

### 12. Unattended logins: a machine-vault login, one exact origin, the run's own browser

The first draft of this ADR said no unattended fill should ever exist. The owner decided otherwise
("Owner's answers"): a job may sign in to a website with nobody present — an agent that signs in to
a service on a schedule and posts, for example. This section is the narrowest design that can be
defended for that, and §12.9 says plainly what it gives up. The reasons the first draft gave are
not withdrawn; they are the costs this section pays:

- **An agent fill gives the login to the agent that asked** (W-21, ADR-0036 §8). Unattended, that
  trust is given in advance to whatever the job's agent will have read by then (point 5).
- **The biometric was the whole defence** against automation clicking its way to a fill (T-15,
  M-29, ADR-0037) and the only step of an agent fill an agent could not perform (ADR-0036 §5). Here
  it is replaced, for machine-vault logins only, by three bindings that are weaker than a person
  but are what remains when nobody is there: a browser nobody else uses (§12.3), one exact origin
  (§12.2), and one run of one job (§4).
- **A one-time code beside a password collapses two factors into one** (§12.5).

#### 12.1 What stays as it is

- `request_fill` on the ordinary socket, the human fill path, every fill of a personal-vault or
  shared-vault login, and every fill into the user's own browsers — including, since the owner's
  answer 20, of a machine-vault login (§2): exactly as ADR-0036, ADR-0037 and ADR-0018 have them,
  sheet and presence proof every time.
- ADR-0002: the MCP reply names fields, never a value; the value crosses only the extension channel,
  in the same `Response::Filled` (or `totp_code`) reply, built only in
  `kagisecure_agent::extension::crossing` (§11).
- Only **Login items in the machine vault** can be filled unattended: service or bot accounts the
  owner deliberately put there (§2). A person's account is there only if the owner moved it in
  knowingly, on a sheet that says what that means. Shared-vault logins cannot be copied in (§13).

#### 12.2 The login grant

A **login grant** answers: *during a run of this job, may this login be typed into this one site, in
the run's own browser?* Created only by the person in the app, on its own sheet, with a presence
proof, never by an agent (the §5 rule, unchanged). It holds:

| Field | Rule |
| --- | --- |
| Job | The one job whose runs may use it; that job must declare a run browser (§12.3) |
| Item | One machine-vault Login item |
| Fields | `username` and `password`, or either alone; `one_time_code` only with the switch of §12.5 |
| Origin | **One exact https origin**, byte-equal after `Origin::parse` and ASCII serialization, and one of the item's websites (§2). No subdomain and no registrable-domain match: stricter than the rule of ADR-0022 and ADR-0036, whose registrable domain (from the Public Suffix List) is still what the sheet emphasizes, in ADR-0036 §5's look-alike rendering |
| Follow-on origins | Optional, exact, each shown on the sheet: where the sign-in may legitimately lead within the flow window (an identity provider, the service's application host). Default: none |
| Limits | Sign-ins per run (default 1; an identifier-first sign-in is one sign-in in two steps, ADR-0036 §7.3), total uses, hard expiry — the defaults of §5 |
| One-time codes | A switch, **off by default** (§12.5) |
| Provenance | As §5 |

The sheet carries point 5's second sentence verbatim, names the account and the origin in the
look-alike rendering, and says: *"The job's agent can read this password. Use an account that can do
only what this job needs, and that you can reset."*

#### 12.3 The run's own browser

A job that holds a login grant declares a **run browser**: a Chromium-family browser executable,
chosen by the owner and pinned like the job's root — by code-signing identity where it has one, by
hash otherwise (§4, owner's answer 7). For each run, kagisecure:

- creates a **fresh profile directory** for the run inside its own `0700` data directory, and
  deletes it when the run ends — so no session cookie outlives the run, and every run signs in
  afresh (owner's answer 15; there is no persistent profile per job);
- loads the kagisecure extension into it, and writes the native messaging manifest into that
  profile, where the browser reads it (the manifest directory follows `--user-data-dir`,
  [browser-extension.md](../browser-extension.md) §9);
- starts the browser **headful**, since an MV3 extension does not load in the headless shell (the
  same section) — *superseded by the Phase 5 measurement: the new headless mode loads it, and a
  run browser is headless (implementation decision 40)* — with `KAGISECURE_EXTENSION_SOCKET` in its environment naming the **unattended
  extension endpoint** — the variable `kagisecure-nmhost` already reads
  (`kagisecure_extension_ipc::endpoint::EXTENSION_SOCKET_ENV`);
- records its pid and start time on the run, registers it in the run's process group so the run's
  end ends it, and gives the run's root the browser's control endpoint in its environment, so the
  job's agent drives this browser and no other.

Two facts, stated plainly. **The control endpoint is a loopback debugging port**, which any
same-user process can find and attach to (the reason ADR-0036 rejected kagisecure driving a
browser itself, alternative (b)); T-3 can read a filled page through it (W-28). And **not every
Chromium-family build still honours `--load-extension`** — browser-extension.md §9 measured one
that silently ignores it — so the run browser must be one that loads the extension, and the fill
phase of the implementation starts by measuring which do (Phase 5).

The user's everyday browser is never a run browser: it holds a person's sessions and other
accounts, a scheduled fill there would put an unattended agent in front of all of them, and the
tab-in-front rule would have to mean nothing.

#### 12.4 Which browser session may receive a value, and which tab

- **The unattended extension endpoint** is a second extension listener in the app, bound while
  armed, serving only machine-vault logins. It accepts a native host only if the kernel-verified
  ancestry of `kagisecure-nmhost` reaches a live run's browser with the recorded pid *and* start
  time — the ancestry gate of [ADR-0019](0019-native-messaging-forwarder.md) ("a native host with
  no browser above it is a program pretending to be a browser extension",
  [architecture.md](../architecture.md) §5), pinned to one process rather than to any recognized
  browser. Any other session is refused before it can say anything. The ordinary extension
  listener reads the machine vault only for an interactive fill, with a sheet and a presence proof
  (§2, owner's answer 20); the unattended endpoint never reads the personal vault or a shared
  replica, and never serves any browser but a run's.
- **The target** follows ADR-0036 §3.2 and §4 with two changes. Only the run's browser is asked —
  never another browser or profile. And the "document is visible" requirement is dropped: nobody
  is looking, and a window on a locked screen may report itself hidden. Everything else holds: top
  frame only, the active tab of that browser's window, exactly one eligible report, an origin
  byte-equal to both the grant's and the agent's claim, the fields detected, and the same tab, frame
  and document re-checked at delivery.

#### 12.5 One-time codes: a separate switch, off by default

A login grant may carry a one-time-code switch, kept and off by default (owner's answer 16). With
it off, a machine item's one-time-password field is never used unattended, and a request for
`one_time_code` is a strike (§12.7). With it on:

- the sheet shows, in its own box, before the presence proof: *"With this on, this account's second
  factor no longer protects it from anything on this Mac: whoever can drive this job's browser
  during a run gets the password and a valid code together. It still protects the account if the
  password leaks from the service."*;
- a code is written only in the same sign-in: the same run, the same tab, within the **flow
  window** — a fixed 60 seconds from the password step, which no grant can change (owner's answer
  17) — at the grant's origin or a listed follow-on origin, into a detected one-time-code field —
  never onto the clipboard, never into a process or a file;
- it is its own release, with its own audit entry under `totp_code` (ADR-0036 §7.4), counted against
  the grant's per-run limit — one code per sign-in;
- the seed never leaves the vault; only a code does.

The recommendation to the owner is to prefer accounts whose service offers a scoped token instead
of a second factor for automation; the switch exists because some services offer nothing else.

#### 12.6 The order of checks

For `request_fill` on the unattended socket, each check answered before the next, as §6:

1. **Armed**: `UNATTENDED_PAUSED`.
2. **In a run** (§4): `NOT_GRANTED`.
3. **Arguments**: `INVALID_ARGUMENT`.
4. **A login grant of this run's job** names the item, the fields and exactly the claimed origin,
   and is not suspended, expired, used up or over its per-run limit: otherwise `NOT_GRANTED`, one
   message for every reason (§6 step 4), and a strike (§12.7).
5. **The item** still has that website and nothing it releases changed since the grant (§7):
   otherwise `NOT_GRANTED`, and the grant is suspended.
6. **The run's browser is connected** through the unattended extension endpoint:
   `FILL_UNAVAILABLE`.
7. **Audit pre-flight** (ADR-0040): `AUDIT_UNAVAILABLE`.
8. **The target** (§12.4): no eligible tab — no form yet — is `NO_MATCHING_TAB` and not a strike;
   a tab in front at an origin that is neither the grant's nor a listed follow-on is `NOT_GRANTED`
   and a strike.
9. **Release**, through ADR-0036's broker (`crates/kagisecure-agent/src/extension/agent_fill.rs`)
   and ADR-0040's audited release: the `Allowed` entry is committed before the value leaves, and the
   value crosses the extension channel exactly as every fill does.

**What happens to ADR-0037's invariant.** ADR-0037 made it structural that every response carrying a
secret comes from a granted `ApprovalQueue::ask`, and every grant went through a presence check. For
machine-vault logins, that stops being true, and the change is made as structurally as the invariant
was: a second constructor for `Approved`, reachable only from the unattended engine, that takes a
standing login grant and a machine-vault item handle — a type no personal-vault or shared item can
produce. `Approved::from_grant` is unchanged, and the source scan that pins value reads to
`crossing.rs` is widened to the new constructor. For every other item the invariant holds as
ADR-0037 states it.

#### 12.7 Suspension, for fills

In addition to §7, every grant of the job, of both kinds, is suspended, the run (and its browser)
is ended, and a notification is raised at once, when:

- **a fill no login grant covers** is asked for: another item, another field (a code with the switch
  off), another origin;
- **the tab in front is elsewhere**: at fill time, at an origin that is neither the grant's nor a
  listed follow-on — the shape of a job steered to a look-alike;
- **the sign-in leaves the site**: within the flow window (60 seconds, fixed, §12.5) after a fill,
  a top-frame document in that tab commits at an origin that is not listed — reported by the run
  browser's content script, which sends each top-frame document's origin for the window, as
  `TargetReport` does (`UNATTENDED_FILL_LEFT_SITE`);
- **a challenge appears**: within that window, the page at the pinned origin shows a password field
  again (a failed sign-in), or a one-time-code field the grant does not cover, or the job asks for a
  second sign-in in the same run (`UNATTENDED_FILL_CHALLENGED`);
- **the tripwire fires**: the filled password input stops being `type=password` (ADR-0036 §8.3;
  `UNATTENDED_FILL_UNMASKED`) — hygiene, as it is there, not a guard.

**Honest limit:** kagisecure recognizes a CAPTCHA or a "new device" challenge only by these
heuristics. A challenge that looks like an ordinary page is not seen, and an agent that solves a
CAPTCHA by itself is invisible to kagisecure (R-14). What a challenge usually means — the service
noticed something — is also what the summary tells the owner (§12.8).

**A suspension caused by a fill is a suspension, nothing more** (owner's answer 18). There is no
"reset required" state: the person may re-create the grant (§7) without confirming that the
account's password was changed. The summary and the notification still advise a reset (§12.8);
kagisecure does not enforce it and cannot tell whether it was done.

#### 12.8 Audit and noticing

- **Entries**, in the machine vault's log, fail-closed as ADR-0040 makes every fill: tool
  `request_fill`, or `totp_code` for a code; actor
  `mcp unattended "<job name>" run <id> pid <n> <executable> via <browser> (run browser)`, so the
  Audit view's agent filter and the **Unattended** filter both include it (§8); `target_path` the
  browser-established origin; `variables` the field names. Details:
  `UNATTENDED_FILL_APPROVED (grant <g> run <r>)`, with `(step 1 of 2)` and `(step 2 of 2, entry N)`
  for identifier-first sign-ins; `NOT_GRANTED (<reason>)`; `UNATTENDED_FILL_NOT_DELIVERED`;
  `UNATTENDED_FILL_LEFT_SITE (entry N)`, `UNATTENDED_FILL_CHALLENGED (entry N)`,
  `UNATTENDED_FILL_UNMASKED (entry N)`; and `GRANT_SUSPENDED (<reason>)`.
- **Noticing**, as §9 with three additions: the menu-bar badge counts sign-ins separately from
  command releases; every suspension from §12.7 is a system notification at once, naming the job,
  the account's title and the origin; and "While you were away" lists every sign-in with its origin,
  and for any suspension says *"reset this account's password at the service"*, because a login the
  job's agent could read has to be treated as read.

#### 12.9 What this gives up, stated plainly

- **M-29 and M-31 do not hold for machine-vault logins**, and ADR-0037's invariant is amended for
  them (§12.6). No person sees the fill.
- **The job's agent holds the login** (W-26). Anything that steers it — an injected page, a
  poisoned input — can make it read the password in the run's browser and send it anywhere. The
  bindings above decide where the value is *typed*, never who can *read* it afterwards.
- **With the switch on, one factor** (W-27). Without it, a service that asks for a code stops the
  job, which then suspends.
- **The run browser is reachable** by any same-user process through its debugging port while a run
  lasts (W-28), and its profile holds the run's session until the run ends.
- **ADR-0036 §3.2's visibility rule** is dropped for run browsers.
- **Challenge detection is heuristic** (R-14).
- **Chromium-family browsers on macOS only**, and only builds that load an unpacked extension; no
  Safari (ADR-0036 §12's push is unmeasured there) and no Windows (§14).
- **No enforced reset** (owner's answer 18). After a suspension a login the job's agent may have
  read can be granted again unchanged; the advice to reset it is advice (§12.7).

### 13. Shared vaults

- **A shared item cannot be granted directly.** A replica is decrypted with device keys that live
  in the personal vault body (ADR-0035 §5), so it is unreadable while the personal vault is locked —
  and making it readable unattended would expose the whole shared vault, since a device reads
  everything in a vault it belongs to (ADR-0035 §3, W-12).
- **A person may copy a shared value into the machine vault** (owner's answer 9), on this device,
  with a presence proof. The copy records its source — shared vault, item, field and the record id
  of the version copied. It is a copy, not a move: removing the item from everyone else's vault is
  not this device's to do.
- **Only for command grants.** A shared *login* cannot be copied into the machine vault, so no
  shared account is ever filled unattended (§12.1). A login everyone shares is, more often than not,
  a person's account; a job that needs a site gets an account of its own.
- **Whether copies are allowed is the vault's decision, not the member's.** An admin sets it, as a
  signed roster-level record (ADR-0035 §6), default *allowed* (owner's answer 21): an admin turns it
  off for a vault whose values must never be held unattended — a management vault, for example — and
  every build refuses the copy while it is off. A vault with no policy record allows copies.
  Enforced only by honest builds, and said so: any member can read the value and paste it anywhere
  (W-12).
- **Other members see that a copy exists** (owner's answer 9). An honest build publishes a signed
  record to the shared vault when it makes an unattended copy and when it deletes one — "Alice's
  MacBook holds an unattended copy of `DEPLOY_TOKEN`" — shown in the members view and on the
  rotation list. Like ADR-0035 §15's usage records, it proves a copy exists; it cannot prove none
  does. **The grant itself** — command, directory, schedule — stays local and is never exported, as
  leases and local audit are never exported (ADR-0035 §14, §15).
- **Who may make one:** any member whose role can read the item — which is every role — while the
  vault allows it. Grants over the copy are this device's person's, like every approval.
- **Rotation.** When the shared field gets a new version, the copy is stale: grants using it are
  suspended (§7) with "source changed by Bob's *Desktop*", and a person re-copies with presence. A
  poisoned value from another writer (W-16) therefore never reaches unattended use without a person
  on this Mac seeing it change.
- **Removal.** If this device or its member is removed, the copy stays on this Mac, as everything
  the device read stays (W-12); the remover's rotation list (M-25) already lists the value, and the
  copy record flags it "held unattended on *Alice's MacBook* — rotate at the service first". If the
  vault later stops allowing copies, existing copies are flagged on every member's view; they cannot
  be deleted remotely.
- **Changes ADR-0035 would need:** the vault policy record and the copy record — the first a roster
  kind, so a build that does not know it becomes read-only for that vault (ADR-0035 §16's safe
  direction), the second a kind older builds keep and forward.

An unattended device enrolled *as a member* of a shared vault that holds only machine credentials is
a plausible later design and stays deferred (owner's answer 9); it is not proposed here. This ADR is
implemented after ADR-0035 has landed ("Owner's answers"), so the records above are designed against
a built format rather than a draft.

### 14. Platforms and hosts

- **macOS app only.** The engine is hosted by the app, like the agent listener
  ([ADR-0013](0013-agent-library-split.md)); the app must be running, and should be a login item for
  jobs to run after the owner logs in (and arms).
- **Windows: never.** A same-user process can read the app's memory there (T-3), so an armed key is
  every same-user process's key; and Windows Hello's presence is account-scoped (W-1). The C ABI
  gains nothing for this, and Windows never offers agent fills at all (ADR-0036 decision 8).
- **Unattended fills: Chromium-family run browsers only** (§12.3); no Safari, whose app-to-extension
  push ADR-0036 §12 has not measured.
- **`kagisecure daemon`: not in this design.** It has no presence proof to arm with — its approval
  is a terminal `y` (ADR-0007 §1). [architecture.md](../architecture.md) §2.6's sentence "a shipped
  binary has no code path to an unattended approval" stays true for *approvals*; it would be
  reworded to say that releases under a standing grant exist, in the app only, and that a grant is
  itself an approval made with a presence proof. Whether a headless process hosts the engine on a
  headless host is §15's question, and would reword that sentence again.
- **Headless hosts** — a build server, a CI runner, a Linux box — are §15's. The owner wants them
  supported and armed without a person (answer 13), which this design does not provide and does not
  attempt. Until §15's follow-up ADR is accepted, the documentation recommends option (c) for them.

### 15. Headless hosts (owner's answer 13): design required

**The requirement.** The owner wants unattended use on hosts where no person and no app is present —
a build server, a CI runner, a Linux box — and wants those hosts **armed automatically**: the
machine vault's key held in the host's own key store (a TPM, or the platform's equivalent), usable
without a person, and surviving reboots. This is deliberately the opposite of answer 2, and answer 2
stays for the Mac app: on a Mac a restart disarms and there is no persistent arming. This section
does not design the headless case. It states what the requirement breaks and what a design has to
decide, and proposes that a follow-up ADR specify it before any of it is implemented. Nothing in
§1–§14 changes for it.

**What it breaks, or needs:**

- **A persistent unattended key with no presence proof.** Arming, the one presence-proven step of
  §3, disappears; the last human decision becomes the provisioning of the host (below). A key sealed
  to a TPM cannot be copied off the disk to another machine, which helps against a stolen disk or a
  backup; but on the running host, anything that can run as the service account — or as root (N-1) —
  can ask the key store to unseal it, and the key is then that process's as much as kagisecure's.
  Point 2's finding holds on these hosts too, and there the answer is no longer memory: it is a key
  at rest that a same-account process can use. A12, M-32, W-24 and T-5 all change for these hosts: a
  host stolen whole, or rebooted by an attacker, arms itself.
- **The daemon path §14 closed.** A headless host has no app, so something else must host the engine
  — `kagisecure daemon` or a new service binary. That reverses, for that binary,
  [ADR-0007](0007-m2-daemon-and-ipc-deviations.md) §2 and [architecture.md](../architecture.md) §2.6
  ("a shipped binary has no code path to an unattended approval"). The design must say how a release
  build keeps `--auto-approve` refused while releasing under standing grants, and why a grant made
  elsewhere (below) is still an approval made with a presence proof.
- **Linux, and each host platform.** §3–§12 are written against the macOS app. The peer check and
  the ancestry walk (`parent_pid`, `process_start_time`) need Linux counterparts — peer credentials,
  `/proc` start times — specified and measured; so do process-group teardown, the socket directory's
  permissions and the key store itself. Windows hosts stay excluded for §14's reasons unless the
  follow-up ADR answers them.
- **Key sealing policy.** Sealed with or without binding to boot measurements (a PCR policy): bound,
  a firmware, bootloader or kernel update fails the unseal and the host disarms until it is
  provisioned again — answer 2's behaviour returning by another route; unbound, the key unseals for
  whatever boots on that board. Also: whether the sealed object needs an authorization value, and
  where that would live; and what a host with no TPM — a container, a runner without one — gets:
  refused, or a key file, which is a `.env` with extra steps.
- **Grants and jobs without a presence prompt.** No person is at the host to read a sheet. The
  candidate: jobs and grants are created on the Mac, with the sheets and presence proofs of §5 and
  §12.2, and exported as a signed bundle that the host verifies against a public key pinned when the
  host was enrolled; the host creates and widens nothing locally. How enrolment itself is done, and
  by whom, is part of the design. Pinning there is by hash (answer 7's fallback), since code-signing
  identity has no general equivalent on Linux, so every update of a pinned tool suspends its grants.
- **Callers kagisecure did not start** (answer 4). On a CI runner the CI service starts jobs, from
  whatever was pushed; kagisecure does not. Either kagisecure is the scheduler on such hosts, which
  is not how CI works, or answer 4 is revisited for them, which reopens point 3: a grant to
  "anything the runner starts" is a grant to anyone who can push a job.
- **Network code is still forbidden** (N-9). Provisioning, revocation and collecting the host's
  audit log are by file only — copied by the owner or the owner's own tooling, never fetched by
  kagisecure. A revoke made on the Mac reaches the host only when someone copies it there; until
  then, a grant's hard expiry is the only bound that acts on its own.
- **Audit and noticing with no app.** No menu bar, no "While you were away", no local notifications,
  and [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)'s anchor is a macOS
  keychain design. The host's log is writable, and can be rolled back, by the account it runs as;
  the owner learns what happened only by bringing that log to a Mac and reading it.
- **Logins** (§12) need a headful Chromium-family browser with the extension loaded. Whether
  unattended sign-ins exist on a host without a display is part of the question.

**Proposal.** Specify headless hosts in their own follow-up ADR, with its own threat-model entries,
before any implementation; keep this ADR's Mac design as it is; and leave headless support out of
this ADR's implementation plan. Until that ADR is accepted, the documentation keeps recommending
option (c) for these hosts. Open question 19 lists what it must answer; it blocks headless hosts
only, not the Mac design. That follow-up is
[ADR-0043](0043-unattended-access-on-headless-hosts.md) (proposed 2026-09-27), which answers each
of those points. On the owner's answer there, jobs a CI service starts may use CI grants on headless
hosts, which changes answer 4 for those hosts only; on the Mac, answer 4 is unchanged.

### Alternatives considered

**(a) Standing grants over the personal vault.** Rejected (options, above): it needs the personal
vault's key unattended.

**(b) A machine vault with no grants.** Rejected: any same-user process could release anything in
it.

**(c) Presence-only, with documentation.** Adopted as the default and as Phase 0 for credentials
that belong on another platform. The owner decided it is not the whole answer ("Owner's answers").

**A persistent key now, in a plain login-keychain item.** Rejected: no code-signature gate against a
same-user process (ADR-0041's own finding), so the machine vault would be as readable at rest as a
`.env`, and more trusted.

**A Secure Enclave key without user presence**, so that arming survives a restart. Rejected by the
owner for the Mac ("Owner's answers", answer 2): a restart disarms, and there is no persistent mode.
It was also blocked by ADR-0011's provisioning profile and ADR-0041's unmeasured Phase 0. Answer 13
asks for its counterpart on headless hosts, which §15 leaves to a follow-up ADR.

**Grants bound to a client program rather than to a run kagisecure started.** Rejected: any
same-user process can start the program (point 3), and an injected interactive session could use
every grant at any hour. The owner decided there is no such mode, labelled or not, later either
(answer 4).

**Interpreter grants that require a pinned input** — the first draft's proposal. The owner chose a
warning instead (answer 6, §5).

**Keeping the machine vault off the ordinary socket**, so the interactive and unattended paths never
meet — the first draft's proposal. The owner decided otherwise (answer 12, §2).

**A "reset required" state after a fill suspension**, refusing the account's grants until the owner
confirms a new password. The owner decided against it (answer 18, §12.7).

**`scrubbed` output for unattended releases.** Rejected (answer 8): scrubbing is not a boundary,
and nobody reads the output.

**A flow window carried by each grant.** Rejected (answer 17): the window is a fixed 60 seconds.

**A helper process or `LaunchAgent` holding the machine vault.** Rejected: a second process holding
key material is what [ADR-0013](0013-agent-library-split.md) avoided, handing the key to it is a new
crossing between processes, and [ADR-0024](0024-safari-app-group-socket.md) already declined to move
a vault-holding process somewhere the user cannot see it. In the app, the key never leaves one
process and the menu bar shows its state.

**An agent proposes a grant; a person approves it**, like `add_variables`' pending entries.
Rejected (§5): it lets a prompt injection ask for months of access in one sheet.

**Unattended `write_env_file`.** Rejected (§1): the file outlives the run and is readable by every
same-user process while it exists.

**No unattended fills at all.** The first draft's position (§12's preamble has its reasons). The
owner decided against it.

**Unattended fills into the user's own browser**, with the tab-in-front rule. Rejected (§12.3): a
person's browser holds a person's sessions, and at night "the tab in front" is whatever the agent
left there.

**kagisecure types the value itself**, over the run browser's debugging protocol, so the extension
is not needed. Rejected: the agent drives the same browser and can read the page either way (point
5), so nothing improves, and a second value-carrying channel would sit beside the one ADR-0018
enumerates.

**A persistent profile per job**, so a session survives between runs and fewer sign-ins are needed.
Rejected (owner's answer 15): a session cookie on disk is a credential kagisecure does not
protect, readable by every same-user process between runs.

**One-time codes refused outright for unattended fills.** Considered; the switch (§12.5) is
adopted instead because some services allow no other automation, and it is off by default. The
owner kept it (answer 16).

**The registrable-domain origin rule of ADR-0022 and ADR-0036**, instead of an exact origin.
Rejected: that rule accepts any subdomain, and with no person to read the subdomain disclosure on a
sheet, a `user-content.` subdomain is the look-alike nobody sees.

**Approval collected by the MCP client** (SEP-2322), labelled as weaker — the fallback
[mcp-server.md](../mcp-server.md) §8 records. Rejected here: at night the client is the only thing
awake to answer, which is the reason §8 gives for distrusting it.

**Approval pushed to a phone.** Rejected: network code (N-9), and still not unattended.

**kagisecure minting short-lived credentials from the target service.** Rejected: network code, and
per-service integrations in a password manager's attack surface. The job can mint; kagisecure can
hold what it mints from.

## Changes in the threat model

**Applied on acceptance (2026-09-27)** to [threat-model.md](../threat-model.md) and
[threat-model-browser-extension.md](../threat-model-browser-extension.md). Every provisional
number below was checked against both files and every branch at acceptance and was still free
(R-15 had been taken by the presence grace window, which skipped the reserved R-14 on purpose), so
none was renumbered. W-24 was rewritten for the persistent arming of implementation decision 1,
and the threat model gained a list of the limitations implementation decisions 1, 2, 3, 5 and 8
accept. As first proposed: the numbers
below continue from the next free ones on `main` when this was written (A12, TB-7, T-18, M-32,
W-22, R-14; no other branch used them) and are **provisional — renumber at acceptance if taken**, as
ADR-0036's were. W-22 has since been taken on `main` by ADR-0035's Phase 0 (the format-upgrade
backup), so this ADR's "no person at release time" weakness is W-29 instead; W-23…W-28 are
unchanged, and [ADR-0043](0043-unattended-access-on-headless-hosts.md) uses W-30…W-43. They cover
the Mac design only: headless hosts (§15) change several of them — A12,
M-32, W-24, T-5 — and their follow-up ADR brings its own entries.

**New entries** *(proposed, provisional — renumber at acceptance if taken)*:

- **A12** — the machine vault: its values, its key while armed (app memory), its standing grants
  and job definitions (in its body). Loss means every machine credential in it, and the ability to
  release them on schedule.
- **TB-7** — a run's process tree and the machine vault. Enforced by the unattended socket's
  same-user gate, ancestry binding to a run kagisecure started, grants that pin the command and its
  inputs, per-run and total limits, suspension on anything unexpected, and audit before release.
- **T-18** — an unattended job's agent, and whatever steers it while nobody is watching: prompt
  injection through what the job reads, and same-user malware (T-3) writing the job's inputs or the
  granted command's inputs so that a scheduled run does its work.
- **M-32** — *The machine vault is separate, and armed by a person for a bounded time.* A separate
  file; its key in memory only, from a presence-proven arm until expiry, restart or pause; websites
  only as exact origins on Login items, one-time-password seeds never released, no references out;
  nothing from the personal vault or a shared replica is ever released or filled unattended
  (§2, §3, §13). Interactively, it is read through the ordinary socket and the ordinary extension
  listener only with the ordinary sheet and a presence proof, and only while the personal vault is
  unlocked (§2).
- **M-33** — *Unattended releases are bound to runs kagisecure started, under pinned, limited
  grants that fail closed.* Ancestry binding with start times; exact executable, arguments,
  directory and variables; pinned inputs; per-run and total limits and a hard expiry; one-strike
  suspension; suspension on a changed pin, or on a value changed other than by the person with a
  presence proof; no agent path to create or widen a grant;
  audit before release, a summary to the person, and local notifications (§4–§9).
- **W-29** — *No person at release time.* The grant is the last human decision; its facts were
  shown once, before the requests it covers existed (W-3, amplified). An edit made with a presence
  proof carries the grants over the edited value forward (§7), so that proof re-approves them too.
- **W-23** — *The granted command is defined by files the account can write.* Pinning detects
  changes to named files only; the job's own inputs are not pinned at all, and an interpreter grant
  may pin none (§5). An injected job agent or same-user malware can redirect an unpinned command's
  credential at the next run.
- **W-24** — *An armed machine vault's key is at rest, and a restart does not disarm it*
  (as applied; first proposed as "the armed key is in memory for days, and a restart disarms").
  The key is in the login Keychain while armed, with no expiry; a Mac stolen or restarted by
  someone else arms itself at the next login and releases machine-vault values to jobs kagisecure
  starts with nobody present, and a same-user process that can read the Keychain item holds the
  whole machine vault.
- **W-25** — *Abuse is noticed locally, after the fact.* No remote alert (N-9); the machine log's
  freshness after a disarm is W-11's until ADR-0041's anchor exists.

Added by the unattended-login design (§12), after the owner's answer:

- **TB-8** — the run's browser and the unattended extension endpoint. Enforced by the
  kernel-verified ancestry of the native host to the run browser's recorded pid and start time, a
  fresh profile per run, and the unattended endpoint serving no other browser. The ordinary
  extension listener reads the machine vault only for an interactive fill with a sheet and a
  presence proof (§2).
- **T-19** — a site, or whatever sits between the job and it, steering an unattended sign-in: a
  look-alike or redirected origin, a challenge page, a changed form. The browser half of T-18.
- **M-34** — *Unattended fills are machine-vault logins, typed at one exact origin, in the run's own
  browser, under a login grant.* Exact https origin with listed follow-ons only; top frame, same
  document at delivery; one sign-in per run by default; one-time codes behind a per-grant switch,
  off by default; suspension on another origin, a site left, a challenge or the tripwire; audit
  before release under the `mcp unattended` actor; an immediate notification and a reset advice
  (§12).
- **W-26** — *The job's agent holds the login.* It can read the filled password in the page it
  drives (W-21 with no person to decide the trust); the account's own scope is the bound. No reset
  is enforced after a suspension (§12.7), so a login that may have been read can be granted again
  unchanged.
- **W-27** — *With the one-time-code switch on, the account has one factor* against anything on
  this Mac.
- **W-28** — *The run browser is reachable by same-user processes* through its loopback debugging
  port for the length of a run, and its profile holds that run's session until the run ends.
- **R-14** (browser addendum) — *Challenge detection is heuristic.* A CAPTCHA or new-device page
  that looks ordinary is not recognized, and an agent that solves one itself is not seen.

No new N- entry.

**Existing entries this weakens or breaks** — for machine-vault releases and fills only; the
personal vault and shared vaults keep every one of them as they are:

| Entry | Effect |
| --- | --- |
| M-3 (human for every injection) | **Broken** for releases under a standing grant |
| M-5 (the prompt shows unforgeable facts) | Shown once, at grant creation, not at release |
| M-6 (least-privilege leases; no "always allow") | **Reversed** for the machine vault: grants persist across restarts and are an "always allow", bounded by §5. Leases are unchanged |
| M-7 (no rate limiter) | A second exception: here the limit bounds access, because nothing else at release time does |
| M-11 (auto-lock) | **Broken** for the machine vault while armed: it survives screen lock, idle and sleep |
| M-19 (caller verification) | Supplemented by ancestry; still no stronger than "a process of this user" against T-3 |
| M-20 (deliberate interaction) | Not applicable at release; applies to arming and grant creation |
| TB-3 (the biometric gate) | Bypassed at release for the machine vault; crossed at arming and at grant creation |
| A3 (vault key in memory while unlocked) | The machine vault key is in memory while armed — up to 14 days, across screen lock and sleep |
| A7 (leases, memory-only) | Grants are persistent state, in the machine vault body |
| W-3 (approving without reading) | Amplified: one approval covers weeks of unseen releases |
| W-4 (child environment readable) | Now routine and unobserved |
| W-11 (audit freshness) | Applies to the machine log after every disarm, and matters more there |
| N-6 (secrets after injection) | Routine, on a schedule, with nobody present |
| T-2 | A new unattended path, confined to a run's grants (§10); interactively, machine-vault environments are also reachable through the ordinary sheet (§2) |
| T-3 | Can cause a granted release at the scheduled time through the job's or the command's inputs (W-23), may read the child's environment (W-4), and can pause jobs |
| T-5 | A Mac stolen while armed holds the machine vault key in RAM |
| T-6 | A rewritten client configuration is a job input (W-23) |
| T-16 | Unchanged: arming and grant creation need a presence proof; pausing and revoking need none |
| M-29 (presence for every fill) | **Broken** for machine-vault logins filled under a login grant (§12) |
| M-31 (a sheet and biometric per agent fill) | **Broken** for the same fills; the origin rule is made stricter (exact origin), the tab-in-front rule looser (no visibility, §12.4) |
| ADR-0037's invariant (every secret response from a presence-checked grant) | Amended: a second `Approved` constructor for machine-vault logins only (§12.6) |
| W-21 (an agent fill is readable by the agent) | Amplified: no person decides the trust (W-26) |
| N-10 (a page reads a value after a genuine fill) | Now also after a fill nobody saw |
| T-15, T-17 | Can drive the run's browser; cannot move a fill off the exact origin or into another browser without suspension |

**Unchanged, and asserted by test:** M-1 and M-2 (ADR-0002), M-12, M-27, M-30 and N-9 everywhere;
M-29, M-31 and every rule of ADR-0004 for the personal vault and for shared vaults.

## Consequences

**Positive**

- Nightly jobs on this Mac get their machine credentials without a person, without the credential
  entering any transcript, and with a better scope, audit and at-rest story than the `.env`, the
  shell profile or the long-running daemon they would use otherwise.
- The personal vault, shared vaults and the user's own browsers keep exactly their current
  protection; the product's claim about them does not change.
- A scheduled sign-in to a website becomes possible without the job holding the password in its
  configuration, without the password entering a transcript, and only at one exact origin in a
  browser nobody else uses — for accounts the owner put in the machine vault on purpose.
- The most likely attack — an injected *interactive* session — cannot use a grant at all, and an
  injected *job* trips suspension on its first attempt to go beyond its grants.
- Every unattended release is recorded before it happens and summarized to the person on return.
- No new key at rest without a person, no network code, no new FFI crossing, no change to ADR-0002.

**Negative — accepted**

- **"The whole product is the prompt" stops being true** for one vault. That sentence is in
  mcp-server.md §5, ADR-0004 rule 6 and M-6, and each would be rewritten to name the machine vault
  as the one exception.
- ~~**Not fully automatic on the Mac.** A restart disarms; someone must arm again, at most every 14
  days.~~ *Amended 2026-09-27 (implementation decision 1):* **a key at rest instead.** Arming
  survives restarts and has no expiry, so the machine vault's key sits in the Keychain for as long
  as it is armed, and a stolen or rebooted Mac keeps releasing to kagisecure-started jobs (W-24).
  Headless hosts wait for their own ADR (§15).
- **Only jobs kagisecure starts.** A client's own scheduler cannot use grants, and there is no
  weaker mode for it (answer 4); the job must be defined in kagisecure.
- **A pinned command still trusts files that are not pinned** (W-23). The design detects what it
  was told to watch.
- **Friction on updates.** An update to an executable pinned by hash suspends its grants until a
  person re-approves. One pinned by code-signing identity keeps them, which also means any build
  its signer ships — an older one included — is accepted (answer 7).
- **Machine credentials are reachable interactively too** (answers 12 and 20): an injected
  interactive session can ask for them through the ordinary sheet, as it can for the personal vault,
  and machine-vault logins can be filled into the user's own browser.
- **State the approval system has avoided**: persistent grants, job definitions, a scheduler, a
  second socket and a second log to read.
- **A second rate limiter**, against M-7's reasoning, justified by what it bounds (§6).
- **More in the shared-vault format** (§13), and copies allowed by default in every shared vault
  until an admin turns them off (answer 21).
- **Unattended sign-ins give the login to the job's agent** (W-26); with the one-time-code switch
  on, the second factor too (W-27). The bindings of §12 decide where a password is typed, not who
  reads it afterwards; the account's scope, and a reset after anything unexpected, are the bound.
- **ADR-0037's structural invariant gains an exception**, for machine-vault logins, and ADR-0036's
  visibility rule is dropped for run browsers (§12.4, §12.6).
- **A run browser**: a second extension endpoint, a browser kagisecure launches and ends, a fresh
  profile per run, and a dependency on Chromium-family builds that still load an unpacked extension
  (§12.3), which may narrow over time.

**Neutral**

- The ordinary socket, the ordinary extension listener, every existing tool and every existing error
  code behave exactly as today for the personal vault and shared vaults; they also serve
  machine-vault items, with the same sheet and presence proof (answers 12 and 20).
- Users who never arm see nothing new.

## Owner's answers (2026-09-27)

The owner answered every open question of the first draft on the day it was written, and the two
follow-up questions (20, 21) those answers raised. Where an answer chose against this ADR's proposal
or the safer option — 6, 10, 12, 13, 18, 20 and 21 — what that costs in the threat model follows it.
Question 19 is still open.

1. **Build it** — the machine vault, not documentation only (former open question 1). Sequencing:
   after shared vaults ([ADR-0035](0035-shared-vaults.md)) have landed.
2. ~~**A restart disarms, and that is acceptable; there is no persistent arming** (former open
   questions 2 and 3). The arm stays at 7 days by default and 14 at most.~~ **Amended
   2026-09-27: arming persists across app and Mac restarts, and has no expiry.** The machine vault
   key is kept in the macOS Keychain (this device only, never synced) while armed, so jobs run
   after a restart without anyone present, and it stays armed until a person disarms it
   (implementation decision 1). *Cost:* a stolen or rebooted Mac can release machine-vault values
   to kagisecure-started jobs with no one present, and the key is at rest where a same-user
   process that can read the Keychain item holds the whole machine vault (W-24).
3. **Unattended browser sign-ins are wanted.** The first draft's §12 ("no unattended fills — not
   narrower, not later") is rejected; §12 is now the narrowest design this ADR can defend, with
   what it gives up stated in §12.9.
4. **Callers kagisecure did not start: never.** There is no weaker, labelled mode for a client's own
   scheduler, now or later (§4).
5. **Grant defaults as proposed:** one release (or one sign-in) per run, 60 uses, a 30-day default
   and a 90-day maximum expiry (§5, §12.2).
6. **Interpreters: a warning, not a requirement.** A grant for a shell, an interpreter or a package
   runner may be created with no pinned input, and its sheet warns when none is (§5). *Cost:* such a
   grant is a grant for whatever script the interpreter reads at release time, and a change to that
   script — by the job's own agent or by same-user malware — redirects the credential with nothing
   suspended (W-23).
7. **Pinning by code-signing identity where there is one, by hash otherwise**, for a job's root, a
   command grant's executable and the run browser alike (§4, §5, §12.3).
8. **Output `none` only:** `scrubbed` is not offered for unattended releases (§1, §5, §6).
9. **Shared-vault copies into the machine vault are allowed, and their copy records are published**
   to the shared vault, so other members see which device holds which item unattended; an unattended
   device as a member of a shared vault stays deferred (§13).
10. **An edit made by the person with a presence proof carries the grants over that value forward**;
    any other change — from the CLI, another writer, a shared-vault merge, or without presence —
    still suspends (§7). *Cost:* the presence proof for an edit becomes a re-approval of every
    standing grant over that value without the grant's own sheet, so a value pasted from an
    untrusted source, or an edit approved without reading, reaches unattended use at the next run
    with no suspension to catch it (W-29).
11. **One strike suspends every grant of the job and ends the run**, as proposed (§7, §12.7).
12. **Interactive use of machine-vault items is allowed** through the ordinary socket, with the
    ordinary sheet and a presence proof, while the personal vault is unlocked (§2). *Cost:* the two
    paths are no longer apart — credentials a job uses at night are also reachable by the most
    likely attacker, an injected interactive session, through one approved sheet (W-3), and
    interactive agents' metadata tools now list the machine vault's environments and variable names,
    which helps an injection aimed at a job.
13. **Headless hosts — build servers, CI runners, Linux hosts — are to be supported and armed
    automatically**, without a person, with the key in the host's key store (a TPM, for example) and
    surviving reboots; answer 2 stays for the Mac (§15). *Cost:* on those hosts the machine vault's
    key is at rest and usable by anything that can run as the service account or as root, no
    presence proof is made anywhere after provisioning, and a host stolen or rebooted by an attacker
    arms itself — which is why §15 leaves the design to a follow-up ADR rather than to this one.
14. **Names kept:** "machine vault", "arm", "standing grant", "job", "run browser".
15. **The run browser's profile is fresh per run** and discarded after it, as proposed (§12.3).
16. **The one-time-code switch is kept, off by default**, with its "two factors become one" warning
    (§12.5).
17. **The flow window is a fixed 60 seconds**; a grant does not carry its own (§12.5, §12.7).
18. **A suspension after a fill suspends only**: there is no "reset required" state, and the person
    may grant the login again without changing its password (§12.7). *Cost:* a login the job's agent
    may have read — and sent anywhere — can go back into unattended use unchanged, kagisecure cannot
    tell whether it was reset, and the advice to reset it is all that stands between a stolen
    password and its continued use (W-26).

To the follow-up questions this ADR's edits for answers 1–18 raised:

20. **Interactive fills of machine-vault logins are allowed**: answer 12 extends to the ordinary
    extension listener — an agent's `request_fill` and the human fill path — with the ordinary sheet
    and presence proof, only while the personal vault is unlocked (§2, §12.1, §12.4). *Cost:* the
    ordinary listener now reads the machine vault, so a service account's password — one the job's
    agent may already have read (W-26) — is also typed into the user's own browser beside a person's
    sessions, where every ordinary-path weakness (W-21, T-15, T-17) reaches it, and the separation
    that kept machine logins out of the user's browsers entirely is gone.
21. **The per-vault copy policy stays, default allowed**: an admin can turn copies off for a vault —
    a management vault, for example — and builds refuse them while it is off (§13). *Cost:* in every
    vault whose admin never changes the setting, any member can put a shared value into a store that
    releases it with nobody present, and the other members learn of it only from the copy record,
    after the fact.

To the questions implementing Phase 1 raised (2026-09-27):

22. **The machine vault needs no recovery of its own**: recovering the personal vault is enough
    (implementation decision 2). *Cost:* losing the personal vault with no armed Keychain copy
    loses the machine vault.
23. **A changed value is detected by its last-changed timestamp, not by a hash** (implementation
    decision 3). *Cost:* a writer that changes a value without moving `updated_at` goes unnoticed.
24. **The key's crossing to Swift for the Keychain is accepted** (implementation decision 5), and
    so is FileVault's effect: after a cold restart, nothing runs until someone logs in.

To the questions implementing Phase 3 raised (2026-09-27):

25. **The app registers itself as a login item the first time the person arms**, with
    `SMAppService.mainApp`, and unregisters only when the person turns the setting off
    (implementation decision 32).
26. **Copies stay copies, and Update syncs them** (implementation decisions 23 and 24, confirmed).
    A value copied into the machine vault changes only when the person presses Update.

The ADR was **accepted for macOS on 2026-09-27**. Answer 13 is recorded, not designed: §15 says
what it needs, and ADR-0043 proposes it.

## Implementation decisions (macOS, 2026-09-27)

Made while implementing Phases 0 to 4, under the owner's priority since 2026-09-27: convenience
first, looser security acceptable, no backward compatibility and no data migration. Where the
design above was heavy only for defence in depth, the simpler variant was taken. Each has a
matching limitation in [threat-model.md](../threat-model.md) §7 ("Unattended jobs: limits of the
convenience-first choices").

1. **Arming persists across restarts, with no expiry** (owner's answer 2, amended). While armed,
   the app keeps the machine vault's key in the login Keychain as a generic-password item,
   accessible after first unlock, this device only (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`),
   never synchronizable — the 48 bytes `MachineVaultKey::to_keychain_bytes` returns (the machine
   vault's `vault_id`, then its key). At launch the app reads it, opens the machine vault
   (`Vault::open_machine`) and is armed again without a person. The machine vault body's `arm`
   record (when, and by which presence proof) says it is armed; a disarm clears it and deletes the
   Keychain item. The app runs only in a login session, so with FileVault a cold restart runs
   nothing until someone logs in; a macOS update's own restart, which logs back in, resumes jobs.
   This supersedes §3's "memory only", its 7- and 14-day bound and its restart row.
2. **No recovery of its own.** The machine vault file has no password, recovery or platform slot.
   Its persistent key copy is the personal vault body's `machine_key`; the personal vault's
   password, Touch ID and recovery code therefore reach it too.
3. **Changed values by timestamp.** A grant records `approved_at`; the engine suspends it when the
   item or environment it releases has an `updated_at` later than that. No hash of any value is
   stored: a hash of a short secret would be an offline guessing oracle. An edit the person makes
   with a presence proof sets `approved_at` of the grants over it in the same transaction (owner's
   answer 10).
4. **One machine vault per personal vault, at a fixed place**: beside it, `<name>.machine.kagivault`
   for `<name>.kagivault` (`machine_vault_path`). The key record names the machine vault's
   `vault_id`, and opening checks it, so a key never opens another file as its machine vault.
5. **The key crosses to Swift**, once per arm, so the app can store it in the Keychain —
   the same kind of crossing as the platform slot's vault key. ADR-0008's list gains it in Phase 3.
6. **Exact origins are stored canonical.** `canonical_https_origin` turns what a person typed into
   `https://host[:port]` (lower-case host, no default port, no trailing slash) or refuses it; the
   structural rule requires every stored website to be in that form. No IDNA mapping in the core:
   an internationalized host is entered in its `xn--` form.
7. **Grant state lives in the grant.** Use counts and suspensions are fields of the grant records
   in the machine vault body, written in the release's own transaction; there is no separate
   state store.
8. **The structural rules are checked on every write, not on read.** `kagisecure-core` refuses to
   seal a machine vault that breaks one (`Error::MachineVault`), and a file that breaks one still
   opens. `resolve_environment` also refuses a one-time-password field in a machine vault, in case
   such a file is read. How the rules are read: "no references out" also refuses fields of kind
   `Reference` and items or environments in a logical vault of another file; one-time-password
   fields are allowed on any Login item, with or without a website; removing a job removes its
   grants, and removing an item, environment or website a grant or binding names is refused until
   that grant or binding goes.
9. **Formats bump, nothing migrates.** A personal vault holding a machine key, and every machine
   vault, is written as `format_ver` 3; the first write that raises an older personal file takes
   the existing create-new backup (vault-format §9 rule 3, W-22) and converts nothing.

Made while implementing Phase 2 (the engine, `crates/kagisecure-agent/src/unattended/`):

10. **Binding checks the root's start time, not every hop's.** A request is walked up the kernel's
    parent links (at most 16) to a live run's root, whose pid **and** start time must be the ones
    recorded; the processes in between are not checked for reuse (§4 asked for every hop). A chain
    broken by re-parenting to `launchd` is still refused.
11. **Local time from the system's current UTC offset.** The scheduler has no time-zone database:
    it adds the offset `/bin/date +%z` reports, asked again every tick (15 s), so a daylight-saving
    change is picked up within a tick. A job's times are the Mac's local times.
12. **Code-signing pins are checked with `/usr/bin/codesign`**: the signature must verify
    (`--verify --strict`) and its `Identifier` and `TeamIdentifier` must be the pinned ones. No
    Security framework binding in Rust. SHA-256 pins are hashed as before.
13. **A grant stands where a lease would, and output is never returned.** `run_with_env`'s reply
    on the unattended socket carries the grant's id as `lease_id` and its hard expiry as
    `expires_at`, so neither the protocol nor the sidecar gains a message; the caller's `output`
    is ignored and served as `none` rather than refused, since agents ask for the default.
14. **The ordinary socket serves machine-vault environments, not items.** With the machine vault
    attached (`Agent::attach_machine_vault`, while the personal vault is unlocked), `list_vaults`
    and `list_environments` include it, and `write_env_file` and `run_with_env` for one of its
    environments are served against it with the ordinary sheet and leases and recorded in its log
    under `mcp`. Its items are not listed or described, `create_environment` and `add_variables`
    never reach it, and interactive fills of machine-vault logins wait for Phase 5.
15. **The unattended socket's metadata tools answer from the run's grants only.**
    `list_environments` and `list_vaults` show only the environments the run's job has grants over,
    with only the granted variable names; `list_items` is empty, `describe_item` answers
    `NOT_FOUND`, `list_leases` is empty and `revoke_env_file` does nothing. `create_environment`,
    `add_variables` and `audit` answer `NOT_GRANTED` without a strike — none releases anything;
    `write_env_file` and a `run_with_env` no grant covers are strikes. `lock` is served to any
    same-user process, in a run or not, and disarms.
16. **A job's output is discarded.** The root starts with standard input, output and error on
    `/dev/null`; there is no job log file, which would be a plaintext file of whatever the job's
    agent printed.
17. **"Run now".** The app may start a job at once (`Engine::run_now`), and its grants apply to
    that run exactly as to a scheduled one.
18. **Missed runs.** At arm and at resume the scheduler counts from that moment, minus the job's
    catch-up window: times that passed while the app was not running are not started and not
    recorded. A time noticed later than its catch-up window (at least two minutes, the tick's
    slack) is recorded `JOB_MISSED (TOO_LATE)`; one that comes while the job is still running,
    `JOB_MISSED (STILL_RUNNING)`.
19. **Re-approving grants on an edit is the app's** (owner's answer 10, Phase 3): the app sets
    `approved_at` of the grants over a value the person edits with a presence proof. Until the app
    does, every edit of a released value suspends its grants.
20. **Deferred to Phase 3:** the "While you were away" summary and `SUMMARY_ACKNOWLEDGED`, with its
    witness of the machine log's head in the personal log. The engine keeps notices
    (`Engine::take_notices`) for the app's notifications.
21. **A machine-vault conflict disarms** at the next request or tick, as §3's table says, and the
    arm record is cleared where the file can still be written.
22. **The Windows C ABI exports none of it** (§14): `kagisecure-ffi`'s `capi` leaves out every
    `unattended_*` call and `agent_attach_machine_vault`.

Made while implementing Phase 3 (the macOS app, `UnattendedService`, `UnattendedView`,
`NewJobSheet`, and `kagisecure-ffi`'s `unattended_manage`):

23. **Values enter by copying a personal environment, not by moving items.** "Add an environment"
    copies a personal environment's current values into the machine vault as inline values,
    resolved inside Rust (none crosses the FFI); the copy remembers its source, and **Update**
    copies again. §2 asked for a move, so there would be one value to rotate: with a copy there
    are two, and the personal one keeps working for the person. The machine vault's logical vault
    is made visible to agents and the copy keeps the source's agent visibility, so the ordinary
    socket can offer it interactively (decision 14) as the source was.
24. **Re-approving on an edit is the Update button** (owner's answer 10, decision 19): copying an
    environment again, after a presence proof, sets `approved_at` of every grant over it, so the
    change carries them forward. A change made any other way still suspends them.
25. **A new job is one sheet, and its grant comes with it.** A program, its arguments, a folder, a
    time (every day or one weekday) and an environment; by default the grant lets the job run its
    own program with the same arguments and every variable of the environment, and a switch names
    another command instead. The executables are pinned when the job is created — by code-signing
    identity when validly signed with a team, by hash otherwise. Grant defaults as §5 (one release
    per run, 60 uses; expiry 30 days, set on the sheet up to 90); run deadline and command timeout
    30 minutes; no catch-up window; no pinned inputs (the sheet shows §5's sentences, and the
    interpreter warning when the command is a shell, an interpreter or a package runner). There is
    no separate grant sheet: changing a grant is revoking the job and creating it again.
26. **Re-enabling clears the suspension in place.** A suspended grant's **Re-enable…** asks for
    presence and clears the suspension, counting what it releases as approved now; its uses and
    expiry stay. §7 asked for re-creation with its sheet.
27. **Presence for arming and for every widening is LocalAuthentication** — Touch ID, an Apple
    Watch or the login password — through the shared `PresenceCoordinator`, recorded as
    `PRESENCE_CONFIRMED`. The master-password fallback of ADR-0038 is not offered for these.
    Revoking, removing an environment and Pause ask for nothing.
28. **The Keychain item** is a generic password in the login Keychain — service
    `com.kagisecure.unattended`, account `machine-vault-key` — accessible after first unlock, this
    device only, not synchronizable, with the Keychain's default access list for the app that
    created it (not measured against another same-user process; W-24 assumes the worst). The app
    deletes it on Pause, on a `DISARMED` notice from the engine, and at launch when the machine
    vault is no longer armed.
29. **The engine starts at app launch, locked or not**, and resumes from the Keychain. Nothing
    registers the app as a login item: for jobs to run after a restart, the person adds
    Kagisecure to Login Items themselves.
30. **"While you were away" lists the machine log since the last acknowledgement**, leaving out
    the person's own decisions (actor `app`); it is shown after an unlock when it is not empty,
    and **Done** writes `SUMMARY_ACKNOWLEDGED` with the machine log's length and head to the
    personal log. Its total, plus unseen notices, is the menu-bar badge.
31. **Notifications** are asked for when arming, and posted for a suspension, a disarm, a missed
    run and a job that did not start — named by job and reason, never by value or command line.
32. **The login item** (owner's answer 25). The first arm registers the app with
    `SMAppService.mainApp` and remembers that it did; from then on only the "Open Kagisecure at
    login" checkbox in Unattended jobs registers or unregisters it — pausing and arming again do
    not. This replaces decision 29's "nothing registers the app as a login item".
33. **Copies stay copies** (owner's answer 26): decisions 23 and 24 stand as built.

Made while implementing Phase 4 (shared vaults: `kagisecure-shared`'s `unattended` module,
`kagisecure-ffi`'s `unattended_manage`, the app's Unattended jobs pane):

34. **A shared copy is of a shared environment, and never of a login.** "Add an Environment…"
    lists each open shared vault's environments; copying one resolves its values inside Rust (none
    crosses the FFI), exactly as a personal copy does, and is refused when a variable is bound to a
    field of a Login item — so no shared account's password becomes unattended, as §13 requires.
    The copy remembers its source — shared vault, environment, and for each variable the records
    its value came from (the variable's own and the bound field's) — and its name is
    `environment (vault)`. Every role may copy, since every role can read (§13).
35. **The policy and copy records, simplified.** Two new encrypted record kinds, `policy` and
    `unattended_copy`, sealed under the current epoch like items and environments. The policy is
    written by an admin's device only and the latest by claimed time, then record id, wins, with
    no ancestry; a vault with none allows copies (owner's answer 21). It is an ordinary record,
    not a roster-level one that makes an older build read-only: an older build keeps and forwards
    both kinds unread. A copy record carries the copy's id, the source environment and name, the
    variable names, whether the copy is held, and the holder's own description of itself (the
    Mac's name) — device labels are sealed to the roster; for each device and copy, the latest
    record stands.
36. **No suspension on a new version: the copy is marked instead.** §13 suspends the grants over a
    copy whose source got a new version, so a value another writer poisoned never reaches
    unattended use unseen. With copies that change only on Update (decision 33), a new version
    cannot reach unattended use without a person pressing Update after Touch ID, so that
    suspension defends nothing more: the copy is marked "changed at its source" in Unattended jobs,
    and its jobs keep running on the value as copied. The same mark shows for a personal copy whose
    environment, or an item it binds, changed since. A copy whose source vault is not open is not
    judged.
37. **Members are told first.** The copy record is written to the shared vault before the value is
    written to the machine vault, so a copy the other members were not told about is not made when
    the record cannot be written; removing a copy writes one saying it is no longer held.
38. **Where copies are shown.** Unattended jobs lists, for each open shared vault, whether copies
    are allowed — a checkbox for its admins — and which devices hold a copy of what, flagging a
    device removed from the vault ("rotate these values at their service first"). The members view
    and the rotation list are unchanged; the flag lives in this pane instead.
39. **Forbidding copies stops new ones only.** Copies already made stay where they are, listed; no
    build deletes another device's copy, and this one does not delete its own.

### Phase 5: the measurement (2026-09-27)

Measured on the owner's working Mac (macOS 27) with **no visible window and no focus taken**: each
browser was launched by Playwright's `launchPersistentContext` with `--headless=new`, a fresh
`--user-data-dir`, `--load-extension` and `--disable-extensions-except` naming `extensions/shared`,
a native messaging manifest written only into `<profile>/NativeMessagingHosts/`, and
`KAGISECURE_EXTENSION_SOCKET` in its environment. "Extension" means the service worker at the
pinned id started; "native host" means `chrome.runtime.connectNative` from that worker launched the
program the profile's manifest names, with the variable in its environment; "visibility" is
`document.visibilityState` of a tab opened in that browser.

| Build | Extension | Native host from the profile's manifest | Visibility |
| --- | --- | --- | --- |
| Microsoft Edge 154.0.4258.37 | yes | yes | `visible` |
| Chromium 153.0.8010.12 (Playwright's) | yes | yes | `visible` |
| Google Chrome 154.0.8037.57 | **no** — `--load-extension` ignored, as browser-extension.md §9 found for Chrome 152 | — | — |
| Brave 154.0.8037.58 | yes | **no** — the profile's manifest is not read | — |

The end-to-end scenario (suite B, `unattended.test.mjs`) repeats the Chromium row with the engine
launching the browser itself rather than Playwright, and a sign-in through it succeeds.

**To measure with the owner present:** what a run browser's tab reports on a **locked screen**, and
whether a headless run browser behaves differently there at all. Nothing was measured with a
locked screen or a visible window, as the owner's machine rule requires. The design does not depend
on the answer: a run browser's reports are taken as visible whatever they say (decision 42).

### Phase 5: unattended sign-ins, convenience-first (2026-09-27)

40. **The run browser is headless** (`--headless=new`), superseding §12.3's "headful": the
    measurement shows the new headless mode loads the extension and reads the profile's manifest
    in Edge and Chromium, and a headless browser opens no window and takes no focus on the owner's
    Mac. The engine starts it with a fresh profile under `unattended-runs/` beside the machine vault
    (`0700`), the manifest written into that profile, `--remote-debugging-port=0` on 127.0.0.1, and
    `--use-mock-keychain`; it reads the port from the profile's `DevToolsActivePort` and gives the
    job `KAGISECURE_RUN_BROWSER_CDP=http://127.0.0.1:<port>`. When the run ends — the root exits,
    the deadline, a strike, a pause, the app quitting — the browser's process group is ended
    (`SIGTERM`, then `SIGKILL` after three seconds) and the profile deleted. A job whose run browser
    cannot start (`RUN_BROWSER_UNAVAILABLE`, `RUN_BROWSER_NOT_STARTED`, `RUN_BROWSER_PIN_CHANGED`)
    does not start at all.
41. **One extension endpoint per run, not one while armed.** §12.4's unattended extension endpoint
    is an `ExtensionAgent` over the machine vault that the engine binds for each run with a run
    browser, at `ux-<app pid>-<run>.sock` beside the unattended socket, and unbinds at the run's
    end. Its gate replaces ADR-0019's "a recognized browser launched it" with "the kernel's parent
    links from the native host reach this run's browser, with its recorded pid and start time"
    (`ExtensionAgent::start_gated`); anything else is refused with `UNTRUSTED_HOST` before it can
    say anything, and recorded as `HOST_REFUSED`. Its broker sees only this browser's sessions, so
    no run's fill can reach another run's browser; its approval queue is closed, so the extension's
    own fill and one-time-code requests there are refused — nothing on it ever asks a person.
42. **Visibility is not required of a run browser.** §12.4 drops ADR-0036's "document is visible"
    for run browsers; the broker built for them takes every report as visible. Top frame, the
    active tab, exactly one eligible report, the origin, the fields and the delivery re-checks are
    ADR-0036's, unchanged.
43. **The standing pass.** The second `Approved` constructor, `Approved::from_standing`, takes a
    `StandingPass`, which only `crate::unattended::login` can issue (`pub(in crate::unattended)`),
    and only for a Login item of a vault that `is_machine()`, under a login grant that vault holds
    unsuspended, for its origin (or a follow-on origin) and fields. The broker's gate 8 spends the
    pass instead of raising a sheet: gates 5–9 — the audit pre-flight, the target, the delivery,
    the committed `Allowed` entry before the value leaves — are ADR-0036's own code. A standing
    fill raises no sheet, so it does not count against the agent's budget of sheets. The source
    scan in `crossing.rs` now also covers `unattended/login.rs` and `unattended/browser.rs` (no
    value read there), and a second scan pins `StandingPass::issue` to `unattended/login.rs`. No
    compile-fail test was added: the pass's fields are private and its constructor's visibility is
    the compile-time guarantee.
44. **Strikes, simplified.** A `request_fill` no login grant of the run's job covers — another
    item, origin or field, or a code with the switch off — is a strike (every grant of the job
    suspended, the run and its browser ended, a notice), and so is the broker's `OriginMismatch`
    (a tab in front at an origin the login is not saved for). A grant that is suspended, expired,
    used up or over its per-run limit refuses with `NOT_GRANTED` and no strike, including a second
    sign-in in one run. `FILL_UNAVAILABLE` (the run browser not connected yet) and
    `NO_MATCHING_TAB` are never strikes: the job may retry.
45. **Left-site and challenge detection are not built.** §12.7's third and fourth bullets — a
    top-frame document at an unlisted origin within the flow window, a password or code field
    appearing again — are dropped; §12.7 already calls them heuristics. The tripwire stays: an
    `Unmasked` notice from the run's broker suspends every grant of the job at the job's next
    request or at the run's end, whichever comes first.
46. **The use is counted after the release.** A sign-in's use is added to the grant in its own
    write after the fill is delivered, not in the transaction that commits the `Allowed` entry; a
    write that fails costs at most one use. An identifier-first sign-in counts once, its second
    step not at all; a one-time code counts against the run's codes — at most one per sign-in in
    that run — not against the grant's sign-ins.
47. **Follow-on origins are recorded but not offered.** A grant may list them, and a request's
    claimed origin may be one; the broker still requires the tab to be at a website the login is
    saved for, so a follow-on origin works only when the login is saved for it too. The app's sheet
    offers none.
48. **Logins enter by copying a personal login** ("Add a Login…"), after a presence proof, as
    environments do (decision 23): the copy keeps the fields, including a one-time-password seed;
    not the password history; its websites become the exact https origins they name, since a
    machine vault holds no other kind (§2); it is agent-visible. **Update** copies it again and
    re-approves the login grants over it (decision 24). A shared login cannot be copied: the call
    reads only the personal vault.
49. **A job may only sign in.** The "New job" sheet takes an environment, a login, or both. With a
    login it names one of the login's origins, the run browser — Microsoft Edge by default, else
    Chromium — and the one-time-code switch, which is offered only for a login with a seed and
    shows §12.5's box when on; the sheet carries the second sentence of point 5 and §12.2's advice
    verbatim. The app ships the extension in `Contents/Resources/ChromiumExtension` (`cargo xtask
    embed`); a development build uses `extensions/shared` from the source tree, or
    `KAGISECURE_RUN_BROWSER_EXTENSION`.
50. **Audit.** An unattended fill's entries are the broker's, in the machine vault's log, under the
    actor `mcp unattended "<job>" run <id> pid <n> <executable> via <browser> (extension "<id>")`
    — the broker's `via` suffix rather than §12.8's `(run browser)`; the Audit view's Unattended
    and agent filters both match it. The `Allowed` detail is
    `UNATTENDED_FILL_APPROVED (grant <g> run <r>)`; refusals are `NOT_GRANTED (<reason>)`, and
    suspensions `GRANT_SUSPENDED (<reason>)` with the reasons `NO_GRANT`, `OTHER_ORIGIN`,
    `UNATTENDED_FILL_UNMASKED`, `VALUE_CHANGED`, `WEBSITE_CHANGED` and `ITEM_GONE`. "While you were
    away" counts a sign-in among the releases; the menu-bar badge does not count sign-ins
    separately.

### After the owner's GUI check (2026-09-27)

51. **A job's own program starts with its environment.** When a command grant of a job names
    exactly the job's own program — the same executable, the whole argument list and the working
    directory, which is what the New Job sheet's "It may run its own program with the environment"
    creates — the engine does not wait for the program to call `run_with_env`: at the run's start
    it resolves the grant's variables and starts the program with them in its environment, so a
    plain script needs no socket call. It is a release like `run_with_env`'s, through the same
    audited path: the grant is checked again and its use counted in the transaction that commits
    the `Allowed` entry (tool `run_with_env`, detail `UNATTENDED_GRANT <g> RUN <r> (JOB_START)`,
    actor `mcp unattended "<job>" run <r> job start <program>`), and only then does the program
    start; the release also takes one of the run's per-run releases of that grant. A grant that is
    suspended, expired or used up starts the program without the variables and records
    `NOT_GRANTED (<reason>)`; a changed pin or value suspends the grant (§7) and starts it
    without them; an audit log that cannot be written starts nothing (`JOB_NOT_STARTED
    (AUDIT_UNAVAILABLE)`). A grant for another command is unchanged: its values are released
    only when the job asks.
52. **Arming creates the machine vault** when the personal vault has none yet: the first Arm is
    also the first use, and needs no separate step.
53. **The arm sheet is one state.** It is shown from the service's own flag, not a view's, and
    **Arm** closes it before the presence prompt; a second Arm while one is in progress, or once
    armed, does nothing.

## Open questions

All eighteen open questions of the first draft, and the follow-ups 20 and 21, are answered above.
One question raised by those answers remains:

19. **Headless hosts — blocking, for headless hosts only** (§15). The follow-up ADR must decide: (a)
    which process hosts the engine where there is no app, and how a release build still refuses
    `--auto-approve` (ADR-0007 §2); (b) the key store and its sealing policy — bound to boot
    measurements or not, an authorization value or not, and what a host with no TPM gets; (c) how
    jobs and grants are provisioned from the Mac by file, how a host is enrolled, and how late a
    revoke may arrive; (d) whether answer 4 holds on a CI runner, whose jobs the CI service starts;
    (e) Linux's counterparts to the peer check, the ancestry walk and process-group teardown; (f)
    audit, its freshness and noticing with no app; (g) whether unattended sign-ins exist on a host
    without a display. [ADR-0043](0043-unattended-access-on-headless-hosts.md) proposes an answer to
    each, and records the owner's answers to its own questions.

## Implementation plan

Each phase ends with something testable on its own. **Done: Phases 0 to 5** (2026-09-27, on
macOS; see "Implementation decisions"). Phase 1's tests are
`crates/kagisecure-core/tests/machine_vault.rs` and the `format_ver` 3 golden vectors
(`v3-machine-key-argon2id-64k`, `v3-machine-vault`) in `tests/vault.rs`. Phase 2's are
`crates/kagisecure-agent/tests/unattended.rs` — a request from outside a run refused; every IPC
message sent from outside a run and from inside a real run, creating and changing no job or
grant; the ADR-0002 canary through the real sidecar with a successful unattended release; the
scheduler; arming, resuming and disarming; the ordinary socket's reads of the machine vault — and
`kagisecure-mcp`'s check that no tool reaches grants, jobs or arming. Of Phase 2's own list, these
are not yet tested: each binding of §5 changed alone, a sibling process started by a different
parent, a changed pin or value suspending, and a restart or pause ending a run's children.
Phase 3's are `crates/kagisecure-ffi/tests/unattended_manage.rs` (copying an environment, creating
a job with its grant, the overview, updating a copy, revoking, the summary) and the app's
`KagisecureTests/UnattendedTests.swift` (arming only after presence and keeping the key in the
Keychain, Pause and an engine disarm forgetting it, re-arming at launch, presence before every
widening, "While you were away", the new-job form, the interpreter warning, the Audit filter). No
UI test covers the new screens. Phase 4's are `crates/kagisecure-shared/tests/unattended_copies.rs`
(copies allowed by default, recorded by a writer and a reader, read by every member, forbidden only
by an admin, a removed copy gone, a removed holder's copy flagged), `kagisecure-ffi`'s
`unattended_manage::shared_copy_tests` (a shared copy announced, marked when its source changes,
updated in place, refused for a login and when forbidden, removed with its record; a personal copy
marked after an edit), and the app's `UnattendedTests` (the login item on the first arm only, the
shared source parsed, stale copies read and forgotten on lock). Phase 5's are e2e suite B's
`unattended.test.mjs`, headless only — a run browser the engine starts, a canary login filled at an
exact https origin and posted by the page, audited `UNATTENDED_FILL_APPROVED`, counted once, found
in no tool result, sidecar byte or audit entry, and a second browser pointed at the run's extension
endpoint refused as `HOST_REFUSED` — `kagisecure-agent`'s
`unattended::a_session_from_a_browser_other_than_the_runs_is_refused` (a stand-in browser: its own
native host served, this test process refused, the endpoint and profile gone at the run's end, the
job handed the control endpoint), the unit tests of the standing pass (a personal vault's login,
another origin, another field and a grant the vault does not hold produce none), of the ancestry
walk and of the grant's coverage, the widened source scans in `crossing.rs`, and `kagisecure-ffi`'s
login copy, sign-in-only job and login grant test; in the app, the form's sign-in rules and
presence before copying a login. Not yet tested of Phase 5's list: each binding changed alone at
the browser end (tab, frame, document), a code fill end to end, a steered tab suspending end to
end, and the ordinary extension listener's interactive fill of a machine-vault login (owner's
answer 20), which is not built. **Sequencing
(owner's answer 1): this work starts after [ADR-0035](0035-shared-vaults.md) has landed** — its
personal-vault format change is a prerequisite here, and §13's records are designed against it.

- **Phase 0 — documentation and prerequisites.** A page, "Credentials for unattended jobs": where
  they belong (option (c)), why short-lived and scoped (d1), and what an unattended sign-in gives
  up (point 5, §12.9). ADR-0035 implemented, including its Phase 0 (`Body`/`Header` passthrough,
  the `format_ver` decision), which both ADRs need.
- **Phase 1 — core.** The machine vault: its key in the personal vault body, its structural rules
  (websites only as exact https origins on Login items, one-time-password seeds never released, no
  outside references), job and grant records of both kinds in its body, golden vectors. Tests: each
  structural rule refused in `kagisecure-core`; a personal vault holding a machine key round-trips.
- **Phase 2 — the engine, in `kagisecure-agent`: command grants.** Arming state, the scheduler,
  launching runs in their own process groups, ancestry binding, the unattended socket, the release
  path of §6, suspension, both logs, `NOT_GRANTED` and `UNATTENDED_PAUSED` in the IPC protocol, and
  the ordinary socket's reads of the machine vault (§2). Tests: every binding of §5 refused when
  changed alone; a request from outside a run refused (including a sibling process of the run
  started by a different parent); a changed pin suspends; a changed value suspends unless the person
  made the change with a presence proof; one strike suspends and ends the run; the ordinary socket
  answers `VAULT_LOCKED` for a machine-vault environment while the personal vault is locked, armed
  or not, and never releases one without a presence proof; a restart, an expiry and a pause disarm;
  nothing is released without its `Allowed` entry; `request_fill` on the unattended socket is
  `FILL_UNAVAILABLE` until Phase 5; the canary with a successful unattended release; and **no IPC
  message and no MCP tool reaches grant or job creation**, asserted by enumerating the protocol.
- **Phase 3 — the app.** The arm sheet, the job and command-grant sheets (ui-spec §10.8), an
  Unattended section in Agent access with Revoke and Pause, the menu-bar state and badge, "While
  you were away", notifications, the Audit view's second log and **Unattended** filter.
- **Phase 4 — shared vaults**: the vault policy record, copies with provenance (command
  credentials only, never logins), copy records, suspension on a new version, rotation-list flags.
- **Phase 5 — unattended sign-ins (§12)**, after the command-grant phases have run for real. It
  starts with a **measurement**: which Chromium-family builds, launched with a fresh
  `--user-data-dir`, still load the unpacked extension and read the native messaging manifest from
  that profile, and what `document.visibilityState` a run browser's tab reports on a locked screen
  — recorded in this ADR the way ADR-0011 and ADR-0024 recorded theirs. Then: the run browser
  (launch, fresh profile, extension, manifest, `KAGISECURE_EXTENSION_SOCKET`, control endpoint,
  teardown); the unattended extension endpoint and its ancestry gate; login grants and their sheet
  with the one-time-code switch; the second `Approved` constructor and the widened source scan;
  the checks of §12.6 through ADR-0036's broker; the post-fill reports and suspensions of §12.7;
  the audit details and notices of §12.8. Tests: a session from any browser but the run's is
  refused before it can speak; a personal-vault or shared item can never produce the new
  `Approved` (a compile-fail test); each binding refused when changed alone (origin, item, field,
  run, tab, frame, document); a one-time code refused with the switch off and suspending the job;
  a top-frame document at an unlisted origin after a fill suspends; a failed sign-in (the password
  field again) suspends; the canary with a *successful* unattended fill and a successful code fill;
  the ordinary extension listener fills a machine-vault login only after a sheet and a presence
  proof, and refuses it while the personal vault is locked, armed or not.
  The browser half runs in e2e suite B's harness, never against the user's real profile.
- **Not in this plan:** headless hosts, which follow their own ADR (§15). There is no weaker caller
  mode (owner's answer 4) and no persistent arming on the Mac (owner's answer 2).

**Documents that change on acceptance** (applied 2026-09-27; where a document describes something
not yet built, the change is a short section marked "accepted, not yet built", and the full text
lands with the phase that builds it): [threat-model.md](../threat-model.md) (the entries above,
and M-3, M-6, M-7, M-11 amended to name the exception), [mcp-server.md](../mcp-server.md) (§5's
"always allow" row, §7's two codes, a section on the unattended socket), ADR-0004 (a pointer on
rules 4 and 6), [architecture.md](../architecture.md) (§2.5 jobs of the app, §2.6's sentence, §4.2
the second endpoint), [vault-format.md](../vault-format.md) (the machine vault and the personal
body's new list), [ui-spec.md](../ui-spec.md) (§6.3, §10.4, a new §10.8 and a login-grant sheet
beside it), [browser-extension.md](../browser-extension.md) (run browsers and the unattended
extension endpoint), [threat-model-browser-extension.md](../threat-model-browser-extension.md)
(R-14, and T-15 and T-17 against run browsers), ADR-0036 and ADR-0037 (pointers to §12), and
[roadmap.md](../roadmap.md) as below.

## Roadmap changes

**Applied on acceptance (2026-09-27)** to [roadmap.md](../roadmap.md) — the milestone M11, "in
progress", in place of the post-v1 bullet, since the ADR is accepted and scheduled — and to
[architecture.md](../architecture.md) §9. As first proposed:

**1. The post-v1 list** gains one bullet:

```text
- Unattended use of machine credentials by scheduled jobs on this Mac — a separate machine vault,
  armed by a person for a bounded time, released only to jobs kagisecure starts, under standing
  grants: commands run with pinned variables, and sign-ins of dedicated service accounts typed at
  one exact origin in a browser kagisecure launches for the run. Proposed in
  [ADR-0042](decisions/0042-unattended-agent-access.md); not accepted, not implemented; to follow
  shared vaults. The personal vault, shared vaults and the user's own browsers are never unattended.
```

**2. If scheduled**, a milestone after shared vaults — M11 if ADR-0035 takes M10 as expected —
with this row:

```text
| M11 | Unattended jobs (machine vault, standing grants, run-browser sign-ins) | M4, M9; ADR-0035 implemented; ADR-0039/0040 implemented | proposed |
```

and acceptance criteria taken from the Phase 2 and 3 test lists, plus:

```text
- [ ] No release from the personal vault or a shared replica is possible without a presence proof,
      armed or not; asserted by test.
- [ ] A request from any process not descended from a run kagisecure started is refused, whatever
      grants exist.
- [ ] No MCP tool and no IPC message creates, widens, extends, re-enables or proposes a grant or a
      job; asserted by test.
- [ ] A restart leaves the machine vault disarmed and releases nothing until a person arms it.
- [ ] A value seeded into the machine vault never appears in any byte the sidecar writes, across a
      successful unattended release (the ADR-0002 canary, extended).
- [ ] An unattended fill lands only in the run's own browser, at the login grant's exact origin;
      a session from any other browser is refused before it can ask anything; the ordinary
      extension listener fills a machine-vault login only with a sheet and a presence proof.
- [ ] A one-time code is never filled unattended unless the login grant's switch is on, and never
      onto the clipboard.
- [ ] A value seeded as a machine-vault password never appears in any byte the sidecar writes,
      across a successful unattended fill.
```

**3. [architecture.md](../architecture.md) §9** ("What is deliberately absent") gains, whether or
not the rest is scheduled:

```text
- No unattended release or fill from the personal vault or a shared vault, and no unattended fill
  into the user's own browser. Unattended use, if built, is confined to a separate machine vault
  and to browsers kagisecure launches for one job run (ADR-0042).
```
