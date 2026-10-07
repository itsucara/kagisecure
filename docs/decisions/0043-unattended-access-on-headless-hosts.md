# ADR-0043: Headless hosts arm themselves from a key in their own key store and take every grant from a signed bundle made on a Mac

- **Status:** **Accepted (2026-10-07) for one scope: deploy keys on a Linux host** — the
  "Accepted scope" section below, which is built (`crates/kagisecure-host`, `kagisecure
  host-bundle`). Everything else in this ADR stays **Proposed** (2026-09-27): it is the design
  the accepted scope is a first slice of, and where the two differ, the accepted scope decides for
  what it covers.
- **Date:** 2026-09-27
- **Deciders:** the owner (accepted scope, 2026-10-07: start with deploy keys on one headless server)
- **Refines:** [ADR-0042](0042-unattended-agent-access.md) §14, §15 and its open question 19 (this
  is the follow-up ADR they call for), and ADR-0042's owner's answer 4, **for headless hosts only**
  (§11); [architecture.md](../architecture.md) §2.6; [threat-model.md](../threat-model.md) M-13 and
  M-15, for headless hosts only
- **Relates to:** [ADR-0002](0002-no-secret-values-over-mcp.md),
  [ADR-0004](0004-biometric-key-wrapping.md),
  [ADR-0007](0007-m2-daemon-and-ipc-deviations.md) §1–§3,
  [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md),
  [ADR-0013](0013-agent-library-split.md),
  [ADR-0015](0015-peer-code-signature-verification.md),
  [ADR-0018](0018-browser-extension-secret-crossing.md),
  [ADR-0019](0019-native-messaging-forwarder.md),
  [ADR-0026](0026-helper-binaries-inside-the-app-bundle.md),
  [ADR-0032](0032-authenticode-peer-verification.md),
  [ADR-0035](0035-shared-vaults.md) (and its 2026-09-27 addendum),
  [ADR-0038](0038-app-release-needs-presence.md),
  [ADR-0039](0039-transactional-vault-writes-and-the-lock-file.md),
  [ADR-0040](0040-audit-before-release.md),
  [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md),
  [vault-format.md](../vault-format.md), [browser-extension.md](../browser-extension.md) §9

> **What is built is the accepted scope only.** The rest of this ADR is a proposal, written
> against [ADR-0042](0042-unattended-agent-access.md). Mechanisms are described in the present
> tense because that is how the other ADRs read, not because code exists. Its threat-model entries
> are listed under "Changes in the threat model" with provisional numbers;
> [threat-model.md](../threat-model.md) is not edited by it.

## Accepted scope (2026-10-07): deploy keys on a headless host

**The owner's decision.** Start with deploy keys: the staging and gateway deploys of a project
run on the owner's headless Ubuntu server take their SSH deploy key from kagisecure
instead of a passphrase-less key file, unattended, under a standing grant that names that exact
command; the key file is then removed. The owner's direction for this stage: correctness and code
quality first, convenience first, no backward compatibility.

What follows decides every question this scope raises, with the simplest choice that is correct.
Where it is simpler than §1–§20, the simplification is named, and the larger design remains the
direction for later scopes.

### A1. One binary, one engine per host, no approval path

`kagisecure-host` (crate `crates/kagisecure-host`, Linux and macOS) is the only process on the host
that holds the key. It has **no approval path**: no prompt, no flag that approves, no message that
creates or widens a grant. Its socket accepts one request — "run grant *G* as *argv* in *cwd*" —
and refuses anything else unread (`deny_unknown_fields`; a test sends an `approve` field and gets
`BAD_REQUEST`). `kagisecure daemon` is unchanged (§2).

Reused, not duplicated: the core's injector (`inject::run_with_env` with `Delivery::Stdin`, its
masking, process group and deadline), the machine-vault grant types (`PinnedExecutable`,
`GrantLimits`, `PresencePath`, `file_sha256`), and the shared-vault crypto (device keys, HPKE,
domain-separated Ed25519). The core gains one field, `RunRequest::run_as`, so a command can be
started as another account. The Mac's engine in `kagisecure-agent` is not linked: its jobs,
schedules, run binding and Keychain arming are what this scope does without (A4).

**Simplified from §2–§3:** one account runs the engine (root, A2) and granted commands run as the
grant's `run_as` account; there is no job/CI account split, no cgroup or peer-pid binding, and no
`separate`/`shared` profile choice at `init`.

### A2. Key protection: a 0600 file by default; a TPM-sealed systemd credential optional

- **Default: a key file.** `kagisecure-host init` creates the host's key pair — a shared-vault
  device key, X25519 for sealing and Ed25519 for identity — in
  `/var/lib/kagisecure-host/host.key`, mode `0600`, in a `0700` directory (`StateDirectory=`).
  The service runs as **root**, so the file is readable by root alone. The true sentence, printed
  by `init` and repeated in the docs: *anything that can read that file — the service, or root —
  can open every bundle made for this host and so holds every value in it.* A host without a TPM
  is no worse than the passphrase-less key file it replaces, and better in one way: what rests on
  disk is ciphertext plus a key only root can read, not a key any process of the operator can.
- **Why root, not a service account.** A granted command runs as the grant's account. A
  non-root service would need `CAP_SETUID`/`CAP_SETGID` as ambient capabilities, which a child
  that changes from one non-root uid to another *keeps* (capabilities(7)) — the deploy would run
  able to become root. From root, the change to the job account clears every capability, so the
  command keeps none. The unit's `CapabilityBoundingSet=` is only `CAP_SETUID CAP_SETGID CAP_KILL
  CAP_DAC_READ_SEARCH` (the last to hash and enter a checkout in a `0750` home).
- **Optional: TPM.** If `$CREDENTIALS_DIRECTORY/kagisecure-host.key` exists it is used instead of
  the file. With `LoadCredentialEncrypted=` and `systemd-creds encrypt --with-key=host+tpm2`,
  the key is sealed by the TPM and systemd decrypts it for the unit (§4.1's mechanism, without
  PCR policy, and with no TPM code in kagisecure). Not required, not checked by `init`.
- **Hardening, honestly limited.** Granted commands run inside the unit, so it cannot be
  sandboxed as §3 wants: `ProtectSystem=full`, `PrivateTmp=yes`, `NoNewPrivileges=yes`,
  `RestrictSUIDSGID=yes`, no core dumps — but no `ProtectHome` and no
  `RestrictAddressFamilies=AF_UNIX` (a deploy needs the network and its home).

### A3. Signed bundles, exported from the Mac, carrying only what that host is granted

- **Owner key.** The signer is the Mac's shared-vault device key, held in the personal vault body
  (`kagisecure host-bundle owner-key` prints it, creating it if the vault has none). The host
  pins it at `init --owner <key>` and accepts bundles from no other device.
- **Export.** `kagisecure host-bundle export --host build-1 --host-key <key> --environment
  app-deploy --grants <file> [--grant NAME]... --out build-1.kgsb` opens the personal vault
  with the master password (recorded as `PRESENCE_CONFIRMED_MASTER_PASSWORD`), reads the named
  **machine-vault** environment, and puts in the bundle **only the variables the chosen grants
  release** — a bundle carrying anything no grant releases does not validate. The export is
  audited in the personal vault, durably, before the file is written.
- **Envelope** (`kagisecure_shared::host_bundle`): magic, signer id, host id, a sequence number
  (milliseconds since the epoch at export), the payload sealed with HPKE Base mode to the host's
  X25519 key under `info = "kagisecure/host-bundle/v1" ‖ signer ‖ host ‖ sequence`, and an Ed25519
  signature in the new domain `kagisecure/shared/sig/host-bundle/v1` over everything after the
  signer id. Verified before it is decrypted: layout, signer is the pinned owner, signature
  (strict), host id, sequence above the last imported, then the payload opens. Tests: every
  single-bit change refused, a stranger's valid signature refused, another host's bundle refused,
  a replay refused, a re-signed header around a lifted payload does not open.
- **Complete, not a delta.** Importing replaces every environment and grant and resets every
  use count and suspension: re-signing is the owner approving again.
- **At rest** the host keeps the bundle exactly as signed and verifies it again on every request;
  there is no host-side machine-vault file and no second copy of a value. Mutable state
  (`state.json`: sequence, uses, suspensions) and the audit log (`audit.log`, JSON lines, synced
  before each release) hold no value.
- **Simplified from §5–§9:** no enrolment ceremony beyond comparing fingerprints, no `narrowing`
  bundles (a new complete bundle narrows), no inbox polling (the operator runs `import`), no
  signed reports or pins from the host, no expiry of the bundle itself beyond its grants'.

### A4. Grants: one exact command, named by the caller, run by the host

A host grant is ADR-0042's command grant with one widening and three narrowings:

- **Argument patterns.** Each argument after the executable is a literal or `{commit}`
  (`ArgPattern::CommitSha`): exactly 40 lower-case hex digits. The argument count is exact.
- **Executable pinned by SHA-256 only** (no code-signing pin on Linux), plus its absolute path;
  the working directory is matched exactly after resolving symbolic links.
- **Named by the caller.** A request names its grant; it is matched against that one grant, never
  searched for. An unknown name is refused (`NO_SUCH_GRANT`) and is not a strike.
- **The host starts the command itself**, as the grant's `run_as` account (looked up in
  `/etc/passwd`; `HOME`, `USER`, `LOGNAME` set to it), in the grant's directory, with the
  unit's fixed `PATH`, a deadline (default 30 minutes, at most 6 hours), and its output masked
  before it is returned to the caller. The caller's environment never reaches the command.
- **Suspension** (ADR-0042 §7): a request whose argv or cwd is not the grant's is a strike and
  suspends that grant (`EXECUTABLE_MISMATCH`, `ARGUMENTS_MISMATCH`, `CWD_MISMATCH`); an executable
  whose hash changed suspends it (`PIN_CHANGED`). A suspended grant answers `SUSPENDED` until a new
  bundle is imported — restoring the file does not lift it. Limits: total uses (default 500) and
  an expiry at most 90 days after creation.
- **Who may ask** is the file system: the socket is `0660` in a `0750` runtime directory, group
  `kagisecure`. A member can do nothing but start, exactly, a command the owner granted.

### A5. Stdin delivery under a host grant: the narrow exception to ADR-0047 §8

ADR-0047 §8 keeps stdin delivery off the unattended socket. A host grant is the one exception, and
only in this form: **delivery is always stdin** (a host grant cannot put values in an
environment), and only for a grant that pins the exact executable by hash, every argument by
literal or `{commit}` pattern, and the working directory. The frame is ADR-0047's
`NAME\0VALUE\0`, written once and closed. Why it is acceptable here: stdin is the form the
deploy script was written to receive (it never writes the key to disk and loads it into a
private `ssh-agent`); an environment would be inherited by everything the deploy starts. ADR-0047
§4's "one approval, one run" does not apply — the grant is the approval (ADR-0042) — and that is
what `kagisecure host-bundle export` prints before it finishes.

### A6. What a deploy looks like

The operator on the host runs the project's deploy script as before. On the host, the script
resolves the commit to 40 hex, then `exec`s `kagisecure-host request deploy-<target> --
<checkout>/infra/deploy/deploy <target> <sha> --key-from-stdin` from the checkout. The host checks
and audits, starts the script as the operator with the key on stdin, and returns the masked output
(when the run ends; it is not streamed) and the exit code. The script holds the key only in memory.
The key file and its public half are then removed.

### A7. Residual risk, stated

- Root on the host holds every bundled value (the key file, or the TPM-unsealed credential
  while the unit runs).
- The grant pins the script, not what it runs: `bash`, `git`, `ssh`, the operator's
  `~/.ssh/config` and `pnpm` are files the operator or root can change. Anything that can change
  what the granted command does can obtain the key — ADR-0042's sentence, unchanged.
- A change to the pinned script (any new commit touching it, pulled on the host) suspends the
  grant until the owner exports a new bundle. That is the intended cost of pinning.
- Masking is best effort (mcp-server.md §2.8); a deploy that prints its key is not prevented
  from doing so, only scrubbed.

### A8. Not in this scope

CI grants (§11), login grants and unattended sign-ins (§15), schedules and jobs started by the
host, signed reports and pins from the host (§8, §14), `narrowing` bundles, enrolment beyond
fingerprints, profiles and their labels on the Mac (§1), Mac build hosts (§17), an FFI hook or a
Mac app screen for exporting (the CLI does it), and `prod` deploys (still from the Mac).

## Context

ADR-0042 designs unattended use on the Mac: a separate **machine vault**, **armed** by a person
with a presence proof for at most 14 days, released only to **jobs** kagisecure starts, under
**standing grants** made on a sheet with a presence proof. A restart disarms it, and the owner
decided that is how the Mac app should behave (ADR-0042, owner's answer 2).

The owner decided the opposite for another class of machine (answer 13), and on 2026-09-27
restated it as binding for this ADR:

- **Build servers, CI runners and Linux hosts** must be able to run kagisecure's unattended jobs —
  ADR-0042's jobs, standing grants and machine vault, and the run browser.
- They are **armed automatically**, with nobody present, from a key held in the host's own key
  store (a TPM, for example), and **stay armed across reboots** — deliberately unlike the Mac app.
- **No network code** ([threat-model.md](../threat-model.md) N-9). Provisioning, revocation and
  collecting the audit log work by files moved by people or by tools they already run — a private
  git repository, for example, as shared vaults are exchanged
  ([ADR-0035](0035-shared-vaults.md) §7).
- ADR-0042's other answers (4–21) apply unless they cannot on a headless host, or the owner decided
  otherwise here; §19 says which and why.

The owner's answers to this ADR's first draft then widened it: hosts without a TPM, containers and
ephemeral CI runners are served in a weaker, labelled mode; jobs a CI service starts may use grants;
a single account may run everything; unattended sign-ins are built from the start; a Mac used as a
build host is in scope; and hosts' machine vaults on the Mac are usable interactively. A second
round let `file` hosts receive everything any host can, and let a CI grant bind to a runner account
alone. Each is a cost, stated where it is decided and collected in "Owner's answers".

ADR-0042 §15 listed what headless hosts break, and its open question 19 lists what a design must
decide as seven points, (a)–(g). This ADR decides each of them (proposed):

| ADR-0042 open question 19 | Decided in |
| --- | --- |
| (a) which process hosts the engine; how a release build still refuses `--auto-approve` | §2, §3 |
| (b) the key store and its sealing policy; hosts with no TPM; macOS headless | §1, §4, §17 |
| (c) provisioning from the Mac by file; enrolment; how late a revoke may arrive | §5–§9 |
| (d) whether answer 4 holds on a CI runner | §10, §11 |
| (e) Linux counterparts of the peer check, the ancestry walk and teardown | §12 |
| (f) audit, its freshness and noticing with no app | §14 |
| (g) unattended sign-ins on a host without a display | §15 |

### What people do on such hosts today

As on the Mac (ADR-0042, "What happens if nothing is built"), the status quo is not free: a token
in a CI service's secret settings, a `.env` in the build account's home, an environment block in a
unit file or a scheduler's configuration — readable by the account, often by every job the host
runs, with no scope, no expiry and no audit. For credentials a CI *platform* can hold, its secret
store or, better, short-lived credentials issued to the job's workload identity remain the better
answer, and the documentation says so first (option (c)). What this ADR adds is for the rest:
scheduled work on a persistent host, and CI jobs whose target service offers nothing better than a
long-lived token.

### Constraints that do not move

- **ADR-0002 is unchanged.** No MCP tool returns a value; the unattended socket carries none (§20).
- **No networking** (N-9), stated again because a server is where it is most tempting: no fetch of
  bundles, of issuer keys or of anything else; no push of logs; no remote alert; no call to a CI
  service; no token minted by kagisecure.
- **The personal vault never leaves the Mac, and no shared vault's replica is ever on a host.** A
  host holds only what was provisioned to it (§5).
- **A person makes every decision that widens access** — on a Mac, with a presence proof. A host
  creates, widens, extends and re-enables nothing on its own authority (§7), the rule ADR-0042 §5
  applies to agents and ADR-0035 §14 to sharing.
- **Audit before release** ([ADR-0040](0040-audit-before-release.md)) holds on hosts, fail-closed.
- **Every weaker profile is labelled** wherever the host appears — on its sheets, in the Mac's view
  of hosts, in bundles, reports and audit entries (§1) — and never presented as the default.

## What automatic, reboot-surviving arming costs, stated before anything is claimed

This section decides what the rest of this ADR may claim, as ADR-0042's "What unattended costs"
does for the Mac. Everything said there — the grant is the last human decision (point 1), the
command is defined by files the account can write (point 4), an unattended fill hands the login to
the job's agent (point 5) — holds on a host unchanged. Points 1–6 below are what the **recommended
profile** (§1: TPM-sealed, separate accounts, persistent) adds; point 7 is what each weaker profile
the owner chose adds on top.

**1. The key is at rest, and the host uses it by itself.** On the Mac the armed key lives only in
the app's memory and a restart ends it. On a host the owner wants the opposite, so the key that
opens the host's machine vault sits on the host's disk, sealed by the TPM, and is unsealed without a
person at every boot. Sealing gives exactly one property: **the sealed file is useless on another
machine.** A copied disk, a backup, a copy in a repository — none of them opens without that TPM.
It gives nothing against what runs on the machine itself. The key is usable by:

- anything that runs as the host service's account (§3), including a compromised host service;
- **root** (N-1), which on a server is a larger set than on a personal Mac: administrators,
  configuration-management and backup agents, and every account that is root-equivalent without
  being root — a member of a container-runtime group, an account with unrestricted `sudo`, anything
  that can start a privileged container (W-34);
- **anything that boots on that board in a way the sealing policy accepts** (§4). With PCR 7, that
  is anything signed under the same Secure Boot certificates — and, if the boot menu lets someone
  edit the kernel command line, a root shell on the host's own kernel, which PCR 7 does not measure.

**2. A stolen host arms itself.** A thief who takes the whole machine, or an attacker who reboots
it, gets a host that unseals its key and starts its jobs on schedule — to wherever its network
reaches — without anyone being asked. Nothing kagisecure does on the host can tell a stolen host
from a rebooted one. What bounds it is time: every grant has a hard expiry (answer 5: 30 days by
default, 90 at most), checked against the host's own clock, which whoever controls the host's
firmware can hold back (§9).

**3. No presence proof is made on the host, ever.** The last human decisions are made on a Mac:
creating a grant, possibly weeks earlier, and exporting the bundle that carries it (§7). The host
verifies a signature, not a finger; that a presence proof preceded the signature is a property of
the honest app that signed it (§2).

**4. Revocation is a file, not an event.** A revoke made on the Mac reaches the host when someone,
or something they run, copies a file there. Until then the host keeps releasing under the revoked
grant, and only its expiry acts on its own (W-31).

**5. The host's log is on the host.** It lives on a machine nobody watches, and the accounts that
can rewrite it are the accounts that can use the key. The owner learns what happened when a report
reaches a Mac (§14) — and learns nothing from a host that stops sending reports, except that it
stopped.

**6. On a virtual machine, the TPM is the hypervisor's.** A virtual TPM is software run by whoever
operates the virtualization platform. Sealing to it binds the key to that platform's honesty, not
to a chip (T-20).

**7. What the weaker profiles add** (§1, owner's answers 2, 3, 4 and 6):

- **A `file` key** (no TPM, Secure Boot off, a container, a Mac host until §17's blockers clear) is
  a key **anyone with the disk, a backup or the image can use**, on any machine, forever — not only
  the service account and root. It is what the status quo already is, plus scope, pins, limits and
  audit — and, since nothing is withheld from a `file` host (owner's answer 10), what it may hold
  includes other members' shared-vault values and a login's one-time-code seed beside its password
  (W-37).
- **A `shared` account** — the jobs run as the account that holds the key — means **every job, and
  whatever steers its agent, can read the key and rewrite the vault and its log.** Grants then bound
  what an honest job does, not what a steered one can take: one injected job is every credential on
  the host (W-38).
- **An `ephemeral` host** — a runner or container recreated for each job — is started by the very
  pipeline it serves. **On such a host kagisecure is a policy layer, not a boundary**: the job holds
  the key, forgets every suspension when it ends, may be handed any unexpired bundle, and decides
  whether its report is ever carried out (W-39).
- **A CI grant** (§11) is a grant to **whoever can make the CI platform issue a matching workload
  token** — anyone who can push to the pinned branch or change the pinned workflow — and to the
  platform itself, which can issue any token it likes (T-22, W-40).
- **A runner-bound CI grant** (§11, owner's answer 12) is a grant to **every job the runner runs** —
  anyone who can make the CI service schedule a pipeline on it — with nothing about the job's origin
  verified (W-43).

The true sentences for this feature, which the documentation and the host sheets carry verbatim —
the first on every host, the others on hosts whose profile has that weakness:

> On a host, kagisecure keeps machine credentials under a key the host unseals by itself at every
> boot. Anyone who can run code there as kagisecure's service account or as root — or who takes the
> machine and boots it — can use every credential provisioned to that host until its grants expire
> or you rotate the credentials at the services.

> This host's key is a file. Anyone with its disk, a backup or its image can use every credential
> provisioned to it, on any machine.

> This host's jobs run as the account that holds its key. A job that is steered can take every
> credential provisioned to this host.

> This host is rebuilt for every job, by the pipeline it serves. kagisecure limits what an honest
> job does there; it does not protect the credentials from that job.

> A CI grant trusts the CI platform and everyone who can push to the branch and workflow it names.

> A runner-bound CI grant can be used by every job this runner runs, whoever started it.

## Recommendation

**Offer one recommended profile and label every other one. The recommended profile is a persistent
Linux host with systemd, cgroup v2, a TPM 2.0 and Secure Boot, where a new service binary,
`kagisecure-host`, runs as a dedicated account, holds one machine vault per host whose key systemd
unseals from the TPM at every boot (PCR 7), and starts runs as systemd units under a separate job
account that can neither read the key nor touch the vault. Everything any host may release — items,
jobs, grants — arrives in a bundle made on a Mac with a presence proof, sealed to that host's key,
signed by the Mac's provisioning key, and replaced wholesale by the next one; reports go back by
file and let the Mac anchor the host's log. At the owner's direction, weaker profiles exist — a key
in a file, one shared account, ephemeral hosts, Macs used as build hosts — each labelled everywhere
the host appears; and jobs a CI service starts may use CI grants, bound to a workload token the
platform signed and kagisecure verifies offline against a key pinned in the bundle — or, labelled,
to the runner account alone. For CI
pipelines, option (c) — the platform's secret store, or better, federated short-lived credentials —
stays the first recommendation wherever the target service supports it.**

### The options, against the threat model

**(h1) The recommended profile.** A per-host machine vault; its key sealed by the TPM through
systemd, PCR 7; a dedicated service account and a separate job account; runs recognized by cgroup;
grants only from signed bundles; reports anchored on the Mac.

**(c) The platform's secret store, or workload identity** (ADR-0042 options (c) and (d1)). The CI
service or the cloud platform holds the credential or, better, the target service issues a
short-lived one to the job through federation. kagisecure holds nothing. It remains the best answer
wherever it applies and is recommended **alongside** everything here: a CI grant (§11) is for a
target that offers nothing better than a long-lived token.

**(h2) A Mac as the only armed machine, called by the hosts.** Rejected: kagisecure would need a
listener other machines can reach (N-9). Forwarding the unattended socket through the owner's own
tunnel keeps network code out of kagisecure but erases every identity the design stands on — the
peer is the tunnel, not a run — and it does not even work, because `run_with_env` runs the command
on the machine that holds the value, which is the Mac, not the host. It also fails the reboot
requirement: the Mac app disarms on restart (answer 2).

**(h3) One machine vault shared by every host.** Rejected (§5): every host would hold every host's
credentials, one stolen host would expose all of them, and pins, grants and revocation are per host
anyway.

**(h4) `kagisecure daemon` with an unattended mode and a key file.** Rejected as a *daemon mode*
(§2): it reverses ADR-0007 §2 inside a binary that also unlocks personal vaults with a terminal `y`.
The key file itself is adopted, at the owner's direction, as `kagisecure-host`'s labelled `file`
profile (§4.2).

| | (h1) recommended | (c) platform / federation | (h2) Mac called by hosts | (h3) one vault for all hosts | `file` · `shared` · `ephemeral` (answers 2, 4) |
| --- | --- | --- | --- | --- | --- |
| Key usable without a person | the host's own machine-vault key, sealed to its TPM | none held | the Mac's, in memory | one key that opens every host's credentials | a file |
| Who can cause a release | a process in a run kagisecure started, within a pinned grant | the platform's workload | anything that reaches the forwarded socket | as (h1), on any host | any process of the account that runs the jobs, directly from the key |
| A copy of the disk or image, elsewhere | useless (sealed) | nothing to copy | n/a | useless (sealed) | holds the key |
| A stolen host | arms itself until its grants expire | nothing on the host | n/a | exposes every host's credentials | holds the key |
| Revocation | a file; expiry acts alone | at the platform, at once | on the Mac | a file per host | a file; on an ephemeral host, expiry only |
| Survives a reboot | yes | yes | no (answer 2) | yes | yes; an ephemeral host has nothing to survive |
| Fits N-9 | yes | yes; the job does the network | only through the owner's tunnel, and then it does not work | yes | yes |

## Decision (proposed)

### 1. Hosts and their profiles

A **host** is a machine where no person and no kagisecure app is present, running
`kagisecure-host`, with a machine vault provisioned from a Mac. Every host has a **profile** of
three parts, declared at enrolment, fixed for the host's life (a different profile is a new host,
enrolled again) and shown wherever the host appears:

| Part | Recommended | Weaker, labelled (owner's answers 2, 4, 6) |
| --- | --- | --- |
| **Sealing** — where the key rests (§4) | `tpm`: sealed by the TPM through systemd, PCR 7, Secure Boot on | `file`: a key file (§4.2). `enclave`, for Macs, is designed and blocked (§17) |
| **Accounts** — who runs the jobs (§3) | `separate`: a service account holds the key; runs execute as a job account | `shared`: one account holds the key and runs the jobs |
| **Lifetime** — whether state persists (§4.3) | `persistent` | `ephemeral`: a runner or container rebuilt for each job; always `file` and `shared` |

- **Supported platforms.** Linux with systemd and cgroup v2, in any profile; Linux containers and
  ephemeral runners without systemd, in `file · shared · ephemeral` only; macOS, as a Mac used as a
  build host (§17), in `file · separate` or `file · shared` until its `enclave` sealing is measured.
  Windows hosts are not in this ADR (§18).
- **`kagisecure-host init`** checks what it can: a TPM 2.0, Secure Boot enabled, systemd and cgroup
  v2 for `tpm`; it refuses `tpm` when any is missing, naming it, and accepts `file` only when asked
  for by name (`--sealing file`), after printing the true sentence for it and requiring it to be
  typed back. There is no silent fallback from `tpm` to `file`.
- **Labels.** The Mac's list of hosts shows each host's profile, with a badge for every weaker part
  and its true sentence under the host's name; every grant sheet and every export sheet for that
  host repeats them; bundles and reports carry the profile in their signed headers, and a host
  refuses a bundle whose profile is not its own; every personal-log entry about a host, and every
  entry in the host's own log, carries the profile — `profile tpm/separate/persistent`, or for
  example `profile file/shared/ephemeral`. The documentation lists profiles in order of strength and
  names only the first as recommended.
- **Nothing is withheld from a `file` host** (owner's answer 10). It may receive copies of
  shared-vault values and login grants with the one-time-code switch on (ADR-0042 §12.5), as any
  host may. The labels go further for both: the copy record ADR-0042 §13 publishes to the shared
  vault names the holding host's profile ("held unattended on host 'build-01' — key in a file"), so
  the other members see where their value went; and the one-time-code switch's sheet adds, for a
  `file` host, that the password and the seed its codes come from would then both sit on a disk
  anyone can copy — two factors in one file (W-37).

### 2. The host process: a new binary, and the daemon unchanged — (a)

**A new binary, not a mode of `kagisecure daemon`.** `kagisecure-host` is a separate executable from
a separate crate, `crates/kagisecure-host`, built for Linux and macOS and distributed separately
from the macOS app, never inside its bundle
([ADR-0026](0026-helper-binaries-inside-the-app-bundle.md)). It hosts **the same unattended engine**
ADR-0042 puts in `kagisecure-agent` — its release path (ADR-0042 §6), suspension (§7), audit
vocabulary (§8) and login-grant checks (§12.6) — so the Mac app and the hosts cannot disagree about
what a grant allows: [ADR-0013](0013-agent-library-split.md)'s rule, applied again. What differs is
a narrow set of host traits, one implementation per platform: where the key comes from (§4), where
grants come from (§7), how a run or a CI session is started, recognized and ended (§10–§12), and
where noticing goes (§14).

**What it does not contain.** It serves no ordinary socket, opens no personal vault, reads no shared
vault, and has **no approval path at all**: no `ApprovalQueue` resolver, no terminal prompt, no
`--auto-approve`, no `--non-interactive`. Every request is covered by a grant from a verified bundle
or refused. No flag, environment variable or configuration file changes that, because there is no
code for it to change. A test enumerates the IPC messages the host's sockets accept and asserts that
none is an interactive approval, as ADR-0042 asserts that none creates a grant.

**`kagisecure daemon` is unchanged.** ADR-0007 §2 stays exactly as it is: `--auto-approve` exists
for tests and is refused at startup in a release build. The daemon gains no engine, no machine vault
and no key store.

**Why not the daemon.** It unlocks a *personal* vault with a master password, answers approvals from
a terminal (ADR-0007 §1) and serves the ordinary socket. Adding a self-arming engine to it would put
a personal vault key and a self-arming key in one process and make "which of the two is this" a
flag — the kind of switch ADR-0007 §2 refused to trust. Two binaries make it structural: the program
that arms itself cannot ask anyone anything, and the program that asks cannot arm itself.

**Why ADR-0013's and ADR-0042's objection to a second key-holding process does not apply.** Both
rejected a process holding key material *beside the app*. A host has no app: `kagisecure-host` is
the only process that holds the key, as the app is on the Mac. A Mac used as a build host runs
`kagisecure-host` and not the app's engine (§17).

**Why a grant made on a Mac is still an approval made with a presence proof.** A grant is created on
the Mac, on ADR-0042's sheet, after the `PresenceGate` of ADR-0038, and reaches the host only inside
a bundle the Mac signs with a key that lives in the personal vault body and is used only in the
app's memory (§6). The bundle records the presence path that authorized each grant
(`PRESENCE_CONFIRMED` or `PRESENCE_CONFIRMED_MASTER_PASSWORD`), and the host logs it. What the host
can verify is the signature; that a presence proof preceded it is a property of the honest app, in
the sense in which ADR-0042 §13's copy policy is "enforced only by honest builds". An attacker who
can make the app sign without a presence proof controls the unlocked app's memory, which on macOS is
root (N-1).

**[architecture.md](../architecture.md) §2.6's sentence** — "a shipped binary has no code path to an
unattended approval" — stays true of *approvals*. On acceptance it is reworded once, for ADR-0042
and this ADR together: *no shipped binary approves a request without a person; releases under a
standing grant exist in the macOS app (ADR-0042) and in `kagisecure-host` (ADR-0043), and every
grant either honours was made by a person with a presence proof on a Mac.*

### 3. Accounts: `separate` recommended, `shared` allowed

**The `separate` profile** (recommended, the default of `init`):

| | Service account | Job account |
| --- | --- | --- |
| Runs | `kagisecure-host` (the engine), in one systemd unit | every run: the launcher, the job's root, its agent, the sidecar, granted commands, a run browser |
| Owns | the state directory (`0700`): the key (sealed or not), the host's machine vault and its lock file; beside it, the inbox and outbox, shared with an administrative group (§7, §14) | nothing of kagisecure's |
| Can use the key | yes, while its unit runs (§4) | no |
| Can write the vault or its log | yes | no |
| Created by | `kagisecure-host init`: a system account, no login shell, no home | `init`, or an existing account the administrator names |

- The job account **must not be root-equivalent** (W-34): `init` refuses a job account that is
  uid 0 or in a group it recognizes as root-equivalent (the administrative and container-runtime
  groups distributions ship), and says plainly that it cannot recognize every way to become root.
  It **should not be a CI runner's account**: whatever a CI service starts runs as that account and
  could write a job's inputs (ADR-0042 W-23). CI sessions (§11) run as the runner's account, which
  is a third account the uid gate admits only for CI grants.
- **The engine's unit is hardened by systemd**, not by promises: no new privileges; a read-only view
  of the system except its state directory; a private `/tmp`; no core dumps; and
  **`RestrictAddressFamilies=AF_UNIX`**, so the kernel refuses the engine any network socket — N-9
  enforced below the code, not only by the crate ban list. The exact directives are Phase 0 work.
- **It is a system unit**, which reverses M-15 ("no system-wide daemon") on hosts, and only there.

**The `shared` profile** (owner's answer 4): one account runs the engine and the jobs. The template
unit of §10 names that account; everything else is as above. **What it loses, stated plainly:**

- **The key.** A process of that account can read what the engine can: the decrypted credential
  systemd exposes to the unit (with `tpm`), or the key file itself (with `file`). With the key and
  the vault file, it can decrypt every credential provisioned to the host, with no grant, no pin and
  no audit entry. So in this profile an injected job agent, or anything else running as that
  account, is one step from every value on the host — ADR-0042's point 1 with the grant removed.
- **The engine's memory.** The engine makes itself non-dumpable, which keeps other processes of the
  account from tracing it or reading its memory — but it no longer needs to, since the key is
  readable.
- **The log.** A job can roll the vault file back, or with the key truncate its log (W-11, now for
  every job).
- **The engine itself.** A job can signal or kill it: a denial of service, as in ADR-0042 §3.
- **What still holds:** grants still bind what an honest job does and what a steered job can
  obtain *through kagisecure* — pins, limits, one strike, audit before release — and the cgroup and
  uid checks still keep other accounts out. What is gone is any protection of the credentials from
  the jobs themselves (W-38).

`init --accounts shared` prints that loss and requires it to be typed back, as `--sealing file`
does.

### 4. The key store — (b)

#### 4.1 `tpm`: sealed by the TPM through systemd, PCR 7 (owner's answer 1)

**The key store is systemd's encrypted credentials, sealed with the TPM and the host's credential
secret.** At `init` the host generates its secrets — its key pair (§6) and its machine vault's key
(§5) — and seals them as one credential with `systemd-creds encrypt --with-key=host+tpm2` under a
PCR 7 policy. The engine's unit loads it with `LoadCredentialEncrypted=`: systemd decrypts it when
the unit starts and exposes the plaintext to that unit for as long as it runs. kagisecure writes
**no TPM code of its own**: sealing, policy evaluation and unsealing are systemd's — widely
deployed, reviewed for exactly this, and opening no network connection.

- **`tpm2`**: the credential decrypts only on this TPM. A copied disk, a backup or a copy of the
  state directory in a repository is useless elsewhere.
- **`host`**: decrypting also needs systemd's host secret, a root-only file. The service account
  cannot decrypt the sealed file itself; it is handed the plaintext at unit start.
- **No authorization value (PIN).** A value someone types at every boot is not automatic; one kept
  beside the sealed file protects nothing.

| Bound to | Kernel or boot-loader update | Firmware update | Secure Boot database update | What it refuses |
| --- | --- | --- | --- | --- |
| Nothing (TPM only) | keeps working | keeps working | keeps working | nothing: any OS booted on the board, a live USB included, unseals with root and the host secret |
| **PCR 7** (Secure Boot state and the certificates that verified the boot) | keeps working | usually keeps working | **disarms** | Secure Boot off; anything not signed under the enrolled certificates |
| PCR 7 + a signed PCR 11 policy (a unified kernel image whose measurements the owner signs) | keeps working, if the new image's policy is signed | usually keeps working | disarms | also any kernel, initrd or command line the host's policy key did not sign |
| PCRs 0, 2, 4 and 7 (firmware, option ROMs, boot loader) | **disarms** | **disarms** | disarms | almost everything, routine updates included |

PCR 7 is the binding (owner's answer 1): it survives the updates a server takes every week and
refuses a boot with Secure Boot off, the cheapest way to boot something else. **It does not refuse
a different operating system signed under the same certificates, nor a changed kernel command
line** — a boot menu that lets someone type `init=/bin/sh` yields root on the host's own kernel,
with PCR 7 unchanged. So the documentation states that the boot menu must be locked, and kagisecure
cannot check it. On hosts that boot a unified kernel image, a signed PCR 11 policy is recommended,
not required; kagisecure passes the options through to systemd and does not manage its signing
key. Binding to firmware and boot-loader PCRs is not offered: it would turn every update into
answer 2's "a restart disarms" by another route.

**When the policy stops matching** — Secure Boot turned off, a certificate database changed — the
credential does not decrypt, the engine does not arm, and the journal says why (§14). Recovery is
re-enrolment (§6): the host's old secrets are gone, the Mac re-provisions from its own copy (§5),
and only host-local state not yet reported is lost (§14).

#### 4.2 `file`: a key file, labelled weaker (owner's answer 2)

For hosts with no TPM or with Secure Boot off, containers, ephemeral runners, and Macs until §17's
sealing exists:

- **What it is.** The host's secrets — the same key pair and machine-vault key — in one file, mode
  `0600`, owned by the service account (the shared account, under `shared`), in the `0700` state
  directory. No wrapping: a wrapping key would sit beside it.
- **Who can use it**: the service account, root, and **anyone who has the disk, a backup, a snapshot
  or the image** — on any machine, with no time limit. Disk encryption helps only while the machine
  is off and only if unlocking it needs a person, which a host that reboots by itself does not have.
- **Provisioning.** `init --sealing file` generates the secrets into the file and writes an
  enrolment request declaring `sealing: file`; enrolment is otherwise §6's. On an ephemeral host the
  file is made once, on a machine the administrator trusts, and then delivered to every instance by
  the platform's own mechanism for secrets (§4.3).
- **Rotation.** The file is a credential and is rotated like one: `kagisecure-host init` again (new
  secrets, a new host), re-enrol, re-provision, retire the old host (§9) — and rotate at the
  services every value the old host held, from its rotation list, whenever the file, a backup or an
  image holding it may have been read. The Mac shows the age of every `file` host's key and flags
  one older than 90 days (a setting) with "rotate this host's key".
- **Nothing is withheld** (§1, owner's answer 10): a `file` host holds whatever its bundles carry,
  shared-vault copies and one-time-code seeds included, each labelled as §1 says.

#### 4.3 `ephemeral`: a host rebuilt for every job (owner's answer 2)

A runner or container recreated for each job keeps nothing between jobs, so:

- **It is always `file · shared`.** The engine is started by the pipeline itself, at the start of
  the job — `kagisecure-host serve --ephemeral` — inside the same runner, as the same account, with
  the secrets file the platform delivered. Nothing on such a host is out of the job's reach;
  kagisecure there is a **policy layer, not a boundary** (point 7, W-39).
- **Its secrets live in the CI platform's secret store**, delivered as a file at job start. Whoever
  can read that platform secret — the platform, its administrators, any pipeline with access to it —
  can use every credential provisioned to the host. That, not kagisecure, is the real boundary here.
- **Its bundle** is delivered the same way, or committed beside the pipeline. With no state kept, a
  host cannot know which generation it saw last, so **any unexpired bundle for it is accepted**,
  including one a revocation superseded. Revocation acts only through expiry, so a bundle for an
  ephemeral host may be valid for at most **7 days** (owner's answer 11) — which means a new bundle,
  with a presence proof on the Mac, at least weekly.
- **Suspension lasts only for the job.** A strike ends the job's session and suspends its grants for
  the rest of that job; the next job starts clean. The report carries the strike to the Mac, which
  records the suspension and prepares a `narrowing` bundle, still to be delivered (§9).
- **Its report is written at the end of the job** to a path the pipeline carries out as an artifact
  — or does not: the job decides whether the Mac ever sees it, so the report is the job's own
  testimony (W-39). The Mac flags an ephemeral host whose bundle is in use but that sent no report
  for seven days.

### 5. The host's machine vault: one per host, kept on the Mac, provisioned to the host

- **One machine vault per host**, never shared between hosts (alternative (h3)). A host holds only
  what its own jobs use; a stolen host exposes its own list, which the Mac can show (§9). A value
  two hosts need is two copies, and the guidance is ADR-0042's (d1): prefer a separate, scoped token
  per host.
- **The Mac keeps the source copy.** For every enrolled host the Mac holds a machine vault in
  ADR-0042's format — its own file, its key in the personal vault body as ADR-0042 §2 keeps the
  Mac's machine vault key — with that host's items, jobs and grants, made and changed only by a
  person in the app on ADR-0042's sheets, with their presence proofs, and every sheet naming the
  host and its profile.
- **Interactive use on the Mac** (owner's answer 7, aligned with ADR-0042 answers 12 and 20). The
  Mac's ordinary socket and ordinary extension listener serve a host's machine vault the way
  ADR-0042 §2 serves the Mac's own: an agent on this Mac may use a host's environment through the
  ordinary tools, and a host's login may be filled into the user's own browser, each with the
  ordinary sheet and a fresh presence proof (or a lease one minted), only while the personal vault
  is unlocked. The sheet names the host ("machine vault of host 'build-01'"). Such a use is not a
  run: it uses no standing grant, counts against none, strikes nothing, and is recorded in the
  Mac-side log of that host's machine vault under the ordinary `mcp` actor. Metadata tools on the
  Mac list hosts' environments and variable names only where the owner made them agent-visible
  (M-9's default, hidden).
- **The host keeps its own file**, written only by the engine, in the vault file layout of
  [vault-format.md](../vault-format.md) §2 under a key the host generated and never exports. Its
  header has one wrapped-key slot of a new kind, `host`, wrapping that key under the host's secrets,
  and **no password or recovery slot**: a host's machine vault is recovered by re-provisioning from
  the Mac, not by a password nobody on the host would type. Its body holds what the last applied
  bundle carried, the engine's own state (per-grant counters, suspensions, the applied generation,
  used workload-token ids, the last run times) and the audit log
  ([vault-format.md](../vault-format.md) §8), written through ADR-0039's lock and transactions.
- **What may be put in it** is ADR-0042 §2's list, under its structural rules, unchanged. Values
  enter the Mac's copy by creation or by copy — from the personal vault, the Mac's own machine
  vault, or a shared vault under ADR-0042 §13's policy (with the label §1 adds for `file` hosts) —
  and each copy records its source, so rotation can find every host that holds a value.

### 6. Enrolment: two keys, compared in full, in both directions — (c)

Two keys are introduced, both in the suite ADR-0035 already adopts (`x25519-ed25519-v1`: X25519 for
HPKE, Ed25519 for signatures; [ADR-0035](0035-shared-vaults.md) §4 and its addendum's encoding
contract):

- **The Mac's provisioning key**, one per Mac, stored in the personal vault body as a `Secret`, the
  way ADR-0035 §5 stores device keys: usable only while the personal vault is unlocked, only in the
  app's memory, never an item, never shown. It is not a shared-vault device key: a signature a host
  accepts must not be producible by the key that signs shared-vault records.
- **The host's key pair**, generated by `kagisecure-host init` and kept with the host's other
  secrets (§4). It opens bundles and signs reports and inventories.

The steps:

1. **On the host**, an administrator runs `kagisecure-host init --issuer <fingerprint>` with the
   **full** fingerprint of the Mac's provisioning key, as the Mac's "Add a host" screen shows it
   (ADR-0035's encoding: ten groups of five digits), and the profile's options. `init` creates the
   accounts and units (§3), generates and stores the host's secrets (§4), pins the issuer, and
   writes an **enrolment request**: the host's label, its profile, the suite, its public keys, its
   sealing policy (which PCRs, or `file`), a self-signature, and nothing secret. It prints the
   host's full fingerprint.
2. **The request travels by any channel.** It is public.
3. **On the Mac**, the owner imports it and compares the host's full fingerprint with the one the
   host printed, read over a different channel from the one that carried the request. **The
   comparison is mandatory: there is no trust on first use for hosts.** A substituted key receives
   every credential provisioned to that host at the next export, with no other member to notice.
   Short confirmation codes are refused, for ADR-0035 §10's reason. Enrolling needs a presence
   proof; the sheet shows the profile and the true sentence of every weaker part; the personal
   vault's log records how the fingerprint was verified.
4. **The Mac pins the host's public keys**, and the host has pinned the Mac's. Neither key changes
   in place: a re-initialized host is a new host, enrolled again, and the old one is retired (§9).

An ephemeral host is enrolled once, from the machine where its secrets file was made.

### 7. Provisioning bundles: complete, signed, sealed and numbered — (c)

A **provisioning bundle** is the only way anything reaches a host:

```text
bundle := {
  magic, format_ver,
  host_id,                     # the pinned host key's id
  profile,                     # must equal the host's own
  issuer,                      # the Mac's provisioning key id
  generation,                  # u64, strictly increasing per host
  kind,                        # "state" | "narrowing"
  issued_at, not_after,        # not_after <= the latest grant expiry; <= 7 days if ephemeral
  payload,                     # HPKE-sealed to the host's X25519 key
  sig                          # Ed25519, by the issuer, over everything above
}
payload of "state"     := the host's machine vault content — items, jobs, grants of every kind
                          with each grant's presence path, the pinned workload-token issuers of
                          its CI grants (§11) — and the Mac's latest accepted report head
payload of "narrowing" := grant ids to revoke, job ids to remove, and whether to pause
```

- **Verified before it is decrypted**, as ADR-0035 §6 does for records: bounded parsing; the
  signature against the pinned issuer; `host_id` and `profile` equal to this host's; `generation`
  greater than the applied one (not checkable on an ephemeral host, §4.3) — then decryption, then
  parsing of the payload, under the limits discipline of M-21 and M-28, with fuzz targets for both
  layers.
- **A `state` bundle is the complete desired state**, not a delta. Applying it replaces the items,
  jobs and grants in one ADR-0039 transaction and keeps the engine's state by grant id: a grant
  carried over keeps its counters and its suspension; a grant the bundle omits is gone; a re-created
  grant has a new id and starts clean (re-enabling is creating again, ADR-0042 §7). An older bundle
  is refused by its generation, order does not matter, and a carrier can only withhold (T-21, W-31).
- **Exporting a `state` bundle needs a presence proof on the Mac** (owner's answer 8), on a sheet
  that names the host and its profile and lists what changed since the last generation, because it
  discloses values to the host's key. The personal vault's log records the generation and the
  bundle's hash.
- **A `narrowing` bundle can only take away** (owner's answer 8). The Mac signs it while the
  personal vault is unlocked, with no presence proof — revoking needs none, as in ADR-0042 §3 — and
  the host enforces the kind: a `narrowing` payload that names anything the host does not hold, or
  carries any item or grant, is refused whole.
- **Moving it is someone else's job.** kagisecure writes the bundle to a file. The owner, or a tool
  the owner already runs — a private git repository the host's administrator pulls on a schedule of
  their own, a copy over a channel they already use, a CI platform's secret or artifact mechanism
  for an ephemeral host — places it in the host's **inbox**, a directory beside the state directory,
  writable by an administrative group and readable by the service account. The engine reads the
  inbox at start and at a fixed interval, as a local path; it watches nothing remote and runs no
  tool. A repository that carries bundles sees ciphertext and what the header shows — host ids,
  profiles, generations, sizes, cadence (W-15's metadata, per host).

### 8. Pins come from the host, signed

A command grant pins executables and inputs (ADR-0042 §5, answer 7): by code-signing identity where
there is one — on a Mac host (§17) — and **by hash** otherwise, which on Linux is always, since a
running Linux binary carries no general code-signing identity. But the grant is made on the Mac,
which has never seen the host's files. So:

- `kagisecure-host inventory <paths…>`, run by an administrator, writes an **inventory**: the
  canonical path and SHA-256 of each named file — and, on a Mac host, its signing identity — as the
  host computed them, signed by the host's key.
- The Mac imports it, verifies it against the pinned host key, and the grant sheet offers its
  entries as pins and says where they came from: *"Pinned to the bytes host 'build-01' reported on
  <date>. This Mac has not seen this file."*
- A distribution update of a hash-pinned tool suspends every grant that pins it until a new
  inventory and a new bundle arrive (W-32).

### 9. Revocation, expiry and retirement — (c)

- **Revoke** on the Mac, then deliver a `narrowing` bundle (§7). The Mac shows, per host, the
  generation it last issued and the one the host last reported applying (§14): a revocation not yet
  applied is visible, not assumed. On an ephemeral host a revocation acts only through expiry
  (§4.3).
- **Pause** on the host: `kagisecure-host pause` by an administrator, or a `lock` request on the
  unattended socket from any process that can reach it — a denial of service, not a disclosure, as
  in ADR-0042 §3. `kagisecure-host resume`, by an administrator, is recorded and reported.
- **Expiry acts alone.** Every grant's hard expiry (answer 5) is checked against the host's clock at
  every release, and a bundle's `not_after` bounds the whole bundle. **The clock is the host's, and
  whoever controls its firmware can hold it back.** The engine refuses to release, and disarms, if
  the clock reads earlier than the newest entry in its own log; a thief who sets it to just after
  the theft at every boot is not caught (W-31). Expiry bounds a revocation never delivered to an
  honest host; it does not bound a stolen one.
- **Every host needs a new bundle at least every 90 days** — every 7 for an ephemeral host — because
  no grant outlives answer 5's maximum. It is the only periodic human act a host needs.
- **Retirement.** The Mac marks a host retired, issues a final `narrowing` bundle that revokes
  everything and pauses, and shows the host's **rotation list** — every value any bundle to it
  carried, with its source — because a host that cannot be reached cannot be wiped, and what it held
  must be treated as held (M-25's reasoning). For a `file` host, the list says so first.
  `kagisecure-host destroy`, run by an administrator, removes the key and the state directory;
  kagisecure cannot confirm it was run.

### 10. Runs: jobs kagisecure starts — (d)

Scheduled jobs defined in the bundle run as on the Mac, with kagisecure as the scheduler (ADR-0042
§4); what CI services start is §11.

- **The engine is the scheduler**: jobs, their calendar schedules, run deadlines and catch-up
  windows come from the bundle, and the engine starts each run on time by the host clock.
- **A run is a systemd unit** (on Linux). `init` installs one template unit,
  `kagisecure-run@.service`, whose user is the job account (the shared account, under `shared`),
  whose main process is kagisecure's own launcher, `kagisecure-run` (root-owned, in the system's
  executable directories), whose kill mode covers the whole cgroup, and whose maximum runtime is
  ADR-0042's ceiling of 6 hours. For each run the engine starts a fresh instance,
  `kagisecure-run@<job>-<run id>.service`, so no two runs share a cgroup. `init` also installs a
  **polkit rule** letting the service account start and stop instances of that template and nothing
  else; the account cannot choose the user a run executes as (the template fixes it) and cannot
  manage any other unit. On an ephemeral host with no systemd, runs are started by the engine
  directly, as its children, in a cgroup of their own where the container allows one and in a
  process group otherwise (§12). On a Mac host, §17.
- **The launcher** connects to the engine's run-control socket, is recognized (§12), receives the
  job's root executable, arguments and directory, **checks the root's pin on the file descriptor it
  opened and executes that same descriptor** — so the bytes that run are the bytes pinned, with no
  gap between checking and running — and stays the root's parent for the run. It holds no value
  until a release (§12).
- **The run's environment** is the template's fixed environment plus `KAGISECURE_SOCKET`, naming the
  host's unattended socket. As on the Mac, nothing a caller supplies reaches a granted command's
  environment.

### 11. CI grants: jobs a CI service starts (owner's answers 3 and 12)

**This changes ADR-0042's answer 4 for headless hosts only.** On the Mac, callers kagisecure did not
start still get nothing. On a host, a job a CI service started may use a **CI grant** — a third kind
of standing grant, beside command grants and login grants — when the grant's binding admits it. A
CI grant has one of two bindings:

- **`token`** (recommended): the grant names an issuer and the claims of one pipeline, and only a
  session that presented a matching, verified workload token can use it;
- **`runner`** (owner's answer 12, labelled weaker): the grant names only runner accounts, and
  **every job the CI service runs as one of them** can use it — whoever pushed it. It is for
  platforms that issue no workload token; its sheet, the Mac's view of the host, and every audit
  entry for it say so, with the true sentence for it.

**What a CI grant holds**, created on the Mac on its own sheet with a presence proof:

| Field | Rule |
| --- | --- |
| Binding | `token` or `runner`. The rows Issuer, Audience and Required claims apply to `token` only |
| Issuer | The platform's issuer identifier, and **its token-signing public keys, pinned** — imported by the owner on the Mac from wherever the owner obtains them; kagisecure fetches nothing. The sheet shows each key's fingerprint and where the owner said it came from |
| Audience | Exactly `kagisecure:<host fingerprint>`; the pipeline asks its platform for a token with this audience, so a token minted for anything else — another host, another service — does not match |
| Required claims | Exact values for the claims that name the pipeline — subject, repository, branch or tag, workflow file, deployment environment, as the platform's token carries them. Every listed claim must match byte for byte; no patterns. The sheet warns if no branch or environment is pinned |
| Runner accounts | The local accounts the CI service's jobs run as on this host; the uid gate (§12) admits them only for CI sessions. For a `runner` grant, the whole binding |
| Command | Executable, arguments, working directory, pinned inputs, output `none` — ADR-0042 §5's command-grant fields, unchanged. The sheet says that files the pipeline checks out change with every push, so pinning them suspends the grant at the next commit, and not pinning them grants whatever was pushed |
| Limits | Releases per session (default 1), total uses, hard expiry (answer 5's defaults) |

Login grants may also name a CI identity instead of a job, under the same rules; their run browser
is started by the session (§15).

**What a job must present.** The pipeline runs the commands that need a release under kagisecure's
launcher: `kagisecure-run ci --token-file <path> -- <command…>`, or, where only `runner` grants
apply, `kagisecure-run ci -- <command…>` with no token. The launcher sends the token, if any, on the
run-control socket and asks to open a **CI session**. The engine:

1. checks the peer: a runner account named by some CI grant, by `SO_PEERCRED` (`LOCAL_PEERCRED` on a
   Mac host); the launcher's executable is kagisecure's own;
2. if a token was presented, verifies it **offline**: its signature against a pinned key of the
   issuer it names, with RSA with SHA-256 (PKCS #1 v1.5) or ECDSA P-256 with SHA-256 only — any
   other algorithm, and an unsigned token, refused (owner's answer 13); `iss` equal to that issuer;
   `aud` equal to this host's audience; `nbf`, `iat` and `exp` against the host clock, with a
   lifetime of at most one hour and an `iat` no older than ten minutes; its token id not seen before
   on this host (on an ephemeral host, which remembers nothing, within this job only);
3. matches: `token` grants whose issuer and required claims the verified token satisfies, and
   `runner` grants that name the peer's account; it opens a session holding the grants that match —
   none is an ordinary refusal, `NOT_GRANTED`, and not a strike. **A presented token that fails
   verification refuses the session outright**; it is never downgraded to a `runner` session;
4. records the session: the launcher's pid and start time, the runner account, the matched grants
   and their binding, and for a token its id, subject and matched claims — **never the token
   itself**, which is a bearer credential of the platform's and appears in no log, report or journal
   line. What a job without a token says about itself — the repository or pipeline names a CI
   service puts in its environment — is recorded for display, marked self-reported, and decides
   nothing.

**The session.** The launcher marks itself a **child subreaper**, so every descendant whose
parent exits is re-parented to the launcher rather than to init, and runs the command as its
child. Requests on the unattended socket from the session are bound by the ancestry walk of ADR-0042
§4 — pid and start time at every hop — to the live launcher; on Linux the subreaper means a double
fork cannot break the chain. The session ends when the launcher exits, when the token expires, or at
the grant's run deadline; the launcher then ends every descendant it has. Releases follow ADR-0042
§6 with "in a run" read as "in a session", and granted commands are spawned by the launcher as in
§12.

**One strike, on a CI grant.** Anything in a session that asks for a release no matched grant covers
suspends every CI grant with the same issuer and required claims on that host — for a `runner`
session, every `runner` grant naming that account — and ends the session
(the engine tells the launcher, which ends its descendants; a launcher that is gone ends the session
anyway, since nothing can be bound to it). On a persistent host the suspension stays until the owner
re-creates the grants on the Mac; on an ephemeral host it lasts for that job and travels to the Mac
in the report (§4.3). A token that fails verification, or a token id already used, is refused and
recorded, not a strike: it may be the platform, the clock or a retried job.

**What this trusts, stated plainly** (T-22, W-40):

- **The platform.** It signs the tokens. A platform that is compromised, or an administrator of it,
  can mint a token with any claims and use every CI grant that trusts it.
- **Everyone who can make the platform issue a matching token**: whoever can push to the pinned
  branch, change the pinned workflow file on it, or approve the pinned deployment environment. The
  platform's branch protections and required reviews become part of what guards the credential;
  kagisecure cannot see them.
- **The token is a bearer credential.** Anything that reads it before the session opens — another
  step of the same job, a process of the runner account — can open the session first. The token id
  is single use and the lifetime short, so the legitimate job then fails, visibly; the credential
  may already have been used.
- **Issuer keys rotate.** When the platform rotates its signing keys, verification fails closed
  until the owner imports the new keys and exports a new bundle.
- **For a `runner` grant, every job on the runner** (W-43). Anyone who can make the CI service run a
  pipeline there — commonly anyone who can push to any repository the runner serves, and on some
  platforms anyone who can propose a change from outside — can use the grant, from any branch, with
  any workflow. The command pins and the one strike still hold; nothing ties the session to a
  particular pipeline.

### 12. Linux counterparts: the peer check, the run binding, teardown — (e)

| ADR-0042, on macOS | On a Linux host |
| --- | --- |
| Same-user gate: the peer's uid equals the app's (M-13) | The peer's uid, from `SO_PEERCRED`, must be the **job account's**, or a runner account named by a CI grant (CI sessions only); any other uid is refused before a byte is read. The sockets live in the engine unit's runtime directory, `0750`, group-owned by a group of exactly those accounts, sockets `0660`, so other local users cannot reach them (T-4) |
| Peer pid from `LOCAL_PEERPID`; start time from `process_start_time` | pid from `SO_PEERCRED`, already kernel-verified ([ADR-0007](0007-m2-daemon-and-ipc-deviations.md) §3); where the kernel offers one, a pidfd for the peer (`SO_PEERPIDFD`), which a later process given the same pid cannot impersonate; otherwise the start time from `/proc/<pid>/stat`, read before and after the check |
| **Ancestry walk** to a run's root pid and start time, at most 16 hops | For runs: **cgroup membership** — `/proc/<pid>/cgroup` must name the cgroup of a live run instance the engine started. The kernel maintains it; a child inherits its parent's cgroup and cannot leave it without write access to another cgroup, which the job account lacks, so a double fork, `setsid` or re-parenting changes nothing. For CI sessions: the ancestry walk to the session's launcher, made unbreakable by the launcher being a subreaper (§11). On an ephemeral host with no cgroup of its own for runs: the ancestry walk, as ADR-0042 |
| The run's process group, ended with `SIGTERM` then `SIGKILL` | The run's unit, stopped through systemd: the whole cgroup is signalled, including processes that left the process group; if the engine dies, the template's runtime ceiling still ends every run. A CI session is ended by its launcher, which signals every descendant |
| The app spawns a granted command, the value in its environment, in the run's process group | The engine cannot start a process as another account, and giving it that power would give it root. So **the launcher spawns it**: once ADR-0042 §6's release path has passed and its `Allowed` entry is committed, the engine sends the run's (or session's) launcher one message on the run-control socket — executable, arguments, directory and the resolved variables — and the launcher checks the pin on the descriptor it opened, executes that descriptor with those variables as a child in the run, and returns only the exit code. Under `shared` the same launcher is used, for uniformity |
| The peer's code signature, recorded as evidence (ADR-0015) | Not available on Linux; the peer's executable path and hash are recorded instead |

**The run-control channel is a new value-carrying channel**, enumerated here the way
[ADR-0018](0018-browser-extension-secret-crossing.md) enumerates the extension channel: one socket
(the run-control socket, never the unattended MCP socket); one message type that carries values
(`Spawn`), built in one module of `kagisecure-host` and read in one module of `kagisecure-run`; sent
only after an audited release, only to the launcher of the run or session that asked, recognized by
its uid, its cgroup or its session, and — for a run — being that unit's main process as systemd
reports it. The canary sweep covers it: a value seeded into a host's machine vault reaches the
launcher only in `Spawn` and appears in no byte the sidecar writes and in no journal line. The
launcher makes itself non-dumpable as its first act, so other processes of its account cannot trace
it or read its memory; the child it starts is W-4's, as every `run_with_env` child is — and on a
host, W-4's "other processes of the same user" is every process of that account (W-35).

**The MCP sidecar** (`kagisecure-mcp`) is unchanged: the job's agent starts it inside the run or
session, it connects to `KAGISECURE_SOCKET`, and it carries no value, exactly as on the Mac.

### 13. Arming, and what each event does

**Arming is automatic.** When the engine starts and has the host's secrets — from systemd (`tpm`) or
from the file (`file`) — it opens the host's machine vault and is armed. There is no arm expiry of
ADR-0042 §3's kind; the bound is the grants' and the bundle's expiry (§9). Arming is still not a
grant: an armed host with no bundle releases nothing.

| Event | On the host |
| --- | --- |
| Boot, policy matches (`tpm`), or the file is readable (`file`) | armed when the unit starts; runs whose time passed while it was down are `JOB_MISSED`, unless within their catch-up window |
| Boot, policy no longer matches (§4.1) | not armed; the journal says why; re-enrol (§6) |
| The engine crashes | systemd restarts the unit, which re-arms; every live run instance and CI session is ended first and recorded `KILLED_ON_RESTART`, because the new engine did not start it |
| `kagisecure-host pause`, `lock` on the unattended socket, a `narrowing` bundle that pauses | disarmed; runs and sessions ended |
| The host's machine vault diverges or is replaced (ADR-0039 `VaultDiverged`, `VaultConflict`) | disarmed. Under `separate` only the engine writes that file, so a divergence is a restore or tampering; it stays disarmed until an administrator runs `kagisecure-host resume`, which is recorded and reported |
| The clock reads earlier than the newest log entry (§9) | disarmed until an administrator resumes |
| A strike (ADR-0042 §7 and §12.7, answer 11; §11 for CI grants) | the job's (or CI identity's) grants suspended; the run's unit stopped, or the session ended |
| An ephemeral host's job ends | the engine writes its report and exits; nothing persists |

### 14. Audit and noticing with no app — (f)

- **The log** is the host's machine vault's own audit log, with ADR-0042 §8's vocabulary and actors
  (`mcp unattended "<job>" run <id> pid <n> <executable>`; for CI sessions
  `mcp unattended ci "<issuer>" "<subject>" session <id> pid <n> <executable>`, or for a `runner`
  session `mcp unattended ci runner "<account>" session <id> pid <n> <executable>`; `unattended` for
  the
  engine's own entries), every entry carrying the host's profile, plus host events:
  `BUNDLE_APPLIED (generation <n> sha256 <h>)`, `BUNDLE_REFUSED (<reason>)`,
  `CI_SESSION_OPENED (<token id> <matched grants>)`, `CI_TOKEN_REFUSED (<reason>)`,
  `KILLED_ON_RESTART`, `CLOCK_BEHIND_LOG`, `PAUSED`, `RESUMED`, `REPORT_WRITTEN (<count> <head>)`.
  Releases are fail-closed exactly as ADR-0040 makes them.
- **The journal.** Every event is also one line on the engine's standard error, which systemd's
  journal keeps (or the platform's job log, on an ephemeral host): event, job or CI subject, grant
  id, outcome, profile — never a value, never a token, never a command line. The administrator's
  existing monitoring may read it and alert; kagisecure does not, and opens nothing to do so (N-9).
  Whoever reads the journal learns job and grant names (A4, to a new audience; W-34).
- **Reports go back by file.** After every run and CI session, and at a fixed interval, the engine
  writes a **report** to its outbox: the whole log (Phase 1 decides when a report may start from the
  head the last `state` bundle acknowledged), the profile, the applied generation, the grants'
  counters and suspensions, and the last unseal time — sealed to the Mac's provisioning key with
  HPKE and signed by the host's key. It carries names, never values. Whatever carries bundles in
  carries reports out.
- **The Mac anchors the host's log.** Importing a report, the Mac verifies it against the pinned
  host key and compares its log with the count and head it last accepted from that host, using
  [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)'s verdicts: `Current`
  and `Extended` are accepted; `TailMissing` and `Diverged` are shown as a warning on that host and
  recorded in the personal vault's log. The Mac is, for each persistent host, the external anchor
  ADR-0041 wants and does not design for Linux. Accepting a report writes
  `HOST_REPORT_ACCEPTED (<host> <count> <head>)` to the personal log — ADR-0042 §8's
  `SUMMARY_ACKNOWLEDGED`, for hosts. An ephemeral host's reports each start a new log; the Mac
  keeps them as a series and can anchor nothing between them.
- **What rollback remains.** Under `separate`, the job account cannot write the log at all (§3),
  which is stronger than the Mac, where same-user malware can roll the machine vault back (W-11).
  The service account and root — and under `shared`, every job — can roll it back or, holding the
  key, truncate it **between two reports**; the next report shows `TailMissing` or `Diverged` —
  unless no report ever comes, which the Mac also shows: **a host whose last report is older than
  seven days (a setting) is flagged**, and silence is presented as silence (W-33).
- **"While you were away", per host.** Importing a report shows ADR-0042 §9's summary for that host
  — runs, CI sessions with their subjects, releases, refusals, suspensions, missed runs, sign-ins
  with their origins and ADR-0042 §12.8's reset advice — plus bundles applied or refused, refused
  tokens, pauses, resumes and restarts. Nothing reaches the owner before a report is imported.
- **Before maintenance that will change PCR 7**, the documentation tells the administrator to let
  the host write a report and carry it out first: a re-enrolled host starts a new log.

### 15. Unattended sign-ins on hosts with no display — (g)

**Built from the start** (owner's answer 5). ADR-0042 §12 applies on hosts, and a run or CI session
whose grants include a login grant gets a run browser without a physical display, by one of two
routes the job's definition chooses and pins:

- **The browser's full headless mode** (not the headless shell, which does not load MV3 extensions,
  [browser-extension.md](../browser-extension.md) §9), with a fresh profile, the unpacked extension
  and the native messaging manifest written into that profile; or
- **a virtual display started for the run**, inside the run's cgroup (or the session's tree), as the
  run's account, listening on no TCP port, on a socket in the run's private directory with its own
  authorization cookie, and ended with the run; the browser then runs headful on it, as ADR-0042
  §12.3 requires on the Mac.

In both:

- **The control endpoint is a pipe, not a port.** On the Mac, ADR-0042 §12.3 gives the job's agent a
  loopback debugging port, reachable by any same-user process (W-28). On a multi-user host a
  loopback TCP port is reachable by **every account**. The run browser is started with its debugging
  protocol on inherited pipes handed to the job's root, and no port is opened.
- **The unattended extension endpoint** accepts `kagisecure-nmhost` by the run's account, the run's
  cgroup (or the session's tree), and ancestry to the run browser's recorded pid and start time —
  ADR-0019's gate, pinned to one process, as on the Mac.
- **A virtual display is reachable by every process of the run's account that finds its cookie**,
  and a client of an X server can read what other clients draw and type (W-36). The fresh profile,
  the per-run display and, under `separate`, the job account's exclusivity (§3) are what bound it.
- The run browser is pinned (by hash on Linux), so a distribution update of it suspends every login
  grant of the jobs that declare it.
- **Whether a given browser build works is an acceptance test, not a precondition.** Some branded
  builds no longer honour `--load-extension` (browser-extension.md §9). Phase 5 runs the sign-in
  suite against each route and each build the documentation names, and records the results in this
  ADR; a job that declares a build or route that does not load the extension gets `FILL_UNAVAILABLE`
  at its first `request_fill`, which is not a strike, and the host's report says why.
- On a Mac host with nobody logged in there is no window server session for a daemon, so the route
  is full headless mode only (§17).

### 16. Where ADR-0042's Mac-only sections change

- ADR-0042 §14's "macOS app only" stays true of the **app**; `kagisecure-host` is a second host of
  the engine, on Linux and on Macs used as build hosts (§17).
- ADR-0042 §15 is superseded by this ADR for everything it leaves to "the follow-up ADR".

### 17. A Mac used as a build host (owner's answer 6)

A Mac with nobody logged in, running scheduled jobs and CI work, is in scope. It runs
`kagisecure-host`, never the app's engine; a Mac running the app with a machine vault is never a
host, and answer 2 holds for it.

**The process.** `kagisecure-host` runs as a system launch daemon, which starts at boot before
anyone logs in, under a dedicated service user (`separate`) or the build account (`shared`). There
are no cgroups, so:

- **Runs** are started by a **run broker**: kagisecure's launcher, `kagisecure-run --broker`, run as
  a second launch daemon under the job account. The engine asks the broker to start a run; the
  broker starts the pinned root as its child in a process group of its own and reports the root's
  pid and start time; requests are bound by ADR-0042 §4's ancestry walk to that root, as on the Mac
  app, and a chain broken by re-parenting is refused. Teardown is the process group, as ADR-0042 §4,
  with the same limit: a process that leaves the group is not ended by it (and cannot use a grant,
  since its chain is broken). `Spawn` goes to the broker. Under `shared`, the engine starts runs
  itself.
- **CI sessions** use the launcher of §11 with the ancestry walk; macOS has no subreaper, so a CI
  job's descendants that are re-parented away cannot use the session.
- **Pins** use code-signing identity where the binary has one (answer 7), from the inventory.
- **The peer check** is `LOCAL_PEERCRED`'s uid and `LOCAL_PEERPID`, with the code-signature verdict
  of ADR-0015 recorded as evidence.
- **Sign-ins** use full headless mode (§15).

**The key store: `enclave`, designed and blocked; `file` until then.**

- **`enclave`** (the target). The host's secrets are wrapped by a Secure Enclave key created without
  a user-presence flag, non-exportable, in the kagisecure team's keychain access group, usable after
  the first unlock since boot. This is the Mac's counterpart of `tpm`: the wrapped secrets are
  useless on any other machine, and the key is usable only through the Enclave on this one. Three
  things block it (owner's answer 9):
  1. the `keychain-access-groups` entitlement needs a provisioning profile, the account action
     [ADR-0011](0011-secure-enclave-under-ad-hoc-signing.md) has waited on since M3 — and
     `kagisecure-host` would need a profile of its own, as a separate signed binary;
  2. whether an access group resists another process of the same user is
     [ADR-0041](0041-anchor-the-audit-logs-freshness-outside-the-vault-file.md)'s unmeasured
     Phase 0; if it does not, `enclave` protects against a copied disk only, like `tpm` without
     PCRs;
  3. whether a launch daemon, with no user logged in, can create and use a Secure Enclave key in a
     keychain at all is unmeasured; if only a logged-in session can, surviving a reboot needs
     automatic login, which requires disk encryption to be off.
- **`file`** (now). Until all three are resolved, a Mac host is a `file` host (§4.2), labelled so
  everywhere. The key file is in the service user's `0700` directory. A plain login-keychain item is
  not offered: it is readable by any same-user process (ADR-0041, "Alternatives considered"), so it
  would be a `file` key under a stronger-sounding name.
- **Disk encryption and unattended boot.** With the platform's disk encryption on, a Mac stops at
  the unlock screen after a restart until someone types a password; an authenticated restart,
  started by an administrator, skips that once, for a planned restart only. So:
  - **encryption on** (recommended): planned restarts keep the host armed if the administrator uses
    an authenticated restart; an unplanned one — a power cut, a crash — leaves the host disarmed
    until someone unlocks it, which is answer 2 by accident, not a failure of kagisecure;
  - **encryption off** (what "survives every reboot" needs): the key file is protected at rest only
    by whatever encryption the platform applies to internal storage on its own, which the platform
    documents as bound to that Mac's hardware on current models — useless if the storage is removed,
    readable by anything that boots the Mac (measured in Phase 0, not assumed). A stolen Mac arms
    itself (W-41).
  The host's enrolment request records which, and the Mac's view of hosts labels it.
- **Freshness.** ADR-0041's keychain anchor would give a Mac host a local freshness witness once
  `enclave` is unblocked; until then, as on Linux, the Mac that provisions it anchors its log (§14).

### 18. Windows hosts: not in this ADR

ADR-0042 §14 excludes Windows because a same-user process can read the app's memory there (T-3).
The `separate` profile removes that particular reason — the job account is not the service's — and
Windows job objects plausibly give a kernel-enforced run identity. But Windows' peer verification
is weaker (W-10, [ADR-0032](0032-authenticode-peer-verification.md)), its named-pipe boundary is
untested against a second account (M-13), and nothing here is measured. Windows hosts are left to a
later ADR, and the documentation recommends option (c) for them.

### 19. ADR-0042's answers on a host

| Answer | On a host |
| --- | --- |
| 1 Build it, after shared vaults | Holds; hosts come after ADR-0042's Mac phases ("Implementation plan") |
| 2 A restart disarms; no persistent arming | **Reversed for hosts only**, by answer 13; unchanged for the Mac app, and a Mac running the app is never a host (§17) |
| 3 Unattended sign-ins are wanted | Holds, built from the start (§15) |
| 4 Callers kagisecure did not start: never | **Changed for hosts only** (owner's answers 3 and 12): a job a CI service starts may use a CI grant — after presenting a verified workload token (recommended), or, for a `runner` grant, by running as a named runner account (§11). Unchanged on the Mac |
| 5 Grant defaults | Hold, for CI grants too; expiry is checked on the host clock (§9) |
| 6 Interpreters: a warning | Holds; the sheet adds that a hash-pinned interpreter's updates suspend |
| 7 Code-signing identity where there is one, hash otherwise | Holds; Linux has none, so always hash; a Mac host uses signing identity (§8, §17) |
| 8 Output `none` only | Holds |
| 9 Shared-vault copies, with published copy records | Holds for every host; the record names the host and its profile ("held unattended on host 'build-01' — key in a file, provisioned from 'Work laptop'") (§1). A host is never a shared-vault member |
| 10 An edit with presence carries grants forward | Holds on the Mac, where every edit is made; the host receives only whole bundles, each exported with a presence proof (§7) |
| 11 One strike | Holds; for CI grants it suspends the CI identity's grants (§11) |
| 12 Interactive use through the ordinary socket | **Does not apply on the host**: no ordinary socket, nobody present. On the Mac, **extended to hosts' machine vaults** (owner's answer 7, §5) |
| 14 Names | Kept; this ADR adds "host", "profile", "provisioning bundle", "report", "inventory", "CI grant", "CI session" |
| 15 A fresh run-browser profile per run | Holds (§15) |
| 16 The one-time-code switch, off by default | Holds on every host; on a `file` host its sheet adds that both factors would sit in one file (§1) |
| 17 A fixed 60-second flow window | Holds |
| 18 A fill suspension suspends only | Holds |
| 20 Interactive fills of machine-vault logins | **Does not apply on the host**; on the Mac, extended to hosts' logins (§5) |
| 21 The per-vault copy policy, default allowed | Holds; an admin who does not want values on hosts at all turns copies off for the vault |

### 20. ADR-0002 and N-9, unchanged

No MCP tool returns a value; the unattended socket speaks the existing protocol through the same
engine code and carries none; `request_fill` still names fields only. On a host exactly two channels
carry values out of the engine, both enumerated: the extension channel, as on the Mac (ADR-0018),
and the run-control socket's `Spawn` (§12). A workload token travels *into* the engine, on the
run-control socket, and is never written anywhere. Machine-vault decryption, bundle parsing, HPKE
and token verification stay in crates that `kagisecure-mcp` and `kagisecure-ipc` cannot depend on,
under the dependency-graph tests that guard M-2 and M-27; the token-signature algorithms add
verification-only public-key crates to `kagisecure-host` alone, with their audit status recorded as
W-6 records the AEAD's. No crate on the N-9 ban list is added; on Linux `kagisecure-host` runs where
the kernel refuses it every non-local socket (§3); it reads bundles from and writes reports to local
paths only, and it never fetches an issuer's keys.

## Alternatives considered

**Option (c) — the platform's secret store, or federated short-lived credentials — instead of any
of this.** Recommended alongside everything here, and first for CI pipelines whose target service
federates. The owner decided it is not the whole answer (answers 2 and 3).

**A Mac as the only armed machine, called by the hosts** (h2). Rejected: network code, or a tunnel
that erases the caller's identity; the release happens on the Mac, not on the host; and the app
disarms on restart.

**One machine vault shared by every host** (h3). Rejected (§5): every host would hold every host's
credentials.

**Reversing the daemon's "never"**: `kagisecure daemon --unattended`. Rejected (§2): one binary
would both unlock a personal vault with a terminal `y` and arm itself, told apart by a flag.

**Refusing hosts without a TPM or Secure Boot, containers and ephemeral runners** — the first
draft's proposal. The owner chose a labelled `file` profile instead (answer 2, §4.2, §4.3).

**Callers kagisecure did not start: never, on hosts too** — the first draft's proposal, keeping
ADR-0042's answer 4 everywhere. The owner chose CI grants (answer 3, §11).

**CI grants bound to the runner account alone**, for platforms that issue no workload token — the
second round's proposal was not to offer them. The owner allowed them as the labelled `runner`
binding (answer 12, §11); the `token` binding stays the recommended form.

**Withholding shared-vault copies and the one-time-code switch from `file` hosts** — the second
round's proposal. The owner chose no restriction (answer 10, §1); the labels are what remains.

**Requiring separate accounts** — the first draft's proposal. The owner allowed `shared` (answer 4,
§3); `separate` stays the default and the recommendation.

**The engine as root**, starting runs as the job account itself. Rejected: every engine bug would
be root's.

**`CAP_SETUID` for the engine, with a system-call filter** limiting it to the job account's uid, so
that the engine spawns granted commands itself and no launcher is needed. Rejected for now: the
capability is root-equivalent the day the filter is wrong, and the launcher costs one small binary
and one enumerated message.

**Transient units defined at run time** instead of one template. Rejected: the authorization that
lets an account start a transient unit does not restrict which user the unit runs as.

**kagisecure's own TPM code** instead of systemd's credentials. Deferred. It would allow a key read
once per boot and then read-locked in the TPM until the next reset, and a monotonic counter
anchoring the log on the host, at the cost of TPM command handling of the project's own. The C TPM
stack in common use can load a TCP transport for simulators, which would need care under N-9.

**No PCR binding**, and **binding to firmware and boot-loader PCRs.** Rejected (§4.1): the first
lets any OS on the board unseal; the second disarms on every routine update.

**A TPM authorization value (PIN).** Rejected: someone types it at every boot, or it sits beside
the sealed file.

**Trust on first use at enrolment**, as ADR-0035 allows for shared vaults. Rejected (§6).

**Delta bundles.** Rejected (§7): a complete state with a generation is idempotent, cannot be
applied out of order and cannot leave a host half-updated.

**The host fetching its own bundles or an issuer's keys** — kagisecure running a git client, or
reading a key-set URL. Rejected: N-9, and ADR-0035 §7's reasoning: kagisecure reads and writes
files; the owner's tools move them.

**Grants created on the host by an administrator**, on a terminal sheet. Rejected: root on a host
is not a presence proof, and this is ADR-0007 §1's terminal `y` with months of access behind it.

**Hosts as members of shared vaults.** Deferred, as ADR-0042 answer 9 defers an unattended member.

**A host serving the ordinary socket.** Rejected: there is nobody on a host to approve anything.

**Hosts' machine vaults kept off the Mac's ordinary socket** — the first draft's proposal. The owner
chose interactive use with the ordinary sheet and a presence proof (answer 7, §5).

**Gating unattended sign-ins on hosts behind a prior measurement** — the first draft's proposal. The
owner chose to build them from the start (answer 5); the measurement is Phase 5's acceptance test.

**Leaving Macs used as build hosts out of this ADR** — the first draft's proposal. The owner brought
them in (answer 6, §17). **A login-keychain item** as their key store is rejected: it is a `file`
key under a stronger-sounding name.

**Windows hosts with the design as it stands.** Not in this ADR (§18).

## Changes in the threat model

Proposed, not applied: [threat-model.md](../threat-model.md) is not edited by this ADR.

> **Numbering note.** On `main` when this was written: A1–A11, TB-1–TB-6, T-1–T-17, M-1–M-31,
> W-1–W-22 (W-18 was reserved for ADR-0037 and never assigned), N-1–N-10, and R-1–R-13 in
> [threat-model-browser-extension.md](../threat-model-browser-extension.md). ADR-0042 (proposed)
> reserves A12, TB-7, TB-8, T-18, T-19, M-32–M-34, W-23–W-29 and R-14 — its "no person at release
> time" entry was drafted as W-22 and moved to W-29 when `main`'s W-22 (the format-upgrade backup of
> ADR-0035's Phase 0) was found to collide. This ADR takes **A13, TB-9, TB-10, T-20–T-22, M-35–M-39
> and W-30–W-43**. No N- or R- entry. All are **provisional — renumber at acceptance if taken**, as
> ADR-0035's and ADR-0036's were.

**New entries** *(proposed, provisional)*:

- **A13** — a host's secrets and its machine vault on the host: the host's key pair and
  machine-vault key (sealed or in a file at rest; in the engine's memory while it runs), the
  provisioned items, jobs and grants, the pinned token issuers, and the host's audit log. Loss means
  every credential provisioned to that host and the ability to release them on its schedule. The
  Mac's source copy (§5) is under A12.
- **TB-9** — the Mac and a host. Everything that crosses is a file moved by people or their tools:
  enrolment requests and inventories one way, bundles the other, reports back. Enforced by mutual
  full-fingerprint enrolment, signatures verified before decryption, HPKE to the pinned key, the
  profile bound into every bundle and report, strictly increasing generations (persistent hosts
  only), and narrowing-only bundles for anything signed without a presence proof.
- **TB-10** — the accounts on a host and the run's cgroup or session. Under `separate`, enforced by
  file ownership, the uid gate, cgroup membership of a run instance the engine started, a template
  unit that fixes the job account, and a polkit rule limited to that template. Under `shared`, the
  boundary between the jobs and the key does not exist (W-38).
- **T-20** — whoever controls a host's hardware or boot: a thief of the whole machine; someone who
  reboots it into something the sealing policy accepts or edits its boot; on a virtual machine, the
  operator of the virtualization platform; and, for a `file` host, anyone with its disk, a backup,
  a snapshot or its image.
- **T-21** — the provisioning channel: the host of the repository that carries bundles and reports,
  the tools that move them, a CI platform's secret and artifact mechanisms for ephemeral hosts, and
  anything that can write the host's inbox. It reads plaintext headers, and can withhold or delay a
  bundle or a report and replay an old one; on a persistent host it cannot take the host back to an
  earlier generation.
- **T-22** — a CI platform and whoever can steer it: the platform itself and its administrators,
  who sign workload tokens; everyone who can push to a pinned branch, change a pinned workflow or
  approve a pinned environment; for a `runner` grant, anyone who can make the CI service run a job
  on that runner; and any step or process that reads a job's token before the job uses it.
- **M-35** — *A `tpm` host arms itself only from a key sealed to its TPM and its host secret, bound
  to PCR 7 with Secure Boot on, in a hardened unit that the kernel keeps off the network; every
  weaker sealing is labelled wherever the host appears* (§1, §3, §4, §13).
- **M-36** — *A host releases only what a signed bundle from its pinned Mac carries*: made with a
  presence proof, sealed to the host, bound to its profile, verified before decryption, applied
  whole, never replayed on a persistent host, at most 7 days old on an ephemeral one; pins from
  host-signed inventories; nothing created or widened on the host (§6–§9).
- **M-37** — *Runs are units kagisecure starts, recognized by their cgroup and executed under the
  job account*: the uid gate; cgroup membership instead of ancestry; the launcher executing the
  descriptor it pinned; teardown of the whole cgroup; a runtime ceiling systemd enforces even if the
  engine dies; values reaching only the run's launcher, in one enumerated message, after an audited
  release (§10, §12).
- **M-38** — *A host's log is anchored on the Mac*: signed, sealed reports; ADR-0041's verdicts
  against the last accepted head; a flag on hosts that stop reporting; one journal line per event,
  with no values and no tokens (§14).
- **M-39** — *A CI grant is used only by a session its binding admits*: for `token`, one that
  presented an unexpired, single-use workload token, verified offline with two named algorithms
  against issuer keys pinned in the bundle, for this host's audience, with every required claim
  matching exactly; for `runner`, one whose peer is a runner account the grant names. Either way
  from a named runner account, bound by ancestry to a subreaper launcher; a presented token that
  fails is never downgraded; one strike suspends the grants of that CI identity or runner account;
  the token is never recorded (§11).
- **W-30** — *The key is at rest and the host uses it by itself.* Usable by the service account, by
  root and by anything that boots in a way PCR 7 accepts — including, with an unlocked boot menu, a
  changed kernel command line. A stolen host arms itself ("costs", points 1 and 2).
- **W-31** — *Revocation arrives by file.* Until a bundle is delivered, a revoked grant keeps
  working; expiry is checked on the host clock, which whoever controls the firmware can hold back.
- **W-32** — *Pins are what the host reported.* The Mac never sees the pinned bytes, and every
  update of a hash-pinned tool suspends its grants.
- **W-33** — *The host's log can be rolled back or truncated between two reports* by whoever holds
  the key, and reports can be withheld; the Mac detects the first at the next report and shows the
  second only as silence.
- **W-34** — *Root-equivalence is common on build hosts, and kagisecure cannot check it.* Journal
  lines disclose job, subject and grant names to the host's administrators.
- **W-35** — *A value-carrying channel to the launcher, and child environments every process of the
  launcher's account can read* (§12).
- **W-36** — *A run's virtual display is reachable by processes of the run's account* that find its
  cookie, and its clients can read one another's input (§15).
- **W-37** — *A `file` key is usable by anyone with the disk, a backup, a snapshot or the image*, on
  any machine and with no time limit; rotating it is re-enrolling the host and rotating everything
  it held. Since nothing is withheld from a `file` host, that can include other members'
  shared-vault values and a login's password together with its one-time-code seed (§1, §4.2).
- **W-38** — *Under `shared`, every job can read the key and rewrite the vault and its log*: an
  injected job agent is one step from every credential on the host, with no grant, no pin and no
  audit entry (§3).
- **W-39** — *An ephemeral host is a policy layer, not a boundary.* The job that starts the engine
  holds its key; suspensions last one job; any unexpired bundle is accepted; the report is the job's
  own testimony; the platform's secret store is the real boundary (§4.3).
- **W-40** — *A CI grant trusts the CI platform and everyone who can make it issue a matching
  token*, and the token is a bearer credential until it is used; pinning a checked-out repository's
  files is impractical, so a CI grant usually releases to whatever was pushed to the pinned branch
  (§11).
- **W-41** — *A Mac host is a `file` host until `enclave` sealing is unblocked*, and one that
  survives every reboot has disk encryption off, so a stolen Mac host arms itself and anything that
  boots it reads the key (§17).
- **W-42** — *Hosts' credentials are reachable from the Mac's interactive sessions.* An injected
  interactive agent on the Mac can ask for any host's credentials through the ordinary sheet, one
  approved sheet from them, and — where the owner made them visible — learn every host's
  environments and variable names (§5).
- **W-43** — *A `runner` CI grant is usable by every job its runner runs.* Nothing about a job's
  origin is verified; anyone who can have a pipeline scheduled on that runner — from any branch,
  with any workflow — can cause the pinned release, up to its limits (§11).

**Existing entries — and ADR-0042's proposed ones — this changes, on hosts only** (the Mac app, the
personal vault and shared vaults keep everything as ADR-0042 leaves them, except W-42 on the Mac):

| Entry | Effect |
| --- | --- |
| A12 (ADR-0042: the machine vault) | Also covers each host's source copy on the Mac, now reachable interactively there (W-42); the host's own copy is A13 |
| M-32 (ADR-0042: armed by a person, in memory only, a restart disarms) | **Reversed** on hosts by M-35: armed by itself, at rest, surviving reboots |
| M-33 (ADR-0042: runs kagisecure started, bound by ancestry) | Holds for runs, with cgroup membership on Linux (M-37); **relaxed** for CI sessions (M-39) |
| W-24 (ADR-0042: the armed key in memory; a restart disarms) | Replaced on hosts by W-30, W-37 and W-41 |
| T-5 (lost or stolen device) | **Weakened**: a stolen host arms itself; a copy of a `tpm` host's disk is useless elsewhere, a copy of a `file` host's disk is not |
| N-1 (root) | A larger class on build hosts (W-34); root holds every credential provisioned to the host |
| M-11 (auto-lock) | Not applicable on hosts |
| M-13 (same-user gate) | On hosts, an allow-list: the job account, and runner accounts for CI sessions |
| M-15 (per-user isolation; no system-wide daemon) | **Reversed** on hosts: `kagisecure-host` is a system service |
| M-19 (caller verification) | No code signature on Linux; executable path and hash recorded |
| T-2 (prompt injection) | Also reaches CI grants through whatever a pipeline reads; under `shared` or `ephemeral`, an injected job can take every credential on the host (W-38, W-39) |
| T-3 (same-user malware) | As the job account under `separate`: granted releases through the job's inputs and children's environments, never the key. Under `shared`, as the service account: everything |
| T-4 (another local user) | Refused by the uid gate and file permissions, unless it is a runner account a CI grant names |
| T-14 (exchange channel) | Joined by T-21, for bundles and reports |
| W-11 (audit freshness) | Narrowed under `separate`; unchanged under `shared`; anchored on the Mac per report either way (W-33) |
| W-28 (ADR-0042: the run browser's debugging port) | Replaced on hosts by pipes; W-36 for a virtual display |
| W-27 (ADR-0042: with the one-time-code switch on, one factor) | On a `file` host, the password and the seed are also in one file anyone with the disk can copy (W-37) |
| W-12 (a member reads everything; a departed member keeps it) | A copy on a `file` host is readable by anyone with that host's disk, whoever they are; the copy record names the profile (§1) |
| N-9 | Unchanged, and additionally enforced by the kernel for the Linux engine's unit |

**Unchanged, and asserted by test:** M-1, M-2, M-27, M-30 and N-9 everywhere; ADR-0042's rule that
no IPC message and no MCP tool creates, widens, extends, re-enables or proposes a grant or a job,
extended to every socket on a host and to CI grants.

## Consequences

**Positive**

- Persistent hosts, ephemeral runners, containers and Macs used as build hosts can all run
  unattended jobs with ADR-0042's scope, pins, limits, suspension and audit, without a token in a
  unit file or a pipeline variable — and CI pipelines whose target offers only a long-lived token
  can use one without holding it in the platform's settings.
- In the recommended profile the key at rest is useless off the machine, and the key, the vault and
  the log are out of reach of the account that runs the jobs — a stronger separation than the Mac
  app's.
- Run identity on Linux is kernel-maintained cgroup membership, and teardown reaches every process
  of a run.
- Every grant on a host was made on a Mac with a presence proof; a host creates nothing.
- The Mac is the freshness anchor for every persistent host's log.
- No TPM code, no new key-agreement or record primitive, no network code.
- Every weaker choice is visible as what it is, wherever the host appears.

**Negative — accepted**

- **A key at rest that the host uses by itself** (W-30), and in the weaker profiles a key that is a
  file (W-37), a key every job can read (W-38), or a host that is the job's own (W-39).
- **CI grants trust the platform and its pushers** (W-40), and change ADR-0042's answer 4 on hosts;
  a `runner` grant trusts every job its runner runs (W-43).
- **`file` hosts may hold shared-vault copies and one-time-code seeds** (W-37), labelled, where the
  first draft would have withheld them.
- **Macs used as build hosts are `file` hosts** until three blockers clear, and surviving every
  reboot means disk encryption off (W-41).
- **Hosts' credentials are reachable from the Mac's interactive sessions** (W-42).
- **Revocation lags delivery** (W-31); on ephemeral hosts it acts only through a 7-day expiry, which
  means a presence-proven export every week.
- **Friction.** Hash-only pins suspend on every update (W-32); a Secure Boot database change forces
  re-enrolment; issuer key rotation stops CI grants until the owner imports new keys; `file` keys
  need rotating.
- **More moving parts**: profiles, two or three accounts, a template unit, a polkit rule, a launcher
  and a run broker, a second value-carrying channel (W-35), token verification with new
  verification-only crates, and bundles, inventories and reports to move.
- **Noticing is late**, and on ephemeral hosts it depends on the job carrying its report out.
- **A system service**, reversing M-15 on hosts.
- **Sign-ins on hosts may not work with a given browser build**; Phase 5 finds out, after the code
  exists.

**Neutral**

- The Mac app's design (ADR-0042) is unchanged apart from serving hosts' machine vaults
  interactively; `kagisecure daemon` is unchanged.
- A Mac that enrols no host sees nothing new.

## Owner's answers (2026-09-27)

The owner answered all eight open questions of the first draft the same day, and then the five
questions those answers raised (9–13). Where an answer chose against the proposal — 2, 3, 4, 5, 6,
7, 10 and 12 — what that costs follows it. In this ADR, "owner's answer N" means this list; a bare
"answer N" means ADR-0042's.

1. **Sealing as proposed**: TPM and systemd's host secret, PCR 7, Secure Boot required; a signed
   PCR 11 policy recommended, not required; the boot menu must be locked, documented and not
   checkable (§4.1).
2. **Hosts without a TPM or Secure Boot, containers and ephemeral CI runners are served, in a
   labelled weaker mode** (§1, §4.2, §4.3). *Cost:* their key is a file that anyone with the disk, a
   backup, a snapshot or the image can use on any machine; on an ephemeral runner the job that
   starts kagisecure holds that key, forgets every suspension, can be handed any unexpired bundle
   and decides whether its log is ever seen, so kagisecure there limits an honest job and does not
   protect the credentials from a steered one (W-37, W-39).
3. **Jobs a CI service starts may use grants**, bound to a workload token the platform signed and
   kagisecure verifies offline, which changes ADR-0042's answer 4 for headless hosts only (§11).
   *Cost:* a CI grant is a grant to the CI platform and to everyone who can push to the pinned
   branch, change the pinned workflow or approve the pinned environment, and the token is a bearer
   credential until it is used — the "anyone who can start the client" of ADR-0042's point 3, moved
   to the platform's permissions, which kagisecure cannot see (T-22, W-40).
4. **A single account may run the engine and the jobs**; separate accounts stay the default and the
   recommendation (§3). *Cost:* under `shared` every job — and whatever steers its agent — can read
   the key and the vault and so take every credential on the host with no grant, pin or audit entry,
   and can rewrite the log (W-38).
5. **Unattended sign-ins on hosts are built from the start**, under full headless mode or a per-run
   virtual display, with the debugging protocol on pipes; the measurement is an acceptance test
   (§15). *Cost:* the code is built before anyone knows which browser builds it works with, a
   virtual display lets processes of the run's account read the sign-in (W-36), and a declared build
   that does not load the extension is found only when its first sign-in fails.
6. **A Mac used as a headless build host is in scope** (§17). *Cost:* until a provisioning profile,
   an access-group measurement and a no-login Secure Enclave measurement all succeed, a Mac host
   keeps its key in a file; and one that survives every reboot has disk encryption off, so a stolen
   Mac host arms itself and anything that boots it can read that key (W-41).
7. **Hosts' machine vaults on the Mac are usable interactively**, with the ordinary sheet and a
   presence proof, as ADR-0042's answers 12 and 20 make the Mac's own machine vault (§5). *Cost:*
   the credentials of every host become reachable by the Mac's most likely attacker, an injected
   interactive agent, one approved sheet away, and hosts' logins can be typed into the user's own
   browser (W-42).
8. **Revocation needs no presence proof, as proposed**: a `narrowing` bundle is signed while the
   personal vault is unlocked; every `state` bundle needs a presence proof (§7).

To the questions those answers raised:

9. **A Mac host's key store as proposed**: `file` hosts now, labelled; disk encryption on
   recommended, with authenticated restarts, an unplanned restart waiting for a person; encryption
   off allowed, labelled; `enclave` only after the provisioning profile and Phase 0's measurements
   (§17).
10. **Nothing is withheld from a `file` host**: shared-vault copies and the one-time-code switch are
    allowed there too, with the labels (§1, §4.2). *Cost:* other members' shared values, and a
    login's password together with the seed of its second factor, can end up in a file that anyone
    with the host's disk, a backup or its image can read on any machine — the other members learn
    of it only from the copy record, and the second factor protects nothing against whoever holds
    that file (W-37).
11. **Bundles for ephemeral hosts live at most 7 days, default 7, as proposed** (§4.3).
12. **A CI grant may bind to runner accounts alone**, with no workload token; the token binding
    stays the recommended form (§11). *Cost:* such a grant is usable by every job the CI service
    runs as that account — anyone who can have a pipeline scheduled on the runner, from any branch
    and any workflow — with nothing about the job's origin verified, so the command pins and the
    per-session and total limits are the only bounds (W-43).
13. **Token signature algorithms as proposed**: RSA with SHA-256 (PKCS #1 v1.5) and ECDSA P-256 with
    SHA-256 only, verification-only, from crates confined to `kagisecure-host`; any other algorithm,
    and unsigned tokens, refused (§11).

The ADR stays **Proposed**: the answers settle direction, not acceptance.

## Open questions

The accepted scope (above) resolves for itself: key protection (A2), bundle provenance and
contents (A3), and stdin delivery under a grant (A5). For the rest of the design: none for the
owner: the eight questions of the first draft and the five their answers raised are
answered above. What remains is measurement, recorded in this ADR when it is made:

- the three blockers of `enclave` sealing for Mac hosts (§17; the first is ADR-0011's account
  action, the other two are Phase 0 measurements) — until they clear, Mac hosts are `file` hosts;
- Phase 0's systemd, PCR 7, `SO_PEERPIDFD`, polkit and unit-hardening measurements on Linux, and
  what protects a Mac's internal storage with disk encryption off;
- Phase 5's sign-in acceptance results, per route and per browser build.

## Implementation plan

No code is written by this ADR. **Sequencing:** after ADR-0035's Phases 0–1 (the public-key crates
and the encoding contract this ADR reuses) and after ADR-0042's Phases 1–3 (the machine vault, the
engine in `kagisecure-agent`, command grants and their sheets on the Mac). Each phase ends with
something testable on its own.

- **Phase 0 — documentation and measurements.** ADR-0042 Phase 0's page, "Credentials for
  unattended jobs", gains a section for CI and hosts: option (c) first, then the profiles in order
  of strength with their true sentences. Measured and recorded in this ADR: the minimum systemd
  version for TPM-sealed credentials under a PCR 7 policy; which processes can read a unit's
  decrypted credential while it runs; what disarms under PCR 7 across kernel, firmware and Secure
  Boot database updates, on hardware and on a virtual TPM; `SO_PEERPIDFD` availability; a polkit
  rule limited to one template's instances; the engine unit's hardening, with
  `RestrictAddressFamilies=AF_UNIX` checked by a test that tries to open a network socket from
  inside it; on macOS, the three `enclave` blockers of §17 and what protects internal storage with
  disk encryption off.
- **Phase 1 — formats.** The enrolment request, the bundle (`state`, `narrowing`, with the profile),
  the inventory and the report; the `host` wrapped-key slot and a vault with no password slot in
  [vault-format.md](../vault-format.md); domain-separation strings in the style of ADR-0035's
  encoding contract; golden vectors; bounded parsers and fuzz targets; in `kagisecure-shared` or a
  sibling crate under the same dependency guard. Tests: a bundle is refused for a wrong issuer, host
  or profile, an equal or lower generation, a bad signature (before any decryption), or a
  `narrowing` payload that adds anything; an ephemeral bundle valid for more than 7 days is refused.
- **Phase 2 — the Mac.** Hosts in the app: adding a host (request, full fingerprint comparison,
  profile and its sentences, presence); the provisioning key; each host's machine vault with sheets
  that name the host and its profile; interactive use of hosts' machine vaults through the ordinary
  socket and extension listener with the ordinary sheet (answer 7); inventory import; issuer-key
  import and the CI-grant sheet; `state` and `narrowing` export; retirement and the rotation list;
  `file`-key age; report import with ADR-0041's verdicts and the per-host summary; staleness flags.
  Tests: a host's machine vault is released interactively only after a sheet and a presence proof,
  and never while the personal vault is locked; no IPC message or MCP tool reaches enrolment, export
  or a grant; for a `file` host, the copy record names its profile and the one-time-code sheet
  carries the added warning; a `runner` CI grant's sheet carries its true sentence.
- **Phase 3 — `kagisecure-host` on Linux.** `init` (profiles, checks, accounts, units, polkit rule,
  sealing or file, request); the engine; inbox and bundle apply; the scheduler; runs as template
  instances; the launcher and the run-control socket; cgroup binding; the uid gate; teardown;
  `pause`, `resume`, `inventory`, `destroy`; journal lines; reports; `serve --ephemeral`. Tests, on
  Linux with a software TPM and on one real host: a request from outside a run, or from another uid,
  is refused; a double-forked process is still recognized and still ended; the root and every
  granted command run from the descriptor that was pinned; a strike stops the unit; an engine
  restart ends every live run; a clock behind the log disarms; the canary sweep with a successful
  release, the value appearing only in `Spawn`; the enumeration test that a host's sockets accept no
  approval and no grant; under `shared`, the labels appear in every report and log entry.
- **Phase 4 — CI grants.** Token parsing and offline verification with the two algorithms of
  owner's answer 13; `token` and `runner` bindings; the CI session launcher as a subreaper; claim
  matching; single-use token ids; the CI strike; the actors and entries of §14. Tests: tokens
  refused for a wrong key, issuer, audience, an expired or too-old token, a reused id, or one
  missing claim; a matching token from a uid no grant names refused; a descendant re-parented after
  its parent exits still bound to the session; a strike suspends every grant of that CI identity; a
  tokenless session from a named account opens only `runner` grants; a token that fails verification
  refuses the session even where `runner` grants exist; a `runner` strike suspends every `runner`
  grant of that account; tokens with any other algorithm, or unsigned, are refused; the token
  appears in no log, report, journal line or sidecar byte.
- **Phase 5 — sign-ins on hosts (§15)**, after ADR-0042's Phase 5 on the Mac: the run browser in
  full headless mode and under a per-run virtual display, pipes for the debugging protocol, the
  native host gated by account, cgroup or session and ancestry. **Acceptance test:** the sign-in
  suite passes on each route with each browser build the documentation names, and the results are
  recorded in this ADR; a build that fails is documented as unsupported, and a job declaring it gets
  `FILL_UNAVAILABLE`.
- **Phase 6 — Mac hosts (§17)**: `kagisecure-host` as a launch daemon, the run broker, the ancestry
  binding, code-signing pins, `file` sealing with the disk-encryption label; `enclave` sealing only
  when owner's answer 9's conditions are met.
- **Phase 7 — shared-vault copies to hosts**: copy records that name the host and its profile
  (answer 9, owner's answer 10), refused while a vault's policy forbids copies (answer 21).
- **Not in this plan:** Windows hosts; kagisecure's own TPM code (read-locked keys, a monotonic
  counter).

**Documents that change on acceptance:** [threat-model.md](../threat-model.md) (the entries above;
M-13 and M-15 amended for hosts); [architecture.md](../architecture.md) (§2, a `kagisecure-host`
row and section; §2.6's sentence, as in §2 here; §4.2, the host's socket locations; §9, below);
[vault-format.md](../vault-format.md) (the `host` slot, a vault with no password slot);
[mcp-server.md](../mcp-server.md) (the unattended socket on hosts, CI sessions); a new operator page
for hosts and their profiles; ADR-0042 (the pointers from §15 and open question 19, already made);
and [roadmap.md](../roadmap.md), as below.

## Proposed roadmap changes

These are **proposals for the owner, not edits**: [roadmap.md](../roadmap.md) is unchanged by this
ADR.

**1. The post-v1 list** gains one bullet, after ADR-0042's:

```text
- Unattended jobs on headless hosts — Linux servers, CI runners (persistent or ephemeral),
  containers and Macs used as build hosts — each with its own machine vault, armed automatically at
  boot from a key in the host's key store (a TPM, sealed to PCR 7, recommended; a labelled key file
  otherwise), with every grant made on a Mac with a presence proof and delivered as a signed bundle
  by file; CI jobs may use grants by presenting a workload token verified offline (recommended) or,
  labelled, by running as a named runner account. Proposed in
  [ADR-0043](decisions/0043-unattended-access-on-headless-hosts.md); not accepted, not implemented;
  to follow ADR-0042.
```

**2. If scheduled**, a milestone after ADR-0042's (M12, if ADR-0042 takes M11):

```text
| M12 | Unattended jobs on headless hosts (kagisecure-host, profiles, bundles, reports, CI grants) | M11; ADR-0035 Phases 0–1 | proposed |
```

with acceptance criteria from the Phase 1–5 test lists, plus:

```text
- [ ] A `tpm` host arms itself after a reboot with nobody present, and refuses to arm when its
      sealing policy no longer matches; a copy of its state directory opens nothing elsewhere.
- [ ] Every weaker profile is shown, with its sentence, in the Mac's view of hosts, on every sheet
      for that host, and in every bundle, report and log entry about it.
- [ ] No process outside a run kagisecure started or a CI session its grant's binding admits, and
      no process of an account not named for it, can cause a release, whatever grants exist; a
      token that fails verification is never downgraded to a `runner` session.
- [ ] Nothing reaches a host except in a bundle signed by its pinned Mac; no host command, socket or
      file creates, widens, extends or re-enables a grant.
- [ ] The Linux engine's unit cannot open a network socket.
- [ ] A value seeded into a host's machine vault never appears in any byte the sidecar writes or in
      the journal, across a successful release; a workload token appears nowhere it was not sent.
- [ ] A report whose log does not contain the head the Mac last accepted is shown as a warning.
```

**3. [architecture.md](../architecture.md) §9** ("What is deliberately absent") gains:

```text
- No network code on headless hosts either. A host receives its grants and returns its log only as
  files the owner's own tools move, verifies CI workload tokens against keys delivered the same way,
  and on Linux its service runs where the kernel refuses it any network socket (ADR-0043).
```
