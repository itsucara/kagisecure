# Credentials for unattended jobs

A job that runs when nobody is at the computer — a nightly deploy, a scheduled agent that signs in
to a service and posts — needs a credential without a person to approve it. This page says where
such a credential belongs, what kind of credential to use, and what kagisecure offers for the jobs
that have to run on your Mac. The design is
[ADR-0042](decisions/0042-unattended-agent-access.md) (accepted for macOS on 2026-09-27).

> **Status.** Built on macOS (ADR-0042 Phases 0 to 5): the machine vault, the engine that runs
> jobs, the app's screens under Agent access → Unattended jobs, shared-vault copies, and unattended
> sign-ins (`request_fill` from a run, in a headless run browser, under a login grant).

## 1. First choice: keep it off this Mac

If the job does not have to run on this Mac, do not bring its credential here.

- **A job on a CI service or a hosted platform** should use that platform's own secret store —
  or, better, its **workload identity**: a short-lived token the platform mints for the job,
  which the target service trusts through federation. Nothing is stored anywhere to be stolen.
- **A CI runner** is not covered by kagisecure: use the platform's store or workload identity.
- **A headless Linux host you run yourself** (a build box, a home server) can get a deploy key or
  similar credential from kagisecure for one exact command: see §5.

kagisecure gives nothing up this way, and the credential never touches this Mac.

## 2. Choose a credential that can do little, for a short time

Whatever store holds it, prefer the smallest credential the service offers:

- **A token scoped to the one action the job performs**, not an account's full access.
- **An expiry set at the service**, so a leaked token dies on its own.
- **A dedicated service or bot account**, never a person's account, for anything that signs in.
- **Short-lived credentials the job mints itself** where the service supports it (federation,
  deploy tokens for one action), with only the long-lived material that mints them stored.

kagisecure does not mint credentials from a service: that would need network code, which it does
not have.

## 3. Jobs that must run on this Mac: the machine vault

For the rest — credentials of service accounts used by jobs that have to run on this Mac —
kagisecure keeps a **machine vault**: a separate vault file, beside your personal vault, for
machine credentials only.

- **Nothing in your personal vault, or in a shared vault, is ever used unattended.** Every release
  from them still needs you, exactly as today. Your own browsers are never filled unattended.
- **You arm the machine vault**, in the app, with Touch ID or your password. It then stays armed —
  across screen lock, sleep and restarts — until you pause it. Its key is kept in this Mac's login
  Keychain (this device only, never synced) so that jobs keep running after a restart.
- **Only jobs kagisecure starts can use it.** You define a job — a program, its arguments, its
  directory, its schedule — and kagisecure starts it at those times. A request from any other
  process, including an interactive agent session, gets nothing unattended.
- **Only under standing grants you create.** A *command grant* lets one job run one exact command,
  in one directory, with named variables from the machine vault, with no output returned. A
  *login grant* lets one job sign in with one machine-vault login at one exact https origin, in a
  browser kagisecure launches for that run. Grants have limits per run and in total and an expiry
  of at most 90 days, and anything unexpected — a request no grant covers, a changed executable,
  a changed value — suspends every grant of that job until you re-create it.
- **Agents never create or widen a grant.** No tool and no message does.
- **You see what happened** when you come back: a summary of runs, releases, refusals and
  suspensions, and local notifications for suspensions. Nothing is sent anywhere.

### Setting up a job

1. In Agent access → **Unattended jobs**, choose **Add an Environment…** and pick the personal
   environment whose values the job needs. Its current values are copied into the machine vault
   (Touch ID). Change a value later in your personal vault, then press **Update** on the copy.
2. Choose **New Job…**: the program to start, its arguments, the folder it runs in, when it runs,
   and the environment. By default the job may run its own program with those variables: then
   kagisecure **starts the program with them already in its environment**, so a plain script just
   reads `$TOKEN` and needs nothing else. Switch that off to name the one command it may run
   instead — for an agent, the deploy tool it calls — whose values are released only when the
   job asks for that command. **Create** asks for Touch ID; the job and its grant are created
   together.
3. Choose **Arm…** (Touch ID). The first arm creates the machine vault if there is none yet. Jobs
   now run on schedule, and keep doing so across restarts until you press
   **Pause** — here or in the menu bar. The first time you arm, Kagisecure adds itself to your
   Login Items so it is running after a restart; the "Open Kagisecure at login" checkbox turns that
   off.
4. A job whose grant is for another command finds kagisecure through `KAGISECURE_SOCKET`, which
   kagisecure sets for it; an agent started as the job uses the kagisecure MCP server as usual,
   and its `run_with_env` call is served under the grant. Output is never returned unattended: have the command write
   what you need to a file.

### Values from a shared vault

A shared vault's environment can be copied too, from the same **Add an Environment…** menu, unless
an admin of that vault turned unattended copies off. Every member sees that your Mac holds the
copy, and which variables. An environment with a variable bound to a login's password is never
copied: give the job an account of its own. When someone changes a value at its source, the copy
is marked; it keeps the value it was copied with until you press **Update**.

### What goes in it

API tokens, deploy keys, database URLs and service-account keys a job uses, and the sign-ins of
dedicated service or bot accounts. A website on a machine-vault item is one exact https origin,
such as `https://service.example`; one-time-password seeds are never released as such, only a
code into a sign-in, and only if a login grant's one-time-code switch is on.

## 4. What unattended use costs

These sentences are the honest ones, and the sheets that create grants carry them:

> kagisecure still never gives an agent a value. Under a standing grant, it hands a machine
> credential to a command you pinned, at times you scheduled, with nobody watching — and anything
> that can change what that command does while you are away can obtain that credential.

> Under a login grant, kagisecure types a service account's password into one site, in a browser it
> started for this job, with nobody watching. The job's agent can read what is typed there: treat
> the account as one the agent holds.

In more detail:

- **The grant is your last decision.** Nobody reads a sheet at release time; what you approved
  once covers every later release it matches.
- **A program started with its variables keeps them for the whole run**, and so does everything
  it starts. Prefer a grant for one command when the program is an agent that runs tools you
  do not control.
- **A command is defined by files your account can write.** kagisecure pins the executable and the
  input files you name; it cannot pin everything the command reads. A grant for a shell, an
  interpreter or a package runner is a grant for whatever script it reads.
- **An unattended sign-in hands the login to the job's agent.** Whatever steers that agent can read
  the password it just had filled, and send it anywhere. The account's own scope is the real
  bound, and after any suspension you should reset its password at the service — kagisecure
  advises it and cannot check it.
- **With the one-time-code switch on, the account has one factor** against anything on this Mac.
- **Armed means armed, even after a restart.** A Mac that is stolen, or restarted by someone
  else, keeps releasing machine credentials to the jobs you defined as soon as a session starts;
  with FileVault, nothing runs after a cold restart until someone logs in. A program running as
  you that can read the Keychain item holds the whole machine vault. Pause when you do not need
  it.
- **The machine vault has no recovery of its own.** Its key lives in your personal vault;
  recovering your personal vault recovers it, and losing your personal vault loses it.

The full list of what this weakens is in [threat-model.md](threat-model.md) (W-23 to W-29, and
"Unattended jobs: limits of the convenience-first choices").

## 5. Headless hosts: `kagisecure-host`

A host with no person and no app — a home server, a build box — runs `kagisecure-host`
([ADR-0043](decisions/0043-unattended-access-on-headless-hosts.md), accepted 2026-10-07 for this
use). It holds no personal vault and never asks anyone anything: everything it releases comes from
a **bundle** you sign on your Mac, and it releases a value only to start one exact command you
granted, writing the value to that command's standard input.

**Built for:** a deploy script that reads its SSH key from standard input (the frame
`NAME\0VALUE\0`, as `run_with_env`'s stdin delivery writes it), run on the host by an operator or
by an agent there. Not built: CI runners, sign-ins, schedules on the host.

### Setting it up

On the Mac:

1. `kagisecure host-bundle owner-key` — prints your owner key and its fingerprint (and creates
   this Mac's device key in your personal vault if it has none).
2. Put the credential in a personal environment and copy it to the machine vault (Agent access →
   Unattended jobs → **Add an Environment…**).
3. Write a grants file (JSON, kept off the repository):

   ```json
   { "grants": [ {
       "name": "deploy-staging",
       "variables": ["ITSUSTAR_DEPLOY_SSH_KEY"],
       "command": ["/home/op/project/infra/deploy/deploy", "staging", "{commit}", "--key-from-stdin"],
       "working_dir": "/home/op/project",
       "run_as": "op",
       "hash_from": "/Users/me/Workspace/project/infra/deploy/deploy",
       "timeout_secs": 3600
   } ] }
   ```

   `command` is the exact command line on the host. `{commit}` matches exactly 40 lower-case hex
   digits and nothing else; every other argument is literal. The executable is pinned by SHA-256:
   `executable_sha256` (hex), or `hash_from`, a copy of the same file on the Mac at the same
   commit. Optional: `total_uses` (default 500), `expires_in_days` (default and maximum 90).

On the host (Linux with systemd):

4. Build and install: `cargo build --release -p kagisecure-host`, then
   `sudo install -m 0755 target/release/kagisecure-host /usr/local/bin/`.
5. `sudo groupadd --system kagisecure`, and `sudo usermod -aG kagisecure <operator>` for each
   account allowed to ask.
6. `kagisecure-host systemd-unit | sudo tee /etc/systemd/system/kagisecure-host.service`, and add
   the operator's tool directories to its `Environment=PATH=` line if the command needs them.
7. `sudo kagisecure-host init --owner <owner key>` — creates the host key and prints the host key
   and fingerprint. Check that the owner fingerprint it prints is the one from step 1.

On the Mac:

8. `kagisecure host-bundle export --host <name> --host-key <host key> --environment <env>
   --grants grants.json --out host.kgsb` (master password), and copy `host.kgsb` to the host.

On the host:

9. `sudo kagisecure-host import host.kgsb`, then `sudo systemctl enable --now kagisecure-host`.
   `sudo kagisecure-host status` lists the grants; `sudo kagisecure-host audit` the log.
10. The command is now run as `kagisecure-host request <grant> -- <argv...>` from its working
    directory, by a member of `kagisecure`. The host checks the request against the grant, logs
    it, starts the command as `run_as` with the value on its standard input, and prints its
    masked output and exits with its code when it ends.

### What it guarantees, and what it does not

- **Only the owner's Mac can give a host anything.** A bundle is sealed to the host's key and
  signed by your device key; the host refuses a bundle from any other signer, for another host,
  altered in any byte, or not newer than the one it holds. A new bundle replaces everything and
  resets uses and suspensions.
- **Only what you granted travels.** A bundle carries only the variables its grants release.
- **One exact command.** A request with another executable, another argument, an extra argument or
  another directory is refused and **suspends** the grant; so does a change to the executable's
  bytes. A suspended grant stays suspended until you export a new bundle. Pulling a commit that
  changes the pinned script therefore needs a new bundle.
- **Never in an environment, an argument, a log or the host's files.** The value is written once to
  the command's standard input; the audit log, the state file and the response hold no value, and
  the bundle at rest is ciphertext.
- **The key rests in a file only root can read** (`/var/lib/kagisecure-host/host.key`, `0600`), or
  — optionally — in a TPM-sealed systemd credential (`systemd-creds encrypt --with-key=host+tpm2`
  to `/etc/kagisecure-host/host.key.cred`, and the unit's `LoadCredentialEncrypted=` line). **Root
  on the host holds every value bundled for it.**
- **The grant pins the command, not everything it runs.** The interpreter, `git`, `ssh`, the
  operator's own configuration are files the operator or root can change; anything that can change
  what the command does can obtain the value.
- **The service runs as root** so that the command it starts, as the operator, keeps no
  capability; its unit is hardened only as far as a deploy still works (read-only system, private
  `/tmp`, no new privileges).
