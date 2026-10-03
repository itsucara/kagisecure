# Windows port — handoff notes

Status, as first written: **only the C# binding prerequisite has been done** (§4: ADR-0003
settled, a minimal P/Invoke proof under `apps/windows/`); there was no Windows app yet. This
document exists so the session that eventually picks this up does not have to re-derive what a
prior survey already found. It is a handoff, not a proposal — the decision to defer Windows was
already made, twice, and is recorded below before anything else.

**Update, 2026-09-25 — no longer accurate, kept for the historical record above rather than
rewritten:** there is now a WinUI 3 app shell (`apps/windows/Kagisecure.App`, see its own `README`
for what is real and what is stubbed), Authenticode peer verification (Tier 2, ADR-0032), and a
release pipeline (`cargo xtask dist-windows`, §7 below, ADR-0034). Tier 3 is still not the full
rewrite §2's estimate describes — the app shell covers first-run, lock, a read-only item list and
the generator, not editing, agent access or import — so treat "there is no Windows app yet" as
false and "Tier 3 is a genuine UI project, not a logic-plus-UI project, and still 8,200 lines of
hand-written Swift's worth of work" as the part of §2's Tier 3 paragraph that is still true.

## 0. This was already decided

From [roadmap.md:22-24](roadmap.md):

> **Platform decision (2026-09-09):** kagisecure is macOS-first. The product is modeled on
> 1Password 8's desktop look and feel (see [ui-spec.md](ui-spec.md)) and is single-user, no
> teams/sharing. Windows (formerly M4) and iOS are demoted to unscheduled optional work — see
> "Optional / later" below — so they no longer occupy numbered slots or block anything.

And from [roadmap.md:832-836](roadmap.md), the "Windows app (optional / later, formerly M4)"
section:

> Deferred indefinitely pending macOS completion — no Windows milestone is scheduled until M3–M7
> ship. `kagisecure-core` and the vault format stay platform-agnostic and sync-ready in the
> meantime (per [architecture.md](architecture.md) and [vault-format.md](vault-format.md) §9), so
> this work is not blocked when it eventually starts; it is simply not being built now.

The practical consequence of that second quote: nothing about the core, the vault format, or the
IPC protocol needs to change to make Windows possible. What's missing is entirely in the platform
integration layer, described below. Nobody needs to re-litigate *whether* to build a Windows app
in this document — only *what it takes* when someone decides to.

## 1. What already exists

More groundwork is in place than "no work has started" suggests. Specifically:

- **`crates/kagisecure-ipc/src/endpoint.rs`** already has a Windows arm. `Endpoint::default_endpoint`
  is `#[cfg(windows)]`-gated (line 63) and produces `Endpoint::Namespaced(format!("kagisecure-{user}.sock"))`
  using the `USERNAME` env var; the non-Windows path (line 69) is Unix-domain-socket-based. The
  doc comment above `discover()` (around line 50) already documents the Windows naming scheme:
  "the named pipe `kagisecure-<user>.sock`".
- **A host can now name a Windows endpoint, and a path is refused rather than accepted.** Added
  after this document's first draft, so the paragraph above understates it: the Windows arm of
  `endpoint.rs` was reachable only through `default_endpoint()`. Anything that named a *specific*
  location handed over a `PathBuf` — `AgentConfig::socket_path`, `ExtensionConfig`'s two path
  fields, `kagisecure daemon --socket`, `KAGISECURE_SOCKET`, `agent_start(socket_path:)` — which
  became `Endpoint::Path` and then failed at `bind` with `Unsupported: "not a named pipe path"`,
  because `to_fs_name::<GenericFilePath>()` on Windows accepts only strings already shaped like
  `\\HOST\pipe\NAME` (`interprocess-2.4.4/src/os/windows/local_socket/name_type.rs:22-28`). Those
  features were documented and completely non-functional on Windows.

  The seam now is: `Endpoint::parse(&OsStr)` reads a user-supplied override — a path on Unix, a
  pipe name on Windows, refusing anything else with a sentence naming the value and what the
  platform accepts; `Endpoint::for_instance(dir, label)` builds an endpoint for one instance of
  the program (a socket in `dir` on Unix, a uniquely-named pipe on Windows), which is what the
  test harnesses and a second vault use; `Endpoint::as_override()` writes one back out for
  `--socket`/`KAGISECURE_SOCKET` when handing it to a child process; and the config structs take
  `Option<Endpoint>` rather than `Option<PathBuf>`, so an in-process host chooses which kind of
  endpoint it means. A path is deliberately **not** synthesized into a pipe name: two directories
  holding the same file name would collapse onto one pipe, merging two vaults' listeners.

  The uniqueness `for_instance` gives on Windows prevents collisions *between our own listeners*.
  It is not an access boundary; the pipe's owner-only DACL is (see "Resolved" in §2 Tier 1),
  and this change is what made that DACL load-bearing.
- **`crates/kagisecure-agent/src/bundle.rs`** already handles `.exe` suffixes: `SIDECAR`, `NMHOST`,
  and `CLI` each have a `#[cfg(windows)]` const ending in `.exe` (lines 24-39) alongside the
  non-Windows const without the suffix.
- **`interprocess` 2.4.4** (pinned; see `Cargo.lock`) already abstracts Unix domain sockets and
  Windows named pipes behind one `local_socket` API, and already exposes a trustworthy peer pid on
  Windows: `Stream::peer_creds()` calls `GetNamedPipeClientProcessId` under the hood
  (`src/os/windows/named_pipe/stream/impl.rs` in the vendored crate). Confirmed directly by reading
  the crate source at `~/.cargo/registry/src/.../interprocess-2.4.4/`, not just from our own
  comments about it.
- **`crates/kagisecure-ipc/src/kernel_peer.rs`** — this module exists because macOS's `xucred`
  carries no pid, so a raw `getsockopt(LOCAL_PEERPID)` shim is needed there.

  **Correction:** this bullet used to describe a single combined "Windows/BSD arm," gated by
  `#[cfg(not(any(target_os = "macos", target_os = "linux")))]` around lines 150-158, that was
  nothing but a `peer_pid` stub returning `None` on both platforms. That was accurate before
  `a5e3a51`. It is not the shape of the file after `a5e3a51`, which gave Windows its own dedicated
  `#[cfg(windows)] mod imp` (line 177) — no longer a stub. Restated for the file as it now stands:

  Windows has its own module (`#[cfg(windows)] mod imp`, line 177). Its `peer_pid` (line 193) is
  still a one-line stub returning `None`, with a doc comment (lines 190-192) giving the same
  reason as before — `interprocess`'s `peer_creds()` already reports a trustworthy pid via
  `GetNamedPipeClientProcessId`, so this module has nothing to add there. But the rest of that
  module is no longer a stub: it also has `executable_path` (line 227, `QueryFullProcessImageNameW`
  — see §2 Tier 1) and `parent_pid` (line 270, `CreateToolhelp32Snapshot` — see §2 Tier 2), plus
  the `OwnedHandle` RAII wrapper both depend on.

  The BSD-only fallback that the old bullet lumped in with Windows is now genuinely BSD-only: its
  guard (line 307) is `#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]` — it
  gained the `windows` exclusion once Windows got its own arm above — and its `peer_pid` stub
  (line 314) is at what used to be "around lines 150-158." Its doc comment (lines 311-313) was
  reworded to match: "The BSDs need no kernel-FFI shim here," not "neither Windows nor the BSDs."

  **Note for whoever picks this up, kept from the original bullet:** an earlier version of the
  comment on this module reportedly claimed the opposite of the `peer_pid` reasoning above (that
  Windows had no such mechanism and would need its own shim). That claim was wrong and was already
  corrected before `a5e3a51`; §6 records that this specific historical claim was never
  independently verified against `git blame`. If you see stale claims like that anywhere else,
  they're wrong the same way this one was — and, as of this correction, that now includes this
  document's own prior wording about which arm is Windows and which is BSD.

None of this makes the port easy, but it means the IPC transport layer and the executable-naming
convention are not blockers — they're done.

## 2. The three tiers, with honest effort estimates

These are rough, not committed dates — nothing about Windows is scheduled (see §0). Treat the
estimates as "this is roughly the shape and size," not as a plan to hold anyone to.

### Tier 1 — CLI + MCP sidecar, no GUI

**Roughly 2-3 weeks.** This is the smallest slice that gives Windows users a working `kagisecure`
CLI and an MCP server an agent can talk to, with no native app. (Two of the four items originally
counted toward this estimate turned out to already be done by the time this document was written
— see the correction below — and are replaced by three narrower gaps the original survey missed.
The net size of the slice looks about the same to whoever is writing this correction, but that's a
judgment call, not a re-measurement; if it's wrong, revise the number rather than trust this
parenthetical.)

**Correction (written the same day as the original survey, after the fact):** the blocker list
below was drafted from a survey taken *before* commit `a5e3a51` applied two fixes later in that
same commit. As originally written, this section said there was no Windows implementation
resolving a pid to an executable path, and that `config_path` fell through to a Linux XDG path on
Windows. Both statements were true when the survey was taken and are false as of `a5e3a51` — see
"Resolved since the original survey" at the end of this section for exactly what landed and where.
Left uncorrected, this section would have sent whoever picks this up to redo work that is already
done. The blockers below are the ones that are actually still open.

Blockers:

- **What the access-control work did not close.** The named-pipe DACL, the same-user gate, and
  the owner-only ACL on the vault, `.env` and import report — the first three blockers this list
  used to carry — are built; see "Resolved" below for exactly what landed. What is still open
  about that boundary, none of it hidden in the code's own comments either:
  - **No second account has ever been refused.** Every test reads a descriptor back
    (`GetSecurityInfo`) and asserts its exact shape: owner = the user, DACL protected, one allow
    entry, `FILE_ALL_ACCESS`, the user's SID. That another account is then refused follows from
    Windows' access check; it has not been observed, because it needs a machine with two
    accounts. Until someone connects to the pipe and opens a vault as a second user and is
    refused, treat the boundary as correct-by-construction, not tested.
  - **The impersonation restriction has only been observed from our own account.** Clients now
    open the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (see "Resolved" below),
    and a test reads the level a server actually gets back as `SecurityIdentification` — but the
    server in that test is this same account. No squatter holding `SeImpersonatePrivilege` has
    tried, and failed, to act as a client; that follows from the documented meaning of the
    level, untested.
  - **The server's SID check goes through a pid.** `peer_is_same_user` resolves the peer via
    `GetNamedPipeClientProcessId` → `OpenProcess` → token. A connection that outlives the process
    that made it (an inherited or duplicated handle) could be judged by whatever process reuses
    that pid. It sits behind the DACL, which keeps other accounts from connecting at all.
  - **Elevation mismatches are untested.** A non-elevated agent reading the token of an elevated
    client of the same user (or the reverse) is expected to work — `PROCESS_QUERY_LIMITED_INFORMATION`
    is granted across integrity levels — but if `OpenProcessToken` is refused there, the gate
    fails closed and that client is turned away. Not observed either way.
  - **Paths longer than `MAX_PATH`.** `windows_acl` passes paths to `CreateFileW` /
    `CreateDirectoryW` as given, without the `\\?\` prefix `std` adds, so a vault or `.env` path
    over 260 characters now fails to be written (loudly) where `std` would have written it.

Resolved since the original survey — kept here for the record rather than deleted, because these
were correctly identified as missing when the survey was taken:

- ~~Windows shell quoting in the Claude Code setup snippet.~~ **Done, in the Windows-port session
  that resolved the three items below it.** `crates/kagisecure-agent/src/setup.rs::snippet_for`'s
  `SetupClient::ClaudeCode` arm used to interpolate the sidecar path unquoted, which a Windows
  install path with a space in it (`C:\Program Files\...`) would have turned into two arguments.
  The decision this bullet deferred — which shell the snippet targets — is now made at compile
  time rather than guessed at render time: `quote_for_shell` targets PowerShell on a Windows build
  (single-quoted, `'` doubled to `''`, no `&`-call operator since the path is an argument to
  `claude` rather than the command itself) and a POSIX shell everywhere else (bare when the path
  has no POSIX-special characters, single-quoted with `'\''` otherwise). Documented at the call
  site in `setup.rs` and in [docs/mcp-server.md](mcp-server.md) §9, next to the snippet itself.
- ~~`executable_for_pid` via `QueryFullProcessImageNameW`.~~ **Done, in `a5e3a51`.**
  `crates/kagisecure-ipc/src/kernel_peer.rs` now has a `#[cfg(windows)]` `imp::executable_path`
  (line 227) built on `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
  `QueryFullProcessImageNameW`, with a 32K-wide-char buffer (sized for long-path systems, not
  `MAX_PATH`) and an `OwnedHandle` RAII wrapper that closes the process handle on every return
  path. `crates/kagisecure-ipc/src/server.rs::executable_for_pid` (line 300) has a
  `#[cfg(windows)]` arm (line 313) calling it. Peer-identity checks on Windows no longer fall back
  to UNVERIFIED for want of this half.
- ~~`%APPDATA%` for the Claude Desktop config path.~~ **Done, in `a5e3a51`.**
  `crates/kagisecure-agent/src/setup.rs::config_path` (line 177) now has a `#[cfg(windows)]` arm
  (line 198) using `directories::BaseDirs::config_dir()` joined with
  `Claude/claude_desktop_config.json` — `%APPDATA%`, the roaming folder (`FOLDERID_RoamingAppData`),
  not `%LOCALAPPDATA%`, per the arm's own comment. The old `#[cfg(not(target_os = "macos"))]`
  catch-all that used to route Windows through the Linux `~/.config` branch is gone.
- ~~Named-pipe DACL on bind, and the same-user gate that depends on it.~~ **Done** (no commit
  hash yet at the time of writing — the change that added `kagisecure_core::windows_acl`). Both
  `bind_listener`s — `crates/kagisecure-ipc/src/server.rs` and
  `crates/kagisecure-extension-ipc/src/listener.rs` — now pass
  `kagisecure_ipc::server::owner_only_pipe_descriptor()` to
  `ListenerOptionsExt::security_descriptor`: `O:<user SID>D:P(A;;FA;;;<user SID>)`, parsed by
  `interprocess`'s own `SecurityDescriptor::deserialize`, deliberately without a `G:` component
  (`interprocess` 2.4.4's descriptor clone writes a group SID into the *owner* slot,
  `src/os/windows/security_descriptor/try_clone.rs`). Before this, the pipe had the default
  descriptor — read back on this machine as full control for SYSTEM, Administrators and the
  owner, and `FILE_GENERIC_READ` for Everyone and Anonymous. Earlier drafts here and in
  `threat-model.md` called that "a null security descriptor … no DACL at all"; it was a DACL,
  just not one this project chose or checked. Whether another account could actually have
  connected through it (a client asks for read *and* write) was never tested either.

  **Why not SYSTEM and Administrators too**, which the old sketch on `Endpoint::prepare_dir`
  included: an Administrators entry would let every elevated process of every admin account read
  the vault as a matter of course, and it buys nothing — SYSTEM and administrators reach any file
  anyway through backup/restore/take-ownership privileges, deliberately and auditably. The full
  reasoning is in the `windows_acl` module doc.

  `peer_is_same_user` now takes `(peer_euid, peer_pid)` and **fails closed on Windows**: it
  compares the user SID in the peer process's token (`kernel_peer::process_user_sid`:
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `OpenProcessToken` → `TokenUser`) with this
  process's, and answers `false` for no kernel pid, an unreadable token, or a different SID. Its
  callers in `kagisecure-agent` pass the kernel pid only (`PeerIdentity::kernel_pid`, and
  `HostIdentity::pid`, which is always the kernel's).

  **Pipe squatting**, which the original bullet did not mention: a named pipe's name is
  first-come, first-served across accounts. Server side, `interprocess` already creates the
  first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  (`src/os/windows/named_pipe/listener/create_instance.rs`), so our bind fails rather than joining
  a pipe someone else created; further instances need `FILE_CREATE_PIPE_INSTANCE`, which our DACL
  grants to the user alone. Client side, `kagisecure_ipc::client::server_is_same_user` reads the
  **owner** of the pipe the client reached (`GetSecurityInfo` on the client handle — a property
  of the object, so no pid-reuse window) and both `kagisecure_ipc::Client::connect` and
  `kagisecure_extension_ipc::Client::connect` refuse a foreign one (new `ForeignServer` error
  variants) before sending anything. `GetNamedPipeServerProcessId` was reachable too
  (`peer_creds()` on a client stream) but was not used: it has the pid-reuse window the owner
  check does not. Impersonation, which this check alone could not stop, is the next bullet.

  Tests: `server::tests::the_pipe_is_created_owner_only` and
  `listener::tests::the_pipe_is_created_owner_only` read each pipe's descriptor back through a
  connected client handle and assert exactly one allow entry for the user plus the protected
  flag and the owner; `server::tests::the_same_user_gate_compares_token_sids_on_windows` checks
  our own pid is accepted and a missing pid, a nonexistent pid and pid 4 (System) are refused.
- ~~Clients do not restrict impersonation.~~ **Done** in 3ff5477, and corrected after it (see
  "The first version reopened the handle" below). `interprocess` 2.4.4 opens a pipe with
  `CreateFileW` and no `SECURITY_SQOS_PRESENT`
  flags (`src/os/windows/named_pipe/c_wrappers.rs`, `connect_without_waiting`), which grants the
  server end `SecurityImpersonation`: a squatter holding `SeImpersonatePrivilege` (a service
  account, not an ordinary user) could act as the client between the connect and the owner check
  above, which needs no bytes to have been sent. Every client-side open in the workspace now goes
  through `kagisecure_ipc::connect::open` instead — both `Client::connect`s (so the CLI, the MCP
  sidecar and the native host), the bind-error probe, and the Unix corpse-socket probes in both
  `bind`s — which calls `CreateFileW` itself with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`
  and returns a `connect::ClientStream`: on Windows a synchronous handle read and written through
  `std::fs::File`, on Unix `interprocess`'s stream as before. Identification rather
  than anonymous so that a server can still read the client's token off the connection, which is
  what closing the pid-reuse window below would need; the `connect` module doc gives the whole
  reasoning. The same function bounds the busy-pipe wait (`PIPE_BUSY_WAIT`, 2 s) that
  `interprocess` leaves unbounded; the extension client already had that bound (82195bf), and now
  shares it rather than keeping its own copy.

  Tests: `connect::tests::a_server_can_identify_our_client_but_not_impersonate_it` has the server
  end read one byte, `ImpersonateNamedPipeClient`, and read `TokenImpersonationLevel` off the
  thread token: `SecurityIdentification` for our client, and — the control — `SecurityImpersonation`
  for a stream `interprocess` opened itself. Not tested: a real second-account squatter (see the
  open bullet above).

  **The first version reopened the handle, and that was wrong.** 3ff5477 opened the handle
  overlapped and handed it to `interprocess` through `DuplexPipeStream: TryFrom<OwnedHandle>`,
  and said here that the conversion's `ReOpenFile` was harmless because the test above read the
  level after it. It was not harmless; that test just never lost the race. On a named-pipe
  client, `ReOpenFile` does not reopen the same connection: it opens a **new** one to whichever
  instance is free, with default flags — so `SecurityImpersonation` again — and the conversion
  then closes the original. If the server's accept had already returned and created its next
  instance, that is what happened: the accepted connection read end-of-stream before its first
  frame, and the client went on talking, at impersonation level, over a connection the server
  had not accepted yet. If not, the reopen failed with `ERROR_PIPE_BUSY` and `interprocess`
  silently kept the original, which is why it looked fine most of the time. It surfaced as
  `the_native_host_exits_when_the_port_closes_even_while_the_app_is_silent` failing about one run
  in five (its app thread accepts exactly once). Measured with a probe: server accepts, then the
  client converts, then writes — the accepted connection read 0 bytes, and the level on the
  second connection read back as `SecurityImpersonation`. `interprocess` has no other public way
  to build a pipe stream from a handle, hence `ClientStream`. The regression test,
  `connect::tests::the_connection_open_returns_is_the_one_the_server_accepted`, runs 50 rounds
  with the server already parked in `accept`; against the old conversion it failed at round 29,
  and it passes against `ClientStream`. A real browser would have been affected too: the app's
  accept loop would have served the second connection, so fills worked, but at impersonation
  level in the losing case, with a phantom connection logged before it.
- ~~Stopping a listener did not release its pipe, so the next unlock's bind failed or hung.~~
  **Done** for both channels: the extension's in 82195bf, the MCP agent's afterwards (no commit
  hash yet at the time of writing). A named pipe's name lives as long as any server-side instance
  of it is open, and a stop joined only the accept thread, leaving each connected client's
  serving thread parked in a read with its instance open. The restart's bind was then refused
  (`ERROR_ACCESS_DENIED` under `FILE_FLAG_FIRST_PIPE_INSTANCE`), and
  `Endpoint::classify_bind_error` probed the name with `interprocess`'s unbounded connect, which
  waited forever behind that same busy instance — 39 minutes on the extension channel's test
  before anyone killed it. The app calls both `*_stop`s on lock and both `*_start`s on unlock, so
  with a sidecar or a browser connected an unlock would have frozen. Now:
  - `kagisecure_ipc::sever` (moved there from `kagisecure-extension-ipc`, which re-exports it)
    holds each accepted connection's handles in `Closing`, which closes them where they are
    dropped rather than in `interprocess`'s linger thread, and hands out a `Severer`
    (`DisconnectNamedPipe` on a duplicate handle) per connection. `LiveConnections` is the
    registry a stop severs and then waits on, for at most 2 s. `Agent::stop` uses it; the
    extension agent still has its own copy of the same registry.
  - `serve_connection` re-checks `stopping` after each read, so a request that wins the race
    against the severing is not served by a stopped agent — on Unix too, where the stale
    connection used to be served on the sidecar's next call.
  - `classify_bind_error` probes once, through `kagisecure_ipc::connect`, and takes a busy name
    as occupied — `ERROR_PIPE_BUSY` only comes back for a name that exists — so a refused bind
    is now reported (`AlreadyBound`) at once instead of hanging.

  Tests: `crates/kagisecure-agent/tests/agent_restart.rs` stops the agent with a sidecar parked
  in a read, restarts it on the same endpoint under a 60 s hard deadline, and asserts the bind
  succeeds within 10 s, the old connection is not served, and a new connection is. Before the
  fix it hit the deadline (the probe's unbounded wait); with only the probe bounded it failed at
  once with `AlreadyBound`; with the fix it passed 10 consecutive runs on Windows 11, the stop
  taking 3-23 ms and the restart's bind under 0.3 ms. What stays open: a stop that comes while a request is still *working* (in practice
  `run_with_env` waiting on its command) cannot hurry it; the connection is severed, but its
  handle keeps the name until the command returns, and a restart in that window is refused as
  `AlreadyBound`. Unix has been compile-checked and clippy-checked only for this change, not run.
- ~~An owner-only ACL for the vault, the `.env` and the import report.~~ **Done**, in the same
  change as the named-pipe DACL above. `crates/kagisecure-core/src/windows_acl.rs` (Windows-only; the one module in
  `kagisecure-core` allowed `unsafe`, which is why the crate attribute is now
  `forbid(unsafe_code)` everywhere but Windows and `deny` there) creates files with the
  descriptor as part of the `CreateFileW` call (`CREATE_NEW`, `FILE_FLAG_OPEN_REPARSE_POINT`, as
  `std` does for `create_new`), so no byte is written before it applies — the same property the
  Unix `OpenOptionsExt::mode` path has. `write_atomically` uses it for the temporary vault file
  (the rename keeps it) and `windows_acl::create_dir_all` for any directory it creates (same
  entry, inheritable: `OICI`); `envfile::write` uses it for the temporary `.env`; and
  `import::write_report` uses `create_or_truncate_file`, which for an existing file replaces the
  DACL *before* truncating it and refuses to write if it cannot. An existing directory's ACL is
  left alone on purpose: rewriting it would propagate down every file under it, and a Windows
  directory's DACL does not stop a user who knows a file's path anyway (Bypass traverse
  checking) — each file's own DACL is the boundary. Checked with `icacls` once by hand as well as
  by tests (`windows_acl` unit tests, `tests/vault.rs`, `tests/adversarial_vault.rs`,
  `envfile::tests::the_file_is_owner_only_on_windows_too`,
  `import::tests::a_report_can_be_rendered_as_json_and_as_a_0600_file`).
  **Update, 2026-09-26 (merging `feat/vault-transactions`):** that branch added a fifth file, the
  vault's sibling `<vault>.lock` ([ADR-0039](decisions/0039-transactional-vault-writes-and-the-lock-file.md)),
  and takes it *before* a new vault's first write — so as merged it created the vault's directory
  with an inherited ACL, which `write_atomically` then found existing and left alone. The lock now
  opens its file with `windows_acl::open_or_create_file` (`OPEN_ALWAYS`, the owner-only descriptor,
  still no `FILE_SHARE_DELETE`) and creates missing directories with `windows_acl::create_dir_all`.
  Tests: `vault::lock::tests::the_lock_file_and_the_directory_it_created_are_owner_only` and the
  lock-file assertion in `tests/adversarial_vault.rs`. Compile-checked for
  `x86_64-pc-windows-msvc`; **not run on Windows yet**.

### Tier 2 — plus the browser extension

**Roughly 6-8 further weeks on top of Tier 1.** This is where the native-messaging host and
autofill become usable from a Windows browser.

Blockers:

- **`CreateToolhelp32Snapshot` ancestry walk**, to replace the `/bin/ps`-based process-ancestry
  check the macOS path uses to confirm which browser process is asking for a fill. Without this,
  every extension fill request has to be refused, because there is no way to verify the calling
  process's parentage.
- **Windows browser executable names** — Chrome, Edge, and any other supported Chromium browser
  ship under different binary names and install paths on Windows than on macOS; the allowlist of
  expected executables needs a Windows-specific table.
- ~~**Registry-based native-messaging registration**~~ **Done**, on the `browser_setup` side —
  `crates/kagisecure-agent/src/browser_setup.rs`'s `windows_all_manifests`,
  `windows_registry_vendor`, `windows_manifest_path` and the `windows_registry` module (the crate's
  one `#[allow(unsafe_code)]` corner) write each Windows Chromium browser its own manifest file
  under `%LOCALAPPDATA%\Kagisecure\NativeMessagingHosts\` and set/clear
  `HKCU\Software\<vendor>\NativeMessagingHosts\<host name>` — `HKCU` only, never `HKLM`, per this
  bullet's own original note. `KnownBrowser::installable()` includes `Arc`, but this is offered
  only for Chrome, Edge, Brave and Chromium: Arc's own Windows registry vendor fragment was not
  confirmed against primary documentation, and an unconfirmed guess seemed worse than an honest
  gap (`windows_registry_vendor`'s doc comment says so in more detail). The "here is the exact
  file, and here is where" setup-UI affordance this bullet flagged as needing rethinking is
  addressed at the data-model level — `BrowserManifestView` gained a `registry_key` field the
  screen can show alongside `path` — but the actual Swift screen text was not rewritten as part of
  this change, since no Windows UI exists yet to rewrite; whoever builds the Tier 3 Windows UI
  still has that copy to write. **Still open, and not attempted here:** the browser executable
  names and `CreateToolhelp32Snapshot` ancestry walk below, both of which the actual *fill* path
  (as opposed to registration) still needs. (Authenticode verification, listed here originally,
  has since been built; see its own bullet.)
- **`CreateToolhelp32Snapshot` ancestry walk**, to replace the `/bin/ps`-based process-ancestry
  check the macOS path uses to confirm which browser process is asking for a fill. Without this,
  every extension fill request has to be refused, because there is no way to verify the calling
  process's parentage.
- **Windows browser executable names** — Chrome, Edge, and any other supported Chromium browser
  ship under different binary names and install paths on Windows than on macOS; the allowlist of
  expected executables needs a Windows-specific table. (`browser_setup::windows_browser_installed`,
  added alongside the registration work above, has a small table of its own — `chrome.exe`,
  `msedge.exe`, `brave.exe` — but it is used only for an "is this installed" *hint* on the setup
  screen, checked via each browser's `App Paths` registry entry. It has not been wired into, and
  was never intended to replace, the ancestry-walk allowlist a real fill request's peer
  verification needs.)
- ~~**Authenticode verification** of the calling browser binary, as the Windows analogue of the
  macOS code-signature check.~~ **Built, and weaker than macOS by design** —
  [ADR-0032](decisions/0032-authenticode-peer-verification.md).
  `crates/kagisecure-ipc/src/authenticode.rs` (`verify_peer`, `verify_browser`; the crate's second
  reviewed `unsafe` exception after `kernel_peer`) checks a pid against one of two requirements:
  **same signer as this build** (leaf certificate public key equal to the one that signed the
  module the code runs in — `kagisecure_ffi.dll` in the app) for the sidecar and the native host,
  and **a named publisher** for browsers, from one table (`KNOWN_BROWSERS`: `chrome.exe` → "Google
  LLC", `msedge.exe` → "Microsoft Corporation", `brave.exe` → "Brave Software, Inc.", the last not
  confirmed on a real install). It holds the process handle for the whole check (pid reuse),
  requires the image path to equal the path on the request, pins the file with `FILE_SHARE_READ`
  only, verifies through that handle, and re-reads the path and liveness afterwards. Embedded
  signatures only (catalog-signed `System32` binaries are "not signed"); no revocation checking and
  no network; an unsigned build never verifies its own helpers. The FFI entry point is
  `verify_peer_code_signature(pid, executable, PeerRequirementKind)` in `kagisecure-ffi`'s
  `agent.rs`, returning the same `ClientVerificationView` `agent_resolve` takes back. **Still
  open:** its C ABI wrapper in `capi.rs` and the C# call site; regenerating the checked-in Swift
  bindings (macOS does not call it); and the gaps §3.1 now lists. Tests run against real processes
  started suspended — Edge (verified), Chrome (verified, and not Edge's signer), `cmd.exe`
  (catalog, so not signed), the unsigned test binary, a wrong expected path, an exited process and
  a renamed image.

### Tier 3 — full WinUI 3 GUI

**Roughly 6-9 months.** The macOS app is around 8,200 lines of hand-written Swift (UI code, not
generated bindings) that would need re-expressing in C#/WinUI 3, plus a parallel XCTest-equivalent
test suite from scratch.

The one piece of good news: ADR-0001's rule that native apps hold *only* UI and platform
integration, never product logic, was actually enforced. Categories, templates, search, filtering,
sidebar counts, the item model, the injector, import, audit — all of that already lives in
`kagisecure-core` and is reachable through the FFI surface (see §4). So Tier 3 is a genuine **UI
project**, not a logic-plus-UI project. That said, it is still a full rewrite of a non-trivial
application, done by hand, with its own test suite — "just a UI" does not make 8,200 lines fast.

**Progress — agent access, approvals and Windows Hello** (`apps/windows/Kagisecure.App`; see its
README's "Agent access, approvals and Windows Hello" section for the file map):

- **Agent host.** Unlocking starts the MCP listener (`Agent.Start`) and the browser-extension
  listener (`BrowserExtension.Start`) — always, as on macOS, which has no switch for either;
  `KAGISECURE_SOCKET` / `KAGISECURE_EXTENSION_SOCKET` move them — and one poll loop over
  `Agent.NextRequestAsync` (250 ms, cancellable). Locking stops both *before* the session is
  released (a `Locking` hook ahead of disposal), waiting at most three poll intervals for the loop.
  `kagisecure lock` over IPC (`Agent.TakeLockRequest`) locks the app.
- **Approval sheet** (ui-spec.md §10) in its own always-on-top window, flashed in the taskbar: the
  sentence, the verdict, the self-reported name in quotes, process, environment, variables,
  command, file/directory, git and overwrite warnings, the TTL control (shorten only), the scope
  summary and the 60-second countdown; the fill variant's two verdicts, item, website, fields,
  extension id and frame warning. `Agent.VerifyPeerCodeSignature` (OwnHelper for the caller,
  Browser for a fill's browser) runs off the UI thread, is shown as a warning and never gates.
  Allow requires Windows Hello (`UserConsentVerifier`); a cancelled or refused prompt grants
  nothing; where Hello is unavailable the master password is the fallback (ADR-0004). Expiry,
  lock, or the next request dismiss it; closing it is Deny.
- **Pages:** Environments (create, share, add/remove variables, fill pending ones, delete, the
  vault-level share switch), Leases (both tables, live countdowns, Revoke, Revoke all), Set up your
  agent (sidecar path and per-client snippets with Copy), Browser extension (per-browser manifest
  path **and HKCU registry key**, Set up/Remove), and Security (Windows Hello).
- **Windows Hello unlock**, as specified in [ADR-0033](decisions/0033-windows-hello-key-derivation.md)
  (revised after a security review: blob v2 bound to the vault-file id, TPM attestation required,
  no automatic prompt, and a plain statement that enrolling lowers protection to "can sign in to
  this Windows account"). Implemented and unit-tested against fakes (and real DPAPI); **not yet
  exercised with a real Hello prompt**, which cannot be driven non-interactively.
- **Presence-gated releases (ADR-0038), merged 2026-09-26 from `feat/vault-transactions` —
  written, not yet built or run on Windows.** That branch removed the ungated `reveal_field`,
  `totp_code` and `item_totp_code` from the FFI: a concealed value, a one-time code or a note now
  leaves the vault only through `release_field` / `release_totp` / `release_notes`, each behind a
  fresh presence check. On Windows the check is **Windows Hello**, reached as one C callback
  (`kgs_session_set_presence_gate`, `crates/kagisecure-ffi/src/capi/presence.rs`) that Rust calls
  synchronously on the thread asking for the release; the app's `WindowsHelloPresenceGate` asks
  `UserConsentVerifier` with Rust's sentence and, only when Hello is unavailable, the vault master
  password, checked by Rust on the same session (rate limited, audited). It fails closed — no
  gate, a null gate, a second gate, an unknown answer, an exception, a stale session, or a call
  on the UI thread all release nothing — and it shares one prompt slot with the approval sheet
  (`PresencePromptGuard`). The app side: Reveal/Copy per field, "Show code" for a one-time code
  (masked until then, live for at most five minutes), "Show notes", a copy of a shown value with
  no second prompt, hide on deselect/cap/lock, an editor that prefills nothing concealed and sends
  `null` to keep a stored secret or note, a save and a permanent delete that carry the item's
  revision, and the approval sheet's password fallback through the same rate-limited check. The
  C ABI side is tested in Rust (`capi::tests`); the C#/WinUI side and its tests were written
  against the regenerated `NativeMethods.g.cs` on a Mac with no .NET SDK, so **`dotnet build` and
  `dotnet test` have not been run on them**. Not built yet: acting on a presence-only approval
  (ADR-0037 — the sheet shows the full sheet, still behind Hello), `EditReveal` in the editor, and
  a UI for the vault-conflict flow (the calls cross the ABI; the app shows the error). ADR-0038's
  "Windows" section has the design; its residual risk is W-1's: Hello proves someone who can sign
  in to this Windows account answered, which is weaker than Touch ID.
- **Agent-requested browser fills are not offered on Windows** (ADR-0036, implementation
  decision 8) — excluded, not degraded. `request_fill` answers `FILL_UNAVAILABLE` there before any
  item is looked up. The C ABI carries only what its exhaustive conversion needs:
  `KgsApprovalAction::AgentFill = 5` (ABI version 5), and none of the agent-fill facts or
  `agent_fill_*` calls (`capi/mod.rs`, "What is not here"). The app's `ApprovalAction.AgentFill`
  member exists so the enum stays in step; `AgentHostService` denies such a request unseen. The
  Audit page's agent filter matches actors by the `mcp` prefix, as the macOS one does, so the
  longer actor an agent fill writes on macOS would still be found in a vault opened here.
  `kagisecure-nmhost` stays lock-step on Windows and forwards no pushes — its client pipe cannot be
  read and written at once — so nothing on this platform could reach a tab even if the switch
  existed. Written on a Mac with no .NET SDK, so not built.
- **Lock ordering.** `VaultService.Lock()` takes the session out and bumps a generation *before*
  it stops the listeners, and always stops them (even with no session); `AgentHostService.Start`
  and `Stop` are serialized and Start re-checks the generation after binding, stopping what it bound
  if a lock raced it. An unlock that finishes its KDF after a lock arrived is disposed, not adopted.

## 3. The two hard problems

These are design problems, not typing. Whoever picks this up should read them before estimating
anything.

### 3.1 Authenticode peer verification is structurally weaker than the macOS check

On macOS, peer verification uses `SecCodeCopyGuestWithAttributes` followed by
`SecCodeCheckValidity` on the **running process itself**, and compares the result against this
app's own signing identity. The object being checked is the process that is, right now, on the
other end of the socket.

`WinVerifyTrust`, the Windows analogue, does not work that way: it inspects a **file on disk, by
path**. To use it for peer verification, you have to resolve pid → image path (via
`QueryFullProcessImageNameW`, see §2 Tier 1) and then verify *that path*. Between those two steps
there is a TOCTOU window: the file at that path can be replaced, or the pid can be reused by a
different process, between resolution and verification. macOS does not have this window, because
it verifies the live process, not a path.

Mitigating this on Windows means either:

- opening the image file with a deny-write share mode for the duration of the check (so nothing
  can replace it out from under the verification), or
- working with a section handle / file handle obtained atomically with the pid resolution, rather
  than a path re-opened later.

Both are more machinery than the macOS side needs. **State this plainly wherever the Windows
verification story is documented: it is weaker than the macOS one, structurally, not just in
current implementation completeness.** Don't let a future doc imply parity here.

**As built** ([ADR-0032](decisions/0032-authenticode-peer-verification.md)): the first option,
plus a held process handle against pid reuse and a path re-read before and after. What it closes
and what it does not, measured on Windows 11 26200:

- **Closed:** pid reuse *during* the check (the handle pins the process object); the file being
  written, deleted or renamed during the check (the share mode refuses it); the running image file
  being renamed away and a signed file put in its place (`QueryFullProcessImageNameW`'s Win32 name
  follows a file rename, so the path no longer matches).
- **Not closed:** a rename of the image's **parent directory** — the reported path does not follow
  it, so a signed file placed at the old path is what gets verified. That needs a user-writable
  install directory. Pid reuse *between the connection and the check* by a process of the same
  image, because the request carries no creation time. And, independent of all of it, a same-user
  process can inject into a genuinely signed one.

That is why the verdict is a warning on the approval sheet and never a gate, exactly as ADR-0015
decided for macOS.

### 3.2 Windows Hello keys are not per-app

This is already a decided, documented fact, not new information. [`docs/threat-model.md`
W-1](threat-model.md) (line 293, confirmed) says:

> Windows Hello keys are **user/device-scoped, not per-app**. Another app running as the same
> user can, in principle, use the same Hello credential.

and [`docs/decisions/0004-biometric-key-wrapping.md`](decisions/0004-biometric-key-wrapping.md)
already specifies the mitigation, under its "Windows" heading:

> The wrapping key comes from `KeyCredentialManager` (TPM-backed where a TPM exists), and each use
> is gated by `UserConsentVerifier.RequestVerificationAsync` — Windows Hello face, fingerprint, or
> PIN.
>
> **Caveat, stated plainly: Windows Hello credentials are scoped to the user and device, not to
> the application.** They do not provide the per-app isolation that a Secure Enclave key with a
> keychain ACL provides on macOS. Another process running as the same user can, in principle,
> obtain Hello consent.
>
> Mitigation (defense in depth, **not** equivalence): the header's platform-wrapped VK is wrapped
> under a key derived from *both* the `KeyCredential` operation **and** an app-specific secret
> stored via DPAPI (`CryptProtectData`, current-user scope) inside the app's own storage.

And the ADR's consequences section is explicit about the overall posture (line 105):

> **Windows is weaker than macOS**, and we say so in the docs rather than claiming parity.

There is nothing to design here — the mitigation (`KeyCredentialManager` + `UserConsentVerifier` +
a DPAPI-wrapped app secret) is already specified. The work is implementation, and the honesty
about the residual gap is already the house style: keep saying it plainly, don't let it soften.

**As built** ([ADR-0033](decisions/0033-windows-hello-key-derivation.md)): there turned out to be one
thing to design after all, because a `KeyCredential` can only *sign* — it has no decrypt. The vault
key is wrapped (AES-256-GCM) under `HKDF-SHA256(Hello signature ‖ DPAPI secret)`, where the Hello
signature is RSASSA-PKCS1-v1_5 over a fixed per-slot challenge — deterministic, which enrolment
checks rather than assumes. Unlock is one Hello prompt (the signature itself); approvals use
`UserConsentVerifier`, with the master password as the fallback where Hello is unavailable
(checked against the unlocked session in memory, never the file on disk).

An independent security review then made the residual gap sharper, and the ADR (§2, §5) now says
it without softening: the deterministic signature is a **static long-term secret** — one approved
Hello prompt raised by a same-user process for this app's credential (its name is derivable from
the vault header), plus the silently readable DPAPI secret and the blob, opens the vault offline,
and the vault key never rotates; Windows Hello **always accepts the account PIN** and is not
invalidated by enrolling a new fingerprint, so enrolling lowers the vault's protection on that PC
to "anyone who can sign in to this Windows account"; and on Windows a same-user process can read
the unlocked app's memory anyway (threat-model T-3). Challenge rotation was considered and rejected
(it costs a prompt per unlock and does not stop the attacker who can obtain a signature). What was
done instead: no automatic Hello prompt, the Hello dialog brought forward only if it belongs to
`%SystemRoot%\System32\CredentialUIBroker.exe`, enrolment only with a successful TPM attestation,
the blob bound to the vault file's id, and the cost stated on the Security page and the lock screen:
*Windows Hello unlock lowers this vault's protection on this PC to "anyone who can sign in to this
Windows account"*.

## 4. The C# binding decision — settled 2026-09-25: the fallback

**Update, 2026-09-26:** since the merge of `feat/vault-transactions`, one callback crosses the C
ABI — the presence gate — under the narrow contract ADR-0003's amendment records; the ABI is
version 4 with 147 exports.

[`docs/decisions/0003-uniffi-vs-csbindgen.md`](decisions/0003-uniffi-vs-csbindgen.md)'s
evaluation gate has been run; its [evaluation record](decisions/0003-uniffi-vs-csbindgen.md#evaluation-record)
has the measured table. The short version:

- **`uniffi-bindgen-cs` fails C1 and C5.** Its newest release, v0.11.0+v0.31.0 (2026-06-23),
  targets uniffi 0.31; we pin 0.32.0. Run against our DLL it cannot even read the metadata (0.32
  changed the metadata wire format). A 0.32 upgrade exists only as an unmerged third-party pull
  request. Downgrading UniFFI was ruled out by the ADR from the start.
- **So the C# layer is the ADR's fallback:** a hand-written P/Invoke assembly,
  [`apps/windows/Kagisecure.Interop`](../apps/windows/README.md), over an explicit `extern "C"`
  surface in `kagisecure-ffi` behind the `capi` feature (`crates/kagisecure-ffi/src/capi.rs`).
  The feature is off by default; the Swift build is unchanged and still `#![forbid(unsafe_code)]`.
- **What exists is a minimal proof, not the surface.** It covers one function per shape the ADR
  worries about — a record in, a record out, an enum with data, typed errors, raw bytes in both
  directions, and the Arc-style `VaultSession` with deterministic `Dispose` — and
  `dotnet test` exercises each against a real vault. 10 of the FFI's 85 entry points are wrapped.
- **C5 now has a command:** `cargo xtask bindgen-cs [--release]` builds `kagisecure_ffi.dll` with
  `capi` and stages it in `target/windows/<Configuration>/`, where the C# projects pick it up. No
  C# is generated yet; the ADR's plan adds `csbindgen` to that command next, with its output
  checked in per ADR-0009's reasoning.

What this means for Tier 3: the premise in the ADR that the FFI is "20–30 functions" is out of
date — it is 85 entry points over 55 types, and on this path every one of them is a Rust adapter
plus a C# wrapper, and every future FFI change is two edits. Budget the bindings as real work
inside the 6-9 months, not as a prerequisite that is now done. The ADR records a re-evaluation
trigger (a `uniffi-bindgen-cs` tag for our UniFFI version); check it before each large wrapping
step, because switching is cheaper the less has been hand-written.

## 5. What doesn't exist on Windows at all: Safari

There is no Safari on Windows, and therefore no Safari App Extension channel. Per the platform
table in `README.md`, kagisecure ships two extension paths on macOS: a Chromium MV3 extension
(native messaging) and a Safari Web Extension bundled in the app. The Safari path is the
**stronger** of the two verification stories, because it runs inside the app's own bundle rather
than talking to an external browser process over native messaging. Windows inherits only the
Chromium/native-messaging shape — the weaker of the two paths — because there is no alternative
available on that platform. This isn't a gap to close; it's a platform ceiling to document
honestly wherever the two extension paths are compared.

## 6. Anchors not independently verified

Everything cited above (file:line anchors in `crates/kagisecure-ipc/src/endpoint.rs`,
`crates/kagisecure-agent/src/bundle.rs`, `crates/kagisecure-ipc/src/kernel_peer.rs`,
`crates/kagisecure-ipc/src/server.rs`, `crates/kagisecure-core/src/vault/mod.rs`,
`crates/kagisecure-core/src/inject/envfile.rs`, `crates/kagisecure-cli/src/commands/import.rs`,
`crates/kagisecure-agent/src/setup.rs`, `deny.toml`, `docs/roadmap.md`, `docs/threat-model.md`,
`docs/decisions/0003-uniffi-vs-csbindgen.md`, `docs/decisions/0004-biometric-key-wrapping.md`,
`xtask/src/bindgen.rs`, and the vendored `interprocess` 2.4.4 source) was read directly while
writing this document, on 2026-09-20. Line numbers may drift as those files change after today; if
a line doesn't match, the surrounding prose and function/const names should still be enough to
relocate the right spot.

**Correction pass, same day, after the §2 Tier 1 list above was first written:** the §2 Tier 1
blocker list was drafted from a survey taken before commit `a5e3a51` landed, and was reconciled
against the tree *at* `a5e3a51` in a second pass, later on 2026-09-20. That second pass read
`crates/kagisecure-ipc/src/kernel_peer.rs` via `git show a5e3a51 -- <path>` (to see the diff
directly rather than infer it) and read `crates/kagisecure-ipc/src/server.rs`,
`crates/kagisecure-agent/src/setup.rs`, `crates/kagisecure-core/src/inject/envfile.rs`, and
`crates/kagisecure-cli/src/commands/import.rs` directly at `a5e3a51`. The `docs/threat-model.md`
TB-4 (line 68) and M-13 (line 224) citations were re-read at the same time; the claim that they
overstate the current Windows named-pipe DACL state rests on that reading, not on this document's
earlier draft. `docs/threat-model.md` itself was not edited as part of this correction — only read.

One item explicitly could **not** be verified from inside this repository: the claim (reported
from the original survey) that `crates/kagisecure-ipc/src/kernel_peer.rs`'s Windows/BSD comment
"had... since been corrected" implies a prior, differently-worded version existed. This refers to
the file as it stood *before* `a5e3a51` — a single combined arm covering both Windows and the
BSDs, per the §1 correction above, which is a different question from whether that arm's wording
was itself once wrong. No `git blame`/history check was run to confirm the earlier wording
actually said the opposite. Treat that specific historical claim as unconfirmed — the present-tense
fact (the comment, in whichever arm it now lives in, is currently correct) is confirmed.

**Second correction pass, same day, after the §1 bullet above and the vault-ACL line numbers in
§2 were flagged as stale by the same root cause as the §2 Tier 1 correction:** re-read
`crates/kagisecure-ipc/src/kernel_peer.rs` directly (not just the `git show a5e3a51` diff used for
the first pass) to locate, at the tree as it stands at `a5e3a51`: the `#[cfg(windows)] mod imp`
opening (line 177), its `peer_pid` stub (line 193) and doc comment (lines 190-192), its
`executable_path` (line 227) and `parent_pid` (line 270), and the now-BSD-only fallback module's
`cfg` guard (line 307), doc comment (lines 311-313), and `peer_pid` stub (line 314). Also re-read
`crates/kagisecure-core/src/vault/mod.rs::write_atomically` directly: the `TODO(windows)` doc
comment begins at line 871, the directory's `set_permissions`/`from_mode(0o700)` call is at line
911, and the file's `0o600` is applied via `OpenOptionsExt::mode` at line 931 — not via
`from_mode`, which the document's original ~899 reference had implied by proximity to the ~879
`from_mode` reference for the directory. Both corrections are reflected in place above (§1 and §2
Tier 1) rather than only noted here.

**Access-control pass, 2026-09-25:** the two "Resolved" entries for the pipe DACL and the file
ACLs, and the "What the access-control work did not close" blocker, were written against the
code as changed that day, on a Windows 11 (26200) machine, and verified there: every test named
in them was run and passed, and one directory tree written through `windows_acl` was read back
with `icacls`. The `interprocess` 2.4.4 anchors in them (`c_wrappers.rs`,
`listener/create_instance.rs`, `security_descriptor/try_clone.rs`) were read directly in the
vendored source. The default-descriptor contents quoted for the old pipe were read back from a
pipe created without a descriptor on the same machine, not taken from Microsoft's documentation.
The line-number anchors in the second correction pass above (for `write_atomically`) point
at a `TODO(windows)` comment that no longer exists; the function name still locates the code.

## 7. Distribution — settled 2026-09-25

There is now a release pipeline: `cargo xtask dist-windows` (`xtask/src/dist_windows.rs`), the
Windows analogue of macOS's `cargo xtask dist`. The package format decision and its trade-offs are
[ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md); the command itself is
documented for a releaser in [`docs/releasing.md`](releasing.md) §10.

The short version: a per-user WiX v5 MSI, not MSIX, installing everything flat into
`%LOCALAPPDATA%\Programs\Kagisecure` with no admin/UAC prompt. "Flat" is the load-bearing word —
it is what lets `kagisecure_agent::bundle::find`'s existing "beside the running executable" search
(§1 above) locate every helper with **no change to `crates/`**, the same way a `cargo build`'s
`target/<triple>/release/` already does for a contributor. MSIX was evaluated and rejected for this
release: its registry/file virtualization is a real risk to two things this port already depends
on — `browser_setup.rs`'s `HKCU\...\NativeMessagingHosts` write landing in the *real* registry a
browser reads, and the absolute path it writes into a manifest file staying valid across an update
— and neither risk is hypothetical, both are read directly off code that already exists. The ADR
has the full trade-off table, including the ones this decision does not solve (SmartScreen
reputation, no auto-update in this release).

Every PE the project builds — `kagisecure_ffi.dll`, all three helper `.exe`s, the app's own
`Kagisecure.App.exe` — is Authenticode-signed individually before packaging, never only covered by
the MSI's own signature. This is not a distribution nicety: [ADR-0032](decisions/0032-authenticode-peer-verification.md)'s
`verify_peer` reads `kagisecure_ffi.dll`'s *embedded* signature at runtime for
`SameSignerAsThisProcess`, so a helper that is only "signed" by virtue of being inside a signed
package is unverified there regardless of what wraps it — the same sentence ADR-0032 already says
about MSIX applies equally to an MSI.

`dist-windows` also settles, as a packaging decision rather than a `crates/` one, the self-contained
question ADR-0032 §"what verified means for a development build" and this document's Tier 3 both
left open implicitly: the checked-in `Kagisecure.App.csproj` stays framework-dependent
(`WindowsAppSDKSelfContained=false`) for the fast `dotnet run` inner loop, and `dist-windows` passes
`--self-contained true -p:WindowsAppSDKSelfContained=true` on the `dotnet publish` command line
only for the release artifact. Nobody has to choose between a fast contributor loop and a release
that does not ask a stranger to separately install the Windows App Runtime first.

**Update, 2026-09-25:** the app icon and the installer UI wizard, both listed below as "not
attempted" when this section was first written the same day, are now done. `apps/windows`'s
`.csproj` sets `ApplicationIcon`, and `Product.wxs` declares `<Icon Id="AppIcon.ico">` from the
published `Kagisecure.App.exe` for the Start Menu shortcut and Add/Remove Programs. The installer
wizard is `WixUI_InstallDir` (WiX UI extension) plus a "Launch Kagisecure" finish-page checkbox
(WiX Util extension's `WixShellExec`), both restored project-locally by `dist_windows.rs`; the
license dialog's text is generated from `LICENSE-MIT`/`LICENSE-APACHE` rather than checked in.
`docs/releasing.md` §10.7 and
[ADR-0034](decisions/0034-windows-distribution-a-per-user-signed-msi.md)'s 2026-09-25 addendum have
the detail. A winget manifest is also now generated — `cargo xtask winget-manifest`,
`docs/releasing.md` §10.8 — but, as that section says outright, not submitted to
`microsoft/winget-pkgs`; `winget install kagisecure` does not work yet.

**Still not attempted here, and worth flagging for whoever next touches distribution:** adding the
CLI to the user's `PATH` automatically (deliberately left manual, mirroring the macOS decision in
`docs/releasing.md` §9 not to write outside the app's own directory without being asked), and
actually submitting the generated winget manifest.
