# ADR-0032: On Windows the peer's Authenticode signature is checked in Rust, through a pinned file, and it is weaker than the macOS check

- **Status:** Accepted
- **Date:** 2026-09-25
- **Deciders:** Windows port, Tier 2
- **Refines:** [ADR-0015](0015-peer-code-signature-verification.md),
  [windows-port.md](../windows-port.md) §3.1, [threat-model.md](../threat-model.md) M-19,
  [architecture.md](../architecture.md) §5

## Context

[ADR-0015](0015-peer-code-signature-verification.md) gave the macOS approval sheet a real
**Verified** / **Unverified** verdict: the Swift app resolves the kernel's pid to a live `SecCode`,
runs `SecCodeCheckValidity` on it, compares its team with the app's own (for our helpers) or with a
hardcoded vendor team (for browsers), and passes the verdict down into Rust with the decision. The
Windows app — WinUI 3 in C#, over the C ABI of
[ADR-0003](0003-uniffi-vs-csbindgen.md)'s fallback — owes the same verdict, and until now every
Windows caller could only ever be reported as a kernel-verified pid.

The Windows analogue is `WinVerifyTrust`, and it answers a different question.
[windows-port.md](../windows-port.md) §3.1 already says so: macOS checks the **running process**;
`WinVerifyTrust` checks a **file**. To use it on a peer, the pid has to be resolved to an image
path, the path opened, and the file verified — and at each step the thing being checked can stop
being the thing that is running. The pid can be reused by another process; the file at the path can
be replaced; the path can stop naming the running image.

Two facts about this machine (Windows 11 Pro 26200) shaped the decision, and are recorded because
they were measured rather than assumed:

1. **Most of `System32` is catalog-signed, not embedded-signed.** `Get-AuthenticodeSignature`
   reports `notepad.exe`, `cmd.exe`, `powershell.exe`, `curl.exe` and `explorer.exe` all as
   `SignatureType: Catalog` (signer "Microsoft Windows"). Microsoft Edge (`msedge.exe`, signer
   "Microsoft Corporation") and Google Chrome (`chrome.exe`, signer "Google LLC") carry
   **embedded** signatures.
2. **`QueryFullProcessImageNameW(PROCESS_NAME_WIN32)` follows a rename of the running image file,
   but not a rename of its parent directory.** Start a copy of an executable, rename the file, and
   the Win32 name reports the new name (the `PROCESS_NAME_NATIVE` form keeps the old one). Rename
   the *directory* it runs from instead, and both keep reporting the old path — which may by then
   name a different file.

## Decision

**The check is `kagisecure_ipc::authenticode::verify_peer`, in Rust; the app calls it through the
FFI (`verify_peer_code_signature`), shows the verdict, and hands it back to `agent_resolve`
unchanged — the same round trip ADR-0015 set up, with the check on the other side of the call.**

### 1. Rust, not C#

ADR-0015 put the macOS check in Swift because `SecCode*` is Security.framework and reaching it from
Rust meant `unsafe` and a CoreFoundation dependency in crates that forbid both. The Windows
situation is the reverse. `kagisecure-ipc` already has an isolated, reviewed FFI module that opens
Windows processes (`kernel_peer`: `OpenProcess`, `QueryFullProcessImageNameW`); .NET has no managed
API that *verifies* an Authenticode signature (`X509Certificate.CreateFromSignedFile` extracts a
certificate and checks nothing), so C# would be P/Invoking `WinVerifyTrust` by hand anyway, in a
codebase with no test harness yet. In Rust the check is one implementation, next to the code that
already resolves the peer, exercised by `cargo test` against real processes on this machine.

ADR-0001 is unaffected: the call is app → Rust, synchronous, value-returning. Rust still never asks
the app for a verdict; the app asks Rust for one and then reports it back with the decision, so
what ends up in `Lease.client_identity` and the audit entry is what the human was shown.

### 2. The order of operations is the TOCTOU mitigation

`verify_peer(pid, expected_executable, requirement)`:

1. **Open the process first and hold the handle to the end**
   (`PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` — both still granted on the same user's
   elevated processes). An open handle keeps the process object, and so its pid, from being
   reused: every later question is about one process.
2. **Check it is running** — `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`, not
   `GetExitCodeProcess == STILL_ACTIVE`, which cannot tell a live process from one that exited
   with code 259.
3. **Read the image path from that handle** and require it to equal `expected_executable`, the path
   on the approval request (resolved from the kernel's pid when the request arrived, and shown on
   the sheet). A mismatch — including a pid now held by a different program — is unverified.
4. **Open the file with `FILE_SHARE_READ` only**, and with `FILE_FLAG_OPEN_REPARSE_POINT`, refusing
   a reparse point. While that handle is open nobody can write, delete or rename the file, and the
   open fails outright if somebody already holds it for writing or deletion. A reparse point at the
   exact path Windows reported for a running image means the path no longer names the image.
5. **Read the image path again.** Because the Win32 name follows a rename of the image file, an
   image renamed away and replaced between steps 3 and 4 shows up here as a changed path.
6. **Verify through the handle**: `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` and
   `WINTRUST_FILE_INFO::hFile` set, so the bytes hashed are the bytes of the file that is pinned;
   read the primary signer's leaf certificate with `WTHelperProvDataFromStateData` →
   `WTHelperGetProvSignerFromChain` → `WTHelperGetProvCertFromChain`; close the state with
   `WTD_STATEACTION_CLOSE` on every path, including failure.
7. **Check again that the process is running and that its image path is unchanged**, then release
   the file and the process.

Every failure is `verified: false` with the reason in the evidence. Nothing is ever retried or
looked up again by path after step 4.

### 3. Two requirements

**`SameSignerAsThisProcess`** — for our own helpers (the MCP sidecar, the native messaging host).
The peer's leaf certificate must carry the same `SubjectPublicKeyInfo` as the leaf certificate that
signed **the module this code is running in** (`GetModuleHandleExW(FROM_ADDRESS)`): in the Windows
app that is `kagisecure_ffi.dll`, not the C# host, because the DLL is what this project builds and
signs and is the code actually making the decision. This module's own signature is read the same
way (pinned, via the handle) once per process.

The key rather than the subject, because a subject is a name and two certificates can carry the
same one; the key rather than the certificate thumbprint, because a renewal that keeps the key is
still the same signer. It is ADR-0015's "same team as this app, not a hardcoded team" in Windows
terms: nothing to update at release time, and a fork that signs both halves with its own
certificate is verified against itself.

**`Publisher`** — for browsers. The executable's file name selects an entry in one table,
`authenticode::KNOWN_BROWSERS`, and the leaf certificate's subject common name must equal one of
that entry's names **exactly** (not "contains": `Not Google LLC` must not pass):

| File name    | Sheet name     | Accepted signer subject CN | Confirmed on this machine |
|--------------|----------------|----------------------------|---------------------------|
| `chrome.exe` | Google Chrome  | `Google LLC`               | yes                       |
| `msedge.exe` | Microsoft Edge | `Microsoft Corporation`    | yes                       |
| `brave.exe`  | Brave Browser  | `Brave Software, Inc.`     | **no** — not installed    |

It mirrors the macOS `knownBrowsers` table minus Arc, whose Windows publisher is unconfirmed — the
same reason `browser_setup` leaves Arc's registry key out — and Chromium, which nobody in
particular signs. Both are reported "not a browser with a known publisher". A wrong Brave value
fails closed: Brave would be unverified, never a stranger verified.

### 4. Embedded signatures only

A catalog-signed file is reported as *"not signed (no embedded Authenticode signature; catalog
signatures are not consulted)"*. Neither requirement can be met through a catalog: our helpers and
every browser in the table carry embedded signatures, and the only catalog signer in sight is
"Microsoft Windows", which is not a peer this app has any reason to trust for anything. The
`CryptCATAdmin*` path would be a second, larger block of `unsafe` with no caller. If a supported
peer ever turns out to be catalog-signed, that is the trigger to add it.

### 5. No revocation checking, and no network

`fdwRevocationChecks = WTD_REVOKE_NONE`, `dwProvFlags = WTD_REVOCATION_CHECK_NONE |
WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4`, `dwUIChoice = WTD_UI_NONE`. The check runs
while an approval sheet is waiting for a human; it must work offline and must not stall on a
CRL or OCSP responder; and fetching one would tell that server which binaries asked this machine
for secrets. The chain must still build to a trusted root, and a timestamped signature from a since
expired certificate is accepted as `WinVerifyTrust` accepts it by default. The evidence of every
verified verdict says *"revocation not checked"*, so nobody reads more into the badge than it
carries.

### 6. What "verified" means for a development build

**Nothing, for our own helpers.** A `cargo build` is unsigned; two unsigned binaries do not share a
signer, they share the absence of one. `SameSignerAsThisProcess` in an unsigned build is always
unverified, with evidence that says so and still reports what the caller is: *"this build of
Kagisecure is unsigned, so no caller can be verified as its signer (the caller is signed by
'Microsoft Corporation')"*. The browser check does not depend on our signature and can report a
genuine browser verified from an unsigned build, exactly as on macOS.

The verified branch of `SameSignerAsThisProcess` therefore cannot be reached from `cargo test`.
The tests reach it by standing Edge's own file in for "this build": the comparison runs on two real
certificates read through the real `WinVerifyTrust` path, and — where Chrome is installed, as it is
on the development machine — Chrome's certificate is shown not to match it. It has not been exercised with this project's own certificate, which is not on the
development machine; the release pipeline is where that happens.

### 7. Evidence lines

One line, prefixed `Authenticode:` so the audit log says which mechanism reached it, e.g.
*"signed by 'Google LLC' (chain valid; revocation not checked)"*, *"signed by 'Microsoft
Corporation', not by Google Chrome's publisher ('Google LLC')"*, *"signed by 'X', which differs
from this build of Kagisecure's signer ('Y')"*, *"not signed (…)"*, *"process 1234 is running
C:\…\a.exe, not C:\…\b.exe — the process that asked may have exited and its pid been reused"*,
*"process 1234 has exited"*, *"signature does not match the file — modified after signing"*.

### Alternatives considered

- **The check in C#.** Rejected for the reasons in §1: no managed verifier, the same P/Invoke
  either way, and no test harness on the C# side yet.
- **Check `OriginalFilename` in the version resource**, as the closest thing Authenticode has to
  the macOS signing identifier. Rejected: the version *strings* `GetFileVersionInfo(Ex)` returns
  can come from a MUI satellite file (`cmd.exe` reports `OriginalFilename` `Cmd.Exe.MUI` on this
  machine), a separate file that is neither covered by the executable's signature nor pinned by the
  check. An attacker who can place
  a satellite next to a renamed Microsoft-signed binary would choose its `OriginalFilename`.
- **Timestamps as a directory-rename detector** (refuse when the file changed after the process
  started). Rejected: `ChangeTime` and `CreationTime` are settable through `FileBasicInformation`
  by anyone who can write the file, which is exactly the attacker in question.
- **Revocation with network retrieval.** Rejected in §5.
- **Catalog signatures.** Deferred in §4.

## Consequences

**Positive**

- The Windows sheet can show a real verdict with a specific reason, and the lease and the audit
  entry record it, as on macOS.
- The check fails closed on every path: no process, an exited process, a pid now running a
  different program, a file held open for writing, a reparse point, a renamed image, a broken
  signature, an untrusted chain, an unreadable signer.
- The rules that decide a verdict — the table, exact subject matching, key comparison, "unsigned
  never matches unsigned" — are safe code, built and tested on every platform; only the Windows
  syscalls are `unsafe`, isolated in one submodule with a `SAFETY:` comment on each block.

**Negative — accepted**

- **This is structurally weaker than the macOS check, not merely less finished.** macOS asks the
  kernel about the code a live process is running; this asks about a file the process was started
  from. Nothing in the documented Win32 API ties the two together for an ordinary process, and the
  mitigations in §2 narrow the gap without closing it.
- **A parent-directory rename defeats the path check.** A same-user attacker who can rename the
  directory their unsigned program runs from can put a genuinely signed file at the old path, and
  that file will be verified. That needs a user-writable install directory — a per-user browser
  install under `%LOCALAPPDATA%`, a `cargo build` in a work tree — and not a per-machine one under
  `Program Files`, which a standard user cannot rename.
- **A same-user process can inject into a genuinely signed one.** Windows gives an ordinary process
  full access to the same user's unprotected processes; there is no counterpart to the hardened
  runtime. A verified signature says what file the process was started from, not what it is doing.
  This, with the previous point, is why the verdict stays a warning on the sheet and never a gate —
  ADR-0015's rule, kept for the stronger reason.
- **Pid reuse between the connection and the check is caught only if the newcomer is a different
  program.** The request carries the pid and the path, not the process's creation time, so a
  process of the *same* image that inherits the pid in between is indistinguishable. Recording
  `GetProcessTimes` at accept time and carrying it on the request would close this; it belongs with
  the same hardening `kagisecure_extension_ipc::peer::parent_pid`'s `TODO(windows)` describes.
- **A publisher is not a program.** Any binary Google signed, renamed `chrome.exe`, satisfies the
  Chrome entry; macOS binds a signing identifier as well, and Authenticode has none that is both
  signed and pinned (see the `OriginalFilename` alternative).
- **Our release pipeline must Authenticode-sign every PE individually** — `kagisecure_ffi.dll`,
  `kagisecure-mcp.exe`, `kagisecure-nmhost.exe`, the CLI — with the same key, before packaging. An
  MSIX signature covers the package, not the files inside it; a helper that is not itself signed is
  "not signed" here. Rotating to a new key mid-release, or mixing helpers from two releases signed
  with different keys, reports them unverified.
- **Revocation is not checked**, so a revoked-but-otherwise-valid signature is verified. The
  evidence says so every time.
- **The checked-in Swift bindings (ADR-0009) do not include `verify_peer_code_signature`** yet: they
  are regenerated by `cargo xtask bindgen` on macOS, which this change was not made on. The
  function is plain UniFFI (a `u32`, a `String`, a fieldless enum, an existing record), so the next
  regeneration picks it up; the macOS app does not call it and keeps its Swift check.
- **The C ABI wrapper for C# is not written here**; it belongs with the rest of `capi.rs`.
