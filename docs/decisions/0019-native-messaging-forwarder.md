# ADR-0019: The native messaging host is a pipe, on a second socket with a different wire format

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6 implementation
- **Refines:** [ADR-0007](0007-m2-daemon-and-ipc-deviations.md),
  [ADR-0013](0013-agent-library-split.md), [architecture.md](../architecture.md) §4.2

## Context

A browser extension cannot open a Unix socket. Chromium's only channel to a local program is
`chrome.runtime.connectNative`, which launches a child process and speaks length-prefixed JSON over
its stdio. So something has to sit between the extension and the app.

The uncomfortable fact that shapes everything below: **Chrome performs no verification of a native
messaging host.** It reads a JSON manifest from the user's own `Application Support` directory and
launches whatever `path` names. No signature, no hash, no allow-list beyond the extension origins
the manifest itself declares. Anything that can write a file as the user can replace it.

## Decision

### 1. The host holds nothing and decides nothing

`kagisecure-nmhost` reads a frame from stdin, writes it to the app's socket, reads the reply,
writes it to stdout. That is the whole program.

It links exactly one kagisecure crate, `kagisecure-extension-ipc`, which depends on
`kagisecure-core` with the `proto` feature and **not** `secret-material`. So the binary a browser
launches cannot name `Secret`, cannot open a vault file, and has no type a vault key could sit in.

Replacing it gains an attacker a pipe. Every check — the origin rule, the approval sheet, the
biometric, the lease, the audit entry — happens on the other side of the socket, in the process
that holds the key.

The alternative, and why it loses: a host that opened the vault itself would need the vault key in
a process Chrome launches without checking, which is the same as not having a lock.

### 2. Frames are decoded and re-encoded, not copied

A byte-copying forwarder would forward anything, including a frame that is not a message of this
protocol. Decoding costs a JSON round trip on a path that is about to show a human a dialog, and
buys the property that this program only ever puts a well-formed `Request` on the app's socket.

### 3. A second socket, with a different byte order

The extension socket is a **sibling** of the agent socket, in the same `0700` directory, and its
frames are **big-endian** where the MCP channel's are little-endian.

Two sockets rather than one, because they are two protocols with opposite properties: the MCP
protocol *cannot* carry a value, and this one deliberately can. Multiplexing them would make the
distinction a matter of message dispatch instead of which file descriptor you are connected to.

The byte order is the belt to that brace. A `{"op":"ListVaults"}` frame arriving on the extension
socket declares a preposterous length under the opposite order and is refused by the size check
before a byte of its body is read; an extension frame on the MCP socket fails the same way. And a
frame that somehow survives the length check still has to carry the `ksx` channel marker to parse
as a message. Both are asserted (`a_frame_written_for_the_mcp_socket_does_not_parse_here`,
`an_mcp_frame_body_does_not_parse_as_an_extension_envelope`).

This is not paranoia about a hostile peer — the uid gate handles that. It is about a
misconfiguration, a stale `KAGISECURE_SOCKET`, a copy-pasted setup snippet: the failure should be
loud rather than a quiet misinterpretation.

### 4. The app checks one hop further up than it does for a sidecar

For the MCP socket, the connecting process *is* the thing being judged. For this socket the
connecting process is a pipe, and the interesting question is **who launched it** — because Chrome
launches a native host as a direct child, and a native host with no browser above it is a program
pretending to be a browser extension.

So the identity carries two halves: the host's pid and executable, and the first recognized browser
within three hops of ancestry. A host with no browser above it is refused with `UNTRUSTED_HOST`
before it can ask anything, and the refusal is audited.

Three hops rather than one, to allow for a launcher shim without letting the search wander up to
`launchd`. The browser test is an **exact file-name match**, so `Google Chrome Helper` — a renderer,
which never launches a native host — is not mistaken for `Google Chrome`.

**This is a path test, not an identity.** ADR-0015 already says a path is not an identity, and that
stands: anything that can write `/Applications` can put a program there. What it buys is that the
sheet can say *"launched by Google Chrome"* instead of *"launched by something"*, and that a shell
script cannot reach the socket at all. The security boundary remains the sheet and the biometric.

The code-signature verdicts — the host's and the browser's — are Swift's, per ADR-0015, and travel
down with the decision.

## Consequences

**Positive**

- The component with the weakest verification story has the least authority, which is the right way
  round.
- A misdirected frame fails loudly on both channels.
- `kagisecure-nmhost` is ~150 lines and reviewable in one sitting.

**Negative — accepted**

- **A seventh crate and a second binary.** The workspace is now core / ipc / extension-ipc / agent /
  mcp / cli / ffi / nmhost. Two of those are "the wire protocol for one channel", which reads as
  duplication until you notice the feature flags differ.
- **One extra process per browser.** Chrome spawns the host on first use and keeps it for the life
  of the port. It is idle between messages.
- **`parent_pid` shells out to `/bin/ps`.** One short-lived process per connection, on a path that
  is about to show a dialog. The alternative was a second `unsafe` FFI module for a fact `ps`
  reports accurately, which is a poor trade in a workspace that keeps its FFI to one reviewed file.
- **Three hops of ancestry is a guess.** One is what Chrome does today. Three is judgement, and if a
  future Chromium moves the launch further away it will need revisiting rather than silently
  failing closed — though failing closed is the direction it fails in.
