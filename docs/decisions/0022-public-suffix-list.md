# ADR-0022: Origin matching uses the Public Suffix List, embedded, with a stated update policy

- **Status:** Accepted
- **Date:** 2026-09-10
- **Deciders:** M6 implementation

## Context

The roadmap's M6 criterion: *"Autofill only ever proposes credentials for an item whose saved URL
matches the current page's origin; there is no fuzzy or 'close enough' domain match."*

"Matches" needs a definition. Three candidates:

1. **Exact origin equality.** `https://example.com` fills only on `https://example.com`, not on
   `https://www.example.com`. Correct, and unusable: most sites move you between the bare domain
   and `www`, or between `example.com` and `accounts.example.com`, during a single login.
2. **Same last two labels.** `example.com` covers `www.example.com`. Also makes `bbc.co.uk` and
   `sainsburys.co.uk` the same site, and `alice.github.io` and `mallory.github.io` the same site.
   That is not a rounding error; it is a credential-theft primitive.
3. **eTLD+1 under the Public Suffix List.** `co.uk` and `github.io` are on the list, so the
   registrable domain of `news.bbc.co.uk` is `bbc.co.uk` and of `alice.github.io` is
   `alice.github.io`.

## Decision

**Option 3, via the `psl` crate, with the list compiled into the binary; plus exact scheme and
exact port; plus exact host equality wherever there is no registrable domain.**

The rule, in one place (`crates/kagisecure-extension-ipc/src/origin.rs`):

1. schemes equal, and both `http` or `https`;
2. ports equal, after the scheme's default is filled in;
3. registrable domains equal — or, when either side has none, hosts byte-for-byte equal.

Clause 3's fallback is the **strict** branch and covers three cases: IP literals (no domain
structure), single-label hosts (`localhost`), and hosts that are themselves a public suffix
(`github.io` covers only `github.io`).

### Why embedded rather than fetched

A password manager that phones home to decide where it may fill a password has invented a network
dependency on its most security-critical decision, and a new way to be attacked (a stale or
poisoned list widens matching). The list is ~250 KB compiled and changes slowly.

### Update policy

The list ships inside the `psl` crate and updates when that crate's pinned version is bumped, and
only then. `Cargo.lock` records which snapshot a given build was made against.

**A stale list fails in the strict direction** for newly delegated suffixes: two sites under a
suffix added after our snapshot look like one registrable domain, so a user could be offered a fill
at a site they did not intend. That is the direction that matters, so:

> **Policy.** `psl` is a security-relevant dependency, not a convenience one. Bump it whenever the
> dependency audit runs (M7's `cargo deny` gate is the natural hook), and treat a version bump as a
> change worth a line in the release notes.

### Why the extension does not carry a copy

The browser-side `KsOrigin.mightMatch` does **whole-origin equality**, which is stricter than the
app's rule, never looser. It decides one thing — whether to draw an icon before anything has been
asked — and a second copy of the list would be 250 KB in a place where it decides nothing and could
drift out of step with the crate's copy.

The visible consequence is small and in the safe direction: on `gist.github.com` with only
`github.com` saved, the icon appears once the app has answered a `match` (which the content script
asks for anyway) rather than a moment before.

## Consequences

**Positive**

- `bbc.co.uk` and `sainsburys.co.uk` are different sites; `alice.github.io` and `mallory.github.io`
  are different sites. Both asserted.
- One implementation of the rule, in Rust, in the process that holds the key. The browser's copy
  cannot widen it because the browser's copy is not consulted by the app.
- No network dependency on the matching decision.

**Negative — accepted**

- **A ~250 KB dependency**, and a build-time code generator inside it.
- **The list is a snapshot.** Between bumps it is wrong about recently delegated suffixes, in the
  strict direction, and nothing in the product notices.
- **eTLD+1 is more permissive than exact origin.** `https://example.com` will fill on
  `https://anything.example.com`, including a subdomain an attacker controls through a subdomain
  takeover. This is what every password manager does, and the alternative breaks real logins; it is
  recorded here rather than left implicit.
