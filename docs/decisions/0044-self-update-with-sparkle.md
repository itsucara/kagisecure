# ADR-0044: The macOS app updates itself with Sparkle, the way itsustar does

- **Status:** Implemented, not yet built or run (written without a Mac; see "Not done").
- **Date:** 2026-10-03
- **Deciders:** the owner — "the same mechanism as itsustar", feed on kagisecure.com, and
  itsustar's install-at-launch behaviour
- **Settles:** the open "Sparkle vs manual" question in
  [ADR-0028](0028-the-release-pipeline.md)

## Decision

The macOS app embeds **Sparkle 2** and keeps itself on the latest release, configured and behaving
exactly like itsustar's updater (`apps/apple/Mac/Updates/` there):

- **Feed:** `https://kagisecure.com/mac/appcast.xml`; archives under
  `https://kagisecure.com/mac/releases/`. The feed is signed (`SURequireSignedFeed`), every archive
  is EdDSA-signed and verified before it is unpacked (`SUVerifyUpdateBeforeExtraction`), and the
  app inside is Developer ID signed, notarized and stapled. No system profile is sent.
- **At launch** the app checks at once; an update found then is downloaded and installed straight
  away and the app relaunches into it, with a small non-activating panel saying so. The vault is
  locked at launch, so the relaunch takes nothing from the person.
- **While running** it checks every hour; an update is downloaded in the background, installed on
  quit, and the panel offers "Relaunch to Update" / "Later".
- **Settings ▸ Updates** turns automatic checks off (then nothing is checked, at launch either) and
  has "Check Now"; the app menu has "Check for Updates…".
- **Only `cargo xtask dist` builds have an updater.** `SUFeedURL` and `SUPublicEDKey` come from
  build settings that are empty in `project.yml`; `dist` passes the feed URL and the public key
  (read from the keychain account `com.kagisecure.app`) on the xcodebuild command line, and checks
  the built Info.plist carries them.
- **The release** zips the stapled app, adds it to the live feed with Sparkle's `generate_appcast`
  (keeping five releases), signs and verifies the feed, and leaves it in `dist/mac-updates/` for
  upload ([releasing.md](../releasing.md) §8). A build that was not notarized gets no feed.
- **Signing:** `crate::embed` re-signs Sparkle's nested helpers inside-out before the app's final
  signature, since Xcode's copy-and-sign covers the framework only.
- **Homebrew:** the cask declares `auto_updates true`.

## Consequences

- Whoever holds the EdDSA private key *and* can write to `kagisecure.com/mac/` can ship code to
  every installation. Both are needed — the key alone cannot serve a feed, the host alone cannot
  sign one — and Developer ID plus notarization still apply on top.
- Losing the private key strands every installed copy on its version; it is backed up offline
  (releasing.md §2.4).
- Sparkle adds a third-party framework to a password manager's process. It runs only in the app,
  not in the helpers or the Safari extension.

## Not done

- Nothing here has been compiled or run: no Swift toolchain was available when it was written.
  The first `cargo xtask dist` is its first build.
- The upload to kagisecure.com is manual; there is no publish step like itsustar's `--publish`.
- Windows is unchanged.
