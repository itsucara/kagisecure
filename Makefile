# Thin wrappers around `cargo xtask` and the macOS toolchain.
#
# Architecture §7 picks `cargo xtask` as the task runner, and it still is: everything here is a
# one-line shortcut for something you could type yourself. The point is that `make macos` is the
# single documented answer to "how do I build the app", so nobody has to reconstruct the order of
# bindgen → xcodegen → xcodebuild from four different files.

CARGO ?= cargo
XCODEGEN ?= xcodegen
XCODEBUILD ?= xcodebuild
NODE ?= node
MACOS_DIR := apps/macos
XCODEPROJ := $(MACOS_DIR)/Kagisecure.xcodeproj
DESTINATION := platform=macOS

# Signing (ADR-0025).
#
#   make macos                     ad-hoc, no account, what a clean checkout does and the default
#   make macos SIGN=developer-id   the Developer ID Application identity in your keychain
#
# Two things need a real identity and neither works ad-hoc: the App Group the Safari extension
# reaches the app through (ADR-0024), and the "verified" rendering of the approval sheet's
# identity check (ADR-0015). A third — the Secure Enclave key — needs a provisioning profile and
# does not work under Developer ID either; ADR-0011 has the measurement.
#
# The identity is named by its *generic* name, so this file carries no organisation's certificate
# in it and a fork signs with its own. TEAM_ID is read out of the same certificate, and can be
# overridden for a machine with more than one.
SIGN ?= adhoc
CONFIG ?= Debug
DEVID_IDENTITY ?= Developer ID Application
TEAM_ID ?= $(shell security find-identity -v -p codesigning 2>/dev/null | \
	sed -n 's/.*Developer ID Application: .*(\([A-Z0-9][A-Z0-9]*\)).*/\1/p' | head -1)

ifeq ($(SIGN),developer-id)
SIGN_FLAGS := CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$(DEVID_IDENTITY)" \
	DEVELOPMENT_TEAM=$(TEAM_ID) OTHER_CODE_SIGN_FLAGS=--timestamp
EMBED_IDENTITY := $(DEVID_IDENTITY)
else
SIGN_FLAGS := CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=
EMBED_IDENTITY := -
endif

.PHONY: all check test fmt clippy deny version bindgen helpers icon project signing-check macos \
	macos-test app run release clean-macos e2e clean-e2e

all: check

## Rust
# Build then test, in one sequential recipe. Deliberately does not depend on `bindgen` (unlike
# `macos`/`macos-test` below): running this concurrently with a `cargo xtask bindgen` in another
# terminal still races both on `target/` — see CONTRIBUTING.md, which asks for one or the other,
# not both at once.
check:
	$(CARGO) build --workspace
	$(CARGO) test --workspace

test:
	$(CARGO) test --workspace

fmt:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

# Licenses and advisories (deny.toml). Gates the release; see docs/releasing.md.
deny:
	$(CARGO) deny check

# One version number, checked in the three places it is written.
version:
	$(CARGO) xtask version

## macOS
# Regenerate the Swift bindings and the xcframework. Idempotent: running it twice leaves the
# working tree unchanged — check with `git diff --exit-code` (this ran in CI until CI was removed
# on 2026-09-19; run it locally now).
bindgen:
	$(CARGO) xtask bindgen

# The three binaries the app bundle carries: kagisecure-mcp, kagisecure-nmhost and the CLI
# (ADR-0026). Staged into target/helpers/$(CONFIG)/, which is where the app's embed build phase
# looks. Building them for a *development* build too is deliberate: the "Set up your agent" and
# "Browser extension" screens then show the same bundled paths a user will see, rather than a
# target/debug path that only works on this machine.
helpers:
	$(CARGO) xtask helpers $(if $(filter Release,$(CONFIG)),--release,)

# The app icon, generated from the committed artwork in apps/macos/Artwork/. The .icns is not
# committed; it is rebuilt whenever the artwork changes.
ICON := $(MACOS_DIR)/Kagisecure/Resources/Kagisecure.icns

$(ICON): $(MACOS_DIR)/Artwork/icon-1024.png
	$(MACOS_DIR)/Scripts/make-icon.sh

icon: $(ICON)

$(XCODEPROJ): $(MACOS_DIR)/project.yml
	cd $(MACOS_DIR) && $(XCODEGEN) generate

project: $(XCODEPROJ)

# Build the app from a clean checkout. `SIGN=developer-id` signs app, extension and every
# embedded binary with the Developer ID identity, under the hardened runtime, with a timestamp.
#
# The `embed` step afterwards puts kagisecure-mcp, kagisecure-nmhost and the CLI into
# Contents/Helpers and re-signs the bundle around them, so that a development build has the same
# shape a released one does and the setup screens show the same paths (ADR-0026). It is a separate
# step rather than a build phase because a sandboxed Run Script phase can do neither half of it —
# see the note in project.yml.
macos: bindgen helpers icon project signing-check
	$(XCODEBUILD) -project $(XCODEPROJ) -scheme Kagisecure -destination '$(DESTINATION)' \
		-configuration $(CONFIG) $(SIGN_FLAGS) build
	@app=$$($(XCODEBUILD) -project $(XCODEPROJ) -scheme Kagisecure -destination '$(DESTINATION)' \
		-configuration $(CONFIG) $(SIGN_FLAGS) \
		-showBuildSettings 2>/dev/null | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{print $$2; exit}'); \
	KAGISECURE_SIGN_IDENTITY=$(EMBED_IDENTITY) $(CARGO) xtask embed \
		$(if $(filter Release,$(CONFIG)),--release,) "$$app/Kagisecure.app"

macos-test: bindgen helpers icon project signing-check
	$(XCODEBUILD) -project $(XCODEPROJ) -scheme Kagisecure -destination '$(DESTINATION)' \
		$(SIGN_FLAGS) test

# Fail before a twenty-second build rather than after it: `DEVELOPMENT_TEAM=` with an empty value
# produces an app whose App Group entitlement expands to a group nothing can use, and the symptom
# is a Safari extension that silently never connects.
signing-check:
ifeq ($(SIGN),developer-id)
	@test -n "$(TEAM_ID)" || { \
		echo "make: no Developer ID Application identity in the keychain."; \
		echo "      security find-identity -v -p codesigning"; \
		echo "      or pass TEAM_ID=XXXXXXXXXX explicitly."; \
		exit 1; }
	@echo "signing with \"$(DEVID_IDENTITY)\", team $(TEAM_ID)"
endif

# Build and launch. Set KAGISECURE_VAULT to point the app at a scratch vault.
run: macos
	@app=$$($(XCODEBUILD) -project $(XCODEPROJ) -scheme Kagisecure -destination '$(DESTINATION)' \
		-configuration $(CONFIG) $(SIGN_FLAGS) \
		-showBuildSettings 2>/dev/null | awk -F' = ' '/ BUILT_PRODUCTS_DIR /{print $$2; exit}'); \
	open "$$app/Kagisecure.app"

# The release: universal build, Developer ID signing, notarization, stapling, DMG, verification.
# Everything lands in dist/. Needs a notarytool credential profile — its *name* in
# NOTARY_KEYCHAIN_PROFILE, never the credential itself. docs/releasing.md is the long version.
#
#   make release                        the real thing
#   make release DIST_FLAGS=--skip-notarize   build and sign only, no submission to Apple
release:
	$(CARGO) xtask dist $(DIST_FLAGS)

clean-macos:
	rm -rf $(XCODEPROJ) $(MACOS_DIR)/KagisecureFFI/Artifacts dist $(ICON)

## End to end
# The cross-process suites: a real sidecar over a real socket, a real browser with the real
# extension, the real CLI against scratch vaults, and the real macOS app driven through XCUITest
# while a real agent asks it for a secret. docs/e2e-harness.md is the long version.
#
#   make e2e                  every suite except D (the macOS app — see the warning below)
#   make e2e SUITE=mcp        one suite (comma-separated for several: SUITE=mcp,cli)
#   make e2e SUITE=mcp,extension,cli   the three headless-ish suites, D always left out
#   make e2e E2E_KEEP=1       keep the temporary vaults, sockets and artifacts
#
# WARNING: suite D takes over the mouse and keyboard for about thirty minutes — XCUITest
# synthesizes real clicks and keystrokes at the window server. Run it only when the Mac is not in
# use, with E2E_GUI=1 set:
#
#   make e2e SUITE=app E2E_GUI=1    just the macOS app
#   make e2e E2E_GUI=1              every suite, D included
#
# Without E2E_GUI=1, a plain `make e2e` leaves suite D out, and `make e2e SUITE=app` refuses
# outright rather than silently running nothing.
#
# Writes e2e/report/index.html (self-contained: screenshots and logs are embedded) and
# e2e/report/junit.xml, and exits non-zero if any scenario failed.
#
# The browser and app suites need a real login session with a window server too. The browser one
# because an MV3 extension does not load in a headless Chromium; the app one because XCUITest
# drives a real window. Both say so and skip rather than failing when they cannot run — the app
# suite also recognises macOS refusing the UI-testing authorization and prints the command that
# grants it (docs/e2e-harness.md §7.4). Neither this target nor that suite will grant it for you.
e2e:
	$(NODE) e2e/run.mjs $(if $(SUITE),--suite $(SUITE),)

clean-e2e:
	rm -rf e2e/report e2e/tmp
