#!/bin/bash
#
# Render the browser extension's icons from the brand mark.
#
# The source is apps/macos/Artwork/icon.svg, the same mark the app icon and kagisecure.com use. The
# PNGs it produces are committed under extensions/shared/icons/, because the extension has no build
# step: Chromium loads extensions/shared as it is, the Safari target copies it, and
# `cargo xtask chrome-package` zips it. Re-run this only when the mark changes.
#
#   extensions/make-icons.sh
#
# Needs `rsvg-convert` (Homebrew: `brew install librsvg`).
#
# Sizes, and why 128 is different:
#
#   16, 32   the toolbar (`action.default_icon`), at 1x and 2x
#   48       chrome://extensions
#   128      the Web Store listing and the install dialog. The store's image guidelines ask for the
#            artwork at 96x96 inside a 128x128 canvas, with 16 px of transparent margin on each side,
#            so this one is rendered smaller and padded. The small sizes use the whole canvas, since
#            at 16 px every pixel of the mark is needed.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_svg="${here}/../apps/macos/Artwork/icon.svg"
out="${here}/shared/icons"

if ! command -v rsvg-convert >/dev/null 2>&1; then
	echo "rsvg-convert not found; install it with: brew install librsvg" >&2
	exit 1
fi

mkdir -p "${out}"

for size in 16 32 48; do
	rsvg-convert --width "${size}" --height "${size}" --keep-aspect-ratio \
		--output "${out}/icon-${size}.png" "${source_svg}"
done

rsvg-convert --width 96 --height 96 --keep-aspect-ratio \
	--page-width 128 --page-height 128 --left 16 --top 16 \
	--output "${out}/icon-128.png" "${source_svg}"

for size in 16 32 48 128; do
	echo "wrote ${out}/icon-${size}.png"
done
