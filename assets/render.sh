#!/bin/sh
# Renders the page's icon and link-preview image from their SVG sources.
# The PNGs are committed, so the server build needs neither resvg nor the fonts.
#
# Usage: nix develop -c assets/render.sh
set -eu
cd "$(dirname "$0")"
fonts=""
for dir in $ASSET_FONT_DIRS; do fonts="$fonts --use-fonts-dir $dir"; done
# shellcheck disable=SC2086
resvg --skip-system-fonts $fonts icon.svg icon.png
# shellcheck disable=SC2086
resvg --skip-system-fonts $fonts og.svg og.png
