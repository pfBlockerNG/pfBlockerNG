#!/bin/sh
# sparse-clone-ports.sh — blobless + sparse clone of the FreeBSD-ports tree.
#
# A full --depth 1 clone is ~1.3 GB; the portable builder reads only the port dir
# plus a handful of dep Makefiles.  A blobless+sparse clone of those directories
# is ~31 MB — ~12x faster and byte-identical in the resulting .pkg.
#
# Usage:
#   sparse-clone-ports.sh URL REF DEST CHANNEL PHP PYFLAVOR
#
#   URL        FreeBSD-ports HTTPS clone URL
#   REF        branch or ref to clone (e.g. pfblockerng/use-github)
#   DEST       destination directory (must not exist)
#   CHANNEL    build-pkg-portable --channel value (devel|stable|nightly)
#   PHP        build-pkg-portable --php value (e.g. 8.3)
#   PYFLAVOR   build-pkg-portable --py-flavor value (e.g. py311)
#
# The script leaves DEST ready for:
#   python3 scripts/build-pkg-portable.py --ports DEST ...
#
# POSIX sh; no bash-isms.

set -eu

usage() {
	printf 'Usage: %s URL REF DEST CHANNEL PHP PYFLAVOR\n' "$0" >&2
	exit 1
}

[ $# -eq 6 ] || usage

URL="$1"
REF="$2"
DEST="$3"
CHANNEL="$4"
PHP="$5"
PYFLAVOR="$6"

# Derive the pfBlockerNG port subdirectory for the channel so we can sparse-checkout
# it first (its Makefile drives --print-build-origins for the rest of the dirs).
case "$CHANNEL" in
	stable)  PORT_SUB="pfSense-pkg-pfBlockerNG" ;;
	devel)   PORT_SUB="pfSense-pkg-pfBlockerNG-devel" ;;
	nightly) PORT_SUB="pfSense-pkg-pfBlockerNG-nightly" ;;
	*)
		printf 'sparse-clone-ports.sh: unknown channel: %s\n' "$CHANNEL" >&2
		exit 1
		;;
esac
PORT_DIR="net/${PORT_SUB}"

# Resolve the repo root relative to this script so the builder can always be found
# regardless of where the caller's CWD is.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILDER="${SCRIPT_DIR}/build-pkg-portable.py"

# 1. Blobless clone — no blobs fetched yet; git knows all tree paths.
git clone --depth 1 --filter=blob:none --no-checkout -b "$REF" "$URL" "$DEST"

# 2. Sparse-checkout the pfBlockerNG port dir so its Makefile is readable.
git -C "$DEST" sparse-checkout set --cone "$PORT_DIR"
git -C "$DEST" checkout

# 3. Ask the builder which origins the build needs.
#    --print-build-origins reads only the port Makefile (already checked out) plus
#    git ls-files for php-ext glob resolution on the blobless clone.
origins="$(python3 "$BUILDER" \
	--ports "$DEST" \
	--channel "$CHANNEL" \
	--php "$PHP" \
	--py-flavor "$PYFLAVOR" \
	--print-build-origins)"

# 4. Add all build origins to the sparse checkout in one pass.
#    SC2086: word-splitting is intentional — $origins is a newline-separated list
#    and each line is a single path token with no spaces.
# shellcheck disable=SC2086
git -C "$DEST" sparse-checkout add $origins
