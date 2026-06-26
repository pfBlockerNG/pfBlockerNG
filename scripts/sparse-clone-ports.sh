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
#   REF        branch or ref to fetch (e.g. pfblockerng/use-github)
#   DEST       destination directory — created (fresh clone) if absent; an EXISTING
#              git work-tree is fetched + checked out at REF (idempotent reuse)
#   CHANNEL    build-pkg-portable --channel value (devel|stable|nightly)
#   PHP        build-pkg-portable --php value (e.g. 8.3)
#   PYFLAVOR   build-pkg-portable --py-flavor value (e.g. py311)
#
# This is the SINGLE 'prepare the ports tree at REF' step shared by CI and local
# builds — CI hits the fresh-clone branch on an empty runner dir, a local/repeat build
# hits the reuse branch on a persistent clone, and both end on REF with the same sparse
# checkout. Reuse FETCHES + checks out REF rather than trusting whatever branch happens
# to be checked out: a tree left on e.g. devel installs an EMPTY pfblockerng_extra.inc
# stub and builds a silently-broken .pkg. So the build never depends on a human having
# remembered to switch branches.
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

# Resolve the repo root relative to this script so the builder can always be found
# regardless of where the caller's CWD is.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILDER="${SCRIPT_DIR}/build-pkg-portable.py"

# Derive the pfBlockerNG port dir for the channel — single source of truth in the
# builder (_CHANNEL_PORT_SUB); validates the channel name and errors on unknown values.
PORT_DIR="$(python3 "$BUILDER" --print-port-origin --channel "$CHANNEL")" || exit 1

# 1. Acquire the tree at REF — fresh blobless clone if DEST is absent, else fetch REF
#    into an EXISTING git work-tree and check it out (idempotent reuse). Either way the
#    tree ends on REF; no blobs are fetched yet, git knows all tree paths.
if [ -d "${DEST}/.git" ]; then
	# Reuse: point origin at the canonical URL (the clone's origin may differ) and fetch REF
	# blobless FROM the named remote, so git registers it as the partial-clone promisor and the
	# sparse checkout below lazy-fetches only the needed blobs — exactly like the fresh clone.
	# Checking out REF corrects a tree left on the wrong branch instead of building from it.
	git -C "$DEST" remote set-url origin "$URL" 2>/dev/null || git -C "$DEST" remote add origin "$URL"
	git -C "$DEST" fetch --depth 1 --filter=blob:none origin "$REF"
	co_target=FETCH_HEAD
elif [ -e "$DEST" ]; then
	printf '%s: %s exists but is not a git work-tree — refusing to overwrite\n' "$0" "$DEST" >&2
	exit 1
else
	git clone --depth 1 --filter=blob:none --no-checkout -b "$REF" "$URL" "$DEST"
	co_target="$REF"
fi

# 2. Sparse-checkout the pfBlockerNG port dir so its Makefile is readable, then check out
#    REF — setting the cone first limits an existing full clone's materialisation too.
git -C "$DEST" sparse-checkout set --cone "$PORT_DIR"
git -C "$DEST" checkout "$co_target"

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
