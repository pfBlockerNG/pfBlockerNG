#!/bin/sh
# prepare-dep-ports.sh — blobless sparse checkout of the FreeBSD-ports tree at a
# pinned full-SHA commit, materializing only the origins the given ROUTE
# matrix's rows declare as extra_pkgs (issue #2454).
#
# This is the dependency flow's OWN "prepare the ports tree" step -- the
# sibling of sparse-clone-ports.sh, which prepares the tree for the CANONICAL
# pfBlockerNG port build. That script sparse-checks-out the pfBlockerNG port
# dir and asks the portable builder which origins IT needs (its own
# RUN_DEPENDS); this script instead derives origins straight from the ROUTE
# matrix's extra_pkgs -- a matrix-level concept the canonical builder doesn't
# know about -- so a caller never needs a second, unrelated tree just to reach
# a dependency's Makefile. publish_deps.py (the builder this feeds) never runs
# git itself; this script is what hands it a ready ports checkout.
#
# Usage:
#   prepare-dep-ports.sh URL SHA DEST ROUTE_MATRIX_JSON
#
#   URL               FreeBSD-ports clone URL (https://, http://, or file://)
#   SHA               full 40-hex commit SHA to fetch -- never a branch/tag
#                     (mirrors sparse-clone-ports.sh's fetch-by-oid branch;
#                     `git fetch <ref>` / `-b` cannot take a bare SHA)
#   DEST              destination directory -- must be ABSENT or EMPTY; unlike
#                     sparse-clone-ports.sh's idempotent-reuse branch, every
#                     dependency-flow caller hands this a fresh runner-temp
#                     path, so an existing non-empty DEST is a caller bug and
#                     is refused rather than silently reused or overwritten
#   ROUTE_MATRIX_JSON compact JSON array of ROUTE matrix rows -- origins
#                     materialized are the sorted, deduplicated union of every
#                     row's extra_pkgs (a route-only row with no extra_pkgs
#                     contributes nothing)
#
# Zero origins across the whole matrix is a legitimate NOOP: DEST is created
# empty and this script exits 0 WITHOUT any network call -- a caller whose
# ROUTE matrix declares no dependency at all never pays for a checkout it will
# never read (today: most of it).
#
# POSIX sh; no bash-isms.

set -eu

usage() {
	printf 'Usage: %s URL SHA DEST ROUTE_MATRIX_JSON\n' "$0" >&2
	exit 1
}

[ $# -eq 4 ] || usage

URL="$1"
SHA="$2"
DEST="$3"
ROUTE_MATRIX="$4"

# issue #1676's same fetch-by-oid shape check, lifted from sparse-clone-ports.sh:
# a bare 40-hex commit SHA is the only accepted form -- never a branch/tag name.
_pfb_is_full_sha() {
	[ "${#1}" -eq 40 ] || return 1
	case "$1" in
		*[!0-9a-f]*) return 1 ;;
	esac
}

if ! _pfb_is_full_sha "$SHA"; then
	printf '%s: SHA must be a full 40-hex commit SHA, got: %s\n' "$0" "$SHA" >&2
	exit 1
fi

if [ -e "$DEST" ]; then
	if [ -d "$DEST" ] && [ -z "$(ls -A "$DEST" 2>/dev/null)" ]; then
		: # an existing, empty directory is fine -- nothing to refuse
	else
		printf '%s: %s exists and is not empty -- refusing to overwrite\n' "$0" "$DEST" >&2
		exit 1
	fi
fi

# No network yet: the origins query is pure local JSON, so a bogus/unreachable
# URL never matters on the zero-origins path below.
origins="$(printf '%s' "$ROUTE_MATRIX" | jq -r '[.[] | .extra_pkgs // [] | .[]] | unique | .[]')"

mkdir -p "$DEST"

if [ -z "$origins" ]; then
	exit 0
fi

git -C "$DEST" init -q
git -C "$DEST" remote add origin "$URL"
git -C "$DEST" fetch --depth 1 --filter=blob:none origin -- "$SHA"
printf '%s\n' "$origins" | git -C "$DEST" sparse-checkout set --cone --stdin
git -C "$DEST" checkout FETCH_HEAD
