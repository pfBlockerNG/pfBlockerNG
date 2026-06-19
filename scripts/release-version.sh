#!/bin/sh
# Single source of truth for the release tag / version scheme.
#
# Tag formats (semver core X.Y.Z, no odd/even conventions):
#   * vX.Y.Z              -> STABLE release    (cut from `main` only)
#   * vX.Y.Z.alpha.N      -> ALPHA  prerelease (cut from `devel` only)
#   * vX.Y.Z.beta.N       -> BETA   prerelease (cut from `devel` only)
#   * vX.Y.Z.rc.N         -> RC     prerelease (cut from `devel` only)
# (N is a 1+ digit sequence number: alpha.1, alpha.2, ..., beta.1, ..., rc.1, ...)
#
# FreeBSD pkg orders these correctly out of the box:
#   4.0.0.alpha.1 < 4.0.0.alpha.2 < 4.0.0.beta.1 < 4.0.0.rc.1 < 4.0.0
# pkg's version comparison special-cases the stage keywords alpha/beta/pre/rc
# (libpkg/pkg_version.c): a component that starts with a letter gets an implicit
# leading number of -1, so any `.alpha`/`.beta`/`.rc` component sorts below the
# bare release (whose missing component is 0); the keyword weight (alpha < beta <
# rc) breaks ties between two prereleases. The tag therefore maps to a pkg-safe
# PORTVERSION verbatim (it carries no '-', the pkg name/version separator) — devel
# keeps its .alpha.N/.beta.N/.rc.N suffix, distinguishing it from the stable X.Y.Z
# within its own (-devel) package name.
#
# Usage:
#   release-version.sh <tag> [branch]
#
# Validates <tag>'s shape and prints, one KEY=VALUE per line:
#   version=<tag without leading v>
#   channel=devel|stable
#   prerelease=true|false
#   prekind=alpha|beta|rc|     (empty for stable)
#   portversion=<version>      (pkg-safe; == version)
#
# Exit 0 + KEY=VALUE on a valid tag. Exit 1 + error on stderr on a malformed
# tag. If [branch] is given (main|devel), also enforces branch<->channel:
# `main` may cut ONLY stable; `devel` may cut ONLY a prerelease — mismatch is
# an error. Other/absent branch values skip the branch check (e.g. dry-run).

set -eu

tag="${1:-}"
branch="${2:-}"

if [ -z "$tag" ]; then
	echo "error: no tag given" >&2
	echo "usage: release-version.sh <tag> [branch]" >&2
	exit 1
fi

version="${tag#v}"

# Classify by shape. Stage prereleases carry a .(alpha|beta|rc).<N> suffix; stable
# is the bare semver core. grep -E with anchors gives a full-string match. Numeric
# parts are strict semver — no leading zeros (`0` or `[1-9][0-9]*`); the stage
# sequence number is >= 1 (`[1-9][0-9]*`), per the documented `N >= 1`.
if printf '%s' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
	channel="stable"
	prerelease="false"
	prekind=""
elif printf '%s' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(alpha|beta|rc)\.[1-9][0-9]*$'; then
	channel="devel"
	prerelease="true"
	# Extract the stage kind (alpha|beta|rc) from the trailing .<kind>.<N> component.
	prekind="$(printf '%s' "$version" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+\.(alpha|beta|rc)\.[0-9]+$/\1/')"
else
	echo "error: '${tag}' is not a valid release tag" >&2
	echo "       stable: vX.Y.Z   prerelease (devel): vX.Y.Z.alpha.N | .beta.N | .rc.N" >&2
	exit 1
fi

# PORTVERSION is the version verbatim — pkg-safe (no '-'); the channel lives in
# the port's PKGNAMESUFFIX, not the version string.
portversion="$version"

# Branch<->channel consistency (only when a known branch is supplied).
case "$branch" in
	main)
		if [ "$channel" != "stable" ]; then
			echo "error: '${tag}' is a ${channel} prerelease but points at 'main'; stable tags from main are vX.Y.Z" >&2
			exit 1
		fi
		;;
	devel)
		if [ "$channel" != "devel" ]; then
			echo "error: '${tag}' is a stable tag but points at 'devel'; prerelease tags from devel are vX.Y.Z.alpha.N | .beta.N | .rc.N" >&2
			exit 1
		fi
		;;
	"") ;;  # no branch context (e.g. dry-run): skip the branch check
	*)  ;;  # unknown branch: skip (caller validates reachability separately)
esac

echo "version=${version}"
echo "channel=${channel}"
echo "prerelease=${prerelease}"
echo "prekind=${prekind}"
echo "portversion=${portversion}"
