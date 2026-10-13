#!/bin/sh
# Install or upgrade Graphify from PyPI at or above the pyproject.toml floor.
# Usage: ensure-graphify.sh [REPOSITORY]
# Prints the resolved Graphify launcher path on stdout.
#
# Under GitHub Actions (GITHUB_ACTIONS set) the floor spec is always installed.
# Anywhere else -- CI=true alone does not count, agent harnesses export it -- an
# installed uv tool `graphifyy` that is a direct-URL (git or local) build at or
# above the floor is kept and one stderr line says why (issues #3339, #3495): a
# deliberately deployed build is never replaced by PyPI. Versions compare by their
# PEP 440 release segment. Fail-safe: when the installed build cannot be identified
# (two dist-info directories, no version), it is kept. An index install is handed
# to `uv tool install --upgrade`, which upgrades it and never downgrades it.

set -eu

usage() {
	echo "usage: ensure-graphify.sh [REPOSITORY]" >&2
	exit 2
}

fail() {
	echo "ensure-graphify.sh: $*" >&2
	exit 1
}

# Succeeds, naming why in $keep_reason, when the installed uv tool `graphifyy`
# must be kept instead of installing $graphify_spec.
installed_beats_pin() {
	installed_version='' installed_commit=''
	keep_reason='order unknown'
	graphify_tools=$(uv tool dir 2>/dev/null) || return 1
	set -- "$graphify_tools"/graphifyy/lib/python*/site-packages/graphifyy-*.dist-info
	[ -d "$1" ] || return 1
	[ "$#" -eq 1 ] || return 0
	[ -f "$1/direct_url.json" ] || return 1
	installed_commit=$(sed -n 's/.*"commit_id": *"\([0-9a-f]\{40\}\)".*/\1/p' "$1/direct_url.json")
	installed_version=$(sed -n '/^Version: /{s///p;q;}' "$1/METADATA" 2>/dev/null)
	installed_release=${installed_version%%[!0-9.]*}
	[ -n "$installed_release" ] || return 0
	awk -v a="${installed_release%.}" -v b="$pin_floor" 'BEGIN {
		n = split(a, x, "."); m = split(b, y, ".")
		for (i = 1; i <= n || i <= m; i++)
			if (x[i] + 0 != y[i] + 0) exit x[i] + 0 < y[i] + 0
	}' || return 1
	keep_reason='direct-URL build at or above the floor'
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	# shellcheck source=scripts/agent/resolve-graphify.sh
	. "$(dirname "$0")/resolve-graphify.sh"
	scrub_git_env "$0"
	[ "$#" -le 1 ] || usage
	require_tool git
	require_tool uv

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "ensure-graphify.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(cd "$root" && pwd -P) || {
		echo "ensure-graphify.sh: cannot resolve Git root '$root'" >&2
		exit 2
	}
	pyproject=$root/pyproject.toml
	if [ ! -f "$pyproject" ]; then
		helper_root=$(cd "$(dirname "$0")/../.." && pwd -P) 2>/dev/null || :
		[ -n "${helper_root:-}" ] && [ -f "$helper_root/pyproject.toml" ] && pyproject=$helper_root/pyproject.toml
	fi
	[ -f "$pyproject" ] ||
		fail "required project configuration '$pyproject' is missing"
	graphify_spec=''
	while IFS= read -r line || [ -n "$line" ]; do
		line=${line#"${line%%[![:space:]]*}"}
		case "$line" in
			\#*) continue ;;
			*\"graphifyy\[leiden\]*)
				# issue #3309: %% takes the FIRST quoted span, not the LAST -- a trailing
				# comment (even one holding a quote) can no longer leak into the spec.
				graphify_spec=${line#*\"}
				graphify_spec=${graphify_spec%%\"*}
				break
				;;
		esac
	done < "$pyproject"
	[ -n "$graphify_spec" ] ||
		fail "graphify package specification not found in '$pyproject'"
	# The pin is a PyPI floor of dot-separated release numbers: no git source, exact
	# pin, upper bound, pre-release, or anything that is not a plain release.
	pin_floor=${graphify_spec#graphifyy\[leiden\]>=}
	case "$graphify_spec:$pin_floor" in
		*:"$graphify_spec" | *: | *:*[!0-9.]* | *:.* | *:*. | *:*..*)
			fail "graphify package specification extracted from '$pyproject' is not a valid requirement (got: '$graphify_spec')" ;;
	esac

	if [ -z "${GITHUB_ACTIONS:-}" ] && installed_beats_pin; then
		echo "ensure-graphify.sh: keeping installed Graphify ${installed_version:-unknown}@${installed_commit:-unknown} over $graphify_spec ($keep_reason)" >&2
	else
		uv tool install --upgrade "$graphify_spec" 1>&2 ||
			fail 'Graphify installation failed'
	fi
	graphify_uv_bin=$(uv tool dir --bin 2>/dev/null) ||
		fail 'cannot resolve uv tool executable directory'
	graphify_bin=$(absolutize_graphify_launcher "$graphify_uv_bin/graphify") ||
		fail 'cannot resolve the installed Graphify launcher'
	[ -x "$graphify_bin" ] ||
		fail "installed Graphify launcher '$graphify_bin' is not executable"
	"$graphify_bin" install --platform agents 1>&2 ||
		fail 'Graphify skill installation failed'
	printf '%s\n' "$graphify_bin"
}

main "$@"
