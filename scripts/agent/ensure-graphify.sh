#!/bin/sh
# Install or upgrade Graphify from the pfBlockerNG fork's immutable commit.
# Usage: ensure-graphify.sh [REPOSITORY]
# Prints the resolved Graphify launcher path on stdout.
#
# Under GitHub Actions (GITHUB_ACTIONS set) the pin is always installed. Anywhere
# else -- CI=true alone does not count, agent harnesses export it -- an installed
# uv tool `graphifyy` that beats the pin is kept and one stderr line says why
# (issue #3339). The higher version (PEP 440 release segment) wins; the pin's
# version comes from uv.lock when it records the pinned commit. Equal or
# uncomparable versions fall back to committer time, fetched shallowly from the
# pin's URL: the fork's integration branch is force-rebuilt, so ancestry cannot
# order builds. The identical commit reinstalls as before. Fail-safe: when the
# order cannot be established (an unidentifiable install, no commit recorded, a
# failed fetch or one past its 30-second bound, same second), the installed build
# is kept, so the pin never replaces a build that may be newer.

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
# must be kept instead of installing $pin_commit.
installed_beats_pin() {
	installed_version='' installed_commit='' pin_version='' installed_time='' pin_time=''
	keep_reason='order unknown'
	graphify_tools=$(uv tool dir 2>/dev/null) || return 1
	set -- "$graphify_tools"/graphifyy/lib/python*/site-packages/graphifyy-*.dist-info
	[ -d "$1" ] || return 1
	[ ! -f "${pyproject%/*}/uv.lock" ] ||
		pin_version=$(awk -v source="#$pin_commit\"" '
			/^version = "/ { version = $3 }
			/^source = / && index($0, source) { gsub(/"/, "", version); print version; exit }
		' "${pyproject%/*}/uv.lock")
	[ "$#" -eq 1 ] || return 0
	installed_version=$(sed -n '/^Version: /{s///p;q;}' "$1/METADATA" 2>/dev/null)
	[ -n "$installed_version" ] || return 0
	[ ! -f "$1/direct_url.json" ] ||
		installed_commit=$(sed -n 's/.*"commit_id": *"\([0-9a-f]\{40\}\)".*/\1/p' "$1/direct_url.json")
	[ "$installed_commit" != "$pin_commit" ] || return 1
	installed_release=${installed_version%%[!0-9.]*}
	pin_release=${pin_version%%[!0-9.]*}
	if [ -n "$installed_release" ] && [ -n "$pin_release" ]; then
		case $(awk -v a="${installed_release%.}" -v b="${pin_release%.}" 'BEGIN {
			n = split(a, x, "."); m = split(b, y, ".")
			for (i = 1; i <= n || i <= m; i++)
				if (x[i] + 0 != y[i] + 0) { print (x[i] + 0 > y[i] + 0 ? "newer" : "older"); exit }
		}') in
			newer) keep_reason='newer version' && return 0 ;;
			older) return 1 ;;
		esac
	fi
	[ -n "$installed_commit" ] || return 0
	graphify_scratch=$(mktemp -d "${TMPDIR:-/tmp}/ensure-graphify.XXXXXX") || return 0
	if git init -q --bare "$graphify_scratch" &&
		GIT_TERMINAL_PROMPT=0 timeout 30 git -C "$graphify_scratch" fetch -q --depth=1 --filter=tree:0 \
			"$pin_url" "$installed_commit" "$pin_commit" 2>/dev/null; then
		installed_time=$(git -C "$graphify_scratch" log -1 --no-show-signature --format=%ct "$installed_commit")
		pin_time=$(git -C "$graphify_scratch" log -1 --no-show-signature --format=%ct "$pin_commit")
	fi
	rm -rf "$graphify_scratch"
	[ -n "$installed_time" ] && [ -n "$pin_time" ] || return 0
	[ "$installed_time" -ne "$pin_time" ] || return 0
	[ "$installed_time" -gt "$pin_time" ] || return 1
	keep_reason='later commit'
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
	# The pin is a git source: the org-fork commit from pyproject.toml is the only
	# valid install target, so the spec must carry the pinned git+https:// URL
	# with a revision, not a bare name, a version pin, or an unpinned URL.
	case "$graphify_spec" in
		*graphifyy\[leiden\]*git+https://*@[0-9a-f]*) ;;
		*) fail "graphify package specification extracted from '$pyproject' is not a valid requirement (got: '$graphify_spec')" ;;
	esac

	pin_url=https://${graphify_spec#*git+https://}
	pin_commit=${pin_url##*@}
	pin_url=${pin_url%@*}

	if [ -z "${GITHUB_ACTIONS:-}" ] && installed_beats_pin; then
		echo "ensure-graphify.sh: keeping installed Graphify ${installed_version:-unknown}@${installed_commit:-unknown} over pin ${pin_version:-unknown}@$pin_commit ($keep_reason)" >&2
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
