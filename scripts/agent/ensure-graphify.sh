#!/bin/sh
# Install or upgrade Graphify from the pfBlockerNG fork's immutable commit.
# Usage: ensure-graphify.sh [REPOSITORY]

set -eu

usage() {
	echo "usage: ensure-graphify.sh [REPOSITORY]" >&2
	exit 2
}

fail() {
	echo "ensure-graphify.sh: $*" >&2
	exit 1
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
		case "$line" in
			*\"graphifyy\[leiden\]*)
				graphify_spec=${line#*\"}
				graphify_spec=${graphify_spec%\"*}
				break
				;;
		esac
	done < "$pyproject"
	[ -n "$graphify_spec" ] ||
		fail "graphify package specification not found in '$pyproject'"

	uv tool install --upgrade "$graphify_spec" 1>&2 ||
		fail 'Graphify installation failed'
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
