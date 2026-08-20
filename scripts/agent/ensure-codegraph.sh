#!/bin/sh
# Ensure the requested checkout owns an exact-root CodeGraph index.

usage() {
	echo "usage: ensure-codegraph.sh [WORKTREE]" >&2
	exit 2
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	[ "$#" -le 1 ] || usage
	require_tool git
	require_tool codegraph

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "ensure-codegraph.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	[ -f "$root/.codegraph/codegraph.db" ] && exit 0

	echo "Initializing CodeGraph in $root" >&2
	codegraph init "$root" >&2 || {
		echo "ensure-codegraph.sh: CodeGraph initialization failed in '$root'" >&2
		exit 1
	}
	[ -f "$root/.codegraph/codegraph.db" ] || {
		echo "ensure-codegraph.sh: CodeGraph reported success without creating '$root/.codegraph/codegraph.db'" >&2
		exit 1
	}
}

main "$@"
