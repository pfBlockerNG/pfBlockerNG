#!/bin/sh
# Initialize repository-intelligence tools for one exact worktree root.

usage() {
	echo "usage: init-worktree-tools.sh [WORKTREE]" >&2
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
		echo "init-worktree-tools.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2
	common=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir) || exit 2
	primary=$(CDPATH='' cd "$common/.." && pwd -P) || exit 2
	case "$root" in
		"$primary/.worktrees/"*) ignore_worktrees "$primary/.worktrees" || exit $? ;;
	esac
	sh "$(dirname "$0")/ensure-codegraph.sh" "$root" || exit $?

	case "${OMP_CLI:-}${PI_CLI:-}" in
		'') ;;
		*) exit 0 ;;
	esac
	command -v serena >/dev/null 2>&1 || exit 0
	serena project index "$root"
}

main "$@"
