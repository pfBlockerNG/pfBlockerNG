#!/bin/sh
# Initialize repository-intelligence tools for one exact worktree root. A worktree under the primary's
# .worktrees/ also has that folder ignore itself (ignore_worktrees, #4265), whether or not the tools are installed.

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

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "init-worktree-tools.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2
	common=$(git -C "$root" rev-parse --git-common-dir) || exit 2
	primary=$(CDPATH='' cd "$root" && cd "$common/.." && pwd -P) || exit 2	# a relative common dir is the root's
	case "$root" in
		"$primary/.worktrees/"*) ignore_worktrees "$primary/.worktrees" || exit $? ;;
	esac
	require_tool codegraph
	sh "$(dirname "$0")/ensure-codegraph.sh" "$root" || exit $?

	case "${OMP_CLI:-}${PI_CLI:-}" in
		'') ;;
		*) exit 0 ;;
	esac
	command -v serena >/dev/null 2>&1 || exit 0
	serena project index "$root"
}

main "$@"
