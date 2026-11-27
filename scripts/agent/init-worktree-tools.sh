#!/bin/sh
# Prepare one exact worktree root: a worktree under the primary's .worktrees/ has that folder ignore itself
# (ignore_worktrees, #4265).

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
}

main "$@"
