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
	sh "$(dirname "$0")/ensure-codegraph.sh" "$root" || exit $?
	# Never `graphify update` here: it rewrites the tracked graph wholesale, so a fresh
	# cut was born dirty and `wt remove` refused it (issue #3091). The FIRST graph's
	# scope is a judgement call, deferred to an AI-assisted `/graphify` run.
	[ -f "$root/graphify-out/graph.json" ] ||
		echo "No Graphify root graph in $root; run /graphify in your AI assistant to build one." >&2

	case "${OMP_CLI:-}${PI_CLI:-}" in
		'') ;;
		*) exit 0 ;;
	esac
	command -v serena >/dev/null 2>&1 || exit 0
	serena project index "$root"
}

main "$@"
