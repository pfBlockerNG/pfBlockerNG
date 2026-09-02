#!/bin/sh
# Initialize repository-intelligence tools for one exact worktree root.

usage() {
	echo "usage: init-worktree-tools.sh [WORKTREE]" >&2
	exit 2
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	# shellcheck source=scripts/agent/resolve-graphify.sh
	. "$(dirname "$0")/resolve-graphify.sh"
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
	# Graphify is mandatory: fail before CodeGraph does any work when it is absent.
	resolve_graphify_launcher >/dev/null || exit 1

	sh "$(dirname "$0")/ensure-codegraph.sh" "$root" || exit $?
	# An unpatched Graphify parses this repository's PHP .inc files as Pascal, and a
	# bare `uv tool upgrade graphifyy` reverts the patch; repair it here so the next
	# `graphify update` extracts correctly.
	sh "$(dirname "$0")/patch-graphify.sh" || exit $?
	# The tracked root graph is never rewritten here. A fresh cut checks out the tree
	# the committed graph describes, and `graphify update` on that tree still rewrites
	# the file wholesale, so the worktree was born dirty and `wt remove` refused it
	# (issue #3091). Refresh the graph with the change that moves it. Building the
	# FIRST graph is a judgement call (which trees, whether the semantic layer earns
	# its cost, what .graphifyignore allows), deferred to an AI-assisted `/graphify` run.
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
