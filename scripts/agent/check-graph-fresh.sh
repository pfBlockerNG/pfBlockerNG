#!/bin/sh
# Prove that the tracked root graph equals a rebuild of its tree, or refresh it in place.
# Usage: check-graph-fresh.sh [--refresh] [WORKTREE]
#
# The rebuild is deterministic only under a fixed hash seed, so it always runs as
# `PYTHONHASHSEED=0 graphify update <root>` through the shared launcher resolver.
# Check mode saves graphify-out/graph.json aside, rebuilds, compares bytes, and puts
# the saved copy back whenever the tree would otherwise be left changed: a stale,
# failed, or interrupted rebuild. --refresh keeps the rebuilt graph.
#
# Exit: 0 fresh or refreshed, 1 stale or rebuild failed, 2 usage/precondition,
# 4 Graphify launcher missing (agent_env.sh convention).

set -u

usage() {
	echo 'usage: check-graph-fresh.sh [--refresh] [WORKTREE]' >&2
	exit 2
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	# shellcheck source=scripts/agent/resolve-graphify.sh
	. "$(dirname "$0")/resolve-graphify.sh"
	scrub_git_env "$0"
	require_tool git

	refresh=0
	case "${1:-}" in
		--refresh) refresh=1; shift ;;
		-*) usage ;;
	esac
	[ "$#" -le 1 ] || usage
	case "${1:-}" in
		-*) usage ;;
	esac

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "check-graph-fresh.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2
	graph=$root/graphify-out/graph.json
	[ -f "$graph" ] || {
		echo "check-graph-fresh.sh: no root graph at '$graph'; run /graphify in your AI assistant to build the first one" >&2
		exit 2
	}
	graphify_bin=$(resolve_graphify_launcher) || {
		echo 'TOOL-MISSING: graphify' >&2
		exit 4
	}

	scratch=$(mktemp -d "${TMPDIR:-/var/tmp}/check-graph-fresh.XXXXXX") || exit 2
	trap 'rm -rf "$scratch"' EXIT
	trap 'exit 1' HUP INT TERM
	saved=$scratch/graph.json
	cp "$graph" "$saved" || exit 2
	# From here on the tree is restored unless a verdict below says it may keep
	# the rebuilt graph; a signal during the rebuild takes the same exit path.
	restore=1
	trap '[ "$restore" = 0 ] || cp "$saved" "$graph"; rm -rf "$scratch"' EXIT

	PYTHONHASHSEED=0 "$graphify_bin" update "$root" >&2
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "check-graph-fresh.sh: rebuild failed (graphify update exited $rc); graphify-out/graph.json restored" >&2
		exit 1
	fi

	if [ "$refresh" = 1 ]; then
		restore=0
		if cmp -s "$saved" "$graph"; then
			echo 'check-graph-fresh.sh: refreshed (unchanged)' >&2
		else
			echo 'check-graph-fresh.sh: refreshed (changed)' >&2
		fi
		exit 0
	fi
	if cmp -s "$saved" "$graph"; then
		restore=0
		echo 'check-graph-fresh.sh: graph is fresh' >&2
		exit 0
	fi
	echo "check-graph-fresh.sh: STALE: graphify-out/graph.json differs from a rebuild of this tree; run 'PYTHONHASHSEED=0 graphify update .' and commit graphify-out/graph.json" >&2
	exit 1
}

main "$@"
