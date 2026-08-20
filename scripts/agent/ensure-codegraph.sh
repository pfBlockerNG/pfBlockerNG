#!/bin/sh
# Ensure the requested checkout owns an exact-root CodeGraph index.

usage() {
	echo "usage: ensure-codegraph.sh [WORKTREE]" >&2
	exit 2
}

index_complete() {
	status=$(codegraph status --json "$root" 2>/dev/null) || return 1
	normalized=$(printf '%s' "$status" | tr -d '[:space:]')
	for required in \
		'"initialized":true' \
		'"worktreeMismatch":null' \
		'"reindexRecommended":false' \
		'"state":"complete"' \
		'"pendingRefs":0'; do
		case "$normalized" in
			*"$required"*) ;;
			*) return 1 ;;
		esac
	done
	return 0
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
	if [ ! -f "$root/.codegraph/codegraph.db" ]; then
		echo "Initializing CodeGraph in $root" >&2
		codegraph init "$root" >&2 || {
			echo "ensure-codegraph.sh: CodeGraph initialization failed in '$root'" >&2
			exit 1
		}
	elif ! index_complete; then
		echo "Rebuilding CodeGraph in $root" >&2
		codegraph index "$root" >&2 || {
			echo "ensure-codegraph.sh: CodeGraph rebuild failed in '$root'" >&2
			exit 1
		}
	fi
	[ -f "$root/.codegraph/codegraph.db" ] || {
		echo "ensure-codegraph.sh: CodeGraph reported success without creating '$root/.codegraph/codegraph.db'" >&2
		exit 1
	}
	index_complete || {
		echo "ensure-codegraph.sh: CodeGraph did not produce a complete index in '$root'" >&2
		exit 1
	}
}

main "$@"
