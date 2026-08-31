#!/bin/sh
# Install Graphify and register its merge driver in the requested checkout.

usage() {
	echo "usage: ensure-graphify-merge-driver.sh [REPOSITORY]" >&2
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
		echo "ensure-graphify-merge-driver.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(cd "$root" && pwd -P) || {
		echo "ensure-graphify-merge-driver.sh: cannot resolve Git root '$root'" >&2
		exit 2
	}

	# The hook rebuilds the graph, so the shared installer applies the override first.
	sh "$(dirname "$0")/ensure-graphify.sh" "$root" || {
		echo "ensure-graphify-merge-driver.sh: Graphify setup failed for '$root'" >&2
		exit 1
	}
	(cd "$root" && graphify hook install) || {
		echo "ensure-graphify-merge-driver.sh: Graphify hook installation failed in '$root'" >&2
		exit 1
	}

	driver=$(git -C "$root" config --local --get merge.graphify.driver 2>/dev/null || :)
	case "$driver" in
		*"graphify merge-driver %O %A %B"*) ;;
		*)
			echo "ensure-graphify-merge-driver.sh: merge.graphify.driver must contain 'graphify merge-driver %O %A %B' (got: '${driver:-missing}')" >&2
			exit 1
			;;
	esac
}

main "$@"
