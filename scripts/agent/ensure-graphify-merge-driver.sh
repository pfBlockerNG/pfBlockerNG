#!/bin/sh
# Install Graphify and register its union merge driver for graphify-out/graph.json
# in the requested checkout.
#
# Registration is two `git config` writes, never the Graphify CLI's own hook
# installer: that command also drops post-commit and post-checkout hooks into the
# directory core.hooksPath names, and this repository's tracked hooks own the
# graph's lifecycle (issue #3139). The driver's output is never trusted either --
# the push gate rebuilds -- it only keeps conflict markers out of the graph.

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

	# The shared installer applies the .inc override first, so the launcher it
	# returns is the one a rebuild must use.
	graphify_bin=$(sh "$(dirname "$0")/ensure-graphify.sh" "$root") || {
		echo "ensure-graphify-merge-driver.sh: Graphify setup failed for '$root'" >&2
		exit 1
	}
	# git hands the driver string to a shell, so the launcher path is quoted, and
	# expands %-sequences (%O %A %B) even inside the quotes; a path that the string
	# cannot carry fails closed rather than registering a driver that never runs.
	case "$graphify_bin" in
		*[\"\$\`\\%]*)
			echo "ensure-graphify-merge-driver.sh: Graphify launcher path '$graphify_bin' cannot be quoted for merge.graphify.driver" >&2
			exit 1
			;;
	esac
	driver="\"$graphify_bin\" merge-driver %O %A %B"
	{
		git -C "$root" config merge.graphify.name 'graphify graph.json union merge' &&
			git -C "$root" config merge.graphify.driver "$driver"
	} || {
		echo "ensure-graphify-merge-driver.sh: cannot record merge.graphify.driver '$driver' in '$root'" >&2
		exit 1
	}

	registered=$(git -C "$root" config --local --get merge.graphify.driver 2>/dev/null || :)
	[ "$registered" = "$driver" ] || {
		echo "ensure-graphify-merge-driver.sh: merge.graphify.driver must read back as '$driver' (got: '${registered:-missing}')" >&2
		exit 1
	}
}

main "$@"
