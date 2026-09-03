#!/bin/sh
# Install or upgrade Graphify from the pfBlockerNG fork's immutable commit.
# Usage: ensure-graphify.sh [REPOSITORY]

set -eu

usage() {
	echo "usage: ensure-graphify.sh [REPOSITORY]" >&2
	exit 2
}

fail() {
	echo "ensure-graphify.sh: $*" >&2
	exit 1
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	# shellcheck source=scripts/agent/resolve-graphify.sh
	. "$(dirname "$0")/resolve-graphify.sh"
	scrub_git_env "$0"
	[ "$#" -le 1 ] || usage
	require_tool git
	require_tool uv

	target=${1:-.}
	git -C "$target" rev-parse --show-toplevel >/dev/null 2>&1 || {
		echo "ensure-graphify.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	uv tool install --upgrade 'graphifyy[leiden] @ git+https://github.com/pfBlockerNG/graphify@67cd9e233fca7cdc3c81ccd36e0ac0d67de46d87' 1>&2 ||
		fail 'Graphify installation failed'
	graphify_bin=$(resolve_graphify_launcher) ||
		fail 'cannot resolve the installed Graphify launcher'
	printf '%s\n' "$graphify_bin"
}

main "$@"
