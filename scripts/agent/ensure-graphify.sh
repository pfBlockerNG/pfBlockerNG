#!/bin/sh
# Install or upgrade Graphify and apply this checkout's temporary .inc=php patch.
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
	scrub_git_env "$0"
	[ "$#" -le 1 ] || usage
	require_tool git
	require_tool uv

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "ensure-graphify.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(CDPATH='' cd "$root" && pwd -P) || {
		echo "ensure-graphify.sh: cannot resolve Git root '$root'" >&2
		exit 2
	}
	# Prefer the target checkout's policy; foreign targets fall back to this
	# trusted helper checkout without receiving repository files of their own.
	patch_graphify=$root/scripts/agent/patch-graphify.sh
	[ -f "$patch_graphify" ] || patch_graphify=$(dirname "$0")/patch-graphify.sh
	[ -f "$patch_graphify" ] ||
		fail "required target or trusted sibling patch-graphify.sh is missing"

	uv tool install --upgrade 'graphifyy>=0.9.51' || fail 'Graphify installation failed'
	sh "$patch_graphify" || fail "Graphify language-override patch failed for '$root'"
}

main "$@"
