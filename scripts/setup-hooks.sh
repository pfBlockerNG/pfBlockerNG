#!/bin/sh
# One-time developer setup: install Graphify from the org fork, activate tracked hooks, and bootstrap CodeGraph.
#
# Run once after cloning:
#   sh scripts/setup-hooks.sh
#
# git cannot auto-apply a committed core.hooksPath (by design — cloning a repo
# must not silently install executable hooks), so this single explicit opt-in is
# the closest to "automatic". The setup installs the pinned Graphify fork before
# activating .githooks; when CodeGraph is installed, it also creates this checkout's
# exact-root index.

set -eu

root=$(git rev-parse --show-toplevel)
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
sh "$script_dir/agent/ensure-graphify.sh" "$root" >/dev/null
git -C "$root" config core.hooksPath .githooks

if command -v codegraph >/dev/null 2>&1; then
	sh "$script_dir/agent/ensure-codegraph.sh" "$root"
fi

printf 'core.hooksPath set to: %s\n' "$(git -C "$root" config core.hooksPath)"
printf 'Active hooks:\n'
for hook in "$root"/.githooks/*; do
	[ -f "$hook" ] && printf '  %s\n' "$(basename "$hook")"
done
