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
# Graphify/CodeGraph need pyproject.toml. A scripts-only helper checkout
# (release-published.yml) still activates hooksPath on the writer repo.
if [ -f "$root/pyproject.toml" ] || [ -f "$script_dir/../pyproject.toml" ]; then
	has_project=1
else
	has_project=0
fi
if [ "$has_project" -eq 1 ]; then
	sh "$script_dir/agent/ensure-graphify.sh" "$root" >/dev/null
fi
git -C "$root" config core.hooksPath .githooks

if [ "$has_project" -eq 1 ] && command -v codegraph >/dev/null 2>&1; then
	sh "$script_dir/agent/ensure-codegraph.sh" "$root"
fi

printf 'core.hooksPath set to: %s\n' "$(git -C "$root" config core.hooksPath)"
printf 'Active hooks:\n'
for hook in "$root"/.githooks/*; do
	[ -f "$hook" ] || continue
	printf '  %s\n' "$(basename "$hook")"
done
