#!/bin/sh
# One-time developer setup: activate tracked hooks and bootstrap CodeGraph.
#
# Run once after cloning:
#   sh scripts/setup-hooks.sh
#
# git cannot auto-apply a committed core.hooksPath (by design — cloning a repo
# must not silently install executable hooks), so this single explicit opt-in is
# the closest to "automatic". When CodeGraph is installed, the setup also creates
# this checkout's exact-root index.

set -eu

root=$(git rev-parse --show-toplevel)
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
# CodeGraph needs pyproject.toml. A scripts-only helper checkout
# (release-published.yml) still activates hooksPath on the writer repo.
if [ -f "$root/pyproject.toml" ] || [ -f "$script_dir/../pyproject.toml" ]; then
	has_project=1
else
	has_project=0
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
