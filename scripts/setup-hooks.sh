#!/bin/sh
# One-time developer setup: point git at the repo's tracked hooks in .githooks.
#
# Run once after cloning:
#   sh scripts/setup-hooks.sh
#
# git cannot auto-apply a committed core.hooksPath (by design — cloning a repo
# must not silently install executable hooks), so this single explicit opt-in is
# the closest to "automatic". After running it, .githooks/pre-commit and
# .githooks/pre-push are active in this clone.

set -eu

root=$(git rev-parse --show-toplevel)
git -C "$root" config core.hooksPath .githooks

printf 'core.hooksPath set to: %s\n' "$(git -C "$root" config core.hooksPath)"
printf 'Active hooks:\n'
for hook in "$root"/.githooks/*; do
	[ -f "$hook" ] && printf '  %s\n' "$(basename "$hook")"
done
