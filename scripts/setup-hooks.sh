#!/bin/sh
# One-time developer setup: activate tracked Git hooks and bootstrap CodeGraph.
#
# Run once after cloning:
#   sh scripts/setup-hooks.sh
#
# git cannot auto-apply a committed core.hooksPath (by design — cloning a repo
# must not silently install executable hooks), so this single explicit opt-in is
# the closest to "automatic". After running it, .githooks/pre-commit and
# .githooks/pre-push are active in this clone. When CodeGraph is installed, the
# same command also creates this checkout's exact-root index.

set -eu

root=$(git rev-parse --show-toplevel)
git -C "$root" config core.hooksPath .githooks

if command -v codegraph >/dev/null 2>&1; then
	script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
	sh "$script_dir/agent/ensure-codegraph.sh" "$root"
fi

# .gitattributes marks graphify-out/graph.json merge=graphify. CI registers that
# driver through scripts/agent/ensure-graphify-merge-driver.sh, but a developer
# clone needs it too: without the driver, git text-merges generated JSON on any
# local merge, rebase or cherry-pick that touches the graph, which yields a
# conflicted or structurally invalid graph instead of a union. Registered here
# rather than by that script because the CI one force-upgrades Graphify, which is
# not a developer's opt-in to make.
#
# The interpreter must be one that can import graphify — a bare python3 on PATH
# usually cannot — so probe the way the hooks do, and stay silent when Graphify
# is absent: this is an optional local convenience, not a precondition.
if command -v graphify >/dev/null 2>&1; then
	gfy_py=''
	[ -f "$root/graphify-out/.graphify_python" ] && gfy_py=$(cat "$root/graphify-out/.graphify_python")
	if [ -z "$gfy_py" ] && command -v uv >/dev/null 2>&1; then
		gfy_py=$(uv tool run --from graphifyy python -c 'import sys; print(sys.executable)' 2>/dev/null || true)
	fi
	if [ -z "$gfy_py" ]; then
		gfy_bin=$(command -v graphify || true)
		[ -n "$gfy_bin" ] && gfy_py=$(head -1 "$gfy_bin" | tr -d '#!')
	fi
	if [ -n "$gfy_py" ] && "$gfy_py" -c 'import graphify' 2>/dev/null; then
		git -C "$root" config merge.graphify.name 'graphify graph.json union merge'
		git -C "$root" config merge.graphify.driver "\"$gfy_py\" -m graphify merge-driver %O %A %B"
		printf 'merge.graphify.driver registered\n'
	else
		printf 'Graphify found but its interpreter is not resolvable; merge=graphify driver not registered\n' >&2
	fi
fi

printf 'core.hooksPath set to: %s\n' "$(git -C "$root" config core.hooksPath)"
printf 'Active hooks:\n'
for hook in "$root"/.githooks/*; do
	[ -f "$hook" ] && printf '  %s\n' "$(basename "$hook")"
done
