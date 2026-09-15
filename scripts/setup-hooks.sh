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

# Graphify's CLI commit-hook writer drops post-commit/post-checkout into
# whatever core.hooksPath names, and leftover copies stay in .git/hooks when
# hooksPath was later set. Those rebuilds are retired (issue #3139). Never
# invoke that writer or the counterpart that also drops merge.graphify.driver.
remove_graphify_git_hook() {
	_file=$1
	_start=$2
	_end=$3
	[ -f "$_file" ] || return 0
	grep -Fq "$_start" "$_file" || return 0
	awk -v s="$_start" -v e="$_end" '
		index($0, s) { if (!st) st = NR }
		st && NR >= st && index($0, e) { ok = 1; exit }
		END { exit !ok }
	' "$_file" || return 0
	_tmp=${_file}.graphify-strip
	awk -v s="$_start" -v e="$_end" '
		index($0, s) && !inblock { inblock = 1; buf = $0 ORS; next }
		inblock {
			buf = buf $0 ORS
			if (index($0, e)) { inblock = 0; buf = ""; next }
			next
		}
		{ print }
		END { if (inblock) printf "%s", buf }
	' "$_file" > "$_tmp" || {
		rm -f "$_tmp"
		return 1
	}
	_leftover=$(sed '1{/^#!/d;}' "$_tmp" | grep -v '^[[:space:]]*$' || true)
	if [ -z "$_leftover" ]; then
		rm -f "$_file" "$_tmp"
	else
		[ -x "$_file" ] && chmod +x "$_tmp"
		mv "$_tmp" "$_file"
	fi
}
common=$(git -C "$root" rev-parse --git-common-dir)
case "$common" in
	/*) ;;
	*) common=$root/$common ;;
esac
for dir in "$common/hooks" "$root/.githooks"; do
	remove_graphify_git_hook "$dir/post-commit" '# graphify-hook-start' '# graphify-hook-end'
	remove_graphify_git_hook "$dir/post-checkout" '# graphify-checkout-hook-start' '# graphify-checkout-hook-end'
done
unset common

if [ "$has_project" -eq 1 ] && command -v codegraph >/dev/null 2>&1; then
	sh "$script_dir/agent/ensure-codegraph.sh" "$root"
fi

printf 'core.hooksPath set to: %s\n' "$(git -C "$root" config core.hooksPath)"
printf 'Active hooks:\n'
for hook in "$root"/.githooks/*; do
	[ -f "$hook" ] || continue
	printf '  %s\n' "$(basename "$hook")"
done
