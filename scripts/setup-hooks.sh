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
#
# CI writers: setup-hooks.sh --writer PROFILE HOOK_DIR
# PROFILE is ci-metadata or ports. HOOK_DIR must live outside the checkout so
# copied commit hooks survive branch/worktree transitions without Graphify.

set -eu

usage() {
	echo "usage: setup-hooks.sh [--writer {ci-metadata|ports} HOOK_DIR]" >&2
	exit 2
}

if [ "${1:-}" = "--writer" ]; then
	[ "$#" -eq 3 ] || usage
	writer_profile=$2
	writer_hook_dir=$3
	case "$writer_profile" in
	ci-metadata|ports) ;;
	*) usage ;;
	esac
	writer_script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
	writer_corpus_dir=$writer_script_dir/../.githooks
	writer_root=$(git rev-parse --show-toplevel)

	# Validate the full corpus before installing or changing core.hooksPath.
	for writer_file in check-commit-identity.sh prepare-commit-msg commit-msg ci-writer/pre-commit; do
		[ -f "$writer_corpus_dir/$writer_file" ] || {
			printf 'setup-hooks.sh: writer hook corpus missing: %s/%s\n' "$writer_corpus_dir" "$writer_file" >&2
			exit 1
		}
	done
	mkdir -p -- "$writer_hook_dir"
	writer_hook_dir=$(CDPATH='' cd -- "$writer_hook_dir" && pwd -P)
	for writer_file in check-commit-identity.sh prepare-commit-msg commit-msg ci-writer/pre-commit; do
		cp -- "$writer_corpus_dir/$writer_file" "$writer_hook_dir/${writer_file##*/}"
		chmod +x -- "$writer_hook_dir/${writer_file##*/}"
	done
	printf '%s\n' "$writer_profile" > "$writer_hook_dir/PROFILE"
	git -C "$writer_root" config core.hooksPath "$writer_hook_dir"
	printf 'Writer hooks (%s) installed at: %s\n' "$writer_profile" "$writer_hook_dir"
	exit 0
fi

[ "$#" -eq 0 ] || usage

root=$(git rev-parse --show-toplevel)
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
# Graphify/CodeGraph require project configuration; writer mode returns above.
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
