#!/bin/sh
# Apply the vendored Graphify .inc language-override patch to the installed package.
# Usage: sh scripts/agent/patch-graphify.sh [REPOSITORY]
#
# Graphify's suffix map sends .inc to the Pascal extractor, so this repository's PHP
# include files extract as a handful of incidental nodes while extraction still
# reports success (issue #2810). Upstream fixes that in Graphify-Labs/graphify#3075,
# which is unreleased, so the patch rides in .agents/patches/ and is re-applied after
# every install: a bare `uv tool upgrade graphifyy` replaces site-packages and reverts
# it. Delete this script, its patch, and its three call sites once a released
# graphifyy provides the override API -- this script no-ops from that release on.
#
# Progress goes to stderr, like the sibling scripts in this directory: callers keep a
# clean stdout.

set -eu

PATCH_REL='.agents/patches/graphify-3075-language-overrides.patch'
UPSTREAM='Graphify-Labs/graphify#3075'

usage() {
	echo "usage: patch-graphify.sh [REPOSITORY]" >&2
	exit 2
}

fail() {
	echo "patch-graphify.sh: $*" >&2
	exit 1
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	[ "$#" -le 1 ] || usage
	require_tool git

	target=${1:-.}
	root=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || {
		echo "patch-graphify.sh: '$target' is not a git worktree" >&2
		exit 2
	}
	root=$(CDPATH='' cd "$root" && pwd -P) || exit 2

	# The script and its patch always ship together, so the patch comes from this
	# script's own checkout -- a worktree cut from a branch that predates the patch
	# still initializes against the invoking checkout's copy.
	checkout=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd -P) || exit 2
	patch_file=$checkout/$PATCH_REL
	[ -f "$patch_file" ] || fail "vendored patch '$patch_file' is missing"

	if [ -n "${PFB_GRAPHIFY_PACKAGE_DIR:-}" ]; then
		# A named package tree is not tied to a tool venv (a nonstandard install, or
		# a test's throwaway copy), so it is imported with the ambient python3.
		require_tool python3
		interpreter=python3
		package=$PFB_GRAPHIFY_PACKAGE_DIR
	else
		require_tool sed
		graphify_bin=$(command -v graphify) ||
			fail "Graphify is not installed; run 'uv tool install --upgrade graphifyy' first"
		# A uv tool venv carries its Python minor version in the site-packages path,
		# so the interpreter that owns the package is read off the CLI's own shebang
		# and the package directory is derived from it -- neither is ever hardcoded.
		# A wrapper or a shim hides the interpreter, and the repository's own shell
		# fixtures stub `graphify` with /bin/sh, so an unreadable shebang falls back
		# to the ambient python3 rather than failing: a Graphify this script cannot
		# reach is a skip, never a dead worktree cut. The tracked graph's include-node
		# floor catches the resulting Pascal parse if a real install is ever skipped.
		interpreter=$(sed -n '1s/^#![[:space:]]*//p' "$graphify_bin")
		case "${interpreter%% *}" in
			/*python*) ;;
			*) interpreter=$(command -v python3 || :) ;;
		esac
		package=''
		if [ -n "$interpreter" ] && [ -x "$interpreter" ]; then
			package=$("$interpreter" -c 'import graphify, os; print(os.path.dirname(graphify.__file__))' 2>/dev/null || :)
		fi
		if [ -z "$package" ]; then
			echo "patch-graphify.sh: cannot locate an importable Graphify package for '$graphify_bin'; skipping the $UPSTREAM override" >&2
			return 0
		fi
	fi
	[ -d "$package" ] || fail "Graphify package directory '$package' does not exist"
	site=$(CDPATH='' cd "$package/.." && pwd -P) || exit 2

	# Ask the package itself, not the file text: this no-ops both on an already
	# patched install and on the release that finally carries the change upstream.
	if PYTHONPATH="$site${PYTHONPATH:+:$PYTHONPATH}" "$interpreter" -c \
		'import graphify.rcfile as rc; raise SystemExit(0 if hasattr(rc, "activate_language_overrides") else 1)' \
		>/dev/null 2>&1; then
		echo "patch-graphify.sh: '$package' already provides the .inc language override; nothing to patch" >&2
		return 0
	fi

	require_tool patch
	# Dry run first: a patch that fails halfway would leave a broken installation.
	patch_output=$(cd "$site" && patch -p1 --forward -V none --dry-run < "$patch_file" 2>&1) || {
		printf '%s\n' "$patch_output" >&2
		fail "vendored patch does not apply to '$package' (tracks $UPSTREAM); refresh Graphify with 'uv tool install --reinstall graphifyy', or delete the patch once upstream releases the change"
	}
	patch_output=$(cd "$site" && patch -p1 --forward -V none < "$patch_file" 2>&1) || {
		printf '%s\n' "$patch_output" >&2
		fail "vendored patch failed midway through '$package' (tracks $UPSTREAM); reinstall Graphify with 'uv tool install --reinstall graphifyy'"
	}
	echo "patch-graphify.sh: applied $UPSTREAM to '$package'" >&2

	# The unpatched AST cache keys an entry by file content alone, with no language
	# component (graphify/cache.py load_cached), so Pascal-parsed entries would be
	# served for the remapped PHP includes until the whole AST cache is dropped.
	cache=$root/graphify-out/cache/ast
	if [ -d "$cache" ]; then
		rm -rf "$cache" || fail "cannot purge the language-blind AST cache '$cache'"
		echo "patch-graphify.sh: purged the language-blind AST cache '$cache'" >&2
	fi
}

main "$@"
