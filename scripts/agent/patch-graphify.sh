#!/bin/sh
# Apply the vendored Graphify .inc language-override patch to the installed package.
# Usage: sh scripts/agent/patch-graphify.sh
#
# Graphify's suffix map sends .inc to the Pascal extractor, so this repository's PHP
# include files extract as a handful of incidental nodes while extraction still
# reports success (issue #2810). Upstream fixes that in Graphify-Labs/graphify#3075,
# which is unreleased, so the patch rides in .agents/patches/ and is re-applied after
# every install: a bare `uv tool upgrade graphifyy` replaces site-packages and reverts
# it. Delete this script, its patch, and its two call sites once a released graphifyy
# provides the override API -- this script no-ops from that release on.
#
# No repository is touched and no cache is purged: the patch salts the AST cache key
# with the remapped language (rcfile.cache_salt, cache._salted_key, salt= threaded
# through every extract.py cache call), so a pre-patch Pascal entry can never be served
# for a .inc file.
#
# Progress goes to stderr, like the sibling scripts in this directory: callers keep a
# clean stdout.

set -eu

PATCH_REL='.agents/patches/graphify-3075-language-overrides.patch'
UPSTREAM='Graphify-Labs/graphify#3075'

fail() {
	echo "patch-graphify.sh: $*" >&2
	exit 1
}

# A Graphify this script cannot reach is a skip, never a dead worktree cut and never a
# guess. The tracked graph's include-node floor catches a real install that got skipped.
skip() {
	echo "patch-graphify.sh: $*; skipping the $UPSTREAM override" >&2
	exit 0
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"

	# The script and its patch always ship together, so the patch comes from this
	# script's own checkout -- a worktree cut from a branch that predates the patch
	# still initializes against the invoking checkout's copy.
	checkout=$(CDPATH='' cd "$(dirname "$0")/../.." && pwd -P) || exit 2
	patch_file=$checkout/$PATCH_REL
	[ -f "$patch_file" ] || fail "vendored patch '$patch_file' is missing"

	require_tool sed
	graphify_bin=$(command -v graphify) ||
		fail "Graphify is not installed; run 'uv tool install --upgrade graphifyy' first"
	# A uv tool venv carries its Python minor version in the site-packages path, so the
	# interpreter that owns the package is read off the CLI's own shebang -- never
	# hardcoded, and never the ambient python3: a different interpreter imports a
	# DIFFERENT graphify, so falling back patches an unrelated package and reports
	# success. A wrapper or shim that hides the interpreter is therefore a skip.
	interpreter=$(sed -n '1s/^#![[:space:]]*//p' "$graphify_bin")
	interpreter=${interpreter%% *}
	case "$interpreter" in
		/*python*) ;;
		*) skip "'$graphify_bin' does not name a Python interpreter on its shebang" ;;
	esac

	# Both probes run isolated (-I: no cwd, no PYTHONPATH, no user site) from a neutral
	# directory, so a module beside the caller cannot answer for the installed package
	# -- or run at all. The CLI's own interpreter already resolves its own graphify.
	package=$(cd / && "$interpreter" -I -c \
		'import graphify, os; print(os.path.dirname(graphify.__file__))' 2>/dev/null) || package=''
	[ -n "$package" ] || skip "cannot locate an importable Graphify package for '$graphify_bin'"
	[ -d "$package" ] || fail "Graphify package directory '$package' does not exist"
	site=$(CDPATH='' cd "$package/.." && pwd -P) || exit 2

	# Ask the package itself, not the file text: this no-ops both on an already
	# patched install and on the release that finally carries the change upstream.
	if (cd / && "$interpreter" -I -c \
		'import graphify.rcfile as rc; raise SystemExit(0 if hasattr(rc, "activate_language_overrides") else 1)') \
		>/dev/null 2>&1; then
		echo "patch-graphify.sh: '$package' already provides the .inc language override; nothing to patch" >&2
		return 0
	fi

	require_tool patch
	# Dry run first: a patch that fails halfway would leave a broken installation.
	patch_output=$(cd "$site" && patch -p1 --forward --dry-run < "$patch_file" 2>&1) || {
		printf '%s\n' "$patch_output" >&2
		fail "vendored patch does not apply to '$package' (tracks $UPSTREAM); refresh Graphify with 'uv tool install --reinstall graphifyy', or delete the patch once upstream releases the change"
	}
	patch_output=$(cd "$site" && patch -p1 --forward < "$patch_file" 2>&1) || {
		printf '%s\n' "$patch_output" >&2
		fail "vendored patch failed midway through '$package' (tracks $UPSTREAM); reinstall Graphify with 'uv tool install --reinstall graphifyy'"
	}

	# No -V is portable -- GNU patch 2.8 reads `-V none` as "numbered" and ENABLES
	# backups, Apple patch 2.0 needs a -V to stay quiet -- so the backups are removed
	# afterwards, for exactly the files this patch touches, and verified gone.
	litter=$(
		sed -n 's|^+++ b/\([^[:space:]]*\).*|\1|p' "$patch_file" |
			while IFS= read -r touched; do
				for backup in "$site/$touched.orig" "$site/$touched".~*~; do
					[ -e "$backup" ] || continue
					rm -f "$backup" || :
					if [ -e "$backup" ]; then
						printf " '%s'" "$backup"
					fi
				done
			done
	)
	[ -z "$litter" ] || fail "cannot remove patch backups left in '$site':$litter"
	echo "patch-graphify.sh: applied $UPSTREAM to '$package'" >&2
}

main "$@"
