#!/bin/sh
# run-gates.sh -- run the CLAUDE.md canonical gates for whatever a diff touches.
# Mechanical runner for the "Canonical gates" table (CLAUDE.md stays the documented
# source; this script implements it -- change them together).
#
# Usage: run-gates.sh [--worktree PATH] [--diff BASE] [--plan] [--allow-missing]
#   --worktree       repo checkout to run in (default: cwd's repo root)
#   --diff BASE      compute touched files: BASE...HEAD merge-base diff UNIONED with
#                     any uncommitted (staged+unstaged) changes vs HEAD (default origin/devel)
#   --plan           print the gate commands that WOULD run, one per line, and exit
#   --allow-missing  a missing tool reports SKIP without failing the run (default: fails)
#
# Per-gate lines `GATE PASS|FAIL|SKIP: <cmd>`; final line `GATES: PASS|FAIL`. Exit 0 only
# when nothing failed (and nothing skipped without --allow-missing). A diff touching
# www/ additionally prints a REMINDER that Tier-A ui_render coverage is a judgment gate
# this script cannot run (test mandate #4).

worktree='' base='origin/devel' plan=0 allow_missing=0
overall=0

usage() {
	echo "usage: run-gates.sh [--worktree PATH] [--diff BASE] [--plan] [--allow-missing]" >&2
	exit 2
}

# Map a touched-file list (stdin, one path per line) to gate commands (stdout, one per
# line). Per-file gates (php -l, sh -n, shellcheck) emit one command per touched file.
gates_for() {
	files=$(cat)
	out=''
	nl='
'
	# Per-file commands (php -l / sh -n / shellcheck) are re-parsed by run_gate's
	# `sh -c`; a diff filename carrying shell metacharacters would inject there.
	# The guard applies ONLY to those buckets -- aggregate gates (.py/.md suites)
	# and gate-less file types never embed the filename, so an unusual name there
	# must neither fail the run nor drop the aggregate gates.
	unsafe=$(printf '%s\n' "$files" | grep -E '\.(php|inc|sh)$' | grep '[^A-Za-z0-9._/-]' || true)
	if [ -n "$unsafe" ]; then
		files=$(printf '%s\n' "$files" | grep -v '[^A-Za-z0-9._/-]' || true)
		out="${out}printf 'unsafe filename in diff\\n' >&2; false${nl}"
	fi
	if printf '%s\n' "$files" | grep -q '\.py$'; then
		out="${out}python3 -m pytest${nl}ruff check .${nl}ruff format --check .${nl}mypy tests/${nl}"
	fi
	if printf '%s\n' "$files" | grep -Eq '\.(php|inc)$'; then
		for f in $(printf '%s\n' "$files" | grep -E '\.(php|inc)$'); do
			out="${out}php -l $f${nl}"
		done
		out="${out}vendor/bin/phpunit${nl}composer phpstan${nl}composer phpcs -- --standard=phpcs.xml.dist src/${nl}"
	fi
	if printf '%s\n' "$files" | grep -q '\.sh$'; then
		for f in $(printf '%s\n' "$files" | grep '\.sh$'); do
			out="${out}sh -n $f${nl}"
			# issue #1210: shellcheck scope mirrors .githooks/pre-commit + test.yml
			# (src, scripts, .claude/hooks); tests/ specs trip SC2034 false-positives.
			case "$f" in
			src/* | scripts/* | .claude/hooks/*) out="${out}shellcheck $f${nl}" ;;
			esac
		done
		out="${out}shellspec --shell \$(command -v dash || command -v sh)${nl}"
	fi
	if printf '%s\n' "$files" | grep -q '\.md$'; then
		out="${out}npx markdownlint-cli2${nl}"
	fi
	printf '%s' "$out"
}

run_gate() {
	# $1 = command line
	tool=${1%% *}
	if ! (cd "$worktree" && { command -v "$tool" >/dev/null 2>&1 || [ -x "$tool" ]; }); then
		printf 'GATE SKIP: %s (TOOL-MISSING: %s)\n' "$1" "$tool"
		[ "$allow_missing" -eq 1 ] || overall=1
		return 0
	fi
	# issue #1194: </dev/null -- a stdin-reading gate (full PHPUnit) otherwise eats
	# the command loop's remaining gate lines, silently skipping those gates.
	if (cd "$worktree" && sh -c "$1" </dev/null >/dev/null 2>&1); then
		printf 'GATE PASS: %s\n' "$1"
	else
		printf 'GATE FAIL: %s\n' "$1"
		overall=1
	fi
}

main() {
	# shellcheck source=scripts/agent/agent_env.sh
	. "$(dirname "$0")/agent_env.sh"
	scrub_git_env "$0"
	while [ $# -gt 0 ]; do
		case "$1" in
			--worktree) worktree=$2; shift 2 ;;
			--diff) base=$2; shift 2 ;;
			--plan) plan=1; shift ;;
			--allow-missing) allow_missing=1; shift ;;
			*) usage ;;
		esac
	done
	require_tool git
	[ -n "$worktree" ] || worktree=$(git rev-parse --show-toplevel) || exit 2

	# --diff-filter=ACMR: a pure deletion stages nothing to lint (same rule as the
	# pre-commit hook) -- per-file gates against ghost paths would always fail.
	committed=$(git -C "$worktree" diff --name-only --diff-filter=ACMR "$base...HEAD") || exit 2
	# issue #1293: union with uncommitted changes, else gates see nothing pre-commit.
	# staged/unstaged unioned SEPARATELY, not via one `diff HEAD` -- `diff <commit>`
	# reads the WORKING TREE, so a staged-then-worktree-reverted file is invisible.
	staged=$(git -C "$worktree" diff --name-only --diff-filter=ACMR --cached) || exit 2
	unstaged=$(git -C "$worktree" diff --name-only --diff-filter=ACMR) || exit 2
	files=$(printf '%s\n%s\n%s\n' "$committed" "$staged" "$unstaged" | LC_ALL=C sort -u | grep -v '^$')
	# The shellspec gate must also fire when only spec files changed (cross-language
	# consumers rule): specs are .sh files, so the extension mapping already covers it.
	cmds=$(printf '%s\n' "$files" | gates_for)

	if [ "$plan" -eq 1 ]; then
		printf '%s' "$cmds"
		exit 0
	fi

	# Pipelines run in subshells under POSIX sh, so `overall` cannot propagate out of a
	# `| while` loop -- run the loop in one subshell and carry the flag in its output.
	report=$(printf '%s\n' "$cmds" | {
		overall=0
		while IFS= read -r c; do
			[ -n "$c" ] && run_gate "$c"
		done
		echo "OVERALL=$overall"
	})
	printf '%s\n' "$report" | grep -v '^OVERALL='
	if printf '%s\n' "$files" | grep -q '^src/usr/local/www/'; then
		printf 'REMINDER: www/ touched -- Tier-A ui_render coverage is required and cannot be script-checked (test mandate #4)\n'
	fi
	if printf '%s\n' "$report" | grep -q 'OVERALL=0'; then
		printf 'GATES: PASS\n'
		exit 0
	fi
	printf 'GATES: FAIL\n'
	exit 1
}

case "${AGENT_SOURCE_ONLY:-0}" in
	1) ;;
	*) main "$@" ;;
esac
