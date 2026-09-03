#!/bin/sh
# run-gates.sh -- run the CLAUDE.md canonical gates for whatever a diff touches.
# Mechanical runner for the "Canonical gates" table (CLAUDE.md stays the documented
# source; this script implements it -- change them together).
#
# Gates run against the host toolchain: Python through the locked uv environment
# (`uv sync --locked --group dev`), PHP and the shell tools from the versions
# CONTRIBUTING.md pins. A host is not automatically CI, so those pins are what keeps the
# two answering the same question. A MISSING tool is a gate FAILURE, not a skip -- a
# skipped gate reads greener than a failed one; --allow-missing downgrades that
# deliberately for an incomplete workstation.
#
# Usage: run-gates.sh [--worktree PATH] [--diff BASE] [--plan] [--allow-missing]
#   --worktree       repo checkout to run in (default: cwd's repo root)
#   --diff BASE      compute touched files: BASE...HEAD merge-base diff UNIONED with
#                     any uncommitted (staged+unstaged+untracked, .gitignore-filtered)
#                     changes vs HEAD (default origin/devel)
#   --plan           print the gate commands that WOULD run, one per line, and exit
#   --allow-missing  a missing tool reports SKIP without failing the run (default: fails).
#                    The Composer vendor checker is exempt: a missing interpreter there
#                    FAILS regardless, so the PHP gates can never silently skip.
#
# Exits 2 without running anything when a changed path holds a literal newline: such a
# path cannot be carried by a line-based file list, and gating a torn fragment would lint
# a path that does not exist while leaving the real file unchecked.
#
# Per-gate lines `GATE PASS|FAIL|SKIP: <cmd>`; a FAILING gate additionally prints its own
# captured stdout+stderr immediately before its `GATE FAIL` line (a passing gate stays
# fully suppressed); final line `GATES: PASS|FAIL`. Exit 0 only when nothing failed (and
# nothing skipped without --allow-missing). A diff touching www/ additionally prints a
# REMINDER that Tier-A ui_render coverage is a judgment gate this script cannot run (test
# mandate #4).
#
# Two gates run on EVERY diff ahead of the file-type mapping: coverage pairing (fed the
# exact name-status stream) and scripts/agent/check-graph-fresh.sh, which rebuilds
# graphify-out/graph.json and fails when the committed file differs -- a stale graph is a
# property of the whole tree, not of a touched file type. Its tool is `sh`, so a missing
# Graphify surfaces as the checker's own FAIL, never as a SKIP.

worktree='' base='origin/devel' plan=0 allow_missing=0
overall=0

usage() {
	echo "usage: run-gates.sh [--worktree PATH] [--diff BASE] [--plan] [--allow-missing]" >&2
	exit 2
}

# Refuse names the line-based lint mapper cannot represent. The status stream
# itself stays byte-exact and NUL-delimited for coverage pairing.
reject_newline_path() {
	if tr -cd '\n' < "$paths_tmp" | grep -q ''; then
		printf 'run-gates.sh: a changed path contains a newline; cannot map it to gates\n' >&2
		return 1
	fi
}

git_paths() {
	git -C "$worktree" "$@" > "$paths_tmp" || return 1
	reject_newline_path || return 1
	tr '\0' '\n' < "$paths_tmp"
}

git_statuses() {
	git -C "$worktree" "$@" > "$paths_tmp" || return 1
	reject_newline_path || return 1
	cat "$paths_tmp" >> "$status_tmp"
}

# Map a touched-file list (stdin, one path per line) to gate commands (stdout, one per
# line). Per-file gates (php -l, sh -n, shellcheck) emit one command per touched file.
gates_for() {
	files=$(grep -v '^legacy/' || true)
	out=''
	# issue #2016: the re-entry-bounds gate belongs to the .php/.inc AND .sh buckets --
	# pfblockerng.sh owns four of the eight sites -- but it is ONE whole-tree scan, so it
	# must be emitted exactly once for a mixed diff.
	reentry_emitted=0
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
	pytest_emitted=0
	if printf '%s\n' "$files" | grep -q '\.py$'; then
		out="${out}uv run --locked pytest${nl}uv run --locked ruff check .${nl}uv run --locked ruff format --check .${nl}uv run --locked mypy tests/${nl}"
		pytest_emitted=1
	fi
	# issue #3166: the skip gate READS tests/skip-allowlist.txt, and the checker plus its red
	# canary ride on the pytest gate (which also carries the two tests that parse the real
	# file) -- but a .txt path matched no extension bucket, so an allowlist-only diff selected
	# no suite and a malformed allowlist first failed in CI. Select pytest for it.
	if [ "$pytest_emitted" != 1 ] && printf '%s\n' "$files" | grep -qx 'tests/skip-allowlist\.txt'; then
		out="${out}uv run --locked pytest${nl}"
	fi
	if printf '%s\n' "$files" | grep -Eq '\.(php|inc)$'; then
		out="${out}uv run --locked python scripts/check_composer_vendor.py${nl}"
		# issue #2123: the on/off toggle contract belongs to pfb_cfg_registry(), not to
		# the page. --self-test is the gate's own red canary and runs first.
		out="${out}uv run --locked python scripts/check_toggle_registry.py --self-test && uv run --locked python scripts/check_toggle_registry.py${nl}"
		# issue #2016: a nested pfblockerng.php re-entry must stay bounded at the
		# pfb_reentry_exec()/pfb_reentry() seam. Same red-canary-first shape.
		out="${out}uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py${nl}"
		reentry_emitted=1
		for f in $(printf '%s\n' "$files" | grep -E '\.(php|inc)$'); do
			out="${out}php -l $f${nl}"
		done
		out="${out}vendor/bin/phpunit${nl}composer phpstan${nl}composer phpcs -- --standard=phpcs.xml.dist src/${nl}"
	fi
	if printf '%s\n' "$files" | grep -q '\.sh$'; then
		if [ "$reentry_emitted" != 1 ]; then
			out="${out}uv run --locked python scripts/check_reentry_bounds.py --self-test && uv run --locked python scripts/check_reentry_bounds.py${nl}"
		fi
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

# The Composer vendor guard is fail-closed: a failure there stops the run before any
# Composer-backed PHP gate, which is unsafe against a missing or stale vendor tree. Matched
# by substring so the check keeps recognising it if the invocation around it changes.
is_vendor_gate() {
	case "$1" in
	*'scripts/check_composer_vendor.py'*) return 0 ;;
	esac
	return 1
}

# Add report generation and the shared skip-set gate only to suites this runner
# already selected. The public plan/labels stay the canonical commands.
# shellcheck disable=SC2016 # report vars and $? expand later in run_gate's sh -c
gate_command() {
	case "$1" in
	'uv run --locked pytest')
		printf '%s' 'uv run --locked pytest --junitxml="$PFB_SKIP_REPORT_DIR/pytest.xml" || exit $?; python3 scripts/check_skip_allowlist.py --suite pytest --allowlist tests/skip-allowlist.txt tests/fixtures/skip-allowlist-canary.xml && :; canary_status=$?; [ "$canary_status" -eq 1 ] || { echo "red canary failed: an unlisted skip did not fail the gate (checker exit $canary_status, expected 1)"; exit 1; }; python3 scripts/check_skip_allowlist.py --suite pytest --allowlist tests/skip-allowlist.txt "$PFB_SKIP_REPORT_DIR/pytest.xml"'
		;;
	'vendor/bin/phpunit')
		printf '%s' 'vendor/bin/phpunit --log-junit "$PFB_SKIP_REPORT_DIR/phpunit.xml" || exit $?; python3 scripts/check_skip_allowlist.py --suite phpunit --allowlist tests/skip-allowlist.txt tests/fixtures/skip-allowlist-canary.xml && :; canary_status=$?; [ "$canary_status" -eq 1 ] || { echo "red canary failed: an unlisted skip did not fail the gate (checker exit $canary_status, expected 1)"; exit 1; }; python3 scripts/check_skip_allowlist.py --suite phpunit --allowlist tests/skip-allowlist.txt "$PFB_SKIP_REPORT_DIR/phpunit.xml"'
		;;
	'shellspec --shell $(command -v dash || command -v sh)')
		printf '%s' 'shellspec --shell $(command -v dash || command -v sh) -o junit --reportdir "$PFB_SKIP_REPORT_DIR/shellspec" || exit $?; python3 scripts/check_skip_allowlist.py --suite shellspec --allowlist tests/skip-allowlist.txt tests/fixtures/skip-allowlist-canary.xml && :; canary_status=$?; [ "$canary_status" -eq 1 ] || { echo "red canary failed: an unlisted skip did not fail the gate (checker exit $canary_status, expected 1)"; exit 1; }; python3 scripts/check_skip_allowlist.py --suite shellspec --allowlist tests/skip-allowlist.txt "$PFB_SKIP_REPORT_DIR/shellspec/results_junit.xml"'
		;;
	*) printf '%s' "$1" ;;
	esac
}


run_gate() {
	# $1 = command line
	label=$1
	tool=${1%% *}
	if ! (cd "$worktree" && { command -v "$tool" >/dev/null 2>&1 || [ -x "$tool" ]; }); then
		if is_vendor_gate "$1"; then
			printf 'GATE FAIL: %s (TOOL-MISSING: %s)\n' "$label" "$tool"
			overall=1
			return 1
		fi
		printf 'GATE SKIP: %s (TOOL-MISSING: %s)\n' "$label" "$tool"
		[ "$allow_missing" -eq 1 ] || overall=1
		return 0
	fi
	# issue #1194: ordinary gates read </dev/null so a stdin-reading gate cannot
	# consume the command loop. Coverage pairing receives the exact name-status
	# stream assembled by main().
	gate_input=/dev/null
	case "$1" in
	'python3 scripts/check_coverage_pairing.py --name-status-z') gate_input=$status_tmp ;;
	esac
	# issue #1865: capture combined stdout+stderr so a failing gate's own output
	# surfaces before its GATE FAIL line; a passing gate stays fully suppressed.
	gate_exec=$(gate_command "$1")
	gate_output=$(cd "$worktree" && sh -c "$gate_exec" < "$gate_input" 2>&1)
	gate_status=$?
	if [ "$gate_status" -eq 0 ]; then
		printf 'GATE PASS: %s\n' "$label"
		return 0
	fi
	[ -z "$gate_output" ] || printf '%s\n' "$gate_output"
	printf 'GATE FAIL: %s\n' "$label"
	overall=1
	is_vendor_gate "$1" && return 1
	return 0
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

	# The path/status files use builtins (no mktemp -- not POSIX). `set -C` makes
	# their redirects fail instead of following a planted file or symlink; mkdir
	# gives the report directory the same fail-if-present property. The residual
	# swap window is bounded by /tmp's sticky bit. Use `true >`, never `: >`: a
	# redirection error on the special builtin `:` exits dash outright instead of
	# yielding to `||` (issues #1172, #1850).
	paths_tmp="${TMPDIR:-/tmp}/pfb-run-gates-paths.$$"
	status_tmp="${TMPDIR:-/tmp}/pfb-run-gates-status.$$"
	skip_report_dir="${TMPDIR:-/tmp}/pfb-run-gates-skip-reports.$$"
	( set -C; true > "$paths_tmp" ) || exit 2
	( set -C; true > "$status_tmp" ) || {
		rm -f "$paths_tmp"
		exit 2
	}
	mkdir "$skip_report_dir" || {
		rm -f "$paths_tmp" "$status_tmp"
		exit 2
	}
	mkdir "$skip_report_dir/shellspec" || {
		rm -f "$paths_tmp" "$status_tmp"
		rm -rf "$skip_report_dir"
		exit 2
	}
	PFB_SKIP_REPORT_DIR=$skip_report_dir
	export PFB_SKIP_REPORT_DIR
	trap 'rm -f "$paths_tmp" "$status_tmp"; rm -rf "$skip_report_dir"' EXIT
	# dash runs no EXIT trap on an untrapped signal, so reap explicitly there too.
	trap 'rm -f "$paths_tmp" "$status_tmp"; rm -rf "$skip_report_dir"; trap - EXIT; exit 129' HUP
	trap 'rm -f "$paths_tmp" "$status_tmp"; rm -rf "$skip_report_dir"; trap - EXIT; exit 130' INT
	trap 'rm -f "$paths_tmp" "$status_tmp"; rm -rf "$skip_report_dir"; trap - EXIT; exit 131' QUIT
	trap 'rm -f "$paths_tmp" "$status_tmp"; rm -rf "$skip_report_dir"; trap - EXIT; exit 143' TERM

	# Coverage pairing consumes status-aware records: deletions and rename sources
	# still trigger production rules, while only live destinations can satisfy tests.
	git_statuses diff --name-status -z --find-renames --diff-filter=ACDMRT "$base...HEAD" || exit 2
	git_statuses diff --name-status -z --find-renames --diff-filter=ACDMRT --cached || exit 2
	git_statuses diff --name-status -z --find-renames --diff-filter=ACDMRT || exit 2
	git -C "$worktree" ls-files -z --others --exclude-standard > "$paths_tmp" || exit 2
	reject_newline_path || exit 2
	tr '\0' '\n' < "$paths_tmp" | while IFS= read -r path; do
		printf 'A\0%s\0' "$path"
	done >> "$status_tmp"

	# Lint/type/test mapping remains live-file-only: deleted ghosts cannot be
	# passed to per-file tools.
	committed=$(git_paths diff --name-only -z --find-renames --diff-filter=ACMRT "$base...HEAD") || exit 2
	staged=$(git_paths diff --name-only -z --find-renames --diff-filter=ACMRT --cached) || exit 2
	unstaged=$(git_paths diff --name-only -z --find-renames --diff-filter=ACMRT) || exit 2
	untracked=$(git_paths ls-files -z --others --exclude-standard) || exit 2
	files=$(printf '%s\n%s\n%s\n%s\n' "$committed" "$staged" "$unstaged" "$untracked" | LC_ALL=C sort -u | grep -v '^$')
	cmds=$(printf '%s\n' "$files" | gates_for)
	pairing_cmd='python3 scripts/check_coverage_pairing.py --name-status-z'
	graph_cmd='sh scripts/agent/check-graph-fresh.sh'
	all_cmds="$pairing_cmd
$graph_cmd
$cmds"

	if [ "$plan" -eq 1 ]; then
		printf '%s' "$all_cmds"
		exit 0
	fi

	# Pipelines run in subshells under POSIX sh, so `overall` cannot propagate out of a
	# `| while` loop -- run the loop in one subshell and carry the flag in its output.
	report=$(printf '%s\n' "$all_cmds" | {
		overall=0
		while IFS= read -r c; do
			[ -n "$c" ] || continue
			if ! run_gate "$c"; then
				is_vendor_gate "$c" && break
			fi
		done
		echo "OVERALL=$overall"
	})
	overall_status=${report##*OVERALL=}
	printf '%s' "${report%OVERALL=*}"
	if printf '%s\n' "$files" | grep -q '^src/usr/local/www/'; then
		printf 'REMINDER: www/ touched -- Tier-A ui_render coverage is required and cannot be script-checked (test mandate #4)\n'
	fi
	if [ "$overall_status" = 0 ]; then
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
