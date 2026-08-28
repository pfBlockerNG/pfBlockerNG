#!/bin/sh
# impacted-tests.sh BASE_REF TEST_DIR
#
# Emit a pytest `-k` expression selecting the test MODULES changed on this branch
# since it diverged from BASE_REF, under TEST_DIR (e.g. `tests/smoke` for the
# smoke marker, `tests/smoke/ui` for the Web-UI tiers). Each changed
# `TEST_DIR/test_*.py` becomes an OR term of its module stem — pytest `-k` matches
# the module name — so a dispatcher gets "only the tests I created/touched" for
# free, with no coverage map to maintain.
#
# Empty output = no changed test modules under TEST_DIR, OR a changed path holding
# a literal newline, which cannot be named in a `-k` expression at all. The caller then
# runs the whole marker (a SAFE over-approximation — never under-runs), and the dispatcher
# can pass an explicit `-k` to narrow to the tests covering changed NON-test code
# (which a live-VM suite can't map automatically — the code runs on the guest,
# out of any runner-side coverage).
#
# Only direct `TEST_DIR/test_*.py` modules match; subdirectories are excluded
# before the shell glob, whose `*` can otherwise cross `/`.
#
# Test seam: PFB_IMPACTED_CHANGED_FILES (newline-separated paths) overrides the
# git diff, so the pure filtering is exercisable without a git fixture.

set -eu

base="${1:?usage: impacted-tests.sh BASE_REF TEST_DIR}"
dir="${2:?usage: impacted-tests.sh BASE_REF TEST_DIR}"
dir="${dir%/}"

if [ -n "${PFB_IMPACTED_CHANGED_FILES+x}" ]; then
	changed="$PFB_IMPACTED_CHANGED_FILES"
else
	# Three-dot: files changed on HEAD since the merge-base with BASE_REF.
	# Tolerate a missing/unfetched base ref — an empty diff routes the caller to
	# the safe full-marker path rather than erroring the run.
	# -z + tr: the newline form C-quotes a path holding a quote, backslash, control
	# byte or non-ASCII byte, and the quoted form matches neither the "$dir"/test_*.py
	# prefix nor the .py suffix — that module would drop out of the derived -k
	# expression and simply never run (issue #2228). A missing/unfetched base ref
	# still yields an empty list (git's failure is silenced, and tr then exits 0),
	# routing the caller to its safe full-marker path.
	changed="$(git diff --name-only -z "${base}...HEAD" 2>/dev/null | tr '\0' '\n' || true)"
	# A path holding a literal newline tears into fragments matching neither the dir
	# prefix nor the .py suffix, so that module would vanish from the expression
	# while its siblings still narrowed the run. Detect it on the RAW NUL-separated
	# stream, which carries a newline byte only in that case (no in-band sentinel is
	# possible -- every byte but NUL and `/` is legal in a path), and emit nothing:
	# empty routes the caller to its full-marker path, which runs everything.
	if git diff --name-only -z "${base}...HEAD" 2>/dev/null | tr -cd '\n' | grep -q ''; then
		changed=''
	fi
fi

# Build the OR expression in a subshell fed by the pipe; the trailing printf runs
# in that SAME subshell, so $expr is in scope when emitted.
printf '%s\n' "$changed" | {
	expr=""
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		case "$f" in
			"$dir"/*/*) continue ;;
			"$dir"/test_*.py) ;;   # a direct test module of THIS dir
			*) continue ;;
		esac
		stem="${f##*/}"; stem="${stem%.py}"
		if [ -z "$expr" ]; then expr="$stem"; else expr="$expr or $stem"; fi
	done
	printf '%s' "$expr"
}
