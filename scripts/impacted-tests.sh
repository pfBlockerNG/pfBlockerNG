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
# Empty output = no changed test modules under TEST_DIR. The caller then runs the
# whole marker (a SAFE over-approximation — never under-runs), and the dispatcher
# can pass an explicit `-k` to narrow to the tests covering changed NON-test code
# (which a live-VM suite can't map automatically — the code runs on the guest,
# out of any runner-side coverage).
#
# The `tests/smoke/test_*.py` glob deliberately does NOT match `tests/smoke/ui/`
# tests: the literal `test_` in the pattern must follow `$dir/` directly, and a
# ui/ path has `ui/` there instead — so the smoke and UI workflows each pick up
# only their own changed tests.
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
	changed="$(git diff --name-only "${base}...HEAD" 2>/dev/null || true)"
fi

# Build the OR expression in a subshell fed by the pipe; the trailing printf runs
# in that SAME subshell, so $expr is in scope when emitted.
printf '%s\n' "$changed" | {
	expr=""
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		case "$f" in
			"$dir"/test_*.py) ;;   # a direct test module of THIS dir
			*) continue ;;
		esac
		stem="${f##*/}"; stem="${stem%.py}"
		if [ -z "$expr" ]; then expr="$stem"; else expr="$expr or $stem"; fi
	done
	printf '%s' "$expr"
}
