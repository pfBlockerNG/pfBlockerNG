#!/bin/sh
# scripts/git-env-scrub-guard.sh — meta-assertion guard for the GIT_* scrub discipline.
#
# Two mechanical clauses — both must pass:
#
#   1. No raw `unset GIT_DIR` outside the lib.
#      Any bare `unset GIT_DIR` in scripts/ or tests/shell/ that is NOT in the
#      canonical lib (scripts/lib/git-env-scrub.sh) is a violation: the class
#      must be suppressed at the lib chokepoint, not scattered.
#
#   2. Any spec that shells out to `git` must call scrub_git_env.
#      A spec file (*_spec.sh) that contains the token `git ` (bare git command)
#      but does NOT call `scrub_git_env` is a violation: inherited GIT_DIR from
#      the pre-commit hook would corrupt its fixture repo operations.
#
# Note: `git -C` and `git fetch` etc. all start with `git ` (space after git).
# `git` in a comment is not excluded — the check is a heuristic; if the file
# only mentions git in a comment but scrub_git_env is not called, that is fine
# in practice (the check may false-positive but the cost is adding the call,
# which is cheap and defensive).
#
# Usage: sh scripts/git-env-scrub-guard.sh [ROOT]
#   ROOT defaults to the repo root (parent of scripts/).
#
# Exit 0 = clean.  Exit 1 = violations; details on stderr.
#
# POSIX sh; shellcheck clean.

set -eu

_SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${1:-${_SELF_DIR%/scripts}}"

TMPF="$(mktemp)"
trap 'rm -f "$TMPF"' EXIT INT TERM

LIB="${ROOT}/scripts/lib/git-env-scrub.sh"

# ── Clause 1: no raw `unset GIT_DIR` outside the lib ────────────────────── #
# PRIMARY trigger: look for bare `unset GIT_DIR` anywhere in scripts/ and
# tests/shell/ (the two zones that need this discipline), then exclude:
#   - the canonical lib itself (pfb_scrub_git_env lives there — that is the point)
#   - this guard script (its grep pattern + comments necessarily contain the string)
#   - the git_env_scrub_spec.sh (it writes the string into TEMP files to test the guard;
#     the in-file mentions are string literals, not production unset calls)
GUARD_SELF="${ROOT}/scripts/git-env-scrub-guard.sh"
SCRUB_SPEC="${ROOT}/tests/shell/git_env_scrub_spec.sh"
grep -rn --include='*.sh' 'unset GIT_DIR' \
    "${ROOT}/tests/shell" "${ROOT}/scripts" 2>/dev/null \
    | grep -v "${LIB}" \
    | grep -v "${GUARD_SELF}" \
    | grep -v "${SCRUB_SPEC}" >> "$TMPF" || true

# ── Clause 2: any spec with `git ` must call scrub_git_env ──────────────── #
find "${ROOT}/tests/shell" -name '*_spec.sh' | LC_ALL=C sort \
| while IFS= read -r _spec; do
    if grep -q 'git ' "$_spec" 2>/dev/null; then
        if ! grep -q 'scrub_git_env' "$_spec" 2>/dev/null; then
            printf '%s: calls git without scrub_git_env (GIT_DIR may corrupt fixture repos)\n' \
                "$_spec" >> "$TMPF"
        fi
    fi
done

if [ -s "$TMPF" ]; then
    cat "$TMPF" >&2
    printf 'git-env-scrub-guard: violations found — add scrub_git_env or move unset to the lib\n' >&2
    exit 1
fi

printf 'git-env-scrub-guard: clean\n'
