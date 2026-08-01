#!/bin/sh
# scripts/git-env-scrub-guard.sh — meta-assertion guard for the GIT_* scrub discipline.
#
# Two mechanical clauses — both must pass:
#
#   1. No raw `unset GIT_*` outside the lib.
#      Any bare `unset` of the six scrubbed vars (GIT_DIR, GIT_INDEX_FILE,
#      GIT_WORK_TREE, GIT_PREFIX, GIT_OBJECT_DIRECTORY, GIT_COMMON_DIR) in
#      scripts/ or tests/shell/ that is NOT in the canonical lib
#      (scripts/lib/git-env-scrub.sh) is a violation: the class must be
#      suppressed at the lib chokepoint, not scattered.
#
#   2. Fixture/setup Git calls use git_fixture(). Raw Git command positions in
#      specs are violations unless a same-line marker carries a non-empty reason.
#      The lexical scan ignores comments and inert quoted text, while retaining
#      active command substitutions and handling env/assignment prefixes.
#
# Intentional Git calls exercising a hook under test may use a same-line marker;
# an empty marker or a marker on a prior line does not exempt the command.
#
# Usage: sh scripts/git-env-scrub-guard.sh [ROOT]
#   ROOT defaults to the repo root (parent of scripts/).
#
# Exit 0 = clean.  Exit 1 = violations; details on stderr.
#
# POSIX sh; shellcheck clean.

set -eu

_SELF_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
ROOT="${1:-${_SELF_DIR%/scripts}}"

TMPF="$(mktemp)"
trap 'rm -f "$TMPF"' EXIT INT TERM

LIB="${ROOT}/scripts/lib/git-env-scrub.sh"

# ── Clause 1: no raw `unset GIT_*` outside the lib ──────────────────────── #
# PRIMARY trigger: look for any bare `unset <VAR>` of the six scrubbed vars
# anywhere in scripts/ and tests/shell/ (the two zones that need this discipline),
# then exclude:
#   - the canonical lib itself (pfb_scrub_git_env lives there — that is the point)
#   - this guard script (its grep pattern + comments necessarily contain the strings)
#   - the git_env_scrub_spec.sh (it writes the strings into TEMP files to test the
#     guard; the in-file mentions are string literals, not production unset calls)
GUARD_SELF="${ROOT}/scripts/git-env-scrub-guard.sh"
SCRUB_SPEC="${ROOT}/tests/shell/git_env_scrub_spec.sh"
grep -Ern --include='*.sh' \
    'unset (GIT_DIR|GIT_INDEX_FILE|GIT_WORK_TREE|GIT_PREFIX|GIT_OBJECT_DIRECTORY|GIT_COMMON_DIR)' \
    "${ROOT}/tests/shell" "${ROOT}/scripts" 2>/dev/null \
    | grep -v "${LIB}" \
    | grep -v "${GUARD_SELF}" \
    | grep -v "${SCRUB_SPEC}" >> "$TMPF" || true

# ── Clause 2: raw fixture Git calls use git_fixture. ────────────────────── #
# Strip comments and quoted text before checking command positions. The guard is
# intentionally lexical rather than a shell evaluator: it catches direct Git at
# indentation, after `&&`/`;`/`!`, and in `$(git ...)` without executing fixtures.
scan_raw_git() {
    awk '
    function unquoted(line,    i,c,state,out,depth) {
        state=""
        out=""
        depth=0
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            if (state == "single") {
                if (c == "\047") state = ""
                out = out " "
                continue
            }
            if (state == "double") {
                if (c == "\\") {
                    i++
                    out = out "  "
                } else if (c == "$" && substr(line, i + 1, 1) == "(") {
                    out = out "$("
                    i++
                    depth=1
                    state="cmd"
                } else if (c == "\"") {
                    state = ""
                    out = out " "
                } else {
                    out = out " "
                }
                continue
            }
            if (state == "cmd_single") {
                if (c == "\047") state = "cmd"
                out = out " "
                continue
            }
            if (state == "cmd_double") {
                if (c == "\\") {
                    i++
                    out = out "  "
                } else if (c == "\"") {
                    state = "cmd"
                    out = out " "
                } else if (c == "$" && substr(line, i + 1, 1) == "(") {
                    out = out "$("
                    i++
                    depth++
                    state="cmd"
                } else {
                    out = out " "
                }
                continue
            }
            if (state == "cmd") {
                if (c == "\047") {
                    state="cmd_single"
                    out = out " "
                } else if (c == "\"") {
                    state="cmd_double"
                    out = out " "
                } else if (c == "$" && substr(line, i + 1, 1) == "(") {
                    out = out "$("
                    i++
                    depth++
                } else if (c == ")") {
                    depth--
                    out = out " "
                    if (depth == 0) state="double"
                } else {
                    out = out c
                }
                continue
            }
            if (c == "#") {
                tail = substr(line, i)
                if (match(tail, /^#[[:space:]]*git-env-scrub-guard:/)) {
                    out = out "# git-env-scrub-guard:" substr(tail, RLENGTH + 1)
                }
                break
            }
            if (c == "\047" || c == "\"") {
                state = c == "\047" ? "single" : "double"
                out = out " "
            } else if (c == "\\") {
                i++
                out = out "  "
            } else {
                out = out c
            }
        }
        return out
    }
    function raw_git(line) {
        prefix="([[:alnum:]_]+=[^[:space:]]+[[:space:]]+)*"
        env_prefix="env([[:space:]]+[^;&|[:space:]]+)*[[:space:]]+"
        boundary="(^[[:space:]]*|[;&|!][[:space:]]*)"
        sub_boundary="\\$\\([[:space:]]*"
        return line ~ (boundary prefix "git([[:space:]]|$)") \
            || line ~ (boundary env_prefix "git([[:space:]]|$)") \
            || line ~ (sub_boundary prefix "git([[:space:]]|$)") \
            || line ~ (sub_boundary env_prefix "git([[:space:]]|$)")
    }
    {
        original = $0
        cleaned = unquoted(original)
        if (!raw_git(cleaned)) next
        marker = "# git-env-scrub-guard:"
        marker_at = index(cleaned, marker)
        if (marker_at) {
            reason = substr(cleaned, marker_at + length(marker))
            sub(/[[:space:]]+$/, "", reason)
            if (reason !~ /^[[:space:]]*$/) next
        }
        printf "%s:%d: raw git setup without fixture helper\n", FILENAME, FNR
    }' "$1"
}

find "${ROOT}/tests/shell" -name '*_spec.sh' | LC_ALL=C sort \
| while IFS= read -r _spec; do
    scan_raw_git "$_spec" >> "$TMPF"
done

if [ -s "$TMPF" ]; then
    cat "$TMPF" >&2
    printf 'git-env-scrub-guard: violations found\n' >&2
    if grep -q 'raw git setup without fixture helper' "$TMPF"; then
        printf 'git-env-scrub-guard: add git_fixture for fixture/setup Git calls\n' >&2
    fi
    if grep -Eq 'unset (GIT_DIR|GIT_INDEX_FILE|GIT_WORK_TREE|GIT_PREFIX|GIT_OBJECT_DIRECTORY|GIT_COMMON_DIR)' "$TMPF"; then
        printf 'git-env-scrub-guard: move GIT_* unsets to the lib\n' >&2
    fi
    exit 1
fi

printf 'git-env-scrub-guard: clean\n'
