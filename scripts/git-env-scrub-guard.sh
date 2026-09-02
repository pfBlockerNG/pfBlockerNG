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
#   2. The swept scratch-repo specs retain every git_fixture() pin. An explicit
#      per-file count catches removal without pretending this guard is a shell
#      parser. A lexical scan also catches common raw Git command forms unless a
#      same-line marker carries a non-empty reason.
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
# The manifest pins the completed sweep. The lexical lint below keeps common raw
# command mistakes visible without claiming to parse arbitrary shell programs.
check_fixture_manifest() {
    marker="${ROOT}/tests/shell/agent_run_gates_spec.sh"
    [ -f "$marker" ] || return 0

    while IFS=: read -r spec expected; do
        path="${ROOT}/tests/shell/${spec}"
        if [ ! -f "$path" ]; then
            printf '%s: swept fixture spec is missing\n' "$path" >> "$TMPF"
            continue
        fi
        actual=$(awk '{
            line=$0
            while (match(line, /(^|[^[:alnum:]_])git_fixture([^[:alnum:]_]|$)/)) {
                count++
                line=substr(line, RSTART + RLENGTH)
            }
        } END { print count + 0 }' "$path")
        if [ "$actual" -ne "$expected" ]; then
            printf '%s: git_fixture pin count changed (expected %s, found %s)\n' \
                "$path" "$expected" "$actual" >> "$TMPF"
        fi
    done <<'EOF'
agent_run_gates_git_spec.sh:2
agent_run_gates_spec.sh:4
agent_work_branch_spec.sh:31
composer_cloud_install_spec.sh:4
git_no_docs_spec.sh:5
githooks_pre_push_lease_spec.sh:54
githooks_pre_push_tag_scheme_spec.sh:28
githooks_prepare_commit_msg_guard_spec.sh:29
impacted_tests_spec.sh:2
pfblockerng_truncate_survival_spec.sh:4
precommit_composer_vendor_spec.sh:2
read_version_matrix_test_spec.sh:5
release_ci_gate_spec.sh:33
session_branch_sync_spec.sh:64
sparse_clone_ports_spec.sh:17
EOF
}

check_fixture_manifest

# This lexical lint covers common direct-command mistakes. The manifest above,
# rather than this deliberately small scanner, is the completed-sweep invariant.
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
