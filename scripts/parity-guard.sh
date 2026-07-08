#!/bin/sh
# scripts/parity-guard.sh — lint GitHub Actions workflows for build/test-parity violations.
#
# After ADR-47 (build path and test path), workflow YAML must route
# through the shared scripts. Violations are caught by five rules.
#
# BUILD RULES:
#   1. build-pkg-portable.py called directly (bypasses build-leg.sh).
#   2. sparse-clone-ports.sh called directly (bypasses build-leg.sh).
#   3. An inline-derived arg to build-leg.sh — $(...) or backtick AFTER the
#      build-leg.sh token on the same line.
#      Legit: PKG="$(sh scripts/build-leg.sh ...)" has $( BEFORE → not flagged.
#
# TEST RULES:
#   4. A direct  python[3] -m pytest tests/smoke  call (bypasses run-smoke.sh).
#      False-positive guard: bare `python -m pytest` with NO tests/smoke path
#      on the same line (e.g. the unit runner in test.yml) is NOT flagged.
#   5. An inline-derived arg to run-smoke.sh — $(...) or backtick AFTER the
#      run-smoke.sh token on the same line (same pattern as Rule 3).
#
# Allowed: YAML comment lines (first non-whitespace char is #).
# Allowed: build-leg.sh / run-smoke.sh calls whose args are GitHub ${{ ... }}
#   expressions or env-sourced $VAR / prior-step captures.
# Rule 3/5 are LOGICAL-COMMAND-scoped: backslash-continuation lines are joined
#   before checking, so a $( on a continuation line is detected.
#
# Usage:  sh scripts/parity-guard.sh [DIR]
#   DIR defaults to .github/workflows
#
# Exit 0 = no violations.  Exit 1 = violations; details on stderr.
#
# POSIX sh; shellcheck clean.

set -eu

WORKFLOWS="${1:-.github/workflows}"

if [ ! -d "$WORKFLOWS" ]; then
    printf 'parity-guard: directory not found: %s\n' "$WORKFLOWS" >&2
    exit 1
fi

# ponytail: temp file accumulates violations across pipeline subshells (no arrays in POSIX sh).
TMPF="$(mktemp)"
trap 'rm -f "$TMPF"' EXIT INT TERM

# grep pre-filter: any line naming one of the scripts/patterns enters the per-line checks.
# python3\{0,1\} matches 'python' or 'python3' (BRE: 3 repeated 0 or 1 times).
PATTERN='build-pkg-portable\.py\|sparse-clone-ports\.sh\|build-leg\.sh\|python3\{0,1\} -m pytest\|run-smoke\.sh'

# Scan every YAML file in DIR (sorted for deterministic output).
find "$WORKFLOWS" \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort \
| while IFS= read -r YAML_FILE; do
    # Pre-join backslash-continuation lines so a $(...) on a continuation line
    # of build-leg.sh / run-smoke.sh is detected (Rules 3/5 logical-command-scoped).
    # awk outputs STARTLINE:joined_content; the existing LINENUM/CONTENT parsing is unchanged.
    awk 'BEGIN{buf="";start=0}{sub(/\r$/,"");if(start==0)start=NR;if(/\\$/){sub(/\\$/," ");buf=buf $0}else{print start":"buf $0;buf="";start=0}}END{if(buf!="")print start":"buf}' "$YAML_FILE" \
        | grep "$PATTERN" 2>/dev/null | while IFS= read -r MATCH; do
        LINENUM="${MATCH%%:*}"
        CONTENT="${MATCH#*:}"
        # Strip leading whitespace to detect YAML comment lines.
        STRIPPED="$(printf '%s' "$CONTENT" | sed 's/^[[:space:]]*//')"
        # Skip YAML comment lines (mentions of the tools in comments are allowed).
        case "$STRIPPED" in
            '#'*) continue ;;
        esac
        # Rules 1-2: a direct call to either underlying build tool.
        case "$STRIPPED" in
            *build-pkg-portable.py*|*sparse-clone-ports.sh*)
                printf '%s:%s: direct build-tool call; use build-leg.sh instead\n  > %s\n' \
                    "$YAML_FILE" "$LINENUM" "$STRIPPED" >> "$TMPF"
                ;;
        esac
        # Rule 3: an inline-derived arg to build-leg.sh — $( or backtick AFTER the
        # build-leg.sh token. Take the substring after the FIRST build-leg.sh
        # occurrence so the legit capture wrapper's $( (which precedes the token)
        # is not flagged.
        case "$STRIPPED" in
            *build-leg.sh*)
                AFTER="${STRIPPED#*build-leg.sh}"
                # The single-quoted '$(' is a LITERAL glob pattern (match a command
                # substitution in the text), not an expansion — SC2016 is expected.
                # shellcheck disable=SC2016
                case "$AFTER" in
                    *'$('*|*'`'*)
                        printf '%s:%s: inline-derived arg to build-leg.sh; derive it in a prior step/env, not in the call\n  > %s\n' \
                            "$YAML_FILE" "$LINENUM" "$STRIPPED" >> "$TMPF"
                        ;;
                esac
                ;;
        esac
        # Rule 4: direct smoke-pytest bypass — python[3] -m pytest ... tests/smoke.
        # False-positive guard: the path check ensures bare `python -m pytest` (the
        # unit runner, no path) is NOT flagged; pytest_marker:/PYTEST_MARKER vars don't
        # match because they don't contain the literal `python` + `-m pytest` prefix.
        case "$STRIPPED" in
            *'python -m pytest '*|*'python3 -m pytest '*)
                # Check that tests/smoke appears AFTER the `-m pytest` token.
                AFTER_PYTEST="${STRIPPED#*-m pytest }"
                case "$AFTER_PYTEST" in
                    *tests/smoke*)
                        printf '%s:%s: direct smoke pytest call; use run-smoke.sh instead\n  > %s\n' \
                            "$YAML_FILE" "$LINENUM" "$STRIPPED" >> "$TMPF"
                        ;;
                esac
                ;;
        esac
        # Rule 5: inline-derived arg to run-smoke.sh — mirrors Rule 3.
        case "$STRIPPED" in
            *run-smoke.sh*)
                AFTER="${STRIPPED#*run-smoke.sh}"
                # shellcheck disable=SC2016
                case "$AFTER" in
                    *'$('*|*'`'*)
                        printf '%s:%s: inline-derived arg to run-smoke.sh; derive it in a prior step/env, not in the call\n  > %s\n' \
                            "$YAML_FILE" "$LINENUM" "$STRIPPED" >> "$TMPF"
                        ;;
                esac
                ;;
        esac
    done
done

if [ -s "$TMPF" ]; then
    cat "$TMPF" >&2
    # Count violations: each prints a message line + a "  > " context line; count
    # the message lines (everything that is NOT a context line).
    _vcount="$(grep -vc '^  > ' "$TMPF" 2>/dev/null || printf '0')"
    printf 'parity-guard: %s violation(s) — build/test-parity issue(s) in workflow YAML\n' \
        "$_vcount" >&2
    exit 1
fi
