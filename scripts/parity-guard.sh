#!/bin/sh
# scripts/parity-guard.sh — lint GitHub Actions workflows for build-parity violations.
#
# After ADR-47 P3, workflow YAML must call build-leg.sh for all .pkg builds, and must
# NOT smuggle CI-only step logic into the build-leg.sh call itself (an inline-derived
# arg one line above the call survives the "use build-leg.sh" rule but breaks parity).
#
# Violations (each on a non-comment workflow line):
#   1. build-pkg-portable.py called directly (bypasses the shared build path).
#   2. sparse-clone-ports.sh called directly (bypasses the shared build path).
#   3. An inline-derived argument fed to build-leg.sh — a command substitution $(...)
#      or backtick positioned AFTER the build-leg.sh token on the same line.
#      The legit capture wrapper  PKG="$(sh scripts/build-leg.sh ...)"  has its $(
#      BEFORE the token, so it is NOT flagged; an evasion like
#      build-leg.sh --pkgversion "$(release-version.sh ...)"  has $( AFTER → flagged.
#
# Allowed: scripts/build-leg.sh calls whose args are GitHub ${{ ... }} expressions or
#   env-sourced $VAR/${VAR} (the documented residual — see RESIDUAL below).
# Allowed: YAML comment lines (first non-whitespace char is #).
#
# RESIDUAL (Verify floor — amendment 5): Rule 3 is LINE-scoped. A value derived on a
#   PRIOR step/line or via an `env:` block and passed in as a bare $VAR is NOT
#   provenance-tracked — full deny-by-default would need real shell/YAML parsing.
#   Generalizing this is a P5 item.
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

# grep pre-filter: any line naming one of the three scripts enters the per-line checks.
PATTERN='build-pkg-portable\.py\|sparse-clone-ports\.sh\|build-leg\.sh'

# Scan every YAML file in DIR (sorted for deterministic output).
find "$WORKFLOWS" \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort \
| while IFS= read -r YAML_FILE; do
    # grep -n: "LINENUM:content" for each match; || true so a no-match file doesn't abort.
    grep -n "$PATTERN" "$YAML_FILE" 2>/dev/null | while IFS= read -r MATCH; do
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
    done
done

if [ -s "$TMPF" ]; then
    cat "$TMPF" >&2
    # Count violations: each prints a message line + a "  > " context line; count
    # the message lines (everything that is NOT a context line).
    _vcount="$(grep -vc '^  > ' "$TMPF" 2>/dev/null || printf '0')"
    printf 'parity-guard: %s violation(s) — build-parity issue(s) in workflow YAML\n' \
        "$_vcount" >&2
    exit 1
fi
