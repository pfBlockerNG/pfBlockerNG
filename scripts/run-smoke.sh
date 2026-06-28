#!/bin/sh
# scripts/run-smoke.sh — the ONE canonical pytest invocation for all three call sites:
#   smoke-single.yml, ui-tests.yml, scripts/smoke-on-box.sh (local runs via lease).
#
# Emits and executes:
#   $PYTHON -m pytest $PATHS -m $MARKER
#     --override-ini="addopts=" --override-ini="timeout_func_only=true"
#     --timeout=$TIMEOUT --timeout-method=signal --durations=0 --capture=tee-sys -v
#     [-k $K] [passthrough...]
#
# --durations=0 reports every test's setup/call/teardown phase timing (issue #605
#   Layer A); --capture=tee-sys streams stdout live so the per-step PFB_TIMING lines
#   (Layer B, tests/timing.py) show on a PASSING run, not only on failure.
#
# Params + defaults (structured flags must precede passthrough):
#   --paths P      default tests/smoke   (UI: tests/smoke/ui)
#   -m/--marker M  default smoke         (CI smoke: smoke|repo; UI: ui_render|...)
#   --timeout N    default 30            (UI: 300)
#   --filter EXPR  optional; ONE arg, no word-split (passed to pytest as -k "expr")
#   trailing passthrough → forwarded to pytest verbatim
#
# AMENDMENTS:
#   bare-path parity: a positional path in the passthrough REPLACES --paths (not
#     appended) — so `local-smoke.sh -m ui_render tests/smoke/ui` runs only that
#     subtree. Only the FIRST non-option token in the passthrough is treated as a
#     path; a subsequent non-'-' token (e.g. the '1' in --maxfail 1) is an option
#     value and must not suppress the default --paths.
#   PYTHON/CI parity: when GITHUB_ACTIONS is set the runner has no .venv; python3
#     is always used.  Locally (GITHUB_ACTIONS unset), prefers the .venv when
#     executable.  PYTHON env overrides both.
#   argv injection: passthrough args are assembled via successive set -- prepends —
#     no eval, no numbered vars; shell metacharacters in passthrough args are
#     never interpreted.
#
# Env passthrough: RUN_ID / PFB_DIAG_DIR / SMOKE_LANE reach pytest by inheritance (no
#   explicit forwarding needed — subprocess env-inherit covers it).
#
# POSIX sh; shellcheck clean.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────── #
_PATHS="tests/smoke"
_MARKER="smoke"
_TIMEOUT=30
_FILTER=""
_MARKER_EXPLICIT=0  # set to 1 when -m/--marker was given as a structured flag

# ── Phase 1: parse structured flags; remaining "$@" = passthrough ─────────── #
# Structured flags must come before any passthrough args.
while [ "$#" -gt 0 ]; do
    case "$1" in
        --paths)
            shift
            _PATHS="${1:?run-smoke: --paths requires an argument}"
            shift
            ;;
        -m|--marker)
            shift
            _MARKER="${1:?run-smoke: -m/--marker requires an argument}"
            _MARKER_EXPLICIT=1
            shift
            ;;
        --timeout)
            shift
            _TIMEOUT="${1:?run-smoke: --timeout requires an argument}"
            shift
            ;;
        --filter)
            shift
            _FILTER="${1:?run-smoke: --filter requires an argument}"
            shift
            ;;
        *)
            # First non-known arg: start of passthrough — stop consuming.
            break
            ;;
    esac
done
# "$@" is now the passthrough.

# ── Phase 2: scan passthrough for the -m guard and bare-path guard ─────────── #
# -m guard: if the passthrough already has -m, do NOT inject our default marker.
# bare-path: a caller-supplied pytest TARGET (path/file/node-id) replaces the
#   default tests/smoke. Detect it by SHAPE, not position: a real target contains
#   '/', ends in '.py', or carries a '::' node-id. This catches a leading path
#   (`tests/smoke/ui`) AND a path after an option (`--lf tests/smoke/ui`), while a
#   bare word/number that is an option VALUE (the '1' in `--maxfail 1`) is NOT a
#   path — so neither position nor option-arity needs to be tracked.
_CALLER_GAVE_M=0
_CALLER_GAVE_PATH=0
for _a in "$@"; do
    case "$_a" in
        -m) _CALLER_GAVE_M=1 ;;
        -*) : ;;
        */*|*.py|*::*) _CALLER_GAVE_PATH=1 ;;
        *) : ;;
    esac
done

# ── Phase 3: PYTHON resolution ─────────────────────────────────────────────── #
# CI parity: when GITHUB_ACTIONS is set the runner has no .venv; use python3
# unconditionally to prevent a stray future .venv from silently drifting CI vs
# local behaviour.  PYTHON env overrides both paths.
if [ -z "${PYTHON:-}" ]; then
    if [ -z "${GITHUB_ACTIONS:-}" ] && [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
        PYTHON="${REPO_ROOT}/.venv/bin/python"
    else
        PYTHON=python3
    fi
fi

# ── Phase 4: build the canonical argv — no eval ───────────────────────────── #
# "$@" = passthrough (intact since Phase 1). Build the final pytest argv via
# successive right-to-left prepends — each set -- replaces "$@" entirely, so the
# LAST prepend ends up LEFTMOST in the final exec. No eval; no numbered vars;
# shell metacharacters in passthrough args are never interpreted.
#
# Final order: [PATH?] [-m MARKER?] [fixed...] [-k K?] [passthrough...]

# 4a. Prepend -k K so it lands between the fixed flags and the passthrough.
if [ -n "$_FILTER" ]; then
    set -- -k "$_FILTER" "$@"
fi

# 4b. Prepend the fixed canonical flags (the drift-kill; see ADR §5.3).
set -- \
    --override-ini="addopts=" \
    --override-ini="timeout_func_only=true" \
    --timeout="$_TIMEOUT" \
    --timeout-method=signal \
    --durations=0 \
    --capture=tee-sys \
    -v \
    "$@"

# 4c. Prepend -m MARKER — inject the structured value (or default) unless the
# passthrough already carries its own -m. An explicit --marker/-m always wins.
if [ "$_MARKER_EXPLICIT" -eq 1 ] || [ "$_CALLER_GAVE_M" -eq 0 ]; then
    set -- -m "$_MARKER" "$@"
fi

# 4d. Prepend the path unless the passthrough already has a leading positional path.
if [ "$_CALLER_GAVE_PATH" -eq 0 ]; then
    set -- "$_PATHS" "$@"
fi

# issue #605: export the diagnostics dir so the pytest process (and tests/timing.py's
# per-step timing.log) sees it — resolved here in the LAUNCHER, never mutated in-program.
# Mirrors tests/smoke/conftest.py's DIAG_DIR default; the on-box pytest otherwise has it
# unset (the orchestrator's value doesn't cross the ssh boundary), so timing.log would
# never join the uploaded smoke-diag/. The unit suite runs plain pytest (not this script),
# so PFB_DIAG_DIR stays unset there — timing is terminal-only, no stray file.
export PFB_DIAG_DIR="${PFB_DIAG_DIR:-smoke-diag}"

exec "$PYTHON" -m pytest "$@"
