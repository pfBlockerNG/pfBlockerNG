#!/bin/sh
# scripts/run-smoke.sh — the ONE canonical pytest invocation for all three call sites:
#   smoke-single.yml, ui-tests.yml, scripts/smoke-on-box.sh (local runs via lease).
#
# Emits and executes:
#   $PYTHON -m pytest $PATHS -m $MARKER
#     --override-ini="addopts=" --override-ini="timeout_func_only=true"
#     --timeout=$TIMEOUT --timeout-method=signal -v
#     [-k $K] [passthrough...]
#
# Params + defaults (structured flags must precede passthrough):
#   --paths P      default tests/smoke   (UI: tests/smoke/ui)
#   -m/--marker M  default smoke         (CI smoke: smoke|repo; UI: ui_render|...)
#   --timeout N    default 30            (UI: 300)
#   -k EXPR        optional; ONE arg, no word-split (passes as -k "expr" to pytest)
#   trailing passthrough → forwarded to pytest verbatim
#
# AMENDMENTS:
#   bare-path parity: a positional path in the passthrough REPLACES --paths (not
#     appended) — so `local-smoke.sh -m ui_render tests/smoke/ui` runs only that subtree.
#   PYTHON/CI parity: prefers $REPO_ROOT/.venv/bin/python when executable (local dev);
#     falls back to python3 (CI runners have no .venv; PYTHON env overrides both).
#     Coupling: CI parity holds because CI has no .venv and no PYTHON override; the .venv
#     path is simply absent on the runner.
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
_K=""
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
        -k)
            shift
            _K="${1:?run-smoke: -k requires an argument}"
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
# bare-path: if the passthrough has a positional arg (no leading -), suppress
#   the default --paths so the caller's positional reaches pytest directly.
_CALLER_GAVE_M=0
_CALLER_GAVE_PATH=0
for _a in "$@"; do
    case "$_a" in
        -m) _CALLER_GAVE_M=1 ;;
        -*) : ;;
        *)  _CALLER_GAVE_PATH=1 ;;
    esac
done

# ── Phase 3: save passthrough before we clobber "$@" with set -- ─────────── #
# POSIX sh has no arrays — store each passthrough arg in a numbered variable and
# replay them at the end.
# ponytail: numbered-var trick for POSIX-sh arg accumulation; no bash-isms.
_PT_N=$#
_i=0
for _a in "$@"; do
    _i=$((_i + 1))
    eval "_pt_${_i}=\$_a"
done

# ── Phase 4: PYTHON resolution ─────────────────────────────────────────────── #
if [ -z "${PYTHON:-}" ]; then
    if [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
        PYTHON="${REPO_ROOT}/.venv/bin/python"
    else
        PYTHON=python3
    fi
fi

# ── Phase 5: build the canonical argv ─────────────────────────────────────── #
# Paths: inject unless the passthrough already carries a positional path.
if [ "$_CALLER_GAVE_PATH" -eq 0 ]; then
    set -- "$_PATHS"
else
    set --
fi

# Marker: inject the structured value (or default) UNLESS the passthrough carries
# its own -m. An explicit --marker/-m always wins; the guard applies only when the
# marker was NOT given as a structured flag.
if [ "$_MARKER_EXPLICIT" -eq 1 ] || [ "$_CALLER_GAVE_M" -eq 0 ]; then
    set -- "$@" -m "$_MARKER"
fi

# Fixed canonical flags (the drift-kill; see ADR §5.3).
set -- "$@" \
    --override-ini="addopts=" \
    --override-ini="timeout_func_only=true" \
    --timeout="$_TIMEOUT" \
    --timeout-method=signal \
    -v

# Optional -k (single arg — no word-split, even for "a and not b").
if [ -n "$_K" ]; then
    set -- "$@" -k "$_K"
fi

# Passthrough (replayed in original order).
_i=0
while [ "$_i" -lt "$_PT_N" ]; do
    _i=$((_i + 1))
    eval "set -- \"\$@\" \"\${_pt_${_i}}\""
done

exec "$PYTHON" -m pytest "$@"
