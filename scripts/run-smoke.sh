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
#   --paths P        default tests/smoke   (UI: tests/smoke/ui)
#   -m/--marker M    default smoke         (CI smoke: smoke|repo; UI: ui_render|...)
#   --timeout N      default 30            (UI: 300)
#   --filter EXPR    optional; ONE arg, no word-split (passed to pytest as -k "expr")
#   --shard I        default 0             (0-based shard index; issue #797)
#   --shard-total N  default 1             (N=1: no-op, byte-identical to pre-#797
#                                            behaviour; N>1: --paths is replaced by
#                                            its shard slice -- a pytest argv
#                                            fragment, module-level or, for an
#                                            oversized module, test-level, issue #855)
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
#   shard slicing (issue #797, hybrid test-level split issue #855): --shard-total
#     N>1 hands the single --paths dir to scripts/shard-modules.sh and splices its
#     newline-separated stdout -- a pytest ARGV FRAGMENT (module paths, bare node
#     IDs, and adjacent `--deselect`/node-ID pairs, one argv word per line) -- in
#     as MULTIPLE leftmost pytest args, in the exact spot the one path occupies
#     today. An explicit passthrough path together with N>1 is a conflict (loud
#     error, never a silent pick); the splitter's own errors (e.g. an empty slice)
#     propagate as-is under `set -eu`. When N>1, pytest exit 5 ("no tests ran") is
#     mapped to 0 — a shard whose slice carries no test matching the marker is a
#     partition artifact, not a failure; unsharded runs keep exit 5 fatal.
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
_SHARD=0       # 0-based shard index (issue #797)
_SHARD_TOTAL=1 # N=1 = no sharding (default; byte-identical to pre-#797)

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
        --shard)
            shift
            _SHARD="${1:?run-smoke: --shard requires an argument}"
            shift
            ;;
        --shard-total)
            shift
            _SHARD_TOTAL="${1:?run-smoke: --shard-total requires an argument}"
            shift
            ;;
        *)
            # First non-known arg: start of passthrough — stop consuming.
            break
            ;;
    esac
done
# "$@" is now the passthrough.

# ── Phase 1b: validate --shard / --shard-total (cheap guard) ───────────────── #
# Out-of-range index (I >= N) is the SPLITTER's job (Phase 4d propagates its
# error); this only rejects non-numeric input and a total < 1 before anything
# else runs.
case "$_SHARD" in
    '' | *[!0-9]*)
        printf 'run-smoke: --shard must be a non-negative integer: %s\n' "$_SHARD" >&2
        exit 1
        ;;
esac
case "$_SHARD_TOTAL" in
    '' | *[!0-9]*)
        printf 'run-smoke: --shard-total must be a non-negative integer: %s\n' "$_SHARD_TOTAL" >&2
        exit 1
        ;;
esac
if [ "$_SHARD_TOTAL" -lt 1 ]; then
    printf 'run-smoke: --shard-total must be >= 1: %s\n' "$_SHARD_TOTAL" >&2
    exit 1
fi

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

# --shard-total N>1 and an explicit passthrough path are conflicting intents —
# never silently prefer one (issue #797): a shard slice REPLACES --paths, so a
# caller-given pytest target makes the request ambiguous.
if [ "$_SHARD_TOTAL" -gt 1 ] && [ "$_CALLER_GAVE_PATH" -eq 1 ]; then
    printf 'run-smoke: --shard-total %s conflicts with an explicit pytest path in the passthrough\n' \
        "$_SHARD_TOTAL" >&2
    exit 1
fi

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

# 4d. Prepend the path(s) unless the passthrough already has a leading positional
# path (the N>1 + caller-path conflict was already rejected above, so
# _CALLER_GAVE_PATH is guaranteed 0 whenever _SHARD_TOTAL > 1 here).
if [ "$_CALLER_GAVE_PATH" -eq 0 ]; then
    if [ "$_SHARD_TOTAL" -eq 1 ]; then
        set -- "$_PATHS" "$@"
    else
        # N>1: replace the single _PATHS dir with its shard slice -- a pytest argv
        # FRAGMENT (module paths, bare node IDs, adjacent `--deselect`/node-ID
        # pairs; one argv word per line, issue #855's hybrid test-level split for
        # an oversized module). A splitter failure (e.g. an empty slice) aborts
        # HERE under `set -eu` — deliberate: only stdout is captured, so the
        # splitter's stderr message still reaches the terminal.
        _shard_modules="$(sh "${REPO_ROOT}/scripts/shard-modules.sh" "$_PATHS" "$_SHARD" "$_SHARD_TOTAL")"
        # Re-split the newline-joined argv fragment into positional words — no
        # eval, no word-splitting of a blob (mirrors shard-modules.sh's own
        # re-split trick): IFS=newline only, glob disabled via set -f. A
        # `--deselect` line and its node-ID value are always two ADJACENT lines
        # (the splitter's own contract), so this re-split never separates them.
        _shard_oldifs="$IFS"
        IFS='
'
        set -f
        # shellcheck disable=SC2086  # intentional: re-split the newline-joined list
        set -- $_shard_modules "$@"
        set +f
        IFS="$_shard_oldifs"
    fi
fi

# issue #605: export the diagnostics dir so the pytest process (and tests/timing.py's
# per-step timing.log) sees it — resolved here in the LAUNCHER, never mutated in-program.
# Mirrors tests/smoke/conftest.py's DIAG_DIR default; the on-box pytest otherwise has it
# unset (the orchestrator's value doesn't cross the ssh boundary), so timing.log would
# never join the uploaded smoke-diag/. The unit suite runs plain pytest (not this script),
# so PFB_DIAG_DIR stays unset there — timing is terminal-only, no stray file.
export PFB_DIAG_DIR="${PFB_DIAG_DIR:-smoke-diag}"

# Sharded runs (N>1): pytest exit 5 ("no tests ran") is a PARTITION ARTIFACT, not
# a failure — a module slice can legitimately contain zero tests matching the
# requested marker (e.g. a slice of only repo/reboot-marked modules under
# -m smoke; first reachable at shards>=20 with today's marker density). The
# partition is complete by construction (the union of all shards is the whole
# run), so an empty shard is a benign no-op. Only exit 5 is mapped; every other
# non-zero rc stays fatal. Unsharded runs keep the exec (byte-identical path)
# where exit 5 still fails loudly — there it means a genuinely wrong invocation.
if [ "$_SHARD_TOTAL" -gt 1 ]; then
    _rc=0
    "$PYTHON" -m pytest "$@" || _rc=$?
    if [ "$_rc" -eq 5 ]; then
        printf 'run-smoke: shard %s/%s selected no tests for this marker — empty slice is a partition artifact, treating as pass\n' \
            "$_SHARD" "$_SHARD_TOTAL" >&2
        exit 0
    fi
    exit "$_rc"
fi

exec "$PYTHON" -m pytest "$@"
