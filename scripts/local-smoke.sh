#!/bin/sh
# local-smoke.sh — run the ADR-04 live-VM smoke suite locally via a leased LXC box.
#
# Leases one box from the PFB_BOXES pool (scripts/select-box.sh), bootstraps it
# to the requested git ref, and runs the ENTIRE smoke suite ON the box — images,
# build, pytest all run there. The orchestrator only provides the bootstrap command.
# The EXIT trap in select-box.sh releases the lease automatically.
#
# Full background + rationale: docs/misc/local-smoke-debian.md
#
# Usage:
#   scripts/local-smoke.sh [--ref REF] [--abi ABI] [--marker M] [--filter EXPR]
#                          [--no-two-vm] [--shards N]
#
# Required (env):
#   PFB_BOXES   space-separated ssh targets, e.g. "root@10.0.0.23 root@10.0.0.24"
#
# Optional (env or flags):
#   PFB_REF     git ref (commit/branch) to test (default: current HEAD)
#   --ref REF   same; flag takes precedence over PFB_REF
#   --abi ABI   build ABI (default: FreeBSD:15:amd64)
#   --channel C pkg channel to BUILD: stable|testing|edge|nightly (default: edge, the
#               channel the devel branch's 4.0.0.a* line belongs to, and the one
#               build-pkg-linux.yml builds, issue #2166). The channel picks the port,
#               and the port names the package, so a run on the wrong channel verifies a
#               differently-named artifact than CI ships (issue #2206).
#   --marker M  pytest -m marker (default: smoke); see also --filter
#   --filter EXPR  pytest -k filter expression (optional)
#   --no-two-vm skip civm image pull and LAN-client tests
#   --shards N  lease N boxes CONCURRENTLY, each running one module-level shard
#               (issue #797; see scripts/run-smoke.sh --shard/--shard-total).
#               Default 1 (today's single-box flow, unchanged). N>1 REFUSES
#               --filter and any --marker other than smoke (a narrowed run can
#               collect zero tests per shard -- pytest exit 5 would fail the
#               shard spuriously). N should be <= the free PFB_BOXES pool; an
#               oversized N just makes the excess shards fail loudly on
#               select-box.sh's own pool-exhaustion path -- this script does
#               NOT pre-count the pool. Logs land in a kept mktemp dir printed
#               at start/end; exits non-zero iff any shard failed.
#
# Test-only (env):
#   PFB_SELECT_BOX  override the select-box.sh path (default: scripts/select-box.sh).
#                   Used by tests/shell/local_smoke_spec.sh to inject a fake.
#
# The leased box runs scripts/smoke-on-box.sh, which:
#   - checks out the requested ref
#   - updates FreeBSD-ports (pfblockerng/use-github)
#   - pulls pfSense + civm images into disposable container-local paths via oras
#   - lowers ip_unprivileged_port_start + kills stale qemu
#   - builds the .pkg via build-leg.sh
#   - runs scripts/run-smoke.sh (the canonical pytest argv)
#
# POSIX sh; quoted expansions; shellcheck clean.

set -eu

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

case "${1:-}" in
    -h|--help) usage 0 ;;
esac

REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Required env ──────────────────────────────────────────────────────────── #
if [ -z "${PFB_BOXES:-}" ]; then
    printf 'local-smoke: PFB_BOXES is required (space-separated ssh targets)\n' >&2
    printf '             e.g. export PFB_BOXES="root@10.0.0.23 root@10.0.0.24"\n' >&2
    exit 2
fi
export PFB_BOXES

# ── Parse flags ───────────────────────────────────────────────────────────── #
_REF="${PFB_REF:-}"
_ABI="FreeBSD:15:amd64"  # version-literal-ok: local-dev default; overridden by --abi
# A local run must build the same-named package CI does, or a green local smoke proves
# nothing about CI's artifact. NOT mechanically pinned to build-pkg-linux.yml: the guard test
# (tests/test_issue2166_workflow_channel_inputs.py) scans the workflows and tests/smoke, never
# this default, so the two are kept in step by hand. Both build the channel the devel branch's
# 4.0.0.a* line belongs to. Revisit if the branch changes release line.
_CHANNEL="edge"
_MARKER="smoke"
_FILTER=""
_NO_TWO_VM=0
_SHARDS=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)      shift; _REF="$1";    shift ;;
        --abi)      shift; _ABI="$1";    shift ;;
        --channel)  shift; _CHANNEL="$1"; shift ;;
        --marker|-m) shift; _MARKER="$1"; shift ;;
        --filter)   shift; _FILTER="$1";      shift ;;
        --no-two-vm) _NO_TWO_VM=1;        shift ;;
        --shards)   shift; _SHARDS="$1"; shift ;;
        --) shift; break ;;
        -*) printf 'local-smoke: unknown flag: %s\n' "$1" >&2; exit 2 ;;
        *)  break ;;
    esac
done
if [ "$#" -gt 0 ]; then
    printf 'local-smoke: unexpected positional args (use --marker/--filter): %s\n' "$*" >&2
    exit 2
fi

case "$_CHANNEL" in
    stable|testing|edge|nightly) ;;
    *)
        printf 'local-smoke: --channel must be stable|testing|edge|nightly: %s\n' "$_CHANNEL" >&2
        exit 2
        ;;
esac

case "$_SHARDS" in
    ''|*[!0-9]*)
        printf 'local-smoke: --shards must be a positive integer: %s\n' "$_SHARDS" >&2
        exit 2
        ;;
esac
if [ "$_SHARDS" -eq 0 ]; then
    printf 'local-smoke: --shards must be >= 1: %s\n' "$_SHARDS" >&2
    exit 2
fi

if [ "$_SHARDS" -gt 1 ]; then
    if [ -n "$_FILTER" ]; then
        printf 'local-smoke: --shards N>1 refuses --filter (a -k slice can collect zero tests -- pytest exit 5 would fail that shard spuriously); drop one of the two\n' >&2
        exit 2
    fi
    if [ "$_MARKER" != "smoke" ]; then
        printf 'local-smoke: --shards N>1 refuses --marker %s (non-default markers select few tests -- same empty-slice hazard; UI tiers must never be split, which smoke-on-box.sh enforces independently); drop one of the two\n' \
            "$_MARKER" >&2
        exit 2
    fi
fi

_SELECT_BOX="${PFB_SELECT_BOX:-scripts/select-box.sh}"

if [ -z "$_REF" ]; then
    _REF="$(git -C "$REPO_ROOT" symbolic-ref --short HEAD 2>/dev/null)" || true
    if [ -z "$_REF" ]; then
        _REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
        printf 'local-smoke: WARNING: detached HEAD; using SHA %s (may not be pushed to remote)\n' \
            "$_REF" >&2
    fi
fi

_REF="${_REF#origin/}"

_sq() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }

_REF_Q="$(_sq "$_REF")"
_ABI_Q="$(_sq "$_ABI")"
_MARKER_Q="$(_sq "$_MARKER")"
_REPO_LIVE_URL_Q="$(_sq "${SMOKE_REPO_LIVE_URL:-}")"
_NIGHTLY_LIVE_URL_Q="$(_sq "${SMOKE_NIGHTLY_LIVE_URL:-}")"
_REPO_EXPECTED_SOURCE_SHA_Q="$(_sq "${SMOKE_REPO_EXPECTED_SOURCE_SHA:-}")"
_REPO_EXPECTED_VERSION_Q="$(_sq "${SMOKE_REPO_EXPECTED_VERSION:-}")"
_NIGHTLY_EXPECTED_SOURCE_SHA_Q="$(_sq "${SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA:-}")"
_NIGHTLY_EXPECTED_VERSION_Q="$(_sq "${SMOKE_NIGHTLY_EXPECTED_VERSION:-}")"
_PFSENSE_REF_Q="$(_sq "${SMOKE_PFSENSE_REF:-}")"
_CIVM_REF_Q="$(_sq "${CIVM_REF:-}")"

_ob_flags="--ref '$_REF_Q' --abi '$_ABI_Q' --channel '$_CHANNEL' --marker '$_MARKER_Q'"
if [ -n "$_FILTER" ]; then
    _ob_flags="$_ob_flags --filter '$(_sq "$_FILTER")'"
fi
if [ "$_NO_TWO_VM" -eq 1 ]; then
    _ob_flags="$_ob_flags --no-two-vm"
fi

_bootstrap="cd /root/pfBlockerNG \
 && git sparse-checkout init --cone \
 && git sparse-checkout set src scripts stubs/python tests/smoke \
 && git fetch --quiet origin '$_REF_Q' \
 && git checkout --quiet --force FETCH_HEAD \
 && git fetch --quiet --no-tags origin ci-metadata:refs/remotes/origin/ci-metadata \
 && exec docker run --rm --init \
      --device /dev/kvm \
      --sysctl net.ipv4.ip_unprivileged_port_start=53 \
      -v /root/pfBlockerNG:/root/pfBlockerNG \
      -v /root/FreeBSD-ports:/root/FreeBSD-ports \
      -v /root/smoke-ssh-key:/root/smoke-ssh-key:ro \
      -e SMOKE_GHCR_TOKEN -e SMOKE_ADMIN_USER -e SMOKE_ADMIN_PASSWORD \
      -e SMOKE_PFSENSE_REF='$_PFSENSE_REF_Q' -e CIVM_REF='$_CIVM_REF_Q' \
      -e SMOKE_LANE -e PFB_DIAG_DIR -e PFB_LAN_REGISTRY \
      -e SMOKE_REPO_LIVE_URL='$_REPO_LIVE_URL_Q' -e SMOKE_NIGHTLY_LIVE_URL='$_NIGHTLY_LIVE_URL_Q' \
      -e SMOKE_REPO_EXPECTED_SOURCE_SHA='$_REPO_EXPECTED_SOURCE_SHA_Q' -e SMOKE_REPO_EXPECTED_VERSION='$_REPO_EXPECTED_VERSION_Q' \
      -e SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA='$_NIGHTLY_EXPECTED_SOURCE_SHA_Q' -e SMOKE_NIGHTLY_EXPECTED_VERSION='$_NIGHTLY_EXPECTED_VERSION_Q' \
      -w /root/pfBlockerNG \
      \${PFB_LAN_REGISTRY:-ghcr.io}/pfblockerng/ci-runner-vm:9 \
      sh scripts/smoke-on-box.sh $_ob_flags"

printf 'local-smoke: leasing box (REF=%s marker=%s%s)\n' \
    "$_REF" "$_MARKER" "${_FILTER:+ filter=$_FILTER}" >&2

if [ "$_SHARDS" -eq 1 ]; then
    sh "$_SELECT_BOX" -- "$_bootstrap"
    exit $?
fi

_LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pfb-local-smoke-shards.XXXXXX")"
printf 'local-smoke: sharded run (--shards %s); logs: %s\n' "$_SHARDS" "$_LOG_DIR" >&2

_PIDS=""
_ABORT=0
trap '_ABORT=1; kill $_PIDS 2>/dev/null' INT TERM

_i=0
while [ "$_i" -lt "$_SHARDS" ] && [ "$_ABORT" -eq 0 ]; do
    _shard_bootstrap="${_bootstrap} --shard '$(_sq "$_i")' --shard-total '$(_sq "$_SHARDS")'"
    _shard_log="${_LOG_DIR}/shard-${_i}.log"
    sh "$_SELECT_BOX" -- "$_shard_bootstrap" > "$_shard_log" 2>&1 &
    _pid=$!
    _PIDS="$_PIDS $_pid"
    if [ "$_ABORT" -eq 1 ]; then
        kill "$_pid" 2>/dev/null || true
        break
    fi
    printf 'local-smoke: launched shard %s (pid=%s) -> %s\n' "$_i" "$_pid" "$_shard_log" >&2
    _i=$((_i + 1))
done

_RCS=""
_FAILED=0
for _pid in $_PIDS; do
    if wait "$_pid"; then
        _RCS="$_RCS 0"
    else
        _rc=$?
        _RCS="$_RCS $_rc"
        _FAILED=1
    fi
done

printf 'local-smoke: shard summary (logs: %s):\n' "$_LOG_DIR" >&2
_i=0
for _rc in $_RCS; do
    printf '  shard %s: rc=%s\n' "$_i" "$_rc" >&2
    _i=$((_i + 1))
done

if [ "$_FAILED" -eq 1 ]; then
    _i=0
    for _rc in $_RCS; do
        if [ "$_rc" -ne 0 ]; then
            printf 'local-smoke: ---- shard %s FAILED (rc=%s); last 25 lines of %s ----\n' \
                "$_i" "$_rc" "${_LOG_DIR}/shard-${_i}.log" >&2
            tail -n 25 "${_LOG_DIR}/shard-${_i}.log" >&2
            printf 'local-smoke: ---- end shard %s log ----\n' "$_i" >&2
        fi
        _i=$((_i + 1))
    done
    exit 1
fi

exit 0
