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
#   scripts/local-smoke.sh [--ref REF] [--abi ABI] [--marker M] [--k K]
#                          [--no-two-vm]
#
# Required (env):
#   PFB_BOXES   space-separated ssh targets, e.g. "root@10.0.0.23 root@10.0.0.24"
#
# Optional (env or flags):
#   PFB_REF     git ref (commit/branch) to test (default: current HEAD)
#   --ref REF   same; flag takes precedence over PFB_REF
#   --abi ABI   build ABI (default: FreeBSD:15:amd64)
#   --marker M  pytest -m marker (default: smoke); see also --k
#   --k K       pytest -k filter expression (optional)
#   --no-two-vm skip civm image pull and LAN-client tests
#
# The leased box runs scripts/smoke-on-box.sh, which:
#   - checks out the requested ref
#   - updates FreeBSD-ports (pfblockerng/use-github)
#   - refreshes or pulls pfSense + civm images via oras
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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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
_ABI="FreeBSD:15:amd64"
_MARKER="smoke"
_K=""
_NO_TWO_VM=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)      shift; _REF="$1";    shift ;;
        --abi)      shift; _ABI="$1";    shift ;;
        --marker|-m) shift; _MARKER="$1"; shift ;;
        --k|-k)     shift; _K="$1";      shift ;;
        --no-two-vm) _NO_TWO_VM=1;       shift ;;
        --) shift; break ;;
        -*) printf 'local-smoke: unknown flag: %s\n' "$1" >&2; exit 2 ;;
        *)  break ;;  # extra positionals not supported in new model
    esac
done
if [ "$#" -gt 0 ]; then
    printf 'local-smoke: unexpected positional args (use --marker/--k): %s\n' "$*" >&2
    exit 2
fi

# ── Resolve REF (default: current branch name, falls back to SHA) ─────────── #
# A branch name is fetchable; a bare SHA is not (unless already pushed).
if [ -z "$_REF" ]; then
    _REF="$(git -C "$REPO_ROOT" symbolic-ref --short HEAD 2>/dev/null)" || true
    if [ -z "$_REF" ]; then
        _REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
        printf 'local-smoke: WARNING: detached HEAD; using SHA %s (may not be pushed to remote)\n' \
            "$_REF" >&2
    fi
fi

# Normalize a remote-qualified ref (origin/devel) to its bare name: the on-box
# `git fetch origin <ref>` wants the REMOTE ref name (devel), not `origin/devel`.
_REF="${_REF#origin/}"

# ── Build the on-box bootstrap command string ─────────────────────────────── #
# The bootstrap runs on the box via ssh; it must be a single shell command string.
# Use single-quote encoding for values that may contain shell metacharacters.
# ponytail: _sq encodes ONE value for embedding in a single-quoted sh literal.
_sq() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }

_REF_Q="$(_sq "$_REF")"
_ABI_Q="$(_sq "$_ABI")"
_MARKER_Q="$(_sq "$_MARKER")"

# Build the smoke-on-box.sh flags string (structured, no word-split risk after encoding).
_ob_flags="--ref '$_REF_Q' --abi '$_ABI_Q' --marker '$_MARKER_Q'"
if [ -n "$_K" ]; then
    _ob_flags="$_ob_flags --k '$(_sq "$_K")'"
fi
if [ "$_NO_TWO_VM" -eq 1 ]; then
    _ob_flags="$_ob_flags --no-two-vm"
fi

# The bootstrap string:
#   1. cd to the repo on the box
#   2. fetch the requested ref and check out its FETCHED TIP (FETCH_HEAD) — NOT a
#      bare `git checkout <ref>`, which lands the box's possibly-stale LOCAL branch
#      (a clone whose local devel predates an upstream commit would miss files added
#      since, e.g. scripts/smoke-on-box.sh itself → "cannot open" + no run).
#   3. exec smoke-on-box.sh (which re-fetches + re-execs at that ref's version)
# Ref-stable: the one-liner is the only part that has to work across refs;
# smoke-on-box.sh handles everything else.
# shellcheck disable=SC2089  # quoting: _ob_flags is pre-encoded for remote sh
_bootstrap="cd /root/pfBlockerNG \
 && git fetch --quiet origin '$_REF_Q' \
 && git checkout --quiet --force FETCH_HEAD \
 && exec sh scripts/smoke-on-box.sh $_ob_flags"

printf 'local-smoke: leasing box (REF=%s marker=%s%s)\n' \
    "$_REF" "$_MARKER" "${_K:+ k=$_K}" >&2

# ── Lease a box and run the bootstrap on it ────────────────────────────────── #
# select-box.sh -- <cmd>: acquires a lease, runs <cmd> on the box over ssh,
# releases the lease on EXIT/INT/TERM (automatic EXIT trap). The KEY=value
# output goes to stdout (ignored here; we don't eval it).
# shellcheck disable=SC2090  # expansion is intentional: _bootstrap is the remote command
sh scripts/select-box.sh -- "$_bootstrap"
