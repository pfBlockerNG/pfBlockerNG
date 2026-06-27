#!/bin/sh
# scripts/smoke-on-box.sh — on-box smoke entrypoint (local runs only).
#
# Runs ON the leased LXC box (invoked by local-smoke.sh via select-box.sh -- <cmd>).
# Single-writer per lease; no other smoke runs share this box concurrently.
#
# USAGE (always via select-box.sh -- "... sh /root/pfBlockerNG/scripts/smoke-on-box.sh <flags>"):
#   smoke-on-box.sh [--ref REF] [--abi ABI] [--marker M] [--k K] [--no-two-vm]
#
# FLAGS:
#   --ref REF      git ref to check out (default: current HEAD)
#   --abi ABI      build ABI string (default: FreeBSD:15:amd64)
#   --marker M     pytest -m marker (default: smoke)
#   --k K          pytest -k filter expr (default: none)
#   --no-two-vm    skip civm image pull and set NO_TWO_VM=1
#
# ENV (set by the select-box.sh lease or inherited):
#   SMOKE_LANE        lane index for port-striding (default 0; always 0 for local runs)
#   PFB_DIAG_DIR      diagnostics dir; defaults to "smoke-diag" relative in REPO_ROOT
#   SMOKE_SSH_KEY     path to pfSense guest SSH key (default /root/smoke-ssh-key)
#   SMOKE_GHCR_TOKEN  optional; used for `oras login ghcr.io` before image pull
#   SMOKE_PFSENSE_REF pfSense image ref (default ghcr.io/pfblockerng/pfsense-ce:2.8)
#   CIVM_REF          civm image ref (default ghcr.io/pfblockerng/civm:v1)
#
# RESPONSIBILITIES (in order):
#   1. Re-exec at requested REF (git fetch + checkout + exec with sentinel).
#   2. Ensure /root/FreeBSD-ports is current on pfblockerng/use-github.
#   3. Refresh /root/images/{pfsense,civm} via oras (digest-compare; pull when absent).
#   4. Host prep: ip_unprivileged_port_start sysctl + pkill stale qemu.
#   5. Build .pkg via build-leg.sh → SMOKE_PKG.
#   6. Run: run-smoke.sh with the configured lane/marker/-k.
#
# POSIX sh; shellcheck clean; all expansions quoted.

set -eu

# ── GIT_* scrub ───────────────────────────────────────────────────────────── #
# Inherited from the pre-commit hook or the orchestrator's env; scrub once.
unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_COMMON_DIR

# ── Defaults ──────────────────────────────────────────────────────────────── #
_REF=""        # resolved below (HEAD) if not given
_ABI="FreeBSD:15:amd64"
_MARKER="smoke"
_K=""
_NO_TWO_VM=0

REPO_ROOT="/root/pfBlockerNG"
PORTS_DIR="/root/FreeBSD-ports"
IMAGES_DIR="/root/images"

PFSENSE_REF="${SMOKE_PFSENSE_REF:-ghcr.io/pfblockerng/pfsense-ce:2.8}"
CIVM_REF="${CIVM_REF:-ghcr.io/pfblockerng/civm:v1}"

# ── Arg parsing ───────────────────────────────────────────────────────────── #
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)      shift; _REF="$1";    shift ;;
        --abi)      shift; _ABI="$1";    shift ;;
        --marker)   shift; _MARKER="$1"; shift ;;
        --k)        shift; _K="$1";      shift ;;
        --no-two-vm) _NO_TWO_VM=1;       shift ;;
        *) printf 'smoke-on-box: unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
done

# ── Step 1: ref-checkout + re-exec ────────────────────────────────────────── #
# The bootstrap (run by select-box.sh) may be at any ref; we git checkout the
# requested ref FIRST, then re-exec this script at that ref's version.
# Guard: PFB_ONBOX_REEXEC=1 skips re-exec (we are already at the right ref).
if [ "${PFB_ONBOX_REEXEC:-}" != "1" ]; then
    cd "$REPO_ROOT"
    printf 'smoke-on-box: fetching latest refs...\n' >&2
    git fetch --quiet
    if [ -z "$_REF" ]; then
        # No explicit ref — stay on whatever HEAD the bootstrap checked out.
        _REF="$(git rev-parse HEAD)"
    fi
    printf 'smoke-on-box: checking out ref %s\n' "$_REF" >&2
    git checkout --quiet "$_REF"

    # Re-exec the now-checked-out version with properly quoted args.
    # Build via set -- so each arg is a distinct word (no word-split on _K spaces).
    set -- --ref "$_REF" --abi "$_ABI" --marker "$_MARKER"
    [ -n "$_K" ] && set -- "$@" --k "$_K"
    [ "$_NO_TWO_VM" -eq 1 ] && set -- "$@" --no-two-vm
    PFB_ONBOX_REEXEC=1 exec sh "$REPO_ROOT/scripts/smoke-on-box.sh" "$@"
fi

# ── From here: running at the correct ref (PFB_ONBOX_REEXEC=1) ─────────────── #
cd "$REPO_ROOT"

# ── Step 2: ports tree — bring to pfblockerng/use-github ───────────────────── #
printf 'smoke-on-box: updating FreeBSD-ports at %s\n' "$PORTS_DIR" >&2
sh scripts/sparse-clone-ports.sh \
    "https://github.com/pfBlockerNG/FreeBSD-ports" \
    "pfblockerng/use-github" \
    "$PORTS_DIR" \
    "devel" "8.3" "py311" >&2

# ── Step 3: oras images (refresh when stale; pull when absent) ─────────────── #
_oras_login_done=0
_oras_login() {
    if [ "$_oras_login_done" -eq 0 ] && [ -n "${SMOKE_GHCR_TOKEN:-}" ]; then
        printf '%s\n' "$SMOKE_GHCR_TOKEN" | \
            oras login ghcr.io --username pfBlockerNG --password-stdin >/dev/null 2>&1 \
            || true
        _oras_login_done=1
    fi
}

# _oras_refresh <ref> <dir> <tag>
# Pull image if absent or if GHCR digest changed.
_oras_refresh() {
    _or_ref="$1"
    _or_dir="$2"
    _or_tag="$3"

    mkdir -p "$_or_dir"

    # Remote digest (best-effort; skip refresh on auth failure).
    _or_remote=""
    _or_remote="$(oras resolve "$_or_ref" 2>/dev/null)" \
        || _or_remote="$(oras manifest fetch "$_or_ref" --descriptor 2>/dev/null \
                         | grep -o '"digest":"[^"]*"' | cut -d'"' -f4)" \
        || _or_remote=""

    _or_local="$(cat "${_or_dir}/.digest" 2>/dev/null)" || _or_local=""

    # Count qcow2s in dir.
    _or_qcnt=0
    for _or_q in "${_or_dir}"/*.qcow2; do
        [ -e "$_or_q" ] && _or_qcnt=$((_or_qcnt + 1))
    done

    if [ "$_or_qcnt" -eq 0 ] || \
       { [ -n "$_or_remote" ] && [ "$_or_remote" != "$_or_local" ]; }; then
        printf 'smoke-on-box: pulling %s image (%s) -> %s\n' "$_or_tag" "$_or_ref" "$_or_dir" >&2
        _oras_login
        if [ -n "$_or_remote" ]; then
            ( cd "$_or_dir" && oras pull "${_or_ref%@*}@${_or_remote}" ) >&2
            printf '%s\n' "$_or_remote" > "${_or_dir}/.digest"
        else
            ( cd "$_or_dir" && oras pull "$_or_ref" ) >&2
        fi
    else
        printf 'smoke-on-box: %s image up-to-date at %s\n' "$_or_tag" "$_or_dir" >&2
    fi
}

_oras_refresh "$PFSENSE_REF" "${IMAGES_DIR}/pfsense" "pfSense"
if [ "$_NO_TWO_VM" -eq 0 ]; then
    _oras_refresh "$CIVM_REF" "${IMAGES_DIR}/civm" "civm"
fi

export SMOKE_IMAGE_DIR="${IMAGES_DIR}/pfsense"
if [ "$_NO_TWO_VM" -eq 0 ]; then
    export SMOKE_CLIENT_IMAGE_DIR="${IMAGES_DIR}/civm"
    export NO_TWO_VM=0
else
    export NO_TWO_VM=1
fi

# ── Step 4: host prep (this box only — single-writer per lease) ─────────────── #
# Lower the unprivileged-port floor so the non-root mock DNS can bind :53.
_floor="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
if [ "$_floor" -gt 53 ]; then
    printf 'smoke-on-box: lowering ip_unprivileged_port_start to 53 (was %s)\n' "$_floor" >&2
    sysctl -w net.ipv4.ip_unprivileged_port_start=53 >/dev/null 2>&1 \
        || sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53 >/dev/null
fi
export SMOKE_STUB_DNS_ADDR="${SMOKE_STUB_DNS_ADDR:-127.0.0.1}"
export SMOKE_STUB_DNS_PORT="${SMOKE_STUB_DNS_PORT:-53}"

# Kill any stale qemu from a previous run on this box (lease guarantees we are
# the only writer; pkill -9 never touches another box's VMs).
pkill -9 -f qemu-system-x86_64 2>/dev/null || true

# ── Step 5: build .pkg ─────────────────────────────────────────────────────── #
printf 'smoke-on-box: building .pkg (abi=%s)...\n' "$_ABI" >&2
SMOKE_PKG="$(sh scripts/build-leg.sh \
    --ports-dir  "$PORTS_DIR" \
    --abi        "$_ABI" \
    --local-src  "$REPO_ROOT")"
export SMOKE_PKG
printf 'smoke-on-box: pkg built: %s\n' "$SMOKE_PKG" >&2

# SSH key for the pfSense guest (baked into the image).
export SMOKE_SSH_KEY="${SMOKE_SSH_KEY:-/root/smoke-ssh-key}"
if [ ! -f "$SMOKE_SSH_KEY" ]; then
    printf 'smoke-on-box: SMOKE_SSH_KEY not a file: %s\n' "$SMOKE_SSH_KEY" >&2
    printf 'smoke-on-box: set SMOKE_SSH_KEY or place the key at /root/smoke-ssh-key\n' >&2
    exit 2
fi

# ── Step 6: run smoke ─────────────────────────────────────────────────────── #
printf 'smoke-on-box: running smoke (marker=%s%s)\n' \
    "$_MARKER" "${_K:+ k=$_K}" >&2

set -- --paths tests/smoke --marker "$_MARKER" --timeout 30
[ -n "$_K" ] && set -- "$@" --k "$_K"
exec sh scripts/run-smoke.sh "$@"
