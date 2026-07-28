#!/bin/sh
# beta-repo-probe.sh — cheap public-beta detection for the version tracker
# (issue #1820): boot the CURRENT published smoke image for a variant as a
# throwaway overlay, list the pfSense update repos on it, and report whether an
# expected upcoming version is already served as a public repo branch. The VM
# starts, runs a handful of commands, and is killed — no upgrade happens here
# (image generation is image-refresh.yml's separate flow).
#
# Usage:
#   scripts/beta-repo-probe.sh --variant ce|plus --expect VERSION \
#       --image GHCR_REF --tag TAG --ssh-key PATH [options]
#
# Options:
#   --variant V       ce | plus (required). plus REQUIRES the identity env vars
#                     below; absent/malformed => verdict "unknown" (a Plus boot
#                     with the wrong identity can burn the license — never risked).
#   --expect V        version to look for in `pfSense-repoc -p` output (required)
#   --image REF       GHCR image ref WITHOUT tag (required)
#   --tag T           tag to pull and boot — the variant's newest published
#                     version (required)
#   --ssh-key PATH    guest SSH private key (required)
#   --ssh-port N      host port forwarded to the guest's :22 (default 2222)
#   --out FILE        write the JSON verdict to FILE instead of stdout
#   --boot-timeout S  max seconds to wait for guest SSH (default 300)
#
# Environment:
#   SMOKE_VM_MAC / SMOKE_VM_SMBIOS_UUID  Plus identity (8 NIC MACs, newline-
#                                        separated + SMBIOS type-1 uuid); read by
#                                        boot_vm.sh. CE uses its committed defaults.
#   PFB_BOOT_VM        boot helper (default tests/smoke/boot_vm.sh) — spec override
#   PFB_POLL_INTERVAL  SSH poll interval seconds (default 5; floored to 1) — spec override
#   PFB_SHUTDOWN_WAIT  max seconds to wait for a clean poweroff (default 60)
#
# Output (single line of JSON):
#   {"variant":"...","expect":"...","verdict":"yes|no|unknown","branch":"..."}
#   yes     — repo list contains --expect; "branch" is the repo-name column of
#             the matching line (the pkg_list_repos() name that
#             image-upgrade.sh --branch consumes), annotations stripped.
#   no      — the guest answered and the repo list lacks --expect.
#   unknown — any infrastructure failure (pull, boot, ssh, Plus identity).
# Exit status: always 0 — a best-effort probe; callers gate on "verdict".
#
# POSIX sh (strict ash/dash semantics); base utilities bare, guest binaries absolute.

set -u

VARIANT=""
EXPECT=""
IMAGE=""
TAG=""
SSH_KEY=""
SSH_PORT=2222
OUT=""
BOOT_TIMEOUT=300
POLL="${PFB_POLL_INTERVAL:-5}"
# A zero/garbage poll interval would stall the elapsed counters below forever.
case "$POLL" in ''|*[!0-9]*|0) POLL=5 ;; esac
SHUTDOWN_WAIT="${PFB_SHUTDOWN_WAIT:-60}"

usage() {
    echo "Usage: $0 --variant ce|plus --expect VERSION --image REF --tag TAG --ssh-key PATH [--ssh-port N] [--out FILE] [--boot-timeout S]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --variant)      [ "$#" -ge 2 ] || usage; VARIANT="$2"; shift 2 ;;
        --expect)       [ "$#" -ge 2 ] || usage; EXPECT="$2"; shift 2 ;;
        --image)        [ "$#" -ge 2 ] || usage; IMAGE="$2"; shift 2 ;;
        --tag)          [ "$#" -ge 2 ] || usage; TAG="$2"; shift 2 ;;
        --ssh-key)      [ "$#" -ge 2 ] || usage; SSH_KEY="$2"; shift 2 ;;
        --ssh-port)     [ "$#" -ge 2 ] || usage; SSH_PORT="$2"; shift 2 ;;
        --out)          [ "$#" -ge 2 ] || usage; OUT="$2"; shift 2 ;;
        --boot-timeout) [ "$#" -ge 2 ] || usage; BOOT_TIMEOUT="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [ -z "$VARIANT" ] || [ -z "$EXPECT" ] || [ -z "$IMAGE" ] || [ -z "$TAG" ] || [ -z "$SSH_KEY" ]; then
    usage
fi
case "$VARIANT" in ce|plus) ;; *) usage ;; esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
BOOT_VM="${PFB_BOOT_VM:-$SCRIPT_DIR/../tests/smoke/boot_vm.sh}"

WORK=$(mktemp -d)
BOOT_PID=""

# shellcheck disable=SC2329,SC2317  # invoked via the EXIT/INT/TERM trap
cleanup() {
    _rc=$?
    if [ -n "$BOOT_PID" ] && kill -0 "$BOOT_PID" 2>/dev/null; then
        kill "$BOOT_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
    trap - EXIT
    exit "$_rc"
}
trap cleanup EXIT INT TERM

# emit VERDICT BRANCH — print the JSON result and exit 0 (always best-effort).
emit() {
    _verdict=$1
    # Branch names come from repoc output; keep the JSON trivially safe.
    _branch=$(printf '%s' "${2:-}" | tr -cd 'A-Za-z0-9._-')
    _json=$(printf '{"variant":"%s","expect":"%s","verdict":"%s","branch":"%s"}' \
        "$VARIANT" "$EXPECT" "$_verdict" "$_branch")
    if [ -n "$OUT" ]; then
        printf '%s\n' "$_json" > "$OUT"
    else
        printf '%s\n' "$_json"
    fi
    exit 0
}

# Plus identity gate — never boot Plus without the full license-keyed identity.
if [ "$VARIANT" = "plus" ]; then
    _mac_count=$(printf '%s\n' "${SMOKE_VM_MAC:-}" | grep -c '[^[:space:]]' || true)
    if [ "${_mac_count:-0}" -ne 8 ] || [ -z "${SMOKE_VM_SMBIOS_UUID:-}" ]; then
        echo "beta-repo-probe: Plus identity absent/malformed — verdict unknown" >&2
        emit unknown
    fi
fi

# Pull the variant's current image and locate its qcow2.
if ! oras pull "${IMAGE}:${TAG}" --output "$WORK" >&2; then
    echo "beta-repo-probe: oras pull ${IMAGE}:${TAG} failed — verdict unknown" >&2
    emit unknown
fi
BASE_IMG=$(find "$WORK" -maxdepth 1 -name '*.qcow2' | head -1)
if [ -z "$BASE_IMG" ]; then
    echo "beta-repo-probe: no qcow2 in ${IMAGE}:${TAG} — verdict unknown" >&2
    emit unknown
fi

# Boot a throwaway overlay (boot_vm.sh never writes the base; the explicit
# overlay lives in WORK and dies with it).
echo "beta-repo-probe: booting ${VARIANT} ${TAG} (ssh 127.0.0.1:${SSH_PORT})" >&2
SMOKE_SSH_HOSTPORT="$SSH_PORT" sh "$BOOT_VM" "$BASE_IMG" "$WORK/overlay.qcow2" \
    > "$WORK/console.log" 2>&1 &
BOOT_PID=$!

guest_ssh() {
    ssh -p "$SSH_PORT" -i "$SSH_KEY" \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        root@127.0.0.1 "$@"
}

# Wait for guest SSH — hard-capped; a dead qemu ends the wait early.
_elapsed=0
_ssh_up=0
while [ "$_elapsed" -lt "$BOOT_TIMEOUT" ]; do
    if ! kill -0 "$BOOT_PID" 2>/dev/null; then
        break
    fi
    if guest_ssh true 2>/dev/null; then
        _ssh_up=1
        break
    fi
    sleep "$POLL"; _elapsed=$((_elapsed + POLL))
done
if [ "$_ssh_up" -ne 1 ]; then
    echo "beta-repo-probe: guest SSH not up within ${BOOT_TIMEOUT}s — verdict unknown" >&2
    emit unknown
fi

# The handful of commands this probe exists for.
if ! REPOS=$(guest_ssh '/usr/local/sbin/pfSense-repoc -p' 2>/dev/null); then
    echo "beta-repo-probe: pfSense-repoc -p failed on the guest — verdict unknown" >&2
    emit unknown
fi

MATCH=$(printf '%s\n' "$REPOS" | grep -F -- "$EXPECT" | head -1 || true)

# Best-effort clean shutdown, then the trap reaps whatever is left (capped).
guest_ssh '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while kill -0 "$BOOT_PID" 2>/dev/null && [ "$_elapsed" -lt "$SHUTDOWN_WAIT" ]; do
    sleep "$POLL"; _elapsed=$((_elapsed + POLL))
done

if [ -z "$MATCH" ]; then
    emit no
fi
# Repo name = the tab-delimited first column, minus trailing "(release)"-style
# annotations (probed live: "26.07<TAB><TAB>Beta Version (26.07)" and
# "26_03_1 (release) (default)<TAB><TAB>Current Stable Version (26.03.1)").
BRANCH=$(printf '%s\n' "$MATCH" | sed -e '1!d' -e 's/	.*//' -e 's/ *(.*$//')
emit yes "$BRANCH"
