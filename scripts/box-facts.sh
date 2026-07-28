#!/bin/sh
# box-facts.sh — boot a published smoke image as a throwaway overlay and gather
# the raw facts the image-reconcile planner needs (issue #1823): /etc/version,
# the `pfSense-repoc -p` branch list, and the `pfSense-upgrade -c` check on the
# image's own configured branch. NO parsing here — scripts/reconcile-plan.py
# owns interpretation. The VM starts, answers three commands, and is killed.
#
# Usage:
#   scripts/box-facts.sh --variant ce|plus --image GHCR_REF --tag TAG \
#       --ssh-key PATH --out-dir DIR [options]
#
# Options:
#   --variant V       ce | plus (required). plus REQUIRES the identity env vars
#                     below; absent/malformed => status "unavailable" (a Plus
#                     boot with the wrong identity can burn the license).
#   --image REF       GHCR image ref WITHOUT tag (required)
#   --tag T           tag to pull and boot (required)
#   --ssh-key PATH    guest SSH private key (required)
#   --out-dir DIR     writes etc-version, repoc.txt, upgrade-check.txt, and
#                     status (ok|unavailable) there (required)
#   --ssh-port N      host port forwarded to the guest's :22 (default 2222)
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
# status file: "ok" = all three facts gathered; "unavailable" = any
# infrastructure failure (pull, boot, ssh, Plus identity) — partial fact files
# may exist but the planner must treat the boot as absent.
# Exit status: always 0 — best-effort; callers gate on the status file.
#
# POSIX sh (strict ash/dash semantics); base utilities bare, guest binaries absolute.

set -u

VARIANT=""
IMAGE=""
TAG=""
SSH_KEY=""
OUT_DIR=""
SSH_PORT=2222
BOOT_TIMEOUT=300
POLL="${PFB_POLL_INTERVAL:-5}"
# A zero/garbage poll interval would stall the elapsed counters below forever.
case "$POLL" in ''|*[!0-9]*|0) POLL=5 ;; esac
SHUTDOWN_WAIT="${PFB_SHUTDOWN_WAIT:-60}"

usage() {
    echo "Usage: $0 --variant ce|plus --image REF --tag TAG --ssh-key PATH --out-dir DIR [--ssh-port N] [--boot-timeout S]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --variant)      [ "$#" -ge 2 ] || usage; VARIANT="$2"; shift 2 ;;
        --image)        [ "$#" -ge 2 ] || usage; IMAGE="$2"; shift 2 ;;
        --tag)          [ "$#" -ge 2 ] || usage; TAG="$2"; shift 2 ;;
        --ssh-key)      [ "$#" -ge 2 ] || usage; SSH_KEY="$2"; shift 2 ;;
        --out-dir)      [ "$#" -ge 2 ] || usage; OUT_DIR="$2"; shift 2 ;;
        --ssh-port)     [ "$#" -ge 2 ] || usage; SSH_PORT="$2"; shift 2 ;;
        --boot-timeout) [ "$#" -ge 2 ] || usage; BOOT_TIMEOUT="$2"; shift 2 ;;
        *) usage ;;
    esac
done

if [ -z "$VARIANT" ] || [ -z "$IMAGE" ] || [ -z "$TAG" ] || [ -z "$SSH_KEY" ] || [ -z "$OUT_DIR" ]; then
    usage
fi
case "$VARIANT" in ce|plus) ;; *) usage ;; esac
mkdir -p "$OUT_DIR"

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

# done_with STATUS — record the outcome and exit 0 (best-effort contract).
done_with() {
    printf '%s\n' "$1" > "$OUT_DIR/status"
    exit 0
}

# Plus identity gate — never boot Plus without the full license-keyed identity.
if [ "$VARIANT" = "plus" ]; then
    _mac_count=$(printf '%s\n' "${SMOKE_VM_MAC:-}" | grep -c '[^[:space:]]' || true)
    if [ "${_mac_count:-0}" -ne 8 ] || [ -z "${SMOKE_VM_SMBIOS_UUID:-}" ]; then
        echo "box-facts: Plus identity absent/malformed — status unavailable" >&2
        done_with unavailable
    fi
fi

# Pull the image and locate its qcow2.
if ! oras pull "${IMAGE}:${TAG}" --output "$WORK" >&2; then
    echo "box-facts: oras pull ${IMAGE}:${TAG} failed — status unavailable" >&2
    done_with unavailable
fi
BASE_IMG=$(find "$WORK" -maxdepth 1 -name '*.qcow2' | head -1)
if [ -z "$BASE_IMG" ]; then
    echo "box-facts: no qcow2 in ${IMAGE}:${TAG} — status unavailable" >&2
    done_with unavailable
fi

# Boot a throwaway overlay (boot_vm.sh never writes the base).
echo "box-facts: booting ${VARIANT} ${TAG} (ssh 127.0.0.1:${SSH_PORT})" >&2
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
    echo "box-facts: guest SSH not up within ${BOOT_TIMEOUT}s — status unavailable" >&2
    done_with unavailable
fi

# The three facts. The -c check refreshes pkg metadata over the network — give
# it a bounded window of its own (a wedged pkg must not hang the run).
_ok=1
guest_ssh 'cat /etc/version' > "$OUT_DIR/etc-version" 2>/dev/null || _ok=0
guest_ssh '/usr/local/sbin/pfSense-repoc -p' > "$OUT_DIR/repoc.txt" 2>/dev/null || _ok=0
guest_ssh 'timeout 240 /usr/local/sbin/pfSense-upgrade -c 2>&1 || true' \
    > "$OUT_DIR/upgrade-check.txt" 2>/dev/null || _ok=0

# Best-effort clean shutdown; the trap reaps whatever is left (capped).
guest_ssh '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while kill -0 "$BOOT_PID" 2>/dev/null && [ "$_elapsed" -lt "$SHUTDOWN_WAIT" ]; do
    sleep "$POLL"; _elapsed=$((_elapsed + POLL))
done

if [ "$_ok" -eq 1 ]; then
    done_with ok
fi
echo "box-facts: one or more guest commands failed — status unavailable" >&2
done_with unavailable
