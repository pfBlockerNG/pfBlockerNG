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
#   PFB_LOCK_RETRIES   upgrade-check attempts while pfSense holds the upgrade
#                      lock (default 8; issue #1844)
#
# status file: "ok" = the REQUIRED facts (etc-version, repoc) were gathered;
# the upgrade-check fact is optional (the planner's second source) and its
# absence leaves an empty file without failing the boot. "unavailable" = a
# required fact or an infrastructure failure (pull, boot, ssh, Plus identity) —
# the planner must then treat the boot as absent.
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

# guest_sh CMD — run CMD under /bin/sh on the guest regardless of the login
# shell: stock pfSense root uses tcsh, which misparses 2>&1 inside a remote
# command string (docs/misc/local-smoke-debian.md); our images use sh, but the
# wrap costs nothing. CMD must not contain single quotes.
guest_sh() {
    guest_ssh "/bin/sh -c '$1'"
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

# The three facts. repoc and the -c check both refresh metadata over the
# network — each runs under its own guest-side hard cap (a wedged pkg/fetch
# must not hang the run). Each failure is named in the log; only the REQUIRED
# facts (etc-version, repoc) decide the boot's status, because the planner
# treats the -c check as an optional second source (issue #1848).
_ok=1

# fact_get LABEL FILE CMD [optional] — run CMD on the guest, write FILE, and
# name the fact in the log when it fails. Anything but a trailing "optional"
# marks the boot unavailable on failure.
fact_get() {
    _fg_label=$1; _fg_file=$2; _fg_cmd=$3; _fg_opt=${4:-}
    guest_sh "$_fg_cmd" > "$_fg_file" 2>/dev/null
    _fg_rc=$?
    [ "$_fg_rc" -eq 0 ] && return 0
    if [ "$_fg_opt" = "optional" ]; then
        echo "box-facts: ${_fg_label} fact failed (optional — boot still usable): ${_fg_cmd} [status ${_fg_rc}]" >&2
        true > "$_fg_file"
        return 1
    fi
    echo "box-facts: ${_fg_label} fact failed — status unavailable: ${_fg_cmd} [status ${_fg_rc}]" >&2
    _ok=0
    return 1
}

fact_get etc-version "$OUT_DIR/etc-version" 'cat /etc/version' || true
fact_get repoc "$OUT_DIR/repoc.txt" 'timeout 120 /usr/local/sbin/pfSense-repoc -p' || true

# The upgrade check is the planner's OPTIONAL second source: rc 0 (current) and
# rc 2 (update available) are healthy; anything else — timeout(1)'s 124, or the
# refusal pfSense returns while another upgrade instance holds the lock — is
# retried, then recorded as absent (an empty file never reads as "up to date").
# Its loss never voids the boot: the branch list is what the reconcile turns on.
_uc_raw="$WORK/upgrade-check.raw"
# Guest-side predicate: pfSense-upgrade -c returns 0 (current) or 2 (update
# available); anything else — including a real check error (1) and timeout's
# 124 — must not become the planner's second source.
_uc_i=0
_uc_ok=0
while true; do
    guest_sh 'timeout 240 /usr/local/sbin/pfSense-upgrade -c 2>&1' > "$_uc_raw" 2>/dev/null
    _uc_rc=$?
    # 0 = current, 2 = update available; anything else (a real check error, or
    # timeout(1)'s 124) must never become the planner's second source.
    case "$_uc_rc" in
        0|2) _uc_ok=1; break ;;
    esac
    grep -q 'Another instance is already running' "$_uc_raw" 2>/dev/null || break
    _uc_i=$((_uc_i + 1))
    [ "$_uc_i" -lt "${PFB_LOCK_RETRIES:-8}" ] || break
    echo "box-facts: upgrade check locked (attempt ${_uc_i}); retrying" >&2
    sleep "$POLL"
done
if [ "$_uc_ok" -eq 1 ]; then
    cat "$_uc_raw" > "$OUT_DIR/upgrade-check.txt"
else
    echo "box-facts: upgrade-check fact failed (optional — boot still usable): pfSense-upgrade -c [status ${_uc_rc:-?}]" >&2
    true > "$OUT_DIR/upgrade-check.txt"
fi

# Best-effort clean shutdown; the trap reaps whatever is left (capped).
guest_sh '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while kill -0 "$BOOT_PID" 2>/dev/null && [ "$_elapsed" -lt "$SHUTDOWN_WAIT" ]; do
    sleep "$POLL"; _elapsed=$((_elapsed + POLL))
done

if [ "$_ok" -eq 1 ]; then
    done_with ok
fi
echo "box-facts: required facts incomplete — status unavailable" >&2
done_with unavailable
