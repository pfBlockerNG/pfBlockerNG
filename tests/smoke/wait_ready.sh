#!/bin/sh
# wait_ready.sh — poll until the booted pfSense guest is actually usable, with
# bounded backoff and a hard timeout. No fixed sleeps for "boot done".
#
# Usage:
#   tests/smoke/wait_ready.sh <ssh-key> [host] [port] [timeout-seconds] \
#       [vm-pid] [web-port]
#
# Defaults: host 127.0.0.1, port 2222, timeout 600s, vm-pid (none),
# web-port (none → SSH-only readiness).
#
# On success: prints "boot-to-ready: <N> seconds", then exits 0. On timeout:
# prints the elapsed time and exits 1.
#
# If <vm-pid> is given, the QEMU process is watched: if it dies before the box
# comes up (e.g. the image failed to open, KVM aborted), we exit 1 IMMEDIATELY
# rather than burning the whole timeout polling a guest that will never answer.
#
# Readiness requires BOTH:
#   - a working SSH command (`true`) over the host-forwarded port with the baked
#     test key — sshd is up and the WAN pass rule lets the runner in; and
#   - if <web-port> is given, the webConfigurator answering an HTTP request
#     (nginx + PHP are fully started, not just sshd) — so callers that install
#     packages / restart nginx don't race a still-starting web stack.
# Backoff grows 2s..15s.
#
# POSIX sh; quoted expansions; absolute binary paths.

set -eu

SSH=/usr/bin/ssh
CURL=/usr/bin/curl

usage() {
    echo "Usage: $0 <ssh-key> [host] [port] [timeout-seconds] [vm-pid] [web-port]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage

SSH_KEY="$1"
HOST="${2:-127.0.0.1}"
PORT="${3:-2222}"
TIMEOUT="${4:-600}"
VM_PID="${5:-}"
WEB_PORT="${6:-}"

if [ ! -x "$SSH" ]; then
    SSH="$(command -v ssh || true)"
fi
if [ -z "$SSH" ] || [ ! -x "$SSH" ]; then
    echo "wait_ready: ssh not found" >&2
    exit 1
fi
if [ ! -f "$SSH_KEY" ]; then
    echo "wait_ready: ssh key not found: $SSH_KEY" >&2
    exit 1
fi
if [ -n "$WEB_PORT" ]; then
    [ -x "$CURL" ] || CURL="$(command -v curl || true)"
    if [ -z "$CURL" ] || [ ! -x "$CURL" ]; then
        echo "wait_ready: curl not found (needed for web-readiness)" >&2
        exit 1
    fi
fi

# Throwaway VM: skip host-key verification, but keep the private key private.
SSH_OPTS="-i ${SSH_KEY} -p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR"

START="$(date +%s)"
BACKOFF=2
ATTEMPT=0

while :; do
    ATTEMPT=$((ATTEMPT + 1))
    NOW="$(date +%s)"
    ELAPSED=$((NOW - START))

    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "wait_ready: TIMEOUT after ${ELAPSED}s (${ATTEMPT} attempts)" >&2
        exit 1
    fi

    # If we're watching a VM PID and it has exited, the boot died — don't keep
    # polling for the full timeout against a guest that will never come up.
    if [ -n "$VM_PID" ] && ! kill -0 "$VM_PID" 2>/dev/null; then
        echo "wait_ready: VM process ${VM_PID} exited after ${ELAPSED}s — boot failed, not waiting" >&2
        exit 1
    fi

    SSH_READY=0
    # shellcheck disable=SC2086
    if "$SSH" $SSH_OPTS "root@${HOST}" true 2>/dev/null; then
        SSH_READY=1
    fi

    # Web readiness is optional; when no web port is given it's a no-op so the
    # gate reduces to SSH-only.
    WEB_READY=1
    if [ -n "$WEB_PORT" ]; then
        WEB_READY=0
        if "$CURL" -fsSL --max-time 5 -o /dev/null "http://${HOST}:${WEB_PORT}/" 2>/dev/null; then
            WEB_READY=1
        fi
    fi

    if [ "$SSH_READY" -eq 1 ] && [ "$WEB_READY" -eq 1 ]; then
        NOW="$(date +%s)"
        ELAPSED=$((NOW - START))
        echo "boot-to-ready: ${ELAPSED} seconds"
        exit 0
    fi

    PENDING=""
    [ "$SSH_READY" -eq 1 ] || PENDING="${PENDING}ssh "
    [ "$WEB_READY" -eq 1 ] || PENDING="${PENDING}web "
    echo "wait_ready: attempt ${ATTEMPT} waiting for: ${PENDING}(${ELAPSED}s elapsed), retry in ${BACKOFF}s" >&2
    sleep "$BACKOFF"

    BACKOFF=$((BACKOFF * 2))
    if [ "$BACKOFF" -gt 15 ]; then
        BACKOFF=15
    fi
done
