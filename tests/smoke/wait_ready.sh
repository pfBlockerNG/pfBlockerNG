#!/bin/sh
# wait_ready.sh — poll until the booted pfSense guest is actually usable, with
# bounded backoff and a hard timeout. No fixed sleeps for "boot done".
#
# Usage:
#   tests/smoke/wait_ready.sh <ssh-key> [host] [port] [timeout-seconds] \
#       [vm-pid] [web-port]
#
# Defaults: host 127.0.0.1, port 2222, timeout 60s, vm-pid (none),
# web-port (none → SSH-only readiness).
#
# On success: prints "boot-to-ready: <N> seconds", then exits 0. On timeout:
# prints the elapsed time and exits 1.
#
# If <vm-pid> is given, the QEMU process is watched: if it dies before the box
# comes up (e.g. the image failed to open, KVM aborted), we exit 1 IMMEDIATELY
# rather than burning the whole timeout polling a guest that will never answer.
#
# Readiness, by role:
#   - <web-port> GIVEN (pfSense): the webConfigurator answering an HTTP request.
#     nginx + PHP come up AFTER sshd, so a live admin panel implies SSH is already
#     usable — the web server is the meaningful "appliance ready" signal, gated on
#     alone (no separate SSH wait).
#   - <web-port> OMITTED (civm): a working SSH command (`true`) over the
#     host-forwarded management NIC with the baked test key.
#
# Poll cadence: no VM answers in under ~8s, so wait out an initial grace, then
# poll every 1s while readiness is imminent (< 30s elapsed) and every 5s after
# that, up to the hard timeout (~1 min). A local-loopback connect that cannot
# complete in 1s is dead, so the per-probe connect timeout is 1s.
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
TIMEOUT="${4:-60}"
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
SSH_OPTS="-i ${SSH_KEY} -p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 -o BatchMode=yes -o LogLevel=ERROR"

# Neither VM becomes reachable in under ~8s, so probing before then is pure waste
# (the old exponential backoff's early probes). Wait out this grace — still watching
# the qemu PID so a dead boot fails immediately — then start polling.
INITIAL_GRACE=8

START="$(date +%s)"
ATTEMPT=0

while :; do
    NOW="$(date +%s)"
    ELAPSED=$((NOW - START))

    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "wait_ready: TIMEOUT after ${ELAPSED}s (${ATTEMPT} attempts)" >&2
        exit 1
    fi

    # A dead qemu (bad image / KVM abort) will never answer — fail fast, even while
    # still inside the initial grace.
    if [ -n "$VM_PID" ] && ! kill -0 "$VM_PID" 2>/dev/null; then
        echo "wait_ready: VM process ${VM_PID} exited after ${ELAPSED}s — boot failed, not waiting" >&2
        exit 1
    fi

    if [ "$ELAPSED" -lt "$INITIAL_GRACE" ]; then
        sleep 1
        continue
    fi

    ATTEMPT=$((ATTEMPT + 1))

    if [ -n "$WEB_PORT" ]; then
        # pfSense: readiness = the webConfigurator answering. nginx + PHP come up
        # AFTER sshd, so a live admin panel implies SSH is already usable — gate on
        # the web server alone (the meaningful "appliance ready" signal).
        if "$CURL" -fsSL --max-time 1 -o /dev/null "http://${HOST}:${WEB_PORT}/" 2>/dev/null; then
            echo "boot-to-ready: ${ELAPSED} seconds"
            exit 0
        fi
        PENDING=web
    else
        # civm: no web server — gate on SSH over the host-forwarded management NIC.
        # The probe is a bare `true` ON PURPOSE: a remote command is parsed by the
        # guest login shell; `true` has no metacharacters so it stays safe even under
        # tcsh (pfSense). A richer command must be wrapped in `/bin/sh -c '<blob>'`
        # (see scripts/install-pkg.sh / tests/smoke/roundtrip.sh).
        # shellcheck disable=SC2086
        if "$SSH" $SSH_OPTS "root@${HOST}" true 2>/dev/null; then
            echo "boot-to-ready: ${ELAPSED} seconds"
            exit 0
        fi
        PENDING=ssh
    fi

    # Tight 1s cadence while readiness is imminent; relax to 5s past the 30s mark.
    if [ "$ELAPSED" -lt 30 ]; then
        INTERVAL=1
    else
        INTERVAL=5
    fi
    echo "wait_ready: attempt ${ATTEMPT} waiting for: ${PENDING} (${ELAPSED}s elapsed), retry in ${INTERVAL}s" >&2
    sleep "$INTERVAL"
done
