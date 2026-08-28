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
# poll every 1s while readiness is plausible (< 75s elapsed) and every 5s after
# that, up to the hard timeout (~3 min). A local-loopback connect that cannot
# complete in 1s is dead, so the per-probe CONNECT timeout is 1s — but a live
# webConfigurator's first response can take a couple of seconds to render on a cold,
# nested-KVM guest (where the bare-metal box answers in <1s), so the web probe
# allows up to 2s total (--connect-timeout 1 --max-time 2). Capping total time at
# 1s instead starves a slow-but-alive server and times out the whole gate on CI.
#
# The windows fit MEASURED boots, not the rule of thumb: pfSense reaches
# web-ready in ~15s on a fast bare-metal host but ~55-60s on a nested-KVM /
# low-power box (the boot is single-threaded + CPU-bound; see the ADR-04 notes).
# The 1s window spans both; 180s leaves headroom for parallel-lane CPU contention.
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
TIMEOUT="${4:-180}"
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
# The key path is passed quoted at the callsite (it may contain spaces); only the
# space-free static options live in this word-split string.
SSH_OPTS="-p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 -o BatchMode=yes -o LogLevel=ERROR"

# Neither VM becomes reachable in under ~8s, so probing before then is pure waste
# (the old exponential backoff's early probes). Wait out this grace — still watching
# the qemu PID so a dead boot fails immediately — then start polling.
INITIAL_GRACE=8

START="$(date +%s)"
ATTEMPT=0
# SSH liveness floor observed (web/pfSense role only); logged once.
WEB_SSH_SEEN=""

while true; do
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
        # Staggered liveness chain: an SSH FLOOR (sshd is up before nginx/PHP) then the
        # web 200 (readiness). Logging the floor once means a slow-but-alive cold box reads
        # as "alive — web warming" instead of looking dead while the webConfigurator renders.
        # (No TCP/ping rung: over SLIRP both are false-green before the guest is up, so the
        # floor must be a real `ssh true`, not a connect.)
        # shellcheck disable=SC2086
        if [ -z "$WEB_SSH_SEEN" ] && \
           "$SSH" -i "$SSH_KEY" $SSH_OPTS "root@${HOST}" true 2>/dev/null; then
            WEB_SSH_SEEN=1
            echo "wait_ready: [${ELAPSED}s] ssh alive — system up, webConfigurator warming" >&2
        fi
        # Readiness = the webConfigurator answering. A live admin panel implies SSH is up.
        if "$CURL" -fsSL --connect-timeout 1 --max-time 2 -o /dev/null "http://${HOST}:${WEB_PORT}/" 2>/dev/null; then
            echo "boot-to-ready: ${ELAPSED} seconds"
            exit 0
        fi
        if [ -n "$WEB_SSH_SEEN" ]; then PENDING="web (ssh alive — warming)"; else PENDING="web (ssh not yet up)"; fi
    else
        # civm: no web server — gate on SSH over the host-forwarded management NIC.
        # The probe is a bare `true` ON PURPOSE: a remote command is parsed by the
        # guest login shell; `true` has no metacharacters so it stays safe even under
        # tcsh (pfSense). A richer command must be wrapped in `/bin/sh -c '<blob>'`
        # (see scripts/install-pkg.sh / tests/smoke/roundtrip.sh).
        # shellcheck disable=SC2086
        if "$SSH" -i "$SSH_KEY" $SSH_OPTS "root@${HOST}" true 2>/dev/null; then
            echo "boot-to-ready: ${ELAPSED} seconds"
            exit 0
        fi
        PENDING=ssh
    fi

    # Tight 1s cadence while readiness is plausible (covers a ~15s fast boot and a
    # ~55-60s slow/contended one); relax to 5s past the 75s mark.
    if [ "$ELAPSED" -lt 75 ]; then
        INTERVAL=1
    else
        INTERVAL=5
    fi
    echo "wait_ready: attempt ${ATTEMPT} waiting for: ${PENDING} (${ELAPSED}s elapsed), retry in ${INTERVAL}s" >&2
    sleep "$INTERVAL"
done
