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
# Readiness, by role (a STAGGERED liveness chain — see the probe loop):
#   - <web-port> GIVEN (pfSense): the liveness floor is a real `ssh true` (sshd comes up
#     before nginx/PHP); readiness is the webConfigurator answering a FULL HTTP request
#     within a generous total cap. The SSH floor makes "alive but web warming" visible, so
#     a slow cold box is never misread as dead.
#   - <web-port> OMITTED (civm): a working SSH command (`true`) over the host-forwarded
#     management NIC with the baked test key.
#
# Poll cadence: no VM answers in under ~8s, so wait out an initial grace, then poll every
# 1s while readiness is plausible (< 75s elapsed) and every 5s after that, up to the hard
# timeout (~3 min). The SSH probe's ConnectTimeout is 1s (a real ssh handshake that slow is
# dead); the web probe is bounded by the generous TOTAL cap (WEB_MAX_TIME), NOT a 1s cap —
# over SLIRP the TCP connect is a false-green (the hostfwd listener accepts before the guest
# is up), so a connect timeout means nothing and only the full HTTP response is a real signal.
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

# Generous TOTAL cap for the web probe (NOT a 1s cap). A cold, CPU-starved nested-KVM
# webConfigurator accepts the connection instantly but can take several seconds to render
# the first response; a 1s total killed every poll while the box was alive. Over SLIRP the
# connect is a false-green (see the probe below), so this total time is the only meaningful
# bound. Env-overridable for an especially slow box.
WEB_MAX_TIME="${SMOKE_WEB_MAX_TIME:-15}"

START="$(date +%s)"
ATTEMPT=0
# Whether the SSH liveness floor has been observed (pfSense/web role only); logged once.
WEB_SSH_SEEN=""

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
        # pfSense readiness is a STAGGERED liveness chain so a slow-but-alive box is never
        # misread as dead. (The bug the old web-only gate hit on cold nested-KVM CI: its 1s
        # TOTAL curl cap killed every poll because the webConfigurator ACCEPTS instantly but
        # takes >1s to render — while SSH was fine the whole time but unexercised, so the box
        # read as dead.)
        #
        # Why no TCP/ping rung, and why connect-timeout is meaningless here: over QEMU SLIRP
        # the hostfwd listener ACCEPTS the host-side connect (and answers a gateway ping)
        # BEFORE the guest is up — both are false-green at 0s, and curl's connect always
        # "succeeds" at the SLIRP layer so --connect-timeout never fires. The only signal that
        # actually separates alive-and-ready from dead is a FULL HTTP response: a down web is
        # RST fast by SLIRP (poll fails quick), a warming web answers within seconds. So the
        # bound that matters is the generous total ${WEB_MAX_TIME}s cap, never a 1s one.

        # Liveness floor: a real `ssh true` (NOT a TCP connect — that is the false-green
        # above). sshd comes up before nginx/PHP; log the crossing once so a CI log makes
        # "alive, web warming" unmistakable versus a genuinely dead boot.
        # shellcheck disable=SC2086
        if [ -z "$WEB_SSH_SEEN" ] && \
           "$SSH" -i "$SSH_KEY" $SSH_OPTS "root@${HOST}" true 2>/dev/null; then
            WEB_SSH_SEEN=1
            echo "wait_ready: [${ELAPSED}s] ssh alive — system up, webConfigurator warming" >&2
        fi

        # Readiness: a FULL webConfigurator response, bounded only by the generous total cap.
        if "$CURL" -fsSL --max-time "$WEB_MAX_TIME" -o /dev/null "http://${HOST}:${WEB_PORT}/" 2>/dev/null; then
            echo "boot-to-ready: ${ELAPSED} seconds"
            exit 0
        fi
        if [ -n "$WEB_SSH_SEEN" ]; then
            PENDING="web (ssh alive — warming)"
        else
            PENDING="web (ssh not yet up)"
        fi
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
