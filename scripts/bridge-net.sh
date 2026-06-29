#!/bin/sh
#shellcheck shell=sh
# bridge-net.sh — per-box bridge + dnsmasq setup for SMOKE_NET_MODE=bridge (ADR-50 P2).
#
# Runs on the Linux host (LXC box or CI runner), once per box, before any test leg.
# Creates two host bridges (br-wan 192.168.89.2/24 + br-mgmt 192.168.43.2/24),
# per-lane tap devices attached to them, and a dnsmasq DHCP-only daemon with static
# MGMT leases so the pfSense + civm MGMT NICs get deterministic IPs.
#
# Subcommands:
#   up    create bridges, taps, start dnsmasq; emit KEY=value on stdout.
#   down  stop dnsmasq, delete taps + bridges (safe when nothing exists).
#
# Env read:
#   SMOKE_LANE              lane index (default 0); tap names are tap-{wan,mgmt,cli}<lane>
#   SMOKE_PFSENSE_MGMT_IP   pfSense MGMT static-lease IP (default 192.168.43.15) — matches P3
#   SMOKE_CLIENT_MGMT_IP    civm MGMT static-lease IP (default 192.168.43.16) — matches P3
#   SMOKE_VM_MAC            newline-separated NIC MACs; line 2 = net1/MGMT MAC (mirrors
#                           boot_vm.sh's nth_mac 1 = sed -n '2p'); default CE source-VM list
#   SMOKE_CLIENT_MGMT_MAC   civm MGMT MAC (default BC:24:11:29:A4:1B)
#
# Overridable binaries (shellspec injects stubs via these):
#   SMOKE_IP_BIN       ip command (default: /usr/sbin/ip, then command -v fallback)
#   SMOKE_DNSMASQ_BIN  dnsmasq command (default: /usr/sbin/dnsmasq, then command -v fallback)
#
# Overridable runtime dir (shellspec points at a tmp dir via this):
#   SMOKE_BRIDGE_RUN_DIR  runtime dir for PID file (default: /run/pfb-smoke)
#
# Output of 'up' (progress + diagnostics go to stderr):
#   SMOKE_WAN_TAP=tap-wan<lane>
#   SMOKE_MGMT_TAP=tap-mgmt<lane>
#   SMOKE_CLIENT_MGMT_TAP=tap-cli<lane>
#   SMOKE_PFSENSE_MGMT_IP=192.168.43.15
#   SMOKE_CLIENT_MGMT_IP=192.168.43.16
#
# ponytail: single-bridge-pair-per-box ceiling — bridges (br-wan / br-mgmt) and dnsmasq
# are singletons; only tap NAMES are per-lane. Multi-lane would need per-lane subnets;
# deferred until P5's A/B justifies bridge mode at all.

set -eu

LANE="${SMOKE_LANE:-0}"

# ponytail: absolute default per CLAUDE.md privileged-binary rule; command -v fallback
# mirrors boot_vm.sh so the path is robust on varied installs; SMOKE_*_BIN stub override
# is honoured because an executable stub path is taken as-is (skips the fallback).
IP_BIN="${SMOKE_IP_BIN:-/usr/sbin/ip}"
DNSMASQ_BIN="${SMOKE_DNSMASQ_BIN:-/usr/sbin/dnsmasq}"
if [ ! -x "$IP_BIN" ]; then IP_BIN="$(command -v ip || true)"; fi
if [ ! -x "$DNSMASQ_BIN" ]; then DNSMASQ_BIN="$(command -v dnsmasq || true)"; fi
if [ -z "$IP_BIN" ] || [ ! -x "$IP_BIN" ]; then
    printf 'bridge-net: ip binary not found (set SMOKE_IP_BIN or install iproute2)\n' >&2
    exit 1
fi
if [ -z "$DNSMASQ_BIN" ] || [ ! -x "$DNSMASQ_BIN" ]; then
    printf 'bridge-net: dnsmasq binary not found (set SMOKE_DNSMASQ_BIN or install dnsmasq)\n' >&2
    exit 1
fi

# Bridge names + addresses (singletons — not per-lane; see ceiling note above).
WAN_BRIDGE="br-wan"
WAN_ADDR="192.168.89.2/24"
MGMT_BRIDGE="br-mgmt"
MGMT_ADDR="192.168.43.2/24"

# DHCP ranges (dnsmasq auto-associates each range with the interface by subnet match).
WAN_RANGE="192.168.89.50,192.168.89.150,255.255.255.0"
MGMT_RANGE="192.168.43.50,192.168.43.150,255.255.255.0"

# Static-lease IPs — MUST match P3 conftest defaults (PFSENSE_MGMT_IP / CLIENT_MGMT_IP).
PFSENSE_MGMT_IP="${SMOKE_PFSENSE_MGMT_IP:-192.168.43.15}"
CLIENT_MGMT_IP="${SMOKE_CLIENT_MGMT_IP:-192.168.43.16}"

# Per-lane tap names (Linux IFNAMSIZ=15; tap-wan0..tap-cli9 are 9 chars — all fit).
WAN_TAP="tap-wan${LANE}"
MGMT_TAP="tap-mgmt${LANE}"
CLI_TAP="tap-cli${LANE}"

# Lane-scoped dnsmasq PID file so 'down' can stop the right instance.
# Root-owned runtime dir (not /tmp) prevents symlink/pre-create attacks on the PID file.
RUNDIR="${SMOKE_BRIDGE_RUN_DIR:-/run/pfb-smoke}"
PIDFILE="${RUNDIR}/dnsmasq-${LANE}.pid"

# MGMT MACs for dnsmasq static leases.
# pfSense net1/MGMT MAC: line 2 of SMOKE_VM_MAC (mirrors boot_vm.sh's nth_mac 1
# = printf '%s\n' "$VM_MAC" | sed -n '2p'). Default = CE source-VM net1 MAC.
# civm MGMT MAC: SMOKE_CLIENT_MGMT_MAC, mirrors boot_vm.sh's CLIENT_MGMT_MAC.
if [ -n "${SMOKE_VM_MAC:-}" ]; then
    _pfsense_mgmt_mac="$(printf '%s\n' "${SMOKE_VM_MAC}" | sed -n '2p')"
else
    _pfsense_mgmt_mac="BC:24:11:80:42:35"
fi
_client_mgmt_mac="${SMOKE_CLIENT_MGMT_MAC:-BC:24:11:29:A4:1B}"

# Validate env-derived inputs — values flow into shell args; reject metacharacters fail-closed.
case "$LANE" in
    ''|*[!0-9]*)
        printf 'bridge-net: SMOKE_LANE must be a non-negative integer (got: %s)\n' "${LANE}" >&2
        exit 2 ;;
esac
case "$PFSENSE_MGMT_IP" in
    *[!0-9.]*)
        printf 'bridge-net: SMOKE_PFSENSE_MGMT_IP contains invalid characters (got: %s)\n' "${PFSENSE_MGMT_IP}" >&2
        exit 2 ;;
esac
case "$CLIENT_MGMT_IP" in
    *[!0-9.]*)
        printf 'bridge-net: SMOKE_CLIENT_MGMT_IP contains invalid characters (got: %s)\n' "${CLIENT_MGMT_IP}" >&2
        exit 2 ;;
esac
case "$_pfsense_mgmt_mac" in
    ''|*[!0-9A-Fa-f:]*)
        printf 'bridge-net: pfSense MGMT MAC contains invalid characters (got: %s)\n' "${_pfsense_mgmt_mac}" >&2
        exit 2 ;;
esac
case "$_client_mgmt_mac" in
    ''|*[!0-9A-Fa-f:]*)
        printf 'bridge-net: client MGMT MAC contains invalid characters (got: %s)\n' "${_client_mgmt_mac}" >&2
        exit 2 ;;
esac

_do_down() {
    # Stop dnsmasq by PID file; silent when absent or already gone.
    if [ -f "${PIDFILE}" ]; then
        _pid="$(cat "${PIDFILE}" 2>/dev/null)" || _pid=""
        if [ -n "${_pid}" ]; then
            kill "${_pid}" 2>/dev/null || true
        fi
        rm -f "${PIDFILE}"
    fi
    # Delete taps first (they are attached to bridges), then the bridges.
    # Each deletion is guarded: a missing device is not an error.
    "${IP_BIN}" link del "${WAN_TAP}"    2>/dev/null || true
    "${IP_BIN}" link del "${MGMT_TAP}"   2>/dev/null || true
    "${IP_BIN}" link del "${CLI_TAP}"    2>/dev/null || true
    "${IP_BIN}" link del "${WAN_BRIDGE}" 2>/dev/null || true
    "${IP_BIN}" link del "${MGMT_BRIDGE}" 2>/dev/null || true
}

_do_up() {
    # ponytail: idempotent recreate IS the teardown; the select-box lease trap is
    # intentionally untouched (CI runners are ephemeral; local boxes have one lane).
    printf 'bridge-net: teardown any stale config (lane=%s)\n' "${LANE}" >&2
    _do_down
    # Create the runtime dir (root-owned 700) before starting dnsmasq.
    mkdir -p "${RUNDIR}"
    chmod 700 "${RUNDIR}"

    printf 'bridge-net: creating bridges and taps (lane=%s)\n' "${LANE}" >&2

    # WAN bridge.
    "${IP_BIN}" link add "${WAN_BRIDGE}" type bridge
    "${IP_BIN}" addr add "${WAN_ADDR}" dev "${WAN_BRIDGE}"
    "${IP_BIN}" link set "${WAN_BRIDGE}" up

    # MGMT bridge (separate subnet from WAN — two NICs on one subnet break pfSense
    # routing/anti-spoof; proven in the ADR §7.2 derisk).
    "${IP_BIN}" link add "${MGMT_BRIDGE}" type bridge
    "${IP_BIN}" addr add "${MGMT_ADDR}" dev "${MGMT_BRIDGE}"
    "${IP_BIN}" link set "${MGMT_BRIDGE}" up

    # WAN tap → br-wan.
    "${IP_BIN}" tuntap add "${WAN_TAP}" mode tap
    "${IP_BIN}" link set "${WAN_TAP}" master "${WAN_BRIDGE}"
    "${IP_BIN}" link set "${WAN_TAP}" up

    # MGMT tap → br-mgmt (pfSense net1).
    "${IP_BIN}" tuntap add "${MGMT_TAP}" mode tap
    "${IP_BIN}" link set "${MGMT_TAP}" master "${MGMT_BRIDGE}"
    "${IP_BIN}" link set "${MGMT_TAP}" up

    # Client tap → br-mgmt (civm MGMT NIC; same subnet, separate MAC/static-lease).
    "${IP_BIN}" tuntap add "${CLI_TAP}" mode tap
    "${IP_BIN}" link set "${CLI_TAP}" master "${MGMT_BRIDGE}"
    "${IP_BIN}" link set "${CLI_TAP}" up

    printf 'bridge-net: starting dnsmasq DHCP on %s %s (lane=%s)\n' \
        "${WAN_BRIDGE}" "${MGMT_BRIDGE}" "${LANE}" >&2

    # dnsmasq: DHCP-only (port=0), bound to the two bridges.
    # §7.3: dnsmasq auto-announces option 3 (gateway) + option 6 (DNS) = its own
    # per-subnet address, so the WAN guest gets DNS→192.168.89.2 (the stub DNS)
    # and gw→192.168.89.2. Rely on that — do NOT fight it with explicit options.
    "${DNSMASQ_BIN}" \
        --port=0 \
        --bind-interfaces \
        --except-interface=lo \
        --interface="${WAN_BRIDGE}" \
        --interface="${MGMT_BRIDGE}" \
        --dhcp-range="${WAN_RANGE}" \
        --dhcp-range="${MGMT_RANGE}" \
        --dhcp-host="${_pfsense_mgmt_mac},${PFSENSE_MGMT_IP}" \
        --dhcp-host="${_client_mgmt_mac},${CLIENT_MGMT_IP}" \
        --pid-file="${PIDFILE}"

    printf 'bridge-net: up (lane=%s); emitting env\n' "${LANE}" >&2

    # Emit KEY=value on stdout; caller parses with a strict allowlist (no eval).
    printf 'SMOKE_WAN_TAP=%s\n'         "${WAN_TAP}"
    printf 'SMOKE_MGMT_TAP=%s\n'        "${MGMT_TAP}"
    printf 'SMOKE_CLIENT_MGMT_TAP=%s\n' "${CLI_TAP}"
    printf 'SMOKE_PFSENSE_MGMT_IP=%s\n' "${PFSENSE_MGMT_IP}"
    printf 'SMOKE_CLIENT_MGMT_IP=%s\n'  "${CLIENT_MGMT_IP}"
}

case "${1:-}" in
    up)   _do_up ;;
    down) _do_down ;;
    *)
        printf 'Usage: %s up|down\n' "$0" >&2
        printf '  up    create bridges, taps, dnsmasq; emit eval-able env vars on stdout\n' >&2
        printf '  down  stop dnsmasq, delete taps and bridges\n' >&2
        exit 2
        ;;
esac
