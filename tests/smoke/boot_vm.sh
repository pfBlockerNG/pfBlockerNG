#!/bin/sh
# boot_vm.sh — boot a hand-built pfSense CE qcow2 headless under QEMU
# for the ADR-04 live-VM smoke suite.
#
# Usage:
#   tests/smoke/boot_vm.sh <base-image.qcow2> [overlay.qcow2]
#
# Boots the image headless with a hardware accelerator (auto-detected, see
# below) and a QEMU user-net (SLIRP) host-forward map so the runner can reach
# the guest. The forwarded host ports default to the historical fixed values
# but are overridable via env so multiple VMs can run in PARALLEL on one host:
#   host ${SMOKE_SSH_PORT:-2222}/tcp -> guest 22   (SSH)
#   host ${SMOKE_WEB_PORT:-8080}/tcp -> guest 80   (WebUI, HTTP)
#   host ${SMOKE_DNS_PORT:-5353}/tcp -> guest 53   (DNS, TCP)
#   host ${SMOKE_DNS_PORT:-5353}/udp -> guest 53   (DNS, UDP)
# The guest reaches the runner at the SLIRP host alias 10.0.2.2.
#
# Accelerator (cross-platform): SMOKE_QEMU_ACCEL overrides; otherwise it is
# auto-detected per host — kvm (Linux + /dev/kvm), hvf (macOS, x86 guest only
# on an Intel Mac), whpx (Windows), else tcg. pfSense ships amd64 ONLY, so an
# arm64 host (Apple Silicon) has no hardware virt for the x86 guest and falls
# back to tcg = full emulation: correct but slow (raise SMOKE_BOOT_TIMEOUT).
# The CPU model pairs with the accel (-cpu host needs kvm/hvf; tcg/whpx use max);
# SMOKE_QEMU_CPU overrides.
#
# Hardware MIRRORS the source Proxmox VM (qm showcmd 103 --pretty) so the
# published qcow2 boots without pfSense re-detecting hardware and dropping
# to the interface-reassignment console prompt:
#   - single virtio-net-pci NIC, MAC pinned to BC:24:11:37:9C:AC
#     (the source VM's MAC; a MAC is not sensitive, so it is hardcoded)
#   - VirtIO-SCSI disk (guest sees da0)
#   - machine type pc (i440fx; Proxmox pc+pve0), 2 vCPU, 4 GB RAM
#
# The base image is NEVER mutated: an ephemeral copy-on-write overlay is
# created over it and the guest writes only to the overlay. The overlay is
# removed on a clean exit; pass an explicit overlay path to keep it for
# post-mortem. The base qcow2 stays read-only.
#
# POSIX sh; quoted expansions; absolute binary paths (pfSense convention).

set -eu

QEMU=/usr/bin/qemu-system-x86_64
QEMU_IMG=/usr/bin/qemu-img

# Source-VM hardware profile (mirror — do not change without re-baking image).
VM_MAC="BC:24:11:37:9C:AC"
VM_SMBIOS_UUID="58fd7964-c40c-4f47-bf02-3fdad18f8b00"
VM_SMP="2,sockets=1,cores=2"
VM_MEM="4096"

usage() {
    echo "Usage: $0 <base-image.qcow2> [overlay.qcow2]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage

BASE_IMG="$1"
OVERLAY="${2:-}"

if [ ! -f "$BASE_IMG" ]; then
    echo "boot_vm: base image not found: $BASE_IMG" >&2
    exit 1
fi

# Make the base path absolute. qemu-img stores the backing-file path in the
# overlay and resolves a RELATIVE one against the OVERLAY's directory (here
# /tmp), not the cwd — so a relative base would be looked up as /tmp/<base>
# and fail. An absolute backing path is location-independent.
case "$BASE_IMG" in
    /*) ;;
    *) BASE_IMG="$(cd "$(dirname "$BASE_IMG")" && pwd)/$(basename "$BASE_IMG")" ;;
esac

# Resolve the qemu binaries by name if the absolute path is not present
# (the GH-hosted ubuntu-latest layout may differ from the pfSense convention).
if [ ! -x "$QEMU" ]; then
    QEMU="$(command -v qemu-system-x86_64 || true)"
fi
if [ ! -x "$QEMU_IMG" ]; then
    QEMU_IMG="$(command -v qemu-img || true)"
fi
if [ -z "$QEMU" ] || [ ! -x "$QEMU" ]; then
    echo "boot_vm: qemu-system-x86_64 not found" >&2
    exit 1
fi
if [ -z "$QEMU_IMG" ] || [ ! -x "$QEMU_IMG" ]; then
    echo "boot_vm: qemu-img not found" >&2
    exit 1
fi

# Create the ephemeral copy-on-write overlay over the read-only base.
# The caller (conftest) normally passes a per-instance overlay path under its
# own pytest tmp dir (parallel isolation + the tmp dir reaps it). For standalone
# use we mktemp one — with a TRAILING-X template only: BSD/macOS mktemp leaves a
# non-trailing run of X's literal (a ".XXXXXX.qcow2" template yields a junk name),
# whereas a trailing-X template is portable across GNU and BSD. The qcow2 format
# is forced explicitly on both create (-f) and the -drive (format=), so the
# overlay needs no ".qcow2" suffix for format detection.
CLEANUP_OVERLAY=0
if [ -z "$OVERLAY" ]; then
    OVERLAY="$(mktemp -t pfb-smoke-overlay.XXXXXX)"
    CLEANUP_OVERLAY=1
fi

cleanup() {
    if [ "$CLEANUP_OVERLAY" -eq 1 ] && [ -n "$OVERLAY" ]; then
        rm -f "$OVERLAY"
    fi
}
trap cleanup EXIT INT TERM

# -b base -F qcow2: the overlay backs onto the read-only base; the base is
# never written. (Equivalent to -snapshot, but explicit + inspectable.)
"$QEMU_IMG" create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "$OVERLAY" >/dev/null

# Host-forward ports (env-overridable so parallel VMs don't collide; the
# defaults preserve the historical fixed map for standalone use).
SSH_PORT="${SMOKE_SSH_PORT:-2222}"
WEB_PORT="${SMOKE_WEB_PORT:-8080}"
DNS_PORT="${SMOKE_DNS_PORT:-5353}"

# Pick the accelerator + CPU model. SMOKE_QEMU_ACCEL/SMOKE_QEMU_CPU override;
# otherwise detect per host. `-accel <name>` generalises the old `-enable-kvm`
# (which is just `-accel kvm`). Probe the binary's own `-accel help` for hvf/whpx
# so an arm64 macOS host (x86 binary lists tcg only) correctly falls back to tcg.
ACCEL="${SMOKE_QEMU_ACCEL:-}"
if [ -z "$ACCEL" ]; then
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux)
            if [ -e /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi ;;
        Darwin)
            if "$QEMU" -accel help 2>/dev/null | grep -qw hvf; then ACCEL=hvf; else ACCEL=tcg; fi ;;
        CYGWIN*|MINGW*|MSYS*|Windows_NT)
            if "$QEMU" -accel help 2>/dev/null | grep -qw whpx; then ACCEL=whpx; else ACCEL=tcg; fi ;;
        *)
            ACCEL=tcg ;;
    esac
fi
# `-cpu host` is only valid with a hardware accelerator (kvm/hvf); tcg/whpx need
# a concrete model (max = every feature the accel can emulate).
CPU="${SMOKE_QEMU_CPU:-}"
if [ -z "$CPU" ]; then
    case "$ACCEL" in
        kvm|hvf) CPU=host ;;
        *) CPU=max ;;
    esac
fi

echo "boot_vm: booting $BASE_IMG via overlay $OVERLAY" >&2
echo "boot_vm: accel=$ACCEL cpu=$CPU hostfwd ssh=${SSH_PORT}->22 web=${WEB_PORT}->80 dns=${DNS_PORT}->53(tcp+udp)" >&2
[ "$ACCEL" = tcg ] && echo "boot_vm: WARNING tcg (no hardware virt) — boots are SLOW; raise SMOKE_BOOT_TIMEOUT" >&2

# Build the arg list incrementally so the control/diagnostic channel is
# optional. If QMP_SOCK is set in the environment, expose a QMP control socket
# there (used by screendump.py to capture the VGA framebuffer of a wedged,
# headless boot) and keep the serial console on stdio for the run log. If it is
# unset (local interactive use), mux the monitor + serial on stdio as before.
set -- \
    -accel "$ACCEL" -machine pc -cpu "$CPU" \
    -smp "$VM_SMP" -m "$VM_MEM" \
    -smbios "type=1,uuid=${VM_SMBIOS_UUID}" \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive "file=${OVERLAY},if=none,id=drive-scsi0,format=qcow2,cache=unsafe,discard=unmap,detect-zeroes=unmap" \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${WEB_PORT}-:80,hostfwd=tcp::${DNS_PORT}-:53,hostfwd=udp::${DNS_PORT}-:53" \
    -device "virtio-net-pci,mac=${VM_MAC},netdev=net0,id=nic0" \
    -display none

if [ -n "${QMP_SOCK:-}" ]; then
    rm -f "$QMP_SOCK"
    set -- "$@" -qmp "unix:${QMP_SOCK},server,nowait" -serial stdio
    echo "boot_vm: QMP control socket at $QMP_SOCK (screendump-capable)" >&2
else
    set -- "$@" -serial mon:stdio
fi

exec "$QEMU" "$@"
