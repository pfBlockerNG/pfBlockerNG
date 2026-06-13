#!/bin/sh
# boot_vm.sh — boot a hand-built pfSense CE qcow2 headless under QEMU/KVM
# for the ADR-04 Phase-1 de-risking spike.
#
# Usage:
#   tests/smoke/boot_vm.sh <base-image.qcow2> [overlay.qcow2]
#
# Boots the image headless with KVM acceleration and a QEMU user-net
# (SLIRP) host-forward map so the runner can reach the guest:
#   host 2222/tcp -> guest 22   (SSH)
#   host 8080/tcp -> guest 80   (WebUI, HTTP)
#   host 5353/tcp -> guest 53   (DNS, TCP)
#   host 5353/udp -> guest 53   (DNS, UDP)
# The guest reaches the runner at the SLIRP host alias 10.0.2.2.
#
# Hardware MIRRORS the source Proxmox VM (qm showcmd 103 --pretty) so the
# published qcow2 boots without pfSense re-detecting hardware and dropping
# to the interface-reassignment console prompt:
#   - single virtio-net-pci NIC, MAC pinned to BC:24:11:37:9C:AC
#     (the CE source VM's MAC; a MAC is not sensitive). The MAC is per-image
#     and defaults to the CE pin; override it with SMOKE_VM_MAC. A pfSense Plus
#     image MUST set SMOKE_VM_MAC to its OWN source-VM MAC: the Plus license/NDI
#     registration is keyed to it, so the CE pin would deregister/reassign it
#     (see ADR-24 and scripts/README.md § "pfSense Plus images").
#   - SMBIOS type-1 uuid pinned, per-image. The Plus Netgate Device ID (NDI) is
#     derived from the source VM's MAC + this SMBIOS uuid, so the uuid is as
#     license-keyed as the MAC. CE defaults to the public CE source-VM uuid;
#     a Plus image MUST set SMOKE_VM_SMBIOS_UUID to its OWN source-VM uuid (held
#     in a secret, NOT the public ci-metadata matrix — license/NDI-keyed).
#   - VirtIO-SCSI disk (guest sees da0)
#   - machine type pc (i440fx; Proxmox pc+pve0), -cpu host, 2 vCPU, 4 GB RAM
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
# MAC + SMBIOS uuid are per-image: CE pins by default, SMOKE_VM_MAC /
# SMOKE_VM_SMBIOS_UUID override (Plus MUST set both — its NDI is derived from
# MAC + uuid, so both are license-keyed and come from secrets, not the matrix).
VM_MAC="${SMOKE_VM_MAC:-BC:24:11:37:9C:AC}"
VM_SMBIOS_UUID="${SMOKE_VM_SMBIOS_UUID:-58fd7964-c40c-4f47-bf02-3fdad18f8b00}"
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
CLEANUP_OVERLAY=0
if [ -z "$OVERLAY" ]; then
    OVERLAY="$(mktemp -t pfb-smoke-overlay.XXXXXX.qcow2)"
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

echo "boot_vm: booting $BASE_IMG via overlay $OVERLAY" >&2
echo "boot_vm: hostfwd ssh=2222->22 web=8080->80 dns=5353->53(tcp+udp)" >&2

# KVM acceleration is required for a FreeBSD guest at usable speed. The
# caller (workflow) asserts /dev/kvm before invoking this helper.
#
# Build the arg list incrementally so the control/diagnostic channel is
# optional. If QMP_SOCK is set in the environment, expose a QMP control socket
# there (used by screendump.py to capture the VGA framebuffer of a wedged,
# headless boot) and keep the serial console on stdio for the run log. If it is
# unset (local interactive use), mux the monitor + serial on stdio as before.
set -- \
    -enable-kvm -machine pc -cpu host \
    -smp "$VM_SMP" -m "$VM_MEM" \
    -smbios "type=1,uuid=${VM_SMBIOS_UUID}" \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive "file=${OVERLAY},if=none,id=drive-scsi0,format=qcow2,cache=unsafe,discard=unmap,detect-zeroes=unmap" \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80,hostfwd=tcp::5353-:53,hostfwd=udp::5353-:53 \
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
