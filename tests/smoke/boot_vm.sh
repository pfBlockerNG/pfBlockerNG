#!/bin/sh
# boot_vm.sh — boot a smoke-test qcow2 headless under QEMU/KVM.
#
# Two roles (ADR-04 two-VM topology):
#
#   --role pfsense  (default) — the pfSense appliance, 8 virtio-net NICs that
#       MIRROR the source VM so pfSense does not re-detect hardware and drop to
#       the interface-reassignment console prompt. Only the first three are
#       assigned in the image:
#         net0 WAN  — SLIRP user-net, 192.168.89.0/24, host alias 192.168.89.2 (the
#                     guest reaches the runner-side mock feed / stub-DNS /
#                     sinkhole servers here); DHCP; egress for the resolver +
#                     feed-update path (`pkg add` is offline — RUN_DEPENDS baked).
#         net1 MGMT — SLIRP user-net, 192.168.43.0/24 (a /24 like net0, NOT a /16:
#                     a /16 made qemu's SLIRP DHCP hand the guest an unexpected
#                     address the forwards never reached); the host->guest forwards
#                     (ssh, web) target the mgmt NIC's DHCP address 192.168.43.15.
#                     This is the harness control path.
#         net2 LAN  — a QEMU `socket` LISTENER (point-to-point L2 "crossover"
#                     to the civm data NIC); pfSense LAN is 192.168.1.1/24.
#         net3..7   — unassigned; present only so the 8-NIC image sees no
#                     hardware change. Isolated (restrict=on), no host access.
#
#   --role client — the Debian client VM ("civm"), 2 virtio-net NICs:
#         net0 MGMT — SLIRP user-net; host->guest ssh forward (the harness runs
#                     `dig @192.168.1.1` here). DHCP; MAC is don't-care.
#         net1 DATA — a QEMU `socket` CONNECTOR to the pfSense LAN listener; its
#                     MAC is SMOKE_CLIENT_MAC_ADDRESS so pfSense's static DHCP
#                     lease hands it 192.168.1.10.
#
# Usage:
#   tests/smoke/boot_vm.sh [--role pfsense|client] <base-image.qcow2> [overlay.qcow2]
#
# Boots headless with KVM acceleration. The base qcow2 is NEVER mutated: an
# ephemeral copy-on-write overlay is created over it and the guest writes only to
# the overlay (removed on a clean exit; pass an explicit overlay path to keep it).
#
# Identity (per-image; ADR-24). pfSense:
#   - SMOKE_VM_MAC — the NIC MAC(s), NEWLINE-SEPARATED, one MAC per NIC in order
#     (net0..net7); NIC i takes line i. Defaults to the CE source-VM's own 8 MACs
#     (committed below — a MAC is not sensitive). A pfSense Plus image overrides
#     it with its license/NDI-keyed source-VM MAC list (from a secret).
#   - SMOKE_VM_SMBIOS_UUID — SMBIOS type-1 uuid (Plus: the source-VM uuid, held
#     in a secret; CE: the public pin). The Plus Netgate Device ID derives from
#     MAC + uuid, so a Plus image MUST set both.
# civm: net MACs default to the civm source VM's own (committed below — net0
#   management, net1 data). The data-NIC MAC (SMOKE_CLIENT_MAC_ADDRESS) keys
#   pfSense's static-lease mapping, so it must match the pfSense image's lease.
#   SMBIOS type-1 uuid also defaults to the civm source VM's (SMOKE_CLIENT_SMBIOS_UUID).
#
# Shared:
#   - SMOKE_LAN_SOCKET_PORT — TCP port (on 127.0.0.1) for the pfSense<->civm LAN
#     socket link. pfSense LISTENs, civm CONNECTs; both roles must use the same
#     port. Default 12340 (a lone pfSense boot just has no LAN carrier).
#   - SMOKE_SSH_HOSTPORT / SMOKE_WEB_HOSTPORT — pfSense host-forward ports
#     (defaults 2222 / 8080). SMOKE_CLIENT_SSH_HOSTPORT — civm ssh host port
#     (default 2223).
#
# POSIX sh; quoted expansions; absolute binary paths (pfSense convention).

set -eu

QEMU=/usr/bin/qemu-system-x86_64
QEMU_IMG=/usr/bin/qemu-img

# Source-VM hardware profile (mirror — do not change without re-baking image).
# DEFAULT_CE_MAC is the CE source VM's own 8 NIC MACs (net0..net7, in order),
# committed as non-secret defaults so a CE boot mirrors the source hardware. A
# Plus image overrides via SMOKE_VM_MAC (its NDI-keyed secret list); an empty or
# unset SMOKE_VM_MAC falls back to these.
DEFAULT_CE_MAC="$(printf '%s\n' \
    BC:24:11:37:9C:AC \
    BC:24:11:80:42:35 \
    BC:24:11:D6:90:DD \
    BC:24:11:FB:41:8A \
    BC:24:11:2D:95:0A \
    BC:24:11:36:D3:34 \
    BC:24:11:02:0B:68 \
    BC:24:11:46:D1:DE)"
VM_MAC="${SMOKE_VM_MAC:-$DEFAULT_CE_MAC}"
VM_SMBIOS_UUID="${SMOKE_VM_SMBIOS_UUID:-58fd7964-c40c-4f47-bf02-3fdad18f8b00}"
# VM_SMP / VM_MEM / CLIENT_SMP / CLIENT_MEM: env-overridable for benchmarks that
# need more cores/RAM (e.g. SMOKE_VM_SMP="3,sockets=1,cores=3" SMOKE_VM_MEM=6144).
# 2 GB is ample for the smoke pfSense (FreeBSD pre-allocates — no ballooning): a
# production box with 500k+ IPs in pf + full DNSBL sits at ~10% of 4 GB; the smoke
# tests load tiny fixtures. Smaller default = denser parallel lanes (2 GB pfSense +
# 1 GB civm = 3 GB/lane). Bump via SMOKE_VM_MEM for the benchmark runner.
VM_SMP="${SMOKE_VM_SMP:-2,sockets=1,cores=2}"
VM_MEM="${SMOKE_VM_MEM:-2048}"

# civm is a light Debian client (sshd + occasional dig/curl); 1 GB is ample, and
# virtio-balloon lets Linux return unused RAM to the host.  pfSense/FreeBSD does NOT
# support ballooning — leave VM_MEM (4096) and every pfSense-role arg untouched.
CLIENT_SMP="${SMOKE_CLIENT_SMP:-2,sockets=1,cores=2}"
CLIENT_MEM="${SMOKE_CLIENT_MEM:-1024}"
# civm source-VM NIC MACs (committed non-secret defaults): net0 management, net1
# data. The data MAC keys pfSense's static DHCP lease (-> 192.168.1.10), so it
# must match the lease baked into the pfSense image. Override either via env.
CLIENT_MGMT_MAC="${SMOKE_CLIENT_MGMT_MAC:-BC:24:11:29:A4:1B}"
CLIENT_MAC="${SMOKE_CLIENT_MAC_ADDRESS:-02:49:E4:CE:92:72}"
# civm SMBIOS type-1 uuid (committed non-secret default — the civm source VM's
# own uuid; keeps machine-id / DHCP identity stable across overlay boots).
CLIENT_SMBIOS_UUID="${SMOKE_CLIENT_SMBIOS_UUID:-7dc13783-e65c-4f62-8fd8-45eeae4c77b9}"

# Host<->guest exposure (mirrors conftest's DEFAULT_*_PORT + the management IP).
SSH_HOSTPORT="${SMOKE_SSH_HOSTPORT:-2222}"
WEB_HOSTPORT="${SMOKE_WEB_HOSTPORT:-8080}"
CLIENT_SSH_HOSTPORT="${SMOKE_CLIENT_SSH_HOSTPORT:-2223}"
PFSENSE_MGMT_IP="192.168.43.15"   # mgmt NIC's DHCP lease on net1 (a /24 — qemu hands the
                                  # lone client .15, exactly as net0/WAN gets 192.168.89.15)
# The hostfwd TARGET defaults to that address. The mgmt net is a /24 (NOT a /16): a /16
# made qemu's SLIRP DHCP hand the MGT1 NIC an unexpected address (10.0.2.x) that the
# forwards never reached; a /24 is predictable (net|.15), mirroring net0. The image makes
# MGT1 DHCP, so the caller MAY still export SMOKE_PFSENSE_MGT_TARGET="" to forward to
# whatever the guest DHCPs (qemu fills in the lease) instead of the explicit IP.
# Single-dash form: an explicit empty override IS honored (vs :- which ignores empty).
PFSENSE_MGT_TARGET="${SMOKE_PFSENSE_MGT_TARGET-$PFSENSE_MGMT_IP}"

# pfSense<->civm LAN crossover socket (point-to-point; pfSense listens, civm connects).
LAN_SOCKET_PORT="${SMOKE_LAN_SOCKET_PORT:-12340}"

ROLE=pfsense

usage() {
    echo "Usage: $0 [--role pfsense|client] <base-image.qcow2> [overlay.qcow2]" >&2
    exit 2
}

# --- option parsing (optional --role, then positionals) --------------------- #
while [ "$#" -gt 0 ]; do
    case "$1" in
        --role) [ "$#" -ge 2 ] || usage; ROLE="$2"; shift 2 ;;
        --)     shift; break ;;
        -*)     echo "boot_vm: unknown option: $1" >&2; usage ;;
        *)      break ;;
    esac
done
case "$ROLE" in
    pfsense|client) ;;
    *) echo "boot_vm: --role must be 'pfsense' or 'client'" >&2; exit 2 ;;
esac

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

echo "boot_vm: role=$ROLE booting $BASE_IMG via overlay $OVERLAY" >&2

# nth_mac N — echo the Nth line (0-based) of the newline-separated VM_MAC, or
# nothing when that line is absent (CE: empty list -> QEMU default per NIC).
nth_mac() {
    printf '%s\n' "$VM_MAC" | sed -n "$(($1 + 1))p"
}

# Machine + disk args (identical for both roles, aside from CPU/RAM sizing).
if [ "$ROLE" = client ]; then
    SMP="$CLIENT_SMP"; MEM="$CLIENT_MEM"
else
    SMP="$VM_SMP"; MEM="$VM_MEM"
fi

# Perf tuning (mirrors a Proxmox prod pfSense VM):
#   - +kvm_pv_eoi,+kvm_pv_unhalt: paravirt interrupt/spinlock hints -> fewer VM exits.
#   - iothread + virtio-scsi: disk I/O runs on its own thread, off QEMU's main loop.
#   - aio=io_uring: modern async I/O backend (lower syscall overhead than aio=threads).
#   cache=unsafe stays (throwaway overlay; host page cache, skips all flushes = fastest).
set -- \
    -enable-kvm -machine pc -cpu host,+kvm_pv_eoi,+kvm_pv_unhalt \
    -smp "$SMP" -m "$MEM" \
    -object iothread,id=iothread0 \
    -device virtio-scsi-pci,id=virtioscsi0,iothread=iothread0 \
    -drive "file=${OVERLAY},if=none,id=drive-scsi0,format=qcow2,aio=io_uring,cache=unsafe,discard=unmap,detect-zeroes=unmap" \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1

if [ "$ROLE" = pfsense ]; then
    # SMBIOS identity (license/NDI-keyed for Plus; public pin for CE).
    set -- "$@" -smbios "type=1,uuid=${VM_SMBIOS_UUID}"

    echo "boot_vm: pfsense hostfwd ssh=${SSH_HOSTPORT}->${PFSENSE_MGT_TARGET}:22 web=${WEB_HOSTPORT}->${PFSENSE_MGT_TARGET}:80 (mgmt net1)" >&2
    echo "boot_vm: pfsense LAN socket LISTEN 127.0.0.1:${LAN_SOCKET_PORT} (net2)" >&2

    i=0
    while [ "$i" -lt 8 ]; do
        case "$i" in
            # net0 WAN: a /24 (NOT a /16). It must NOT contain the DNSBL sinkhole
            # VIP (10.10.10.1) or the auto-VIP (10.10.10.53) — pfBlockerNG refuses
            # a VIP that overlaps an interface subnet and disables DNSBL wholesale.
            # 192.168.89.0/24 keeps the host alias 192.168.89.2 while leaving 10.10.10.x free.
            0) netdev="user,id=net0,net=192.168.89.0/24,host=192.168.89.2" ;;
            # net1 MGMT: a /24 (NOT a /16). A /16 made qemu's SLIRP DHCP lease the
            # guest an unexpected address (10.0.2.x) the forwards never reached; a
            # /24 is predictable (net|.15), mirroring net0. 192.168.43.0/24 avoids
            # the DNSBL VIP ranges and the LAN (192.168.1.0/24).
            1) netdev="user,id=net1,net=192.168.43.0/24,host=192.168.43.2,hostfwd=tcp::${SSH_HOSTPORT}-${PFSENSE_MGT_TARGET}:22,hostfwd=tcp::${WEB_HOSTPORT}-${PFSENSE_MGT_TARGET}:80" ;;
            2) netdev="socket,id=net2,listen=127.0.0.1:${LAN_SOCKET_PORT}" ;;
            # net3..7: present so the 8-NIC image sees no hardware change, but
            # isolated (restrict=on) with distinct dummy subnets — pfSense leaves
            # them unassigned so they never get an IP.
            *) netdev="user,id=net${i},net=10.${i}0.0.0/24,restrict=on" ;;
        esac
        mac="$(nth_mac "$i")"
        if [ -n "$mac" ]; then
            dev="virtio-net-pci,mac=${mac},netdev=net${i},id=nic${i}"
        else
            dev="virtio-net-pci,netdev=net${i},id=nic${i}"
        fi
        set -- "$@" -netdev "$netdev" -device "$dev"
        i=$((i + 1))
    done
else
    # civm: net0 management (ssh hostfwd, DHCP, don't-care MAC); net1 data
    # (socket CONNECT to the pfSense LAN listener, MAC = static-lease key).
    set -- "$@" -smbios "type=1,uuid=${CLIENT_SMBIOS_UUID}"
    echo "boot_vm: client hostfwd ssh=${CLIENT_SSH_HOSTPORT}->:22 (mgmt net0)" >&2
    echo "boot_vm: client DATA socket CONNECT 127.0.0.1:${LAN_SOCKET_PORT} mac=${CLIENT_MAC} (net1)" >&2
    set -- "$@" \
        -netdev "user,id=net0,hostfwd=tcp::${CLIENT_SSH_HOSTPORT}-:22" \
        -device "virtio-net-pci,mac=${CLIENT_MGMT_MAC},netdev=net0,id=nic0" \
        -netdev "socket,id=net1,connect=127.0.0.1:${LAN_SOCKET_PORT}" \
        -device "virtio-net-pci,mac=${CLIENT_MAC},netdev=net1,id=nic1" \
        -device virtio-balloon
fi

set -- "$@" -display none

# KVM acceleration is required for a FreeBSD guest at usable speed. The caller
# (workflow) asserts /dev/kvm before invoking this helper.
#
# If QMP_SOCK is set, expose a QMP control socket there (used by screendump.py to
# capture the VGA framebuffer of a wedged, headless boot) and keep the serial
# console on stdio for the run log. If unset (local interactive use), mux the
# monitor + serial on stdio as before.
if [ -n "${QMP_SOCK:-}" ]; then
    rm -f "$QMP_SOCK"
    set -- "$@" -qmp "unix:${QMP_SOCK},server,nowait" -serial stdio
    echo "boot_vm: QMP control socket at $QMP_SOCK (screendump-capable)" >&2
else
    set -- "$@" -serial mon:stdio
fi

exec "$QEMU" "$@"
