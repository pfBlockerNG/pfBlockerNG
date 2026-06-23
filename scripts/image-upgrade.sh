#!/bin/sh
# image-upgrade.sh — upgrade a published pfSense (CE or Plus) smoke base to a
# newer release and publish the result as a new tag (ADR-04, Phase 2 "upgrade in
# place").
#
# Drive it FROM YOUR MACHINE: the KVM boot + in-VM upgrade must run on a KVM host
# (your Proxmox host), so pass its SSH coordinates and the script runs qemu there
# over SSH while `oras` pull/push stay LOCAL (nothing extra to install on Proxmox
# beyond its native qemu). The guest is reached by jumping THROUGH Proxmox, so the
# guest SSH key never leaves your machine. Omit --proxmox to run locally (i.e.
# directly on the KVM host), as before.
#
# TYPE (--type ce|plus, default ce) follows image-publish.sh's scheme: it derives
# the image name (pfsense-ce|pfsense-plus), the qcow2 filename, the description and
# the OCI artifact-type. The published artifact is BYTE-IDENTICAL to what you would
# get by running this upgrade by hand and then `image-publish.sh --type <type>
# <tag>` — the two share scripts/image-lib.sh, so they cannot drift.
#
# The publish TAG is the upgraded system's major.minor (2.8.1 -> 2.9 once the box
# reports 2.9.0; 26.05.1 -> 26.05), unless --to overrides it.
#
# Flow: pull the current image from GHCR (local) -> stream it to the Proxmox host
# -> boot it under QEMU/KVM there (read-write, with internet) ->
# [optional: pkg update -f + pkg upgrade, reboot, wait SSH back] ->
# check for an available OS upgrade (pfSense-upgrade -c); if the box is already
# current, exit 0 WITHOUT publishing -> else run pfSense-upgrade over an SSH jump
# -> wait for /etc/version to change + reboot -> health-gate (webConfigurator HTTP
# or pfctl live ruleset; confirms it boots and works on the NEW version) ->
# power off cleanly -> compress on Proxmox -> stream back ->
# push the new tag (local). The source tag is left untouched, so the old image
# is always kept.
#
# Usage:
#   ./scripts/image-upgrade.sh --from <current-version> [--type ce|plus] [options]
#
# Examples:
#   ./scripts/image-upgrade.sh --from 2.8 --proxmox root@pve.lan --ssh-key ~/.ssh/smoke_ed25519
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.9 --proxmox pve.lan --proxmox-port 2222
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.8 --force --upgrade-pkgs   # patch refresh
#   # Plus (its MAC + SMBIOS uuid are license-keyed — pass the Plus VM's own):
#   ./scripts/image-upgrade.sh --from 26.03 --type plus --proxmox pve.lan \
#       --mac <plus-mac> --smbios-uuid <plus-uuid> --ssh-key ~/.ssh/smoke_ed25519
#
# Proxmox connection (the KVM host that boots the VM):
#   --proxmox [USER@]HOST   SSH target of the Proxmox/KVM host. If omitted (and
#                           PROXMOX_SSH_HOST is unset), runs locally.
#   --proxmox-port N        SSH port           (default: $PROXMOX_SSH_PORT or 22)
#   --proxmox-ssh-key PATH  SSH private key     (default: $PROXMOX_SSH_KEY)
#   --remote-tmpdir DIR     scratch dir on the KVM host for the image copies
#                           (several GB) (default: $PROXMOX_TMPDIR or /tmp)
#   USER defaults to $PROXMOX_SSH_USER or root.
#
# Options:
#   --from VERSION   current published tag to upgrade (required)
#   --to VERSION     tag to publish as (default: major.minor of the upgraded box)
#   --type T         ce (default) | plus — derives the image name, description and
#                    artifact-type (image-publish.sh's scheme)
#   --registry REF   GHCR namespace for the derived --type ref (default:
#                    $SMOKE_IMAGE_REPO or ghcr.io/pfblockerng)
#   --image REF      GHCR image ref without tag (default: the --type-derived
#                    ${registry}/${name}); overrides the derived ref
#   --description D  OCI description (default: "<edition> <tag>", as image-publish.sh)
#   --artifact-type T  OCI artifact-type (default: the --type-derived value)
#   --ssh-key PATH   GUEST SSH private key (default: $SMOKE_SSH_KEY) — its public
#                    half is baked into the image's root authorized_keys
#   --ssh-port N     Proxmox-local port forwarded to the guest's :22 (default: 2222)
#   --mac LIST       the 8 guest NIC MACs, NEWLINE-separated, one per NIC
#                    (net0..net7); pfSense assigns interfaces by MAC so all must
#                    match the image (mirror of boot_vm.sh's SMOKE_VM_MAC).
#                    Default: $SMOKE_VM_MAC, else the committed CE source-VM list
#                    (ce). For --type plus the identity is the SMOKE_PLUS_MAC secret
#                    and is REQUIRED (see below).
#   --smbios-uuid U  SMBIOS type-1 uuid; must match the image (default:
#                    $SMOKE_VM_SMBIOS_UUID, else the CE pin). The Netgate Device ID
#                    (Plus) derives from the MAC set + this uuid.
#
# Plus identity (license/NDI — REQUIRED for --type plus): the source VM's MACs and
# SMBIOS uuid come from the SMOKE_PLUS_MAC (8-MAC list) and SMOKE_PLUS_SMBIOS_UUID
# secrets. image-upgrade REFUSES to boot Plus unless the effective MAC set and uuid
# equal those secrets — a wrong NDI can burn the license. CE uses public defaults.
#   --compression T  qcow2 compression for the published image: zstd|zlib|off (default: zstd)
#   --upgrade-timeout S  MAX seconds to wait for the pfSense-upgrade+reboot
#                    (default: 1200). The poll exits the instant /etc/version
#                    changes, so this only bounds how long a STUCK upgrade waits
#                    before the run fails — it is not added to a successful run.
#   --upgrade-pkgs   before pfSense-upgrade, run `pkg update -f` + `pkg upgrade -y`
#                    to upgrade baked deps (qemu-guest-agent, etc.) to their latest
#                    versions; reboots the guest and waits for SSH before proceeding.
#                    Default OFF; pass this flag to enable. build-image.yml does NOT
#                    pass this flag (it calls this script directly), so callers that
#                    only want the pfSense-upgrade step are unaffected.
#   --branch NAME    switch the pfSense update branch to NAME before running the OS
#                    upgrade. pfSense stores the selected branch in config.xml key
#                    system/pkg_repo_conf_path; applying the change calls
#                    pkg_switch_repo() (runs pfSense-repo-setup -U and refreshes pkg
#                    metadata), followed by an explicit `pkg update -f` so the
#                    subsequent pfSense-upgrade -c check sees the new branch's
#                    versions. Use this to upgrade TO a pre-release or development
#                    build. Branch names are dynamic — use the exact name reported by
#                    pkg_list_repos() on that pfSense version. The script validates
#                    NAME against the list of available repos on the booted image and
#                    fails if it is not found. Default empty = leave the image's
#                    configured branch unchanged. Example (Plus pre-release):
#                    --branch pfSense-plus-v26.07-DEVTEST
#   --keep           keep the work dirs (image copies, console log) afterwards
#   --force          overwrite the target tag if it already exists
#
# Auth: as in image-publish.sh (local oras login, or SMOKE_GHCR_USER/SMOKE_GHCR_TOKEN).

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Shared type/tag/push helpers — sourced so the published artifact is byte-identical
# to running image-publish.sh --type <type> with the derived tag.
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
[ -f "$SCRIPT_DIR/image-lib.sh" ] || die "image-lib.sh not found next to this script: $SCRIPT_DIR/image-lib.sh"
# shellcheck source=scripts/image-lib.sh
. "$SCRIPT_DIR/image-lib.sh"

FROM=""
TO=""
# Image type: ce (default — the common case) | plus. Derives the image name,
# description and artifact-type from the type (image-publish.sh's scheme). The
# registry NAMESPACE defaults to ghcr.io/pfblockerng; --image/--registry override.
TYPE=ce
REGISTRY="${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}"
IMAGE=""
DESCRIPTION=""
ARTIFACT_TYPE=""
GUEST_KEY="${SMOKE_SSH_KEY:-}"
GUEST_PORT=2222
# Source-VM hardware identity — MUST match the image (mirror of boot_vm.sh).
# SMOKE_VM_MAC is a NEWLINE-separated list of 8 MACs, one per NIC (net0..net7);
# pfSense assigns interfaces by MAC, and the Plus Netgate Device ID (NDI/license)
# is keyed to the WHOLE set + the SMBIOS uuid. So all 8 must match the source VM.
# CE defaults to the committed public list; Plus comes from the SMOKE_PLUS_* secrets
# and is enforced below. The CE pin (net0 = BC:24:11:37:9C:AC) is the public default.
DEFAULT_CE_MAC="$(printf '%s\n' \
    BC:24:11:37:9C:AC \
    BC:24:11:80:42:35 \
    BC:24:11:D6:90:DD \
    BC:24:11:FB:41:8A \
    BC:24:11:2D:95:0A \
    BC:24:11:36:D3:34 \
    BC:24:11:02:0B:68 \
    BC:24:11:46:D1:DE)"
DEFAULT_CE_SMBIOS_UUID="58fd7964-c40c-4f47-bf02-3fdad18f8b00"
# Explicit override (full 8-MAC list / uuid) or empty — resolved by --type below.
MAC="${SMOKE_VM_MAC:-}"
SMBIOS_UUID="${SMOKE_VM_SMBIOS_UUID:-}"
COMPRESSION=zstd
UPGRADE_TIMEOUT=1200
UPGRADE_PKGS=0
BRANCH=""
KEEP=0
FORCE=0

# Proxmox SSH coordinates (env fallbacks; --proxmox overrides).
PX_HOST="${PROXMOX_SSH_HOST:-}"
PX_USER="${PROXMOX_SSH_USER:-root}"
PX_PORT="${PROXMOX_SSH_PORT:-22}"
PX_KEY="${PROXMOX_SSH_KEY:-}"
REMOTE_TMPDIR="${PROXMOX_TMPDIR:-/tmp}"

# The non-interactive pfSense upgrade command. NOTE: confirm the exact flags for
# the running CE release during the Phase-1 spike (ADR-04 §6 flags this) — `yes |`
# is a hedge against any interactive prompt; the version-poll below detects the
# real completion regardless of how it reboots.
UPGRADE_CMD='yes | /usr/local/sbin/pfSense-upgrade -d'

# After pfSense-upgrade completes and a new version is detected, poll up to this
# many seconds for the box to be "working fine" before proceeding to shutdown.
HEALTH_TIMEOUT=300

while [ $# -gt 0 ]; do
    case "$1" in
        --proxmox)         PX_TARGET="$2"; shift 2 ;;
        --proxmox-port)    PX_PORT="$2"; shift 2 ;;
        --proxmox-ssh-key) PX_KEY="$2"; shift 2 ;;
        --remote-tmpdir)   REMOTE_TMPDIR="$2"; shift 2 ;;
        --from)            FROM="$2"; shift 2 ;;
        --to)              TO="$2"; shift 2 ;;
        --type)            TYPE="$2"; shift 2 ;;
        --registry)        REGISTRY="$2"; shift 2 ;;
        --image)           IMAGE="$2"; shift 2 ;;
        --description)     DESCRIPTION="$2"; shift 2 ;;
        --artifact-type)   ARTIFACT_TYPE="$2"; shift 2 ;;
        --ssh-key)         GUEST_KEY="$2"; shift 2 ;;
        --ssh-port)        GUEST_PORT="$2"; shift 2 ;;
        --mac)             MAC="$2"; shift 2 ;;
        --smbios-uuid)     SMBIOS_UUID="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --upgrade-timeout) UPGRADE_TIMEOUT="$2"; shift 2 ;;
        --upgrade-pkgs)    UPGRADE_PKGS=1; shift ;;
        --branch)          BRANCH="$2"; shift 2 ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        -h|--help)         sed -n '2,108p' "$0"; exit 0 ;;
        *)                 die "unknown option: $1" ;;
    esac
done

if [ -n "${PX_TARGET:-}" ]; then
    case "$PX_TARGET" in
        *@*) PX_USER="${PX_TARGET%@*}"; PX_HOST="${PX_TARGET#*@}" ;;
        *)   PX_HOST="$PX_TARGET" ;;
    esac
fi

[ -n "$FROM" ] || die "missing --from <current-version>"
[ -n "$GUEST_KEY" ] || die "missing --ssh-key (or set SMOKE_SSH_KEY)"
[ -f "$GUEST_KEY" ] || die "guest ssh key not found: $GUEST_KEY"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

# Only pfSense images get an OS upgrade (civm is not an upgradable OS).
case "$TYPE" in ce|plus) ;; *) die "--type must be ce|plus (got '$TYPE')" ;; esac
# Derive the image-shaped fields from the type (image-publish.sh's scheme). An
# explicit --image / --description / --artifact-type always wins; the DESCRIPTION
# default needs the published TAG, so it is filled in after the version is known.
image_type_fields "$TYPE" || die "--type must be ce|plus (got '$TYPE')"
[ -n "$IMAGE" ]         || IMAGE="${REGISTRY%/}/${IMG_NAME}"
[ -n "$ARTIFACT_TYPE" ] || ARTIFACT_TYPE="$IMG_ATYPE"

# Resolve the source-VM identity per type. pfSense assigns interfaces by MAC, so
# all 8 must match the image. CE uses the committed PUBLIC defaults (the source
# VM's own — a MAC is not sensitive). Plus MUST use its own license/NDI-keyed
# identity from the SMOKE_PLUS_* secrets: booting Plus with the wrong MAC set or
# SMBIOS uuid registers a wrong Netgate Device ID and can burn the license, so we
# REFUSE unless the effective identity equals the Plus secret.
if [ "$TYPE" = plus ]; then
    [ -n "$MAC" ]         || MAC="${SMOKE_PLUS_MAC:-}"
    [ -n "$SMBIOS_UUID" ] || SMBIOS_UUID="${SMOKE_PLUS_SMBIOS_UUID:-}"
    { [ -n "${SMOKE_PLUS_MAC:-}" ] && [ -n "${SMOKE_PLUS_SMBIOS_UUID:-}" ]; } \
        || die "--type plus needs the Plus source-VM identity: set the SMOKE_PLUS_MAC (newline-separated 8-MAC list) and SMOKE_PLUS_SMBIOS_UUID secrets"
    { [ -n "$MAC" ] && [ "$MAC" = "$SMOKE_PLUS_MAC" ]; } \
        || die "--type plus: the guest MAC list must equal SMOKE_PLUS_MAC (the license/NDI-keyed identity); refusing to boot Plus with a wrong NDI"
    [ "$SMBIOS_UUID" = "$SMOKE_PLUS_SMBIOS_UUID" ] \
        || die "--type plus: the SMBIOS uuid must equal SMOKE_PLUS_SMBIOS_UUID; refusing to boot Plus with a wrong NDI"
else
    [ -n "$MAC" ]         || MAC="$DEFAULT_CE_MAC"
    [ -n "$SMBIOS_UUID" ] || SMBIOS_UUID="$DEFAULT_CE_SMBIOS_UUID"
fi

# A full 8-MAC list is mandatory (one per NIC, net0..net7) — a single MAC would
# leave net1..7 with random MACs and break interface assignment / the Plus NDI.
_mac_count=$(printf '%s\n' "$MAC" | grep -c '.')
[ "$_mac_count" -eq 8 ] || die "expected 8 NIC MACs (newline-separated, net0..net7), got ${_mac_count}"

PX_REMOTE=0
[ -n "$PX_HOST" ] && PX_REMOTE=1

# ssh option words (intentionally unquoted at use; no spaces in port/key).
PX_PORT_OPT=""; [ -n "$PX_PORT" ] && PX_PORT_OPT="-p $PX_PORT"
PX_KEY_OPT="";  [ -n "$PX_KEY" ]  && PX_KEY_OPT="-i $PX_KEY"

# px CMD — run CMD on the KVM host (over SSH, or locally); stdin/stdout stream.
px() {
    if [ "$PX_REMOTE" -eq 1 ]; then
        # shellcheck disable=SC2086
        ssh -o BatchMode=yes -o ConnectTimeout=10 $PX_PORT_OPT $PX_KEY_OPT \
            "${PX_USER}@${PX_HOST}" "$1"
    else
        sh -c "$1"
    fi
}

# ssh_guest — reach the VM's forwarded :22. When driving a remote Proxmox host we
# jump THROUGH it (ProxyCommand -W), so the guest key stays on this machine and
# the hostfwd only needs to bind Proxmox's localhost.
ssh_guest() {
    if [ "$PX_REMOTE" -eq 1 ]; then
        # shellcheck disable=SC2086
        ssh -o ProxyCommand="ssh -o BatchMode=yes $PX_PORT_OPT $PX_KEY_OPT ${PX_USER}@${PX_HOST} -W %h:%p" \
            -p "$GUEST_PORT" -i "$GUEST_KEY" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            root@127.0.0.1 "$@"
    else
        ssh -p "$GUEST_PORT" -i "$GUEST_KEY" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            root@127.0.0.1 "$@"
    fi
}

# wait_guest_ssh TIMEOUT — poll until root SSH answers or TIMEOUT seconds elapse.
wait_guest_ssh() {
    _wgs_timeout="$1"
    _wgs_elapsed=0
    while ! ssh_guest true 2>/dev/null; do
        [ "$_wgs_elapsed" -ge "$_wgs_timeout" ] && \
            die "VM did not answer SSH within ${_wgs_timeout}s (see $REMOTE_DIR/console.log on the KVM host)"
        sleep 5; _wgs_elapsed=$((_wgs_elapsed + 5))
    done
}

# nth_mac N — echo the Nth line (0-based) of the newline-separated MAC list, i.e.
# the MAC for NIC net${N}. Mirrors boot_vm.sh so every NIC gets the source-VM MAC.
nth_mac() {
    printf '%s\n' "$MAC" | sed -n "$(($1 + 1))p"
}

# Local tooling: oras always; ssh only when driving a remote host.
command -v oras >/dev/null 2>&1 || die "required local tool not found: oras"
if [ "$PX_REMOTE" -eq 1 ]; then
    command -v ssh >/dev/null 2>&1 || die "required local tool not found: ssh"
    log "KVM host: ${PX_USER}@${PX_HOST}${PX_PORT:+:$PX_PORT} (qemu runs there over SSH; guest reached via jump)"
else
    log "running locally (assuming this IS the KVM host)"
fi

# KVM-host tooling (native qemu). Detect the system emulator binary.
QEMU_BIN=$(px "command -v qemu-system-x86_64 || command -v kvm" 2>/dev/null | head -n1 | tr -d '\r')
[ -n "$QEMU_BIN" ] || die "no qemu-system-x86_64/kvm on the KVM host"
px "command -v qemu-img >/dev/null 2>&1" || die "qemu-img not found on the KVM host"
px "test -e /dev/kvm" || warn "/dev/kvm not present on the KVM host — the guest will be very slow under TCG"

if [ -n "${SMOKE_GHCR_TOKEN:-}" ] && [ -n "${SMOKE_GHCR_USER:-}" ]; then
    log "logging in to ghcr.io as $SMOKE_GHCR_USER"
    printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ghcr.io -u "$SMOKE_GHCR_USER" --password-stdin
fi

LOCAL_DIR=$(mktemp -d)
REMOTE_DIR=$(px "mkdir -p '$REMOTE_TMPDIR' && mktemp -d -p '$REMOTE_TMPDIR'" | tr -d '\r')
[ -n "$REMOTE_DIR" ] || die "could not create a work dir under $REMOTE_TMPDIR on the KVM host"
QPID=""

cleanup() {
    if [ -n "$QPID" ]; then
        px "kill -0 $QPID 2>/dev/null && { echo 'killing leftover QEMU'; kill $QPID; }" 2>/dev/null || true
    fi
    if [ "$KEEP" -eq 0 ]; then
        px "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
        rm -rf "$LOCAL_DIR" 2>/dev/null || true
    else
        log "work dirs kept — local: $LOCAL_DIR   KVM host: ${PX_HOST:+$PX_HOST:}$REMOTE_DIR"
    fi
}
trap cleanup EXIT INT TERM

# --- pull current image (local), stream to the KVM host --------------------
log "pulling ${IMAGE}:${FROM} (local oras)"
oras pull "${IMAGE}:${FROM}" -o "$LOCAL_DIR"
BASE=$(find "$LOCAL_DIR" -maxdepth 1 -name '*.qcow2' | head -n1)
[ -n "$BASE" ] || die "no qcow2 found in pulled artifact ${IMAGE}:${FROM}"

# Stream to a writable working copy on the KVM host. We boot THIS copy; the GHCR
# source tag is never modified.
log "streaming base image to the KVM host -> $REMOTE_DIR/work.qcow2"
px "cat > '$REMOTE_DIR/work.qcow2'" < "$BASE"
px "test -s '$REMOTE_DIR/work.qcow2'" || die "streamed image is empty on the KVM host"

# --- boot under QEMU on the KVM host (internet ON for the upgrade) ----------
# Mirror the smoke 8-NIC topology (tests/smoke/boot_vm.sh) so the image boots
# without pfSense re-detecting hardware and dropping to the interface-reassignment
# console prompt. Only the first three are assigned in the image:
#   net0 WAN  — SLIRP 10.10.0.0/24, NATs to the internet (the upgrade download).
#   net1 MGMT — SLIRP 10.0.0.0/16; the ssh host-forward targets the static
#               management IP 10.0.0.20 (the upgrade's control path). WAN uses
#               10.10.0.0/24 so it overlaps neither mgmt 10.0/16 nor the DNSBL
#               sinkhole VIP 10.10.10.1 (matches tests/smoke/boot_vm.sh).
#   net2 LAN  — present but isolated (no civm peer during an upgrade).
#   net3..7   — unassigned; present only so the 8-NIC image sees no change.
# EVERY NIC carries its source-VM MAC (net${i} = the i-th line of $MAC), exactly
# as boot_vm.sh does: pfSense assigns interfaces by MAC, so the mgmt path (net1 ->
# 10.0.0.20, the upgrade's SSH control channel) and — for Plus — the whole
# license/NDI-keyed set must match the image, or pfSense re-detects hardware and
# drops to the interface-reassignment prompt (and Plus would register a wrong NDI).
M0=$(nth_mac 0); M1=$(nth_mac 1); M2=$(nth_mac 2); M3=$(nth_mac 3)
M4=$(nth_mac 4); M5=$(nth_mac 5); M6=$(nth_mac 6); M7=$(nth_mac 7)
log "booting VM on the KVM host (guest mgmt :22 -> 127.0.0.1:$GUEST_PORT there)"
QEMU_CMD="$QEMU_BIN \
    -enable-kvm -machine pc -cpu host \
    -smp 2,sockets=1,cores=2 -m 4096 \
    -smbios type=1,uuid=$SMBIOS_UUID \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive file=$REMOTE_DIR/work.qcow2,if=none,id=drive-scsi0,format=qcow2,discard=unmap,detect-zeroes=unmap \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev user,id=net0,net=10.10.0.0/24,host=10.10.0.2 \
    -device virtio-net-pci,mac=$M0,netdev=net0,id=nic0 \
    -netdev user,id=net1,net=10.0.0.0/16,host=10.0.0.2,hostfwd=tcp:127.0.0.1:$GUEST_PORT-10.0.0.20:22 \
    -device virtio-net-pci,mac=$M1,netdev=net1,id=nic1 \
    -netdev user,id=net2,net=10.20.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M2,netdev=net2,id=nic2 \
    -netdev user,id=net3,net=10.30.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M3,netdev=net3,id=nic3 \
    -netdev user,id=net4,net=10.40.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M4,netdev=net4,id=nic4 \
    -netdev user,id=net5,net=10.50.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M5,netdev=net5,id=nic5 \
    -netdev user,id=net6,net=10.60.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M6,netdev=net6,id=nic6 \
    -netdev user,id=net7,net=10.70.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M7,netdev=net7,id=nic7 \
    -display none -serial file:$REMOTE_DIR/console.log \
    -pidfile $REMOTE_DIR/qemu.pid -daemonize"
px "$QEMU_CMD"
QPID=$(px "cat '$REMOTE_DIR/qemu.pid'" | tr -d '\r')
[ -n "$QPID" ] || die "QEMU did not write a pidfile (see ${PX_HOST:+$PX_HOST:}$REMOTE_DIR/console.log)"

log "waiting for SSH..."
wait_guest_ssh 300

OLD_VER=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r')
log "current version on box: ${OLD_VER:-unknown}"

# --- optional: upgrade baked deps (pkg update -f + conditional pkg upgrade) -
if [ "$UPGRADE_PKGS" -eq 1 ]; then
    log "refreshing package catalogue (pkg update -f)"
    # pkg update may print output; connection stays up (not a reboot command).
    ssh_guest 'pkg update -f' 2>&1 | tee "$LOCAL_DIR/pkg-update.log" || true

    # Dry-run detect: pkg prints "Your packages are up to date" when nothing is
    # pending; otherwise it prints an upgrade plan (Number of packages to be
    # upgraded / to be installed / to be reinstalled, etc.).  Parse the output —
    # do NOT rely solely on exit code, as pkg(8) exit semantics vary by version.
    log "checking for pending package upgrades (pkg upgrade -n)"
    _pkg_dry=$(ssh_guest 'pkg upgrade -n' 2>&1 | tee "$LOCAL_DIR/pkg-upgrade-dryrun.log" || true)
    if printf '%s' "$_pkg_dry" | grep -q 'Your packages are up to date'; then
        log "packages already up to date — skipping pkg upgrade + reboot"
    else
        log "package upgrades pending — running pkg upgrade -y"
        ssh_guest 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y' 2>&1 | tee "$LOCAL_DIR/pkg-upgrade.log" || true
        log "rebooting after pkg upgrade"
        # /sbin/reboot drops the connection — expected; ignore the exit code.
        ssh_guest '/sbin/reboot' 2>/dev/null || true
        log "waiting for SSH after pkg-upgrade reboot..."
        wait_guest_ssh 300
        log "box is back after pkg-upgrade reboot"
    fi
fi

# --- optional: switch the pfSense update branch ----------------------------
# When --branch is given, validate the name against the repos available on the
# booted image, write it into config.xml via pkg_switch_repo(), then refresh
# the pkg catalogue so the subsequent pfSense-upgrade -c check sees the new
# branch's versions. Fail-closed: a wrong/missing branch name aborts the run
# rather than silently upgrading on the wrong (stable) branch.
if [ -n "$BRANCH" ]; then
    # Guard against a branch name containing a single quote (it would break the
    # PHP string literal below). Branch names from ci-metadata are safe, but
    # reject anything surprising rather than silently truncating or injecting.
    case "$BRANCH" in
        *\'*) die "--branch name must not contain a single quote: $BRANCH" ;;
    esac

    log "switching pfSense update branch to '$BRANCH' (via pkg_switch_repo)"

    # Build the pfSsh.php snippet. pfSsh.php reads PHP statements on stdin,
    # then the literal line "exec", then "exit". It runs the snippet inside the
    # pfSense PHP environment with all pfSense functions available.
    _php=$(printf '%s\n' \
        "require_once('pkg-utils.inc');" \
        "\$repos = pkg_list_repos();" \
        "\$names = array_column(\$repos, 'name');" \
        "\$avail = implode(' ', \$names);" \
        "if (!in_array('$BRANCH', \$names, true)) {" \
        "    echo 'PFB_BRANCH_NOT_FOUND available=' . \$avail . PHP_EOL;" \
        "} else {" \
        "    config_set_path('system/pkg_repo_conf_path', '$BRANCH');" \
        "    write_config('image-upgrade: switch update branch to $BRANCH');" \
        "    pkg_switch_repo();" \
        "    echo 'PFB_BRANCH_OK' . PHP_EOL;" \
        "}" \
        "exec" \
        "exit")

    _branch_out=$(printf '%s\n' "$_php" | ssh_guest 'pfSsh.php' 2>&1 | tee "$LOCAL_DIR/branch-switch.log" || true)

    if printf '%s' "$_branch_out" | grep -q 'PFB_BRANCH_NOT_FOUND'; then
        _avail=$(printf '%s' "$_branch_out" | grep 'PFB_BRANCH_NOT_FOUND' | sed 's/.*available=//')
        die "branch '$BRANCH' not found on this image. Available repos: ${_avail:-<none listed; see $LOCAL_DIR/branch-switch.log>}"
    fi
    if ! printf '%s' "$_branch_out" | grep -q 'PFB_BRANCH_OK'; then
        die "branch switch to '$BRANCH' did not confirm success (PFB_BRANCH_OK not in output; see $LOCAL_DIR/branch-switch.log)"
    fi

    log "branch switch confirmed — refreshing pkg catalogue (pkg update -f)"
    ssh_guest 'pkg update -f' 2>&1 | tee "$LOCAL_DIR/pkg-update-branch.log" || true
fi

# --- check whether an OS upgrade is available ------------------------------
# pfSense-upgrade -c reports the available version without applying it. Parsing
# is best-effort (the wording varies by release); the AUTHORITATIVE signal is
# the /etc/version change after the upgrade run below. If the check clearly says
# the box is already current there is nothing to publish -> graceful no-op exit.
log "checking for an available OS upgrade (pfSense-upgrade -c)"
UPGRADE_CHECK=$(ssh_guest 'pfSense-upgrade -c' 2>&1 | tee "$LOCAL_DIR/upgrade-check.log" || true)
printf '%s\n' "$UPGRADE_CHECK" | sed 's/^/    /'
if printf '%s' "$UPGRADE_CHECK" | grep -qiE 'up.to.date|already.*(latest|current)|no [a-z ]*update'; then
    log "no OS upgrade available — box is current at '${OLD_VER}'; nothing to publish."
    exit 0
fi

# --- run the pfSense upgrade -----------------------------------------------
log "running pfSense upgrade (this reboots the box; up to ${UPGRADE_TIMEOUT}s)"
# Connection will drop when the box reboots — that is expected, so ignore it.
ssh_guest "$UPGRADE_CMD" 2>&1 | tee "$LOCAL_DIR/upgrade.log" || true

# --- wait for the new version to come up -----------------------------------
log "waiting for the upgraded box to come back..."
NEW_VER=""
_elapsed=0
sleep 20  # let the reboot begin so we don't read the pre-reboot version
while [ "$_elapsed" -lt "$UPGRADE_TIMEOUT" ]; do
    _v=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r' || true)
    if [ -n "$_v" ] && [ "$_v" != "$OLD_VER" ]; then
        NEW_VER="$_v"
        break
    fi
    sleep 15; _elapsed=$((_elapsed + 15))
done
if [ -z "$NEW_VER" ]; then
    # Version unchanged: a graceful no-op only if pfSense-upgrade reports the box
    # is already current (the pre-check missed it); otherwise a genuine stuck/failed
    # upgrade — fail-closed.
    if printf '%s\n%s' "$UPGRADE_CHECK" "$(cat "$LOCAL_DIR/upgrade.log" 2>/dev/null)" \
        | grep -qiE 'up.to.date|already.*(latest|current)|no [a-z ]*update'; then
        log "no OS upgrade applied — box is current at '${OLD_VER}'; nothing to publish."
        exit 0
    fi
    die "version did not change within ${UPGRADE_TIMEOUT}s (still '${OLD_VER}'; see $LOCAL_DIR/upgrade.log)"
fi
log "upgraded: ${OLD_VER} -> ${NEW_VER}"

# --- health gate: wait until box is "working fine" -------------------------
# Poll up to HEALTH_TIMEOUT seconds. The box is considered healthy when EITHER:
#   a) the webConfigurator answers HTTP (login page is up), OR
#   b) pfctl -sr returns a live (non-empty) ruleset.
# If neither within HEALTH_TIMEOUT, die — fail-closed; no publish.
log "health-gating upgraded box (up to ${HEALTH_TIMEOUT}s for webConfigurator/pfctl)..."
_hg_elapsed=0
_hg_healthy=0
while [ "$_hg_elapsed" -lt "$HEALTH_TIMEOUT" ]; do
    # Check webConfigurator: fetch https://127.0.0.1/ on-box (port 443).
    # fetch(1) is the FreeBSD/pfSense http client available on all pfSense versions.
    if ssh_guest 'fetch -qT 15 --no-verify-peer --no-verify-hostname -o /dev/null https://127.0.0.1/ 2>/dev/null' 2>/dev/null; then
        log "health gate PASS: webConfigurator answered HTTP"
        _hg_healthy=1
        break
    fi
    # Fallback: check pfctl for a live ruleset.
    _pf_rules=$(ssh_guest '/sbin/pfctl -sr' 2>/dev/null | grep -c '.' || true)
    if [ "${_pf_rules:-0}" -gt 0 ]; then
        log "health gate PASS: pfctl shows ${_pf_rules} live rules"
        _hg_healthy=1
        break
    fi
    sleep 10; _hg_elapsed=$((_hg_elapsed + 10))
done
[ "$_hg_healthy" -eq 1 ] || die "upgraded box did not become healthy within ${HEALTH_TIMEOUT}s (webConfigurator and pfctl both failed; see $LOCAL_DIR/upgrade.log)"

# --- power off cleanly -----------------------------------------------------
log "shutting the box down"
ssh_guest '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while px "kill -0 $QPID 2>/dev/null"; do
    if [ "$_elapsed" -ge 120 ]; then
        warn "QEMU still up 120s after poweroff; killing"
        px "kill $QPID 2>/dev/null" || true
        break
    fi
    sleep 3; _elapsed=$((_elapsed + 3))
done
QPID=""

# --- publish the new version (old tag kept) --------------------------------
# Tag: explicit --to wins; otherwise the major.minor of the detected new version
# (2.9.0 -> 2.9, 26.05.1 -> 26.05). Description defaults to the same "<edition>
# <tag>" wording image-publish.sh emits, so the artifacts match exactly.
TAG="${TO:-$(image_version_tag "$NEW_VER")}"
[ -n "$TAG" ] || die "could not determine target tag"
[ -n "$DESCRIPTION" ] || DESCRIPTION="${IMG_DESC} ${TAG}"
QCOW_NAME="${IMG_PRETTY}_${TAG}.qcow2"

if [ "$FORCE" -eq 0 ] && oras manifest fetch "${IMAGE}:${TAG}" >/dev/null 2>&1; then
    die "tag ${IMAGE}:${TAG} already exists (use --force). The source tag ${FROM} is kept regardless."
fi

# Compress on the KVM host (native qemu-img), then stream the smaller result back.
log "compressing upgraded image on the KVM host (compression: $COMPRESSION)"
case "$COMPRESSION" in
    zstd)
        px "qemu-img convert -O qcow2 -c -o compression_type=zstd '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" || {
            warn "zstd unsupported; falling back to zlib"
            px "qemu-img convert -O qcow2 -c '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'"
        } ;;
    zlib) px "qemu-img convert -O qcow2 -c '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" ;;
    off)  px "qemu-img convert -O qcow2 '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" ;;
esac

OUT="$LOCAL_DIR/${QCOW_NAME}"
log "streaming upgraded image back -> $(basename "$OUT")"
px "cat '$REMOTE_DIR/out.qcow2'" > "$OUT"
[ -s "$OUT" ] || die "streamed upgraded image is empty: $OUT"

log "pushing ${IMAGE}:${TAG} (local oras)"
# Shared push — identical to image-publish.sh --type ${TYPE} ${TAG} (same image
# ref, qcow2 title, description and artifact-type).
image_oci_push "$OUT" "$IMAGE" "$TAG" "$ARTIFACT_TYPE" "$DESCRIPTION" "$QCOW_NAME"

log "done. ${IMAGE}:${TAG} published; ${IMAGE}:${FROM} kept."
