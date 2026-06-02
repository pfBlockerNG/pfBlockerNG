#!/bin/sh
# image-upgrade.sh — upgrade the published pfSense CE smoke base to a new CE
# release and publish the result as a new tag (ADR-04, Phase 2 "upgrade in place").
#
# Flow: pull the current image from GHCR -> boot it under QEMU/KVM (read-write,
# with internet) -> run pfSense-upgrade over SSH -> wait for it to finish and
# reboot -> power off cleanly -> compress -> push the new version tag. The source
# tag is left untouched, so the old image is always kept.
#
# Run on a host with KVM (the Proxmox host qualifies). Needs the SSH PRIVATE key
# whose public half is baked into the image's root authorized_keys.
#
# Usage:
#   ./scripts/image-upgrade.sh --from <current-version> [options]
#
# Examples:
#   ./scripts/image-upgrade.sh --from 2.8.1 --ssh-key ~/.ssh/smoke_ed25519
#   ./scripts/image-upgrade.sh --from 2.8.1 --to 2.8.2 --force
#
# Options:
#   --from VERSION   current published tag to upgrade (required)
#   --to VERSION     tag to publish as (default: auto-detected from the upgraded box)
#   --image REF      GHCR image ref without tag
#                    (default: $SMOKE_IMAGE or ghcr.io/andrebrait/pfsense-ce)
#   --ssh-key PATH   SSH private key (default: $SMOKE_SSH_KEY)
#   --ssh-port N     host port forwarded to the guest's :22 (default: 2222)
#   --mac ADDR       guest NIC MAC (default: BC:24:11:37:9C:AC — must match the image)
#   --compression T  qcow2 compression for the published image: zstd|zlib|off (default: zstd)
#   --upgrade-timeout S  seconds to wait for the upgrade+reboot (default: 1800)
#   --keep           keep the work dir (image copies, console log) afterwards
#   --force          overwrite the target tag if it already exists
#
# Auth: as in image-publish.sh (oras login, or SMOKE_GHCR_USER/SMOKE_GHCR_TOKEN).

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

FROM=""
TO=""
IMAGE="${SMOKE_IMAGE:-ghcr.io/andrebrait/pfsense-ce}"
SSH_KEY="${SMOKE_SSH_KEY:-}"
SSH_PORT=2222
MAC="BC:24:11:37:9C:AC"
COMPRESSION=zstd
UPGRADE_TIMEOUT=1800
KEEP=0
FORCE=0

# The non-interactive pfSense upgrade command. NOTE: confirm the exact flags for
# the running CE release during the Phase-1 spike (ADR-04 §6 flags this) — `yes |`
# is a hedge against any interactive prompt; the version-poll below detects the
# real completion regardless of how it reboots.
UPGRADE_CMD='yes | /usr/local/sbin/pfSense-upgrade -d'

while [ $# -gt 0 ]; do
    case "$1" in
        --from)            FROM="$2"; shift 2 ;;
        --to)              TO="$2"; shift 2 ;;
        --image)           IMAGE="$2"; shift 2 ;;
        --ssh-key)         SSH_KEY="$2"; shift 2 ;;
        --ssh-port)        SSH_PORT="$2"; shift 2 ;;
        --mac)             MAC="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --upgrade-timeout) UPGRADE_TIMEOUT="$2"; shift 2 ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        -h|--help)         sed -n '2,40p' "$0"; exit 0 ;;
        *)                 die "unknown option: $1" ;;
    esac
done

[ -n "$FROM" ] || die "missing --from <current-version>"
[ -n "$SSH_KEY" ] || die "missing --ssh-key (or set SMOKE_SSH_KEY)"
[ -f "$SSH_KEY" ] || die "ssh key not found: $SSH_KEY"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

for bin in oras qemu-img qemu-system-x86_64 ssh; do
    command -v "$bin" >/dev/null 2>&1 || die "required tool not found: $bin"
done
[ -e /dev/kvm ] || warn "/dev/kvm not present — the guest will be very slow under TCG"

if [ -n "${SMOKE_GHCR_TOKEN:-}" ] && [ -n "${SMOKE_GHCR_USER:-}" ]; then
    log "logging in to ghcr.io as $SMOKE_GHCR_USER"
    printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ghcr.io -u "$SMOKE_GHCR_USER" --password-stdin
fi

WORKDIR=$(mktemp -d)
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        warn "killing leftover QEMU (pid $QEMU_PID)"
        kill "$QEMU_PID" 2>/dev/null || true
    fi
    if [ "$KEEP" -eq 0 ]; then
        rm -rf "$WORKDIR"
    else
        log "work dir kept: $WORKDIR"
    fi
}
trap cleanup EXIT INT TERM

ssh_guest() {
    ssh -p "$SSH_PORT" -i "$SSH_KEY" \
        -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        root@127.0.0.1 "$@"
}

# --- pull current image ----------------------------------------------------
log "pulling ${IMAGE}:${FROM}"
oras pull "${IMAGE}:${FROM}" -o "$WORKDIR"
BASE=$(find "$WORKDIR" -maxdepth 1 -name '*.qcow2' | head -n1)
[ -n "$BASE" ] || die "no qcow2 found in pulled artifact ${IMAGE}:${FROM}"

# Writable working copy — the upgrade runs on THIS, never on the pulled base,
# so the source image (and its GHCR tag) is never modified.
WORK="$WORKDIR/work.qcow2"
log "preparing writable working copy (source image stays untouched)"
qemu-img convert -O qcow2 "$BASE" "$WORK"

# --- boot under QEMU (internet ON for the upgrade) -------------------------
log "booting VM (SSH on 127.0.0.1:$SSH_PORT)"
qemu-system-x86_64 \
    -enable-kvm -machine pc -cpu host \
    -smp 2,sockets=1,cores=2 -m 4096 \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive file="$WORK",if=none,id=drive-scsi0,format=qcow2,discard=unmap,detect-zeroes=unmap \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev user,id=net0,hostfwd=tcp::"$SSH_PORT"-:22 \
    -device virtio-net-pci,mac="$MAC",netdev=net0,id=net0 \
    -display none -serial "file:$WORKDIR/console.log" \
    -pidfile "$WORKDIR/qemu.pid" -daemonize
QEMU_PID=$(cat "$WORKDIR/qemu.pid")

log "waiting for SSH..."
_elapsed=0
while ! ssh_guest true 2>/dev/null; do
    [ "$_elapsed" -ge 300 ] && die "VM did not answer SSH within 300s (see $WORKDIR/console.log)"
    sleep 5; _elapsed=$((_elapsed + 5))
done

OLD_VER=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r')
log "current version on box: ${OLD_VER:-unknown}"

# --- run the upgrade -------------------------------------------------------
log "running pfSense upgrade (this reboots the box; up to ${UPGRADE_TIMEOUT}s)"
# Connection will drop when the box reboots — that is expected, so ignore it.
ssh_guest "$UPGRADE_CMD" 2>&1 | tee "$WORKDIR/upgrade.log" || true

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
[ -n "$NEW_VER" ] || die "version did not change within ${UPGRADE_TIMEOUT}s (still '${OLD_VER}'; see $WORKDIR/upgrade.log)"
log "upgraded: ${OLD_VER} -> ${NEW_VER}"

# --- power off cleanly -----------------------------------------------------
log "shutting the box down"
ssh_guest '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if [ "$_elapsed" -ge 120 ]; then
        warn "QEMU still up 120s after poweroff; killing"
        kill "$QEMU_PID" 2>/dev/null || true
        break
    fi
    sleep 3; _elapsed=$((_elapsed + 3))
done
QEMU_PID=""

# --- publish the new version (old tag kept) --------------------------------
TAG="${TO:-$(printf '%s' "$NEW_VER" | sed 's/-RELEASE$//')}"
[ -n "$TAG" ] || die "could not determine target tag"

if [ "$FORCE" -eq 0 ] && oras manifest fetch "${IMAGE}:${TAG}" >/dev/null 2>&1; then
    die "tag ${IMAGE}:${TAG} already exists (use --force). The source tag ${FROM} is kept regardless."
fi

OUT="$WORKDIR/pfSense-CE-${TAG}.qcow2"
log "compressing upgraded image -> $(basename "$OUT") (compression: $COMPRESSION)"
if [ "$COMPRESSION" = zstd ]; then
    if ! qemu-img convert -p -O qcow2 -c -o compression_type=zstd "$WORK" "$OUT"; then
        warn "zstd unsupported; falling back to zlib"
        qemu-img convert -p -O qcow2 -c "$WORK" "$OUT"
    fi
elif [ "$COMPRESSION" = zlib ]; then
    qemu-img convert -p -O qcow2 -c "$WORK" "$OUT"
else
    qemu-img convert -p -O qcow2 "$WORK" "$OUT"
fi

log "pushing ${IMAGE}:${TAG}"
(
    cd "$WORKDIR"
    oras push \
        --artifact-type application/vnd.netgate.pfsense-ce.disk.v1 \
        --annotation "org.opencontainers.image.title=$(basename "$OUT")" \
        --annotation "org.opencontainers.image.version=${TAG}" \
        --annotation "org.opencontainers.image.description=pfSense CE ${TAG} pfBlockerNG smoke-test base (upgraded from ${FROM})" \
        "${IMAGE}:${TAG}" \
        "$(basename "$OUT"):application/vnd.qemu.qcow2"
)

log "done. ${IMAGE}:${TAG} published; ${IMAGE}:${FROM} kept."
