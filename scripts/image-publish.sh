#!/bin/sh
# image-publish.sh — export a Proxmox VM's disk to a compressed qcow2 and
# publish it to GHCR as the pfSense CE smoke-test base image (ADR-04, Phase 2).
#
# Run this ON THE PROXMOX HOST: it reads the VM's disk via pvesm/qemu-img.
# The VM MUST be powered off — a live disk export is inconsistent.
#
# This is the "maintainer-provided qcow2, wholesale" path: no Packer. Each call
# publishes one version tag; older tags are left untouched (kept).
#
# Usage:
#   ./scripts/image-publish.sh <pfsense-ce-version> [options]
#
# Examples:
#   ./scripts/image-publish.sh 2.8.1
#   ./scripts/image-publish.sh 2.8.1 --vmid 103 --disk scsi0 --force
#
# Options:
#   --vmid N         Proxmox VM id (default: 103)
#   --disk KEY       disk config key to export (default: scsi0)
#   --image REF      GHCR image ref without tag
#                    (default: $SMOKE_IMAGE or ghcr.io/andrebrait/pfsense-ce)
#   --compression T  qcow2 compression: zstd | zlib | off (default: zstd)
#   --out FILE       working qcow2 path (default: a temp file, removed after)
#   --keep           keep the local qcow2 after publishing
#   --force          overwrite the tag if it already exists
#
# Auth: be logged in to GHCR (`oras login ghcr.io -u USER -p TOKEN`), or export
# SMOKE_GHCR_USER + SMOKE_GHCR_TOKEN to have this script log in for you. The
# token needs `write:packages`.

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

VMID=103
DISK=scsi0
IMAGE="${SMOKE_IMAGE:-ghcr.io/andrebrait/pfsense-ce}"
COMPRESSION=zstd
OUT=""
KEEP=0
FORCE=0
VERSION=""

while [ $# -gt 0 ]; do
    case "$1" in
        --vmid)        VMID="$2"; shift 2 ;;
        --disk)        DISK="$2"; shift 2 ;;
        --image)       IMAGE="$2"; shift 2 ;;
        --compression) COMPRESSION="$2"; shift 2 ;;
        --out)         OUT="$2"; shift 2 ;;
        --keep)        KEEP=1; shift ;;
        --force)       FORCE=1; shift ;;
        -h|--help)     sed -n '2,32p' "$0"; exit 0 ;;
        -*)            die "unknown option: $1" ;;
        *)
            [ -z "$VERSION" ] || die "unexpected argument: $1"
            VERSION="$1"; shift ;;
    esac
done

[ -n "$VERSION" ] || die "missing <pfsense-ce-version> (e.g. 2.8.1)"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

for bin in qm pvesm qemu-img oras; do
    command -v "$bin" >/dev/null 2>&1 || die "required tool not found: $bin"
done

# Optional non-interactive GHCR login.
if [ -n "${SMOKE_GHCR_TOKEN:-}" ] && [ -n "${SMOKE_GHCR_USER:-}" ]; then
    log "logging in to ghcr.io as $SMOKE_GHCR_USER"
    printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ghcr.io -u "$SMOKE_GHCR_USER" --password-stdin
fi

# The VM must be off so the on-disk filesystem is consistent.
if ! qm status "$VMID" 2>/dev/null | grep -q 'status: stopped'; then
    die "VM $VMID is not stopped. Power it off first: qm stop $VMID"
fi

# Resolve the disk's backing device (e.g. /dev/zvol/rpool/data/vm-103-disk-1).
VOLID=$(qm config "$VMID" | sed -n "s/^${DISK}: \\([^,]*\\).*/\\1/p")
[ -n "$VOLID" ] || die "disk '$DISK' not found in VM $VMID config"
DEV=$(pvesm path "$VOLID")
[ -e "$DEV" ] || die "resolved device does not exist: $DEV"
log "source: VM $VMID $DISK -> $VOLID -> $DEV"

# Refuse to clobber an existing tag unless --force (old tags are kept).
if [ "$FORCE" -eq 0 ] && oras manifest fetch "${IMAGE}:${VERSION}" >/dev/null 2>&1; then
    die "tag ${IMAGE}:${VERSION} already exists (use --force to overwrite). Older versions stay under their own tags."
fi

CREATED_OUT=0
if [ -z "$OUT" ]; then
    OUT="${TMPDIR:-/tmp}/pfSense-CE-${VERSION}.qcow2"
    CREATED_OUT=1
fi
rm -f "$OUT"

log "exporting -> $OUT (compression: $COMPRESSION)"
if [ "$COMPRESSION" = zstd ]; then
    if ! qemu-img convert -p -f raw -O qcow2 -c -o compression_type=zstd "$DEV" "$OUT"; then
        warn "zstd compression unsupported by this qemu-img; falling back to zlib"
        qemu-img convert -p -f raw -O qcow2 -c "$DEV" "$OUT"
    fi
elif [ "$COMPRESSION" = zlib ]; then
    qemu-img convert -p -f raw -O qcow2 -c "$DEV" "$OUT"
else
    qemu-img convert -p -f raw -O qcow2 "$DEV" "$OUT"
fi
log "exported: $(qemu-img info --output=human "$OUT" | sed -n 's/^disk size: /qcow2 size /p')"

log "pushing ${IMAGE}:${VERSION}"
# cd so the stored layer title is the bare filename (predictable on pull).
(
    cd "$(dirname "$OUT")"
    oras push \
        --artifact-type application/vnd.netgate.pfsense-ce.disk.v1 \
        --annotation "org.opencontainers.image.title=$(basename "$OUT")" \
        --annotation "org.opencontainers.image.version=${VERSION}" \
        --annotation "org.opencontainers.image.description=pfSense CE ${VERSION} pfBlockerNG smoke-test base" \
        "${IMAGE}:${VERSION}" \
        "$(basename "$OUT"):application/vnd.qemu.qcow2"
)

if [ "$KEEP" -eq 0 ] && [ "$CREATED_OUT" -eq 1 ]; then
    rm -f "$OUT"
else
    log "local image kept at: $OUT"
fi

log "done. Pull with:  oras pull ${IMAGE}:${VERSION}"
log "Pin by digest in CI:  oras manifest fetch --descriptor ${IMAGE}:${VERSION}"
