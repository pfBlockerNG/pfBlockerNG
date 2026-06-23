#!/bin/sh
# image-publish.sh — export a Proxmox VM's disk to a compressed qcow2 and
# publish it to GHCR as the pfSense CE smoke-test base image (ADR-04, Phase 2).
#
# Drive it FROM YOUR MACHINE: pass the Proxmox SSH coordinates and the script
# runs the native steps (qm/pvesm/qemu-img — all shipped with Proxmox VE) over
# SSH, streams the finished qcow2 back, and pushes to GHCR with a LOCAL `oras`.
# Nothing extra needs installing on the Proxmox host. Omit --proxmox to run the
# whole thing locally (i.e. directly on the Proxmox host), as before.
#
# The VM MUST be powered off — a live disk export is inconsistent.
#
# This is the "maintainer-provided qcow2, wholesale" path: no Packer. Each call
# publishes one version tag; older tags are left untouched (kept).
#
# Usage:
#   ./scripts/image-publish.sh <pfsense-ce-version> [options]
#
# Examples:
#   ./scripts/image-publish.sh 2.8.1 --proxmox root@pve.lan
#   ./scripts/image-publish.sh 2.8.1 --proxmox pve.lan --proxmox-port 2222 --vmid 103
#   ./scripts/image-publish.sh 2.8.1            # run locally, on the Proxmox host
#   # a non-pfSense image (e.g. the smoke client VM):
#   ./scripts/image-publish.sh v1 --vmid 104 --image ghcr.io/pfblockerng/civm \
#       --artifact-type application/vnd.pfblockerng.smoke-client.disk.v1 \
#       --description "pfBlockerNG smoke client VM v1"
#   # just print the VM's NIC MACs + SMBIOS UUID (no export/push):
#   ./scripts/image-publish.sh --vmid 104 --print-identity
#
# Proxmox connection (where the disk lives):
#   --proxmox [USER@]HOST   SSH target of the Proxmox host. If omitted (and
#                           PROXMOX_SSH_HOST is unset), runs locally.
#   --proxmox-port N        SSH port           (default: $PROXMOX_SSH_PORT or 22)
#   --proxmox-ssh-key PATH  SSH private key     (default: $PROXMOX_SSH_KEY)
#   --remote-tmpdir DIR     scratch dir on Proxmox for the qcow2 (it can be a few
#                           GB) (default: $PROXMOX_TMPDIR or /tmp)
#   USER defaults to $PROXMOX_SSH_USER or root.
#
# Options:
#   --vmid N         Proxmox VM id (default: 103)
#   --disk KEY       disk config key to export (default: scsi0)
#   --image REF      GHCR image ref without tag (default composed from the
#                    SMOKE_IMAGE_REPO + SMOKE_IMAGE_NAME env vars:
#                    ${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}/${SMOKE_IMAGE_NAME:-pfsense-ce})
#   --compression T  qcow2 compression: zstd | zlib | off (default: zstd)
#   --out FILE       local working qcow2 path (default: a temp file, removed after)
#   --keep           keep the local qcow2 after publishing
#   --force          overwrite the tag if it already exists
#   --artifact-type T  OCI artifact-type annotation (default: the pfSense CE type)
#   --description D    OCI image-description annotation (default: pfSense CE wording)
#   --print-identity   print every NIC's MAC + the SMBIOS UUID from the VM config,
#                      then exit (no export/push). <version> is not required.
#
# Auth: be logged in to GHCR (`oras login ghcr.io -u USER -p TOKEN`), or export
# SMOKE_GHCR_USER + SMOKE_GHCR_TOKEN to have this script log in for you. The
# token needs `write:packages`. `oras` runs locally — no GHCR creds on Proxmox.

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

VMID=103
DISK=scsi0
# Compose the untagged image ref from the namespace + name vars (org-transfer
# scheme; supports pfsense-ce, pfsense-plus, … under one namespace). --image overrides.
IMAGE="${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}"
IMAGE="${IMAGE%/}/${SMOKE_IMAGE_NAME:-pfsense-ce}"
COMPRESSION=zstd
OUT=""
KEEP=0
FORCE=0
VERSION=""
PRINT_IDENTITY=0
# Default OCI annotations describe the pfSense CE base image. Shared with
# image-upgrade.sh + IMAGE_RUNBOOK.md — keep this default in sync there.
ARTIFACT_TYPE="application/vnd.netgate.pfsense-ce.disk.v1"
DESCRIPTION=""

# Proxmox SSH coordinates (env fallbacks; --proxmox overrides).
PX_HOST="${PROXMOX_SSH_HOST:-}"
PX_USER="${PROXMOX_SSH_USER:-root}"
PX_PORT="${PROXMOX_SSH_PORT:-22}"
PX_KEY="${PROXMOX_SSH_KEY:-}"
REMOTE_TMPDIR="${PROXMOX_TMPDIR:-/tmp}"

while [ $# -gt 0 ]; do
    case "$1" in
        --proxmox)         PX_TARGET="$2"; shift 2 ;;
        --proxmox-port)    PX_PORT="$2"; shift 2 ;;
        --proxmox-ssh-key) PX_KEY="$2"; shift 2 ;;
        --remote-tmpdir)   REMOTE_TMPDIR="$2"; shift 2 ;;
        --vmid)            VMID="$2"; shift 2 ;;
        --disk)            DISK="$2"; shift 2 ;;
        --image)           IMAGE="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --out)             OUT="$2"; shift 2 ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        --artifact-type)   ARTIFACT_TYPE="$2"; shift 2 ;;
        --description)     DESCRIPTION="$2"; shift 2 ;;
        --print-identity)  PRINT_IDENTITY=1; shift ;;
        -h|--help)         sed -n '2,56p' "$0"; exit 0 ;;
        -*)                die "unknown option: $1" ;;
        *)
            [ -z "$VERSION" ] || die "unexpected argument: $1"
            VERSION="$1"; shift ;;
    esac
done

# --proxmox [USER@]HOST splits an optional user from the host.
if [ -n "${PX_TARGET:-}" ]; then
    case "$PX_TARGET" in
        *@*) PX_USER="${PX_TARGET%@*}"; PX_HOST="${PX_TARGET#*@}" ;;
        *)   PX_HOST="$PX_TARGET" ;;
    esac
fi

# --print-identity needs only a VM id; a version tag is required for a real publish.
[ "$PRINT_IDENTITY" -eq 1 ] || [ -n "$VERSION" ] || die "missing <pfsense-ce-version> (e.g. 2.8.1); or use --print-identity"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

# Remote when a Proxmox host is given, else everything runs locally.
PX_REMOTE=0
[ -n "$PX_HOST" ] && PX_REMOTE=1

# ssh option words (intentionally unquoted at use; no spaces in port/key).
PX_PORT_OPT=""; [ -n "$PX_PORT" ] && PX_PORT_OPT="-p $PX_PORT"
PX_KEY_OPT="";  [ -n "$PX_KEY" ]  && PX_KEY_OPT="-i $PX_KEY"

# px CMD — run CMD on the Proxmox host (over SSH, or locally). stdin/stdout pass
# through, so it streams (e.g.  px "cat file" > local  and  ... | px "cat > f").
px() {
    if [ "$PX_REMOTE" -eq 1 ]; then
        # shellcheck disable=SC2086
        ssh -o BatchMode=yes -o ConnectTimeout=10 $PX_PORT_OPT $PX_KEY_OPT \
            "${PX_USER}@${PX_HOST}" "$1"
    else
        sh -c "$1"
    fi
}

# print_vm_identity QMCFG — print every NIC's MAC + the SMBIOS UUID from a
# `qm config <vmid>` dump. These feed the fixed-MAC-series + SMBIOS-UUID secrets
# that keep the Netgate Device ID (Plus licensing) constant across re-publishes.
print_vm_identity() {
    log "VM $VMID identity (capture for your MAC-series + SMBIOS UUID secrets):"
    printf '%s\n' "$1" | grep -E '^net[0-9]+:' | sort -V | while IFS= read -r line; do
        ifc=${line%%:*}
        mac=$(printf '%s\n' "$line" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
        printf '    %s  MAC %s\n' "$ifc" "$mac"
    done
    uuid=$(printf '%s\n' "$1" | sed -n 's/^smbios1:.*uuid=\([0-9A-Fa-f-]*\).*/\1/p' | head -1)
    printf '    SMBIOS UUID: %s\n' "${uuid:-<not set in VM config>}"
}

# Local tooling: oras for a real publish; ssh only when driving a remote host.
[ "$PRINT_IDENTITY" -eq 1 ] || command -v oras >/dev/null 2>&1 || die "required local tool not found: oras"
if [ "$PX_REMOTE" -eq 1 ]; then
    command -v ssh >/dev/null 2>&1 || die "required local tool not found: ssh"
    log "Proxmox host: ${PX_USER}@${PX_HOST}${PX_PORT:+:$PX_PORT} (native steps run there over SSH)"
else
    log "running locally (assuming this IS the Proxmox host)"
fi

# Proxmox-side tooling (all native to Proxmox VE — nothing to install). A real
# publish needs the full export chain; --print-identity only reads `qm config`.
if [ "$PRINT_IDENTITY" -eq 1 ]; then
    px "command -v qm >/dev/null 2>&1" || die "tool not found on Proxmox host: qm"
else
    for bin in qm pvesm qemu-img; do
        px "command -v $bin >/dev/null 2>&1" || die "tool not found on Proxmox host: $bin"
    done
fi

# Read the VM config once — both --print-identity and the VOLID resolve use it.
QMCFG=$(px "qm config $VMID") || die "could not read 'qm config $VMID'"

if [ "$PRINT_IDENTITY" -eq 1 ]; then
    print_vm_identity "$QMCFG"
    exit 0
fi

# Optional non-interactive GHCR login (local oras).
if [ -n "${SMOKE_GHCR_TOKEN:-}" ] && [ -n "${SMOKE_GHCR_USER:-}" ]; then
    log "logging in to ghcr.io as $SMOKE_GHCR_USER"
    printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ghcr.io -u "$SMOKE_GHCR_USER" --password-stdin
fi

# Refuse to clobber an existing tag unless --force (old tags are kept).
if [ "$FORCE" -eq 0 ] && oras manifest fetch "${IMAGE}:${VERSION}" >/dev/null 2>&1; then
    die "tag ${IMAGE}:${VERSION} already exists (use --force to overwrite). Older versions stay under their own tags."
fi

# The VM must be off so the on-disk filesystem is consistent.
if ! px "qm status $VMID 2>/dev/null" | grep -q 'status: stopped'; then
    die "VM $VMID is not stopped. Power it off first: qm stop $VMID"
fi

# Resolve the disk's backing device (e.g. /dev/zvol/rpool/data/vm-103-disk-1).
VOLID=$(printf '%s\n' "$QMCFG" | sed -n "s/^${DISK}: \\([^,]*\\).*/\\1/p")
[ -n "$VOLID" ] || die "disk '$DISK' not found in VM $VMID config"
DEV=$(px "pvesm path '$VOLID'")
[ -n "$DEV" ] || die "could not resolve a device for $VOLID"
px "test -e '$DEV'" || die "resolved device does not exist on Proxmox: $DEV"
log "source: VM $VMID $DISK -> $VOLID -> $DEV"

# Informational: surface the NIC MACs + SMBIOS UUID so a re-publish can confirm
# the VM identity (Netgate Device ID inputs) is unchanged.
print_vm_identity "$QMCFG"

# Local output path for the streamed-back qcow2.
CREATED_OUT=0
if [ -z "$OUT" ]; then
    OUT="${TMPDIR:-/tmp}/pfSense-CE-${VERSION}.qcow2"
    CREATED_OUT=1
fi
rm -f "$OUT"

# Remote temp the conversion writes to (then streamed back, then removed).
px "mkdir -p '$REMOTE_TMPDIR'" || die "cannot create remote tmpdir on Proxmox: $REMOTE_TMPDIR"
REMOTE_TMP="${REMOTE_TMPDIR%/}/pfb-publish-${VERSION}.$$.qcow2"

cleanup() {
    px "rm -f '$REMOTE_TMP'" >/dev/null 2>&1 || true
    if [ "$KEEP" -eq 0 ] && [ "$CREATED_OUT" -eq 1 ]; then
        rm -f "$OUT"
    fi
}
trap cleanup EXIT INT TERM

# Convert ON the Proxmox host (native qemu-img); compression happens there too,
# so the stream back to this machine is already the compressed image.
log "converting on Proxmox -> $REMOTE_TMP (compression: $COMPRESSION)"
case "$COMPRESSION" in
    zstd)
        px "qemu-img convert -f raw -O qcow2 -c -o compression_type=zstd '$DEV' '$REMOTE_TMP'" || {
            warn "zstd compression unsupported by this qemu-img; falling back to zlib"
            px "qemu-img convert -f raw -O qcow2 -c '$DEV' '$REMOTE_TMP'"
        } ;;
    zlib) px "qemu-img convert -f raw -O qcow2 -c '$DEV' '$REMOTE_TMP'" ;;
    off)  px "qemu-img convert -f raw -O qcow2 '$DEV' '$REMOTE_TMP'" ;;
esac

log "streaming image back -> $OUT"
px "cat '$REMOTE_TMP'" > "$OUT"
[ -s "$OUT" ] || die "streamed image is empty: $OUT"
log "local image: $(qemu-img info --output=human "$OUT" 2>/dev/null | sed -n 's/^disk size: /qcow2 size /p' || echo "$(wc -c < "$OUT") bytes")"

# Default the description to the pfSense CE wording unless overridden.
[ -n "$DESCRIPTION" ] || DESCRIPTION="pfSense CE ${VERSION} pfBlockerNG smoke-test base"

log "pushing ${IMAGE}:${VERSION}"
# cd so the stored layer title is the bare filename (predictable on pull).
(
    cd "$(dirname "$OUT")"
    oras push \
        --artifact-type "$ARTIFACT_TYPE" \
        --annotation "org.opencontainers.image.title=$(basename "$OUT")" \
        --annotation "org.opencontainers.image.version=${VERSION}" \
        --annotation "org.opencontainers.image.description=${DESCRIPTION}" \
        "${IMAGE}:${VERSION}" \
        "$(basename "$OUT"):application/vnd.qemu.qcow2"
)

if [ "$KEEP" -eq 1 ] || [ "$CREATED_OUT" -eq 0 ]; then
    log "local image kept at: $OUT"
fi

log "done. Pull with:  oras pull ${IMAGE}:${VERSION}"
log "Pin by digest in CI:  oras manifest fetch --descriptor ${IMAGE}:${VERSION}"
