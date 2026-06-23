#!/bin/sh
# image-publish.sh — export a Proxmox VM's disk to a compressed qcow2 and
# publish it to GHCR as a pfBlockerNG smoke-test base image (ADR-04, Phase 2).
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
# IMAGE TYPE (--type) — the easy path for the three real images. Pass --type and
# everything else (image name, qcow2 filename, description, artifact-type) is
# DERIVED from the type + version, so the common publish is just:
#
#       ./scripts/image-publish.sh <version> --type ce   --vmid 103 [--proxmox …]
#       ./scripts/image-publish.sh <version> --type plus --vmid 103 [--proxmox …]
#       ./scripts/image-publish.sh <version> --type civm --vmid 104 [--proxmox …]
#
#   type   image ref                          qcow2 / OCI title      description
#   ----   --------------------------------   --------------------   ------------------------------
#   ce     ghcr.io/pfblockerng/pfsense-ce     pfSense-CE_<v>.qcow2    pfSense CE <v>
#   plus   ghcr.io/pfblockerng/pfsense-plus   pfSense-Plus_<v>.qcow2  pfSense Plus <v>
#   civm   ghcr.io/pfblockerng/civm           civm_<v>.qcow2          pfBlockerNG smoke client VM <v>
#
# Without --type there are NO image-shaped defaults: --image, --description and
# --artifact-type are all REQUIRED (the script will not guess them). The
# tag/version is always a positional argument. The registry namespace defaults
# to ghcr.io/pfblockerng (override with SMOKE_IMAGE_REPO or --registry).
#
# For the friendly interactive front-end that only asks the few things that
# change, use scripts/publish-smoke-image.sh.
#
# Usage:
#   ./scripts/image-publish.sh <version> --type <ce|plus|civm> [options]
#   ./scripts/image-publish.sh <version> --image REF --description D \
#                              --artifact-type T [options]      # custom image
#
# Examples:
#   ./scripts/image-publish.sh 2.8.1 --type ce --proxmox root@pve.lan
#   ./scripts/image-publish.sh 2.8.1 --type ce --proxmox pve.lan --proxmox-port 2222 --vmid 103
#   ./scripts/image-publish.sh 2.8.1 --type ce          # run locally, on the Proxmox host
#   ./scripts/image-publish.sh v1    --type civm --vmid 104
#   # a fully-custom image (every image field explicit, no --type):
#   ./scripts/image-publish.sh v1 --vmid 104 --image ghcr.io/pfblockerng/other \
#       --artifact-type application/vnd.example.disk.v1 --description "Some image v1"
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
#   --type T         image type: ce | plus | civm. Derives --image, the qcow2
#                    filename, --description and --artifact-type from T + version.
#   --vmid N         Proxmox VM id (default by --type: ce 103, plus 104, civm 105;
#                    103 when no --type)
#   --disk KEY       disk config key to export (default: scsi0)
#   --registry REF   GHCR namespace for the derived --type ref (default:
#                    $SMOKE_IMAGE_REPO or ghcr.io/pfblockerng)
#   --image REF      GHCR image ref WITHOUT tag. Required unless --type is given;
#                    overrides the --type-derived ref when both are present.
#   --compression T  qcow2 compression: zstd | zlib | off (default: zstd)
#   --out FILE       local working qcow2 path (default: a temp file named from
#                    the type/image, removed after)
#   --keep           keep the local qcow2 after publishing
#   --force          overwrite the tag if it already exists
#   --artifact-type T  OCI artifact-type annotation. Required unless --type
#                      derives it; overrides the derived value when present.
#   --description D    OCI image-description annotation. Required unless --type is
#                      given; overrides the derived value when present.
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

# VM id default is per --type (ce 103, plus 104, civm 105; else 103) — applied
# after --type is known, unless --vmid was given. Empty here = "not set".
VMID=""
DISK=scsi0
# Registry NAMESPACE only (no hard-coded image name). The image name comes from
# --type (derived) or --image (explicit) — never from an environment variable.
REGISTRY="${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}"
TYPE=""
IMAGE=""
COMPRESSION=zstd
OUT=""
KEEP=0
FORCE=0
VERSION=""
PRINT_IDENTITY=0
# NO image-shaped defaults: these are derived from --type, or required explicitly.
ARTIFACT_TYPE=""
DESCRIPTION=""
# Derived qcow2 basename (the OCI layer title); set from --type / --image / --out.
QCOW_NAME=""

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
        --type)            TYPE="$2"; shift 2 ;;
        --vmid)            VMID="$2"; shift 2 ;;
        --disk)            DISK="$2"; shift 2 ;;
        --registry)        REGISTRY="$2"; shift 2 ;;
        --image)           IMAGE="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --out)             OUT="$2"; shift 2 ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        --artifact-type)   ARTIFACT_TYPE="$2"; shift 2 ;;
        --description)     DESCRIPTION="$2"; shift 2 ;;
        --print-identity)  PRINT_IDENTITY=1; shift ;;
        -h|--help)         sed -n '2,87p' "$0"; exit 0 ;;
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
[ "$PRINT_IDENTITY" -eq 1 ] || [ -n "$VERSION" ] || die "missing <version> (e.g. 2.8.1, or v1 for civm); or use --print-identity"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

# ---------------------------------------------------------------------------
# Derive the image-shaped fields from --type (ce|plus|civm), unless overridden.
# Every field a real publish needs (image ref, qcow2 filename, description,
# artifact-type) comes from here for the three common images. An explicit flag
# always wins over the derived value. Without --type there is NO default — the
# fields are required and validated below.
# ---------------------------------------------------------------------------
if [ -n "$TYPE" ]; then
    case "$TYPE" in
        ce)   _name=pfsense-ce;   _pretty=pfSense-CE;   _desc="pfSense CE";                 _atype="application/vnd.netgate.pfsense-ce.disk.v1";        _vmid=103 ;;
        plus) _name=pfsense-plus; _pretty=pfSense-Plus; _desc="pfSense Plus";               _atype="application/vnd.netgate.pfsense-plus.disk.v1";      _vmid=104 ;;
        civm) _name=civm;         _pretty=civm;         _desc="pfBlockerNG smoke client VM"; _atype="application/vnd.pfblockerng.smoke-client.disk.v1";  _vmid=105 ;;
        *)    die "--type must be ce|plus|civm (got '$TYPE')" ;;
    esac
    [ -n "$IMAGE" ]         || IMAGE="${REGISTRY%/}/${_name}"
    [ -n "$DESCRIPTION" ]   || DESCRIPTION="${_desc} ${VERSION}"
    [ -n "$ARTIFACT_TYPE" ] || ARTIFACT_TYPE="$_atype"
    [ -n "$QCOW_NAME" ]     || QCOW_NAME="${_pretty}_${VERSION}.qcow2"
    [ -n "$VMID" ]          || VMID="$_vmid"
fi

# VM id fallback for the custom (no --type) and --print-identity paths.
[ -n "$VMID" ] || VMID=103

# A real publish needs the image-shaped fields. With --type they are filled in
# above; without it they MUST be provided explicitly (no guessing).
if [ "$PRINT_IDENTITY" -eq 0 ]; then
    _missing=""
    [ -n "$IMAGE" ]         || _missing="$_missing --image"
    [ -n "$DESCRIPTION" ]   || _missing="$_missing --description"
    [ -n "$ARTIFACT_TYPE" ] || _missing="$_missing --artifact-type"
    [ -z "$_missing" ] || die "missing required option(s):${_missing}. Pass --type ce|plus|civm to derive them, or set each explicitly."
fi

# Resolve the qcow2 basename (the OCI layer title, predictable on pull):
#   --out wins (its basename) -> --type-derived name -> last path component of
#   the image ref. Never a hard-coded 'pfSense-CE' string.
if [ -n "$OUT" ]; then
    QCOW_NAME="$(basename "$OUT")"
elif [ -z "$QCOW_NAME" ]; then
    QCOW_NAME="${IMAGE##*/}_${VERSION}.qcow2"
fi

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
log "target: ${IMAGE}:${VERSION}  (qcow2: ${QCOW_NAME})"

# Informational: surface the NIC MACs + SMBIOS UUID so a re-publish can confirm
# the VM identity (Netgate Device ID inputs) is unchanged.
print_vm_identity "$QMCFG"

# Local output path for the streamed-back qcow2, named from the resolved qcow2
# basename (so the stored OCI layer title is predictable on pull).
CREATED_OUT=0
if [ -z "$OUT" ]; then
    OUT="${TMPDIR:-/tmp}/${QCOW_NAME}"
    CREATED_OUT=1
fi
rm -f "$OUT"

# Remote temp the conversion writes to (then streamed back, then removed). Named
# from the qcow2 basename so concurrent publishes of different images don't clash.
px "mkdir -p '$REMOTE_TMPDIR'" || die "cannot create remote tmpdir on Proxmox: $REMOTE_TMPDIR"
REMOTE_TMP="${REMOTE_TMPDIR%/}/pfb-publish-${QCOW_NAME%.qcow2}.$$.qcow2"

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
