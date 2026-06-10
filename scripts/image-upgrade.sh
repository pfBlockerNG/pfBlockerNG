#!/bin/sh
# image-upgrade.sh — upgrade the published pfSense CE smoke base to a new CE
# release and publish the result as a new tag (ADR-04, Phase 2 "upgrade in place").
#
# Drive it FROM YOUR MACHINE: the KVM boot + in-VM upgrade must run on a KVM host
# (your Proxmox host), so pass its SSH coordinates and the script runs qemu there
# over SSH while `oras` pull/push stay LOCAL (nothing extra to install on Proxmox
# beyond its native qemu). The guest is reached by jumping THROUGH Proxmox, so the
# guest SSH key never leaves your machine. Omit --proxmox to run locally (i.e.
# directly on the KVM host), as before.
#
# Flow: pull the current image from GHCR (local) -> stream it to the Proxmox host
# -> boot it under QEMU/KVM there (read-write, with internet) ->
# [optional: pkg update -f + pkg upgrade, reboot, wait SSH back] ->
# run pfSense-upgrade over an SSH jump -> wait for it to finish and reboot ->
# health-gate (webConfigurator HTTP or pfctl live ruleset) ->
# power off cleanly -> compress on Proxmox -> stream back ->
# push the new tag (local). The source tag is left untouched, so the old image
# is always kept.
#
# Usage:
#   ./scripts/image-upgrade.sh --from <current-version> [options]
#
# Examples:
#   ./scripts/image-upgrade.sh --from 2.8 --proxmox root@pve.lan --ssh-key ~/.ssh/smoke_ed25519
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.9 --proxmox pve.lan --proxmox-port 2222
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.8 --force --upgrade-pkgs   # patch refresh
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
#   --to VERSION     tag to publish as (default: auto-detected from the upgraded box)
#   --image REF      GHCR image ref without tag (default composed from the
#                    SMOKE_IMAGE_REPO + SMOKE_IMAGE_NAME env vars:
#                    ${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}/${SMOKE_IMAGE_NAME:-pfsense-ce})
#   --ssh-key PATH   GUEST SSH private key (default: $SMOKE_SSH_KEY) — its public
#                    half is baked into the image's root authorized_keys
#   --ssh-port N     Proxmox-local port forwarded to the guest's :22 (default: 2222)
#   --mac ADDR       guest NIC MAC (default: BC:24:11:37:9C:AC — must match the image)
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
#   --keep           keep the work dirs (image copies, console log) afterwards
#   --force          overwrite the target tag if it already exists
#
# Auth: as in image-publish.sh (local oras login, or SMOKE_GHCR_USER/SMOKE_GHCR_TOKEN).

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

FROM=""
TO=""
# Compose the untagged image ref from the namespace + name vars (org-transfer
# scheme; supports pfsense-ce, pfsense-plus, … under one namespace). --image overrides.
IMAGE="${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}"
IMAGE="${IMAGE%/}/${SMOKE_IMAGE_NAME:-pfsense-ce}"
GUEST_KEY="${SMOKE_SSH_KEY:-}"
GUEST_PORT=2222
MAC="BC:24:11:37:9C:AC"
COMPRESSION=zstd
UPGRADE_TIMEOUT=1200
UPGRADE_PKGS=0
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
        --image)           IMAGE="$2"; shift 2 ;;
        --ssh-key)         GUEST_KEY="$2"; shift 2 ;;
        --ssh-port)        GUEST_PORT="$2"; shift 2 ;;
        --mac)             MAC="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --upgrade-timeout) UPGRADE_TIMEOUT="$2"; shift 2 ;;
        --upgrade-pkgs)    UPGRADE_PKGS=1; shift ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        -h|--help)         sed -n '2,62p' "$0"; exit 0 ;;
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
log "booting VM on the KVM host (guest :22 -> 127.0.0.1:$GUEST_PORT there)"
QEMU_CMD="$QEMU_BIN \
    -enable-kvm -machine pc -cpu host \
    -smp 2,sockets=1,cores=2 -m 4096 \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive file=$REMOTE_DIR/work.qcow2,if=none,id=drive-scsi0,format=qcow2,discard=unmap,detect-zeroes=unmap \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$GUEST_PORT-:22 \
    -device virtio-net-pci,mac=$MAC,netdev=net0,id=net0 \
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
[ -n "$NEW_VER" ] || die "version did not change within ${UPGRADE_TIMEOUT}s (still '${OLD_VER}'; see $LOCAL_DIR/upgrade.log)"
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
TAG="${TO:-$(printf '%s' "$NEW_VER" | sed 's/-RELEASE$//')}"
[ -n "$TAG" ] || die "could not determine target tag"

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

OUT="$LOCAL_DIR/pfSense-CE-${TAG}.qcow2"
log "streaming upgraded image back -> $(basename "$OUT")"
px "cat '$REMOTE_DIR/out.qcow2'" > "$OUT"
[ -s "$OUT" ] || die "streamed upgraded image is empty: $OUT"

log "pushing ${IMAGE}:${TAG} (local oras)"
(
    cd "$LOCAL_DIR"
    oras push \
        --artifact-type application/vnd.netgate.pfsense-ce.disk.v1 \
        --annotation "org.opencontainers.image.title=$(basename "$OUT")" \
        --annotation "org.opencontainers.image.version=${TAG}" \
        --annotation "org.opencontainers.image.description=pfSense CE ${TAG} pfBlockerNG smoke-test base (upgraded from ${FROM})" \
        "${IMAGE}:${TAG}" \
        "$(basename "$OUT"):application/vnd.qemu.qcow2"
)

log "done. ${IMAGE}:${TAG} published; ${IMAGE}:${FROM} kept."
