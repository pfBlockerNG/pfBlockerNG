# image-lib.sh — shared helpers for image-publish.sh and image-upgrade.sh so the
# two produce BYTE-CONSISTENT GHCR artifacts for a given (type, version). Sourced,
# never executed. Keeping the type table, the tag rule, the `oras push` AND the
# Proxmox/KVM-host SSH plumbing (env defaults, --proxmox target split, the `px`
# remote-or-local runner, GHCR login) in one place is what guarantees an
# upgrade-and-publish equals a manual publish, and that the two scripts' remote
# access never drifts apart.
# shellcheck shell=sh

# log/warn/die are defined by the SOURCING script before it sources this file;
# image_ghcr_login() below calls log(), which is safe because a sourced function
# only runs later, once the caller's shell already has log() defined.

# image_px_defaults — set the Proxmox/KVM-host SSH-coordinate defaults from their
# env-var fallbacks. Call before parsing --proxmox*/--remote-tmpdir options,
# which then override these via plain assignment.
image_px_defaults() {
    PX_HOST="${PROXMOX_SSH_HOST:-}"
    PX_USER="${PROXMOX_SSH_USER:-root}"
    PX_PORT="${PROXMOX_SSH_PORT:-22}"
    PX_KEY="${PROXMOX_SSH_KEY:-}"
    # REMOTE_TMPDIR is consumed by the sourcing script, not here.
    # shellcheck disable=SC2034
    REMOTE_TMPDIR="${PROXMOX_TMPDIR:-/tmp}"
}

# image_px_target_split — if PX_TARGET ("[USER@]HOST", set by a --proxmox
# option) is non-empty, split it into PX_USER/PX_HOST; a no-op otherwise (the
# locally-run case, where PX_HOST stays whatever image_px_defaults left it).
# Call once option parsing is done.
image_px_target_split() {
    if [ -n "${PX_TARGET:-}" ]; then
        case "$PX_TARGET" in
            *@*) PX_USER="${PX_TARGET%@*}"; PX_HOST="${PX_TARGET#*@}" ;;
            *)   PX_HOST="$PX_TARGET" ;;
        esac
    fi
}

# image_px_ssh_opts — derive the ssh(1) option WORDS PX_PORT_OPT/PX_KEY_OPT from
# PX_PORT/PX_KEY. Intentionally unquoted at use (word-split into separate ssh
# args); safe here since port/key never contain spaces. Call after PX_REMOTE is
# known to be set (px() and, in image-upgrade.sh, ssh_guest() both read these).
image_px_ssh_opts() {
    PX_PORT_OPT=""; [ -n "$PX_PORT" ] && PX_PORT_OPT="-p $PX_PORT"
    PX_KEY_OPT="";  [ -n "$PX_KEY" ]  && PX_KEY_OPT="-i $PX_KEY"
    # A shell function's exit status is its last command's; unlike the same
    # "[ -n ... ] && assign" line at top level, under `set -e` a FUNCTION CALL
    # returning non-zero (PX_PORT/PX_KEY empty is the common case) would abort
    # the sourcing script. Force success explicitly.
    return 0
}

# px CMD — run CMD on the Proxmox/KVM host (over SSH, using PX_REMOTE/PX_USER/
# PX_HOST/PX_PORT_OPT/PX_KEY_OPT) or locally when no remote host was given.
# stdin/stdout pass through, so it composes with pipes/redirection (e.g.
# `px "cat file" > local` or `... | px "cat > f"`).
px() {
    if [ "$PX_REMOTE" -eq 1 ]; then
        # shellcheck disable=SC2086
        ssh -o BatchMode=yes -o ConnectTimeout=10 $PX_PORT_OPT $PX_KEY_OPT \
            "${PX_USER}@${PX_HOST}" "$1"
    else
        sh -c "$1"
    fi
}

# image_ghcr_login — non-interactive `oras login ghcr.io`, iff both
# SMOKE_GHCR_TOKEN and SMOKE_GHCR_USER are set; a no-op otherwise (an
# already-authenticated local oras config is left alone).
image_ghcr_login() {
    if [ -n "${SMOKE_GHCR_TOKEN:-}" ] && [ -n "${SMOKE_GHCR_USER:-}" ]; then
        log "logging in to ghcr.io as $SMOKE_GHCR_USER"
        printf '%s' "$SMOKE_GHCR_TOKEN" | oras login ghcr.io -u "$SMOKE_GHCR_USER" --password-stdin
    fi
}

# image_type_fields TYPE — validate TYPE and set, for the caller, the derived
# image-shaped fields. Returns non-zero on an unknown type (caller decides how to
# fail). On success sets:
#   IMG_NAME    GHCR repository name      (pfsense-ce | pfsense-plus | civm)
#   IMG_PRETTY  qcow2 / OCI-title prefix  (pfSense-CE | pfSense-Plus | civm)
#   IMG_DESC    human description prefix  (pfSense CE | pfSense Plus | pfBlockerNG smoke client VM)
#   IMG_ATYPE   OCI artifact-type annotation
#   IMG_VMID    conventional Proxmox VM id (ce 103, plus 104, civm 105)
image_type_fields() {
    # The IMG_* outputs are consumed by the sourcing script, not here.
    # shellcheck disable=SC2034
    case "$1" in
        ce)   IMG_NAME=pfsense-ce;   IMG_PRETTY=pfSense-CE;   IMG_DESC="pfSense CE";                 IMG_ATYPE="application/vnd.netgate.pfsense-ce.disk.v1";       IMG_VMID=103 ;;
        plus) IMG_NAME=pfsense-plus; IMG_PRETTY=pfSense-Plus; IMG_DESC="pfSense Plus";               IMG_ATYPE="application/vnd.netgate.pfsense-plus.disk.v1";     IMG_VMID=104 ;;
        civm) IMG_NAME=civm;         IMG_PRETTY=civm;         IMG_DESC="pfBlockerNG smoke client VM"; IMG_ATYPE="application/vnd.pfblockerng.smoke-client.disk.v1"; IMG_VMID=105 ;;
        *)    return 1 ;;
    esac
    return 0
}

# image_version_tag VERSION — echo the GHCR tag for a raw OS version string: the
# first two dot-separated components (major.minor), after dropping a -RELEASE /
# -RC.N / -p1 style suffix. Both CE and Plus tag by major.minor:
#   2.8.1 -> 2.8   2.9.0-RELEASE -> 2.9   26.05.1 -> 26.05   26.05 -> 26.05
# A version with no dot echoes verbatim (degenerate, should not happen).
image_version_tag() {
    _v=${1%%-*}                 # drop any -RELEASE / -RC.N / -pN suffix
    _maj=${_v%%.*}              # major: before the first dot
    case "$_v" in
        *.*) _rest=${_v#*.}; printf '%s.%s' "$_maj" "${_rest%%.*}" ;;  # major.minor
        *)   printf '%s' "$_v" ;;                                       # no dot (degenerate)
    esac
}

# image_oci_push FILE IMAGE TAG ATYPE DESCRIPTION TITLE — push the local qcow2
# FILE to IMAGE:TAG as a qcow2 OCI artifact with the standard annotations, stored
# under the layer title TITLE so a pull always sees a predictable *.qcow2 name.
# Identical call shape in both scripts => identical artifacts. `oras` runs locally.
image_oci_push() {
    _f=$1; _image=$2; _tag=$3; _atype=$4; _desc=$5; _title=$6
    _dir=$(dirname "$_f")
    _pushname=$_title
    # Ensure an on-disk file whose basename equals TITLE (the stored layer title
    # follows the pushed file's basename). Hardlink when possible, else copy.
    if [ "$(basename "$_f")" != "$_title" ]; then
        ln -f "$_f" "$_dir/$_title" 2>/dev/null || cp -f "$_f" "$_dir/$_title"
    fi
    (
        cd "$_dir" || exit 1
        oras push \
            --artifact-type "$_atype" \
            --annotation "org.opencontainers.image.title=$_pushname" \
            --annotation "org.opencontainers.image.version=$_tag" \
            --annotation "org.opencontainers.image.description=$_desc" \
            "${_image}:${_tag}" \
            "${_pushname}:application/vnd.qemu.qcow2"
    )
}
