# image-lib.sh — shared helpers for image-publish.sh and image-upgrade.sh so the
# two produce BYTE-CONSISTENT GHCR artifacts for a given (type, version). Sourced,
# never executed. Keeping the type table, the tag rule and the `oras push` in one
# place is what guarantees an upgrade-and-publish equals a manual publish.
# shellcheck shell=sh

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
