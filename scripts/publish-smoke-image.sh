#!/bin/sh
# publish-smoke-image.sh — friendly front-end for image-publish.sh.
#
# Asks only the handful of things that actually change between publishes:
#
#   * the image type   — ce | plus | civm
#   * the version/tag  — e.g. 2.8.1 (pfSense) or v1 (civm)
#   * the Proxmox VM id
#   * the Proxmox host — blank = run locally (on the Proxmox host itself)
#   * the SSH port     — only when a host was given
#
# Everything else (image ref, qcow2 filename, description, OCI artifact-type) is
# DERIVED by image-publish.sh from the type + version, so you never type those
# again. Any extra arguments are passed straight through to image-publish.sh,
# e.g.:
#
#   ./scripts/publish-smoke-image.sh --force --compression zlib
#   ./scripts/publish-smoke-image.sh --proxmox-ssh-key ~/.ssh/pve
#
# Non-interactive? Call image-publish.sh directly with --type (see its --help).

set -e

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
PUBLISH="$SCRIPT_DIR/image-publish.sh"
[ -x "$PUBLISH" ] || die "image-publish.sh not found next to this script: $PUBLISH"

# ask VAR "prompt" ["default"] — prompt on stderr, read a line, fall back to the
# default when the answer is empty. Result is assigned to VAR.
ask() {
    _var=$1; _prompt=$2; _default=${3:-}
    if [ -n "$_default" ]; then
        printf '%s [%s]: ' "$_prompt" "$_default" >&2
    else
        printf '%s: ' "$_prompt" >&2
    fi
    read -r _ans || _ans=""
    [ -n "$_ans" ] || _ans=$_default
    eval "$_var=\$_ans"
}

# 1. Image type (drives all the derived fields downstream).
TYPE=""
while :; do
    ask TYPE "Image type (ce | plus | civm)"
    case "$TYPE" in
        ce|plus|civm) break ;;
        *) printf 'Please answer ce, plus or civm.\n' >&2 ;;
    esac
done

# 2. Version / tag (required).
VERSION=""
while [ -z "$VERSION" ]; do
    case "$TYPE" in
        civm) ask VERSION "Version / tag (e.g. v1)" ;;
        *)    ask VERSION "Version / tag (e.g. 2.8.1)" ;;
    esac
    [ -n "$VERSION" ] || printf 'A version/tag is required.\n' >&2
done

# 3. VM id — civm conventionally lives on 104, the pfSense VMs on 103.
case "$TYPE" in
    civm) _vmid_default=104 ;;
    *)    _vmid_default=103 ;;
esac
ask VMID "Proxmox VM id" "$_vmid_default"

# 4. Proxmox host — blank means "run locally, on the Proxmox host".
ask PXHOST "Proxmox host (blank = local)" ""

# 5. SSH port — only meaningful when reaching a remote host.
PXPORT=""
[ -z "$PXHOST" ] || ask PXPORT "SSH port" "22"

# Confirm before doing anything (the export + push is not cheap).
printf '\nAbout to publish:\n' >&2
printf '  type      %s\n' "$TYPE" >&2
printf '  version   %s\n' "$VERSION" >&2
printf '  vmid      %s\n' "$VMID" >&2
if [ -n "$PXHOST" ]; then
    printf '  proxmox   %s (port %s)\n' "$PXHOST" "$PXPORT" >&2
else
    printf '  proxmox   local\n' >&2
fi
[ "$#" -eq 0 ] || printf '  extra     %s\n' "$*" >&2
ask CONFIRM "Proceed?" "y"
case "$CONFIRM" in
    y|Y|yes|YES) ;;
    *) die "aborted" ;;
esac

# Hand off to image-publish.sh, which derives the image ref, qcow2 filename,
# description and artifact-type from --type + version and prints the resolved
# target before it runs. Extra args ("$@") pass straight through.
if [ -n "$PXHOST" ]; then
    exec "$PUBLISH" "$VERSION" --type "$TYPE" --vmid "$VMID" \
        --proxmox "$PXHOST" --proxmox-port "$PXPORT" "$@"
else
    exec "$PUBLISH" "$VERSION" --type "$TYPE" --vmid "$VMID" "$@"
fi
