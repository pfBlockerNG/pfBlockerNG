#!/bin/sh
# freebsd-image-url.sh — print the download.freebsd.org BASIC-CLOUDINIT qcow2.xz
# URL for a given FreeBSD version, so the build environment can be selected by
# version (and keyed for caching) instead of pasting a full URL.
#
# RELEASE builds live under releases/VM-IMAGES; CURRENT and STABLE snapshots
# under snapshots/VM-IMAGES. Pick the version to match the target pfSense base:
#   pfSense CE 2.8.1 -> 15.0-RELEASE   (FreeBSD 15)
#   pfSense Plus     -> 16.0-CURRENT   (FreeBSD 16)
#
# Usage:
#   freebsd-image-url.sh <version> [arch]
# Examples:
#   freebsd-image-url.sh 15.0-RELEASE          -> releases/.../15.0-RELEASE/...
#   freebsd-image-url.sh 16.0-CURRENT          -> snapshots/.../16.0-CURRENT/...
#
# POSIX sh.

set -eu

VERSION="${1:?usage: freebsd-image-url.sh <version> [arch]}"
ARCH="${2:-amd64}"

case "$VERSION" in
    *-RELEASE)          area="releases" ;;
    *-CURRENT|*-STABLE) area="snapshots" ;;
    *)
        echo "freebsd-image-url: unrecognized version '$VERSION'" >&2
        echo "  expected e.g. 15.0-RELEASE, 16.0-CURRENT, 15.0-STABLE" >&2
        exit 1
        ;;
esac

printf 'https://download.freebsd.org/%s/VM-IMAGES/%s/%s/Latest/FreeBSD-%s-%s-BASIC-CLOUDINIT-zfs.qcow2.xz\n' \
    "$area" "$VERSION" "$ARCH" "$VERSION" "$ARCH"
