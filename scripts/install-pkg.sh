#!/bin/sh
# install-pkg.sh — install a locally-built pfBlockerNG .pkg onto a pfSense box
# over SSH. Unlike the rsync overlay, `pkg add` registers the package in pkg's
# database and runs its POST-INSTALL hooks (menus, services, Unbound wiring),
# and resolves the RUN_DEPENDS from the configured repos. The .pkg is produced
# by the FreeBSD build job (scripts/build-pkg.sh) for the exact branch commit.
#
# Needs egress on the target to fetch RUN_DEPENDS (open during the smoke spike).
#
# Usage:
#   install-pkg.sh <ssh-target> --pkg <local .pkg> [--port N] [--ssh-key PATH]
#
# POSIX sh; quoted expansions; absolute binary paths where it matters.

set -eu

PORT=22
SSH_KEY=""
SSH_TARGET=""
PKGFILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --pkg)     PKGFILE="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        -*)        echo "install-pkg: unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$SSH_TARGET" ]; then SSH_TARGET="$1"; else
                echo "install-pkg: unexpected argument: $1" >&2; exit 1
            fi
            shift ;;
    esac
done

[ -n "$SSH_TARGET" ] || { echo "Usage: $0 <ssh-target> --pkg <file> [--port N] [--ssh-key PATH]" >&2; exit 1; }
[ -n "$PKGFILE" ] && [ -f "$PKGFILE" ] || { echo "install-pkg: --pkg file not found: ${PKGFILE}" >&2; exit 1; }

SSH_OPTS="-p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
# scp uses -P (capital) for the port; -p means "preserve times" there.
SCP_OPTS="-P ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="-i ${SSH_KEY} ${SSH_OPTS}"
    SCP_OPTS="-i ${SSH_KEY} ${SCP_OPTS}"
fi

ssh_t() {
    # SC2086: SSH_OPTS is a deliberate word-split option list.
    # SC2029: callers pass literal remote-command strings — client-side
    # expansion of "$@" into the remote command is intended.
    # shellcheck disable=SC2086,SC2029
    ssh ${SSH_OPTS} "$SSH_TARGET" "$@"
}

REMOTE="/tmp/$(basename "$PKGFILE")"

echo "==> Copying $(basename "$PKGFILE") to ${SSH_TARGET}:${REMOTE}"
# shellcheck disable=SC2086
scp ${SCP_OPTS} "$PKGFILE" "${SSH_TARGET}:${REMOTE}"

# `pkg add` of a LOCAL file does not fetch the package's RUN_DEPENDS from the
# repos (it just errors "Missing dependency"), so install them first — queried
# straight from the package manifest (%dn) so the list always matches the .pkg —
# then add the local file. `pkg add` then runs the package's POST-INSTALL hooks.
echo "==> Installing the package's dependencies from the repos"
DEPS="$(ssh_t "pkg query -F '${REMOTE}' '%dn'" 2>/dev/null | tr -d '\r' | tr '\n' ' ')"
echo "deps: ${DEPS}"
if [ -n "${DEPS}" ]; then
    ssh_t "env ASSUME_ALWAYS_YES=yes pkg install -y ${DEPS}"
fi
echo "==> pkg add ${REMOTE}"
ssh_t "env ASSUME_ALWAYS_YES=yes pkg add '${REMOTE}'"

# POST-INSTALL restarts Unbound asynchronously; wait for it before the caller
# queries the resolver (see feedback: poll the real readiness signal).
echo "==> Waiting for Unbound to be ready"
i=0
until ssh_t '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1'; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "install-pkg: Unbound did not become ready after install" >&2
        exit 1
    fi
    sleep 2
done

echo "==> Installed $(basename "$PKGFILE") on ${SSH_TARGET}"
