#!/bin/sh
# install-pkg.sh — install a locally-built pfBlockerNG .pkg onto a pfSense box
# over SSH. Unlike the rsync overlay, `pkg add` registers the package in pkg's
# database and runs its POST-INSTALL hooks (menus, services, Unbound wiring).
# The .pkg is produced by the portable Linux builder (scripts/build-pkg-portable.py,
# driven by build-pkg-linux.yml) for the exact branch commit.
#
# RUN_DEPENDS: NOT fetched here. By convention the pre-baked smoke image ships
# pfBlockerNG's runtime dependencies, so `pkg add` of the local .pkg resolves
# them from the local pkg db and runs fully OFFLINE (no egress, no repo-catalogue
# round-trip — a more stable deploy). If a dependency is missing, `pkg add` fails
# loudly with "Missing dependency": that means the image is bad — fix the image
# (re-bake with the deps), don't paper over it with a repo install here.
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
# Pure precondition tests; the || branch is the intended else (SC2015 N/A).
# shellcheck disable=SC2015
[ -n "$PKGFILE" ] && [ -f "$PKGFILE" ] || { echo "install-pkg: --pkg file not found: ${PKGFILE}" >&2; exit 1; }

SSH_OPTS="-p ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
# scp uses -P (capital) for the port; -p means "preserve times" there.
SCP_OPTS="-P ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="-i ${SSH_KEY} ${SSH_OPTS}"
    SCP_OPTS="-i ${SSH_KEY} ${SCP_OPTS}"
fi

# Always run the remote command under /bin/sh. pfSense's root login shell is tcsh,
# and sshd re-parses the command string with it; tcsh mangles POSIX sh constructs
# (`;` chains, `||`, `2>&1` redirects) and any `grep -E`/glob pattern containing
# `|` `(` `)` `[` `$` — exactly what the diagnostic commands below use. Single-quote
# the whole command into one token so tcsh only sees `/bin/sh -c '<blob>'` and hands
# the blob to sh for real parsing. Mirrors roundtrip.sh / conftest SmokeVM.ssh_argv.
ssh_t() {
    if [ "$#" -eq 1 ]; then
        _cmd=$1
    else
        _cmd=""
        for _a in "$@"; do
            _q=$(printf '%s' "$_a" | sed "s/'/'\\\\''/g")
            _cmd="${_cmd:+$_cmd }'${_q}'"
        done
    fi
    _sq="'$(printf '%s' "$_cmd" | sed "s/'/'\\\\''/g")'"
    # SC2086: SSH_OPTS is a deliberate word-split option list.
    # shellcheck disable=SC2086
    ssh ${SSH_OPTS} "$SSH_TARGET" /bin/sh -c "$_sq"
}

REMOTE="/tmp/$(basename "$PKGFILE")"

echo "==> Copying $(basename "$PKGFILE") to ${SSH_TARGET}:${REMOTE}"
# shellcheck disable=SC2086
scp ${SCP_OPTS} "$PKGFILE" "${SSH_TARGET}:${REMOTE}"

# `pkg add` of a LOCAL file resolves RUN_DEPENDS from the LOCAL pkg db — it does
# not reach the repos when the deps are already installed. The smoke image bakes
# pfBlockerNG's RUN_DEPENDS (convention), so this runs offline and then executes
# the package's POST-INSTALL hooks. A "Missing dependency" error here = bad image.
echo "==> pkg add ${REMOTE} (deps pre-baked; offline)"
ssh_t "env ASSUME_ALWAYS_YES=yes pkg add '${REMOTE}'"

# POST-INSTALL restarts Unbound asynchronously; wait for it before the caller
# queries the resolver (see feedback: poll the real readiness signal).
echo "==> Waiting for Unbound to be ready"
i=0
until ssh_t '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1'; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "install-pkg: Unbound did not become ready after install" >&2
        echo "==> Unbound readiness diagnostics (resolver did not come up):" >&2
        ssh_t 'echo "---- unbound-checkconf ----"; /usr/local/sbin/unbound-checkconf /var/unbound/unbound.conf 2>&1; echo "---- unbound-control status ----"; /usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status 2>&1; echo "---- ls -la /var/unbound ----"; ls -la /var/unbound 2>&1; echo "---- unbound.conf python block ----"; grep -nE "python|module-config" /var/unbound/unbound.conf 2>&1; echo "---- config unbound/python flag ----"; /usr/local/sbin/read_xml_tag.sh string unbound/python 2>&1; /usr/local/sbin/read_xml_tag.sh string unbound/python_script 2>&1; echo "---- resolver.log tail ----"; tail -n 40 /var/log/resolver.log 2>&1; echo "---- unbound processes ----"; ps auxww | grep -i "[u]nbound" 2>&1' >&2 || true
        exit 1
    fi
    sleep 2
done

echo "==> Installed $(basename "$PKGFILE") on ${SSH_TARGET}"
