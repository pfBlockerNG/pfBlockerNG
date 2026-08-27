#!/bin/sh
# install-pkg.sh — install a locally-built pfBlockerNG .pkg onto a pfSense box
# over SSH. Unlike the rsync overlay, `pkg add` registers the package in pkg's
# database and runs its POST-INSTALL hooks (menus, services, Unbound wiring).
# The .pkg is produced by the portable Linux builder (scripts/build-pkg-portable.py,
# driven by build-pkg-linux.yml) for the exact branch commit.
#
# RUN_DEPENDS: resolved from the LOCAL pkg db, either because the pre-baked smoke
# image ships them (convention), OR because SMOKE_DEP_PKGS names extra dep .pkgs
# this script installs FIRST (issue #1806: pfSense CE's own repo does not carry
# every RUN_DEPENDS a port needs, e.g. textproc/py-charset-normalizer, so its dep
# .pkg ships alongside the branch build instead of being baked into the image).
# Either way, `pkg add` of the local .pkg then resolves fully OFFLINE (no egress,
# no repo-catalogue round-trip — a more stable deploy). If a dependency is still
# missing, `pkg add` fails loudly with "Missing dependency": that means it is
# missing from BOTH the image AND SMOKE_DEP_PKGS — fix one of those, don't paper
# over it with a repo install here.
#
# Usage:
#   install-pkg.sh <ssh-target> --pkg <local .pkg> [--port N] [--ssh-key PATH]
#
# Env:
#   SMOKE_DEP_PKGS   space-separated absolute paths of extra dep .pkg files,
#                    scp'd + `pkg add`ed BEFORE the branch .pkg, in the given
#                    order. Unset/empty (the default) -> skipped entirely.
#   SMOKE_ABI        when set, each `pkg add` is `pkg -o ABI=$SMOKE_ABI add`
#                    so a guest whose `pkg config ABI` drifted after
#                    rc.update_pkg_metadata still accepts the matrix-built
#                    local .pkg (issue #2730). Unset -> plain `pkg add`.
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


# issue #2237: a first-boot pfSense runs its own pkg(8) activity, and `pkg add`
# then dies on "Cannot get an exclusive lock on a database" (observed on the
# containerized runner fleet, run 31229687348). Retry ONLY that signature,
# bounded per the waits policy: hard attempt cap, loud DISTINCT give-up. Any
# other pkg-add failure (e.g. "Missing dependency") stays immediate — see the
# header: those mean a bad image/dep set, and retrying would just mask them.
# Seams (spec-only): PFB_INSTALL_PKG_RETRY_MAX / PFB_INSTALL_PKG_RETRY_DELAY.
PKG_LOCK_RETRY_MAX="${PFB_INSTALL_PKG_RETRY_MAX:-12}"
PKG_LOCK_RETRY_DELAY="${PFB_INSTALL_PKG_RETRY_DELAY:-5}"
# A non-integer cap makes the -ge comparison silently FALSE and the loop
# unbounded — the same trap guarded by the publication retry loops. Reject bad
# values before any ssh/sleep runs; 0 delay is valid.
case "$PKG_LOCK_RETRY_MAX" in '' | *[!0-9]*) PKG_LOCK_RETRY_MAX=0 ;; esac
[ "$PKG_LOCK_RETRY_MAX" -ge 1 ] || {
    echo "install-pkg: PFB_INSTALL_PKG_RETRY_MAX must be a positive integer" >&2
    exit 1
}
case "$PKG_LOCK_RETRY_DELAY" in
    *[!0-9]*)
        echo "install-pkg: PFB_INSTALL_PKG_RETRY_DELAY must be a non-negative integer" >&2
        exit 1
        ;;
esac

pkg_add_lock_retry() {
    _pkg_remote=$1
    _try=1
    while true; do
        _rc=0
        # Same-shell probe: a separate SSH round-trip can observe a different ABI
        # while first-boot metadata settles. The final pkg command supplies status.
        if [ -n "${SMOKE_ABI:-}" ]; then
            # Quote ABI for dash; empty SMOKE_ABI is treated as unset by -n above.
            _abi_q=$(printf '%s' "$SMOKE_ABI" | sed "s/'/'\\\\''/g")
            _pkg_add="pkg -o ABI='${_abi_q}' add"
        else
            _pkg_add="pkg add"
        fi
        _out=$(ssh_t "printf 'PFB_PKG_CONTEXT utc='; date -u '+%Y-%m-%dT%H:%M:%SZ'; printf 'PFB_PKG_CONTEXT absolute_abi='; /usr/local/sbin/pkg config ABI 2>&1 || true; printf 'PFB_PKG_CONTEXT path_pkg='; command -v pkg 2>&1 || true; printf 'PFB_PKG_CONTEXT path_abi='; pkg config ABI 2>&1 || true; printf 'PFB_PKG_CONTEXT boot_pkg_processes='; ps axww -o pid= -o comm= -o args= 2>&1 | awk '((\$2 == \"sh\" && \$3 == \"/bin/sh\" && (\$4 == \"/etc/rc.update_pkg_metadata\" || \$4 == \"/usr/local/sbin/pfSense-upgrade\" || \$4 == \"/usr/local/libexec/pfSense-upgrade\")) || (\$2 == \"lockf\" && \$0 ~ /\/tmp\/pfSense-upgrade\.lock/) || \$2 == \"pkg\" || \$2 == \"pkg-static\") { found=1; print } END { if (!found) print \"none\" }'; env ASSUME_ALWAYS_YES=yes ${_pkg_add} '${_pkg_remote}'" 2>&1) || _rc=$?
        if [ -n "$_out" ]; then printf '%s\n' "$_out"; fi
        # pkg(8) can exit 0 after POST-INSTALL/DEINSTALL still failed — files are
        # already extracted (issue #2575). Smoke 20260827T005125Z-smoke then printed
        # "==> Installed" and helpers.deploy treated rc=0 as PASSED. Same matcher
        # as install.sh, including the glued ``thrown</pre>pkg: POST-INSTALL script failed``.
        if [ "$_rc" -eq 0 ]; then
            _script_failed=0
            while IFS= read -r _line || [ -n "${_line:-}" ]; do
                case "$_line" in
                    *'pkg: '*' script failed'*) _script_failed=1; break ;;
                esac
            done <<EOF
${_out}
EOF
            if [ "$_script_failed" -eq 1 ]; then
                echo "install-pkg: pkg reported a package-script failure — POST-INSTALL can fail while pkg still exits 0 (issue #2575)" >&2
                return 1
            fi
            return 0
        fi
        case "$_out" in
            *'Cannot get an exclusive lock on a database'* | *'Package database is busy'*) ;;
            *) return "$_rc" ;;
        esac
        if [ "$_try" -ge "$PKG_LOCK_RETRY_MAX" ]; then
            echo "install-pkg: guest pkg database still locked after ${PKG_LOCK_RETRY_MAX} attempts — giving up (issue #2237)" >&2
            return "$_rc"
        fi
        echo "install-pkg: guest pkg database locked (boot-time pkg activity); retry ${_try}/${PKG_LOCK_RETRY_MAX} in ${PKG_LOCK_RETRY_DELAY}s" >&2
        _try=$((_try + 1))
        sleep "$PKG_LOCK_RETRY_DELAY"
    done
}

REMOTE="/tmp/$(basename "$PKGFILE")"

# issue #1806 D2: install any SMOKE_DEP_PKGS FIRST, in the given order. `set -eu`
# already makes a dep `pkg add` failure abort the whole script right here — the
# SAME loud error contract as the branch .pkg add below, and the branch .pkg is
# never reached (not even copied).
for _dep in ${SMOKE_DEP_PKGS:-}; do
    [ -f "$_dep" ] || { echo "install-pkg: SMOKE_DEP_PKGS file not found: ${_dep}" >&2; exit 1; }
    _dep_remote="/tmp/$(basename "$_dep")"
    echo "==> Copying dep $(basename "$_dep") to ${SSH_TARGET}:${_dep_remote}"
    # shellcheck disable=SC2086
    scp ${SCP_OPTS} "$_dep" "${SSH_TARGET}:${_dep_remote}"
    echo "==> pkg add ${_dep_remote} (dep, from SMOKE_DEP_PKGS)"
    pkg_add_lock_retry "$_dep_remote"
done

echo "==> Copying $(basename "$PKGFILE") to ${SSH_TARGET}:${REMOTE}"
# shellcheck disable=SC2086
scp ${SCP_OPTS} "$PKGFILE" "${SSH_TARGET}:${REMOTE}"

# `pkg add` of a LOCAL file resolves RUN_DEPENDS from the LOCAL pkg db — it does
# not reach the repos when the deps are already installed. The smoke image bakes
# pfBlockerNG's RUN_DEPENDS (convention), so this runs offline and then executes
# the package's POST-INSTALL hooks. A "Missing dependency" error here = bad image.
echo "==> pkg add ${REMOTE} (deps pre-baked; offline)"
pkg_add_lock_retry "$REMOTE"

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
