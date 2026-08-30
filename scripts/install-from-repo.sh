#!/bin/sh
# install-from-repo.sh — install pfBlockerNG onto a FRESH pfSense straight from
# this repo's src/ (no Netgate pkg): sync the files, register the package from
# its GUI XML, and run its real install hooks so it is a functional, registered
# package. The smoke harness runs this after every boot — the disk is immutable
# (overlay discarded), so every run is a clean install of the branch under test.
#
# It does NOT add feeds / addresses / whitelists / response modes — that is
# per-case config injection (ADR-04), done later by the test harness.
#
# The pfSense setup wizard is a GUI-only first-run prompt; the baked image is
# already a configured box (config.xml present), so there is nothing to skip
# here — the harness drives everything over SSH/CLI.
#
# Usage:
#   ./scripts/install-from-repo.sh <ssh-target> [options]
#
# Examples:
#   ./scripts/install-from-repo.sh root@127.0.0.1 --port 2222 --ssh-key ~/.ssh/smoke_key
#   ./scripts/install-from-repo.sh root@192.168.1.1
#
# Options:
#   --channel devel|stable   package name to register (default: devel)
#   --port N                 SSH port (default: 22; the smoke VM uses 2222)
#   --ssh-key PATH           SSH private key (default: ssh-agent / default keys)
#
# Run from the repository root.

set -e

REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
CHANNEL="devel"
PORT=22
SSH_KEY=""
SSH_TARGET=""

while [ $# -gt 0 ]; do
    case "$1" in
        --channel) CHANNEL="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        -*)        echo "Unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$SSH_TARGET" ]; then SSH_TARGET="$1"; else
                echo "Unexpected argument: $1" >&2; exit 1
            fi
            shift ;;
    esac
done

[ -n "$SSH_TARGET" ] || { echo "Usage: $0 <ssh-target> [--channel devel|stable] [--port N] [--ssh-key PATH]" >&2; exit 1; }
[ "$CHANNEL" = devel ] || [ "$CHANNEL" = stable ] || { echo "Error: --channel must be devel|stable" >&2; exit 1; }

PKG_NAME="pfBlockerNG"
[ "$CHANNEL" = devel ] && PKG_NAME="pfBlockerNG-devel"

# Build the remote-shell string (single arg for rsync -e) and an ssh wrapper.
RSH="ssh -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
[ -n "$SSH_KEY" ] && RSH="$RSH -i $SSH_KEY"
ssh_t() {
    if [ -n "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_TARGET" "$@"
    else
        ssh -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$SSH_TARGET" "$@"
    fi
}

echo "==> Installing pfBlockerNG ($PKG_NAME) onto $SSH_TARGET from repo"

# 0a) rsync — needed twice over: it is a pfBlockerNG RUN_DEPENDS (net/rsync, for
#     rsync-format feed lists) AND the transport for the overlay sync below; a
#     fresh pfSense ships none. Check-then-install (pfSense's pkg repo carries it).
#     Needs egress (open during the smoke spike / image build; the test job blocks
#     egress only AFTER install). Fatal if it can't be installed — nothing syncs.
if ! ssh_t 'command -v rsync >/dev/null 2>&1'; then
    echo "==> rsync missing on target — installing via pkg"
    ssh_t 'env ASSUME_ALWAYS_YES=yes pkg install -y rsync' \
        || { echo "Error: failed to install rsync on $SSH_TARGET" >&2; exit 1; }
fi

# The Python flavor for the py3xx-* RUN_DEPENDS is DERIVED FROM THE VERSION MATRIX (no
# hardcoded py311): match the box's FreeBSD major (parsed from its concrete ABI, e.g.
# FreeBSD:15:amd64) to its matrix entry's py_flavor. issue #1806: the matrix is arch-less
# (no `arch` field). issue #2926: the BUILD matrix dedupes to one row per exact runtime
# TUPLE (freebsd_major, php_version, py_flavor), so matching by major alone is NOT exact —
# when a major carries two tuples a [0] pick installs the WRONG py3xx deps. A
# SMOKE_PY_FLAVOR/SMOKE_PHP_VERSION env pair (already exported by the CI fan-out) names
# the tuple; with no disambiguator and an ambiguous major, REFUSE rather than guess —
# the box's own installed py3xx flavor is probed as the fallback (a live box knows which
# python it runs). Fallbacks keep the installer working when the matrix/jq is
# unavailable: the box's OWN installed py3xx flavor, then py311.
# (read-version-matrix.sh self-fetches the ci-metadata ref.)
PY_FLAVOR=""
BOX_ABI="$(ssh_t 'pkg config ABI 2>/dev/null' | tr -d '\r')"
BOX_MAJOR="$(printf '%s' "$BOX_ABI" | cut -d: -f2)"
if [ -n "$BOX_MAJOR" ] && command -v jq >/dev/null 2>&1; then
    _MATCHES="$(sh "${REPO_ROOT}/scripts/read-version-matrix.sh" --print-build 2>/dev/null \
        | jq -c --arg major "$BOX_MAJOR" --arg php "${SMOKE_PHP_VERSION:-}" --arg py "${SMOKE_PY_FLAVOR:-}" \
            '[ .[] | select(.freebsd_major == $major) | select($php == "" or .php_version == $php) | select($py == "" or .py_flavor == $py) ]' \
        2>/dev/null || true)"
    _MATCH_COUNT="$(printf '%s' "$_MATCHES" | jq 'length' 2>/dev/null || echo 0)"
    if [ "$_MATCH_COUNT" -gt 1 ]; then
        echo "Error: FreeBSD major ${BOX_MAJOR} matches more than one BUILD row for runtime tuple selection (ABI ${BOX_ABI:-unknown}) — refusing to silently install a sibling tuple's py flavor; set SMOKE_PHP_VERSION/SMOKE_PY_FLAVOR" >&2
        exit 1
    fi
    if [ "$_MATCH_COUNT" -eq 1 ]; then
        PY_FLAVOR="$(printf '%s' "$_MATCHES" | jq -r '.[0].py_flavor')"
    fi
fi
if [ -z "$PY_FLAVOR" ]; then
    # The box knows its own python: the py3xx that owns its py-sqlite3, if already present.
    PY_FLAVOR="$(ssh_t "pkg query %n 2>/dev/null | grep -E '^py3[0-9]+-sqlite3\$' | sed 's/-sqlite3//' | head -1" | tr -d '\r' || true)"
fi
[ -n "$PY_FLAVOR" ] || PY_FLAVOR="py311"  # version-literal-ok: last-resort fallback after probing the box + matrix
echo "==> Python dep flavor for ${BOX_ABI:-unknown ABI}: ${PY_FLAVOR}"

# 0b) Install the package's other RUN_DEPENDS — what `pkg install
#     pfSense-pkg-pfBlockerNG[-devel]` pulls per the port Makefile — so the
#     installed package is actually functional (jq/grepcidr/iprange for the IP
#     path, libmaxminddb/py-maxminddb for GeoIP, py-sqlite3 for the DNSBL DB,
#     lighttpd for the sinkhole webserver; rsync is handled in 0a). Best-effort:
#     a renamed/absent dep shouldn't block the smoke install, so warn not abort.
echo "==> Installing pfBlockerNG runtime dependencies (mirrors port RUN_DEPENDS)"
ssh_t "env ASSUME_ALWAYS_YES=yes pkg install -y libmaxminddb gnugrep grepcidr iprange jq lighttpd ${PY_FLAVOR}-sqlite3 ${PY_FLAVOR}-maxminddb" \
    || echo "WARN: some pfBlockerNG runtime deps failed to install (continuing)" >&2

# 1) Sync the package files. src/ mirrors the filesystem root, so src/usr/local/
#    maps to /usr/local/ (NOT src/usr/ -> /usr/local/, which would land under
#    /usr/local/local/). Matches the port's WRKSRC${PREFIX} -> ${PREFIX} install.
rsync -az -e "$RSH" \
    --exclude="*.pyc" --exclude="__pycache__/" \
    "${REPO_ROOT}/src/usr/local/" "${SSH_TARGET}:/usr/local/"
rsync -az -e "$RSH" \
    "${REPO_ROOT}/src/etc/" "${SSH_TARGET}:/etc/"

# info.xml with the package name AND version substituted (the port does both:
# %%PKGNAME%% in post-extract, %%PKGVERSION%% in do-install). %%PKGNAME%% is the
# FULL port name (pfSense-pkg-pfBlockerNG[-devel]) — the port substitutes
# ${PORTNAME}, not the short channel name. Derive the version from git (tags may
# be absent in a shallow CI checkout -> short hash; fall back to a dev marker).
PORTNAME="pfSense-pkg-${PKG_NAME}"
PKGVERSION="$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null || echo '0.0.0-dev')"
sed -e "s|%%PKGNAME%%|${PORTNAME}|g" -e "s|%%PKGVERSION%%|${PKGVERSION}|g" \
    "${REPO_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
    > "${REPO_ROOT}/.info.xml.tmp"
ssh_t mkdir -p "/usr/local/share/${PORTNAME}"
rsync -az -e "$RSH" "${REPO_ROOT}/.info.xml.tmp" \
    "${SSH_TARGET}:/usr/local/share/${PORTNAME}/info.xml"
rm -f "${REPO_ROOT}/.info.xml.tmp"

# 2) Run pfSense's package POST-INSTALL — the EXACT step `pkg` runs after
#    extracting files. The FreeBSD port's files/pkg-install.in does:
#        php -f /etc/rc.packages <PORTNAME> POST-INSTALL
#    and rc.packages registers the package from pfblockerng.xml, installs the
#    menu/services, and runs the package's custom_php_install_command, which
#    includes pfblockerng_install.inc. PORTNAME = pfSense-pkg-pfBlockerNG[-devel].
echo "==> Running package POST-INSTALL (registration + install hooks)"
ssh_t "/usr/local/bin/php -f /etc/rc.packages ${PORTNAME} POST-INSTALL"

# 3) Restart the services that load the new files (svc restart is a real
#    pfSense built-in; pfBlockerNG itself is driven via the php CLI, not pfSsh).
#    The restarts are async, so WAIT for Unbound to answer again before the
#    caller queries it — otherwise an unbound-control / dig races the reload.
echo "==> Restarting unbound + nginx"
ssh_t "pfSsh.php playback svc restart unbound"
echo "==> Waiting for Unbound to come back up"
i=0
until ssh_t '/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1'; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
        echo "Error: Unbound did not come back up after restart" >&2
        exit 1
    fi
    sleep 2
done
ssh_t "pfSsh.php playback svc restart nginx"

echo "==> Done. pfBlockerNG ($PKG_NAME) installed on $SSH_TARGET"
echo "    Next (harness, per case): inject feeds/addresses/whitelist via the"
echo "    config API, then: /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update"
