#!/bin/sh
# deploy.sh — copy pfBlockerNG files to a running pfSense instance over SSH
# and restart the services that need to pick up the changes.
#
# Usage:
#   ./scripts/deploy.sh <ssh-target>
#
# Example:
#   ./scripts/deploy.sh root@192.168.1.1
#
# The script must be run from the root of the pfBlockerNG repository. The
# package identity is the canonical pfSense-pkg-pfBlockerNG on every channel
# (issue #2148: the channel comes from the installed repository, never from a
# name suffix; the -devel port is retired).

set -e

REPO_ROOT="$(CDPATH='' cd "$(dirname "$0")/.." && pwd)"
SSH_TARGET=""

for a; do case "$a" in -*) echo "Unknown option: $a" >&2; exit 1 ;; esac; done
[ $# -eq 1 ] || { echo "Usage: $0 <ssh-target>" >&2; exit 1; }
SSH_TARGET="$1"

PKG_PREFIX="/usr/local"

echo "==> Deploying pfBlockerNG to $SSH_TARGET"

# Sync all source files. src/ mirrors the filesystem root, so src/usr/local/ maps
# to /usr/local/ — syncing src/usr/ -> /usr/local/ would land everything under
# /usr/local/local/ (silently a no-op on a running box). Matches the port's
# WRKSRC${PREFIX} -> ${PREFIX} install.
#
# OVERWRITE CONTENTS ONLY — never touch the box's ownership/permissions. We push
# from a dev checkout where the files are owned by the local user (uid 501/staff),
# NOT root:wheel; with -a's -o/-g/-p, root rsync would rewrite the live files'
# owner/group/mode to those bogus dev values. --no-owner/--no-group/--no-perms
# leave each existing file's owner/group/mode exactly as pfSense installed them
# and only replace the bytes (-t still preserved for an efficient size+mtime sync;
# a freshly edited file carries a recent mtime, so php-fpm opcache revalidates it).
rsync -az --no-owner --no-group --no-perms --rsync-path="rsync" \
    --exclude="*.pyc" \
    --exclude="__pycache__/" \
    "${REPO_ROOT}/src/usr/local/" \
    "${SSH_TARGET}:${PKG_PREFIX}/"

rsync -az --no-owner --no-group --no-perms --rsync-path="rsync" \
    "${REPO_ROOT}/src/etc/" \
    "${SSH_TARGET}:/etc/"

# info.xml: <name> is the SHORT pfBlockerNG (what pfSense's get_package_id looks
# up; the port renders ${PORTNAME:S/pfSense-pkg-//}), the share directory the full
# port name.
sed "s|%%PKGNAME%%|pfBlockerNG|g" \
    "${REPO_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
    > "${REPO_ROOT}/.info.xml.tmp"
ssh "$SSH_TARGET" mkdir -p "${PKG_PREFIX}/share/pfSense-pkg-pfBlockerNG"
rsync -az --no-owner --no-group --no-perms --rsync-path="rsync" "${REPO_ROOT}/.info.xml.tmp" \
    "${SSH_TARGET}:${PKG_PREFIX}/share/pfSense-pkg-pfBlockerNG/info.xml"
rm -f "${REPO_ROOT}/.info.xml.tmp"

echo "==> Files synced. Restarting services..."

# Restart Unbound to reload pfb_unbound.py and the DNS blocklists
ssh "$SSH_TARGET" "pfSsh.php playback svc restart unbound"

# Reload the pfSense package subsystem so PHP changes take effect
ssh "$SSH_TARGET" "pfSsh.php playback svc restart nginx"

echo "==> Done. pfBlockerNG deployed to $SSH_TARGET"
echo ""
echo "    Tip: to trigger a pfBlockerNG update from the pfSense shell:"
echo "    ssh $SSH_TARGET '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update'"
