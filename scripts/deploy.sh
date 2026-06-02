#!/bin/sh
# deploy.sh — copy pfBlockerNG files to a running pfSense instance over SSH
# and restart the services that need to pick up the changes.
#
# Usage:
#   ./scripts/deploy.sh <ssh-target> [--channel devel|stable]
#
# Examples:
#   ./scripts/deploy.sh root@192.168.1.1
#   ./scripts/deploy.sh root@192.168.1.1 --channel stable
#
# The script must be run from the root of the pfBlockerNG repository.
# It defaults to the devel channel.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHANNEL="devel"
SSH_TARGET=""

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --channel)
            CHANNEL="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [ -z "$SSH_TARGET" ]; then
                SSH_TARGET="$1"
            else
                echo "Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$SSH_TARGET" ]; then
    echo "Usage: $0 <ssh-target> [--channel devel|stable]" >&2
    exit 1
fi

if [ "$CHANNEL" != "devel" ] && [ "$CHANNEL" != "stable" ]; then
    echo "Error: --channel must be 'devel' or 'stable'" >&2
    exit 1
fi

PKG_PREFIX="/usr/local"
PKG_NAME="pfBlockerNG"
if [ "$CHANNEL" = "devel" ]; then
    PKG_NAME="pfBlockerNG-devel"
fi

echo "==> Deploying pfBlockerNG ($CHANNEL) to $SSH_TARGET"

# Sync all source files, preserving permissions
rsync -az --rsync-path="rsync" \
    --exclude="*.pyc" \
    --exclude="__pycache__/" \
    "${REPO_ROOT}/src/usr/" \
    "${SSH_TARGET}:${PKG_PREFIX}/"

rsync -az --rsync-path="rsync" \
    "${REPO_ROOT}/src/etc/" \
    "${SSH_TARGET}:/etc/"

# Substitute %%PKGNAME%% in info.xml and sync to the channel-specific directory
sed "s|%%PKGNAME%%|${PKG_NAME}|g" \
    "${REPO_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
    > "${REPO_ROOT}/.info.xml.tmp"
ssh "$SSH_TARGET" mkdir -p "${PKG_PREFIX}/share/pfSense-pkg-${PKG_NAME}"
rsync -az "${REPO_ROOT}/.info.xml.tmp" \
    "${SSH_TARGET}:${PKG_PREFIX}/share/pfSense-pkg-${PKG_NAME}/info.xml"
rm -f "${REPO_ROOT}/.info.xml.tmp"

echo "==> Files synced. Restarting services..."

# Restart Unbound to reload pfb_unbound.py and the DNS blocklists
ssh "$SSH_TARGET" "pfSsh.php playback svc restart unbound"

# Reload the pfSense package subsystem so PHP changes take effect
ssh "$SSH_TARGET" "pfSsh.php playback svc restart nginx"

echo "==> Done. pfBlockerNG ($CHANNEL) deployed to $SSH_TARGET"
echo ""
echo "    Tip: to trigger a pfBlockerNG update from the pfSense shell:"
echo "    ssh $SSH_TARGET '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update'"
