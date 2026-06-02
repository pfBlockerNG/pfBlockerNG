#!/bin/sh
# install-from-repo.sh — install pfBlockerNG onto a FRESH pfSense straight from
# this repo's src/ (no Netgate pkg): sync the files, register the package from
# its GUI XML, and run its real install hooks so it is a functional, registered
# package. The smoke harness runs this after every boot — the disk is immutable
# (overlay discarded), so every run is a clean install of the branch under test.
#
# It does NOT add feeds / addresses / whitelists / response modes — that is
# per-case config injection (ADR-04 Phase 4), done later by the test harness.
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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# 1) Sync the package files (mirrors deploy.sh).
rsync -az -e "$RSH" \
    --exclude="*.pyc" --exclude="__pycache__/" \
    "${REPO_ROOT}/src/usr/" "${SSH_TARGET}:/usr/local/"
rsync -az -e "$RSH" \
    "${REPO_ROOT}/src/etc/" "${SSH_TARGET}:/etc/"

# info.xml with the channel package name substituted.
sed "s|%%PKGNAME%%|${PKG_NAME}|g" \
    "${REPO_ROOT}/src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml" \
    > "${REPO_ROOT}/.info.xml.tmp"
ssh_t mkdir -p "/usr/local/share/pfSense-pkg-${PKG_NAME}"
rsync -az -e "$RSH" "${REPO_ROOT}/.info.xml.tmp" \
    "${SSH_TARGET}:/usr/local/share/pfSense-pkg-${PKG_NAME}/info.xml"
rm -f "${REPO_ROOT}/.info.xml.tmp"

# 2) Run pfSense's package POST-INSTALL — the EXACT step `pkg` runs after
#    extracting files. The FreeBSD port's files/pkg-install.in does:
#        php -f /etc/rc.packages <PORTNAME> POST-INSTALL
#    and rc.packages registers the package from pfblockerng.xml, installs the
#    menu/services, and runs the package's custom_php_install_command, which
#    includes pfblockerng_install.inc. PORTNAME = pfSense-pkg-pfBlockerNG[-devel].
echo "==> Running package POST-INSTALL (registration + install hooks)"
ssh_t "/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-${PKG_NAME} POST-INSTALL"

# 3) Restart the services that load the new files (svc restart is a real
#    pfSense built-in; pfBlockerNG itself is driven via the php CLI, not pfSsh).
echo "==> Restarting unbound + nginx"
ssh_t "pfSsh.php playback svc restart unbound"
ssh_t "pfSsh.php playback svc restart nginx"

echo "==> Done. pfBlockerNG ($PKG_NAME) installed on $SSH_TARGET"
echo "    Next (harness, per case): inject feeds/addresses/whitelist via the"
echo "    config API, then: /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update"
