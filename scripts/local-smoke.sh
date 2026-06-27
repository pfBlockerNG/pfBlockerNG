#!/bin/sh
# local-smoke.sh — run the ADR-04 live-VM smoke suite locally on a Debian/KVM box.
#
# Wraps the environment setup that the GitHub Actions smoke workflow does inline, so a
# local two-VM run "just works": the stub-DNS-on-:53 relay, the civm client image, and
# the standard SMOKE_* variables. Full background + rationale: docs/misc/local-smoke-debian.md.
#
# Usage:
#   scripts/local-smoke.sh [pytest args...]
#
# Required (env or flags):
#   SMOKE_SSH_KEY        guest SSH private key (baked into the image)
#   SMOKE_PKG            built branch .pkg (scripts/build-pkg-portable.py)
#   SMOKE_IMAGE_DIR      dir holding exactly one pfSense *.qcow2
#
# Optional:
#   SMOKE_CLIENT_IMAGE_DIR   dir holding the civm *.qcow2 (enables the two-VM cases).
#                            Defaults to ./.smoke-civm; pulled via oras if absent.
#   CIVM_REF                 civm image ref (default ghcr.io/pfblockerng/civm:v1)
#   PYTHON                   python to use (default: ./.venv/bin/python, else python3)
#   SMOKE_PYTEST_TARGET      default test path (default tests/smoke)
#   NO_TWO_VM=1              skip the civm setup (pfSense-only suites)
#
# POSIX sh; quoted expansions.

set -eu

usage() {
	sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

case "${1:-}" in
	-h|--help) usage 0 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# --- required inputs ------------------------------------------------------- #
missing=
for var in SMOKE_SSH_KEY SMOKE_PKG SMOKE_IMAGE_DIR; do
	eval "val=\${$var:-}"
	[ -n "$val" ] || missing="$missing $var"
done
if [ -n "$missing" ]; then
	echo "local-smoke: missing required env:$missing" >&2
	echo "             see docs/misc/local-smoke-debian.md" >&2
	exit 2
fi
[ -f "$SMOKE_SSH_KEY" ] || { echo "local-smoke: SMOKE_SSH_KEY not a file: $SMOKE_SSH_KEY" >&2; exit 2; }
[ -f "$SMOKE_PKG" ] || { echo "local-smoke: SMOKE_PKG not a file: $SMOKE_PKG" >&2; exit 2; }
[ -d "$SMOKE_IMAGE_DIR" ] || { echo "local-smoke: SMOKE_IMAGE_DIR not a directory: $SMOKE_IMAGE_DIR" >&2; exit 2; }
# Fail early if the image dir doesn't hold exactly one *.qcow2 (the harness requires it).
# Count via a loop, NOT `set --`, so we never clobber "$@" (the pass-through pytest args).
_qcow_n=0
for _qcow in "$SMOKE_IMAGE_DIR"/*.qcow2; do [ -e "$_qcow" ] && _qcow_n=$((_qcow_n + 1)); done
[ "$_qcow_n" -eq 1 ] || { echo "local-smoke: SMOKE_IMAGE_DIR must contain exactly one *.qcow2 (found $_qcow_n)" >&2; exit 2; }
[ -e /dev/kvm ] || { echo "local-smoke: /dev/kvm absent — KVM is required" >&2; exit 2; }

# --- stub-DNS-on-:53 relay ------------------------------------------------- #
# The mock DNS binds 127.0.0.1:53 so libslirp NATs the guest's 192.168.89.2:53 to it
# (port-preserving). Lower the unprivileged-port floor so the non-root process can bind :53.
SMOKE_STUB_DNS_ADDR="${SMOKE_STUB_DNS_ADDR:-127.0.0.1}"
SMOKE_STUB_DNS_PORT="${SMOKE_STUB_DNS_PORT:-53}"
export SMOKE_STUB_DNS_ADDR SMOKE_STUB_DNS_PORT
if [ "$SMOKE_STUB_DNS_PORT" -lt 1024 ]; then
	floor="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
	if [ "$floor" -gt "$SMOKE_STUB_DNS_PORT" ]; then
		echo "local-smoke: lowering net.ipv4.ip_unprivileged_port_start to $SMOKE_STUB_DNS_PORT (was $floor)" >&2
		sysctl -w "net.ipv4.ip_unprivileged_port_start=$SMOKE_STUB_DNS_PORT" >/dev/null 2>&1 \
			|| sudo sysctl -w "net.ipv4.ip_unprivileged_port_start=$SMOKE_STUB_DNS_PORT" >/dev/null
	fi
fi

# --- civm client image (two-VM topology) ----------------------------------- #
if [ "${NO_TWO_VM:-}" != "1" ]; then
	if [ -z "${SMOKE_CLIENT_IMAGE_DIR:-}" ]; then
		SMOKE_CLIENT_IMAGE_DIR="$REPO_ROOT/.smoke-civm"
	fi
	if [ ! -d "$SMOKE_CLIENT_IMAGE_DIR" ] || [ -z "$(ls "$SMOKE_CLIENT_IMAGE_DIR"/*.qcow2 2>/dev/null)" ]; then
		CIVM_REF="${CIVM_REF:-ghcr.io/pfblockerng/civm:v1}"
		echo "local-smoke: pulling civm image $CIVM_REF -> $SMOKE_CLIENT_IMAGE_DIR" >&2
		command -v oras >/dev/null 2>&1 || { echo "local-smoke: oras not on PATH (needed to pull civm)" >&2; exit 2; }
		mkdir -p "$SMOKE_CLIENT_IMAGE_DIR"
		( cd "$SMOKE_CLIENT_IMAGE_DIR" && oras pull "$CIVM_REF" )
	fi
	export SMOKE_CLIENT_IMAGE_DIR
fi

# --- python ---------------------------------------------------------------- #
if [ -z "${PYTHON:-}" ]; then
	if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
		PYTHON="$REPO_ROOT/.venv/bin/python"
	else
		PYTHON=python3
	fi
fi

# --- free stale host forwards --------------------------------------------- #
pkill -9 -f qemu-system-x86_64 2>/dev/null || true

target="${SMOKE_PYTEST_TARGET:-tests/smoke}"

# Inject `-m smoke` only as a DEFAULT — if the caller passed their own `-m`
# (e.g. `-m ui_render` for a Tier-A run, `-m repo`), respect it instead of
# silently appending a second, winning `-m smoke`. A `-k` selector and every
# other pytest arg always pass straight through.
# ponytail: bare `-m` token detection; refine only if someone needs the `-m=foo` form.
marker_args="-m smoke"
for a in "$@"; do
	[ "$a" = "-m" ] && { marker_args=""; break; }
done

# Explicit pytest args (if any) override the default target; quote everything (repo
# shell rule) and branch instead of relying on word-splitting an unquoted $target.
if [ "$#" -gt 0 ]; then
	echo "local-smoke: running smoke suite ($*${marker_args:+ $marker_args})" >&2
	# shellcheck disable=SC2086  # marker_args is a deliberate 0-or-2-word default
	exec "$PYTHON" -m pytest "$@" $marker_args --override-ini="addopts="
fi
echo "local-smoke: running smoke suite ($target)" >&2
exec "$PYTHON" -m pytest "$target" -m smoke --override-ini="addopts="
