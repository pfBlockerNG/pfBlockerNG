#!/bin/sh
# add-repo.sh — bootstrap pfBlockerNG's self-hosted pkg repository on a pfSense
# box (ADR-17 Phase 4, the client side). Run it ON the pfSense box. It writes a
# pkg(8) repo conf under /usr/local/etc/pkg/repos/, runs `pkg update`, and
# VERIFIES our package is visible from OUR repo — after which
#   pkg install pfSense-pkg-pfBlockerNG-devel   (or -y, no -f, no -r)
# resolves deps and installs our build, and the stock webConfigurator Install
# pulls it too via cross-repo resolution (ADR §2; install is not repo-locked).
#
# CHANNELS
#   devel  (default) -> conf /usr/local/etc/pkg/repos/pfblockerng-devel.conf
#                       repo name `pfblockerng-devel`, pkg pfSense-pkg-pfBlockerNG-devel
#   stable           -> conf /usr/local/etc/pkg/repos/pfblockerng.conf
#                       repo name `pfblockerng`,       pkg pfSense-pkg-pfBlockerNG
#
# THE CONF (single source of truth — matches `build-repo.sh --print-conf`):
#   url:            STATIC base + the literal ${ABI} pkg(8) variable (expanded by
#                   pkg, NOT the shell) so one conf auto-follows the box's ABI
#                   across a pfSense OS upgrade. No shell/query interpolation, so
#                   the URL-encoding gate passes.
#   mirror_type:    none.
#   signature_type: none — NONE-signed; trust anchor is HTTPS to the host (no CI
#                   signing key). pfSense honors per-repo `none` (ADR §1 Context 4).
#   priority:       ABOVE the base Netgate `pfSense` repo (ships 0). Phase 1 PROVED
#                   repo priority decides cross-repo selection (a higher-priority
#                   repo wins even at a lower version), so this is what makes our
#                   build win. 100 clears pfSense's 0 with margin.
#   enabled:        yes.
#
# IDEMPOTENT: re-running rewrites the conf (safe to run again at any time).
#
# Usage:
#   add-repo.sh [devel|stable]      # write the conf, pkg update, verify (default: devel)
#   add-repo.sh --print-conf [devel|stable]   # print the conf to stdout and exit (no writes)
#   add-repo.sh --base-url <url> [devel|stable]   # override the base (forks/staging)
#
# POSIX sh; quoted expansions; absolute path for the privileged `pkg` binary.

set -eu

# Absolute path for the privileged binary (pfSense convention; don't trust $PATH).
PKG_BIN="/usr/local/sbin/pkg"
REPOS_DIR="/usr/local/etc/pkg/repos"

# The published GitHub Pages base (custom domain, served over HTTPS). This is the
# SAME base build-repo.sh / build-repo-portable.py default to — the conf below is
# byte-identical to their --print-conf for the devel channel. Override --base-url
# for a fork/staging host. The conf appends the literal ${ABI} pkg(8) variable.
DEFAULT_BASE_URL="https://brait.dev/pfBlockerNG"
CONF_PRIORITY=100

CHANNEL="devel"
PRINT_CONF=0
BASE_URL="$DEFAULT_BASE_URL"

# ── Arg parsing ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --print-conf)   PRINT_CONF=1; shift ;;
        --base-url)     BASE_URL="$2"; shift 2 ;;
        devel|stable)   CHANNEL="$1"; shift ;;
        -h|--help)
            sed -n '29,40p' "$0"   # the Usage block from the header
            exit 0 ;;
        -*) echo "add-repo: unknown option: $1" >&2; exit 2 ;;
        *)  echo "add-repo: unknown channel '$1' (expected devel|stable)" >&2; exit 2 ;;
    esac
done

# ── Per-channel identity ───────────────────────────────────────────────────────
# devel -> repo `pfblockerng-devel`, conf pfblockerng-devel.conf, pkg ...-devel
# stable-> repo `pfblockerng`,       conf pfblockerng.conf,       pkg pfSense-pkg-pfBlockerNG
if [ "$CHANNEL" = devel ]; then
    REPO_NAME="pfblockerng-devel"
    CONF_NAME="pfblockerng-devel.conf"
    PKG_NAME="pfSense-pkg-pfBlockerNG-devel"
    CHANNEL_LABEL="devel"
else
    REPO_NAME="pfblockerng"
    CONF_NAME="pfblockerng.conf"
    PKG_NAME="pfSense-pkg-pfBlockerNG"
    CHANNEL_LABEL="stable"
fi
CONF_PATH="${REPOS_DIR}/${CONF_NAME}"

# ── The conf body (single source of truth; matches build-repo.sh --print-conf) ──
# $1 = base URL (trailing slash stripped). The url value is a STATIC string with
# the literal ${ABI} pkg(8) variable appended — single-quoted on emission so
# neither this shell nor the URL-encoding gate sees a live expansion.
print_conf() {
    base="${1%/}"
    cat <<EOF
# pfBlockerNG (${CHANNEL_LABEL} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The \${ABI}
# variable is expanded by pkg(8) and follows the box across a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects our build.
${REPO_NAME}: {
  url: "${base}/\${ABI}",
  mirror_type: none,
  signature_type: none,
  priority: ${CONF_PRIORITY},
  enabled: yes
}
EOF
}

# ── --print-conf: emit and exit, no side effects (the test + a dry-run use this) ─
if [ "$PRINT_CONF" -eq 1 ]; then
    print_conf "$BASE_URL"
    exit 0
fi

# ── Live bootstrap ─────────────────────────────────────────────────────────────
command -v "$PKG_BIN" >/dev/null 2>&1 || {
    echo "add-repo: '$PKG_BIN' not found — run this ON a pfSense box" >&2
    exit 1
}

echo "==> Writing ${CHANNEL_LABEL} repo conf to ${CONF_PATH}"
mkdir -p "$REPOS_DIR"
# Rewrite unconditionally => idempotent (a re-run refreshes the conf in place).
print_conf "$BASE_URL" > "$CONF_PATH"

echo "==> pkg update (refreshing catalogs, including our repo)"
env ASSUME_ALWAYS_YES=yes "$PKG_BIN" update -f >/dev/null

# VERIFY our package is visible FROM OUR repo (not merely that pkg update ran).
# `pkg rquery -r <repo>` queries that ONE repo's catalog; a hit means our catalog
# loaded and carries the package. Exit non-zero (fail loud) if it is absent.
echo "==> Verifying ${PKG_NAME} is visible from repo '${REPO_NAME}'"
if "$PKG_BIN" rquery -r "$REPO_NAME" '%n %v' "$PKG_NAME" 2>/dev/null | grep -q .; then
    found="$("$PKG_BIN" rquery -r "$REPO_NAME" '%n-%v' "$PKG_NAME" 2>/dev/null | head -n1)"
    echo "==> OK: ${found} available from '${REPO_NAME}' (${CONF_PATH})"
    echo "    Install:  ${PKG_BIN} install ${PKG_NAME}"
    echo "    Upgrade:  ${PKG_BIN} upgrade ${PKG_NAME}"
else
    echo "add-repo: ${PKG_NAME} is NOT visible from repo '${REPO_NAME}' after pkg update." >&2
    echo "  Checked conf: ${CONF_PATH}" >&2
    echo "  The catalog may not be published yet for this box's ABI, or the URL is unreachable." >&2
    echo "  Inspect with: ${PKG_BIN} -d update   (traces the catalog fetch)" >&2
    exit 1
fi
