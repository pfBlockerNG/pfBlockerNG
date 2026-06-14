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
#   The stable and devel packages share ONE repo/catalog — the `pfblockerng` repo,
#   exactly like Netgate ships `pfSense-pkg-pfBlockerNG` and `-devel` from its single
#   `pfSense` repo (the two packages CONFLICT — install one). So `stable` and `devel`
#   write the SAME conf (byte-identical); they differ only in which package the verify
#   step checks + the install hint printed. Nightly lives on its own catalog path and
#   so needs its own conf.
#   devel  (default) -> conf /usr/local/etc/pkg/repos/pfblockerng.conf
#                       repo name `pfblockerng`,       pkg pfSense-pkg-pfBlockerNG-devel
#   stable           -> conf /usr/local/etc/pkg/repos/pfblockerng.conf  (SAME file)
#                       repo name `pfblockerng`,       pkg pfSense-pkg-pfBlockerNG
#   nightly          -> conf /usr/local/etc/pkg/repos/pfblockerng-nightly.conf
#                       repo name `pfblockerng-nightly`, pkg ...-nightly (bleeding edge)
#
# THE CONF (single source of truth — matches `build-repo.sh --print-conf`):
#   url:            Cloudflare Worker URL (ADR-20). The Worker routes requests to
#                   the correct versioned catalog dir based on the pfSense User-Agent
#                   (CE vs Plus, major.minor version). One conf written once; never
#                   needs re-running after a pfSense OS upgrade — the Worker re-routes
#                   automatically. Override --base-url for forks/staging.
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
#   add-repo.sh [devel|stable|nightly]      # write the conf, pkg update, verify (default: devel)
#   add-repo.sh --print-conf [devel|stable|nightly]   # print the conf to stdout and exit (no writes)
#   add-repo.sh --base-url <url> [devel|stable|nightly]   # override the base (forks/staging)
#
# POSIX sh; quoted expansions; absolute path for the privileged `pkg` binary.
# Env:
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /); override in tests to
#                     redirect conf writes to a temp dir.
#   PKG_BIN           pkg binary path (default: /usr/local/sbin/pkg); override
#                     in tests to stub out pkg (conf write happens before any pkg call).

set -eu

# Absolute path for the privileged binary (pfSense convention; don't trust $PATH).
# Override via PKG_BIN env var for testing without a live pfSense box.
PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"

# PFBLOCKERNG_ROOT: filesystem root prefix (tests override to a tmpdir).
PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
REPOS_DIR="${PFBLOCKERNG_ROOT%/}/usr/local/etc/pkg/repos"

# Cloudflare Worker URL (ADR-20, primary path). The Worker routes to the correct
# versioned catalog dir (ce-2.8/${ABI}/, plus-26.03/${ABI}/, …) based on the
# pfSense User-Agent header — pkg(8) injects it automatically on every repo fetch.
# Written once; the conf never needs updating on a pfSense OS upgrade.
# Override with --base-url for forks/staging.
DEFAULT_BASE_URL="https://pkg.pfblockerng.workers.dev"
CONF_PRIORITY=100

CHANNEL="devel"
PRINT_CONF=0
BASE_URL="$DEFAULT_BASE_URL"

# ── Arg parsing ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --print-conf)   PRINT_CONF=1; shift ;;
        --base-url)     BASE_URL="$2"; shift 2 ;;
        devel|stable|nightly)   CHANNEL="$1"; shift ;;
        -h|--help)
            sed -n '34,39p' "$0"   # the Usage block from the header
            exit 0 ;;
        -*) echo "add-repo: unknown option: $1" >&2; exit 2 ;;
        *)  echo "add-repo: unknown channel '$1' (expected devel|stable|nightly)" >&2; exit 2 ;;
    esac
done

# ── Per-channel identity ───────────────────────────────────────────────────────
# devel  -> repo `pfblockerng`,         conf pfblockerng.conf,         pkg ...-devel
# stable -> repo `pfblockerng`,         conf pfblockerng.conf,         pkg pfSense-pkg-pfBlockerNG
# nightly-> repo `pfblockerng-nightly`, conf pfblockerng-nightly.conf, pkg ...-nightly
# stable + devel deliberately resolve to the SAME repo/conf (one shared `pfblockerng`
# catalog carries both packages); only PKG_NAME (verify target + install hint) differs.
# URL_SUBPATH: nightly is served from the `nightly/` catalog subtree; the release
# channels from the Pages root. The literal ${ABI} pkg(8) variable follows it.
# CONF_LABEL names the REPO (not the channel) in the conf comment, so the stable and
# devel confs stay byte-identical (both "release"); CHANNEL_LABEL stays per-channel for
# the user-facing progress/verify messages only.
case "$CHANNEL" in
    devel)
        REPO_NAME="pfblockerng"
        CONF_NAME="pfblockerng.conf"
        CONF_LABEL="release"
        PKG_NAME="pfSense-pkg-pfBlockerNG-devel"
        CHANNEL_LABEL="devel"
        URL_SUBPATH=""
        ;;
    stable)
        REPO_NAME="pfblockerng"
        CONF_NAME="pfblockerng.conf"
        CONF_LABEL="release"
        PKG_NAME="pfSense-pkg-pfBlockerNG"
        CHANNEL_LABEL="stable"
        URL_SUBPATH=""
        ;;
    nightly)
        REPO_NAME="pfblockerng-nightly"
        CONF_NAME="pfblockerng-nightly.conf"
        CONF_LABEL="nightly"
        PKG_NAME="pfSense-pkg-pfBlockerNG-nightly"
        CHANNEL_LABEL="nightly"
        URL_SUBPATH="nightly/"
        ;;
esac
CONF_PATH="${REPOS_DIR}/${CONF_NAME}"

# ── The conf body (single source of truth; matches build-repo.sh --print-conf) ──
# $1 = base URL (trailing slash stripped). The url value is a STATIC string with
# the literal ${ABI} pkg(8) variable appended — single-quoted on emission so
# neither this shell nor the URL-encoding gate sees a live expansion.
print_conf() {
    base="${1%/}"
    cat <<EOF
# pfBlockerNG (${CONF_LABEL} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The \${ABI}
# variable is expanded by pkg(8) and follows the box across a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects our build.
${REPO_NAME}: {
  url: "${base}/${URL_SUBPATH}\${ABI}",
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
