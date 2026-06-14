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
#   Default (NO argument) sets up the RELEASE repo `pfblockerng` — one shared catalog
#   carrying BOTH the stable and devel packages, exactly like Netgate ships
#   `pfSense-pkg-pfBlockerNG` and `-devel` from its single `pfSense` repo (the two
#   packages CONFLICT — install one). After the bootstrap, pick the package:
#       pkg install pfSense-pkg-pfBlockerNG          # stable
#       pkg install pfSense-pkg-pfBlockerNG-devel    # development tree
#
#   --nightly sets up the SEPARATE `pfblockerng-nightly` repo instead (its own
#   `nightly/` catalog path). Bleeding edge — NOT for daily use: the only guarantee is
#   that CI passed (devel still carries a stability target; nightly does not):
#       pkg install pfSense-pkg-pfBlockerNG-nightly
#
#   default     -> conf /usr/local/etc/pkg/repos/pfblockerng.conf,         repo `pfblockerng`
#   --nightly   -> conf /usr/local/etc/pkg/repos/pfblockerng-nightly.conf, repo `pfblockerng-nightly`
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
#   add-repo.sh                       # set up the release repo (stable + devel), pkg update, verify
#   add-repo.sh --nightly             # set up the nightly repo instead (bleeding edge)
#   add-repo.sh --print-conf [--nightly]       # print the conf to stdout and exit (no writes)
#   add-repo.sh --base-url <url> [--nightly]   # override the catalog base (forks/staging)
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

CHANNEL="release"
PRINT_CONF=0
BASE_URL="$DEFAULT_BASE_URL"

usage() {
    cat <<'USAGE'
add-repo.sh — bootstrap pfBlockerNG's self-hosted pkg repository (run ON the pfSense box).

Usage:
  add-repo.sh                                set up the release repo (stable + devel), pkg update, verify
  add-repo.sh --nightly                      set up the nightly repo instead (bleeding edge; not for daily use)
  add-repo.sh --print-conf [--nightly]       print the repo conf to stdout and exit (no writes)
  add-repo.sh --base-url <url> [--nightly]   override the catalog base (forks/staging)

After the release bootstrap, install ONE of (the packages conflict):
  pkg install pfSense-pkg-pfBlockerNG          # stable
  pkg install pfSense-pkg-pfBlockerNG-devel    # development tree
USAGE
}

# ── Arg parsing ────────────────────────────────────────────────────────────────
# The channel is a FLAG, not a positional: default is the release repo; --nightly
# selects the separate nightly repo. (There is no stable/devel switch — both live in
# the one release repo; you pick the package at `pkg install` time.)
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly)      CHANNEL="nightly"; shift ;;
        --print-conf)   PRINT_CONF=1; shift ;;
        --base-url)     BASE_URL="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        -*) echo "add-repo: unknown option: $1 (see --help)" >&2; exit 2 ;;
        *)  echo "add-repo: unexpected argument '$1' — the channel is a flag (--nightly); the release repo is the default. See --help." >&2; exit 2 ;;
    esac
done

# ── Per-channel identity ───────────────────────────────────────────────────────
# release (default) -> repo `pfblockerng`,        conf pfblockerng.conf,        Pages root
#                      carries BOTH pfSense-pkg-pfBlockerNG (stable) and ...-devel
# nightly           -> repo `pfblockerng-nightly`, conf pfblockerng-nightly.conf, `nightly/` subtree
# URL_SUBPATH: nightly is served from the `nightly/` catalog subtree; the release repo
# from the Pages root. The literal ${ABI} pkg(8) variable follows it.
# PKG_NAMES: the package(s) the verify step checks + the install hints printed (the
# release repo carries two; nightly one).
case "$CHANNEL" in
    release)
        REPO_NAME="pfblockerng"
        CONF_NAME="pfblockerng.conf"
        URL_SUBPATH=""
        PKG_NAMES="pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-devel"
        ;;
    nightly)
        REPO_NAME="pfblockerng-nightly"
        CONF_NAME="pfblockerng-nightly.conf"
        URL_SUBPATH="nightly/"
        PKG_NAMES="pfSense-pkg-pfBlockerNG-nightly"
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
# pfBlockerNG (${CHANNEL} channel) — self-hosted pkg repository (ADR-17).
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

echo "==> Writing ${CHANNEL} repo conf to ${CONF_PATH}"
mkdir -p "$REPOS_DIR"
# Rewrite unconditionally => idempotent (a re-run refreshes the conf in place).
print_conf "$BASE_URL" > "$CONF_PATH"

echo "==> pkg update (refreshing catalogs, including our repo)"
env ASSUME_ALWAYS_YES=yes "$PKG_BIN" update -f >/dev/null

# VERIFY a pfBlockerNG package is visible FROM OUR repo (not merely that pkg update
# ran). `pkg rquery -r <repo>` queries that ONE repo's catalog; a hit means our catalog
# loaded and carries the package. The release repo carries two packages (stable may not
# be published yet) — finding EITHER proves the repo loaded; nightly carries one. Exit
# non-zero (fail loud) only if NONE is present.
echo "==> Verifying pfBlockerNG package(s) are visible from repo '${REPO_NAME}'"
found_any=0
# Word-splitting the space-separated package list is intentional.
# shellcheck disable=SC2086
for pkg_name in $PKG_NAMES; do
    if "$PKG_BIN" rquery -r "$REPO_NAME" '%n %v' "$pkg_name" 2>/dev/null | grep -q .; then
        found="$("$PKG_BIN" rquery -r "$REPO_NAME" '%n-%v' "$pkg_name" 2>/dev/null | head -n1)"
        echo "==> OK: ${found} available from '${REPO_NAME}'"
        echo "    Install:  ${PKG_BIN} install ${pkg_name}"
        found_any=1
    fi
done
if [ "$found_any" -eq 0 ]; then
    echo "add-repo: no pfBlockerNG package visible from repo '${REPO_NAME}' after pkg update." >&2
    echo "  Checked conf: ${CONF_PATH}" >&2
    echo "  The catalog may not be published yet for this box's ABI, or the URL is unreachable." >&2
    echo "  Inspect with: ${PKG_BIN} -d update   (traces the catalog fetch)" >&2
    exit 1
fi
echo "==> Done — conf at ${CONF_PATH}"
