#!/bin/sh
# add-repo.sh — bootstrap pfBlockerNG's self-hosted pkg repository on a pfSense
# box (ADR-17 Phase 4, the client side). Run it ON the pfSense box. It detects
# the box's pfSense edition/version/arch, writes a DIRECT, fully-resolved pkg(8)
# repo conf under /usr/local/etc/pkg/repos/, installs the self-heal rc.d hook
# (ADR-39), runs `pkg update`, and VERIFIES our package is visible from OUR
# repo — after which
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
#   url:            Direct GitHub Pages URL, fully resolved at install time:
#                   https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>
#                   where <varver>/<arch> are detected from the box (ADR-39).
#                   On a pfSense OS upgrade the self-heal rc.d hook rewrites only
#                   the <varver>/<arch> segment (see /usr/local/etc/rc.d/).
#   mirror_type:    none.
#   signature_type: none — NONE-signed; trust anchor is HTTPS to the host (no CI
#                   signing key). pfSense honors per-repo `none` (ADR §1 Context 4).
#   priority:       ABOVE the base Netgate `pfSense` repo (ships 0). Phase 1 PROVED
#                   repo priority decides cross-repo selection (a higher-priority
#                   repo wins even at a lower version), so this is what makes our
#                   build win. 100 clears pfSense's 0 with margin.
#   enabled:        yes.
#
# IDEMPOTENT: re-running rewrites the conf and hook (safe to run again at any time).
#
# Usage:
#   add-repo.sh                       # set up the release repo (stable + devel), pkg update, verify
#   add-repo.sh --nightly             # set up the nightly repo instead (bleeding edge)
#   add-repo.sh --print-conf [--nightly] [--catalog-path <varver>/<arch>]
#                                     # print the conf to stdout and exit (no writes)
#   add-repo.sh --base-url <url> [--nightly]   # override the catalog base (forks/staging)
#
# POSIX sh; quoted expansions; absolute path for the privileged `pkg` binary.
# Env:
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /); override in tests to
#                     redirect conf/hook writes to a temp dir.
#   PKG_BIN           pkg binary path (default: /usr/local/sbin/pkg); override
#                     in tests to stub out pkg (conf write happens before any pkg call).
#   PFB_GLOBALS_PLUS_INC / PFB_VERSION_FILE / PFB_PKG_CMD — overridable paths for
#                     detect_variant.sh (see that file); used by tests for box mocking.

set -eu

# Absolute path for the privileged binary (pfSense convention; don't trust $PATH).
# Override via PKG_BIN env var for testing without a live pfSense box.
PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"

# PFBLOCKERNG_ROOT: filesystem root prefix (tests override to a tmpdir).
PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
REPOS_DIR="${PFBLOCKERNG_ROOT%/}/usr/local/etc/pkg/repos"

# On-box installed paths for the detection helper and the self-heal hook.
# These must be absolute paths on the target pfSense box.
ON_BOX_RCD_DIR="${PFBLOCKERNG_ROOT%/}/usr/local/etc/rc.d"
ON_BOX_LIB_DIR="${PFBLOCKERNG_ROOT%/}/usr/local/lib/pfblockerng"
ON_BOX_DETECT_HELPER="${ON_BOX_LIB_DIR}/detect_variant.sh"
ON_BOX_HOOK="${ON_BOX_RCD_DIR}/pfblockerng_repo_selfheal.sh"

# The detection helper and self-heal hook source scripts live next to this file.
# Resolve relative to this script's directory so it works regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DETECT_VARIANT_SRC="${SCRIPT_DIR}/lib/detect_variant.sh"
HOOK_SRC="${SCRIPT_DIR}/rc.d/pfblockerng_repo_selfheal.sh"

# Direct GitHub Pages catalog base (ADR-39; no Cloudflare Worker).
DEFAULT_BASE_URL="https://pfblockerng.github.io/pkg"
CONF_PRIORITY=100

CHANNEL="release"
PRINT_CONF=0
BASE_URL="$DEFAULT_BASE_URL"
CATALOG_PATH=""

usage() {
    cat <<'USAGE'
add-repo.sh — bootstrap pfBlockerNG's self-hosted pkg repository (run ON the pfSense box).

Usage:
  add-repo.sh                                set up the release repo (stable + devel), pkg update, verify
  add-repo.sh --nightly                      set up the nightly repo instead (bleeding edge; not for daily use)
  add-repo.sh --print-conf [--nightly] [--catalog-path <varver>/<arch>]
                                             print the repo conf to stdout and exit (no writes)
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
        --catalog-path)
            [ $# -ge 2 ] || { printf 'add-repo: --catalog-path requires a value\n' >&2; exit 2; }
            CATALOG_PATH="$2"; shift 2 ;;
        --base-url)
            [ $# -ge 2 ] || { printf 'add-repo: --base-url requires a value\n' >&2; exit 2; }
            BASE_URL="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        -*) printf 'add-repo: unknown option: %s (see --help)\n' "$1" >&2; exit 2 ;;
        *)  printf 'add-repo: unexpected argument '\''%s'\'' — the channel is a flag (--nightly); the release repo is the default. See --help.\n' "$1" >&2; exit 2 ;;
    esac
done

# ── Per-channel identity ───────────────────────────────────────────────────────
# release (default) -> repo `pfblockerng`,        conf pfblockerng.conf,        Pages root
#                      carries BOTH pfSense-pkg-pfBlockerNG (stable) and ...-devel
# nightly           -> repo `pfblockerng-nightly`, conf pfblockerng-nightly.conf, `nightly/` subtree
# PKG_NAMES: the package(s) the verify step checks + the install hints printed (the
# release repo carries two; nightly one).
case "$CHANNEL" in
    release)
        REPO_NAME="pfblockerng"
        CONF_NAME="pfblockerng.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-devel"
        ;;
    nightly)
        REPO_NAME="pfblockerng-nightly"
        CONF_NAME="pfblockerng-nightly.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG-nightly"
        ;;
esac
CONF_PATH="${REPOS_DIR}/${CONF_NAME}"

# ── Variant detection (on-box) ─────────────────────────────────────────────────
# Source the detection helper on demand (when CATALOG_PATH is not explicitly
# provided). In tests, PFB_GLOBALS_PLUS_INC / PFB_VERSION_FILE / PFB_PKG_CMD
# are injected via the environment; detect_variant.sh respects those overrides.
_DETECT_SOURCED=0
_source_detect_helper() {
    if [ "${_DETECT_SOURCED}" -eq 0 ]; then
        # shellcheck disable=SC1090
        . "${DETECT_VARIANT_SRC}"
        _DETECT_SOURCED=1
    fi
}

# Resolve the <varver>/<arch> catalog path: explicit --catalog-path wins (tests/forks);
# otherwise source the helper and detect from the live box.
detect_catalog() {
    if [ -n "${CATALOG_PATH}" ]; then
        printf '%s' "${CATALOG_PATH}"
    else
        _source_detect_helper
        pfb_detect_catalog
    fi
}

# ── The conf body (single source of truth; matches build-repo.sh --print-conf) ──
# $1 = fully-resolved URL (no trailing slash).
# The URL is a STATIC, directly-resolved string — no ${ABI} token anywhere.
# One run of add-repo.sh writes one resolved conf for this box's edition/version/arch.
# The self-heal rc.d hook rewrites only the <varver>/<arch> segment on a pfSense
# OS upgrade (ADR-39).
print_conf() {
    _pc_url="${1%/}"
    cat <<EOF
# pfBlockerNG (${CHANNEL} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is
# fully resolved for this box's edition/version/arch (ADR-39); the self-heal
# rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects our build.
${REPO_NAME}: {
  url: "${_pc_url}",
  mirror_type: none,
  signature_type: none,
  priority: ${CONF_PRIORITY},
  enabled: yes
}
EOF
}

# ── --print-conf: emit and exit, no side effects (the test + a dry-run use this) ─
if [ "$PRINT_CONF" -eq 1 ]; then
    _catalog="$(detect_catalog)"
    _url="${BASE_URL%/}/${CHANNEL}/${_catalog}"
    print_conf "${_url}"
    exit 0
fi

# ── Live bootstrap ─────────────────────────────────────────────────────────────
command -v "$PKG_BIN" >/dev/null 2>&1 || {
    printf 'add-repo: '\''%s'\'' not found — run this ON a pfSense box\n' "$PKG_BIN" >&2
    exit 1
}

# Resolve the catalog path from the live box (sources detect_variant.sh on demand).
CATALOG="$(detect_catalog)"
RESOLVED_URL="${BASE_URL%/}/${CHANNEL}/${CATALOG}"

printf '==> Writing %s repo conf to %s\n' "${CHANNEL}" "${CONF_PATH}"
mkdir -p "${REPOS_DIR}"
# Rewrite unconditionally => idempotent (a re-run refreshes the conf in place).
print_conf "${RESOLVED_URL}" > "${CONF_PATH}"

# ── Install the self-heal rc.d hook and detection helper ──────────────────────
printf '==> Installing self-heal hook to %s\n' "${ON_BOX_HOOK}"
mkdir -p "${ON_BOX_RCD_DIR}"
mkdir -p "${ON_BOX_LIB_DIR}"

# Install the detection helper so the hook can source it on-box.
cp "${DETECT_VARIANT_SRC}" "${ON_BOX_DETECT_HELPER}"
chmod 644 "${ON_BOX_DETECT_HELPER}"

# Install the self-heal rc.d hook from the source tree.
cp "${HOOK_SRC}" "${ON_BOX_HOOK}"
chmod 755 "${ON_BOX_HOOK}"
printf '==> Self-heal hook installed: %s\n' "${ON_BOX_HOOK}"
printf '==> Detection helper installed: %s\n' "${ON_BOX_DETECT_HELPER}"

printf '==> pkg update (refreshing catalogs, including our repo)\n'
env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" update -f >/dev/null

# VERIFY a pfBlockerNG package is visible FROM OUR repo (not merely that pkg update
# ran). `pkg rquery -r <repo>` queries that ONE repo's catalog; a hit means our catalog
# loaded and carries the package. The release repo carries two packages (stable may not
# be published yet) — finding EITHER proves the repo loaded; nightly carries one. Exit
# non-zero (fail loud) only if NONE is present.
printf '==> Verifying pfBlockerNG package(s) are visible from repo '\''%s'\''\n' "${REPO_NAME}"
found_any=0
# Word-splitting the space-separated package list is intentional.
# shellcheck disable=SC2086
for pkg_name in $PKG_NAMES; do
    if "${PKG_BIN}" rquery -r "${REPO_NAME}" '%n %v' "${pkg_name}" 2>/dev/null | grep -q .; then
        found="$("${PKG_BIN}" rquery -r "${REPO_NAME}" '%n-%v' "${pkg_name}" 2>/dev/null | head -n1)"
        printf '==> OK: %s available from '\''%s'\''\n' "${found}" "${REPO_NAME}"
        printf '    Install:  %s install %s\n' "${PKG_BIN}" "${pkg_name}"
        found_any=1
    fi
done
if [ "${found_any}" -eq 0 ]; then
    printf 'add-repo: no pfBlockerNG package visible from repo '\''%s'\'' after pkg update.\n' "${REPO_NAME}" >&2
    printf '  Checked conf: %s\n' "${CONF_PATH}" >&2
    printf '  The catalog may not be published yet for this box'\''s variant, or the URL is unreachable.\n' >&2
    printf '  Inspect with: %s -d update   (traces the catalog fetch)\n' "${PKG_BIN}" >&2
    exit 1
fi
printf '==> Done — conf at %s\n' "${CONF_PATH}"
