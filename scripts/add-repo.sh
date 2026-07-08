#!/bin/sh
# add-repo.sh — bootstrap pfBlockerNG's self-hosted pkg repository on a pfSense
# box (ADR-17, the client side). Run it ON the pfSense box: installs the
# boot-time repo-conf generator rc.d hook (ADR-39), which does ALL edition/
# version/arch detection itself (an OS upgrade self-corrects, no work here),
# runs the hook once now, then `pkg update` + verifies the package is visible
# from OUR repo. Default sets up the shared `pfblockerng` release repo (stable
# + devel; pick the package at install time); --nightly sets up the separate
# bleeding-edge `pfblockerng-nightly` repo instead. Idempotent; see --help.

set -eu

# Absolute path for the privileged binary (pfSense convention; don't trust $PATH).
# Override via PKG_BIN env var for testing without a live pfSense box.
PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"

# PFBLOCKERNG_ROOT: filesystem root prefix (tests override to a tmpdir).
PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
ROOT="${PFBLOCKERNG_ROOT%/}"
REPOS_DIR="${ROOT}/usr/local/etc/pkg/repos"

# On-box installed path for the boot-time generator hook (no /lib helper — the
# hook is fully self-contained; detection is folded in, ADR-39).
ON_BOX_RCD_DIR="${ROOT}/usr/local/etc/rc.d"
ON_BOX_HOOK="${ON_BOX_RCD_DIR}/pfblockerng_repo_generate.sh"

# The hook source script lives next to this file. Resolve relative to this
# script's directory so it works regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_SRC="${SCRIPT_DIR}/rc.d/pfblockerng_repo_generate.sh"

# pfb_emit_embedded_hook — print the rc.d generator hook to stdout. In the repository
# copy this is a STUB that fails loud: the standalone scripts/rc.d/pfblockerng_repo_generate.sh
# is the source of truth, used directly from a checkout. The website build (gen_landing.py)
# replaces the body between the PFB_EMBED markers with the hook in a single-quoted heredoc,
# producing the one-file add-repo.sh served at <base>/add-repo.sh for `fetch | sh`.
pfb_emit_embedded_hook() {
    # PFB_EMBED_HOOK_BEGIN — do not edit; replaced by gen_landing.py at website-build time.
    printf 'add-repo: no embedded hook in this copy. Run from a checkout, or use the\n' >&2
    printf '  published one-file bootstrap: fetch -qo - %s/add-repo.sh | sh\n' "${DEFAULT_BASE_URL}" >&2
    return 1
    # PFB_EMBED_HOOK_END
}

# Direct GitHub Pages catalog base (ADR-39; no Cloudflare Worker).
DEFAULT_BASE_URL="https://pfblockerng.github.io/pkg"
CONF_PRIORITY=100

# The marker the hook writes as the conf's first line (the verify target).
CONF_MARKER="Generated at boot by pfblockerng_repo_generate"

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

# ── The conf body (single source of truth; byte-identical to the hook + the
#    build-repo[-portable] --print-conf generators) ──────────────────────────────
# $1 = fully-resolved URL (no trailing slash). The URL is a STATIC, directly-resolved
# string — no ${ABI} token. One run writes one resolved conf for this box's variant.
# The boot rc.d hook regenerates it on a pfSense OS upgrade (ADR-39).
print_conf() {
    _pc_url="${1%/}"
    cat <<EOF
# ${CONF_MARKER} (ADR-39) — do not edit; re-run add-repo.sh to change.
# pfBlockerNG (${CHANNEL} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is
# fully resolved for this box's edition/version/arch (ADR-39); the boot
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
# A resolved URL needs --catalog-path <varver>/<arch> (the live bootstrap leaves
# detection to the hook; --print-conf is a documentation/dry-run aid).
if [ "$PRINT_CONF" -eq 1 ]; then
    [ -n "${CATALOG_PATH}" ] || {
        printf 'add-repo: --catalog-path <varver>/<arch> is required with --print-conf\n' >&2
        exit 2
    }
    _url="${BASE_URL%/}/${CHANNEL}/${CATALOG_PATH}"
    print_conf "${_url}"
    exit 0
fi

# ── Live bootstrap ─────────────────────────────────────────────────────────────
command -v "$PKG_BIN" >/dev/null 2>&1 || {
    printf 'add-repo: '\''%s'\'' not found — run this ON a pfSense box\n' "$PKG_BIN" >&2
    exit 1
}

# 1. Install the boot-time generator rc.d hook (the only file we install). From a git
#    checkout the hook is the sibling file (HOOK_SRC); the published one-file bootstrap
#    (served at <base>/add-repo.sh) carries it embedded — see pfb_emit_embedded_hook.
printf '==> Installing boot-time generator hook to %s\n' "${ON_BOX_HOOK}"
mkdir -p "${ON_BOX_RCD_DIR}"
if [ -f "${HOOK_SRC}" ]; then
    cp "${HOOK_SRC}" "${ON_BOX_HOOK}"
else
    pfb_emit_embedded_hook > "${ON_BOX_HOOK}"
fi
chmod 755 "${ON_BOX_HOOK}"

# 2. Stub the conf so the hook regenerates it (the hook only rewrites confs that
#    already exist — an absent channel stays absent). The stub is overwritten in
#    place by the hook in step 3; it is left intact only if detection fails, in
#    which case the marker check below fails loud.
printf '==> Staging %s conf at %s (hook will resolve it)\n' "${CHANNEL}" "${CONF_PATH}"
mkdir -p "${REPOS_DIR}"
printf '# pfBlockerNG %s repo conf — pending boot-time generation (ADR-39).\n' "${CHANNEL}" > "${CONF_PATH}"

# 3. Run the hook once now to resolve the conf for THIS box (it also runs every
#    boot via rc.d). Pass the box paths explicitly so a non-default
#    PFBLOCKERNG_ROOT (tests) and --base-url (forks/staging) are honored.
printf '==> Running the generator hook to resolve the conf now\n'
PFB_RELEASE_CONF="${REPOS_DIR}/pfblockerng.conf" \
PFB_NIGHTLY_CONF="${REPOS_DIR}/pfblockerng-nightly.conf" \
PFB_BASE_URL="${BASE_URL}" \
PFB_PKG_BIN="${PKG_BIN}" \
PFB_PRODUCT_LABEL="${ROOT}/etc/product_label" \
PFB_VERSION_FILE="${ROOT}/etc/version" \
    sh "${ON_BOX_HOOK}" onestart || true

# 4. Verify the hook resolved the conf (the marker line is present). If detection
#    failed the stub from step 2 survives (no marker) — fail loud.
if ! grep -q "${CONF_MARKER}" "${CONF_PATH}" 2>/dev/null; then
    printf 'add-repo: the generator hook did not resolve %s (no marker line).\n' "${CONF_PATH}" >&2
    printf '  Variant detection may have failed. Inspect: sh %s onestart\n' "${ON_BOX_HOOK}" >&2
    exit 1
fi
printf '==> Conf resolved:\n'
sed -n 's/^[[:space:]]*url:[[:space:]]*/    url: /p' "${CONF_PATH}" >&2

# 5. pkg update (refresh catalogs, including our repo).
printf '==> pkg update (refreshing catalogs, including our repo)\n'
env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" update -f >/dev/null

# 6. VERIFY a pfBlockerNG package is visible FROM OUR repo (not merely that pkg
#    update ran). `pkg rquery -r <repo>` queries that ONE repo's catalog; a hit
#    means our catalog loaded and carries the package. The release repo carries
#    two (stable may not be published yet) — finding EITHER proves the repo
#    loaded; nightly carries one. Exit non-zero (fail loud) only if NONE present.
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
