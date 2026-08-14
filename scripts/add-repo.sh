#!/bin/sh
# add-repo.sh — subscribe a pfSense box to ONE pfBlockerNG pkg channel (ADR-17,
# the client side). Run it ON the pfSense box. It installs the boot-time
# repo-conf generator rc.d hook (ADR-39), retires any other pfBlockerNG channel
# conf, stubs this channel's conf so the hook regenerates it for THIS box's
# edition/version, runs the hook once to resolve the conf now, then runs
# `pkg update` and VERIFIES the package is visible from the channel's repo —
# after which
#   pkg install pfSense-pkg-pfBlockerNG   (or -y, no -f, no -r)
# resolves deps and installs the pfBlockerNG build, and the stock
# webConfigurator Install pulls it too via cross-repo resolution (ADR §2;
# install is not repo-locked). Invocation forms: see --help.
#
# WHY A HOOK DOES THE DETECTION: a pfSense OS upgrade can change the box's
# edition/version (which moves the catalog subtree). The rc.d hook
# regenerates the conf every boot, so the URL self-corrects after an upgrade
# with no work here. add-repo.sh therefore does NO detection itself — it installs
# the hook and runs it; the hook is the single source of the resolved conf.
#
# CHANNELS
#   The Pages catalogue is FOUR channels — stable, testing, edge, nightly — each
#   owning its own <channel>/<varver>/ catalog subtree, ALL resolving to the ONE
#   canonical package `pfSense-pkg-pfBlockerNG` (channel is catalogue placement,
#   not a package-name suffix). Select one with `--channel <ch>`.
#
#   SINGLE-REPOSITORY SUBSCRIPTION (issue #2148): a box enables EXACTLY ONE
#   project channel repository. Every channel repo shares one priority (100) and
#   `pkg` does not order across equal-priority repositories, so two enabled
#   channels would leave the selected build undetermined. Each channel catalogue
#   strictly contains its slower channels' files (edge ⊇ testing ⊇ stable), so one
#   repository always suffices — including for an in-repo rollback on a faster
#   channel. Subscribing therefore RETIRES every other pfBlockerNG channel conf on
#   the box, reporting each removal — but only AFTER the new channel's catalogue is
#   proven to serve this box, so a channel with no build for this edition/version
#   can never strand a box by taking its working subscription with it. A run that
#   fails leaves the repository configuration exactly as it found it.
#
#   Moving FORWARD is: re-run with the new `--channel`, then upgrade normally —
#   ordinary `pkg` resolution applies only when the target version is higher
#   (`pkg` orders versions numerically, component-wise, never by date). Moving
#   BACK is an explicit repository-qualified downgrade/reinstall; disabling a
#   faster repository is not itself a downgrade.
#
#   Moving an EXISTING install off a legacy suffixed identity
#   (`pfSense-pkg-pfBlockerNG-devel`, `-nightly`) onto a channel is the job of the
#   sibling `migrate-channel.sh`; this script configures repositories only.
#
#   LEGACY (unchanged; still the behaviour with NO argument): sets up the RELEASE
#   repo `pfblockerng` — one shared catalog carrying BOTH the stable and devel
#   packages, exactly like Netgate ships `pfSense-pkg-pfBlockerNG` and `-devel`
#   from its single `pfSense` repo (the two packages CONFLICT — install one, see
#   --help). `--channel release` is REJECTED — release is this legacy default,
#   not one of the four channel names.
#
#   default                       -> conf pfblockerng.conf,          repo `pfblockerng`          (legacy release)
#   --nightly / --channel nightly -> conf pfblockerng-nightly.conf,  repo `pfblockerng-nightly`
#   --channel stable              -> conf pfblockerng-stable.conf,   repo `pfblockerng-stable`
#   --channel testing             -> conf pfblockerng-testing.conf,  repo `pfblockerng-testing`
#   --channel edge                -> conf pfblockerng-edge.conf,     repo `pfblockerng-edge`
#
# THE CONF (single source of truth — byte-identical to `build-repo.sh --print-conf`,
# `build-repo-portable.py --print-conf`, and what the rc.d hook writes):
#   url:            Direct GitHub Pages URL, fully resolved by the hook for this box
#                   (arch-less; NO_ARCH, issue #1806):
#                   https://pfblockerng.github.io/pkg/<channel>/<varver>
#   mirror_type:    none.
#   signature_type: none — NONE-signed; trust anchor is HTTPS to the host (no CI
#                   signing key). pfSense honors per-repo `none` (ADR §1 Context 4).
#   priority:       ABOVE the base Netgate `pfSense` repo (ships 0). Repo priority
#                   decides cross-repo selection (a higher-priority repo wins even
#                   at a lower version — proven in ADR-17), so this is what makes
#                   the pfBlockerNG build win. 100 clears pfSense's 0 with margin.
#   enabled:        yes.
#
# IDEMPOTENT: re-running reinstalls the hook and re-runs it (safe at any time).
#
# POSIX sh; quoted expansions; absolute path for the privileged `pkg` binary.
# Env:
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /); override in tests to
#                     redirect conf/hook writes to a temp dir.
#   PKG_BIN           pkg binary path (default: /usr/local/sbin/pkg); override
#                     in tests to stub out pkg.

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
SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
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
add-repo.sh — subscribe this pfSense box to ONE pfBlockerNG pkg channel (run ON the box).

Usage:
  add-repo.sh --channel stable|testing|edge|nightly
                                             subscribe to that channel, pkg update, verify
  add-repo.sh --nightly                      alias for --channel nightly
  add-repo.sh                                legacy: the pre-channel shared release repo
  add-repo.sh --print-conf --channel <ch> --catalog-path <varver>
                                             print the repo conf to stdout and exit (no writes)
  add-repo.sh --base-url <url> [--channel <ch>]
                                             override the catalog base (forks/staging)

A box subscribes to EXACTLY ONE project channel repository: every channel serves the
same canonical package at the same priority, and each channel's catalogue strictly
contains its slower channels' files, so one repository is always sufficient.
Subscribing therefore retires any other pfBlockerNG channel conf on the box.

After subscribing, install the one canonical package:
  pkg install pfSense-pkg-pfBlockerNG

To move to another channel, re-run with the new --channel and upgrade. Moving BACK to
an older build is an explicit repository-qualified operation, e.g.
  pkg install -f -r pfblockerng-edge pfSense-pkg-pfBlockerNG-<older-version>
USAGE
}

# ── Arg parsing ────────────────────────────────────────────────────────────────
# The channel is a FLAG, not a positional: default is the legacy release repo;
# --channel <stable|testing|edge|nightly> selects a four-channel repo (issue #2147)
# and --nightly stays the alias for --channel nightly. (The legacy release repo has
# no stable/devel switch — both live in it; you pick the package at `pkg install`
# time.)
while [ $# -gt 0 ]; do
    case "$1" in
        --nightly)      CHANNEL="nightly"; shift ;;
        --channel)
            [ $# -ge 2 ] || { printf 'add-repo: --channel requires a value\n' >&2; exit 2; }
            case "$2" in
                stable|testing|edge|nightly) CHANNEL="$2" ;;
                *) printf 'add-repo: invalid --channel '\''%s'\'' — valid channels: stable, testing, edge, nightly\n' "$2" >&2; exit 2 ;;
            esac
            shift 2 ;;
        --print-conf)   PRINT_CONF=1; shift ;;
        --catalog-path)
            [ $# -ge 2 ] || { printf 'add-repo: --catalog-path requires a value\n' >&2; exit 2; }
            CATALOG_PATH="$2"; shift 2 ;;
        --base-url)
            [ $# -ge 2 ] || { printf 'add-repo: --base-url requires a value\n' >&2; exit 2; }
            BASE_URL="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        -*) printf 'add-repo: unknown option: %s (see --help)\n' "$1" >&2; exit 2 ;;
        *)  printf 'add-repo: unexpected argument '\''%s'\'' — the channel is a flag (--nightly / --channel); the release repo is the default. See --help.\n' "$1" >&2; exit 2 ;;
    esac
done

# ── Per-channel identity ───────────────────────────────────────────────────────
# release (default) -> repo `pfblockerng`,          conf pfblockerng.conf,          `release/` subtree (legacy)
#                      carries BOTH pfSense-pkg-pfBlockerNG (stable) and ...-devel
# nightly           -> repo `pfblockerng-nightly`,  conf pfblockerng-nightly.conf,  `nightly/` subtree
# stable            -> repo `pfblockerng-stable`,   conf pfblockerng-stable.conf,   `stable/` subtree
# testing           -> repo `pfblockerng-testing`,  conf pfblockerng-testing.conf,  `testing/` subtree
# edge              -> repo `pfblockerng-edge`,     conf pfblockerng-edge.conf,     `edge/` subtree
# The four channels (stable/testing/edge/nightly) all carry the ONE canonical
# `pfSense-pkg-pfBlockerNG` identity — channel is catalogue placement, not a
# package-name suffix (the `-nightly` spelling is a native ports RECIPE name; the
# published nightly artifact is canonical). PKG_NAMES: the package(s) the verify
# step checks + the install hints printed. Only the legacy release repo carries
# two; every channel repo carries exactly the canonical one.
case "$CHANNEL" in
    release)
        REPO_NAME="pfblockerng"
        CONF_NAME="pfblockerng.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-devel"
        ;;
    nightly)
        REPO_NAME="pfblockerng-nightly"
        CONF_NAME="pfblockerng-nightly.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG"
        ;;
    stable)
        REPO_NAME="pfblockerng-stable"
        CONF_NAME="pfblockerng-stable.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG"
        ;;
    testing)
        REPO_NAME="pfblockerng-testing"
        CONF_NAME="pfblockerng-testing.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG"
        ;;
    edge)
        REPO_NAME="pfblockerng-edge"
        CONF_NAME="pfblockerng-edge.conf"
        PKG_NAMES="pfSense-pkg-pfBlockerNG"
        ;;
esac
CONF_PATH="${REPOS_DIR}/${CONF_NAME}"

# Every project conf this script may ever have written. Exactly ONE of them may be
# enabled at a time: the channel repos share one priority (100) and pkg does not
# order across equal-priority repositories, so two enabled channels would make the
# build a box receives depend on nothing the user can see. Each channel catalogue
# strictly contains its slower channels' files, so one repository is always enough
# — including for an in-repo rollback on a faster channel (issue #2148).
PROJECT_CONFS="pfblockerng.conf
pfblockerng-stable.conf
pfblockerng-testing.conf
pfblockerng-edge.conf
pfblockerng-nightly.conf"

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
# fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,
# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.
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
# A resolved URL needs --catalog-path <varver> (the live bootstrap leaves
# detection to the hook; --print-conf is a documentation/dry-run aid).
if [ "$PRINT_CONF" -eq 1 ]; then
    [ -n "${CATALOG_PATH}" ] || {
        printf 'add-repo: --catalog-path <varver> is required with --print-conf\n' >&2
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

# 2. Stage the conf so the hook regenerates it (the hook only rewrites confs that
#    already exist — an absent channel stays absent). The stub is overwritten in
#    place by the hook in step 3; it is left intact only if detection fails, in
#    which case the marker check below fails loud.
#
#    Every OTHER project conf stays in place for now. Retiring it here — before the
#    target catalogue is known to work — would destroy a working subscription on
#    behalf of one that may not be published for this box's variant yet, which is
#    the same "never delete what cannot be replaced" rule the sibling
#    migrate-channel.sh is built around. Retirement is step 6, after the verify.
mkdir -p "${REPOS_DIR}"
# Staging TRUNCATES the conf, so "it existed" is not enough to undo it — a re-subscribe
# to the channel the box is already on would be left holding the one-line stub, i.e. a
# conf that subscribes to nothing. Keep the previous body aside instead.
CONF_BACKUP=""
if [ -f "${CONF_PATH}" ]; then
    CONF_BACKUP="${CONF_PATH}.pfb-prev.$$"
    cp "${CONF_PATH}" "${CONF_BACKUP}"
fi
printf '==> Staging %s conf at %s (hook will resolve it)\n' "${CHANNEL}" "${CONF_PATH}"
printf '# pfBlockerNG %s repo conf — pending boot-time generation (ADR-39).\n' "${CHANNEL}" > "${CONF_PATH}"

# Undo everything THIS run did to the repository configuration, so a failed bootstrap
# leaves the box exactly as it found it: a conf this run created is removed, and a conf
# it truncated is restored byte-for-byte. Either way the box keeps a working
# subscription — losing one is the destruction this ordering exists to prevent.
# $1 = exit status (default 1; the signal trap passes 130).
abort_unstaged() {
    if [ -n "${CONF_BACKUP}" ]; then
        mv -f "${CONF_BACKUP}" "${CONF_PATH}"
        CONF_BACKUP=""
        printf '  Restored the previous %s conf; your subscription is unchanged.\n' "${CHANNEL}" >&2
    else
        rm -f "${CONF_PATH}"
        printf '  Removed the conf this run staged; your previous subscription is untouched.\n' >&2
    fi
    exit "${1:-1}"
}

# On success the backup is redundant — drop it so no stray file is left in the repos dir.
drop_conf_backup() {
    [ -n "${CONF_BACKUP}" ] && rm -f "${CONF_BACKUP}"
    CONF_BACKUP=""
}

# An interrupt lands in the same half-applied state a failure does, so it gets the same
# treatment rather than just a tidy-up: the conf goes back to what it was. Both traps are
# needed — EXIT sweeps the backup on every ordinary path, and the signal trap has to exit
# itself or the script would carry on past the handler.
trap 'drop_conf_backup' EXIT
trap 'abort_unstaged 130' INT HUP TERM

# 3. Run the hook once now to resolve the conf for THIS box (it also runs every
#    boot via rc.d). Pass every channel path explicitly so a non-default
#    PFBLOCKERNG_ROOT (tests) and --base-url (forks/staging) are honored — an
#    omitted override would fall back to the real /usr/local path.
printf '==> Running the generator hook to resolve the conf now\n'
PFB_RELEASE_CONF="${REPOS_DIR}/pfblockerng.conf" \
PFB_STABLE_CONF="${REPOS_DIR}/pfblockerng-stable.conf" \
PFB_TESTING_CONF="${REPOS_DIR}/pfblockerng-testing.conf" \
PFB_EDGE_CONF="${REPOS_DIR}/pfblockerng-edge.conf" \
PFB_NIGHTLY_CONF="${REPOS_DIR}/pfblockerng-nightly.conf" \
PFB_BASE_URL="${BASE_URL}" \
PFB_PRODUCT_LABEL="${ROOT}/etc/product_label" \
PFB_VERSION_FILE="${ROOT}/etc/version" \
    sh "${ON_BOX_HOOK}" onestart || true

# 4. Verify the hook resolved the conf (the marker line is present). If detection
#    failed the stub from step 2 survives (no marker) — fail loud.
if ! grep -q "${CONF_MARKER}" "${CONF_PATH}" 2>/dev/null; then
    printf 'add-repo: the generator hook did not resolve %s (no marker line).\n' "${CONF_PATH}" >&2
    printf '  Variant detection may have failed. Inspect: sh %s onestart\n' "${ON_BOX_HOOK}" >&2
    abort_unstaged
fi
printf '==> Conf resolved:\n'
sed -n 's/^[[:space:]]*url:[[:space:]]*/    url: /p' "${CONF_PATH}" >&2

# 5. pkg update (refresh catalogs, including the pfBlockerNG repo), then VERIFY a
#    pfBlockerNG package is visible FROM the pfBlockerNG repo (not merely that pkg
#    update ran). `pkg rquery -r <repo>` queries that ONE repo's catalog, so a
#    still-enabled previous channel cannot mask a missing package here. Every
#    channel repo carries the one canonical package; only the legacy release repo
#    carries two (stable may not be published yet) — finding EITHER proves that
#    repo loaded. Exit non-zero (fail loud) only if NONE present.
# `pkg update` exits non-zero when ANY enabled repository fails to refresh — including
# the channel this run is switching AWAY from, whose catalogue may be exactly what went
# unpublished. Under `set -e` that would abort here: after the conf was staged, before
# retirement, leaving the box subscribed to TWO project repositories at equal priority.
# Route it through the same cleanup as every other failure instead.
printf '==> pkg update (refreshing catalogs, including the pfBlockerNG repo)\n'
env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" update -f >/dev/null || {
    printf 'add-repo: %s update -f failed — catalogs were not refreshed.\n' "${PKG_BIN}" >&2
    printf '  A repository is unreachable or serving an unreadable catalog.\n' >&2
    printf '  Inspect with: %s -d update   (traces the catalog fetch)\n' "${PKG_BIN}" >&2
    abort_unstaged
}

printf '==> Verifying pfBlockerNG package(s) are visible from repo '\''%s'\''\n' "${REPO_NAME}"
found_any=0
# Word-splitting the space-separated package list is intentional.
# shellcheck disable=SC2086
for pkg_name in $PKG_NAMES; do
    if "${PKG_BIN}" rquery -r "${REPO_NAME}" '%n %v' "${pkg_name}" 2>/dev/null | grep -q .; then
        # rquery lists EVERY version the catalogue retains, in catalogue order —
        # report the newest one, which is what `pkg install` would resolve.
        found="$("${PKG_BIN}" rquery -r "${REPO_NAME}" '%n-%v' "${pkg_name}" 2>/dev/null | sort -V | tail -n1)"
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
    abort_unstaged
fi

# 6. Only now enforce single-repository subscription: the target is proven usable, so
#    retiring every OTHER project conf cannot strand the box. After this the box is
#    subscribed to exactly one channel and `pkg` never has to choose between two
#    equal-priority project repositories. Reported, never silent.
printf '%s\n' "${PROJECT_CONFS}" | while IFS= read -r _other_conf; do
    [ -n "${_other_conf}" ] || continue
    [ "${_other_conf}" = "${CONF_NAME}" ] && continue
    [ -f "${REPOS_DIR}/${_other_conf}" ] || continue
    printf '==> Retiring %s — a box subscribes to ONE pfBlockerNG channel\n' \
        "${REPOS_DIR}/${_other_conf}"
    rm -f "${REPOS_DIR}/${_other_conf}"
done
drop_conf_backup

printf '==> Done — conf at %s\n' "${CONF_PATH}"
