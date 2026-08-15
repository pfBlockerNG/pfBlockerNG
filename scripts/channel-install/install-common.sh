#!/bin/sh
# shellcheck shell=sh
# install-common.sh — shared state machine behind install-{stable,testing,edge,nightly}.sh
# (issue #2416). Sourced only — never run directly; defines pfb_channel_install() and
# helpers, with no top-level side effects beyond variable defaults (a `.` of this file
# from any shell context is inert until pfb_channel_install is called).
#
# WHY ONE SCRIPT PER CHANNEL: folds add-repo.sh (repo bootstrap) and migrate-channel.sh
# (installed-package move) into ONE idempotent state machine — a fresh box and an
# already-installed box converge through the same steps instead of two scripts run in
# sequence, and re-running on a converged box mutates nothing (check-then-act throughout).
#
# WHY EVERY pkg(8) CALL REDIRECTS STDIN FROM /dev/null: the published form is piped into
# `sh` (`fetch -qo - .../install-<ch>.sh | sh`), so the script's own stdin IS the script
# text — any child process that reads stdin without redirection would consume trailing
# script bytes and corrupt the run.
#
# Env (all overridable; forks/staging/tests set these):
#   PKG_BIN           pkg(8) binary path (default: /usr/local/sbin/pkg)
#   PFBLOCKERNG_ROOT  filesystem root prefix (default: /)
#   PFB_BASE_URL      catalog base (default: https://pfblockerng.github.io/pkg)
#
# Exit codes: see usage() below (kept in sync — the header is the interface doc).

PKG_BIN="${PKG_BIN:-/usr/local/sbin/pkg}"
PFBLOCKERNG_ROOT="${PFBLOCKERNG_ROOT:-/}"
ROOT="${PFBLOCKERNG_ROOT%/}"
PFB_BASE_URL="${PFB_BASE_URL:-https://pfblockerng.github.io/pkg}"

# The hook source lives next to this file's sibling scripts/rc.d/ in a checkout.
# Resolved once at source time (this file and install-<ch>.sh share a directory, so
# $0 here is still install-<ch>.sh's path — same CDPATH='' guard as add-repo.sh).
PFB_COMMON_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
HOOK_SRC="${PFB_COMMON_DIR}/../rc.d/pfblockerng_repo_generate.sh"

CANONICAL_PKG="pfSense-pkg-pfBlockerNG"
REPO_NAME="pfblockerng-${PFB_CHANNEL}"
CONF_NAME="pfblockerng-${PFB_CHANNEL}.conf"
REPOS_DIR="${ROOT}/usr/local/etc/pkg/repos"
CONF_PATH="${REPOS_DIR}/${CONF_NAME}"
ON_BOX_HOOK="${ROOT}/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"
CONFIG_XML="${ROOT}/cf/conf/config.xml"
CONF_MARKER="Generated at boot by pfblockerng_repo_generate"

# Every project conf any channel-install script (or the legacy add-repo.sh) may have
# written. Exactly one may be enabled at a time — single-repository subscription,
# issue #2148.
PROJECT_CONFS="pfblockerng.conf
pfblockerng-stable.conf
pfblockerng-testing.conf
pfblockerng-edge.conf
pfblockerng-nightly.conf"

# die CODE MSG... — every non-zero exit goes through this.
die() {
    _die_code="$1"
    shift
    printf 'install-%s: %s\n' "${PFB_CHANNEL}" "$*" >&2
    exit "${_die_code}"
}

# _pkg ARGS... — every pkg(8) invocation: /dev/null stdin (piped-script safety, see
# header) + ASSUME_ALWAYS_YES so a stray prompt cannot wedge a non-interactive run.
# Callers add -y themselves on verbs that take it (delete/install); read-only verbs
# (query/rquery/version/info) ignore ASSUME_ALWAYS_YES harmlessly.
_pkg() {
    env ASSUME_ALWAYS_YES=yes "${PKG_BIN}" "$@" </dev/null
}

usage() {
    cat <<USAGE
install-${PFB_CHANNEL}.sh — put this pfSense box on the pfBlockerNG ${PFB_CHANNEL} channel.

Usage:
  install-${PFB_CHANNEL}.sh              subscribe + install/converge (idempotent)
  install-${PFB_CHANNEL}.sh -h|--help    this text

Published at ${PFB_BASE_URL}/install-${PFB_CHANNEL}.sh; run ON the box:
  fetch -qo - ${PFB_BASE_URL}/install-${PFB_CHANNEL}.sh | sh

Installs the boot-time repo-conf generator hook (ADR-39), subscribes this box to the
${PFB_CHANNEL} channel ALONE (retiring any other pfBlockerNG channel conf), then
installs or moves the running package onto pfSense-pkg-pfBlockerNG from that channel.
Safe to re-run: a converged box performs no package changes.

Exit codes:
  0  ok, including a reported no-op (already up to date)
  1  environment: pkg binary or hook source not found
  2  usage: unknown argument
  4  target unavailable: the hook could not resolve the conf, pkg update failed, the
     catalogue offers nothing, or pkg version -t gave no usable answer
  5  a pkg operation (delete/install) failed
  6  post-install verification failed
USAGE
}

# pfb_emit_embedded_hook — print the rc.d generator hook to stdout. In the repository
# copy this is a STUB that fails loud: the standalone scripts/rc.d/pfblockerng_repo_generate.sh
# is the source of truth, used directly from a checkout via HOOK_SRC. The website build
# (gen_landing.py) replaces the body between the PFB_EMBED markers with the hook in a
# single-quoted heredoc, producing the self-contained install-<ch>.sh served at
# <base>/install-<ch>.sh for `fetch | sh`.
pfb_emit_embedded_hook() {
    # PFB_EMBED_HOOK_BEGIN — do not edit; replaced by gen_landing.py at website-build time.
    printf 'install-%s: no embedded hook in this copy — run from a checkout, or use the published %s/install-%s.sh\n' "${PFB_CHANNEL}" "${PFB_BASE_URL}" "${PFB_CHANNEL}" >&2
    return 1
    # PFB_EMBED_HOOK_END
}

# pfb_channel_install ARGS... — the state machine. Every step is check-then-act
# against live state, so a second run on a converged box performs zero package
# mutations and leaves the conf + hook bytes unchanged (idempotent).
pfb_channel_install() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h | --help)
                usage
                return 0
                ;;
            *)
                usage >&2
                die 2 "unknown argument: $1"
                ;;
        esac
    done

    # 1. Environment.
    command -v "${PKG_BIN}" >/dev/null 2>&1 ||
        die 1 "'${PKG_BIN}' not found — run this ON a pfSense box, or set PKG_BIN"

    # 2. Boot-time generator hook: install/refresh only if missing or different.
    _hook_tmp="$(mktemp "${TMPDIR:-/tmp}/pfb-hook.XXXXXX")" || die 1 "mktemp failed while staging the boot hook"
    if [ -f "${HOOK_SRC}" ]; then
        cp "${HOOK_SRC}" "${_hook_tmp}"
    else
        pfb_emit_embedded_hook >"${_hook_tmp}" || {
            rm -f "${_hook_tmp}"
            exit 1
        }
    fi
    if [ -f "${ON_BOX_HOOK}" ] && cmp -s "${_hook_tmp}" "${ON_BOX_HOOK}"; then
        printf '==> Hook up to date\n'
    else
        mkdir -p "$(dirname "${ON_BOX_HOOK}")"
        cp "${_hook_tmp}" "${ON_BOX_HOOK}"
        chmod 755 "${ON_BOX_HOOK}"
        printf '==> Installed boot-time generator hook to %s\n' "${ON_BOX_HOOK}"
    fi
    rm -f "${_hook_tmp}"

    # 3. Conf: stage a stub ONLY if absent — an existing conf is never truncated, the
    #    hook rewrites it in place (or leaves it untouched if detection fails), so no
    #    backup/restore dance is needed here (unlike add-repo.sh, which used to stage
    #    over a possibly-working conf before proving the new one).
    CONF_CREATED=0
    if [ ! -f "${CONF_PATH}" ]; then
        mkdir -p "${REPOS_DIR}"
        printf '# pfBlockerNG %s repo conf — pending boot-time generation (ADR-39).\n' "${PFB_CHANNEL}" >"${CONF_PATH}"
        CONF_CREATED=1
    fi

    printf '==> Running the generator hook to resolve the conf now\n'
    PFB_RELEASE_CONF="${REPOS_DIR}/pfblockerng.conf" \
        PFB_STABLE_CONF="${REPOS_DIR}/pfblockerng-stable.conf" \
        PFB_TESTING_CONF="${REPOS_DIR}/pfblockerng-testing.conf" \
        PFB_EDGE_CONF="${REPOS_DIR}/pfblockerng-edge.conf" \
        PFB_NIGHTLY_CONF="${REPOS_DIR}/pfblockerng-nightly.conf" \
        PFB_BASE_URL="${PFB_BASE_URL}" \
        PFB_PRODUCT_LABEL="${ROOT}/etc/product_label" \
        PFB_VERSION_FILE="${ROOT}/etc/version" \
        sh "${ON_BOX_HOOK}" onestart </dev/null || true

    if ! grep -q "${CONF_MARKER}" "${CONF_PATH}" 2>/dev/null; then
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        die 4 "the generator hook did not resolve ${CONF_PATH} (no marker line) — variant detection may have failed; inspect: sh ${ON_BOX_HOOK} onestart"
    fi
    printf '==> Conf resolved:\n'
    sed -n 's/^[[:space:]]*url:[[:space:]]*/    url: /p' "${CONF_PATH}" >&2

    # 4. Refresh THIS repo's catalog only (a stale/unpublished peer must not veto the
    #    switch — issue #2384).
    printf '==> pkg update -f -r %s (refreshing the pfBlockerNG catalog)\n' "${REPO_NAME}"
    _pkg update -f -r "${REPO_NAME}" || {
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        die 4 "$(printf '%s update -f -r %s failed — the catalog was not refreshed. Repo '\''%s'\'' is unreachable or serving an unreadable catalog. Inspect with: %s -d update -r %s' \
            "${PKG_BIN}" "${REPO_NAME}" "${REPO_NAME}" "${PKG_BIN}" "${REPO_NAME}")"
    }

    # 5. Pick the newest offered version with the SAME comparator pkg install itself
    #    resolves by (issue #2393) — rquery order is catalogue order, not version order.
    OFFERED=""
    for _offered in $(_pkg rquery -r "${REPO_NAME}" '%v' "${CANONICAL_PKG}" 2>/dev/null || true); do
        if [ -z "${OFFERED}" ]; then
            OFFERED="${_offered}"
            continue
        fi
        _order="$(_pkg version -t "${_offered}" "${OFFERED}" 2>/dev/null || true)"
        case "${_order}" in
            '>') OFFERED="${_offered}" ;;
            '<' | '=') ;;
            *)
                [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
                die 4 "\`${PKG_BIN} version -t\` gave no usable answer comparing '${_offered}' and '${OFFERED}' — cannot tell which build ${REPO_NAME} would install"
                ;;
        esac
    done
    [ -n "${OFFERED}" ] || {
        [ "${CONF_CREATED}" -eq 1 ] && rm -f "${CONF_PATH}"
        die 4 "repo '${REPO_NAME}' does not offer ${CANONICAL_PKG} — run \`pkg update -f\`, and check the ${PFB_CHANNEL} catalogue has a build for this pfSense edition/version"
    }
    printf '==> Target: %s-%s (repo %s)\n' "${CANONICAL_PKG}" "${OFFERED}" "${REPO_NAME}"

    # 6. Only now retire every OTHER project conf — the target is proven usable, so
    #    this cannot strand the box (issue #2148).
    for _other in ${PROJECT_CONFS}; do
        [ "${_other}" = "${CONF_NAME}" ] && continue
        [ -f "${REPOS_DIR}/${_other}" ] || continue
        printf '==> Retiring %s — a box subscribes to ONE pfBlockerNG channel\n' "${REPOS_DIR}/${_other}"
        rm -f "${REPOS_DIR}/${_other}"
    done

    # 7. Report installed state.
    _installed_names="$(_pkg query -g '%n' 'pfSense-pkg-pfBlockerNG*' 2>/dev/null || true)"
    _installed_names="$(printf '%s\n' "${_installed_names}" | grep -v '^[[:space:]]*$' || true)"
    if [ -n "${_installed_names}" ]; then
        for _iname in ${_installed_names}; do
            _iver="$(_pkg query '%v' "${_iname}" 2>/dev/null || true)"
            _irepo="$(_pkg query '%R' "${_iname}" 2>/dev/null || true)"
            printf '==> Installed: %s-%s (from repo %s)\n' "${_iname}" "${_iver:-unknown}" "${_irepo:-unknown}"
        done
    else
        printf '==> Installed: none\n'
    fi

    # 8. Snapshot the config section so a silent loss during 9 becomes a step-10 failure.
    CONFIG_SECTION_BEFORE=0
    if [ -f "${CONFIG_XML}" ] && grep -q '<pfblockerng>' "${CONFIG_XML}" 2>/dev/null; then
        CONFIG_SECTION_BEFORE=1
    fi

    # 9. Converge.
    # 9a. Every OTHER identity (legacy suffix, fork) is a different pkg NAME, so a
    #     plain install could never replace it — delete first.
    for _iname in ${_installed_names}; do
        [ "${_iname}" = "${CANONICAL_PKG}" ] && continue
        printf '==> Removing %s\n' "${_iname}"
        _pkg delete -y "${_iname}" ||
            die 5 "\`pkg delete ${_iname}\` failed — re-run after fixing the cause, or finish manually: ${PKG_BIN} delete -y ${_iname}"
    done

    _canon_ver="$(_pkg query '%v' "${CANONICAL_PKG}" 2>/dev/null || true)"
    _canon_repo="$(_pkg query '%R' "${CANONICAL_PKG}" 2>/dev/null || true)"

    if [ -n "${_canon_ver}" ] && [ "${_canon_repo}" = "${REPO_NAME}" ] && [ "${_canon_ver}" = "${OFFERED}" ]; then
        # 9b. Already converged — no pkg mutation.
        printf '==> Already up to date: %s-%s (repo %s) — nothing to do.\n' "${CANONICAL_PKG}" "${_canon_ver}" "${REPO_NAME}"
    elif [ -n "${_canon_ver}" ]; then
        # 9c. Canonical installed from another repo, or another version of this repo —
        #     a repository-qualified force reinstall (ordinary `pkg upgrade` refuses a
        #     same-or-older version; crossing repos or channels needs -f by design).
        _order="$(_pkg version -t "${OFFERED}" "${_canon_ver}" 2>/dev/null || true)"
        if [ "${_order}" = "<" ]; then
            _fam_offered="$(printf '%s' "${OFFERED}" | cut -d. -f1,2)"
            _fam_installed="$(printf '%s' "${_canon_ver}" | cut -d. -f1,2)"
            if [ "${_fam_offered}" != "${_fam_installed}" ]; then
                {
                    printf 'install-%s: WARNING — moving back from %s to %s crosses release families:\n' "${PFB_CHANNEL}" "${_canon_ver}" "${OFFERED}"
                    printf '  settings written by the newer build may be rolled back or dropped by the\n'
                    printf '  older build'\''s migrations, features present in the newer build disappear,\n'
                    printf '  and a re-save may be needed.\n'
                } >&2
            fi
        fi
        printf '==> Reinstalling %s from %s (repository-qualified)\n' "${CANONICAL_PKG}" "${REPO_NAME}"
        _pkg install -y -f -r "${REPO_NAME}" "${CANONICAL_PKG}-${OFFERED}" ||
            die 5 "\`pkg install -f -r ${REPO_NAME} ${CANONICAL_PKG}-${OFFERED}\` failed — the previous build is still installed"
    else
        # 9d. Nothing canonical installed (fresh box, or right after 9a's deletes).
        printf '==> Installing %s from %s\n' "${CANONICAL_PKG}" "${REPO_NAME}"
        _pkg install -y -r "${REPO_NAME}" "${CANONICAL_PKG}" ||
            die 5 "\`pkg install -r ${REPO_NAME} ${CANONICAL_PKG}\` failed — no pfBlockerNG is currently installed; fix the cause, then finish with: ${PKG_BIN} install -y -r ${REPO_NAME} ${CANONICAL_PKG}"
    fi

    # 10. Prove the result — every claim is re-read from pkg after the fact.
    _final_names="$(_pkg query -g '%n' "${CANONICAL_PKG}*" 2>/dev/null || true)"
    _final_names="$(printf '%s\n' "${_final_names}" | grep -v '^[[:space:]]*$' || true)"
    [ "${_final_names}" = "${CANONICAL_PKG}" ] ||
        die 6 "$(printf 'expected exactly %s installed, found:\n%s' "${CANONICAL_PKG}" "${_final_names:-(none)}")"

    _final_repo="$(_pkg query '%R' "${CANONICAL_PKG}" 2>/dev/null || true)"
    [ "${_final_repo}" = "${REPO_NAME}" ] ||
        die 6 "${CANONICAL_PKG} reports repo '${_final_repo:-unknown}', expected '${REPO_NAME}'"

    _final_ver="$(_pkg query '%v' "${CANONICAL_PKG}" 2>/dev/null || true)"
    [ "${_final_ver}" = "${OFFERED}" ] ||
        die 6 "${CANONICAL_PKG} reports version '${_final_ver:-unknown}', expected '${OFFERED}' from ${REPO_NAME}"

    _missing="$(
        _pkg info -l "${CANONICAL_PKG}" 2>/dev/null |
            sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' |
            grep '^/' |
            while IFS= read -r _path; do
                [ -e "${ROOT}${_path}" ] || printf '%s\n' "${_path}"
            done
    )"
    [ -z "${_missing}" ] ||
        die 6 "$(printf 'the installed payload is incomplete — these files listed by pkg info -l are missing:\n%s' "${_missing}")"

    if [ "${CONFIG_SECTION_BEFORE}" -eq 1 ]; then
        grep -q '<pfblockerng>' "${CONFIG_XML}" 2>/dev/null ||
            die 6 "the installedpackages/pfblockerng section is gone from ${CONFIG_XML} — restore your configuration backup"
    fi

    # 11. Done.
    printf '==> Done — %s-%s installed from %s (%s channel).\n' "${CANONICAL_PKG}" "${OFFERED}" "${REPO_NAME}" "${PFB_CHANNEL}"
}
