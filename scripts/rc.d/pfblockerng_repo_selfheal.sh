#!/bin/sh
# /usr/local/etc/rc.d/pfblockerng_repo_selfheal.sh — self-heal hook (ADR-39).
#
# Keeps the pfBlockerNG pkg repo conf(s) aligned with this box's pfSense
# edition/version/arch across OS upgrades. Installed by add-repo.sh.
#
# rc.d ordering: REQUIRE NETWORKING LOGIN — after the resolver is up.
# The heal does a pkg network fetch; it must not run before the local resolver
# (unbound) is available on boxes that resolve via 127.0.0.1.  LOGIN is a
# standard late-boot milestone that follows the resolver on pfSense.
# Exact ordering is smoke-validated per ADR-39 §7.
# HARD RULE: every code path ends in `exit 0`. This hook MUST NEVER wedge boot.
#
# Logic:
#   1. GUARD: if none of our conf files exists, exit 0 (orphaned hook is inert).
#   2. For each present conf: parse the <varver>/<arch> from its url: line.
#   3. Compute the box's current <varver>/<arch> via the detection helper.
#   4. MATCH -> continue (no-op; the every-boot fast path, zero pkg calls).
#   5. MISMATCH -> snapshot the conf, rewrite only the <varver>/<arch> segment,
#      run `pkg update` for that repo.
#      If pkg update FAILS: restore the snapshot (next boot retries) and log a
#      WARNING; do not reconcile.
#      If pkg update SUCCEEDS: run reconcile (best-effort; a reconcile failure
#      is logged but the conf stays correct — recoverable by the user's next pkg
#      op).  pkg failures are logged but never propagated (always exit 0).
#
# POSIX sh only; quote all expansions.

# shellcheck shell=sh

# PROVIDE: pfblockerng_repo_selfheal
# REQUIRE: NETWORKING LOGIN

. /etc/rc.subr

name="pfblockerng_repo_selfheal"
rcvar="${name}_enable"
start_cmd="${name}_start"
stop_cmd=":"

load_rc_config "${name}"
: "${pfblockerng_repo_selfheal_enable:=YES}"

# On-box paths (installed by add-repo.sh).
# Override via env for tests.
: "${PFB_DETECT_HELPER:=/usr/local/lib/pfblockerng/detect_variant.sh}"
: "${PFB_RELEASE_CONF:=/usr/local/etc/pkg/repos/pfblockerng.conf}"
: "${PFB_NIGHTLY_CONF:=/usr/local/etc/pkg/repos/pfblockerng-nightly.conf}"
: "${PFB_PKG_BIN:=/usr/local/sbin/pkg}"

_RELEASE_REPO="pfblockerng"
_NIGHTLY_REPO="pfblockerng-nightly"
# Package names per conf (release carries stable + devel; nightly its own).
_RELEASE_PKGS="pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-devel"
_NIGHTLY_PKGS="pfSense-pkg-pfBlockerNG-nightly"

pfblockerng_repo_selfheal_start() {
    # Fail-proof wrapper: any unexpected error inside is caught here.
    _selfheal_main || true
    return 0
}

# Extract the <varver>/<arch> segment from a conf file's url: line.
# Prints "<varver>/<arch>" (e.g. "ce-2.8/amd64") or "" if not parseable.
# Pattern: url: "https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>"
_parse_catalog_from_conf() {
    _pcc_conf="$1"
    # Use sed to extract the bare URL from the url: line (strips surrounding quotes,
    # whitespace, and trailing comma/semicolons).  Avoids \"  inside ${...} which is
    # not valid in POSIX dash.
    _pcc_url="$(sed -n 's/.*url:[[:space:]]*"\([^"]*\)".*/\1/p' "${_pcc_conf}" | head -1)"
    if [ -z "${_pcc_url}" ]; then
        return 0
    fi
    # Strip any trailing slashes.
    while [ "${_pcc_url}" != "${_pcc_url%/}" ]; do
        _pcc_url="${_pcc_url%/}"
    done
    # The last two path components are <varver>/<arch>.
    _pcc_arch="${_pcc_url##*/}"
    _pcc_rest="${_pcc_url%/*}"
    _pcc_varver="${_pcc_rest##*/}"
    if [ -n "${_pcc_varver}" ] && [ -n "${_pcc_arch}" ]; then
        printf '%s/%s' "${_pcc_varver}" "${_pcc_arch}"
    fi
}

# Rewrite ONLY the <varver>/<arch> segment of the url: line in a conf file.
# $1 = conf path, $2 = old "<varver>/<arch>", $3 = new "<varver>/<arch>".
# Uses sed to replace exactly the old token; preserves every other byte.
_rewrite_conf_catalog() {
    _rcc_conf="$1"
    _rcc_old="$2"
    _rcc_new="$3"
    # Escape any regex metacharacters in the path components.
    _rcc_old_esc="$(printf '%s' "${_rcc_old}" | sed 's|[].[\*^$]|\\&|g')"
    _rcc_new_esc="$(printf '%s' "${_rcc_new}" | sed 's|[&\\]|\\&|g')"
    # Use | as the sed delimiter to avoid conflicts with / in the path.
    # Try in-place edit first (BSD/macOS sed); fall back to temp-file for GNU sed.
    if sed -i '' "s|${_rcc_old_esc}|${_rcc_new_esc}|" "${_rcc_conf}" 2>/dev/null; then
        return 0
    fi
    sed "s|${_rcc_old_esc}|${_rcc_new_esc}|" "${_rcc_conf}" > "${_rcc_conf}.tmp" \
        && mv "${_rcc_conf}.tmp" "${_rcc_conf}" 2>/dev/null \
        || printf '[pfblockerng_repo_selfheal] WARNING: could not rewrite %s\n' "${_rcc_conf}" >&2
}

# Reconcile the pfBlockerNG package for a given repo after a catalog update.
# $1 = space-separated list of package names to check/install.
# Failure is logged and swallowed (always returns 0).
_reconcile_pkg() {
    _rp_pkgs="$1"
    # shellcheck disable=SC2086  # word-split is intentional for the package list
    for _rp_pkg in ${_rp_pkgs}; do
        if "${PFB_PKG_BIN}" info "${_rp_pkg}" >/dev/null 2>&1; then
            # Package present — upgrade it so the new catalog's version wins.
            FETCH_TIMEOUT=5 FETCH_RETRY=2 "${PFB_PKG_BIN}" upgrade -y "${_rp_pkg}" 2>/dev/null \
                || printf '[pfblockerng_repo_selfheal] WARNING: pkg upgrade %s failed (continuing)\n' "${_rp_pkg}" >&2
            return 0
        fi
    done
    # No package found — try to install the first name in the list.
    _rp_first="${_rp_pkgs%% *}"
    printf '[pfblockerng_repo_selfheal] INFO: installing %s from new catalog\n' "${_rp_first}" >&2
    FETCH_TIMEOUT=5 FETCH_RETRY=2 "${PFB_PKG_BIN}" install -y "${_rp_first}" 2>/dev/null \
        || printf '[pfblockerng_repo_selfheal] WARNING: pkg install %s failed (continuing)\n' "${_rp_first}" >&2
}

# Heal one conf file.
# $1 = conf path, $2 = repo name, $3 = space-separated package names.
_heal_one_conf() {
    _hoc_conf="$1"
    _hoc_repo="$2"
    _hoc_pkgs="$3"

    # Guard: skip if not present.
    [ -f "${_hoc_conf}" ] || return 0

    # Parse the current catalog subtree from the conf.
    _hoc_conf_catalog="$(_parse_catalog_from_conf "${_hoc_conf}")"
    if [ -z "${_hoc_conf_catalog}" ]; then
        printf '[pfblockerng_repo_selfheal] WARNING: could not parse catalog from %s — skipping\n' "${_hoc_conf}" >&2
        return 0
    fi

    # Detect the box's current catalog subtree.
    _hoc_box_catalog="$(pfb_detect_catalog 2>/dev/null)" || {
        printf '[pfblockerng_repo_selfheal] WARNING: detect_variant failed — skipping %s\n' "${_hoc_conf}" >&2
        return 0
    }

    # MATCH: no work needed (the every-boot fast path).
    if [ "${_hoc_conf_catalog}" = "${_hoc_box_catalog}" ]; then
        return 0
    fi

    # MISMATCH: snapshot the conf, rewrite, attempt pkg update, revert on failure.
    printf '[pfblockerng_repo_selfheal] INFO: %s varver mismatch — conf has %s, box is %s — rewriting\n' \
        "${_hoc_conf}" "${_hoc_conf_catalog}" "${_hoc_box_catalog}" >&2

    # a. Snapshot the conf before any modification so we can revert on failure.
    _hoc_snap="${_hoc_conf}.pfb_selfheal_snap"
    cp "${_hoc_conf}" "${_hoc_snap}" 2>/dev/null || {
        printf '[pfblockerng_repo_selfheal] WARNING: could not snapshot %s — skipping\n' "${_hoc_conf}" >&2
        return 0
    }

    # b. Rewrite only the <varver>/<arch> segment.
    _rewrite_conf_catalog "${_hoc_conf}" "${_hoc_conf_catalog}" "${_hoc_box_catalog}"

    # c. Update the catalog for this repo (network call — guarded by FETCH_TIMEOUT/FETCH_RETRY).
    printf '[pfblockerng_repo_selfheal] INFO: pkg update -r %s\n' "${_hoc_repo}" >&2
    if FETCH_TIMEOUT=5 FETCH_RETRY=2 "${PFB_PKG_BIN}" update -r "${_hoc_repo}" 2>/dev/null; then
        # d. SUCCESS: keep the rewritten conf; remove the snapshot; reconcile (best-effort).
        rm -f "${_hoc_snap}"
        _reconcile_pkg "${_hoc_pkgs}"
    else
        # d. FAILURE: restore the snapshot so the next boot sees a mismatch and retries.
        printf '[pfblockerng_repo_selfheal] WARNING: pkg update -r %s failed — restoring conf for retry on next boot\n' \
            "${_hoc_repo}" >&2
        mv "${_hoc_snap}" "${_hoc_conf}" 2>/dev/null \
            || cp "${_hoc_snap}" "${_hoc_conf}" 2>/dev/null \
            || printf '[pfblockerng_repo_selfheal] WARNING: could not restore snapshot of %s\n' "${_hoc_conf}" >&2
        rm -f "${_hoc_snap}" 2>/dev/null
        # Do NOT reconcile — the conf is back to the old <varver>/<arch>.
    fi
}

_selfheal_main() {
    # Overall guard: exit 0 immediately if NEITHER conf exists.
    if [ ! -f "${PFB_RELEASE_CONF}" ] && [ ! -f "${PFB_NIGHTLY_CONF}" ]; then
        return 0
    fi

    # Source the detection helper (installed by add-repo.sh alongside this hook).
    if [ ! -f "${PFB_DETECT_HELPER}" ]; then
        printf '[pfblockerng_repo_selfheal] WARNING: detection helper not found at %s — skipping\n' \
            "${PFB_DETECT_HELPER}" >&2
        return 0
    fi
    # shellcheck disable=SC1090
    . "${PFB_DETECT_HELPER}"

    # Heal each channel's conf independently.
    _heal_one_conf "${PFB_RELEASE_CONF}" "${_RELEASE_REPO}" "${_RELEASE_PKGS}" || true
    _heal_one_conf "${PFB_NIGHTLY_CONF}" "${_NIGHTLY_REPO}" "${_NIGHTLY_PKGS}" || true
}

run_rc_command "$1"
# Ensure we always exit 0 regardless of run_rc_command's return.
exit 0
