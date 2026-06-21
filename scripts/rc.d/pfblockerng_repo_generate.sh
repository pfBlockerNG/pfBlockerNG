#!/bin/sh
# /usr/local/etc/rc.d/pfblockerng_repo_generate.sh — boot-time repo-conf
# regenerator (ADR-39). Installed by add-repo.sh.
#
# WHAT IT DOES (and nothing more): for each of our pkg-repo conf files that
# EXISTS, it detects this box's pfSense edition/version/arch and UNCONDITIONALLY
# overwrites the conf with the canonical body — a fully-resolved GitHub Pages
# catalog URL for the box's variant (ADR-17 / ADR-20) plus a marker comment.
# No pkg call, no network fetch, no snapshot, no parse-and-compare, no
# reconcile. It is a pure conf REGENERATOR: re-deriving the conf from scratch is
# strictly simpler — and never wrong — than diffing and patching one in place.
#
# WHY AT BOOT: a pfSense OS upgrade can change the box's edition/version/arch
# (all of which require a reboot), which moves the catalog subtree. Regenerating
# every boot keeps the conf aligned with no upgrade hook to register.
#
# rc.d ordering: REQUIRE FILESYSTEMS (so /usr/local is mounted) and
# BEFORE NETWORKING (so the conf is correct before anything that could invoke
# pkg over the network runs). Safe to run this early precisely because it is
# local-file-only — it touches no network and no daemon.
#
# HARD RULE: every path ends in `exit 0`. This hook MUST NEVER wedge boot.
#
# Detection (KISS): edition = "/etc/product_label contains 'Plus'" -> plus, else
# ce; version = major.minor of /etc/version; arch = the leaf of `pkg config abi`.
# This mirrors catalog_name_from_version() in scripts/build-repo-portable.py.
#
# The emitted conf body is BYTE-IDENTICAL to `add-repo.sh --print-conf`,
# `build-repo.sh --print-conf`, and `build-repo-portable.py --print-conf`
# (pinned by tests/test_add_repo_conf.py).
#
# POSIX sh only; quote all expansions.

# shellcheck shell=sh
#
# FreeBSD rc.d script: rc.subr's run_rc_command dispatches the *_start handler
# via indirect variables, so shellcheck cannot see those call sites — SC2317
# (unreachable command) and SC2034 ($rcvar assigned-but-unused) are false
# positives here.
# shellcheck disable=SC2317,SC2034

# PROVIDE: pfblockerng_repo_generate
# REQUIRE: FILESYSTEMS
# BEFORE: NETWORKING

name="pfblockerng_repo_generate"

# On-box paths (installed by add-repo.sh). Override via env for tests.
: "${PFB_RELEASE_CONF:=/usr/local/etc/pkg/repos/pfblockerng.conf}"
: "${PFB_NIGHTLY_CONF:=/usr/local/etc/pkg/repos/pfblockerng-nightly.conf}"
: "${PFB_PRODUCT_LABEL:=/etc/product_label}"
: "${PFB_VERSION_FILE:=/etc/version}"
: "${PFB_PKG_BIN:=/usr/local/sbin/pkg}"
: "${PFB_BASE_URL:=https://pfblockerng.github.io/pkg}"

CONF_PRIORITY=100

# Detect this box's catalog subtree "<varver>/<arch>" (e.g. "ce-2.8/amd64").
# Returns 1 (no output) if version or arch can't be resolved — the caller then
# leaves the existing conf untouched rather than writing a malformed URL.
_detect_catalog() {
    # Edition: lowercase prefix matching build-repo-portable.py (ce | plus).
    if grep -q 'Plus' "${PFB_PRODUCT_LABEL}" 2>/dev/null; then
        _dc_edition='plus'
    else
        _dc_edition='ce'
    fi
    # Version: major.minor of /etc/version (e.g. "2.8.1" -> "2.8").
    _dc_ver=''
    [ -r "${PFB_VERSION_FILE}" ] && IFS= read -r _dc_ver < "${PFB_VERSION_FILE}"
    _dc_mm="$(printf '%s' "${_dc_ver}" | cut -d. -f1,2)"
    # Arch: leaf of `pkg config abi` ("FreeBSD:15:amd64" -> "amd64").
    _dc_abi="$("${PFB_PKG_BIN}" config abi 2>/dev/null)"
    _dc_arch="${_dc_abi##*:}"
    [ -n "${_dc_mm}" ] && [ -n "${_dc_arch}" ] || return 1
    printf '%s-%s/%s' "${_dc_edition}" "${_dc_mm}" "${_dc_arch}"
}

# Emit the canonical conf body. $1 = channel word, $2 = repo name, $3 = url.
# Kept byte-identical to the *_print_conf generators (drift-pinned by tests).
_emit_conf() {
    _ec_channel="$1"
    _ec_repo="$2"
    _ec_url="$3"
    cat <<EOF
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run add-repo.sh to change.
# pfBlockerNG (${_ec_channel} channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is
# fully resolved for this box's edition/version/arch (ADR-39); the boot
# rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects our build.
${_ec_repo}: {
  url: "${_ec_url}",
  mirror_type: none,
  signature_type: none,
  priority: ${CONF_PRIORITY},
  enabled: yes
}
EOF
}

# Regenerate one conf IF it exists (orphan guard: an absent conf stays absent —
# we never create a channel the user didn't bootstrap).
# $1 = conf path, $2 = channel word (release|nightly), $3 = repo name.
_regen_one() {
    _ro_conf="$1"
    _ro_channel="$2"
    _ro_repo="$3"
    [ -f "${_ro_conf}" ] || return 0
    _ro_catalog="$(_detect_catalog)" || {
        printf '[%s] WARNING: variant detection failed — leaving %s unchanged\n' \
            "${name}" "${_ro_conf}" >&2
        return 0
    }
    _ro_url="${PFB_BASE_URL%/}/${_ro_channel}/${_ro_catalog}"
    if _emit_conf "${_ro_channel}" "${_ro_repo}" "${_ro_url}" > "${_ro_conf}.tmp" 2>/dev/null \
        && mv "${_ro_conf}.tmp" "${_ro_conf}" 2>/dev/null; then
        printf '[%s] INFO: regenerated %s -> %s\n' "${name}" "${_ro_conf}" "${_ro_url}" >&2
    else
        rm -f "${_ro_conf}.tmp" 2>/dev/null
        printf '[%s] WARNING: could not rewrite %s\n' "${name}" "${_ro_conf}" >&2
    fi
}

# Regenerate each channel's conf independently (channel keyed by filename).
pfblockerng_repo_generate_start() {
    _regen_one "${PFB_RELEASE_CONF}" 'release' 'pfblockerng'
    _regen_one "${PFB_NIGHTLY_CONF}" 'nightly' 'pfblockerng-nightly'
    return 0
}

# Run as an rc.d service when rc.subr is present (the pfSense box); otherwise run
# the regeneration directly (off-box: add-repo.sh bootstrap + the shellspec suite,
# where /etc/rc.subr does not exist).
if [ -r /etc/rc.subr ]; then
    . /etc/rc.subr
    rcvar="${name}_enable"
    start_cmd="pfblockerng_repo_generate_start"
    stop_cmd=":"
    load_rc_config "${name}"
    : "${pfblockerng_repo_generate_enable:=YES}"
    run_rc_command "${1:-onestart}"
else
    pfblockerng_repo_generate_start
fi
# Always exit 0 regardless of the above — never wedge boot.
exit 0
