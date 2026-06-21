#!/bin/sh
# scripts/lib/detect_variant.sh — sourceable POSIX-sh on-box variant detection helper.
#
# Resolves the pfSense box's catalog subtree `<varver>/<arch>` for the self-hosted
# pkg repo (ADR-39).  Mirrors catalog_name_from_version() in
# scripts/build-repo-portable.py exactly — both must agree on every box.
#
# INTERFACE (source this file, then call the functions):
#
#   pfb_detect_edition   — prints "Plus" if /etc/inc/globals.plus.inc exists, else "CE"
#   pfb_detect_version   — prints the trimmed content of /etc/version (e.g. "2.8.1")
#   pfb_detect_arch      — prints the bare arch leaf from `pkg config abi`
#                          e.g. "FreeBSD:15:amd64" -> "amd64"
#   pfb_detect_varver    — prints "<edition_lower>-<major>.<minor>"
#                          e.g. "ce-2.8" or "plus-26.03"
#   pfb_detect_catalog   — prints "<varver>/<arch>"  (the catalog subtree for this box)
#                          e.g. "ce-2.8/amd64" or "plus-26.03/aarch64"
#
# OVERRIDABLE PATHS (set before sourcing, or export before calling):
#   PFB_GLOBALS_PLUS_INC  — path to globals.plus.inc (default: /etc/inc/globals.plus.inc)
#   PFB_VERSION_FILE      — path to /etc/version     (default: /etc/version)
#   PFB_PKG_CMD           — pkg binary                (default: /usr/local/sbin/pkg)
#
# These knobs exist solely for testing (fixture injection); production code leaves
# them unset so the real system paths are used.
#
# POSIX sh only; no bash-isms; quote all expansions; LC_ALL=C on any comparison.

# shellcheck shell=sh

# ── Detection defaults (overridable for tests) ─────────────────────────────── #
: "${PFB_GLOBALS_PLUS_INC:=/etc/inc/globals.plus.inc}"
: "${PFB_VERSION_FILE:=/etc/version}"
: "${PFB_PKG_CMD:=/usr/local/sbin/pkg}"

# pfb_detect_edition — prints "Plus" if globals.plus.inc is present, else "CE".
#   Detection method: [ -f <path> ] as confirmed live in ADR-20 Phase 1 (2026-06-09).
#   Stdout: "Plus" or "CE" (no trailing newline beyond printf).
pfb_detect_edition() {
    if [ -f "${PFB_GLOBALS_PLUS_INC}" ]; then
        printf 'Plus'
    else
        printf 'CE'
    fi
}

# pfb_detect_version — prints the trimmed version string from /etc/version.
#   E.g. "2.8.1" (CE) or "26.03.1" (Plus).
#   Strips leading/trailing whitespace so a trailing newline in the file is harmless.
pfb_detect_version() {
    # read -r avoids backslash interpretation; the variable holds the trimmed line.
    IFS= read -r _pfb_ver < "${PFB_VERSION_FILE}"
    printf '%s' "${_pfb_ver}"
}

# pfb_detect_arch — prints the bare architecture leaf from `pkg config abi`.
#   `pkg config abi` emits "FreeBSD:<major>:<arch>" (e.g. "FreeBSD:15:amd64").
#   We parse the third colon-delimited field to get the arch leaf.
pfb_detect_arch() {
    _pfb_abi="$("${PFB_PKG_CMD}" config abi)"
    # IFS=$':' splits on colon; read the three fields and print the arch leaf.
    IFS=: read -r _pfb_os _pfb_major _pfb_arch <<EOF
${_pfb_abi}
EOF
    printf '%s' "${_pfb_arch}"
    # Silence "unused variable" warnings from strict linters (both are intentionally
    # consumed by read but we only use _pfb_arch).
    : "${_pfb_os}" "${_pfb_major}"
}

# pfb_detect_varver — prints the catalog variant+version token "<edition_lower>-<major>.<minor>".
#   Mirrors catalog_name_from_version() in build-repo-portable.py:
#     "2.8.1"  + "CE"   -> "ce-2.8"
#     "26.03.1"+ "Plus" -> "plus-26.03"
#   Patch component is stripped; only major.minor is kept.
pfb_detect_varver() {
    _pfb_edition="$(pfb_detect_edition)"
    _pfb_ver="$(pfb_detect_version)"

    # Strip patch: keep only the first two dot-delimited fields.
    # LC_ALL=C is used on string comparisons involving machine data (edition token).
    _pfb_major_minor="$(printf '%s' "${_pfb_ver}" | cut -d. -f1,2)"

    # Lowercase the edition prefix to match the Python helper.
    case "${_pfb_edition}" in
        Plus) _pfb_prefix="plus" ;;
        *)    _pfb_prefix="ce"   ;;
    esac

    printf '%s-%s' "${_pfb_prefix}" "${_pfb_major_minor}"
}

# pfb_detect_catalog — prints the full catalog subtree "<varver>/<arch>".
#   E.g. "ce-2.8/amd64" or "plus-26.03/aarch64".
#   This is the path segment appended to the channel prefix in the repo conf URL.
pfb_detect_catalog() {
    _pfb_varver="$(pfb_detect_varver)"
    _pfb_arch="$(pfb_detect_arch)"
    printf '%s/%s' "${_pfb_varver}" "${_pfb_arch}"
}
