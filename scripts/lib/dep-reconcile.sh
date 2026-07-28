#!/bin/sh
# scripts/lib/dep-reconcile.sh — post-upgrade dependency reconcile+shed decision
# logic (issue #1806 final step).
#
# Sourced by scripts/image-upgrade.sh once the box reports the NEW version, so a
# baked-dependency break (most notably a py_flavor flip, e.g. py311 -> py312
# stranding every old-flavor package) is repaired before the health gate/publish
# instead of shipping a broken image. Pure functions only — no ssh, no pkg(8), no
# side effects — so the plan is unit-testable without a live box; the actual
# `pkg install`/`pkg delete`/`pkg info -e`/python import-probe execution against
# the plan this emits lives in image-upgrade.sh itself (live-proof-only).
#
# The needed-package set is the port's explicit RUN_DEPENDS (docs/misc/
# pfSense_versions.md "pfBlockerNG runtime dependencies"): a FLAVOR-INDEPENDENT
# core (libmaxminddb, lighttpd, jq, rsync, grepcidr, iprange, gnugrep) plus two
# python packages whose name tracks the base Python (py<flavor>-maxminddb,
# py<flavor>-sqlite3), plus zero or more EXTRA python packages the matrix row's
# extra_pkgs carries (port origins pfSense's own repo doesn't serve for that
# channel, e.g. CE's textproc/py-charset-normalizer — see the CE-only note in
# pfSense_versions.md; scripts/build-dep-pkg-portable.py is the same "pyNNN"
# naming convention this file's extra-pkg-name transform mirrors).
#
# POSIX sh; shellcheck clean; no bashisms.

# pfb_dep_core_pkgs FLAVOR — echo the flavor-independent + flavor-tracking core
# RUN_DEPENDS package names, one per line, in the docs/misc/pfSense_versions.md
# table's order. FLAVOR must look like pyNNN (py311, py39, py312, ...).
pfb_dep_core_pkgs() {
    case "$1" in
        py[0-9][0-9]*) ;;
        *) printf 'pfb_dep_core_pkgs: invalid py_flavor: %s\n' "$1" >&2; return 1 ;;
    esac
    printf '%s\n' \
        libmaxminddb \
        lighttpd \
        jq \
        rsync \
        grepcidr \
        iprange \
        gnugrep \
        "${1}-maxminddb" \
        "${1}-sqlite3"
}

# pfb_dep_python_dotted FLAVOR — echo the dotted python version for a pyNNN
# flavor (py311 -> 3.11, py39 -> 3.9, py312 -> 3.12). Mirrors
# build-dep-pkg-portable.py's python_dotted_version().
pfb_dep_python_dotted() {
    case "$1" in
        py[0-9][0-9]*) ;;
        *) printf 'pfb_dep_python_dotted: invalid py_flavor: %s\n' "$1" >&2; return 1 ;;
    esac
    _pdd_digits="${1#py}"
    _pdd_maj="${_pdd_digits%"${_pdd_digits#?}"}"
    _pdd_min="${_pdd_digits#?}"
    printf '%s.%s\n' "$_pdd_maj" "$_pdd_min"
    unset _pdd_digits _pdd_maj _pdd_min
}

# pfb_dep_extra_pkg_name ORIGIN FLAVOR — echo the package name for a port
# ORIGIN (e.g. "textproc/py-charset-normalizer") under python FLAVOR, e.g.
# "py311-charset-normalizer". The "py-" PKGNAMEPREFIX is a FreeBSD python-port
# convention (stripped and replaced by pyNNN-); every current/known extra_pkgs
# entry is a python port (build-dep-pkg-portable.py requires --py-flavor).
pfb_dep_extra_pkg_name() {
    _depn_base="${1##*/}"
    case "$_depn_base" in
        py-*) _depn_base="${_depn_base#py-}" ;;
    esac
    printf '%s-%s\n' "$2" "$_depn_base"
    unset _depn_base
}

# pfb_dep_needed_pkgs FLAVOR EXTRA_ORIGINS — echo the FULL needed package set
# for FLAVOR: the core list, then one pfb_dep_extra_pkg_name line per non-empty
# line of EXTRA_ORIGINS (newline-separated port origins; empty string = none).
pfb_dep_needed_pkgs() {
    pfb_dep_core_pkgs "$1" || return 1
    [ -n "$2" ] || return 0
    printf '%s\n' "$2" | while IFS= read -r _needp_origin; do
        [ -n "$_needp_origin" ] || continue
        pfb_dep_extra_pkg_name "$_needp_origin" "$1"
    done
}

# pfb_dep_python_modules FLAVOR EXTRA_ORIGINS — echo the python import-probe
# module names for FLAVOR's needed set: the two core modules (maxminddb,
# sqlite3) plus one per EXTRA_ORIGINS entry, with its package-name dashes
# turned into the underscores python's import name uses (charset-normalizer ->
# charset_normalizer).
pfb_dep_python_modules() {
    printf '%s\n' maxminddb sqlite3
    [ -n "$2" ] || return 0
    printf '%s\n' "$2" | while IFS= read -r _modp_origin; do
        [ -n "$_modp_origin" ] || continue
        _modp_base="${_modp_origin##*/}"
        case "$_modp_base" in
            py-*) _modp_base="${_modp_base#py-}" ;;
        esac
        printf '%s\n' "$_modp_base" | tr '-' '_'
    done
    unset _modp_base
}

# pfb_dep_plan OLD_FLAVOR OLD_EXTRA NEW_FLAVOR NEW_EXTRA INSTALLED — echo the
# reconcile plan as lines "install <pkg>" / "shed <pkg>":
#   install = NEW's needed set minus what INSTALLED (newline-separated package
#             names, e.g. `pkg query '%n'`) already has.
#   shed    = OLD's needed set minus NEW's needed set, INTERSECTED with
#             INSTALLED (never a general autoremove — only a package this
#             function itself considers part of the known pfBlockerNG dep
#             namespace, and only if actually present).
# A same-row call (OLD==NEW) is the "verify only" shape (e.g. the new version
# has no matrix row yet): shed is always empty and install is exactly the
# currently-missing packages.
pfb_dep_plan() {
    _planp_old_needed="$(pfb_dep_needed_pkgs "$1" "$2")" || return 1
    _planp_new_needed="$(pfb_dep_needed_pkgs "$3" "$4")" || return 1
    _planp_installed="$5"

    printf '%s\n' "$_planp_new_needed" | while IFS= read -r _planp_pkg; do
        [ -n "$_planp_pkg" ] || continue
        if ! printf '%s\n' "$_planp_installed" | grep -qxF "$_planp_pkg"; then
            printf 'install %s\n' "$_planp_pkg"
        fi
    done

    printf '%s\n' "$_planp_old_needed" | while IFS= read -r _planp_pkg; do
        [ -n "$_planp_pkg" ] || continue
        if printf '%s\n' "$_planp_new_needed" | grep -qxF "$_planp_pkg"; then
            continue
        fi
        if printf '%s\n' "$_planp_installed" | grep -qxF "$_planp_pkg"; then
            printf 'shed %s\n' "$_planp_pkg"
        fi
    done

    unset _planp_old_needed _planp_new_needed _planp_installed
}
