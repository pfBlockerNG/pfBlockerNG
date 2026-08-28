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
# The image's NEEDED/INSTALL/VERIFY set is the CORE RUN_DEPENDS ONLY (docs/misc/
# pfSense_versions.md "pfBlockerNG runtime dependencies"): a FLAVOR-INDEPENDENT
# core (libmaxminddb, lighttpd, jq, rsync, grepcidr, iprange, gnugrep) plus two
# python packages whose name tracks the base Python (py<flavor>-maxminddb,
# py<flavor>-sqlite3). A matrix row's extra_pkgs (e.g. CE's
# textproc/py-charset-normalizer) NEVER enter needed/install/verify — that
# package is DELIBERATELY not baked into the image (the per-leg smoke harness
# ships+installs it via SMOKE_DEP_PKGS, and a real install resolves it from our
# self-hosted repo as an ordinary RUN_DEPENDS; see the CE-only note in
# pfSense_versions.md). extra_pkgs participate ONLY in shed: a package matching
# an extra_pkgs-derived name (at ANY py-flavor) is shed if OLD_EXTRA carried its
# origin and NEW_EXTRA has since dropped it — i.e. a genuinely stale stray, not
# every image that happens to have Netgate's own copy of it (Plus's extra_pkgs
# is [] on every row, so its baked charset-normalizer is never recognised as
# extra-derived and stays untouched).
#
# POSIX sh; shellcheck clean; no bashisms.

# pfb_dep_core_pkgs FLAVOR — echo the flavor-independent + flavor-tracking core
# RUN_DEPENDS package names, one per line, in the docs/misc/pfSense_versions.md
# table's order. FLAVOR must look like pyNNN (py311, py39, py312, ...). This IS
# the image's full needed/install/verify set — extra_pkgs never add to it.
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

# pfb_dep_extra_basename ORIGIN — echo the basename of a port ORIGIN with its
# "py-" PKGNAMEPREFIX stripped (FreeBSD python-port convention), e.g.
# "textproc/py-charset-normalizer" -> "charset-normalizer". SHED-recognition
# only (see file header) — never used to add anything to needed/install/verify.
pfb_dep_extra_basename() {
    _extb_base="${1##*/}"
    case "$_extb_base" in
        py-*) _extb_base="${_extb_base#py-}" ;;
    esac
    printf '%s\n' "$_extb_base"
    unset _extb_base
}

# pfb_dep_extra_basenames EXTRA_ORIGINS — pfb_dep_extra_basename for each
# non-empty line of EXTRA_ORIGINS (newline-separated port origins; empty
# string = none, echoes nothing).
pfb_dep_extra_basenames() {
    [ -n "$1" ] || return 0
    printf '%s\n' "$1" | while IFS= read -r _extbs_origin; do
        [ -n "$_extbs_origin" ] || continue
        pfb_dep_extra_basename "$_extbs_origin"
    done
}

# pfb_dep_plan OLD_FLAVOR OLD_EXTRA NEW_FLAVOR NEW_EXTRA INSTALLED — echo the
# reconcile plan as lines "install <pkg>" / "shed <pkg>":
#   install = the NEW row's CORE needed set (pfb_dep_core_pkgs; extra_pkgs
#             never included) minus what INSTALLED (newline-separated package
#             names, e.g. `pkg query '%n'`) already has.
#   shed    = two sources, both INTERSECTED with INSTALLED (never a general
#             autoremove):
#             (1) CORE packages the OLD row needed that the NEW row no longer
#                 does (a py_flavor flip strands the old-flavor ones), and
#             (2) any installed package matching pyNNN-<basename> (any
#                 py-flavor) for a basename OLD_EXTRA carried that NEW_EXTRA
#                 has since dropped — a genuinely stale extra_pkgs stray. A
#                 basename still listed by NEW_EXTRA is NEVER shed here, even
#                 across a py_flavor flip (that transition is the per-leg
#                 harness's job, not the image's).
# A same-row call (OLD==NEW) is the "verify only" shape (e.g. the new version
# has no matrix row yet): both shed sources are empty and install is exactly
# the currently-missing CORE packages.
pfb_dep_plan() {
    _planp_old_flavor="$1"; _planp_old_extra="$2"
    _planp_new_flavor="$3"; _planp_new_extra="$4"
    _planp_installed="$5"

    _planp_old_needed="$(pfb_dep_core_pkgs "$_planp_old_flavor")" || return 1
    _planp_new_needed="$(pfb_dep_core_pkgs "$_planp_new_flavor")" || return 1

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

    # Extra-derived shed: basenames OLD_EXTRA carried that NEW_EXTRA dropped.
    _planp_old_basenames="$(pfb_dep_extra_basenames "$_planp_old_extra")"
    _planp_new_basenames="$(pfb_dep_extra_basenames "$_planp_new_extra")"
    _planp_dropped_basenames="$(printf '%s\n' "$_planp_old_basenames" | while IFS= read -r _b; do
        [ -n "$_b" ] || continue
        printf '%s\n' "$_planp_new_basenames" | grep -qxF "$_b" || printf '%s\n' "$_b"
    done)"

    printf '%s\n' "$_planp_installed" | while IFS= read -r _planp_pkg; do
        [ -n "$_planp_pkg" ] || continue
        # CR-3: never shed a package the NEW core needed set still requires --
        # a dropped extra_pkgs basename can collide with a core package name
        # (e.g. net/py-maxminddb's basename "maxminddb" collides with the
        # CORE py<flavor>-maxminddb dependency); the core requirement always
        # wins over an extra_pkgs-derived shed.
        if printf '%s\n' "$_planp_new_needed" | grep -qxF "$_planp_pkg"; then
            continue
        fi
        printf '%s\n' "$_planp_dropped_basenames" | while IFS= read -r _planp_base; do
            [ -n "$_planp_base" ] || continue
            case "$_planp_pkg" in
                py[0-9][0-9]*-"$_planp_base") printf 'shed %s\n' "$_planp_pkg" ;;
            esac
        done
    done

    unset _planp_old_flavor _planp_old_extra _planp_new_flavor _planp_new_extra \
        _planp_installed _planp_old_needed _planp_new_needed \
        _planp_old_basenames _planp_new_basenames _planp_dropped_basenames
}
