#!/bin/sh
# scripts/fetch-legacy-pkg.sh — fetch the SHIPPED v3.3.13 pfBlockerNG .pkg (SMOKE_LEGACY_PKG).
#
# The settings-family lifecycle smoke (issue #3710, tests/smoke/test_settings_family_lifecycle.py)
# installs the release a 3.2 user is told to run, over the branch build, to prove the downgrade
# restores the saved 3.3 settings. Those are the exact shipped bytes, so they are downloaded from
# the public GitHub Release, never rebuilt, and checked against a sha256 pinned in this file, once.
# smoke-on-box.sh and smoke-single.yml call the script and carry neither the tag nor a hash.
#
# USAGE:
#   fetch-legacy-pkg.sh --print-tag
#   fetch-legacy-pkg.sh --image-ref REF [--pfsense-version V]
#
#   --print-tag          print the pinned release tag and exit.
#   --image-ref REF      the leg's pfSense image ref. Its name, pfsense-ce or pfsense-plus, picks the
#                        edition (a leading registry host, a port and a @digest are ignored); its tag
#                        is the pfSense version unless --pfsense-version gives a usable one.
#   --pfsense-version V  the leg's pfSense version, e.g. 2.8, 2.8.1-RELEASE or 26.03. Only its
#                        MAJOR.MINOR counts. A value that is not a version (smoke-on-box.sh passes
#                        `?` for a digest-only ref) is ignored in favour of the ref's tag.
#
# Prints the absolute path of the verified .pkg (and NOTHING else) on stdout. All other output,
# including the identity line `fetch-legacy-pkg: tag=<t> leg=<L> pkg=<file> sha256=<h>`, goes to
# stderr. Every stage that fails exits non-zero naming itself, so a caller that runs this under
# `set -e` stops instead of carrying on without the package.
#
# ENV:
#   TMPDIR   scratch root: the .pkg is kept in ${TMPDIR:-/tmp}/pfb-legacy-pkg and reused while it
#            still matches its pin; a file that does not is deleted and downloaded again.
#
# Test-only (env), never set on a box or in CI:
#   PFB_LEGACY_PKG_WORK      replaces the scratch dir.
#   PFB_LEGACY_PKG_BASE_URL  replaces the release download URL (the specs use a file:// dir). The
#                            pins have no override: the specs rewrite the pin lines of a fixture copy.
#
# POSIX sh; shellcheck clean; all expansions quoted.

set -eu

_TAG=v3.3.13

# sha256 of each .pkg the release ships, computed from the release's own assets. The leg is
# <edition>-<pfSense major.minor>; a leg the release has no asset for has no pin and is refused.
pinned_sha256() {
    case "$1" in
        CE-2.8) printf '%s\n' 'c4b9d854df390b5c05d9bbff7ee650eb8087ad5105fa00994be6f37f428624c5' ;;
        CE-2.9) printf '%s\n' 'ed843c73e761c078d7562f60aca8baec22e91c08991bf7abe1055432b6ab75e0' ;;
        Plus-25.11) printf '%s\n' '6563a0f40c444d87b21c6a4178a9307ec471dd51de8ac4b4c71c55fcdda36784' ;;
        Plus-26.03) printf '%s\n' '8f482c8608ee2e9dcb0feed2300d61ccb04112b0fbf6532c91ee0bc8d3a282bb' ;;
        Plus-26.07) printf '%s\n' 'ddbf0329f2d5abaef1fcc88c0bbd285bf719c828ee62ff2b82e5870a7fdcf614' ;;
        *) return 1 ;;
    esac
}

die() {
    printf 'fetch-legacy-pkg: %s\n' "$*" >&2
    exit 1
}

sha256_of() { sha256sum "$1" | cut -d ' ' -f 1; }

# MAJOR.MINOR of a version string, or nothing when it is not one.
major_minor() { printf '%s\n' "$1" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\)\([^0-9].*\)\{0,1\}$/\1/p'; }

_ref=''
_version=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --print-tag)
            printf '%s\n' "$_TAG"
            exit 0
            ;;
        --image-ref)
            [ "$#" -ge 2 ] || die '--image-ref requires a value'
            _ref="$2"
            shift 2
            ;;
        --pfsense-version)
            [ "$#" -ge 2 ] || die '--pfsense-version requires a value'
            _version="$2"
            shift 2
            ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$_ref" ] || die '--image-ref is required'

# ── Stage 1: the leg ──────────────────────────────────────────────────────── #
_leaf="${_ref%@*}"
_leaf="${_leaf##*/}"
_name="${_leaf%%:*}"
_tag=''
case "$_leaf" in *:*) _tag="${_leaf#*:}" ;; esac
case "$_name" in
    pfsense-ce) _edition=CE ;;
    pfsense-plus) _edition=Plus ;;
    *) die "unknown image '${_name}' in ${_ref}: expected pfsense-ce or pfsense-plus" ;;
esac
_mm="$(major_minor "$_version")"
[ -n "$_mm" ] || _mm="$(major_minor "$_tag")"
[ -n "$_mm" ] || die "no pfSense version in --pfsense-version '${_version}' or the tag of ${_ref}"
_leg="${_edition}-${_mm}"
_want="$(pinned_sha256 "$_leg")" || die "no pinned package for leg ${_leg}: ${_TAG} ships none"

# ── Stage 2: the file, verified ───────────────────────────────────────────── #
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum not found'
_file="pfSense-pkg-pfBlockerNG-${_TAG#v}-${_leg}.pkg"
_work="${PFB_LEGACY_PKG_WORK:-${TMPDIR:-/tmp}/pfb-legacy-pkg}"
mkdir -p "$_work" || die "cannot create ${_work}"
_work="$(CDPATH='' cd "$_work" && pwd)"
_dest="${_work}/${_file}"
if [ "$(sha256_of "$_dest" 2>/dev/null)" != "$_want" ]; then
    _url="${PFB_LEGACY_PKG_BASE_URL:-https://github.com/pfBlockerNG/pfBlockerNG/releases/download/${_TAG}}/${_file}"
    rm -f "$_dest" "${_dest}.part"
    printf 'fetch-legacy-pkg: downloading %s\n' "$_url" >&2
    curl -fsSL --retry 3 -o "${_dest}.part" "$_url" >&2 || {
        rm -f "${_dest}.part"
        die "download failed: ${_url}"
    }
    _got="$(sha256_of "${_dest}.part")"
    if [ "$_got" != "$_want" ]; then
        rm -f "${_dest}.part"
        die "sha256 mismatch for ${_file}: expected ${_want}, got ${_got}"
    fi
    mv "${_dest}.part" "$_dest"
fi

printf 'fetch-legacy-pkg: tag=%s leg=%s pkg=%s sha256=%s\n' "$_TAG" "$_leg" "$_dest" "$_want" >&2
printf '%s\n' "$_dest"
