#!/bin/sh
# scripts/build-prev-pkg.sh — build the PREVIOUS-devel pfBlockerNG .pkg (SMOKE_PREV_PKG).
#
# The two-node HA smoke rows for legacy sync (issue #3455: the upgrade row and the
# new-sender / old-receiver row) install a package built from the last devel commit BEFORE
# the per-field XMLRPC sync series landed. That commit is pinned in this file, once;
# smoke-on-box.sh and smoke-single.yml call the script and never carry the SHA.
#
# USAGE:
#   build-prev-pkg.sh --print-ref
#   build-prev-pkg.sh [--like PKG] [build-leg.sh args ...]
#
#   --print-ref  print the pinned commit and exit.
#   --like PKG   build the channel PKG (the branch .pkg) was built for. Its name,
#                pfSense-pkg-pfBlockerNG[-<channel>]-<version>.pkg, gives --channel and, for
#                nightly (which requires one), --pkgversion. Without it build-leg.sh's own
#                default channel applies.
#   Anything else goes to build-leg.sh (--ports-dir, --ports-repo, --abi, --php, ...). This
#   script appends its own --local-src and --out-dir, which win because build-leg.sh takes
#   the last flag. Native builds ignore --variant, so a Plus leg gets the same package.
#
# Prints the resolved absolute .pkg path (and NOTHING else) on stdout. All other output,
# including the identity line `build-prev-pkg: ref=<P> pkg=<file> version=<v>`, goes to
# stderr. Every stage that fails exits non-zero naming itself, so a caller that runs this
# under `set -e` stops instead of carrying on without the package.
#
# ENV:
#   PFB_GIT_REMOTE     remote P is fetched from when this checkout lacks it (default
#                      origin; local-smoke.sh forwards the remote the box fetched the ref from).
#   TMPDIR             scratch root; the work dir is recreated on every run (one writer).
#
# Test-only (env), never set on a box or in CI:
#   PFB_PREV_PKG_WORK  replaces the work dir (default ${TMPDIR:-/tmp}/pfb-prev-pkg).
# The pin itself has no override: the specs rewrite the `_PIN=` line of a fixture copy.
#
# POSIX sh; shellcheck clean; all expansions quoted.

set -eu

# P: the last devel commit before the per-field sync series. In P the sender still keys
# off `syncinterfaces` and `syncscope` does not exist yet.
_PIN=af7d608dd1123d0f4db40d1ff171bed1d8ea74b4
_ref="$_PIN"

die() {
    printf 'build-prev-pkg: %s\n' "$*" >&2
    exit 1
}

_like=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --print-ref)
            printf '%s\n' "$_ref"
            exit 0
            ;;
        --like)
            [ "$#" -ge 2 ] || die '--like requires a package path'
            _like="$2"
            shift 2
            ;;
        *) break ;;
    esac
done

SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# shellcheck source=scripts/lib/git-env-scrub.sh
. "${SCRIPT_DIR}/lib/git-env-scrub.sh"
pfb_scrub_git_env

# ── --like: the branch package's channel (and nightly's required version) ──── #
# A pkg version never contains '-', so the last '-' ends the name.
if [ -n "$_like" ]; then
    _base="${_like##*/}"
    _base="${_base%.pkg}"
    _name="${_base%-*}"
    case "$_name" in
        pfSense-pkg-pfBlockerNG) _chan=stable ;;
        pfSense-pkg-pfBlockerNG-*) _chan="${_name#pfSense-pkg-pfBlockerNG-}" ;;
        *) die "--like: not a pfBlockerNG package name: ${_like}" ;;
    esac
    # First, so an explicit flag from the caller still overrides it.
    set -- --channel "$_chan" "$@"
    [ "$_chan" != nightly ] || set -- --pkgversion "${_base##*-}" "$@"
fi

_work="${PFB_PREV_PKG_WORK:-${TMPDIR:-/tmp}/pfb-prev-pkg}"
_tree="${_work}/tree"
_out="${_work}/out"
_remote="${PFB_GIT_REMOTE:-origin}"

# ── Stage 1: P must be in this checkout ─────────────────────────────────────── #
# A CI checkout is shallow and a box clone fetched only the ref under test, so P can be
# absent. Fetch it by SHA; depth 1 only when the clone is already shallow, because on a
# full clone it would truncate the history.
if ! git -C "$REPO_ROOT" cat-file -e "${_ref}^{commit}" 2>/dev/null; then
    _depth=''
    [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null)" != true ] || _depth='--depth=1'
    printf 'build-prev-pkg: fetching %s from %s\n' "$_ref" "$_remote" >&2
    git -C "$REPO_ROOT" fetch --quiet --no-tags ${_depth:+"$_depth"} -- "$_remote" "$_ref" >&2 \
        || die "fetch failed: ${_ref} from ${_remote}"
fi

# ── Stage 2: P's src/ tree, never the checked-out one ───────────────────────── #
rm -rf "$_tree" "$_out" "${_work}/tree.tar"
mkdir -p "$_tree" "$_out"
git -C "$REPO_ROOT" archive --format=tar -o "${_work}/tree.tar" "$_ref" src \
    || die "extract failed: git archive ${_ref} src"
tar -xf "${_work}/tree.tar" -C "$_tree" || die "extract failed: tar -x of ${_ref} src"
rm -f "${_work}/tree.tar"

# ── Stage 3: the same builder every other build site uses ───────────────────── #
set -- "$@" --local-src "$_tree" --out-dir "$_out"
_built="$(sh "${SCRIPT_DIR}/build-leg.sh" "$@")" || die "build failed: build-leg.sh exited non-zero for ${_ref}"
# build-leg.sh prints the path alone, but take the last line in case a stage leaks one.
_pkg="$(printf '%s\n' "$_built" | tail -n 1)"
[ -f "$_pkg" ] || die "build produced no package file (build-leg.sh printed '${_pkg}')"

_file="${_pkg##*/}"
_file="${_file%.pkg}"
printf 'build-prev-pkg: ref=%s pkg=%s version=%s\n' "$_ref" "$_pkg" "${_file##*-}" >&2
printf '%s\n' "$_pkg"
