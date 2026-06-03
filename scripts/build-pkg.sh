#!/bin/sh
# build-pkg.sh — build the pfBlockerNG FreeBSD package via the pfSense port,
# with the port's USE_GITHUB fetch PINNED to a specific commit (the HEAD of the
# branch under test) so the packaged artifact is the exact code under test, not
# the tagged release the port defaults to (GH_TAGNAME=v${PORTVERSION}). The
# resulting .pkg installs on pfSense with `pkg add` — properly registered, so
# rc.packages POST-INSTALL runs the package's hooks. Less hacky and more
# reproducible than rsync-overlaying files onto a running box.
#
# MUST run on a FreeBSD host whose MAJOR version matches the target pfSense
# base, because that fixes the pkg ABI: pfSense CE 2.8.1 is FreeBSD 15 ->
# ABI FreeBSD:15:amd64. A .pkg built on FreeBSD 15 installs on pfSense 2.8.1;
# a mismatched major would be rejected. (The workflow selects the FreeBSD
# release from the pfSense version under test.)
#
# Usage:
#   build-pkg.sh --ports <FreeBSD-ports checkout> --gh-tagname <commit-sha> \
#                [--channel devel|stable] [--out <dir>]
#
# --gh-tagname is the commit to package (use the full 40-char SHA of the branch
# HEAD; GitHub's codeload tarball for a commit extracts to <project>-<sha>/).
# The port + the Mk framework both live in the FreeBSD-ports checkout.
#
# POSIX sh; quoted expansions; run as root in the build VM (pkg + make).

set -eu

PORTS=""
CHANNEL="devel"
OUT="$(pwd)"
GH_TAGNAME=""
PHP_DEFAULT="8.3"

while [ $# -gt 0 ]; do
    case "$1" in
        --ports)      PORTS="$2"; shift 2 ;;
        --channel)    CHANNEL="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        --gh-tagname) GH_TAGNAME="$2"; shift 2 ;;
        --php)        PHP_DEFAULT="$2"; shift 2 ;;
        *)            echo "build-pkg: unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PORTS" ] && [ -n "$GH_TAGNAME" ] || {
    echo "Usage: $0 --ports <freebsd-ports> --gh-tagname <commit-sha> [--channel devel|stable] [--out <dir>]" >&2
    exit 2
}
[ "$CHANNEL" = devel ] || [ "$CHANNEL" = stable ] || {
    echo "build-pkg: --channel must be devel|stable" >&2; exit 2
}

PORT_SUBDIR="net/pfSense-pkg-pfBlockerNG-devel"
[ "$CHANNEL" = stable ] && PORT_SUBDIR="net/pfSense-pkg-pfBlockerNG"
PORTDIR="${PORTS}/${PORT_SUBDIR}"
[ -f "${PORTDIR}/Makefile" ] || { echo "build-pkg: port not found at ${PORTDIR}" >&2; exit 1; }
[ -f "${PORTS}/Mk/bsd.port.mk" ] || { echo "build-pkg: Mk framework missing in ${PORTS}" >&2; exit 1; }

# The port hardcodes WRKSRC to <project>-<PORTVERSION>/src (for the default tag
# fetch). Pinning GH_TAGNAME to a commit changes the extracted dir to
# <project>-<sha>/, so override WRKSRC to match.
GH_PROJECT="$(make -C "${PORTDIR}" -V GH_PROJECT)"
WRKDIR="$(make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" -V WRKDIR)"
WRKSRC="${WRKDIR}/${GH_PROJECT}-${GH_TAGNAME}/src"

echo "==> Build host: FreeBSD $(freebsd-version 2>/dev/null || echo '?'), pkg ABI $(pkg config ABI 2>/dev/null || echo '?')"
echo "==> Port ${PORT_SUBDIR}, fetching ${GH_PROJECT}@${GH_TAGNAME}"
echo "==> WRKSRC=${WRKSRC}"

# pfSense pins its PHP version; the fork's ports tree may default to a newer one
# than the target pfSense (CE 2.8.1 = PHP 8.3), which would make the .pkg depend
# on e.g. php84 — absent from pfSense's repo, so `pkg add` can't satisfy it. Pin
# the ports default to match the target so the recorded deps line up.
if [ -n "${PHP_DEFAULT}" ]; then
    echo "DEFAULT_VERSIONS+=php=${PHP_DEFAULT}" >> /etc/make.conf
    echo "==> Pinned DEFAULT_VERSIONS php=${PHP_DEFAULT} in /etc/make.conf"
fi

# clean prior work; makesum fetches the pinned commit's tarball and records its
# checksum (the port ships no distinfo), so `package` verifies integrity rather
# than skipping it. BATCH/DISABLE_LICENSES: no interactive prompts in CI.
make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" WRKSRC="${WRKSRC}" BATCH=yes clean >/dev/null 2>&1 || true

echo "==> make makesum (fetch pinned commit)"
make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" WRKSRC="${WRKSRC}" BATCH=yes DISABLE_LICENSES=yes makesum

# Install the port's build/lib/run deps as BINARY packages from the remote repo.
# The ports framework can't fetch remote packages for deps itself: by default it
# COMPILES them from source (which hits stale ports-patch failures in the fork's
# tree, e.g. gmake), and USE_PACKAGE_DEPENDS_ONLY only looks for locally-built
# .pkg files. Pre-installing satisfies the depends checks so `make package`
# skips building them, and the .pkg records exactly these as its deps.
#
# Resolve each dep ORIGIN to its DEFAULT-flavor package name (PKGBASE) and
# install by name. Installing by bare origin is ambiguous for flavored ports
# (net/rsync -> {rsync, rsync-python}) and pulls the wrong flavor, which then
# gets baked into the manifest (rsync-python, absent from pfSense's repo). The
# default flavor (FLAVOR?=${FLAVORS:[1]}) is what pfSense's own build records.
echo "==> Resolving port dependencies (default flavor) to binary packages"
ORIGINS="$(make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" WRKSRC="${WRKSRC}" \
    -V BUILD_DEPENDS -V LIB_DEPENDS -V RUN_DEPENDS \
    | tr ' ' '\n' | sed -n 's/^[^:]*:\([^:]*\).*/\1/p' | sed 's/@.*//' | sort -u)"
DEPS=""
for o in ${ORIGINS}; do
    [ -d "${PORTS}/${o}" ] || continue
    b="$(make -C "${PORTS}/${o}" -V PKGBASE 2>/dev/null)"
    [ -n "${b}" ] && DEPS="${DEPS} ${b}"
done
echo "deps:${DEPS}"
if [ -n "${DEPS}" ]; then
    # shellcheck disable=SC2086
    pkg install -y ${DEPS}
fi

echo "==> make package"
make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" WRKSRC="${WRKSRC}" BATCH=yes DISABLE_LICENSES=yes package

# `make package` writes the .pkg under ${WRKDIR}/pkg/ (not the .CURDIR path that
# `make -V PKGFILE` reports), so locate it by name rather than trusting PKGFILE.
PKGNAME="$(make -C "${PORTDIR}" GH_TAGNAME="${GH_TAGNAME}" WRKSRC="${WRKSRC}" -V PKGNAME)"
PKGFILE="$(find "${WRKDIR}" "${PORTDIR}" -type f \( -name "${PKGNAME}.pkg" -o -name "${PKGNAME}.txz" \) 2>/dev/null | head -1)"
if [ -z "${PKGFILE}" ] || [ ! -f "${PKGFILE}" ]; then
    echo "build-pkg: package ${PKGNAME}.pkg not found after 'make package'" >&2
    find "${WRKDIR}" "${PORTDIR}" -type f \( -name '*.pkg' -o -name '*.txz' \) 2>/dev/null >&2 || true
    exit 1
fi
mkdir -p "${OUT}"
cp "${PKGFILE}" "${OUT}/"
echo "==> Built $(basename "${PKGFILE}") -> ${OUT}/"
