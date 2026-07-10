#!/bin/sh
# build-repo.sh — turn a directory of ONE variant/version's pfBlockerNG .pkg
# files into a FreeBSD `pkg` repository tree (ADR-17): reads each .pkg's ABI
# FROM THE PACKAGE (never the filename), lays the catalog out under
# <out>/release/<varver>/<arch>/ (the ADR-20 varver keying — an ABI is NOT
# 1:1 with an edition/version, so the varver cannot be derived from the
# package and is supplied by the caller), and runs unsigned `pkg repo` on the
# bucket (NONE-signed trust model, ADR §2). Deterministic + re-runnable + no
# network: the bucket is wiped and rebuilt every run. A flavor collision
# (same name+version+ABI, different php/py flavor) or a mixed-ABI input
# fails loud — see the guards below. `pkg` must be a real libpkg build on
# PATH (override PKG_BIN).
#
# Usage:
#   build-repo.sh --in <dir-of-.pkg> --out <dir> --varver <varver>
#   build-repo.sh --print-conf --catalog-path <varver>/<arch> [--base-url <url>]
#
# Options:
#   --in DIR          directory holding the input .pkg files (searched, non-recursive)
#   --out DIR         output root; the catalog is created at release/<varver>/<arch>/
#   --varver NAME     catalog key, e.g. ce-2.8 / plus-26.03 (ADR-20; required with --in)
#   --print-conf      print the client repo-conf template to stdout and exit
#   --catalog-path P  <varver>/<arch> path the printed conf's url resolves to
#   --base-url URL    base URL for --print-conf (default: the ADR Pages base)
#
# Env:
#   PKG_BIN           the pkg binary to use (default: pkg)
#
# POSIX sh; quoted expansions; no bash-isms. Run from anywhere.

set -eu

# ── The shared client repo-conf template ─────────────────────────────────────
# Single source of the client stanza — add-repo.sh, build-repo-portable.py, and
# the README reuse this exact shape (byte-identical; pinned by
# tests/test_add_repo_conf.py). url carries the LITERAL ${ABI} pkg(8) variable
# (expanded by pkg itself, never shell-interpolated), so one conf auto-follows
# an OS upgrade. priority sits above the base Netgate `pfSense` repo (ships 0)
# because priority — not version — decides cross-repo resolution; that is the
# lever that makes the pfBlockerNG build win. Override the base with --base-url for a fork.
DEFAULT_BASE_URL="https://pfblockerng.github.io/pkg"
CONF_PRIORITY=100

print_conf() {
    # $1 = fully-resolved URL (no trailing slash). The URL is a STATIC, directly-resolved
    # string for the box's edition/version/arch — no ${ABI} token (ADR-39).
    # Supply --catalog-path <varver>/<arch> (e.g. "ce-2.8/amd64") so the test can
    # pin the exact resolved conf; the url is then base/release/<varver>/<arch>.
    base="$1"
    cat <<EOF
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run add-repo.sh to change.
# pfBlockerNG (release channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is
# fully resolved for this box's edition/version/arch (ADR-39); the boot
# rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.
pfblockerng: {
  url: "${base}",
  mirror_type: none,
  signature_type: none,
  priority: ${CONF_PRIORITY},
  enabled: yes
}
EOF
}

# ── Arg parsing ────────────────────────────────────────────────────────────────
IN=""
OUT=""
PRINT_CONF=0
BASE_URL="$DEFAULT_BASE_URL"
CATALOG_PATH=""
PKG_BIN="${PKG_BIN:-pkg}"

VARVER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --in)            IN="$2"; shift 2 ;;
        --out)           OUT="$2"; shift 2 ;;
        --varver)        VARVER="$2"; shift 2 ;;
        --print-conf)    PRINT_CONF=1; shift ;;
        --base-url)      BASE_URL="$2"; shift 2 ;;
        --catalog-path)  CATALOG_PATH="$2"; shift 2 ;;
        -h|--help)
            sed -n '14,29p' "$0"   # the Usage/Options/Env block from the header
            exit 0 ;;
        *) echo "build-repo: unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ "$PRINT_CONF" -eq 1 ]; then
    [ -n "${CATALOG_PATH}" ] || {
        echo "build-repo: --catalog-path <varver>/<arch> is required with --print-conf" >&2
        exit 2
    }
    _full_url="${BASE_URL%/}/release/${CATALOG_PATH}"
    print_conf "${_full_url%/}"
    exit 0
fi

# Pure precondition test; the || branch (usage + exit) is the intended else and
# the && chain is side-effect-free, so SC2015's caveat does not apply.
# shellcheck disable=SC2015
[ -n "$IN" ] && [ -n "$OUT" ] && [ -n "$VARVER" ] || {
    echo "Usage: $0 --in <dir-of-.pkg> --out <dir> --varver <varver>   |   $0 --print-conf --catalog-path <varver>/<arch> [--base-url <url>]" >&2
    exit 2
}
[ -d "$IN" ] || { echo "build-repo: --in is not a directory: $IN" >&2; exit 1; }
# The varver becomes a path segment (rm -rf'd + rebuilt) — same safety rule as ABIs.
# issue #1148: class check via LC_ALL=C tr, not a `case` range — a collating
# locale lets [a-z] admit uppercase/accented letters, defeating the guard.
if [ -z "$VARVER" ] || [ "${VARVER#*..}" != "$VARVER" ] || \
   [ -n "$(printf '%s' "$VARVER" | LC_ALL=C tr -d 'a-z0-9.-')" ]; then
    echo "build-repo: unsafe or invalid --varver: '$VARVER' (expect e.g. ce-2.8 / plus-26.03)" >&2
    exit 2
fi

command -v "$PKG_BIN" >/dev/null 2>&1 || {
    echo "build-repo: '$PKG_BIN' not found on PATH — need a libpkg \`pkg\` binary (set PKG_BIN)" >&2
    exit 1
}

# ── Helpers ────────────────────────────────────────────────────────────────────

# The ABI of a .pkg, READ from the package (not guessed from the filename).
pkg_abi() {
    "$PKG_BIN" query -F "$1" '%q' 2>/dev/null
}

# The flavor signature of a .pkg: its php*/python*/py*- dependency NAMES, sorted.
# Two builds of the same name+version+ABI that differ here are different flavors
# and cannot share a catalog (the collision guard). Empty for a flavor-free pkg.
pkg_flavor_sig() {
    "$PKG_BIN" query -F "$1" '%dn' 2>/dev/null \
        | grep -E '^(php[0-9]+|python[0-9]+|py[0-9]+-)' \
        | LC_ALL=C sort \
        | tr '\n' ',' || true
}

pkg_nv() {
    # "<name>-<version>" of a .pkg — the hyphenated form `pkg repo` records in
    # the catalog and clients fetch (issue #1081: a space here broke the served
    # path).
    "$PKG_BIN" query -F "$1" '%n-%v' 2>/dev/null
}

# ── Enumerate inputs ───────────────────────────────────────────────────────────
# Collect the .pkg paths into the positional params (POSIX-portable iteration,
# no arrays). `set --` resets them; the nullglob-free guard skips a literal
# no-match. Non-recursive: inputs are a flat dir of release .pkg.
set --
for f in "$IN"/*.pkg; do
    [ -e "$f" ] || continue
    set -- "$@" "$f"
done
[ "$#" -gt 0 ] || { echo "build-repo: no .pkg files in $IN" >&2; exit 1; }

# ── Collision guard: name+version+ABI must map to ONE flavor ────────────────────
# Build a "<name>|<version>|<ABI> -> flavor-signature" check. A repeated key with
# a DIFFERENT signature is an unhandled flavor collision -> FAIL LOUD. A repeated
# key with the SAME signature is a duplicate input (harmless; pkg repo dedups).
# Use a temp file as the associative store (POSIX sh has no maps).
seen="$(mktemp)"
trap 'rm -f "$seen"' EXIT INT TERM
for f in "$@"; do
    abi="$(pkg_abi "$f")"
    [ -n "$abi" ] || { echo "build-repo: could not read ABI from $f" >&2; exit 1; }
    nv="$(pkg_nv "$f")"
    sig="$(pkg_flavor_sig "$f")"
    key="${nv}|${abi}"
    prev="$(grep -F "KEY=${key}=SIG=" "$seen" 2>/dev/null | head -n1 || true)"
    if [ -n "$prev" ]; then
        prev_sig="${prev#KEY="${key}"=SIG=}"
        if [ "$prev_sig" != "$sig" ]; then
            echo "build-repo: FLAVOR COLLISION — two packages share name+version+ABI '${key}'" >&2
            echo "  but differ in php/py flavor:" >&2
            echo "    flavor A: ${prev_sig:-<none>}" >&2
            echo "    flavor B: ${sig:-<none>}" >&2
            echo "  They cannot coexist in one catalog (the second would shadow the first)." >&2
            echo "  Resolve by splitting into a flavored layout: <out>/<ABI>-<php><py>/" >&2
            echo "  (not implemented — no colliding combo exists today; teach the tool when one does)." >&2
            exit 1
        fi
    else
        echo "KEY=${key}=SIG=${sig}" >> "$seen"
    fi
done

# Reject an ABI that is not a single safe path segment — it becomes a directory
# name (${OUT}/${abi}) that is `rm -rf`'d + rebuilt, so `..` / `/` / odd chars could
# escape $OUT. FreeBSD ABIs look like `FreeBSD:15:amd64` (the `:` is allowed).
validate_abi() {
    # issue #1148: LC_ALL=C tr, not a `case` range — see the --varver guard.
    if [ -z "$1" ] || [ "${1#*..}" != "$1" ] || \
       [ -n "$(printf '%s' "$1" | LC_ALL=C tr -d 'A-Za-z0-9:._+-')" ]; then
        echo "build-repo: unsafe or invalid ABI in package metadata: '$1'" >&2
        exit 1
    fi
}

# ── Lay out the varver bucket + run `pkg repo` ─────────────────────────────────
# issue #1081: the catalog lives at <out>/release/<varver>/<arch>/ (ADR-20 varver
# keying, matching build-repo-portable.py and this script's own --print-conf
# url); one ABI per invocation — a mixed input would silently mix editions.
bucket_abi=""
for f in "$@"; do
    abi="$(pkg_abi "$f")"
    validate_abi "$abi"
    if [ -z "$bucket_abi" ]; then
        bucket_abi="$abi"
    elif [ "$abi" != "$bucket_abi" ]; then
        echo "build-repo: mixed ABIs in one run ('$bucket_abi' vs '$abi') — filter --in to one ABI and invoke once per ABI/arch (keep the same --varver for one edition)" >&2
        exit 1
    fi
done
arch="${bucket_abi##*:}"
dir="${OUT}/release/${VARVER}/${arch}"
rm -rf "$dir"
mkdir -p "$dir"
for f in "$@"; do
    # Copy under the CANONICAL `<name>-<version>.pkg` name (never the staging input
    # filename), so the catalog path is clean and an identical name+version from
    # another source (branch + release artifact) overwrites to a single file (dedup;
    # a different-flavor clash was already rejected above).
    nv="$(pkg_nv "$f")"
    cp "$f" "${dir}/${nv}.pkg"
done

echo "==> pkg repo ${dir}" >&2
# No key argument => an unsigned (NONE-signed) catalog. ASSUME_ALWAYS_YES so
# pkg never prompts in CI.
env ASSUME_ALWAYS_YES=yes "$PKG_BIN" repo "$dir"

echo "==> built catalog (release channel) at release/${VARVER}/${arch}" >&2
