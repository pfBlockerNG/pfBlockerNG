#!/bin/sh
# build-repo.sh — turn a directory of ONE variant/version's pfBlockerNG .pkg
# files into a FreeBSD `pkg` repository tree (ADR-17): reads each .pkg's ABI
# FROM THE PACKAGE (never the filename), lays the catalog out DIRECTLY under
# <out>/release/<varver>/ — arch-less (issue #1806: all three
# pfSense-pkg-pfBlockerNG ports are NO_ARCH, so one varver directory serves
# every arch of its FreeBSD major; the ADR-20 varver keying — an ABI is NOT
# 1:1 with an edition/version, so the varver cannot be derived from the
# package and is supplied by the caller) — and runs unsigned `pkg repo` on
# the bucket (NONE-signed trust model, ADR §2). Deterministic + re-runnable +
# no network: the bucket is wiped and rebuilt every run. A flavor collision
# (same name+version+ABI, different php/py flavor), a mixed-ABI input, or a
# CONCRETE (non-NO_ARCH) package ABI all fail loud — see the guards below
# (arch-less catalogs serve every arch, so a concrete package would silently
# install on only one). `pkg` must be a real libpkg build on PATH (override
# PKG_BIN).
#
# Usage:
#   build-repo.sh --in <dir-of-.pkg> --out <dir> --varver <varver>
#   build-repo.sh --print-conf --catalog-path <varver> [--base-url <url>] [--channel <ch>]
#
# Options:
#   --in DIR          directory holding the input .pkg files (searched, non-recursive)
#   --out DIR         output root; the catalog is created at release/<varver>/
#   --varver NAME     catalog key, e.g. ce-2.8 / plus-26.03 (ADR-20; required with --in)
#   --print-conf      print the client repo-conf template to stdout and exit
#   --catalog-path P  <varver> path the printed conf's url resolves to
#   --base-url URL    base URL for --print-conf (default: the ADR Pages base)
#   --channel CH      catalogue channel for --print-conf: stable|testing|edge|nightly
#                     (default: the legacy release channel, repo `pfblockerng`)
#
# Env:
#   PKG_BIN           the pkg binary to use (default: pkg)
#
# POSIX sh; quoted expansions; no bash-isms. Run from anywhere.

set -eu

# ── The shared client repo-conf template ─────────────────────────────────────
# Single source of the client stanza — build-repo-portable.py and the README
# reuse this exact shape (byte-identical; pinned by
# tests/test_repo_conf_generators.py). url carries the LITERAL ${ABI} pkg(8) variable
# (expanded by pkg itself, never shell-interpolated), so one conf auto-follows
# an OS upgrade. priority sits above the base Netgate `pfSense` repo (ships 0)
# because priority — not version — decides cross-repo resolution; that is the
# lever that makes the pfBlockerNG build win. Override the base with --base-url for a fork.
# The pkg repository domain; the scheme is chosen per use site. The catalogue is
# fetched over plain HTTP because pkg's CA store is Netgate-pinned on pfSense Plus
# (issue #2675); authenticity rides the catalogue signature instead.
REPO_HOST='pkg.pfblockerng.com'
DEFAULT_BASE_URL="http://${REPO_HOST}"
CONF_PRIORITY=100

# Per-channel repo-conf stanza key (issue #2147 step B): the four channels
# (stable/testing/edge/nightly) plus the legacy `release` default all carry the
# ONE canonical pfSense-pkg-pfBlockerNG identity — this only picks the stanza
# name + URL path segment. Mirrors install.sh's PROJECT_CONFS keying.
_conf_repo_name() {
    case "$1" in
        release) printf 'pfblockerng' ;;
        nightly) printf 'pfblockerng-nightly' ;;
        stable)  printf 'pfblockerng-stable' ;;
        testing) printf 'pfblockerng-testing' ;;
        edge)    printf 'pfblockerng-edge' ;;
    esac
}


# Whether a base is the host whose catalogues our key signs. A fork base serves a
# catalogue our key never touched, so pinning our fingerprint to it would break it.
_conf_signed_host() {
    case "$1" in
        "https://${REPO_HOST}" | "https://${REPO_HOST}/"* | \
            "http://${REPO_HOST}" | "http://${REPO_HOST}/"*) return 0 ;;
    esac
    return 1
}

# Trust comment + signature fields, keyed on that host.
CONF_FINGERPRINT_DIR='/usr/local/etc/pkg/fingerprints/pfblockerng'

_conf_trust_comment() {
    if _conf_signed_host "$1"; then
        printf '%s\n%s\n%s\n' \
            '# Signed catalogue (issue #2675): the trust anchor is our own ECDSA key, whose' \
            "# fingerprint the boot rc.d hook installs; the fetch is plain HTTP because pkg's" \
            '# CA store is Netgate-pinned on pfSense Plus and unreachable from the GUI.'
    else
        printf '%s\n' '# Unsigned catalogue: this base is not the signed project host.'
    fi
}

_conf_signature_lines() {
    if _conf_signed_host "$1"; then
        printf '  signature_type: fingerprints,\n  fingerprints: "%s",' "${CONF_FINGERPRINT_DIR}"
    else
        printf '  signature_type: none,'
    fi
}

print_conf() {
    # $1 = fully-resolved URL (no trailing slash). $2 = channel (default "release").
    # The URL is a STATIC, directly-resolved string for the box's edition/version —
    # no ${ABI} token (ADR-39), arch-less since issue #1806 (NO_ARCH). Supply
    # --catalog-path <varver> (e.g. "ce-2.8") so the test can pin the exact

    # resolved conf; the url is then base/<channel>/<varver>.
    base="$1"
    channel="${2:-release}"
    repo="$(_conf_repo_name "${channel}")"
    # install.sh --channel rejects "release" (issue #2384) — the legacy release
    # default's hint keeps a literal <channel> placeholder instead of naming a
    # channel install.sh refuses.
    channel_hint="${channel}"
    [ "${channel}" = "release" ] && channel_hint='<channel>'
    url="${base}"
    cat <<EOF
# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run install.sh --channel ${channel_hint} to change.
# pfBlockerNG (${channel} channel) — self-hosted pkg repository (ADR-17).
$(_conf_trust_comment "${url}")
# The URL is fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,
# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.
${repo}: {
  url: "${url}",
  mirror_type: none,
$(_conf_signature_lines "${url}")
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
CHANNEL="release"
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
        --channel)
            [ $# -ge 2 ] || { echo "build-repo: --channel requires a value" >&2; exit 2; }
            case "$2" in
                stable|testing|edge|nightly) CHANNEL="$2" ;;
                *) echo "build-repo: invalid --channel '$2' — valid channels: stable, testing, edge, nightly" >&2; exit 2 ;;
            esac
            shift 2 ;;
        -h|--help)
            sed -n '18,33p' "$0"   # the Usage/Options/Env block from the header
            exit 0 ;;
        *) echo "build-repo: unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ "$PRINT_CONF" -eq 1 ]; then
    [ -n "${CATALOG_PATH}" ] || {
        echo "build-repo: --catalog-path <varver> is required with --print-conf" >&2
        exit 2
    }
    _full_url="${BASE_URL%/}/${CHANNEL}/${CATALOG_PATH}"
    print_conf "${_full_url%/}" "${CHANNEL}"
    exit 0
fi

# Pure precondition test; the || branch (usage + exit) is the intended else and
# the && chain is side-effect-free, so SC2015's caveat does not apply.
# shellcheck disable=SC2015
[ -n "$IN" ] && [ -n "$OUT" ] && [ -n "$VARVER" ] || {
    echo "Usage: $0 --in <dir-of-.pkg> --out <dir> --varver <varver>   |   $0 --print-conf --catalog-path <varver> [--base-url <url>]" >&2
    exit 2
}
[ -d "$IN" ] || { echo "build-repo: --in is not a directory: $IN" >&2; exit 1; }
# The varver becomes a path segment (rm -rf'd + rebuilt) — same safety rule as ABIs.
# issue #1148: class check via LC_ALL=C tr, not a `case` range — a collating
# locale lets [a-z] admit uppercase/accented letters, defeating the guard. The
# '/' sentinel (outside the class) survives tr, so the remainder is compared
# against it — an emptiness check would let $(...) strip a trailing newline.
if [ -z "$VARVER" ] || [ "${VARVER#*..}" != "$VARVER" ] || \
   [ "$(printf '%s/' "$VARVER" | LC_ALL=C tr -d 'a-z0-9.-')" != '/' ]; then
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

# True (status 0) iff $1 is EXACTLY the tight NO_ARCH wildcard shape
# "OS:major:*" (issue #1806) — '*' as the WHOLE final segment, preceded by
# EXACTLY one colon-separated, non-empty, safe-charset "OS:major" pair.
# gate-B finding: a charset-only check on `rest` (everything but the trailing
# ':*') wrongly accepted 'FreeBSD:*' (0 colons in rest — no major segment) and
# 'FreeBSD:15:16:*' (2 colons in rest — an extra segment); counting colons via
# LC_ALL=C tr -cd closes both. Shared by validate_abi() and require_noarch_abi()
# so the tight shape is defined once (ladder rung 2: reuse, not two copies).
_abi_is_tight_wildcard() {
    case "$1" in
        *:\*) : ;;
        *) return 1 ;;
    esac
    rest="${1%:*}"
    case "$rest" in
        :*|*:) return 1 ;;
    esac
    ncolons="$(printf '%s' "$rest" | LC_ALL=C tr -cd ':')"
    [ "${#ncolons}" -eq 1 ] || return 1
    [ "$(printf '%s/' "$rest" | LC_ALL=C tr -d 'A-Za-z0-9:._+-')" = '/' ]
}

# Reject an ABI that is not a single safe path segment or, when it wildcards
# the CPU segment (a NO_ARCH package; issue #1806), not in the TIGHT
# "OS:major:*" shape. The ABI is never used as a directory name any more
# (arch-less catalog), but package metadata still lands verbatim in error
# messages, so it stays validated before any of it is trusted.
# FreeBSD ABIs look like `FreeBSD:15:amd64` (the `:` is allowed); a NO_ARCH
# package's is `FreeBSD:15:*` — '*' is valid ONLY as the WHOLE final segment.
validate_abi() {
    # issue #1148: LC_ALL=C tr + '/' sentinel, not a `case` range — see the
    # --varver guard for both traps (locale collation; trailing-newline strip).
    if [ -z "$1" ] || [ "${1#*..}" != "$1" ]; then
        echo "build-repo: unsafe or invalid ABI in package metadata: '$1'" >&2
        exit 1
    fi
    last="${1##*:}"
    if [ "$last" = "*" ]; then
        if _abi_is_tight_wildcard "$1"; then
            return 0
        fi
        echo "build-repo: unsafe or invalid ABI in package metadata: '$1'" >&2
        exit 1
    fi
    if [ "$(printf '%s/' "$1" | LC_ALL=C tr -d 'A-Za-z0-9:._+-')" != '/' ]; then
        echo "build-repo: unsafe or invalid ABI in package metadata: '$1'" >&2
        exit 1
    fi
}

# Hard-require a NO_ARCH (CPU-wildcarded) ABI at catalog-emission time
# (issue #1806): the catalog is arch-less (release/<varver>/ serves every arch
# of a FreeBSD major from ONE directory), so a concrete-ABI package would
# silently install on only one arch — the tripwire that forces a conscious
# layout decision if a compiled, per-arch dependency is ever added.
require_noarch_abi() {
    if _abi_is_tight_wildcard "$1"; then
        return 0
    fi
    echo "build-repo: catalog requires a NO_ARCH (wildcard-ABI) package — got concrete ABI '$1'." >&2
    echo "  The catalog tree is arch-less (one directory serves every arch of a FreeBSD major);" >&2
    echo "  a concrete-ABI package would silently install on only one arch. Ship a wildcard-ABI" >&2
    echo "  (NO_ARCH) build instead." >&2
    exit 1
}

# ── Lay out the varver bucket + run `pkg repo` ─────────────────────────────────
# issue #1081/#1806: the catalog lives DIRECTLY at <out>/release/<varver>/ —
# arch-less (ADR-20 varver keying, matching build-repo-portable.py and this
# script's own --print-conf url); one (wildcarded) ABI per invocation — a
# mixed input would silently mix editions.
bucket_abi=""
for f in "$@"; do
    abi="$(pkg_abi "$f")"
    validate_abi "$abi"
    require_noarch_abi "$abi"
    if [ -z "$bucket_abi" ]; then
        bucket_abi="$abi"
    elif [ "$abi" != "$bucket_abi" ]; then
        echo "build-repo: mixed ABIs in one run ('$bucket_abi' vs '$abi') — filter --in to one ABI and invoke once per major (keep the same --varver for one edition)" >&2
        exit 1
    fi
done
dir="${OUT}/release/${VARVER}"
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

echo "==> built catalog (release channel) at release/${VARVER}" >&2
