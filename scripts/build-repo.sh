#!/bin/sh
# build-repo.sh — turn a directory of pfBlockerNG .pkg files into a per-ABI
# FreeBSD `pkg` repository tree (ADR-17 Phase 2). This is the reusable, proven
# catalog generator the Phase-3 publish job calls over the .pkg assets ADR-09
# attaches to each GitHub Release.
#
# WHAT IT DOES
#   1. Reads each input .pkg's ABI FROM THE PACKAGE (`pkg query -F <f> '%q'`) —
#      never guessed from the filename.
#   2. Buckets each .pkg under  <out>/<ABI>/  (one catalog per ABI, e.g.
#      <out>/FreeBSD:15:amd64/) and copies the .pkg there.
#   3. Runs `pkg repo <out>/<ABI>` per bucket with NO signing key, emitting the
#      catalog triple (meta.conf / packagesite.pkg / data.pkg) a client
#      `pkg update` consumes. NONE-signed by construction (the ADR trust model:
#      TLS to the host, no CI key — ADR §2 "Trust model").
#   4. Optionally prints the shared client repo-conf TEMPLATE (`--print-conf`):
#      the single `${ABI}` / NONE-signed / above-pfSense-priority stanza Phase 4's
#      add-repo.sh and the README reuse.
#
# Deterministic + re-runnable + NO network: the same inputs yield the same tree;
# a re-run wipes and rebuilds each ABI bucket so a removed .pkg never lingers.
#
# FLAVOR-COLLISION GUARD: two .pkg sharing package-name + version + ABI but
# differing in php/py flavor (their `php*`/`py*-*` dependency names) CANNOT
# coexist in one catalog — the second would silently shadow the first. We FAIL
# LOUD rather than drop a build. No colliding combo exists today (CE 2.8 + Plus
# 25.03 are both FreeBSD:15:amd64 / php83 / py311); when one ever does, the fix
# is a flavored layout `<out>/<ABI>-<php><py>/` (add-repo.sh would then detect +
# pin the box's flavor). That split is intentionally NOT implemented here — see
# the guard below.
#
# LIBPKG PROVENANCE: `pkg repo` is a libpkg op needing the `pkg` binary. On
# FreeBSD (or the pfSense VM) `pkg` is present. On a Linux CI runner it is NOT in
# apt and has no official prebuilt — see RESULTS/02 for the libpkg-on-Linux vs
# FreeBSD-VM-fallback verdict that decides where Phase 3 runs this. The script is
# transport-agnostic: it only needs SOME `pkg` on PATH (override with PKG_BIN).
#
# Usage:
#   build-repo.sh --in <dir-of-.pkg> --out <dir>      # build the per-ABI tree
#   build-repo.sh --print-conf [--base-url <url>]     # print the client repo-conf
#
# Options:
#   --in DIR          directory holding the input .pkg files (searched, non-recursive)
#   --out DIR         output root; one <ABI>/ catalog subtree is created per ABI
#   --print-conf      print the client repo-conf template to stdout and exit
#   --base-url URL    base URL for --print-conf (default: the ADR Pages base);
#                     the conf appends the literal ${ABI} pkg variable to it
#
# Env:
#   PKG_BIN           the pkg binary to use (default: pkg)
#
# POSIX sh; quoted expansions; no bash-isms. Run from anywhere.

set -eu

# ── The shared client repo-conf template ───────────────────────────────────────
#
# The SINGLE source of the client stanza (Phase 4's add-repo.sh + the README
# reuse this exact shape). Fields, per ADR §2 "Client bootstrap":
#   * url:            STATIC base + the literal ${ABI} pkg variable (NO shell/query
#                     interpolation) so one conf auto-follows the box's ABI across
#                     an OS upgrade. ${ABI} is expanded by pkg(8), not the shell.
#   * mirror_type: none / signature_type: none — NONE-signed; trust = HTTPS to the host.
#   * priority:       ABOVE the base Netgate `pfSense` repo so cross-repo resolution
#                     picks our build. Phase 1 PROVED priority dominates version (a
#                     higher-priority repo wins even at a lower version), so this is
#                     the real precedence lever. The pfSense repo ships priority 0 by
#                     default; 100 clears it with margin while staying an ordinary
#                     positive value (add-repo.sh may recompute it live, +100 over the
#                     effective pfSense priority, the way the Phase-1 smoke does).
#   * enabled: yes.
# `pfblockerng-devel` matches the channel-named conf Phase 4 writes
# (/usr/local/etc/pkg/repos/pfblockerng-devel.conf).
# The published GitHub Pages base — the repo's standard project Pages URL
# (gh api repos/.../pages -> html_url https://andrebrait.github.io/pfBlockerNG/);
# we serve over HTTPS, so the base is https://andrebrait.github.io/pfBlockerNG and the conf
# appends the literal ${ABI} pkg(8) variable. Override with --base-url for a fork.
DEFAULT_BASE_URL="https://andrebrait.github.io/pfBlockerNG"
CONF_PRIORITY=100

print_conf() {
    # $1 = base URL (no trailing slash). The url value is a STATIC string with the
    # literal ${ABI} pkg variable appended — deliberately single-quoted on emission
    # so neither this shell nor the URL-encoding gate sees a live expansion.
    base="$1"
    cat <<EOF
# pfBlockerNG (devel channel) — self-hosted pkg repository (ADR-17).
# NONE-signed: trust anchor is HTTPS to the host (no signing key). The \${ABI}
# variable is expanded by pkg(8) and follows the box across a pfSense OS upgrade.
# priority ${CONF_PRIORITY} sits above the base Netgate \`pfSense\` repo so cross-repo
# resolution (pkg install/upgrade, GUI Install) selects our build.
pfblockerng-devel: {
  url: "${base}/\${ABI}",
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
PKG_BIN="${PKG_BIN:-pkg}"

while [ $# -gt 0 ]; do
    case "$1" in
        --in)         IN="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        --print-conf) PRINT_CONF=1; shift ;;
        --base-url)   BASE_URL="$2"; shift 2 ;;
        -h|--help)
            sed -n '37,57p' "$0"   # the Usage/Options/Env block from the header
            exit 0 ;;
        *) echo "build-repo: unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ "$PRINT_CONF" -eq 1 ]; then
    print_conf "${BASE_URL%/}"
    exit 0
fi

# Pure precondition test; the || branch (usage + exit) is the intended else and
# the && chain is side-effect-free, so SC2015's caveat does not apply.
# shellcheck disable=SC2015
[ -n "$IN" ] && [ -n "$OUT" ] || {
    echo "Usage: $0 --in <dir-of-.pkg> --out <dir>   |   $0 --print-conf [--base-url <url>]" >&2
    exit 2
}
[ -d "$IN" ] || { echo "build-repo: --in is not a directory: $IN" >&2; exit 1; }

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
    # "<name> <version>" of a .pkg.
    "$PKG_BIN" query -F "$1" '%n %v' 2>/dev/null
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

# ── Lay out per-ABI buckets + run `pkg repo` ───────────────────────────────────
mkdir -p "$OUT"
# Track which ABI buckets we (re)built, so each is wiped exactly once for
# determinism even when several .pkg share an ABI.
built=""
for f in "$@"; do
    abi="$(pkg_abi "$f")"
    dir="${OUT}/${abi}"
    case " $built " in
        *" $abi "*) : ;;                 # already wiped this run
        *) rm -rf "$dir"; mkdir -p "$dir"; built="$built $abi" ;;
    esac
    cp "$f" "${dir}/"
done

for abi in $built; do
    dir="${OUT}/${abi}"
    echo "==> pkg repo ${dir}" >&2
    # No key argument => an unsigned (NONE-signed) catalog. ASSUME_ALWAYS_YES so
    # pkg never prompts in CI.
    env ASSUME_ALWAYS_YES=yes "$PKG_BIN" repo "$dir"
done

echo "==> built catalogs for ABI:${built}" >&2
