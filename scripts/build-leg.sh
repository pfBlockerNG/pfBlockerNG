#!/bin/sh
# scripts/build-leg.sh — build ONE .pkg leg: prepare the FreeBSD-ports tree, then
# run the portable builder.  Single shared path for all three build sites (CI build,
# release, smoke).  Sites differ ONLY in parameter values; the build logic is here.
#
# USAGE:
#   build-leg.sh [--ports-repo OWNER/NAME|URL] [--ports-ref REF]
#                [--channel stable|testing|edge|nightly] [--variant CE|Plus]
#                [--build-record JSON|PATH] [--abi ABI]
#                [--py-flavor PYxx] [--php X.Y] [--local-src DIR]
#                [--pkgversion V] [--annotate K=V]...
#                [--ports-dir DEST] [--out-dir OUT]
#
# Prints the resolved absolute .pkg path (and NOTHING else) on stdout.
# All other output — including the ports-prep step — goes to stderr.
# Callers use:  PKG="$(sh scripts/build-leg.sh ...)"
#
# Params + defaults:
#   --ports-repo  pfBlockerNG/FreeBSD-ports   → https://github.com/<repo>
#                 (file:// and https:// URLs pass through unchanged)
#   --ports-ref   pfblockerng/use-github
#   --channel     testing        (→ sparse-clone arg4 AND builder --channel)
#   --variant     CE             (→ builder --variant; native builds ignore it)
#   --build-record (empty)       → --build-record JSON|PATH when supplied
#   --abi         FreeBSD:15:amd64
#   --py-flavor   py311
#   --php         8.3
#   --local-src   .              (→ builder --local-src)
#   --pkgversion  (empty)        → flag omitted; builder derives from ports Makefile
#   --annotate    (none)         repeatable; each → --annotate K=V to builder
#   --ports-dir   (run-keyed)    ${PFB_PORTS_DIR:-$PFB_RUN_DIR/ports}
#   --out-dir     (run-keyed)    ${PFB_OUT_DIR:-$PFB_RUN_DIR/out}
#
# Run-keying (sources scripts/lib/run-id.sh — same chokepoint as select-box.sh):
#   RUN_ID already exported (CI: set by caller via select-box.sh --print-id) → used as-is.
#   RUN_ID absent → minted here: GITHUB_RUN_ID set → pfb_mint_run_id_ci (CI);
#                   else → pfb_mint_run_id_local (local).
#   In CI, if LEG is unset, a filesystem-safe slug is derived from ABI
#   (FreeBSD:15:amd64 → freebsd-15-amd64) so the run-id carries a readable leg token
#   without path-component colons.  Set LEG before calling for explicit control.
#   PFB_RUN_DIR=${PFB_RUN_DIR:-${PFB_RUN_ROOT:-/var/tmp/pfb-runs}/$RUN_ID}
#
# Ports-tree caching: the run-keyed default re-clones each run (avoids stale trees).
# Override --ports-dir with a stable path to reuse an existing clone across runs;
# sparse-clone-ports.sh fetches + resets the ref idempotently (~3 s vs ~30 s).
#
# POSIX sh; shellcheck clean.

set -eu

# ── Locate helpers relative to this script (CWD-independent) ────────────────
SCRIPT_DIR="$(CDPATH='' cd "$(dirname "$0")" && pwd)"

# ── Scrub inherited git context (pre-commit hook exports GIT_DIR etc.) ──────
# shellcheck source=scripts/lib/git-env-scrub.sh
. "${SCRIPT_DIR}/lib/git-env-scrub.sh"
pfb_scrub_git_env

# ── Source the run-id library ────────────────────────────────────────────────
# shellcheck source=scripts/lib/run-id.sh
. "${SCRIPT_DIR}/lib/run-id.sh"

# ── Defaults ─────────────────────────────────────────────────────────────────
PORTS_REPO='pfBlockerNG/FreeBSD-ports'
PORTS_REF='pfblockerng/use-github'
CHANNEL='testing'
VARIANT='CE'
BUILD_RECORD=''
ABI='FreeBSD:15:amd64'  # version-literal-ok: default; overridden by --abi (CI passes the matrix ABI)
PYFLAVOR='py311'  # version-literal-ok: default; overridden by --py-flavor (CI passes the matrix flavor)
PHP='8.3'
LOCAL_SRC='.'
PKGVERSION=''
PORTS_DIR=''
OUT_DIR=''

# Collect --annotate K=V items into a temp file (POSIX-clean repeatable accumulation).
# ponytail: temp file for repeatable args — arrays don't exist in POSIX sh.
_BL_ANN_FILE="$(mktemp)"
trap 'rm -f "$_BL_ANN_FILE"' EXIT INT TERM

# ── Argument parsing ─────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    _opt="$1"
    shift
    case "$_opt" in
        --ports-repo)  PORTS_REPO="${1?build-leg.sh: --ports-repo requires an argument}"; shift ;;
        --ports-ref)   PORTS_REF="${1?build-leg.sh: --ports-ref requires an argument}";   shift ;;
        --channel)     CHANNEL="${1?build-leg.sh: --channel requires an argument}";       shift ;;
        --variant)     VARIANT="${1?build-leg.sh: --variant requires an argument}";       shift ;;
        --build-record) BUILD_RECORD="${1?build-leg.sh: --build-record requires an argument}"; shift ;;
        --abi)         ABI="${1?build-leg.sh: --abi requires an argument}";               shift ;;
        --py-flavor)   PYFLAVOR="${1?build-leg.sh: --py-flavor requires an argument}";   shift ;;
        --php)         PHP="${1?build-leg.sh: --php requires an argument}";               shift ;;
        --local-src)   LOCAL_SRC="${1?build-leg.sh: --local-src requires an argument}";  shift ;;
        --pkgversion)  PKGVERSION="${1?build-leg.sh: --pkgversion requires an argument}"; shift ;;
        --annotate)    printf '%s\n' "${1?build-leg.sh: --annotate requires an argument}" >> "$_BL_ANN_FILE"; shift ;;
        --ports-dir)   PORTS_DIR="${1?build-leg.sh: --ports-dir requires an argument}";  shift ;;
        --out-dir)     OUT_DIR="${1?build-leg.sh: --out-dir requires an argument}";       shift ;;
        --) break ;;
        -*)
            printf '%s: unknown option: %s\n' "$0" "$_opt" >&2
            exit 1
            ;;
        *)
            printf '%s: unexpected argument: %s\n' "$0" "$_opt" >&2
            exit 1
            ;;
    esac
done

# ── Derive ports URL ─────────────────────────────────────────────────────────
# file:// and https:// (and http://) pass through unchanged for testing; OWNER/NAME
# style → prepend the GitHub HTTPS prefix.
case "$PORTS_REPO" in
    file://*|https://*|http://*) PORTS_URL="$PORTS_REPO" ;;
    *) PORTS_URL="https://github.com/${PORTS_REPO}" ;;
esac

# ── Run-id + run directory ───────────────────────────────────────────────────
if [ -z "${RUN_ID:-}" ]; then
    if [ -n "${GITHUB_RUN_ID:-}" ]; then
        # CI: slug the ABI into a path-safe LEG token if not externally set.
        # FreeBSD:15:amd64 → freebsd-15-amd64 (colons → dashes; no path separators).
        # issue #1806: --abi stays a CONCRETE guest/builder ABI here regardless of
        # the arch-less matrix -- this fallback slug is unaffected by the
        # major-collapse (callers that want the fbsd<major>-only naming set LEG
        # explicitly before calling, e.g. release.yml/smoke.yml).
        if [ -z "${LEG:-}" ]; then
            LEG="$(printf '%s' "$ABI" | tr '[:upper:]' '[:lower:]' | tr ':' '-')"
            export LEG
        fi
        RUN_ID="$(pfb_mint_run_id_ci)"
    else
        RUN_ID="$(pfb_mint_run_id_local "${PFB_BOX:-$(hostname)}")"
    fi
    export RUN_ID
fi

PFB_RUN_DIR="${PFB_RUN_DIR:-${PFB_RUN_ROOT:-/var/tmp/pfb-runs}/${RUN_ID}}"
export PFB_RUN_DIR

DEST="${PORTS_DIR:-${PFB_PORTS_DIR:-${PFB_RUN_DIR}/ports}}"
OUT="${OUT_DIR:-${PFB_OUT_DIR:-${PFB_RUN_DIR}/out}}"

mkdir -p "$OUT"

# ── Step 1: prepare the ports tree ──────────────────────────────────────────
# AMENDMENT 1: redirect sparse-clone stdout to stderr.
# git checkout writes branch-tracking chatter (e.g. "Your branch is up to date
# with origin/<REF>.") to stdout.  That chatter must NEVER appear on build-leg's
# stdout — callers use PKG="$(build-leg.sh ...)" and expect exactly one line:
# the resolved .pkg path.
sh "${SCRIPT_DIR}/sparse-clone-ports.sh" \
    "$PORTS_URL" \
    "$PORTS_REF" \
    "$DEST" \
    "$CHANNEL" \
    "$PHP" \
    "$PYFLAVOR" 1>&2

# ── Step 2: build the .pkg ──────────────────────────────────────────────────
# Assemble the builder's positional arg list using set --.
set -- \
    --ports     "$DEST"     \
    --channel   "$CHANNEL"  \
    --variant   "$VARIANT"  \
    --local-src "$LOCAL_SRC" \
    --abi       "$ABI"      \
    --py-flavor "$PYFLAVOR" \
    --php       "$PHP"      \
    --out       "$OUT"

# Append --pkgversion only when supplied (empty → omit so builder uses Makefile).
[ -n "$PKGVERSION" ] && set -- "$@" --pkgversion "$PKGVERSION"

# Pass the normalized record only when project mode is requested; native builds
# remain recipe-driven and keep their existing argv.
[ -n "$BUILD_RECORD" ] && set -- "$@" --build-record "$BUILD_RECORD"

# Append one --annotate K=V per collected item.
while IFS= read -r _ann; do
    [ -n "$_ann" ] && set -- "$@" --annotate "$_ann"
done < "$_BL_ANN_FILE"

# Capture the resolved .pkg path from the builder's stdout (the ONLY thing it prints).
# All builder progress goes to stderr — its stdout contract matches ours.
PKG="$(python3 "${SCRIPT_DIR}/build-pkg-portable.py" "$@")"
printf '%s\n' "$PKG"
