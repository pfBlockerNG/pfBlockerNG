#!/bin/sh
# read-version-matrix.sh — read supported-versions.json from the ci-metadata
# orphan ref and emit the BUILD matrix and CI matrix as JSON.
#
# Usage:
#   read-version-matrix.sh [--ref <git-ref>] [--file <path>] [--github-output]
#                          [--print-build | --print-ci | --print-test | --print-all
#                           | --print-route]
#                          [--variant CE|Plus]
#
# Options:
#   --ref <git-ref>      Git ref to read from (default: origin/ci-metadata).
#                        Must be reachable in the current git repo.
#   --file <path>        Matrix file path on the ref
#                        (default: supported-versions.json).
#   --github-output      Write build_matrix, ci_matrix, variant, python_versions,
#                        and php_versions to $GITHUB_OUTPUT (GitHub Actions step
#                        outputs format).
#   --print-build        Print BUILD matrix JSON to stdout. Excludes role=route-only
#                        entries (those are served but not built or smoked).
#   --print-ci           Print CI matrix JSON to stdout. Excludes role=route-only
#                        entries (same exclusion as --print-build).
#   --print-test         Print the derived test matrices (python_versions +
#                        php_versions) to stdout (labelled). Excludes role=route-only.
#   --print-all          Print both BUILD and CI matrices to stdout (labelled).
#   --print-route        Print ROUTE matrix JSON to stdout — every entry with a live
#                        catalog: role=build (or absent) UNION role=route-only. This
#                        is the set whose release/<varver>/<arch>/ catalog is served.
#                        Excludes truly-dropped entries (those are simply absent from
#                        supported-versions.json).
#   --variant CE|Plus    Filter both matrices to entries whose `variant` field
#                        matches the given value (case-insensitive). Returns ALL
#                        matching entries — during a transition window there may
#                        be multiple CE or Plus entries simultaneously. Without
#                        this flag all entries are returned (backward-compatible).
#
# Outputs:
#   BUILD matrix     — role=build entries (absent role treated as build; back-compat).
#     Each entry carries: pfsense_version, channel, freebsd_version, freebsd_major,
#     php_version, py_flavor, variant, status, ci, arch. `arch` is resolved
#     (default "amd64"), so the build fans out version × arch — an entry that
#     omits arch (every entry today) stays amd64, while an aarch64 entry
#     (Plus-only, Netgate ARM appliances) builds a FreeBSD:N:aarch64 .pkg
#     (issue #199). role=route-only entries are EXCLUDED: they are served from a
#     frozen .pkg but never built or smoked.
#   CI matrix        — the ci:true entries (ANY channel), subset of BUILD matrix.
#     Inherits the resolved `arch` from the BUILD matrix, and additionally carries
#     a resolved image_name (default "pfsense-ce") and mac (default the CE pin
#     "BC:24:11:37:9C:AC"), so an entry that omits them — every CE entry today —
#     keeps the CE image + MAC, while a ci:true Plus entry can carry its own
#     image_name/mac (ADR-24). role=route-only entries are EXCLUDED (same as BUILD).
#   ROUTE matrix     — BUILD matrix UNION role=route-only entries. Every entry whose
#     release/<varver>/<arch>/ catalog is actively served. The generator uses this
#     to determine which varver paths to build (route-only from frozen .pkg, build
#     entries from the fresh build). Absent role == build (fully back-compat).
#   python_versions  — DISTINCT python versions derived from each BUILD-matrix
#     entry's py_flavor (`pyN` + `MM` => `N.MM`, e.g. py311 => 3.11; py39 => 3.9),
#     sorted + deduped. test.yml's pytest matrix (supported-only — only the
#     pythons the matrix actually ships). Excludes route-only (no build, no test leg).
#   php_versions     — DISTINCT php_version across the BUILD-matrix entries,
#     sorted + deduped. test.yml's PHP-jobs matrix (supported-only).
#     Excludes route-only (no build, no test leg).
#
# Requirements: git, jq (both available on ubuntu-latest GH runners).
# Pure read — no writes anywhere; exits non-zero on any error.
#
# The matrix lives on the ci-metadata ORPHAN branch — off main/devel —
# so editing it never touches the channel branches.
# See: scripts/README.md § "Supported-version matrix"

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
MATRIX_REF="${MATRIX_REF:-origin/ci-metadata}"
MATRIX_FILE="${MATRIX_FILE:-supported-versions.json}"
DO_GITHUB_OUTPUT=0
DO_PRINT_BUILD=0
DO_PRINT_CI=0
DO_PRINT_TEST=0
DO_PRINT_ROUTE=0
VARIANT_FILTER=""

# ── Argument parsing ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --ref)       MATRIX_REF="$2";  shift 2 ;;
    --file)      MATRIX_FILE="$2"; shift 2 ;;
    --variant)   VARIANT_FILTER="$2"; shift 2 ;;
    --github-output) DO_GITHUB_OUTPUT=1; shift ;;
    --print-build)   DO_PRINT_BUILD=1;   shift ;;
    --print-ci)      DO_PRINT_CI=1;      shift ;;
    --print-test)    DO_PRINT_TEST=1;    shift ;;
    --print-route)   DO_PRINT_ROUTE=1;   shift ;;
    --print-all)     DO_PRINT_BUILD=1; DO_PRINT_CI=1; shift ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

# Default: print both matrices when running standalone with no print flags and no
# GH output. (--print-test and --print-route alone are explicit requests — don't
# add build/ci to them.)
if [ "$DO_GITHUB_OUTPUT" -eq 0 ] && [ "$DO_PRINT_BUILD" -eq 0 ] && [ "$DO_PRINT_CI" -eq 0 ] && [ "$DO_PRINT_TEST" -eq 0 ] && [ "$DO_PRINT_ROUTE" -eq 0 ]; then
  DO_PRINT_BUILD=1
  DO_PRINT_CI=1
fi

# ── Validate dependencies ──────────────────────────────────────────────────────
if ! command -v git >/dev/null 2>&1; then
  printf '::error::git is required but not found\n' >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  printf '::error::jq is required but not found\n' >&2
  exit 1
fi

# ── Read the matrix JSON from the ref ─────────────────────────────────────────
# Verify the ref is reachable before trying to cat.
if ! git fetch origin ci-metadata >/dev/null 2>&1; then
  # If fetch fails (e.g. offline or --ref is a local path), proceed with whatever
  # is already in the local repo. Not an error — the caller may have pre-fetched.
  :
fi

RAW_JSON="$(git show "${MATRIX_REF}:${MATRIX_FILE}" 2>/dev/null)" || {
  printf '::error::cannot read %s from ref %s — is origin/ci-metadata pushed?\n' \
    "$MATRIX_FILE" "$MATRIX_REF" >&2
  exit 1
}

# Validate: must be a JSON object with a "versions" array.
if ! printf '%s' "$RAW_JSON" | jq -e '.versions | type == "array"' >/dev/null 2>&1; then
  printf '::error::%s does not contain a valid "versions" array\n' "$MATRIX_FILE" >&2
  exit 1
fi

# ── Route matrix: ALL entries with a live catalog (build ∪ route-only) ───────
# role absent/build/route-only all have a served catalog. A truly dropped version
# is simply absent from the JSON. Absent role defaults to "build" (back-compat).
if [ -n "$VARIANT_FILTER" ]; then
  # Case-insensitive match: compare lowercase of both sides.
  _VF_LOWER="$(printf '%s' "$VARIANT_FILTER" | tr '[:upper:]' '[:lower:]')"
  ROUTE_MATRIX="$(printf '%s' "$RAW_JSON" | jq -c \
    --arg vf "$_VF_LOWER" \
    '[.versions[] | select((.variant // "" | ascii_downcase) == $vf)]')"
else
  ROUTE_MATRIX="$(printf '%s' "$RAW_JSON" | jq -c '.versions')"
fi

# Normalise arch in the ROUTE matrix (same rule as BUILD: absent/empty => amd64).
ROUTE_MATRIX="$(printf '%s' "$ROUTE_MATRIX" | jq -c '
  [ .[] | . + { arch: (if ((.arch // "") == "") then "amd64" else .arch end) } ]')"

# ── Build matrix: role=build entries only (excludes role=route-only) ──────────
# An absent role is treated as "build" ((.role // "build") == "build") so with
# today's matrices — no route-only entries — the BUILD matrix is byte-identical to
# the old full .versions[] output (fully back-compat).
BUILD_MATRIX="$(printf '%s' "$ROUTE_MATRIX" | jq -c \
  '[.[] | select((.role // "build") != "route-only")]')"

# BUILD_MATRIX inherits already-normalised arch from ROUTE_MATRIX (absent/empty =>
# amd64, done above). The CI matrix inherits this resolved arch verbatim.

# ── CI matrix: the ci:true entries (ANY channel) within the variant-filtered set ──
# The channel no longer filters (ADR-24): a ci:true Plus entry is a first-class CI
# leg. Each entry gains a resolved image_name (default "pfsense-ce") and mac (default
# the CE pin) — an entry that omits them keeps the CE image + MAC, while a Plus entry
# carries its own. The MAC is load-bearing for a Plus image (license/NDI keyed to it).
CI_MATRIX="$(printf '%s' "$BUILD_MATRIX" | jq -c '
  [ .[]
    | select(.ci == true)
    | . + {
        image_name: (if ((.image_name // "") == "") then "pfsense-ce" else .image_name end),
        mac: (if ((.mac // "") == "") then "BC:24:11:37:9C:AC" else .mac end)
      }
  ]')"

# ── Sanity: CI matrix must not be empty ───────────────────────────────────────
# Skip when --variant filters to a non-CE variant (a Plus-only filtered set may have
# no ci:true entry while Plus is still ci=false on the live matrix).
if [ "${_VF_LOWER:-}" != "plus" ]; then
  CI_COUNT="$(printf '%s' "$CI_MATRIX" | jq 'length')"
  if [ "$CI_COUNT" -eq 0 ]; then
    printf '::error::CI matrix is empty — no ci:true CE entries in %s\n' "$MATRIX_FILE" >&2
    exit 1
  fi
fi

# ── Emit ──────────────────────────────────────────────────────────────────────
# Variant JSON array: distinct variant values present in the BUILD matrix.
VARIANT_ARRAY="$(printf '%s' "$BUILD_MATRIX" | jq -c '[.[].variant // empty] | unique')"

# ── Derived test matrices (test.yml — supported-only) ─────────────────────────
# python_versions: map each entry's py_flavor ("pyN" + "MM") to "N.MM"
#   (py311 => 3.11, py39 => 3.9), then dedup + sort. The regex captures the
#   single major digit and the remaining minor digits, joined with a dot.
# php_versions: distinct php_version values, deduped + sorted.
# Both feed test.yml's strategy.matrix unfiltered (CE + Plus) so the pytest /
# PHP gates only ever run a version the matrix actually ships.
PYTHON_VERSIONS="$(printf '%s' "$BUILD_MATRIX" | jq -c '
  [ .[].py_flavor
    | capture("^py(?<maj>[0-9])(?<min>[0-9]+)$")
    | "\(.maj).\(.min)"
  ] | unique')"
PHP_VERSIONS="$(printf '%s' "$BUILD_MATRIX" | jq -c '[.[].php_version] | unique')"

# Fail-closed: every entry in a non-empty BUILD matrix must yield a python AND a php
# version. The py_flavor map above already aborts on a malformed flavor (jq capture()
# errors under set -e); guard the php side SYMMETRICALLY — a null/empty php_version on
# any entry must fail HERE, not slip through as a [null] matrix leg (a bare length check
# would pass [null], whose length is 1, straight into test.yml's strategy.matrix).
if [ "$(printf '%s' "$BUILD_MATRIX" | jq 'length')" -gt 0 ]; then
  if [ "$(printf '%s' "$PYTHON_VERSIONS" | jq 'length')" -eq 0 ]; then
    printf '::error::no python versions derived from py_flavor in %s (malformed py_flavor?)\n' "$MATRIX_FILE" >&2
    exit 1
  fi
  if [ "$(printf '%s' "$BUILD_MATRIX" | jq '[.[].php_version | select(. == null or . == "")] | length')" -gt 0 ]; then
    printf '::error::an entry has a missing/empty php_version in %s\n' "$MATRIX_FILE" >&2
    exit 1
  fi
fi

if [ "$DO_GITHUB_OUTPUT" -eq 1 ]; then
  if [ -z "${GITHUB_OUTPUT:-}" ]; then
    printf '::error::GITHUB_OUTPUT is not set — cannot write step outputs\n' >&2
    exit 1
  fi
  # Use heredoc delimiter to safely embed JSON (may contain special chars).
  {
    printf 'build_matrix<<__EOF_BUILD_MATRIX__\n%s\n__EOF_BUILD_MATRIX__\n' "$BUILD_MATRIX"
    printf 'ci_matrix<<__EOF_CI_MATRIX__\n%s\n__EOF_CI_MATRIX__\n' "$CI_MATRIX"
    printf 'variant<<__EOF_VARIANT__\n%s\n__EOF_VARIANT__\n' "$VARIANT_ARRAY"
    printf 'python_versions<<__EOF_PYTHON_VERSIONS__\n%s\n__EOF_PYTHON_VERSIONS__\n' "$PYTHON_VERSIONS"
    printf 'php_versions<<__EOF_PHP_VERSIONS__\n%s\n__EOF_PHP_VERSIONS__\n' "$PHP_VERSIONS"
  } >> "$GITHUB_OUTPUT"
fi

if [ "$DO_PRINT_BUILD" -eq 1 ]; then
  if [ "$DO_PRINT_CI" -eq 1 ]; then
    printf 'BUILD matrix:\n'
  fi
  printf '%s' "$BUILD_MATRIX" | jq .
fi

if [ "$DO_PRINT_CI" -eq 1 ]; then
  if [ "$DO_PRINT_BUILD" -eq 1 ]; then
    printf '\nCI matrix:\n'
  fi
  printf '%s' "$CI_MATRIX" | jq .
fi

if [ "$DO_PRINT_TEST" -eq 1 ]; then
  printf 'python_versions:\n'
  printf '%s' "$PYTHON_VERSIONS" | jq .
  printf '\nphp_versions:\n'
  printf '%s' "$PHP_VERSIONS" | jq .
fi

if [ "$DO_PRINT_ROUTE" -eq 1 ]; then
  printf '%s' "$ROUTE_MATRIX" | jq .
fi
