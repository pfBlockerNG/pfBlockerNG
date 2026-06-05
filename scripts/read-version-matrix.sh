#!/bin/sh
# read-version-matrix.sh — read supported-versions.json from the ci-metadata
# orphan ref and emit the BUILD matrix and CI matrix as JSON.
#
# Usage:
#   read-version-matrix.sh [--ref <git-ref>] [--file <path>] [--github-output]
#                          [--print-build | --print-ci | --print-all]
#
# Options:
#   --ref <git-ref>      Git ref to read from (default: origin/ci-metadata).
#                        Must be reachable in the current git repo.
#   --file <path>        Matrix file path on the ref
#                        (default: supported-versions.json).
#   --github-output      Write build_matrix and ci_matrix to $GITHUB_OUTPUT
#                        (GitHub Actions step outputs format).
#   --print-build        Print BUILD matrix JSON to stdout.
#   --print-ci           Print CI matrix JSON to stdout.
#   --print-all          Print both matrices to stdout (labelled).
#
# Outputs:
#   BUILD matrix — all entries from supported-versions.json, each carrying:
#     pfsense_version, channel, freebsd_version, freebsd_major,
#     php_version, py_flavor, status, ci
#   CI matrix    — the ci:true CE entries only (subset of BUILD matrix).
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

# ── Argument parsing ───────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --ref)       MATRIX_REF="$2";  shift 2 ;;
    --file)      MATRIX_FILE="$2"; shift 2 ;;
    --github-output) DO_GITHUB_OUTPUT=1; shift ;;
    --print-build)   DO_PRINT_BUILD=1;   shift ;;
    --print-ci)      DO_PRINT_CI=1;      shift ;;
    --print-all)     DO_PRINT_BUILD=1; DO_PRINT_CI=1; shift ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

# Default: print both when running standalone with no print flags and no GH output.
if [ "$DO_GITHUB_OUTPUT" -eq 0 ] && [ "$DO_PRINT_BUILD" -eq 0 ] && [ "$DO_PRINT_CI" -eq 0 ]; then
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

# ── Build matrix: all entries ──────────────────────────────────────────────────
BUILD_MATRIX="$(printf '%s' "$RAW_JSON" | jq -c '.versions')"

# ── CI matrix: ci:true CE entries only ────────────────────────────────────────
CI_MATRIX="$(printf '%s' "$RAW_JSON" | jq -c '[.versions[] | select(.ci == true and .channel == "CE")]')"

# ── Sanity: CI matrix must not be empty ───────────────────────────────────────
CI_COUNT="$(printf '%s' "$CI_MATRIX" | jq 'length')"
if [ "$CI_COUNT" -eq 0 ]; then
  printf '::error::CI matrix is empty — no ci:true CE entries in %s\n' "$MATRIX_FILE" >&2
  exit 1
fi

# ── Emit ──────────────────────────────────────────────────────────────────────
if [ "$DO_GITHUB_OUTPUT" -eq 1 ]; then
  if [ -z "${GITHUB_OUTPUT:-}" ]; then
    printf '::error::GITHUB_OUTPUT is not set — cannot write step outputs\n' >&2
    exit 1
  fi
  # Use heredoc delimiter to safely embed JSON (may contain special chars).
  {
    printf 'build_matrix<<__EOF_BUILD_MATRIX__\n%s\n__EOF_BUILD_MATRIX__\n' "$BUILD_MATRIX"
    printf 'ci_matrix<<__EOF_CI_MATRIX__\n%s\n__EOF_CI_MATRIX__\n' "$CI_MATRIX"
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
