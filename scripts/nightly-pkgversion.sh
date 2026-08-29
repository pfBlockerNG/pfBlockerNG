#!/bin/sh
# shellcheck shell=sh
# nightly-pkgversion.sh — YYYYMMDDHHMMSS.<7-character source SHA> (issue #2754).
#
# nightly.yml, smoke-single.yml, and smoke-on-box.sh call this same helper so a
# local nightly smoke cannot silently build a different pkgversion than CI.
#
# Usage:
#   nightly-pkgversion.sh <source-sha>
# Prints one line to stdout. <source-sha> is a hex git object name, at least 7
# characters; the helper lowercases and takes the first 7.

set -eu

if [ "$#" -ne 1 ]; then
    printf 'nightly-pkgversion: usage: nightly-pkgversion.sh <source-sha>\n' >&2
    exit 2
fi
_sha=$1
case "$_sha" in
    *[!0-9a-fA-F]* | "")
        printf 'nightly-pkgversion: source sha must be hex\n' >&2
        exit 2
        ;;
esac
if [ "${#_sha}" -lt 7 ]; then
    printf 'nightly-pkgversion: source sha too short\n' >&2
    exit 2
fi
_short=$(printf '%.7s' "$_sha" | tr 'A-F' 'a-f')
printf '%s.%s\n' "$(date -u +%Y%m%d%H%M%S)" "$_short"
