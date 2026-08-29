#!/bin/sh
# portrevision-rebuild.sh — compute the next PORTREVISION for a same-version rebuild.
#
# Usage: portrevision-rebuild.sh <old_portversion> <old_portrevision> <new_portversion>
#
# Prints the new PORTREVISION integer to stdout:
#   - same PORTVERSION  → old_portrevision + 1  (rebuild bump)
#   - different PORTVERSION → 0                  (version change; reset revision)
#
# old_portrevision may be empty or absent (treated as 0).
# On argument error, prints a message to stderr and exits 2.

set -eu

if [ "$#" -ne 3 ]; then
    printf 'usage: %s <old_portversion> <old_portrevision> <new_portversion>\n' \
        "${0##*/}" >&2
    exit 2
fi

old_portversion="$1"
old_portrevision="$2"
new_portversion="$3"

# Treat blank/absent revision as 0.
case "${old_portrevision}" in
    ''|*[!0-9]*)
        old_portrevision=0
        ;;
esac

if [ "${new_portversion}" = "${old_portversion}" ]; then
    # Same PORTVERSION — this is a rebuild; bump PORTREVISION.
    printf '%d\n' "$((old_portrevision + 1))"
else
    # PORTVERSION changed — reset PORTREVISION.
    printf '0\n'
fi
