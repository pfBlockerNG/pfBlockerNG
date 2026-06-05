#!/bin/sh
# aws_region_prefixes.sh - shared implementation for the per-region AWS IP-prefix
# pre-scripts (ip_pre_AWS_*.sh). Each region script is a thin wrapper that calls
# this with its jq region filter, so the parse/aggregate logic lives in ONE place
# (fix it once, not 25 times). Copyright (c) 2015-2024 BBcan177@gmail.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Args:
#   $1  alias  - the downloaded AWS ip-ranges.json; OVERWRITTEN in place with the
#                extracted prefixes (only on success).
#   $2  prefix - '_v4' (IPv4, aggregated via iprange) or '_v6' (IPv6, no iprange).
#   $3  region - region-prefix filter for jq startswith() (e.g. 'af-'); empty = all.

alias="${1}"
prefix="${2}"
region="${3}"

if [ -z "${alias}" ] || [ ! -f "${alias}" ]; then
	echo "AWS pre-script: input file not found: ${alias}"
	exit 1
fi

rawfile="$(mktemp "${TMPDIR:-/tmp}/pfbtemp0.XXXXXXXX")" || exit 1
tempfile="$(mktemp "${TMPDIR:-/tmp}/pfbtemp1.XXXXXXXX")" || { rm -f "${rawfile}"; exit 1; }

# Select the v4/v6 JSON array + field, with an optional per-region filter.
if [ "${prefix}" = '_v4' ]; then
	jqarray='.prefixes[]'
	jqvalue='.ip_prefix'
else
	jqarray='.ipv6_prefixes[]'
	jqvalue='.ipv6_prefix'
fi

if [ -n "${region}" ]; then
	jqfilter="${jqarray} | select(.region | startswith(\"${region}\")) ${jqvalue}"
else
	jqfilter="${jqarray} ${jqvalue}"
fi

# Extract first and CHECK jq's exit status. The previous `jq ... | iprange`
# pipeline hid a jq failure (POSIX sh has no pipefail): a malformed/truncated
# download could emit a partial set that iprange happily passed through, silently
# overwriting the alias with bad data. Parse to a temp, verify, THEN publish.
if ! jq -r "${jqfilter}" "${alias}" > "${rawfile}"; then
	echo "AWS pre-script: jq failed to parse ${alias}"
	rm -f "${rawfile}" "${tempfile}"
	exit 1
fi

if [ "${prefix}" = '_v4' ]; then
	# iprange aggregates the IPv4 CIDRs (reads stdin, as the original pipeline did).
	if ! iprange < "${rawfile}" > "${tempfile}"; then
		echo "AWS pre-script: iprange aggregation failed"
		rm -f "${rawfile}" "${tempfile}"
		exit 1
	fi
else
	mv -f "${rawfile}" "${tempfile}"
fi
rm -f "${rawfile}"

if [ -s "${tempfile}" ]; then
	mv -f "${tempfile}" "${alias}"
else
	# No prefixes matched: leave the original file untouched (as before), but
	# report failure via the exit code (the old script exited 0 on this path).
	rm -f "${tempfile}"
	echo "AWS pre-script: no prefixes matched (region='${region:-ALL}', proto='${prefix}')"
	exit 1
fi
