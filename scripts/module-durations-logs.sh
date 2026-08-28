#!/bin/sh
# module-durations-logs.sh — select ONE CE version's pytest-durations logs from
# an extracted smoke-artifacts tree, for scripts/module-durations.sh (issue
# #901; #910 review). The duration table's contract allows exactly ONE
# full-suite leg: Plus legs are excluded by the artifact prefix, and when the
# supported window holds two GA CE versions (ci-metadata `drop_ce` policy — the
# NORMAL steady state, not an edge case) the MINIMUM version is selected, the
# same min-CE convention resolve-legs.sh uses for impacted scope. Failing on a
# multi-CE window would permanently red the nightly refresh instead.
#
# Usage: module-durations-logs.sh <artifacts-dir>
#   stdout — the selected pytest-durations.log paths, one per line
#   stderr — the multi-version selection notice + loud errors
#   rc 1   — no CE logs found, or artifact naming drifted from the PREFIX shape
#
# PREFIX must stay in sync with smoke-single.yml's smoke-diagnostics artifact
# name and module-durations.yml's download `pattern:` (a with: block cannot
# share a shell variable).
set -eu

PREFIX='smoke-diagnostics-pfsense-ce-'
dir="${1:?usage: module-durations-logs.sh <artifacts-dir>}"

LOGS=$(find "$dir" -path "*/${PREFIX}*" -name pytest-durations.log | LC_ALL=C sort)
if [ -z "$LOGS" ]; then
	echo "module-durations-logs: no pytest-durations.log under ${dir} matching ${PREFIX}* — nothing to aggregate." >&2
	exit 1
fi

# Version token sits between the prefix and the shard suffix: <PREFIX><ver>-s<N>/.
# Numeric two-field sort (2.8 < 2.10, not lexical).
VERSIONS=$(printf '%s\n' "$LOGS" \
	| sed -n "s|.*/${PREFIX}\(.*\)-s[0-9][0-9]*/.*|\1|p" \
	| LC_ALL=C sort -t. -k1,1n -k2,2n -u)
if [ -z "$VERSIONS" ]; then
	echo "module-durations-logs: CE logs found but no version extracted — artifact naming drifted from ${PREFIX}<ver>-s<N>/." >&2
	exit 1
fi

MIN_VER=$(printf '%s\n' "$VERSIONS" | head -n 1)
if [ "$(printf '%s\n' "$VERSIONS" | wc -l)" -gt 1 ]; then
	echo "module-durations-logs: multiple CE versions present ($(printf '%s' "$VERSIONS" | tr '\n' ' ')) — selecting min ${MIN_VER}; the table aggregates exactly one full-suite leg." >&2
fi

printf '%s\n' "$LOGS" | grep -F "/${PREFIX}${MIN_VER}-s"
