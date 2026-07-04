#!/bin/sh
# scripts/shard-modules.sh — deterministic round-robin module splitter (issue
# #797). Splits a test dir's direct-child `test_*.py` modules into N shards
# so the live-VM smoke suite can fan out at MODULE granularity across CI
# legs / local boxes, each getting its own VM boot.
#
# Usage: shard-modules.sh <test-dir> <shard-index> <shard-total>
#   <shard-index>  0-based
#   <shard-total>  >= 1
#
# Enumerates ONLY direct children `<test-dir>/test_*.py` — a glob never
# recurses, so a subdirectory like tests/smoke/ui/ is never picked up (same
# exclusion idea as impacted-tests.sh; the UI tier is sharded as a unit, not
# split by this script). The list is sorted under `LC_ALL=C` for
# locale-independent determinism (ADR-26), then the j-th module (0-based,
# sorted order) is assigned to shard `j % shard-total`. Prints the selected
# shard's module paths, one per line, to stdout; diagnostics go to stderr
# only.
#
# Errors loudly (non-zero exit, one-line stderr message) on: wrong arg
# count; non-numeric/negative index or total; total < 1; index >= total; a
# missing or empty test-dir; or a shard-total large enough to leave the
# requested shard EMPTY — never a silent empty success.

set -eu

usage() {
	printf 'usage: shard-modules.sh <test-dir> <shard-index> <shard-total>\n' >&2
	exit 1
}

[ "$#" -eq 3 ] || usage

dir="$1"
index="$2"
total="$3"

is_uint() {
	case "$1" in
		'' | *[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}

is_uint "$index" || {
	printf 'shard-modules: shard-index must be a non-negative integer: %s\n' "$index" >&2
	exit 1
}
is_uint "$total" || {
	printf 'shard-modules: shard-total must be a non-negative integer: %s\n' "$total" >&2
	exit 1
}

[ "$total" -ge 1 ] || {
	printf 'shard-modules: shard-total must be >= 1: %s\n' "$total" >&2
	exit 1
}
[ "$index" -lt "$total" ] || {
	printf 'shard-modules: shard-index (%s) must be < shard-total (%s)\n' "$index" "$total" >&2
	exit 1
}

[ -d "$dir" ] || {
	printf 'shard-modules: test-dir not found: %s\n' "$dir" >&2
	exit 1
}
dir="${dir%/}"

# Direct children only: the glob never descends into a subdirectory such as
# ui/. An unmatched glob stays literal in POSIX sh, hence the -e check below.
set -- "${dir}"/test_*.py
if [ ! -e "$1" ]; then
	printf 'shard-modules: no test_*.py modules found in %s\n' "$dir" >&2
	exit 1
fi
modules="$(printf '%s\n' "$@" | LC_ALL=C sort)"

# Re-split the sorted, newline-joined list back into positional params.
# Module paths are plain ASCII (test-dir + `test_*.py`), so splitting on
# newline only is exact; -f guards against any accidental re-glob.
oldifs="$IFS"
IFS='
'
set -f
# shellcheck disable=SC2086  # intentional: re-split the sorted newline list
set -- $modules
set +f
IFS="$oldifs"

module_count="$#"
j=0
selected_any=0
for module in "$@"; do
	if [ "$((j % total))" -eq "$index" ]; then
		printf '%s\n' "$module"
		selected_any=1
	fi
	j=$((j + 1))
done

[ "$selected_any" -eq 1 ] || {
	printf 'shard-modules: shard %s of %s is empty (only %s module(s) found)\n' \
		"$index" "$total" "$module_count" >&2
	exit 1
}
