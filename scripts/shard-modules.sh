#!/bin/sh
# scripts/shard-modules.sh — module splitter for the live-VM smoke suite
# (issue #797), now duration-balanced (issue #816). Splits a test dir's
# direct-child `test_*.py` modules into N shards so the suite can fan out at
# MODULE granularity across CI legs / local boxes, each getting its own VM
# boot.
#
# Usage: shard-modules.sh <test-dir> <shard-index> <shard-total>
#   <shard-index>  0-based
#   <shard-total>  >= 1
#
# Enumerates ONLY direct children `<test-dir>/test_*.py` — a glob never
# recurses, so a subdirectory like tests/smoke/ui/ is never picked up (same
# exclusion idea as impacted-tests.sh; the UI tier is sharded as a unit, not
# split by this script). The list is sorted under `LC_ALL=C` for
# locale-independent determinism (ADR-26).
#
# Two assignment modes, chosen by whether `<test-dir>/module-durations.txt`
# (scripts/module-durations.sh's output) exists:
#
#   - Present -> duration-balanced greedy LPT (longest processing time
#     first). Each enumerated module's weight is its table duration; a
#     module with no row, or a row <= 0, is clamped to a 0.01s epsilon so it
#     still adds load (this is what stops zero-weight modules from piling
#     onto one shard and leaving another falsely empty). Modules are
#     processed weight DESC, then path ASC under `LC_ALL=C` (ties), each
#     going to the currently least-loaded shard (ties -> lowest index).
#   - Absent -> plain round-robin: the j-th module (0-based, sorted order)
#     goes to shard `j % shard-total`. This is the fallback every table-less
#     dir rides (e.g. tests/smoke/ui/).
#
# Both modes print the selected shard's module paths, one per line, sorted
# `LC_ALL=C` by path, to stdout; diagnostics go to stderr only.
#
# Errors loudly (non-zero exit, one-line stderr message) on: wrong arg
# count; non-numeric/negative index or total; total < 1; index >= total; a
# missing or empty test-dir; or a shard-total large enough to leave the
# requested shard EMPTY — never a silent empty success. The min-weight
# epsilon guarantees this condition is identical for both modes: whenever
# module-count >= shard-total every shard gets >= 1 module (LPT's first N
# assignments land on N distinct shards, same as round-robin's).

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
durfile="${dir}/module-durations.txt"

if [ -f "$durfile" ]; then
	# Duration-balanced greedy LPT (issue #816). Pass 1 (awk): weight each
	# enumerated module from the table by BASENAME (a stale/foreign row is
	# simply never looked up), clamped to a 0.01 floor. Pass 2 (sort): order
	# weight DESC then path ASC under LC_ALL=C -- the LPT processing order.
	# Pass 3 (awk): greedy-assign each module, in that order, to the
	# currently least-loaded shard (ties -> lowest index), printing only
	# the requested shard's paths. Module paths are plain ASCII with no
	# embedded spaces (test-dir + `test_*.py`), so plain whitespace-split
	# "<weight> <path>" records are exact -- no delimiter escaping needed.
	assigned="$(
		printf '%s\n' "$modules" | awk -v durfile="$durfile" '
			BEGIN {
				while ((getline line < durfile) > 0) {
					if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
					n = split(line, f)
					if (n >= 2) dur[f[1]] = f[2] + 0
				}
				close(durfile)
			}
			{
				path = $0
				base = path
				sub(/^.*\//, "", base)
				w = ((base in dur) && dur[base] > 0) ? dur[base] : 0.01
				printf "%.6f %s\n", w, path
			}
		' | LC_ALL=C sort -k1,1rn -k2,2 | awk -v total="$total" -v want="$index" '
			BEGIN {
				for (i = 0; i < total; i++) load[i] = 0
			}
			{
				w = $1 + 0
				path = $2
				min_i = 0
				for (i = 1; i < total; i++) {
					if (load[i] < load[min_i]) min_i = i
				}
				load[min_i] += w
				if (min_i == want) print path
			}
		'
	)"
	selected_any=0
	if [ -n "$assigned" ]; then
		selected_any=1
		printf '%s\n' "$assigned" | LC_ALL=C sort
	fi
else
	j=0
	selected_any=0
	for module in "$@"; do
		if [ "$((j % total))" -eq "$index" ]; then
			printf '%s\n' "$module"
			selected_any=1
		fi
		j=$((j + 1))
	done
fi

[ "$selected_any" -eq 1 ] || {
	printf 'shard-modules: shard %s of %s is empty (only %s module(s) found)\n' \
		"$index" "$total" "$module_count" >&2
	exit 1
}
