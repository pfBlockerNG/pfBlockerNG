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
# (scripts/module-durations.sh's output; override the path with the
# test-only `SHARD_DURATIONS_FILE` env var — see below) exists:
#
#   - Present -> duration-balanced greedy LPT (longest processing time
#     first), HYBRID at test granularity for oversized modules (issue #855,
#     extending #816). Each enumerated module's baseline weight is its table
#     duration; a module with no row, or a row <= 0, is clamped to a 0.01s
#     epsilon so it still adds load (this is what stops zero-weight modules
#     from piling onto one shard and leaving another falsely empty). Given
#     `target = total-weight / shard-total`, a module whose weight exceeds
#     `target` AND has per-test rows in the table (scripts/module-durations.sh
#     emits both a module-sum row and one row per test, see its header) is
#     OVERSIZED: it is split into one LPT unit per KNOWN test instead of one
#     lump unit for the whole module (same 0.01 epsilon clamp, per test). A
#     module that qualifies but has NO per-test rows (an old table predating
#     this feature) cannot be split and rides whole, same as before — and so
#     does one that DOES have per-test rows when `<test-dir>` is itself an
#     ABSOLUTE path (issue #861 nitpick): pytest's `--deselect` matches by
#     PREFIX against ROOTDIR-RELATIVE node IDs, so an absolute-path carrier
#     deselect would silently never match and the deselected test would
#     double-run. All
#     units — normal modules and oversized modules' individual tests — are
#     processed together: weight DESC, then path/nodeid ASC under `LC_ALL=C`
#     (ties), each going to the currently least-loaded shard (ties -> lowest
#     index).
#
#     For an oversized module, the shard receiving the LARGEST summed test
#     weight (ties -> lowest shard index) is its CARRIER: it gets the
#     module's PATH plus a `--deselect <nodeid>` pair for every one of that
#     module's KNOWN tests assigned to any OTHER shard. Every other shard
#     that received some of that module's tests gets plain pytest node-ID
#     lines for its own tests only. Why the path+deselect carrier and not
#     node IDs everywhere: a test added or renamed after the last table
#     regeneration has NO row, so it can never be individually assigned or
#     deselected — it rides the carrier's whole-module collection instead.
#     That keeps coverage complete UNLESS the new/renamed test's nodeid is a
#     STRICT STRING EXTENSION of a known test's id assigned OFF the carrier:
#     pytest's `--deselect` matches by PREFIX, not exact id (see below), so
#     the carrier's deselect for the shorter known id also strips the longer
#     unknown one — it then runs on NO shard, coverage is NOT complete by
#     construction for that case. A stale row for a RENAMED/REMOVED test is
#     the mirror failure: it becomes a bare nonexistent node-id arg on
#     whichever shard it lands on, and pytest exits 4 there. Both are
#     CI-blocking regressions, not hypotheticals: tests/test_shard_union.py's
#     committed-table drift gate (issue #861) checks the COMMITTED
#     tests/smoke/module-durations.txt against a live `--collect-only` pass
#     for exactly these two cases — regenerate the table
#     (scripts/module-durations.sh) whenever it fires. run-smoke.sh splices
#     this script's stdout
#     newline-split straight into pytest's argv, one line = one argv word
#     (scripts/run-smoke.sh's shard-splice step), so a `--deselect` line and
#     its node-ID value are always emitted as two ADJACENT lines, in that
#     order, never merged or reordered relative to each other.
#   - Absent -> plain round-robin: the j-th module (0-based, sorted order)
#     goes to shard `j % shard-total`. This is the fallback every table-less
#     dir rides (e.g. tests/smoke/ui/).
#
# Both modes print the selected shard's assigned lines to stdout — module
# paths (round-robin and LPT's normal/carrier units), pytest node IDs
# (LPT's non-carrier test units), and `--deselect`/node-ID pairs (LPT's
# carrier units) — deterministically ordered, one entry per line; diagnostics
# go to stderr only. `SHARD_DURATIONS_FILE` (test-only env override; unset in
# every real caller) replaces the default `<test-dir>/module-durations.txt`
# path, so a test can inject a synthetic table over a real, unmodified
# test-dir tree.
#
# Errors loudly (non-zero exit, one-line stderr message) on: wrong arg
# count; non-numeric/negative index or total; total < 1; index >= total; a
# missing or empty test-dir; or a shard-total large enough to leave the
# requested shard EMPTY — never a silent empty success. The min-weight
# epsilon guarantees this condition is identical for both modes: whenever
# module-count >= shard-total every shard gets >= 1 module (LPT's first N
# assignments land on N distinct shards, same as round-robin's); splitting
# an oversized module into more, smaller units only ever adds candidates for
# an under-full shard, never removes one.

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

# An absolute test-dir defeats pytest's --deselect (nodeid PREFIX match
# against ROOTDIR-RELATIVE ids) for the LPT hybrid split's carrier — computed
# once here; the durfile-present branch below gates oversized-module
# splitting on it (issue #861 nitpick).
case "$dir" in
	/*) dir_abs=1 ;;
	*) dir_abs=0 ;;
esac

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
durfile="${SHARD_DURATIONS_FILE:-${dir}/module-durations.txt}"

if [ -f "$durfile" ]; then
	# Reject a hostile row before it's ever parsed (issue #907, latent found
	# reviewing #861): the table reader below (stage 1's awk BEGIN block)
	# rebuilds a row's key via awk's DEFAULT field split, which COLLAPSES any
	# run of whitespace -- a nodeid containing a TAB or two-plus consecutive
	# spaces silently reconstructs to the WRONG key. That produces either a
	# never-matching `--deselect` (the test then double-runs across shards)
	# or a nonexistent bare node ID (pytest exit 4 on that shard) -- a
	# confusing downstream failure instead of a pointed one. A single space
	# is fine and expected (a parametrized nodeid's own bracket text, e.g.
	# `test_foo[hello world]`, round-trips correctly -- see the #861 table
	# reader fix); only a TAB or a run of 2+ spaces is hostile. One guard
	# here, at first read of the table, so every stage after it inherits it
	# -- checked on the RAW line, before any split collapses the evidence.
	LC_ALL=C awk '
		/^[ \t]*#/ || /^[ \t]*$/ { next }
		index($0, "\t") {
			printf "shard-modules: duration-table row has an embedded TAB, would corrupt the nodeid key: %s\n", $0 > "/dev/stderr"
			exit 1
		}
		index($0, "  ") {
			printf "shard-modules: duration-table row has consecutive spaces, would corrupt the nodeid key: %s\n", $0 > "/dev/stderr"
			exit 1
		}
	' "$durfile"

	# Hybrid duration-balanced greedy LPT (issue #855, extending #816) — see
	# the header for the full rule. Three stages:
	#
	# Stage 1 (awk): read the table once, splitting rows into module sums
	# (`dur[base]`) and per-test sums (`tw[base,n]`/`tid[base,n]`, keyed by a
	# running per-base counter — awk has no ordered multi-value map). Then,
	# for each enumerated module (fed via stdin), compute its module-level
	# weight exactly as #816 did (0.01 epsilon fallback) and accumulate the
	# true total; at END, with the total known, compute `target` and decide
	# each module's oversized status, emitting one LPT unit per module
	# (kind=module) or one per known test (kind=test) — tagged with its sort
	# key (path or nodeid), weight, module basename, module path, and (for a
	# test unit) its test id.
	#
	# Stage 2 (sort): weight DESC, sort key ASC under LC_ALL=C — the same
	# LPT processing order as #816, now over the mixed module/test units.
	# Records are "<sortkey>\t<weight>\t...", TAB-delimited so a path
	# containing a space still round-trips exactly.
	#
	# Stage 3 (awk): greedy-assign each unit, in that order, to the
	# currently least-loaded shard (ties -> lowest index) — #816's greedy
	# core, extended. A module-kind unit destined for the requested shard is
	# queued for direct output. A test-kind unit is NOT printed here —
	# bookkeeping only (summed weight + test list per (module, shard)),
	# because deciding the carrier needs every shard's assignment, known
	# only once every unit is processed. At END, per oversized module: find
	# the carrier (largest summed test weight, ties -> lowest shard index)
	# from that bookkeeping alone, BEFORE the prefix-safety fixup below.
	#
	# pytest's `--deselect` matches by NODE-ID PREFIX, not exact equality
	# (`_pytest.main.pytest_collection_modifyitems`: `colitem.nodeid.
	# startswith(deselect_prefixes)`, confirmed against a real pytest and
	# caught for real by tests/test_shard_union.py's union oracle running
	# against this repo's OWN test_smoke_feeds.py, where
	# `test_cron_detects_changed_local_feed` is a literal string-prefix of
	# the unrelated sibling `test_cron_detects_changed_local_feed_same_
	# second`). Naively deselecting the shorter test from the carrier's
	# whole-module collection would ALSO silently strip the longer sibling
	# — a real coverage hole, not a hypothetical. Fix: flatten every known
	# test of the base into one list tagged with its assigned shard, then
	# run a fixpoint pass — any test STAYING on the carrier whose id is a
	# STRICT prefix-match victim of a test going ELSEWHERE is PROMOTED onto
	# that elsewhere test's shard (repeated to a fixed point, so a 3+ level
	# prefix chain settles fully). A promoted test is no longer implicit on
	# the carrier: it becomes its own explicit node-ID line on the shard it
	# was promoted to (a bare positional node-id arg resolves by EXACT
	# nodeid, never by prefix, so that side is always safe). Carrier
	# selection is fixed before this pass, so the fixup can never flip who
	# the carrier is.
	#
	# Every record carries a 2-char group prefix ("0"=plain path,
	# "1"=deselect pair, "2"=bare node ID) plus its own sort key, so the
	# following sort groups paths first, then each deselect pair as ONE
	# still-paired record, then bare node IDs.
	#
	# Stage 4 (sort + awk): LC_ALL=C sort by group then sort key — this is
	# the ONLY sort allowed on the final shape, because a naive re-sort of
	# already-expanded `--deselect`/node-ID lines would separate a flag from
	# its value (they must stay adjacent for run-smoke.sh's argv splice).
	# The trailing awk expands each sorted record into its final output
	# line(s) — a "pair" record becomes `--deselect` then the node ID, on
	# two consecutive lines; everything else becomes its single payload
	# line — AFTER sorting, so sort only ever orders whole not-yet-expanded
	# records, never a flag separately from its value.
	tab="$(printf '\t')"
	units="$(
		printf '%s\n' "$modules" | LC_ALL=C awk -v durfile="$durfile" -v stotal="$total" -v dirabs="$dir_abs" '
			BEGIN {
				while ((getline line < durfile) > 0) {
					if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
					n = split(line, f)
					if (n < 2) continue
					# Weight is always the LAST whitespace field -- a
					# parametrized test id can itself contain a space (issue
					# #861 nitpick), so the key is fields 1..n-1 rejoined,
					# never a fixed f[1]/f[2].
					w = f[n] + 0
					key = f[1]
					for (i = 2; i < n; i++) key = key " " f[i]
					sep = index(key, "::")
					if (sep > 0) {
						base = substr(key, 1, sep - 1)
						testid = substr(key, sep + 2)
						# Per-test rows are last-wins, same as the module
						# rows below (dur[key] = w plainly overwrites) -- a
						# duplicated row must overwrite its existing slot,
						# not append a second LPT unit for the same test
						# (issue #861 nitpick: a dupe would otherwise place
						# one test on two shards, double-running it).
						if ((base, testid) in tpos) {
							cnt = tpos[base, testid]
						} else {
							cnt = ++tcount[base]
							tpos[base, testid] = cnt
							tid[base, cnt] = testid
						}
						tw[base, cnt] = w
					} else {
						dur[key] = w
					}
				}
				close(durfile)
			}
			{
				path = $0
				base = path
				sub(/^.*\//, "", base)
				w = ((base in dur) && dur[base] > 0) ? dur[base] : 0.01
				n_modules++
				mpath[n_modules] = path
				mbase[n_modules] = base
				mweight[n_modules] = w
				wsum += w
			}
			END {
				target = wsum / stotal
				for (i = 1; i <= n_modules; i++) {
					base = mbase[i]
					w = mweight[i]
					if (w > target && (base in tcount) && dirabs == 0) {
						for (t = 1; t <= tcount[base]; t++) {
							tv = (tw[base, t] > 0) ? tw[base, t] : 0.01
							nodeid = mpath[i] "::" tid[base, t]
							printf "%s\t%.6f\ttest\t%s\t%s\t%s\n", nodeid, tv, base, mpath[i], tid[base, t]
						}
					} else {
						printf "%s\t%.6f\tmodule\t%s\t%s\t%s\n", mpath[i], w, base, mpath[i], ""
					}
				}
			}
		' | LC_ALL=C sort -t "$tab" -k2,2rn -k1,1 | LC_ALL=C awk -F '\t' -v total="$total" -v want="$index" '
			BEGIN {
				for (i = 0; i < total; i++) load[i] = 0
			}
			{
				w = $2 + 0
				kind = $3
				base = $4
				modpath = $5
				testid = $6
				min_i = 0
				for (i = 1; i < total; i++) {
					if (load[i] < load[min_i]) min_i = i
				}
				load[min_i] += w
				if (kind == "module") {
					if (min_i == want) print "0\t" modpath "\tsingle\t" modpath
				} else {
					bw[base, min_i] += w
					c = ++bt_count[base, min_i]
					bt_id[base, min_i, c] = testid
					if (!(base in seen_base)) {
						seen_base[base] = 1
						base_list[++base_n] = base
					}
					base_modpath[base] = modpath
				}
			}
			END {
				for (bi = 1; bi <= base_n; bi++) {
					base = base_list[bi]
					carrier = 0
					best = ((base, 0) in bw) ? bw[base, 0] + 0 : 0
					for (s = 1; s < total; s++) {
						cur = ((base, s) in bw) ? bw[base, s] + 0 : 0
						if (cur > best) {
							best = cur
							carrier = s
						}
					}

					# Flatten every known test of this base into one
					# 1..m indexed list tagged with its currently-assigned
					# shard, so a test can be reassigned (promoted) without
					# disturbing bt_id/bt_count (shared across bases).
					m = 0
					for (s = 0; s < total; s++) {
						cnt = bt_count[base, s] + 0
						for (c = 1; c <= cnt; c++) {
							m++
							ftest[m] = bt_id[base, s, c]
							fshard[m] = s
						}
					}

					# Prefix-safety fixpoint (see the header comment above
					# this awk block): promote any carrier-staying test
					# whose id is a strict prefix of a differently-shard-
					# bound sibling id, onto that sibling shard — repeat
					# until one full pass makes no more changes.
					changed = 1
					while (changed) {
						changed = 0
						for (a = 1; a <= m; a++) {
							if (fshard[a] == carrier) continue
							for (b = 1; b <= m; b++) {
								if (fshard[b] != carrier) continue
								if (length(ftest[b]) > length(ftest[a]) && index(ftest[b], ftest[a]) == 1) {
									fshard[b] = fshard[a]
									changed = 1
								}
							}
						}
					}

					if (carrier == want) {
						print "0\t" base_modpath[base] "\tsingle\t" base_modpath[base]
						for (a = 1; a <= m; a++) {
							if (fshard[a] == carrier) continue
							nid = base_modpath[base] "::" ftest[a]
							print "1\t" nid "\tpair\t" nid
						}
					} else {
						for (a = 1; a <= m; a++) {
							if (fshard[a] != want) continue
							nid = base_modpath[base] "::" ftest[a]
							print "2\t" nid "\tsingle\t" nid
						}
					}
				}
			}
		' | LC_ALL=C sort -t "$tab" -k1,1 -k2,2 | LC_ALL=C awk -F '\t' '{
			if ($3 == "pair") {
				print "--deselect"
				print $4
			} else {
				print $4
			}
		}'
	)"
	selected_any=0
	if [ -n "$units" ]; then
		selected_any=1
		printf '%s\n' "$units"
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
