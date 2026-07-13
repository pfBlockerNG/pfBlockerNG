#!/bin/sh
# bench_ip_recompute.sh — compare the legacy per-feed duplicate() accretion
# path against the batch `recompute` verb (issue #1084) on synthetic feed
# classes. Dev-only tooling; run from the repo root on a dev machine with a
# REAL grepcidr on PATH (brew/apt: grepcidr). Prints a table; no CI wiring.
#
# Usage: sh scripts/bench_ip_recompute.sh [workdir]
#   workdir  scratch root (default: mktemp -d); kept after the run.
#
# Scenarios (deterministic; overlap = one shared block common to all feeds,
# so overlap fraction = shared/rows; IPs are a bijective map over 10/8 —
# (i*99991) mod 2^24 with disjoint counter ranges, collision-free):
#   A  20 x 5k feeds,  1.5% overlap      B  20 x 5k feeds, 25% overlap
#   C  3 x 300k feeds, 3% overlap        D  2 x 300k + 10 x 5k, heavy overlap
#                                           (5 small feeds fully inside big01)
# Each scenario runs 3 orderings (listed / reversed / interleaved) x
# {old, new}. Sanity per run: the UNION of surviving rows must be identical
# old-vs-new (ownership may differ; membership must not). Extras: a
# single-feed-change parity run (old re-dedups ONE feed vs one full
# recompute) and a dMax-enabled recompute run on scenario D.
#
# run_old exercises duplicate(), removed by issue #1084 (commit 63ac46e8) --
# on this tree it is dead (the `duplicate` call fails). To actually run/compare
# the old arm, check out 12c2b4a2 (the commit immediately before the removal)
# for that side of the comparison; duplicate() is never resurrected here.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PFBSH="${REPO_ROOT}/src/usr/local/pkg/pfblockerng/pfblockerng.sh"
GREPCIDR="$(command -v grepcidr || true)"
[ -n "$GREPCIDR" ] || { echo "bench: real grepcidr not found on PATH" >&2; exit 1; }
# BSD time: -l, RSS in bytes; GNU time: -v, RSS in kB.
if /usr/bin/time -l true >/dev/null 2>&1; then TFLAG='-l'; DIV=1048576; else TFLAG='-v'; DIV=1024; fi

# ── deterministic generator ────────────────────────────────────────────────
gen_range() { # $1 base_counter  $2 count
	awk -v base="$1" -v n="$2" 'BEGIN {
		for (i = 0; i < n; i++) {
			v = ((base + i) * 99991) % 16777216
			printf "10.%d.%d.%d\n", int(v/65536)%256, int(v/256)%256, v%256
		}
	}'
}

scenario() { # $1 name  $2 nfeeds  $3 rows  $4 shared
	d="$WORK/data/$1"; mkdir -p "$d"
	sh_file="$d/.shared"; gen_range 0 "$4" > "$sh_file"
	own=$(( $3 - $4 )); i=1
	while [ "$i" -le "$2" ]; do
		{ awk 1 "$sh_file"; gen_range "$(( $4 + i * own ))" "$own"; } \
			| LC_ALL=C sort -u > "$d/feed$(printf %02d "$i")_v4.txt"
		i=$(( i + 1 ))
	done
	rm -f "$sh_file"
}

gen_all() {
	scenario A 20 5000   75
	scenario B 20 5000   1250
	scenario C 3  300000 9000
	d="$WORK/data/D"; mkdir -p "$d"
	gen_range 0      300000 | LC_ALL=C sort -u > "$d/big01_v4.txt"
	{ gen_range 285000 285000; head -15000 "$d/big01_v4.txt"; } \
		| LC_ALL=C sort -u > "$d/big02_v4.txt"
	i=1
	while [ "$i" -le 10 ]; do
		if [ "$i" -le 5 ]; then
			awk -v off="$(( i * 20000 ))" 'NR > off && NR <= off + 5000' \
				"$d/big01_v4.txt" | LC_ALL=C sort -u > "$d/small$(printf %02d "$i")_v4.txt"
		else
			{ awk -v off="$(( i * 17000 ))" 'NR > off && NR <= off + 3000' "$d/big02_v4.txt"
			  gen_range "$(( 700000 + i * 2000 ))" 2000; } \
				| LC_ALL=C sort -u > "$d/small$(printf %02d "$i")_v4.txt"
		fi
		i=$(( i + 1 ))
	done
}

order_files() { # $1 datadir  $2 listed|reversed|interleaved
	case "$2" in
		listed)      ls "$1"/*.txt ;;
		reversed)    ls "$1"/*.txt | sort -r ;;
		interleaved) ls "$1"/*.txt | awk '{ a[NR] = $0 } END {
		                for (i = 1; i <= NR; i += 2) print a[i]
		                for (i = 2; i <= NR; i += 2) print a[i] }' ;;
	esac
}

setup_state() { # $1 statedir
	rm -rf "$1"
	mkdir -p "$1/deny" "$1/orig" "$1/match" "$1/tmp"
	true > "$1/master"; true > "$1/mastercat"; true > "$1/err.log"
}

# old path: per-feed accretion through the sourced duplicate()
# shellcheck disable=SC1090,SC2034  # computed source path; globals consumed by the sourced functions
run_old() { # $1 statedir  $2 orderfile
	st="$1"
	PFB_SOURCED=1 . "$PFBSH"
	masterfile="$st/master"; mastercat="$st/mastercat"
	pfbdeny="$st/deny/"; pfborig="$st/orig/"; pfbmatch="$st/match/"
	tempfile="$st/tmp/t1"; tempfile2="$st/tmp/t2"
	dedupfile="$st/tmp/dd"; dupfile="$st/tmp/dup"; matchfile="$st/tmp/mf"
	tempmatchfile="$st/tmp/tmf"; errorlog="$st/err.log"
	pathgrepcidr="$GREPCIDR"; dedup='on'
	ip_placeholder='127.1.7.7'; ip_placeholder2='127.1.7.7'; ip_placeholder3='240.0.0'
	while IFS= read -r f; do
		alias="$(basename "$f" .txt)"
		cp "$f" "${pfbdeny}${alias}.txt"
		duplicate
	done < "$2"
}

# new path: one recompute pass over pristine snapshots
# shellcheck disable=SC1090,SC2034  # computed source path; globals consumed by the sourced functions
run_new() { # $1 statedir  $2 orderfile [$3 repmode $4 max $5 cc $6 ccw $7 ccb]
	st="$1"
	PFB_SOURCED=1 . "$PFBSH"
	masterfile="$st/master"; mastercat="$st/mastercat"
	pfbdeny="$st/deny/"; pfbmatch="$st/match/"; tmpdir="$st/tmp"
	errorlog="$st/err.log"; pathgrepcidr="$GREPCIDR"
	ip_placeholder3='240.0.0'
	# dMax's offender classify needs pathgeoip/pathgeoipdat DEFINED under `set -u`
	# (else "unbound variable" aborts the whole script) -- a dev box lacking
	# mmdblookup; stub it like the shellspec make_geoip_stub helper so the bench
	# exercises real classification instead of the no-GeoIP bail.
	pathgeoip="$st/mmdblookup"; pathgeoipdat="$st/geo.mmdb"
	printf '#!/bin/sh\nprintf %%s "Could not find an entry for this IP address"\n' > "$pathgeoip"
	chmod +x "$pathgeoip"; touch "$pathgeoipdat"
	pfb_recompute recompute v4 "$2" "$st/counts" on \
		"${3:-off}" "${4:-0}" "${5:-}" "${6:-off}" "${7:-off}"
}

# internal re-entry so /usr/bin/time can wrap one runner in a fresh sh
if [ "${1:-}" = '__run' ]; then
	WORK='' # unused in runner mode
	shift
	"$@"
	exit $?
fi

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/pfb-bench.XXXXXX")}"
mkdir -p "$WORK"
echo "workdir: $WORK  grepcidr: $GREPCIDR  time: $TFLAG"

measure() { # $1 label  $2... runner+args
	label="$1"; shift
	tf="$WORK/.time.$$"
	start=$(date +%s)
	/usr/bin/time "$TFLAG" sh "$0" __run "$@" > /dev/null 2> "$tf"
	end=$(date +%s)
	rss=$(awk -v d="$DIV" '/[Mm]aximum resident set size/ {
		for (i = 1; i <= NF; i++) if ($i + 0 > 0) { printf "%d", $i / d; exit } }' "$tf")
	printf '%-30s wall=%3ds  peak_rss=%sMB\n' "$label" "$(( end - start ))" "${rss:-?}"
	rm -f "$tf"
}

# data rows only: the old path's duplicate() calls emptyfiles(), which refills
# a fully-pruned feed with the placeholder IP; recompute leaves it empty and
# the production caller runs emptyfiles() itself — not a membership difference.
union_cksum() {
	# issue #1263: awk 1, not cat -- an unterminated member file must not weld into its neighbour.
	awk 1 "$1"/*.txt 2>/dev/null | grep -v '^127\.1\.7\.7$' | LC_ALL=C sort -u | cksum
}

echo "generating data..."; gen_all
for sc in A B C D; do
	for ord in listed reversed interleaved; do
		order_files "$WORK/data/$sc" "$ord" > "$WORK/order"
		setup_state "$WORK/st-old"
		measure "$sc/$ord old(duplicate)" run_old "$WORK/st-old" "$WORK/order"
		setup_state "$WORK/st-new"
		measure "$sc/$ord new(recompute)" run_new "$WORK/st-new" "$WORK/order"
		u_old="$(union_cksum "$WORK/st-old/deny")"
		u_new="$(union_cksum "$WORK/st-new/deny")"
		[ "$u_old" = "$u_new" ] || echo "  !! UNION MISMATCH ($sc/$ord)"
	done
done

# single-feed-change parity (scenario D, listed): old re-dedups ONE feed
# against the accreted masterfile; new pays one full pass.
order_files "$WORK/data/D" listed > "$WORK/order"
setup_state "$WORK/st-old"
sh "$0" __run run_old "$WORK/st-old" "$WORK/order" > /dev/null 2>&1
head -1 "$WORK/order" > "$WORK/order-one"
measure "D single-change old(1 feed)" run_old "$WORK/st-old" "$WORK/order-one"
setup_state "$WORK/st-new"
measure "D single-change new(full)" run_new "$WORK/st-new" "$WORK/order"

# Reputation runs on D. run_new's own GeoIP stub reports "not found" for every
# offender, so ccblack=block classifies + collapses for real (not the no-
# GeoIP bail). pMax needs no GeoIP; max=8 sits below D's ~9 rows-per-/24
# average, so tens of thousands of offender windows exercise the divert/
# window/reinject path for real.
setup_state "$WORK/st-new"
measure "D dmax new(recompute)" run_new "$WORK/st-new" "$WORK/order" dmax 50 '' off block
setup_state "$WORK/st-new"
measure "D pmax-heavy new(recompute)" run_new "$WORK/st-new" "$WORK/order" pmax 8 '' off block

echo "done. workdir kept at: $WORK"
