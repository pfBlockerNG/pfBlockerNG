#!/bin/sh
# bench_aggregate_union.sh — dev-only benchmark: cost of unioning pfBlockerNG's
# Deny set into the aggregate ("Uber") alias (cat -> sort -u -> cidr_aggregate()
# /iprange): wall-time, peak RSS, dedup ratio. Uses the real `iprange` when
# present; else a Python ipaddress.collapse_addresses stand-in — ratio-faithful
# but its wall-clock is a dev-box proxy only (live iprange timing needs a
# maintainer run on real hardware). Synthetic data; not part of the release
# archive (only src/ ships).
#
# Usage: scripts/misc/bench_aggregate_union.sh [v4_cidrs=2000000] [v6_cidrs=500000] [members=30]

set -eu

# --- privileged/add-on binaries: absolute paths (pfSense convention) ----------
pathaggregate='/usr/local/bin/iprange'   # the production cidr_aggregate() binary

# --- args ---------------------------------------------------------------------
v4_total="${1:-2000000}"
v6_total="${2:-500000}"
members="${3:-30}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/pfb_adr11_bench.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT INT TERM

memberdir="${workdir}/members"
mkdir -p "${memberdir}"

# --- pick the aggregation primitive ------------------------------------------
if [ -x "${pathaggregate}" ]; then
	agg_mode='iprange (production binary — LIVE-equivalent timing)'
	use_iprange=1
else
	agg_mode='Python ipaddress.collapse_addresses (dev-box stand-in — RATIO faithful, TIME is a proxy)'
	use_iprange=0
fi

# --- a portable wall-time + peak-RSS wrapper ---------------------------------
# macOS:  /usr/bin/time -l  -> "... maximum resident set size" (bytes)
# GNU:    /usr/bin/time -v  -> "Maximum resident set size (kbytes): ..."
# Falls back to plain timing if neither flavour is available.
time_log="${workdir}/time.log"
run_timed() {
	# $@ = command to run; appends a 'WALL <s>' and 'MAXRSS_BYTES <n>' line to time_log.
	_start="$(python3 -c 'import time; print(time.time())')"
	if /usr/bin/time -l true >/dev/null 2>&1; then
		/usr/bin/time -l "$@" 2>"${workdir}/t.err" >/dev/null || { cat "${workdir}/t.err" >&2; return 1; }
		_rss="$(awk '/maximum resident set size/ {print $1; exit}' "${workdir}/t.err")"
		# macOS reports bytes already.
	elif /usr/bin/time -v true >/dev/null 2>&1; then
		/usr/bin/time -v "$@" 2>"${workdir}/t.err" >/dev/null || { cat "${workdir}/t.err" >&2; return 1; }
		_kb="$(awk -F': ' '/Maximum resident set size/ {print $2; exit}' "${workdir}/t.err")"
		_rss="$((_kb * 1024))"
	else
		"$@" >/dev/null || return 1
		_rss=''
	fi
	_end="$(python3 -c 'import time; print(time.time())')"
	_wall="$(python3 -c "print(f'{${_end} - ${_start}:.2f}')")"
	printf 'WALL %s\n' "${_wall}" >> "${time_log}"
	printf 'MAXRSS_BYTES %s\n' "${_rss:-NA}" >> "${time_log}"
}

human_bytes() {
	python3 -c "
b = ${1:-0}
for u in ('B','KiB','MiB','GiB','TiB'):
    if b < 1024 or u == 'TiB':
        print(f'{b:.1f} {u}'); break
    b /= 1024
"
}

# --- 1. synthesize representative member files -------------------------------
echo "ADR-11 aggregate-union cost benchmark"
echo "================================================"
echo "host          : $(uname -s -m -r)"
echo "agg primitive : ${agg_mode}"
echo "target scale  : ${v4_total} IPv4 + ${v6_total} IPv6 CIDRs across ${members} member files"
echo
echo "[1/4] synthesizing member files ..."

python3 - "${memberdir}" "${v4_total}" "${v6_total}" "${members}" <<'PY'
import ipaddress, random, sys, os

memberdir, v4_total, v6_total, members = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
random.seed(1108)  # deterministic: ADR-11

fhs = [open(os.path.join(memberdir, f"deny_{i:03d}.txt"), "w") for i in range(members)]

def emit(line):
    random.choice(fhs).write(line + "\n")

# IPv4: random /24..../32 with deliberate overlap + exact dups so sort -u and
# the aggregate have real collapsing to do (mirrors overlapping real feeds).
n = 0
while n < v4_total:
    base = random.getrandbits(32) & 0xFFFFFF00          # /24-aligned
    pl = random.choice((24, 24, 25, 26, 32))            # mix; many /24 -> heavy collapse
    net = ipaddress.IPv4Network((base, pl), strict=False)
    emit(net.with_prefixlen)
    n += 1
    # ~12% of the time also emit an adjacent or duplicate line (cross-member overlap)
    if n < v4_total and random.random() < 0.12:
        emit(net.with_prefixlen if random.random() < 0.5
             else ipaddress.IPv4Network((base + 256, pl), strict=False).with_prefixlen)
        n += 1

# IPv6: random /48../128 under 2001:db8::/32-ish space, same overlap injection.
m = 0
while m < v6_total:
    hi = (0x2001 << 112) | (random.getrandbits(80) << 32)
    pl = random.choice((48, 48, 56, 64, 128))
    net = ipaddress.IPv6Network((hi, pl), strict=False)
    emit(net.with_prefixlen)
    m += 1
    if m < v6_total and random.random() < 0.12:
        emit(net.with_prefixlen)
        m += 1

for fh in fhs:
    fh.close()
print(f"      wrote {members} member files, {n} IPv4 + {m} IPv6 lines")
PY

input_count="$(cat "${memberdir}"/deny_*.txt | grep -c ^)"
echo "      total input lines (with duplicates/overlap): ${input_count}"
echo

# --- 2. union: cat -> sort -u (the dedup half) -------------------------------
echo "[2/4] cat members -> sort -u ..."
union_sorted="${workdir}/union.sorted"
# `sort` is a base utility (bare per CLAUDE.md shell rules).
run_timed sh -c "cat \"${memberdir}\"/deny_*.txt | LC_ALL=C sort -u > \"${union_sorted}\""
sortu_wall="$(awk '/^WALL/{w=$2} END{print w}' "${time_log}")"
sortu_rss="$(awk '/^MAXRSS_BYTES/{r=$2} END{print r}' "${time_log}")"
sortu_count="$(grep -c ^ "${union_sorted}")"
echo "      after sort -u : ${sortu_count} unique lines  (wall ${sortu_wall}s, peak RSS $(human_bytes "${sortu_rss}"))"
echo

# --- 3. aggregate: collapse overlapping/adjacent CIDRs -----------------------
echo "[3/4] aggregate (cidr_aggregate primitive) ..."
union_agg="${workdir}/union.agg"
true > "${time_log}"   # reset timing capture for this step
if [ "${use_iprange}" -eq 1 ]; then
	# iprange handles mixed input but is family-agnostic; pfBlockerNG calls it
	# per-family. We split, aggregate each, recombine — matching production.
	grep -F ':' "${union_sorted}" > "${workdir}/u6.txt" || true
	grep -Fv ':' "${union_sorted}" > "${workdir}/u4.txt" || true
	run_timed sh -c "\"${pathaggregate}\" \"${workdir}/u4.txt\" > \"${workdir}/a4.txt\"; \"${pathaggregate}\" \"${workdir}/u6.txt\" > \"${workdir}/a6.txt\"; cat \"${workdir}/a4.txt\" \"${workdir}/a6.txt\" > \"${union_agg}\""
else
	# Portable stand-in: identical collapse semantics via ipaddress.
	run_timed python3 - "${union_sorted}" "${union_agg}" <<'PY'
import ipaddress, sys
src, dst = sys.argv[1], sys.argv[2]
v4, v6 = [], []
with open(src) as fh:
    for line in fh:
        s = line.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        (v6 if net.version == 6 else v4).append(net)
with open(dst, "w") as out:
    for net in ipaddress.collapse_addresses(v4):
        out.write(net.with_prefixlen + "\n")
    for net in ipaddress.collapse_addresses(v6):
        out.write(net.with_prefixlen + "\n")
PY
fi
agg_wall="$(awk '/^WALL/{w=$2} END{print w}' "${time_log}")"
agg_rss="$(awk '/^MAXRSS_BYTES/{r=$2} END{print r}' "${time_log}")"
agg_count="$(grep -c ^ "${union_agg}")"
echo "      after aggregate : ${agg_count} CIDRs  (wall ${agg_wall}s, peak RSS $(human_bytes "${agg_rss}"))"
echo

# --- 4. report ----------------------------------------------------------------
echo "[4/4] summary"
echo "------------------------------------------------------------------"
printf '  %-34s %s\n' 'input lines (raw union)'      "${input_count}"
printf '  %-34s %s\n' 'after sort -u (unique)'       "${sortu_count}"
printf '  %-34s %s\n' 'after aggregate (final CIDRs)' "${agg_count}"
python3 -c "
inp, su, ag = ${input_count}, ${sortu_count}, ${agg_count}
print(f'  {\"dedup ratio (raw->unique)\":<34} {inp/su:.3f}x  ({100*(1-su/inp):.1f}% removed)' if su else '')
print(f'  {\"aggregate ratio (unique->final)\":<34} {su/ag:.3f}x  ({100*(1-ag/su):.1f}% collapsed)' if ag else '')
print(f'  {\"overall ratio (raw->final)\":<34} {inp/ag:.3f}x  ({100*(1-ag/inp):.1f}% removed)' if ag else '')
"
echo "------------------------------------------------------------------"
printf '  %-34s %s\n' 'sort -u   wall / peak RSS' "${sortu_wall}s / $(human_bytes "${sortu_rss}")"
printf '  %-34s %s\n' 'aggregate wall / peak RSS' "${agg_wall}s / $(human_bytes "${agg_rss}")"
python3 -c "print(f'  {\"union total wall (sort -u + agg)\":<34} {${sortu_wall} + ${agg_wall}:.2f}s')"
echo "------------------------------------------------------------------"
echo
echo "NOTE: when the agg primitive is the Python stand-in, the aggregate WALL"
echo "is a dev-box proxy; the live /usr/local/bin/iprange timing is a"
echo "maintainer-run slot. The ratios + counts are collapse-faithful regardless."
