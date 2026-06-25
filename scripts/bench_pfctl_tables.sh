#!/bin/sh
# bench_pfctl_tables.sh — ADR-40 Phase 2: pfctl table benchmark harness (guest side).
#
# Runs ON the pfSense guest (as root, via SSH from the pytest harness).
# Outputs: key=val lines to stdout; progress/diagnostics to stderr.
#
# Measures:
#   (a) pfctl -T replace wall-time at 10k / 100k / 1M entries.
#   (b) Chunked -T add + -T delete delta at multiple batch sizes x churn levels.
#       Batch sizes: giant (single op), 1, 64, 256, 1024, 4096.
#   (c) LC_ALL=C sort -u recompute cost (pfb_canonical_alias_set proxy).
#
# The DATA-PLANE stall is the PRIMARY signal; it is measured by the Python
# test harness running ICMP (ping) probes on civm WHILE THIS SCRIPT RUNS.
# This script emits epoch_start / epoch_end so the Python side can correlate
# the probe window with each op.
#
# SECONDARY (control-plane) signal: concurrent pfctl -T show latency, measured
# here as a proxy for the rules write-lock hold time.
#
# Usage (each sub-command is called by the Python driver):
#   bench_pfctl_tables.sh system_info
#   bench_pfctl_tables.sh raise_limits [MAX]
#   bench_pfctl_tables.sh gen N
#   bench_pfctl_tables.sh replace N
#   bench_pfctl_tables.sh delta N CHURN BATCH  (BATCH=0 = single-giant-op)
#   bench_pfctl_tables.sh recompute N
#   bench_pfctl_tables.sh cleanup
#
# Dependencies (stock pfSense): /sbin/pfctl, awk, LC_ALL=C sort, perl (Time::HiRes).

set -eu

PFCTL=/sbin/pfctl
PERL=/usr/local/bin/perl
TMP=/tmp/pfb_bench
TABLE=pfb_bench_main

mkdir -p "${TMP}"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

# Millisecond wall-clock via perl (FreeBSD date lacks %N).
now_ms() {
    "${PERL}" -MTime::HiRes=time -e 'printf "%d\n", time()*1000'
}

# Unix epoch with 3 decimal places (for cross-VM probe correlation).
now_epoch() {
    "${PERL}" -MTime::HiRes=time -e 'printf "%.3f\n", time()'
}

# p50/p99/max/n from a file of integers, one per line.
# Emits one key=val per line with optional PREFIX (e.g. "ctrl_").
pctls_from_file() {
    _pf_file="$1"
    _pf_prefix="${2:-}"
    if [ ! -s "${_pf_file}" ]; then
        printf '%sp50=0\n%sp99=0\n%smax=0\n%sn=0\n' \
            "${_pf_prefix}" "${_pf_prefix}" "${_pf_prefix}" "${_pf_prefix}"
        return
    fi
    LC_ALL=C sort -n "${_pf_file}" | awk -v pfx="${_pf_prefix}" '
        { a[NR] = $1 }
        END {
            n = NR
            if (n == 0) {
                printf "%sp50=0\n%sp99=0\n%smax=0\n%sn=0\n", pfx, pfx, pfx, pfx; exit
            }
            i50 = int(n * 0.50) + 1; if (i50 > n) i50 = n
            i99 = int(n * 0.99) + 1; if (i99 > n) i99 = n
            printf "%sp50=%d\n%sp99=%d\n%smax=%d\n%sn=%d\n", pfx, a[i50], pfx, a[i99], pfx, a[n], pfx, n
        }'
}

# --------------------------------------------------------------------------- #
# Control-plane probe (background pfctl -T show loop).
# Runs as a background shell; emits a latency per iteration to CTRL_PROBE_OUT.
# --------------------------------------------------------------------------- #
CTRL_PROBE_OUT="${TMP}/ctrl_probe.txt"
CTRL_PROBE_PID=""

start_ctrl_probe() {
    : > "${CTRL_PROBE_OUT}"
    touch "${TMP}/ctrl_probe_run"
    (
        while [ -f "${TMP}/ctrl_probe_run" ]; do
            _t0=$(now_ms)
            "${PFCTL}" -t "${TABLE}" -T show >/dev/null 2>&1 || true
            _t1=$(now_ms)
            echo $(( _t1 - _t0 )) >> "${CTRL_PROBE_OUT}"
        done
    ) &
    CTRL_PROBE_PID=$!
}

stop_ctrl_probe() {
    rm -f "${TMP}/ctrl_probe_run"
    if [ -n "${CTRL_PROBE_PID}" ]; then
        wait "${CTRL_PROBE_PID}" 2>/dev/null || true
    fi
    CTRL_PROBE_PID=""
}

# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #

do_system_info() {
    printf 'hostname=%s\n' "$(hostname)"
    printf 'date=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'ram_mib=%s\n' "$(sysctl -n hw.physmem | awk '{printf "%.0f", $1/1048576}')"
    printf 'ncpu=%s\n' "$(sysctl -n hw.ncpu)"
    _tl=$("${PFCTL}" -sm 2>/dev/null | awk '/table-entries/{print $NF}' || echo unknown)
    printf 'pf_table_limit=%s\n' "${_tl}"
    printf 'net_pf_request_maxcount=%s\n' "$(sysctl -n net.pf.request_maxcount 2>/dev/null || echo unknown)"
}

do_raise_limits() {
    _limit="${1:-10000000}"
    sysctl "net.pf.request_maxcount=${_limit}" >/dev/null 2>&1 || true
    printf 'set limit table-entries %s\n' "${_limit}" | "${PFCTL}" -mf - 2>/dev/null || true
    printf 'raised_limit=%s\n' "${_limit}"
    _tl=$("${PFCTL}" -sm 2>/dev/null | awk '/table-entries/{print $NF}' || echo unknown)
    printf 'pf_table_limit=%s\n' "${_tl}"
    printf 'net_pf_request_maxcount=%s\n' "$(sysctl -n net.pf.request_maxcount 2>/dev/null || echo unknown)"
}

# Generate N unique synthetic IPv4s into /tmp/pfb_bench/table_N.txt.
# RFC 5737 first (192.0.2/198.51.100/203.0.113), then 10.x.y.z.  Idempotent.
do_gen() {
    _n="$1"
    _out="${TMP}/table_${_n}.txt"
    if [ -f "${_out}" ]; then
        printf 'cached=%s\n' "${_out}"
        return
    fi
    awk -v n="${_n}" 'BEGIN {
        c = 0
        for (x = 1; x <= 254 && c < n; x++) { print "192.0.2."    x; c++ }
        for (x = 1; x <= 254 && c < n; x++) { print "198.51.100." x; c++ }
        for (x = 1; x <= 254 && c < n; x++) { print "203.0.113."  x; c++ }
        for (a = 0; a <= 255 && c < n; a++)
            for (b = 0; b <= 255 && c < n; b++)
                for (z = 1; z <= 254 && c < n; z++) { print "10." a "." b "." z; c++ }
    }' > "${_out}"
    printf 'generated=%s count=%d\n' "${_out}" "${_n}"
}

# (a) Benchmark -T replace.
# Emits: op=replace size=N wall_ms=W epoch_start=S epoch_end=E loaded=L [error=...]
#        ctrl_p50=P ctrl_p99=P ctrl_max=P ctrl_n=N
do_replace() {
    _n="$1"
    _file="${TMP}/table_${_n}.txt"
    [ -f "${_file}" ] || { printf 'error=table_%d_not_generated\n' "${_n}"; return 1; }

    # Prime the table so the control probe has something to look up.
    "${PFCTL}" -t "${TABLE}" -T replace -f "${_file}" >/dev/null 2>&1 || true

    start_ctrl_probe
    _epoch_start=$(now_epoch)
    _t0=$(now_ms)
    _err=$("${PFCTL}" -t "${TABLE}" -T replace -f "${_file}" 2>&1) || true
    _t1=$(now_ms)
    _epoch_end=$(now_epoch)
    stop_ctrl_probe

    _wall_ms=$(( _t1 - _t0 ))
    _loaded=$("${PFCTL}" -t "${TABLE}" -T show 2>/dev/null | grep -c . || echo 0)

    printf 'op=replace size=%d wall_ms=%d epoch_start=%s epoch_end=%s loaded=%d\n' \
        "${_n}" "${_wall_ms}" "${_epoch_start}" "${_epoch_end}" "${_loaded}"
    pctls_from_file "${CTRL_PROBE_OUT}" "ctrl_"

    if [ "${_loaded}" -lt "${_n}" ]; then
        printf 'error=load_failed loaded=%d expected=%d detail=%s\n' \
            "${_loaded}" "${_n}" "$(printf '%s' "${_err}" | head -1 | tr ' ' '_')"
    fi
}

# (b) Benchmark chunked -T add / -T delete.
# BATCH=0 = single-giant-op (all adds in one pfctl call, all deletes in one call).
# Emits: op=delta size=N churn=C batch=B wall_ms=W epoch_start=S epoch_end=E
#        ctrl_p50=P ctrl_p99=P ctrl_max=M ctrl_n=N
do_delta() {
    _n="$1"; _churn="$2"; _batch="$3"
    _file="${TMP}/table_${_n}.txt"
    [ -f "${_file}" ] || { printf 'error=table_%d_not_generated\n' "${_n}"; return 1; }

    # Clamp churn to at most half table size.
    _actual_churn="${_churn}"
    _half=$(( _n / 2 ))
    [ "${_churn}" -gt "${_half}" ] && _actual_churn="${_half}"

    # Build adds/dels: first/last _actual_churn lines of the table.
    # These are non-overlapping because _actual_churn <= n/2 and the table is sequential.
    _adds="${TMP}/adds_${_n}_${_actual_churn}.txt"
    _dels="${TMP}/dels_${_n}_${_actual_churn}.txt"
    if [ ! -f "${_adds}" ]; then
        head -n "${_actual_churn}" "${_file}" > "${_adds}"
        tail -n "${_actual_churn}" "${_file}" > "${_dels}"
    fi

    # Load baseline table.
    "${PFCTL}" -t "${TABLE}" -T replace -f "${_file}" >/dev/null 2>&1 || true

    start_ctrl_probe
    _epoch_start=$(now_epoch)
    _t0=$(now_ms)

    if [ "${_batch}" -eq 0 ]; then
        # Single-giant-op: one pfctl call per direction.
        "${PFCTL}" -t "${TABLE}" -T add    -f "${_adds}" >/dev/null 2>&1 || true
        "${PFCTL}" -t "${TABLE}" -T delete -f "${_dels}" >/dev/null 2>&1 || true
    else
        # Chunked: split each direction into files of at most _batch lines, call pfctl per chunk.
        _chunk_dir="${TMP}/chunks_${_n}_${_actual_churn}_${_batch}"
        rm -rf "${_chunk_dir}"
        mkdir -p "${_chunk_dir}"

        # Split and apply adds.
        _chunk_idx=0
        _line_count=0
        _chunk="${_chunk_dir}/add_$(printf '%07d' "${_chunk_idx}").txt"
        while IFS= read -r _line; do
            printf '%s\n' "${_line}" >> "${_chunk}"
            _line_count=$(( _line_count + 1 ))
            if [ "${_line_count}" -ge "${_batch}" ]; then
                "${PFCTL}" -t "${TABLE}" -T add -f "${_chunk}" >/dev/null 2>&1 || true
                _chunk_idx=$(( _chunk_idx + 1 ))
                _line_count=0
                _chunk="${_chunk_dir}/add_$(printf '%07d' "${_chunk_idx}").txt"
            fi
        done < "${_adds}"
        # Flush last partial chunk.
        if [ -f "${_chunk}" ] && [ -s "${_chunk}" ]; then
            "${PFCTL}" -t "${TABLE}" -T add -f "${_chunk}" >/dev/null 2>&1 || true
        fi

        # Split and apply deletes.
        _chunk_idx=0
        _line_count=0
        _chunk="${_chunk_dir}/del_$(printf '%07d' "${_chunk_idx}").txt"
        while IFS= read -r _line; do
            printf '%s\n' "${_line}" >> "${_chunk}"
            _line_count=$(( _line_count + 1 ))
            if [ "${_line_count}" -ge "${_batch}" ]; then
                "${PFCTL}" -t "${TABLE}" -T delete -f "${_chunk}" >/dev/null 2>&1 || true
                _chunk_idx=$(( _chunk_idx + 1 ))
                _line_count=0
                _chunk="${_chunk_dir}/del_$(printf '%07d' "${_chunk_idx}").txt"
            fi
        done < "${_dels}"
        if [ -f "${_chunk}" ] && [ -s "${_chunk}" ]; then
            "${PFCTL}" -t "${TABLE}" -T delete -f "${_chunk}" >/dev/null 2>&1 || true
        fi

        rm -rf "${_chunk_dir}"
    fi

    _t1=$(now_ms)
    _epoch_end=$(now_epoch)
    stop_ctrl_probe

    _wall_ms=$(( _t1 - _t0 ))
    _batch_label="${_batch}"
    [ "${_batch}" -eq 0 ] && _batch_label="giant"

    printf 'op=delta size=%d churn=%d batch=%s wall_ms=%d epoch_start=%s epoch_end=%s\n' \
        "${_n}" "${_actual_churn}" "${_batch_label}" \
        "${_wall_ms}" "${_epoch_start}" "${_epoch_end}"
    pctls_from_file "${CTRL_PROBE_OUT}" "ctrl_"
}

# (c) Recompute cost: LC_ALL=C sort -u (lower bound — omits file read/concat).
do_recompute() {
    _n="$1"
    _file="${TMP}/table_${_n}.txt"
    [ -f "${_file}" ] || { printf 'error=table_%d_not_generated\n' "${_n}"; return 1; }
    _t0=$(now_ms)
    LC_ALL=C sort -u "${_file}" > /dev/null
    _t1=$(now_ms)
    printf 'op=recompute size=%d wall_ms=%d\n' "${_n}" "$(( _t1 - _t0 ))"
}

do_cleanup() {
    "${PFCTL}" -t "${TABLE}" -T kill 2>/dev/null || true
    rm -rf "${TMP}"
    printf 'cleaned=ok\n'
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

case "${1:-}" in
    system_info)  do_system_info ;;
    raise_limits) do_raise_limits "${2:-10000000}" ;;
    gen)          do_gen "${2:?missing N}" ;;
    replace)      do_replace "${2:?missing N}" ;;
    delta)        do_delta "${2:?missing N}" "${3:?missing CHURN}" "${4:?missing BATCH}" ;;
    recompute)    do_recompute "${2:?missing N}" ;;
    cleanup)      do_cleanup ;;
    *)
        printf 'usage: bench_pfctl_tables.sh <system_info|raise_limits [MAX]|gen N|replace N|delta N CHURN BATCH|recompute N|cleanup>\n' >&2
        exit 2
        ;;
esac
