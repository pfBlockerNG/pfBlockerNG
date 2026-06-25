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
#   bench_pfctl_tables.sh get_interfaces
#   bench_pfctl_tables.sh setup_rules [lan_if|floating|none]
#   bench_pfctl_tables.sh teardown_rules
#   bench_pfctl_tables.sh verify_reject
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
#
# Uses 11.0.0.0/8 (baseline block, ~16.7M addresses — enough for any table ≤1M).
# Entries never overlap the harness probe path: skips 10.0.0.0/8 (harness nets),
# 192.168.0.0/16 (pfSense LAN 192.168.1.1 + civm 192.168.1.10), loopback, etc.
# Idempotent.
do_gen() {
    _n="$1"
    _out="${TMP}/table_${_n}.txt"
    if [ -f "${_out}" ]; then
        printf 'cached=%s\n' "${_out}"
        return
    fi
    awk -v n="${_n}" 'BEGIN {
        c = 0
        for (a = 0; a <= 255 && c < n; a++)
            for (b = 0; b <= 255 && c < n; b++)
                for (z = 1; z <= 254 && c < n; z++) { print "11." a "." b "." z; c++ }
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

    # Clamp churn to at most table size (sanity, not address-space).
    _actual_churn="${_churn}"
    [ "${_churn}" -gt "${_n}" ] && _actual_churn="${_n}"

    # Build adds/dels.
    # _dels: last _actual_churn lines of the table (entries to remove from baseline).
    # _adds: a DISJOINT set of _actual_churn entries from 13.0.0.0/8 (~16.7M addrs),
    #   which do_gen() never touches (baseline uses 11.x), so -T add calls are real
    #   insertions (never no-ops on already-loaded IPs).
    _adds="${TMP}/adds_${_n}_${_actual_churn}.txt"
    _dels="${TMP}/dels_${_n}_${_actual_churn}.txt"
    if [ ! -f "${_adds}" ]; then
        tail -n "${_actual_churn}" "${_file}" > "${_dels}"
        awk -v n="${_actual_churn}" 'BEGIN {
            c = 0
            for (a = 0; a <= 255 && c < n; a++)
                for (b = 0; b <= 255 && c < n; b++)
                    for (z = 1; z <= 254 && c < n; z++) { print "13." a "." b "." z; c++ }
        }' > "${_adds}"
    fi

    # Load baseline table.
    "${PFCTL}" -t "${TABLE}" -T replace -f "${_file}" >/dev/null 2>&1 || true

    start_ctrl_probe
    _epoch_start=$(now_epoch)
    _t0=$(now_ms)

    _chunk_errors=0

    _pfctl_op() {
        # Run pfctl; on failure increment _chunk_errors and log to stderr (row still recorded).
        _op_out=$("${PFCTL}" "$@" 2>&1) || {
            _chunk_errors=$(( _chunk_errors + 1 ))
            printf 'chunk_error: pfctl %s rc=%d detail=%s\n' \
                "$*" "$?" "$(printf '%s' "${_op_out}" | head -1 | tr ' ' '_')" >&2
        }
    }

    if [ "${_batch}" -eq 0 ]; then
        # Single-giant-op: one pfctl call per direction.
        _pfctl_op -t "${TABLE}" -T add    -f "${_adds}" >/dev/null
        _pfctl_op -t "${TABLE}" -T delete -f "${_dels}" >/dev/null
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
                _pfctl_op -t "${TABLE}" -T add -f "${_chunk}" >/dev/null
                _chunk_idx=$(( _chunk_idx + 1 ))
                _line_count=0
                _chunk="${_chunk_dir}/add_$(printf '%07d' "${_chunk_idx}").txt"
            fi
        done < "${_adds}"
        # Flush last partial chunk.
        if [ -f "${_chunk}" ] && [ -s "${_chunk}" ]; then
            _pfctl_op -t "${TABLE}" -T add -f "${_chunk}" >/dev/null
        fi

        # Split and apply deletes.
        _chunk_idx=0
        _line_count=0
        _chunk="${_chunk_dir}/del_$(printf '%07d' "${_chunk_idx}").txt"
        while IFS= read -r _line; do
            printf '%s\n' "${_line}" >> "${_chunk}"
            _line_count=$(( _line_count + 1 ))
            if [ "${_line_count}" -ge "${_batch}" ]; then
                _pfctl_op -t "${TABLE}" -T delete -f "${_chunk}" >/dev/null
                _chunk_idx=$(( _chunk_idx + 1 ))
                _line_count=0
                _chunk="${_chunk_dir}/del_$(printf '%07d' "${_chunk_idx}").txt"
            fi
        done < "${_dels}"
        if [ -f "${_chunk}" ] && [ -s "${_chunk}" ]; then
            _pfctl_op -t "${TABLE}" -T delete -f "${_chunk}" >/dev/null
        fi

        rm -rf "${_chunk_dir}"
    fi

    _t1=$(now_ms)
    _epoch_end=$(now_epoch)
    stop_ctrl_probe

    _wall_ms=$(( _t1 - _t0 ))
    _batch_label="${_batch}"
    [ "${_batch}" -eq 0 ] && _batch_label="giant"

    printf 'op=delta size=%d churn=%d batch=%s wall_ms=%d epoch_start=%s epoch_end=%s chunk_errors=%d\n' \
        "${_n}" "${_actual_churn}" "${_batch_label}" \
        "${_wall_ms}" "${_epoch_start}" "${_epoch_end}" "${_chunk_errors}"
    pctls_from_file "${CTRL_PROBE_OUT}" "ctrl_"
    if [ "${_chunk_errors}" -gt 0 ]; then
        printf 'error=chunk_failures count=%d\n' "${_chunk_errors}"
    fi
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
# Reject-loop rule wiring (ADR-40 follow-up)
# --------------------------------------------------------------------------- #
#
# setup_rules TYPE   — install reject anchor for the data-plane bench.
#   TYPE = lan_if    — block return QUICK on the LAN interface (vtnet2/em2, etc.)
#          floating  — block return QUICK as a floating rule (all interfaces)
#
# In BOTH cases a WAN-out floating reject is also installed to catch traffic NOT
# in the table (11.x misses → route to WAN → WAN reject → RST back to civm).
#
# SSH is explicitly protected: an early PASS for the pfSense management SSH port
# (port 22 on the mgmt interface) fires before any block.
#
# The rules go into a pf anchor "pfb_bench_reject" loaded via pfctl -a.  A fresh
# setup_rules call replaces the anchor contents; teardown_rules kills it cleanly.
#
# Interface discovery: WAN / LAN are read from pfSense's running config
# (pf -sn output) at setup time so the rule adapts to different QEMU NIC orderings.
#
# CRITICAL: the PASS rule for port 22 is the first rule in the anchor and uses
# the `quick` keyword so it terminates immediately.  The bench VMs are throwaway
# so any mis-fire is recoverable by killing qemu on the host box; nevertheless
# we document the invariant here.

# Discover WAN and LAN interface names from pf's running rule state.
# Returns via stdout: wan_if=<name> lan_if=<name>
do_get_interfaces() {
    # pfctl -sn shows the pf ruleset; NAT rules reveal the WAN interface (the
    # "nat on <if>" lines that are always present for SLIRP).  The LAN interface
    # is the one carrying 192.168.1.0/24 according to ifconfig.
    _wan=$("${PFCTL}" -sn 2>/dev/null | awk '/^nat on /{print $3; exit}' | tr -d '{}')
    _lan=$(ifconfig 2>/dev/null | awk '
        /^[a-z]/{cur=$1; sub(/:$/,"",cur)}
        /192\.168\.1\./{print cur; exit}
    ')
    # Fallback to vtnet names if discovery fails.
    [ -z "${_wan}" ] && _wan=$(ifconfig 2>/dev/null | awk '/^vtnet0/{print "vtnet0"; exit}' || echo "vtnet0")
    [ -z "${_lan}" ] && _lan="vtnet2"
    printf 'wan_if=%s lan_if=%s\n' "${_wan}" "${_lan}"
}

# Load the reject ruleset. TYPE is 'lan_if' or 'floating'. 'none' = WAN reject only.
#
# Root cause investigation revealed that pfSense's "Default Allow LAN to any" rule
# is loaded as a DIRECT flat rule in the main pf ruleset, AFTER the anchor call
# points (userrules/*, tftp-proxy/*). Any anchor-based approach fires too late and
# the Default Allow LAN pass quick short-circuits first.
#
# Solution: replace the entire main ruleset with a minimal bench ruleset that:
#   1. Protects the control SSH path (vtnet1 mgmt, port 22/80)
#   2. Protects DHCP so civm stays on LAN
#   3. Rejects in-table traffic from civm (LAN reject rule, floating or if-scoped)
#   4. Rejects out-of-table traffic at WAN egress (WAN floating reject)
#   5. Passes everything else (keeps civm reachable for probe driving)
#
# The bench table must already be loaded (do_replace/do_gen) before calling this.
# The minimal ruleset references <pfb_bench_main> which is a persistent pf table —
# pfctl -f - can reference any table already loaded in the kernel by name.
#
# Teardown ('none' type) loads the same ruleset WITHOUT the in-table block, leaving
# only the WAN reject active (not-in-table baseline). A full restore of pfSense's
# original ruleset is not needed: this is a throwaway benchmark VM.
do_setup_rules() {
    _type="${1:-floating}"

    # Discover interfaces.
    _wan=$("${PFCTL}" -sn 2>/dev/null | awk '/^nat on /{print $3; exit}' | tr -d '{}" ')
    _lan=$(ifconfig 2>/dev/null | awk '/^[a-z]/{cur=$1; sub(/:$/,"",cur)} /192\.168\.1\./{print cur; exit}')
    [ -z "${_wan}" ] && _wan="vtnet0"
    [ -z "${_lan}" ] && _lan="vtnet2"

    # Verify the bench table exists (must be loaded before we reference it in rules).
    _loaded=$("${PFCTL}" -t "${TABLE}" -T show 2>/dev/null | wc -l | tr -d ' ')
    if [ "${_loaded}" -eq 0 ]; then
        printf 'error=table_not_loaded wan_if=%s lan_if=%s\n' "${_wan}" "${_lan}"
        return 1
    fi

    # Build the minimal ruleset file.
    _rules_file="${TMP}/bench_minimal.conf"

    # Mgmt interface (vtnet1): always pass SSH + HTTP (harness control channel).
    printf 'pass quick on %s proto tcp to port 22\n' "${_lan}" > "${_rules_file}"
    printf 'pass quick on vtnet1 proto tcp to port 22\n' >> "${_rules_file}"
    printf 'pass quick on vtnet1 proto tcp to port 80\n' >> "${_rules_file}"

    # DHCP on LAN: civm needs DHCP to keep its 192.168.1.10 address.
    printf 'pass quick on %s proto udp from any port 68 to any port 67\n' "${_lan}" >> "${_rules_file}"
    printf 'pass quick on %s proto udp from any port 67 to any port 68\n' "${_lan}" >> "${_rules_file}"

    # In-table reject: placed BEFORE the catch-all pass so it fires with quick.
    if [ "${_type}" = "lan_if" ]; then
        # Interface-scoped: fires only on the LAN interface (inbound from civm).
        printf 'block return quick on %s from 192.168.1.10 to <%s>\n' \
            "${_lan}" "${TABLE}" >> "${_rules_file}"
    elif [ "${_type}" = "floating" ]; then
        # Floating (no on clause): fires on any interface for any direction.
        printf 'block return quick from 192.168.1.10 to <%s>\n' \
            "${TABLE}" >> "${_rules_file}"
    fi
    # 'none' type: no in-table reject rule (WAN reject only, for no-rule baseline).

    # WAN egress reject: traffic NOT in the table routes toward WAN and is rejected
    # here, generating an immediate RST for the not-in-table probe path.
    printf 'block return out quick on %s all\n' "${_wan}" >> "${_rules_file}"

    # pfSense-self outbound: pfSense must be able to exit WAN for DHCP renewals.
    printf 'pass out quick on %s from (self) to any\n' "${_wan}" >> "${_rules_file}"

    # Catch-all pass: everything else (LAN↔LAN, management, probe driving).
    printf 'pass quick all\n' >> "${_rules_file}"

    # Replace the entire main ruleset. pfctl -f - accepts <table_name> references
    # for tables already persistent in the kernel — no table definition needed.
    "${PFCTL}" -f "${_rules_file}" 2>&1 || {
        printf 'error=ruleset_load_failed type=%s wan_if=%s lan_if=%s\n' \
            "${_type}" "${_wan}" "${_lan}"
        return 1
    }

    printf 'rules_loaded=ok type=%s wan_if=%s lan_if=%s table_entries=%s\n' \
        "${_type}" "${_wan}" "${_lan}" "${_loaded}"
}

do_teardown_rules() {
    # Restore a pass-everything ruleset (no reject rules active).
    # We do not restore pfSense's original complex ruleset (this is a throwaway VM).
    # Load the setup_rules 'none' variant to clear in-table block while keeping
    # the WAN reject active for the baseline measurement.
    do_setup_rules none
    printf 'rules_torn_down=ok\n'
}

# Verify the reject loop: confirm table is loaded and rules reference it.
# Table membership is checked via pfctl -T test (authoritative, not text-grep).
do_verify_reject() {
    _in_ip="11.0.0.1"
    _out_ip="13.0.0.1"

    # pfctl -T test exits 0 if the address is matched by any table entry, 1 otherwise.
    # Redirect stdout+stderr to suppress the "N/N addresses match." line.
    if "${PFCTL}" -t "${TABLE}" -T test "${_in_ip}" >/dev/null 2>&1; then
        _in_member=1
    else
        _in_member=0
    fi
    if "${PFCTL}" -t "${TABLE}" -T test "${_out_ip}" >/dev/null 2>&1; then
        _out_member=1
    else
        _out_member=0
    fi

    printf 'verify_in_ip=%s in_table=%s verify_out_ip=%s out_table=%s\n' \
        "${_in_ip}" "${_in_member}" "${_out_ip}" "${_out_member}"
    printf 'verify_rules=%s\n' \
        "$("${PFCTL}" -sr 2>/dev/null | grep -c 'block return' || echo 0)"
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

case "${1:-}" in
    system_info)    do_system_info ;;
    raise_limits)   do_raise_limits "${2:-10000000}" ;;
    gen)            do_gen "${2:?missing N}" ;;
    replace)        do_replace "${2:?missing N}" ;;
    delta)          do_delta "${2:?missing N}" "${3:?missing CHURN}" "${4:?missing BATCH}" ;;
    recompute)      do_recompute "${2:?missing N}" ;;
    get_interfaces) do_get_interfaces ;;
    setup_rules)    do_setup_rules "${2:-floating}" ;;
    teardown_rules) do_teardown_rules ;;
    verify_reject)  do_verify_reject ;;
    cleanup)        do_cleanup ;;
    *)
        printf 'usage: bench_pfctl_tables.sh <system_info|raise_limits [MAX]|gen N|replace N|delta N CHURN BATCH|recompute N|get_interfaces|setup_rules [lan_if|floating]|teardown_rules|verify_reject|cleanup>\n' >&2
        exit 2
        ;;
esac
