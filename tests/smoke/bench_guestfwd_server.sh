#!/bin/sh
# bench_guestfwd_server.sh — inetd-style request/response server for the
# issue #584 Step 1 dual-path (allowed vs blocked traffic) data-plane
# disruption bench — the "small-server test" ADR-40's benchmark shortcomings
# note (RESULTS/00_Benchmark_Summary_And_Shortcomings.md §1) calls for.
#
# QEMU slirp's `guestfwd=...-cmd:<this script>` forks a fresh copy per guest
# TCP connection, with the connection's stream wired to stdin/stdout — no
# listening socket of our own, no loop: one request in, one response out,
# exit. QEMU owns the connection lifecycle (accept/close); this script never
# manages sockets or timeouts. The two virtual WAN IPs that forward here
# (192.168.89.100 "flip" + 192.168.89.101 control) are defined in boot_vm.sh.
#
# Protocol: read ONE line from the peer, echo it back verbatim prefixed with
# "PFB_BENCH_OK ", then exit. The request line is DATA ONLY — never executed
# (quoted expansion into printf; no eval, no command interpolation).

set -eu

req=""
if IFS= read -r req; then
    # Normal case: a complete line (empty or not) was read.
    printf 'PFB_BENCH_OK %s\n' "$req"
elif [ -n "$req" ]; then
    # EOF hit mid-line (peer closed without a trailing newline) but partial
    # data was still captured by read — respond with what we got.
    printf 'PFB_BENCH_OK %s\n' "$req"
fi
# Else: EOF with nothing read at all — exit silently.

exit 0
