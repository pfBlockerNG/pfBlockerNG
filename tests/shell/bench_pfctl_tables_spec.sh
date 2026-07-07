#shellcheck shell=sh
# bench_pfctl_tables_spec.sh — shellspec suite for scripts/bench_pfctl_tables.sh's
# issue #584 dual-path (allowed vs blocked traffic) bench additions:
#   - setup_rules 'server' type: outbound NAT + in-table reject, NO WAN blanket
#     reject (so allowed traffic actually reaches WAN/slirp).
#   - flip_in IP / flip_out IP: move a single IP in/out of the live bench table
#     (phase setup between measurements, never itself measured).
#   - do_replace's optional EXTRA_IP argument: keeps a flip IP resident across a
#     MEASURED replace during the BLOCKED phase (a bare replace from the base
#     table file would otherwise silently evict it).
#
# Hermetic: PFCTL and PERL are env-overridable (unchanged absolute defaults
# on-box — see bench_pfctl_tables.sh); this spec points PFCTL at a recording
# stub and PERL at the real system perl, and PFB_BENCH_TMP redirects TMP into a
# spec tmpdir, so the script runs off a pfSense box without touching
# /tmp/pfb_bench or /sbin/pfctl. ifconfig is left unstubbed (not present on the
# CI/dev box) — do_setup_rules's own vtnet0/vtnet2 fallbacks fire, which is the
# documented, correct degrade path.
#
# NOTE on the 'server' nat-line-ordering row: the DESIGN this spec pins places
# the mgmt/DHCP `pass` lines BEFORE the `nat` line (see bench_pfctl_tables.sh's
# do_setup_rules doc comment — the ordering/necessity claim is ASSUMED there,
# validated live at the CI-dispatch step). So "the nat line appears before any
# block/pass filter line" is checked here as "before the in-table reject and
# catch-all pass lines that structurally follow it" — the leading mgmt/DHCP
# pass lines necessarily precede the nat line by construction and are excluded
# from that claim.

Describe 'bench_pfctl_tables.sh'
  SCRIPT="${PFB_ROOT}/scripts/bench_pfctl_tables.sh"

  # Returns "nat-before-other nat_line=X other_line=Y" (or nat-after-other /
  # missing-line) so a failing assertion shows both line numbers, not a bare
  # true/false.
  nat_line_precedes() {
    _f="$1"; _other_pat="$2"
    _nat_ln="$(grep -n -F 'nat on ' "$_f" | head -1 | cut -d: -f1)"
    _other_ln="$(grep -n -F "$_other_pat" "$_f" | head -1 | cut -d: -f1)"
    if [ -z "$_nat_ln" ] || [ -z "$_other_ln" ]; then
      printf 'missing-line nat_line=%s other_line=%s\n' "${_nat_ln:-none}" "${_other_ln:-none}"
      return 1
    fi
    if [ "$_nat_ln" -lt "$_other_ln" ]; then
      printf 'nat-before-other nat_line=%s other_line=%s\n' "$_nat_ln" "$_other_ln"
    else
      printf 'nat-after-other nat_line=%s other_line=%s\n' "$_nat_ln" "$_other_ln"
    fi
  }

  setup() {
    scrub_git_env
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/benchpfctl.XXXXXX")"
    BENCH_TMP="${WORK}/bench_tmp"
    mkdir -p "${BENCH_TMP}"
    ARGV_LOG="${WORK}/pfctl_argv.log"
    : > "${ARGV_LOG}"
    RULES_FILE="${BENCH_TMP}/bench_minimal.conf"
    BIN="${WORK}/bin"
    mkdir -p "${BIN}"

    # Recording pfctl stub: appends every invocation's argv (space-joined, one
    # call per line) to ARGV_LOG (read back from the exported env var at stub
    # RUNTIME — not baked in at heredoc-creation time), then answers just
    # enough for the script's own guards: a nonempty '-T show' so the
    # table-loaded guard (do_setup_rules) and loaded-count reads (do_replace)
    # see a real table. Everything else (nat/-f/-k/-sn/add/delete) is a no-op
    # returning 0 — this stub only needs to prove WHAT pfctl was called with,
    # never simulate real table state.
    cat > "${BIN}/pfctl" << 'STUBEOF'
#!/bin/sh
printf '%s\n' "$*" >> "${ARGV_LOG}"
case "$*" in
    *"-T show"*)
        printf '11.0.0.1\n11.0.0.2\n11.0.0.3\n'
        ;;
esac
exit 0
STUBEOF
    chmod +x "${BIN}/pfctl"

    PFCTL="${BIN}/pfctl"
    PERL="$(command -v perl)"
    PFB_BENCH_TMP="${BENCH_TMP}"
    export PFCTL PERL PFB_BENCH_TMP ARGV_LOG WORK BENCH_TMP RULES_FILE
  }
  teardown() { rm -rf "$WORK"; }
  BeforeEach 'setup'
  AfterEach 'teardown'

  # ---- setup_rules server type (issue #584 dual-path bench) -----------------

  Describe 'setup_rules server type'
    It 'contains the nat-on line'
      When run sh "$SCRIPT" setup_rules server
      The status should be success
      The output should include 'rules_loaded=ok type=server'
      The contents of file "$RULES_FILE" should include 'nat on vtnet0 inet from 192.168.1.0/24 to any -> (vtnet0)'
    End

    It 'places the nat line before the in-table reject line'
      sh "$SCRIPT" setup_rules server > /dev/null 2>&1
      When call nat_line_precedes "$RULES_FILE" 'block return quick on vtnet2 from 192.168.1.10'
      The output should start with 'nat-before-other'
    End

    It 'places the nat line before the catch-all pass line'
      sh "$SCRIPT" setup_rules server > /dev/null 2>&1
      When call nat_line_precedes "$RULES_FILE" 'pass quick all'
      The output should start with 'nat-before-other'
    End

    It 'contains the lan in-table reject referencing <pfb_bench_main>'
      When run sh "$SCRIPT" setup_rules server
      The status should be success
      The output should include 'rules_loaded=ok type=server'
      The contents of file "$RULES_FILE" should include 'block return quick on vtnet2 from 192.168.1.10 to <pfb_bench_main>'
    End

    It 'does NOT contain the WAN blanket reject (allowed traffic must exit WAN)'
      When run sh "$SCRIPT" setup_rules server
      The status should be success
      The output should include 'rules_loaded=ok type=server'
      The contents of file "$RULES_FILE" should not include 'block return out quick on vtnet0 all'
    End

    # Vacuity pair: a floating setup DOES contain the WAN blanket reject, proving
    # the negative assertion above is a real check that CAN fail, not a typo'd
    # string that would never have matched anything.
    It 'vacuity: a floating setup DOES contain the WAN blanket reject'
      When run sh "$SCRIPT" setup_rules floating
      The status should be success
      The output should include 'rules_loaded=ok type=floating'
      The contents of file "$RULES_FILE" should include 'block return out quick on vtnet0 all'
    End
  End

  # ---- flip_in / flip_out (table-membership phase setup) --------------------

  Describe 'flip_in / flip_out'
    It 'flip_in adds the IP via -T add and reports the post-op table count'
      When run sh "$SCRIPT" flip_in 192.168.89.100
      The status should be success
      The output should include 'op=flip_in ip=192.168.89.100 table_count=3'
      The contents of file "$ARGV_LOG" should include '-t pfb_bench_main -T add 192.168.89.100'
    End

    It 'flip_out removes the IP via -T delete and reports the post-op table count'
      When run sh "$SCRIPT" flip_out 192.168.89.100
      The status should be success
      The output should include 'op=flip_out ip=192.168.89.100 table_count=3'
      The contents of file "$ARGV_LOG" should include '-t pfb_bench_main -T delete 192.168.89.100'
    End
  End

  # ---- do_replace EXTRA_IP argument (BLOCKED-phase measured replace) --------

  Describe 'do_replace EXTRA_IP argument'
    gen_table() { sh "$SCRIPT" gen 5 > /dev/null 2>&1; }
    BeforeEach 'gen_table'

    It 'without EXTRA_IP: -f argv points at the original table file (unchanged behaviour pin)'
      When run sh "$SCRIPT" replace 5
      The status should be success
      The output should include 'op=replace size=5'
      The contents of file "$ARGV_LOG" should include "-f ${BENCH_TMP}/table_5.txt"
      The contents of file "$ARGV_LOG" should not include 'table_5_extra.txt'
    End

    It 'with EXTRA_IP: builds the extra file (original rows + extra IP) and -f targets it'
      When run sh "$SCRIPT" replace 5 192.168.89.100
      The status should be success
      The output should include 'op=replace size=5'
      The path "${BENCH_TMP}/table_5_extra.txt" should be exist
      The contents of file "${BENCH_TMP}/table_5_extra.txt" should include '11.0.0.1'
      The contents of file "${BENCH_TMP}/table_5_extra.txt" should include '11.0.0.5'
      The contents of file "${BENCH_TMP}/table_5_extra.txt" should include '192.168.89.100'
      The contents of file "$ARGV_LOG" should include "-f ${BENCH_TMP}/table_5_extra.txt"
    End

    It 'with EXTRA_IP: the loaded-check compares against the extra file line count (6), not N (5)'
      When run sh "$SCRIPT" replace 5 192.168.89.100
      The status should be success
      The output should include 'expected=6'
      The output should not include 'expected=5'
    End
  End
End
