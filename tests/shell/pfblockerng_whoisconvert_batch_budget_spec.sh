#shellcheck shell=sh
# whoisconvert() whole-batch deadline (issue #2877).
#
# Issue #2015 bounded each Domain lookup (timeout -s TERM -k 5 30), but the two
# synchronous PHP launch sites still wait for an UNCAPPED number of per-entry
# budgets: whoisconvert() iterates every configured entry, so a batch of N
# Domain rows could hold an update pass for N x 30s (plus the first-use ASN
# re-entry). #2877 adds a whole-batch deadline:
#
#   - The deadline is checked BEFORE each entry, and the per-entry timeout is
#     clipped to the time left, so no Domain/AS ordering can bypass the total
#     budget; the batch ends within the budget plus one lookup's kill grace.
#   - Partial-state policy is explicit: entries that resolved before the
#     deadline are KEPT (append semantics, #714 accumulation), the skipped
#     remainder leaves the .fail marker, and an operator-visible line names
#     the expiry -- never a silent publish or erase.
#   - #2015's per-entry 30-second reaper bound is preserved whenever the
#     budget leaves 30s or more, and #2016's nested pfb_reentry() seam keeps
#     its own bound untouched (the batch routes nothing around it).
#   - A lookup descendant that ignores TERM is reaped by the reaper's kill
#     grace (FreeBSD timeout(1) default reaper mode; GNU -k grace KILLs the
#     whole process group -- probed, 7s wall, tree empty on return).
#
# The executed rows use a real timeout(1) from PATH (recorded argv + real
# enforcement) plus a deterministic fake host whose per-entry calls stay
# individually bounded while their total exceeds the budget.

make_recording_enforcing_timeout() {
  # Records its argv (one space-joined invocation per line) and enforces with
  # a REAL timeout(1), so clipped durations actually bound a slow fake host.
  pathtimeout="${work}/timeout"
  cat > "$pathtimeout" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${TIMEOUT_ARGS}"
exec timeout "$@"
EOF
  chmod +x "$pathtimeout"
}

make_recording_passthrough_timeout() {
  # Records its argv, then runs the command directly (no real wait) -- for
  # rows that must observe the composed durations without spending them.
  pathtimeout="${work}/timeout"
  cat > "$pathtimeout" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "${TIMEOUT_ARGS}"
shift 5
exec "$@"
EOF
  chmod +x "$pathtimeout"
}

make_counting_host() {
  # Each call sleeps HOST_SLEEP seconds, then answers with a unique address
  # (203.0.113.<n>) so the spec can tell exactly which entries ran.
  pathhost="${work}/host"
  cat > "$pathhost" <<'EOF'
#!/bin/sh
sleep "${HOST_SLEEP}"
n="$(cat "${HOST_COUNT}")"
n=$((n + 1))
echo "$n" > "${HOST_COUNT}"
echo "$3 has address 203.0.113.$n"
EOF
  chmod +x "$pathhost"
}

pfb_require_real_timeout() {
  real_timeout="$(command -v timeout)"
  if [ -z "${real_timeout}" ]; then
    echo "no timeout(1) on PATH: the executed batch rows need a real one" >&2
    return 1
  fi
}

twenty_domains() {
  _wd_i=1
  while [ "${_wd_i}" -le 20 ]; do
    if [ "${_wd_i}" -gt 1 ]; then printf ','; fi
    printf 'd%s.example' "${_wd_i}"
    _wd_i=$((_wd_i + 1))
  done
}

Describe 'whoisconvert() bounds the total batch duration (issue #2877)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/whoisbatch.XXXXXX")"
    pfborig="${work}/orig/"; mkdir -p "$pfborig"
    alias="BudgetList"
    max="_v4"
    errorlog="${work}/error.log"
    timeout_args="${work}/timeout.args"
    true > "$timeout_args"
    host_count="${work}/host.count"; echo 0 > "$host_count"
    pfb_require_real_timeout
    export TIMEOUT_ARGS="$timeout_args" HOST_COUNT="$host_count"
  }
  cleanup() {
    rm -rf "$work"
    unset TIMEOUT_ARGS HOST_COUNT HOST_SLEEP whoisbatchtimeout
  }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  # The batch-expiry scenario, run once per It (setup is per-example). The
  # first lookup's duration is asserted separately: it is clipped to the time
  # left, which at entry 1 IS the budget -- modulo a date(1) second boundary
  # between the batch start and the first check, so 1 is also a clipped value,
  # while any widened budget composes 4, 30, or the bare 30s bound.
  It 'stops at the budget, keeps the resolved prefix, and marks the skipped remainder'
    whoisbatchtimeout=2
    export HOST_SLEEP=0.2
    dedup="$(twenty_domains)"
    make_recording_enforcing_timeout
    make_counting_host
    # A prior .orig so the run proves append semantics: successful entries are
    # ADDED to the last-good data and the .bk is consumed, not restored.
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    # The expiry is named, with the exact budget, on stdout and in error.log.
    The stdout should include 'WHOIS batch [ BudgetList ] TIMED OUT after 2s total; remaining Domain/AS entries skipped'
    The contents of file "$errorlog" should include 'WHOIS batch [ BudgetList ] TIMED OUT after 2s total; remaining Domain/AS entries skipped'
    # A resolved prefix survived (append semantics) alongside the prior data...
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.3'
    # ...the stale .bk data does NOT reappear in the fresh .orig (the batch
    # replaces the file's contents with this run's collections)...
    The contents of file "${pfborig}${alias}.orig" should not include '198.51.100.7'
    # ...the last entry never ran (an unbounded batch runs all twenty)...
    The contents of file "${pfborig}${alias}.orig" should not include '203.0.113.20'
    # ...the skipped remainder is a visible failure, and the consumed .bk is gone.
    The path "${pfborig}${alias}.fail" should be exist
    The path "${pfborig}${alias}.bk" should not be exist
  End

  It 'clips the first lookup to the budget itself, not to the bare 30s bound'
    whoisbatchtimeout=2
    export HOST_SLEEP=0
    dedup="$(twenty_domains)"
    make_recording_enforcing_timeout
    make_counting_host
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should not include 'TIMED OUT'
    # Reaper mode and the kill grace are byte-identical to issue #2015; only
    # the duration is clipped to the time left within the batch.
    The contents of file "$timeout_args" should include '-s TERM -k 5 '
    The contents of file "$timeout_args" should include " ${pathhost} -t A d1.example"
    clip_duration="$(sed -n '1s/.* -k 5 \([1-9][0-9]*\) .*/\1/p' "$timeout_args")"
    if [ -z "${clip_duration}" ] || [ "${clip_duration}" -gt 2 ]; then
      echo "first lookup was not clipped to the 2s budget: '${clip_duration}'" >&2
      false
    fi
  End

  It 'expires after the first-use ASN re-entry feeds the batch, and leaves the seam untouched'
    whoisbatchtimeout=2
    export HOST_SLEEP=0.2
    dedup="AS64500,$(twenty_domains)"
    make_recording_enforcing_timeout
    make_counting_host
    # No asn.csv on disk: the ASN branch takes the first-use path through the
    # ONE nested re-entry seam. The fake interpreter materializes the database,
    # so the same entry then resolves and the batch continues.
    pathasncsv="${work}/asn.csv"
    pathphp="${work}/php"
    cat > "$pathphp" <<EOF
#!/bin/sh
printf '203.0.113.64,203.0.113.127,AS64500,ExampleNet\n2001:db8::,2001:db8::ffff,AS64500,ExampleNet\n' > '${pathasncsv}'
exit 0
EOF
    chmod +x "$pathphp"
    pathpfbphp="${work}/pfblockerng.php"

    When call whoisconvert
    The status should be success
    # The nested seam's own argv is unchanged: reaper mode, its full budget.
    The contents of file "$timeout_args" should include "-s TERM -k 5 1800 ${pathphp} ${pathpfbphp} asn_shell scheduled"
    # The ASN entry resolved, the batch continued into the Domain rows, and the
    # deadline still ended the pass (ordering did not bypass the budget).
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.64-203.0.113.127'
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.3'
    The contents of file "${pfborig}${alias}.orig" should not include '203.0.113.20'
    The stdout should include 'WHOIS batch [ BudgetList ] TIMED OUT after 2s total; remaining Domain/AS entries skipped'
    The path "${pfborig}${alias}.fail" should be exist
  End

  It 'reaps a transient tree whose members all ignore TERM, after the kill grace'
    whoisbatchtimeout=2
    dedup='d1.example,d2.example'
    make_recording_enforcing_timeout
    # A host(1) stand-in where NOTHING dies on TERM -- only the reaper's kill
    # grace (-k 5) can end this transient tree (issue #2877 hostile row). The
    # second list entry exists only so the loop reaches the deadline check
    # after the reaped first lookup.
    pathhost="${work}/host"
    grandpid_file="${work}/grandpid"
    cat > "$pathhost" <<EOF
#!/bin/sh
trap '' TERM
(sleep 10) &
echo \$! > '${grandpid_file}'
sleep 10
EOF
    chmod +x "$pathhost"
    # A prior .orig proves the timeout follows the existing failure/restore path.
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should include 'WHOIS batch [ BudgetList ] TIMED OUT after 2s total; remaining Domain/AS entries skipped'
    The contents of file "${pfborig}${alias}.orig" should equal '198.51.100.7'
    The path "${pfborig}${alias}.fail" should be exist
    The stderr should be present
    # The tree the lookup left behind is reaped once the kill grace lapses --
    # before the batch reports its expiry, not orphaned past it.
    reap_waits=0
    grandpid="$(cat "${grandpid_file}")"
    while kill -0 "${grandpid}" 2>/dev/null && [ "${reap_waits}" -lt 20 ]; do
      sleep 0.1
      reap_waits=$((reap_waits + 1))
    done
    if kill -0 "${grandpid}" 2>/dev/null; then
      echo "lookup descendant ${grandpid} survived the reaper" >&2
      false
    fi
  End

  It 'runs a batch that fits the budget with the untouched 30-second per-entry bound'
    whoisbatchtimeout=30
    export HOST_SLEEP=0
    dedup='d1.example'
    make_recording_passthrough_timeout
    make_counting_host
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should not include 'TIMED OUT'
    The stdout should include 'completed'
    The contents of file "$timeout_args" should include "-s TERM -k 5 30 ${pathhost} -t A d1.example"
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.1'
    The path "${pfborig}${alias}.fail" should not be exist
    The path "${pfborig}${alias}.bk" should not be exist
  End

  It 'degrades a zero budget to the default instead of an instant expiry'
    whoisbatchtimeout=0
    export HOST_SLEEP=0
    dedup='d1.example'
    make_recording_passthrough_timeout
    make_counting_host
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should not include 'TIMED OUT'
    # A 0-second budget must not become a 0-second timeout: the default leaves
    # the full 30-second per-entry bound in the composed command.
    The contents of file "$timeout_args" should include "-s TERM -k 5 30 ${pathhost} -t A d1.example"
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.1'
    The path "${pfborig}${alias}.fail" should not be exist
  End

  It 'accepts a zero-padded positive budget instead of degrading to the default'
    whoisbatchtimeout=008
    export HOST_SLEEP=0
    dedup='d1.example'
    make_recording_passthrough_timeout
    make_counting_host
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should not include 'TIMED OUT'
    # 008 is eight seconds, so the first lookup is clipped to 8 not 30.

    The contents of file "$timeout_args" should include "-s TERM -k 5 8 ${pathhost} -t A d1.example"
    The contents of file "${pfborig}${alias}.orig" should include '203.0.113.1'
    The path "${pfborig}${alias}.fail" should not be exist
  End

  It 'treats an empty entry list as a no-expiry pass that restores the prior file'
    whoisbatchtimeout=2
    export HOST_SLEEP=0
    dedup=''
    make_recording_passthrough_timeout
    make_counting_host
    printf '198.51.100.7\n' > "${pfborig}${alias}.orig"

    When call whoisconvert
    The status should be success
    The stdout should include 'Restoring previous data'
    The stdout should not include 'TIMED OUT'
    The contents of file "${pfborig}${alias}.orig" should equal '198.51.100.7'
    The contents of file "$timeout_args" should equal ''
    The path "${pfborig}${alias}.fail" should not be exist
  End
End
