#shellcheck shell=sh
# issue #1084 review: closingprocess()'s Database Sanity check compares mastercat
# (masterfile column 2 -- now BOTH families' rows, since v6 Deny joined cross-list
# dedup) against a deny-folder re-scan that still excludes '*_v6.txt' (a leftover
# from when the masterfile/mastercat pair was v4-only). The family mismatch makes
# the check spuriously FAIL on every pass that has any v6 Deny content at all.

Describe "closingprocess() Database Sanity check counts v6 Deny rows too (issue #1084 review)"
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/closesanv6.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    alias="on"
    # A v4 alias (2 rows) + a v6 alias (1 row) -- exactly what recompute produces
    # once dedup=on drives both families through the batch pass every reload.
    printf 'FeedA_v4 192.0.2.1\nFeedA_v4 192.0.2.2\nFeedB_v6 2001:db8::1\n' > "$masterfile"
    printf '192.0.2.1\n192.0.2.2\n2001:db8::1\n' > "$mastercat"
    printf '192.0.2.1\n192.0.2.2\n' > "${pfbdeny}FeedA_v4.txt"
    printf '2001:db8::1\n' > "${pfbdeny}FeedB_v6.txt"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'passes the sanity check once the deny-folder re-scan includes v6 Deny files'
    When call closingprocess
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stdout should not include 'FAILED'
  End
End
