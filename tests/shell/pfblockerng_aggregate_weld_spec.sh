#shellcheck shell=sh
# issue #1263 (PR #1271 gap): pfb_aggregate()'s member-file union still ran a bare
# `cat` over the memberlist -- an unterminated member welds its last line onto the
# next member's first line, silently dropping a real address and inventing a bogus
# one. This is the REAL ADR-11 union site (pfblockerng.sh), not the
# scripts/misc/bench_aggregate_union.sh benchmark stand-in PR #1271 fixed instead.

Describe 'pfb_aggregate() member union never welds records across an unterminated file (issue #1263)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/aggweld.XXXXXX")"
    tempfile="${work}/t1"
    dedupfile="${work}/dedup"
    errorlog="${work}/err.log"
    memberlist="${work}/members"
    aggout="${work}/agg.txt"
    consumer="${work}/agg.lst"
  }
  cleanup() { rm -rf "${work}"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'unions an unterminated member with a terminated one into TWO real lines, never a welded record'
    # Member 1 has NO trailing newline; member 2 is properly terminated.
    printf '1.1.1.1' > "${work}/m1"
    printf '2.2.2.2\n' > "${work}/m2"
    printf '%s\n%s\n' "${work}/m1" "${work}/m2" > "${memberlist}"

    When call pfb_aggregate agg v6 "${memberlist}" "${aggout}" "${consumer}"

    The status should be success
    # The welded run logs "union 1 -> 1 CIDRs" -- the reported count is itself the bug signal.
    The stdout should include 'union 2 -> 2 CIDRs'
    The contents of file "${aggout}" should include '1.1.1.1'
    The contents of file "${aggout}" should include '2.2.2.2'
    The contents of file "${aggout}" should not include '1.1.1.12.2.2.2'
    linecount="$(grep -c ^ "${aggout}")"
    The variable linecount should equal 2
  End
End
