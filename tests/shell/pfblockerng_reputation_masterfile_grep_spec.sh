#shellcheck shell=sh
# reputation_pmax() masterfile block-removal grep (#730) -- pins the
# sibling-alias over-match at the "Removing [ Block ] IPs" tail. reputation_dmax()
# carried the identical fix/bug (deleted alongside the function, issue #1084).
#
# Each dedupfile line is '<alias> 10.0.0.' and the removal step subtracts every
# matching masterfile row so the aggregated '10.0.0.0/24' can replace them. The
# pre-fix code matched with an UNANCHORED `grep -F "${ips}"`, so the substring
# 'MYLIST 1.2.3.' also matched a SIBLING alias whose name ends with this one's
# and whose IP is in the same /24 -- e.g. the row 'XMYLIST 1.2.3.9/32' contains
# 'MYLIST 1.2.3.' -- and the follow-up awk then stripped that unrelated alias's
# entry from masterfile. Same bug class as #728/#714, on the '<alias> <ip>' field.
#
# Transition proven both ways: the offender's OWN /24 rows ARE removed (so the
# removal genuinely ran, not a no-op) while the sibling's row SURVIVES.

Describe 'reputation_pmax() masterfile block removal (#730)'
  # shellcheck disable=SC2034  # consumed by the sourced reputation_pmax()
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/reppmaxmf.XXXXXX")"
    pfbdeny="${work}/deny/"
    mkdir -p "$pfbdeny"
    tmpdir="${work}"
    tempfile="${work}/t1"; tempfile2="${work}/t2"
    dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
    masterfile="${work}/master"; mastercat="${work}/mastercat"
    ip_placeholder='240.0.0.0'
    ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
    now="now"
    count=0; countb=0
    max=1
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${pfbdeny}MYLIST.txt"
    printf 'MYLIST 1.2.3.4/32\nXMYLIST 1.2.3.9/32\n' > "${masterfile}"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'removes only the offender alias rows, keeping a sibling alias in the same /24'
    When call reputation_pmax
    The status should be success
    The stdout should include "Reputation - pMax Stats"
    The contents of file "${masterfile}" should not include "MYLIST 1.2.3.4/32"
    The contents of file "${masterfile}" should include "XMYLIST 1.2.3.9/32"
  End
End
