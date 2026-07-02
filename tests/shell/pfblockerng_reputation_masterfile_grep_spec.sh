#shellcheck shell=sh
# reputation_dmax()/reputation_pmax() masterfile block-removal grep (#730) --
# pins the sibling-alias over-match at the "Removing [ Block ] IPs" tail of both
# functions.
#
# Each dedupfile line is '<alias> 10.0.0.' and the removal step subtracts every
# matching masterfile row so the aggregated '10.0.0.0/24' can replace them. The
# pre-fix code matched with an UNANCHORED `grep -F "${ips}"`, so the substring
# 'MYLIST 1.2.3.' also matched a SIBLING alias whose name ends with this one's
# and whose IP is in the same /24 -- e.g. the row 'XMYLIST 1.2.3.9/32' contains
# 'MYLIST 1.2.3.' -- and the follow-up awk then stripped that unrelated alias's
# entry from masterfile. Same bug class as #728/#714, on the '<alias> <ip>' field.
#
# Transition proven both ways per case: the offender's OWN /24 rows ARE removed
# (so the removal genuinely ran, not a no-op) while the sibling's row SURVIVES.

Describe 'reputation_dmax() masterfile block removal (#730)'
  # shellcheck disable=SC2034  # consumed by the sourced reputation_dmax()
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/repdmaxmf.XXXXXX")"
    pfbdeny="${work}/deny/"; pfbmatch="${work}/match/"
    mkdir -p "$pfbdeny" "$pfbmatch"
    tmpdir="${work}"
    tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"
    matchfile="${work}/t7"; tempmatchfile="${work}/t8"
    dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
    masterfile="${work}/master"; mastercat="${work}/mastercat"
    pathgeoip="${work}/mmdblookup"
    pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
    ip_placeholder='240.0.0.0'
    ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
    now="now"
    count=0; countb=0; counts=0; countr=0
    dedup="off"; ccwhite="match"; ccblack="block"; cc="US"
    matchdedup="matchdedup_v4.txt"
    max=1
    # One /24 with >max members in the MYLIST outfile -> a repeat offender.
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${pfbdeny}MYLIST.txt"
    # masterfile rows are '<alias> <cidr>'. MYLIST's own row must be removed;
    # XMYLIST (a DIFFERENT alias whose name ends with 'MYLIST', same /24) must
    # survive -- the substring 'MYLIST 1.2.3.' occurs inside its row.
    printf 'MYLIST 1.2.3.4/32\nXMYLIST 1.2.3.9/32\n' > "${masterfile}"
    # A GeoIP miss routes the offender down the block path (empty ${ccheck}).
    make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'removes only the offender alias rows, keeping a sibling alias in the same /24'
    When call reputation_dmax
    The status should be success
    The stdout should include "Reputation - dMax Stats"
    # The offender's own /24 rows were subtracted (removal actually ran)...
    The contents of file "${masterfile}" should not include "MYLIST 1.2.3.4/32"
    # ...but the sibling alias's row -- merely a substring match -- is untouched.
    The contents of file "${masterfile}" should include "XMYLIST 1.2.3.9/32"
  End
End

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
