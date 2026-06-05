#shellcheck shell=sh
# reputation_dmax() GeoIP-country classification — pins the empty-${ccheck}
# (GeoIP miss) branch added alongside the reputation_max() fix. dmax carries the
# same `case "${cc}" in *"${ccheck}"*` country classification and the same
# empty-ccheck guard, so it can regress independently of reputation_max() — this
# suite exercises BOTH sides of that branch in dmax directly.
#
# Paired cases (same input, only the GeoIP result differs):
#   - country resolves (US, cc=US, ccwhite=match) -> the offender is treated as a
#     country match: it lands in the match output, NOT the block dupfile.
#   - GeoIP miss (empty ${ccheck})               -> the offender takes the block
#     path: counted and written (trailing dot) to the dupfile.
# Proving the classification is a real branch, not an always-match path.

Describe 'reputation_dmax() GeoIP classification branch'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/repdmax.XXXXXX")"
    pfbdeny="${work}/deny/"
    pfbmatch="${work}/match/"
    mkdir -p "$pfbdeny" "$pfbmatch"
    tmpdir="${work}"
    tempfile="${work}/t1"; tempfile2="${work}/t2"; dupfile="${work}/t3"
    matchfile="${work}/t7"; tempmatchfile="${work}/t8"
    dedupfile="${work}/d4"; addfile="${work}/d5"; : > "$dedupfile"; : > "$addfile"
    masterfile="${work}/master"; mastercat="${work}/mastercat"
    pathgeoip="${work}/mmdblookup"
    pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
    # ip_placeholder3 (the /24 excluded from the repeat-offender scan) must not
    # match the test /24, or the offender would be filtered out before classify.
    ip_placeholder='240.0.0.0'
    ip_placeholder3="$(echo "${ip_placeholder}" | cut -d '.' -f 1-3)"
    now="now"
    count=0; countb=0; counts=0; countr=0
    dedup="off"; ccwhite="match"; ccblack="off"; cc="US"
    matchdedup="matchdedup_v4.txt"
    max=1
    # One /24 with >max members -> a repeat offender. Mirror it in the masterfile
    # so the block-removal tail of the function runs cleanly.
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${pfbdeny}MYLIST.txt"
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${masterfile}"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'treats a resolved-country offender as a match, NOT a block (no dupfile)'
    make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
    When call reputation_dmax
    The status should be success
    # Country matched ${cc}=US with ccwhite=match -> match output, not the block path.
    The path "${pfbmatch}${matchdedup}" should be file
    The path "${dupfile}" should not be exist
    The stdout should include "Reputation - dMax Stats"
  End

  It 'blocks (writes to the dupfile) when the GeoIP country lookup misses'
    # Regression: an empty ${ccheck} once collapsed *${ccheck}* to '**', matching
    # every ${cc} and mis-routing the offender to the match path. It must block.
    # A mmdblookup miss prints "Could not find ..."; after the script's
    # `grep -v 'Could\|Got\|^$'` filter, ${ccheck} is empty.
    make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
    When call reputation_dmax
    The status should be success
    # Block path ran: the offender /24 is written (trailing dot) to the dupfile.
    The contents of file "${dupfile}" should include "1.2.3."
    The stdout should include "Reputation - dMax Stats"
  End
End
