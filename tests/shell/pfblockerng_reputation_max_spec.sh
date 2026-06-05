#shellcheck shell=sh
# reputation_max() match-output filename — locks the issue #27 fix (the pre-fix
# code built the match filename from a stale $header global and removed a stale
# file via a relative path instead of the absolute ${pfbmatch} path).

Describe 'reputation_max() match output (issue #27)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/repmax.XXXXXX")"
    pfbdeny="${work}/deny/"
    pfbmatch="${work}/match/"
    mkdir -p "$pfbdeny" "$pfbmatch"
    tempfile="${work}/t1"; tempfile2="${work}/t2"
    dupfile="${work}/t3"; matchfile="${work}/t7"; tempmatchfile="${work}/t8"
    pathgeoip="${work}/mmdblookup"
    pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
    now="now"
    count=0; countb=0; counts=0; countr=0
    dedup="off"; ccwhite="match"; ccblack="off"; cc="US"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'cleans a stale match file by alias-derived name under ${pfbmatch} (no repeat offenders)'
    alias="MYLIST"
    max=999999
    printf '1.2.3.4\n1.2.3.5\n9.9.9.9\n' > "${pfbdeny}${alias}.txt"
    # Stale match output the run must clean up at its absolute ${pfbmatch} path.
    printf 'old\n' > "${pfbmatch}match${alias}.txt"
    When call reputation_max
    The status should be success
    The path "${pfbmatch}match${alias}.txt" should not be exist
  End

  It 'writes match output to ${pfbmatch}match<alias>.txt (repeat offenders, ccwhite=match)'
    alias="MYLIST"
    max=1
    make_geoip_stub "$pathgeoip" 'xx iso_code: "US" xx'
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${pfbdeny}${alias}.txt"
    When call reputation_max
    The status should be success
    The path "${pfbmatch}match${alias}.txt" should be file
    The contents of file "${pfbmatch}match${alias}.txt" should include "1.2.3.0/24"
    The stdout should include "Reputation -Max Stats"
  End

  It 'blocks (does NOT match) a repeat offender when the GeoIP country lookup misses'
    # Regression: a failed GeoIP lookup yields an empty ${ccheck}. The pre-fix
    # code used an unquoted *${ccheck}* case pattern, which collapsed to '**' and
    # matched every ${cc} — so an unknown-country repeat offender was wrongly
    # routed to the match/whitelist path instead of being blocked. With the fix it
    # must take the block path (mirroring the "country not in ${cc}" default).
    #
    # Paired with the country-match case above: same input, the only difference is
    # whether GeoIP resolves a country — proving the classification is a real
    # branch, not an always-match path.
    alias="MYLIST"
    max=1
    # A mmdblookup miss prints "Could not find ..."; after the script's
    # `grep -v 'Could\|Got\|^$'` filter, ${ccheck} is empty.
    make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
    printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n' > "${pfbdeny}${alias}.txt"
    When call reputation_max
    The status should be success
    # Not matched/whitelisted: no match-output file is produced for this alias.
    The path "${pfbmatch}match${alias}.txt" should not be exist
    # Counted as a blocked repeat-offender range (the block branch ran).
    The stdout should include "Reputation -Max Stats"
  End
End
