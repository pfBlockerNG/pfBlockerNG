#shellcheck shell=sh
# Feed-token matching during IP-list processing. The reputation/suppress/process
# loops derive octet-prefix tokens from list data and splice them into `grep`.
# Previously only the literal dot was escaped, so any other regex metacharacter
# in a token stayed live and grep treated it as a pattern -- an over-broad /
# incorrect match. The fix validates each token to a digits/dots (CIDR: + slash)
# shape and drops a non-conforming one, then matches the survivor as an exact
# anchored literal. This suite pins BOTH branches: a well-formed token still
# matches its intended lines, and a metachar-bearing token is dropped (matches
# nothing).

Describe 'feed-token shape guards'
  BeforeAll 'pfb_source'

  # Trivial mapping: assert each side of the digits/dots membership rule.
  Describe 'pfb_is_octet_prefix'
    It 'accepts a digits-and-dots octet prefix'
      When call pfb_is_octet_prefix '10.0.0'
      The status should be success
    End
    It 'accepts a prefix with a trailing dot (the form written to the dup/match files)'
      When call pfb_is_octet_prefix '10.0.0.'
      The status should be success
    End
    It 'rejects a token carrying a regex metacharacter'
      When call pfb_is_octet_prefix '10.0.*'
      The status should be failure
    End
    It 'rejects a token with an alternation/anchor metacharacter'
      When call pfb_is_octet_prefix '10|^9'
      The status should be failure
    End
    It 'rejects a slash (an octet prefix carries no mask)'
      When call pfb_is_octet_prefix '10.0.0/24'
      The status should be failure
    End
    It 'rejects the empty string'
      When call pfb_is_octet_prefix ''
      The status should be failure
    End
  End

  Describe 'pfb_is_cidr_token'
    It 'accepts a digits/dots/slash CIDR token'
      When call pfb_is_cidr_token '10.0.0.1/32'
      The status should be success
    End
    It 'rejects a token carrying a regex metacharacter'
      When call pfb_is_cidr_token '10.0.0.*'
      The status should be failure
    End
    It 'rejects the empty string'
      When call pfb_is_cidr_token ''
      The status should be failure
    End
  End

  # The escaper turns a validated prefix into an anchored, dot-escaped BRE. Once
  # the caller has validated the token to digits/dots, this is the ONLY pattern
  # text that reaches grep -- so it must escape every dot and anchor at '^'.
  Describe 'pfb_anchor_octet_pattern'
    It 'anchors at line start and escapes every dot'
      When call pfb_anchor_octet_pattern '10.0.0.'
      The output should equal '^10\.0\.0\.'
    End
  End
End

# End-to-end through a real list-processing function (reputation_max), driven the
# same way the in-tree reputation specs drive it (sourced library + GeoIP stub).
# This proves the guard+escaper are wired into the production path, not just unit
# correct in isolation.
Describe 'reputation_max() feed-token matching'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/feedtok.XXXXXX")"
    pfbdeny="${work}/deny/"
    pfbmatch="${work}/match/"
    mkdir -p "$pfbdeny" "$pfbmatch"
    tempfile="${work}/t1"; tempfile2="${work}/t2"
    dupfile="${work}/t3"; matchfile="${work}/t7"; tempmatchfile="${work}/t8"
    pathgeoip="${work}/mmdblookup"
    pathgeoipdat="${work}/geo.mmdb"; touch "$pathgeoipdat"
    now="now"
    count=0; countb=0; counts=0; countr=0
    # ccblack=block routes a repeat offender to the block path: the function
    # removes its /24 members from the list and appends a single 'p.q.r.0/24'.
    dedup="off"; ccwhite="off"; ccblack="block"; cc="ZZ"
    alias="MYLIST"
    max=1
    # A GeoIP miss keeps every offender on the block path (country never equals
    # cc=ZZ), so classification cannot divert the test IPs into a match file.
    make_geoip_stub "$pathgeoip" 'Could not find an entry for this IP address'
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  # Scenario: a well-formed octet prefix matches ONLY its own /24, anchored.
  #   Given a list whose '1.2.3.*' members repeat past Max, plus a decoy
  #         '91.2.3.7' that a non-anchored / substring match would wrongly catch,
  #   When  reputation_max runs (the offender token is '1.2.3'),
  #   Then  the three '1.2.3.*' members are replaced by '1.2.3.0/24'
  #   And   the decoy '91.2.3.7' survives untouched (the '^1\.2\.3\.' anchor does
  #         not match it) -- proving the match is anchored and literal.
  Describe 'a well-formed octet prefix (anchored, literal)'
    fixture() { printf '1.2.3.4\n1.2.3.5\n1.2.3.6\n91.2.3.7\n' > "${pfbdeny}${alias}.txt"; }
    Before 'fixture'

    # Before-state: the offender member and the look-alike decoy are both present
    # in the unprocessed list (so the after-state below proves the run caused the
    # change, not a pre-existing absence).
    It 'starts with the offender member and the look-alike decoy present'
      When call cat "${pfbdeny}${alias}.txt"
      The output should include '1.2.3.4'
      The output should include '91.2.3.7'
    End

    It 'collapses only the anchored /24 and leaves the decoy intact'
      When call reputation_max
      The status should be success
      The stdout should include 'Reputation -Max Stats'
      The contents of file "${pfbdeny}${alias}.txt" should include '1.2.3.0/24'
      The contents of file "${pfbdeny}${alias}.txt" should not include '1.2.3.4'
      The contents of file "${pfbdeny}${alias}.txt" should include '91.2.3.7'
    End
  End

  # Scenario: a token carrying a regex metacharacter is DROPPED, never matched.
  #   Given list members whose first three dot-fields contain a '*' ('1.2.*.N'),
  #         so the repeat-offender token is the metachar-bearing '1.2.*', plus a
  #         decoy '1.2.9.9' that a live '^1.2.*' regex would match,
  #   When  reputation_max runs,
  #   Then  the validation drops '1.2.*' (not digits/dots) -> no /24 is produced,
  #         nothing is removed, and the decoy survives -- proving the token is no
  #         longer interpreted as a regex.
  Describe 'a metacharacter-bearing token (dropped)'
    fixture() { printf '1.2.*.4\n1.2.*.5\n1.2.9.9\n' > "${pfbdeny}${alias}.txt"; }
    Before 'fixture'

    # Before-state: the metachar members and the decoy are present unprocessed.
    It 'starts with the metachar members and the decoy present'
      When call cat "${pfbdeny}${alias}.txt"
      The output should include '1.2.*.4'
      The output should include '1.2.9.9'
    End

    It 'drops the token instead of matching as a regex (list unchanged)'
      When call reputation_max
      The status should be success
      The contents of file "${pfbdeny}${alias}.txt" should not include '0/24'
      The contents of file "${pfbdeny}${alias}.txt" should include '1.2.9.9'
      The contents of file "${pfbdeny}${alias}.txt" should include '1.2.*.4'
    End
  End
End
