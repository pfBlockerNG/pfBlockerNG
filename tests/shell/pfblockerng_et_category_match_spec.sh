#shellcheck shell=sh
# processet() ET IQRisk category selection (issue #713 bug 6). etblock/etmatch are
# ", "-separated category-name lists (see the `sed 's/,/, /g'` transform near the
# top of the script); processet() used to test membership with a bare substring
# glob (`case "${etblock}" in *$list*)`), so selecting 'ET_P2Pcnc' also matched
# the unrelated 'ET_P2P' category (its name is a literal substring of
# 'ET_P2Pcnc') and wrongly pulled ET_P2P's IPs into the block output too. The fix
# pads both sides with the ", " delimiter and anchors on it, so only the exact
# selected token matches. This suite pins the fixed (anchored) behaviour
# end-to-end through processet(), and separately proves the 'x' no-selection
# sentinel still matches nothing real.

Describe 'processet() ET category selection (issue #713 bug 6)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/etcat.XXXXXX")"
    pfborig="${work}/orig/"
    etdir="${work}/ET"
    pfbmatch="${work}/match"
    pfbmatchgen="${work}/match/generated/"
    mkdir -p "$pfborig" "$etdir" "$pfbmatch" "$pfbmatchgen"
    tempfile="${work}/t1"; tempfile2="${work}/t2"
    alias='MYLIST'
    ip_placeholder='240.0.0.0'
    ip_placeholder2="$(echo "${ip_placeholder}" | sed 's/\./\\\./g')"
    # ET_P2P is category 15, ET_P2Pcnc is category 31 in processet()'s etcat
    # position table (1-based index into the etcat word list) -- both are
    # "in use" categories (neither sits in the 8|11|12|14|18|22|32|36 skip set).
    printf '10.0.0.15,15,50\n10.0.0.31,31,60\n' > "${pfborig}${alias}.orig"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  # Scenario: selecting ET_P2Pcnc alone must not also pull in ET_P2P.
  #   Given .orig rows for BOTH ET_P2P (category 15) and ET_P2Pcnc (category 31),
  #   When  processet runs with etblock='ET_P2Pcnc' (etmatch='x' = none selected),
  #   Then  only ET_P2Pcnc's IP survives into the rewritten .orig -- ET_P2P's IP,
  #         which a bare substring match would have pulled in too, does not.
  Describe 'etblock selects one category whose name is a substring of another'
    It 'starts with both categories present in the unprocessed .orig'
      When call cat "${pfborig}${alias}.orig"
      The output should include '10.0.0.15,15,'
      The output should include '10.0.0.31,31,'
    End

    It 'blocks only the exact selected category (ET_P2Pcnc), not the substring sibling ET_P2P'
      etblock='ET_P2Pcnc'
      etmatch='x'
      When call processet
      The status should be success
      The stdout should include 'Block:   ET_P2Pcnc'
      The stdout should not include 'Block:   ET_P2P '
      The contents of file "${pfborig}${alias}.orig" should include '10.0.0.31'
      The contents of file "${pfborig}${alias}.orig" should not include '10.0.0.15'
    End
  End

  # Same anchoring bug, symmetric on the etmatch side (bug 6 explicitly requires
  # both case statements fixed identically).
  Describe 'etmatch selects one category whose name is a substring of another'
    It 'matches only the exact selected category (ET_P2Pcnc), not the substring sibling ET_P2P'
      etblock='x'
      etmatch='ET_P2Pcnc'
      When call processet
      The status should be success
      # The selected token matches exactly; the substring sibling ET_P2P must not
      # (matching the etblock case's stdout check + closing the shellspec output gap).
      The stdout should include 'Match:   ET_P2Pcnc'
      The stdout should not include 'Match:   ET_P2P '
      The path "${pfbmatchgen}/pfB_Match_ET_v4.txt" should be file
      The contents of file "${pfbmatchgen}/pfB_Match_ET_v4.txt" should include '10.0.0.31'
      The contents of file "${pfbmatchgen}/pfB_Match_ET_v4.txt" should not include '10.0.0.15'
    End
  End

  # The 'x' no-selection sentinel (both etblock and etmatch absent -> literal 'x',
  # see pfblockerng.inc's `?: 'x'` default) must still match nothing real: no ET
  # category is ever literally named 'x', but a naive unpadded anchor could still
  # accidentally line up on a bare 'x' substring somewhere in a real token.
  Describe 'the x no-selection sentinel'
    It 'blocks nothing and writes no pfB_Match_ET_v4.txt when neither is selected'
      etblock='x'
      etmatch='x'
      When call processet
      The status should be success
      # No category selected -> processet emits neither a Block nor a Match row
      # (closes the shellspec unchecked-output gap for the sentinel case).
      The stdout should not include 'Block:'
      The stdout should not include 'Match:'
      The path "${pfbmatchgen}/pfB_Match_ET_v4.txt" should not be exist
      The contents of file "${pfborig}${alias}.orig" should not include '10.0.0.15'
      The contents of file "${pfborig}${alias}.orig" should not include '10.0.0.31'
    End
  End

  # issue #1250: a user Match-type list literally headed 'ETMatch' collides
  # with processet()'s own ET artifact under the single ${pfbmatch} namespace
  # -- the ET write must never touch a pre-existing user file, and lands in
  # ${pfbmatchgen} instead.
  Describe 'a pre-existing user Match-list ETMatch.txt survives processet() (issue #1250)'
    It 'leaves the user file byte-unchanged and writes the ET output to pfbmatchgen instead'
      etblock='x'
      etmatch='ET_P2Pcnc'
      # The user's OWN Match-type list content -- RFC 5737, unrelated to any ET IP.
      printf '203.0.113.77\n' > "${pfbmatch}/ETMatch.txt"
      before_content="$(cat "${pfbmatch}/ETMatch.txt")"

      When call processet
      The status should be success
      The stdout should include 'Match:   ET_P2Pcnc'
      The value "$before_content" should equal '203.0.113.77'
      The contents of file "${pfbmatch}/ETMatch.txt" should equal '203.0.113.77'
      The contents of file "${pfbmatchgen}/pfB_Match_ET_v4.txt" should include '10.0.0.31'
      The contents of file "${pfbmatchgen}/pfB_Match_ET_v4.txt" should not include '10.0.0.15'
    End
  End
End
