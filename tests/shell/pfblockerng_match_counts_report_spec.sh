#shellcheck shell=sh
# closingprocess()'s "Match List IP Counts" section must stay keyed on the match
# .txt files that actually exist, and must still count the machine-generated
# artifacts after issue #1250 moved them into match/generated/. The section's
# guard used to test the match dir for ANY entry, which the always-present
# generated/ subdir alone satisfies -- printing an empty section forever.

Describe 'closingprocess() Match List IP Counts section (#1250)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/matchcounts.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    # Production creates the generated/ subdir unconditionally on every run
    # (pfblockerng.sh), so the sandbox has it too -- that is the whole point.
    pfbmatchgen="${pfbmatch}generated/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative" "$pfbmatchgen"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    alias="off"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'omits the section entirely when no Match list and no generated artifact exists'
    # Given a box with no Match-type lists at all -- only the empty generated/
    # subdir production always creates.

    # When the final report runs.
    When call closingprocess

    # Then no Match section is printed: an empty subdir is not a Match list.
    The status should be success
    The stdout should not include 'Match List IP Counts'
  End

  It "counts a user's Match list and a generated artifact side by side"
    # Given one user Match-type list file and one machine-generated artifact,
    # each now living in its own directory.
    printf '198.51.100.0/24\n' > "${pfbmatch}Ads_v4.txt"
    printf '192.0.2.0/24\n'    > "${pfbmatchgen}pfB_Match_Rep_Spam_v4.txt"

    # When the final report runs.
    When call closingprocess

    # Then the section appears and names BOTH -- the relocation must not drop the
    # reputation counts out of the update log.
    The status should be success
    The stdout should include 'Match List IP Counts'
    The stdout should include 'Ads_v4.txt'
    The stdout should include 'pfB_Match_Rep_Spam_v4.txt'
  End
End
