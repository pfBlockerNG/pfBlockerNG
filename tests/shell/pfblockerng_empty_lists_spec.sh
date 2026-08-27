#shellcheck shell=sh
# closingprocess()'s "Empty Lists" report names the DENY-LIST FILE whose sole
# content is the placeholder IP -- not the placeholder IP itself. grep only
# emits a "path:" prefix when given >=2 file args, so a deny glob that
# resolves to exactly ONE file used to return the bare match line (the
# placeholder), and `cut -d ':' -f1` picked that up instead of the filename
# (issue #844).

Describe 'closingprocess() Empty Lists report names the file, not the matched IP (#844)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/emptylists.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative"
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

  It 'names the sole file when the deny glob resolves to exactly ONE list'
    # Given a single deny-list file whose only content is the placeholder IP.
    printf '%s\n' "$ip_placeholder2" > "${pfbdeny}LONEFEED.txt"

    # When the final report runs.
    When call closingprocess

    # Then the Empty Lists section names the file, not the bare placeholder IP.
    The status should be success
    The stdout should include 'LONEFEED.txt'
    The stdout should not include "$ip_placeholder2"
  End

  It 'names each file when the deny glob resolves to MULTIPLE lists'
    # Given two deny-list files, both emptied down to the placeholder IP.
    printf '%s\n' "$ip_placeholder2" > "${pfbdeny}FeedA.txt"
    printf '%s\n' "$ip_placeholder2" > "${pfbdeny}FeedB.txt"

    # When the final report runs.
    When call closingprocess

    # Then both files are named in the Empty Lists section.
    The status should be success
    The stdout should include 'FeedA.txt'
    The stdout should include 'FeedB.txt'
  End
End
