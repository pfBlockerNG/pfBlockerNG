#shellcheck shell=sh
# issue #3154: closingprocess()'s dedup-mode probes re-sorted what they had just
# sorted. mastercat got a numeric octet sort (sort -t . -k1,1n ...) whose ordering
# no consumer reads -- every reader is a grep/awk set operation and the file is
# re-cut from masterfile next pass -- and s3 then sorted it AGAIN to feed uniq -d;
# the deny folder was concatenated and walked twice, once for the count (s2) and
# once sorted for the duplicate listing (s4). One C sort per side now feeds both
# probes. What the sanity check REPORTS -- the PASSED/FAILED line and the two
# duplicate listings, placeholder rows included in the masterfile listing and
# excluded from the deny listing -- must be unchanged.

Describe 'closingprocess() dedup-mode sort trim (#3154)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/closingsort.XXXXXX")"
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    pfbmatchgen="${pfbmatch}generated/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative" "$pfbmatchgen"
    pfsensealias="${work}/alias/"; mkdir -p "$pfsensealias"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    alias="on"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  closing_then_mastercat() {
    closingprocess > /dev/null
    cat "$mastercat"
  }

  deny_concat_count() {
    sed -n '/^closingprocess()/,/^}/p' "${PFB_PKGDIR}/pfblockerng.sh" |
      grep -c 'find "${pfbdeny}"'
  }

  It 'leaves mastercat in byte order, not octet-numeric order (C1)'
    # Given a mastercat whose rows sort differently by byte than by octet value
    # (9. before 10. numerically; 10. before 9. by byte).
    printf 'A 9.0.0.0\nB 10.0.0.1\nC 192.0.2.1\n' > "$masterfile"
    printf '192.0.2.1\n9.0.0.0\n10.0.0.1\n'       > "$mastercat"

    # When the final report runs.
    When call closing_then_mastercat

    # Then the file is left sorted the one way the duplicate probe reads it --
    # LC_ALL=C -- with no row lost.
    The status should be success
    The lines of stdout should equal 3
    The line 1 of stdout should equal '10.0.0.1'
    The line 2 of stdout should equal '192.0.2.1'
    The line 3 of stdout should equal '9.0.0.0'
  End

  It 'reports both duplicate listings and PASSED when the counts match (C2)'
    # Given a duplicate inside mastercat and the same row in two different deny
    # files, with the masterfile and deny-folder counts still equal.
    printf 'A 1.2.3.4\nA 1.2.3.4\nB 5.6.7.8\n' > "$masterfile"
    printf '1.2.3.4\n1.2.3.4\n5.6.7.8\n'       > "$mastercat"
    printf '1.2.3.4\n5.6.7.8\n' > "${pfbdeny}A.txt"
    printf '1.2.3.4\n'          > "${pfbdeny}B.txt"

    # When the final report runs.
    When call closingprocess

    # Then the sanity check passes and each listing names the duplicate directly
    # under its own heading.
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stdout should include "$(printf 'Masterfile/Deny folder uniq check\n1.2.3.4')"
    The stdout should include "$(printf 'Deny folder/Masterfile uniq check\n1.2.3.4')"
  End

  It 'keeps the placeholder out of the deny listing but not the masterfile one (C3)'
    # Given the empty-list placeholder duplicated on both sides: s3 reports it,
    # s4 filters it out -- an asymmetry the rewrite must not level.
    printf 'A 127.0.0.1\nA 127.0.0.1\nB 1.2.3.4\n' > "$masterfile"
    printf '127.0.0.1\n127.0.0.1\n1.2.3.4\n'       > "$mastercat"
    printf '127.0.0.1\n1.2.3.4\n' > "${pfbdeny}A.txt"
    printf '127.0.0.1\n'          > "${pfbdeny}B.txt"

    # When the final report runs.
    When call closingprocess

    # Then only the masterfile listing names it; the deny listing is empty and the
    # placeholder-free counts still match.
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stdout should include "$(printf 'Masterfile/Deny folder uniq check\n127.0.0.1')"
    The stdout should include "$(printf 'Deny folder/Masterfile uniq check\n\nSync check')"
  End

  It 'sorts each side once: no numeric octet sort, one deny concatenation (C4)'
    # Given the sourced script's closingprocess() body.
    When run sh -c 'sed -n "/^closingprocess()/,/^}/p" "${PFB_PKGDIR}/pfblockerng.sh"'

    # Then the extraction was real, the octet sort is gone, and the deny folder is
    # concatenated once for both probes.
    The status should be success
    The output should include 'closingprocess()'
    The output should not include 'sort -t .'
    The output should include 'uniq -d'
    The result of function deny_concat_count should equal 1
  End
End
