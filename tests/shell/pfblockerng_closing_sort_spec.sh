#shellcheck shell=sh
# issue #3154: closingprocess()'s dedup probes now sort each side once -- mastercat in
# place, the deny folder into tempfile -- and read those files. What the sanity check
# REPORTS must not move: the PASSED/FAILED line with both counts, and the two duplicate
# listings, placeholder rows kept in the masterfile listing and dropped from the deny one.

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

  closing_body() {
    sed -n '/^closingprocess()/,/^}/p' "${PFB_PKGDIR}/pfblockerng.sh"
  }

  deny_concat_count() {
    closing_body | grep -c 'find "${pfbdeny}"'
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
    When call closing_body

    # Then the extraction was real, the octet sort is gone, and the deny folder is
    # concatenated once for both probes.
    The status should be success
    The output should include 'closingprocess()'
    The output should not include 'sort -t .'
    The output should include 'uniq -d'
    The result of function deny_concat_count should equal 1
  End

  It 'reports FAILED with both counts when the two sides disagree (C5)'
    # Given a deny folder holding one row more than mastercat -- the mismatch the check
    # exists to catch, and the only branch that prints s2 as a number.
    printf 'A 1.2.3.4\n'         > "$masterfile"
    printf '1.2.3.4\n'           > "$mastercat"
    printf '1.2.3.4\n5.6.7.8\n'  > "${pfbdeny}A.txt"

    # When the final report runs.
    When call closingprocess

    # Then the verdict flips and each side's count is named.
    The status should be success
    The stdout should include 'Database Sanity check [  FAILED  ]'
    The stdout should include 'Masterfile Count    [ 1 ]'
    The stdout should include 'Deny folder Count   [ 2 ]'
  End

  It 'never reports PASSED when the deny concatenation cannot be written (C6)'
    # Given the same real mismatch, plus a `sort` that writes part of its output and
    # exits nonzero -- what an exhausted tmpdir does (partial write, exit 2). Truncation
    # only ever LOWERS the deny count, so it can drag s2 down onto s1 and print PASSED
    # over a genuine mismatch; the sanity verdict is mirrored into the GUI dedup ledger
    # by pfb_sync_status_dedup_check(), so a false PASSED closes a key that must stay open.
    printf 'A 1.2.3.4\n'  > "$masterfile"
    printf '1.2.3.4\n'    > "$mastercat"
    printf '1.2.3.4\n'    > "${pfbdeny}A.txt"
    printf '5.6.7.8\n'    > "${pfbdeny}B.txt"
    mkdir -p "${work}/bin"
    real_sort="$(command -v sort)"
    {
      printf '#!/bin/sh\n'
      printf 'case " $* " in *" -o "*) exec %s "$@" ;; esac\n' "$real_sort"
      printf '%s "$@" | head -1\nexit 2\n' "$real_sort"
    } > "${work}/bin/sort"
    chmod +x "${work}/bin/sort"
    PATH="${work}/bin:${PATH}"

    # When the final report runs.
    When call closingprocess

    # Then no count is reported from the short write, the verdict stays FAILED, and the
    # failure is logged instead of being papered over.
    The status should be success
    The stdout should not include 'PASSED'
    The stdout should include 'Database Sanity check [  FAILED  ]'
    The stdout should include 'deny folder concatenation'
    The contents of the file "$errorlog" should include 'sanity counts unreliable'
  End
End
