#shellcheck shell=sh
# issue #3165: closingprocess()'s deny-folder concatenation must refuse a verdict when the
# PRODUCER breaks, not just when the write does. `if <pipeline>` observes only the last
# stage, so a deny file awk could not open -- or a name `find | xargs` mis-split -- left
# `sort` exit 0 over partial input, and the resulting low count read as agreement with the
# masterfile. That verdict is not display-only: pfb_sync_status_dedup_check() closes the
# ip/dedup ledger key on PASSED.

Describe 'closingprocess() deny concatenation producer status (#3165)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/closingproducer.XXXXXX")"
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

  # A deny folder holding 4 rows across two files, against a mastercat holding only the
  # single row the FIRST file contributes: a producer that gives up after that file lands
  # the deny count exactly on the masterfile count, so the report agrees with itself while
  # three rows on disk were never read.
  hidden_mismatch_fixture() {
    printf 'A 1.2.3.4\n' > "$masterfile"
    printf '1.2.3.4\n'   > "$mastercat"
    printf '1.2.3.4\n'                   > "${pfbdeny}A.txt"
    printf '5.6.7.8\n9.9.9.9\n7.7.7.7\n' > "${pfbdeny}B.txt"
  }

  It 'refuses a verdict when the concatenation cannot read every deny file (S1)'
    # Given that hidden mismatch and an `awk` that aborts on the second file after emitting
    # what it already read -- what one-true-awk does on a file it cannot open (FATAL, exit
    # 2), which on the appliance is a deny file left mode-000 by a failed write.
    hidden_mismatch_fixture
    mkdir -p "${work}/bin"
    real_awk="$(command -v awk)"
    {
      printf '#!/bin/sh\n'
      printf 'case " $* " in\n'
      printf '\t*" %sB.txt "*)\n' "$pfbdeny"
      printf '\t\t%s 1 %sA.txt\n' "$real_awk" "$pfbdeny"
      printf '\t\techo "awk: cannot open \\"%sB.txt\\" (Permission denied)" >&2\n' "$pfbdeny"
      printf '\t\texit 2 ;;\n'
      printf 'esac\n'
      printf 'exec %s "$@"\n' "$real_awk"
    } > "${work}/bin/awk"
    chmod +x "${work}/bin/awk"
    PATH="${work}/bin:${PATH}"

    # When the final report runs.
    When call closingprocess

    # Then the count says `incomplete` rather than the partial stream's total, the verdict
    # stays FAILED, and the failure is logged -- the producer really did fail (stderr).
    The status should be success
    The stdout should not include 'PASSED'
    The stdout should include 'Database Sanity check [  FAILED  ]'
    The stdout should include 'Deny folder Count   [ incomplete ]'
    The stdout should include 'deny folder concatenation'
    The stderr should include 'cannot open'
    The contents of the file "$errorlog" should include 'sanity counts unreliable'
  End

  It 'refuses a verdict when a deny file is genuinely unreadable (S2)'
    # Given the same hidden mismatch with the real fault instead of a shim: the second deny
    # file is mode-000, so the concatenation reads one row of the four on disk.
    Skip if 'root bypasses file permissions, so a mode-000 file stays readable' [ "$(id -u)" -eq 0 ]
    hidden_mismatch_fixture
    chmod 000 "${pfbdeny}B.txt"

    # When the final report runs.
    When call closingprocess

    # Then the same refusal, driven by a permission denial no shim manufactured.
    The status should be success
    The stdout should not include 'PASSED'
    The stdout should include 'Database Sanity check [  FAILED  ]'
    The stdout should include 'Deny folder Count   [ incomplete ]'
    The stderr should include 'B.txt'
    The contents of the file "$errorlog" should include 'sanity counts unreliable'
  End

  It 'counts a deny file whose name holds whitespace (S3)'
    # Given a deny filename with a space in it -- what a list header carrying one produces
    # -- holding two of the masterfile's three rows.
    printf 'A 1.2.3.4\nB 5.6.7.8\nB 9.9.9.9\n' > "$masterfile"
    printf '1.2.3.4\n5.6.7.8\n9.9.9.9\n'       > "$mastercat"
    printf '1.2.3.4\n'          > "${pfbdeny}A.txt"
    printf '5.6.7.8\n9.9.9.9\n' > "${pfbdeny}B C.txt"

    # When the final report runs.
    When call closingprocess

    # Then its rows are counted like any other file's -- the sides agree, and nothing
    # complained about a fragment of the name.
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stderr should equal ''
  End

  It 'concatenates nothing when the deny folder is empty (S4)'
    # Given no deny files at all: an unmatched glob must still yield an empty concatenation
    # and a zero count, never a refusal and never a read of the caller's stdin.
    true > "$masterfile"
    true > "$mastercat"

    # When the final report runs.
    When call closingprocess

    # Then the two empty sides agree.
    The status should be success
    The stdout should include 'Database Sanity check [  PASSED  ]'
    The stderr should equal ''
  End
End
