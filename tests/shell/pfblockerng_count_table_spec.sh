#shellcheck shell=sh
# pfb_count_table() renders the closing report's per-file line counts (wc -l
# shaped: right-aligned count, path, 'total' row, sorted descending) but counts
# with `grep -c ^` so an unterminated final line is counted -- the row #3151
# found `wc -l` undercounting. closingprocess() must have no `wc -l` left.

Describe 'pfb_count_table (#3151)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/counttable.XXXXXX")"
  }
  cleanup() { rm -rf "$work"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'renders a wc -l shaped table for two files (C1: total first, then descending)'
    # Given two files (one with a space in its name) holding 2 and 1 lines.
    printf '1.2.3.4\n5.6.7.8\n' > "${work}/my list.txt"
    printf '9.9.9.9\n'          > "${work}/other.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/my list.txt" "${work}/other.txt"

    # Then exactly three rows appear, total first, sorted descending.
    The status should be success
    The lines of stdout should equal 3
    The line 1 of stdout should equal '       3 total'
    The line 2 of stdout should equal "       2 ${work}/my list.txt"
    The line 3 of stdout should equal "       1 ${work}/other.txt"
  End

  It 'counts an unterminated final line that wc -l would drop (C2)'
    # Given a file whose last line has no trailing newline -- exactly the row
    # `wc -l` gets wrong (it would report 1).
    printf 'x\ny' > "${work}/unterminated.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/unterminated.txt"

    # Then the count is 2, not 1.
    The status should be success
    The stdout should include "       2 ${work}/unterminated.txt"
  End

  It 'renders a single file as one row with no total, like wc -l (C3)'
    # Given one file whose contents include a line that itself reads like a
    # grep "path:count" output line.
    printf 'hello\n/dev/null: 5\n' > "${work}/solo.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/solo.txt"

    # Then exactly one row shows -- wc -l prints no total for a single file --
    # and the real file survives even though its content resembles the prefix.
    The status should be success
    The lines of stdout should equal 1
    The line 1 of stdout should equal "       2 ${work}/solo.txt"
  End

  It 'reports an empty file as a single 0 row (C4)'
    # Given an empty list file.
    true > "${work}/empty.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/empty.txt"

    # Then the file is present in the table with count 0 and no total row.
    The status should be success
    The lines of stdout should equal 1
    The line 1 of stdout should equal "       0 ${work}/empty.txt"
  End

  It 'prints nothing and succeeds with no arguments (C5)'
    # Given no file arguments at all.
    When call pfb_count_table

    # Then there is neither output nor an error.
    The status should be success
    The stdout should equal ''
    The stderr should equal ''
  End

  It 'ignores an unmatched glob beside a real file, without leaking stderr (C6)'
    # Given a literal nonexistent path (an unmatched glob passes through
    # exactly as today) alongside a real file.
    printf '1.1.1.1\n' > "${work}/real.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/missing*.txt" "${work}/real.txt"

    # Then only the real file's row appears, plus the total wc -l prints whenever
    # it was handed more than one argument -- even one that does not exist.
    The status should be success
    The lines of stdout should equal 2
    The stdout should include "       1 ${work}/real.txt"
    The stdout should include '       1 total'
    The stderr should equal ''
  End

  It 'keeps a path containing a colon whole (C7)'
    # Given a file whose name itself contains a colon.
    mkdir -p "${work}/dir"
    printf 'a\nb\nc\n' > "${work}/dir/a:b.txt"

    # When the table is rendered.
    When call pfb_count_table "${work}/dir/a:b.txt"

    # Then the one row shows the full path (only the trailing :count is stripped).
    The status should be success
    The lines of stdout should equal 1
    The line 1 of stdout should equal "       3 ${work}/dir/a:b.txt"
  End

  It "reports the 'Deny List IP Counts' section with the grep -c count for an unterminated deny file (C8)"
    # Given the closingprocess sandbox with one deny file lacking a trailing
    # newline: wc -l would print 1, grep -c ^ must print 2.
    pfborig="${work}/orig/"; pfbdeny="${work}/deny/"
    pfbpermit="${work}/permit/"; pfbmatch="${work}/match/"; pfbnative="${work}/native/"
    pfbmatchgen="${pfbmatch}generated/"
    mkdir -p "$pfborig" "$pfbdeny" "$pfbpermit" "$pfbmatch" "$pfbnative" "$pfbmatchgen"
    pfsensealias="${work}/alias/"; mkdir -p "$pfsensealias"
    masterfile="${work}/masterfile"; mastercat="${work}/mastercat"
    tempfile="${work}/t1"; errorlog="${work}/err.log"; now="now"
    ip_placeholder2="127.0.0.1"
    alias="off"
    pathpfctl="${work}/pfctl"; printf '#!/bin/sh\n' > "$pathpfctl"; chmod +x "$pathpfctl"
    printf '1.2.3.4\n5.6.7.8' > "${pfbdeny}Deny1.txt"

    # When the final report runs.
    When call closingprocess

    # Then the Deny section reports the full count of 2.
    The status should be success
    The stdout should include 'Deny List IP Counts'
    The stdout should include "       2 ${pfbdeny}Deny1.txt"
  End

  It 'leaves no wc -l in closingprocess() (C9)'
    # Given the sourced script's closingprocess() body.
    When run sed -n '/^closingprocess()/,/^}/p' "${PFB_PKGDIR}/pfblockerng.sh"

    # Then the extraction was real and every table is counted by the helper.
    The output should include 'closingprocess()'
    The output should include 'pfb_count_table'
    The output should not include 'wc -l'
  End

  It 'still reports a deny-folder duplicate under the dedup sanity check (C10)'
    # Given the closingprocess sandbox in dedup mode (alias=on) with the same IP in
    # two deny files: the "Deny folder/Masterfile uniq check" probe (s4) must name it.
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
    printf 'A 1.2.3.4\nB 5.6.7.8\n' > "$masterfile"
    printf '1.2.3.4\n5.6.7.8\n' > "$mastercat"
    printf '1.2.3.4\n' > "${pfbdeny}A.txt"
    printf '1.2.3.4\n5.6.7.8\n' > "${pfbdeny}B.txt"

    # When the final report runs.
    When call closingprocess

    # Then the duplicate is listed right after the deny-folder uniq check heading.
    The status should be success
    The stdout should include 'Deny folder/Masterfile uniq check'
    The stdout should include "$(printf 'Deny folder/Masterfile uniq check\n1.2.3.4')"
  End
End
