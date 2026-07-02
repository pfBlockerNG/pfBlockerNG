#shellcheck shell=sh
# pfblockerng.sh secure temp-file handling — locks the issue #30 fix (predictable
# /tmp paths replaced by a private mktemp -d directory).

Describe 'pfblockerng.sh secure temp files (issue #30)'
  BeforeAll 'pfb_source'

  Describe 'pfb_make_tmpdir'
    It 'creates a private mktemp directory and points the temp vars inside it'
      When call pfb_make_tmpdir
      The variable tmpdir should match pattern "*/pfb.*"
      The path "$tmpdir" should be directory
      The variable tempfile should equal "${tmpdir}/pfbtemp1"
      The variable tempmatchfile should equal "${tmpdir}/pfbtemp8"
      # mktemp -d must create the directory mode 0700 (no group/other access).
      The value "$(ls -ld "$tmpdir" | cut -c1-10)" should equal "drwx------"
    End

    # issue #714: the XLSX scratch dir used to be a fixed, predictable /tmp/xlsx/
    # path (TOCTOU/symlink risk for this root-run script). It must now live
    # INSIDE the private per-run mktemp dir, not at a fixed /tmp location.
    It 'folds the xlsx scratch dir inside the private tmpdir (issue #714)'
      When call pfb_make_tmpdir
      The variable tmpxlsx should match pattern "*/pfb.*/xlsx/"
      # Containment: tmpxlsx must sit under this run's own tmpdir, not /tmp/xlsx/.
      The variable tmpxlsx should match pattern "${tmpdir}/xlsx/"
    End
  End

  Describe 'exitnow'
    It 'removes its per-run temp directory'
      dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbexit.XXXXXX")"
      touch "${dir}/pfbtemp1"
      When run run_exitnow_on "$dir"
      The status should be success
      The path "$dir" should not be exist
    End
  End
End
