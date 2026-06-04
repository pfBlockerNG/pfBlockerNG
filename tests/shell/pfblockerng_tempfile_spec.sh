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
