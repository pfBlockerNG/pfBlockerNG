#shellcheck shell=sh
# module_durations_spec.sh — pins scripts/module-durations.sh (issue #816), the
# generator that turns pytest `--durations=0` CI log output into a per-module
# duration table (the DATA side of balancing the smoke-suite module sharding
# by measured LOAD instead of blind round-robin; the LPT consumer is a
# separate step and not covered here).
#
# RED->GREEN evidence: this suite was run BEFORE scripts/module-durations.sh
# existed (the script temporarily renamed aside) and failed 10 of 11 examples
# outright plus 1 WARNING -- every "When call"/"When run" invocation hit "No
# such file or directory" from the missing script rather than the asserted
# table/error output, so the failures are the real absence, not a tautology.
# After implementing the script, all 11 examples pass with no other change
# to this file.
#
# No git operations here (pure filesystem + text), so no scrub_git_env is
# needed -- see tests/shell/README.md / git-env-scrub-guard.sh clause 2.

Describe 'module-durations.sh'
  SCRIPT="${PFB_ROOT}/scripts/module-durations.sh"

  # Two fixture log files, CI-prefixed like a real `pytest -m smoke` job log
  # (tab-separated step columns before the timestamp + payload). Duration
  # lines cover: multiple phases for one module (setup+call+teardown), a
  # class-based nodeid (module::TestClass::test_method -- must sum under the
  # MODULE, not split on the second "::"), a module split across both files
  # (multi-file summation), and interleaved noise lines that must be ignored.
  ci_line() {
    # $1=duration (e.g. "1.00s") $2=phase $3=nodeid
    printf 'Smoke (CE 2.8 shard 1/2) / pytest -m smoke (live pfSense VM)\tUNKNOWN STEP\t2026-07-04T08:16:37.0000000Z %s %s     %s\n' \
      "$1" "$2" "$3"
  }

  setup() {
    log_a="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-a.XXXXXX")"
    log_b="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-b.XXXXXX")"

    {
      printf '##[group]Run pytest\n'
      ci_line '1.00s' setup 'tests/smoke/test_alpha.py::test_one'
      ci_line '2.50s' call 'tests/smoke/test_alpha.py::test_one'
      ci_line '0.50s' teardown 'tests/smoke/test_alpha.py::test_one'
      ci_line '3.25s' call 'tests/smoke/test_beta.py::test_two'
      ci_line '1.11s' call 'tests/smoke/test_gamma.py::TestFoo::test_bar'
      printf 'Results (192 passed, 0 failed) in 456.78s\n'
      printf '##[endgroup]\n'
    } > "$log_a"

    {
      ci_line '0.50s' call 'tests/smoke/test_alpha.py::test_other'
      ci_line '0.75s' teardown 'tests/smoke/test_beta.py::test_two'
      printf 'some unrelated CI noise line with 9.99s in it but no phase keyword\n'
    } > "$log_b"

    noise_only="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-noise.XXXXXX")"
    printf 'no duration lines here at all\n' > "$noise_only"
  }
  cleanup() { rm -f "$log_a" "$log_b" "$noise_only"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  gen() { sh "$SCRIPT" "$@"; }

  # Strip the generated-by header (deterministic text, not the data under
  # test here) so these assertions pin the TABLE contract, not the wording.
  rows() { gen "$@" | grep -v '^#'; }

  Describe 'per-module duration sums (single file)'
    It 'sums setup+call+teardown into one total for test_alpha.py'
      When call rows "$log_a"
      The line 1 of output should equal 'test_alpha.py 4.00'
    End

    It 'sums the single call phase for test_beta.py'
      When call rows "$log_a"
      The line 2 of output should equal 'test_beta.py 3.25'
    End

    It 'attributes a class-based nodeid (module::Class::test) to its MODULE, not the class'
      When call rows "$log_a"
      The line 3 of output should equal 'test_gamma.py 1.11'
    End
  End

  Describe 'multi-file input sums across files'
    It 'adds the second file test_alpha.py call onto the first file total'
      When call rows "$log_a" "$log_b"
      The line 1 of output should equal 'test_alpha.py 4.50'
    End

    It 'adds the second file test_beta.py teardown onto the first file total'
      When call rows "$log_a" "$log_b"
      The line 2 of output should equal 'test_beta.py 4.00'
    End
  End

  Describe 'sort order (LC_ALL=C by module name)'
    It 'emits modules alphabetically: alpha, beta, gamma'
      When call rows "$log_a" "$log_b"
      The output should equal "test_alpha.py 4.50
test_beta.py 4.00
test_gamma.py 1.11"
    End
  End

  Describe 'noise lines'
    It 'ignores non-duration lines (no phantom rows, no crash)'
      When call gen "$log_a" "$log_b"
      The output should not include '9.99'
      The output should not include 'endgroup'
      The output should not include 'Results ('
    End
  End

  Describe 'determinism'
    It 'produces byte-identical output across two invocations with the same args'
      first="$(gen "$log_a" "$log_b")"
      When call gen "$log_a" "$log_b"
      The output should equal "$first"
    End
  End

  Describe 'error handling'
    It 'rejects being called with no arguments'
      When run sh "$SCRIPT"
      The status should be failure
      The stderr should include 'usage'
    End

    It 'rejects an unreadable input file'
      When run sh "$SCRIPT" "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-does-not-exist.log"
      The status should be failure
      The stderr should include 'cannot read'
    End

    It 'rejects input with zero duration lines across all files'
      When run gen "$noise_only"
      The status should be failure
      The stderr should include 'no duration lines'
    End

    It 'rejects a directory passed as an input file (readable but not a regular file)'
      dir_input="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-dir.XXXXXX")"
      When run sh "$SCRIPT" "$dir_input"
      The status should be failure
      The stderr should include 'cannot read'
    End
  End
End
