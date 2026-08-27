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
# RED->GREEN evidence (#855): the "per-test duration rows" Describe block
# below was run against the PRE-#855 script (module sums only) and failed --
# the old script never emitted a `module::test` line at all, so every
# per-test assertion missed. After adding per-test rows (same source lines,
# no new log format), the examples pass with the module-sum examples above
# unchanged (same line numbers/values), proving the addition is additive.
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

  # These assert by "should include" rather than a positional "line N", since
  # #855 interleaves each module's per-test rows directly after its own sum
  # row (see the "per-test duration rows" + "sort order" Describes below) --
  # a positional check would break on the interleaving alone, not on a real
  # regression in the summed value.
  Describe 'per-module duration sums (single file)'
    It 'sums setup+call+teardown into one total for test_alpha.py'
      When call rows "$log_a"
      The output should include 'test_alpha.py 4.00'
    End

    It 'sums the single call phase for test_beta.py'
      When call rows "$log_a"
      The output should include 'test_beta.py 3.25'
    End

    It 'attributes a class-based nodeid (module::Class::test) to its MODULE, not the class'
      When call rows "$log_a"
      The output should include 'test_gamma.py 1.11'
    End
  End

  Describe 'multi-file input sums across files'
    It 'adds the second file test_alpha.py call onto the first file total'
      When call rows "$log_a" "$log_b"
      The output should include 'test_alpha.py 4.50'
    End

    It 'adds the second file test_beta.py teardown onto the first file total'
      When call rows "$log_a" "$log_b"
      The output should include 'test_beta.py 4.00'
    End
  End

  Describe 'per-test duration rows (issue #855)'
    # log_a + log_b together give test_alpha.py TWO distinct tests
    # (test_one, test_other) and test_beta.py the SAME test (test_two) split
    # across both files -- the per-test row must sum across files exactly
    # like the module row does, and a class-based nodeid's test id keeps its
    # own embedded `::` verbatim.
    It 'emits a per-test row for test_alpha.py::test_one, summed within one file'
      When call rows "$log_a" "$log_b"
      The output should include 'test_alpha.py::test_one 4.00'
    End

    It 'emits a separate per-test row for the second test in the same module (test_other)'
      When call rows "$log_a" "$log_b"
      The output should include 'test_alpha.py::test_other 0.50'
    End

    It 'sums test_beta.py::test_two across BOTH files into one per-test row'
      When call rows "$log_a" "$log_b"
      The output should include 'test_beta.py::test_two 4.00'
    End

    It 'keeps the class-based nodeid test id verbatim (TestFoo::test_bar)'
      When call rows "$log_a" "$log_b"
      The output should include 'test_gamma.py::TestFoo::test_bar 1.11'
    End
  End

  Describe 'a parametrized nodeid containing a space (issue #861 nitpick)'
    # pytest node ids from string params may embed a literal space (e.g.
    # test_x.py::test_foo[hello world]) -- capturing "the next token" instead
    # of "to end of line" would truncate the row at that space, corrupting
    # both the key (silently dropping "world]") and, downstream, whatever
    # reads the table by a fixed field position.
    setup_spaced() {
      log_spaced="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/module-durations-spaced.XXXXXX")"
      ci_line '12.30s' call 'tests/smoke/test_sp.py::test_foo[hello world]' > "$log_spaced"
    }
    cleanup_spaced() { rm -f "$log_spaced"; }
    BeforeEach 'setup_spaced'
    AfterEach 'cleanup_spaced'

    It 'keeps the full bracketed id, space included, in the per-test row'
      When call rows "$log_spaced"
      The output should include 'test_sp.py::test_foo[hello world] 12.30'
    End

    It 'sums the same spaced id into the module row too'
      When call rows "$log_spaced"
      The output should include 'test_sp.py 12.30'
    End
  End

  Describe 'sort order (LC_ALL=C by module name, module row before its own test rows)'
    It 'emits module sums and per-test rows interleaved: alpha (+2 tests), beta (+1 test), gamma (+1 test)'
      When call rows "$log_a" "$log_b"
      The output should equal "test_alpha.py 4.50
test_alpha.py::test_one 4.00
test_alpha.py::test_other 0.50
test_beta.py 4.00
test_beta.py::test_two 4.00
test_gamma.py 1.11
test_gamma.py::TestFoo::test_bar 1.11"
    End
  End

  Describe 'locale independence (issue #861 nitpick: LC_ALL=C on the awk stage)'
    # Best-effort, never-flaky demonstration (mirrors
    # pfblockerng_adr26_locale_spec.sh's pattern): a comma-decimal locale's
    # printf "%.2f" emits "4,00" instead of "4.00" unless the awk stage pins
    # LC_ALL=C itself -- skip (never fail) if this libc has none installed.
    comma_decimal_locale() {
      for loc in de_DE.UTF-8 fr_FR.UTF-8 es_ES.UTF-8 it_IT.UTF-8 pt_BR.UTF-8; do
        if LC_ALL="$loc" awk 'BEGIN { printf "%.2f", 1.5 }' 2>/dev/null | grep -q ','; then
          printf '%s' "$loc"
          return 0
        fi
      done
      # No comma-decimal locale on this libc: emit nothing, rc 0 -- the caller's
      # `Skip if [ -z "$loc" ]` is the signal. A nonzero rc here aborts the whole
      # example under ShellSpec's errexit shell (bit the CI runner, PR #861).
      true
    }

    It 'keeps dotted-decimal output even under an ambient comma-decimal locale'
      loc="$(comma_decimal_locale)"
      Skip if 'no comma-decimal locale installed on this box to demonstrate the guard' [ -z "$loc" ]
      When call env LC_ALL="$loc" sh "$SCRIPT" "$log_a"
      The output should include 'test_alpha.py 4.00'
      The output should not include ','
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
