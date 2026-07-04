#shellcheck shell=sh
# shard_modules_spec.sh — pins scripts/shard-modules.sh (issue #797), the pure
# round-robin module splitter that lets the live-VM smoke suite fan out across
# N parallel shards (CI legs / local boxes) at MODULE granularity.
#
# RED->GREEN evidence: this suite was run BEFORE scripts/shard-modules.sh
# existed and failed 15/15 (every example — the generic "invalid input"
# stderr checks assert the specific field name, e.g. 'shard-index', so even
# they fail on the missing-script "No such file or directory" message rather
# than passing vacuously). After implementing the script, the same 15
# examples pass with no other change to this file — proving the suite
# exercises the real script, not a tautology.
#
# No git operations here (pure filesystem + text), so no scrub_git_env is
# needed — see tests/shell/README.md / git-env-scrub-guard.sh clause 2.

Describe 'shard-modules.sh'
  SCRIPT="${PFB_ROOT}/scripts/shard-modules.sh"

  # Build a fixture dir (under shellspec's own tmpbase, never repo state) with:
  #   - 5 direct-child modules: test_a.py test_b.py test_c.py test_d.py test_e.py
  #   - a ui/ subdir with its own test_zz.py (must NEVER be picked up)
  #   - a non-matching file (conftest.py)
  setup() {
    fixture_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/shard-modules-fixture.XXXXXX")"
    : > "${fixture_dir}/test_a.py"
    : > "${fixture_dir}/test_b.py"
    : > "${fixture_dir}/test_c.py"
    : > "${fixture_dir}/test_d.py"
    : > "${fixture_dir}/test_e.py"
    : > "${fixture_dir}/conftest.py"
    mkdir -p "${fixture_dir}/ui"
    : > "${fixture_dir}/ui/test_zz.py"
  }
  cleanup() { rm -rf "${fixture_dir}"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  shard() { sh "$SCRIPT" "${fixture_dir}" "$1" "$2"; }

  Describe 'round-robin assignment (total=2, sorted order a,b,c,d,e)'
    It 'gives shard 0 the even-indexed modules (a, c, e)'
      When call shard 0 2
      The output should equal "${fixture_dir}/test_a.py
${fixture_dir}/test_c.py
${fixture_dir}/test_e.py"
    End

    It 'gives shard 1 the odd-indexed modules (b, d)'
      When call shard 1 2
      The output should equal "${fixture_dir}/test_b.py
${fixture_dir}/test_d.py"
    End
  End

  Describe 'partition properties (total=3)'
    It 'reunites to the full sorted module list with no overlap/gap'
      s0="$(shard 0 3)"
      s1="$(shard 1 3)"
      s2="$(shard 2 3)"
      union="$(printf '%s\n%s\n%s\n' "$s0" "$s1" "$s2" | LC_ALL=C sort)"
      expected="$(printf '%s\n' "${fixture_dir}/test_a.py" "${fixture_dir}/test_b.py" \
        "${fixture_dir}/test_c.py" "${fixture_dir}/test_d.py" "${fixture_dir}/test_e.py" | LC_ALL=C sort)"
      When call printf '%s' "$union"
      The output should equal "$expected"
    End

    It 'keeps shards pairwise disjoint (line count sums to the total module count)'
      s0_n="$(shard 0 3 | wc -l | tr -d ' ')"
      s1_n="$(shard 1 3 | wc -l | tr -d ' ')"
      s2_n="$(shard 2 3 | wc -l | tr -d ' ')"
      When call expr "$s0_n" + "$s1_n" + "$s2_n"
      The output should equal '5'
    End
  End

  Describe 'total=1'
    It 'puts every module in the single shard 0'
      When call shard 0 1
      The output should equal "${fixture_dir}/test_a.py
${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_d.py
${fixture_dir}/test_e.py"
    End
  End

  Describe 'determinism'
    It 'produces byte-identical output across two invocations with the same args'
      first="$(shard 1 3)"
      When call shard 1 3
      The output should equal "$first"
    End
  End

  Describe 'ui/ exclusion'
    It 'never emits ui/test_zz.py in any shard, across every shard of total=4'
      all_output="$(shard 0 4; shard 1 4; shard 2 4; shard 3 4)"
      When call printf '%s' "$all_output"
      The output should not include 'ui/test_zz.py'
    End
  End

  Describe 'error handling'
    It 'rejects a shard-index >= shard-total'
      When run shard 3 3
      The status should be failure
      The stderr should include 'shard-index'
    End

    It 'rejects a negative shard-index'
      When run shard -1 3
      The status should be failure
      The stderr should include 'shard-index'
    End

    It 'rejects shard-total 0'
      When run shard 0 0
      The status should be failure
      The stderr should include 'shard-total'
    End

    It 'rejects a non-numeric shard-index'
      When run shard notanumber 3
      The status should be failure
      The stderr should include 'shard-index'
    End

    It 'rejects a non-numeric shard-total'
      When run shard 0 notanumber
      The status should be failure
      The stderr should include 'shard-total'
    End

    It 'rejects a missing test-dir'
      When run sh "$SCRIPT" "${fixture_dir}/does-not-exist" 0 1
      The status should be failure
      The stderr should include 'not found'
    End

    It 'rejects a dir with zero matching test_*.py modules'
      empty_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/shard-modules-empty.XXXXXX")"
      When run sh "$SCRIPT" "$empty_dir" 0 1
      The status should be failure
      The stderr should include 'no test_*.py modules'
    End

    It 'rejects a shard-total large enough to leave the requested shard EMPTY'
      # 5 modules, total=6, index=5 -> every shard has at most 1 module (0..4);
      # shard 5 would be empty -- must error, never a silent empty success.
      When run shard 5 6
      The status should be failure
      The stderr should include 'empty'
    End
  End
End
