#shellcheck shell=sh
# shard_modules_spec.sh — pins scripts/shard-modules.sh (issues #797, #816):
# the module splitter that lets the live-VM smoke suite fan out across N
# parallel shards (CI legs / local boxes) at MODULE granularity, either by
# plain round-robin (no `module-durations.txt` in the fixture dir) or by
# duration-balanced greedy LPT (the table is present).
#
# RED->GREEN evidence (#797): this suite was run BEFORE scripts/shard-modules.sh
# existed and failed 15/15 (every example — the generic "invalid input"
# stderr checks assert the specific field name, e.g. 'shard-index', so even
# they fail on the missing-script "No such file or directory" message rather
# than passing vacuously). After implementing the script, the same 15
# examples pass with no other change to this file — proving the suite
# exercises the real script, not a tautology.
#
# RED->GREEN evidence (#816): the "duration-balanced LPT" Describe block
# below was run against the PRE-#816 (round-robin-only) script and failed on
# every table-sensitive assertion — the old script ignores the fixture's
# `module-durations.txt` entirely, so it still emits the round-robin split
# (a,c,e | b,d) instead of the LPT split the examples assert. The 15
# table-less examples above stayed green throughout, unchanged, proving the
# round-robin fallback is untouched by the LPT addition.
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

  Describe 'duration-balanced LPT (module-durations.txt present, issue #816)'
    # Writes/overwrites module-durations.txt in the fixture dir; every It
    # below calls this itself right before invoking shard(), so no example
    # depends on another's table content (self-encapsulated per the
    # test-coverage mandate).
    write_table() {
      : > "${fixture_dir}/module-durations.txt"
      for line in "$@"; do
        printf '%s\n' "$line" >> "${fixture_dir}/module-durations.txt"
      done
    }

    Describe 'LPT beats round-robin (the headline red->green case)'
      # a is 10x heavier than b..e -- round-robin (a,c,e | b,d) would split
      # a's load across both shards; LPT must isolate it alone on shard 0.
      It 'puts the one heavy module (a) alone on shard 0'
        write_table 'test_a.py 100.00' 'test_b.py 10.00' 'test_c.py 10.00' \
          'test_d.py 10.00' 'test_e.py 10.00'
        When call shard 0 2
        The output should equal "${fixture_dir}/test_a.py"
      End

      It 'puts the four light modules (b,c,d,e) together on shard 1'
        write_table 'test_a.py 100.00' 'test_b.py 10.00' 'test_c.py 10.00' \
          'test_d.py 10.00' 'test_e.py 10.00'
        When call shard 1 2
        The output should equal "${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_d.py
${fixture_dir}/test_e.py"
      End
    End

    It 'ignores comment and blank lines in the table'
      write_table '# generated table' '' 'test_a.py 100.00' '' \
        '# a trailing comment' 'test_b.py 10.00' 'test_c.py 10.00' \
        'test_d.py 10.00' 'test_e.py 10.00'
      When call shard 0 2
      The output should equal "${fixture_dir}/test_a.py"
    End

    Describe 'a module absent from the table gets the 0.01 epsilon weight'
      # c, d, e have no row at all; a/b's real weights (50/40) still
      # dominate, so the epsilon trio lands deterministically alongside b
      # (the currently-lighter-loaded shard) on shard 1.
      It 'keeps the heaviest listed module (a) alone on shard 0'
        write_table 'test_a.py 50.00' 'test_b.py 40.00'
        When call shard 0 2
        The output should equal "${fixture_dir}/test_a.py"
      End

      It 'puts b plus the three unlisted (epsilon-weight) modules on shard 1'
        write_table 'test_a.py 50.00' 'test_b.py 40.00'
        When call shard 1 2
        The output should equal "${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_d.py
${fixture_dir}/test_e.py"
      End
    End

    It 'ignores a stale row for a module no longer present in the dir'
      write_table 'test_a.py 100.00' 'test_b.py 10.00' 'test_c.py 10.00' \
        'test_d.py 10.00' 'test_e.py 10.00' 'test_removed.py 999.00'
      s0="$(shard 0 2)"
      s1="$(shard 1 2)"
      When call printf '%s\n---\n%s' "$s0" "$s1"
      The output should equal "${fixture_dir}/test_a.py
---
${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_d.py
${fixture_dir}/test_e.py"
    End

    Describe 'partition properties with a table (total=3)'
      It 'reunites to the full sorted module list with no overlap/gap'
        write_table 'test_a.py 50.00' 'test_b.py 40.00' 'test_c.py 30.00' \
          'test_d.py 20.00' 'test_e.py 10.00'
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
        write_table 'test_a.py 50.00' 'test_b.py 40.00' 'test_c.py 30.00' \
          'test_d.py 20.00' 'test_e.py 10.00'
        s0_n="$(shard 0 3 | wc -l | tr -d ' ')"
        s1_n="$(shard 1 3 | wc -l | tr -d ' ')"
        s2_n="$(shard 2 3 | wc -l | tr -d ' ')"
        When call expr "$s0_n" + "$s1_n" + "$s2_n"
        The output should equal '5'
      End
    End

    It 'produces byte-identical output across two invocations with the same args'
      write_table 'test_a.py 50.00' 'test_b.py 40.00' 'test_c.py 30.00' \
        'test_d.py 20.00' 'test_e.py 10.00'
      first="$(shard 1 3)"
      When call shard 1 3
      The output should equal "$first"
    End

    It 'gives every one of 5 shards exactly one module when every weight is the epsilon fallback'
      write_table '# header only -- no data rows'
      all="$(shard 0 5; shard 1 5; shard 2 5; shard 3 5; shard 4 5)"
      sorted_all="$(printf '%s\n' "$all" | LC_ALL=C sort)"
      expected="$(printf '%s\n' "${fixture_dir}/test_a.py" "${fixture_dir}/test_b.py" \
        "${fixture_dir}/test_c.py" "${fixture_dir}/test_d.py" "${fixture_dir}/test_e.py" | LC_ALL=C sort)"
      When call printf '%s' "$sorted_all"
      The output should equal "$expected"
    End

    It 'still rejects a shard-total large enough to leave the requested shard EMPTY'
      write_table '# header only -- no data rows'
      When run shard 5 6
      The status should be failure
      The stderr should include 'empty'
    End

    Describe 'an assignment-affecting weight tie resolves by path ASC (deterministic)'
      # b and c tie at 50; the path-ascending tiebreak must process b first,
      # so b lands on shard 0 and c on shard 1. The epsilon trio (a, d, e)
      # then alternates from the re-tied loads: a->0, d->1, e->0. Pins the
      # sort's secondary key -- without it a tie's order (and therefore the
      # whole assignment) would be implementation-defined.
      It 'puts the first-by-path tied module (b) plus a,e on shard 0'
        write_table 'test_b.py 50.00' 'test_c.py 50.00'
        When call shard 0 2
        The output should equal "${fixture_dir}/test_a.py
${fixture_dir}/test_b.py
${fixture_dir}/test_e.py"
      End

      It 'puts the second-by-path tied module (c) plus d on shard 1'
        write_table 'test_b.py 50.00' 'test_c.py 50.00'
        When call shard 1 2
        The output should equal "${fixture_dir}/test_c.py
${fixture_dir}/test_d.py"
      End
    End

    It 'clamps a zero, negative, or non-numeric row to the 0.01 epsilon (documented input class)'
      # a=0, b=negative, c=non-numeric -- all three clamp to epsilon, so only
      # d carries real weight and sits alone on shard 0; everything else
      # (including the row-less e) balances onto shard 1.
      write_table 'test_a.py 0.00' 'test_b.py -5.00' 'test_c.py junk' \
        'test_d.py 50.00'
      s0="$(shard 0 2)"
      s1="$(shard 1 2)"
      When call printf '%s\n---\n%s' "$s0" "$s1"
      The output should equal "${fixture_dir}/test_d.py
---
${fixture_dir}/test_a.py
${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_e.py"
    End

    It 'takes the LAST row when the table lists the same module twice (last-wins)'
      # First a=1.00 would spread the load (a would ride shard 0 with b,d);
      # the later a=100.00 must override it, reproducing the headline split.
      write_table 'test_a.py 1.00' 'test_b.py 10.00' 'test_c.py 10.00' \
        'test_d.py 10.00' 'test_e.py 10.00' 'test_a.py 100.00'
      When call shard 0 2
      The output should equal "${fixture_dir}/test_a.py"
    End

    Describe 'a test-dir containing a space (LPT mode round-trips full paths)'
      # The LPT pipeline carries "<path>\t<weight>" records, so a space in
      # the dir must survive intact -- pre-fix the whitespace-split pass
      # truncated the path at the space and emitted silently-wrong output.
      space_setup() {
        space_dir="${fixture_dir}/sub dir"
        mkdir -p "$space_dir"
        : > "${space_dir}/test_a.py"
        : > "${space_dir}/test_b.py"
        : > "${space_dir}/test_c.py"
        printf '%s\n' 'test_a.py 100.00' 'test_b.py 10.00' 'test_c.py 10.00' \
          > "${space_dir}/module-durations.txt"
      }
      BeforeEach 'space_setup'

      It 'emits the heavy module with its full space-containing path on shard 0'
        When call sh "$SCRIPT" "$space_dir" 0 2
        The output should equal "${space_dir}/test_a.py"
      End

      It 'emits the light modules with their full space-containing paths on shard 1'
        When call sh "$SCRIPT" "$space_dir" 1 2
        The output should equal "${space_dir}/test_b.py
${space_dir}/test_c.py"
      End
    End
  End
End
