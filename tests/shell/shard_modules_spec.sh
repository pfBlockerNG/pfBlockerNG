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
# RED->GREEN evidence (#855): the "hybrid test-level split for oversized
# modules" Describe block below was run against the PRE-#855 (whole-module-only
# LPT) script and failed every split-sensitive assertion — the old script has
# no concept of a per-test row or a target threshold, so an oversized module
# always lands whole on one shard (e.g. the headline case put ALL of test_a.py
# on shard 1, never splitting it into node IDs + a deselect-carrier). Every
# other Describe block in this file (round-robin, plain LPT, error handling)
# stayed green throughout, proving the hybrid addition doesn't disturb the
# non-oversized paths.
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

  Describe 'hybrid test-level split for oversized modules (issue #855)'
    # A module whose table weight exceeds the ideal per-shard load
    # (total-weight / shard-total) AND carries per-test rows is split at TEST
    # granularity instead of riding whole on one shard -- the fix for the
    # "one module dominates the shard floor" problem (test_smoke_feeds.py's
    # 789.6s of a 2015s table). All hand-traced against the documented greedy
    # LPT + carrier-selection algorithm before being pinned here.
    #
    # write_table (defined here, at the Describe level, so every It below --
    # nested or direct -- shares it) overwrites/rewrites module-durations.txt
    # in the fixture dir; every It calls it itself right before shard(), so
    # no example depends on another's table content.
    write_table() {
      : > "${fixture_dir}/module-durations.txt"
      for line in "$@"; do
        printf '%s\n' "$line" >> "${fixture_dir}/module-durations.txt"
      done
    }
    write_hybrid_table() {
      write_table 'test_a.py 100.00' 'test_a.py::test_1 40.00' \
        'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
        'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00'
    }

    # Real callers (run-smoke.sh, tests/test_shard_union.py) always pass a
    # test-dir RELATIVE to pytest's rootdir -- an absolute one disables the
    # per-test split entirely (see the dedicated Describe below, which pins
    # that guard). Shadow the outer shard() so every It in this Describe
    # (nested ones included) invokes the script the same relative way a real
    # caller does; fixture_dir itself stays absolute (needed for the direct
    # file writes above and elsewhere in this file), so rel() gives its
    # basename for use in expected output -- recomputed per It since
    # fixture_dir is per-example (BeforeEach 'setup').
    shard() {
      (cd "$(dirname "$fixture_dir")" && sh "$SCRIPT" "$(basename "$fixture_dir")" "$1" "$2")
    }
    rel() { basename "$fixture_dir"; }

    Describe 'oversized module (a) beats target and gets test-level LPT'
      # wsum = 100 (a) + 4*5 (b,c,d,e) = 120; target = 60. a=100 > 60 and has
      # 3 per-test rows -> oversized+splittable. LPT order: a::test_1(40),
      # a::test_2(30), a::test_3(30, tie->sortkey ASC after test_2), then
      # b,c,d,e(5 each, tie->path ASC). Greedy over 2 shards: test_1->0
      # (load 40), test_2->1 (load 30), test_3->1 (load 60, beats shard0's
      # 40), then b,c,d,e all go to shard0 (lighter: 40->45->50->55->60).
      # Final per-a-test weight on shard0=40 (test_1 only), on shard1=60
      # (test_2+test_3) -> shard1 is the carrier (60 > 40).
      It 'gives the non-carrier shard (0) the light whole modules plus ONE node ID (test_1)'
        write_hybrid_table
        r="$(rel)"
        When call shard 0 2
        The output should equal "${r}/test_b.py
${r}/test_c.py
${r}/test_d.py
${r}/test_e.py
${r}/test_a.py::test_1"
      End

      It 'gives the carrier shard (1) the module PATH plus a --deselect pair for the test that rode elsewhere'
        write_hybrid_table
        r="$(rel)"
        When call shard 1 2
        The output should equal "${r}/test_a.py
--deselect
${r}/test_a.py::test_1"
      End

      It 'produces byte-identical output across two invocations (determinism)'
        write_hybrid_table
        first="$(shard 1 2)"
        When call shard 1 2
        The output should equal "$first"
      End

      It 'still rejects a shard-total large enough to leave the requested shard EMPTY (guard survives the split)'
        write_hybrid_table
        # 7 LPT units total (3 a-tests + b,c,d,e) can't fill 8 shards -> shard
        # 7 is empty.
        When run shard 7 8
        The status should be failure
        The stderr should include 'empty'
      End

      It 'takes the LAST row when the table lists the same per-test id twice (last-wins, issue #861 nitpick)'
        # A duplicated per-test row used to APPEND a second LPT unit for the
        # same test id (module rows were already last-wins; per-test rows
        # were not) -- two units sharing one node ID can land on DIFFERENT
        # shards, double-running the test with every shard green. The early,
        # would-be-different test_1=1.00 row must be fully superseded by the
        # later test_1=40.00 row, reproducing the exact write_hybrid_table
        # split (a single test_1 unit at weight 40).
        write_table 'test_a.py 100.00' 'test_a.py::test_1 1.00' \
          'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
          'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00' \
          'test_a.py::test_1 40.00'
        r="$(rel)"
        s0="$(shard 0 2)"
        s1="$(shard 1 2)"
        When call printf '%s\n---\n%s' "$s0" "$s1"
        The output should equal "${r}/test_b.py
${r}/test_c.py
${r}/test_d.py
${r}/test_e.py
${r}/test_a.py::test_1
---
${r}/test_a.py
--deselect
${r}/test_a.py::test_1"
      End
    End

    Describe 'a per-test row whose id contains a space (issue #861 nitpick, table parser)'
      # A parametrized nodeid can carry its own space (e.g.
      # test_foo[hello world], from scripts/module-durations.sh's matching
      # end-of-line fix). The table reader must treat the WEIGHT as the last
      # whitespace field and rejoin everything before it as the key -- a
      # fixed f[1]/f[2] split would take "world]" as the weight (clamped to
      # the 0.01 epsilon) and truncate the key, corrupting the split. Same
      # weights as the headline case above (40/30/30), just test_1 renamed,
      # so the expected assignment is identical.
      It 'places the spaced-id test correctly (weight honored, id untruncated) on the non-carrier shard'
        write_table 'test_a.py 100.00' 'test_a.py::test_foo[hello world] 40.00' \
          'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
          'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00'
        r="$(rel)"
        When call shard 0 2
        The output should equal "${r}/test_b.py
${r}/test_c.py
${r}/test_d.py
${r}/test_e.py
${r}/test_a.py::test_foo[hello world]"
      End

      It 'deselects the spaced-id test, whole and untruncated, from the carrier shard'
        write_table 'test_a.py 100.00' 'test_a.py::test_foo[hello world] 40.00' \
          'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
          'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00'
        r="$(rel)"
        When call shard 1 2
        The output should equal "${r}/test_a.py
--deselect
${r}/test_a.py::test_foo[hello world]"
      End
    End

    It "rides an oversized module WHOLE when it has no per-test rows (can't split what isn't measured per-test)"
      # wsum = 100 (d) + 5 (e) + 3*0.01 (a,b,c epsilon, absent from table) =
      # 105.03; target ~= 52.5. d=100 > target but carries NO per-test row ->
      # must stay a single whole-module unit, never emitting a nodeid/deselect
      # for it. e + the epsilon trio balance onto the other shard.
      write_table 'test_d.py 100.00' 'test_e.py 5.00'
      r="$(rel)"
      When call shard 0 2
      The output should equal "${r}/test_d.py"
    End

    Describe 'prefix-safety fixup: a deselected test id must never be a STRING PREFIX of a surviving sibling'
      # pytest's own --deselect matches by NODE-ID PREFIX, not exact equality
      # (_pytest.main.pytest_collection_modifyitems: `nodeid.startswith(...)`),
      # confirmed for real against this repo's OWN test_smoke_feeds.py, where
      # `test_cron_detects_changed_local_feed` is a literal prefix of the
      # sibling `test_cron_detects_changed_local_feed_same_second` --
      # tests/test_shard_union.py's union oracle caught it. This is the
      # minimal reproduction: test_x (short, light) lands elsewhere; test_xy
      # (long -- literally "test_x"+"y", heavy) naturally stays on the
      # carrier. Deselecting test_x alone would ALSO silently strip test_xy
      # from the carrier's whole-module collection (real pytest behavior) --
      # test_xy must instead be PROMOTED onto test_x's shard too.
      write_prefix_table() {
        write_table 'test_a.py 100.00' 'test_a.py::test_x 1.00' \
          'test_a.py::test_xy 50.00' 'test_b.py 5.00' 'test_c.py 5.00' \
          'test_d.py 5.00' 'test_e.py 5.00'
      }

      It 'deselects BOTH the short prefix test AND its longer sibling from the carrier (shard 0)'
        write_prefix_table
        r="$(rel)"
        When call shard 0 2
        The output should equal "${r}/test_a.py
--deselect
${r}/test_a.py::test_x
--deselect
${r}/test_a.py::test_xy"
      End

      It 'gives the recipient shard (1) BOTH tests as explicit node IDs -- the longer one never silently vanishes'
        write_prefix_table
        r="$(rel)"
        When call shard 1 2
        The output should equal "${r}/test_b.py
${r}/test_c.py
${r}/test_d.py
${r}/test_e.py
${r}/test_a.py::test_x
${r}/test_a.py::test_xy"
      End
    End

    It 'honors SHARD_DURATIONS_FILE to hybrid-split from an injected table even with no on-disk module-durations.txt (test-only override)'
      # The fixture dir has NO module-durations.txt (round-robin's trigger
      # condition), yet the override must force the hybrid LPT path -- proof
      # the override, not the default path, decides the mode. Invoked the
      # same relative way as shard() above (this Describe's opening comment);
      # SHARD_DURATIONS_FILE itself may stay absolute -- only the test-dir
      # ARG is what the absolute-dir guard checks.
      ext_table="$(mktemp "${SHELLSPEC_TMPBASE:-/tmp}/shard-modules-ext.XXXXXX")"
      printf '%s\n' 'test_a.py 100.00' 'test_a.py::test_1 40.00' \
        'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
        'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00' \
        > "$ext_table"
      r="$(rel)"
      # shellcheck disable=SC2016  # intentional: expanded by the child sh -c, not this shell
      When call sh -c 'cd "$1" && SHARD_DURATIONS_FILE="$2" sh "$3" "$4" "$5" "$6"' -- \
        "$(dirname "$fixture_dir")" "$ext_table" "$SCRIPT" "$r" 1 2
      The output should equal "${r}/test_a.py
--deselect
${r}/test_a.py::test_1"
      rm -f "$ext_table"
    End
  End

  Describe 'absolute test-dir (issue #861 nitpick): an oversized module rides WHOLE, never split'
    # pytest's --deselect matches by nodeid PREFIX against ROOTDIR-RELATIVE
    # ids; an absolute dir's carrier --deselect would never match, silently
    # double-running the deselected test. shard-modules.sh guards this by
    # treating an oversized module as unsplittable (ride whole) whenever the
    # test-dir arg is absolute -- exactly like the no-per-test-rows case.
    # fixture_dir (from the outer BeforeEach) is already absolute, so the
    # OUTER shard() (plain "sh $SCRIPT $fixture_dir ...") is what we want
    # here -- no override needed in this Describe.
    write_oversized_table() {
      : > "${fixture_dir}/module-durations.txt"
      printf '%s\n' 'test_a.py 100.00' 'test_a.py::test_1 40.00' \
        'test_a.py::test_2 30.00' 'test_a.py::test_3 30.00' \
        'test_b.py 5.00' 'test_c.py 5.00' 'test_d.py 5.00' 'test_e.py 5.00' \
        >> "${fixture_dir}/module-durations.txt"
    }

    It 'rides the oversized module (a) WHOLE on its assignment shard -- no node ID, no --deselect'
      write_oversized_table
      When call shard 0 2
      The output should equal "${fixture_dir}/test_a.py"
    End

    It 'never emits a bare node ID or --deselect for the oversized module on any other shard'
      write_oversized_table
      When call shard 1 2
      The output should equal "${fixture_dir}/test_b.py
${fixture_dir}/test_c.py
${fixture_dir}/test_d.py
${fixture_dir}/test_e.py"
    End
  End

  Describe 'locale independence (issue #861 nitpick: LC_ALL=C on every awk stage)'
    # Best-effort, never-flaky demonstration (mirrors
    # pfblockerng_adr26_locale_spec.sh's pattern): a comma-decimal locale's
    # printf "%.6f" and numeric coercion ("40,00"+0) would otherwise corrupt
    # weights/tie-breaks unless every awk stage pins LC_ALL=C itself -- skip
    # (never fail) if this libc has none installed.
    write_table() {
      : > "${fixture_dir}/module-durations.txt"
      for line in "$@"; do
        printf '%s\n' "$line" >> "${fixture_dir}/module-durations.txt"
      done
    }
    comma_decimal_locale() {
      for loc in de_DE.UTF-8 fr_FR.UTF-8 es_ES.UTF-8 it_IT.UTF-8 pt_BR.UTF-8; do
        if LC_ALL="$loc" awk 'BEGIN { printf "%.2f", 1.5 }' 2>/dev/null | grep -q ','; then
          printf '%s' "$loc"
          return 0
        fi
      done
      return 1
    }

    It 'produces the SAME split under an ambient comma-decimal locale as under C'
      # Weights carry a fractional part that MATTERS to the tie-break: under
      # a comma-decimal locale, an unguarded awk's string-to-number coercion
      # truncates a dotted-decimal table value at the '.' (verified live:
      # "100.51" + 0 reads as 100 under de_DE.UTF-8's LC_NUMERIC), which would
      # tie test_a.py/test_b.py at weight 50 and flip their assignment order
      # (untruncated: b(50.99) beats a(50.01), b->shard0; truncated tie:
      # path-ASC tiebreak puts a->shard0 instead) -- the LC_ALL=C awk fix
      # keeps the table's real C-locale values intact regardless of the
      # ambient locale, so shard 0's winner must be identical either way.
      write_table 'test_a.py 50.01' 'test_b.py 50.99'
      loc="$(comma_decimal_locale)"
      Skip if 'no comma-decimal locale installed on this box to demonstrate the guard' [ -z "$loc" ]
      # Baseline forced to LC_ALL=C: on a comma-decimal AMBIENT shell an
      # inherited-locale baseline would equal the injected run even with the
      # inline awk guard removed, false-passing this regression (review #861).
      baseline="$(env LC_ALL=C sh "$SCRIPT" "${fixture_dir}" 0 2)"
      When call env LC_ALL="$loc" sh "$SCRIPT" "${fixture_dir}" 0 2
      The output should equal "$baseline"
    End
  End
End
