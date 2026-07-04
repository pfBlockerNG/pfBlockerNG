#shellcheck shell=sh
# local_smoke_spec.sh — shellspec suite for scripts/local-smoke.sh --shards N
# (issue #797, work item 3): concurrent multi-box module sharding.
#
# TOPOLOGY UNDER TEST:
#   A fake select-box.sh (PFB_SELECT_BOX testability seam) records the full
#   "-- <bootstrap>" string of every invocation to its own file under a shared
#   CALLS_DIR, then exits 0 unless a per-shard fail marker file is present —
#   letting each example assert both WHICH invocations happened and HOW MANY,
#   with no real ssh/box/pytest involved (fully hermetic, per sibling specs).
#
# RED→GREEN evidence: before local-smoke.sh parses --shards, the flag falls
# through the `-*) unknown flag; exit 2` arm — EVERY example below that
# expects N invocations, per-shard --shard/--shard-total tagging, or a
# passing multi-shard exit 0 FAILS pre-change (0 calls recorded, exit 2
# instead of the expected exit code). The N=1-default and the flag-validation
# guards (--filter, non-smoke --marker, non-integer/zero --shards) also fail
# pre-change for the same reason (any --shards flag at all is "unknown").
# After implementation those flip to green; the N=1-compat examples
# independently confirm --shards changes nothing when N=1 or absent.

Describe 'local-smoke.sh --shards'
  SCRIPT="${PFB_ROOT}/scripts/local-smoke.sh"

  setup() {
    scrub_git_env
    unset PFB_REF
    WORK="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/localsmokespec.XXXXXX")"
    CALLS_DIR="${WORK}/calls"
    mkdir -p "$CALLS_DIR"

    # Fake select-box.sh: records "-- <bootstrap>" to a unique file under
    # CALLS_DIR, then fails iff a fail-<shard-index> marker exists under WORK.
    # Never touches ssh/PFB_BOXES — local-smoke.sh still requires PFB_BOXES
    # set (a dummy value), but this fake never reads it.
    FAKE_SELECT_BOX="${WORK}/fake-select-box.sh"
    cat > "$FAKE_SELECT_BOX" <<'FAKEEOF'
#!/bin/sh
_call_file="$(mktemp "${CALLS_DIR}/call.XXXXXX")"
printf '%s\n' "$*" > "$_call_file"
_shard_idx="$(printf '%s' "$*" | sed -n "s/.*--shard '\([0-9]*\)'.*/\1/p")"
if [ -n "$_shard_idx" ] && [ -f "${WORK}/fail-${_shard_idx}" ]; then
    exit 1
fi
exit 0
FAKEEOF
    chmod +x "$FAKE_SELECT_BOX"

    # Keep the "kept" shard-logs mktemp dir INSIDE WORK (hermetic: teardown's
    # rm -rf "$WORK" cleans it up instead of leaving debris under real /tmp).
    TMPDIR="$WORK"

    PFB_SELECT_BOX="$FAKE_SELECT_BOX"
    PFB_BOXES="dummy@dummy"
    export PFB_SELECT_BOX PFB_BOXES WORK CALLS_DIR TMPDIR
  }

  teardown() {
    rm -rf "$WORK"
  }

  BeforeEach 'setup'
  AfterEach  'teardown'

  # ── Helpers ────────────────────────────────────────────────────────────── #
  call_count() { find "$CALLS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }

  # Run local-smoke.sh with the given args and print three diagnostic blocks:
  # line 1 = exit=<rc>, line 2 = calls=<N recorded select-box invocations>,
  # remaining lines = the combined stdout+stderr (for substring/"include"
  # checks) followed by every recorded call's bootstrap string (for
  # --shard/--shard-total tagging checks).
  run_and_diag() {
    _out="$(sh "$SCRIPT" "$@" 2>&1)"
    _rc=$?
    printf 'exit=%s\n' "$_rc"
    printf 'calls=%s\n' "$(call_count)"
    printf '%s\n' "$_out"
    cat "$CALLS_DIR"/* 2>/dev/null
    return 0   # diagnostics-only function; assertions read the printed lines, not $?
  }

  # ── --shards 3: three concurrent invocations, each correctly shard-tagged ── #
  Describe '--shards 3'
    It 'launches exactly 3 select-box invocations, each tagged with its shard index and total'
      When call run_and_diag --ref dummy --shards 3
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=3'
      The output should include "--shard '0'"
      The output should include "--shard '1'"
      The output should include "--shard '2'"
      The output should include "--shard-total '3'"
      # every shard still carries the usual ref/abi/marker flags
      The output should include "--ref 'dummy'"
      The output should include "--marker 'smoke'"
    End
  End

  # ── N=1 compat pin: no --shards flag ─ byte-identical to pre-#797 ────────── #
  Describe 'no --shards flag (default N=1)'
    It 'makes a single select-box invocation with no --shard tagging at all'
      When call run_and_diag --ref dummy
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should not include "--shard "
    End
  End

  # ── N=1 compat pin: explicit --shards 1 ─ same as no flag ────────────────── #
  Describe '--shards 1 (explicit)'
    It 'behaves exactly like no flag: a single untagged select-box invocation'
      When call run_and_diag --ref dummy --shards 1
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=1'
      The output should not include "--shard "
    End
  End

  # ── --shards 2, all shards pass → exit 0 ──────────────────────────────────── #
  Describe '--shards 2, both shards pass'
    It 'aggregates to exit 0 with both shards launched'
      When call run_and_diag --ref dummy --shards 2
      The line 1 of output should equal 'exit=0'
      The line 2 of output should equal 'calls=2'
    End
  End

  # ── --shards 2, one shard fails → non-zero exit, but BOTH shards ran ─────── #
  # Assert-the-before-state discipline: the all-pass example above already
  # proves exit=0 when nothing fails, so THIS example genuinely proves the
  # failure path flips the aggregate result rather than always reporting 0.
  run_shards2_one_fails() {
    : > "${WORK}/fail-1"   # shard index 1 fails; shard 0 must still run
    run_and_diag --ref dummy --shards 2
  }

  Describe '--shards 2, shard 1 fails'
    It 'exits non-zero AND still ran the passing shard (both invocations recorded)'
      When call run_shards2_one_fails
      The line 1 of output should not equal 'exit=0'
      The line 2 of output should equal 'calls=2'
    End
  End

  # ── --shards N>1 + --filter: refused before any invocation ────────────────── #
  Describe '--shards 2 --filter x'
    It 'exits 2 and never invokes select-box.sh (empty-slice hazard)'
      When call run_and_diag --ref dummy --shards 2 --filter x
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'filter'
    End
  End

  # ── --shards N>1 + non-smoke --marker: refused before any invocation ─────── #
  Describe '--shards 2 --marker repo'
    It 'exits 2 and never invokes select-box.sh (non-default markers select few tests)'
      When call run_and_diag --ref dummy --shards 2 --marker repo
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'marker'
    End
  End

  # ── --shards garbage: rejected by the case guard ──────────────────────────── #
  Describe '--shards abc'
    It 'exits 2 (non-integer) and never invokes select-box.sh'
      When call run_and_diag --ref dummy --shards abc
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include 'positive integer'
    End
  End

  # ── --shards 0: passes the digit check, fails the >=1 check ──────────────── #
  Describe '--shards 0'
    It 'exits 2 (zero is not a positive integer) and never invokes select-box.sh'
      When call run_and_diag --ref dummy --shards 0
      The line 1 of output should equal 'exit=2'
      The line 2 of output should equal 'calls=0'
      The output should include '>= 1'
    End
  End

End
