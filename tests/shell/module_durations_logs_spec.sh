#shellcheck shell=sh
# module_durations_logs_spec.sh — pins scripts/module-durations-logs.sh (issue
# #901; #910 review), the selector that picks ONE CE version's
# pytest-durations.log files out of an extracted smoke-artifacts tree for
# module-durations.sh. The table's contract allows exactly one full-suite leg,
# and the supported window normally holds TWO GA CE versions (ci-metadata
# drop_ce policy), so the selector must pick the numeric-minimum CE version —
# never fail on the steady state, never mix legs, and fail LOUDLY on zero
# logs or artifact-name drift.
#
# RED->GREEN evidence: this suite was authored against the #910 first-cut
# behaviour (inline workflow guard that hard-failed on ANY multi-CE-version
# artifact set and did not exist as a script). Run before the script existed,
# every example failed with "No such file or directory"; the multi-version
# example additionally pins the behaviour CHANGE (select min, rc 0) that the
# first-cut guard (exit 1) would fail.
#
# No git operations here (pure filesystem), so no scrub_git_env is needed.

Describe 'module-durations-logs.sh'
  SCRIPT="${PFB_ROOT}/scripts/module-durations-logs.sh"

  setup() {
    fixture_dir=$(mktemp -d)
  }
  cleanup() {
    rm -rf "$fixture_dir"
  }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Lay out an extracted-artifact directory: <root>/smoke-diagnostics-<image>-<ver>-s<shard>/pytest-durations.log
  add_shard_log() {
    # $1=image ("pfsense-ce"/"pfsense-plus") $2=version $3=shard
    mkdir -p "${fixture_dir}/smoke-diagnostics-$1-$2-s$3"
    printf 'log\n' > "${fixture_dir}/smoke-diagnostics-$1-$2-s$3/pytest-durations.log"
  }

  It 'selects all shards of the single CE version and ignores Plus legs'
    add_shard_log pfsense-ce 2.8 0
    add_shard_log pfsense-ce 2.8 1
    add_shard_log pfsense-plus 26.03 0
    When run sh "$SCRIPT" "$fixture_dir"
    The status should be success
    The output should include 'smoke-diagnostics-pfsense-ce-2.8-s0/pytest-durations.log'
    The output should include 'smoke-diagnostics-pfsense-ce-2.8-s1/pytest-durations.log'
    The output should not include 'pfsense-plus'
    The stderr should equal ''
  End

  It 'picks the NUMERIC minimum CE version in a two-GA-CE window (2.8 < 2.10, not lexical) with a loud notice'
    # The drop_ce steady state: two GA CE versions ci:true at once. The
    # selector must not fail (the #910 first-cut guard did) and must sort
    # numerically -- a lexical sort would pick 2.10.
    add_shard_log pfsense-ce 2.8 0
    add_shard_log pfsense-ce 2.10 0
    add_shard_log pfsense-ce 2.10 1
    When run sh "$SCRIPT" "$fixture_dir"
    The status should be success
    The output should include 'smoke-diagnostics-pfsense-ce-2.8-s0/pytest-durations.log'
    The output should not include 'pfsense-ce-2.10'
    The stderr should include 'multiple CE versions present'
    The stderr should include 'selecting min 2.8'
  End

  It 'fails loudly when no CE logs exist at all (Plus-only artifacts)'
    add_shard_log pfsense-plus 26.03 0
    When run sh "$SCRIPT" "$fixture_dir"
    The status should be failure
    The stderr should include 'no pytest-durations.log'
  End

  It 'fails loudly on artifact-name drift (CE log present but no <ver>-s<N> shape to extract)'
    mkdir -p "${fixture_dir}/smoke-diagnostics-pfsense-ce-weird"
    printf 'log\n' > "${fixture_dir}/smoke-diagnostics-pfsense-ce-weird/pytest-durations.log"
    When run sh "$SCRIPT" "$fixture_dir"
    The status should be failure
    The stderr should include 'artifact naming drifted'
  End
End
