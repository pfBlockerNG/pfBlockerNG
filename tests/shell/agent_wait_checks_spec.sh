#shellcheck shell=sh
#shellcheck disable=SC2034 # spec-set globals are consumed by the Included evaluate_checks()
# wait-checks.sh evaluate_checks(): the CI-wait verdict reduction. Pins: fail/cancel win,
# skipping counts as done-not-failed, PASS requires at least one relevant check (never
# green-by-absence), and the coderabbit|snyk exclusion is honoured.

Describe 'wait-checks.sh evaluate_checks()'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-checks.sh
  exclude='coderabbit|snyk'

  It 'reports PASS when every relevant check passed'
    When call evaluate_checks '[{"name":"pytest","bucket":"pass"},{"name":"ShellCheck","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  It 'reports PASS with skipping checks (done-not-failed)'
    When call evaluate_checks '[{"name":"pytest","bucket":"pass"},{"name":"UI fan-out","bucket":"skipping"}]'
    The output should equal 'PASS'
  End

  It 'reports FAIL on any fail bucket'
    When call evaluate_checks '[{"name":"pytest","bucket":"fail"},{"name":"ShellCheck","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'reports FAIL on a cancelled check'
    When call evaluate_checks '[{"name":"pytest","bucket":"cancel"}]'
    The output should equal 'FAIL'
  End

  It 'reports PENDING while anything is still running'
    When call evaluate_checks '[{"name":"pytest","bucket":"pending"},{"name":"ShellCheck","bucket":"pass"}]'
    The output should equal 'PENDING'
  End

  It 'ignores excluded advisory bots -- a CodeRabbit fail never gates'
    When call evaluate_checks '[{"name":"CodeRabbit","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  It 'ignores a Snyk error status the same way'
    When call evaluate_checks '[{"name":"code/snyk (pfBlockerNG)","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  It 'reports EMPTY when no relevant check has registered (never green-by-absence)'
    When call evaluate_checks '[{"name":"CodeRabbit","bucket":"pass"}]'
    The output should equal 'EMPTY'
  End
End

Describe 'wait-checks.sh loop verdicts (stub gh)'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    printf '#!/bin/sh\n[ -n "${GH_STUB_FAIL:-}" ] && exit 1\necho "$GH_STUB_CHECKS"\n' > "$stubdir/gh"
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'
  script="scripts/agent/wait-checks.sh"

  It 'reports TIMEOUT when checks stay pending through the cap'
    export GH_STUB_CHECKS='[{"name":"pytest","bucket":"pending"}]'
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 2
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'honours the wall-clock deadline even when a verdict would be reached'
    export GH_STUB_CHECKS='[{"name":"pytest","bucket":"pass"}]'
    export PFB_WAIT_DEADLINE=1
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 3
    The line 1 of output should equal 'TIMEOUT'
  End
End

Describe 'wait-checks.sh gh-failure detection'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    printf '#!/bin/sh\nexit 1\n' > "$stubdir/gh"
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'

  It 'reports GH-ERROR after repeated gh failures instead of polling to a blind TIMEOUT'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 10
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End
End
