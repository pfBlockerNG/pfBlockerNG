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
