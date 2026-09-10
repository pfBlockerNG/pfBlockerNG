#shellcheck shell=sh
# PR #2809's original 2026-08-28T04:40:41Z CodeRabbit quota body.

Describe 'wait-reviewer.sh historical quota fixture'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-reviewer.sh

  It 'reports the notice-stated six-minute window'
    handle='coderabbitai'
    mode='finished'
    inline=''
    review=''
    issuec=$(cat tests/fixtures/reviewer/coderabbit-quota-6.md)
    sinfo=''
    When call classify
    The output should equal 'QUOTA 6'
  End

  Parameters
    '1 minute' 'QUOTA 1'
    '1 hour' 'QUOTA 60'
  End
  It "accepts the singular duration $1"
    handle='coderabbitai'
    mode='finished'
    inline=''
    review=''
    issuec="Review limit reached. Next included review available in $1."
    sinfo=''
    When call classify
    The output should equal "$2"
  End
End
