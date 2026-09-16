#shellcheck shell=sh
#shellcheck disable=SC2034
# Copilot/CodeRabbit on PR #3300: requested head must be at least seven hex
# characters, and a bare --head must usage-exit.

Describe 'wait-reviewer.sh requested-head length'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-reviewer.sh

  It 'does not FINISHED when --head is shorter than seven hex characters'
    mode='finished'
    handle='coderabbitai'
    inline=''
    review=''
    sinfo=''
    head='71df67'
    issuec='Review limit reached. Next included review available in 6 minutes.
No actionable comments were generated.
Reviewing files that changed from the base of the PR and between 0f84b1cb9622e93dfba0daa99698d6cd0c821701 and 71df67073b8704c6389e3c544bf1a5b68aa6aa4d.'
    When call classify
    The output should equal 'QUOTA 6'
  End
End

Describe 'wait-reviewer.sh bare --head'
  It 'exits usage when --head has no value'
    When run sh scripts/agent/wait-reviewer.sh --repo o/r --pr 1 --handle coderabbitai --head
    The status should equal 2
    The stderr should include 'usage:'
  End
End
