#shellcheck shell=sh
#shellcheck disable=SC2034 # spec-set globals are consumed by the Included classify()
# wait-reviewer.sh classify(): the reviewer-wait state machine's verdicts. Pins the
# content-first rule (real review content beats a co-present quota notice), the QUOTA
# resume-minutes parse (hours convert), DECLINE/PAUSE detection, ack-mode semantics,
# Snyk status handling, and the gh-unavailable exit-3 contract.

Describe 'wait-reviewer.sh classify()'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-reviewer.sh

  reset_state() {
    mode='finished' handle='coderabbitai' inline='' review='' issuec='' sinfo=''
  }
  Before 'reset_state'

  It 'reports FINISHED on inline comments even when a quota notice is also present'
    inline='123'
    issuec='You have reached your PR review limit. Next review available in: **46 minutes**'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports FINISHED on the actionable-comments summary header'
    issuec='Actionable comments posted: 3'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports FINISHED on a clean no-actionable-comments pass'
    issuec='No actionable comments were generated.'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports QUOTA with the notice-stated minutes when no content exists'
    issuec='Review limit reached. Next review available in: **46 minutes**'
    When call classify
    The output should equal 'QUOTA 46'
  End

  It 'converts an hours-denominated quota resume time to minutes'
    issuec='Review limit reached. Next review available in: **2 hours**'
    When call classify
    The output should equal 'QUOTA 120'
  End

  It 'reports QUOTA 999 when the resume time is unparsable'
    issuec='You have run out of usage credits.'
    When call classify
    The output should equal 'QUOTA 999'
  End

  It 'reports DECLINE on a review-skipped-for-base-branch notice'
    issuec='Review skipped: reviews are limited to specific base branches.'
    When call classify
    The output should equal 'DECLINE'
  End

  It 'reports PAUSE when reviews are paused'
    issuec='Reviews paused because the branch is too active.'
    When call classify
    The output should equal 'PAUSE'
  End

  It 'keeps polling (empty verdict) on unrelated chatter'
    issuec='Walkthrough coming soon...'
    When call classify
    The output should equal ''
  End

  It 'reports ACK in ack mode on any handle message'
    mode='ack'
    issuec='anything at all'
    When call classify
    The output should equal 'ACK'
  End

  It 'stays silent in ack mode with zero engagement'
    mode='ack'
    When call classify
    The output should equal ''
  End

  It 'reports QUOTA 999 for a Snyk error status (a skipped scan is never a clean pass)'
    handle='snyk'
    sinfo='error Code test limit reached'
    When call classify
    The output should equal 'QUOTA 999'
  End

  It 'reports FINISHED for a terminal Snyk verdict'
    handle='snyk'
    sinfo='success Scan completed'
    When call classify
    The output should equal 'FINISHED'
  End
End

Describe 'wait-reviewer.sh gh-unavailable contract'
  It 'exits 3 with the MCP fallback pointer when gh is absent'
    When run sh -c 'PATH=/dev/null; . scripts/agent/agent_env.sh; require_gh'
    The status should equal 3
    The stderr should include 'GH-UNAVAILABLE'
    The stderr should include 'mcp__github__'
  End
End
