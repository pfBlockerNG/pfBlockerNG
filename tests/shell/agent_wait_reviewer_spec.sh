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

  It 'reports QUOTA on the PR-review-limit phrasing (no "rate" in the notice)'
    issuec='@user, you have reached your PR review limit. Next review available in: **46 minutes**'
    When call classify
    The output should equal 'QUOTA 46'
  End

  It 'reports QUOTA on the rate-limited-by-coderabbit phrasing'
    issuec='This PR is rate limited by CodeRabbit.'
    When call classify
    The output should equal 'QUOTA 999'
  End

  Parameters
    action_required
    timed_out
    cancelled
    stale
  End
  It "reports QUOTA for the non-verdict Snyk state $1"
    handle='snyk'
    sinfo="$1 scan did not complete"
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

  It 'reports PAUSE on the emoji-only pause marker'
    issuec='⏸ CodeRabbit'
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

Describe 'wait-reviewer.sh login matching (anchored substring)'
  # shellcheck disable=SC2034
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-reviewer.sh
  since=''

  match_ids() {
    # $1 = handle, $2 = fixture JSON; prints matched ids via the REAL jq filter
    handle=$1
    printf '%s' "$2" | jq "[$(jq_filter created_at) | .id] | join(\",\")" -r
  }
  FIXTURE='[{"user":{"login":"coderabbitai[bot]"},"id":1},{"user":{"login":"not-coderabbitai"},"id":2},{"user":{"login":"copilot-pull-request-reviewer[bot]"},"id":3}]'

  It 'matches the [bot]-suffixed login from the bare handle'
    When call match_ids coderabbitai "$FIXTURE"
    The output should equal '1'
  End

  It 'matches the prefixed bot login from the short handle'
    When call match_ids copilot "$FIXTURE"
    The output should equal '3'
  End

  It 'matches a full bracketed login given verbatim (no regex-metachar breakage)'
    When call match_ids 'copilot-pull-request-reviewer[bot]' "$FIXTURE"
    The output should equal '3'
  End

  It 'does NOT match a login that merely contains the handle (anchored, not free substring)'
    When call match_ids coderabbitai '[{"user":{"login":"not-coderabbitai"},"id":2}]'
    The output should equal ''
  End
End

Describe 'wait-reviewer.sh loop verdicts (stub gh)'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
case "$*" in
	*pulls/*/comments*) cat "$GH_STUB_INLINE" 2>/dev/null ;;
	*pulls/*/reviews*)
		case "$*" in
			*'select(.submitted_at >'*) cat "$GH_STUB_REVIEW_SINCE" 2>/dev/null ;;
			*) cat "$GH_STUB_REVIEW_ANY" 2>/dev/null ;;
		esac
		;;
	*) exit 0 ;;
esac
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'
  script="scripts/agent/wait-reviewer.sh"

  It 'reports NOACK when the cap expires in ack mode with zero engagement'
    unset GH_STUB_INLINE
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until ack --interval 0 --max-iter 2 --presence 0
    The line 1 of output should equal 'NOACK'
  End

  It 'reports NOTPRESENT after the presence window with zero engagement'
    unset GH_STUB_INLINE
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 9 --presence 1
    The line 1 of output should equal 'NOTPRESENT'
  End

  It 'reports FINISHED when an inline comment id appears'
    export GH_STUB_INLINE="$stubdir/inline.txt"
    echo 42 > "$GH_STUB_INLINE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3
    The output should include 'FINISHED'
  End

  It 'honours the wall-clock deadline even when content would be found (No-orphaned-waits #1)'
    export GH_STUB_INLINE="$stubdir/inline.txt"
    echo 42 > "$GH_STUB_INLINE"
    export PFB_WAIT_DEADLINE=1
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'treats a review posted before --since as presence: TIMEOUT, not NOTPRESENT (issue #1325)'
    export GH_STUB_REVIEW_ANY="$stubdir/review_any.txt"
    echo 99 > "$GH_STUB_REVIEW_ANY"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3 --presence 1
    The line 1 of output should equal 'TIMEOUT'
  End
End
