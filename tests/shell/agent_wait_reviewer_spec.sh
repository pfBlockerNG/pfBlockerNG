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

  It 'reports QUOTA with the stated minutes when the notice carries no colon'
    issuec='> ## Review limit reached
>
> **Next included review available in 40 minutes.**'
    When call classify
    The output should equal 'QUOTA 40'
  End

  It 'converts a colonless hours-denominated resume time to minutes'
    issuec='> ## Review limit reached
>
> **Next included review available in 2 hours.**'
    When call classify
    The output should equal 'QUOTA 120'
  End

  It 'falls back rather than reading a multi-unit window as its first number'
    issuec='Review limit reached. Next included review available in 1 day 30 minutes.'
    When call classify
    The output should equal 'QUOTA 999'
  End

  It 'falls back when the window names an hour and a minute component'
    issuec='Review limit reached. Next included review available in 1 hour 30 minutes.'
    When call classify
    The output should equal 'QUOTA 999'
  End

  It 'falls back when the window names its components in the other order'
    issuec='Review limit reached. Next included review available in 40 minutes and 2 hours.'
    When call classify
    The output should equal 'QUOTA 999'
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
    issuec='Reviews are paused because the branch is too active.'
    When call classify
    The output should equal 'PAUSE'
  End

  It 'reports PAUSE when reviews paused'
    issuec='Reviews paused because the branch is too active.'
    When call classify
    The output should equal 'PAUSE'
  End

  It 'reports PAUSE on the emoji-only pause marker'
    issuec='⏸ CodeRabbit'
    When call classify
    The output should equal 'PAUSE'
  End

  It 'keeps polling after a triggered-review disclaimer mentions paused reviews'
    issuec='Review triggered.

> Note: CodeRabbit is an incremental review system and does not re-review already
> reviewed commits. This command is applicable only when automatic reviews are paused.'
    When call classify
    The output should equal ''
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
  setup_tool_path() {
    toolpath="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/toolpath.XXXXXX")"
    ln -s "$(command -v dirname)" "$toolpath/dirname"
    ln -s "$(command -v tr)" "$toolpath/tr"
  }
  cleanup_tool_path() { rm -rf "$toolpath"; }
  Before 'setup_tool_path'
  After 'cleanup_tool_path'

  It 'exits 3 with the MCP fallback pointer when gh is absent'
    When run sh -c 'PATH=/dev/null; . scripts/agent/agent_env.sh; require_gh'
    The status should equal 3
    The stderr should include 'GH-UNAVAILABLE'
    The stderr should include 'mcp__github__'
  End

  It 'exits 4 when timeout is absent'
    printf '#!/bin/sh\nexit 0\n' > "$toolpath/gh"
    chmod +x "$toolpath/gh"
    When run env PATH="$toolpath" /bin/sh scripts/agent/wait-reviewer.sh --repo o/r --pr 1 --handle bot --until ack --interval 0 --max-iter 1
    The status should equal 4
    The stderr should include 'TOOL-MISSING: timeout'
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
count=0
if [ -n "${GH_STUB_COUNT_FILE:-}" ]; then
	[ ! -f "$GH_STUB_COUNT_FILE" ] || count=$(cat "$GH_STUB_COUNT_FILE")
	count=$((count + 1))
	printf '%s\n' "$count" > "$GH_STUB_COUNT_FILE"
	case " ${GH_STUB_FAIL_CALLS:-} " in
		*" $count "*) printf '%s\n' "${GH_STUB_FAIL_OUTPUT:-HTTP 404}"; exit 1 ;;
	esac
fi

site='' file=''
case "$*" in
	*'--json commits'*) site='default-since' ;;
	*pulls/*/comments*)
		case "$*" in
			*'created_at >'*) site='inline-content'; file=${GH_STUB_INLINE:-} ;;
			*) site='inline-presence'; file=${GH_STUB_INLINE_ANY:-${GH_STUB_INLINE:-}} ;;
		esac
		;;
	*pulls/*/reviews*)
		case "$*" in
			*'submitted_at >'*) site='review-content'; file=${GH_STUB_REVIEW_SINCE:-} ;;
			*) site='review-presence'; file=${GH_STUB_REVIEW_ANY:-${GH_STUB_REVIEW_SINCE:-}} ;;
		esac
		;;
	*issues/*/comments*)
		case "$*" in
			*'updated_at >'*) site='issue-content'; file=${GH_STUB_ISSUE_SINCE:-} ;;
			*) site='issue-presence'; file=${GH_STUB_ISSUE_ANY:-${GH_STUB_ISSUE_SINCE:-}} ;;
		esac
		;;
	*'--json headRefOid'*) site='snyk-head' ;;
	*/status*) site='snyk-status'; file=${GH_STUB_SNYK_STATUS:-} ;;
	*/check-runs*) site='snyk-check-runs'; file=${GH_STUB_SNYK_CHECKS:-} ;;
esac

if [ "${GH_STUB_FAIL_SITE:-}" = "$site" ]; then
	[ "$site" = 'default-since' ] || printf '%s\n' "${GH_STUB_FAIL_OUTPUT:-HTTP 404}"
	exit 1
fi

case "$site" in
	default-since) printf '%s\n' '2026-01-01T00:00:00Z' ;;
	snyk-head) printf '%s\n' 'deadbeef' ;;
	*) [ -z "$file" ] || cat "$file" ;;
esac
exit 0
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'
  script="scripts/agent/wait-reviewer.sh"

  setup_near_deadline() {
    cat > "$stubdir/date" <<'STUB'
#!/bin/sh
printf '100\n'
STUB
    cat > "$stubdir/sleep" <<'STUB'
#!/bin/sh
printf '%s\n' "$1" >> "$WAIT_SLEEP_FILE"
STUB
    chmod +x "$stubdir/date" "$stubdir/sleep"
    export PFB_WAIT_DEADLINE=103 WAIT_SLEEP_FILE="$stubdir/sleeps"
  }

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

  It 'reports FINISHED when a submitted review appears'
    export GH_STUB_REVIEW_SINCE="$stubdir/review.txt"
    echo review > "$GH_STUB_REVIEW_SINCE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3
    The output should include 'FINISHED'
  End

  It 'reports FINISHED when an actionable issue comment appears'
    export GH_STUB_ISSUE_SINCE="$stubdir/issue.txt"
    echo 'Actionable comments posted: 1' > "$GH_STUB_ISSUE_SINCE"
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

  It 'uses the default time floor while treating an older review only as presence'
    export GH_STUB_REVIEW_ANY="$stubdir/review_any.txt"
    echo 99 > "$GH_STUB_REVIEW_ANY"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --interval 0 --max-iter 3 --presence 1
    The line 1 of output should equal 'TIMEOUT'
  End


  It 'treats an inline comment before --since as presence: TIMEOUT, not NOTPRESENT'
    export GH_STUB_INLINE_ANY="$stubdir/inline_any.txt"
    echo 98 > "$GH_STUB_INLINE_ANY"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3 --presence 1
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'treats an issue comment before --since as presence: TIMEOUT, not NOTPRESENT'
    export GH_STUB_ISSUE_ANY="$stubdir/issue_any.txt"
    echo 97 > "$GH_STUB_ISSUE_ANY"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3 --presence 1
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'reads a terminal Snyk commit status'
    export GH_STUB_SNYK_STATUS="$stubdir/status.txt"
    echo 'success Scan completed' > "$GH_STUB_SNYK_STATUS"
    When run sh "$script" --repo o/r --pr 1 --handle snyk --until finished --since x --interval 0 --max-iter 3
    The output should include 'FINISHED'
  End

  It 'reads a terminal Snyk check-run'
    export GH_STUB_SNYK_CHECKS="$stubdir/checks.txt"
    echo 'completed Scan completed' > "$GH_STUB_SNYK_CHECKS"
    When run sh "$script" --repo o/r --pr 1 --handle snyk --until finished --since x --interval 0 --max-iter 3
    The output should include 'FINISHED'
  End

  It 'discards earlier terminal data when a later snapshot call fails'
    export GH_STUB_INLINE="$stubdir/inline.txt"
    echo 42 > "$GH_STUB_INLINE"
    export GH_STUB_FAIL_SITE='issue-content'
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 1
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'never classifies actionable stdout from a failed gh call'
    export GH_STUB_FAIL_SITE='inline-content'
    export GH_STUB_FAIL_OUTPUT='Actionable comments posted: 3 (HTTP 404)'
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 3
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End

  It 'keeps the default time floor when its lookup fails, rejecting a stale review'
    export GH_STUB_FAIL_SITE='default-since'
    export GH_STUB_REVIEW_ANY="$stubdir/stale_review.txt"
    echo stale-review > "$GH_STUB_REVIEW_ANY"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --interval 0 --max-iter 3
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End

  It 'resets the failure streak after a complete successful poll'
    export GH_STUB_COUNT_FILE="$stubdir/count"
    export GH_STUB_FAIL_CALLS='1 2 6 7'
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until ack --interval 0 --max-iter 5 --presence 0
    The status should equal 0
    The line 1 of output should equal 'NOACK'
  End

  It 'caps sleep after a successful pending poll at the remaining deadline'
    setup_near_deadline
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until ack --interval 99 --max-iter 1 --presence 0
    The line 1 of output should equal 'NOACK'
    The contents of file "$WAIT_SLEEP_FILE" should equal '3'
  End

  It 'caps sleep after a failed poll at the remaining deadline'
    setup_near_deadline
    export GH_STUB_FAIL_SITE='inline-content'
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 99 --max-iter 1 --presence 0
    The line 1 of output should equal 'TIMEOUT'
    The contents of file "$WAIT_SLEEP_FILE" should equal '3'
  End

  Parameters
    inline-content coderabbitai
    review-content coderabbitai
    issue-content coderabbitai
    inline-presence coderabbitai
    review-presence coderabbitai
    issue-presence coderabbitai
    snyk-head snyk
    snyk-status snyk
    snyk-check-runs snyk
  End
  It "reports GH-ERROR when reviewer endpoint $1 fails for three polls"
    export GH_STUB_FAIL_SITE="$1"
    When run sh "$script" --repo o/r --pr 1 --handle "$2" --until finished --since x --interval 0 --max-iter 3 --presence 0
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End
End
