#shellcheck shell=sh
#shellcheck disable=SC2034 # spec-set globals are consumed by the Included classify()
# issue #3294: historical CodeRabbit review text retained in an edited quota
# comment must not FINISHED a wait for the current head.

Describe 'wait-reviewer.sh head-bound classify()'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-reviewer.sh

  reset_state() {
    mode='finished' handle='coderabbitai' inline='' review='' issuec='' sinfo=''
    head='71df67073b8704c6389e3c544bf1a5b68aa6aa4d'
  }
  Before 'reset_state'

  It 'reports QUOTA for the captured PR 3293 quota body with a retained older review'
    issuec=$(cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md)
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'reports FINISHED when current-head completion sits beside stale quota text'
    issuec='Review limit reached. Next included review available in 6 minutes.
No actionable comments were generated in the recent review.
Reviewing files that changed from the base of the PR and between 0f84b1cb9622e93dfba0daa99698d6cd0c821701 and 71df67073b8704c6389e3c544bf1a5b68aa6aa4d.'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports QUOTA on a plain quota notice with no completion phrases'
    issuec='Review limit reached. Next included review available in 32 minutes.'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'reports FINISHED on plain completion with no quota and no commit range'
    issuec='No actionable comments were generated.'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'does not FINISHED when the only completion range is the previous head'
    issuec='Review limit reached. Next included review available in 32 minutes.
No actionable comments were generated in the recent review.
Reviewing files that changed from the base of the PR and between 498690ef7c7f54d4475d9773064f28fadc45ffb9 and 0f84b1cb9622e93dfba0daa99698d6cd0c821701.'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'reports FINISHED on in-window inline comment ids without parsing the quota body'
    inline='123'
    issuec=$(cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md)
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports FINISHED on an in-window submitted review body without CodeRabbit parsing'
    review='looks good'
    issuec=$(cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md)
    When call classify
    The output should equal 'FINISHED'
  End

  It 'reports ACK in ack mode on a historical quota body'
    mode='ack'
    issuec=$(cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md)
    When call classify
    The output should equal 'ACK'
  End


  It 'reports QUOTA when historical completion is markdown-quoted beside current quota'
    issuec='> No actionable comments were generated in the recent review.
> Reviewing files that changed from the base of the PR and between 498690ef7c7f54d4475d9773064f28fadc45ffb9 and 0f84b1cb9622e93dfba0daa99698d6cd0c821701.
Review limit reached. Next included review available in 32 minutes.'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'reports QUOTA when both ranges appear and only the old range has completion'
    issuec='Review limit reached. Next included review available in 32 minutes.
Reviewing files that changed from the base of the PR and between 0f84b1cb9622e93dfba0daa99698d6cd0c821701 and 71df67073b8704c6389e3c544bf1a5b68aa6aa4d.
No actionable comments were generated in the recent review.
Reviewing files that changed from the base of the PR and between 498690ef7c7f54d4475d9773064f28fadc45ffb9 and 0f84b1cb9622e93dfba0daa99698d6cd0c821701.'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'reports QUOTA when completion names a SHA that is not the requested head'
    issuec='Review limit reached. Next included review available in 32 minutes.
Actionable comments posted: 3
between deadbeefdead and cafebabe0123'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'does not FINISHED from a SHA shorter than seven hex characters'
    issuec='Review limit reached. Next included review available in 32 minutes.
No actionable comments were generated.
between 498690ef7c7f54d4475d9773064f28fadc45ffb9 and 71df67'
    When call classify
    The output should equal 'QUOTA 32'
  End

  It 'binds an explicit 7-character head prefix to the matching range'
    head='71df670'
    issuec='Review limit reached. Next included review available in 6 minutes.
No actionable comments were generated.
Reviewing files that changed from the base of the PR and between 0f84b1cb9622e93dfba0daa99698d6cd0c821701 and 71df67073b8704c6389e3c544bf1a5b68aa6aa4d.'
    When call classify
    The output should equal 'FINISHED'
  End

  It 'leaves Snyk terminal verdicts unchanged'
    handle='snyk'
    sinfo='success Scan completed'
    When call classify
    The output should equal 'FINISHED'
  End
End

Describe 'wait-reviewer.sh --head loop (stub gh)'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
site='' file=''
case "$*" in
	*'--json commits'*) site='default-since' ;;
	*pulls/*/comments*) site='inline' ;;
	*pulls/*/reviews*) site='review' ;;
	*issues/*/comments*) site='issue'; file=${GH_STUB_ISSUE_SINCE:-} ;;
	*'--json headRefOid'*) site='head' ;;
esac
case "$site" in
	default-since) printf '%s\n' '2026-01-01T00:00:00Z' ;;
	head) printf '%s\n' "${GH_STUB_HEAD_OID:-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef}" ;;
	*) [ -z "$file" ] || cat "$file" ;;
esac
exit 0
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
    script="scripts/agent/wait-reviewer.sh"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'

  It 'reports QUOTA when --since admits an edited comment whose completion is historical'
    export GH_STUB_ISSUE_SINCE="$stubdir/issue.txt"
    export GH_STUB_HEAD_OID='71df67073b8704c6389e3c544bf1a5b68aa6aa4d'
    cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md > "$GH_STUB_ISSUE_SINCE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since 2026-09-14T17:50:56Z --interval 0 --max-iter 1 --presence 0
    The status should equal 0
    The output should include 'QUOTA 32'
  End

  It 'uses the PR head when --head is omitted'
    export GH_STUB_ISSUE_SINCE="$stubdir/issue.txt"
    export GH_STUB_HEAD_OID='71df67073b8704c6389e3c544bf1a5b68aa6aa4d'
    cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md > "$GH_STUB_ISSUE_SINCE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --interval 0 --max-iter 1 --presence 0
    The output should include 'QUOTA 32'
  End

  It 'binds an explicit --head even when it is not the PR head'
    export GH_STUB_ISSUE_SINCE="$stubdir/issue.txt"
    export GH_STUB_HEAD_OID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md > "$GH_STUB_ISSUE_SINCE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --head 71df67073b8704c6389e3c544bf1a5b68aa6aa4d --interval 0 --max-iter 1 --presence 0
    The output should include 'QUOTA 32'
  End

  It 'reports FINISHED when explicit --head matches the retained review range'
    export GH_STUB_ISSUE_SINCE="$stubdir/issue.txt"
    export GH_STUB_HEAD_OID='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    cat tests/fixtures/reviewer/coderabbit-pr3293-quota-historical.md > "$GH_STUB_ISSUE_SINCE"
    When run sh "$script" --repo o/r --pr 1 --handle coderabbitai --until finished --since x --head 0f84b1cb9622e93dfba0daa99698d6cd0c821701 --interval 0 --max-iter 1 --presence 0
    The output should include 'FINISHED'
  End
End
