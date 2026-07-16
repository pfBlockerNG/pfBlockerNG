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

Describe 'agent_env.sh bounded gh execution'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/agent_env.sh

  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
printf '%s' "${GH_STUB_STDOUT-partial stdout}"
printf '%s' "${GH_STUB_STDERR- + stderr}" >&2
if [ -n "${GH_STUB_HANG:-}" ]; then
	[ -z "${GH_STUB_IGNORE_TERM:-}" ] || trap '' TERM
	sleep "${GH_STUB_HANG_SECONDS:-4}"
	[ -z "${GH_STUB_HANG_MARKER:-}" ] || printf done > "$GH_STUB_HANG_MARKER"
fi
exit "${GH_STUB_STATUS:-0}"
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'

  It 'captures combined diagnostics and preserves the gh child status'
    deadline=$(( $(date +%s) + 60 ))
    export GH_STUB_STATUS=7
    When call gh_bounded api endpoint
    The status should equal 7
    The output should equal 'partial stdout + stderr'
  End

  It 'suppresses stderr from a successful stderr-only request'
    deadline=$(( $(date +%s) + 60 ))
    export GH_STUB_STDOUT=''
    When call gh_bounded api endpoint
    The status should equal 0
    The output should equal ''
  End

  It 'keeps successful JSON stdout valid when gh also writes stderr'
    deadline=$(( $(date +%s) + 60 ))
    export GH_STUB_STDOUT='[{"name":"pytest","bucket":"pass"}]'
    export GH_STUB_STDERR='warning from gh'
    When call gh_bounded pr checks 1
    The status should equal 0
    The output should equal '[{"name":"pytest","bucket":"pass"}]'
  End

  It 'caps one call at 30 seconds even when the deadline is farther away'
    cat > "$stubdir/timeout" <<'STUB'
#!/bin/sh
printf '%s' "$*"
exit 124
STUB
    chmod +x "$stubdir/timeout"
    deadline=$(( $(date +%s) + 300 ))
    When call gh_bounded api endpoint
    The status should equal 124
    The output should equal '-k 1 29 gh api endpoint'
  End

  It 'returns timeout status with partial output when the remaining deadline expires'
    deadline=$(( $(date +%s) + 2 ))
    export GH_STUB_HANG=1
    When call gh_bounded api endpoint
    The status should equal 124
    The output should equal 'partial stdout + stderr'
  End

  It 'kills a TERM-ignoring gh child before it can outlive the deadline'
    deadline=$(( $(date +%s) + 2 ))
    export GH_STUB_HANG=1 GH_STUB_IGNORE_TERM=1 GH_STUB_HANG_SECONDS=3
    export GH_STUB_HANG_MARKER="$stubdir/outlived"
    When call gh_bounded api endpoint
    The status should not equal 0
    The output should include 'partial stdout + stderr'
    The file "$GH_STUB_HANG_MARKER" should not be exist
  End
End

Describe 'wait-checks.sh tool contracts'
  setup_tool_path() {
    toolpath="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/toolpath.XXXXXX")"
    ln -s "$(command -v dirname)" "$toolpath/dirname"
  }
  cleanup_tool_path() { rm -rf "$toolpath"; }
  Before 'setup_tool_path'
  After 'cleanup_tool_path'

  It 'exits 3 when gh is absent'
    When run env PATH="$toolpath" /bin/sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 3
    The stderr should include 'GH-UNAVAILABLE'
  End

  It 'exits 4 when timeout is absent'
    printf '#!/bin/sh\nexit 0\n' > "$toolpath/gh"
    chmod +x "$toolpath/gh"
    When run env PATH="$toolpath" /bin/sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 4
    The stderr should include 'TOOL-MISSING: timeout'
  End
End

Describe 'wait-checks.sh loop verdicts (stub gh)'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
count=0
[ ! -f "${GH_STUB_COUNT_FILE:-}" ] || count=$(cat "$GH_STUB_COUNT_FILE")
count=$((count + 1))
[ -z "${GH_STUB_COUNT_FILE:-}" ] || printf '%s\n' "$count" > "$GH_STUB_COUNT_FILE"
case " ${GH_STUB_FAIL_CALLS:-} " in
	*" $count "*) printf '%s\n' "${GH_STUB_FAIL_OUTPUT:-HTTP 404}"; exit 1 ;;
esac
printf '%s\n' "$GH_STUB_CHECKS"
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'
  script="scripts/agent/wait-checks.sh"

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

  It 'resets the failure streak after a successful pending snapshot'
    export GH_STUB_COUNT_FILE="$stubdir/count"
    export GH_STUB_FAIL_CALLS='1 2 4 5'
    export GH_STUB_CHECKS='[{"name":"pytest","bucket":"pending"}]'
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 5
    The status should equal 0
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'caps sleep after a successful pending poll at the remaining deadline'
    setup_near_deadline
    export GH_STUB_CHECKS='[{"name":"pytest","bucket":"pending"}]'
    When run sh "$script" --repo o/r --pr 1 --interval 99 --max-iter 1
    The line 1 of output should equal 'TIMEOUT'
    The contents of file "$WAIT_SLEEP_FILE" should equal '3'
  End

  It 'caps sleep after a failed poll at the remaining deadline'
    setup_near_deadline
    export GH_STUB_COUNT_FILE="$stubdir/count"
    export GH_STUB_FAIL_CALLS='1'
    When run sh "$script" --repo o/r --pr 1 --interval 99 --max-iter 1
    The line 1 of output should equal 'TIMEOUT'
    The contents of file "$WAIT_SLEEP_FILE" should equal '3'
  End
End

Describe 'wait-checks.sh gh-failure detection'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    printf '#!/bin/sh\nprintf '\''[{"name":"pytest","bucket":"fail"}] HTTP 404\\n'\''\nexit 1\n' > "$stubdir/gh"
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'

  It 'reports GH-ERROR after repeated failures without classifying their actionable stdout'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 10
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
    The output should include 'HTTP 404'
  End
End
