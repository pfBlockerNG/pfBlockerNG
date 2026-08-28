#shellcheck shell=sh
#shellcheck disable=SC2034 # spec-set globals are consumed by the Included evaluate_checks()
# wait-checks.sh evaluate_checks(): the CI-wait verdict reduction. Pins: fail/cancel win,
# skipping counts as done-not-failed, PASS requires at least one relevant check (never
# green-by-absence), and the advisory-bot exclusion is honoured.
#
# #1706: these specs deliberately do NOT set `exclude` -- they run on the production
# default the Included script assigns, so an over-broad default cannot hide behind a
# spec-local override.

Describe 'wait-checks.sh evaluate_checks()'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-checks.sh

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

  It 'ignores the bare snyk context'
    When call evaluate_checks '[{"name":"snyk","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  # The org qualifier is whatever Snyk's project is named -- the only context this repo
  # has ever actually served is `code/snyk (BBcan177)` (probed across PRs #450-#850).
  It 'ignores the code/snyk context under the org qualifier this repo really serves'
    When call evaluate_checks '[{"name":"code/snyk (BBcan177)","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  It 'ignores the unqualified code/snyk context'
    When call evaluate_checks '[{"name":"code/snyk","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  # #1706: the default exclusion names exact advisory contexts. A required check is not
  # advisory merely because its name contains "snyk" or "coderabbit" -- excluding it by
  # substring turns a failing gate into a false green.
  It 'gates on a failing required check whose name merely starts with snyk'
    When call evaluate_checks '[{"name":"snyk-adjacent-but-required","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'gates on a failing required check whose path segment merely contains snyk'
    When call evaluate_checks '[{"name":"security/snyk-policy-check","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'gates on a failing required check whose name merely ends with coderabbit'
    When call evaluate_checks '[{"name":"not-coderabbit","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'gates on a failing required check whose name merely starts with coderabbit'
    When call evaluate_checks '[{"name":"coderabbit-required","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'gates on a failing required check embedding Snyk in mixed case'
    When call evaluate_checks '[{"name":"MySnykRequired","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'FAIL'
  End

  It 'keeps a caller-supplied --exclude regex broad (substring, unanchored)'
    exclude='snyk'
    When call evaluate_checks '[{"name":"snyk-adjacent-but-required","bucket":"fail"},{"name":"pytest","bucket":"pass"}]'
    The output should equal 'PASS'
  End

  It 'reports EMPTY when no relevant check has registered (never green-by-absence)'
    When call evaluate_checks '[{"name":"CodeRabbit","bucket":"pass"}]'
    The output should equal 'EMPTY'
  End
End

# checks_to_buckets(): maps the two SHA-addressed REST reads (check-runs + commit status,
# each possibly several `--paginate` pages concatenated) to the {name, bucket} shape
# evaluate_checks() consumes. Unrecognised conclusion/state values fall to "pending", never
# "pass" (#1690: an unmapped value must surface as a TIMEOUT a human looks at).
Describe 'wait-checks.sh checks_to_buckets()'
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/wait-checks.sh

  It 'maps a queued check run to pending'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"queued","conclusion":null}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pending"}]'
  End

  It 'maps an in_progress check run to pending'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"in_progress","conclusion":null}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pending"}]'
  End

  It 'maps a completed/success check run to pass'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pass"}]'
  End

  It 'maps a completed/neutral check run to pass'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"neutral"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pass"}]'
  End

  It 'maps a completed/skipped check run to skipping'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"skipped"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"skipping"}]'
  End

  It 'maps a completed/cancelled check run to cancel'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"cancelled"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"cancel"}]'
  End

  It 'maps a completed/failure check run to fail'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"failure"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"fail"}]'
  End

  It 'maps a completed/timed_out check run to fail'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"timed_out"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"fail"}]'
  End

  It 'maps a completed/action_required check run to fail'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"action_required"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"fail"}]'
  End

  It 'maps a completed/stale check run to fail'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"stale"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"fail"}]'
  End

  It 'maps a completed/startup_failure check run to fail'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"startup_failure"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"fail"}]'
  End

  It 'maps a completed check run with a null conclusion to pending, never pass'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":null}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pending"}]'
  End

  It 'maps a completed check run with an unrecognised conclusion to pending, never pass'
    When call checks_to_buckets '{"check_runs":[{"name":"pytest","status":"completed","conclusion":"weird_future_value"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"pytest","bucket":"pending"}]'
  End

  It 'maps a success commit status to pass'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"context":"legacy-ci","state":"success"}]}'
    The output should equal '[{"name":"legacy-ci","bucket":"pass"}]'
  End

  It 'maps a pending commit status to pending'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"context":"legacy-ci","state":"pending"}]}'
    The output should equal '[{"name":"legacy-ci","bucket":"pending"}]'
  End

  It 'maps an error commit status to fail'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"context":"legacy-ci","state":"error"}]}'
    The output should equal '[{"name":"legacy-ci","bucket":"fail"}]'
  End

  It 'maps a failure commit status to fail'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"context":"legacy-ci","state":"failure"}]}'
    The output should equal '[{"name":"legacy-ci","bucket":"fail"}]'
  End

  It 'maps an unrecognised commit-status state to pending, never pass'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"context":"legacy-ci","state":"weird"}]}'
    The output should equal '[{"name":"legacy-ci","bucket":"pending"}]'
  End

  It 'takes the status name from .context, ignoring any .name field on the status object'
    When call checks_to_buckets '{"check_runs":[]}' '{"statuses":[{"name":"WRONG","context":"right-name","state":"success"}]}'
    The output should equal '[{"name":"right-name","bucket":"pass"}]'
  End

  It 'concatenates check-run and status entries from both payloads, dropping nothing'
    cr='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    st='{"statuses":[{"context":"legacy-ci","state":"success"}]}'
    When call checks_to_buckets "$cr" "$st"
    The output should equal '[{"name":"pytest","bucket":"pass"},{"name":"legacy-ci","bucket":"pass"}]'
  End

  It 'reads every page when --paginate concatenates multiple JSON documents in one payload'
    cr=$(printf '%s\n%s\n' \
      '{"check_runs":[{"name":"page1","status":"completed","conclusion":"success"}]}' \
      '{"check_runs":[{"name":"page2","status":"completed","conclusion":"success"}]}')
    When call checks_to_buckets "$cr" '{"statuses":[]}'
    The output should equal '[{"name":"page1","bucket":"pass"},{"name":"page2","bucket":"pass"}]'
  End

  It 'contributes zero entries from a page missing its check_runs/statuses key, without a jq error'
    cr=$(printf '%s\n%s\n' '{"total_count":0}' '{"check_runs":[{"name":"only-one","status":"completed","conclusion":"success"}]}')
    When call checks_to_buckets "$cr" '{"total_count":0}'
    The output should equal '[{"name":"only-one","bucket":"pass"}]'
  End

  It 'maps a null check-run name to an empty string instead of crashing downstream'
    When call checks_to_buckets '{"check_runs":[{"name":null,"status":"completed","conclusion":"success"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"","bucket":"pass"}]'
  End

  It 'maps a missing check-run name field to an empty string'
    When call checks_to_buckets '{"check_runs":[{"status":"completed","conclusion":"success"}]}' '{"statuses":[]}'
    The output should equal '[{"name":"","bucket":"pass"}]'
  End

  It 'evaluate_checks does not crash on a checks_to_buckets result carrying an empty name'
    buckets=$(checks_to_buckets '{"check_runs":[{"name":null,"status":"completed","conclusion":"success"}]}' '{"statuses":[]}')
    When call evaluate_checks "$buckets"
    The output should equal 'PASS'
  End

  It 'preserves a check-run name containing quotes and backslashes through the jq round-trip'
    cr='{"check_runs":[{"name":"weird \"quoted\" \\ name","status":"completed","conclusion":"success"}]}'
    When call checks_to_buckets "$cr" '{"statuses":[]}'
    The output should equal '[{"name":"weird \"quoted\" \\ name","bucket":"pass"}]'
  End

  It 'treats an empty check-runs payload as zero entries, not a jq error'
    When call checks_to_buckets '' '{"statuses":[{"context":"x","state":"success"}]}'
    The output should equal '[{"name":"x","bucket":"pass"}]'
  End

  It 'treats both payloads empty as zero entries, not a jq error'
    When call checks_to_buckets '' ''
    The output should equal '[]'
  End

  It 'treats an unexpected-shape payload (e.g. a Not-Found error body) as zero entries, not a crash'
    When call checks_to_buckets '{"message":"Not Found"}' '{"message":"Not Found"}'
    The output should equal '[]'
  End

  It 'excludes a failing CodeRabbit commit status beside a passing check run, across both payload classes'
    cr='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    st='{"statuses":[{"context":"CodeRabbit","state":"failure"}]}'
    buckets=$(checks_to_buckets "$cr" "$st")
    When call evaluate_checks "$buckets"
    The output should equal 'PASS'
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
	printf 'ready\n' > "$GH_STUB_READY_FIFO"
	exec 9< "$GH_STUB_RELEASE_FIFO"
	[ -z "${GH_STUB_HANG_MARKER:-}" ] || printf done > "$GH_STUB_HANG_MARKER"
fi
exit "${GH_STUB_STATUS:-0}"
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }

  setup_synchronised_timeout() {
    export REAL_TIMEOUT
    REAL_TIMEOUT=$(command -v timeout)
    mkfifo "$stubdir/ready" "$stubdir/release"
    export GH_STUB_READY_FIFO="$stubdir/ready" GH_STUB_RELEASE_FIFO="$stubdir/release"
    export TIMEOUT_STUB_ARGS="$stubdir/timeout-args"
    cat > "$stubdir/date" <<'STUB'
#!/bin/sh
printf '100\n'
STUB
    cat > "$stubdir/timeout" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" > "$TIMEOUT_STUB_ARGS"
case "$1" in
	-k|-s) shift 2 ;;
esac
shift
"$@" &
child=$!
if ! "$REAL_TIMEOUT" 10 sh -c 'IFS= read -r event < "$GH_STUB_READY_FIFO"'; then
	echo 'stuck/environment: gh stub did not signal readiness' >&2
	kill -KILL "$child" 2>/dev/null || :
	wait "$child" 2>/dev/null || :
	exit 125
fi
kill -TERM "$child"
if [ -n "${GH_STUB_IGNORE_TERM:-}" ]; then
	kill -0 "$child" || exit 125
	[ -z "${TIMEOUT_STUB_KILL_MARKER:-}" ] || true > "$TIMEOUT_STUB_KILL_MARKER"
	kill -KILL "$child"
fi
wait "$child" 2>/dev/null || :
exit 124
STUB
    chmod +x "$stubdir/date" "$stubdir/timeout"
    deadline=102
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
    setup_synchronised_timeout
    export GH_STUB_HANG=1
    When call gh_bounded api endpoint
    The status should equal 124
    The output should equal 'partial stdout + stderr'
    The contents of file "$TIMEOUT_STUB_ARGS" should equal '-k 1 1 gh api endpoint'
  End

  It 'kills a TERM-ignoring gh child before it can outlive the deadline'
    setup_synchronised_timeout
    export GH_STUB_HANG=1 GH_STUB_IGNORE_TERM=1
    export GH_STUB_HANG_MARKER="$stubdir/outlived"
    export TIMEOUT_STUB_KILL_MARKER="$stubdir/killed"
    When call gh_bounded api endpoint
    The status should equal 124
    The output should include 'partial stdout + stderr'
    The file "$TIMEOUT_STUB_KILL_MARKER" should be exist
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

  # A flag whose value is missing used to reach a bare `shift 2`: fatal under dash (with
  # a raw "can't shift that many" instead of the usage text), but merely non-zero under
  # a bash-provided /bin/sh, where `$1` stayed put and the parse loop SPUN FOREVER --
  # a hang that never reaches the deadline logic at all.
  It 'exits 2 with usage when --exclude is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --exclude
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'exits 2 with usage when --sha is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'exits 2 with usage when --repo is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'exits 2 with usage when --max-iter is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --max-iter
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'exits 2 with usage when --pr is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo o/r --pr
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'exits 2 with usage when --interval is given no value'
    When run timeout 10 sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval
    The status should equal 2
    The stderr should include 'usage:'
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
  # gh now serves 3 call shapes: `pr view` (SHA arm/re-verify), `.../check-runs`,
  # `.../status` -- GH_STUB_CHECK_RUNS / GH_STUB_STATUS_PAYLOAD replace the old
  # single-shape GH_STUB_CHECKS fixture (#1690: checks moved SHA-addressed).
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
count=0
[ ! -f "${GH_STUB_COUNT_FILE:-}" ] || count=$(cat "$GH_STUB_COUNT_FILE")
count=$((count + 1))
[ -z "${GH_STUB_COUNT_FILE:-}" ] || printf '%s\n' "$count" > "$GH_STUB_COUNT_FILE"
case " ${GH_STUB_FAIL_CALLS:-} " in
	*" $count "*)
		printf '%s\n' "${GH_STUB_FAIL_OUTPUT:-HTTP 404}"
		[ -z "${GH_STUB_MARK_FAILURE:-}" ] || true > "$GH_STUB_POLL_MARKER"
		exit 1
		;;
esac
case "$*" in
	*"pr view "*)
		printf '%s\n' "${GH_STUB_SHA:-deadbeef}"
		[ -z "${GH_STUB_ARMED_MARKER:-}" ] || true > "$GH_STUB_ARMED_MARKER"
		;;
	*"/check-runs"*) printf '%s\n' "$GH_STUB_CHECK_RUNS" ;;
	*"/status"*)
		printf '%s\n' "$GH_STUB_STATUS_PAYLOAD"
		[ -z "${GH_STUB_MARK_STATUS:-}" ] || true > "$GH_STUB_POLL_MARKER"
		;;
esac
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'
  script="scripts/agent/wait-checks.sh"

  pending_fixture() {
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"in_progress","conclusion":null}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
  }

  setup_near_deadline() {
    cat > "$stubdir/date" <<'STUB'
#!/bin/sh
if [ -e "$GH_STUB_POLL_MARKER" ]; then
	printf '100\n'
else
	printf '0\n'
fi
STUB
    cat > "$stubdir/sleep" <<'STUB'
#!/bin/sh
printf '%s\n' "$1" >> "$WAIT_SLEEP_FILE"
STUB
    chmod +x "$stubdir/date" "$stubdir/sleep"
    export GH_STUB_POLL_MARKER="$stubdir/polled"
    export PFB_WAIT_DEADLINE=103 WAIT_SLEEP_FILE="$stubdir/sleeps"
  }

  It 'reports TIMEOUT when checks stay pending through the cap'
    pending_fixture
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 2
    The line 1 of output should equal 'TIMEOUT'
  End

  # #1756: the exclusion pattern is DATA. A pattern jq cannot compile used to make the
  # whole filter collapse -- empty counts, `[: : integer expected`, verdict PENDING --
  # so a hard FAIL was polled past and surfaced as a blind TIMEOUT. Reject it at the
  # boundary (exit 2, usage/precondition) instead.
  failing_fixture() {
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
  }

  # A quote is a literal regex character: `sn"yk` is a perfectly valid pattern and must
  # be MATCHED, not rejected. It only ever broke because it terminated the jq string.
  It 'matches an --exclude regex containing a quote as a literal pattern, gating the failing check'
    failing_fixture
    When run sh "$script" --repo o/r --pr 1 --exclude 'sn"yk' --interval 0 --max-iter 2
    The status should equal 0
    The line 2 of output should equal '[{"name":"pytest","bucket":"fail"}]'
    The line 3 of output should equal 'FAIL'
    The output should not include 'TIMEOUT'
  End

  # The negative case above only proves the pattern does not blow up. Pin the positive
  # half too: a check whose name really does contain the quote is excluded BY it, so the
  # pattern is demonstrably being matched rather than merely tolerated.
  It 'excludes the check a quote-bearing --exclude regex actually matches'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"},{"name":"sn\"yk-advisory","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh "$script" --repo o/r --pr 1 --exclude 'sn"yk' --interval 0 --max-iter 2
    The status should equal 0
    The line 2 of output should equal '[{"name":"pytest","bucket":"pass"}]'
    The line 3 of output should equal 'PASS'
  End

  It 'rejects an --exclude regex ending in a dangling backslash'
    failing_fixture
    When run sh "$script" --repo o/r --pr 1 --exclude 'snyk\' --interval 0 --max-iter 2
    The status should equal 2
    The stderr should include 'not a valid regex'
    The output should not include 'TIMEOUT'
  End

  # An empty pattern compiles fine and matches EVERY name, so it excluded every check:
  # `total` fell to 0, the verdict became EMPTY, and the loop -- which only acts on
  # PASS/FAIL -- drained to TIMEOUT with a hard failure sitting right there. Same silent
  # class as an uncompilable pattern, so it dies at the same boundary.
  It 'rejects an empty --exclude instead of excluding every check and draining to TIMEOUT'
    failing_fixture
    When run sh "$script" --repo o/r --pr 1 --exclude '' --interval 0 --max-iter 2
    The status should equal 2
    The stderr should include 'must not be empty'
    The output should not include 'TIMEOUT'
    The output should not include 'PASS'
  End

  It 'treats a jq-injecting --exclude value as a pattern, never as program text'
    failing_fixture
    When run sh "$script" --repo o/r --pr 1 --exclude 'a") or true or ("' --interval 0 --max-iter 2
    The status should equal 2
    The stderr should include 'not a valid regex'
    The output should not include 'TIMEOUT'
    The output should not include 'PASS'
  End

  It 'accepts a valid custom --exclude regex carrying anchors and a character class'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"},{"name":"code/snyk (BBcan177)","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh "$script" --repo o/r --pr 1 --exclude '^code/snyk( [(][^)]*[)])?$' --interval 0 --max-iter 2
    The status should equal 0
    The line 2 of output should equal '[{"name":"pytest","bucket":"pass"}]'
    The line 3 of output should equal 'PASS'
  End

  It 'honours the wall-clock deadline even when a verdict would be reached'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    # Advance the fake clock only after the gh stub signals that SHA arming completed.
    # The loop must then break on its own deadline check before fetching the checks.
    cat > "$stubdir/date" <<'STUB'
#!/bin/sh
if [ -e "$GH_STUB_ARMED_MARKER" ]; then
	printf '200\n'
else
	printf '0\n'
fi
STUB
    chmod +x "$stubdir/date"
    export GH_STUB_ARMED_MARKER="$stubdir/armed"
    export PFB_WAIT_DEADLINE=101
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 3
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'resets the failure streak after a successful pending snapshot'
    pending_fixture
    export GH_STUB_COUNT_FILE="$stubdir/count"
    # call 1 = arm `pr view` (must succeed); each iteration is 1 call when check-runs
    # fails (short-circuits the status read) or 2 when it succeeds: iters 1-2 fail
    # (calls 2,3), iter 3 succeeds (calls 4,5) and resets the streak, iters 4-5 fail
    # (calls 6,7) -- never 3 consecutive, so TIMEOUT not GH-ERROR.
    export GH_STUB_FAIL_CALLS='2 3 6 7'
    When run sh "$script" --repo o/r --pr 1 --interval 0 --max-iter 5
    The status should equal 0
    The line 1 of output should equal 'TIMEOUT'
  End

  It 'caps sleep after a successful pending poll at the remaining deadline'
    setup_near_deadline
    export GH_STUB_MARK_STATUS=1
    pending_fixture
    When run sh "$script" --repo o/r --pr 1 --interval 99 --max-iter 1
    The line 1 of output should equal 'TIMEOUT'
    The contents of file "$WAIT_SLEEP_FILE" should equal '3'
  End

  It 'caps sleep after a failed poll at the remaining deadline'
    setup_near_deadline
    export GH_STUB_MARK_FAILURE=1
    export GH_STUB_COUNT_FILE="$stubdir/count"
    # call 1 = arm `pr view` (must succeed so the loop is reached at all); call 2 =
    # the single iteration's check-runs read, which fails.
    export GH_STUB_FAIL_CALLS='2'
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

Describe 'wait-checks.sh SHA pinning (#1690 regression)'
  setup_stub() {
    stubdir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/ghstub.XXXXXX")"
    cat > "$stubdir/gh" <<'STUB'
#!/bin/sh
argv="$*"
[ -z "${ARGV_LOG:-}" ] || printf '%s\n' "$argv" >> "$ARGV_LOG"
case "$argv" in
	*"pr checks"*)
		printf '%s\n' "$GH_STUB_PR_CHECKS_LEGACY"
		;;
	*"pr view "*)
		count=0
		[ ! -f "${GH_STUB_PRVIEW_COUNT_FILE:-/nonexistent}" ] || count=$(cat "$GH_STUB_PRVIEW_COUNT_FILE")
		count=$((count + 1))
		[ -z "${GH_STUB_PRVIEW_COUNT_FILE:-}" ] || printf '%s\n' "$count" > "$GH_STUB_PRVIEW_COUNT_FILE"
		case " ${GH_STUB_PRVIEW_FAIL_CALLS:-} " in
			*" $count "*) printf '%s\n' "${GH_STUB_PRVIEW_FAIL_OUTPUT:-pr view failed}" >&2; exit 1 ;;
		esac
		case " ${GH_STUB_PRVIEW_EMPTY_CALLS:-} " in
			*" $count "*) exit 0 ;;
		esac
		if [ "$count" -eq 1 ]; then
			printf '%s\n' "$GH_STUB_HEAD_SHA_1"
		else
			printf '%s\n' "${GH_STUB_HEAD_SHA_2:-$GH_STUB_HEAD_SHA_1}"
		fi
		;;
	*"/check-runs"*)
		if [ -z "${GH_STUB_EXPECT_SHA:-}" ]; then
			printf '%s\n' "$GH_STUB_CHECK_RUNS"
		else
			case "$argv" in
				*"/commits/$GH_STUB_EXPECT_SHA/check-runs"*) printf '%s\n' "$GH_STUB_CHECK_RUNS" ;;
				*) exit 1 ;;
			esac
		fi
		;;
	*"/status"*)
		if [ -z "${GH_STUB_EXPECT_SHA:-}" ]; then
			printf '%s\n' "$GH_STUB_STATUS_PAYLOAD"
		else
			case "$argv" in
				*"/commits/$GH_STUB_EXPECT_SHA/status"*) printf '%s\n' "$GH_STUB_STATUS_PAYLOAD" ;;
				*) exit 1 ;;
			esac
		fi
		;;
	*"/commits/"*)
		# The arm-time pin resolution (#2476): the real endpoint expands an
		# abbreviated ref to the commit's full 40-character OID. Serving the
		# canned value on ANY ref would let a resolution of the WRONG ref pass,
		# so GH_STUB_EXPECT_RAW_SHA pins the ref actually asked for, exactly as
		# GH_STUB_EXPECT_SHA pins the polled one above.
		[ -z "${GH_STUB_RESOLVE_FAIL:-}" ] || { printf '%s\n' 'HTTP 422' >&2; exit 1; }
		if [ -n "${GH_STUB_EXPECT_RAW_SHA:-}" ]; then
			case "$argv" in
				*"/commits/$GH_STUB_EXPECT_RAW_SHA "*|*"/commits/$GH_STUB_EXPECT_RAW_SHA") ;;
				*) exit 1 ;;
			esac
		fi
		printf '%s\n' "${GH_STUB_RESOLVED_SHA:-${GH_STUB_HEAD_SHA_1:-}}"
		;;
	*)
		exit 1
		;;
esac
STUB
    chmod +x "$stubdir/gh"
    PATH="$stubdir:$PATH"
  }
  cleanup_stub() { rm -rf "$stubdir"; }
  Before 'setup_stub'
  After 'cleanup_stub'

  It 'never reports PASS for a force-pushed head with zero registered checks, even though the previous commit was green (#1690)'
    export GH_STUB_PR_CHECKS_LEGACY='[{"name":"pytest","bucket":"pass"}]'
    export GH_STUB_HEAD_SHA_1='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    export GH_STUB_CHECK_RUNS='{"check_runs":[]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 2
    The output should include 'TIMEOUT'
    The output should not include 'PASS'
  End

  It 'reports STALE, never PASS, when the head moves after the pinned checks went green'
    export GH_STUB_PR_CHECKS_LEGACY='[{"name":"pytest","bucket":"pass"}]'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_HEAD_SHA_2='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The output should include 'STALE'
    The output should not include 'PASS'
    The output should include 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    The output should include 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    The status should equal 0
  End

  It 'reports PASS when the pinned SHA is all-green and the head has not moved'
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 1 of output should equal 'pinned=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    The line 2 of output should equal '[{"name":"pytest","bucket":"pass"}]'
    The line 3 of output should equal 'PASS'
  End

  It 'reports FAIL when the pinned SHA has a failing check and the head has not moved'
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 1 of output should equal 'pinned=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    The line 2 of output should equal '[{"name":"pytest","bucket":"fail"}]'
    The line 3 of output should equal 'FAIL'
  End

  It 'reports FAIL, retaining the hostile required check in the terminal JSON, when a snyk-named required check fails (#1706)'
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"},{"name":"snyk-adjacent-but-required","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[{"context":"code/snyk (pfBlockerNG)","state":"failure"}]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 1 of output should equal 'pinned=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    The line 2 of output should equal '[{"name":"pytest","bucket":"pass"},{"name":"snyk-adjacent-but-required","bucket":"fail"}]'
    The line 3 of output should equal 'FAIL'
  End

  It 'honours a caller-supplied broad --exclude regex unchanged (documented escape hatch)'
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"},{"name":"snyk-adjacent-but-required","status":"completed","conclusion":"failure"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --exclude snyk --interval 0 --max-iter 1
    The status should equal 0
    The line 2 of output should equal '[{"name":"pytest","bucket":"pass"}]'
    The line 3 of output should equal 'PASS'
  End

  It '--sha resolves without a pr view (that read stays for the pre-verdict re-verification)'
    explicit_sha='cccccccccccccccccccccccccccccccccccccccc'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1="$explicit_sha"
    export GH_STUB_EXPECT_SHA="$explicit_sha"
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha "$explicit_sha" --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '1'
  End

  # #2476: `headRefOid` is always the full 40-character OID, so an abbreviated --sha
  # could never equal it at the pre-verdict identity check -- a completed, fully green
  # wait was discarded as STALE. The pin is resolved to the full OID at arm time, so
  # both the SHA-addressed polls and `pinned=` carry the resolved value.
  It 'resolves an abbreviated --sha to the full OID, reaching the verdict instead of STALE'
    full_sha='cccccccccccccccccccccccccccccccccccccccc'
    export GH_STUB_HEAD_SHA_1="$full_sha"
    export GH_STUB_RESOLVED_SHA="$full_sha"
    export GH_STUB_EXPECT_RAW_SHA='ccccccccc'
    export GH_STUB_EXPECT_SHA="$full_sha"
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha ccccccccc --interval 0 --max-iter 1
    The status should equal 0
    The line 1 of output should equal "pinned=$full_sha"
    The line 3 of output should equal 'PASS'
    The output should not include 'STALE'
  End

  # The example above pins the polled address too, so the pre-fix script died at the
  # address rather than at the identity check. Here the API accepts the abbreviated
  # address -- as GitHub really does -- which is the shape that reported STALE.
  It 'reports the real verdict, never STALE, for an abbreviated --sha the API resolves'
    full_sha='cccccccccccccccccccccccccccccccccccccccc'
    export GH_STUB_HEAD_SHA_1="$full_sha"
    export GH_STUB_RESOLVED_SHA="$full_sha"
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha ccccccccc --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The output should not include 'STALE'
  End

  It 'fails loudly with GH-ERROR when the --sha pin cannot be resolved, never polling an unresolved ref'
    export GH_STUB_RESOLVE_FAIL=1
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha nosuchsha --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
    The output should include 'HTTP 422'
  End

  It 'fails loudly with GH-ERROR when arm-time SHA resolution itself errors (gh exits nonzero)'
    export GH_STUB_PRVIEW_FAIL_CALLS='1'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End

  It 'fails loudly with GH-ERROR when arm-time SHA resolution yields an empty value'
    export GH_STUB_HEAD_SHA_1=''
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
  End

  It 'recovers from transient arm-time pr-view failures within the retry budget, reaching a normal verdict'
    # A blip on the very first call (right after a force-push, when the API is
    # least settled) must not kill the whole wait: 2 failures then a success is
    # inside the same 3-strike tolerance the poll loop already has.
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_PRVIEW_FAIL_CALLS='1 2'
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The output should not include 'GH-ERROR'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '4'
  End

  It 'still fails loudly with GH-ERROR once the arm-time retry budget (3 attempts) is exhausted'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_PRVIEW_FAIL_CALLS='1 2 3'
    export GH_STUB_PRVIEW_FAIL_OUTPUT='HTTP 503'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
    The output should include 'HTTP 503'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '3'
  End

  It 'recovers from a transient pre-verdict re-read blip, reaching a normal verdict'
    # Same 3-strike tolerance as arm-time: a single blip on the re-read -- e.g. at
    # minute 39 of a 40-minute wait -- must not discard an otherwise-completed wait.
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_PRVIEW_FAIL_CALLS='2'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The output should not include 'GH-ERROR'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '3'
  End

  It 'still fails loudly with GH-ERROR once the pre-verdict re-read retry budget (3 attempts) is exhausted, never emitting a verdict'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_PRVIEW_FAIL_CALLS='2 3 4'
    export GH_STUB_PRVIEW_FAIL_OUTPUT='HTTP 503'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
    The output should include 'HTTP 503'
    The output should not include 'PASS'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '4'
  End

  It 'recovers from a single transient EMPTY pre-verdict re-read (not just a hard gh failure), reaching a normal verdict'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_PRVIEW_EMPTY_CALLS='2'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The output should not include 'GH-ERROR'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '3'
  End

  It 'treats a sustained empty pre-verdict re-read as GH-ERROR, never STALE (an empty read is not proof the head moved)'
    export GH_STUB_PRVIEW_COUNT_FILE="$stubdir/prview-count"
    export GH_STUB_HEAD_SHA_1='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    export GH_STUB_PRVIEW_EMPTY_CALLS='2 3 4'
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --interval 0 --max-iter 1
    The status should equal 1
    The line 1 of output should equal 'GH-ERROR'
    The output should not include 'STALE'
    The output should not include 'PASS'
    The contents of file "$GH_STUB_PRVIEW_COUNT_FILE" should equal '4'
  End

  It 'rejects an explicit empty --sha as a usage error, never falling through to an unpinned poll'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha '' --interval 0 --max-iter 1
    The status should equal 2
    The stderr should include 'usage:'
  End

  It 'passes a metacharacter-laden --sha through to gh as inert opaque data, never evaluated'
    canary="$stubdir/injected"
    weird='sha; touch '"$canary"'; $(touch '"$canary"')'
    export GH_STUB_HEAD_SHA_1="$weird"
    export GH_STUB_CHECK_RUNS='{"check_runs":[{"name":"pytest","status":"completed","conclusion":"success"}]}'
    export GH_STUB_STATUS_PAYLOAD='{"statuses":[]}'
    When run sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --sha "$weird" --interval 0 --max-iter 1
    The status should equal 0
    The line 3 of output should equal 'PASS'
    The file "$canary" should not be exist
  End
End
