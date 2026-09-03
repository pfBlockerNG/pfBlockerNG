#shellcheck shell=sh
# .githooks/pre-push root-graph freshness gate (issue #3139): a push that
# publishes anything is refused unless scripts/agent/check-graph-fresh.sh, run
# from the pushing tree, exits 0 -- stale (1), no graph (2) and missing Graphify
# (4) all refuse with the checker's own message. The checker runs once per push,
# after the cheap gates, and only in a tree that ships it.
#
# Fixture: a bare remote and clone A whose scripts/agent/check-graph-fresh.sh is a
# stub that logs each call and exits GRAPH_CHECK_RC with the real script's
# message shape. Direct rows feed the hook its stdin contract; the money rows run
# a real `git push` through core.hooksPath and read the remote tip afterwards.

Describe 'pre-push root-graph freshness gate (issue #3139)'
  hook="${PFB_ROOT}/.githooks/pre-push"
  Z40="0000000000000000000000000000000000000000"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prepushgraph.XXXXXX")"
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git_fixture -C "${base}/A" config user.email a@example.com
    git_fixture -C "${base}/A" config user.name A
    git_fixture -C "${base}/A" config commit.gpgsign false
    ( cd "${base}/A" && git_fixture checkout -q -b devel && echo one > f \
        && git_fixture add f && git_fixture commit -q -m c1 && git_fixture push -q origin devel \
        && echo two >> f && git_fixture add f && git_fixture commit -q -m c2 )
    a_local="$(git_fixture -C "${base}/A" rev-parse devel)"
    remote_tip="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel)"
    check_log="${base}/check.log"
    mkdir -p "${base}/A/scripts/agent"
    cat > "${base}/A/scripts/agent/check-graph-fresh.sh" <<'CHECK'
#!/bin/sh
printf 'check:%s:%s\n' "$PWD" "$*" >> "$GRAPH_CHECK_LOG"
case "${GRAPH_CHECK_RC:-0}" in
  0) echo 'check-graph-fresh.sh: graph is fresh' >&2 ;;
  1) echo "check-graph-fresh.sh: STALE: graphify-out/graph.json differs from a rebuild of this tree; run 'PYTHONHASHSEED=0 graphify update .' and commit graphify-out/graph.json" >&2 ;;
  2) echo 'check-graph-fresh.sh: no root graph; run /graphify' >&2 ;;
  4) echo 'TOOL-MISSING: graphify' >&2 ;;
esac
exit "${GRAPH_CHECK_RC:-0}"
CHECK
    export GRAPH_CHECK_LOG="$check_log"
  }

  cleanup() {
    rm -rf "$base"
    unset GRAPH_CHECK_LOG GRAPH_CHECK_RC
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  remote_tip_now() {
    git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel
  }

  # A markerless session: only the gates every push pays for run.
  human_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        sh "$hook" origin "${base}/remote.git"
  }
  agent_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
  }

  It 'lets a fast-forward through when the tree graph is fresh'
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal 'check-graph-fresh.sh: graph is fresh'
    The contents of file "$check_log" should equal "check:${base}/A:"
  End

  It 'refuses the push with the checker message when the graph is stale'
    export GRAPH_CHECK_RC=1
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'STALE'
    The stderr should include "PYTHONHASHSEED=0 graphify update ."
  End

  It 'refuses the push when the tree has no root graph (checker exit 2)'
    export GRAPH_CHECK_RC=2
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'no root graph'
  End

  It 'refuses the push when Graphify is missing (checker exit 4): the tool is mandatory'
    export GRAPH_CHECK_RC=4
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'graphify'
  End

  It 'grades the tree once per push, however many refs it carries'
    two_refs() {
      cd "${base}/A" && printf '%s\n%s\n' \
        "refs/heads/devel $a_local refs/heads/devel $remote_tip" \
        "refs/heads/other $a_local refs/heads/other $Z40" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
          -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
          sh "$hook" origin "${base}/remote.git"
    }
    When run two_refs
    The status should equal 0
    The stderr should equal 'check-graph-fresh.sh: graph is fresh'
    The contents of file "$check_log" should equal "check:${base}/A:"
  End

  It 'does not rebuild for a deletion-only push'
    export GRAPH_CHECK_RC=1
    When run human_hook "refs/heads/devel $Z40 refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
    The file "$check_log" should not be exist
  End

  It 'does not grade a tree that ships no checker (a line that never adopted the invariant)'
    rm -f "${base}/A/scripts/agent/check-graph-fresh.sh"
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
    The file "$check_log" should not be exist
  End

  It 'keeps the lease guard ahead of the rebuild: a denied agent rewrite never reaches the checker'
    export GRAPH_CHECK_RC=1
    When run agent_hook "refs/heads/devel $a_local refs/heads/devel 1111111111111111111111111111111111111111"
    The status should equal 1
    The stderr should include 'unfetched'
    The file "$check_log" should not be exist
  End

  # The money rows: a REAL push through core.hooksPath, with the stale/fresh
  # verdict as the only difference between refusal and landing.
  It 'refuses a real push and leaves the remote tip untouched when the graph is stale'
    real_push_stale() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI GRAPH_CHECK_RC=1 \
          git push origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_push_stale
    The status should not equal 0
    The stderr should include 'STALE'
    The result of function remote_tip_now should equal "$remote_tip"
    The contents of file "$check_log" should equal "check:${base}/A:"
  End

  It 'lands the same real push when the graph is fresh (control)'
    real_push_fresh() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI \
          git push -q origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_push_fresh
    The status should equal 0
    The stderr should include 'graph is fresh'
    The result of function remote_tip_now should equal "$a_local"
    The contents of file "$check_log" should equal "check:${base}/A:"
  End
End
