#shellcheck shell=sh
# .githooks/pre-push root-graph freshness gate (issue #3139): a push that
# publishes anything is refused unless scripts/agent/check-graph-fresh.sh exits 0
# for the TREE OF EVERY PUSHED TIP -- stale (1), no graph (2) and missing
# Graphify (4) all refuse with the checker's own message. Each distinct tip is
# checked out into a detached scratch worktree under the sibling worktrees root
# (<repo-parent>/.<repo>_worktrees/.graph-check-<sha7>, the work-branch.sh
# layout), graded there, and the scratch is removed whatever the verdict. The
# checked-out tree is never what is graded: uncommitted bytes or another branch
# at HEAD would launder a stale commit. Intermediate commits of a multi-commit
# push are not graded. The gate runs after the cheap gates, and only for a tip
# whose OWN tree ships the checker: the checkout's checker is the executable and
# decides nothing about whether a tip is graded.
#
# Fixture: a bare remote and clone A whose devel commits scripts/agent/check-graph-fresh.sh
# as a stub that logs each call (cwd and the graded path) and grades the graph
# bytes of the tree it is handed: 'fresh graph' passes, anything else is stale,
# absent is exit 2; GRAPH_CHECK_RC forces a verdict. Direct rows feed the hook its
# stdin contract; the money rows run a real `git push` through core.hooksPath and
# read the remote afterwards.

Describe 'pre-push root-graph freshness gate (issue #3139)'
  hook="${PFB_ROOT}/.githooks/pre-push"
  Z40="0000000000000000000000000000000000000000"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prepushgraph.XXXXXX")"
    base="$(cd "$base" && pwd -P)"
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git_fixture -C "${base}/A" config user.email a@example.com
    git_fixture -C "${base}/A" config user.name A
    git_fixture -C "${base}/A" config commit.gpgsign false
    mkdir -p "${base}/A/graphify-out" "${base}/A/scripts/agent"
    printf 'fresh graph\n' > "${base}/A/graphify-out/graph.json"
    check_log="${base}/check.log"
    cat > "${base}/A/scripts/agent/check-graph-fresh.sh" <<'CHECK'
#!/bin/sh
target=${1:-.}
printf 'check:%s:%s\n' "$PWD" "$*" >> "$GRAPH_CHECK_LOG"
[ ! -e "$target/graphify-out/cache/warm" ] || printf 'cache:warm\n' >> "$GRAPH_CHECK_LOG"
rc=${GRAPH_CHECK_RC:-}
if [ -z "$rc" ]; then
  if [ ! -f "$target/graphify-out/graph.json" ]; then rc=2
  elif [ "$(cat "$target/graphify-out/graph.json")" = 'fresh graph' ]; then rc=0
  else rc=1
  fi
fi
case "$rc" in
  0) echo 'check-graph-fresh.sh: graph is fresh' >&2 ;;
  1) echo "check-graph-fresh.sh: STALE: graphify-out/graph.json differs from a rebuild of this tree; run 'PYTHONHASHSEED=0 graphify update .' and commit graphify-out/graph.json" >&2 ;;
  2) echo 'check-graph-fresh.sh: no root graph; run /graphify' >&2 ;;
  4) echo 'TOOL-MISSING: graphify' >&2 ;;
esac
exit "$rc"
CHECK
    export GRAPH_CHECK_LOG="$check_log"
    ( cd "${base}/A" && git_fixture checkout -q -b devel && echo one > f \
        && git_fixture add f graphify-out/graph.json scripts/agent/check-graph-fresh.sh \
        && git_fixture commit -q -m c1 && git_fixture push -q origin devel \
        && echo two >> f && git_fixture add f && git_fixture commit -q -m c2 )
    a_local="$(git_fixture -C "${base}/A" rev-parse devel)"
    remote_tip="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel)"
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
  remote_has() {
    git_fixture -C "${base}/remote.git" rev-parse --verify -q "refs/heads/$1" >/dev/null && echo yes || echo no
  }
  # The scratch worktree the hook grades commit $1 in, and what is left of any.
  scratch_of() { printf '%s/.A_worktrees/.graph-check-%.7s' "$base" "$1"; }
  scratch_leftovers() {
    git_fixture -C "${base}/A" worktree list --porcelain | grep 'graph-check' || true
    ls -A "${base}/.A_worktrees" 2>/dev/null || true
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
  # A real push through core.hooksPath, markerless.
  real_push() {
    cd "${base}/A" \
      && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
      && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
        -u OMP_CLI -u PI_CLI \
        git push -q origin "$@" # git-env-scrub-guard: allow hook-under-test push
  }
  # A line that never adopted the invariant: its tree ships neither checker nor
  # graph, so grading it would refuse (exit 2). HEAD returns to devel, which ships both.
  rel_tip() {
    cd "${base}/A" && git_fixture checkout -q -b rel \
      && git_fixture rm -q -r scripts graphify-out && git_fixture commit -q -m rel \
      && git_fixture checkout -q devel && git_fixture rev-parse rel
  }

  It 'lets a fast-forward through when the pushed tip graph is fresh, grading it in a scratch worktree that is gone afterwards'
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal 'check-graph-fresh.sh: graph is fresh'
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
    The result of function scratch_leftovers should equal ''
  End

  It 'refuses the push with the checker message when the graph is stale, and removes the scratch worktree'
    export GRAPH_CHECK_RC=1
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'STALE'
    The stderr should include "PYTHONHASHSEED=0 graphify update ."
    The result of function scratch_leftovers should equal ''
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

  It 'grades a tip once, however many refs carry it'
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
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
  End

  It 'grades every distinct tip of a multi-ref push, each in its own scratch worktree'
    two_tips() {
      cd "${base}/A" && printf '%s\n%s\n' \
        "refs/heads/devel $a_local refs/heads/devel $remote_tip" \
        "refs/heads/other $remote_tip refs/heads/other $Z40" \
        | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
          -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
          sh "$hook" origin "${base}/remote.git"
    }
    When run two_tips
    The status should equal 0
    The line 1 of contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
    The line 2 of contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$remote_tip")"
    The result of function scratch_leftovers should equal ''
  End

  It 'seeds the scratch worktree with the checked-out graphify-out/cache so the rebuild stays warm'
    mkdir -p "${base}/A/graphify-out/cache"
    true > "${base}/A/graphify-out/cache/warm"
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal 'check-graph-fresh.sh: graph is fresh'
    The line 1 of contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
    The line 2 of contents of file "$check_log" should equal 'cache:warm'
  End

  It 'does not rebuild for a deletion-only push'
    export GRAPH_CHECK_RC=1
    When run human_hook "refs/heads/devel $Z40 refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
    The file "$check_log" should not be exist
  End

  It 'does not grade a pushed tip whose tree ships no checker (a line that never adopted the invariant), whatever the checkout ships'
    tip=$(rel_tip)
    When run human_hook "refs/heads/rel $tip refs/heads/rel $Z40"
    The status should equal 0
    The stderr should equal ''
    The file "$check_log" should not be exist
    The result of function scratch_leftovers should equal ''
  End

  It 'refuses a pushed tip that ships the checker when the checkout does not: nothing here can grade it'
    rm -f "${base}/A/scripts/agent/check-graph-fresh.sh"
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'ships scripts/agent/check-graph-fresh.sh but this checkout does not'
    The file "$check_log" should not be exist
    The result of function scratch_leftovers should equal ''
  End

  It 'refuses the push and leaves a scratch it did not cut in place (a concurrent push of the same tip owns it)'
    mkdir -p "${base}/.A_worktrees"
    git_fixture -C "${base}/A" worktree add -q --detach "$(scratch_of "$a_local")" "$a_local"
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'retry the push'
    The file "$check_log" should not be exist
    The result of function scratch_leftovers should include "$(scratch_of "$a_local")"
  End

  It 'keeps the lease guard ahead of the rebuild: a denied agent rewrite never reaches the checker'
    export GRAPH_CHECK_RC=1
    When run agent_hook "refs/heads/devel $a_local refs/heads/devel 1111111111111111111111111111111111111111"
    The status should equal 1
    The stderr should include 'unfetched'
    The file "$check_log" should not be exist
  End

  # The money rows: a REAL push through core.hooksPath, with the stale/fresh
  # verdict of the PUSHED TIP as the only difference between refusal and landing.
  It 'refuses a real push and leaves the remote tip untouched when the graph is stale'
    export GRAPH_CHECK_RC=1
    real_push_stale() {
      [ "$(remote_tip_now)" = "$remote_tip" ] && real_push devel
    }
    When run real_push_stale
    The status should not equal 0
    The stderr should include 'STALE'
    The result of function remote_tip_now should equal "$remote_tip"
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
    The result of function scratch_leftovers should equal ''
  End

  It 'refuses a real push of a stale committed graph even when the working tree holds fresh bytes (a dirty tree launders nothing)'
    stale_head=$(cd "${base}/A" && printf 'stale graph\n' > graphify-out/graph.json \
      && git_fixture add graphify-out/graph.json && git_fixture commit -q -m stale \
      && printf 'fresh graph\n' > graphify-out/graph.json && git_fixture rev-parse devel)
    When run real_push devel
    The status should not equal 0
    The stderr should include 'STALE'
    The result of function remote_tip_now should equal "$remote_tip"
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$stale_head")"
    The result of function scratch_leftovers should equal ''
  End

  It 'refuses a real push of a branch other than HEAD when ITS tip is stale (HEAD stays on a fresh devel)'
    stale_tip=$(cd "${base}/A" && git_fixture checkout -q -b stalebr \
      && printf 'stale graph\n' > graphify-out/graph.json \
      && git_fixture add graphify-out/graph.json && git_fixture commit -q -m stale \
      && git_fixture checkout -q devel && git_fixture rev-parse stalebr)
    When run real_push stalebr
    The status should not equal 0
    The stderr should include 'STALE'
    The value "$(remote_has stalebr)" should equal 'no'
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$stale_tip")"
    The result of function scratch_leftovers should equal ''
  End

  It 'lands the same real push when the graph is fresh (control)'
    real_push_fresh() {
      [ "$(remote_tip_now)" = "$remote_tip" ] && real_push devel
    }
    When run real_push_fresh
    The status should equal 0
    The stderr should include 'graph is fresh'
    The result of function remote_tip_now should equal "$a_local"
    The contents of file "$check_log" should equal "check:${base}/A:$(scratch_of "$a_local")"
    The result of function scratch_leftovers should equal ''
  End

  It 'lands a real push of a line that never adopted the invariant, ungraded, from a checkout that ships the checker'
    rel_tip >/dev/null
    When run real_push rel
    The status should equal 0
    The stderr should not include 'check-graph-fresh.sh'
    The value "$(remote_has rel)" should equal 'yes'
    The file "$check_log" should not be exist
    The result of function scratch_leftovers should equal ''
  End
End
