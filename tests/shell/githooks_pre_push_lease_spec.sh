#shellcheck shell=sh
# .githooks/pre-push agent lease-by-effect guard (issue #1307): a recognized
# Claude, Codex, Copilot, Grok, or OMP/Pi session that rewrites a remote branch's
# history is allowed only
# when the hook's advertised remote oid equals the local remote-tracking ref —
# i.e. the agent has fetched the history it is about to overwrite. That is
# --force-with-lease's check, enforced on the push's EFFECT, so an alias or a
# script that never spells a force flag is still caught. Fast-forwards, branch
# creations/deletions, tag refs, and sessions with no recognized agent marker pass untouched.
#
# Fixture: a bare remote, clone A (the agent, whose tracking ref goes stale),
# and clone B (another session that advances the remote behind A's back).
# Direct rows feed the hook its stdin contract ("<lref> <lsha> <rref> <rsha>")
# from A; the integration rows run a real `git push --force` through
# core.hooksPath with a human control proving the deny is caused by the guard.

Describe 'pre-push agent lease-by-effect guard (issue #1307)'
  hook="${PFB_ROOT}/.githooks/pre-push"
  Z40="0000000000000000000000000000000000000000"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/prepushlease.XXXXXX")"
    git_fixture init -q --bare "${base}/remote.git"
    git_fixture clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git_fixture -C "${base}/A" config user.email a@example.com
    git_fixture -C "${base}/A" config user.name A
    git_fixture -C "${base}/A" config commit.gpgsign false
    ( cd "${base}/A" && git_fixture checkout -q -b devel && echo one > f \
        && git_fixture add f && git_fixture commit -q -m c1 && git_fixture push -q origin devel )
    git_fixture clone -q "${base}/remote.git" "${base}/B" 2>/dev/null
    git_fixture -C "${base}/B" config user.email b@example.com
    git_fixture -C "${base}/B" config user.name B
    git_fixture -C "${base}/B" config commit.gpgsign false
    ( cd "${base}/B" && git_fixture checkout -q devel && echo two >> f \
        && git_fixture add f && git_fixture commit -q -m c2-other && git_fixture push -q origin devel )
    # A now diverges; its tracking ref still holds c1 while the remote is at c2.
    ( cd "${base}/A" && git_fixture commit -q --amend -m c1-amended )
    a_local="$(git_fixture -C "${base}/A" rev-parse devel)"
    a_tracking="$(git_fixture -C "${base}/A" rev-parse refs/remotes/origin/devel)"
    remote_tip="$(git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel)"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  remote_tip_now() {
    git_fixture -C "${base}/remote.git" rev-parse refs/heads/devel
  }

  # Feed one stdin line to the hook from inside clone A, agent env explicit
  # per row (the suite itself may run under CLAUDECODE=1).
  agent_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
  }
  codex_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CODEX_THREAD_ID=codex-test \
        sh "$hook" origin "${base}/remote.git"
  }
  grok_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
        -u COPILOT_CLI -u CODEX_THREAD_ID -u OMP_CLI -u PI_CLI \
        GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$hook" origin "${base}/remote.git"
  }
  omp_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
        -u PI_CLI OMP_CLI=1 sh "$hook" origin "${base}/remote.git"
  }
  pi_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
        -u OMP_CLI PI_CLI=1 sh "$hook" origin "${base}/remote.git"
  }
  human_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        sh "$hook" origin "${base}/remote.git"
  }

  It 'denies an agent history rewrite when the remote moved past the tracking ref'
    When run agent_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
    The stderr should include 'git fetch origin'
  End

  It 'allows the same rewrite once the tracking ref matches the advertised remote'
    git_fixture -C "${base}/A" fetch -q origin
    fresh_tracking() {
      tracking="$(git_fixture -C "${base}/A" rev-parse refs/remotes/origin/devel)"
      [ "$tracking" = "$remote_tip" ] || { echo "tracking=$tracking != remote=$remote_tip" >&2; return 1; }
      agent_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    }
    When run fresh_tracking
    The status should equal 0
    The stderr should equal ''
  End

  It 'denies the same stale rewrite for a Codex session'
    When run codex_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for a Grok session'
    When run grok_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for an OMP session'
    When run omp_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'denies the same stale rewrite for a Pi-compatible session'
    When run pi_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'allows an agent fast-forward push with a stale tracking ref'
    ff_push() {
      cd "${base}/A" && git_fixture fetch -q origin \
        && git_fixture update-ref refs/remotes/origin/devel "$a_tracking" \
        && git_fixture checkout -q -B devel "$remote_tip" && echo three >> f \
        && git_fixture add f && git_fixture commit -q -m c3 \
        && agent_hook "refs/heads/devel $(git_fixture rev-parse devel) refs/heads/devel $remote_tip"
    }
    When run ff_push
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows an agent branch creation'
    When run agent_hook "refs/heads/new $a_local refs/heads/new $Z40"
    The status should equal 0
    The stderr should equal ''
  End

  It 'allows an agent branch deletion'
    When run agent_hook "refs/heads/devel $Z40 refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  It 'ignores tag refs (a non-version tag passes untouched)'
    When run agent_hook "refs/tags/scratch $a_local refs/tags/scratch $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  It 'denies a multi-ref push whose second ref is the stale rewrite'
    two_refs() {
      cd "${base}/A" && printf '%s\n%s\n' \
        "refs/heads/new $a_local refs/heads/new $Z40" \
        "refs/heads/devel $a_local refs/heads/devel $remote_tip" \
        | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
    }
    When run two_refs
    The status should equal 1
    The stderr should include 'unfetched'
  End

  It 'leaves a human history rewrite to git itself'
    When run human_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 0
    The stderr should equal ''
  End

  # The money rows: a REAL bare force push through core.hooksPath. The human
  # control proves the abort is caused by the guard, not the harness setup.
  It 'blocks a real agent force-push and leaves the remote tip untouched'
    real_force() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CLAUDECODE=1 git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'blocks the same real force-push for a Codex agent marker'
    real_force_codex() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CODEX_THREAD_ID=codex-test git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_codex
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'blocks the same real force-push for a Grok agent marker'
    real_force_grok() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
          GROK_AGENT=1 GROK_SESSION_ID=grok-test \
          git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_grok
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'lands the same real force-push for a human (control)'
    real_force_human() {
      cd "${base}/A" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          git push --force origin devel # git-env-scrub-guard: allow hook-under-test push
    }
    When run real_force_human
    The status should equal 0
    The result of function remote_tip_now should equal "$a_local"
  End
End
