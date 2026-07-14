#shellcheck shell=sh
# .githooks/pre-push agent lease-by-effect guard (issue #1307): an agent
# (CLAUDECODE=1 or CODEX_THREAD_ID set) push that rewrites a remote branch's
# history is allowed only
# when the hook's advertised remote oid equals the local remote-tracking ref —
# i.e. the agent has fetched the history it is about to overwrite. That is
# --force-with-lease's check, enforced on the push's EFFECT, so an alias or a
# script that never spells a force flag is still caught. Fast-forwards, branch
# creations/deletions, tag refs, and humans (no CLAUDECODE) pass untouched.
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
    git init -q --bare "${base}/remote.git"
    git clone -q "${base}/remote.git" "${base}/A" 2>/dev/null
    git -C "${base}/A" config user.email a@example.com
    git -C "${base}/A" config user.name A
    git -C "${base}/A" config commit.gpgsign false
    ( cd "${base}/A" && git checkout -q -b devel && echo one > f \
        && git add f && git commit -q -m c1 && git push -q origin devel )
    git clone -q "${base}/remote.git" "${base}/B" 2>/dev/null
    git -C "${base}/B" config user.email b@example.com
    git -C "${base}/B" config user.name B
    git -C "${base}/B" config commit.gpgsign false
    ( cd "${base}/B" && git checkout -q devel && echo two >> f \
        && git add f && git commit -q -m c2-other && git push -q origin devel )
    # A now diverges; its tracking ref still holds c1 while the remote is at c2.
    ( cd "${base}/A" && git commit -q --amend -m c1-amended )
    a_local="$(git -C "${base}/A" rev-parse devel)"
    a_tracking="$(git -C "${base}/A" rev-parse refs/remotes/origin/devel)"
    remote_tip="$(git -C "${base}/remote.git" rev-parse refs/heads/devel)"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  remote_tip_now() {
    git -C "${base}/remote.git" rev-parse refs/heads/devel
  }

  # Feed one stdin line to the hook from inside clone A, agent env explicit
  # per row (the suite itself may run under CLAUDECODE=1).
  agent_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
  }
  codex_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE CODEX_THREAD_ID=codex-test \
        sh "$hook" origin "${base}/remote.git"
  }
  human_hook() {
    cd "${base}/A" && printf '%s\n' "$1" \
      | env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        sh "$hook" origin "${base}/remote.git"
  }

  It 'denies an agent history rewrite when the remote moved past the tracking ref'
    When run agent_hook "refs/heads/devel $a_local refs/heads/devel $remote_tip"
    The status should equal 1
    The stderr should include 'unfetched'
    The stderr should include 'git fetch origin'
  End

  It 'allows the same rewrite once the tracking ref matches the advertised remote'
    git -C "${base}/A" fetch -q origin
    fresh_tracking() {
      tracking="$(git -C "${base}/A" rev-parse refs/remotes/origin/devel)"
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

  It 'allows an agent fast-forward push with a stale tracking ref'
    ff_push() {
      cd "${base}/A" && git fetch -q origin \
        && git update-ref refs/remotes/origin/devel "$a_tracking" \
        && git checkout -q -B devel "$remote_tip" && echo three >> f \
        && git add f && git commit -q -m c3 \
        && agent_hook "refs/heads/devel $(git rev-parse devel) refs/heads/devel $remote_tip"
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
        | env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID CLAUDECODE=1 sh "$hook" origin "${base}/remote.git"
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
        && git config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID CLAUDECODE=1 git push --force origin devel
    }
    When run real_force
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'blocks the same real force-push for a Codex agent marker'
    real_force_codex() {
      cd "${base}/A" \
        && git config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL CODEX_THREAD_ID=codex-test git push --force origin devel
    }
    When run real_force_codex
    The status should not equal 0
    The stderr should include 'unfetched'
    The result of function remote_tip_now should equal "$remote_tip"
  End

  It 'lands the same real force-push for a human (control)'
    real_force_human() {
      cd "${base}/A" \
        && git config core.hooksPath "${PFB_ROOT}/.githooks" \
        && [ "$(remote_tip_now)" = "$remote_tip" ] \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID git push --force origin devel
    }
    When run real_force_human
    The status should equal 0
    The result of function remote_tip_now should equal "$a_local"
  End
End
