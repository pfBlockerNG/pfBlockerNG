#shellcheck shell=sh
# Copilot session detection in the git hooks (issue #2177). Copilot CLI exports
# NO environment variable to the shells it spawns (upstream feature request), so
# its sessionStart hook records the CLI pid under <common-git-dir>/
# pfb-copilot-sessions/ and sessionEnd removes that record. Both guards that gate
# on "is an agent driving this" — the prepare-commit-msg primary-checkout block
# (#1262) and the pre-push lease-by-effect guard (#1307) — must read those records.
#
# Records are created by RUNNING the real marker script, never by hand-writing a
# file: an earlier revision recorded $PPID, which named the dispatcher shell that
# exits immediately, and a fixture that injected its own live pid could not see
# that every real session was already dead on arrival.
#
# The liveness check is the point of the stale rows: a session killed without its
# sessionEnd hook leaves its record behind, and a record whose pid is gone must
# NOT turn the human owner's own commit into a blocked "agent" commit. The
# concurrency row is the other half — ending one of two live sessions must not
# disarm the guards for the one still running.
#
# The cloud agent is the one Copilot surface with an environment marker of its
# own (COPILOT_AGENT_PROMPT), so it is detected without any record.

Describe 'Copilot session detection in the git hooks (issue #2177)'
  pcm_hook="${PFB_ROOT}/.githooks/prepare-commit-msg"
  push_hook="${PFB_ROOT}/.githooks/pre-push"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/copilotmarker.XXXXXX")"
    primary="${base}/primary"
    wt="${base}/wt"
    git_fixture init -q -b devel "$primary"
    git_fixture -C "$primary" config user.email human@example.com
    git_fixture -C "$primary" config user.name Human
    git_fixture -C "$primary" config commit.gpgsign false
    git_fixture -C "$primary" config maintenance.auto false
    ( cd "$primary" && echo seed > seed.txt && git_fixture add seed.txt \
        && git_fixture commit -q -m seed )
    git_fixture -C "$primary" worktree add -q "$wt" -b spec-branch
    printf '%s\n' 'msg' > "${primary}/.git/PCM_MSG"
    printf '%s\n' 'msg' > "${primary}/.git/worktrees/wt/PCM_MSG"
    sessions="${primary}/.git/pfb-copilot-sessions"
    marker_script="${PFB_ROOT}/scripts/agent/copilot-session-marker.sh"
    # A second live process to stand in for a concurrent session; killed in cleanup.
    sleep 300 &
    other_pid=$!
  }

  cleanup() {
    kill "$other_pid" 2>/dev/null
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Every record below is produced by the production script; PFB_COPILOT_PID is
  # its documented seam, standing in for the `copilot` ancestor that only exists
  # under a real CLI session.
  record_for() {
    ( cd "$primary" && PFB_COPILOT_PID="$1" sh "$marker_script" start )
  }
  end_for() {
    ( cd "$primary" && PFB_COPILOT_PID="$1" sh "$marker_script" end )
  }

  # This spec's own shell is running, so its pid is alive.
  live_marker() {
    record_for "$$"
  }

  # pid 2^22 + 1 is above the maximum on the supported platforms (macOS
  # kern.maxproc and Linux pid_max both cap below it), so it names no process.
  stale_marker() {
    record_for '4194305'
  }

  # Env is cleared per row because the suite itself may run under CLAUDECODE=1
  # or CODEX_THREAD_ID — the marker alone must carry the decision.
  copilot_pcm_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      -u COPILOT_AGENT_PROMPT sh "$pcm_hook" "$2"
  }
  cloud_pcm_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      COPILOT_AGENT_PROMPT='work the issue' sh "$pcm_hook" "$2"
  }

  It 'blocks a Copilot commit in the primary checkout'
    live_marker
    When run copilot_pcm_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a Copilot commit in a linked worktree'
    live_marker
    When run copilot_pcm_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'blocks a Copilot cloud-agent commit in the primary checkout without a marker file'
    When run cloud_pcm_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a human commit in the primary checkout when the marker is stale'
    stale_marker
    When run copilot_pcm_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'passes a human commit in the primary checkout when no marker exists'
    When run copilot_pcm_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'reads the records from a linked worktree, whose own git dir does not hold them'
    live_marker
    marker_seen() {
      cd "$wt" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
        -u COPILOT_AGENT_PROMPT sh -c \
        'test -e "$(git rev-parse --git-common-dir)/pfb-copilot-sessions/'"$$"'" && echo found'
    }
    When run marker_seen
    The status should equal 0
    The stdout should include 'found'
  End

  It 'keeps the guard armed for a session that is still running when another ends'
    live_marker
    record_for "$other_pid"
    end_for "$other_pid"
    When run copilot_pcm_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'disarms only once every recorded session has ended'
    live_marker
    record_for "$other_pid"
    end_for "$other_pid"
    end_for "$$"
    When run copilot_pcm_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'records nothing when no Copilot CLI is in the process tree'
    # The production path with the seam unset: the ancestor walk finds no
    # `copilot` process, so a spec shell must not be mistaken for a session.
    no_ancestor() {
      ( cd "$primary" && sh "$marker_script" start )
      ls "$sessions" 2>/dev/null | wc -l | tr -d ' '
    }
    When run no_ancestor
    The status should equal 0
    The stdout should include '0'
  End

  It 'credits the Copilot-specific coauthor identity'
    live_marker
    git_fixture -C "$primary" config coauthor.copilot.name Owner
    git_fixture -C "$primary" config coauthor.copilot.email owner@example.com
    When run copilot_pcm_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include 'Co-Authored-By: Owner <owner@example.com>'
  End

  It 'does not apply a legacy Claude coauthor identity to a Copilot commit'
    live_marker
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run copilot_pcm_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  Describe 'pre-push lease-by-effect guard (issue #1307)'
    push_setup() {
      remote="${base}/remote.git"
      git_fixture init -q --bare -b devel "$remote"
      git_fixture -C "$primary" remote add origin "$remote"
      git_fixture -C "$primary" push -q origin devel
      # The remote moves on without this checkout fetching it: the advertised
      # oid stops matching the remote-tracking ref, which is what the guard reads.
      moved="${base}/moved"
      git_fixture clone -q "$remote" "$moved"
      git_fixture -C "$moved" config user.email other@example.com
      git_fixture -C "$moved" config user.name Other
      git_fixture -C "$moved" config commit.gpgsign false
      ( cd "$moved" && echo more > more.txt && git_fixture add more.txt \
          && git_fixture commit -q -m more && git_fixture push -q origin devel )
      remote_sha=$(git_fixture -C "$remote" rev-parse refs/heads/devel)
      local_sha=$(git_fixture -C "$primary" rev-parse HEAD)
      updates="refs/heads/devel ${local_sha} refs/heads/devel ${remote_sha}"
    }
    BeforeEach 'push_setup'

    copilot_push() {
      cd "$primary" && printf '%s\n' "$updates" | env -u CLAUDECODE \
        -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT sh "$push_hook" origin "$remote"
    }

    It 'denies a Copilot push that would rewrite unfetched history'
      live_marker
      When run copilot_push
      The status should equal 1
      The stderr should include 'unfetched history'
    End

    It 'leaves a human push alone when the marker is stale'
      stale_marker
      When run copilot_push
      The status should equal 0
      The stderr should equal ''
    End
  End
End
