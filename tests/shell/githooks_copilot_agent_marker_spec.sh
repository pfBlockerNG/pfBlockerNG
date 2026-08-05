#shellcheck shell=sh
# Copilot session detection in the git hooks (issue #2177). Copilot CLI exports
# NO environment variable to the shells it spawns (upstream feature request), so
# the repo's Copilot sessionStart hook writes a marker holding the CLI's pid into
# the COMMON git dir and sessionEnd removes it. Both guards that gate on "is an
# agent driving this" — the prepare-commit-msg primary-checkout block (#1262) and
# the pre-push lease-by-effect guard (#1307) — must read that marker.
#
# The liveness check is the point of the stale rows: a session killed without its
# sessionEnd hook leaves the marker behind, and a marker whose pid is gone must
# NOT turn the human owner's own commit into a blocked "agent" commit.
#
# The cloud agent is the one Copilot surface with an environment marker of its
# own (COPILOT_AGENT_PROMPT), so it is detected without the file.

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
    marker="${primary}/.git/pfb-copilot-session"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # A live marker: this spec's own shell is running, so its pid is alive.
  live_marker() {
    printf '%s\n' "$$" > "$marker"
  }

  # A stale marker: pid 2^22 + 1 is above every attainable pid on the supported
  # platforms, so it can never name a live process.
  stale_marker() {
    printf '%s\n' '4194305' > "$marker"
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

  It 'reads the marker from a linked worktree, whose own git dir does not hold it'
    live_marker
    marker_seen() {
      cd "$wt" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
        -u COPILOT_AGENT_PROMPT sh -c \
        'test -r "$(git rev-parse --git-common-dir)/pfb-copilot-session" && echo found'
    }
    When run marker_seen
    The status should equal 0
    The stdout should include 'found'
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
