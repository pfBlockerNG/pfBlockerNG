#shellcheck shell=sh
# Grok agent detection in the git hooks (issue #2439).
#
# Grok CLI exports GROK_AGENT=1 and GROK_SESSION_ID into every shell it
# spawns — inherited by nested shells and visible to git hooks (probed on
# 1.0.4, 2026-08-15: nested sh/bash `env | grep ^GROK_`). So the
# client is detected exactly as Claude (CLAUDECODE), Codex (CODEX_THREAD_ID),
# and Copilot (COPILOT_CLI) are: environment variables, nothing installed,
# no process inspection.
#
# Coauthor identities are retired: marker detection still drives the worktree
# guard, but neither provider-local nor legacy config ever creates a trailer.

Describe 'Grok detection in the git hooks (issue #2439)'
  pcm_hook="${PFB_ROOT}/.githooks/prepare-commit-msg"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/grokenv.XXXXXX")"
    primary="${base}/primary"
    wt="${base}/wt"
    git_fixture init -q -b devel "$primary"
    git_fixture -C "$primary" config user.email agent@example.com
    git_fixture -C "$primary" config user.name Agent
    git_fixture -C "$primary" config commit.gpgsign false
    git_fixture -C "$primary" config maintenance.auto false
    ( cd "$primary" && echo seed > seed.txt && git_fixture add seed.txt \
        && git_fixture commit -q -m seed )
    git_fixture -C "$primary" worktree add -q "$wt" -b spec-branch
    printf '%s\n' 'msg' > "${primary}/.git/PCM_MSG"
    printf '%s\n' 'msg' > "${primary}/.git/worktrees/wt/PCM_MSG"
    wt_msg="${primary}/.git/worktrees/wt/PCM_MSG"
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  # Env is set explicitly per row because the suite itself may run under
  # CLAUDECODE=1, CODEX_THREAD_ID, COPILOT_CLI, or GROK_SESSION_ID.
  grok_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u OMP_CLI -u PI_CLI \
      GROK_AGENT=1 GROK_SESSION_ID=grok-test sh "$pcm_hook" "$2"
  }
  human_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
      -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI sh "$pcm_hook" "$2"
  }

  grok_marker_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_AGENT -u GROK_SESSION_ID \
      -u OMP_CLI -u PI_CLI "$3" sh "$pcm_hook" "$2"
  }

  It 'ignores the legacy fake Claude identity in a Grok session'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run grok_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should not include 'Co-Authored-By:'
    The contents of file "$wt_msg" should not include 'noreply@anthropic.com'
  End

  It 'ignores the retired Grok-specific identity config'
    git_fixture -C "$primary" config coauthor.grok.name Grok
    git_fixture -C "$primary" config coauthor.grok.email noreply@x.ai
    When run grok_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should not include 'Co-Authored-By:'
    The contents of file "$wt_msg" should not include 'noreply@x.ai'
  End

  It 'ignores the legacy human identity config for a plain human commit'
    git_fixture -C "$primary" config coauthor.name 'Pair Human'
    git_fixture -C "$primary" config coauthor.email pair@example.com
    When run human_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should not include 'Co-Authored-By:'
    The contents of file "$wt_msg" should not include 'pair@example.com'
  End

  It 'ignores provider-specific identities when one agent runs inside another'
    # Grok launched from a Claude session inherits CLAUDECODE while setting
    # GROK_SESSION_ID. Both markers remain active, but neither owns attribution.
    git_fixture -C "$primary" config coauthor.claude.name 'Claude Sonnet 5'
    git_fixture -C "$primary" config coauthor.claude.email noreply@anthropic.com
    git_fixture -C "$primary" config coauthor.grok.name Grok
    git_fixture -C "$primary" config coauthor.grok.email noreply@x.ai
    nested() {
      cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$pcm_hook" "$wt_msg"
    }
    When run nested
    The status should equal 0
    The contents of file "$wt_msg" should not include 'Co-Authored-By:'
    The contents of file "$wt_msg" should not include 'noreply@anthropic.com'
    The contents of file "$wt_msg" should not include 'noreply@x.ai'
  End

  It 'invents no identity for nested clients'
    git_fixture -C "$primary" config coauthor.claude.name 'Claude Sonnet 5'
    git_fixture -C "$primary" config coauthor.claude.email noreply@anthropic.com
    nested_unconfigured() {
      cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$pcm_hook" "$wt_msg"
    }
    When run nested_unconfigured
    The status should equal 0
    The contents of file "$wt_msg" should not include 'Co-Authored-By:'
    The contents of file "$wt_msg" should not include 'noreply@anthropic.com'
    The contents of file "$wt_msg" should not include 'grok'
  End

  Context 'independent Grok marker successes'
    Parameters
      agent GROK_AGENT=1
      session GROK_SESSION_ID=grok-test
    End

    It "leaves a clean GROK_$1-only message byte-identical"
      cp "$wt_msg" "${base}/grok-marker.before"
      When run grok_marker_hook_in "$wt" "$wt_msg" "$2"
      The status should equal 0
      The stderr should equal ''
      Assert [ "$(cmp -s "${base}/grok-marker.before" "$wt_msg"; printf '%s' "$?")" -eq 0 ]
    End
  End

  It 'blocks a Grok commit in the primary checkout (issue #1262)'
    When run grok_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'leaves a human commit in the primary checkout alone'
    When run human_hook_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'detects GROK_AGENT alone, without GROK_SESSION_ID'
    When run grok_marker_hook_in "$primary" .git/PCM_MSG GROK_AGENT=1
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'detects GROK_SESSION_ID alone, without GROK_AGENT'
    When run grok_marker_hook_in "$primary" .git/PCM_MSG GROK_SESSION_ID=grok-test
    The status should equal 1
    The stderr should include 'primary checkout'
  End
End
