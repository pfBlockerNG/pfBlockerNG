#shellcheck shell=sh
# Grok attribution and agent detection in the git hooks (issue #2439).
#
# Grok CLI exports GROK_AGENT=1 and GROK_SESSION_ID into every shell it
# spawns — inherited by nested shells and visible to git hooks (probed on
# 1.0.4, 2026-08-15: nested sh/bash `env | grep ^GROK_`). So the
# client is detected exactly as Claude (CLAUDECODE), Codex (CODEX_THREAD_ID),
# and Copilot (COPILOT_CLI) are: environment variables, nothing installed,
# no process inspection.
#
# The attribution rows are the load-bearing ones. This repo sets the legacy
# `coauthor.email` to Claude's identity, so a Grok commit with no provider
# detection is credited to CLAUDE — the same misattribution the Codex and
# Copilot branches exist to prevent.

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
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
      GROK_AGENT=1 GROK_SESSION_ID=grok-test sh "$pcm_hook" "$2"
  }
  human_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
      -u GROK_SESSION_ID -u GROK_AGENT sh "$pcm_hook" "$2"
  }

  It 'never credits the legacy Claude identity to a Grok commit'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run grok_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should not include 'noreply@anthropic.com'
  End

  It 'credits the Grok-specific identity when one is configured'
    git_fixture -C "$primary" config coauthor.grok.name Owner
    git_fixture -C "$primary" config coauthor.grok.email owner@example.com
    When run grok_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should include 'Co-Authored-By: Owner <owner@example.com>'
  End

  It 'still credits the legacy identity for a plain human commit'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run human_hook_in "$wt" "$wt_msg"
    The status should equal 0
    The contents of file "$wt_msg" should include 'Co-Authored-By: Claude <noreply@anthropic.com>'
  End

  It 'credits every client present when one agent runs inside another'
    # Grok launched from a Claude session inherits CLAUDECODE while setting
    # GROK_SESSION_ID: both ran, so both are credited rather than one winning.
    git_fixture -C "$primary" config coauthor.claude.name Claude
    git_fixture -C "$primary" config coauthor.claude.email noreply@anthropic.com
    git_fixture -C "$primary" config coauthor.grok.name Owner
    git_fixture -C "$primary" config coauthor.grok.email owner@example.com
    nested() {
      cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        CLAUDECODE=1 GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$pcm_hook" "$wt_msg"
    }
    When run nested
    The status should equal 0
    The contents of file "$wt_msg" should include 'Co-Authored-By: Claude <noreply@anthropic.com>'
    The contents of file "$wt_msg" should include 'Co-Authored-By: Owner <owner@example.com>'
  End

  It 'invents no identity for a client that has none configured'
    git_fixture -C "$primary" config coauthor.claude.name Claude
    git_fixture -C "$primary" config coauthor.claude.email noreply@anthropic.com
    nested_unconfigured() {
      cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
        -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        CLAUDECODE=1 GROK_AGENT=1 GROK_SESSION_ID=grok-test \
        sh "$pcm_hook" "$wt_msg"
    }
    When run nested_unconfigured
    The status should equal 0
    The contents of file "$wt_msg" should include 'Co-Authored-By: Claude <noreply@anthropic.com>'
    The contents of file "$wt_msg" should not include 'grok'
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
    agent_only() {
      cd "$primary" && env -u CLAUDECODE -u CODEX_THREAD_ID -u CLAUDE_CODE_USER_EMAIL \
        -u COPILOT_CLI -u COPILOT_AGENT_PROMPT -u GROK_SESSION_ID \
        GROK_AGENT=1 sh "$pcm_hook" .git/PCM_MSG
    }
    When run agent_only
    The status should equal 1
    The stderr should include 'primary checkout'
  End
End
