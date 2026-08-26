#shellcheck shell=sh
# .githooks/prepare-commit-msg agent worktree guard (issue #1262): an agent
# commit (Claude, Codex, Copilot, Grok, or OMP marker set) in the PRIMARY
# checkout aborts; a linked-worktree commit, a human commit, and an
# agent-dedicated checkout (managed-remote marker CLAUDE_CODE_USER_EMAIL, or the
# pfblockerng.allowprimarycommit valve) all pass. Enforced in
# prepare-commit-msg because that hook still runs when
# verification is skipped — the verify-skip row below is the point.
#
# The guard discriminates on git STATE (--git-dir vs --git-common-dir), never
# on command text, so nothing here exercises payload parsing: these rows pin
# the operation-layer contract that replaced the rejected Rule E text scan.

Describe 'prepare-commit-msg agent worktree guard (issue #1262)'
  hook="${PFB_ROOT}/.githooks/prepare-commit-msg"

  setup() {
    scrub_git_env
    base="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pcmguard.XXXXXX")"
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
  }

  cleanup() {
    rm -rf "$base"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  commit_count() {
    git_fixture -C "$primary" rev-list --count HEAD
  }

  # Direct hook invocations: cwd selects primary vs linked worktree; env is
  # set explicitly per row because the suite itself may run under CLAUDECODE=1.
  agent_hook_in() {
    cd "$1" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
      -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
      CLAUDECODE=1 sh "$hook" "$2"
  }
  codex_hook_in() {
    cd "$1" && env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
      -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
      CODEX_THREAD_ID=codex-test sh "$hook" "$2"
  }
  grok_hook_in() {
    cd "$1" && env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u COPILOT_AGENT_PROMPT \
      -u COPILOT_CLI -u CODEX_THREAD_ID -u OMP_CLI -u PI_CLI \
      GROK_AGENT=1 GROK_SESSION_ID=grok-test sh "$hook" "$2"
  }
  omp_hook_in() {
    cd "$1" && env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
      -u PI_CLI OMP_CLI=1 sh "$hook" "$2"
  }
  pi_hook_in() {
    cd "$1" && env -u CLAUDE_CODE_USER_EMAIL -u CLAUDECODE -u CODEX_THREAD_ID \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
      -u OMP_CLI PI_CLI=1 sh "$hook" "$2"
  }
  human_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
      -u OMP_CLI -u PI_CLI sh "$hook" "$2"
  }

  It 'blocks an agent commit in the primary checkout'
    When run agent_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
    The stderr should include 'worktree'
  End

  It 'passes an agent commit in a linked worktree'
    When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'blocks a Codex commit in the primary checkout'
    When run codex_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a Codex commit in a linked worktree'
    When run codex_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'blocks a Grok commit in the primary checkout'
    When run grok_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a Grok commit in a linked worktree'
    When run grok_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'blocks an OMP commit in the primary checkout'
    When run omp_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes an OMP commit in a linked worktree'
    When run omp_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'credits OMP only from its provider-specific identity'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    git_fixture -C "$primary" config coauthor.omp.name OMP
    git_fixture -C "$primary" config coauthor.omp.email omp@example.com
    When run omp_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include 'Co-Authored-By: OMP <omp@example.com>'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'blocks a Pi-compatible commit in the primary checkout'
    When run pi_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a Pi-compatible commit in a linked worktree'
    When run pi_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'credits a Pi-compatible session as OMP'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    git_fixture -C "$primary" config coauthor.omp.name OMP
    git_fixture -C "$primary" config coauthor.omp.email omp@example.com
    When run pi_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include 'Co-Authored-By: OMP <omp@example.com>'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'does not borrow the legacy Claude identity for unconfigured OMP'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run omp_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'does not borrow the legacy Claude identity for unconfigured Pi compatibility'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run pi_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'does not apply a legacy Claude coauthor identity to a Codex commit'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run codex_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'keeps the legacy coauthor identity for a Claude commit'
    git_fixture -C "$primary" config coauthor.name Claude
    git_fixture -C "$primary" config coauthor.email noreply@anthropic.com
    When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include 'Co-Authored-By: Claude <noreply@anthropic.com>'
  End

  It 'passes a human commit in the primary checkout'
    When run human_hook_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'passes an agent commit when the valve marks the checkout agent-dedicated'
    git_fixture -C "$primary" config pfblockerng.allowprimarycommit true
    When run agent_hook_in "$primary" .git/PCM_MSG
    The status should equal 0
    The stderr should equal ''
  End

  It 'passes an agent commit in a managed-remote session (owner email marker set)'
    managed_hook() {
      cd "$primary" && env -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT \
        CLAUDECODE=1 CLAUDE_CODE_USER_EMAIL=owner@example.com \
        sh "$hook" .git/PCM_MSG
    }
    When run managed_hook
    The status should equal 0
    The stderr should equal ''
  End

  # The money rows: a REAL verify-skipping commit (git commit -n skips
  # pre-commit/commit-msg but not prepare-commit-msg). The human control row
  # proves the abort is CAUSED by the agent guard, not by the harness setup.
  It 'aborts a verify-skipping agent commit in the primary checkout'
    real_commit() {
      cd "$primary" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && echo change >> seed.txt && git_fixture add seed.txt \
        && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT \
          -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          CLAUDECODE=1 git commit -n -m blocked # git-env-scrub-guard: allow hook-under-test commit
    }
    When run real_commit
    The status should not equal 0
    The stderr should include 'primary checkout'
    The result of function commit_count should equal 1
  End

  It 'lands the same verify-skipping commit for a human (control)'
    real_commit_human() {
      cd "$primary" \
        && git_fixture config core.hooksPath "${PFB_ROOT}/.githooks" \
        && echo change >> seed.txt && git_fixture add seed.txt \
        && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          git commit -n -m allowed # git-env-scrub-guard: allow hook-under-test commit
    }
    When run real_commit_human
    The status should equal 0
    The result of function commit_count should equal 2
  End
End
