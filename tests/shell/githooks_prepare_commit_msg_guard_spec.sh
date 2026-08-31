#shellcheck shell=sh
# .githooks/prepare-commit-msg agent worktree guard (issue #1262): an agent
# commit (Claude, Codex, Copilot, Grok, or OMP marker set) in the PRIMARY
# checkout aborts. Linked-worktree and human commits pass; a managed-remote
# marker or allowprimarycommit valve bypasses only the primary-location check.
# Every agent ident must still match the configured user, and every
# Co-authored-by trailer is forbidden. Enforced here because this hook still
# runs when verification is skipped — the verify-skip row below is the point.
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
      CLAUDECODE=1 sh "$hook" "$2" "${3:-}"
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

  marker_mismatch_hook_in() {
    cd "$1" && env -u CLAUDECODE -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
      -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
      -u OMP_CLI -u PI_CLI "$3" \
      GIT_AUTHOR_NAME='Pair Human' GIT_AUTHOR_EMAIL=pair@example.com \
      GIT_COMMITTER_NAME='Pair Human' GIT_COMMITTER_EMAIL=pair@example.com \
      sh "$hook" "$2"
  }

  It 'blocks an agent commit in the primary checkout'
    When run agent_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
    The stderr should include 'worktree'
  End

  It 'passes an agent commit in a linked worktree'
    cp "${primary}/.git/worktrees/wt/PCM_MSG" "${base}/ordinary.before"
    When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
    Assert [ "$(cmp -s "${base}/ordinary.before" "${primary}/.git/worktrees/wt/PCM_MSG"; printf '%s' "$?")" -eq 0 ]
  End

  It 'blocks a Codex commit in the primary checkout'
    When run codex_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a Codex commit in a linked worktree'
    cp "${primary}/.git/worktrees/wt/PCM_MSG" "${base}/codex.before"
    When run codex_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
    Assert [ "$(cmp -s "${base}/codex.before" "${primary}/.git/worktrees/wt/PCM_MSG"; printf '%s' "$?")" -eq 0 ]
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
    cp "${primary}/.git/worktrees/wt/PCM_MSG" "${base}/omp.before"
    When run omp_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
    Assert [ "$(cmp -s "${base}/omp.before" "${primary}/.git/worktrees/wt/PCM_MSG"; printf '%s' "$?")" -eq 0 ]
  End

  It 'blocks a PI_CLI-only commit in the primary checkout'
    When run pi_hook_in "$primary" .git/PCM_MSG
    The status should equal 1
    The stderr should include 'primary checkout'
  End

  It 'passes a PI_CLI-only commit in a linked worktree'
    cp "${primary}/.git/worktrees/wt/PCM_MSG" "${base}/pi.before"
    When run pi_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
    Assert [ "$(cmp -s "${base}/pi.before" "${primary}/.git/worktrees/wt/PCM_MSG"; printf '%s' "$?")" -eq 0 ]
  End

  Context 'forbidden Co-authored-by trailers'
    Parameters
      'Claude Sonnet 5 <noreply@anthropic.com>'
      'GPT-5.6 Sol <noreply@openai.com>'
      'Oh My Pi GLM lane <noreply@omp.local>'
      'Pair Human <pair@example.com>'
    End

    It "rejects pre-seeded $1"
      printf '%s\n\nCo-authored-by: %s\n' 'msg' "$1" \
        > "${primary}/.git/worktrees/wt/PCM_MSG"
      When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
      The status should not equal 0
      The stderr should equal 'Co-authored-by trailers are forbidden'
      The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include "Co-authored-by: $1"
    End
  End

  Context 'forbidden trailers across commit message sources'
    Parameters
      empty ''
      message message
      template template
      merge merge
      squash squash
      commit commit
    End

    It "rejects a pre-seeded forbidden trailer for the $1 source"
      printf '%s\n\n%s\n' 'msg' 'Co-authored-by: Claude Sonnet 5 <noreply@anthropic.com>' \
        > "${primary}/.git/worktrees/wt/PCM_MSG"
      When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG "${2:-}"
      The status should not equal 0
      The stderr should equal 'Co-authored-by trailers are forbidden'
      The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should include 'Co-authored-by: Claude Sonnet 5 <noreply@anthropic.com>'
    End
  End

  It 'rejects a mixed-case Co-authored-by token with leading whitespace'
    printf '%s\n\n%s\n' 'msg' '  cO-aUtHoReD-bY: Pair Human <pair@example.com>' \
      > "${primary}/.git/worktrees/wt/PCM_MSG"
    When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should not equal 0
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End

  It 'rejects a human Co-authored-by trailer without an agent marker'
    printf '%s\n\n%s\n' 'msg' 'Co-authored-by: Pair Human <pair@example.com>' \
      > "${primary}/.git/worktrees/wt/PCM_MSG"
    When run human_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should not equal 0
    The stderr should equal 'Co-authored-by trailers are forbidden'
  End

  It 'ignores the retired Claude-specific identity config'
    git_fixture -C "$primary" config coauthor.claude.name 'Claude Sonnet 5'
    git_fixture -C "$primary" config coauthor.claude.email noreply@anthropic.com
    When run agent_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@anthropic.com'
  End

  It 'ignores the retired Codex-specific identity config'
    git_fixture -C "$primary" config coauthor.codex.name 'GPT-5.6 Sol'
    git_fixture -C "$primary" config coauthor.codex.email noreply@openai.com
    When run codex_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@openai.com'
  End

  It 'ignores the retired OMP-specific identity config'
    git_fixture -C "$primary" config coauthor.omp.name 'Oh My Pi GLM lane'
    git_fixture -C "$primary" config coauthor.omp.email noreply@omp.local
    When run omp_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@omp.local'
  End

  It 'ignores the retired OMP identity config in Pi compatibility mode'
    git_fixture -C "$primary" config coauthor.omp.name 'Oh My Pi GLM lane'
    git_fixture -C "$primary" config coauthor.omp.email noreply@omp.local
    When run pi_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'noreply@omp.local'
  End

  It 'ignores the legacy coauthor identity config for a plain human commit'
    git_fixture -C "$primary" config coauthor.name 'Pair Human'
    git_fixture -C "$primary" config coauthor.email pair@example.com
    When run human_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG
    The status should equal 0
    The stderr should equal ''
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/worktrees/wt/PCM_MSG" should not include 'pair@example.com'
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

  It 'passes a managed-remote agent whose idents match the configured user'
    git_fixture -C "$primary" config user.name Owner
    git_fixture -C "$primary" config user.email owner@example.com
    cp "${primary}/.git/PCM_MSG" "${base}/managed.before"
    managed_hook() {
      cd "$primary" && env -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT \
        CLAUDECODE=1 CLAUDE_CODE_USER_EMAIL=owner@example.com \
        sh "$hook" .git/PCM_MSG
    }
    When run managed_hook
    The status should equal 0
    The stderr should equal ''
    The contents of file "${primary}/.git/PCM_MSG" should not include 'Co-Authored-By:'
    The contents of file "${primary}/.git/PCM_MSG" should not include 'owner@example.com'
    Assert [ "$(cmp -s "${base}/managed.before" "${primary}/.git/PCM_MSG"; printf '%s' "$?")" -eq 0 ]
  End

  Context 'missing configured user identity fields'
    Parameters
      user.name
      user.email
    End

    It "rejects an agent commit when $1 is missing"
      git_fixture -C "$primary" config --unset "$1"
      missing_user_hook() {
        cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
          CLAUDECODE=1 sh "$hook" ../primary/.git/worktrees/wt/PCM_MSG
      }
      When run missing_user_hook
      The status should not equal 0
      The stderr should equal 'Agent commits must use the configured user identity'
    End
  End

  Context 'agent author identity mismatches'
    Parameters
      'Pair Human' human@example.com
      Human pair@example.com
      human human@example.com
      Human Human@Example.com
    End

    It "rejects mismatched author identity $1 <$2>"
      differing_author_hook() {
        cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI CLAUDECODE=1 \
          GIT_AUTHOR_NAME="$1" GIT_AUTHOR_EMAIL="$2" \
          sh "$hook" ../primary/.git/worktrees/wt/PCM_MSG
      }
      When run differing_author_hook "$1" "$2"
      The status should not equal 0
      The stderr should equal 'Agent commits must use the configured user identity'
    End
  End

  Context 'agent committer identity mismatches'
    Parameters
      'Pair Human' human@example.com
      Human pair@example.com
      human human@example.com
      Human Human@Example.com
    End

    It "rejects mismatched committer identity $1 <$2>"
      differing_committer_hook() {
        cd "$wt" && env -u CLAUDE_CODE_USER_EMAIL -u CODEX_THREAD_ID \
          -u COPILOT_AGENT_PROMPT -u COPILOT_CLI -u GROK_SESSION_ID -u GROK_AGENT \
          -u OMP_CLI -u PI_CLI CLAUDECODE=1 \
          GIT_COMMITTER_NAME="$1" GIT_COMMITTER_EMAIL="$2" \
          sh "$hook" ../primary/.git/worktrees/wt/PCM_MSG
      }
      When run differing_committer_hook "$1" "$2"
      The status should not equal 0
      The stderr should equal 'Agent commits must use the configured user identity'
    End
  End

  Context 'identity mismatch through each independent agent marker'
    Parameters
      claude CLAUDECODE=1
      codex CODEX_THREAD_ID=codex-test
      'copilot CLI' COPILOT_CLI=1
      'copilot cloud' 'COPILOT_AGENT_PROMPT=work the issue'
      'grok agent' GROK_AGENT=1
      'grok session' GROK_SESSION_ID=grok-test
      omp OMP_CLI=1
      pi PI_CLI=1
    End

    It "rejects mismatched author and committer identities through $1"
      When run marker_mismatch_hook_in "$wt" ../primary/.git/worktrees/wt/PCM_MSG "$2"
      The status should not equal 0
      The stderr should equal 'Agent commits must use the configured user identity'
    End
  End

  It 'does not let allowprimarycommit exempt an identity mismatch'
    git_fixture -C "$primary" config pfblockerng.allowprimarycommit true
    When run marker_mismatch_hook_in "$primary" .git/PCM_MSG CLAUDECODE=1
    The status should not equal 0
    The stderr should equal 'Agent commits must use the configured user identity'
  End

  It 'does not let CLAUDE_CODE_USER_EMAIL exempt an identity mismatch'
    managed_mismatch_hook() {
      cd "$primary" && env -u CODEX_THREAD_ID -u COPILOT_AGENT_PROMPT -u COPILOT_CLI \
        -u GROK_SESSION_ID -u GROK_AGENT -u OMP_CLI -u PI_CLI \
        CLAUDECODE=1 CLAUDE_CODE_USER_EMAIL=human@example.com \
        GIT_AUTHOR_NAME='Pair Human' GIT_AUTHOR_EMAIL=pair@example.com \
        GIT_COMMITTER_NAME='Pair Human' GIT_COMMITTER_EMAIL=pair@example.com \
        sh "$hook" .git/PCM_MSG
    }
    When run managed_mismatch_hook
    The status should not equal 0
    The stderr should equal 'Agent commits must use the configured user identity'
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
          -u OMP_CLI -u PI_CLI \
          git commit -n -m allowed # git-env-scrub-guard: allow hook-under-test commit
    }
    When run real_commit_human
    The status should equal 0
    The result of function commit_count should equal 2
  End
End
