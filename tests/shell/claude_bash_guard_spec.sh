#shellcheck shell=sh
# claude-bash-guard.sh -- shellspec pinning the PreToolUse Bash guard (#923).
#
# TOPOLOGY UNDER TEST: the guard reads one PreToolUse-shaped JSON payload from
# stdin and either denies (prints the PreToolUse deny JSON, exit 0) or passes
# through silently (exit 0, empty stdout). Each example feeds one payload via
# a `Data` block (raw stdin -- shellspec's `shellspec_evaluation_execute`
# redirects stdin from the Data block for both `When call` and `When run`) and
# asserts the exit status + stdout shape.
#
# Contracts pinned here:
#   Rule A  -- git commit + --no-verify                       -> DENY
#   Rule B  -- git push + force flag (--force / standalone -f)
#              WITHOUT --force-with-lease                     -> DENY
#              (lease present -> PASS, lease wins even alongside a bare -f)
#   Rule C  -- git worktree remove + force flag                -> DENY
#   fail-open -- empty / garbled stdin, no rule match           -> PASS
#   -f boundary -- standalone -f only; never matches inside
#                  --force/-force/a token like foo-f            -> PASS
#
# One documented, ACCEPTED false-positive (B10): a commit message that merely
# CONTAINS the literal text "--no-verify" also denies -- the guard is a raw
# text scan (no jq / real argv parse in scope, see the guard's own header),
# so it cannot distinguish "the flag" from "prose about the flag". Erring
# toward blocking is the intended tradeoff, not a bug.

Describe 'claude-bash-guard.sh'
  GUARD="${PFB_ROOT}/scripts/claude-bash-guard.sh"

  setup() {
    # Every example's Data payload embeds the literal text "git " (e.g.
    # `git commit --no-verify`) which trips git-env-scrub-guard.sh's clause 2
    # unless scrub_git_env is called -- defensive, cheap, mandatory per spec_helper.
    scrub_git_env
  }
  BeforeEach 'setup'

  # ── Rule A: git commit + --no-verify ────────────────────────────────────────

  Describe 'Rule A: git commit --no-verify'
    It 'B1: --no-verify first (git commit --no-verify -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B2: --no-verify last (git commit -m x --no-verify) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m x --no-verify"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B3: --no-verify amid other flags (git commit -m "wip" --no-verify --amend) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m \"wip\" --no-verify --amend"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B10 (documented accepted false-positive): --no-verify inside the commit MESSAGE text -> DENY'
      # `git commit -m 'handle the --no-verify flag'` is a normal commit whose
      # message merely mentions --no-verify in prose. The guard is a raw text
      # scan (no argv parse), so it denies this too. ACCEPTED: erring toward
      # blocking is the intended tradeoff (see guard header + spec header).
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m 'handle the --no-verify flag'"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'P3: normal commit, no --no-verify (git commit -m x) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P10: git commit --amend, no --no-verify -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit --amend"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── Rule B: git push + force flag, without --force-with-lease ──────────────

  Describe 'Rule B: git push force (non-lease)'
    It 'B4: long flag (git push --force) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B5: short flag (git push -f) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B6: flag after args (git push origin main --force) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin main --force"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B7: flag before args (git push --force origin main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'P1: --force-with-lease alone -> PASS (contains substring --force but lease wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P2: --force-with-lease with args -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P4: normal push, no force flag (git push origin main) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P13 (edge case): --force-with-lease alongside a bare -f -> PASS (lease wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── Rule C: git worktree remove + force flag ────────────────────────────────

  Describe 'Rule C: git worktree remove --force'
    It 'B8: long flag (git worktree remove --force ../wt) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove --force ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B9: short flag (git worktree remove -f ../wt) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove -f ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'P5: remove without force -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P6: worktree add (not remove) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree add ../wt -b br origin/devel"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── standalone -f boundary: must not over-match ─────────────────────────────

  Describe 'standalone -f boundary (no false match inside another token, or out of scope)'
    It 'P7: bare -f on a non-git command (ls -f) -> PASS (force rule out of scope, no git push/worktree remove)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"ls -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P8: bare -f on grep (grep -f pattern.txt file) -> PASS (not git)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"grep -f pattern.txt file"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P14: -f embedded in a path token (git worktree add ../my-f-dir) -> PASS (not a standalone -f, and not remove)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree add ../my-f-dir"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── plain git, no rule in scope ─────────────────────────────────────────────

  It 'P9: plain git status -> PASS'
    Data
      #|{"tool_name":"Bash","tool_input":{"command":"git status"}}
    End
    When run script "$GUARD"
    The status should be success
    The output should equal ""
  End

  # ── fail-open: empty / garbled stdin never blocks ───────────────────────────

  Describe 'fail-open: unparseable input never denies'
    It 'P11: empty stdin -> PASS'
      Data
        #|
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P12: garbled non-JSON stdin -> PASS'
      Data
        #|not json at all {{{
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End
End
