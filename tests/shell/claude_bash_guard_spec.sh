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
#   Rule B  -- git push + force flag (--force / standalone -f /
#              a clustered short flag like -uf, -fu, -4f)
#              WITHOUT --force-with-lease                     -> DENY
#              (lease present AND no bare force flag after the LAST
#              --force-with-lease -> PASS; git honors the last force
#              flag, so a bare force AFTER the lease still denies, #1058)
#   Rule C  -- git worktree remove + force flag                -> DENY
#   fail-open -- empty / garbled stdin, no rule match           -> PASS
#   -f boundary -- standalone -f / an f-bearing short-flag cluster,
#                  never matching inside --force/-force/a token
#                  like foo-f                                   -> PASS
#   normalization (#923 review F1) -- every rule matches against a
#              normalized view (quotes/backslashes stripped, whitespace
#              runs collapsed to one space), so double/tab whitespace and a
#              quoted subcommand token can't evade a rule               -> DENY
#   force-flag boundary (#923 review F2/F3) -- a shell metacharacter
#              (`; | & ( ) < > ,`) directly after -f, or a clustered short
#              flag (-uf/-fu), still counts as force                    -> DENY
#
# One documented, ACCEPTED false-positive (B10): a commit message that merely
# CONTAINS the literal text "--no-verify" also denies -- the guard is a raw
# text scan (no jq / real argv parse in scope, see the guard's own header),
# so it cannot distinguish "the flag" from "prose about the flag". Erring
# toward blocking is the intended tradeoff, not a bug. More generally
# (#923 review F6): the scan runs over the WHOLE stdin payload, so a trigger
# phrase occurring ANYWHERE in the payload denies, not just in the command.

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

    It 'H1 (F1 whitespace evasion): double space between git and commit (git  commit --no-verify -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git  commit --no-verify -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H2 (F1 whitespace evasion): a literal TAB between git and commit -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git	commit --no-verify"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H3 (F1 quoting evasion): quoted subcommand token (git \"commit\" --no-verify) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git \"commit\" --no-verify"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H12a (F5 full JSON validity): exact deny JSON for Rule A'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit --no-verify -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"the pre-commit lint gate'"'"'s --no-verify bypass is for humans, not agents (CLAUDE.md)"}}'
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
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P10: git commit --amend, no --no-verify -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt commit --amend"}}
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

    It 'H4 (F2 metachar boundary): git push -f;true -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -f;true"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H5 (F2 metachar boundary): git push -f|cat -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -f|cat"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H6 (F2 metachar boundary): git push -f&&echo done -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -f&&echo done"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H7 (F3 clustered short flag): git push -uf origin main -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -uf origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H8 (F3 clustered short flag, other order): git push -fu origin main -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -fu origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H10: --force-with-lease with a trailing metachar (;true) -> PASS (lease still wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force-with-lease;true"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'H12b (F5 full JSON validity): exact deny JSON for Rule B'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"the rebase-only landing flow uses --force-with-lease exclusively; a bare force-push can clobber another session'"'"'s PR (CLAUDE.md)"}}'
    End

    It 'P1: --force-with-lease alone -> PASS (contains substring --force but lease wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P2: --force-with-lease with args -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force-with-lease origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P4: normal push, no force flag (git push origin main) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P13 (issue #1058): bare -f AFTER --force-with-lease -> DENY (git honors the last force flag)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H13 (issue #1058): digit-bearing short-flag cluster (git push -4f origin main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push -4f origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H14 (issue #1058): --force AFTER --force-with-lease -> DENY (last force flag wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease --force"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'P14 (issue #1058): bare force BEFORE --force-with-lease -> PASS (the lease, last, wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force --force-with-lease origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P15 (issue #1058): --force-with-lease --force-if-includes -> PASS (lease companion, not a bare force)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force-with-lease --force-if-includes"}}
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

    It 'H9 (F1 whitespace evasion): double space (git worktree  remove --force ../wt) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree  remove --force ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H12c (F5 full JSON validity): exact deny JSON for Rule C'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove --force ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"CLAUDE.md forbids force-removing a worktree you do not own"}}'
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

    It 'H11 (F3 over-match guard): bare -f on a non-push/remove git command (echo -f && git status) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"echo -f && git status"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── per-segment scoping: a force flag in one compound-command segment must
  #    not leak into a rule for an unrelated, unforced segment (#923 review,
  #    Copilot false-positive) ───────────────────────────────────────────────

  Describe 'per-segment scoping (compound commands): a rule only fires when its trigger and its force flag share ONE segment'
    It 'C1 (Rule C FP, Copilot case): unforced worktree remove && leased push -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove ../wt && git -C /abs/wt push --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C2 (Rule C FP, reversed order): leased push && unforced worktree remove -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt push --force-with-lease && git worktree remove ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C3 (Rule B FP): git clean --force && normal git push -> PASS (force belongs to git clean, not the push)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt clean --force && git -C /abs/wt push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C4 (Rule B FP, subshell boundary): (git clean --force); git push origin main -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"(git -C /abs/wt clean --force); git -C /abs/wt push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C5 (still caught): git status && a genuinely forced push in its own segment -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git status && git push --force"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C6 (still caught): git fetch && a genuinely forced worktree remove -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git fetch && git worktree remove -f ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C7 (still caught): git status && git commit --no-verify -m x -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git status && git commit --no-verify -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C8 (unforced remove next to a genuinely forced push): the push segment is still denied on its own merits'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove ../wt && git push --force origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End
  End

  # ── Rule D: a wait script backgrounded with & ───────────────────────────────
  #
  # Backgrounding is a property of the TOOL CALL (run_in_background: true), not of
  # shell syntax: a wait launched with `&` inside a foreground call is not tracked
  # by the harness, so no completion notification ever fires and the turn stalls
  # while the wait has already finished (#1225, observed on PR #1222).

  Describe 'Rule D: wait-*.sh backgrounded with &'
    It 'D1: wait-checks.sh backgrounded, output redirected -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 > /tmp/ci.txt 2>&1 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D2: wait-reviewer.sh backgrounded with a command after the & -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-reviewer.sh --handle copilot > /tmp/r.txt 2>&1 & echo armed"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D3: wait-checks.sh in the FOREGROUND (the run_in_background shape) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 > /tmp/ci.txt 2>&1"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'D4: the & backgrounds something ELSE, the wait runs in the foreground -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sleep 1 & sh scripts/agent/wait-checks.sh --repo o/r --pr 1"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    # ACCEPTED FALSE POSITIVE. Collapsing `&&` as a list operator is not safe either: an
    # argument value ending in `&`, fused by quote-stripping with the REAL background `&`,
    # reads as `&&` and would be collapsed away -- erasing the operator the rule hunts
    # (D18). A wait therefore gets its own call, chained to nothing, which is the shape
    # run_in_background wants anyway.
    It 'D5: a && chain after the wait script -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 && gh pr merge 1 --rebase"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D18: an argument ending in & cannot fuse with the real & into a fake && -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --pr 1 --exclude \"coderabbit&\"&"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # ACCEPTED FALSE POSITIVE: the fd-redirect lookalike now needs a MANDATORY leading fd
    # digit (D16), so the digit-less `>&N` shorthand no longer reads as a redirection and
    # a FOREGROUND wait using it denies. Nothing in this repo writes it that way.
    It 'D19: a foreground wait using the digit-less >&2 shorthand -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 >&2"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # ── Rule D's two ACCEPTED BYPASSES, pinned so a future edit cannot widen them ──
    #
    # Both need a payload no honest command produces, which is the guard's existing
    # ACCEPTED LIMITATION (a text scan cannot beat deliberate payload construction).
    # They are pinned, not merely described, because every other accepted surface here
    # is -- prose drifts, tests do not.

    It 'D20: ACCEPTED BYPASS -- a quoted value ending in a DIGIT and > forges a real redirect'
      # `--threshold "1>"&2` quote-strips to `1>&2`, textually identical to a genuine fd
      # redirect, so the only surviving lookalike-neutralizer eats the real background &.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --threshold \"1>\"&2"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'D21: ACCEPTED BYPASS -- an & written as the JSON escape \u0026 is never decoded'
      # The scan reads raw payload bytes and never JSON-decodes, so an escaped & is
      # invisible. No serializer the harness uses emits this for a plain ASCII &.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --pr 1 \u0026"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    # ACCEPTED FALSE POSITIVE, same family as D7. The `;` that would prove this & belongs
    # to a LATER command is indistinguishable from a `;` sitting inside a quoted argument
    # (the guard strips quote markers without knowing what they protected), and trusting
    # it let a genuinely backgrounded wait through -- see D14. Any & after the wait script
    # therefore denies.
    It 'D6: a & belonging to a LATER command (after a ;) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 ; sleep 5 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D14: a ; inside a QUOTED ARGUMENT cannot end the wait statement early -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --exclude 'coderabbit;snyk' &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D15: a quoted > must not fuse with the background & into a fake redirection -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --threshold \">\"&"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # The same fusion, one character further along: a quoted `>` + the real `&` + any
    # digit from the NEXT token reads exactly like a real `N>&M` redirect. Only a
    # MANDATORY leading fd digit tells them apart -- a real redirect always has one.
    It 'D16: a fused >& followed by a digit is not a redirection -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --threshold \">\"&2"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # And the mirror image: the real background & fusing with a FOLLOWING quoted `>`
    # into `&>`. No repo flow uses `&>file`, so that lookalike is not neutralized at
    # all -- eating it would erase the very & the rule exists to find.
    It 'D17: a background & fused with a following quoted > still denies -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --pr 1 &\">\" foo"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # ACCEPTED FALSE POSITIVE. Treating a newline as a separator (so this would pass)
    # is what a text scan cannot do safely: it cannot tell a newline that ends a
    # command from one inside a quoted argument, and getting that wrong the other way
    # SILENTLY UN-DENIES a backgrounded wait -- the rule failing open, which is far
    # worse than denying a call the agent can simply split into two. Blocking is the
    # deliberate direction here, as it is for B10.
    It 'D7: MULTI-LINE, wait in the foreground, a LATER line backgrounded -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1\necho done &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D7b: a NEWLINE INSIDE A QUOTED ARGUMENT cannot hide the background & -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --pr 1 --msg \"a\nb\" &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'D8: MULTI-LINE, the WAIT ITSELF backgrounded on its own line -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"echo arming\nsh scripts/agent/wait-checks.sh --repo o/r --pr 1 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # A LITERAL backslash-n inside an argument is TWO backslashes in the JSON payload,
    # where a real newline is one. Conflating them let a genuinely backgrounded wait
    # slip through: the fake `;` the escape produced fell between the script and its &.
    It 'D9: a literal backslash-n in an argument does NOT hide a real background & -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --exclude \"foo\\\\nbar\" > /tmp/x 2>&1 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # ── Rule D's two ACCEPTED surfaces, pinned so they cannot drift silently ──
    #
    # Both follow from the guard being a raw text scan (see its header): it has no
    # argv parse and cannot follow indirection. They are pinned as EXPECTED, exactly
    # as B10 pins the --no-verify-in-a-commit-message false positive.

    It 'D10: ACCEPTED FALSE POSITIVE -- an & inside an argument value denies a foreground wait'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --exclude \"coderabbit&snyk\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # Indirection through a variable no longer evades: the script's PATH still appears in
    # the payload, and any & after it denies. Only an invocation that never names the
    # script at all (a path assembled from pieces) escapes -- the guard's documented
    # ACCEPTED LIMITATION for deliberate circumvention.
    It 'D11: a wait reached through a variable still denies -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"W=scripts/agent/wait-checks.sh; sh \"$W\" --repo o/r --pr 1 > /tmp/ci.txt 2>&1 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # A backslash before a newline is a LINE CONTINUATION: it JOINS the two lines
    # with no separator, the opposite of a `;`. Treating it as one lets the common
    # "split a long command across lines" idiom hide the trailing background &.
    It 'D12: a line continuation before the background & does not hide it -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 \\\n&"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    # An argument value carrying odd text must not perturb the scan.
    It 'D13: an odd-looking argument value does not perturb the verdict -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh --repo o/r --pr 1 --exclude @PFB_BS@ > /tmp/x 2>&1 &"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End
  End

  # ── Rule E: a mutating git command depends on the ambient cwd, which the ──
  #    hook cannot see -- deny unless the call names its target explicitly,
  #    and deny when that target IS the primary checkout (issue #1262: a
  #    stray `cd` into the primary checkout silently misdirected a
  #    rebase+push, and the misfire was caught only by luck).

  Describe 'Rule E: mutating git command depends on the ambient cwd'
    PROJ="/home/agent/pfBlockerNG"

    Describe 'E1: no explicit -C/cd target anywhere in the payload -> DENY (one row per mutating verb)'
      It 'E-a1: git commit -m x -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git commit -m x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a2: git push origin main -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a3: git rebase origin/devel -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git rebase origin/devel"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a4: git merge foo -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git merge foo"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a5: git reset --hard HEAD~1 -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a6: git checkout devel -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git checkout devel"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a7: git switch devel -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git switch devel"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a8: git cherry-pick abc123 -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git cherry-pick abc123"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a9: git revert abc123 -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git revert abc123"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a10: git stash -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git stash"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a11: git am file.patch -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git am file.patch"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a12: git clean -fd -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git clean -fd"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-a13 (the real bug, issue #1262): fetch+rebase+push with no -C/cd anywhere -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git fetch -q origin && git rebase origin/devel && git push --force-with-lease origin issue/1257-x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End
    End

    Describe 'E1 satisfied: an explicit -C/cd target is present -> ALLOW'
      It 'E-b1: git -C /abs/wt commit -m x -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt commit -m x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-b2: cd /abs/wt && git commit -m x -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"cd /abs/wt && git commit -m x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-b3: cd /abs/wt, then add+commit+push all in one call -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"cd /abs/wt && git add -A && git commit -q -m x && git push"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-b4: git -C /abs/wt on every mutating segment -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git -C /abs/wt rebase origin/devel && git -C /abs/wt push --force-with-lease origin b"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End
    End

    Describe 'E2: the named target IS the primary checkout ($CLAUDE_PROJECT_DIR) -> DENY'
      setup_proj() { export CLAUDE_PROJECT_DIR="$PROJ"; }
      BeforeEach 'setup_proj'

      It 'E-c1: cd $PROJ && git commit -m x -> DENY'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $PROJ && git commit -m x\"}}"
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-c1b: a TRAILING SLASH on the primary checkout must not defeat E2 -> DENY'
        # Shell tab-completion appends the slash, so without this it is the single
        # easiest way to run a mutating command straight in the primary checkout.
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $PROJ/ && git commit -m x\"}}"
        When run script "$GUARD"
        The status should be success
        The output should include '"permissionDecision":"deny"'
      End

      It 'E-c2: git -C $PROJ push -> DENY'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git -C $PROJ push\"}}"
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-c3: cd $PROJ&&git reset --hard, no spaces -> DENY'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $PROJ&&git reset --hard\"}}"
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-c4: cd $PROJ alone, no git verb -> ALLOW (nothing mutating)'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $PROJ\"}}"
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End
    End

    Describe 'THE PREFIX TRAP: a worktree lives UNDER the project dir -> ALLOW'
      setup_proj() { export CLAUDE_PROJECT_DIR="$PROJ"; }
      BeforeEach 'setup_proj'

      It 'E-d1: cd into a worktree under the project dir -> ALLOW (the / after $PROJ disqualifies the match)'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd $PROJ/.claude/worktrees/issue-1262 && git commit -m x\"}}"
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-d2: git -C into a worktree under the project dir -> ALLOW'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git -C $PROJ/.claude/worktrees/issue-1262 push --force-with-lease origin b\"}}"
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-d3: a SIBLING dir sharing the project-dir prefix (not a subdirectory) -> ALLOW'
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git -C $PROJ-other commit -m x\"}}"
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End
    End

    Describe 'exemptions: git worktree add/remove and every read-only verb -> ALLOW'
      It 'E-e1: git worktree add /abs/wt branch -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git worktree add /abs/wt branch"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e2: git worktree remove /abs/wt -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove /abs/wt"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e3: git status -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git status"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e4: git log --oneline -5 -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git log --oneline -5"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e5: git fetch origin -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git fetch origin"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e6: git rev-parse HEAD -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git rev-parse HEAD"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e7: git diff origin/devel...HEAD -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git diff origin/devel...HEAD"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-e8: git grep -n foo -- src -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git grep -n foo -- src"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End
    End

    Describe 'hostile inputs (issue #1262 brief section 4)'
      It 'E-h1 (accepted false positive, same class as B10): a commit MESSAGE containing text that looks like a cd to the primary checkout -> DENY'
        export CLAUDE_PROJECT_DIR="$PROJ"
        Data "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cd /abs/wt && git commit -m 'reminder: never cd $PROJ directly'\"}}"
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End

      It 'E-h2: cd to a RELATIVE path -> ALLOW (a cd is present; the guard cannot resolve it and must not try)'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"cd ../wt && git commit -m x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-h3: git -C with the path in a VARIABLE -> ALLOW (git -C  is present, whatever it resolves to)'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git -C \"$WT\" commit -m x"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-h4 (most likely false positive, must not fire): a mutating verb word as an ARGUMENT VALUE -> ALLOW'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"git log --grep=commit"}}
        End
        When run script "$GUARD"
        The status should be success
        The output should equal ""
      End

      It 'E-h5 (accepted false positive): git push inside a quoted string passed to another tool -> DENY'
        Data
          #|{"tool_name":"Bash","tool_input":{"command":"sh -c \"git push\""}}
        End
        When run script "$GUARD"
        The status should be success
        The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
      End
    End

    It 'E-h6: a commit MESSAGE containing a cd-shaped token must NOT forge a target -> DENY'
      # The fail-OPEN direction: a bare space before `cd ` means it sits in an ARGUMENT,
      # not command position. Honouring it would let `-m "cd into the worktree"` satisfy
      # E1 and wave a target-less mutating command through (issue #1262).
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m run cd /tmp first"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h7: a real target in command position still ALLOWs (the E-h6 boundary is not too tight)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cd /abs/wt && git add -A && git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ''
    End

    It 'E-h8: a conventional-commit message (fix: cd ...) must NOT forge a target -> DENY'
      # The `:` that lets the JSON scaffold (command:cd ...) name a target also appears in
      # ordinary commit prose. `fix:`/`feat:` are ubiquitous, so accepting a bare `:` as a
      # command-position boundary let a target-less mutating command through -- fail-OPEN.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m \"fix: cd /tmp\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h9: git merge-base is READ-ONLY and must not be denied by the merge verb -> ALLOW'
      # Verb matching must carry a trailing boundary: `merge-base`/`commit-tree` are
      # read-only plumbing and must not be caught by the `merge`/`commit` prefix.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git merge-base HEAD origin/devel"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ''
    End

    It 'E-h10: the JSON scaffold still names a target (the E-h8 boundary is not too tight)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cd /abs/wt && git commit -m \"fix: something\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ''
    End

    It 'E-h11: git checkout-index overwrites the working tree -> DENY (the hyphen boundary must not wave it through)'
      # The [^a-z-] boundary that stops `merge-base` being denied by `merge` would also
      # wave through the hyphenated MUTATORS, so each is named in full. checkout-index
      # rewrites the working tree of whatever repo the cwd points at.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git checkout-index -a -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h12: git update-ref moves a ref -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git update-ref refs/heads/x abc123"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h13: git apply writes the working tree -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git apply p.patch"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h14: git commit-tree is read-only plumbing -> ALLOW (the boundary is not too tight)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit-tree abc123"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ''
    End

    It 'E-h15: a MID-CHAIN cd does not govern a later verb -> DENY (only a leading cd does)'
      # Deliberate behaviour change: `git add -A && cd /wt && git commit` is legal shell,
      # but trusting a cd found anywhere in the payload is what let a commit MESSAGE forge
      # one. Only a cd that is the FIRST command counts. Put the cd first.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git add -A && cd /abs/wt && git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E-h16: a SUBSHELL cd does not persist to its siblings -> DENY'
      # `sh -c '(cd /tmp); pwd'` prints the ORIGINAL cwd. Trusting a subshell cd would
      # re-admit the exact issue #1262 shape with the cd scoped out of the mutating segments.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"(cd /abs/wt && git fetch); git rebase origin/devel && git push --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End


    It 'E-h18: `git -C` inside a MESSAGE must not forge an in-place target -> DENY'
      # The -C must be adjacent to the verb it governs, never merely present in the segment.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin main -m \"note: git -C x is nice\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
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

    It 'E-f2 (Rule E hostile input): garbled non-JSON stdin containing a mutating-verb pair, no cd/-C -> DENY (documented accepted false positive, same class as B10/D10)'
      Data
        #|not json at all {{{ git commit
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'E-f3 (Rule E): CLAUDE_PROJECT_DIR unset, explicit target present -> ALLOW (E2 skipped, E1 satisfied)'
      unset CLAUDE_PROJECT_DIR
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cd /abs/wt && git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E-f4 (Rule E): CLAUDE_PROJECT_DIR unset, no explicit target -> DENY (E1 still applies, unset never crashes or denies wrongly)'
      unset CLAUDE_PROJECT_DIR
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End
  End
End
