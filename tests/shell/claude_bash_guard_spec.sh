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
#   Rule A  -- git commit + --no-verify (long flag, standalone -n, or a
#              clustered short flag like -an, -anm)            -> DENY
#              (#1292: -n is git's own short form of --no-verify on
#              `git commit`, and clusters exactly like Rule B's f-cluster)
#   Rule B  -- git push + EITHER a force flag (--force / standalone -f /
#              a clustered short flag like -uf, -fu, -4f)
#              WITHOUT --force-with-lease, OR a `+`-prefixed force
#              REFSPEC (`git push origin +branch:branch`)      -> DENY
#              (lease present AND no bare force flag after the LAST
#              --force-with-lease -> PASS; git honors the last force
#              flag, so a bare force AFTER the lease still denies, #1058.
#              #1292: a `+` refspec is git's OTHER force syntax -- no flag
#              at all, and NEVER lease-protected, so it denies even
#              alongside --force-with-lease)
#   Rule C  -- git worktree remove + force flag                -> DENY
#   Rule E  -- (1) a cp -a/-R/-r/-al or rsync whose SOURCE carries a .git
#              entry (the copy-a-worktree shape, #3101)                -> DENY
#              (the guard probes the resolved source argument -- the only
#              rule that touches the filesystem; a source without a .git
#              entry passes)
#              (2) git clone / git worktree add whose TARGET resolves
#              under the system temp dir (/tmp, /private/tmp, or
#              $TMPDIR when it resolves inside either)                 -> DENY
#              (boundary-anchored: /var/tmp/... and /tmpfoo never match)
#   fail-open -- empty / garbled stdin, no rule match           -> PASS
#   -f boundary -- standalone -f / an f-bearing short-flag cluster,
#                  never matching inside --force/-force/a token
#                  like foo-f                                   -> PASS
#   normalization (#923 review F1) -- every rule matches against a
#              normalized view (JSON tab escapes decoded, quotes/backslashes
#              stripped, whitespace runs collapsed to one space), so double/tab
#              whitespace and a quoted subcommand token can't evade a rule -> DENY
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

    It 'A1 (#1375): a serialized tab between git and commit with short -n -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\tcommit -n"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'A2 (#1375): a serialized tab between commit and short -n -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit\t-n"}}
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

    It 'H22 (#1339): single-quoted subcommand token (git '\''commit'\'' -n -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git 'commit' -n -m x"}}
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

    It 'B11 (#1292): standalone short flag (git commit -n -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -n -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B18 (#1339): single-quoted standalone short flag (git commit '\''-n'\'' -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit '-n' -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B12 (#1292): clustered short flag, n mid-cluster (git commit -anm x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -anm x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B19 (#1339): single-quoted short-flag cluster (git commit '\''-an'\'' -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit '-an' -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H15 (#1292 F3 clustered short flag, other order): git commit -an -m x -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -an -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H16 (#1292 F1 whitespace evasion): double space before a short -n (git  commit -n -m x) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git  commit -n -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H17 (#1292 F2 metachar boundary): git commit -n;true -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -n;true"}}
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

    It 'B16 (#1292, documented accepted false-positive): -n inside the commit MESSAGE text -> DENY'
      # Same accepted class as B10, one letter over: a message quoting a real
      # -n flag from another tool (grep -n, sed -n, ...) also denies -- the
      # guard cannot distinguish "the flag" from "prose about a flag".
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -am \"use grep -n to show line numbers\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H20 (#1292 F3 clustered short flag, n FIRST): git commit -na -m x -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git commit -na -m x"}}
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

    It 'B20 (#1339): single-quoted standalone short flag (git push '\''-f'\'' origin main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push '-f' origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B21 (#1339): single-quoted push subcommand token (git '\''push'\'' -f origin main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git 'push' -f origin main"}}
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

    It 'H23 (#1339): single-quoted short-flag cluster (git push '\''-uf'\'' origin main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push '-uf' origin main"}}
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
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease;true"}}
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
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"PR branch rebases use --force-with-lease exclusively; a bare force-push can clobber another session'"'"'s PR (CLAUDE.md)"}}'
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

    It 'P13 (issue #1058): bare -f AFTER --force-with-lease -> DENY (git honors the last force flag)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease -f"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B22 (#1339): single-quoted -f AFTER --force-with-lease -> DENY (last force flag wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease '-f' origin main"}}
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

    It 'B1 (#1375): a serialized tab between git and push with clustered -4f -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\tpush -4f origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B2 (#1375): a serialized tab between push and clustered -4f -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push\t-4f origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B3 (#1375): serialized tabs with single-quoted push and flag tokens -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\t'push'\t'-4f' origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'T1 (#1375): consecutive serialized tabs collapse to a token boundary -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\t\tpush -4f origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'T2 (#1375): a serialized literal backslash-t remains data -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\\tpush -4f origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'T3 (#1375): a backslash before a serialized tab retains tab whitespace semantics -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\\\tpush -4f origin main"}}
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
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force --force-with-lease origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P17 (#1339): single-quoted -f BEFORE --force-with-lease -> PASS (the lease, last, wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push '-f' --force-with-lease origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P16 (issue #1298): bare force BETWEEN two leases -> PASS (the final lease wins)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease --force --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P15 (issue #1058): --force-with-lease --force-if-includes -> PASS (lease companion, not a bare force)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease --force-if-includes"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'B13 (#1292): + force refspec, no flag at all (git push origin +branch:branch) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin +branch:branch"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B14 (#1292): + force refspec, src != dst (git push origin +feature:main) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin +feature:main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'B15 (#1292, load-bearing): + force refspec ALONGSIDE --force-with-lease still DENIES (the lease never protects it)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease origin +branch:branch"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H18 (#1292 F2 metachar boundary): git push origin +branch:branch;true -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin +branch:branch;true"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H19 (#1292 F1 quoting evasion): a quoted refspec (git push origin \"+branch:branch\") -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin \"+branch:branch\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H24 (#1339): a single-quoted force refspec (git push origin '\''+branch:branch'\'') -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin '+branch:branch'"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'H25 (#1339): a leased single-quoted force refspec still DENIES'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease origin '+branch:branch'"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'P18 (#1339): a bare + token is not a force refspec -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin '+'"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'P19 (#1339): a mid-token + is not a force refspec -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin 'branch+branch'"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'B17 (#1292, documented accepted false-positive): a `+` opening a push option VALUE -> DENY'
      # `-o "+1 note"` is a normal push option whose value happens to start
      # with +. Double-quote stripping (normalization) exposes it at a
      # segment boundary, same accepted class as B10/B16 one char over.
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push origin main -o \"+1 note\""}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
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

    It 'B23 (#1339): single-quoted short flag (git worktree remove '\''-f'\'' ../wt) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove '-f' ../wt"}}
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

    It 'C1 (#1375): a serialized tab between git and worktree -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git\tworktree remove -f ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C2 (#1375): a serialized tab between worktree and remove -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree\tremove -f ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C3 (#1375): a serialized tab between remove and short -f -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove\t-f ../wt"}}
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
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree remove ../wt && git push --force-with-lease"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C2 (Rule C FP, reversed order): leased push && unforced worktree remove -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git push --force-with-lease && git worktree remove ../wt"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C3 (Rule B FP): git clean --force && normal git push -> PASS (force belongs to git clean, not the push)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clean --force && git push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C4 (Rule B FP, subshell boundary): (git clean --force); git push origin main -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"(git clean --force); git push origin main"}}
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

    It 'C9 (#1292, still caught): git status && a + force refspec push in its own segment -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git status && git push origin +branch:branch"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C10 (#1292, no leak): a literal + in an unrelated segment does not force an unforced push -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"echo +1 && git push origin main"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'C11 (#1292, still caught): git status && a -n commit bypass in its own segment -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git status && git commit -n -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"'
    End

    It 'C12 (#1292, no leak): a literal -n in an unrelated segment does not bypass an unforced commit -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"echo -n && git commit -m x"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End
  End

  # ── GitHub repository settings own PR merge methods ─────────────────────────

  Describe 'GitHub PR merge method ownership'
    It 'passes a forbidden server-side method to authoritative repository settings'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"gh pr merge 1 --rebase"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'passes the canonical explicit squash command'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"gh pr merge 1 --squash"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
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

    It 'D1-tab (#1375): a serialized tab before a wait option remains DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"sh scripts/agent/wait-checks.sh\t--repo o/r --pr 1 > /tmp/ci.txt 2>&1 &"}}
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

  # ── Rule E: scratch trees -- copy a git-bearing tree / clone into system tmp ──
  #
  # The scratch-tree rule (#3089 prose, #3101 mechanical): a scratch tree is a
  # throwaway worktree or a git archive extraction -- never a cp/rsync of a
  # git-bearing tree (the copy keeps the source's .git, so its git commands
  # drive the ORIGINAL's index, HEAD, and refs), never a tree under the
  # system temp dir (invisible to git worktree list; no prune can reach it).
  #
  # E1 probes the resolved SOURCE argument -- the only rule that touches the
  # filesystem. The `.` source resolves against the guard's CWD, which under
  # the canonical invocation (shellspec from the repo root, CI, run-gates.sh)
  # is the checkout root: a real .git, the strongest fixture available. The
  # non-repo case uses tests/ (no .git entry) and passes from any CWD.

  Describe 'Rule E1: cp/rsync of a git-bearing tree'
    It 'E1: cp -a of the current checkout (a real .git) -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -a . /var/tmp/agents/guard-e1"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E2: cp -R of the current checkout -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -R . /var/tmp/agents/guard-e2"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E3: cp -r of the current checkout -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -r . /var/tmp/agents/guard-e3"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E4: cp -al of the current checkout -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -al . /var/tmp/agents/guard-e4"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E5: rsync -a of the current checkout -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"rsync -a . /var/tmp/agents/guard-e5"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E6: cp -a of a non-repo directory (tests/ has no .git entry) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -a tests /var/tmp/agents/guard-e6"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E6b: cp -a of a source that does not exist (probe is fail-open) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -a /nonexistent/wt /var/tmp/agents/guard-e6b"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E7 (F5 full JSON validity): exact deny JSON names the two sanctioned alternatives'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"cp -a . /var/tmp/agents/guard-e1"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"a cp/rsync of a git checkout keeps the source'"'"'s .git, so the copy'"'"'s git commands drive the ORIGINAL checkout'"'"'s index, HEAD, and refs (CLAUDE.md scratch trees). Use git archive <sha> | tar -x for a read-only extraction, or wt switch --create --base <sha> for a throwaway worktree"}}'
    End
  End

  Describe 'Rule E2: git clone / worktree add into the system temp dir'
    It 'E8: git clone into /tmp/... -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /tmp/r"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E9: git clone into exactly /tmp -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /tmp"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E10: git clone into /var/tmp/agents -> PASS (/var/tmp is not /tmp)'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /var/tmp/agents/r"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E11: compound command mentioning /tmp unrelated to the clone target -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /var/tmp/agents/r && echo /tmp/junk"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E12: git worktree add under /tmp -> DENY'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree add /tmp/wt deadbeef"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should include '"permissionDecision":"deny"'
    End

    It 'E13: git worktree add under /var/tmp/agents -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git worktree add /var/tmp/agents/wt deadbeef"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E14: /tmpfoo is not the system temp dir (boundary) -> PASS'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /tmpfoo/r"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal ""
    End

    It 'E15 (F5 full JSON validity): exact deny JSON names /var/tmp/agents'
      Data
        #|{"tool_name":"Bash","tool_input":{"command":"git clone https://example.com/r.git /tmp/r"}}
      End
      When run script "$GUARD"
      The status should be success
      The output should equal '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"a clone or worktree under the system temp dir is unreclaimable: no git worktree list entry, no prune or wt remove can reach it, and /tmp is RAM-backed tmpfs on Linux. Use /var/tmp/agents for scratch trees, or wt switch --create --base <sha> for a throwaway worktree"}}'
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
