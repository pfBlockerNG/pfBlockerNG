#!/bin/sh
# scripts/claude-bash-guard.sh -- PreToolUse Bash guard: deny 3 agent git bypasses.
#
# Wired in .claude/settings.json as a PreToolUse hook matching the Bash tool.
# Denies, at the TOOL layer (before the command ever runs), three git
# operations CLAUDE.md forbids an AGENT from running even though a human may:
#
#   Rule A -- `git commit` with `--no-verify`   : the pre-commit lint gate's
#             --no-verify bypass is for humans, not agents (CLAUDE.md "Git
#             hooks").
#   Rule B -- `git push` with a force flag (--force, --force-with-lease,
#             standalone -f, or a clustered short flag like -uf/-fu) and
#             WITHOUT --force-with-lease        : the rebase-only landing
#             flow uses --force-with-lease exclusively; a bare force-push can
#             clobber another session's in-flight PR (CLAUDE.md "Worktrees").
#   Rule C -- `git worktree remove` with a force flag : CLAUDE.md forbids
#             force-removing a worktree an agent does not own.
#
# First matching rule wins (A, then B, then C).
#
# FAIL-OPEN CONTRACT: this hook must NEVER block a legitimate Bash call
# because of a parsing failure. Empty stdin, garbled/non-JSON stdin, or no
# rule match all fall through to `exit 0` with NO stdout, which Claude Code
# reads as "no decision" (normal permission flow continues unaffected).
# Only an actual rule match prints the PreToolUse deny JSON. `set -u`, not
# `set -e`: an unset var is a script bug that must surface immediately, not a
# reason to abort -- an abort here would look identical to normal
# pass-through and hide the bug instead of failing loudly.
#
# MATCHING: deliberately a raw-text scan, not a JSON parser (no jq / no
# non-base dependency -- see issue #923). It reads the whole PreToolUse stdin
# payload once, builds ONE normalized view of it ($norm, see below), and
# every rule matches against $norm as text -- never a real shell/argv parse.
# This is robust to garbled JSON (it just fails to match, i.e. fail-open) but
# has TWO documented, ACCEPTED false-positive surfaces:
#
#   1. The scan runs over the WHOLE payload (JSON structure and all), not
#      just tool_input.command, so a trigger phrase occurring ANYWHERE in the
#      payload denies -- e.g. a commit MESSAGE that merely CONTAINS the
#      literal text "--no-verify" (`git commit -m 'handle the --no-verify
#      flag'`) also denies, because the guard cannot distinguish "the flag"
#      from "prose about the flag" without a real parse.
#   2. Normalization (below) strips quotes/backslashes and collapses
#      whitespace before matching, specifically so whitespace/quoting
#      variance in the invoking command can't evade a rule -- but it applies
#      to the WHOLE payload, so the same phrase-anywhere caveat holds after
#      normalization too.
#
# Erring toward blocking is the intended tradeoff in both cases.
#
# NORMALIZATION (issue #923 review F1): rather than matching rules against
# the raw payload, everything matches against $norm, built by:
#   1. Deleting every `"` and `\` character -- collapses JSON-escaped quotes
#      and a quoted subcommand token alike (`git \"commit\"` -> `git commit`).
#   2. Collapsing every run of whitespace (space/tab/newline) to one space --
#      defeats `git  commit` (double space) or a literal tab between tokens.
# Fail-open holds through normalization: empty/garbled input still normalizes
# to a string with no rule match, i.e. exit 0.
#
# Standalone `-f` (short form of --force) and a clustered short flag
# containing `f` (`-uf`, `-fu`, ...) are matched with an explicit boundary so
# they do NOT fire inside --force, --force-with-lease, -force, or a filename
# ending in "-f" (e.g. my-f-dir) -- see _has_force_flag below.
set -u

payload="$(cat)"

# norm -- the single normalized view every rule matches against (see
# NORMALIZATION above): strip " and \, then collapse whitespace runs to one
# space.
norm="$(printf '%s' "$payload" | tr -d '\\"' | tr -s '[:space:]' ' ')"

# _contains <needle> -- true (rc 0) iff $norm contains <needle> as a literal
# substring, independent of where else in the payload it occurs.
_contains() {
	case "$norm" in
	*"$1"*) return 0 ;;
	*) return 1 ;;
	esac
}

# Boundary class for a short force-flag token: the separator on either side
# is start/end-of-string, whitespace, a shell word-terminator a metacharacter
# can place directly after a flag with no space in between (`; | & ( ) < >
# ,`), or a JSON structural brace (`{` `}`) -- normalization (above) strips
# the payload's quotes, so a flag at the end of the JSON command value sits
# directly against the closing `}}` with no other separator left to match.
_SEP='[[:space:];|&(){}<>,]'

# _has_force_flag -- true iff $norm carries a force flag:
#   * the literal substring --force (covers --force and --force-with-lease
#     alike; callers that must distinguish the two check --force-with-lease
#     separately), OR
#   * a single-dash short-flag CLUSTER containing f (-f, -uf, -fu, ...) --
#     getopt clusters short flags, so `git push -uf origin main` force-pushes
#     exactly like `-f`. The mandatory single leading dash (never --) is why
#     this never matches --force/--force-with-lease: the character right
#     after the boundary dash in "--force" is another dash, not [a-z], so the
#     match can't start there, and the first dash itself has no valid
#     boundary before it either. The only f-bearing short flag on `git push`
#     / `git worktree remove` is force, so treating any single-dash
#     f-cluster as force on those two subcommands is safe.
_has_force_flag() {
	_contains '--force' && return 0
	printf '%s' "$norm" | grep -Eq "(^|${_SEP})-[a-z]*f[a-z]*(\$|${_SEP})"
}

# _deny <reason> -- print the PreToolUse deny JSON and exit 0 (exit 0 is
# required even for a deny: Claude Code reads the decision from stdout, not
# from the process exit status). <reason> must contain no " or \ so it can
# be inlined into the JSON string literally, with no escaping.
_deny() {
	printf '%s\n' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$1\"}}"
	exit 0
}

if _contains 'git commit' && _contains '--no-verify'; then
	_deny "the pre-commit lint gate's --no-verify bypass is for humans, not agents (CLAUDE.md)"
fi

if _contains 'git push' && _has_force_flag; then
	if ! _contains '--force-with-lease'; then
		_deny "the rebase-only landing flow uses --force-with-lease exclusively; a bare force-push can clobber another session's PR (CLAUDE.md)"
	fi
fi

if _contains 'git worktree remove' && _has_force_flag; then
	_deny "CLAUDE.md forbids force-removing a worktree you do not own"
fi

exit 0
