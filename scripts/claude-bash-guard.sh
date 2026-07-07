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
#   Rule B -- `git push` with a force flag (--force or standalone -f) and
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
# payload once and greps it AS TEXT for the git tokens/flags, which appear
# verbatim (unescaped) inside tool_input.command for every shape the three
# rules care about. This is robust to garbled JSON (it just fails to match,
# i.e. fail-open) but has ONE documented, ACCEPTED false-positive: a commit
# message that merely CONTAINS the literal text "--no-verify" (e.g.
# `git commit -m 'handle the --no-verify flag'`) also denies, because the
# guard cannot distinguish "the flag" from "prose about the flag" without a
# real shell/argv parse. Erring toward blocking is the intended tradeoff.
#
# Standalone `-f` (short form of --force) is matched with an explicit
# boundary so it does NOT fire inside --force, --force-with-lease, -force,
# or a filename ending in "-f" (e.g. my-f-dir) -- see _has_force_flag below.
set -u

payload="$(cat)"

# _contains <needle> -- true (rc 0) iff $payload contains <needle> as a
# literal substring, independent of where else in the payload it occurs.
_contains() {
	case "$payload" in
	*"$1"*) return 0 ;;
	*) return 1 ;;
	esac
}

# _has_force_flag -- true iff $payload carries a force flag: the literal
# substring --force (covers --force and --force-with-lease alike; callers
# that must distinguish the two check --force-with-lease separately), OR a
# standalone -f token bounded LEFT by start/whitespace/" and RIGHT by
# end/whitespace/"/backslash. The boundary keeps -f from matching inside
# --force*, -force, or a token like foo-f.
_has_force_flag() {
	_contains '--force' && return 0
	printf '%s' "$payload" | grep -Eq '(^|[[:space:]"])-f($|[[:space:]"\\])'
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
