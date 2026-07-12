#!/bin/sh
# scripts/claude-bash-guard.sh -- PreToolUse Bash guard: deny 4 agent footguns.
#
# Wired in .claude/settings.json as a PreToolUse hook matching the Bash tool.
# Denies, at the TOOL layer (before the command ever runs), four operations an
# AGENT must not run -- three git bypasses a human may legitimately use, plus a
# wait-launch shape that silently strands the turn:
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
#   Rule D -- a `wait-*.sh` backgrounded with the shell's `&` : backgrounding
#             is a property of the TOOL CALL (run_in_background: true), not of
#             shell syntax, so a wait started with `&` inside a foreground call
#             is never harness-tracked -- no completion notification fires and
#             the turn stalls while the wait has already finished (#1225).
#             Whole-payload, not per-segment: `&` is one of the characters
#             $segs splits on.
#
# Rule D runs first (whole-payload). Then the per-segment rules: segments are
# scanned left to right (see MATCHING below); within one segment, A, then B,
# then C. First matching pair wins.
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
# payload once, builds ONE normalized view of it ($norm, see below), splits
# $norm into newline-separated SEGMENTS on shell command-separator
# metacharacters (`; & | ( )`, see $segs below), and every rule matches
# against ONE segment at a time ($seg) -- never a real shell/argv parse, and
# never across a segment boundary. Per-segment scoping is what fixes a
# cross-segment false positive (issue #923 review, Copilot): scanning the
# WHOLE payload let a force flag belonging to one part of a compound command
# "leak" into a rule for an unrelated, unforced git subcommand elsewhere in
# the same command, e.g. `git worktree remove ../wt && git push
# --force-with-lease` used to wrongly deny on the (unforced) worktree remove
# because `--force` appeared ANYWHERE in the payload.
#
# This is robust to garbled JSON (it just fails to match, i.e. fail-open) but
# has TWO documented, ACCEPTED false-positive surfaces, each now scoped to a
# single segment rather than the whole payload:
#
#   1. The scan runs over a segment's full text (JSON structure and all, for
#      whichever segment the JSON's tool_input.command value falls into), so
#      a trigger phrase occurring ANYWHERE in that SAME segment denies --
#      e.g. a commit MESSAGE that merely CONTAINS the literal text
#      "--no-verify" (`git commit -m 'handle the --no-verify flag'`) also
#      denies, because the guard cannot distinguish "the flag" from "prose
#      about the flag" without a real parse.
#   2. Normalization (below) strips quotes/backslashes and collapses
#      whitespace BEFORE splitting into segments, specifically so
#      whitespace/quoting variance in the invoking command can't evade a
#      rule -- but matching still runs over a segment's full text, so the
#      same phrase-anywhere-in-segment caveat holds after normalization too.
#
# Erring toward blocking is the intended tradeoff in both cases.
#
# Rule D inherits both surfaces, and adds nothing new in kind:
#
#   * An `&` inside an ARGUMENT VALUE (`--exclude "a&b"`) denies a foreground
#     wait, for the same reason B10's --no-verify-in-a-message denies: no argv
#     parse, so data and operator look alike. Pinned by spec D10. No flag of any
#     wait-*.sh takes an `&`-bearing value today, so the trigger is theoretical --
#     and erring toward blocking is the stated tradeoff.
#   * A wait reached through INDIRECTION (a variable, a function, an alias) is
#     invisible: the literal `wait-*.sh` token never sits in the backgrounded
#     statement. Pinned by spec D11 -- the same class as the git-alias case below,
#     and out of scope for the same reason.
#
# ACCEPTED LIMITATION (issue #923 review F4): being a static text scan, this
# guard cannot defend against ACTIVE circumvention -- e.g. an agent that
# pre-defines a git alias (`git config alias.p 'push --force'; git p`) so the
# blocked subcommand phrase never appears in the command text at all.
# Detecting that would require running `git config` with repo knowledge the
# hook does not have. Out of scope BY DESIGN: issue #923's threat model is an
# agent "talking itself past prose", not one deliberately constructing
# payloads to defeat a technical control (if an agent does the latter, the
# prose rules have already failed and this guard is not the intended
# backstop). Accepted and documented per maintainer sign-off.
#
# NORMALIZATION (issue #923 review F1): rather than matching rules against
# the raw payload, everything matches against $norm, built by:
#   1. Deleting every `"` and `\` character -- collapses JSON-escaped quotes
#      and a quoted subcommand token alike (`git \"commit\"` -> `git commit`).
#   2. Collapsing every run of whitespace (space/tab/newline) to one space --
#      defeats `git  commit` (double space) or a literal tab between tokens.
# Fail-open holds through normalization: empty/garbled input still normalizes
# to a string with no rule match, i.e. exit 0. $norm is then split into
# per-segment matching units ($segs/$seg, see below) -- normalization always
# runs on the WHOLE payload first, splitting happens second.
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

# segs -- $norm split into newline-separated SEGMENTS on shell
# command-separator metacharacters (`; & | ( )`). Each rule below matches
# against ONE segment at a time ($seg, set by the per-segment loop further
# down) instead of the whole payload -- this is what keeps a force flag in
# one part of a compound command from "leaking" into a rule for an
# unrelated, unforced git subcommand elsewhere in the same command (issue
# #923 review, Copilot). $norm has already collapsed real newlines to spaces
# (see NORMALIZATION above), so using a bare newline as the segment
# delimiter here is unambiguous.
segs="$(printf '%s' "$norm" | tr ';&|()' '\n')"

# norm_bg -- the view Rule D matches on. Built from $payload, NOT from $norm, and
# never split into $segs: `&` is one of the characters $segs splits on, so
# backgrounding is invisible per-segment, and $norm has already dissolved one of the
# two things Rule D must see. Each step is load-bearing:
#   1. Park every ESCAPED backslash (`\\` in the payload = one literal backslash in
#      the command). JSON spells a real newline `\n` and a literal backslash-n `\\n`,
#      so step 2 would otherwise read the latter's tail as a newline and inject a fake
#      `;` INSIDE an argument -- which, landing between the wait script and its `&`,
#      silently un-denies a genuinely backgrounded wait.
#   2. A NEWLINE ENDS A COMMAND, exactly like `;`. A multi-line command arrives as the
#      JSON escape `\n`, which $norm's backslash-strip turns into a bare `n` -- welding
#      two commands into one, so a FOREGROUND wait whose only sin is a later
#      backgrounded line would deny. Both newline forms become `;` here.
#   3. Unpark the literal backslashes, then $norm's own steps: strip quotes/backslashes
#      and collapse whitespace runs.
#   4. Neutralize the two `&` LOOKALIKES -- a redirection (`2>&1`, `>&2`, `&>`) and
#      the `&&` list operator -- so a surviving `&` is unambiguously a background.
norm_bg="$(printf '%s' "$payload" \
	| sed -e 's/\\\\/@PFB_BS@/g' \
	| sed -e 's/\\n/;/g' \
	| tr '\n' ';' \
	| sed -e 's/@PFB_BS@/\\/g' \
	| tr -d '\\"' \
	| tr -s '[:space:]' ' ' \
	| sed -e 's/[0-9]*>&[0-9-]*//g' -e 's/&>//g' -e 's/&&/ /g')"

# _contains <needle> -- true (rc 0) iff the CURRENT SEGMENT ($seg, set by
# the per-segment loop below) contains <needle> as a literal substring.
_contains() {
	case "$seg" in
	*"$1"*) return 0 ;;
	*) return 1 ;;
	esac
}

# Boundary class for a short force-flag token: the separator on either side
# is start/end-of-segment, whitespace, a shell word-terminator a
# metacharacter can place directly after a flag with no space in between
# (`; | & ( ) < > ,` -- none of `; | & ( )` can actually occur WITHIN a
# segment any more, since those are exactly the characters $segs split on;
# they stay in this class as harmless dead alternatives), or a JSON
# structural brace (`{` `}`) -- normalization (above) strips the payload's
# quotes, so a flag at the end of the last segment sits directly against
# the closing `}}` with no other separator left to match.
_SEP='[[:space:];|&(){}<>,]'

# _has_force_flag -- true iff the CURRENT SEGMENT ($seg) carries a force
# flag:
#   * the literal substring --force (covers --force and --force-with-lease
#     alike; callers that must distinguish the two check --force-with-lease
#     separately), OR
#   * a single-dash short-flag CLUSTER containing f (-f, -uf, -fu, -4f, ...)
#     -- getopt clusters short flags, so `git push -uf origin main`
#     force-pushes exactly like `-f`, and digit short flags (`-4`/`-6`)
#     cluster the same way (issue #1058). The mandatory single leading dash
#     (never --) is why this never matches --force/--force-with-lease: the
#     character right after the boundary dash in "--force" is another dash,
#     not [a-z0-9], so the match can't start there, and the first dash
#     itself has no valid boundary before it either. The only f-bearing
#     short flag on `git push` / `git worktree remove` is force, so treating
#     any single-dash f-cluster as force on those two subcommands is safe.
_FORCE_CLUSTER="-[a-z0-9]*f[a-z0-9]*"
_has_force_flag() {
	_contains '--force' && return 0
	printf '%s' "$seg" | grep -Eq "(^|${_SEP})${_FORCE_CLUSTER}(\$|${_SEP})"
}

# _bare_force_after_last_lease -- git honors the LAST force flag: a bare
# --force (exact word) or f-cluster after the last --force-with-lease is a
# bare force push (issue #1058); --force-if-includes stays clean.
_bare_force_after_last_lease() {
	printf '%s' "${seg##*--force-with-lease}" \
		| grep -Eq "(^|${_SEP})(--force|${_FORCE_CLUSTER})(\$|${_SEP})"
}

# _deny <reason> -- print the PreToolUse deny JSON and exit 0 (exit 0 is
# required even for a deny: Claude Code reads the decision from stdout, not
# from the process exit status). <reason> must contain no " or \ so it can
# be inlined into the JSON string literally, with no escaping.
_deny() {
	printf '%s\n' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$1\"}}"
	exit 0
}

# Rule D (whole-payload, not per-segment -- see norm_bg above). `[^;]*` keeps the
# `&` bound to the wait's OWN command: an `&` after a `;` backgrounds a later one.
if printf '%s' "$norm_bg" | grep -Eq 'wait-[a-z0-9_-]*\.sh[^;]*&'; then
	_deny "a wait script backgrounded with & is invisible to the harness: no completion notification fires, so the turn stalls while the wait has already finished (issue #1225). Launch it as its OWN Bash call with run_in_background: true -- backgrounding is a property of the tool call, not of shell syntax (CLAUDE.md No orphaned waits)"
fi

# Walk $segs one segment at a time, applying rules A-C to each ($seg
# is read by _contains / _has_force_flag above). Fed via a heredoc (not a
# `| while`) so this loop runs in the CURRENT shell, not a subshell: dash (the
# box's /bin/sh) forks a subshell for the reader end of a pipe, which would
# swallow _deny's `exit 0` instead of ending the whole script.
while IFS= read -r seg; do
	if _contains 'git commit' && _contains '--no-verify'; then
		_deny "the pre-commit lint gate's --no-verify bypass is for humans, not agents (CLAUDE.md)"
	fi

	if _contains 'git push' && _has_force_flag; then
		if ! _contains '--force-with-lease' || _bare_force_after_last_lease; then
			_deny "the rebase-only landing flow uses --force-with-lease exclusively; a bare force-push can clobber another session's PR (CLAUDE.md)"
		fi
	fi

	if _contains 'git worktree remove' && _has_force_flag; then
		_deny "CLAUDE.md forbids force-removing a worktree you do not own"
	fi
done <<_PFB_SEGS_
$segs
_PFB_SEGS_

exit 0
