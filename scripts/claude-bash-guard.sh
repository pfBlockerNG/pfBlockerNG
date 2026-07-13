#!/bin/sh
# scripts/claude-bash-guard.sh -- PreToolUse Bash guard: deny 4 agent footguns.
#
# Wired in .claude/settings.json as a PreToolUse hook matching the Bash tool.
# Denies, at the TOOL layer (before the command ever runs), five operations an
# AGENT must not run -- three git bypasses a human may legitimately use, a
# wait-launch shape that silently strands the turn, and a mutating git command
# whose target the hook cannot verify:
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
#   Rule E -- a MUTATING git command (commit, push, rebase, merge, reset,
#             checkout, switch, cherry-pick, revert, stash, am, clean) that
#             depends on the AMBIENT working directory : the PreToolUse
#             payload carries no cwd (see WHY BELOW), so the hook cannot
#             detect "you are in the wrong directory" -- it can only refuse
#             a mutating command whose target is UNSTATED, making the bad
#             state unrepresentable instead of detected (issue #1262: a
#             stray `cd` into the primary checkout, left over from an
#             unrelated fix, silently redirected a rebase+push at the wrong
#             repo; the rebase reported "up to date" and the push was a
#             silent no-op, hiding that the real branch was a commit
#             behind). DENIES when neither `git -C <path>` nor `cd <path>`
#             names a target anywhere in the payload (E1), and DENIES when
#             the named target IS the primary checkout -- $CLAUDE_PROJECT_DIR,
#             exported into this hook by .claude/settings.json (E2) --
#             CLAUDE.md "Worktrees": all repository work happens in a
#             dedicated worktree, never there. `git worktree add`/`remove`
#             are exempt from Rule E entirely, and need no special-case code
#             for it: neither "add" nor "remove" is one of the mutating
#             verbs above, so a `git worktree ...` segment never matches the
#             verb check that would trigger E1/E2 in the first place.
#
# Rule D runs first (whole-payload). Rule E's target checks (E1: is a
# `-C`/`cd` target named anywhere; E2: does that target equal the primary
# checkout) are ALSO whole-payload and precomputed once, right after Rule D,
# for the same reason Rule D itself is whole-payload -- see THE WHOLE-PAYLOAD
# CRUX below. Only Rule E's MUTATING-VERB detection runs per-segment. Then
# the per-segment rules: segments are scanned left to right (see MATCHING
# below); within one segment, A, then B, then C, then E's verb check against
# the precomputed E1/E2 booleans. First matching pair wins.
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
#   * A `&&` chain after a wait denies (D5), and so does a foreground wait using the
#     digit-less `>&N` redirect shorthand (D19). Both fall out of refusing to trust
#     any operator a quoted value could have forged -- see norm_bg. A wait belongs in
#     its own call, and nothing here writes `>&N` without its fd.
#   * A MULTI-LINE call that mentions a wait script and backgrounds anything at all
#     -- even on a different line -- denies. Pinned by spec D7. Distinguishing those
#     lines needs a separator the scan cannot trust (see norm_bg): every attempt to
#     read a newline as one re-opened a silent bypass, and a rule that fails open is
#     worse than no rule. Split the call in two, which is the right shape anyway.
#   * A wait whose PATH IS NEVER NAMED (assembled from pieces, or hidden behind an
#     alias) is invisible -- the same class as the git-alias case below, and out of
#     scope for the same reason. Indirection that still spells the path out, e.g.
#     through a variable, IS caught (pinned by D11).
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
#
# WHY BELOW (Rule E, issue #1262): the PreToolUse payload is
# {"tool_name":"Bash","tool_input":{"command":"..."}} -- there is no cwd
# field, and the harness's Bash working directory PERSISTS across calls (a
# `cd` two calls ago is still in effect). The hook therefore cannot compare
# "the cwd" against anything; it can only refuse a mutating git command whose
# target is never named, which makes the dangerous state (running a mutating
# command against whatever directory the shell happens to be sitting in)
# unrepresentable rather than something the hook detects after the fact.
#
# THE WHOLE-PAYLOAD CRUX: `cd /path && git commit` splits into segments
# `cd /path ` and ` git commit` (see $segs below) -- the `cd` and the verb
# are in DIFFERENT segments. So E1's "is a target named at all" test and
# E2's "does that target equal the primary checkout" test both run against
# $norm (the whole payload), exactly as Rule D's background-`&` test does,
# and for the identical reason: the thing being looked for can sit in a
# different segment than the verb that triggers the rule. Only the
# MUTATING-VERB check itself is per-segment (_seg_has_mutating_verb, run
# inside the A-C loop against $seg) -- pinned by E-b3/E-b4 (a `cd` naming the
# target once at the front of a compound command covers every mutating verb
# in every later segment of that SAME payload).
#
# THE PREFIX TRAP: worktrees live UNDER the project dir
# ($CLAUDE_PROJECT_DIR/.claude/worktrees/<slug>), so E2 must never match
# $CLAUDE_PROJECT_DIR as a plain substring prefix -- that would deny every
# worktree command and make the hook unusable. _targets_primary_checkout
# requires the character immediately after $CLAUDE_PROJECT_DIR to be a
# genuine separator (space/&/;/|/(/)/{/}/</>/,) or end-of-payload (a
# synthetic trailing space is appended before matching so end-of-payload
# reads as that same separator class, collapsing two cases into one glob
# pattern) -- a worktree path's next character is always `/`, which is NOT
# in that class, so `cd $CLAUDE_PROJECT_DIR/.claude/worktrees/x` and
# `git -C $CLAUDE_PROJECT_DIR-other` (a SIBLING dir sharing the prefix) both
# correctly fail to match. Pinned by E-d1/E-d2/E-d3.
#
# JSON-ADJACENCY BOUNDARY: E1's target search needs a LEADING boundary too
# (so `cd ` embedded inside a longer word, e.g. `abcd `, cannot forge a
# target and wrongly ALLOW a mutating command with no real target -- the
# dangerous direction, unlike this file's other accepted false positives
# which all err toward denying). But the real payload is JSON, and
# normalization (above) strips its quotes, so `"command":"cd ...` collapses
# to `command:cd ...` -- the character immediately before a target sitting at
# the very start of the command value is `:`, not whitespace. E1's boundary
# class (_E_TARGET_LEAD) therefore adds `:` to $_SEP's separator set, for the
# same structural reason $_SEP itself already carries `{`/`}` (a flag can sit
# directly against the JSON's closing `}}`, see above). This is a narrower,
# deliberate widening of the general acceptance already documented above (a
# raw text scan is not a real parse) -- a literal `:cd ` sequence inside an
# argument VALUE (not the JSON scaffold) could in theory forge a target, but
# no realistic git invocation produces that token sequence.
#
# ACCEPTED FALSE POSITIVES (E, same family as B10/D10): E2's target-equality
# check has no leading boundary of its own (only the trailing one above), so
# a commit MESSAGE that merely CONTAINS text shaped like
# "cd $CLAUDE_PROJECT_DIR " denies even when the command's REAL cd target is
# a worktree (pinned by E-h1) -- and a mutating verb phrase sitting inside a
# quoted argument to another tool (`sh -c "git push"`) denies with no target
# check able to save it, same as B10 (pinned by E-h5). Both directions err
# toward blocking, the stated tradeoff throughout this file.
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

# norm_bg -- the view Rule D matches on: $norm (quotes/backslashes stripped, whitespace
# collapsed) with the two `&` LOOKALIKES neutralized -- a redirection (`2>&1`, `>&2`,
# `&>`) and the `&&` list operator -- so a surviving `&` is unambiguously a background.
# Never $segs: `&` is one of the characters $segs splits on, so backgrounding is
# invisible per-segment.
#
# NO SEPARATOR IS TRUSTED HERE, deliberately, and that is the whole design. $norm has
# already deleted the quote markers WITHOUT knowing what they protected, so a `;` or a
# `>` sitting in an argument VALUE is indistinguishable from a real one. Every attempt
# to read one as a boundary re-opened a silent bypass: a newline mistaken for a
# separator (whether a real one, one a backslash continued, or a literal backslash-n),
# and a quoted `;` ending the wait's statement early, each dropped a false boundary
# between a wait script and its trailing `&` and un-denied it. A rule that fails OPEN is
# worse than useless; one that over-denies costs a call split in two. So ANY background
# `&` after a wait script denies, whatever sits between (pinned by D6/D7/D14).
#
# EXACTLY ONE `&` lookalike is neutralized, in the only form a quoted value cannot fake:
# an fd redirection carrying a MANDATORY leading fd number (`2>&1`, `1>&2`). The digit is
# the anchor -- the character before a quote-fused `>` is the space that preceded the
# quote, never a digit (pinned by D15/D16). Every other lookalike is left alone, because
# each can be forged out of inert argument data fused with the REAL `&` by quote-strip:
# `&>file` (D17), and `&&` itself, which a value ending in `&` completes (D18). Deleting
# either would erase the very `&` the rule exists to find. The cost is that a `&&` chain
# after a wait denies (D5) -- a wait belongs in its own call regardless.
#
# Two shapes still slip, both pinned (D20/D21) and both requiring a payload no honest
# command produces -- the ACCEPTED LIMITATION above: a quoted value ending in a DIGIT and
# a `>` right before the `&` (`--x \"1>\"&2`) is textually identical to a real redirect,
# and an `&` written as the JSON escape `\u0026` is never decoded by a scan that reads raw
# bytes.
norm_bg="$(printf '%s' "$norm" | sed -e 's/[0-9][0-9]*>&[0-9-][0-9-]*//g')"

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

# _E_TARGET_LEAD -- leading-boundary class for E1's `git -C `/`cd ` search. A
# target only counts in COMMAND POSITION: preceded by start-of-payload, the JSON
# scaffold's `:` (normalization strips the quotes, so `"command":"cd ...`
# collapses to `command:cd ...`), or a command separator -- optionally followed
# by spaces, so `&& cd /wt` still reads as a target.
#
# A bare SPACE is deliberately NOT a boundary here: a space before `cd ` means it
# sits inside an ARGUMENT, and honouring it would let a commit message reading
# `-m fix: cd into the worktree` forge a target and ALLOW an otherwise target-less
# mutating command. That direction fails OPEN -- the one direction this file never
# accepts (every other documented false positive errs toward denying). Pinned by
# E-h6/E-h7.
_E_TARGET_LEAD='[:;|&(){}<>,]'

# _has_explicit_target -- true iff $norm (the WHOLE payload) names a target
# via `git -C ` or `cd ` IN COMMAND POSITION (see _E_TARGET_LEAD above).
# Whole-payload, not $seg: the target can sit in a different segment than the
# verb it covers (E-b3/E-b4).
_has_explicit_target() {
	printf '%s' "$norm" | grep -Eq "(^|${_E_TARGET_LEAD})[[:space:]]*(git -C |cd )"
}

# _TARGET_SEP -- trailing-boundary glob class for _targets_primary_checkout:
# a real separator, or (via the caller's synthetic trailing space) end of
# payload -- see THE PREFIX TRAP above. Case globbing, not grep -E, so
# $CLAUDE_PROJECT_DIR's `/` and `.` never need escaping.
_TARGET_SEP='[ &;|(){}<>,]'

# _targets_primary_checkout -- true iff $norm names $CLAUDE_PROJECT_DIR
# itself (never a subdirectory or a sibling sharing its prefix) as a `cd `/
# `git -C ` target. Unset CLAUDE_PROJECT_DIR -> false, never a crash (fail-open
# under set -u): E2 has nothing to compare against.
_targets_primary_checkout() {
	[ -n "${CLAUDE_PROJECT_DIR:-}" ] || return 1
	case "${norm} " in
	*"cd ${CLAUDE_PROJECT_DIR}"${_TARGET_SEP}* | *"git -C ${CLAUDE_PROJECT_DIR}"${_TARGET_SEP}*) return 0 ;;
	esac
	return 1
}

# _seg_has_mutating_verb -- true iff the CURRENT SEGMENT ($seg) contains a
# Rule E mutating verb as the pair `git <verb>` OR `git -C <path> <verb>` --
# never a bare verb word, so `git log --grep=commit` (the verb as an ARGUMENT
# VALUE) does not match (E-h4). The `-C <path>` skip is required: without it,
# the verb in `git -C /wt push` sits two tokens after `git`, not adjacent, so
# the very syntax Rule E asks callers to use would itself evade detection
# (E-c2). `git worktree add/remove` needs no exemption clause: neither "add"
# nor "remove" is in this list.
_seg_has_mutating_verb() {
	printf '%s' "$seg" \
		| grep -Eq 'git (-C [^ ]+ )?(commit|push|rebase|merge|reset|checkout|switch|cherry-pick|revert|stash|am|clean)'
}

# _deny <reason> -- print the PreToolUse deny JSON and exit 0 (exit 0 is
# required even for a deny: Claude Code reads the decision from stdout, not
# from the process exit status). <reason> must contain no " or \ so it can
# be inlined into the JSON string literally, with no escaping.
_deny() {
	printf '%s\n' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"$1\"}}"
	exit 0
}

# Rule D (whole-payload, not per-segment -- see norm_bg above). ANY background `&` after
# a wait script denies: the `;` that would prove the `&` belongs to a LATER command is
# not trustworthy in a quote-blind view, and trusting it let a real one through (D14).
if printf '%s' "$norm_bg" | grep -Eq 'wait-[a-z0-9_-]*\.sh.*&'; then
	_deny "a wait script backgrounded with & is invisible to the harness: no completion notification fires, so the turn stalls while the wait has already finished (issue #1225). Launch it as its OWN Bash call with run_in_background: true -- backgrounding is a property of the tool call, not of shell syntax (CLAUDE.md No orphaned waits)"
fi

# Rule E's target checks (whole-payload, precomputed once -- see THE
# WHOLE-PAYLOAD CRUX above; only the verb check below is per-segment).
if _has_explicit_target; then _e_has_target=1; else _e_has_target=0; fi
if _targets_primary_checkout; then _e_targets_primary=1; else _e_targets_primary=0; fi

# Walk $segs one segment at a time, applying rules A, B, C, and E's
# per-segment verb check to each ($seg is read by _contains /
# _has_force_flag / _seg_has_mutating_verb above). Fed via a heredoc (not a
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

	if _seg_has_mutating_verb; then
		if [ "$_e_has_target" = 0 ]; then
			_deny "a mutating git command depends on the ambient working directory, which this hook cannot see: name the target explicitly with git -C <path> or cd <path> first (CLAUDE.md Worktrees, issue #1262)"
		fi
		if [ "$_e_targets_primary" = 1 ]; then
			_deny "the named target is the primary checkout: every AI agent must do repository work in its own dedicated worktree, never the primary checkout (CLAUDE.md Worktrees)"
		fi
	fi
done <<_PFB_SEGS_
$segs
_PFB_SEGS_

exit 0
