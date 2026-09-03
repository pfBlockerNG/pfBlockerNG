#!/bin/sh
# scripts/claude-bash-guard.sh -- PreToolUse Bash guard: deny 5 agent footguns.
#
# Wired in .claude/settings.json as a PreToolUse hook matching the Bash tool.
# Denies, at the TOOL layer (before the command ever runs), five operations an
# AGENT must not run -- three git bypasses a human may legitimately use, a
# wait-launch shape that silently strands the turn, and the scratch-tree
# shapes that share or strand a git tree (issue #3101):
#
#   Rule A -- `git commit` with `--no-verify` (long flag, standalone -n, or a
#             clustered short flag like -an/-anm)   : the pre-commit lint
#             gate's --no-verify bypass is for humans, not agents (CLAUDE.md
#             "Git hooks").
#   Rule B -- `git push` with EITHER a force flag (--force,
#             --force-with-lease, standalone -f, or a clustered short flag
#             like -uf/-fu) WITHOUT --force-with-lease, OR a `+`-prefixed
#             force REFSPEC (`git push origin +branch:branch`) -- git's
#             OTHER force syntax, with no flag at all and NEVER
#             --force-with-lease-protected : PR branch rebases use
#             --force-with-lease exclusively; a bare force-push can clobber
#             another session's in-flight PR (CLAUDE.md "Worktrees").
#   Rule C -- `git worktree remove` with a force flag : CLAUDE.md forbids
#             force-removing a worktree an agent does not own.
#   Rule D -- a `wait-*.sh` backgrounded with the shell's `&` : backgrounding
#             is a property of the TOOL CALL (run_in_background: true), not of
#             shell syntax, so a wait started with `&` inside a foreground call
#             is never harness-tracked -- no completion notification fires and
#             the turn stalls while the wait has already finished (#1225).
#             Whole-payload, not per-segment: `&` is one of the characters
#             $segs splits on.
#   Rule E -- (1) a `cp -a`/`cp -R`/`cp -r`/`cp -al`/`rsync` whose SOURCE
#             carries a `.git` entry : the copy-a-worktree shape -- the copy
#             keeps the source's `.git` pointer, so every git command in the
#             copy drives the ORIGINAL tree's index, `HEAD`, and refs (issue
#             #3101, observed writing another session's `ORIG_HEAD` and index).
#             Sanctioned: `git archive <sha> | tar -x` (read-only) or
#             `wt switch --create --base <sha>` (throwaway worktree).
#             (2) a `git clone`/`git worktree add` whose TARGET resolves under
#             the system temp dir (`/tmp`, `/private/tmp`, or `$TMPDIR` when
#             it resolves inside either) : an unregistered tree no
#             `git worktree list`, prune, or `wt remove` can reach, on a
#             RAM-backed tmpfs on Linux. Sanctioned: `/var/tmp/agents`
#             (CLAUDE.md scratch trees).
#
# Rule E is the ONLY rule that touches the filesystem, and only for (1): a
# text scan cannot see a `.git` entry, so it probes the resolved SOURCE
# argument (`test -e <src>/.git` -- a DIRECTORY in a main checkout, a FILE in
# a linked worktree; `-e` covers both). A source that does not exist or does
# not resolve probes FALSE (fail-open); a relative source resolves from the
# HOOK's CWD, which differs from the agent's when the agent cd'd -- the
# accepted gap, same class as the git-alias accepted limitation above. (2) is
# per-segment text like the rest: a boundary-anchored path token in a git
# clone / worktree add segment, so `/var/tmp/...`, `/tmpfoo`, and an
# unrelated `/tmp` in another segment never match (spec E10/E11/E14).
#
# Rule D runs first (whole-payload). Then the per-segment rules: segments are
# scanned left to right (see MATCHING below); within one segment, A, then B,
# then C, then E. First matching pair wins.
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
#   2. Normalization (below) strips single/double quotes and backslashes,
#      then collapses whitespace BEFORE splitting into segments, specifically so
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
#   1. Converting odd-parity JSON `\t` escapes to tabs while leaving even-parity
#      literal backslash+t data intact.
#   2. Deleting every `'`, `"`, and `\` character -- collapses JSON-escaped quotes
#      and a quoted subcommand token alike (`git 'commit'` -> `git commit`).
#   3. Collapsing every run of whitespace (space/tab/newline) to one space --
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
# Standalone `-n` (short form of --no-verify on `git commit`) and a clustered
# short flag containing `n` (`-an`, `-anm`, ...) use the IDENTICAL boundary
# mechanism -- see _has_noverify_flag below. A `+`-prefixed force refspec
# (`git push origin +branch:branch`) is git's OTHER force syntax on `git
# push`, independent of any flag and NEVER --force-with-lease-protected --
# see _has_force_refspec below (issue #1292).
set -u

payload="$(cat)"

# norm -- the single normalized view every rule matches against (see
# NORMALIZATION above): decode odd-parity JSON tab escapes, strip ', ", and \,
# then collapse whitespace runs to one space.
tab="$(printf '\t')"
norm="$(printf '%s' "$payload" | sed -E "
:a
s/(^|[^\\\\])((\\\\\\\\)*)\\\\t/\\1\\2${tab}/g
ta
" | tr -d "\\\\\"'" | tr -s '[:space:]' ' ')"

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

# norm_bg -- the view Rule D matches on: $norm (single/double quotes and
# backslashes stripped, whitespace collapsed) with the two `&` LOOKALIKES
# neutralized -- a redirection (`2>&1`, `>&2`,
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

# _has_noverify_flag -- true iff the CURRENT SEGMENT ($seg) carries a
# --no-verify bypass on `git commit`:
#   * the literal substring --no-verify, OR
#   * a single-dash short-flag CLUSTER containing n (-n, -an, -anm, ...) --
#     -n is git's own short form of --no-verify on `git commit` (`git
#     commit -h`), and clusters exactly like _has_force_flag's f-cluster
#     (issue #1292). The same mandatory single leading dash is why this
#     never matches --no-verify/--amend -- identical double-dash-boundary
#     argument as _FORCE_CLUSTER above.
_NOVERIFY_CLUSTER="-[a-z0-9]*n[a-z0-9]*"
_has_noverify_flag() {
	_contains '--no-verify' && return 0
	printf '%s' "$seg" | grep -Eq "(^|${_SEP})${_NOVERIFY_CLUSTER}(\$|${_SEP})"
}

# _SEP_NOT -- the complement of _SEP: any character that is NOT a boundary
# separator. Used by _has_force_refspec so the character right after a
# leading `+` must belong to a ref-name token, not another separator (a bare
# `+`, or one glued mid-token, doesn't match).
_SEP_NOT='[^[:space:];|&(){}<>,]'

# _has_force_refspec -- true iff the CURRENT SEGMENT ($seg) carries a
# `+`-prefixed force REFSPEC on `git push` (`git push origin
# +branch:branch`) -- git's OTHER force syntax, with no flag at all (`git
# help push`: a leading `+` on a refspec forces a non-fast-forward update).
# NEVER --force-with-lease-protected -- the lease guards a FLAG, not this
# refspec shorthand, so callers must check it unconditionally (issue #1292).
_has_force_refspec() {
	printf '%s' "$seg" | grep -Eq "(^|${_SEP})\\+${_SEP_NOT}"
}

# _copy_srcs <anchor> -- sets _srcs to the candidate SOURCE tokens of the
# CURRENT SEGMENT's cp/rsync, space-separated, for tool+flag anchor $1
# (`cp -a` ... `rsync`): every non-flag token after the LAST anchor
# occurrence except the last one (the destination), with the trailing JSON
# braces the normalization leaves fused onto tokens stripped. The caller
# gates on the anchor being present first (see _has_copy_source_git), so
# the `##*` cut always lands on the real command, never the JSON prefix.
_copy_srcs() {
	_srcs=""
	_last_tok=""
	_rest="${seg##*"$1 "}"
	for _w in $_rest; do    # shellcheck disable=SC2086  # intentional: word-splitting into tokens
		case "$_w" in
		-*) continue ;;
		esac
		while true; do
			case "$_w" in
			*"}" ) _w="${_w%?}" ;;
			*) break ;;
			esac
		done
		[ -n "$_w" ] || continue
		_srcs="${_srcs:+$_srcs }$_last_tok"
		_last_tok="$_w"
	done
}

# _any_src_has_git -- true iff any candidate source in _srcs carries a .git
# entry: a DIRECTORY in a main checkout, a FILE (a gitdir pointer) in a
# linked worktree -- -e covers both. A source that does not exist or does
# not resolve probes false: fail-open, the contract for every parse failure
# in this guard.
_any_src_has_git() {
	[ -n "$_srcs" ] || return 1
	for _w in $_srcs; do   # shellcheck disable=SC2086  # intentional: word-splitting into tokens
		[ -e "$_w/.git" ] && return 0
	done
	return 1
}

# _has_copy_source_git -- true iff the CURRENT SEGMENT is a copy of a
# git-bearing tree: cp -a/-R/-r/-al (the recursive spellings a
# copy-a-worktree takes) or rsync, whose SOURCE contains a .git entry.
_has_copy_source_git() {
	if _contains 'cp -a '; then
		_copy_srcs 'cp -a'
		_any_src_has_git && return 0
	fi
	if _contains 'cp -R '; then
		_copy_srcs 'cp -R'
		_any_src_has_git && return 0
	fi
	if _contains 'cp -r '; then
		_copy_srcs 'cp -r'
		_any_src_has_git && return 0
	fi
	if _contains 'cp -al '; then
		_copy_srcs 'cp -al'
		_any_src_has_git && return 0
	fi
	if _contains 'rsync '; then
		_copy_srcs 'rsync'
		_any_src_has_git && return 0
	fi
	return 1
}

# _tmp_target -- true iff the CURRENT SEGMENT carries a path token under the
# system temp dir as written in the command: /tmp or /tmp/..., /private/tmp
# or /private/tmp/..., or $TMPDIR/$TMPDIR/... where $TMPDIR (this hook's
# environment, the one the agent shell inherits) resolves inside either.
# Boundary-anchored like the force-flag boundary, so /var/tmp/... and a
# /tmpfoo directory never match, and neither does /tmp inside a URL path
# (the character before a URL's /tmp is never a boundary).
_tmp_target() {
	if printf '%s' "$seg" | grep -Eq "(^|${_SEP})(/tmp|/private/tmp)(/|${_SEP})"; then
		return 0
	fi
	case "${TMPDIR:-}" in
	/tmp*|/private/tmp*)
		# shellcheck disable=SC2016  # intentional: match the literal $TMPDIR token
		if _contains '$TMPDIR' &&
			printf '%s' "$seg" | grep -Eq "(^|${_SEP})\\\$TMPDIR(/|${_SEP})"; then
			return 0
		fi
		;;
	esac
	return 1
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

# Walk $segs one segment at a time, applying rules A-C and E to each ($seg
# is read by _contains / _has_force_flag above). Fed via a heredoc (not a
# `| while`) so this loop runs in the CURRENT shell, not a subshell: dash (the
# box's /bin/sh) forks a subshell for the reader end of a pipe, which would
# swallow _deny's `exit 0` instead of ending the whole script.
while IFS= read -r seg; do
	if _contains 'git commit' && _has_noverify_flag; then
		_deny "the pre-commit lint gate's --no-verify bypass is for humans, not agents (CLAUDE.md)"
	fi

	if _contains 'git push' && _has_force_flag; then
		if ! _contains '--force-with-lease' || _bare_force_after_last_lease; then
			_deny "PR branch rebases use --force-with-lease exclusively; a bare force-push can clobber another session's PR (CLAUDE.md)"
		fi
	fi

	# A `+` force refspec (issue #1292) is NEVER lease-protected -- unconditional,
	# unlike the flag check above which --force-with-lease can clear.
	if _contains 'git push' && _has_force_refspec; then
		_deny "PR branch rebases use --force-with-lease exclusively; a bare force-push can clobber another session's PR (CLAUDE.md)"
	fi

	if _contains 'git worktree remove' && _has_force_flag; then
		_deny "CLAUDE.md forbids force-removing a worktree you do not own"
	fi

	# Rule E1: a copy of a git-bearing tree -- the copy keeps the source's
	# .git, so its git commands drive the ORIGINAL's index/HEAD/refs (#3101).
	if _has_copy_source_git; then
		_deny "a cp/rsync of a git checkout keeps the source's .git, so the copy's git commands drive the ORIGINAL checkout's index, HEAD, and refs (CLAUDE.md scratch trees). Use git archive <sha> | tar -x for a read-only extraction, or wt switch --create --base <sha> for a throwaway worktree"
	fi

	# Rule E2: a clone / worktree add whose target resolves under the system
	# temp dir -- a tree no worktree list, prune, or wt remove can reach.
	if { _contains 'git clone' || _contains 'git worktree add'; } && _tmp_target; then
		_deny "a clone or worktree under the system temp dir is unreclaimable: no git worktree list entry, no prune or wt remove can reach it, and /tmp is RAM-backed tmpfs on Linux. Use /var/tmp/agents for scratch trees, or wt switch --create --base <sha> for a throwaway worktree"
	fi

done <<_PFB_SEGS_
$segs
_PFB_SEGS_

exit 0
