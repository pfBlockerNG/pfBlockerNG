#!/bin/sh
# PreToolUse hook, matcher "Skill": re-syncs the current branch onto its base
# right before gh-issue, adr-phase, adr-create, delegate, or adr-all runs --
# the skills whose Step 0 mandates "git fetch origin + rebase, every
# invocation, including mid-session" (the remote advances out of band between
# work items in one session; SessionStart's sync only covers the first item).
# This mechanically enforces that mandate instead of relying on the agent to
# re-read and re-run Step 0's prose each time.
#
# FAIL-OPEN: any parse failure or a Skill call for a skill NOT in the
# allowlist below -> exit 0, no output, tool proceeds untouched (same
# contract as scripts/claude-bash-guard.sh's PreToolUse Bash guard).
#
# Text-scan of tool_input.skill (no jq -- house style, see
# claude-bash-guard.sh MATCHING): matches "skill":"gh-issue" /
# "skill": "gh-issue" regardless of whitespace around the colon.

set -u

payload="$(cat)"

case "$payload" in
	*'"skill"'*'"gh-issue"'* | *'"skill"'*'"adr-phase"'* | *'"skill"'*'"adr-create"'* | *'"skill"'*'"delegate"'* | *'"skill"'*'"adr-all"'*)
		;;
	*)
		exit 0
		;;
esac

. "$(dirname "$0")/branch-sync-core.sh"
branch_sync_run PreToolUse
