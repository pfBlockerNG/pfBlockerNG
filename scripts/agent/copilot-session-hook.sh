#!/bin/sh
# Copilot session lifecycle hook — one dispatcher for both call sites.
#
#   .github/hooks/pfblockerng.json     (repo-level, per the documented schema)
#   ~/.copilot/hooks/pfblockerng.json  (installed by install-copilot-hooks.sh)
#
# Two call sites because repo-level hooks did NOT fire in Copilot CLI 1.0.78:
# probed 2026-08-05 with `copilot -p`, an identical hook file at the user level
# fired both sessionStart and userPromptSubmitted while `.github/hooks/*.json`
# and inline `.github/copilot/settings.json` produced nothing (interactive mode
# untested). The repo file is the forward-compatible home; the user-level
# install is what actually runs today.
#
# SCOPE GUARD — the user-level hook file is GLOBAL: Copilot runs it for every
# session in every repository on the machine. So this dispatcher acts only when
# the session's repository IS the checkout this script itself lives in, compared
# by canonicalised common git dir (which makes a linked worktree of that checkout
# match, and everything else not). Identity, never a presence test: an earlier
# revision checked for an `AGENTS.md` plus an executable marker script and then
# EXECUTED both from the session's repo, so any checkout that created those two
# paths got this repo's capsule and arbitrary code execution out of a global
# hook. Everything executed below now comes from this script's own checkout.
#
# The marker script resolves the Copilot CLI pid by walking the process tree, so
# this dispatcher's own short life does not matter — it is not what gets recorded.
#
# Usage: copilot-session-hook.sh start|end|subagent

set -u

action=${1:-}
case "$action" in
	start | end | subagent) ;;
	*)
		echo "usage: copilot-session-hook.sh start|end|subagent" >&2
		exit 2
		;;
esac

unset CDPATH # a CDPATH hit makes cd echo the dir, corrupting $(cd ... && pwd -P)

# The checkout this script belongs to — scripts/agent/<this> — and the only one
# whose files it will run.
self_root=$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd -P) || exit 0
self_common=$(cd "$self_root" 2>/dev/null && git rev-parse --git-common-dir 2>/dev/null) || exit 0
self_common=$(cd "$self_root" 2>/dev/null && cd "$self_common" 2>/dev/null && pwd -P) || exit 0

session_common=$(git rev-parse --git-common-dir 2>/dev/null) || exit 0
session_common=$(cd "$session_common" 2>/dev/null && pwd -P) || exit 0

[ "$session_common" = "$self_common" ] || exit 0

marker_script="${self_root}/scripts/agent/copilot-session-marker.sh"
[ -f "$marker_script" ] || exit 0

if [ "$action" = "end" ]; then
	sh "$marker_script" end
	exit 0
fi

# subagentStart also has its stdout parsed for additionalContext, and a subagent
# inherits none of the session capsule.
if [ "$action" = "subagent" ]; then
	cat <<'PFB_COPILOT_SUBAGENT_CAPSULE'
{"additionalContext":"SESSION MODES: PONYTAIL full — YAGNI, reuse existing code, stdlib/native first, shortest correct diff; review-only tasks stay fully thorough. CAVEMAN full — terse connective prose, exact technical content and evidence. TOKEN-SAVIOR recall preference applies where the MCP server is configured. AGENTS.md and the routed .agents/policy/ files are binding. Public-facing text and documentation use normal professional grammar."}
PFB_COPILOT_SUBAGENT_CAPSULE
	exit 0
fi

sh "$marker_script" start
branch_sync="${self_root}/.claude/hooks/session-branch-sync.sh"
[ ! -f "$branch_sync" ] || sh "$branch_sync" >/dev/null 2>&1 || true

# sessionStart is the one Copilot event whose stdout is parsed for
# additionalContext. The capsule mirrors .claude/settings.json and
# .codex/hooks.json; .github/copilot-instructions.md carries the same content as
# the reliable path, since a CLI build that drops this output must not drop the
# modes with it.
cat <<'PFB_COPILOT_CAPSULE'
{"additionalContext":"MANDATORY: AGENTS.md is the canonical agent bootstrap of this repo; .github/copilot-instructions.md is the thin Copilot adapter and .agents/context/copilot-adapter.md holds the Copilot noun translation. Follow the bootstrap, especially Working principles (investigate, do not assume; confirm genuine forks) and the never-list. The .agents/policy/ and .agents/context/ files and the docs/misc/ annexes are POLICY, binding like the bootstrap itself; read the relevant file whenever a routing-table trigger matches the task. Activate PONYTAIL full (laziest working solution) and CAVEMAN full (terse, no filler, full technical accuracy). TOKEN-SAVIOR recall preference applies where the MCP server is configured. This step CANNOT be skipped. Exception for external or public-facing text and documentation (GitHub issue and PR comments, PR bodies, commit messages, docs): concise but normal professional grammar."}
PFB_COPILOT_CAPSULE
