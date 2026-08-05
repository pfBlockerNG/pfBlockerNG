#!/bin/sh
# Copilot session lifecycle hook — one dispatcher for both call sites.
#
#   .github/hooks/pfblockerng.json  (repo-level, per the documented schema)
#   ~/.copilot/hooks/pfblockerng.json  (installed by install-copilot-hooks.sh)
#
# Two call sites because repo-level hooks did NOT fire in Copilot CLI 1.0.78:
# probed 2026-08-05 with `copilot -p`, an identical hook file at the user level
# fired both sessionStart and userPromptSubmitted while `.github/hooks/*.json`
# and inline `.github/copilot/settings.json` produced nothing (interactive mode
# untested). The repo file is the forward-compatible home; the user-level
# install is what actually runs today.
#
# Because the user-level file is global, EVERY command here first confirms the
# session's repository is a pfBlockerNG-org checkout — otherwise a session in an
# unrelated repo would get this repo's capsule and a stray marker file.
#
# Usage: copilot-session-hook.sh start|end

set -u

action=${1:-}
case "$action" in
	start | end) ;;
	*)
		echo "usage: copilot-session-hook.sh start|end" >&2
		exit 2
		;;
esac

top=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
[ -n "$top" ] || exit 0
marker_script="${top}/scripts/agent/copilot-session-marker.sh"
# The bootstrap plus this repo's own marker script: the pair that identifies a
# checkout this hook is allowed to act on.
[ -f "${top}/AGENTS.md" ] && [ -x "$marker_script" ] || exit 0

if [ "$action" = "end" ]; then
	sh "$marker_script" end
	exit 0
fi

sh "$marker_script" start
sh "${top}/.claude/hooks/session-branch-sync.sh" >/dev/null 2>&1 || true

# sessionStart is the one Copilot event whose stdout is parsed for
# additionalContext. The capsule mirrors .claude/settings.json and
# .codex/hooks.json; .github/copilot-instructions.md carries the same content as
# the reliable path, since a CLI build that drops this output must not drop the
# modes with it.
cat <<'PFB_COPILOT_CAPSULE'
{"additionalContext":"MANDATORY: AGENTS.md is the canonical agent bootstrap of this repo; .github/copilot-instructions.md is the thin Copilot adapter and .agents/context/copilot-adapter.md holds the Copilot noun translation. Follow the bootstrap, especially Working principles (investigate, do not assume; confirm genuine forks) and the never-list. The .agents/policy/ and .agents/context/ files and the docs/misc/ annexes are POLICY, binding like the bootstrap itself; read the relevant file whenever a routing-table trigger matches the task. Activate PONYTAIL full (laziest working solution) and CAVEMAN full (terse, no filler, full technical accuracy). TOKEN-SAVIOR recall preference applies where the MCP server is configured. This step CANNOT be skipped. Exception for external or public-facing text and documentation (GitHub issue and PR comments, PR bodies, commit messages, docs): concise but normal professional grammar."}
PFB_COPILOT_CAPSULE
