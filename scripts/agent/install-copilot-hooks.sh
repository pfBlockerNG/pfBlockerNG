#!/bin/sh
# Install this repo's Copilot session hooks at the user level.
#
# Copilot CLI 1.0.78 did not run repo-level `.github/hooks/*.json` (probed
# 2026-08-05, non-interactive `copilot -p`); an identical file under
# ~/.copilot/hooks/ did run. So the repo file stays as the forward-compatible
# definition and this installer wires the same dispatcher into the user-level
# location that works today. The dispatcher no-ops in any repository that is not
# a pfBlockerNG-org checkout, so a global install stays safe.
#
# Idempotent — rerun after moving the checkout. Mirrors scripts/setup-hooks.sh.
#
# Usage: sh scripts/agent/install-copilot-hooks.sh [--uninstall] [--root DIR]

set -u

root=''
uninstall=0
while [ $# -gt 0 ]; do
	case $1 in
		--uninstall) uninstall=1 ;;
		--root)
			shift
			[ $# -gt 0 ] && [ -n "${1:-}" ] || {
				echo 'install-copilot-hooks: --root needs a directory' >&2
				exit 2
			}
			root=$1
			;;
		*)
			echo "install-copilot-hooks: unknown argument: $1" >&2
			exit 2
			;;
	esac
	shift
done

if [ -z "$root" ]; then
	root=$(git rev-parse --show-toplevel 2>/dev/null) || {
		echo 'install-copilot-hooks: not inside a git checkout' >&2
		exit 1
	}
	# The primary checkout owns the scripts; a linked worktree shares them anyway,
	# but the installed hook must not point into a worktree that gets removed.
	# --root overrides this for testing an unmerged branch.
	common=$(git rev-parse --git-common-dir 2>/dev/null) || common=''
	case "$common" in
		*/.git) root=$(cd "${common%/.git}" && pwd -P) ;;
	esac
fi

hook_dir="${COPILOT_HOME:-$HOME/.copilot}/hooks"
hook_file="${hook_dir}/pfblockerng.json"

if [ "$uninstall" = "1" ]; then
	rm -f "$hook_file"
	echo "install-copilot-hooks: removed $hook_file"
	exit 0
fi

dispatcher="${root}/scripts/agent/copilot-session-hook.sh"
[ -f "$dispatcher" ] || {
	echo "install-copilot-hooks: missing $dispatcher" >&2
	exit 1
}

# The hook file is built by interpolation, so a path carrying JSON-significant
# characters would emit a file Copilot silently refuses to parse. The newline is
# matched through a variable holding a literal one: `$(printf '\n')` collapses to
# the empty string in a command substitution, and `*""*` matches every path.
pfb_nl='
'
pfb_bs=$(printf '\134') # octal escape: a literal '\' trips shellcheck SC1003
case "$dispatcher" in
	*'"'* | *"$pfb_bs"* | *"$pfb_nl"* | *"$(printf '\t')"*)
		echo "install-copilot-hooks: checkout path contains a character that cannot be embedded in JSON: $dispatcher" >&2
		exit 1
		;;
esac

mkdir -p "$hook_dir" || exit 1
cat > "$hook_file" <<PFB_COPILOT_HOOKS
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "bash": "sh \\"${dispatcher}\\" start",
        "timeoutSec": 120
      }
    ],
    "sessionEnd": [
      {
        "type": "command",
        "bash": "sh \\"${dispatcher}\\" end",
        "timeoutSec": 10
      }
    ],
    "subagentStart": [
      {
        "type": "command",
        "bash": "sh \\"${dispatcher}\\" subagent",
        "timeoutSec": 10
      }
    ]
  }
}
PFB_COPILOT_HOOKS

echo "install-copilot-hooks: wrote $hook_file -> $dispatcher"
